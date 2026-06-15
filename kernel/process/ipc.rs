// RunixOS Rendezvous IPC System -- Phase 3: structured messages
//
// Phase 3 changes over Phase 2:
//   - `Message` gains a `tag` (IpcTag enum) and `version` field, turning the
//     raw byte blob into a typed envelope.  The kernel can inspect the tag
//     to validate/route messages without understanding the payload.
//   - `sys_send_typed` is the new ring-3 entry point.  It accepts a user-
//     supplied tag and version; the kernel enforces that the tag is valid
//     (known enum variant) before forwarding.  Unknown tags are rejected
//     with `Err(IpcError::InvalidTag)`.
//   - `IpcError` replaces the stringly-typed `()` error so callers can
//     distinguish "no capability" from "bad tag" from "target gone".
//   - The old `sys_send`/`sys_receive` remain for kernel-internal use (Task 1,
//     the kernel sender task) to avoid breaking Phase 2 paths while the ring-3
//     userspace blob is updated in a follow-up.
use crate::process::{TaskId, TaskState};
use crate::process::capability::Resource;
use crate::scheduler::SCHEDULER;

// ── Structured message types ────────────────────────────────────────────────

/// A discriminant that identifies the semantic type of an IPC message.
///
/// The kernel validates that the tag is a known variant before forwarding
/// (open-world enum variants are reserved for future phases).  This means a
/// receiver can trust the tag was not forged by a buggy sender: the kernel
/// would have rejected it.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcTag {
    /// Untyped raw bytes -- backward-compat with Phase 2 paths.
    Raw     = 0,
    /// A UTF-8 log line destined for the logging service.
    Log     = 1,
    /// A key=value sensor reading (Phase 3 demo).
    Sensor  = 2,
    /// An explicit "no operation" heartbeat ping.
    Ping    = 3,
}

impl IpcTag {
    /// Attempts to parse a u16 discriminant into a known tag.
    /// Returns `None` for unknown values so the kernel can reject them.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0 => Some(IpcTag::Raw),
            1 => Some(IpcTag::Log),
            2 => Some(IpcTag::Sensor),
            3 => Some(IpcTag::Ping),
            _ => None,
        }
    }
}

/// The structured IPC message envelope.
///
/// `tag` and `version` are kernel-visible and validated before delivery.
/// `payload` is opaque to the kernel; the receiver interprets it.
#[derive(Debug, Clone, Copy)]
pub struct Message {
    /// The task ID of the sender (set by the kernel, not the sender).
    pub sender: TaskId,
    /// Message type discriminant, validated by the kernel.
    pub tag: IpcTag,
    /// Protocol version for forward-compat (kernel only checks != 0xFFFF).
    pub version: u16,
    /// Fixed-size message payload; no shared buffers.
    pub payload: [u8; 128],
    /// Actual byte count of valid payload data.
    pub len: usize,
}

/// Typed error returned by IPC operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// The capability index is invalid or does not name an IpcChannel.
    NoCapability,
    /// The target task no longer exists.
    TargetGone,
    /// The payload exceeds the 128-byte limit.
    PayloadTooLarge,
    /// The tag discriminant is not a known IpcTag variant.
    InvalidTag,
    /// The version field is the reserved sentinel (0xFFFF).
    BadVersion,
    /// No current task context (called outside a scheduled task).
    NoContext,
    /// The target message queue is full (for async send).
    QueueFull,
    /// No message available in the queue (for async receive).
    NoMessage,
}

pub const MSG_QUEUE_CAPACITY: usize = 8;

/// Static message queue for async IPC.
#[derive(Debug, Clone, Copy)]
pub struct MessageQueue {
    pub buffer: [Option<Message>; MSG_QUEUE_CAPACITY],
    pub head: usize,
    pub tail: usize,
    pub count: usize,
}

impl MessageQueue {
    pub const fn new() -> Self {
        Self {
            buffer: [None; MSG_QUEUE_CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn is_full(&self) -> bool {
        self.count == MSG_QUEUE_CAPACITY
    }

    pub fn enqueue(&mut self, msg: Message) -> Result<(), ()> {
        if self.is_full() {
            return Err(());
        }
        self.buffer[self.tail] = Some(msg);
        self.tail = (self.tail + 1) % MSG_QUEUE_CAPACITY;
        self.count += 1;
        Ok(())
    }

    pub fn dequeue(&mut self) -> Option<Message> {
        if self.is_empty() {
            return None;
        }
        let msg = self.buffer[self.head].take();
        self.head = (self.head + 1) % MSG_QUEUE_CAPACITY;
        self.count -= 1;
        msg
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Validates a send capability against an **already-held** scheduler lock,
/// resolving the IpcChannel it authorizes to a concrete target task.
///
/// This is the *validation* half of a send. Splitting it out so it can run under
/// a caller-held lock is what lets the send path keep validation and use in one
/// indivisible critical section (see `sys_send_typed`): the old design validated
/// under its own short-lived lock and then re-locked to deliver, leaving a gap in
/// which the capability could be revoked -- the Phase 11 TOCTOU.
fn resolve_target_locked(
    sched: &crate::scheduler::Scheduler,
    current: TaskId,
    cap_idx: usize,
) -> Result<TaskId, IpcError> {
    let task = sched.get_task(current).ok_or(IpcError::NoContext)?;
    let cap = task.cap_table.get(cap_idx).ok_or(IpcError::NoCapability)?;
    match cap.resource {
        Resource::IpcChannel { target_task } => Ok(target_task),
        _ => Err(IpcError::NoCapability),
    }
}

/// Resolves the IpcChannel target from the current task's capability table,
/// acquiring the scheduler lock itself. Used by paths that only need a one-shot
/// resolution (not the atomic validate→use of the blocking send).
fn resolve_target(cap_idx: usize) -> Result<TaskId, IpcError> {
    let sched = SCHEDULER.lock();
    let id = sched.current_task_id.ok_or(IpcError::NoContext)?;
    resolve_target_locked(&sched, id, cap_idx)
}

/// Outcome of one validate→use attempt inside the send loop.
enum SendStep {
    /// Message deposited and receiver marked runnable.
    Delivered,
    /// Target is gone (terminated/missing); fail without delivering.
    Gone,
    /// Target not ready to receive; sender parked, will retry after waking.
    Blocked,
}

// ── Phase 3 & 5 public API ───────────────────────────────────────────────────

/// Sends a **structured** message to the task named by an IpcChannel
/// capability.  The kernel validates `tag` and `version` before forwarding.
///
/// Blocks (cooperative) until the target receives the message.
pub fn sys_send_typed(
    cap_idx: usize,
    tag: u16,
    version: u16,
    payload: &[u8],
) -> Result<(), IpcError> {
    // Validate inputs before touching shared state.
    if payload.len() > 128 {
        return Err(IpcError::PayloadTooLarge);
    }
    let tag = IpcTag::from_u16(tag).ok_or(IpcError::InvalidTag)?;
    if version == 0xFFFF {
        return Err(IpcError::BadVersion);
    }

    let current_task_id = {
        let sched = SCHEDULER.lock();
        sched.current_task_id.ok_or(IpcError::NoContext)?
    };

    let mut msg_payload = [0u8; 128];
    msg_payload[..payload.len()].copy_from_slice(payload);
    let len = payload.len();

    loop {
        // ── Non-preemptible capability validate→use region (Phase 11) ─────────
        //
        // The send capability is (re)validated and *used* inside one indivisible
        // region, so the authority that delivers the message is exactly the
        // authority we just checked -- never a snapshot taken before a blocking
        // wait, and never one another task revoked in the gap between check and
        // use. This closes the TOCTOU the Phase 11 VULNERABLE/GUARDED experiment
        // reproduces, now in the real path every ring-3 sender travels.
        //
        // The "use-point" -- where the region must extend to -- is deliberately
        // AFTER both halves of delivery: the message is deposited in the
        // receiver's `ipc_buffer` AND the receiver is marked `Ready`. The
        // guarantee is therefore "a delivered message implies the capability was
        // valid at the instant of delivery and the receiver will observe it";
        // a half-delivery (deposited but receiver not woken, or vice versa) can
        // never be observed.
        //
        // The blocking wait is OUTSIDE the region: a non-preemptible region must
        // never contain a yield (the global preempt-count would leak to whatever
        // task we yield to). Each wakeup re-enters the region and re-validates
        // from scratch, so even a capability revoked *while the sender was
        // blocked* is caught before the next delivery attempt.
        let outcome = {
            // The guard raises the non-preemptible count (and marks the window)
            // and releases both when this scope ends -- covering the early-return
            // validation-failure path too. The blocking wait below is outside it.
            let _region = crate::preempt::CriticalWindow::enter();
            let mut sched = SCHEDULER.lock();

            // VALIDATE.
            match resolve_target_locked(&sched, current_task_id, cap_idx) {
                Err(e) => {
                    // Authority invalid/revoked: discard any payload parked on a
                    // prior attempt so it can't be mistaken for an inbound message.
                    if let Some(sender) = sched.get_task_mut(current_task_id) {
                        sender.ipc_buffer = None;
                    }
                    return Err(e);
                }
                Ok(target_task_id) => {
                    let msg = Message {
                        sender: current_task_id,
                        tag,
                        version,
                        payload: msg_payload,
                        len,
                    };

                    // USE. Read the target's state first (immutable borrow), then
                    // act, to keep the borrows of the two task slots disjoint.
                    match sched.get_task(target_task_id).map(|t| t.state) {
                        // A dead target can never receive: fail fast, don't block.
                        None | Some(TaskState::Terminated) => SendStep::Gone,
                        Some(TaskState::BlockedOnReceive) => {
                            if let Some(target) = sched.get_task_mut(target_task_id) {
                                target.ipc_buffer = Some(msg);
                                target.state = TaskState::Ready;
                            }
                            SendStep::Delivered
                        }
                        Some(_) => {
                            if let Some(sender) = sched.get_task_mut(current_task_id) {
                                sender.state = TaskState::BlockedOnSend(target_task_id);
                                sender.ipc_buffer = Some(msg);
                            }
                            SendStep::Blocked
                        }
                    }
                }
            }
            // `_region` (and the scheduler lock) drop here: end of validate→use.
        };

        match outcome {
            SendStep::Delivered => return Ok(()),
            SendStep::Gone => {
                let mut sched = SCHEDULER.lock();
                if let Some(sender) = sched.get_task_mut(current_task_id) {
                    sender.ipc_buffer = None;
                }
                return Err(IpcError::TargetGone);
            }
            SendStep::Blocked => {
                // Preemptible wait. A receiver that consumes our parked message
                // clears our ipc_buffer; on resume we detect that and finish.
                crate::scheduler::yield_cpu();
                let consumed = {
                    let sched = SCHEDULER.lock();
                    match sched.get_task(current_task_id) {
                        Some(t) => t.ipc_buffer.is_none(),
                        None => return Err(IpcError::TargetGone),
                    }
                };
                if consumed {
                    return Ok(());
                }
                // Spurious wake: loop, re-validate, retry.
            }
        }
    }
}

/// Receives a structured IPC message.  Blocks until one arrives.
pub fn sys_receive_typed() -> Result<Message, IpcError> {
    let current_task_id = {
        let sched = SCHEDULER.lock();
        sched.current_task_id.ok_or(IpcError::NoContext)?
    };

    loop {
        let mut sched = SCHEDULER.lock();

        // 1. Check if there is a message in our message queue
        if let Some(receiver) = sched.get_task_mut(current_task_id) {
            if let Some(msg) = receiver.msg_queue.dequeue() {
                return Ok(msg);
            }
            // 2. Check if a message was deposited directly in our ipc_buffer
            if let Some(msg) = receiver.ipc_buffer.take() {
                return Ok(msg);
            }
        }

        // 3. Check for a queued/blocked sender (Rendezvous)
        let mut found_sender_id = None;
        for i in 0..crate::process::MAX_TASKS {
            if let Some(ref t) = sched.tasks[i] {
                if t.state == TaskState::BlockedOnSend(current_task_id) {
                    found_sender_id = Some(t.id);
                    break;
                }
            }
        }

        if let Some(sender_id) = found_sender_id {
            let mut msg = None;
            if let Some(sender) = sched.get_task_mut(sender_id) {
                msg = sender.ipc_buffer.take();
                sender.state = TaskState::Ready;
            }
            if let Some(receiver) = sched.get_task_mut(current_task_id) {
                receiver.state = TaskState::Running;
            }
            return msg.ok_or(IpcError::TargetGone);
        }

        // 4. Block on receive.
        if let Some(receiver) = sched.get_task_mut(current_task_id) {
            receiver.state = TaskState::BlockedOnReceive;
        }

        drop(sched);
        crate::scheduler::yield_cpu();
    }
}

/// Sends a typed message asynchronously to the task named by an IpcChannel capability.
/// Does not block. If the target queue is full, returns `Err(IpcError::QueueFull)`.
pub fn sys_send_async(
    cap_idx: usize,
    tag: u16,
    version: u16,
    payload: &[u8],
) -> Result<(), IpcError> {
    if payload.len() > 128 {
        return Err(IpcError::PayloadTooLarge);
    }
    let tag = IpcTag::from_u16(tag).ok_or(IpcError::InvalidTag)?;
    if version == 0xFFFF {
        return Err(IpcError::BadVersion);
    }

    let current_task_id = {
        let sched = SCHEDULER.lock();
        sched.current_task_id.ok_or(IpcError::NoContext)?
    };

    let mut msg_payload = [0u8; 128];
    msg_payload[..payload.len()].copy_from_slice(payload);
    let msg = Message {
        sender: current_task_id,
        tag,
        version,
        payload: msg_payload,
        len: payload.len(),
    };

    // Same non-preemptible validate→use region as `sys_send_typed`, minus the
    // blocking wait (async send never parks). Validating and enqueuing under one
    // held lock + preempt guard means the capability that authorizes the enqueue
    // is the one we just checked.
    crate::preempt::enter_critical();
    let mut sched = SCHEDULER.lock();

    let result = match resolve_target_locked(&sched, current_task_id, cap_idx) {
        Err(e) => Err(e),
        Ok(target_task_id) => match sched.get_task_mut(target_task_id) {
            Some(target) if target.state == TaskState::Terminated => Err(IpcError::TargetGone),
            Some(target) => {
                if target.msg_queue.enqueue(msg).is_ok() {
                    if target.state == TaskState::BlockedOnReceive {
                        target.state = TaskState::Ready;
                    }
                    Ok(())
                } else {
                    Err(IpcError::QueueFull)
                }
            }
            None => Err(IpcError::TargetGone),
        },
    };

    drop(sched);
    crate::preempt::exit_critical();
    result
}

/// Non-blocking receive: returns the first message from the queue or blocked senders,
/// or returns `Err(IpcError::NoMessage)` if none is available.
pub fn sys_receive_async() -> Result<Message, IpcError> {
    let current_task_id = {
        let sched = SCHEDULER.lock();
        sched.current_task_id.ok_or(IpcError::NoContext)?
    };

    let mut sched = SCHEDULER.lock();

    // 1. Check if there is a message in our message queue
    if let Some(receiver) = sched.get_task_mut(current_task_id) {
        if let Some(msg) = receiver.msg_queue.dequeue() {
            return Ok(msg);
        }
        // 2. Check if a message was deposited directly in our ipc_buffer by a rendezvous sender
        if let Some(msg) = receiver.ipc_buffer.take() {
            return Ok(msg);
        }
    }

    // 3. Check for a queued/blocked sender (Rendezvous fallback)
    let mut found_sender_id = None;
    for i in 0..crate::process::MAX_TASKS {
        if let Some(ref t) = sched.tasks[i] {
            if t.state == TaskState::BlockedOnSend(current_task_id) {
                found_sender_id = Some(t.id);
                break;
            }
        }
    }

    if let Some(sender_id) = found_sender_id {
        let mut msg = None;
        if let Some(sender) = sched.get_task_mut(sender_id) {
            msg = sender.ipc_buffer.take();
            sender.state = TaskState::Ready;
        }
        if let Some(receiver) = sched.get_task_mut(current_task_id) {
            receiver.state = TaskState::Running;
        }
        return msg.ok_or(IpcError::TargetGone);
    }

    Err(IpcError::NoMessage)
}

// ── Phase 1/2 compatibility shims ───────────────────────────────────────────
// Kept so the kernel-task paths (task_sender in boot/main.rs) and the legacy
// receive path in the logger blob still compile without modification.
/// Legacy untyped send (Phase 1/2 compatibility).  Wraps as `IpcTag::Raw`.
pub fn sys_send(cap_idx: usize, payload: &[u8]) -> Result<(), ()> {
    sys_send_typed(cap_idx, IpcTag::Raw as u16, 0, payload).map_err(|_| ())
}

/// Legacy untyped receive (Phase 1/2 compatibility).
pub fn sys_receive() -> Result<Message, ()> {
    sys_receive_typed().map_err(|_| ())
}

