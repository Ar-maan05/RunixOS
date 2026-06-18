// RunixOS syscall surface: structured dispatch and capability grant
//
// RunixOS has no traditional syscall model. The `int 0x80` trap is purely the
// ring-3 to ring-0 transport. Every request is validated against the caller's
// capabilities.
//
// Syscall entry points:
//   * `SYS_CAP_GRANT`   (5): delegate an attenuated capability to another task
//   * `SYS_SEND_TYPED`  (6): IPC send with tag and version validated by kernel
//   * The dispatcher uses a match on a `KernelRequest` enum built
//     from the raw register frame, rather than ad-hoc if/else chains.

use crate::process::capability::{Capability, Resource, RightsMask};
use crate::scheduler::SCHEDULER;

// ── Syscall numbers (passed in rax) ─────────────────────────────────────────
pub const SYS_DEBUG:      u64 = 0; // liveness ping
pub const SYS_YIELD:      u64 = 1; // cooperative yield
pub const SYS_SEND:       u64 = 2; // legacy IPC send (compatibility mode)
pub const SYS_RECEIVE:    u64 = 3; // IPC receive
pub const SYS_SERIAL_WRITE: u64 = 4; // capability-gated serial write
pub const SYS_CAP_GRANT:  u64 = 5; // delegate attenuated capability
pub const SYS_SEND_TYPED: u64 = 6; // structured IPC send
pub const SYS_CAP_REVOKE: u64 = 7; // revoke capability from target task
pub const SYS_SEND_ASYNC: u64 = 8; // async IPC send
pub const SYS_RECEIVE_ASYNC: u64 = 9; // async IPC receive
pub const SYS_SPAWN_TASK: u64 = 10; // spawn user task

// ── Register frame ──────────────────────────────────────────────────────────

/// Register state saved by the `syscall_entry` stub, in memory order (the
/// first field is at the lowest address = top of stack on entry to dispatcher).
#[repr(C)]
pub struct SyscallFrame {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8:  u64,
    pub r9:  u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    // CPU-pushed interrupt frame (rip, cs, rflags, rsp, ss) follows.
}

// ── int 0x80 entry stub ──────────────────────────────────────────────────────

core::arch::global_asm!(
    ".global syscall_entry",
    "syscall_entry:",
    "    push r15",
    "    push r14",
    "    push r13",
    "    push r12",
    "    push r11",
    "    push r10",
    "    push r9",
    "    push r8",
    "    push rbp",
    "    push rdi",
    "    push rsi",
    "    push rdx",
    "    push rcx",
    "    push rbx",
    "    push rax",
    "    mov rdi, rsp",          // &SyscallFrame
    "    call syscall_dispatch",
    "    pop rax",
    "    pop rbx",
    "    pop rcx",
    "    pop rdx",
    "    pop rsi",
    "    pop rdi",
    "    pop rbp",
    "    pop r8",
    "    pop r9",
    "    pop r10",
    "    pop r11",
    "    pop r12",
    "    pop r13",
    "    pop r14",
    "    pop r15",
    "    iretq",
);

extern "C" {
    /// The `int 0x80` entry stub (address installed into the IDT).
    pub fn syscall_entry();
}

// ── Kernel dispatch layer ────────────────────────────────────────────────────

/// A typed representation of the caller's request, built from a `SyscallFrame`.
/// Having a separate enum means the match in `syscall_dispatch` is exhaustive
/// and each arm has already validated its inputs.
enum KernelRequest<'a> {
    Debug,
    Yield,
    /// Legacy untyped send: cap_idx, payload slice.
    Send { cap_idx: usize, payload: &'a [u8] },
    Receive { buf: *mut u8, cap: usize },
    SerialWrite { cap_idx: usize, bytes: &'a [u8] },
    /// Grant an attenuated cap to a target task.
    CapGrant {
        /// Slot in the caller's table to grant from.
        src_cap_idx: usize,
        /// Target task ID to grant into.
        target_task: usize,
        /// Requested rights for the derived capability.
        rights: RightsMask,
    },
    /// Structured send with tag + version.
    SendTyped {
        cap_idx: usize,
        tag: u16,
        version: u16,
        payload: &'a [u8],
    },
    /// Revoke capability from target task.
    CapRevoke {
        target_task: usize,
        cap_idx: usize,
    },
    /// Async IPC send
    SendAsync {
        cap_idx: usize,
        tag: u16,
        version: u16,
        payload: &'a [u8],
    },
    /// Async IPC receive
    ReceiveAsync {
        buf: *mut u8,
        cap: usize,
    },
    /// Spawn user task
    SpawnTask {
        blob_type: usize,
    },
    Unknown(u64),
}

/// Converts a raw `SyscallFrame` into a typed `KernelRequest`.  Does *not*
/// yet validate the semantics; that happens inside each dispatch arm.
///
/// # Safety
/// `frame` must be the live syscall frame on the kernel stack.
unsafe fn parse_request(frame: &SyscallFrame) -> KernelRequest<'_> {
    match frame.rax {
        SYS_DEBUG => KernelRequest::Debug,
        SYS_YIELD => KernelRequest::Yield,

        SYS_SEND => {
            let cap_idx = frame.rdi as usize;
            let ptr     = frame.rsi as *const u8;
            let len     = frame.rdx as usize;
            if len <= 128 && crate::memory::validate_user_range(ptr, len, false).is_ok() {
                let payload = unsafe { core::slice::from_raw_parts(ptr, len) };
                KernelRequest::Send { cap_idx, payload }
            } else {
                KernelRequest::Unknown(frame.rax)
            }
        }

        SYS_RECEIVE => {
            let buf = frame.rsi as *mut u8;
            let cap = frame.rdx as usize;
            let check_len = core::cmp::min(cap, 128);
            if crate::memory::validate_user_range(buf, check_len, true).is_ok() {
                KernelRequest::Receive { buf, cap }
            } else {
                KernelRequest::Unknown(frame.rax)
            }
        }

        SYS_SERIAL_WRITE => {
            let cap_idx = frame.rdi as usize;
            let ptr     = frame.rsi as *const u8;
            let len     = frame.rdx as usize;
            if len <= 4096 && crate::memory::validate_user_range(ptr, len, false).is_ok() {
                let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
                KernelRequest::SerialWrite { cap_idx, bytes }
            } else {
                KernelRequest::Unknown(frame.rax)
            }
        }

        SYS_CAP_GRANT => {
            let src_cap_idx = frame.rdi as usize;
            let target_task = frame.rsi as usize;
            let bits        = frame.rdx as u8;
            let rights = RightsMask {
                read:  (bits & 0x1) != 0,
                write: (bits & 0x2) != 0,
                grant: (bits & 0x4) != 0,
            };
            KernelRequest::CapGrant { src_cap_idx, target_task, rights }
        }

        SYS_SEND_TYPED => {
            let cap_idx = frame.rdi as usize;
            let ptr     = frame.rsi as *const u8;
            let tag     = (frame.rdx & 0xFFFF) as u16;
            let version = ((frame.rdx >> 16) & 0xFFFF) as u16;
            let len     = frame.r8 as usize;
            if len <= 128 && crate::memory::validate_user_range(ptr, len, false).is_ok() {
                let payload = unsafe { core::slice::from_raw_parts(ptr, len) };
                KernelRequest::SendTyped { cap_idx, tag, version, payload }
            } else {
                KernelRequest::Unknown(frame.rax)
            }
        }

        SYS_CAP_REVOKE => {
            let target_task = frame.rdi as usize;
            let cap_idx     = frame.rsi as usize;
            KernelRequest::CapRevoke { target_task, cap_idx }
        }

        SYS_SEND_ASYNC => {
            let cap_idx = frame.rdi as usize;
            let ptr     = frame.rsi as *const u8;
            let tag     = (frame.rdx & 0xFFFF) as u16;
            let version = ((frame.rdx >> 16) & 0xFFFF) as u16;
            let len     = frame.r8 as usize;
            if len <= 128 && crate::memory::validate_user_range(ptr, len, false).is_ok() {
                let payload = unsafe { core::slice::from_raw_parts(ptr, len) };
                KernelRequest::SendAsync { cap_idx, tag, version, payload }
            } else {
                KernelRequest::Unknown(frame.rax)
            }
        }

        SYS_RECEIVE_ASYNC => {
            let buf = frame.rsi as *mut u8;
            let cap = frame.rdx as usize;
            let check_len = core::cmp::min(cap, 128);
            if crate::memory::validate_user_range(buf, check_len, true).is_ok() {
                KernelRequest::ReceiveAsync { buf, cap }
            } else {
                KernelRequest::Unknown(frame.rax)
            }
        }

        SYS_SPAWN_TASK => {
            let blob_type = frame.rdi as usize;
            KernelRequest::SpawnTask { blob_type }
        }

        other => KernelRequest::Unknown(other),
    }
}

/// Dispatches a syscall. Return value is written into `frame.rax`; the user
/// sees it after `iretq`. Convention: 0 = OK, u64::MAX = generic error.
#[no_mangle]
pub extern "C" fn syscall_dispatch(frame: &mut SyscallFrame) {
    let task_id = SCHEDULER
        .lock()
        .current_task_id
        .map(|t| t.0)
        .unwrap_or(usize::MAX);

    crate::dbg_println!("[syscall] task {} entry: rax={}, rdi={}, rsi={}, rdx={}, r8={}, stack_cs={:#x}",
        task_id, frame.rax, frame.rdi, frame.rsi, frame.rdx, frame.r8,
        unsafe { *(frame as *const SyscallFrame as *const u64).add(16) });

    // SAFETY: frame is the live kernel stack frame built by syscall_entry.
    let req = unsafe { parse_request(frame) };

    match req {
        KernelRequest::Debug => {
            crate::dbg_println!(
                "[ring3] task {} alive: syscall via int 0x80 reached the kernel.",
                task_id
            );
            frame.rax = 0;
        }

        KernelRequest::Yield => {
            crate::scheduler::yield_cpu();
            frame.rax = 0;
        }

        KernelRequest::Send { cap_idx, payload } => {
            frame.rax = match crate::process::ipc::sys_send(cap_idx, payload) {
                Ok(())  => 0,
                Err(()) => u64::MAX,
            };
        }

        KernelRequest::Receive { buf, cap } => {
            match crate::process::ipc::sys_receive() {
                Ok(msg) if crate::memory::validate_user_range(buf, core::cmp::min(msg.len, cap), true).is_ok() => {
                    let n = core::cmp::min(msg.len, cap);
                    unsafe { core::ptr::copy_nonoverlapping(msg.payload.as_ptr(), buf, n) };
                    frame.rax = n as u64;
                }
                _ => frame.rax = u64::MAX,
            }
        }

        KernelRequest::SerialWrite { cap_idx, bytes } => {
            if current_has_serial_cap(cap_idx) {
                if let Ok(s) = core::str::from_utf8(bytes) {
                    crate::print!("{}", s);
                }
                frame.rax = 0;
            } else {
                frame.rax = u64::MAX;
            }
        }

        // ── Capability grant ──────────────────────────────────────────────
        KernelRequest::CapGrant { src_cap_idx, target_task, rights } => {
            frame.rax = dispatch_cap_grant(task_id, src_cap_idx, target_task, rights);
        }

        // ── Structured send ───────────────────────────────────────────────
        KernelRequest::SendTyped { cap_idx, tag, version, payload } => {
            frame.rax = match crate::process::ipc::sys_send_typed(cap_idx, tag, version, payload) {
                Ok(())     => 0,
                Err(e) => {
                    // Log rejection reason for observability.
                    crate::println!("[syscall] SYS_SEND_TYPED rejected: {:?}", e);
                    u64::MAX
                }
            };
        }

        // ── Async send & receive ──────────────────────────────────────────
        KernelRequest::SendAsync { cap_idx, tag, version, payload } => {
            frame.rax = match crate::process::ipc::sys_send_async(cap_idx, tag, version, payload) {
                Ok(()) => 0,
                Err(crate::process::IpcError::QueueFull) => {
                    u64::MAX - 7
                }
                Err(e) => {
                    crate::println!("[syscall] SYS_SEND_ASYNC rejected: {:?}", e);
                    u64::MAX
                }
            };
        }

        KernelRequest::ReceiveAsync { buf, cap } => {
            match crate::process::ipc::sys_receive_async() {
                Ok(msg) => {
                    let n = core::cmp::min(msg.len, cap);
                    if crate::memory::validate_user_range(buf, n, true).is_ok() {
                        unsafe { core::ptr::copy_nonoverlapping(msg.payload.as_ptr(), buf, n) };
                        frame.rax = n as u64;
                    } else {
                        frame.rax = u64::MAX;
                    }
                }
                Err(crate::process::IpcError::NoMessage) => {
                    frame.rax = u64::MAX - 8;
                }
                Err(e) => {
                    crate::println!("[syscall] SYS_RECEIVE_ASYNC rejected: {:?}", e);
                    frame.rax = u64::MAX;
                }
            }
        }

        // ── Spawn user task ───────────────────────────────────────────────
        KernelRequest::SpawnTask { blob_type } => {
            if task_id == 1 {
                frame.rax = dispatch_spawn_task(blob_type);
            } else {
                frame.rax = u64::MAX;
            }
        }

        // ── Capability revocation ─────────────────────────────────────────
        KernelRequest::CapRevoke { target_task, cap_idx } => {
            frame.rax = dispatch_cap_revoke(task_id, target_task, cap_idx);
        }

        KernelRequest::Unknown(n) => {
            crate::println!("[syscall] task {} made unknown syscall {}", task_id, n);
            frame.rax = u64::MAX;
        }
    }
    crate::dbg_println!("[syscall] task {} exit: rax={}, stack_cs={:#x}",
        task_id, frame.rax,
        unsafe { *(frame as *const SyscallFrame as *const u64).add(16) });
}

// ── Capability grant implementation ─────────────────────────────────────────

/// Executes the SYS_CAP_GRANT request for the running task.
///
/// 1. Locate the source capability in the caller's table.
/// 2. Call `attenuate` to derive a capability with the requested rights.
///    This enforces rights attenuation: the derived cap cannot exceed the donor.
/// 3. Insert the derived capability into the target task's table.
///
/// Returns 0 on success, u64::MAX on any error.
fn dispatch_cap_grant(
    caller_task: usize,
    src_cap_idx: usize,
    target_task: usize,
    rights: RightsMask,
) -> u64 {
    let caller_id = crate::process::TaskId(caller_task);
    let target_id = crate::process::TaskId(target_task);

    // Step 1: derive the attenuated capability from the caller's table.
    let derived: Capability = {
        let sched = SCHEDULER.lock();
        let task = match sched.get_task(caller_id) {
            Some(t) => t,
            None => {
                crate::println!("[cap_grant] caller task {} not found", caller_task);
                return u64::MAX;
            }
        };
        let cap = match task.cap_table.get(src_cap_idx) {
            Some(c) => c,
            None => {
                crate::println!(
                    "[cap_grant] task {} slot {} is empty",
                    caller_task, src_cap_idx
                );
                return u64::MAX;
            }
        };
        match cap.attenuate(rights) {
            Ok(mut derived) => {
                // Stamp derivation lineage (the donor capability's
                // unique id) so a later revocation of the donor propagates here.
                derived.origin = Some(cap.id);
                derived
            }
            Err(()) => {
                crate::println!(
                    "[cap_grant] task {} slot {} lacks grant right",
                    caller_task, src_cap_idx
                );
                return u64::MAX;
            }
        }
    };

    // Step 2: insert the derived cap into the target task's table.
    let mut sched = SCHEDULER.lock();
    let target = match sched.get_task_mut(target_id) {
        Some(t) => t,
        None => {
            crate::println!("[cap_grant] target task {} not found", target_task);
            return u64::MAX;
        }
    };
    match target.cap_table.insert(derived) {
        Ok(slot) => {
            crate::dbg_println!(
                "[cap_grant] task {} -> task {} granted {:?} at slot {}",
                caller_task, target_task, derived.resource, slot
            );
            crate::process::audit::record(
                crate::process::audit::AuditKind::Grant,
                caller_id,
                target_id,
                derived.resource,
                slot,
            );
            0
        }
        Err(()) => {
            crate::println!("[cap_grant] target task {} cap table full", target_task);
            u64::MAX
        }
    }
}

// ── Capability revocation implementation ─────────────────────────────────────

/// Executes the SYS_CAP_REVOKE request for the running task.
///
/// 1. Verifies that the caller task holds a capability targeting the target task
///    with `grant = true`. This prevents arbitrary unauthorized revocation.
/// 2. Calls `kernel_revoke` on the target task's capability table, bypassing
///    any slot sealing checks.
///
/// Returns 0 on success, u64::MAX on error.
fn dispatch_cap_revoke(
    caller_task: usize,
    target_task: usize,
    cap_idx: usize,
) -> u64 {
    // Step 1: Enforce capability gating. Caller must hold a grant/delegation
    // capability to the target task.
    if !current_has_grant_cap_to(target_task) {
        crate::println!(
            "[cap_revoke] caller task {} lacks grant/delegation capability to task {}",
            caller_task, target_task
        );
        return u64::MAX;
    }

    let target_id = crate::process::TaskId(target_task);
    let mut sched = SCHEDULER.lock();
    let target = match sched.get_task_mut(target_id) {
        Some(t) => t,
        None => {
            crate::println!("[cap_revoke] target task {} not found", target_task);
            return u64::MAX;
        }
    };

    match target.cap_table.kernel_revoke(cap_idx) {
        Some(cap) => {
            crate::dbg_println!(
                "[cap_revoke] task {} forced revocation of {:?} from slot {} of task {}",
                caller_task, cap.resource, cap_idx, target_task
            );
            crate::process::audit::record(
                crate::process::audit::AuditKind::Revoke,
                crate::process::TaskId(caller_task),
                target_id,
                cap.resource,
                cap_idx,
            );
            // Revocation propagation: revoke every capability derived
            // (transitively) from the one just removed.
            propagate_revocation(&mut sched, cap.id);
            0
        }
        None => {
            crate::println!(
                "[cap_revoke] target task {} slot {} is empty",
                target_task, cap_idx
            );
            u64::MAX
        }
    }
}

/// Scratch set of revoked capability ids, used only by `propagate_revocation`.
/// Sized to every capability the system can hold (`MAX_TASKS * MAX_CAPS`) plus
/// one for the revoked root id (which no longer occupies a slot), so the cascade
/// is never truncated. Safe as a `static mut`: propagation runs to completion
/// under the scheduler lock without yielding, so it is never re-entered.
const REVOKED_IDS_CAP: usize =
    crate::process::MAX_TASKS * crate::process::capability::MAX_CAPS + 1;
static mut REVOKED_IDS: [u64; REVOKED_IDS_CAP] = [0; REVOKED_IDS_CAP];

/// Transitively revokes every capability whose lineage (`origin`) traces back to
/// the capability with id `root_id` (the one just revoked).
///
/// Runs under the held scheduler lock in the single-threaded cooperative model,
/// so the table snapshot is stable. Implemented as a fixpoint over the capability
/// tables keyed by globally-unique capability *ids*: a child is revoked once its
/// `origin` is found in the revoked set, and its own id joins the set, until a
/// full pass makes no further changes. This is complete (no fan-out limit) and
/// terminates (ids are unique; each cap is revoked at most once).
fn propagate_revocation(sched: &mut crate::scheduler::Scheduler, root_id: u64) {
    use crate::process::{MAX_TASKS};
    use crate::process::capability::MAX_CAPS;
    use crate::process::audit::{record, AuditKind, KERNEL_ACTOR};

    // SAFETY: single-threaded, non-reentrant (no yield within this function).
    let revoked = unsafe { &mut *core::ptr::addr_of_mut!(REVOKED_IDS) };
    let mut count = 0usize;
    revoked[count] = root_id;
    count += 1;

    let is_revoked = |set: &[u64], n: usize, id: u64| -> bool {
        set[..n].iter().any(|&x| x == id)
    };

    loop {
        let mut changed = false;
        for t_idx in 0..MAX_TASKS {
            if let Some(task) = sched.tasks[t_idx].as_mut() {
                let child_task = task.id;
                for s in 0..MAX_CAPS {
                    if let Some(cap) = task.cap_table.get(s).copied() {
                        if let Some(parent_id) = cap.origin {
                            if is_revoked(revoked, count, parent_id) && count < revoked.len() {
                                task.cap_table.kernel_revoke(s);
                                record(
                                    AuditKind::RevokePropagated,
                                    KERNEL_ACTOR,
                                    child_task,
                                    cap.resource,
                                    s,
                                );
                                revoked[count] = cap.id;
                                count += 1;
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
}

// ── Security and capability maturity demonstration ──────────────────────────

/// Self-contained demonstration of capability maturity: builds a
/// three-level derivation chain across scratch tasks, revokes the root, and
/// verifies the revocation propagates transitively to every derived capability.
/// Finishes by dumping the kernel audit trail.
///
/// Uses dedicated high scratch slots so it never perturbs the live ecosystem,
/// and removes them afterwards. Runs entirely under one scheduler lock.
pub fn security_demo() {
    use crate::process::{Capability, CapTable, Resource, Task, TaskId};
    use crate::process::audit::{record, AuditKind, KERNEL_ACTOR};

    const A: usize = 120; // root holder
    const B: usize = 121; // first-level grantee
    const C: usize = 122; // second-level grantee (derived from B)

    crate::println!("[security-demo] capability revocation-propagation demo:");

    {
        let mut sched = SCHEDULER.lock();

        // Scratch holders. They never run; they only carry capability tables.
        let mut a_caps = CapTable::new();
        let _ = a_caps.insert(Capability {
            resource: Resource::Serial,
            read: true,
            write: true,
            grant: true,
            sealed: false,
            id: 0,
            origin: None, // root
        });
        sched.tasks[A] = Some(Task::new(TaskId(A), scratch_entry, a_caps));
        sched.tasks[B] = Some(Task::new(TaskId(B), scratch_entry, CapTable::new()));
        sched.tasks[C] = Some(Task::new(TaskId(C), scratch_entry, CapTable::new()));

        // Grant A.slot0 to B (derived, origin = A's cap id).
        let from_a = sched.get_task(TaskId(A)).unwrap().cap_table.get(0).copied().unwrap();
        let mut to_b = from_a;
        to_b.sealed = false;
        to_b.origin = Some(from_a.id);
        let b_slot = sched.get_task_mut(TaskId(B)).unwrap().cap_table.insert(to_b).unwrap();
        // Read back B's installed cap id (assigned by insert) to chain C off it.
        let b_id = sched.get_task(TaskId(B)).unwrap().cap_table.get(b_slot).unwrap().id;
        record(AuditKind::Grant, TaskId(A), TaskId(B), to_b.resource, b_slot);

        // Grant B.slot to C (derived, origin = B's cap id).
        let mut to_c = to_b;
        to_c.origin = Some(b_id);
        let c_slot = sched.get_task_mut(TaskId(C)).unwrap().cap_table.insert(to_c).unwrap();
        record(AuditKind::Grant, TaskId(B), TaskId(C), to_c.resource, c_slot);

        crate::println!(
            "  built chain: A(slot0) to B(slot{}) to C(slot{}).",
            b_slot, c_slot
        );

        // Revoke the root at A.slot0 and propagate by capability id.
        let revoked = sched.get_task_mut(TaskId(A)).unwrap().cap_table.kernel_revoke(0);
        if let Some(cap) = revoked {
            record(AuditKind::Revoke, KERNEL_ACTOR, TaskId(A), cap.resource, 0);
            propagate_revocation(&mut sched, cap.id);
        }

        // Verify the cascade: B and C must no longer hold the capability.
        let b_has = sched.get_task(TaskId(B)).unwrap().cap_table.get(b_slot).is_some();
        let c_has = sched.get_task(TaskId(C)).unwrap().cap_table.get(c_slot).is_some();
        if !b_has && !c_has {
            crate::println!("  PASS: revoking A propagated to B and C (both lost the cap).");
        } else {
            crate::println!(
                "  FAIL: propagation incomplete (B holds={}, C holds={}).",
                b_has, c_has
            );
        }

        // Remove scratch holders so they never get scheduled.
        sched.tasks[A] = None;
        sched.tasks[B] = None;
        sched.tasks[C] = None;
    }

    crate::process::audit::dump();
}

/// Entry for scratch capability-holder tasks that must never actually run.
extern "C" fn scratch_entry() -> ! {
    crate::scheduler::terminate_current_task();
}

/// Returns true if the currently running task holds a capability targeting
/// `target_task` with `grant = true`.
fn current_has_grant_cap_to(target_task: usize) -> bool {
    let sched = SCHEDULER.lock();
    if let Some(id) = sched.current_task_id {
        if let Some(task) = sched.get_task(id) {
            for slot in task.cap_table.slots.iter() {
                if let Some(cap) = slot {
                    if cap.grant {
                        match cap.resource {
                            Resource::IpcChannel { target_task: target_id } => {
                                if target_id.0 == target_task {
                                    return true;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    false
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Returns true if the currently running task holds a `Resource::Serial`
/// capability at `cap_idx`.
fn current_has_serial_cap(cap_idx: usize) -> bool {
    let sched = SCHEDULER.lock();
    if let Some(id) = sched.current_task_id {
        if let Some(task) = sched.get_task(id) {
            if let Some(cap) = task.cap_table.get(cap_idx) {
                return cap.resource == Resource::Serial;
            }
        }
    }
    false
}

/// Capability-gated kernel action: write to the serial console only if the
/// caller holds a `Resource::Serial` capability at `cap_idx`.
/// Used by kernel-mode tasks (ring 0).
pub fn sys_serial_write(cap_idx: usize, message: &str) -> Result<(), ()> {
    let current_task_id = {
        let sched = SCHEDULER.lock();
        sched.current_task_id.ok_or(())?
    };

    let has_access = {
        let sched = SCHEDULER.lock();
        if let Some(task) = sched.get_task(current_task_id) {
            if let Some(cap) = task.cap_table.get(cap_idx) {
                cap.resource == Resource::Serial
            } else {
                false
            }
        } else {
            false
        }
    };

    if has_access {
        crate::print!("{}", message);
        Ok(())
    } else {
        Err(())
    }
}

/// Capability-gated kernel action: revoke a capability slot in `target_task`'s
/// table. Allowed only if the caller holds a capability to `target_task` with
/// the `grant` right.
/// Used by kernel-mode tasks (ring 0).
pub fn sys_cap_revoke(target_task: usize, cap_idx: usize) -> Result<(), ()> {
    let caller_task = {
        let sched = SCHEDULER.lock();
        sched.current_task_id.ok_or(())?.0
    };
    if dispatch_cap_revoke(caller_task, target_task, cap_idx) == 0 {
        Ok(())
    } else {
        Err(())
    }
}

// ── Spawn Task Implementation ────────────────────────────────────────────────

/// Handles the SYS_SPAWN_TASK syscall.
/// Only Task 1 (init) is allowed to call this.
/// Spawns the task type, inserts its IPC capability into init's table, and returns the TaskId.
fn dispatch_spawn_task(blob_type: usize) -> u64 {
    let mut sched = SCHEDULER.lock();

    // Find a free task slot starting from index 2
    let mut next_id = None;
    for i in 2..crate::process::MAX_TASKS {
        if sched.tasks[i].is_none() {
            next_id = Some(crate::process::TaskId(i));
            break;
        }
    }

    let id = match next_id {
        Some(id) => id,
        None => {
            crate::println!("[kernel] SYS_SPAWN_TASK: no free task slots left");
            return u64::MAX;
        }
    };

    let new_task = match blob_type {
        1 => crate::userspace::spawn_logger_task(id, crate::process::CapTable::new()),
        2 => crate::userspace::spawn_demo_user_task(id, crate::process::CapTable::new()),
        3 => crate::userspace::spawn_ramfs_task(id, crate::process::CapTable::new()),
        _ => {
            crate::println!("[kernel] SYS_SPAWN_TASK: unknown blob type {}", blob_type);
            return u64::MAX;
        }
    };

    crate::dbg_println!("[debug] new_task: rsp={:#x}, kstack={:#x}, cr3={:#x}", new_task.rsp, new_task.kstack_top, new_task.cr3);

    sched.tasks[id.0] = Some(new_task);

    // Insert an IpcChannel targeting this new task into init's capability table
    let cap = crate::process::Capability {
        resource: crate::process::Resource::IpcChannel { target_task: id },
        read: true,
        write: true,
        grant: true,
        sealed: false,
        id: 0,
        origin: None, // root IpcChannel minted by the kernel for init
    };

    let init_id = crate::process::TaskId(1);
    if let Some(init_task) = sched.get_task_mut(init_id) {
        crate::dbg_println!("[debug] init_task: rsp={:#x}, kstack={:#x}, cr3={:#x}", init_task.rsp, init_task.kstack_top, init_task.cr3);
        match init_task.cap_table.insert(cap) {
            Ok(slot) => {
                crate::println!(
                    "[kernel] spawned task {} (type {}) at slot {} in init's table",
                    id.0, blob_type, slot
                );
                id.0 as u64
            }
            Err(()) => {
                crate::println!("[kernel] SYS_SPAWN_TASK: init's capability table is full");
                // Rollback task creation
                sched.tasks[id.0] = None;
                u64::MAX
            }
        }
    } else {
        sched.tasks[id.0] = None;
        u64::MAX
    }
}

