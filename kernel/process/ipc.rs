// RunixOS Rendezvous IPC System
use crate::process::{TaskId, TaskState};
use crate::process::capability::Resource;
use crate::scheduler::SCHEDULER;

/// Structure representing a message sent between tasks.
#[derive(Debug, Clone, Copy)]
pub struct Message {
    /// The task ID of the sender.
    pub sender: TaskId,
    /// Fixed-size message payload.
    pub payload: [u8; 128],
    /// Actual length of the sent payload.
    pub len: usize,
}

/// Sends a message to a target task using a capability.
/// This call blocks until the target receives the message (Rendezvous).
pub fn sys_send(cap_idx: usize, payload: &[u8]) -> Result<(), ()> {
    if payload.len() > 128 {
        return Err(());
    }

    let mut msg_payload = [0u8; 128];
    msg_payload[..payload.len()].copy_from_slice(payload);

    let current_task_id = {
        let sched = SCHEDULER.lock();
        sched.current_task_id.ok_or(())?
    };

    // Resolve target task ID from capability table
    let target_task_id = {
        let sched = SCHEDULER.lock();
        let current_task = sched.get_task(current_task_id).ok_or(())?;
        let cap = current_task.cap_table.get(cap_idx).ok_or(())?;
        match cap.resource {
            Resource::IpcChannel { target_task } => target_task,
            _ => return Err(()), // Access denied or invalid capability
        }
    };

    let msg = Message {
        sender: current_task_id,
        payload: msg_payload,
        len: payload.len(),
    };

    loop {
        let mut sched = SCHEDULER.lock();

        // 1. If target is already blocked on receive, deliver immediately (rendezvous met)
        if let Some(target_task) = sched.get_task_mut(target_task_id) {
            if target_task.state == TaskState::BlockedOnReceive {
                target_task.ipc_buffer = Some(msg);
                target_task.state = TaskState::Ready;
                return Ok(());
            }
        } else {
            return Err(());
        }

        // 2. Target is not ready, block current task on send
        if let Some(sender_task) = sched.get_task_mut(current_task_id) {
            sender_task.state = TaskState::BlockedOnSend(target_task_id);
            sender_task.ipc_buffer = Some(msg);
        }

        // Yield execution to allow other tasks to run
        drop(sched);
        crate::scheduler::yield_cpu();

        // 3. After rescheduling, check if the message was retrieved
        let sched_check = SCHEDULER.lock();
        if let Some(check_task) = sched_check.get_task(current_task_id) {
            if check_task.ipc_buffer.is_none() {
                // Buffer was cleared by receiver, send successful
                return Ok(());
            }
        } else {
            return Err(());
        }
    }
}

/// Receives an IPC message from any sending task.
/// Blocks if no sending task is currently ready.
pub fn sys_receive() -> Result<Message, ()> {
    let current_task_id = {
        let sched = SCHEDULER.lock();
        sched.current_task_id.ok_or(())?
    };

    loop {
        let mut sched = SCHEDULER.lock();

        // 1. Check if there are any senders waiting to send to us
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
            // Sender found! Pull message from sender's buffer and unblock it
            let mut msg = None;
            if let Some(sender_task) = sched.get_task_mut(sender_id) {
                msg = sender_task.ipc_buffer.take();
                sender_task.state = TaskState::Ready;
            }

            if let Some(receiver_task) = sched.get_task_mut(current_task_id) {
                receiver_task.state = TaskState::Running;
            }

            return msg.ok_or(());
        }

        // 2. No sender available, block receiver
        if let Some(receiver_task) = sched.get_task_mut(current_task_id) {
            receiver_task.state = TaskState::BlockedOnReceive;
        }

        // Yield execution
        drop(sched);
        crate::scheduler::yield_cpu();

        // 3. Resumed, check if message has been placed in our buffer
        let mut sched_check = SCHEDULER.lock();
        if let Some(receiver_task) = sched_check.get_task_mut(current_task_id) {
            if let Some(msg) = receiver_task.ipc_buffer.take() {
                return Ok(msg);
            }
        }
    }
}
