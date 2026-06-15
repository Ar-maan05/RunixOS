// RunixOS microkernel scheduler
use crate::process::{Task, TaskId, TaskState, switch_context};
use crate::drivers::serial::Spinlock;

/// The central scheduler tracking tasks and the currently running task.
pub struct Scheduler {
    pub tasks: [Option<Task>; crate::process::MAX_TASKS],
    pub current_task_id: Option<TaskId>,
}

impl Scheduler {
    /// Safe helper to query a reference to a task by ID.
    pub fn get_task(&self, id: TaskId) -> Option<&Task> {
        let idx = id.0;
        if idx < self.tasks.len() {
            if let Some(ref t) = self.tasks[idx] {
                if t.id == id {
                    return Some(t);
                }
            }
        }
        None
    }

    /// Safe helper to query a mutable reference to a task by ID.
    pub fn get_task_mut(&mut self, id: TaskId) -> Option<&mut Task> {
        let idx = id.0;
        if idx < self.tasks.len() {
            if let Some(ref mut t) = self.tasks[idx] {
                if t.id == id {
                    return Some(t);
                }
            }
        }
        None
    }
}

/// Global scheduler protected by a spinlock.
pub static SCHEDULER: Spinlock<Scheduler> = Spinlock::new(Scheduler {
    tasks: [const { None }; crate::process::MAX_TASKS],
    current_task_id: None,
});

/// Returns the ID of the currently running task, if any.
pub fn current_task_id() -> Option<TaskId> {
    SCHEDULER.lock().current_task_id
}

/// Terminates the currently running task and switches to the next ready task.
///
/// Two callers:
///   - the fault handler, to *contain* a buggy task (its context is abandoned
///     and the kernel proceeds with the remaining tasks); and
///   - a kernel task that has finished its work and wants to exit cleanly.
///
/// Either way the dying task's stack is never resumed, any task blocked sending
/// to it is woken (and will observe `TargetGone`), and control passes to the
/// next ready task. Never returns to the caller.
pub fn terminate_current_task() -> ! {
    let mut new_rsp_val: usize = 0;
    let mut new_kstack_top: usize = 0;
    let mut new_cr3: usize = 0;

    unsafe {
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }

    {
        let mut sched = SCHEDULER.lock();
        let max_tasks = crate::process::MAX_TASKS;

        // Mark the current task terminated.
        let curr_idx = sched.current_task_id.map(|curr_id| curr_id.0);
        if let Some(idx) = curr_idx {
            if idx < max_tasks {
                if let Some(t) = sched.tasks[idx].as_mut() {
                    t.state = TaskState::Terminated;
                }
            }
        }

        // Failure containment: wake any task blocked sending to the dying task.
        // On resume each sees the target Terminated and gets `TargetGone`
        // instead of blocking forever on a channel that can never complete.
        if let Some(dead) = sched.current_task_id {
            for slot in sched.tasks.iter_mut() {
                if let Some(t) = slot.as_mut() {
                    if t.state == TaskState::BlockedOnSend(dead) {
                        t.state = TaskState::Ready;
                    }
                }
            }
        }

        // Pick the next ready task (round-robin from after the current one).
        let start = curr_idx.map(|i| (i + 1) % max_tasks).unwrap_or(0);
        for offset in 0..max_tasks {
            let idx = (start + offset) % max_tasks;
            if let Some(t) = sched.tasks[idx].as_mut() {
                if t.state == TaskState::Ready {
                    t.state = TaskState::Running;
                    new_rsp_val = t.rsp;
                    new_kstack_top = t.kstack_top;
                    new_cr3 = t.cr3;
                    sched.current_task_id = Some(t.id);
                    break;
                }
            }
        }
    }

    if new_rsp_val != 0 {
        if new_kstack_top != 0 {
            crate::arch::gdt::set_kernel_stack(new_kstack_top as u64);
        }
        if new_cr3 != 0 {
            crate::memory::switch_address_space(new_cr3);
        }
        // Discard the dying task's context: save area is a throwaway local.
        let mut dummy: usize = 0;
        unsafe {
            // SAFETY: `new_rsp_val` is a ready task's saved stack pointer built
            // by `Task::new` (or previously saved by `switch_context`). We never
            // return to `dummy`, so abandoning it is sound.
            switch_context(&mut dummy as *mut usize, new_rsp_val as *const usize);
        }
    }

    // No other task to run: nothing left to schedule, halt.
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

/// Involuntary reschedule, driven by the timer ISR (Phase 11).
///
/// Mirrors the *selection* half of [`yield_cpu`], but with two differences that
/// make it safe to run from interrupt context on a single core:
///
///   1. It acquires the scheduler lock with `try_lock`. If the interrupted task
///      was already holding it (mid-IPC, mid-spawn, …), we must not spin -- that
///      would deadlock the core. We defer the preemption to a later tick.
///   2. The current task is left `Ready` (it was `Running` and is merely being
///      time-sliced out), never blocked.
///
/// The switch itself reuses the cooperative `switch_context`, so the preempted
/// task's resume frame is identical to a voluntarily-yielded one.
pub fn preempt_reschedule() {
    let mut old_rsp_ptr: *mut usize = core::ptr::null_mut();
    let mut new_rsp_val: usize = 0;
    let mut new_kstack_top: usize = 0;
    let mut new_cr3: usize = 0;

    {
        let mut sched = match SCHEDULER.try_lock() {
            Some(g) => g,
            None => {
                // Interrupted code holds the scheduler lock: defer, don't deadlock.
                crate::preempt::note_deferred_locked();
                return;
            }
        };
        let max_tasks = crate::process::MAX_TASKS;

        let curr_idx = match sched.current_task_id {
            Some(id) if id.0 < max_tasks && sched.tasks[id.0].is_some() => id.0,
            _ => return,
        };

        let start = (curr_idx + 1) % max_tasks;
        let mut next_idx = None;
        for offset in 0..max_tasks {
            let idx = (start + offset) % max_tasks;
            if let Some(ref t) = sched.tasks[idx] {
                if t.state == TaskState::Ready {
                    next_idx = Some(idx);
                    break;
                }
            }
        }

        let next = match next_idx {
            Some(n) if n != curr_idx => n,
            _ => return, // nothing else ready: keep running the current task
        };

        if sched.tasks[curr_idx].as_ref().unwrap().state == TaskState::Running {
            sched.tasks[curr_idx].as_mut().unwrap().state = TaskState::Ready;
        }
        sched.tasks[next].as_mut().unwrap().state = TaskState::Running;

        old_rsp_ptr = &mut sched.tasks[curr_idx].as_mut().unwrap().rsp as *mut usize;
        new_rsp_val = sched.tasks[next].as_ref().unwrap().rsp;
        new_kstack_top = sched.tasks[next].as_ref().unwrap().kstack_top;
        new_cr3 = sched.tasks[next].as_ref().unwrap().cr3;
        sched.current_task_id = Some(sched.tasks[next].as_ref().unwrap().id);
    }

    if !old_rsp_ptr.is_null() && new_rsp_val != 0 {
        if new_kstack_top != 0 {
            crate::arch::gdt::set_kernel_stack(new_kstack_top as u64);
        }
        if new_cr3 != 0 {
            crate::memory::switch_address_space(new_cr3);
        }
        crate::preempt::note_preemption();
        unsafe {
            switch_context(old_rsp_ptr, new_rsp_val as *const usize);
        }
    }
}

/// Yields the CPU to the next scheduled task.
/// Implements cooperative context switching.
pub fn yield_cpu() {
    // Disable interrupts and save previous state
    let interrupts_enabled = unsafe {
        let rflags: usize;
        core::arch::asm!("pushfq; pop {}", out(reg) rflags);
        core::arch::asm!("cli");
        (rflags & 0x200) != 0
    };

    let mut current_idx = None;
    let mut next_idx = None;

    let mut old_rsp_ptr: *mut usize = core::ptr::null_mut();
    let mut new_rsp_val: usize = 0;
    let mut new_kstack_top: usize = 0;
    let mut new_cr3: usize = 0;

    {
        let mut sched = SCHEDULER.lock();
        let max_tasks = crate::process::MAX_TASKS;

        // Find the index of the currently executing task
        if let Some(curr_id) = sched.current_task_id {
            let idx = curr_id.0;
            if idx < max_tasks && sched.tasks[idx].is_some() {
                current_idx = Some(idx);
            }
        }

        // Perform cooperative round-robin search starting after current task
        if let Some(curr_idx) = current_idx {
            let start = (curr_idx + 1) % max_tasks;
            for offset in 0..max_tasks {
                let idx = (start + offset) % max_tasks;
                if let Some(ref t) = sched.tasks[idx] {
                    if t.state == TaskState::Ready {
                        next_idx = Some(idx);
                        break;
                    }
                }
            }
        } else {
            // No active task running yet, schedule the first ready task
            for i in 0..max_tasks {
                if let Some(ref t) = sched.tasks[i] {
                    if t.state == TaskState::Ready {
                        next_idx = Some(i);
                        break;
                    }
                }
            }
        }

        if let Some(next) = next_idx {
            if let Some(curr) = current_idx {
                if curr != next {
                    // Update state of currently active task (if it wasn't blocked/terminated)
                    if sched.tasks[curr].as_ref().unwrap().state == TaskState::Running {
                        sched.tasks[curr].as_mut().unwrap().state = TaskState::Ready;
                    }
                    // Start running the next task
                    sched.tasks[next].as_mut().unwrap().state = TaskState::Running;

                    old_rsp_ptr = &mut sched.tasks[curr].as_mut().unwrap().rsp as *mut usize;
                    new_rsp_val = sched.tasks[next].as_ref().unwrap().rsp;
                    new_kstack_top = sched.tasks[next].as_ref().unwrap().kstack_top;
                    new_cr3 = sched.tasks[next].as_ref().unwrap().cr3;
                    sched.current_task_id = Some(sched.tasks[next].as_ref().unwrap().id);
                }
            } else {
                // First-time scheduler boot: start running the target task
                sched.tasks[next].as_mut().unwrap().state = TaskState::Running;
                new_rsp_val = sched.tasks[next].as_ref().unwrap().rsp;
                new_kstack_top = sched.tasks[next].as_ref().unwrap().kstack_top;
                new_cr3 = sched.tasks[next].as_ref().unwrap().cr3;
                sched.current_task_id = Some(sched.tasks[next].as_ref().unwrap().id);

                // Use static dummy area to write the initial boot context's stack pointer
                static mut BOOT_RSP: usize = 0;
                old_rsp_ptr = unsafe { &raw mut BOOT_RSP as *mut usize };
            }
        }
    }

    // Perform context switch if we found a valid next task and stack pointer
    if !old_rsp_ptr.is_null() && new_rsp_val != 0 {
        // Point the TSS at the incoming task's kernel stack so its next ring-3
        // -> ring-0 transition lands on the right stack.
        if new_kstack_top != 0 {
            crate::arch::gdt::set_kernel_stack(new_kstack_top as u64);
        }
        // Activate the incoming task's address space (no-op if unchanged).
        if new_cr3 != 0 {
            crate::memory::switch_address_space(new_cr3);
        }
        unsafe {
            switch_context(old_rsp_ptr, new_rsp_val as *const usize);
        }
    }

    // Restore interrupts if they were enabled
    if interrupts_enabled {
        unsafe {
            core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
        }
    }
}
