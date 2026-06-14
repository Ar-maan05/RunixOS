// RunixOS task and process subsystem
pub mod capability;
pub mod ipc;

pub use capability::{Capability, CapTable, Resource};
pub use ipc::{Message, sys_send, sys_receive};

/// Unique identifier for each process/task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskId(pub usize);

/// Enumeration of possible task states in the microkernel scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Ready to be scheduled.
    Ready,
    /// Currently running on the CPU.
    Running,
    /// Blocked waiting to receive an IPC message.
    BlockedOnReceive,
    /// Blocked waiting to deliver an IPC message to target task.
    BlockedOnSend(TaskId),
    /// Execution terminated.
    Terminated,
}

/// Representation of a kernel task.
pub struct Task {
    pub id: TaskId,
    pub state: TaskState,
    pub rsp: usize,
    /// Top of this task's kernel stack. Loaded into TSS.rsp0 when the task runs
    /// so that ring-3 -> ring-0 transitions (syscalls/faults) land on the
    /// task's own kernel stack.
    pub kstack_top: usize,
    /// Physical base of this task's PML4 (address space). Loaded into CR3 when
    /// the task is scheduled. Kernel tasks share the boot PML4; user tasks each
    /// have their own.
    pub cr3: usize,
    pub cap_table: CapTable,
    pub ipc_buffer: Option<Message>,
}

pub const MAX_TASKS: usize = 8;
pub const STACK_SIZE: usize = 8192; // 8 KiB stack

// Statically allocate task stacks to avoid heap requirements in Phase 1
#[no_mangle]
pub static mut TASK_STACKS: [[u8; STACK_SIZE]; MAX_TASKS] = [[0; STACK_SIZE]; MAX_TASKS];

extern "C" {
    /// Assembly stub to switch execution context between two tasks.
    pub fn switch_context(old_rsp: *mut usize, new_rsp: *const usize);
}

// Global assembly for the cooperative context switch
core::arch::global_asm!(
    ".global switch_context",
    "switch_context:",
    "    push rbp",
    "    push rbx",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    mov [rdi], rsp", // Save old RSP to *old_rsp
    "    mov rsp, rsi",   // Load new RSP
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbx",
    "    pop rbp",
    "    ret"
);

// Trampoline that drops to ring 3. `switch_context`'s final `ret` lands here
// with the stack pointing at a CPU interrupt frame (rip/cs/rflags/rsp/ss) that
// `Task::new_user` placed; `iretq` consumes it and enters user mode.
core::arch::global_asm!(
    ".global iret_to_user",
    "iret_to_user:",
    "    iretq",
);

extern "C" {
    fn iret_to_user();
}

impl Task {
    /// Creates a new Task structure and sets up its stack for context switching.
    pub fn new(id: TaskId, entry: extern "C" fn() -> !, cap_table: CapTable) -> Self {
        let idx = id.0;
        assert!(idx < MAX_TASKS, "Task ID exceeds maximum supported tasks");

        let stack_top = unsafe { &TASK_STACKS[idx] as *const _ as usize + STACK_SIZE };
        let mut rsp = stack_top;

        // Set up stack frames for cooperative switch resume
        rsp -= 8; // dummy return address
        unsafe {
            *(rsp as *mut usize) = 0;
        }

        rsp -= 8; // entry point of the task
        unsafe {
            *(rsp as *mut usize) = entry as usize;
        }

        // Space for registers: r15, r14, r13, r12, rbx, rbp
        for _ in 0..6 {
            rsp -= 8;
            unsafe {
                *(rsp as *mut usize) = 0;
            }
        }

        Self {
            id,
            state: TaskState::Ready,
            rsp,
            kstack_top: stack_top,
            // Kernel tasks run in the boot address space.
            cr3: crate::memory::current_pml4_paddr(),
            cap_table,
            ipc_buffer: None,
        }
    }

    /// Creates a ring-3 user task. `entry_vaddr` and `user_stack_top` are
    /// addresses in the task's user-accessible address space. The kernel stack
    /// (`TASK_STACKS[idx]`) is primed with a CPU interrupt frame so that the
    /// first context switch into this task drops to user mode via `iret_to_user`.
    pub fn new_user(
        id: TaskId,
        entry_vaddr: usize,
        user_stack_top: usize,
        cr3: usize,
        cap_table: CapTable,
    ) -> Self {
        use crate::arch::gdt::{USER_CODE, USER_DATA};

        let idx = id.0;
        assert!(idx < MAX_TASKS, "Task ID exceeds maximum supported tasks");

        let kstack_top = unsafe { &TASK_STACKS[idx] as *const _ as usize + STACK_SIZE };
        let mut rsp = kstack_top;

        // Push the iretq frame consumed by `iret_to_user` (top-down: ss, rsp,
        // rflags, cs, rip).
        let mut push = |val: usize| unsafe {
            rsp -= 8;
            *(rsp as *mut usize) = val;
        };
        push(USER_DATA as usize); // ss
        push(user_stack_top); // rsp
        push(0x002); // rflags: reserved bit set, IF cleared (cooperative)
        push(USER_CODE as usize); // cs
        push(entry_vaddr); // rip

        // `switch_context`'s `ret` target: the iretq trampoline.
        push(iret_to_user as *const () as usize);

        // Saved callee-saved registers popped by `switch_context` (r15..rbp).
        for _ in 0..6 {
            push(0);
        }

        Self {
            id,
            state: TaskState::Ready,
            rsp,
            kstack_top,
            cr3,
            cap_table,
            ipc_buffer: None,
        }
    }
}
