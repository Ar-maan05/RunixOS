// RunixOS task and process subsystem — Phase 3
pub mod capability;
pub mod ipc;
pub mod audit;
pub mod snapshot;
pub mod dist;

pub use capability::{Capability, CapTable, Resource, RightsMask};
pub use ipc::{IpcError, IpcTag, Message, MessageQueue, sys_send, sys_receive,
              sys_send_typed, sys_receive_typed, sys_send_async, sys_receive_async};

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
    pub msg_queue: MessageQueue,
    pub fault_registers: Option<crate::interrupts::ExceptionFrame>,
}

pub const MAX_TASKS: usize = 132;
pub const STACK_SIZE: usize = 32768; // 32 KiB stack

/// A single task's kernel stack, forced to 16-byte alignment.
///
/// A bare `[u8; N]` has alignment 1, so `&TASK_STACKS[idx]` (and thus every
/// task's initial `rsp`) could land on any byte boundary depending on where the
/// linker places the static. The x86_64 SysV ABI requires 16-byte stack
/// alignment, and stack pushes must be 8-aligned; an unaligned stack base is
/// undefined behavior (and trips debug's misaligned-pointer check). Aligning the
/// element type pins every stack — and every derived `rsp` — to a 16-byte
/// boundary regardless of the static's placement.
#[repr(C, align(16))]
pub struct TaskStack(pub [u8; STACK_SIZE]);

// Statically allocate task stacks to avoid heap requirements in Phase 1
#[no_mangle]
pub static mut TASK_STACKS: [TaskStack; MAX_TASKS] =
    [const { TaskStack([0; STACK_SIZE]) }; MAX_TASKS];

extern "C" {
    /// Assembly stub to switch execution context between two tasks.
    pub fn switch_context(old_rsp: *mut usize, new_rsp: *const usize);
}

// Global assembly for the cooperative context switch
core::arch::global_asm!(
    ".global switch_context",
    "switch_context:",
    "    pushfq",
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
    "    popfq",
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

// Trampoline a *fresh* kernel task is resumed through on its first schedule.
// `switch_context` reaches it via `ret` with `r15` preloaded to the task's real
// entry point (see `Task::new`). It enables interrupts before entering the body.
//
// Why this matters under Phase 11: a fresh task can be scheduled for the first
// time *from the timer ISR* (an involuntary preemption picks it). The ISR runs
// with IF=0, and the cooperative `switch_context` is a plain `ret` that does not
// touch RFLAGS — so without this `sti` the task would run with interrupts
// disabled, no further timer tick could ever fire, and the system would wedge.
// (Tasks resumed *after* being preempted restore IF via the ISR's `iretq`; only
// first-run tasks need this.) Ring-3 tasks use `iret_to_user` instead and manage
// IF through their iretq frame.
core::arch::global_asm!(
    ".global kernel_task_trampoline",
    "kernel_task_trampoline:",
    "    sti",
    "    jmp r15",
);

extern "C" {
    fn kernel_task_trampoline();
}

impl Task {
    /// Creates a new Task structure and sets up its stack for context switching.
    pub fn new(id: TaskId, entry: extern "C" fn() -> !, cap_table: CapTable) -> Self {
        let idx = id.0;
        assert!(idx < MAX_TASKS, "Task ID exceeds maximum supported tasks");

        let stack_top = unsafe { &TASK_STACKS[idx] as *const _ as usize + STACK_SIZE };
        let mut rsp = stack_top;

        // Build the frame `switch_context` consumes on this task's first run.
        // `switch_context` pops r15,r14,r13,r12,rbx,rbp, then popfq, then `ret`s. We arrange:
        //   - the `ret` target = `kernel_task_trampoline` (does `sti; jmp r15`)
        //   - r15 (popped first, so lowest address) = the real entry point
        // so the task starts with interrupts enabled and jumps to `entry`.
        rsp -= 8; // dummy slot above the ret target (unused; entry never returns)
        unsafe { *(rsp as *mut usize) = 0; }

        rsp -= 8; // ret target consumed after the 6 register pops + popfq
        unsafe { *(rsp as *mut usize) = kernel_task_trampoline as *const () as usize; }

        // Initial rflags (0x202 enables interrupts, SysV ABI default)
        rsp -= 8;
        unsafe { *(rsp as *mut usize) = 0x202; }

        // Saved callee regs, pushed high→low so the *first* popped (r15) is lowest:
        // rbp, rbx, r12, r13, r14, then r15 = entry.
        for _ in 0..5 {
            rsp -= 8;
            unsafe { *(rsp as *mut usize) = 0; }
        }
        rsp -= 8; // r15 (popped first) = entry point
        unsafe { *(rsp as *mut usize) = entry as usize; }

        Self {
            id,
            state: TaskState::Ready,
            rsp,
            kstack_top: stack_top,
            // Kernel tasks run in the boot address space.
            cr3: crate::memory::current_pml4_paddr(),
            cap_table,
            ipc_buffer: None,
            msg_queue: MessageQueue::new(),
            fault_registers: None,
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

        // Saved RFLAGS popped by `switch_context`'s `popfq`.
        push(0x202);

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
            msg_queue: MessageQueue::new(),
            fault_registers: None,
        }
    }
}
