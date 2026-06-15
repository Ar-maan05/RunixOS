// RunixOS interrupt & CPU-exception management.
//
// Phase 1 fault isolation: we install an IDT with handlers for the CPU
// exception vectors. Recoverable faults raised by a task (page fault, general
// protection fault, invalid opcode, divide error) terminate *that task* and
// reschedule, so a buggy task cannot bring down the kernel. Unrecoverable
// conditions (double fault) halt the machine with diagnostics.

use crate::println;
use crate::scheduler;

/// The CPU state pushed by the processor when an exception/interrupt is taken.
/// Layout matches the hardware interrupt stack frame for x86_64.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InterruptStackFrame {
    pub instruction_pointer: u64,
    pub code_segment: u64,
    pub cpu_flags: u64,
    pub stack_pointer: u64,
    pub stack_segment: u64,
}

/// A single 16-byte x86_64 IDT gate descriptor.
#[repr(C)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    zero: u32,
}

impl IdtEntry {
    const fn empty() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            zero: 0,
        }
    }

    /// Builds a present 64-bit interrupt gate at the given privilege level.
    /// `dpl` 0 = kernel-only; `dpl` 3 lets ring-3 code invoke the gate (used by
    /// the `int 0x80` syscall trap).
    fn new(handler_addr: u64, selector: u16, dpl: u8) -> Self {
        Self {
            offset_low: (handler_addr & 0xffff) as u16,
            selector,
            ist: 0,
            // P=1, DPL=dpl, type=0xE (64-bit interrupt gate)
            type_attr: 0x8e | ((dpl & 0x3) << 5),
            offset_mid: ((handler_addr >> 16) & 0xffff) as u16,
            offset_high: ((handler_addr >> 32) & 0xffff_ffff) as u32,
            zero: 0,
        }
    }
}

/// Pointer used by the `lidt` instruction.
#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

const IDT_ENTRIES: usize = 256;
static mut IDT: [IdtEntry; IDT_ENTRIES] = [IdtEntry::empty(); IDT_ENTRIES];

/// Reads the current code-segment selector so IDT gates use the segment Limine
/// established for the kernel.
fn current_cs() -> u16 {
    let cs: u16;
    unsafe {
        // SAFETY: reading the CS selector register has no side effects.
        core::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
    }
    cs
}

fn set_handler(vector: usize, handler_addr: u64, selector: u16) {
    set_handler_dpl(vector, handler_addr, selector, 0);
}

fn set_handler_dpl(vector: usize, handler_addr: u64, selector: u16, dpl: u8) {
    unsafe {
        // SAFETY: `vector` is bounded by callers to < IDT_ENTRIES; we hold the
        // only reference to the IDT during single-threaded init.
        let idt = &raw mut IDT;
        (*idt)[vector] = IdtEntry::new(handler_addr, selector, dpl);
    }
}

/// The full register frame saved by the exception assembly stubs.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionFrame {
    // General-purpose registers (pushed by exception_common)
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
    // Pushed by entry stubs
    pub vector: u64,
    pub error_code: u64,
    // Pushed by CPU hardware on interrupt/exception
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

// ── Exception Entry Stubs ───────────────────────────────────────────────────

core::arch::global_asm!(
    ".global divide_error_entry",
    "divide_error_entry:",
    "    push 0",                  // dummy error code
    "    push 0",                  // vector 0
    "    jmp exception_common",

    ".global invalid_opcode_entry",
    "invalid_opcode_entry:",
    "    push 0",                  // dummy error code
    "    push 6",                  // vector 6
    "    jmp exception_common",

    ".global general_protection_entry",
    "general_protection_entry:",
    "    // error code already pushed by CPU",
    "    push 13",                 // vector 13
    "    jmp exception_common",

    ".global page_fault_entry",
    "page_fault_entry:",
    "    // error code already pushed by CPU",
    "    push 14",                 // vector 14
    "    jmp exception_common",

    "exception_common:",
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
    "    mov rdi, rsp",            // &ExceptionFrame
    "    mov rsi, [rsp + 15*8]",   // vector number
    "    call exception_dispatch",
    "    // In case the handler returns (e.g. for non-terminating faults):",
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
    "    add rsp, 16",             // clean vector and error code
    "    iretq",
);

extern "C" {
    pub fn divide_error_entry();
    pub fn invalid_opcode_entry();
    pub fn general_protection_entry();
    pub fn page_fault_entry();
}

// ── Phase 11: timer interrupt (preemptive scheduling) ───────────────────────
//
// The timer ISR must save the *full* general-purpose register file, not just
// the callee-saved set the cooperative switch handles. A timer fires at an
// arbitrary instruction, so the interrupted task never reached a call boundary
// where the System V ABI would have spilled its caller-saved registers; if we
// clobber them the task resumes corrupted. So the stub below pushes all 15 GP
// registers, then calls into Rust. The actual task switch (when the policy in
// `timer_isr` decides to preempt) reuses the *cooperative* `switch_context`: it
// saves this stack's rsp into the task and loads the next task's. Because both
// voluntary yields and timer preemptions leave a `switch_context` frame on top
// of a suspended task's stack, the two paths unify — a preempted task is
// resumed exactly like one that yielded, and on its way back out this stub
// restores the full register file and `iretq`s to the interrupted instruction.

core::arch::global_asm!(
    ".global timer_interrupt_entry",
    "timer_interrupt_entry:",
    "    push rax",
    "    push rcx",
    "    push rdx",
    "    push rsi",
    "    push rdi",
    "    push r8",
    "    push r9",
    "    push r10",
    "    push r11",
    "    push rbx",
    "    push rbp",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    call timer_isr",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbp",
    "    pop rbx",
    "    pop r11",
    "    pop r10",
    "    pop r9",
    "    pop r8",
    "    pop rdi",
    "    pop rsi",
    "    pop rdx",
    "    pop rcx",
    "    pop rax",
    "    iretq",
);

extern "C" {
    fn timer_interrupt_entry();
}

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;
const PIC_EOI: u8 = 0x20;

/// Timer interrupt is delivered on PIC vector base + IRQ0.
pub const TIMER_VECTOR: usize = 0x20;

unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}

/// Remaps the legacy 8259 PIC pair so hardware IRQs land on vectors 0x20-0x2F
/// (out of the way of the CPU exception vectors), then masks every line except
/// IRQ0 (the PIT). Without the remap, IRQ0 would alias vector 8 (#DF).
pub fn init_pic() {
    unsafe {
        // ICW1: begin init, expect ICW4.
        outb(PIC1_CMD, 0x11);
        outb(PIC2_CMD, 0x11);
        // ICW2: vector offsets.
        outb(PIC1_DATA, 0x20);
        outb(PIC2_DATA, 0x28);
        // ICW3: master/slave wiring (slave on IRQ2).
        outb(PIC1_DATA, 0x04);
        outb(PIC2_DATA, 0x02);
        // ICW4: 8086 mode.
        outb(PIC1_DATA, 0x01);
        outb(PIC2_DATA, 0x01);
        // Masks: unmask only IRQ0 on the master; mask everything else.
        outb(PIC1_DATA, 0xFE);
        outb(PIC2_DATA, 0xFF);
    }
}

/// Programs PIT channel 0 to fire IRQ0 at `hz` Hz in square-wave mode.
pub fn init_pit(hz: u32) {
    let divisor: u32 = 1_193_182 / hz;
    let div = divisor as u16;
    unsafe {
        // Channel 0, lobyte/hibyte, mode 3 (square wave).
        outb(0x43, 0x36);
        outb(0x40, (div & 0xFF) as u8);
        outb(0x40, (div >> 8) as u8);
    }
}

/// Signals end-of-interrupt to the master PIC (IRQ0 lives on the master).
#[inline]
pub fn pic_eoi() {
    unsafe { outb(PIC1_CMD, PIC_EOI); }
}

/// The Rust half of the timer interrupt, called by `timer_interrupt_entry` with
/// the full register file already on the stack. Acks the PIC, then asks the
/// preemption policy whether to switch; if so, performs an involuntary
/// reschedule via the cooperative switch machinery.
#[no_mangle]
pub extern "C" fn timer_isr() {
    // Ack immediately so the next tick can be delivered after we `iretq`.
    pic_eoi();

    if crate::preempt::on_tick_should_switch() {
        // `preempt_reschedule` uses `try_lock`; if the interrupted code holds
        // the scheduler lock it returns without switching (deferred), avoiding
        // the single-core deadlock that a blocking lock would cause here.
        crate::scheduler::preempt_reschedule();
    }
}

/// Installs the IDT and points the CPU at it.
pub fn init_idt() {
    let cs = current_cs();

    set_handler(0, divide_error_entry as *const () as u64, cs);
    set_handler(6, invalid_opcode_entry as *const () as u64, cs);
    set_handler(8, double_fault_handler as *const () as u64, cs);
    set_handler(13, general_protection_entry as *const () as u64, cs);
    set_handler(14, page_fault_entry as *const () as u64, cs);

    // Phase 11: timer interrupt (IRQ0 -> vector 0x20) for preemptive scheduling.
    set_handler(TIMER_VECTOR, timer_interrupt_entry as *const () as u64, cs);

    // Syscall trap: reachable from ring 3 (DPL=3).
    set_handler_dpl(0x80, crate::syscall::syscall_entry as *const () as u64, cs, 3);

    let ptr = IdtPointer {
        limit: (core::mem::size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
        base: (&raw const IDT) as u64,
    };

    unsafe {
        // SAFETY: `ptr` describes a valid, fully-initialized IDT that lives for
        // the rest of the kernel's lifetime ('static).
        core::arch::asm!("lidt [{}]", in(reg) &ptr, options(readonly, nostack, preserves_flags));
    }

    println!("IDT installed: CPU exceptions are now caught.");
}

/// Shared logic: log a fault with full register diagnostics, save context,
/// and terminate only the offending task (or halt if no task context).
#[no_mangle]
pub extern "C" fn exception_dispatch(frame: &ExceptionFrame, vector: u64) -> ! {
    let name = match vector {
        0  => "divide error (#DE)",
        6  => "invalid opcode (#UD)",
        13 => "general protection fault (#GP)",
        14 => "page fault (#PF)",
        _  => "unknown CPU exception",
    };

    let cr2 = if vector == 14 {
        let val: u64;
        unsafe {
            // SAFETY: reading CR2 (faulting address) has no side effects.
            core::arch::asm!("mov {}, cr2", out(reg) val, options(nomem, nostack, preserves_flags));
        }
        Some(val)
    } else {
        None
    };

    if let Some(id) = scheduler::current_task_id() {
        // Save the full register context into the task structure
        {
            let mut sched = scheduler::SCHEDULER.lock();
            if let Some(task) = sched.get_task_mut(id) {
                task.fault_registers = Some(*frame);
            }
        }

        println!(
            "[FAULT] {} in task {} at rip={:#x} -> terminating task, kernel continues.",
            name, id.0, frame.rip
        );
        if let Some(addr) = cr2 {
            println!("  Faulting address: {:#x}", addr);
        }
        println!("  Error code: {:#x}", frame.error_code);
        println!("  Registers:");
        println!(
            "    RAX={:#018x} RBX={:#018x} RCX={:#018x} RDX={:#018x}",
            frame.rax, frame.rbx, frame.rcx, frame.rdx
        );
        println!(
            "    RSI={:#018x} RDI={:#018x} RBP={:#018x} RSP={:#018x}",
            frame.rsi, frame.rdi, frame.rbp, frame.rsp
        );
        println!(
            "    R8 ={:#018x} R9 ={:#018x} R10={:#018x} R11={:#018x}",
            frame.r8, frame.r9, frame.r10, frame.r11
        );
        println!(
            "    R12={:#018x} R13={:#018x} R14={:#018x} R15={:#018x}",
            frame.r12, frame.r13, frame.r14, frame.r15
        );
        println!(
            "    CS ={:#06x} SS ={:#06x} RFLAGS={:#018x}",
            frame.cs, frame.ss, frame.rflags
        );

        scheduler::terminate_current_task();
    } else {
        println!(
            "[FAULT] {} at rip={:#x} with no task context -> halting.",
            name, frame.rip
        );
        if let Some(addr) = cr2 {
            println!("  Faulting address: {:#x}", addr);
        }
        halt_forever();
    }
}

fn halt_forever() -> ! {
    loop {
        unsafe {
            // SAFETY: halting is always sound.
            core::arch::asm!("hlt");
        }
    }
}

extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, _error_code: u64) -> ! {
    println!("[FATAL] double fault (#DF) at rip={:#x} -> halting.", frame.instruction_pointer);
    halt_forever();
}

