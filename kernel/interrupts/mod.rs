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

/// Installs the IDT and points the CPU at it.
pub fn init_idt() {
    let cs = current_cs();

    set_handler(0, divide_error_handler as *const () as u64, cs);
    set_handler(6, invalid_opcode_handler as *const () as u64, cs);
    set_handler(8, double_fault_handler as *const () as u64, cs);
    set_handler(13, general_protection_handler as *const () as u64, cs);
    set_handler(14, page_fault_handler as *const () as u64, cs);

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

/// Shared logic: report a recoverable fault and either terminate the offending
/// task (and reschedule) or, if no task context exists, halt.
fn contain_fault(name: &str, rip: u64) -> ! {
    if let Some(id) = scheduler::current_task_id() {
        println!(
            "[FAULT] {} in task {} at rip={:#x} -> terminating task, kernel continues.",
            name, id.0, rip
        );
        scheduler::terminate_current_task();
    } else {
        println!("[FAULT] {} at rip={:#x} with no task context -> halting.", name, rip);
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

extern "x86-interrupt" fn divide_error_handler(frame: InterruptStackFrame) {
    contain_fault("divide error (#DE)", frame.instruction_pointer);
}

extern "x86-interrupt" fn invalid_opcode_handler(frame: InterruptStackFrame) {
    contain_fault("invalid opcode (#UD)", frame.instruction_pointer);
}

extern "x86-interrupt" fn general_protection_handler(frame: InterruptStackFrame, error_code: u64) {
    println!("[FAULT] #GP error_code={:#x}", error_code);
    contain_fault("general protection fault (#GP)", frame.instruction_pointer);
}

extern "x86-interrupt" fn page_fault_handler(frame: InterruptStackFrame, error_code: u64) {
    let cr2: u64;
    unsafe {
        // SAFETY: reading CR2 (faulting address) has no side effects.
        core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
    }
    println!("[FAULT] #PF faulting_addr={:#x} error_code={:#x}", cr2, error_code);
    contain_fault("page fault (#PF)", frame.instruction_pointer);
}

extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, _error_code: u64) -> ! {
    println!("[FATAL] double fault (#DF) at rip={:#x} -> halting.", frame.instruction_pointer);
    halt_forever();
}
