#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

use core::panic::PanicInfo;
use limine::request::FramebufferRequest;
use limine::{BaseRevision, RequestsEndMarker, RequestsStartMarker};

// Declare the module tree with explicit paths matching the repo design
#[path = "../arch/x86_64/mod.rs"]
pub mod arch;
#[path = "../memory/mod.rs"]
pub mod memory;
#[path = "../interrupts/mod.rs"]
pub mod interrupts;
#[path = "../process/mod.rs"]
pub mod process;
#[path = "../scheduler/mod.rs"]
pub mod scheduler;
#[path = "../syscall/mod.rs"]
pub mod syscall;
#[path = "../fs/mod.rs"]
pub mod fs;
#[path = "../drivers/mod.rs"]
pub mod drivers;
#[path = "../userspace/mod.rs"]
pub mod userspace;

// Inform the Limine bootloader about the protocol revision we support
// NOTE: `BaseRevision::new()` requests the crate's MAX_SUPPORTED revision (6),
// which the bundled Limine 7.13.3 bootloader does not acknowledge, leaving
// `is_supported()` false and silently halting the kernel. Pin to revision 2,
// the highest the bundled bootloader supports.
#[used]
#[unsafe(link_section = ".requests")]
pub static BASE_REVISION: BaseRevision = BaseRevision::with_revision(2);

#[used]
#[unsafe(link_section = ".requests_start_marker")]
pub static _START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

// Framebuffer request (required to initialize display, used in later milestones)
#[used]
#[unsafe(link_section = ".requests")]
pub static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
#[unsafe(link_section = ".requests_end_marker")]
pub static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

/// The entry point of the RunixOS kernel.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Force the compiler and linker to keep the Limine requests by performing volatile reads.
    unsafe {
        core::ptr::read_volatile(&BASE_REVISION);
        core::ptr::read_volatile(&_START_MARKER);
        core::ptr::read_volatile(&FRAMEBUFFER_REQUEST);
        core::ptr::read_volatile(&_END_MARKER);
        core::ptr::read_volatile(&memory::MEMMAP_REQUEST);
        core::ptr::read_volatile(&memory::HHDM_REQUEST);
    }

    // Initialize serial console
    drivers::serial::SERIAL1.lock().init();

    // Print the rebranding initialization message
    println!("RunixOS kernel initialized.");

    // Check if the bootloader supports the base revision
    if !BASE_REVISION.is_supported() {
        loop {
            unsafe {
                // SAFETY:
                // - Why necessary: Halt instruction puts CPU in low power sleep.
                // - Invariants: None.
                // - Soundness: Safe to halt when we cannot boot further.
                core::arch::asm!("hlt");
            }
        }
    }

    // Initialize Memory Manager (Physical frame allocator)
    unsafe {
        memory::FRAME_ALLOCATOR.init();
    }

    // Install our GDT + TSS (kernel & user segments, ring-3 transition stack).
    arch::gdt::init();

    // Install the IDT so CPU exceptions are caught and faults are contained.
    interrupts::init_idt();

    // Setup capability table for Task 1 (IPC Sender Driver)
    let mut cap_table_sender = process::CapTable::new();
    // Task 1 can only send IPC to Task 2 (index 0)
    let _ = cap_table_sender.insert(process::Capability {
        resource: process::Resource::IpcChannel { target_task: process::TaskId(2) },
        read: false,
        write: true,
        grant: false,
    });

    // Setup capability table for Task 2 (the user-space logging service).
    // Its only authority is a serial-write capability at slot 0.
    let mut cap_table_logger = process::CapTable::new();
    let _ = cap_table_logger.insert(process::Capability {
        resource: process::Resource::Serial,
        read: false,
        write: true,
        grant: false,
    });

    // Task 3 (buggy task) holds no capabilities; it deliberately faults to
    // demonstrate fault containment — the kernel must survive and keep running
    // the other tasks.
    let cap_table_buggy = process::CapTable::new();

    // Instantiate tasks. Task 2 is now a ring-3 user-space service; the kernel
    // only routes IPC to it and enforces its serial capability.
    let task_1 = process::Task::new(process::TaskId(1), task_sender, cap_table_sender);
    let task_2 = userspace::spawn_logger_task(process::TaskId(2), cap_table_logger);
    let task_3 = process::Task::new(process::TaskId(3), task_buggy, cap_table_buggy);

    // Task 4: a ring-3 user process. It holds a single capability — an IPC
    // channel to the logging service (Task 2) at slot 0 — and nothing else.
    let mut cap_table_user = process::CapTable::new();
    let _ = cap_table_user.insert(process::Capability {
        resource: process::Resource::IpcChannel { target_task: process::TaskId(2) },
        read: false,
        write: true,
        grant: false,
    });
    let task_4 = userspace::spawn_demo_user_task(process::TaskId(4), cap_table_user);

    // Place tasks into the scheduler
    {
        let mut sched = scheduler::SCHEDULER.lock();
        sched.tasks[1] = Some(task_1);
        sched.tasks[2] = Some(task_2);
        sched.tasks[3] = Some(task_3);
        sched.tasks[4] = Some(task_4);
    }

    println!("Microkernel tasks loaded. Launching scheduler...");

    // Yield control to start execution
    scheduler::yield_cpu();

    // Infinite halt loop (fallback)
    loop {
        unsafe {
            // SAFETY:
            // - Why necessary: Halt instruction puts CPU in low power sleep.
            // - Invariants: None.
            // - Soundness: Safe to halt when we cannot boot further.
            core::arch::asm!("hlt");
        }
    }
}

/// Simulated user-space driver task (Sender).
/// Generates data packets and sends them to the Logging service.
extern "C" fn task_sender() -> ! {
    loop {
        // Test capability gate: Attempt unauthorized write directly to serial via index 1 (unassigned slot)
        if syscall::sys_serial_write(1, "[Task 1] ERROR: Unauthorized serial write succeeded!").is_err() {
            // Correctly blocked by capability check
        }

        // Send a message using the IPC capability at index 0 (points to Task 2)
        let msg = "Sensor data: Temp=24.5C";
        let _ = process::ipc::sys_send(0, msg.as_bytes());

        // Yield execution cooperatively
        scheduler::yield_cpu();
    }
}

/// Simulated buggy task. Dereferences an unmapped address, raising a page
/// fault. The kernel's fault handler must terminate this task and continue
/// scheduling the others, proving fault containment.
extern "C" fn task_buggy() -> ! {
    unsafe {
        // SAFETY: this is intentionally unsound — we read a non-present address
        // to provoke a #PF and exercise fault containment. The task is expected
        // to be terminated by the handler and never resumes past this point.
        let p = 0xdead_beef_0000usize as *const u64;
        let _ = core::ptr::read_volatile(p);
    }
    // Unreachable: the fault handler terminates this task.
    loop {
        scheduler::yield_cpu();
    }
}

/// Panic handler called when the kernel panics.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("KERNEL PANIC: {}", info);
    loop {
        unsafe {
            // SAFETY:
            // - Why necessary: Halt instruction puts CPU in low power sleep.
            // - Invariants: None.
            // - Soundness: Safe to halt in panic loop.
            core::arch::asm!("hlt");
        }
    }
}
