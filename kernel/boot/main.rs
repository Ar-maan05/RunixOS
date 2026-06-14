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

// Inform the Limine bootloader about the protocol revision we support.
// NOTE: Pin to revision 2, the highest the bundled Limine 7.13.3 supports.
#[used]
#[unsafe(link_section = ".requests")]
pub static BASE_REVISION: BaseRevision = BaseRevision::with_revision(2);

#[used]
#[unsafe(link_section = ".requests_start_marker")]
pub static _START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[unsafe(link_section = ".requests")]
pub static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
#[unsafe(link_section = ".requests_end_marker")]
pub static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

/// The entry point of the RunixOS kernel.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Force the compiler and linker to keep the Limine requests.
    unsafe {
        core::ptr::read_volatile(&BASE_REVISION);
        core::ptr::read_volatile(&_START_MARKER);
        core::ptr::read_volatile(&FRAMEBUFFER_REQUEST);
        core::ptr::read_volatile(&_END_MARKER);
        core::ptr::read_volatile(&memory::MEMMAP_REQUEST);
        core::ptr::read_volatile(&memory::HHDM_REQUEST);
    }

    // Initialize serial console (must be first — everything below may print).
    drivers::serial::SERIAL1.lock().init();

    println!("RunixOS kernel initialized.");
    unsafe {
        dbg_println!("[debug] GDT address: {:p}", &raw const arch::gdt::GDT);
        dbg_println!("[debug] SCHEDULER address: {:p}", &raw const scheduler::SCHEDULER);
        dbg_println!("[debug] TASK_STACKS address: {:p}", &raw const process::TASK_STACKS);
        dbg_println!("[debug] size_of Scheduler: {}", core::mem::size_of::<scheduler::Scheduler>());
        dbg_println!("[debug] size_of Task: {}", core::mem::size_of::<process::Task>());
        dbg_println!("[debug] size_of CapTable: {}", core::mem::size_of::<process::CapTable>());
        dbg_println!("[debug] size_of MessageQueue: {}", core::mem::size_of::<process::ipc::MessageQueue>());
        dbg_println!("[debug] size_of Message: {}", core::mem::size_of::<process::ipc::Message>());
    }

    // Verify bootloader handshake before using *any* bootloader response.
    if !BASE_REVISION.is_supported() {
        println!("FATAL: Limine base revision not acknowledged. Halting.");
        halt_loop()
    }

    // Initialize physical frame allocator.
    unsafe {
        memory::FRAME_ALLOCATOR.init();
    }

    // Install GDT + TSS (kernel & user segments, ring-3 transition stack).
    arch::gdt::init();
    unsafe {
        dbg_println!("[debug] TSS address: {:?}", arch::gdt::get_tss_address());
        dbg_println!("[debug] GDT[3] post-init: {:#x}, GDT[4] post-init: {:#x}",
            *(&raw const arch::gdt::GDT as *const u64).add(3),
            *(&raw const arch::gdt::GDT as *const u64).add(4));
    }

    // Install IDT: CPU exceptions are caught; faulting tasks are terminated.
    interrupts::init_idt();

    // ── Phase 6: Userspace Ecosystem ──────────────────────────────────────────
    //
    // Spawn user-space init task (Task 1) and pass it the root capability set.
    // The root capability set here is the Serial capability with grant rights.
    let mut cap_table_init = process::CapTable::new();
    let _ = cap_table_init.insert(process::Capability {
        resource: process::Resource::Serial,
        read:  false,
        write: true,
        grant: true,     // init must hold grant to delegate it
        sealed: false,
        id: 0,           // stamped on insert
        origin: None,    // root capability minted by the kernel
    });

    let init_task = userspace::spawn_init_task(process::TaskId(1), cap_table_init);

    // Place tasks into the scheduler.
    {
        let mut sched = scheduler::SCHEDULER.lock();
        sched.tasks[1] = Some(init_task);
    }

    // Phase 7: load the stress / failure / scale harness alongside init.
    load_phase7_harness();

    // Phase 8: load the capability security / audit demonstration task.
    load_phase8_demo();

    // Phase 9: load the watchdog and the service it monitors/recovers.
    load_phase9_watchdog();

    // Phase 10: load the checkpoint/restore persistence demonstration.
    load_phase10_persistence();

    // Phase 10 (Parts 4-8): load the distribution / migration demonstration.
    load_phase10_dist();

    println!("Microkernel tasks loaded. Launching scheduler...");

    scheduler::yield_cpu();

    halt_loop()
}

fn halt_loop() -> ! {
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}

// ── Phase 7: stress, scale & failure harness ───────────────────────────────────
//
// These are ring-0 *kernel* tasks (they call the kernel APIs directly rather
// than trapping via `int 0x80`). They run alongside the user-space init/service
// ecosystem to exercise the Phase 7 success criteria at runtime:
//
//   - fault containment   : `task_crasher` faults; the kernel terminates only it
//   - failure semantics    : `task_probe` sends to an already-dead task and must
//                            observe `TargetGone` instead of blocking forever
//   - scale / stability    : `WORKER_COUNT` workers churn the scheduler and IPC,
//                            each exiting cleanly, proving round-robin handles
//                            many ready tasks without kernel instability
//
// Slot layout (kept clear of init's user tasks, which occupy 1..=4):
const HARNESS_CRASHER: usize = 100;
const HARNESS_DEAD:    usize = 101;
const HARNESS_PROBE:   usize = 102;
const HARNESS_WORKER_BASE: usize = 103;
const WORKER_COUNT: usize = 16;

/// Loads the Phase 7 kernel harness tasks into the scheduler.
fn load_phase7_harness() {
    use process::{Capability, CapTable, Resource, Task, TaskId};

    let mut sched = scheduler::SCHEDULER.lock();

    // Fault containment: a task that performs an illegal access and dies.
    sched.tasks[HARNESS_CRASHER] =
        Some(Task::new(TaskId(HARNESS_CRASHER), task_crasher, CapTable::new()));

    // Failure semantics: a target that exits immediately, and a probe that
    // holds an IpcChannel capability to it and tries to send after it is gone.
    sched.tasks[HARNESS_DEAD] =
        Some(Task::new(TaskId(HARNESS_DEAD), task_dead_target, CapTable::new()));

    let mut probe_caps = CapTable::new();
    let _ = probe_caps.insert(Capability {
        resource: Resource::IpcChannel { target_task: TaskId(HARNESS_DEAD) },
        read: true,
        write: true,
        grant: false,
        sealed: false,
        id: 0,
        origin: None,
    });
    sched.tasks[HARNESS_PROBE] =
        Some(Task::new(TaskId(HARNESS_PROBE), task_probe, probe_caps));

    // Scale: a batch of cooperative workers.
    for i in 0..WORKER_COUNT {
        let id = HARNESS_WORKER_BASE + i;
        sched.tasks[id] = Some(Task::new(TaskId(id), task_worker, CapTable::new()));
    }

    println!(
        "[phase7] harness loaded: crasher + dead/probe + {} workers.",
        WORKER_COUNT
    );
}

/// Fault containment: deliberately dereferences an unmapped address. The IDT
/// handler catches the #PF, terminates only this task, and the kernel proceeds.
extern "C" fn task_crasher() -> ! {
    println!("[crasher] about to perform an illegal memory access...");
    unsafe {
        let p = 0xdead_beef_0000usize as *const u64;
        let _ = core::ptr::read_volatile(p);
    }
    // Unreachable: the fault handler terminates us before we get here.
    loop { scheduler::yield_cpu(); }
}

/// Failure semantics: exits immediately so the probe's later send finds it gone.
extern "C" fn task_dead_target() -> ! {
    println!("[dead] exiting immediately (target will be gone).");
    scheduler::terminate_current_task();
}

/// Failure semantics: after the target has had a chance to exit, sends to it and
/// expects `TargetGone` (proving a send to a dead task does not deadlock).
extern "C" fn task_probe() -> ! {
    // Yield a few times so `task_dead_target` runs and terminates first.
    for _ in 0..4 {
        scheduler::yield_cpu();
    }
    match process::ipc::sys_send_typed(0, process::IpcTag::Ping as u16, 1, b"ping") {
        Err(process::IpcError::TargetGone) => {
            println!("[probe] send to dead task correctly returned TargetGone.");
        }
        Ok(()) => {
            println!("[probe] ERROR: send to dead task unexpectedly succeeded!");
        }
        Err(e) => {
            println!("[probe] ERROR: unexpected error {:?} (expected TargetGone).", e);
        }
    }
    scheduler::terminate_current_task();
}

/// Phase 8 slot for the security-demonstration kernel task.
const HARNESS_SECURITY: usize = 119;

/// Loads the Phase 8 security demo task. It runs after init has performed its
/// grants, so the audit dump reflects the full ecosystem plus the demo's own
/// grant/revoke chain.
fn load_phase8_demo() {
    use process::{CapTable, Task, TaskId};
    let mut sched = scheduler::SCHEDULER.lock();
    sched.tasks[HARNESS_SECURITY] =
        Some(Task::new(TaskId(HARNESS_SECURITY), task_security_demo, CapTable::new()));
}

/// Phase 8: runs the capability revocation-propagation demo and audit dump,
/// then exits cleanly.
extern "C" fn task_security_demo() -> ! {
    // Let init finish its spawn/grant orchestration first.
    for _ in 0..2 {
        scheduler::yield_cpu();
    }
    syscall::phase8_security_demo();
    scheduler::terminate_current_task();
}

/// Scale: cooperative worker that yields a bounded number of times, then exits
/// cleanly. Many of these running concurrently exercise the round-robin
/// scheduler under load without destabilizing the kernel.
extern "C" fn task_worker() -> ! {
    for _ in 0..3 {
        scheduler::yield_cpu();
    }
    let id = scheduler::current_task_id().map(|t| t.0).unwrap_or(0);
    println!("[worker {}] done, exiting cleanly.", id);
    scheduler::terminate_current_task();
}

// ── Phase 9: stability, watchdog & service recovery ─────────────────────────────
//
// A kernel watchdog monitors a service task. When the service crashes (faults),
// the IDT handler contains it and leaves it `Terminated`. The watchdog detects
// that, restarts the service in the same slot with a freshly granted capability
// set (capability redistribution on failure), and bounds restarts so a service
// that cannot be recovered does not loop forever. This demonstrates the Phase 9
// criteria: services recover from failure, the kernel stays minimal and stable,
// and boot/recovery is deterministic.

use core::sync::atomic::{AtomicUsize, Ordering};

const HARNESS_SERVICE: usize = 123; // monitored service slot
const HARNESS_WATCHDOG: usize = 124;
const MAX_RESTARTS: usize = 2;

/// Counts how many times the fragile service has started (each start increments
/// it). Incarnations 0 and 1 crash on purpose; incarnation 2 runs stably.
static FRAGILE_INCARNATION: AtomicUsize = AtomicUsize::new(0);

/// Builds the capability set handed to each fresh incarnation of the service —
/// i.e. capabilities are *redistributed* on every restart, never inherited from
/// the dead incarnation.
fn fragile_service_caps() -> process::CapTable {
    let mut caps = process::CapTable::new();
    let _ = caps.insert(process::Capability {
        resource: process::Resource::Serial,
        read: false,
        write: true,
        grant: false,
        sealed: false,
        id: 0,
        origin: None,
    });
    caps
}

/// Loads the Phase 9 watchdog and its monitored service.
fn load_phase9_watchdog() {
    use process::{Task, TaskId};
    let mut sched = scheduler::SCHEDULER.lock();
    sched.tasks[HARNESS_SERVICE] = Some(Task::new(
        TaskId(HARNESS_SERVICE),
        task_fragile_service,
        fragile_service_caps(),
    ));
    sched.tasks[HARNESS_WATCHDOG] =
        Some(Task::new(TaskId(HARNESS_WATCHDOG), task_watchdog, process::CapTable::new()));
}

/// A service that crashes on its first `MAX_RESTARTS` incarnations and runs
/// stably on the next one, exercising the watchdog's detect-and-restart loop.
/// Crash count is tied to `MAX_RESTARTS` so the two stay in sync.
extern "C" fn task_fragile_service() -> ! {
    let inc = FRAGILE_INCARNATION.fetch_add(1, Ordering::SeqCst);
    println!("[service] starting (incarnation {}).", inc);
    scheduler::yield_cpu();
    if inc < MAX_RESTARTS {
        println!("[service] incarnation {} crashing...", inc);
        unsafe {
            let p = 0x0000_1234_5678usize as *const u64;
            let _ = core::ptr::read_volatile(p);
        }
    }
    println!("[service] incarnation {} is stable and serving.", inc);
    loop {
        scheduler::yield_cpu();
    }
}

/// Watchdog: detects the monitored service terminating, restarts it (with fresh
/// capabilities) up to `MAX_RESTARTS` times, then declares recovery once a stable
/// incarnation is observed running. Exits cleanly when done.
extern "C" fn task_watchdog() -> ! {
    let mut restarts = 0usize;
    loop {
        scheduler::yield_cpu();

        // Read the monitored service's liveness. We release the lock here and
        // re-acquire it below to restart; that gap is safe ONLY because the
        // scheduler is cooperative — no task runs between our `yield_cpu`
        // returns, so nothing can mutate the slot in between. This TOCTOU window
        // would need closing if preemption is ever added.
        let terminated = {
            let sched = scheduler::SCHEDULER.lock();
            match sched.get_task(process::TaskId(HARNESS_SERVICE)) {
                Some(t) => t.state == process::TaskState::Terminated,
                None => true,
            }
        };

        if terminated {
            if restarts < MAX_RESTARTS {
                restarts += 1;
                {
                    let mut sched = scheduler::SCHEDULER.lock();
                    sched.tasks[HARNESS_SERVICE] = Some(process::Task::new(
                        process::TaskId(HARNESS_SERVICE),
                        task_fragile_service,
                        fragile_service_caps(),
                    ));
                }
                println!(
                    "[watchdog] monitored service died; restarted it (restart #{}) with fresh capabilities.",
                    restarts
                );
            } else {
                println!("[watchdog] service exceeded {} restarts; giving up (kernel stays stable).", MAX_RESTARTS);
                scheduler::terminate_current_task();
            }
        } else if FRAGILE_INCARNATION.load(Ordering::SeqCst) > MAX_RESTARTS {
            // The post-crash (stable) incarnation has started and is alive.
            // Tied to MAX_RESTARTS: incarnations 0..MAX_RESTARTS crash, so the
            // first stable one bumps the counter to MAX_RESTARTS + 1.
            println!("[watchdog] service recovered and stable after {} restart(s).", restarts);
            scheduler::terminate_current_task();
        }
    }
}

// ── Phase 10: persistence (checkpoint / restore) ────────────────────────────────
//
// In-memory demonstration of Parts 1-3: checkpoint the whole system's
// checkpointable state, simulate state loss, restore, and verify the capability
// graph round-trips intact. Cross-reboot durability and distribution (Parts 4-8)
// are out of scope for this kernel build (see process/snapshot.rs).

const HARNESS_PERSIST: usize = 125;

/// Loads the Phase 10 persistence demonstration task.
fn load_phase10_persistence() {
    use process::{CapTable, Task, TaskId};
    let mut sched = scheduler::SCHEDULER.lock();
    sched.tasks[HARNESS_PERSIST] =
        Some(Task::new(TaskId(HARNESS_PERSIST), task_persistence_demo, CapTable::new()));
}

/// Phase 10: runs the checkpoint/restore demo against the logging service
/// (task 2), which holds a granted Serial capability by the time this runs.
extern "C" fn task_persistence_demo() -> ! {
    // Let init finish spawning + granting before we snapshot.
    for _ in 0..3 {
        scheduler::yield_cpu();
    }
    process::snapshot::demo(process::TaskId(2));
    scheduler::terminate_current_task();
}

// ── Phase 10 (Parts 4-8): distribution substrate ────────────────────────────────
//
// Demonstrates network-transparent IPC, distributed capabilities, service
// migration, and failover. Nodes are simulated logical domains within this
// kernel image and the transport is in-kernel (see process/dist.rs); the routing
// /migration machinery and programming-model invariance are what's exercised.

const DIST_DRIVER:  usize = 128; // runs the demo
const DIST_BACKING: usize = 129; // local task backing the service before migration
const DIST_REPLICA: usize = 130; // local task the service fails over onto

/// Loads the Phase 10 distribution demo plus its two scratch service tasks.
fn load_phase10_dist() {
    use process::{CapTable, Task, TaskId};
    let mut sched = scheduler::SCHEDULER.lock();
    sched.tasks[DIST_DRIVER] =
        Some(Task::new(TaskId(DIST_DRIVER), task_dist_demo, CapTable::new()));
    // Scratch service instances; they only hold state/queues, never run.
    sched.tasks[DIST_BACKING] =
        Some(Task::new(TaskId(DIST_BACKING), dist_scratch_entry, dist_service_caps()));
    sched.tasks[DIST_REPLICA] =
        Some(Task::new(TaskId(DIST_REPLICA), dist_scratch_entry, CapTable::new()));
}

/// Capabilities the demo service "owns" — carried across migration to prove
/// state preservation (Part 7).
fn dist_service_caps() -> process::CapTable {
    let mut caps = process::CapTable::new();
    let _ = caps.insert(process::Capability {
        resource: process::Resource::Serial,
        read: false, write: true, grant: false, sealed: false, id: 0, origin: None,
    });
    let _ = caps.insert(process::Capability {
        resource: process::Resource::Service { id: 1 },
        read: true, write: true, grant: false, sealed: false, id: 0, origin: None,
    });
    caps
}

extern "C" fn dist_scratch_entry() -> ! {
    scheduler::terminate_current_task();
}

extern "C" fn task_dist_demo() -> ! {
    // Run after the other phase demos have settled.
    for _ in 0..6 {
        scheduler::yield_cpu();
    }
    process::dist::demo(1, process::TaskId(DIST_BACKING), process::TaskId(DIST_REPLICA));
    scheduler::terminate_current_task();
}

/// Panic handler.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("KERNEL PANIC: {}", info);
    halt_loop()
}
