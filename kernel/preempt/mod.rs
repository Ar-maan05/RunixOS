// RunixOS preemption subsystem — Phase 11: preemptive scheduling.
//
// This module holds the *policy* state that turns the timer interrupt into a
// scheduler tick, plus the synchronization primitives the capability/IPC layer
// needs once a task can be interrupted at an arbitrary instruction.
//
// The central research artifact lives here. Under the cooperative scheduler,
// "validate a capability, then use it" was atomic *for free*: nothing else ran
// between the two steps. Preemption withdraws that guarantee. The state below
// lets us (a) measure how often a timer tick lands *inside* a critical section
// that the cooperative design assumed was indivisible, and (b) close that window
// with an explicit non-preemptible region — and prove, on a booting VM, the
// difference between the two.

use core::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};

/// Total timer ticks observed since `sti`. Proof the mechanism is live.
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Number of involuntary context switches the timer actually performed.
static PREEMPTIONS: AtomicU64 = AtomicU64::new(0);

/// Ticks that wanted to preempt but were deferred because the interrupted code
/// was inside a non-preemptible region (preempt-count > 0) or held the
/// scheduler lock. A healthy guarded kernel turns "window hits" into these.
static DEFERRED: AtomicU64 = AtomicU64::new(0);

/// Nesting depth of explicit non-preemptible regions. Timer ticks taken while
/// this is > 0 are deferred, never switched. This is the "make the IPC critical
/// section non-preemptible" knob.
static PREEMPT_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Master switch: until preemption is armed, the timer only counts (Stage 1
/// mechanism bring-up and the windows before/after a demo).
static ARMED: AtomicBool = AtomicBool::new(false);

// ── Research instrumentation: the validate→use window in IPC ─────────────────
//
// `IN_IPC_WINDOW` is raised by the IPC send path between the moment it has
// *resolved* a capability to a target and the moment it *uses* that target to
// deliver. `WINDOW_TICKS` counts timer ticks that landed in exactly that
// window — the empirical width of the TOCTOU the cooperative scheduler hid.
static IN_IPC_WINDOW: AtomicBool = AtomicBool::new(false);
static WINDOW_TICKS: AtomicU64 = AtomicU64::new(0);

/// A deterministic adversary: when armed, the *next* timer tick that catches a
/// task inside the IPC validate→use window will execute a pending capability
/// revocation right there — winning the race on purpose so the hazard is
/// reproducible instead of statistical. Set to the (task, slot) to revoke.
static PENDING_REVOKE: AtomicUsize = AtomicUsize::new(NO_REVOKE);
static PENDING_REVOKE_TASK: AtomicUsize = AtomicUsize::new(0);
const NO_REVOKE: usize = usize::MAX;
/// Set by the adversary hook once it has fired, so the demo can confirm the
/// revoke landed *inside* the window.
static REVOKE_FIRED_IN_WINDOW: AtomicBool = AtomicBool::new(false);

/// Arms/disarms involuntary preemption (the timer may switch tasks).
pub fn set_armed(on: bool) {
    ARMED.store(on, Ordering::SeqCst);
}

pub fn is_armed() -> bool {
    ARMED.load(Ordering::SeqCst)
}

/// Enters a non-preemptible region. Pair with [`exit_critical`]. Re-entrant.
#[inline]
pub fn enter_critical() {
    PREEMPT_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Leaves a non-preemptible region.
#[inline]
pub fn exit_critical() {
    PREEMPT_COUNT.fetch_sub(1, Ordering::SeqCst);
}

#[inline]
pub fn in_critical() -> bool {
    PREEMPT_COUNT.load(Ordering::SeqCst) != 0
}

/// RAII scope guard for a capability validate→use region. Entering raises the
/// non-preemptible count *and* marks the IPC validate→use window (telemetry the
/// timer uses to measure, and the demo adversary uses to target, in-flight
/// capability operations). Dropping clears both — on every control-flow path,
/// including early `return`s — which is why the real send path uses this rather
/// than hand-balanced enter/exit calls.
pub struct CriticalWindow {
    _private: (),
}

impl CriticalWindow {
    #[inline]
    pub fn enter() -> Self {
        enter_critical();
        enter_ipc_window();
        CriticalWindow { _private: () }
    }
}

impl Drop for CriticalWindow {
    #[inline]
    fn drop(&mut self) {
        exit_ipc_window();
        exit_critical();
    }
}

/// Called from the timer ISR on every tick. Returns `true` if the scheduler is
/// allowed to perform an involuntary switch on this tick. Records the decision
/// for later reporting. Never blocks, never prints.
pub fn on_tick_should_switch() -> bool {
    TICKS.fetch_add(1, Ordering::Relaxed);

    // Research probe: measure how often a tick lands inside the IPC validate→use
    // window. This is pure observation — the hardware interrupt fires regardless
    // of whether we are in a non-preemptible region, so this count rises even
    // when guarded. What changes under guarding is whether the tick is *allowed
    // to act* (switch / let a revoker run), handled below.
    let in_window = IN_IPC_WINDOW.load(Ordering::SeqCst);
    if in_window {
        WINDOW_TICKS.fetch_add(1, Ordering::Relaxed);
    }

    if !ARMED.load(Ordering::SeqCst) {
        return false;
    }
    if PREEMPT_COUNT.load(Ordering::SeqCst) != 0 {
        // Non-preemptible region: we neither switch nor let the adversarial
        // revoker run. This is precisely what makes the IPC critical section
        // atomic again under preemption.
        DEFERRED.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    // Preemption is permitted on this tick. Only here — where a concurrent
    // revoker task could really be scheduled in — does the modelled adversary
    // get to act mid-window.
    if in_window {
        maybe_fire_adversary();
    }
    true
}

/// Records that an involuntary switch was carried out.
pub fn note_preemption() {
    PREEMPTIONS.fetch_add(1, Ordering::Relaxed);
}

/// Records that an armed switch was skipped because the scheduler lock was held
/// by the interrupted code (the mechanism-level hazard from the writeup).
pub fn note_deferred_locked() {
    DEFERRED.fetch_add(1, Ordering::Relaxed);
}

// ── IPC window API (used by process::ipc) ────────────────────────────────────

/// Marks the start of the capability validate→use window. Anything that runs
/// (a timer tick, a deterministic adversary) between this and [`exit_ipc_window`]
/// is observing a non-atomic capability operation.
#[inline]
pub fn enter_ipc_window() {
    IN_IPC_WINDOW.store(true, Ordering::SeqCst);
}

#[inline]
pub fn exit_ipc_window() {
    IN_IPC_WINDOW.store(false, Ordering::SeqCst);
}

/// Arms the deterministic adversary: the next tick inside the IPC window will
/// revoke capability `slot` from `task`'s table.
pub fn arm_adversary(task: usize, slot: usize) {
    REVOKE_FIRED_IN_WINDOW.store(false, Ordering::SeqCst);
    PENDING_REVOKE_TASK.store(task, Ordering::SeqCst);
    PENDING_REVOKE.store(slot, Ordering::SeqCst);
}

pub fn disarm_adversary() {
    PENDING_REVOKE.store(NO_REVOKE, Ordering::SeqCst);
}

pub fn adversary_fired_in_window() -> bool {
    REVOKE_FIRED_IN_WINDOW.load(Ordering::SeqCst)
}

/// Executed from the timer ISR when a tick lands inside the IPC window and the
/// adversary is armed. Performs the revoke *now*, mid-flight, deterministically
/// reproducing the TOCTOU. Uses the scheduler lock's owner-blind raw access via
/// a best-effort try-lock; if it can't get it this tick, it stays armed.
fn maybe_fire_adversary() {
    let slot = PENDING_REVOKE.load(Ordering::SeqCst);
    if slot == NO_REVOKE {
        return;
    }
    let task = PENDING_REVOKE_TASK.load(Ordering::SeqCst);
    if let Some(mut sched) = crate::scheduler::SCHEDULER.try_lock() {
        if let Some(t) = sched.get_task_mut(crate::process::TaskId(task)) {
            // Force-revoke even if sealed: this is the adversary, modelling a
            // concurrent SYS_CAP_REVOKE that wins the race.
            let _ = t.cap_table.kernel_revoke(slot);
            REVOKE_FIRED_IN_WINDOW.store(true, Ordering::SeqCst);
            PENDING_REVOKE.store(NO_REVOKE, Ordering::SeqCst);
        }
    }
}

// ── Reporting ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct Stats {
    pub ticks: u64,
    pub preemptions: u64,
    pub deferred: u64,
    pub window_ticks: u64,
}

pub fn stats() -> Stats {
    Stats {
        ticks: TICKS.load(Ordering::Relaxed),
        preemptions: PREEMPTIONS.load(Ordering::Relaxed),
        deferred: DEFERRED.load(Ordering::Relaxed),
        window_ticks: WINDOW_TICKS.load(Ordering::Relaxed),
    }
}

pub fn reset_window_ticks() {
    WINDOW_TICKS.store(0, Ordering::SeqCst);
}
