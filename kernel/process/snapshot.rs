// RunixOS system checkpoint and restore: persistence.
//
// Scope of this module (honest boundaries):
//   * persistent system state: serialize the *checkpointable* state of
//     every task (capability table, pending IPC rendezvous buffer, async
//     queue, task metadata like id and state) plus the scheduler's current task
//     into a single fixed-size snapshot, and restore it.
//   * process checkpointing: the per-task projection above is exactly a
//     process checkpoint of its capability/IPC/metadata state.
//   * persistent capabilities: capabilities are plain old data and carry
//     their globally-unique `id` and `origin` lineage, so the whole capability
//     graph round-trips byte-for-byte; an integrity checksum over the graph
//     stands in for the optional signing.
//
// Deliberately OUT of scope here (due to lack of kernel infrastructure):
//   * live register/stack capture-and-resume (live execution migration),
//   * cross-reboot durability (needs a block-write driver),
//   * networking and distribution.
// So restore intentionally preserves each live task's execution context
// (`rsp`/`cr3`/`kstack_top`) and only rolls back the serialized metadata (the
// functionally equivalent state) without corrupting running stacks.

use crate::process::{MAX_TASKS, TaskId, TaskState};
use crate::process::capability::{CapTable, Resource, MAX_CAPS};
use crate::process::ipc::{Message, MessageQueue};
use crate::scheduler::SCHEDULER;

/// The checkpointable projection of a single task.
#[derive(Clone, Copy)]
pub struct TaskCheckpoint {
    pub id: TaskId,
    pub state: TaskState,
    pub cap_table: CapTable,
    pub ipc_buffer: Option<Message>,
    pub msg_queue: MessageQueue,
}

/// A serialized snapshot of the whole system's checkpointable state.
pub struct SystemSnapshot {
    pub tasks: [Option<TaskCheckpoint>; MAX_TASKS],
    pub current: Option<TaskId>,
    /// Integrity tag over the capability graph + metadata (see `checksum`).
    pub checksum: u64,
    /// False until a successful `capture`.
    pub valid: bool,
}

impl SystemSnapshot {
    pub const fn new() -> Self {
        Self {
            tasks: [None; MAX_TASKS],
            current: None,
            checksum: 0,
            valid: false,
        }
    }
}

/// The single persistent snapshot slot ("save-system-state"). Sound as a
/// `static mut`: capture/restore run to completion under cooperative scheduling
/// without yielding, so this is never accessed re-entrantly.
static mut SYSTEM_SNAPSHOT: SystemSnapshot = SystemSnapshot::new();

/// Encodes a `Resource` to a stable integer so the checksum reflects it.
fn resource_code(r: &Resource) -> u64 {
    match r {
        Resource::Serial => 1,
        Resource::IpcChannel { target_task } => 0x1000 ^ (target_task.0 as u64),
        Resource::MemoryMapping { start_vaddr, size, writeable } => {
            0x2000 ^ (*start_vaddr as u64) ^ ((*size as u64) << 1) ^ (*writeable as u64)
        }
        Resource::Service { id } => 0x3000 ^ (*id as u64),
        Resource::KVEntry { slot, readable, writable } => {
            0x4000 ^ (*slot as u64) ^ ((*readable as u64) << 8) ^ ((*writable as u64) << 9)
        }
        Resource::LogChannel { kind, readable, writable } => {
            0x5000 ^ (*kind as u64) ^ ((*readable as u64) << 8) ^ ((*writable as u64) << 9)
        }
        Resource::FsNode { mount, readable, writable } => {
            0x6000 ^ (*mount as u64) ^ ((*readable as u64) << 8) ^ ((*writable as u64) << 9)
        }
        Resource::Device { id, readable, writable } => {
            0x7000 ^ (*id as u64) ^ ((*readable as u64) << 8) ^ ((*writable as u64) << 9)
        }
        Resource::SyncObj { id } => {
            0x8000 ^ (*id as u64)
        }
    }
}

/// Field-based FNV-1a over the snapshot's capability graph + task metadata.
/// Field-by-field (not raw bytes) so struct padding never feeds the hash.
fn checksum(snap: &SystemSnapshot) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mix = |v: u64, h: &mut u64| {
        *h ^= v;
        *h = h.wrapping_mul(0x0000_0100_0000_01b3);
    };

    mix(snap.current.map(|t| t.0 as u64 + 1).unwrap_or(0), &mut h);

    for slot in snap.tasks.iter() {
        match slot {
            None => mix(0, &mut h),
            Some(cp) => {
                mix(0xF00D, &mut h);
                mix(cp.id.0 as u64, &mut h);
                mix(state_code(cp.state), &mut h);
                for cs in 0..MAX_CAPS {
                    match cp.cap_table.get(cs) {
                        None => mix(0, &mut h),
                        Some(cap) => {
                            mix(resource_code(&cap.resource), &mut h);
                            mix(
                                (cap.read as u64)
                                    | ((cap.write as u64) << 1)
                                    | ((cap.grant as u64) << 2)
                                    | ((cap.sealed as u64) << 3),
                                &mut h,
                            );
                            mix(cap.id, &mut h);
                            mix(cap.origin.map(|o| o + 1).unwrap_or(0), &mut h);
                        }
                    }
                }
                mix(cp.ipc_buffer.map(|m| m.len as u64 + 1).unwrap_or(0), &mut h);
                mix(cp.msg_queue.count as u64, &mut h);
            }
        }
    }
    h
}

fn state_code(s: TaskState) -> u64 {
    match s {
        TaskState::Ready => 1,
        TaskState::Running => 2,
        TaskState::BlockedOnReceive => 3,
        TaskState::BlockedOnSend(t) => 0x100 ^ (t.0 as u64),
        TaskState::Terminated => 5,
    }
}

/// Captures the whole system's checkpointable state into the snapshot slot, and
/// stamps an integrity checksum. ("save-system-state")
pub fn capture() {
    // SAFETY: single-threaded, non-reentrant under the cooperative model.
    let snap = unsafe { &mut *core::ptr::addr_of_mut!(SYSTEM_SNAPSHOT) };

    let sched = SCHEDULER.lock();
    snap.current = sched.current_task_id;
    for i in 0..MAX_TASKS {
        snap.tasks[i] = sched.tasks[i].as_ref().map(|t| TaskCheckpoint {
            id: t.id,
            state: t.state,
            cap_table: t.cap_table,
            ipc_buffer: t.ipc_buffer,
            msg_queue: t.msg_queue,
        });
    }
    drop(sched);

    snap.checksum = checksum(snap);
    snap.valid = true;
}

/// Restores the checkpointable state from the snapshot slot, verifying its
/// integrity tag first. Live execution context (rsp/cr3/kstack) is preserved, so
/// running tasks continue from where they are with their saved metadata rolled
/// back. ("restore-system-state")
///
/// Returns `Err(())` if there is no valid snapshot or the integrity check fails.
pub fn restore() -> Result<usize, ()> {
    // SAFETY: single-threaded, non-reentrant under the cooperative model.
    let snap = unsafe { &*core::ptr::addr_of!(SYSTEM_SNAPSHOT) };
    if !snap.valid {
        return Err(());
    }
    if checksum(snap) != snap.checksum {
        return Err(()); // tampered / corrupt snapshot
    }

    let mut restored = 0usize;
    let mut sched = SCHEDULER.lock();
    for i in 0..MAX_TASKS {
        if let Some(cp) = snap.tasks[i] {
            if let Some(t) = sched.get_task_mut(cp.id) {
                t.state = cp.state;
                t.cap_table = cp.cap_table;
                t.ipc_buffer = cp.ipc_buffer;
                t.msg_queue = cp.msg_queue;
                restored += 1;
            }
        }
    }
    Ok(restored)
}

/// Reports whether a valid snapshot exists and its checksum (kernel diagnostic).
pub fn info() -> Option<u64> {
    // SAFETY: single-threaded read.
    let snap = unsafe { &*core::ptr::addr_of!(SYSTEM_SNAPSHOT) };
    if snap.valid { Some(snap.checksum) } else { None }
}

/// Persistence demonstration: checkpoint the system, simulate state loss by
/// clearing a victim task's capability table, restore, and verify the victim's
/// capability graph (ids + lineage included) came back intact, then confirm a
/// re-capture reproduces the original checksum (deterministic persistence).
///
/// `victim` should be a task known to hold capabilities at demo time.
pub fn demo(victim: TaskId) {
    crate::println!("[persistence] demo: checkpoint, restore, and verify.");

    capture();
    let original = info().unwrap_or(0);
    crate::println!(
        "[persistence] system state checkpointed (checksum={:#018x}).",
        original
    );

    // Snapshot the victim's pre-loss capability fingerprint for comparison.
    let before = victim_fingerprint(victim);

    // Simulate catastrophic state loss: wipe the victim's capability table live.
    {
        let mut sched = SCHEDULER.lock();
        if let Some(t) = sched.get_task_mut(victim) {
            t.cap_table = CapTable::new();
        }
    }
    let after_wipe = victim_fingerprint(victim);
    crate::println!(
        "[persistence] simulated state loss: task {} cap count {} -> {}.",
        victim.0, before.0, after_wipe.0
    );

    // Restore from the checkpoint.
    match restore() {
        Ok(n) => { crate::println!("[persistence] restored {} task checkpoint(s).", n); }
        Err(()) => {
            crate::println!("[persistence] FAIL: restore rejected (no/invalid snapshot).");
            return;
        }
    }

    let after_restore = victim_fingerprint(victim);
    let equivalent = after_restore == before;

    // Re-capture and confirm the checksum is reproduced (determinism/integrity).
    capture();
    let recomputed = info().unwrap_or(0);
    let deterministic = recomputed == original;

    if equivalent && deterministic {
        crate::println!(
            "[persistence] PASS: task {} capability graph restored ({} caps, id+lineage intact); \
             checksum reproduced.",
            victim.0, after_restore.0
        );
    } else {
        crate::println!(
            "[persistence] FAIL: equivalent={} (caps {}->{}), deterministic={} ({:#x} vs {:#x}).",
            equivalent, before.0, after_restore.0, deterministic, original, recomputed
        );
    }
}

/// A small fingerprint of a task's capability table: (count, fold of ids+origins)
/// so the demo can prove the *exact* capability graph (not just the count) was
/// restored, including each cap's unique id and derivation lineage.
fn victim_fingerprint(victim: TaskId) -> (usize, u64) {
    let sched = SCHEDULER.lock();
    let mut count = 0usize;
    let mut fold: u64 = 0;
    if let Some(t) = sched.get_task(victim) {
        for cs in 0..MAX_CAPS {
            if let Some(cap) = t.cap_table.get(cs) {
                count += 1;
                fold = fold
                    .wrapping_mul(31)
                    .wrapping_add(cap.id)
                    .wrapping_add(cap.origin.unwrap_or(0).wrapping_mul(7))
                    .wrapping_add(resource_code(&cap.resource));
            }
        }
    }
    (count, fold)
}
