// RunixOS capability audit log: security and capability maturity
//
// The kernel keeps a tamper-proof, append-only record of every capability
// grant and revocation. It is *kernel-only*: there is no syscall that exposes
// it to ring-3 tasks (future expansion may add a capability-gated introspection
// service). The log is a fixed-capacity ring buffer so it never allocates and
// never grows without bound: under sustained churn it simply overwrites the
// oldest entries, and `dropped` counts how many were lost.

use crate::process::TaskId;
use crate::process::capability::Resource;
use crate::drivers::serial::Spinlock;

/// The kind of capability lifecycle event being recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditKind {
    /// A capability was delegated from one task to another (SYS_CAP_GRANT).
    Grant,
    /// A capability was forcibly removed from a task (SYS_CAP_REVOKE / kernel).
    Revoke,
    /// A capability was revoked as a downstream consequence of revoking the
    /// capability it was derived from (revocation propagation).
    RevokePropagated,
}

/// A single immutable audit record.
#[derive(Debug, Clone, Copy)]
pub struct AuditEvent {
    pub kind: AuditKind,
    /// The task that initiated the action (granter / revoker), or the kernel
    /// (`TaskId(usize::MAX)`) for kernel-internal actions.
    pub actor: TaskId,
    /// The task whose capability table was affected.
    pub target: TaskId,
    /// The resource the capability refers to.
    pub resource: Resource,
    /// The slot index in the target's table that was written/cleared.
    pub slot: usize,
}

/// Number of events retained before the oldest is overwritten.
pub const AUDIT_CAPACITY: usize = 64;

/// The kernel-only capability audit log.
pub struct AuditLog {
    buffer: [Option<AuditEvent>; AUDIT_CAPACITY],
    /// Index where the next event will be written.
    next: usize,
    /// Total events recorded since boot (may exceed AUDIT_CAPACITY).
    total: usize,
    /// Events overwritten (lost) because the ring wrapped.
    dropped: usize,
}

impl AuditLog {
    pub const fn new() -> Self {
        Self {
            buffer: [None; AUDIT_CAPACITY],
            next: 0,
            total: 0,
            dropped: 0,
        }
    }

    fn push(&mut self, ev: AuditEvent) {
        if self.buffer[self.next].is_some() {
            self.dropped += 1;
        }
        self.buffer[self.next] = Some(ev);
        self.next = (self.next + 1) % AUDIT_CAPACITY;
        self.total += 1;
    }
}

/// The global, kernel-only audit log.
pub static AUDIT_LOG: Spinlock<AuditLog> = Spinlock::new(AuditLog::new());

/// Sentinel actor for kernel-internal capability actions (no ring-3 caller).
pub const KERNEL_ACTOR: TaskId = TaskId(usize::MAX);

/// Records a capability lifecycle event.
pub fn record(kind: AuditKind, actor: TaskId, target: TaskId, resource: Resource, slot: usize) {
    AUDIT_LOG.lock().push(AuditEvent { kind, actor, target, resource, slot });
}

/// Dumps the full audit trail to the serial console. Kernel-only diagnostic.
pub fn dump() {
    let log = AUDIT_LOG.lock();
    crate::println!(
        "[audit] capability trail: {} event(s) recorded, {} dropped (ring capacity {}).",
        log.total, log.dropped, AUDIT_CAPACITY
    );
    // Walk oldest -> newest. When the ring has wrapped, the oldest live entry is
    // at `next`; otherwise entries start at 0.
    let wrapped = log.total > AUDIT_CAPACITY;
    let count = if wrapped { AUDIT_CAPACITY } else { log.total };
    let start = if wrapped { log.next } else { 0 };
    for i in 0..count {
        let idx = (start + i) % AUDIT_CAPACITY;
        if let Some(ev) = log.buffer[idx] {
            if ev.actor == KERNEL_ACTOR {
                crate::println!(
                    "  #{:<3} {:?}: actor=kernel target=task{} slot={} resource={:?}",
                    i, ev.kind, ev.target.0, ev.slot, ev.resource
                );
            } else {
                crate::println!(
                    "  #{:<3} {:?}: actor=task{} target=task{} slot={} resource={:?}",
                    i, ev.kind, ev.actor.0, ev.target.0, ev.slot, ev.resource
                );
            }
        }
    }
}
