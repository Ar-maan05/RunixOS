// RunixOS capability system -- Phase 3: sealing, rights attenuation, grant
//
// Phase 3 additions over Phase 2:
//   - `sealed` flag: a sealed capability cannot be removed by the holder;
//     only the kernel (at task-creation time, or via a future revocation API)
//     can clear it.  Prevents a task from discarding a mandatory obligation.
//   - Rights attenuation on grant: `Capability::attenuate` returns a derived
//     capability whose rights are the *intersection* of the donor's rights and
//     the requested rights.  You cannot grant more authority than you hold.
//   - `CapTable::grant_to` copies an attenuated capability into another task's
//     table in one atomic step, enforcing the grant-right check.
use crate::process::TaskId;
use core::sync::atomic::{AtomicU64, Ordering};

/// Monotonic source of globally-unique capability identities. Every capability
/// installed into a slot is stamped with a fresh `id` from here, so identity is
/// never recycled even when a *slot index* is reused. Lineage (`origin`) and
/// revocation propagation key off this id rather than `(task, slot)`, which
/// would alias across slot reuse. `0` is reserved as "unassigned".
static NEXT_CAP_ID: AtomicU64 = AtomicU64::new(1);

fn next_cap_id() -> u64 {
    NEXT_CAP_ID.fetch_add(1, Ordering::SeqCst)
}

/// Represents a system resource guarded by the capability system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    /// Permission to write to the serial port.
    Serial,
    /// Permission to send IPC messages to a specific target task.
    IpcChannel { target_task: TaskId },
    /// Permission to access a virtual memory mapping.
    MemoryMapping { start_vaddr: usize, size: usize, writeable: bool },
    /// Phase 10: a *location-independent* reference to a service by id. Unlike
    /// `IpcChannel`, which names a concrete local task, this names a service that
    /// the distribution layer may resolve to a local task or a remote node -- and
    /// that resolution can change (migration) without invalidating the holder's
    /// capability. This is what makes a capability "identify a service rather
    /// than a physical machine location".
    Service { id: usize },
}

/// A capability represents a bundle of access rights to a resource.
///
/// Phase 3 adds two new fields:
/// - `grant`: the holder may delegate this capability (with equal or lesser
///   rights) to another task via `SYS_CAP_GRANT`.
/// - `sealed`: the kernel (or the granting entity) may lock the slot so the
///   holder cannot `remove` it.  Sealing is one-way: once set, only a kernel-
///   level revocation (future Phase 4) can clear it.
#[derive(Debug, Clone, Copy)]
pub struct Capability {
    pub resource: Resource,
    pub read:  bool,
    pub write: bool,
    /// If true, the holder may delegate this capability to another task.
    pub grant: bool,
    /// If true, the holder cannot remove this slot from their own table.
    /// Set by the kernel when handing the cap to a task, or propagated from
    /// the donor's sealed flag on a grant.
    pub sealed: bool,
    /// Globally-unique identity, stamped by `CapTable::insert` from
    /// [`next_cap_id`]. `0` means "not yet installed in a slot".
    pub id: u64,
    /// Derivation lineage (Phase 8): if this capability was produced by granting
    /// from another capability, `origin` is that donor capability's `id`.
    /// Root capabilities the kernel mints directly have `origin = None`.
    /// Revocation propagation follows these ids; because ids are never recycled,
    /// it cannot mis-target a derived capability after a slot index is reused.
    pub origin: Option<u64>,
}

impl Capability {
    /// Returns a derived capability with rights clamped to *at most* the
    /// rights expressed in `requested`.  This enforces rights attenuation:
    /// a task cannot grant more authority than it currently holds.
    ///
    /// Returns `Err(())` if the holder lacks the `grant` right.
    pub fn attenuate(&self, requested: RightsMask) -> Result<Capability, ()> {
        if !self.grant {
            return Err(());
        }
        Ok(Capability {
            resource: self.resource,
            read:   self.read  && requested.read,
            write:  self.write && requested.write,
            // The grantee never inherits the grant right unless explicitly
            // requested *and* the donor has it (already checked above).
            grant:  self.grant && requested.grant,
            // Sealed-ness is never inherited through grant -- the recipient
            // gets an unsealed copy; the kernel seals at task-creation time.
            sealed: false,
            // Identity is assigned when the cap is installed into a slot.
            id: 0,
            // Lineage is stamped by the granting kernel path (it knows the
            // donor capability's id); `attenuate` alone leaves it unset.
            origin: None,
        })
    }
}

/// A bitmask of requested rights, used as the argument to `attenuate`.
#[derive(Debug, Clone, Copy)]
pub struct RightsMask {
    pub read:  bool,
    pub write: bool,
    pub grant: bool,
}

pub const MAX_CAPS: usize = 16;

/// Fixed-size capability table for a task, avoiding dynamic allocation.
#[derive(Clone, Copy)]
pub struct CapTable {
    pub slots: [Option<Capability>; MAX_CAPS],
}

impl CapTable {
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_CAPS],
        }
    }

    /// Inserts a capability into the first free slot, stamping it with a fresh
    /// globally-unique identity. Returns the slot index on success.
    pub fn insert(&mut self, mut cap: Capability) -> Result<usize, ()> {
        cap.id = next_cap_id();
        for (idx, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(cap);
                return Ok(idx);
            }
        }
        Err(())
    }

    /// Inserts a capability and immediately seals the slot.
    /// Used by the kernel when constructing a task's initial authority set.
    pub fn insert_sealed(&mut self, mut cap: Capability) -> Result<usize, ()> {
        cap.sealed = true;
        self.insert(cap)
    }

    /// Retrieves a capability reference by index.
    pub fn get(&self, idx: usize) -> Option<&Capability> {
        if idx < MAX_CAPS {
            self.slots[idx].as_ref()
        } else {
            None
        }
    }

    /// Revokes/removes a capability by index.
    ///
    /// Returns `Err(())` if the slot is **sealed** -- sealed capabilities can
    /// only be revoked by the kernel through its own revocation path (Phase 4).
    pub fn remove(&mut self, idx: usize) -> Result<Option<Capability>, ()> {
        if idx >= MAX_CAPS {
            return Ok(None);
        }
        if let Some(ref cap) = self.slots[idx] {
            if cap.sealed {
                return Err(()); // sealed: holder cannot remove
            }
        }
        Ok(self.slots[idx].take())
    }

    /// Kernel-level forced revocation: removes regardless of sealed flag.
    /// Only the kernel calls this (from fault handlers / Phase 4 revocation).
    pub fn kernel_revoke(&mut self, idx: usize) -> Option<Capability> {
        if idx < MAX_CAPS {
            self.slots[idx].take()
        } else {
            None
        }
    }
}
