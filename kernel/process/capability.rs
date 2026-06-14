// RunixOS capability system
use crate::process::TaskId;

/// Represents a system resource guarded by the capability system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    /// Permission to write to the serial port.
    Serial,
    /// Permission to send IPC messages to a specific target task.
    IpcChannel { target_task: TaskId },
    /// Permission to access a virtual memory mapping.
    MemoryMapping { start_vaddr: usize, size: usize, writeable: bool },
}

/// A capability represents a bundle of access rights to a resource.
#[derive(Debug, Clone, Copy)]
pub struct Capability {
    pub resource: Resource,
    pub read: bool,
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

    /// Inserts a capability into the first free slot.
    pub fn insert(&mut self, cap: Capability) -> Result<usize, ()> {
        for (idx, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(cap);
                return Ok(idx);
            }
        }
        Err(())
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
    pub fn remove(&mut self, idx: usize) -> Option<Capability> {
        if idx < MAX_CAPS {
            self.slots[idx].take()
        } else {
            None
        }
    }
}
