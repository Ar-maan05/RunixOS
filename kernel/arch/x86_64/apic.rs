// RunixOS Local APIC Driver.
//
// Implements core enable/disable, LAPIC ID lookup, and Inter-Processor
// Interrupt (IPI) sending for Symmetric Multiprocessing (SMP) core wakeup.

use core::sync::atomic::{AtomicU64, Ordering};

pub static IPI_ACK_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub struct Lapic {
    base: *mut u32,
}

impl Lapic {
    pub unsafe fn read(&self, reg: usize) -> u32 {
        core::ptr::read_volatile(self.base.add(reg / 4))
    }

    pub unsafe fn write(&self, reg: usize, val: u32) {
        core::ptr::write_volatile(self.base.add(reg / 4), val);
    }
}

/// Returns the virtual address mapping of the LAPIC registers.
pub unsafe fn lapic_base() -> Lapic {
    let offset = crate::memory::hhdm_offset();
    Lapic { base: (0xFEE00000 + offset) as *mut u32 }
}

/// Enables the Local APIC software enable bit (SVR offset 0xF0, bit 8).
pub unsafe fn enable_lapic() {
    let lapic = lapic_base();
    let svr = lapic.read(0xF0);
    // Set bit 8 (Software Enable) and a spurious vector of 0xFF
    lapic.write(0xF0, svr | (1 << 8) | 0xFF);
}

/// Returns the LAPIC ID of the calling processor.
pub unsafe fn lapic_id() -> u32 {
    let lapic = lapic_base();
    // LAPIC ID register is at offset 0x20, high byte contains the ID in xAPIC mode
    lapic.read(0x20) >> 24
}

/// Sends an IPI to a target Local APIC.
pub unsafe fn send_ipi(dest_lapic_id: u32, vector: u8) {
    let lapic = lapic_base();
    // Wait for any previous send to complete (Delivery Status bit 12 of ICR low)
    while (lapic.read(0x300) & (1 << 12)) != 0 {
        core::hint::spin_loop();
    }
    // Write destination to ICR high (bits 24-31)
    lapic.write(0x310, dest_lapic_id << 24);
    // Write command to ICR low: Fixed delivery (0), Physical dest (0), Assert (1 << 14), Edge trigger (0), specified vector
    lapic.write(0x300, (vector as u32) | (1 << 14));
}

/// Handler function invoked when an IPI is received on an AP.
pub fn handle_ipi() {
    IPI_ACK_COUNT.fetch_add(1, Ordering::SeqCst);
}
