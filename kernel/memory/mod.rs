// RunixOS memory management subsystem
use crate::println;
use limine::request::{HhdmRequest, MemmapRequest};
use limine::memmap::MEMMAP_USABLE;

#[used]
#[unsafe(link_section = ".requests")]
pub static MEMMAP_REQUEST: MemmapRequest = MemmapRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
pub static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

/// A simple page frame allocator utilizing the UEFI memory map from Limine.
pub struct FrameAllocator {
    next_free_paddr: usize,
    usable_end: usize,
}

impl FrameAllocator {
    pub const fn new() -> Self {
        Self {
            next_free_paddr: 0,
            usable_end: 0,
        }
    }

    /// Initializes the physical frame allocator using the largest conventional memory block.
    pub fn init(&mut self) {
        let mmap_response = MEMMAP_REQUEST.response();
        if let Some(mmap) = mmap_response {
            println!("Memory Map Entries:");
            for entry in mmap.entries() {
                println!(
                    "  Base: {:#x}, Length: {:#x}, Type: {}",
                    entry.base, entry.length, entry.type_
                );
                // Track usable conventional memory
                if entry.type_ == MEMMAP_USABLE {
                    let start = entry.base as usize;
                    let end = (entry.base + entry.length) as usize;
                    if end - start > self.usable_end - self.next_free_paddr {
                        // Align to 4 KiB boundaries
                        self.next_free_paddr = (start + 0xfff) & !0xfff;
                        self.usable_end = end & !0xfff;
                    }
                }
            }
            println!(
                "Frame Allocator initialized. Usable start: {:#x}, end: {:#x}",
                self.next_free_paddr, self.usable_end
            );
        } else {
            println!("ERROR: Memory map request failed!");
        }
    }

    /// Allocates a 4 KiB page frame from physical memory.
    pub fn allocate_frame(&mut self) -> Option<usize> {
        if self.next_free_paddr + 4096 <= self.usable_end {
            let paddr = self.next_free_paddr;
            self.next_free_paddr += 4096;
            Some(paddr)
        } else {
            None
        }
    }
}

/// Global physical frame allocator instance.
pub static mut FRAME_ALLOCATOR: FrameAllocator = FrameAllocator::new();

/// Maps a virtual page to a physical frame by traversing the 4-level page tables.
///
/// # Safety
/// This function is unsafe because editing page tables alters hardware virtual memory mapping,
/// which can cause general protection faults if incorrectly mapped.
pub unsafe fn map_page(vaddr: usize, paddr: usize, writeable: bool) -> Result<(), ()> {
    let hhdm = HHDM_REQUEST.response().map(|r| r.offset as usize).ok_or(())?;

    // Query active PML4 table from CR3 register
    let cr3: u64;
    unsafe {
        // SAFETY:
        // - Why necessary: Inline assembly to read the CR3 control register.
        // - Invariants: Valid CPU execution state.
        // - Soundness: Simply reads the current paging directory base register.
        core::arch::asm!("mov {}, cr3", out(reg) cr3);
    }
    let pml4_paddr = (cr3 & 0x000ffffffffff000) as usize;
    let pml4 = (pml4_paddr + hhdm) as *mut u64;

    let pml4_idx = (vaddr >> 39) & 0x1ff;
    let pdpt_idx = (vaddr >> 30) & 0x1ff;
    let pd_idx = (vaddr >> 21) & 0x1ff;
    let pt_idx = (vaddr >> 12) & 0x1ff;

    // Traverse levels and allocate tables as needed
    let pdpt_paddr = unsafe { get_or_create_table(pml4, pml4_idx, hhdm)? };
    let pdpt = (pdpt_paddr + hhdm) as *mut u64;

    let pd_paddr = unsafe { get_or_create_table(pdpt, pdpt_idx, hhdm)? };
    let pd = (pd_paddr + hhdm) as *mut u64;

    let pt_paddr = unsafe { get_or_create_table(pd, pd_idx, hhdm)? };
    let pt = (pt_paddr + hhdm) as *mut u64;

    // Set page table entry: Present (0x1) + Writeable (0x2 if writeable)
    let page_flags = 0x1 | (if writeable { 0x2 } else { 0x0 });
    unsafe {
        // SAFETY:
        // - Why necessary: Writing directly into page table memory.
        // - Invariants: Table pointer must be valid and index within bounds.
        // - Soundness: We safely allocate intermediate tables and resolve virtual addresses.
        *pt.add(pt_idx) = (paddr as u64 & 0x000ffffffffff000) | page_flags;
    }

    // Flush the translation lookaside buffer (TLB) for this page address
    unsafe {
        // SAFETY:
        // - Why necessary: Assembly instruction to flush TLB entry.
        // - Invariants: None.
        // - Soundness: Required to ensure the CPU registers the updated page mapping immediately.
        core::arch::asm!("invlpg [{}]", in(reg) vaddr);
    }

    Ok(())
}

/// Returns the HHDM (higher-half direct map) offset Limine established, used to
/// reach physical frames through kernel virtual addresses.
pub fn hhdm_offset() -> usize {
    HHDM_REQUEST.response().map(|r| r.offset as usize).unwrap_or(0)
}

/// Physical base address of the currently active PML4 (from CR3).
pub fn current_pml4_paddr() -> usize {
    let cr3: u64;
    unsafe {
        // SAFETY: reading CR3 has no side effects.
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    (cr3 & 0x000ffffffffff000) as usize
}

/// Creates a fresh address space: allocates a new PML4 and copies the kernel's
/// higher-half mappings (entries 256..512) from the active PML4 so the kernel
/// stays mapped when a process using this address space runs. The lower half is
/// left empty for per-process user mappings.
///
/// Returns the new PML4's physical address.
///
/// # Safety
/// Allocates and writes page-table memory; the caller must use the result only
/// as a process address space.
pub unsafe fn new_address_space() -> Option<usize> {
    let hhdm = hhdm_offset();
    let new_pml4_paddr = unsafe { FRAME_ALLOCATOR.allocate_frame()? };
    let new_pml4 = (new_pml4_paddr + hhdm) as *mut u64;
    let cur_pml4 = (current_pml4_paddr() + hhdm) as *const u64;

    unsafe {
        core::ptr::write_bytes(new_pml4 as *mut u8, 0, 4096);
        // Share the kernel's higher half (code, stacks, HHDM, GDT/IDT/TSS).
        for i in 256..512 {
            *new_pml4.add(i) = *cur_pml4.add(i);
        }
    }
    Some(new_pml4_paddr)
}

/// Switches the active address space by loading `pml4_paddr` into CR3 (a no-op
/// if it is already active). Safe because every address space shares the kernel
/// higher half, so the currently executing kernel code and stack stay mapped.
pub fn switch_address_space(pml4_paddr: usize) {
    if pml4_paddr == current_pml4_paddr() {
        return;
    }
    unsafe {
        // SAFETY: `pml4_paddr` roots a valid address space that includes the
        // kernel higher half (code + current stack), so execution continues
        // uninterrupted after the load.
        core::arch::asm!("mov cr3, {}", in(reg) pml4_paddr as u64, options(nostack, preserves_flags));
    }
}

/// Maps a user-accessible page into the *currently active* address space.
///
/// # Safety
/// See [`map_page_user_into`].
pub unsafe fn map_page_user(vaddr: usize, paddr: usize, writeable: bool) -> Result<(), ()> {
    unsafe { map_page_user_into(current_pml4_paddr(), vaddr, paddr, writeable) }
}

/// Maps a virtual page to a physical frame with the User-accessible (US) bit set
/// at every level, into the address space rooted at `pml4_paddr`.
///
/// # Safety
/// Editing page tables alters hardware virtual memory mapping; an incorrect
/// mapping can fault. Intended for fresh user-half virtual addresses whose
/// page-table hierarchy this kernel owns exclusively.
pub unsafe fn map_page_user_into(
    pml4_paddr: usize,
    vaddr: usize,
    paddr: usize,
    writeable: bool,
) -> Result<(), ()> {
    let hhdm = HHDM_REQUEST.response().map(|r| r.offset as usize).ok_or(())?;

    let pml4 = (pml4_paddr + hhdm) as *mut u64;

    let pml4_idx = (vaddr >> 39) & 0x1ff;
    let pdpt_idx = (vaddr >> 30) & 0x1ff;
    let pd_idx = (vaddr >> 21) & 0x1ff;
    let pt_idx = (vaddr >> 12) & 0x1ff;

    let pdpt = (unsafe { get_or_create_table_user(pml4, pml4_idx, hhdm)? } + hhdm) as *mut u64;
    let pd = (unsafe { get_or_create_table_user(pdpt, pdpt_idx, hhdm)? } + hhdm) as *mut u64;
    let pt = (unsafe { get_or_create_table_user(pd, pd_idx, hhdm)? } + hhdm) as *mut u64;

    // Present (0x1) + User (0x4) + Writeable (0x2 if requested).
    let flags = 0x1 | 0x4 | (if writeable { 0x2 } else { 0x0 });
    unsafe {
        // SAFETY: leaf table pointer is valid and `pt_idx` is bounded to 0-511.
        *pt.add(pt_idx) = (paddr as u64 & 0x000ffffffffff000) | flags;
        core::arch::asm!("invlpg [{}]", in(reg) vaddr);
    }

    Ok(())
}

/// Like `get_or_create_table` but marks intermediate tables User-accessible.
unsafe fn get_or_create_table_user(table: *mut u64, idx: usize, hhdm: usize) -> Result<usize, ()> {
    let entry = unsafe { *table.add(idx) };
    if (entry & 0x1) == 0 {
        let new_table_paddr = unsafe { FRAME_ALLOCATOR.allocate_frame().ok_or(())? };
        let new_table_vaddr = (new_table_paddr + hhdm) as *mut u8;
        unsafe {
            // SAFETY: freshly allocated frame, owned exclusively here.
            core::ptr::write_bytes(new_table_vaddr, 0, 4096);
            // Present + Writeable + User so ring-3 walks succeed at this level.
            *table.add(idx) = new_table_paddr as u64 | 0x7;
        }
        Ok(new_table_paddr)
    } else {
        // Ensure an existing intermediate table is User-accessible too.
        unsafe {
            *table.add(idx) = entry | 0x4;
        }
        Ok((entry & 0x000ffffffffff000) as usize)
    }
}

/// Helper function to traverse page table entry or allocate a new lower-level table page.
unsafe fn get_or_create_table(table: *mut u64, idx: usize, hhdm: usize) -> Result<usize, ()> {
    let entry = unsafe {
        // SAFETY:
        // - Why necessary: Reading raw page table entry.
        // - Invariants: Pointer must point to valid table.
        // - Soundness: Index is bounded to 0-511 by bitmask index extraction.
        *table.add(idx)
    };

    if (entry & 0x1) == 0 {
        // Table does not exist, allocate page frame
        let new_table_paddr = unsafe { FRAME_ALLOCATOR.allocate_frame().ok_or(())? };
        let new_table_vaddr = (new_table_paddr + hhdm) as *mut u8;

        // Clear the newly allocated page
        unsafe {
            // SAFETY:
            // - Why necessary: Overwriting memory region bytes.
            // - Invariants: Allocated page frame is exclusive to this allocator caller.
            // - Soundness: Clears page entries to zero (defaults to not present).
            core::ptr::write_bytes(new_table_vaddr, 0, 4096);
        }

        // Write entry to parent table: Present (0x1) + Writeable (0x2)
        unsafe {
            // SAFETY:
            // - Why necessary: Modifying raw parent page table entry.
            // - Invariants: Pointer is bounded and correct.
            // - Soundness: Links parent table entry to newly allocated lower-level page.
            *table.add(idx) = new_table_paddr as u64 | 0x3;
        }

        Ok(new_table_paddr)
    } else {
        Ok((entry & 0x000ffffffffff000) as usize)
    }
}

/// The inclusive upper bound of canonical user-space lower half in x86_64.
const USER_SPACE_UPPER_BOUND: usize = 0x0000_7FFF_FFFF_FFFFusize;

/// Validates that the virtual address range `[ptr, ptr + len)` is mapped,
/// user-accessible (U/S bit set at all levels), and writeable (if `writeable` is true).
/// Returns `Ok(())` if fully valid, otherwise `Err(())`.
pub fn validate_user_range(ptr: *const u8, len: usize, writeable: bool) -> Result<(), ()> {
    if len == 0 {
        return Ok(());
    }

    let start = ptr as usize;
    let end = match start.checked_add(len) {
        Some(e) => e,
        None => return Err(()), // overflow
    };

    if end > USER_SPACE_UPPER_BOUND + 1 {
        return Err(());
    }

    let hhdm = hhdm_offset();
    let pml4_paddr = current_pml4_paddr();

    let start_page = start & !0xfff;
    let end_page = (end - 1) & !0xfff;

    let mut vaddr = start_page;
    loop {
        let pml4 = (pml4_paddr + hhdm) as *const u64;
        let pml4_idx = (vaddr >> 39) & 0x1ff;
        let pml4_entry = unsafe { *pml4.add(pml4_idx) };
        if (pml4_entry & 0x1) == 0 || (pml4_entry & 0x4) == 0 {
            return Err(());
        }
        if writeable && (pml4_entry & 0x2) == 0 {
            return Err(());
        }

        let pdpt_paddr = (pml4_entry & 0x000ffffffffff000) as usize;
        let pdpt = (pdpt_paddr + hhdm) as *const u64;
        let pdpt_idx = (vaddr >> 30) & 0x1ff;
        let pdpt_entry = unsafe { *pdpt.add(pdpt_idx) };
        if (pdpt_entry & 0x1) == 0 || (pdpt_entry & 0x4) == 0 {
            return Err(());
        }
        if writeable && (pdpt_entry & 0x2) == 0 {
            return Err(());
        }

        let pd_paddr = (pdpt_entry & 0x000ffffffffff000) as usize;
        let pd = (pd_paddr + hhdm) as *const u64;
        let pd_idx = (vaddr >> 21) & 0x1ff;
        let pd_entry = unsafe { *pd.add(pd_idx) };
        if (pd_entry & 0x1) == 0 || (pd_entry & 0x4) == 0 {
            return Err(());
        }
        if writeable && (pd_entry & 0x2) == 0 {
            return Err(());
        }

        let pt_paddr = (pd_entry & 0x000ffffffffff000) as usize;
        let pt = (pt_paddr + hhdm) as *const u64;
        let pt_idx = (vaddr >> 12) & 0x1ff;
        let pt_entry = unsafe { *pt.add(pt_idx) };
        if (pt_entry & 0x1) == 0 || (pt_entry & 0x4) == 0 {
            return Err(());
        }
        if writeable && (pt_entry & 0x2) == 0 {
            return Err(());
        }

        if vaddr == end_page {
            break;
        }
        vaddr += 4096;
    }

    Ok(())
}

