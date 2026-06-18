// RunixOS Global Descriptor Table + Task State Segment.
//
// Limine hands us a usable GDT, but to run code in ring 3 and to take
// interrupts/syscalls back into ring 0 we need our own descriptors:
//   - kernel code/data (ring 0)
//   - user code/data (ring 3)
//   - a TSS providing rsp0, the kernel stack the CPU loads on a privilege
//     transition from ring 3 to ring 0.

use crate::println;

// Segment selectors (index << 3 | RPL).
pub const KERNEL_CODE: u16 = 0x08;
pub const KERNEL_DATA: u16 = 0x10;
pub const USER_CODE: u16 = 0x18 | 3; // RPL 3
pub const USER_DATA: u16 = 0x20 | 3; // RPL 3
pub const TSS_SELECTOR: u16 = 0x28;

/// 64-bit Task State Segment. Only `rsp0` and `iomap_base` matter for us.
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Tss {
    reserved0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

impl Tss {
    const fn new() -> Self {
        Self {
            reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            reserved1: 0,
            ist: [0; 7],
            reserved2: 0,
            reserved3: 0,
            iomap_base: core::mem::size_of::<Tss>() as u16, // no I/O bitmap
        }
    }
}

static mut TSSS: [Tss; 4] = [Tss::new(); 4];
pub static mut GDTS: [[u64; GDT_LEN]; 4] = [[0; GDT_LEN]; 4];
const KSTACK_SIZE: usize = 16 * 1024;
static mut KERNEL_STACKS: [[u8; KSTACK_SIZE]; 4] = [[0; KSTACK_SIZE]; 4];

pub fn get_tss_address() -> *const () {
    unsafe { &raw const TSSS[0] as *const () }
}

const GDT_LEN: usize = 7;
pub static mut GDT: [u64; GDT_LEN] = [0; GDT_LEN];

#[repr(C, packed)]
struct GdtPointer {
    limit: u16,
    base: u64,
}

const fn segment(access: u8, flags: u8) -> u64 {
    ((access as u64) << 40) | (((flags & 0x0f) as u64) << 52)
}

pub fn init() {
    init_cpu(0);
}

pub fn init_cpu(cpu_id: usize) {
    let tss_base = unsafe { &raw const TSSS[cpu_id] as u64 };
    let tss_limit = (core::mem::size_of::<Tss>() - 1) as u64;

    unsafe {
        let gdt = &raw mut GDTS[cpu_id];
        // Kernel code (DPL0, exec/read, long mode L bit) and data.
        (*gdt)[1] = segment(0x9a, 0x2);
        (*gdt)[2] = segment(0x92, 0x0);
        // User code (DPL3) and data.
        (*gdt)[3] = segment(0xfa, 0x2);
        (*gdt)[4] = segment(0xf2, 0x0);
        // TSS descriptor (system segment, occupies two GDT slots).
        (*gdt)[5] = (tss_limit & 0xffff)
            | ((tss_base & 0xffff) << 16)
            | (((tss_base >> 16) & 0xff) << 32)
            | (0x89u64 << 40) // present, 64-bit available TSS
            | (((tss_limit >> 16) & 0xf) << 48)
            | (((tss_base >> 24) & 0xff) << 56);
        (*gdt)[6] = (tss_base >> 32) & 0xffff_ffff;

        // Initialise rsp0 to the dedicated kernel stack top (16-byte aligned).
        let kstack_top = (&raw const KERNEL_STACKS[cpu_id]) as u64 + KSTACK_SIZE as u64;
        (*(&raw mut TSSS[cpu_id])).rsp0 = kstack_top & !0xf;

        if cpu_id == 0 {
            GDT = GDTS[0];
        }
    }

    let ptr = GdtPointer {
        limit: (core::mem::size_of::<[u64; GDT_LEN]>() - 1) as u16,
        base: unsafe { &raw const GDTS[cpu_id] as u64 },
    };

    unsafe {
        core::arch::asm!(
            "lgdt [{ptr}]",
            // Reload data segment registers.
            "mov ax, {kdata:x}",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "mov fs, ax",
            "mov gs, ax",
            // Reload CS via a far return to a local label.
            "lea rax, [rip + 2f]",
            "push {kcode}",
            "push rax",
            "retfq",
            "2:",
            // Load the task register with the TSS selector.
            "mov ax, {tss:x}",
            "ltr ax",
            ptr = in(reg) &ptr,
            kdata = in(reg) KERNEL_DATA as u64,
            kcode = in(reg) KERNEL_CODE as u64,
            tss = in(reg) TSS_SELECTOR as u64,
            out("rax") _,
            options(preserves_flags),
        );
    }

    if cpu_id == 0 {
        println!("GDT + TSS installed (kernel & user segments active).");
    }
}

pub fn set_kernel_stack(rsp: u64) {
    unsafe {
        (*(&raw mut TSSS[0])).rsp0 = rsp;
    }
}
