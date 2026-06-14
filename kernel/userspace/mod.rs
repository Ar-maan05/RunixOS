// RunixOS user-space support.
//
// Phase 2 has no ELF loader yet, so the demo "user program" is a small
// position-independent code blob assembled into the kernel image. We copy it
// into a fresh user-accessible page and run it in ring 3. It does nothing but
// invoke syscalls (`int 0x80`) in a loop, proving the ring 3 -> ring 0 -> ring 3
// round trip and that the kernel routes user requests.

use crate::memory::{self, FRAME_ALLOCATOR};
use crate::process::{CapTable, Task, TaskId};

// Fixed user-half virtual addresses for the demo task's code and stack. These
// live in the lower half, whose page-table hierarchy the kernel owns and maps
// User-accessible.
const USER_CODE_VADDR: usize = 0x0040_0000;
const USER_STACK_VADDR: usize = 0x007f_f000;
const USER_STACK_TOP: usize = 0x0080_0000;

// Position-independent user program: in a loop, send an IPC message (from its
// own memory, addressed RIP-relative) over capability slot 0, then yield. The
// trailing string is data the loop never executes (it jumps back before
// reaching it).
core::arch::global_asm!(
    ".global user_blob_start",
    ".global user_blob_end",
    "user_blob_start:",
    "2:",
    "    mov rax, 2",          // SYS_SEND
    "    mov rdi, 0",          // capability slot 0 (-> logging service)
    "    lea rsi, [rip + 3f]", // &message (RIP-relative => user vaddr)
    "    mov rdx, 29",         // message length (bytes of the string below)
    "    int 0x80",
    "    mov rax, 1",          // SYS_YIELD
    "    int 0x80",
    "    jmp 2b",
    "3:",
    "    .ascii \"Hello from ring-3 user task 4\"", // exactly 29 bytes
    "user_blob_end:",
);

// Position-independent user-space logging service. In a loop it receives an IPC
// message into a buffer in its own memory, then prints a prefix, the payload,
// and a newline via the capability-gated serial-write syscall. The kernel only
// routes the message and enforces the Serial capability; the service logic lives
// entirely in ring 3.
core::arch::global_asm!(
    ".global logger_blob_start",
    ".global logger_blob_end",
    "logger_blob_start:",
    "5:",
    "    mov rax, 3",           // SYS_RECEIVE
    "    lea rsi, [rip + 8f]",  // &recvbuf
    "    mov rdx, 128",         // capacity
    "    int 0x80",
    "    mov rbx, rax",         // save received length (preserved across syscalls)
    "    mov rax, 4",           // SYS_SERIAL_WRITE (prefix)
    "    mov rdi, 0",           // serial capability slot 0
    "    lea rsi, [rip + 6f]",  // &prefix
    "    mov rdx, 24",          // prefix length
    "    int 0x80",
    "    mov rax, 4",           // SYS_SERIAL_WRITE (payload)
    "    mov rdi, 0",
    "    lea rsi, [rip + 8f]",  // &recvbuf
    "    mov rdx, rbx",         // received length
    "    int 0x80",
    "    mov rax, 4",           // SYS_SERIAL_WRITE (newline)
    "    mov rdi, 0",
    "    lea rsi, [rip + 7f]",  // &newline
    "    mov rdx, 1",
    "    int 0x80",
    "    jmp 5b",
    "6:",
    "    .ascii \"[user-logger] received: \"", // 24 bytes
    "7:",
    "    .ascii \"\\n\"",
    "8:",
    "    .space 128",           // recvbuf (writable, in the code page)
    "logger_blob_end:",
);

extern "C" {
    static user_blob_start: u8;
    static user_blob_end: u8;
    static logger_blob_start: u8;
    static logger_blob_end: u8;
}

/// Builds a fresh address space for a user program: allocates a PML4, maps user
/// code + stack pages into it, copies the program bytes into the code frame (via
/// the HHDM, since that low-half address isn't mapped in the boot space), and
/// returns a ring-3 task bound to that address space.
fn spawn_user(id: TaskId, blob_start: *const u8, blob_end: *const u8, cap_table: CapTable) -> Task {
    let len = blob_end as usize - blob_start as usize;
    let cr3 = unsafe {
        // SAFETY: single-threaded boot; the new address space shares the kernel
        // higher half and owns its own lower half exclusively. Both user tasks
        // can reuse the same virtual addresses precisely because each has its
        // own PML4 (true isolation).
        let cr3 = memory::new_address_space().expect("no frame for user PML4");
        let code_frame = FRAME_ALLOCATOR.allocate_frame().expect("no frame for user code");
        let stack_frame = FRAME_ALLOCATOR.allocate_frame().expect("no frame for user stack");

        memory::map_page_user_into(cr3, USER_CODE_VADDR, code_frame, true).expect("map user code");
        memory::map_page_user_into(cr3, USER_STACK_VADDR, stack_frame, true).expect("map user stack");

        let dst = (code_frame + memory::hhdm_offset()) as *mut u8;
        core::ptr::copy_nonoverlapping(blob_start, dst, len);

        cr3
    };

    Task::new_user(id, USER_CODE_VADDR, USER_STACK_TOP, cr3, cap_table)
}

/// Spawns the ring-3 demo sender task.
pub fn spawn_demo_user_task(id: TaskId, cap_table: CapTable) -> Task {
    spawn_user(id, &raw const user_blob_start, &raw const user_blob_end, cap_table)
}

/// Spawns the ring-3 logging service.
pub fn spawn_logger_task(id: TaskId, cap_table: CapTable) -> Task {
    spawn_user(id, &raw const logger_blob_start, &raw const logger_blob_end, cap_table)
}
