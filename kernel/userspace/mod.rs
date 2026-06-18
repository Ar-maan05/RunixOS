// RunixOS user-space support.
//
// The system has no ELF loader yet, so the demo user program is a small
// position-independent code blob assembled into the kernel image. We copy it
// into a fresh user-accessible page and run it as a ring-3 task. It does nothing but
// invoke syscalls (`int 0x80`) in a loop, proving the ring-3 task to ring-0 kernel to ring-3 task
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
    "    // Send to logging service (slot 0)",
    "    mov rax, 2",          // SYS_SEND
    "    mov rdi, 0",          // slot 0
    "    lea rsi, [rip + 3f]", // message
    "    mov rdx, 29",
    "    int 0x80",
    "    // Send to ramfs service (slot 1)",
    "    mov rax, 2",          // SYS_SEND
    "    mov rdi, 1",          // slot 1
    "    lea rsi, [rip + 4f]", // message
    "    mov rdx, 23",
    "    int 0x80",
    "    mov rax, 1",          // SYS_YIELD
    "    int 0x80",
    "    jmp 2b",
    "3:",
    "    .ascii \"Hello from ring-3 user task 4\"", // 29 bytes
    "4:",
    "    .ascii \"write /data/sensor.log\"", // 23 bytes
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

core::arch::global_asm!(
    ".global faulty_user_blob_start",
    ".global faulty_user_blob_end",
    "faulty_user_blob_start:",
    "    // 1. Write to serial using capability slot 0 (should succeed initially)",
    "    mov rax, 4",              // SYS_SERIAL_WRITE
    "    mov rdi, 0",              // slot 0
    "    lea rsi, [rip + 10f]",    // msg_ok
    "    mov rdx, 27",             // len
    "    int 0x80",
    "",
    "    // 2. Yield to let Task 5 run and revoke our Serial capability",
    "    mov rax, 1",              // SYS_YIELD
    "    int 0x80",
    "",
    "    // 3. Try writing again (should fail because slot 0 was revoked)",
    "    mov rax, 4",              // SYS_SERIAL_WRITE
    "    mov rdi, 0",
    "    lea rsi, [rip + 10f]",
    "    mov rdx, 27",
    "    int 0x80",
    "    mov rbx, 0xffffffffffffffff",
    "    cmp rax, rbx",
    "    jne 9f",
    "",
    "    // 4. Test user-pointer validation: pass a kernel pointer",
    "    mov rax, 4",
    "    mov rdi, 0",
    "    mov rsi, 0xffffffff80000000",
    "    mov rdx, 10",
    "    int 0x80",
    "    mov rbx, 0xffffffffffffffff",
    "    cmp rax, rbx",
    "    jne 9f",
    "",
    "    // 5. Trigger page fault by reading from unmapped user address",
    "    mov rax, 0x12345678",
    "    mov rbx, [rax]",          // triggers #PF
    "    jmp 9f",
    "",
    "9:",
    "    // Loop forever if unexpected behavior or after page fault",
    "    mov rax, 1",              // SYS_YIELD
    "    int 0x80",
    "    jmp 9b",
    "",
    "10:",
    "    .ascii \"[Task 6] Serial is active.\\n\"", // 27 bytes
    "faulty_user_blob_end:",
);

extern "C" {
    static user_blob_start: u8;
    static user_blob_end: u8;
    static logger_blob_start: u8;
    static logger_blob_end: u8;
    static faulty_user_blob_start: u8;
    static faulty_user_blob_end: u8;
}

/// Builds a fresh address space for a user program: allocates a PML4, maps user
/// code + stack pages into it, copies the program bytes into the code frame (via
/// the HHDM, since that low-half address isn't mapped in the boot space), and
/// returns a ring-3 task bound to that address space.
fn spawn_user(id: TaskId, blob_start: *const u8, blob_end: *const u8, cap_table: CapTable) -> Task {
    let len = blob_end as usize - blob_start as usize;
    crate::dbg_println!("[kernel] spawn_user: task {}, len={}, blob_start={:p}", id.0, len, blob_start);
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

/// Spawns the faulty user task that tests isolation, revocation, and validation.
pub fn spawn_faulty_user_task(id: TaskId, cap_table: CapTable) -> Task {
    spawn_user(id, &raw const faulty_user_blob_start, &raw const faulty_user_blob_end, cap_table)
}

// Position-independent async sender user task.
// Tries to asynchronously send a Sensor message to Task 8.
// If successful, prints a success message. If it gets QueueFull, it yields.
core::arch::global_asm!(
    ".global async_sender_blob_start",
    ".global async_sender_blob_end",
    "async_sender_blob_start:",
    "1:",
    "    mov rax, 8",          // SYS_SEND_ASYNC
    "    mov rdi, 0",          // capability slot 0 (IPC to Task 8)
    "    lea rsi, [rip + 3f]", // payload
    "    mov rdx, 0x00010002", // tag=Sensor(2) (lower 16 bits) and version=1 (upper 16 bits)
    "    mov r8, 19",          // length (exact string is 19 bytes)
    "    int 0x80",
    "    // check if QueueFull (u64::MAX - 7 = 0xfffffffffffffff8)",
    "    mov rbx, 0xfffffffffffffff8",
    "    cmp rax, rbx",
    "    je 2f",
    "    // success: print message via serial using slot 1",
    "    mov rax, 4",          // SYS_SERIAL_WRITE
    "    mov rdi, 1",          // slot 1 (Serial)
    "    lea rsi, [rip + 4f]",
    "    mov rdx, 28",         // length (exact string is 28 bytes)
    "    int 0x80",
    "2:",
    "    mov rax, 1",          // SYS_YIELD
    "    int 0x80",
    "    jmp 1b",
    "3:",
    "    .ascii \"Async Sensor Msg #1\"", // 19 bytes
    "4:",
    "    .ascii \"[Task 7] Async send success\\n\"", // 28 bytes
    "async_sender_blob_end:",
);

// Position-independent async receiver user task.
// Tries to asynchronously receive messages and prints them.
core::arch::global_asm!(
    ".global async_receiver_blob_start",
    ".global async_receiver_blob_end",
    "async_receiver_blob_start:",
    "1:",
    "    mov rax, 9",          // SYS_RECEIVE_ASYNC
    "    lea rsi, [rip + 4f]", // recvbuf
    "    mov rdx, 128",        // capacity
    "    int 0x80",
    "    // check if NoMessage (u64::MAX - 8 = 0xfffffffffffffff7)",
    "    mov rbx, 0xfffffffffffffff7",
    "    cmp rax, rbx",
    "    je 2f",
    "    // success: save length in rbx",
    "    mov rbx, rax",
    "    // print prefix using slot 0",
    "    mov rax, 4",          // SYS_SERIAL_WRITE
    "    mov rdi, 0",          // slot 0 (Serial)
    "    lea rsi, [rip + 3f]",
    "    mov rdx, 25",         // length (exact string is 25 bytes)
    "    int 0x80",
    "    // print payload",
    "    mov rax, 4",
    "    mov rdi, 0",
    "    lea rsi, [rip + 4f]",
    "    mov rdx, rbx",
    "    int 0x80",
    "    // print newline",
    "    mov rax, 4",
    "    mov rdi, 0",
    "    lea rsi, [rip + 5f]",
    "    mov rdx, 1",
    "    int 0x80",
    "2:",
    "    mov rax, 1",          // SYS_YIELD
    "    int 0x80",
    "    jmp 1b",
    "3:",
    "    .ascii \"[Task 8] Async received: \"", // 25 bytes
    "4:",
    "    .space 128",          // recvbuf
    "5:",
    "    .ascii \"\\n\"",
    "async_receiver_blob_end:",
);

extern "C" {
    static async_sender_blob_start: u8;
    static async_sender_blob_end: u8;
    static async_receiver_blob_start: u8;
    static async_receiver_blob_end: u8;
}

pub fn spawn_async_sender_task(id: TaskId, cap_table: CapTable) -> Task {
    spawn_user(id, &raw const async_sender_blob_start, &raw const async_sender_blob_end, cap_table)
}

pub fn spawn_async_receiver_task(id: TaskId, cap_table: CapTable) -> Task {
    spawn_user(id, &raw const async_receiver_blob_start, &raw const async_receiver_blob_end, cap_table)
}

// Position-independent RAM filesystem service.
core::arch::global_asm!(
    ".global ramfs_blob_start",
    ".global ramfs_blob_end",
    "ramfs_blob_start:",
    "1:",
    "    mov rax, 3",           // SYS_RECEIVE
    "    lea rsi, [rip + 4f]",  // &recvbuf
    "    mov rdx, 128",         // capacity
    "    int 0x80",
    "    mov rbx, rax",         // save length
    "    // print prefix",
    "    mov rax, 4",           // SYS_SERIAL_WRITE
    "    mov rdi, 0",           // Serial capability slot 0
    "    lea rsi, [rip + 2f]",
    "    mov rdx, 27",          // prefix length
    "    int 0x80",
    "    // print payload",
    "    mov rax, 4",
    "    mov rdi, 0",
    "    lea rsi, [rip + 4f]",
    "    mov rdx, rbx",
    "    int 0x80",
    "    // print newline",
    "    mov rax, 4",
    "    mov rdi, 0",
    "    lea rsi, [rip + 3f]",
    "    mov rdx, 1",
    "    int 0x80",
    "    jmp 1b",
    "2:",
    "    .ascii \"[user-ramfs] file request: \"", // 27 bytes
    "3:",
    "    .ascii \"\\n\"",
    "4:",
    "    .space 128",
    "ramfs_blob_end:",
);

// Position-independent init system.
core::arch::global_asm!(
    ".global init_blob_start",
    ".global init_blob_end",
    "init_blob_start:",
    "    // 1. Spawn logging service (Task type 1)",
    "    mov rax, 10",         // SYS_SPAWN_TASK
    "    mov rdi, 1",          // Logger type
    "    int 0x80",            // returns task_id (which is 2) in rax
    "    // The kernel inserts IpcChannel to Task 2 in init's slot 1",
    "    // 2. Grant Serial cap (slot 0) to Task 2",
    "    mov rax, 5",          // SYS_CAP_GRANT
    "    mov rdi, 0",          // Slot 0 (Serial)
    "    mov rsi, 2",          // Target Task 2
    "    mov rdx, 3",          // Read + Write rights
    "    int 0x80",
    "    // 3. Spawn RAM FS service (Task type 3)",
    "    mov rax, 10",         // SYS_SPAWN_TASK
    "    mov rdi, 3",          // RAM FS type
    "    int 0x80",            // returns task_id (which is 3) in rax
    "    // The kernel inserts IpcChannel to Task 3 in init's slot 2",
    "    // 4. Grant Serial cap (slot 0) to Task 3",
    "    mov rax, 5",          // SYS_CAP_GRANT
    "    mov rdi, 0",          // Slot 0 (Serial)
    "    mov rsi, 3",          // Target Task 3
    "    mov rdx, 3",          // Read + Write
    "    int 0x80",
    "    // 5. Spawn User Demo Task (Task type 2)",
    "    mov rax, 10",         // SYS_SPAWN_TASK
    "    mov rdi, 2",          // User Demo type
    "    int 0x80",            // returns task_id (which is 4) in rax
    "    // The kernel inserts IpcChannel to Task 4 in init's slot 3",
    "    // 6. Grant IpcChannel to Task 2 (held in init's slot 1) to Task 4",
    "    mov rax, 5",          // SYS_CAP_GRANT
    "    mov rdi, 1",          // Slot 1 (IpcChannel to Task 2)
    "    mov rsi, 4",          // Target Task 4
    "    mov rdx, 3",          // Read + Write
    "    int 0x80",
    "    // 7. Grant IpcChannel to Task 3 (held in init's slot 2) to Task 4",
    "    mov rax, 5",          // SYS_CAP_GRANT
    "    mov rdi, 2",          // Slot 2 (IpcChannel to Task 3)
    "    mov rsi, 4",          // Target Task 4
    "    mov rdx, 3",          // Read + Write
    "    int 0x80",
    "    // init's job of orchestration is complete! It can now print a message",
    "    // and loop yielding CPU.",
    "    mov rax, 4",          // SYS_SERIAL_WRITE
    "    mov rdi, 0",          // Slot 0 (Serial)
    "    lea rsi, [rip + 8f]",
    "    mov rdx, 35",
    "    int 0x80",
    "9:",
    "    mov rax, 1",          // SYS_YIELD
    "    int 0x80",
    "    jmp 9b",
    "8:",
    "    .ascii \"[user-init] system boot complete.\\n\"", // 35 bytes
    "init_blob_end:",
);

extern "C" {
    static ramfs_blob_start: u8;
    static ramfs_blob_end: u8;
    static init_blob_start: u8;
    static init_blob_end: u8;
}

pub fn spawn_ramfs_task(id: TaskId, cap_table: CapTable) -> Task {
    spawn_user(id, &raw const ramfs_blob_start, &raw const ramfs_blob_end, cap_table)
}

pub fn spawn_init_task(id: TaskId, cap_table: CapTable) -> Task {
    spawn_user(id, &raw const init_blob_start, &raw const init_blob_end, cap_table)
}

core::arch::global_asm!(
    ".global preempt_user_blob_start",
    ".global preempt_user_blob_end",
    "preempt_user_blob_start:",
    "    mov rcx, 0",
    "100:",
    "    add rcx, 1",
    "    jmp 100b",
    "preempt_user_blob_end:",
);

extern "C" {
    static preempt_user_blob_start: u8;
    static preempt_user_blob_end: u8;
}

pub fn spawn_preempt_user_task(id: TaskId, cap_table: CapTable) -> Task {
    spawn_user(id, &raw const preempt_user_blob_start, &raw const preempt_user_blob_end, cap_table)
}
