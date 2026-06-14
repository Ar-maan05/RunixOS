// RunixOS syscall surface.
//
// RunixOS has no traditional syscall model. The `int 0x80` trap is purely the
// ring-3 -> ring-0 transport for IPC-style requests: a user process asks the
// kernel to route a message, receive one, or perform a capability-gated action
// on its behalf. Every request is still validated against the caller's
// capabilities — there is no ambient authority.

use crate::process::capability::Resource;
use crate::scheduler::SCHEDULER;

// Syscall numbers (passed in rax).
pub const SYS_DEBUG: u64 = 0; // print a fixed kernel-side liveness message
pub const SYS_YIELD: u64 = 1; // cooperatively yield the CPU
pub const SYS_SEND: u64 = 2; // IPC send: rdi=cap_idx, rsi=*payload, rdx=len
pub const SYS_RECEIVE: u64 = 3; // IPC receive into rsi (max rdx); returns len in rax
pub const SYS_SERIAL_WRITE: u64 = 4; // capability-gated serial write: rdi=cap_idx, rsi=*buf, rdx=len

/// Register state saved by the `syscall_entry` stub, in memory order (the first
/// field is at the lowest address = top of stack on entry to the dispatcher).
#[repr(C)]
pub struct SyscallFrame {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    // The CPU-pushed interrupt frame (rip, cs, rflags, rsp, ss) follows.
}

// Assembly trampoline for `int 0x80`. Saves all general-purpose registers in
// the layout of `SyscallFrame`, hands a pointer to the dispatcher, then
// restores and returns to ring 3 via `iretq`.
core::arch::global_asm!(
    ".global syscall_entry",
    "syscall_entry:",
    "    push r15",
    "    push r14",
    "    push r13",
    "    push r12",
    "    push r11",
    "    push r10",
    "    push r9",
    "    push r8",
    "    push rbp",
    "    push rdi",
    "    push rsi",
    "    push rdx",
    "    push rcx",
    "    push rbx",
    "    push rax",
    "    mov rdi, rsp",        // &SyscallFrame
    "    call syscall_dispatch",
    "    pop rax",
    "    pop rbx",
    "    pop rcx",
    "    pop rdx",
    "    pop rsi",
    "    pop rdi",
    "    pop rbp",
    "    pop r8",
    "    pop r9",
    "    pop r10",
    "    pop r11",
    "    pop r12",
    "    pop r13",
    "    pop r14",
    "    pop r15",
    "    iretq",
);

extern "C" {
    /// The `int 0x80` entry stub (address installed into the IDT).
    pub fn syscall_entry();
}

/// Dispatches a syscall. `frame.rax` is the request number; the return value is
/// written back into `frame.rax` so the user sees it in `rax` after `iretq`.
#[no_mangle]
pub extern "C" fn syscall_dispatch(frame: &mut SyscallFrame) {
    let task_id = SCHEDULER
        .lock()
        .current_task_id
        .map(|t| t.0)
        .unwrap_or(usize::MAX);

    match frame.rax {
        SYS_DEBUG => {
            crate::println!("[ring3] task {} alive: syscall via int 0x80 reached the kernel.", task_id);
            frame.rax = 0;
        }
        SYS_YIELD => {
            crate::scheduler::yield_cpu();
            frame.rax = 0;
        }
        SYS_SEND => {
            // rdi = capability index, rsi = pointer into the caller's memory,
            // rdx = length. The IPC layer resolves the target from the caller's
            // capability table, so an unauthorized send simply fails.
            let cap_idx = frame.rdi as usize;
            let ptr = frame.rsi as *const u8;
            let len = frame.rdx as usize;
            if len <= 128 && !ptr.is_null() {
                // SAFETY (Phase 2 limitation): same address space as the kernel,
                // so the user pointer is directly readable. Strict user-pointer
                // validation arrives with per-process address spaces (Phase 4).
                let payload = unsafe { core::slice::from_raw_parts(ptr, len) };
                frame.rax = match crate::process::ipc::sys_send(cap_idx, payload) {
                    Ok(()) => 0,
                    Err(()) => u64::MAX,
                };
            } else {
                frame.rax = u64::MAX;
            }
        }
        SYS_RECEIVE => {
            // rsi = destination buffer in the caller's memory, rdx = capacity.
            // Blocks until a message arrives, then copies the payload to the
            // caller and returns the byte count in rax.
            let ptr = frame.rsi as *mut u8;
            let max = frame.rdx as usize;
            match crate::process::ipc::sys_receive() {
                Ok(msg) if !ptr.is_null() => {
                    let n = core::cmp::min(msg.len, max);
                    // SAFETY: control is back in the caller's address space after
                    // the receive, so `ptr` (its user buffer) is mapped.
                    unsafe { core::ptr::copy_nonoverlapping(msg.payload.as_ptr(), ptr, n) };
                    frame.rax = n as u64;
                }
                _ => frame.rax = u64::MAX,
            }
        }
        SYS_SERIAL_WRITE => {
            // rdi = capability slot, rsi = buffer, rdx = length. Allowed only if
            // the caller holds a Serial capability at that slot.
            let cap_idx = frame.rdi as usize;
            let ptr = frame.rsi as *const u8;
            let len = frame.rdx as usize;
            if !ptr.is_null() && len <= 4096 && current_has_serial_cap(cap_idx) {
                // SAFETY: caller's address space is active; `ptr..ptr+len` is
                // user memory it owns.
                let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
                if let Ok(s) = core::str::from_utf8(bytes) {
                    crate::print!("{}", s);
                }
                frame.rax = 0;
            } else {
                frame.rax = u64::MAX;
            }
        }
        other => {
            crate::println!("[syscall] task {} made unknown syscall {}", task_id, other);
            frame.rax = u64::MAX; // -1
        }
    }
}

/// Returns true if the currently running task holds a `Resource::Serial`
/// capability at `cap_idx`.
fn current_has_serial_cap(cap_idx: usize) -> bool {
    let sched = SCHEDULER.lock();
    if let Some(id) = sched.current_task_id {
        if let Some(task) = sched.get_task(id) {
            if let Some(cap) = task.cap_table.get(cap_idx) {
                return cap.resource == Resource::Serial;
            }
        }
    }
    false
}

/// Capability-gated kernel action: write to the serial console only if the
/// caller holds a `Resource::Serial` capability at `cap_idx`.
pub fn sys_serial_write(cap_idx: usize, message: &str) -> Result<(), ()> {
    let current_task_id = {
        let sched = SCHEDULER.lock();
        sched.current_task_id.ok_or(())?
    };

    let has_access = {
        let sched = SCHEDULER.lock();
        if let Some(task) = sched.get_task(current_task_id) {
            if let Some(cap) = task.cap_table.get(cap_idx) {
                cap.resource == Resource::Serial
            } else {
                false
            }
        } else {
            false
        }
    };

    if has_access {
        crate::print!("{}", message);
        Ok(())
    } else {
        Err(())
    }
}
