# RunixOS Interactive Console -- Ironclad Implementation Specification (v2)

> **How to use this document.** This is a build order for an implementer with no
> prior knowledge of RunixOS and no authority to make design decisions. Every
> interface, address, register, struct, string, and acceptance test is pinned
> here. If something appears underspecified, it is a bug in this document -- stop
> and treat the **most conservative** reading as correct; do **not** invent
> behavior. Implement sections in the order given. After each numbered build
> step there is a **GATE**: a headless boot test that must pass before
> proceeding. Do not start step N+1 until step N's GATE is green.

---

## 0. Ground truth (non-negotiable facts about the environment)

These are properties of the actual codebase and target. They override anything
in the original v1 draft.

G1. **Target**: x86_64, UEFI, booted by Limine into the kernel higher half. Runs
    in QEMU `-M q35`. Single core. No SMP.

G2. **No heap.** There is no allocator. All state is fixed-size and statically
    allocated. You may **not** use `alloc`, `Box`, `Vec`, `String`, or any
    growable collection. Use fixed `[T; N]` arrays and byte buffers.

G3. **No display text mode.** Under UEFI there is no VGA `0xB8000` text buffer.
    Limine provides a *linear graphical* framebuffer and the QEMU window is blank
    by design. **All console I/O is over COM1 serial (port `0x3F8`).** The v1
    draft's "Display Service / framebuffer / VGA attribute byte / keyboard
    service" are replaced by: output = serial TX, input = serial RX. Color is
    done with **ANSI SGR escape codes** over serial, not VGA attribute bytes.

G4. **Userspace is hand-written position-independent assembly blobs**, embedded
    via `core::arch::global_asm!` and copied into a per-task address space by
    `userspace::spawn_user`. There is **no ELF loader, no libc, no Rust user
    runtime**. A multi-command parser cannot be expressed as one of these blobs.
    **Therefore the console runs as a ring-0 kernel task written in Rust** (a
    `Task` created with `process::Task::new`). This is a deliberate deviation
    from the v1 "ring-3 shell process" and is mandatory. Capability-gating is
    still demonstrated: the shell owns a real `CapTable` and every command
    consults it (see §6, `cap *`).

G5. **Syscalls** are `int 0x80`; they exist for ring-3 blobs. The kernel shell
    does **not** use `int 0x80` -- it calls the same kernel functions the syscall
    dispatcher calls, directly. Syscall numbers/ABI are documented in §3 only so
    that commands which *spawn ring-3 helpers* can drive them.

G6. **Concurrency model**: cooperative round-robin (`scheduler::yield_cpu`) plus
    Phase-11 preemption (PIT @100 Hz, IDT vector `0x20`). A kernel task runs with
    interrupts enabled only after `sti`; ring-3 tasks run with IF=0. The 100 Hz
    timer is the only clock: **1 tick = 10 ms**. `preempt::stats().ticks` is the
    clock source for any "time"/"latency"/"throughput" output.

G7. **Verification is headless**: boot QEMU with `-serial stdio -display none`,
    pipe commands into stdin (these arrive at COM1 RX), capture stdout, strip
    ANSI, and grep. There is no other way to "see" the console. Every command in
    §6 ships with an acceptance test in this exact form.

---

## 1. Pinned ABI reference (read-only facts; do not change these)

All paths are relative to repo root. Line numbers are approximate; match by name.

### 1.1 Capabilities -- `kernel/process/capability.rs`
```rust
pub enum Resource {
    Serial,
    IpcChannel { target_task: TaskId },
    MemoryMapping { start_vaddr: usize, size: usize, writeable: bool },
    Service { id: usize },
}
pub struct Capability {
    pub resource: Resource,
    pub read: bool, pub write: bool, pub grant: bool, pub sealed: bool,
    pub id: u64,            // globally-unique, stamped by insert(); 0 == unassigned
    pub origin: Option<u64>,// donor cap id for derived caps; None for root
}
pub const MAX_CAPS: usize = 16;
pub struct CapTable { pub slots: [Option<Capability>; MAX_CAPS] }
impl CapTable {
    pub const fn new() -> Self;
    pub fn insert(&mut self, cap: Capability) -> Result<usize, ()>;        // stamps id
    pub fn insert_sealed(&mut self, cap: Capability) -> Result<usize, ()>;
    pub fn get(&self, idx: usize) -> Option<&Capability>;
    pub fn remove(&mut self, idx: usize) -> Result<Option<Capability>, ()>; // Err if sealed
    pub fn kernel_revoke(&mut self, idx: usize) -> Option<Capability>;      // ignores sealed
}
impl Capability { pub fn attenuate(&self, requested: RightsMask) -> Result<Capability, ()>; }
pub struct RightsMask { pub read: bool, pub write: bool, pub grant: bool }
```

### 1.2 Tasks / scheduler -- `kernel/process/mod.rs`, `kernel/scheduler/mod.rs`
```rust
pub struct TaskId(pub usize);
pub enum TaskState { Ready, Running, BlockedOnReceive, BlockedOnSend(TaskId), Terminated }
pub struct Task {
    pub id: TaskId, pub state: TaskState, pub rsp: usize, pub kstack_top: usize,
    pub cr3: usize, pub cap_table: CapTable,
    pub ipc_buffer: Option<Message>, pub msg_queue: MessageQueue,
    pub fault_registers: Option<crate::interrupts::ExceptionFrame>,
}
impl Task { pub fn new(id: TaskId, entry: extern "C" fn() -> !, cap_table: CapTable) -> Self; }
pub const MAX_TASKS: usize = 132;

pub static SCHEDULER: Spinlock<Scheduler>;     // scheduler/mod.rs
pub struct Scheduler { pub tasks: [Option<Task>; MAX_TASKS], pub current_task_id: Option<TaskId> }
impl Scheduler {
    pub fn get_task(&self, id: TaskId) -> Option<&Task>;
    pub fn get_task_mut(&mut self, id: TaskId) -> Option<&mut Task>;
}
pub fn current_task_id() -> Option<TaskId>;
pub fn yield_cpu();
pub fn terminate_current_task() -> !;
pub fn preempt_reschedule();   // called from timer ISR only
```
Boot PML4 (kernel tasks share it): `crate::memory::current_pml4_paddr()`. A task is
**ring 3 iff `task.cr3 != current_pml4_paddr()`**, else **ring 0**. (Ring-3 tasks
get their own PML4 from `spawn_user`; kernel tasks reuse the boot PML4.)

### 1.3 IPC -- `kernel/process/ipc.rs`
```rust
pub enum IpcTag { Raw = 0, Log = 1, Sensor = 2, Ping = 3 }   // from_u16(v) -> Option
pub struct Message { pub sender: TaskId, pub tag: IpcTag, pub version: u16,
                     pub payload: [u8;128], pub len: usize }
pub enum IpcError { NoCapability, TargetGone, PayloadTooLarge, InvalidTag,
                    BadVersion, NoContext, QueueFull, NoMessage }
pub fn sys_send_typed(cap_idx, tag: u16, version: u16, payload: &[u8]) -> Result<(), IpcError>;
pub fn sys_receive_typed() -> Result<Message, IpcError>;
pub fn sys_send_async(cap_idx, tag, version, payload) -> Result<(), IpcError>;
pub fn sys_receive_async() -> Result<Message, IpcError>;
```
`sys_send_typed`/`sys_send_async` are **already guarded** (Phase 11): they wrap
capability validate→use in `preempt::CriticalWindow` (non-preemptible region).
The shell relies on this; do not duplicate the guard.

### 1.4 Preemption -- `kernel/preempt/mod.rs`
```rust
pub fn set_armed(on: bool);  pub fn is_armed() -> bool;
pub fn enter_critical();     pub fn exit_critical();     pub fn in_critical() -> bool;
pub struct CriticalWindow;   impl CriticalWindow { pub fn enter() -> Self; }   // RAII
pub fn arm_adversary(task: usize, slot: usize);  pub fn disarm_adversary();
pub fn adversary_fired_in_window() -> bool;
pub fn enter_ipc_window(); pub fn exit_ipc_window(); pub fn reset_window_ticks();
pub struct Stats { pub ticks: u64, pub preemptions: u64, pub deferred: u64, pub window_ticks: u64 }
pub fn stats() -> Stats;
```

### 1.5 Phase entry points the console reuses (already implemented, verified)
```rust
crate::syscall::phase8_security_demo();           // prints grant→revoke cascade + audit
crate::process::audit::dump();                    // prints the grant/revoke ring buffer
crate::process::snapshot::capture();              // save-system-state (in-memory, 1 slot)
crate::process::snapshot::restore() -> Result<usize,()>;
crate::process::snapshot::info() -> Option<u64>;  // checksum of current snapshot
crate::process::dist::demo(service_id, backing: TaskId, replica: TaskId);
crate::process::dist::migrate(svc: ServiceId, dest: NodeId) -> Result<usize,()>;
```

### 1.6 Syscall ABI (only for ring-3 helpers spawned by commands) -- `kernel/syscall/mod.rs`
`int 0x80`, number in `rax`. Args: `rdi, rsi, rdx, r8`. Numbers:
`0 DEBUG, 1 YIELD, 2 SEND, 3 RECEIVE, 4 SERIAL_WRITE, 5 CAP_GRANT, 6 SEND_TYPED,
7 CAP_REVOKE, 8 SEND_ASYNC, 9 RECEIVE_ASYNC, 10 SPAWN_TASK`.
SEND_TYPED: `rdi=cap_idx, rsi=&payload, rdx=(version<<16)|tag, r8=len(<=128)`.

### 1.7 Serial -- `kernel/drivers/serial.rs`
```rust
pub static SERIAL1: Spinlock<SerialPort>;     // COM1 @ 0x3F8, TX implemented
crate::print!(...); crate::println!(...);     // write to SERIAL1
```
**RX does not exist yet -- you build it in step 1.**

### 1.8 Free task slots
Occupied: `1..=4` (user ecosystem), `90..=94` (Phase 11), `100..=130` (Phases 7–10),
`119..=125`, `128..=130`. **Free for the console: `5..=89` and `95..=99` and `131`.**
The console reserves **`64` = shell task**, and uses **`65..=80`** as its scratch
pool for spawned helpers (echo service, stress workers, fault tasks, race tasks).
Never write a slot outside its owner's range.

---

## 2. Architecture (revised, authoritative)

```
        COM1 RX (0x3F8)                         COM1 TX (0x3F8)
              |                                       ^
              v                                       |
     serial::read_line() ----> shell task (ring-0 Rust) ----> crate::print!
                                     |
                                     | direct kernel calls (NOT int 0x80)
            +------------------------+-------------------------+
            v            v           v            v            v
        CapTable     SCHEDULER     ipc::*      preempt::*   snapshot/dist
       (shell's)    (task list)  (real IPC)  (race/slice)  (checkpoint)
```

There is exactly one console task. It is the only task that calls
`serial::read_line`. It never blocks the kernel except inside that read.

---

## 3. Module / file layout (create or modify exactly these)

- **MODIFY** `kernel/drivers/serial.rs` -- add RX (step 1).
- **CREATE** `kernel/shell/mod.rs` -- the console (steps 2–6). Declared in
  `kernel/boot/main.rs` as `#[path = "../shell/mod.rs"] pub mod shell;` next to
  the other `#[path=...] pub mod` lines.
- **MODIFY** `kernel/boot/main.rs` -- add `const SHELL_MODE: bool`, conditional
  boot wiring (step 5).

No other files change. Do not touch Phases 1–11 code paths.

---

## 4. Step 1 -- Serial RX (build first)

Add to `serial.rs`, on `impl SerialPort`:
```rust
/// Returns a byte if one is waiting in the receive buffer, else None.
/// LSR is at base+5; bit 0 (Data Ready) set => a byte is in RBR (base+0).
pub fn try_read(&self) -> Option<u8> {
    unsafe {
        if (inb(self.port + 5) & 1) == 0 { return None; }
        Some(inb(self.port + 0))
    }
}
```
Add free functions:
```rust
/// Blocking single-byte read. Yields the CPU between polls so other tasks run.
pub fn read_byte() -> u8 {
    loop {
        if let Some(b) = SERIAL1.lock().try_read() { return b; }
        crate::scheduler::yield_cpu();
    }
}
/// Reads one line into `buf` (no trailing newline). Echoes typed characters.
/// Editing: handle '\b' (0x08) and DEL (0x7F) as backspace. Terminators: '\n'
/// (0x0A) or '\r' (0x0D). Returns the number of bytes stored. Caps at buf.len().
pub fn read_line(buf: &mut [u8]) -> usize {
    let mut n = 0;
    loop {
        let b = read_byte();
        match b {
            b'\n' | b'\r' => { crate::print!("\r\n"); return n; }
            0x08 | 0x7F => { if n > 0 { n -= 1; crate::print!("\x08 \x08"); } }
            0x20..=0x7E => { if n < buf.len() { buf[n] = b; n += 1; crate::print!("{}", b as char); } }
            _ => {} // ignore control bytes
        }
    }
}
```
`inb` already exists in `serial.rs` (it is currently `unsafe fn inb(port:u16)->u8`).
Keep it; just ensure `try_read` can call it.

**GATE 1.** Temporarily, at the end of `_start` (guarded by `SHELL_MODE`, step 5),
echo input: read a line and print `echo: <line>`. Boot test:
```
printf 'hello\n' | timeout 8 qemu-system-x86_64 -M q35 \
  -drive if=pflash,unit=0,format=raw,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on \
  -drive file=disk.img,format=raw,media=disk -serial stdio -display none -m 2G \
  | sed 's/\x1b\[[0-9;]*m//g' | grep -q 'echo: hello'
```
Must exit 0. Remove the echo stub once green.

---

## 5. Step 2 -- Shell scaffold, SHELL_MODE, output format

### 5.1 SHELL_MODE
In `main.rs` add `pub const SHELL_MODE: bool = true;`. When `true`, in `_start`:
- **Skip** `load_phase7_harness`, `load_phase8_demo`, `load_phase9_watchdog`,
  `load_phase10_persistence`, `load_phase10_dist`, `load_phase11_preempt`, **and**
  the perpetual user ecosystem (`spawn_init_task` + its logger/ramfs/demo loop) --
  i.e. do **not** put task 1 into the scheduler in shell mode. (Commands spawn
  what they need on demand.)
- **Do** keep: GDT/IDT/frame-allocator init, `init_pic`, `init_pit(100)`,
  `shell::load()`, the final `sti`, then `yield_cpu()`.
- `preempt::set_armed(false)` at boot; commands that need preemption arm it
  themselves and disarm before returning (so the prompt is never preempted away
  mid-print).

When `SHELL_MODE == false`, boot is exactly today's behavior (all phases). The
console must be a pure addition behind this flag.

### 5.2 Shell task
`shell::load()` inserts a kernel task at slot **64**:
```rust
pub fn load() {
    let mut sched = scheduler::SCHEDULER.lock();
    sched.tasks[64] = Some(process::Task::new(process::TaskId(64), shell_main, root_caps()));
}
```
`root_caps()` returns a `CapTable` containing exactly, in this slot order:
- slot 0: `Serial` `{read:false,write:true,grant:true,sealed:false}`
- slot 1: `IpcChannel{target_task:TaskId(65)}` `{read:true,write:true,grant:true}` (the echo service, spawned lazily by `ipc send`)
- slot 2: `Service{id:1}` `{read:true,write:true,grant:false}`
(ids are stamped by `insert`; capture them once for display.)

`shell_main` (`extern "C" fn() -> !`):
```
1. sti is already on (set in _start). print BANNER (see 5.4).
2. loop:
     a. print PROMPT  ("runix> ", in default color)
     b. let n = serial::read_line(&mut line_buf[..128]);
     c. if n == 0 { continue; }
     d. echo the command: tag CMD with the raw line.
     e. dispatch(&line_buf[..n]);   // §6
3. never returns; on an unrecoverable internal error, print FAIL and continue.
```
`line_buf` is a `static mut [u8; 128]` or a stack array; single task, no reentrancy.

### 5.3 Tokenizer (exact)
- Split the input line on ASCII spaces (0x20). Collapse runs of spaces. Ignore
  leading/trailing spaces. Max **4** tokens; extra tokens are folded into the
  4th (so `ipc send 5 hello world` → `["ipc","send","5","hello world"]`, where
  token 4 is the remainder of the line verbatim after the 3rd token).
- Tokens are `&[u8]` slices into `line_buf`. Comparison is byte-exact, case
  sensitive.
- Integer args: parse base-10 `usize` from ASCII digits; on non-digit or
  overflow print `FAIL` "bad number: <tok>" and abort the command.

### 5.4 Output format (ANSI over serial)
Define one helper per tag. Each prints `<COLOR><TAG> <text><RESET>\r\n`.
```
[CMD]  default (no color)   prefix "\x1b[0m[CMD]   "
[OK]   green   "\x1b[32m[OK]    "
[FAIL] red     "\x1b[31m[FAIL]  "
[PASS] cyan    "\x1b[36m[PASS]  "
[VULN] yellow  "\x1b[33m[VULN]  "
[INFO] white   "\x1b[37m[INFO]  "
[WARN] yellow  "\x1b[33m[WARN]  "
RESET  "\x1b[0m"
```
Always emit RESET at end of line. Alignment: tag field is 7 columns
(`[OK]` padded to `[OK]   `). BANNER is two `[INFO]` lines: `RunixOS console`
and `type 'help'`. PROMPT is the literal `runix> ` with no tag and no newline.

**GATE 2.** `printf 'help\n' | <qemu>` (as in GATE 1) and assert the output
contains `runix>` and (after `help` is implemented in step 3) the command list.
For now `help` may print just `[INFO] commands: ...`. Assert `[INFO]` appears and
prompt re-appears after the command (two `runix>` occurrences for one `help`).

---

## 6. Step 3–6 -- Command catalog (each fully pinned)

Dispatch is a flat match on `(token0, token1)`. Unknown → 
`FAIL "unknown command: <line>"` then `INFO "try: help"`. A command that needs a
capability the shell lacks prints `FAIL "no capability"` and returns. Build the
commands in the group order below; each group is one GATE.

For brevity, "list shell caps" means: iterate `root_caps` slots 0..16, skip
`None`. "tick now" means `preempt::stats().ticks`. "arm" means
`preempt::set_armed(true)`; always `set_armed(false)` before the command returns.

### Group A -- `help`, `cap *` (step 3)

**`help`** -- print one `[INFO]` line per command group listing exact syntaxes.
Acceptance: output contains `cap list`, `ipc send`, `sched preempt-race`, `fault spawn`.

**`cap list`** -- for each present slot i: 
`OK "slot {i}: id={cap.id} {resource_name} r={read} w={write} g={grant} sealed={sealed} origin={origin?}"`.
`resource_name`: `Serial` | `IpcChannel(task {t})` | `Service(#{id})` | `Memory`.
Then `INFO "no ambient authority: {count} capabilities, nothing else reachable"`.
Acceptance: `cap list` → contains `slot 0:` and `Serial` and `no ambient authority`.

**`cap grant <id>`** -- `<id>` is a slot index. If slot empty → `FAIL "no capability"`.
Derive `cap.attenuate(RightsMask{read:true,write:true,grant:false})`; if `Err` →
`FAIL "slot {id} lacks grant right"`. Spawn a fresh scratch task at slot **66**
(`Task::new(TaskId(66), park, CapTable::new())`, `park` = `terminate_current_task`),
insert the derived cap into **its** table, set its `origin = Some(donor.id)`, read
back the stamped id. Print `OK "granted: new token id={newid} origin={donorid} -> task 66"`.
Acceptance: `cap grant 0` → contains `granted:` and `origin=`.

**`cap revoke <id>`** -- `<id>` is a slot in the shell's table. 
`root_caps.kernel_revoke(id)`; if it returned `None` → `FAIL "slot {id} empty"`.
Then immediately attempt to *use* it: `cap list` re-scan shows the slot gone, and
if the revoked cap was `Serial` (slot 0) attempt a `SerialWrite`-style check by
calling `current_has_serial_cap`-equivalent against the shell table; print
`OK "revoked id={id}; re-use denied (slot now empty)"`.
Acceptance: `cap revoke 2` then `cap list` → second listing does **not** contain `Service(#1)`.

**`cap seal <id>`** -- set `slots[id].sealed = true` (direct field write under lock).
Then call `root_caps.remove(id)`; it must return `Err(())`. Print
`OK "sealed id={id}; holder remove() -> Err (locked)"`. If slot empty → `FAIL`.
Acceptance: `cap seal 0` → contains `locked`.

**`cap audit`** -- call `crate::process::audit::dump()` (prints its own lines), then
`INFO "audit trail above"`. Acceptance: `cap audit` → exit 0 (no crash); output
contains either an audit line or `audit trail above`.

GATE A: run all of the above piped as one session; assert each acceptance substring.

### Group B -- `sched *` (step 4)

**`sched info`** -- lock SCHEDULER; for each present slot: determine ring via
`task.cr3 != memory::current_pml4_paddr()` (ring3) else ring0; map state to
`run|ready|recv|send|term`. Print `OK "task {id}: ring{0|3} {state}"`. Footer:
`INFO "ticks={tick} armed={preempt::is_armed()}"`.
Acceptance: `sched info` → contains `task 64: ring0` (the shell itself, running).

**`sched timeslice`** -- reproduce Phase 11 part A but shell-driven:
1. spawn two never-yielding counter tasks at slots **67, 68** (each: `sti`,
   then `loop { COUNTER[x]+=1; if ticks-start >= 200 break; }`, then terminate).
   200 ticks = 2 s.
2. `set_armed(true)`. Wait (yield loop) until both slots are `Terminated`,
   bounded by a 4 s tick deadline. `set_armed(false)`.
3. If both counters > 0: `PASS "time-sliced: A={a} B={b} preemptions={p}; cooperative could not run B"`.
   else `FAIL`.
Acceptance: `sched timeslice` → contains `[PASS]` and `time-sliced`.

**`sched preempt-race`** -- reproduce Phase 11 part B in the shell, using the real
`preempt` adversary against a real cap in a scratch victim task (slot **69**):
1. VULNERABLE: install an `IpcChannel{target:70}` cap in task 69 slot 0; record id.
   `set_armed(true); arm_adversary(69,0); reset_window_ticks(); enter_ipc_window();`
   spin (no yield) until `stats().window_ticks>=1` (bounded 1 s); `exit_ipc_window();`
   read cap back. If gone & `adversary_fired_in_window()`:
   `VULN "validated id={id}; revoker ran mid-window; cap GONE at use"`.
2. GUARDED: re-install cap; `arm_adversary; reset_window_ticks;`
   `enter_critical(); enter_ipc_window();` spin until a window tick lands (bounded);
   `exit_ipc_window(); exit_critical();` read cap back. If present & not fired:
   `PASS "non-preemptible region: tick landed but revoker deferred; cap intact"`.
3. `disarm_adversary(); set_armed(false)`.
Acceptance: `sched preempt-race` → contains both `[VULN]` and `[PASS]`.

GATE B: piped session; assert substrings above.

### Group C -- `fault *` (step 5)

**`fault spawn`** -- spawn one task at slot **71** whose entry does
`unsafe { read_volatile(0x0000_1234_5678 as *const u64) }` (an unmapped read →
`#PF`). `yield_cpu()` a few times so it runs and faults (the IDT handler prints
`[FAULT] ... in task 71 ...` and terminates it). Then verify the shell (task 64)
and at least one other task are still alive (`sched info`-style scan), and that
task 71 is now `Terminated` or `None`. Print
`OK "task 71 faulted (#PF) and was contained; kernel + {n} tasks alive"`.
Acceptance: `fault spawn` → contains `[FAULT]` (from kernel) and `contained`.

**`fault cascade <n>`** -- `n` in `1..=8`. Spawn `n` faulting tasks at slots
`72..72+n`, each like `fault spawn`. Yield until all are gone. Print one
`OK "task {s} contained"` per task and a footer `PASS "isolation held under {n} concurrent faults"`.
Acceptance: `fault cascade 3` → contains `[PASS]` and `isolation held under 3`.

GATE C: piped session.

### Group D -- `ipc *`, `service *` (step 6)

**`ipc send <task_id> <message>`** -- `<task_id>` must equal **65** (the echo
service; if not 65 → `FAIL "only task 65 (echo) is reachable in v1"`). Lazily
spawn the echo service at slot 65 if absent (kernel task: loops
`sys_receive_typed()` then re-sends `Raw` back to sender -- needs an `IpcChannel`
cap to the shell; install it at spawn). Record `t0=tick`. `sys_send_typed(1, Raw,
1, msg)` over shell slot 1. On `Ok`: `OK "sent {len}B to task 65"`, then
`INFO "round-trip ~{(tick-t0)*10} ms"`. On `Err(e)`: `FAIL "{e:?}"`.
Acceptance: `ipc send 65 hello` → contains `sent` and `round-trip`.

**`ipc typed <schema> <payload>`** -- `<schema>` parsed as `u16` tag (0..=3 valid;
else `FAIL "schema must be 0..3"`). `sys_send_typed(1, schema, 2, payload)` to the
echo service; print `OK "typed send tag={schema} ver=2 {len}B"`, and on the echo
reply `INFO "echo tag={tag} '{payload}'"`. 
Acceptance: `ipc typed 1 hi` → contains `tag=1`.

**`ipc stress <n>`** -- `n` in `1..=8`. Spawn `n` worker pairs in slots `73..80`
that ping-pong `Raw` messages for 300 ticks (3 s) under `set_armed(true)`,
counting deliveries in a shared `static AtomicU64`. After the deadline disarm,
terminate workers, print `PASS "stress: {count} msgs in 3s = {count/3}/s, dropped=0"`.
Acceptance: `ipc stress 2` → contains `[PASS]` and `msgs in 3s`.

**`service list`** -- like `sched info` but only tasks in slots `1..=4` and
`65` with a known name table: `{1:init,2:logger,3:ramfs,4:demo,65:echo}`. Print
`OK "service {name} (task {id}): {state}, caps={count}, queue={msg_queue.count}"`.
If none present (shell mode suppresses 1..4): `INFO "no standing services; spawn via ipc/echo"`.
Acceptance: `service list` → contains `service` or `no standing services`.

**`service restart <name>`** -- only `<name>=="echo"` supported in v1. Terminate
task 65, respawn it with a fresh cap set, print lifecycle:
`INFO "echo: shutdown"`, `INFO "echo: respawn (task 65)"`, `INFO "echo: caps redistributed"`,
`PASS "service echo recovered"`. Other names → `FAIL "unknown service: <name>"`.
Acceptance: `service restart echo` → contains `[PASS]` and `recovered`.

GATE D: piped session.

### Group E -- Phase 10 commands (step 7)

**`checkpoint`** -- call `snapshot::capture()`; `let sum = snapshot::info()`. Print
`OK "checkpoint taken: id=0 checksum={sum:#x}"`, then `INFO "captured {k} task cap-tables"`
where `k` = count of present tasks at capture. (Snapshot is a single in-memory
slot; "id" is always 0.) Acceptance: `checkpoint` → contains `checksum=0x`.

**`restore <id>`** -- `<id>` must be `0` (only one snapshot slot; else
`FAIL "no snapshot id {id}"`). Call `snapshot::restore()`; on `Ok(k)`:
`OK "restored {k} task checkpoints; checksum verified"`; on `Err`:
`FAIL "no valid snapshot (run checkpoint first)"`.
Acceptance: `checkpoint` then `restore 0` → second contains `restored`.

**`migrate <service> <node>`** -- `<service>` must be `1`, `<node>` must be `1`
(the simulated remote node; else `FAIL "v1 supports: migrate 1 1"`). This calls
`dist::demo(1, TaskId(75), TaskId(76))` (it spawns its own scratch tasks at the
given slots -- use 75,76 which are inside the console pool) which prints the full
migrate/failover handshake. Then `PASS "service 1 migrated node0->node1, capability stable"`.
Acceptance: `migrate 1 1` → contains `[dist]` (from the real path) and `[PASS]`.

GATE E: piped session.

---

## 7. Out of scope for v1 (explicit -- do NOT attempt)

These have no real kernel path and must **not** be faked. If invoked, print the
exact `FAIL`/`INFO` shown:
- Real PS/2 keyboard, framebuffer text, color attribute bytes (G3). Input/output
  is serial only.
- Cross-reboot durable `restore` (snapshot is in-memory only). `restore` works
  within one boot session only; say so in `help`.
- `migrate` to a real second machine / NIC (the node is simulated in-kernel).
- Arbitrary `ipc send <task_id>` to any task (only the echo service, task 65).
- Line history / arrow keys (backspace only -- G stated in §4).

---

## 8. Global definition of done

A single **paced** session must pass headlessly. The guest UART has a 16-byte RX
FIFO and no flow control, so you **must not** bulk-pipe (`cat session.txt | qemu`)
-- the FIFO overflows and most commands are lost. Feed one command at a time with
a delay sized to that command (the timed commands run for seconds), and send a
throwaway newline first so the boot-time first-byte drop cannot eat a real
command:
```
feed() {
  sleep 4; printf '\n'                                  # let boot settle; flush
  for spec in "help:2" "cap list:2" "cap grant 0:2" "cap seal 0:2" "cap revoke 2:2" \
              "cap audit:2" "sched info:2" "sched timeslice:6" "sched preempt-race:5" \
              "fault spawn:3" "fault cascade 3:3" "ipc send 65 hello:3" "ipc typed 1 hi:3" \
              "ipc stress 2:6" "service list:2" "service restart echo:3" \
              "checkpoint:2" "restore 0:2" "migrate 1 1:4"; do
    printf '%s\n' "${spec%:*}"; sleep "${spec##*:}"
  done; sleep 2
}
feed | timeout 90 qemu-system-x86_64 -M q35 \
  -drive if=pflash,unit=0,format=raw,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on \
  -drive file=disk.img,format=raw,media=disk -serial stdio -display none -m 2G \
  2>/dev/null | sed 's/\x1b\[[0-9;]*[mGKHJ]//g' > /tmp/out.txt
```
(Interactive use over a real terminal via `./run.sh` needs none of this pacing --
you type at human speed, well within the FIFO.)
**Acceptance -- `/tmp/out.txt` must contain ALL of:**
1. `no ambient authority`            (cap list)
2. `granted: new token id=`          (cap grant)
3. `locked`                          (cap seal)
4. `revoked id=2`                    (cap revoke)
5. `task 64: ring0`                  (sched info)
6. `[PASS]` ... `time-sliced`        (sched timeslice)
7. `[VULN]` AND `[PASS]` ... `deferred`  (sched preempt-race)
8. `[FAULT]` ... `contained`         (fault spawn)
9. `isolation held under 3`          (fault cascade)
10. `sent 5B to task 65`             (ipc send)
11. `[PASS]` ... `msgs in 3s`        (ipc stress)
12. `echo recovered`                 (service restart)
13. `checksum=0x`                    (checkpoint)
14. `restored`                       (restore)
15. `[dist]` AND `service 1 migrated` (migrate)
16. The prompt `runix>` appears at least 19 times (one per command + final).
17. No `KERNEL PANIC` anywhere in the output.

Each GATE in §4–6 must also pass independently. Build strictly in order
1→2→3(A)→4(B)→5(C)→6(D)→7(E); never advance past a red GATE.

## 9. Invariants the implementer must never violate
- No heap / no `alloc` (G2).
- Never hold the `SCHEDULER` lock across `serial::read_*` or across `print!`.
- Every command that calls `set_armed(true)` must `set_armed(false)` before it
  returns, on every path.
- Only the shell task (64) calls `serial::read_line`.
- Never write a task slot outside `64..=80` from console code.
- Leave Phases 1–11 behavior identical when `SHELL_MODE == false`.
