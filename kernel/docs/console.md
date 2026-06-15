# RunixOS Interactive Console -- Command Reference

The interactive console is a live, capability-gated shell that drives **the real
kernel paths** -- every command exercises an actual subsystem, not a simulation.
It is the capstone demonstration of the project: each research contribution
(Phases 1–11) is reachable through a single command.

- **Implementation:** `kernel/shell/mod.rs`
- **Specification:** [`CONSOLE_SPEC.md`](../../CONSOLE_SPEC.md)
- **Transport:** COM1 serial only (input = serial RX, output = serial TX with
  ANSI color). Under UEFI there is no VGA text mode, so the QEMU graphical
  window is intentionally blank.
- **Privilege:** the shell runs as a ring-0 kernel task (slot 64). RunixOS
  userspace is hand-written position-independent assembly with no runtime/heap,
  so a multi-command parser cannot live in ring 3. Capability enforcement is
  still demonstrated: the shell owns a real `CapTable` and every `cap` command
  operates on it.

---

## Launching

The console is gated behind `SHELL_MODE` in `kernel/boot/main.rs`:

```rust
pub const SHELL_MODE: bool = true;   // true: boot into console; false: run Phase 1–11 demos
```

With `SHELL_MODE = true`, build and run, then type commands over the serial line:

```bash
./build_disk.sh && ./run.sh        # serial is wired to your terminal (stdio)
```

Headless / scripted (note the pacing -- see *Serial pacing* below):

```bash
( sleep 4; printf 'cap list\n'; sleep 2; printf 'sched preempt-race\n'; sleep 5 ) | \
  qemu-system-x86_64 -M q35 \
    -drive if=pflash,unit=0,format=raw,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on \
    -drive file=disk.img,format=raw,media=disk -serial stdio -display none -m 2G
```

Prompt: `runix> ` · Line editing: backspace (`\b` / DEL) · Terminator: Enter.

### Output tags

| Tag      | Color  | Meaning                                            |
|----------|--------|----------------------------------------------------|
| `[CMD]`  | --      | echo of the command you entered                    |
| `[OK]`   | green  | success result                                     |
| `[FAIL]` | red    | failure result (with reason)                       |
| `[INFO]` | white  | informational output                               |
| `[WARN]` | yellow | non-fatal anomaly                                  |
| `[PASS]` | cyan   | research demo result -- expected outcome confirmed  |
| `[VULN]` | yellow | research demo result -- vulnerability demonstrated (intentional) |

---

## Commands

### Capability system -- Phases 1, 3, 8

| Command | Description | Real path |
|---|---|---|
| `cap list` | Print the shell's full capability table: token id, resource, rights (r/w/grant), sealed flag, derivation origin. Ends with a "no ambient authority" line -- what isn't listed does not exist to this process. | `CapTable::slots` |
| `cap grant <id>` | Derive an attenuated child capability from slot `<id>` and install it into a fresh task (slot 66); print the new globally-unique token id and its `origin` lineage. Fails if the slot lacks the `grant` right. | `Capability::attenuate` + `CapTable::insert` |
| `cap revoke <id>` | Revoke the capability in slot `<id>` and immediately confirm the slot is now unreachable. | `CapTable::kernel_revoke` |
| `cap seal <id>` | Seal slot `<id>` so the holder can no longer remove it; demonstrate that `remove()` now returns `Err`. | `Capability::sealed` + `CapTable::remove` |
| `cap audit` | Dump the kernel's capability grant/revoke audit ring buffer. | `process::audit::dump` |

```
runix> cap list
[OK]    slot 0: id=1 Serial r=false w=true g=true sealed=false origin=None
[OK]    slot 1: id=3 IpcChannel(task 65) r=true w=true g=true sealed=false origin=None
[OK]    slot 2: id=2 Service(#1) r=true w=true g=false sealed=false origin=None
[INFO]  no ambient authority: 3 capabilities, nothing else reachable
```

### IPC -- Phases 1, 5, 7

| Command | Description | Real path |
|---|---|---|
| `ipc send <task_id> <message>` | Send a message to the echo service (task 65, spawned lazily) via blocking rendezvous IPC; print byte count and round-trip time. | `ipc::sys_send_typed` (guarded) |
| `ipc typed <schema> <payload>` | Send a typed, schema-versioned message (`<schema>` = tag `0..3`); print the schema and the echoed reply. | `ipc::sys_send_typed` |
| `ipc stress <n>` | Run `n` worker pairs exchanging messages for 3 s under the timer; print total messages, throughput, and dropped count. | async IPC + `preempt::stats` clock |

### Scheduler -- Phase 11

| Command | Description | Real path |
|---|---|---|
| `sched info` | List every task: id, ring level (0/3, derived from `cr3`), state, plus the live tick count and whether preemption is armed. | `SCHEDULER.tasks` |
| `sched timeslice` | Spawn two tasks that **never yield** and run them ~2 s under the PIT timer; print each task's progress. Cooperative scheduling could never have run the second one. | `preempt::set_armed` + timer ISR |
| `sched preempt-race` | Reproduce the Phase 11 capability-atomicity finding side by side: **VULNERABLE** (an unguarded validate→use where a revoker wins mid-window and the capability is gone at use) vs **GUARDED** (the same window made non-preemptible -- the revoker is deferred and the capability survives). | `preempt` adversary + `CriticalWindow` |

```
runix> sched preempt-race
[VULN]  validated id=5; revoker ran mid-window; cap GONE at use
[PASS]  non-preemptible region: tick landed but revoker deferred; cap intact
```

### Fault containment -- Phase 4

| Command | Description | Real path |
|---|---|---|
| `fault spawn` | Spawn a task that triggers a page fault; the IDT handler terminates only that task and the kernel continues. Prints the fault type, the terminated task id, and survivor count. | IDT `#PF` handler + `terminate_current_task` |
| `fault cascade <n>` | Spawn `n` (1–8) simultaneously faulting tasks; show isolation holds under concurrent failure. | same, ×n |

### Services -- Phases 6, 9

| Command | Description | Real path |
|---|---|---|
| `service list` | List running ring-3 services: name, task id, state, capability count, message-queue depth. | `SCHEDULER.tasks` + name table |
| `service restart <name>` | Restart a named service (v1: `echo`); print the lifecycle -- shutdown → respawn → capability redistribution → recovery. | `terminate_current_task` + respawn |

### Persistence & distribution -- Phase 10

| Command | Description | Real path |
|---|---|---|
| `checkpoint` | Capture a full in-memory system snapshot; print the snapshot id, integrity checksum, and number of captured cap-tables. | `snapshot::capture` |
| `restore <id>` | Restore from snapshot `<id>` (v1: only `0`); verify the checksum. In-memory only -- not durable across reboot. | `snapshot::restore` |
| `migrate <service> <node>` | Migrate a service to a simulated remote node (v1: `migrate 1 1`); print the full transparent-IPC migration and failover handshake. | `dist::demo` / `dist::migrate` |

### Observability and Usability -- Group F

| Command | Description | Real path |
|---|---|---|
| `history [<n>]` | Show command history or re-run command at index n. Supports scrollable history using Up and Down arrow keys in the console. | Local shell ring buffer |
| `trace <command>` | Run any command with detailed kernel path tracing (scheduler switches, capability inserts/lookups/revocations, CPU exceptions, and IPC Rendezvous) and print a structured call trace. | `log_trace` hooks in kernel paths |
| `perf` | Print live kernel performance and health statistics: ticks, preemptions, deferred ticks, IPC messages delivered, faults caught, and tasks spawned/terminated. | `preempt::stats` + global atomic counters |
| `watch <command> <interval>` | Re-run any command every `<interval>` ticks and print a line-by-line diff of the output. Press any key to exit. | `REDIRECT_TARGET` serial hook |

### Meta

| Command | Description |
|---|---|
| `help [<command> [<subcommand>]]` | List all command groups and syntaxes, or display detailed usage instructions for a specific command/subcommand (e.g. `help cap list`). |
| *(unknown)* | Prints `[FAIL] unknown command: <input>` and `[INFO] try: help`. |

---

## What each command validates

| Command | Research contribution |
|---|---|
| `cap list / grant / revoke / seal / audit` | Phase 1, 3, 8 -- capability enforcement, attenuation, sealing, revocation propagation, audit trail |
| `ipc send / typed / stress` | Phase 1, 5, 7 -- rendezvous + async IPC, structured messages, scaling |
| `sched info / timeslice` | Phase 11 -- cooperative + preemptive scheduling coexisting |
| `sched preempt-race` | Phase 11 -- capability validate→use atomicity (the central finding) |
| `fault spawn / cascade` | Phase 4 -- fault containment and isolation under concurrent failure |
| `service list / restart` | Phase 6, 9 -- userspace ecosystem and service recovery |
| `checkpoint / restore / migrate` | Phase 10 -- persistent system state and transparent migration |
| `history / trace / perf / watch` | Observability & usability -- system health, event tracing, line diffing, scrollable history |

---

## Serial pacing (important for scripted use)

The guest UART has a 16-byte receive FIFO and no flow control. Two consequences
for headless scripting:

1. **The first command sent at boot can be dropped** if it arrives before the
   shell reaches its read loop. Send a throwaway newline first, or wait ~4 s
   after boot before the first command.
2. **Do not bulk-pipe** all commands at once (`cat session.txt | qemu`): the FIFO
   overflows and most commands are lost. Feed one command at a time, pausing
   long enough for each to finish -- the timed commands (`sched timeslice`,
   `sched preempt-race`, `ipc stress`) run for several seconds. The launch
   snippet above shows the pattern.

Interactive use over a real terminal (`./run.sh`) is unaffected -- you type at
human speed, well within the FIFO.

---

## Out of scope (v1)

These have no real kernel path and are intentionally **not** faked:

- PS/2 keyboard, framebuffer text rendering, VGA color attributes (serial only).
- Durable cross-reboot `restore` (the snapshot is in-memory for one boot).
- `migrate` to a physical second machine (the remote node is simulated in-kernel).
- `ipc send` to arbitrary tasks (only the echo service, task 65).
- Line editing features like cursor movements or tab-completion (history scrolling and backspace are supported).
