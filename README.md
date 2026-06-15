# RunixOS

> A capability-based microkernel research operating system written in Rust.

[![Rust](https://img.shields.io/badge/Rust-nightly-orange)](#)
[![Architecture](https://img.shields.io/badge/Architecture-x86__64-blue)](#)
[![Boot](https://img.shields.io/badge/Boot-UEFI%20%2B%20Limine-green)](#)
[![Status](https://img.shields.io/badge/Status-Phases%200--11%20%2B%20Console-success)](#)
[![License](https://img.shields.io/badge/License-MIT-yellow)](#)

RunixOS is an experimental operating system that explores what modern systems software might look like if capabilities, message passing, and persistence were treated as first-class principles from the beginning.

The project investigates:

* Minimal kernels and rich user-space services
* Capability-based security
* IPC-first system design
* User-space drivers and services
* Transparent service distribution
* Persistent system state
* Service migration and recovery

RunixOS is not intended to be a Linux replacement or a POSIX-compatible operating system. It is a clean-slate systems research platform focused on isolation, modularity, and recoverability.

> [!NOTE]
> RunixOS is a research and educational project and is not intended for production use.

---

## Architecture at a Glance

```text
+----------------------------------------------------------------+
|                           User Space                           |
|----------------------------------------------------------------|
| Init | Drivers | Filesystem | Logger | Services | Supervisor   |
+----------------------------------------------------------------+
                       ↑                     ↓
                 IPC + Capabilities + Persistence
                       ↓                     ↑
+----------------------------------------------------------------+
|                             Kernel                             |
|----------------------------------------------------------------|
| Scheduler | Memory | IPC | Capability Enforcement | Checkpoint |
+----------------------------------------------------------------+
                       ↑                     ↓
                Hardware / Firmware / Devices
```

---

## Core Principles

* Minimal kernel, rich user space
* Capabilities are the sole security primitive
* IPC is the sole communication primitive
* No ambient authority
* Isolation by default
* Distribution should be transparent
* Persistence should be a first-class system property
* Correctness over performance
* Simplicity over feature count

---

## Core Identity

RunixOS is a capability-based microkernel.

It is:

* IPC-first
* Capability-gated
* User-space service driven
* Minimal by design

It is explicitly:

* Not Unix-like
* Not POSIX-compatible
* Not monolithic
* Not syscall-centric

There is:

* No shared memory between processes
* No global registries
* No ambient authority

The kernel implements only:

* Physical memory management
* Virtual memory management
* Scheduling
* IPC routing
* Capability enforcement
* Checkpoint and persistence primitives

Everything else lives in user space.

---

## Project Status

### Completed

* ✅ Phase 0: Boot infrastructure
* ✅ Phase 1: Microkernel core
* ✅ Phase 2: Userspace shift
* ✅ Phase 3: System coherence
* ✅ Phase 4: Isolation and safety hardening
* ✅ Phase 5: Async IPC and scaling
* ✅ Phase 6: Userspace ecosystem
* ✅ Phase 7: Stress, scale, and failure testing
* ✅ Phase 8: Security and capability maturity
* ✅ Phase 9: Stability and self-sufficiency
* ✅ Phase 10: Distributed persistence and service migration (in-memory; boot-verified)
* ✅ Phase 11: Preemptive scheduling and capability validate→use atomicity
* ✅ Interactive Console: live capability-gated shell over the real kernel paths

### Experimental / simulated

* ⚠️ Phase 10 distribution uses simulated in-kernel nodes (no NIC); persistence is
  in-memory (not durable across reboot).
* ⚠️ Ring-3 tasks are not yet preemptible (they run with interrupts disabled);
  Phase 11 preemption applies to ring-0 tasks.

---

## Highlight: capability validate→use atomicity (Phase 11)

Adding preemptive scheduling (PIT timer, full-register context switch) surfaced a
finding the cooperative scheduler had hidden: **capability *validation* and
capability *use* were never atomic -- cooperative scheduling was silently
donating that atomicity for free.** An IPC send validates a capability, then (in
a separate step) uses it to deliver. Under preemption a concurrent task can
revoke the capability in the gap, so the send delivers on revoked authority -- a
classic TOCTOU.

The fix is now a system property: `ipc::sys_send_typed` / `sys_send_async` wrap
validate→use in a **non-preemptible critical section** (`preempt::CriticalWindow`)
that extends past *both* halves of delivery (message deposited **and** receiver
marked runnable), with the blocking wait deliberately outside it and a fresh
re-validation on every wakeup. The console reproduces both sides live:

```
runix> sched preempt-race
[VULN]  validated id=5; revoker ran mid-window; cap GONE at use
[PASS]  non-preemptible region: tick landed but revoker deferred; cap intact
```

---

## Interactive Console

RunixOS ships a live, capability-gated **interactive console** that drives the
real kernel paths -- every command exercises an actual subsystem, not a
simulation. It is the single end-to-end demonstration of Phases 1–11.

Enable it via `SHELL_MODE` in `kernel/boot/main.rs` (default `true`), then build
and run and type at the `runix> ` prompt over the serial line:

```bash
./build_disk.sh && ./run.sh
```

```
runix> cap list
[OK]    slot 0: id=1 Serial r=false w=true g=true sealed=false origin=None
[INFO]  no ambient authority: 3 capabilities, nothing else reachable
runix> sched timeslice
[PASS]  time-sliced: A=2938800 B=2972002 preemptions=201; cooperative could not run B
runix> fault spawn
[FAULT] page fault (#PF) in task 71 ... -> terminating task, kernel continues.
[OK]    task 71 faulted (#PF) and was contained; kernel + 1 tasks alive
runix> migrate 1 1
[PASS]  service 1 migrated node0->node1, capability stable
```

| Group | Commands | Validates |
|---|---|---|
| Capability | `cap list / grant / revoke / seal / audit` | Phase 1, 3, 8 |
| IPC | `ipc send / typed / stress` | Phase 1, 5, 7 |
| Scheduler | `sched info / timeslice / preempt-race` | Phase 11 |
| Fault | `fault spawn / cascade` | Phase 4 |
| Services | `service list / restart` | Phase 6, 9 |
| Persistence | `checkpoint / restore / migrate` | Phase 10 |

**Full command reference:** [`kernel/docs/console.md`](kernel/docs/console.md).
**Implementation spec:** [`CONSOLE_SPEC.md`](CONSOLE_SPEC.md).

> The console is a ring-0 kernel task and renders over COM1 serial (the QEMU
> window is blank by design under UEFI). When scripting it headlessly, feed one
> command at a time -- the 16-byte UART FIFO drops bulk input. See the console
> reference for the pacing pattern.

---

## Research Questions

RunixOS aims to answer the following questions:

1. Can capabilities replace traditional access control mechanisms?
2. Can an IPC-first operating system remain practical at scale?
3. Can user-space services provide sufficient reliability?
4. Can distribution be made transparent to applications?
5. Can operating system state become a persistent object?
6. Can services survive failures through checkpointing and restoration?
7. Can a capability-based operating system scale from a single machine to a distributed system without changing its programming model?

---

## Build and Run

### Requirements

* Rust nightly
* QEMU (`qemu-system-x86_64`)
* `mtools`
* `dosfstools`
* `parted`
* OVMF firmware

### Build

```bash
./build_disk.sh
```

### Run

```bash
./run.sh
```

### Headless Verification

```bash
timeout 12 qemu-system-x86_64 -M q35 \
  -drive if=pflash,unit=0,format=raw,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on \
  -drive file=disk.img,format=raw,media=disk \
  -serial stdio -m 2G -display none -no-reboot > serial.log 2>&1
```

The graphical display is intentionally blank. All diagnostics are emitted through the serial console.

---

## Repository Structure

```text
kernel/
├── arch/x86_64/      # GDT/TSS, low-level CPU setup
├── boot/             # entry point, task loading, SHELL_MODE wiring
├── docs/             # architecture.md, console.md
├── drivers/          # serial (COM1 TX/RX), spinlock
├── fs/
├── interrupts/       # IDT, fault handlers, PIC/PIT timer (Phase 11)
├── memory/           # frame allocator, paging, address spaces
├── preempt/          # Phase 11: preemption policy, non-preemptible regions
├── process/          # tasks, capabilities, IPC, snapshot, distribution, audit
├── scheduler/        # round-robin + preemptive reschedule
├── shell/            # interactive console
├── syscall/          # int 0x80 dispatch, capability syscalls
├── tests/
└── userspace/        # ring-3 position-independent service blobs
```

Documentation:

* `OS_PLAN.md` -- the complete phase-by-phase design directive.
* `kernel/docs/architecture.md` -- detailed implementation reference.
* `kernel/docs/console.md` -- interactive console command reference.
* `CONSOLE_SPEC.md` -- console implementation specification.

---

## Final Research Thesis

RunixOS demonstrates that:

> A capability-based, IPC-driven distributed operating system can support persistence, migration, and fault tolerance while maintaining a minimal kernel, strict isolation, and a uniform programming model.

---

## License

MIT

