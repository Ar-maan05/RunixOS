# RunixOS

> A capability-based microkernel research operating system written in Rust.

[![Rust](https://img.shields.io/badge/Rust-nightly-orange)](#)
[![Architecture](https://img.shields.io/badge/Architecture-x86__64-blue)](#)
[![Boot](https://img.shields.io/badge/Boot-UEFI%20%2B%20Limine-green)](#)
[![Status](https://img.shields.io/badge/Status-Phases%200--9%20Complete-success)](#)
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

### Experimental

* ⚠️ Phase 10: Distributed persistence and service migration

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
├── arch/x86_64/
├── boot/
├── docs/
├── drivers/
├── fs/
├── interrupts/
├── memory/
├── process/
├── scheduler/
├── syscall/
├── tests/
└── userspace/
```

The complete phase-by-phase design directive is available in `OS_PLAN.md`.

The detailed implementation reference is available in `kernel/docs/architecture.md`.

---

## Final Research Thesis

RunixOS demonstrates that:

> A capability-based, IPC-driven distributed operating system can support persistence, migration, and fault tolerance while maintaining a minimal kernel, strict isolation, and a uniform programming model.

---

## License

MIT

