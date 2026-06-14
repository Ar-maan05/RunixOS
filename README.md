# RunixOS

A capability-based **microkernel** research OS written in Rust, targeting `x86_64`.

> [!NOTE]
> RunixOS is a research and educational project. It is not intended for production use.
> The focus is on exploring a minimal, IPC-first kernel where security is enforced by
> unforgeable capabilities and all services live in user space.

---

## Core Identity (non-negotiable)

RunixOS is a **capability-based microkernel**. It is:

- **IPC-first** — message passing is the only communication mechanism
- **Capability-gated** — no ambient authority; every kernel API requires a valid capability
- **User-space service driven** — drivers, filesystem, logging, and init run as processes
- **Minimal by design** — the kernel implements only core primitives

It is explicitly **not** Unix-like, **not** POSIX-compatible, **not** monolithic, and has
**no** traditional syscall model (no `fork`/`exec` semantics). There is no shared memory
between processes and no global registries or hidden state.

The kernel implements only:

- physical memory manager
- virtual memory manager
- round-robin scheduler
- IPC (message passing)
- capability system

No filesystem, no drivers, no OS abstractions live in the kernel.

---

## Roadmap & Progress

The architecture is developed in phases (see [`../OS_PLAN.md`](../OS_PLAN.md) for the full
directive). Milestone 0 (boot, serial, higher-half mapping, build/disk pipeline) is complete.

- [x] **Milestone 0: Boot & Toolchain** — UEFI boot via Limine, COM1 serial, higher-half
      mapping, build/disk pipeline, CI
- [x] **Phase 1: Microkernel Core** — minimal kernel primitives
  - [x] Physical page frame allocator
  - [x] Virtual memory (4-level page-table mapper)
  - [x] Cooperative round-robin scheduler + context switch
  - [x] Capability system (per-process capability table, resource binding)
  - [x] Rendezvous (blocking) IPC: `send` / `receive`
  - [x] Capability-gated kernel service (serial write)
  - [x] Fault isolation — IDT catches CPU exceptions; a faulting task is
        terminated and the kernel keeps scheduling the rest
- [x] **Phase 2: Userspace Shift** — user-mode execution & IPC-based syscalls
  - [x] GDT + TSS with ring-3 segments and a per-task kernel (rsp0) stack
  - [x] Ring-3 execution (iretq into user mode)
  - [x] Per-process address spaces (own PML4 + CR3 switch on context switch)
  - [x] IPC-based syscall transport (`int 0x80`): `send` / `receive` /
        `serial_write` / `yield`, no traditional syscall model
  - [x] A ring-3 logging **service** runs entirely in user space: it receives
        IPC and prints via a capability-gated serial syscall
  - [x] Both a kernel task and a ring-3 user task send capability-gated IPC
        (from their own memory) to that user-space service
- [ ] **Phase 3: System Coherence** — capability sealing/scoping/inheritance, structured
      IPC, kernel dispatch layer
- [ ] **Phase 4: Isolation & Safety Hardening** — strict memory isolation, fault containment
- [ ] **Phase 5: Async IPC & System Scaling** — typed/versioned messages, non-blocking IPC,
      identical behavior at 3 and 300 processes
- [ ] **Phase 6: Userspace Ecosystem** — init system, capability distribution, service
      lifecycle; all services in user space

### Phase 1 status

The current build boots in QEMU and runs two kernel tasks:

- **Task 1 (sender)** generates a data packet and sends it over an IPC capability.
- **Task 2 (logging service)** receives the message and prints it using its serial capability.

Capability gating is demonstrated: Task 1's attempt to write to the serial console through a
capability slot it does not own is rejected by the kernel.

---

## Repository Structure

```
kernel/
├── arch/x86_64/    # CPU-specific setup (GDT, IDT, paging) — stubs for now
├── boot/           # Kernel entry point (main.rs) and Limine protocol requests
├── docs/           # Architecture design documentation
├── drivers/        # Boot-essential drivers only (COM1 serial for early logging)
├── fs/             # Reserved: filesystem is a user-space service (Phase 2+)
├── interrupts/     # Reserved: exception/fault handling (Phase 1 fault isolation)
├── memory/         # Physical frame allocator + virtual memory mapper
├── process/        # Task abstraction, capability table, IPC
│   ├── capability.rs   # Capability + CapTable (per-process)
│   └── ipc.rs          # Rendezvous message passing
├── scheduler/      # Cooperative round-robin scheduler + context switch
├── syscall/        # Capability-gated kernel entry points (transitional)
├── tests/          # Kernel integration tests
└── userspace/      # Reserved: user-mode transition & ELF loading (Phase 2+)
```

> The `fs/`, `userspace/`, and `interrupts/` directories are intentionally empty stubs:
> per the directive, the kernel must **not** grow these subsystems. Filesystem, drivers,
> logging, and init are destined for user space (Phase 2+).

---

## Prerequisites

- **Rust** (nightly toolchain, selected automatically by `rust-toolchain.toml`)
- **QEMU** (`qemu-system-x86_64`)
- **mtools** (`mcopy`, `mformat`)
- **dosfstools** (`mkfs.vfat`)
- **parted**, and OVMF firmware (`/usr/share/OVMF/OVMF_CODE.fd`)

---

## How to Build and Run

### 1. Build the disk image

```bash
./build_disk.sh
```

### 2. Launch in QEMU

```bash
./run.sh
```

COM1 serial output is redirected to your host console. On boot you should see:

```
RunixOS kernel initialized.
Memory Map Entries:
  ...
Frame Allocator initialized. Usable start: 0x..., end: 0x...
Microkernel tasks loaded. Launching scheduler...
[Task 2 Logging Service] Received IPC from Task 1: Sensor data: Temp=24.5C
```

> **Bootloader note:** the bundled bootloader is Limine 7.13.3, which supports Limine base
> revision 2. The kernel pins `BaseRevision::with_revision(2)` accordingly. If you upgrade
> the bootloader in `limine-bin/`, you may raise the requested base revision to match.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
