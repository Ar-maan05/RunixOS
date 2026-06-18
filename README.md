# RunixOS

RunixOS is a capability-based, IPC-driven distributed operating system that supports persistence, service migration, and fault tolerance while maintaining a minimal kernel, strict isolation, and a uniform programming model. It serves as an experimental systems research platform written in Rust.

---

## Core Principles

- **Minimal Kernel:** The kernel implements only memory management, scheduling, IPC, and capability enforcement. All other services are deferred to user space.
- **Capabilities as the Sole Security Primitive:** Every kernel operation requires a valid, unforgeable, kernel-issued capability.
- **IPC as the Sole Communication Primitive:** Message passing is the only communication mechanism, with no shared memory between tasks.
- **No Ambient Authority:** Tasks only have authority over resources explicitly granted to them in their capability table.
- **Isolation by Default:** Tasks run in isolated address spaces with hardware-enforced protection boundaries.

---

## Subsystem Inventory

RunixOS is composed of the following subsystems. For detailed design documents, see [ARCHITECTURE.md](file:///home/armaan/Documents/vscode/OperatingSystem/ARCHITECTURE.md).

- **Boot and Platform Bring-up:** Manages UEFI and Limine handoff, GDT, TSS, and initialization order.
- **Memory Management:** Implements page table mapping, page frame allocation, and user buffer safety validation.
- **Capability System:** Manages resource capability tables, rights attenuation, capability sealing, and transitive revocation propagation.
- **Task Model and Scheduler:** Governs task execution contexts, state transitions, and round-robin scheduling.
- **Preemption:** Coordinates PIT timer interrupts and non-preemptible critical sections.
- **Interrupts and Fault Containment:** Manages the IDT, exception handling, and isolating crashes to protect the system.
- **IPC:** Manages synchronous rendezvous and asynchronous message queues.
- **Syscall Surface:** Handles software interrupt entry decoding and capability-gated dispatch.
- **Interactive Console:** Provides a command-line interface over serial to interact with kernel subsystems.
- **Persistence:** Supports consistent system-wide checkpointing and state restoration in memory.
- **Distribution Substrate:** Implements location-transparent routing, service migration, and failover.
- **Filesystem Service:** Provides an IPC-accessed, capability-gated in-memory RAM filesystem.
- **Device Abstraction:** Abstracts serial and keyboard hardware behind capability-gated IPC interfaces.
- **Synchronization Service:** Provides mutexes and semaphores over IPC with deferred-reply blocking.
- **Architecture Simulation Toolkit:** Simulates set-associative caches and execution pipelines from kernel traces.
- **SMP:** Boots multiple CPU cores and coordinates inter-processor interrupts.

---

## What RunixOS Can Do

- Run a live capability-gated interactive console over a serial connection.
- Enforce strict memory isolation between user tasks and the kernel.
- Contain application and driver crashes, recovering services automatically via a watchdog.
- Perform system checkpoints and rollback states in memory.
- Migrate active services between logical nodes transparently without client interruption.
- Coordinate synchronization objects (mutexes and semaphores) over IPC.
- Run multi-core execution (SMP) with AP startup and IPI coordination.
- Feed cache and pipeline simulators using trace buffers recorded from live system execution.

---

## Build and Run

### Requirements
- Rust nightly toolchain
- QEMU (`qemu-system-x86_64`)
- `mtools`
- `dosfstools`
- `parted`
- UEFI OVMF firmware (located at `/usr/share/OVMF/OVMF_CODE.fd`)

### Build
To build the kernel and compile the bootable disk image:
```bash
./build_disk.sh
```

### Run
To launch the interactive console:
```bash
./run.sh
```

### Headless Verification
To execute the automated headless test harness:
```bash
timeout 12 qemu-system-x86_64 -M q35 \
  -drive if=pflash,unit=0,format=raw,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on \
  -drive file=disk.img,format=raw,media=disk \
  -serial stdio -m 2G -display none -no-reboot > serial.log 2>&1
```

---

## Repository Structure

- [kernel/boot/](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/boot/) - UEFI boot loader entry and task loading setup
- [kernel/memory/](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/memory/) - Frame allocation and virtual memory mapping
- [kernel/process/](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/process/) - Tasks, capability tables, snapshotting, and location-transparent IPC routing
- [kernel/scheduler/](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/scheduler/) - Cooperative and preemptive task selectors
- [kernel/preempt/](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/preempt/) - Critical section guards and preemption logic
- [kernel/interrupts/](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/interrupts/) - IDT descriptors, hardware IRQs, and CPU exception recovery handlers
- [kernel/syscall/](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/syscall/) - System call entry vectors and dispatch routing
- [kernel/shell/](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/shell/) - Interactive console commands and filesystem/synchronization services
- [kernel/drivers/](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/drivers/) - Boot drivers, serial console interface, and spinlock synchronization
- [kernel/arch_sim/](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/arch_sim/) - Set-associative cache and pipeline simulators
- [kernel/userspace/](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/userspace/) - Ring-3 assembly application binaries

---

## Documentation Pointers

- [ARCHITECTURE.md](file:///home/armaan/Documents/vscode/OperatingSystem/ARCHITECTURE.md) - Deep dive into design, invariants, and implementation of subsystems
- [CONSOLE_SPEC.md](file:///home/armaan/Documents/vscode/OperatingSystem/CONSOLE_SPEC.md) - Interactive console command syntax and expected outputs
- [EVALUATION.md](file:///home/armaan/Documents/vscode/OperatingSystem/EVALUATION.md) - Experimental answers to research questions backed by live QEMU outputs
- [CS3013_MAPPING.md](file:///home/armaan/Documents/vscode/OperatingSystem/CS3013_MAPPING.md) - Mapping of operating systems topics to RunixOS implementation
- [CS4513_MAPPING.md](file:///home/armaan/Documents/vscode/OperatingSystem/CS4513_MAPPING.md) - Mapping of distributed computing systems topics to RunixOS implementation
- [CS4515_MAPPING.md](file:///home/armaan/Documents/vscode/OperatingSystem/CS4515_MAPPING.md) - Mapping of computer architecture topics to RunixOS implementation
