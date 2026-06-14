# RunixOS

> A capability-based, IPC-driven distributed operating system research platform written in Rust.

RunixOS is an experimental operating system designed to explore what modern systems software might look like if capabilities, message passing, and persistence were treated as first-class principles from the beginning rather than added as features later.

The project investigates:

* Minimal kernels and rich user-space services
* Capability-based security
* IPC-first system design
* User-space drivers and services
* Transparent service distribution
* Persistent system state
* Service migration and recovery

RunixOS is not intended to be a Linux replacement or a POSIX-compatible operating system. It is a clean-slate systems research platform focused on isolation, modularity, and recoverability.

---

# Project Status

Status: **Implemented**

* [x] Milestone 0 – Boot Infrastructure
* [x] Phase 1 – Microkernel Core
* [x] Phase 2 – Userspace Shift
* [x] Phase 3 – System Coherence
* [x] Phase 4 – Isolation & Safety Hardening
* [x] Phase 5 – Async IPC & System Scaling
* [x] Phase 6 – Userspace Ecosystem
* [x] Phase 7 – Stress, Scale & Failure Testing
* [x] Phase 8 – Security & Capability Maturity
* [x] Phase 9 – System Stability & Self-Sufficiency
* [x] Phase 10 – Distributed Persistence & Service Migration

---

# Guiding Principles

1. Minimal kernel, rich user space.
2. Capabilities are the sole security primitive.
3. IPC is the sole communication primitive.
4. No ambient authority.
5. Isolation by default.
6. Distribution should be transparent.
7. Persistence should be a first-class system property.
8. Correctness over performance.
9. Simplicity over feature count.

---

# System Architecture

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

# Core Architecture

RunixOS is built around four fundamental ideas:

## 1. Minimal Kernel

The kernel is intentionally small and is responsible only for:

* Physical memory management
* Virtual memory management
* Scheduling
* IPC routing
* Capability enforcement
* Checkpoint and persistence primitives

All other functionality exists in user space.

---

## 2. Capability-Based Security

Every resource is protected by a capability.

Capabilities are:

* Unforgeable
* Revocable
* Delegatable
* Serializable
* Optionally cryptographically signed

No process can perform an operation without possessing an explicit capability granting that authority.

There is no ambient authority anywhere in the system.

---

## 3. IPC-First Design

All interactions occur through message passing.

Processes communicate exclusively via:

```text
send(capability, message)
receive()
```

The programming model remains identical whether the target service is:

* local
* remote
* migrated

No shared memory communication exists between isolated services.

---

## 4. User-Space Services

The following systems execute entirely in user space:

* Device drivers
* Filesystem services
* Logging services
* System supervisor
* Debugging and introspection services
* Distributed services

The kernel acts solely as a coordinator and enforcement layer.

---

# Implemented Architecture

## Milestone 0 – Boot Infrastructure

Implemented:

* Limine bootloader integration
* UEFI boot via OVMF
* Higher-half kernel mapping
* Serial console
* Build and disk pipeline
* QEMU development environment

---

## Phase 1 – Microkernel Core

Implemented:

* Physical memory manager
* Virtual memory manager
* Round-robin scheduler
* IPC subsystem
* Capability subsystem
* Process abstraction

---

## Phase 2 – Userspace Shift

Implemented:

* User-mode execution
* Process isolation
* IPC-based service interaction
* Initial user-space services

---

## Phase 3 – System Coherence

Implemented:

* Capability sealing
* Capability scoping
* Capability inheritance
* Structured IPC messages
* Kernel dispatch layer

---

## Phase 4 – Isolation & Safety Hardening

Implemented:

* Strict address-space isolation
* Fault containment
* Capability violation handling
* Kernel resilience against process failures

---

## Phase 5 – Async IPC & System Scaling

Implemented:

* Non-blocking IPC
* Message queues
* Structured message schemas
* High-concurrency process support

---

## Phase 6 – Userspace Ecosystem

Implemented:

* Init system
* Logging service
* RAM filesystem service
* Device abstraction service
* Service supervisor

---

## Phase 7 – Stress, Scale & Failure Testing

Implemented:

* Process scaling tests
* IPC stress testing
* Resource exhaustion handling
* Failure recovery semantics
* Service crash containment

---

## Phase 8 – Security & Capability Maturity

Implemented:

* Capability revocation propagation
* Capability audit system
* Capability delegation rules
* Least-authority enforcement

---

## Phase 9 – System Stability & Self-Sufficiency

Implemented:

* Deterministic boot sequence
* Watchdog services
* Service restart capabilities
* Recovery mode
* Kernel survival mechanisms

---

## Phase 10 – Distributed Persistence & Service Migration

Implemented:

* System checkpointing
* Process snapshots
* Persistent capabilities
* Network-transparent IPC
* Service migration
* Persistent service relocation
* Distributed fault tolerance

---

# Distributed Persistence Model

RunixOS treats system state as a first-class object.

The following entities are persistent:

* Processes
* Capability graphs
* IPC queues
* Scheduler state
* Filesystem state
* Service metadata

The system supports:

```text
save-system-state
shutdown
reboot
restore-system-state
continue execution
```

without reconstructing services from scratch.

---

# Service Migration

Services may migrate between machines while preserving state.

Clients continue using existing capabilities without modification.

```text
Node A:
    Filesystem Service

Node B:
    Logger Service

Filesystem Service:
    Node A → Node B
```

The programming model remains unchanged.

---

# Research Questions

RunixOS explores the following questions:

1. Can capabilities completely replace traditional access control?
2. Can an IPC-first operating system remain practical at scale?
3. Can user-space services provide sufficient reliability?
4. Can distribution be made transparent to applications?
5. Can operating system state become a persistent object?
6. Can services survive failures through checkpointing and restoration?
7. Can a capability-based operating system scale from a single machine to a distributed system without changing its programming model?

---

# Final Demonstration

A complete RunixOS deployment can:

1. Boot multiple nodes.
2. Launch distributed services.
3. Checkpoint service state.
4. Migrate services between machines.
5. Recover from node failures.
6. Restore execution transparently.
7. Continue operation without application changes.

---

# Final Research Thesis

RunixOS demonstrates that:

> A capability-based, IPC-driven distributed operating system can support persistence, migration, and fault tolerance while maintaining a minimal kernel, strict isolation, and a uniform programming model.

---

# Final System State

RunixOS is a capability-based, IPC-driven distributed operating system research platform in Rust featuring:

* Minimal kernel primitives
* User-space services and drivers
* Strong capability security
* Transparent distribution
* Persistent system state
* Service migration
* Fault tolerance
* Strict isolation by design

RunixOS is an exploration of what an operating system might look like if capabilities, message passing, and persistence were treated as foundational principles rather than optional features.

