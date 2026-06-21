CS 4515 - Computer Architecture

| Catalog Topic (Verbatim) | Implementation Location | Explanation Reference |
|---|---|---|
| instruction-level and thread-level pipelining | [kernel/arch_sim/mod.rs](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/arch_sim/mod.rs) (Architecture simulation toolkit subsystem) | EVALUATION.md: Architecture Simulation Toolkit Results |
| multi-core systems (boot-time AP enablement only; scheduling remains BSP-only) | [kernel/arch/x86_64/apic.rs](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/arch/x86_64/apic.rs), [kernel/boot/main.rs](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/boot/main.rs) (AP wake-up via LAPIC IPI; APs idle on `hlt` after init) | ARCHITECTURE.md: SMP |
| caching and memory hierarchies | [kernel/arch_sim/mod.rs](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/arch_sim/mod.rs) (Architecture simulation toolkit subsystem) | EVALUATION.md: Architecture Simulation Toolkit Results |
| simulating significant components of modern computer architectures | [kernel/arch_sim/mod.rs](file:///home/armaan/Documents/vscode/OperatingSystem/kernel/arch_sim/mod.rs) (Architecture simulation toolkit subsystem) | ARCHITECTURE.md: Architecture Simulation Toolkit |
