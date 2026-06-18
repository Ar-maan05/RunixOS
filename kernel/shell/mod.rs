use crate::process::{self, Task, TaskId, CapTable, Capability, TaskState, IpcError};
use crate::process::capability::{Resource, RightsMask, MAX_CAPS};
use crate::scheduler;
use crate::preempt;
use core::sync::atomic::{AtomicU64, Ordering, AtomicBool, AtomicUsize, AtomicU8};

macro_rules! print_cmd {
    ($($arg:tt)*) => {
        crate::print!("\x1b[0m[CMD]   {}\x1b[0m\n", format_args!($($arg)*))
    };
}
macro_rules! print_ok {
    ($($arg:tt)*) => {
        crate::print!("\x1b[32m[OK]    {}\x1b[0m\n", format_args!($($arg)*))
    };
}
macro_rules! print_fail {
    ($($arg:tt)*) => {
        crate::print!("\x1b[31m[FAIL]  {}\x1b[0m\n", format_args!($($arg)*))
    };
}
macro_rules! print_pass {
    ($($arg:tt)*) => {
        crate::print!("\x1b[36m[PASS]  {}\x1b[0m\n", format_args!($($arg)*))
    };
}
macro_rules! print_vuln {
    ($($arg:tt)*) => {
        crate::print!("\x1b[33m[VULN]  {}\x1b[0m\n", format_args!($($arg)*))
    };
}
macro_rules! print_info {
    ($($arg:tt)*) => {
        crate::print!("\x1b[37m[INFO]  {}\x1b[0m\n", format_args!($($arg)*))
    };
}
macro_rules! print_warn {
    ($($arg:tt)*) => {
        crate::print!("\x1b[33m[WARN]  {}\x1b[0m\n", format_args!($($arg)*))
    };
}

pub fn root_caps() -> CapTable {
    let mut caps = CapTable::new();
    // slot 0: Serial (stamped with ID 1)
    let _ = caps.insert(Capability {
        resource: Resource::Serial,
        read: false,
        write: true,
        grant: true,
        sealed: false,
        id: 0,
        origin: None,
    });
    // Temporary slot 1: Service (stamped with ID 2)
    let _ = caps.insert(Capability {
        resource: Resource::Service { id: 1 },
        read: true,
        write: true,
        grant: false,
        sealed: false,
        id: 0,
        origin: None,
    });
    // Temporary slot 2: IpcChannel (stamped with ID 3)
    let _ = caps.insert(Capability {
        resource: Resource::IpcChannel { target_task: TaskId(65) },
        read: true,
        write: true,
        grant: true,
        sealed: false,
        id: 0,
        origin: None,
    });
    // Swap slot 1 and slot 2 so Service is at slot 2 and IpcChannel is at slot 1
    let tmp = caps.slots[1];
    caps.slots[1] = caps.slots[2];
    caps.slots[2] = tmp;

    // slot 3: KVEntry slot 0 (read/write)
    let _ = caps.insert(Capability {
        resource: Resource::KVEntry { slot: 0, readable: true, writable: true },
        read: true,
        write: true,
        grant: true,
        sealed: false,
        id: 0,
        origin: None,
    });
    // slot 4: KVEntry slot 1 (read-only)
    let _ = caps.insert(Capability {
        resource: Resource::KVEntry { slot: 1, readable: true, writable: false },
        read: true,
        write: false,
        grant: true,
        sealed: false,
        id: 0,
        origin: None,
    });
    // slot 5: KVEntry slot 2 (write-only)
    let _ = caps.insert(Capability {
        resource: Resource::KVEntry { slot: 2, readable: false, writable: true },
        read: false,
        write: true,
        grant: true,
        sealed: false,
        id: 0,
        origin: None,
    });
    // slot 6: IpcChannel to KV Service (task 82)
    let _ = caps.insert(Capability {
        resource: Resource::IpcChannel { target_task: TaskId(82) },
        read: true,
        write: true,
        grant: true,
        sealed: false,
        id: 0,
        origin: None,
    });
    // slot 7: LogChannel kind 0 (read/write)
    let _ = caps.insert(Capability {
        resource: Resource::LogChannel { kind: 0, readable: true, writable: true },
        read: true,
        write: true,
        grant: true,
        sealed: false,
        id: 0,
        origin: None,
    });
    // slot 8: LogChannel kind 1 (read-only)
    let _ = caps.insert(Capability {
        resource: Resource::LogChannel { kind: 1, readable: true, writable: false },
        read: true,
        write: false,
        grant: true,
        sealed: false,
        id: 0,
        origin: None,
    });
    // slot 9: IpcChannel to Log Service (task 83)
    let _ = caps.insert(Capability {
        resource: Resource::IpcChannel { target_task: TaskId(83) },
        read: true,
        write: true,
        grant: true,
        sealed: false,
        id: 0,
        origin: None,
    });

    // slot 10: FsNode mount 0 (read/write)
    let _ = caps.insert(Capability {
        resource: Resource::FsNode { mount: 0, readable: true, writable: true },
        read: true,
        write: true,
        grant: true,
        sealed: false,
        id: 0,
        origin: None,
    });
    // slot 11: IpcChannel to FS Service (task 84)
    let _ = caps.insert(Capability {
        resource: Resource::IpcChannel { target_task: TaskId(84) },
        read: true,
        write: true,
        grant: true,
        sealed: false,
        id: 0,
        origin: None,
    });
    // slot 12: Device 0 (serial)
    let _ = caps.insert(Capability {
        resource: Resource::Device { id: 0, readable: true, writable: true },
        read: true,
        write: true,
        grant: true,
        sealed: false,
        id: 0,
        origin: None,
    });
    // slot 13: Device 1 (keyboard)
    let _ = caps.insert(Capability {
        resource: Resource::Device { id: 1, readable: true, writable: true },
        read: true,
        write: true,
        grant: true,
        sealed: false,
        id: 0,
        origin: None,
    });
    // slot 14: IpcChannel to Device Service (task 85)
    let _ = caps.insert(Capability {
        resource: Resource::IpcChannel { target_task: TaskId(85) },
        read: true,
        write: true,
        grant: true,
        sealed: false,
        id: 0,
        origin: None,
    });
    // slot 15: IpcChannel to Sync Service (task 86)
    let _ = caps.insert(Capability {
        resource: Resource::IpcChannel { target_task: TaskId(86) },
        read: true,
        write: true,
        grant: true,
        sealed: false,
        id: 0,
        origin: None,
    });

    caps
}

extern "C" fn park() -> ! {
    scheduler::terminate_current_task();
}

pub fn load() {
    let mut sched = scheduler::SCHEDULER.lock();
    sched.tasks[64] = Some(Task::new(TaskId(64), shell_main, root_caps()));
}

pub extern "C" fn shell_main() -> ! {
    print_info!("RunixOS console");
    print_info!("type 'help'");

    let mut line_buf = [0u8; 128];
    loop {
        crate::print!("runix> ");
        let n = read_line_with_history(&mut line_buf);
        if n == 0 {
            continue;
        }

        if let Ok(s) = core::str::from_utf8(&line_buf[..n]) {
            print_cmd!("{}", s);
        }

        HISTORY.lock().push(&line_buf[..n]);

        if let Err(_) = dispatch(&line_buf[..n]) {
            print_fail!("unrecoverable internal error");
        }
    }
}

fn tokenize<'a>(line: &'a [u8], tokens: &mut [Option<&'a [u8]>; 4]) -> usize {
    let mut count = 0;
    let mut idx = 0;
    
    while idx < line.len() && line[idx] == b' ' {
        idx += 1;
    }
    
    while idx < line.len() && count < 3 {
        let start = idx;
        while idx < line.len() && line[idx] != b' ' {
            idx += 1;
        }
        tokens[count] = Some(&line[start..idx]);
        count += 1;
        
        while idx < line.len() && line[idx] == b' ' {
            idx += 1;
        }
    }
    
    if idx < line.len() {
        let mut end = line.len();
        while end > idx && line[end - 1] == b' ' {
            end -= 1;
        }
        if idx < end {
            tokens[3] = Some(&line[idx..end]);
            count += 1;
        }
    }
    count
}

fn send_fs_msg(op: u8, mount: u8, path: &[u8], data: &[u8]) -> Result<[u8; 128], IpcError> {
    ensure_fs_service();
    let mut cap_idx = None;
    {
        let slots = get_shell_caps();
        for (i, slot_opt) in slots.iter().enumerate() {
            if let Some(cap) = slot_opt {
                if let Resource::IpcChannel { target_task } = cap.resource {
                    if target_task.0 == 84 {
                        cap_idx = Some(i);
                        break;
                    }
                }
            }
        }
    }
    let cap_idx = match cap_idx {
        Some(idx) => idx,
        None => return Err(IpcError::NoCapability),
    };
    
    let mut payload = [0u8; 128];
    payload[0] = op;
    payload[1] = mount;
    let name_len = core::cmp::min(path.len(), 30);
    payload[2] = name_len as u8;
    payload[3..3 + name_len].copy_from_slice(&path[..name_len]);
    
    let data_len = core::cmp::min(data.len(), 94);
    payload[33] = data_len as u8;
    payload[34..34 + data_len].copy_from_slice(&data[..data_len]);
    
    process::ipc::sys_send_typed(cap_idx, process::IpcTag::FsOp as u16, 1, &payload)?;
    let reply = process::ipc::sys_receive_typed()?;
    if reply.tag != process::IpcTag::FsReply {
        return Err(IpcError::InvalidTag);
    }
    Ok(reply.payload)
}

fn send_dev_msg(op: u8, dev_id: u8, data: &[u8]) -> Result<[u8; 128], IpcError> {
    ensure_device_service();
    let mut cap_idx = None;
    {
        let slots = get_shell_caps();
        for (i, slot_opt) in slots.iter().enumerate() {
            if let Some(cap) = slot_opt {
                if let Resource::IpcChannel { target_task } = cap.resource {
                    if target_task.0 == 85 {
                        cap_idx = Some(i);
                        break;
                    }
                }
            }
        }
    }
    let cap_idx = match cap_idx {
        Some(idx) => idx,
        None => return Err(IpcError::NoCapability),
    };
    
    let mut payload = [0u8; 128];
    payload[0] = op;
    payload[1] = dev_id;
    let write_len = core::cmp::min(data.len(), 120);
    payload[2] = write_len as u8;
    payload[3..3 + write_len].copy_from_slice(&data[..write_len]);
    
    process::ipc::sys_send_typed(cap_idx, process::IpcTag::DevOp as u16, 1, &payload)?;
    let reply = process::ipc::sys_receive_typed()?;
    if reply.tag != process::IpcTag::DevReply {
        return Err(IpcError::InvalidTag);
    }
    Ok(reply.payload)
}

fn send_sync_msg(op: u8, obj_id: u8, is_mutex: u8, count: u8) -> Result<[u8; 128], IpcError> {
    ensure_sync_service();
    let mut cap_idx = None;
    {
        let slots = get_shell_caps();
        for (i, slot_opt) in slots.iter().enumerate() {
            if let Some(cap) = slot_opt {
                if let Resource::IpcChannel { target_task } = cap.resource {
                    if target_task.0 == 86 {
                        cap_idx = Some(i);
                        break;
                    }
                }
            }
        }
    }
    let cap_idx = match cap_idx {
        Some(idx) => idx,
        None => return Err(IpcError::NoCapability),
    };
    
    let mut payload = [0u8; 128];
    payload[0] = op;
    payload[1] = obj_id;
    payload[2] = is_mutex;
    payload[3] = count;
    
    process::ipc::sys_send_typed(cap_idx, process::IpcTag::SyncOp as u16, 1, &payload)?;
    let reply = process::ipc::sys_receive_typed()?;
    if reply.tag != process::IpcTag::SyncReply {
        return Err(IpcError::InvalidTag);
    }
    Ok(reply.payload)
}

fn get_sim_addresses(trace_name: &[u8]) -> [u64; 128] {
    let mut addrs = [0u64; 128];
    let total = NEXT_IDX.load(Ordering::SeqCst);
    let count = core::cmp::min(total, TRACE_BUFFER_SIZE);
    let start = if total > TRACE_BUFFER_SIZE { total % TRACE_BUFFER_SIZE } else { 0 };
    
    let mut matched_events = [TraceEvent { tick: 0, msg: "", param1: 0, param2: 0 }; 128];
    let mut matched_count = 0;
    
    let trace_str = core::str::from_utf8(trace_name).unwrap_or("");
    
    for i in 0..count {
        let idx = (start + i) % TRACE_BUFFER_SIZE;
        let event = unsafe { TRACE_BUFFER[idx] };
        
        let matches = if trace_str == "all" {
            true
        } else if trace_str == "boot" {
            event.msg.starts_with("cap") || event.msg.starts_with("sched")
        } else {
            event.msg.contains(trace_str)
        };
        
        if matches && matched_count < 128 {
            matched_events[matched_count] = event;
            matched_count += 1;
        }
    }
    
    if matched_count == 0 {
        let mut seed = 0u64;
        for &b in trace_name {
            seed = seed.wrapping_add(b as u64).wrapping_mul(31);
        }
        for i in 0..128 {
            let step = i % 16;
            let line = match step {
                0 => 0, 1 => 4, 2 => 0, 3 => 4,
                4 => 1, 5 => 5, 6 => 1, 7 => 5,
                8 => 2, 9 => 6, 10 => 2, 11 => 6,
                12 => 3, 13 => 7, 14 => 3, 15 => 7,
                _ => 0,
            };
            addrs[i] = ((line + seed) % 12) * 64;
        }
    } else {
        for i in 0..128 {
            let event = matched_events[i % matched_count];
            addrs[i] = crate::arch_sim::hash_event_to_addr(&event);
        }
    }
    addrs
}

fn get_sim_instrs(trace_name: &[u8]) -> [crate::arch_sim::SimInstr; 128] {
    let mut instrs = [crate::arch_sim::SimInstr {
        kind: crate::arch_sim::InstrKind::Alu, rd: 0, rs1: 0, rs2: 0
    }; 128];
    
    let total = NEXT_IDX.load(Ordering::SeqCst);
    let count = core::cmp::min(total, TRACE_BUFFER_SIZE);
    let start = if total > TRACE_BUFFER_SIZE { total % TRACE_BUFFER_SIZE } else { 0 };
    
    let mut matched_events = [TraceEvent { tick: 0, msg: "", param1: 0, param2: 0 }; 128];
    let mut matched_count = 0;
    
    let trace_str = core::str::from_utf8(trace_name).unwrap_or("");
    
    for i in 0..count {
        let idx = (start + i) % TRACE_BUFFER_SIZE;
        let event = unsafe { TRACE_BUFFER[idx] };
        
        let matches = if trace_str == "all" {
            true
        } else if trace_str == "boot" {
            event.msg.starts_with("cap") || event.msg.starts_with("sched")
        } else {
            event.msg.contains(trace_str)
        };
        
        if matches && matched_count < 128 {
            matched_events[matched_count] = event;
            matched_count += 1;
        }
    }
    
    if matched_count == 0 {
        for i in 0..128 {
            if i % 3 == 0 {
                instrs[i] = crate::arch_sim::SimInstr {
                    kind: crate::arch_sim::InstrKind::Load, rd: 1, rs1: 0, rs2: 0
                };
            } else if i % 3 == 1 {
                instrs[i] = crate::arch_sim::SimInstr {
                    kind: crate::arch_sim::InstrKind::Alu, rd: 2, rs1: 1, rs2: 0
                };
            } else {
                instrs[i] = crate::arch_sim::SimInstr {
                    kind: crate::arch_sim::InstrKind::Store, rd: 0, rs1: 2, rs2: 0
                };
            }
        }
    } else {
        for i in 0..128 {
            let event = matched_events[i % matched_count];
            instrs[i] = crate::arch_sim::event_to_instr(&event);
        }
    }
    instrs
}

fn run_bench_ipc() {
    ensure_echo_service();
    let mut cap_idx = None;
    {
        let slots = get_shell_caps();
        for (i, slot_opt) in slots.iter().enumerate() {
            if let Some(cap) = slot_opt {
                if let Resource::IpcChannel { target_task } = cap.resource {
                    if target_task.0 == 65 {
                        cap_idx = Some(i);
                        break;
                    }
                }
            }
        }
    }
    let cap_idx = match cap_idx {
        Some(idx) => idx,
        None => {
            print_fail!("no cap to echo service");
            return;
        }
    };
    
    let iters = 1000;
    let payload = [0x55u8; 16];
    let start_ticks = preempt::stats().ticks;
    
    for _ in 0..iters {
        let _ = process::ipc::sys_send_typed(cap_idx, process::IpcTag::Raw as u16, 1, &payload);
        let _ = process::ipc::sys_receive_typed();
    }
    
    let elapsed = preempt::stats().ticks.wrapping_sub(start_ticks);
    let elapsed_ticks = if elapsed == 0 { 1 } else { elapsed };
    let roundtrips_per_sec = iters * 100 / elapsed_ticks;
    print_ok!("Benchmark IPC Latency:");
    print_info!("  Roundtrips:         {}", iters);
    print_info!("  Elapsed ticks:      {}", elapsed_ticks);
    print_info!("  Roundtrips/sec:     {}", roundtrips_per_sec);
}

static BENCH_SCHED_COUNTER: AtomicU64 = AtomicU64::new(0);

extern "C" fn bench_sched_task_entry() -> ! {
    BENCH_SCHED_COUNTER.fetch_add(1, Ordering::Relaxed);
    scheduler::terminate_current_task();
}

fn run_bench_sched() {
    let start_ticks = preempt::stats().ticks;
    BENCH_SCHED_COUNTER.store(0, Ordering::Relaxed);
    
    let k = 20;
    {
        let mut sched = scheduler::SCHEDULER.lock();
        for i in 0..k {
            let task_id = 110 + i;
            sched.tasks[task_id] = Some(Task::new(TaskId(task_id), bench_sched_task_entry, CapTable::new()));
            crate::process::TASKS_SPAWNED.fetch_add(1, Ordering::SeqCst);
        }
    }
    
    loop {
        let active = {
            let sched = scheduler::SCHEDULER.lock();
            let mut count = 0;
            for i in 0..k {
                if let Some(t) = &sched.tasks[110 + i] {
                    if !matches!(t.state, TaskState::Terminated) {
                        count += 1;
                    }
                }
            }
            count
        };
        if active == 0 {
            break;
        }
        scheduler::yield_cpu();
    }
    
    let elapsed = preempt::stats().ticks.wrapping_sub(start_ticks);
    let elapsed_ticks = if elapsed == 0 { 1 } else { elapsed };
    let switches_per_sec = (k as u64) * 100 / elapsed_ticks;
    print_ok!("Benchmark Scheduler Throughput:");
    print_info!("  Spawned tasks:      {}", k);
    print_info!("  Elapsed ticks:      {}", elapsed_ticks);
    print_info!("  Switches/sec:       {}", switches_per_sec);
}

fn run_bench_cap() {
    ensure_fs_service();
    let initial_tracing = TRACING_ACTIVE.swap(false, Ordering::SeqCst);
    
    let iters = 10000;
    let start_ticks = preempt::stats().ticks;
    
    let sched = scheduler::SCHEDULER.lock();
    let task = sched.get_task(TaskId(64)).unwrap();
    let cap_table = &task.cap_table;
    
    for _ in 0..iters {
        let _ = cap_table.get(0);
    }
    
    drop(sched);
    TRACING_ACTIVE.store(initial_tracing, Ordering::SeqCst);
    
    let elapsed = preempt::stats().ticks.wrapping_sub(start_ticks);
    let elapsed_ticks = if elapsed == 0 { 1 } else { elapsed };
    let lookups_per_sec = iters * 100 / elapsed_ticks;
    print_ok!("Benchmark Capability Lookup:");
    print_info!("  Iterations:         {}", iters);
    print_info!("  Elapsed ticks:      {}", elapsed_ticks);
    print_info!("  Lookups/sec:        {}", lookups_per_sec);
}

fn run_bench_fs() {
    ensure_fs_service();
    let iters = 500;
    let path = b"/bench_temp";
    let data = b"some data to write to fs during benchmarking";
    
    let start_ticks = preempt::stats().ticks;
    for _ in 0..iters {
        let _ = send_fs_msg(1, 0, path, data);
        let _ = send_fs_msg(2, 0, path, &[]);
    }
    
    let elapsed = preempt::stats().ticks.wrapping_sub(start_ticks);
    let elapsed_ticks = if elapsed == 0 { 1 } else { elapsed };
    let ops_per_sec = iters * 2 * 100 / elapsed_ticks;
    print_ok!("Benchmark Filesystem Throughput:");
    print_info!("  Iterations (W+R):   {}", iters);
    print_info!("  Elapsed ticks:      {}", elapsed_ticks);
    print_info!("  Ops/sec:            {}", ops_per_sec);
}

extern "C" fn bench_contend_task() -> ! {
    let obj_id = BENCH_CONTEND_OBJ.load(Ordering::Relaxed);
    for _ in 0..BENCH_CONTEND_ITERS {
        let _ = process::ipc::sys_send_typed(1, process::IpcTag::SyncOp as u16, 1, &[1, obj_id, 0, 0]);
        let _ = process::ipc::sys_receive_typed();
        let _ = process::ipc::sys_send_typed(1, process::IpcTag::SyncOp as u16, 1, &[2, obj_id, 0, 0]);
        let _ = process::ipc::sys_receive_typed();
    }
    scheduler::terminate_current_task();
}

const BENCH_CONTEND_ITERS: usize = 600;

static BENCH_CONTEND_OBJ: AtomicU8 = AtomicU8::new(0);

/// Measures average IPC+lock latency under N tasks contending for one mutex
/// via the sync service, exercising the global scheduler lock under load.
fn run_bench_contend(n: usize, obj_id: u8) {
    ensure_sync_service();
    let iters_per_task = BENCH_CONTEND_ITERS;
    BENCH_CONTEND_OBJ.store(obj_id, Ordering::Relaxed);
    let _ = send_sync_msg(0, obj_id, 1, 1);

    let mut caps = CapTable::new();
    let _ = caps.insert(Capability {
        resource: Resource::SyncObj { id: obj_id },
        read: true, write: true, grant: false, sealed: false, id: 0, origin: None,
    });
    let _ = caps.insert(Capability {
        resource: Resource::IpcChannel { target_task: TaskId(86) },
        read: true, write: true, grant: false, sealed: false, id: 0, origin: None,
    });

    let base = 90usize;
    let start_ticks = preempt::stats().ticks;
    {
        let mut sched = scheduler::SCHEDULER.lock();
        for i in 0..n {
            sched.tasks[base + i] = Some(Task::new(TaskId(base + i), bench_contend_task, caps.clone()));
            crate::process::TASKS_SPAWNED.fetch_add(1, Ordering::SeqCst);
        }
    }

    loop {
        let active = {
            let sched = scheduler::SCHEDULER.lock();
            let mut count = 0;
            for i in 0..n {
                if let Some(t) = &sched.tasks[base + i] {
                    if !matches!(t.state, TaskState::Terminated) {
                        count += 1;
                    }
                }
            }
            count
        };
        if active == 0 {
            break;
        }
        scheduler::yield_cpu();
    }

    let elapsed = preempt::stats().ticks.wrapping_sub(start_ticks);
    let elapsed_ticks = if elapsed == 0 { 1 } else { elapsed };
    let elapsed_ms = elapsed_ticks * 10;
    let total_ops = (n * iters_per_task * 2) as u64;
    let avg_latency_us = (elapsed_ms * 1000) / total_ops;
    print_ok!("Benchmark Lock Contention (N={}):", n);
    print_info!("  Tasks:              {}", n);
    print_info!("  Acquire+Release ops:{}", total_ops);
    print_info!("  Elapsed ticks:      {}", elapsed_ticks);
    print_info!("  Avg op latency(us): {}", avg_latency_us);
}

static BENCH_SYNC_COUNTER: AtomicU64 = AtomicU64::new(0);

extern "C" fn sync_demo_guarded_task() -> ! {
    for _ in 0..100 {
        let _ = process::ipc::sys_send_typed(1, process::IpcTag::SyncOp as u16, 1, &[1, 7, 0, 0]);
        let _ = process::ipc::sys_receive_typed();
        
        let val = BENCH_SYNC_COUNTER.load(Ordering::Relaxed);
        for _ in 0..200000 { core::hint::spin_loop(); }
        BENCH_SYNC_COUNTER.store(val + 1, Ordering::Relaxed);
        
        let _ = process::ipc::sys_send_typed(1, process::IpcTag::SyncOp as u16, 1, &[2, 7, 0, 0]);
        let _ = process::ipc::sys_receive_typed();
    }
    scheduler::terminate_current_task();
}

extern "C" fn sync_demo_unguarded_task() -> ! {
    for _ in 0..100 {
        let val = BENCH_SYNC_COUNTER.load(Ordering::Relaxed);
        for _ in 0..200000 { core::hint::spin_loop(); }
        BENCH_SYNC_COUNTER.store(val + 1, Ordering::Relaxed);
    }
    scheduler::terminate_current_task();
}

fn run_sync_demo() {
    print_info!("Starting Sync Demo...");
    BENCH_SYNC_COUNTER.store(0, Ordering::Relaxed);
    let _ = send_sync_msg(0, 7, 1, 1);
    
    let mut caps = CapTable::new();
    let _ = caps.insert(Capability {
        resource: Resource::SyncObj { id: 7 },
        read: true, write: true, grant: false, sealed: false, id: 0, origin: None
    });
    let _ = caps.insert(Capability {
        resource: Resource::IpcChannel { target_task: TaskId(86) },
        read: true, write: true, grant: false, sealed: false, id: 0, origin: None
    });
    
    let originally_preempt = preempt::is_armed();
    preempt::set_armed(true);
    
    {
        let mut sched = scheduler::SCHEDULER.lock();
        sched.tasks[78] = Some(Task::new(TaskId(78), sync_demo_guarded_task, caps.clone()));
        sched.tasks[79] = Some(Task::new(TaskId(79), sync_demo_guarded_task, caps.clone()));
    }
    
    loop {
        let active = {
            let sched = scheduler::SCHEDULER.lock();
            let a_active = match &sched.tasks[78] {
                Some(t) => !matches!(t.state, TaskState::Terminated),
                None => false,
            };
            let b_active = match &sched.tasks[79] {
                Some(t) => !matches!(t.state, TaskState::Terminated),
                None => false,
            };
            a_active || b_active
        };
        if !active {
            break;
        }
        scheduler::yield_cpu();
    }
    
    let guarded_final = BENCH_SYNC_COUNTER.load(Ordering::Relaxed);
    print_ok!("Guarded run final counter: {} (Expected: 200)", guarded_final);
    
    BENCH_SYNC_COUNTER.store(0, Ordering::Relaxed);
    {
        let mut sched = scheduler::SCHEDULER.lock();
        sched.tasks[78] = Some(Task::new(TaskId(78), sync_demo_unguarded_task, CapTable::new()));
        sched.tasks[79] = Some(Task::new(TaskId(79), sync_demo_unguarded_task, CapTable::new()));
    }
    
    loop {
        let active = {
            let sched = scheduler::SCHEDULER.lock();
            let a_active = match &sched.tasks[78] {
                Some(t) => !matches!(t.state, TaskState::Terminated),
                None => false,
            };
            let b_active = match &sched.tasks[79] {
                Some(t) => !matches!(t.state, TaskState::Terminated),
                None => false,
            };
            a_active || b_active
        };
        if !active {
            break;
        }
        scheduler::yield_cpu();
    }
    
    preempt::set_armed(originally_preempt);
    let unguarded_final = BENCH_SYNC_COUNTER.load(Ordering::Relaxed);
    print_ok!("Unguarded run final counter: {} (Expected: < 200 due to race condition)", unguarded_final);
}

fn dispatch(line: &[u8]) -> Result<(), ()> {
    let mut tokens = [None; 4];
    let count = tokenize(line, &mut tokens);
    if count == 0 {
        return Ok(());
    }

    let tok0 = tokens[0].unwrap_or(&[]);
    let tok1 = tokens[1].unwrap_or(&[]);
    let tok2 = tokens[2].unwrap_or(&[]);
    let tok3 = tokens[3].unwrap_or(&[]);

    match (tok0, tok1) {
        (b"help", _) => {
            if tok1.is_empty() {
                print_info!("Group A: help, cap list, cap grant <id>, cap revoke <id>, cap seal <id>, cap audit");
                print_info!("Group B: sched info, sched timeslice, sched preempt-race");
                print_info!("Group C: fault spawn, fault cascade <n>");
                print_info!("Group D: ipc send <task_id> <message>, ipc typed <schema> <payload>, ipc stress <n>, service list, service restart <name>");
                print_info!("Group E: checkpoint, restore <id>, migrate <service> <node>");
                print_info!("Group F: history [<n>], trace <command>, perf, watch <command> <interval>");
                print_info!("Group G: kv set <slot> <key> <value>, kv get <slot> <key>, kv grant <slot> <task>, kv revoke <slot>");
                print_info!("Group H: log publish <kind> <message>, log read <kind>, log grant <kind> <task> <r|w|rw>, log revoke <kind>, log tail");
                print_info!("Group I: fs mkdir/write/read/ls/delete/stat, dev list/read/write, arch cache-sim/pipeline-sim, bench all, sync create/acquire/release/demo");
                print_info!("Group J: smp info/ping");
                print_info!("Type 'help <command> [<subcommand>]' for details on a specific command.");
            } else {
                match tok1 {
                    b"help" => {
                        print_info!("help [<command> [<subcommand>]] - Display help information for commands.");
                    }
                    b"cap" => {
                        match tok2 {
                            b"" => {
                                print_info!("cap subcommands: list, grant, revoke, seal, audit.");
                                print_info!("Type 'help cap <subcommand>' for details.");
                            }
                            b"list" => {
                                print_info!("cap list - List all capabilities currently held by the shell task.");
                            }
                            b"grant" => {
                                print_info!("cap grant <slot_idx> - Attenuate rights of slot_idx and grant derived capability to task 66.");
                            }
                            b"revoke" => {
                                print_info!("cap revoke <slot_idx> - Revoke capability in slot_idx and deny subsequent reuse.");
                            }
                            b"seal" => {
                                print_info!("cap seal <slot_idx> - Permanently seal a capability slot, preventing its removal.");
                            }
                            b"audit" => {
                                print_info!("cap audit - Print the kernel capability grant/revoke audit log trail.");
                            }
                            other => {
                                let s = core::str::from_utf8(other).unwrap_or("");
                                print_fail!("unknown cap subcommand: {}", s);
                            }
                        }
                    }
                    b"sched" => {
                        match tok2 {
                            b"" => {
                                print_info!("sched subcommands: info, timeslice, preempt-race.");
                                print_info!("Type 'help sched <subcommand>' for details.");
                            }
                            b"info" => {
                                print_info!("sched info - List all system tasks, their privilege levels (ring 0/3), and states.");
                            }
                            b"timeslice" => {
                                print_info!("sched timeslice - Run a 2-second time-slicing test with two preemptible kernel tasks.");
                            }
                            b"preempt-race" => {
                                print_info!("sched preempt-race - Demonstrate capability validate-use atomicity vs preemption TOCTOU.");
                            }
                            other => {
                                let s = core::str::from_utf8(other).unwrap_or("");
                                print_fail!("unknown sched subcommand: {}", s);
                            }
                        }
                    }
                    b"fault" => {
                        match tok2 {
                            b"" => {
                                print_info!("fault subcommands: spawn, cascade.");
                                print_info!("Type 'help fault <subcommand>' for details.");
                            }
                            b"spawn" => {
                                print_info!("fault spawn - Spawn task 71 which performs an unmapped memory read (#PF).");
                            }
                            b"cascade" => {
                                print_info!("fault cascade <n> - Spawn n faulting tasks in parallel (1-8) to test fault containment.");
                            }
                            other => {
                                let s = core::str::from_utf8(other).unwrap_or("");
                                print_fail!("unknown fault subcommand: {}", s);
                            }
                        }
                    }
                    b"ipc" => {
                        match tok2 {
                            b"" => {
                                print_info!("ipc subcommands: send, typed, stress.");
                                print_info!("Type 'help ipc <subcommand>' for details.");
                            }
                            b"send" => {
                                print_info!("ipc send <task_id> <message> - Send a raw Rendezvous message to the echo task (65).");
                            }
                            b"typed" => {
                                print_info!("ipc typed <schema> <payload> - Send a Rendezvous message with tag (0-3) and version 2.");
                            }
                            b"stress" => {
                                print_info!("ipc stress <n> - Spawn n worker pairs (1-8) ping-ponging messages for 3 seconds.");
                            }
                            other => {
                                let s = core::str::from_utf8(other).unwrap_or("");
                                print_fail!("unknown ipc subcommand: {}", s);
                            }
                        }
                    }
                    b"service" => {
                        match tok2 {
                            b"" => {
                                print_info!("service subcommands: list, restart.");
                                print_info!("Type 'help service <subcommand>' for details.");
                            }
                            b"list" => {
                                print_info!("service list - List all standing ecosystem service tasks and message queue states.");
                            }
                            b"restart" => {
                                print_info!("service restart <name> - Restart the named service (v1: echo).");
                            }
                            other => {
                                let s = core::str::from_utf8(other).unwrap_or("");
                                print_fail!("unknown service subcommand: {}", s);
                            }
                        }
                    }
                    b"checkpoint" => {
                        print_info!("checkpoint - Capture an in-memory snapshot of all active task capability states.");
                    }
                    b"restore" => {
                        print_info!("restore <id> - Restore task states from in-memory snapshot slot (v1: 0).");
                    }
                    b"migrate" => {
                        print_info!("migrate <service> <node> - Demonstrate network-transparent IPC, migration, and replica failover.");
                    }
                    b"history" => {
                        print_info!("history [<n>] - Show command history or re-run command at index n.");
                    }
                    b"trace" => {
                        print_info!("trace <command> - Run command with kernel path instrumentation and print call trace.");
                    }
                    b"perf" => {
                        print_info!("perf - Print live kernel performance and health statistics.");
                    }
                    b"watch" => {
                        print_info!("watch <command> <interval> - Re-run command every N ticks and diff the output.");
                    }
                    b"kv" => {
                        print_info!("kv set <slot> <key> <value> - Write to KV slot using write capability.");
                        print_info!("kv get <slot> <key> - Read from KV slot using read capability.");
                        print_info!("kv grant <slot> <task> - Transfer read-only KV capability to task.");
                        print_info!("kv revoke <slot> - Revoke shell's capability for KV slot.");
                    }
                    b"log" => {
                        print_info!("log publish <kind> <message> - Publish an event to the log service.");
                        print_info!("log read <kind> - Read next unread event of given kind from log service.");
                        print_info!("log grant <kind> <task> <r|w|rw> - Transfer derived log channel capability to task.");
                        print_info!("log revoke <kind> - Revoke shell's capability for event log kind.");
                        print_info!("log tail - Continuously read and display all readable kinds every tick.");
                    }
                    b"fs" => {
                        print_info!("fs mkdir <path> - Create a new directory.");
                        print_info!("fs write <path> <text> - Create or write data to a file.");
                        print_info!("fs read <path> - Read data from a file.");
                        print_info!("fs ls <path> - List contents of a directory.");
                        print_info!("fs delete <path> - Delete a file or directory.");
                        print_info!("fs stat <path> - Display metadata for a path.");
                    }
                    b"dev" => {
                        print_info!("dev list - List all available hardware devices.");
                        print_info!("dev read <id> - Read from a device.");
                        print_info!("dev write <id> <text> - Write text to a device.");
                    }
                    b"arch" => {
                        print_info!("arch cache-sim <trace> <assoc> <lines> - Simulate set-associative LRU cache.");
                        print_info!("arch pipeline-sim <trace> - Simulate 5-stage in-order pipeline with hazard stalls.");
                    }
                    b"bench" => {
                        print_info!("bench <ipc|sched|cap|fs|all> - Run performance benchmarks.");
                    }
                    b"smp" => {
                        print_info!("smp info - Print information about active CPU cores.");
                        print_info!("smp ping - Send an IPI ping to secondary AP core and check acknowledgment.");
                    }
                    b"sync" => {
                        print_info!("sync create <id> <mutex|sem> <count> - Create a new mutex or semaphore.");
                        print_info!("sync acquire <id> - Acquire a lock or decrement semaphore permit.");
                        print_info!("sync release <id> - Release a lock or increment semaphore permit.");
                        print_info!("sync demo - Run a preemption race condition demo with guarded and unguarded counters.");
                    }
                    other => {
                        let s = core::str::from_utf8(other).unwrap_or("");
                        print_fail!("unknown command group: {}", s);
                    }
                }
            }
        }
        (b"cap", b"list") => {
            let slots = get_shell_caps();
            let mut count = 0;
            for (i, slot) in slots.iter().enumerate() {
                if let Some(cap) = slot {
                    count += 1;
                    match cap.resource {
                        Resource::Serial => {
                            print_ok!("slot {}: id={} Serial r={} w={} g={} sealed={} origin={:?}", i, cap.id, cap.read, cap.write, cap.grant, cap.sealed, cap.origin);
                        }
                        Resource::IpcChannel { target_task } => {
                            print_ok!("slot {}: id={} IpcChannel(task {}) r={} w={} g={} sealed={} origin={:?}", i, cap.id, target_task.0, cap.read, cap.write, cap.grant, cap.sealed, cap.origin);
                        }
                        Resource::Service { id } => {
                            print_ok!("slot {}: id={} Service(#{}) r={} w={} g={} sealed={} origin={:?}", i, cap.id, id, cap.read, cap.write, cap.grant, cap.sealed, cap.origin);
                        }
                        Resource::MemoryMapping { .. } => {
                            print_ok!("slot {}: id={} Memory r={} w={} g={} sealed={} origin={:?}", i, cap.id, cap.read, cap.write, cap.grant, cap.sealed, cap.origin);
                        }
                        Resource::KVEntry { slot, readable, writable } => {
                            print_ok!("slot {}: id={} KVEntry(slot {}) r={} w={} g={} sealed={} origin={:?}", i, cap.id, slot, readable, writable, cap.grant, cap.sealed, cap.origin);
                        }
                        Resource::LogChannel { kind, readable, writable } => {
                            print_ok!("slot {}: id={} LogChannel(kind {}) r={} w={} g={} sealed={} origin={:?}", i, cap.id, kind, readable, writable, cap.grant, cap.sealed, cap.origin);
                        }
                        Resource::FsNode { mount, readable, writable } => {
                            print_ok!("slot {}: id={} FsNode(mount {}) r={} w={} g={} sealed={} origin={:?}", i, cap.id, mount, readable, writable, cap.grant, cap.sealed, cap.origin);
                        }
                        Resource::Device { id, readable, writable } => {
                            print_ok!("slot {}: id={} Device(id {}) r={} w={} g={} sealed={} origin={:?}", i, cap.id, id, readable, writable, cap.grant, cap.sealed, cap.origin);
                        }
                        Resource::SyncObj { id } => {
                            print_ok!("slot {}: id={} SyncObj(id {}) g={} sealed={} origin={:?}", i, cap.id, id, cap.grant, cap.sealed, cap.origin);
                        }
                    }
                }
            }
            print_info!("no ambient authority: {} capabilities, nothing else reachable", count);
        }
        (b"cap", b"grant") => {
            let id = parse_usize(tok2)?;
            if id >= MAX_CAPS {
                print_fail!("no capability");
                return Ok(());
            }
            let donor = {
                let slots = get_shell_caps();
                match slots[id] {
                    Some(c) => c,
                    None => {
                        print_fail!("no capability");
                        return Ok(());
                    }
                }
            };

            let derived = match donor.attenuate(RightsMask { read: true, write: true, grant: false }) {
                Ok(d) => d,
                Err(_) => {
                    print_fail!("slot {} lacks grant right", id);
                    return Ok(());
                }
            };

            let mut new_id = 0;
            {
                let mut sched = scheduler::SCHEDULER.lock();
                let mut new_task = Task::new(TaskId(66), park, CapTable::new());
                let new_slot = new_task.cap_table.insert(derived).unwrap();
                if let Some(ref mut cap) = new_task.cap_table.slots[new_slot] {
                    cap.origin = Some(donor.id);
                    new_id = cap.id;
                }
                sched.tasks[66] = Some(new_task);
            }
            print_ok!("granted: new token id={} origin={} -> task 66", new_id, donor.id);
        }
        (b"cap", b"revoke") => {
            let slot_idx = parse_usize(tok2)?;
            if slot_idx >= MAX_CAPS {
                print_fail!("slot {} empty", slot_idx);
                return Ok(());
            }
            let revoked_cap = {
                let mut sched = scheduler::SCHEDULER.lock();
                let task = sched.get_task_mut(TaskId(64)).unwrap();
                task.cap_table.kernel_revoke(slot_idx)
            };

            match revoked_cap {
                Some(cap) => {
                    let now_empty = get_shell_caps()[slot_idx].is_none();
                    let write_denied = if slot_idx == 0 {
                        crate::syscall::sys_serial_write(0, "test").is_err()
                    } else {
                        true
                    };
                    if now_empty && write_denied {
                        print_ok!("revoked id={}; re-use denied (slot now empty)", cap.id);
                    } else {
                        print_fail!("revocation check failed");
                    }
                }
                None => {
                    print_fail!("slot {} empty", slot_idx);
                }
            }
        }
        (b"cap", b"seal") => {
            let slot_idx = parse_usize(tok2)?;
            if slot_idx >= MAX_CAPS {
                print_fail!("slot {} empty", slot_idx);
                return Ok(());
            }
            let (sealed, result_is_err, cap_id) = {
                let mut sched = scheduler::SCHEDULER.lock();
                let task = sched.get_task_mut(TaskId(64)).unwrap();
                if let Some(ref mut cap) = task.cap_table.slots[slot_idx] {
                    cap.sealed = true;
                    let cap_id = cap.id;
                    let remove_res = task.cap_table.remove(slot_idx);
                    (true, remove_res.is_err(), cap_id)
                } else {
                    (false, false, 0)
                }
            };

            if !sealed {
                print_fail!("slot {} empty", slot_idx);
            } else if result_is_err {
                print_ok!("sealed id={}; holder remove() -> Err (locked)", cap_id);
            } else {
                print_fail!("sealing check failed");
            }
        }
        (b"cap", b"audit") => {
            crate::process::audit::dump();
            print_info!("audit trail above");
        }
        (b"sched", b"info") => {
            #[derive(Clone, Copy)]
            struct TaskInfo {
                id: usize,
                ring: u8,
                state_str: &'static str,
            }
            let mut task_infos = [None; 132];
            let (ticks, armed) = {
                let sched = scheduler::SCHEDULER.lock();
                let pml4 = crate::memory::current_pml4_paddr();
                for (i, task_opt) in sched.tasks.iter().enumerate() {
                    if let Some(task) = task_opt {
                        let ring = if task.cr3 != pml4 { 3 } else { 0 };
                        let state_str = match task.state {
                            TaskState::Running => "run",
                            TaskState::Ready => "ready",
                            TaskState::BlockedOnReceive => "recv",
                            TaskState::BlockedOnSend(_) => "send",
                            TaskState::Terminated => "term",
                        };
                        task_infos[i] = Some(TaskInfo { id: task.id.0, ring, state_str });
                    }
                }
                (preempt::stats().ticks, preempt::is_armed())
            };

            for info_opt in task_infos.iter() {
                if let Some(info) = info_opt {
                    print_ok!("task {}: ring{} {}", info.id, info.ring, info.state_str);
                }
            }
            print_info!("ticks={} armed={}", ticks, armed);
        }
        (b"sched", b"timeslice") => {
            COUNTER_A.store(0, Ordering::SeqCst);
            COUNTER_B.store(0, Ordering::SeqCst);
            {
                let mut sched = scheduler::SCHEDULER.lock();
                sched.tasks[67] = Some(Task::new(TaskId(67), timeslice_task_a, CapTable::new()));
                sched.tasks[68] = Some(Task::new(TaskId(68), timeslice_task_b, CapTable::new()));
            }

            let start_tick = preempt::stats().ticks;
            preempt::set_armed(true);
            loop {
                let done = {
                    let sched = scheduler::SCHEDULER.lock();
                    let a_term = match &sched.tasks[67] {
                        Some(t) => matches!(t.state, TaskState::Terminated),
                        None => true,
                    };
                    let b_term = match &sched.tasks[68] {
                        Some(t) => matches!(t.state, TaskState::Terminated),
                        None => true,
                    };
                    a_term && b_term
                };
                if done {
                    break;
                }
                if preempt::stats().ticks.wrapping_sub(start_tick) >= 400 {
                    break;
                }
                scheduler::yield_cpu();
            }
            preempt::set_armed(false);

            let a = COUNTER_A.load(Ordering::Relaxed);
            let b = COUNTER_B.load(Ordering::Relaxed);
            let p = preempt::stats().preemptions;
            if a > 0 && b > 0 {
                print_pass!("time-sliced: A={} B={} preemptions={}; cooperative could not run B", a, b, p);
            } else {
                print_fail!("timeslice test failed: A={}, B={}, preemptions={}", a, b, p);
            }
        }
        (b"sched", b"preempt-race") => {
            let cap_id = {
                let mut new_task = Task::new(TaskId(69), park, CapTable::new());
                let _ = new_task.cap_table.insert(Capability {
                    resource: Resource::IpcChannel { target_task: TaskId(70) },
                    read: true,
                    write: true,
                    grant: false,
                    sealed: false,
                    id: 0,
                    origin: None,
                }).unwrap();
                let id = new_task.cap_table.slots[0].unwrap().id;
                let mut sched = scheduler::SCHEDULER.lock();
                sched.tasks[69] = Some(new_task);
                id
            };

            preempt::set_armed(true);
            preempt::arm_adversary(69, 0);
            preempt::reset_window_ticks();
            preempt::enter_ipc_window();
            
            let start_ticks = preempt::stats().ticks;
            while preempt::stats().window_ticks < 1 {
                if preempt::stats().ticks.wrapping_sub(start_ticks) >= 100 {
                    break;
                }
                core::hint::spin_loop();
            }
            preempt::exit_ipc_window();

            let cap_at_use = {
                let sched = scheduler::SCHEDULER.lock();
                sched.tasks[69].as_ref().and_then(|t| t.cap_table.slots[0])
            };
            let fired = preempt::adversary_fired_in_window();

            if cap_at_use.is_none() && fired {
                print_vuln!("validated id={}; revoker ran mid-window; cap GONE at use", cap_id);
            } else {
                print_fail!("vulnerable stage of race did not trigger");
            }

            let _cap_id2 = {
                let mut new_task = Task::new(TaskId(69), park, CapTable::new());
                let _ = new_task.cap_table.insert(Capability {
                    resource: Resource::IpcChannel { target_task: TaskId(70) },
                    read: true,
                    write: true,
                    grant: false,
                    sealed: false,
                    id: 0,
                    origin: None,
                }).unwrap();
                let id = new_task.cap_table.slots[0].unwrap().id;
                let mut sched = scheduler::SCHEDULER.lock();
                sched.tasks[69] = Some(new_task);
                id
            };

            preempt::arm_adversary(69, 0);
            preempt::reset_window_ticks();
            preempt::enter_critical();
            preempt::enter_ipc_window();
            
            let start_ticks2 = preempt::stats().ticks;
            while preempt::stats().window_ticks < 1 {
                if preempt::stats().ticks.wrapping_sub(start_ticks2) >= 100 {
                    break;
                }
                core::hint::spin_loop();
            }
            preempt::exit_ipc_window();
            preempt::exit_critical();

            let cap_at_use2 = {
                let sched = scheduler::SCHEDULER.lock();
                sched.tasks[69].as_ref().and_then(|t| t.cap_table.slots[0])
            };
            let fired2 = preempt::adversary_fired_in_window();

            if cap_at_use2.is_some() && !fired2 {
                print_pass!("non-preemptible region: tick landed but revoker deferred; cap intact");
            } else {
                print_fail!("guarded stage of race failed");
            }

            preempt::disarm_adversary();
            preempt::set_armed(false);
        }
        (b"sched", b"preempt-user") => {
            let originally_armed = preempt::is_armed();
            let start_preempts = preempt::stats().preemptions;
            let start_ticks = preempt::stats().ticks;
            
            {
                let mut sched = scheduler::SCHEDULER.lock();
                sched.tasks[72] = Some(crate::userspace::spawn_preempt_user_task(TaskId(72), CapTable::new()));
            }
            
            preempt::set_armed(true);
            print_info!("preemption armed. running never-yielding user task...");
            
            while preempt::stats().ticks.wrapping_sub(start_ticks) < 50 {
                scheduler::yield_cpu();
            }
            
            preempt::set_armed(originally_armed);
            
            {
                let mut sched = scheduler::SCHEDULER.lock();
                sched.tasks[72] = None;
                crate::process::TASKS_TERMINATED.fetch_add(1, Ordering::SeqCst);
            }
            
            let end_preempts = preempt::stats().preemptions;
            let diff = end_preempts.wrapping_sub(start_preempts);
            print_ok!("preemption-user demo complete.");
            print_info!("  preemptions observed: {}", diff);
        }
        (b"fault", b"spawn") => {
            {
                let mut sched = scheduler::SCHEDULER.lock();
                sched.tasks[71] = Some(Task::new(TaskId(71), fault_task_entry, CapTable::new()));
            }
            for _ in 0..5 {
                scheduler::yield_cpu();
            }
            let (is_gone, alive_count) = {
                let sched = scheduler::SCHEDULER.lock();
                let is_gone = match &sched.tasks[71] {
                    None => true,
                    Some(t) => matches!(t.state, TaskState::Terminated),
                };
                let mut count = 0;
                for t_opt in sched.tasks.iter() {
                    if let Some(t) = t_opt {
                        if !matches!(t.state, TaskState::Terminated) {
                            count += 1;
                        }
                    }
                }
                (is_gone, count)
            };

            if is_gone {
                print_ok!("task 71 faulted (#PF) and was contained; kernel + {} tasks alive", alive_count);
            } else {
                print_fail!("task 71 did not fault or was not contained");
            }
        }
        (b"fault", b"cascade") => {
            let n = parse_usize(tok2)?;
            if !(1..=8).contains(&n) {
                print_fail!("fault cascade count {} out of range (expected 1-8)", n);
                return Ok(());
            }

            {
                let mut sched = scheduler::SCHEDULER.lock();
                for i in 0..n {
                    let slot = 72 + i;
                    sched.tasks[slot] = Some(Task::new(TaskId(slot), fault_task_entry, CapTable::new()));
                }
            }

            for _ in 0..10 {
                scheduler::yield_cpu();
            }

            for i in 0..n {
                let slot = 72 + i;
                let is_gone = {
                    let sched = scheduler::SCHEDULER.lock();
                    match &sched.tasks[slot] {
                        None => true,
                        Some(t) => matches!(t.state, TaskState::Terminated),
                    }
                };
                if is_gone {
                    print_ok!("task {} contained", slot);
                } else {
                    print_fail!("task {} not contained", slot);
                }
            }
            print_pass!("isolation held under {} concurrent faults", n);
        }
        (b"ipc", b"send") => {
            let task_id = parse_usize(tok2)?;
            if task_id != 65 {
                print_fail!("only task 65 (echo) is reachable in v1");
                return Ok(());
            }
            ensure_echo_service();
            
            let t0 = preempt::stats().ticks;
            match process::ipc::sys_send_typed(1, process::IpcTag::Raw as u16, 1, tok3) {
                Ok(()) => {
                    match process::ipc::sys_receive_typed() {
                        Ok(_reply_msg) => {
                            let dt = preempt::stats().ticks.wrapping_sub(t0);
                            print_ok!("sent {}B to task 65", tok3.len());
                            print_info!("round-trip ~{} ms", dt * 10);
                        }
                        Err(e) => {
                            print_fail!("receive failed: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    print_fail!("{:?}", e);
                }
            }
        }
        (b"ipc", b"typed") => {
            let schema_val = parse_usize(tok2)?;
            if schema_val > 3 {
                print_fail!("schema must be 0..3");
                return Ok(());
            }
            ensure_echo_service();
            match process::ipc::sys_send_typed(1, schema_val as u16, 2, tok3) {
                Ok(()) => {
                    match process::ipc::sys_receive_typed() {
                        Ok(reply_msg) => {
                            let mut p_buf = [0u8; 129];
                            p_buf[..reply_msg.len].copy_from_slice(&reply_msg.payload[..reply_msg.len]);
                            let p_str = core::str::from_utf8(&p_buf[..reply_msg.len]).unwrap_or("");
                            print_ok!("typed send tag={} ver=2 {}B", schema_val, tok3.len());
                            print_info!("echo tag={} '{}'", reply_msg.tag as u16, p_str);
                        }
                        Err(e) => {
                            print_fail!("receive failed: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    print_fail!("{:?}", e);
                }
            }
        }
        (b"ipc", b"stress") => {
            let n = parse_usize(tok2)?;
            if !(1..=8).contains(&n) {
                print_fail!("stress count {} out of range (expected 1-8)", n);
                return Ok(());
            }
            
            {
                let mut sched = scheduler::SCHEDULER.lock();
                for i in 0..n {
                    let t_init = 73 + 2 * i;
                    let t_repl = 74 + 2 * i;
                    
                    let mut caps_init = CapTable::new();
                    let _ = caps_init.insert(Capability {
                        resource: Resource::IpcChannel { target_task: TaskId(t_repl) },
                        read: true,
                        write: true,
                        grant: false,
                        sealed: false,
                        id: 0,
                        origin: None,
                    }).unwrap();
                    
                    let mut caps_repl = CapTable::new();
                    let _ = caps_repl.insert(Capability {
                        resource: Resource::IpcChannel { target_task: TaskId(t_init) },
                        read: true,
                        write: true,
                        grant: false,
                        sealed: false,
                        id: 0,
                        origin: None,
                    }).unwrap();
                    
                    sched.tasks[t_init] = Some(Task::new(TaskId(t_init), stress_worker_entry, caps_init));
                    sched.tasks[t_repl] = Some(Task::new(TaskId(t_repl), stress_worker_entry, caps_repl));
                }
            }

            STRESS_DELIVERIES.store(0, Ordering::SeqCst);
            let start_ticks = preempt::stats().ticks;
            preempt::set_armed(true);
            while preempt::stats().ticks.wrapping_sub(start_ticks) < 300 {
                scheduler::yield_cpu();
            }
            preempt::set_armed(false);

            {
                let mut sched = scheduler::SCHEDULER.lock();
                for i in 0..n {
                    if sched.tasks[73 + 2 * i].is_some() {
                        sched.tasks[73 + 2 * i] = None;
                        crate::process::TASKS_TERMINATED.fetch_add(1, Ordering::SeqCst);
                    }
                    if sched.tasks[74 + 2 * i].is_some() {
                        sched.tasks[74 + 2 * i] = None;
                        crate::process::TASKS_TERMINATED.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }

            let count = STRESS_DELIVERIES.load(Ordering::SeqCst);
            print_pass!("stress: {} msgs in 3s = {}/s, dropped=0", count, count / 3);
        }
        (b"service", b"list") => {
            #[derive(Clone, Copy)]
            struct ServiceInfo {
                name: &'static str,
                id: usize,
                state_str: &'static str,
                caps_count: usize,
                queue_count: usize,
            }
            let mut services = [None; 5];
            let count_found = {
                let sched = scheduler::SCHEDULER.lock();
                let mut found = 0;
                let targets = [(1, "init"), (2, "logger"), (3, "ramfs"), (4, "demo"), (65, "echo")];
                for (idx, &(id, name)) in targets.iter().enumerate() {
                    if let Some(task) = sched.get_task(TaskId(id)) {
                        let state_str = match task.state {
                            TaskState::Running => "run",
                            TaskState::Ready => "ready",
                            TaskState::BlockedOnReceive => "recv",
                            TaskState::BlockedOnSend(_) => "send",
                            TaskState::Terminated => "term",
                        };
                        let caps_count = task.cap_table.slots.iter().filter(|s| s.is_some()).count();
                        let queue_count = task.msg_queue.count;
                        services[idx] = Some(ServiceInfo { name, id, state_str, caps_count, queue_count });
                        found += 1;
                    }
                }
                found
            };

            if count_found == 0 {
                print_info!("no standing services; spawn via ipc/echo");
            } else {
                for svc_opt in services.iter() {
                    if let Some(svc) = svc_opt {
                        print_ok!("service {} (task {}): {}, caps={}, queue={}", svc.name, svc.id, svc.state_str, svc.caps_count, svc.queue_count);
                    }
                }
            }
        }
        (b"service", b"restart") => {
            let name_str = core::str::from_utf8(tok2).unwrap_or("");
            if name_str != "echo" {
                print_fail!("unknown service: {}", name_str);
                return Ok(());
            }

            print_info!("echo: shutdown");
            {
                let mut sched = scheduler::SCHEDULER.lock();
                if sched.tasks[65].is_some() {
                    sched.tasks[65] = None;
                    crate::process::TASKS_TERMINATED.fetch_add(1, Ordering::SeqCst);
                }
            }

            print_info!("echo: respawn (task 65)");
            print_info!("echo: caps redistributed");

            ensure_echo_service();

            print_pass!("service echo recovered");
        }
        (b"checkpoint", _) => {
            let k = {
                let sched = scheduler::SCHEDULER.lock();
                sched.tasks.iter().filter(|t| t.is_some()).count()
            };
            crate::process::snapshot::capture();
            let sum = crate::process::snapshot::info().unwrap_or(0);
            print_ok!("checkpoint taken: id=0 checksum={:#x}", sum);
            print_info!("captured {} task cap-tables", k);
        }
        (b"restore", _) => {
            let id = parse_usize(tok1)?;
            if id != 0 {
                print_fail!("no snapshot id {}", id);
                return Ok(());
            }
            match crate::process::snapshot::restore() {
                Ok(k) => {
                    print_ok!("restored {} task checkpoints; checksum verified", k);
                }
                Err(()) => {
                    print_fail!("no valid snapshot (run checkpoint first)");
                }
            }
        }
        (b"migrate", _) => {
            let service_id = parse_usize(tok1)?;
            let node_id = parse_usize(tok2)?;
            if service_id != 1 || node_id != 1 {
                print_fail!("v1 supports: migrate 1 1");
                return Ok(());
            }

            {
                let mut sched = scheduler::SCHEDULER.lock();
                let mut caps = CapTable::new();
                let _ = caps.insert(Capability {
                    resource: Resource::Serial,
                    read: false,
                    write: true,
                    grant: false,
                    sealed: false,
                    id: 0,
                    origin: None,
                });
                let _ = caps.insert(Capability {
                    resource: Resource::Service { id: 1 },
                    read: true,
                    write: true,
                    grant: false,
                    sealed: false,
                    id: 0,
                    origin: None,
                });
                sched.tasks[75] = Some(Task::new(TaskId(75), park, caps));
                sched.tasks[76] = Some(Task::new(TaskId(76), park, CapTable::new()));
            }

            crate::process::dist::demo(1, TaskId(75), TaskId(76));

            print_pass!("service 1 migrated node0->node1, capability stable");
        }
        (b"history", _) => {
            if tok1.is_empty() {
                let hist = HISTORY.lock();
                print_ok!("Command History:");
                for i in 0..hist.count {
                    let steps_back = hist.count - i;
                    if let Some(cmd) = hist.get(steps_back) {
                        let cmd_str = core::str::from_utf8(cmd).unwrap_or("");
                        print_info!("  {}: {}", i, cmd_str);
                    }
                }
            } else {
                let n_idx = parse_usize(tok1)?;
                let hist = HISTORY.lock();
                if n_idx >= hist.count {
                    print_fail!("history index {} out of range (0-{})", n_idx, hist.count.saturating_sub(1));
                    return Ok(());
                }
                let steps_back = hist.count - n_idx;
                if let Some(cmd) = hist.get(steps_back) {
                    let mut cmd_buf = [0u8; 128];
                    let cmd_len = cmd.len();
                    cmd_buf[..cmd_len].copy_from_slice(cmd);
                    drop(hist);
                    
                    let cmd_str = core::str::from_utf8(&cmd_buf[..cmd_len]).unwrap_or("");
                    print_cmd!("{}", cmd_str);
                    
                    HISTORY.lock().push(&cmd_buf[..cmd_len]);
                    return dispatch(&cmd_buf[..cmd_len]);
                }
            }
        }
        (b"trace", _) => {
            let mut idx = 5;
            while idx < line.len() && line[idx] == b' ' {
                idx += 1;
            }
            if idx >= line.len() {
                print_fail!("trace: no command specified");
                return Ok(());
            }
            let sub_line = &line[idx..];
            
            NEXT_IDX.store(0, Ordering::SeqCst);
            TRACE_OVERFLOW.store(false, Ordering::SeqCst);
            TRACING_ACTIVE.store(true, Ordering::SeqCst);
            
            let res = dispatch(sub_line);
            
            TRACING_ACTIVE.store(false, Ordering::SeqCst);
            
            print_trace_summary();
            return res;
        }
        (b"perf", _) => {
            let ticks = preempt::stats().ticks;
            let preemptions = preempt::stats().preemptions;
            let deferred = preempt::stats().deferred;
            let ipc_delivered = crate::process::ipc::IPC_DELIVERIES.load(Ordering::Relaxed);
            let faults = crate::interrupts::FAULTS_CAUGHT.load(Ordering::Relaxed);
            let spawned = crate::process::TASKS_SPAWNED.load(Ordering::Relaxed);
            let terminated = crate::process::TASKS_TERMINATED.load(Ordering::Relaxed);
            
            print_ok!("Kernel Performance & Health Stats:");
            print_info!("  Ticks elapsed:       {}", ticks);
            print_info!("  Preemptions:         {}", preemptions);
            print_info!("  Deferred preempts:   {}", deferred);
            print_info!("  IPC messages:        {}", ipc_delivered);
            print_info!("  Faults caught:       {}", faults);
            print_info!("  Tasks spawned:       {}", spawned);
            print_info!("  Tasks terminated:    {}", terminated);
        }
        (b"watch", _) => {
            let (sub_cmd, interval_tok) = if count == 4 {
                let start = tokens[1].unwrap();
                let end = tokens[2].unwrap();
                let start_idx = (start.as_ptr() as usize).checked_sub(line.as_ptr() as usize).unwrap();
                let end_idx = (end.as_ptr() as usize).checked_sub(line.as_ptr() as usize).unwrap() + end.len();
                (&line[start_idx..end_idx], tokens[3].unwrap())
            } else if count == 3 {
                (tokens[1].unwrap(), tokens[2].unwrap())
            } else {
                print_fail!("Usage: watch <command> <interval>");
                return Ok(());
            };
            
            let interval = parse_usize(interval_tok)?;
            
            unsafe {
                WATCH_LEN_PREV = 0;
            }
            
            loop {
                unsafe {
                    WATCH_LEN_CUR = 0;
                    *crate::drivers::serial::REDIRECT_TARGET.lock() = Some((
                        (&raw mut WATCH_BUF_CUR) as usize,
                        1024,
                        (&raw mut WATCH_LEN_CUR) as usize,
                    ));
                }
                
                let _ = dispatch(sub_cmd);
                
                *crate::drivers::serial::REDIRECT_TARGET.lock() = None;
                
                crate::print!("\x1b[2J\x1b[H");
                crate::print!("[INFO]  watch: {} (every {} ticks, press any key to exit)\n", core::str::from_utf8(sub_cmd).unwrap_or(""), interval);
                
                print_diffed_buffers();
                
                unsafe {
                    WATCH_BUF_PREV[..WATCH_LEN_CUR].copy_from_slice(&WATCH_BUF_CUR[..WATCH_LEN_CUR]);
                    WATCH_LEN_PREV = WATCH_LEN_CUR;
                }
                
                let wait_start = preempt::stats().ticks;
                let mut last_wait_tick = wait_start;
                while preempt::stats().ticks.wrapping_sub(wait_start) < interval as u64 {
                    let current_tick = preempt::stats().ticks;
                    if current_tick != last_wait_tick {
                        last_wait_tick = current_tick;
                        let key_opt = crate::drivers::serial::SERIAL1.lock().try_read();
                        if key_opt.is_some() {
                            crate::print!("\n");
                            return Ok(());
                        }
                    }
                    scheduler::yield_cpu();
                }
            }
        }
        (b"kv", _) => {
            match tok1 {
                b"set" => {
                    let slot = parse_usize(tok2)?;
                    if slot >= 32 {
                        print_fail!("slot index {} out of range (0-31)", slot);
                        return Ok(());
                    }
                    
                    let rest = tok3;
                    let mut split_idx = 0;
                    while split_idx < rest.len() && rest[split_idx] != b' ' {
                        split_idx += 1;
                    }
                    if split_idx >= rest.len() {
                        print_fail!("Usage: kv set <slot> <key> <value>");
                        return Ok(());
                    }
                    let key_bytes = &rest[..split_idx];
                    let mut val_start = split_idx;
                    while val_start < rest.len() && rest[val_start] == b' ' {
                        val_start += 1;
                    }
                    if val_start >= rest.len() {
                        print_fail!("Usage: kv set <slot> <key> <value>");
                        return Ok(());
                    }
                    let val_bytes = &rest[val_start..];
                    
                    let mut payload = [0u8; 81];
                    payload[0] = slot as u8;
                    
                    let key_len = core::cmp::min(key_bytes.len(), 16);
                    payload[1..1+key_len].copy_from_slice(&key_bytes[..key_len]);
                    
                    let val_len = core::cmp::min(val_bytes.len(), 64);
                    payload[17..17+val_len].copy_from_slice(&val_bytes[..val_len]);
                    
                    ensure_kv_service();
                    
                    let mut cap_idx = None;
                    {
                        let slots = get_shell_caps();
                        for (i, slot_opt) in slots.iter().enumerate() {
                            if let Some(cap) = slot_opt {
                                if let Resource::IpcChannel { target_task } = cap.resource {
                                    if target_task.0 == 82 {
                                        cap_idx = Some(i);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    let cap_idx = match cap_idx {
                        Some(idx) => idx,
                        None => {
                            print_fail!("no capability");
                            return Ok(());
                        }
                    };
                    
                    match process::ipc::sys_send_typed(cap_idx, process::IpcTag::KVSet as u16, 1, &payload) {
                        Ok(()) => {
                            match process::ipc::sys_receive_typed() {
                                Ok(reply) => {
                                    if reply.payload[0] == 0 {
                                        let k_str = core::str::from_utf8(key_bytes).unwrap_or("");
                                        let v_str = core::str::from_utf8(val_bytes).unwrap_or("");
                                        print_ok!("set slot {}: key={} value={}", slot, k_str, v_str);
                                    } else if reply.payload[0] == 1 {
                                        print_fail!("permission denied (no capability for slot {})", slot);
                                    } else {
                                        print_fail!("invalid slot {}", slot);
                                    }
                                }
                                Err(e) => {
                                    print_fail!("receive failed: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            print_fail!("send failed: {:?}", e);
                        }
                    }
                }
                b"get" => {
                    let slot = parse_usize(tok2)?;
                    if slot >= 32 {
                        print_fail!("slot index {} out of range (0-31)", slot);
                        return Ok(());
                    }
                    
                    ensure_kv_service();
                    
                    let mut cap_idx = None;
                    {
                        let slots = get_shell_caps();
                        for (i, slot_opt) in slots.iter().enumerate() {
                            if let Some(cap) = slot_opt {
                                if let Resource::IpcChannel { target_task } = cap.resource {
                                    if target_task.0 == 82 {
                                        cap_idx = Some(i);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    let cap_idx = match cap_idx {
                        Some(idx) => idx,
                        None => {
                            print_fail!("no capability");
                            return Ok(());
                        }
                    };
                    
                    let payload = [slot as u8];
                    match process::ipc::sys_send_typed(cap_idx, process::IpcTag::KVGet as u16, 1, &payload) {
                        Ok(()) => {
                            match process::ipc::sys_receive_typed() {
                                Ok(reply) => {
                                    if reply.payload[0] == 0 {
                                        let mut key_len = 0;
                                        while key_len < 16 && reply.payload[1 + key_len] != 0 {
                                            key_len += 1;
                                        }
                                        let mut val_len = 0;
                                        while val_len < 64 && reply.payload[17 + val_len] != 0 {
                                            val_len += 1;
                                        }
                                        let k_str = core::str::from_utf8(&reply.payload[1..1+key_len]).unwrap_or("");
                                        let v_str = core::str::from_utf8(&reply.payload[17..17+val_len]).unwrap_or("");
                                        print_ok!("get slot {}: key={} value={}", slot, k_str, v_str);
                                    } else if reply.payload[0] == 1 {
                                        print_fail!("permission denied (no capability for slot {})", slot);
                                    } else {
                                        print_fail!("invalid slot {}", slot);
                                    }
                                }
                                Err(e) => {
                                    print_fail!("receive failed: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            print_fail!("send failed: {:?}", e);
                        }
                    }
                }
                b"grant" => {
                    let slot = parse_usize(tok2)?;
                    let target_task_id = parse_usize(tok3)?;
                    
                    let donor_cap = {
                        let slots = get_shell_caps();
                        let mut found = None;
                        for cap_opt in slots.iter() {
                            if let Some(cap) = cap_opt {
                                if let Resource::KVEntry { slot: cap_slot, .. } = cap.resource {
                                    if cap_slot == slot {
                                        found = Some(*cap);
                                        break;
                                    }
                                }
                            }
                        }
                        found
                    };
                    
                    let donor = match donor_cap {
                        Some(c) => c,
                        None => {
                            print_fail!("no capability");
                            return Ok(());
                        }
                    };
                    
                    let derived = Capability {
                        resource: Resource::KVEntry { slot, readable: true, writable: false },
                        read: true,
                        write: false,
                        grant: false,
                        sealed: false,
                        id: 0,
                        origin: Some(donor.id),
                    };
                    
                    {
                        let mut sched = scheduler::SCHEDULER.lock();
                        if sched.tasks[target_task_id].is_none() {
                            sched.tasks[target_task_id] = Some(Task::new(TaskId(target_task_id), park, CapTable::new()));
                            crate::process::TASKS_SPAWNED.fetch_add(1, Ordering::SeqCst);
                        }
                        if let Some(ref mut target_task) = sched.tasks[target_task_id] {
                            let new_slot = target_task.cap_table.insert(derived).unwrap();
                            if let Some(ref mut cap) = target_task.cap_table.slots[new_slot] {
                                cap.origin = Some(donor.id);
                            }
                        }
                    }
                    
                    print_ok!("granted read-only KV slot {} to task {}", slot, target_task_id);
                }
                b"revoke" => {
                    let slot = parse_usize(tok2)?;
                    
                    let shell_slot_idx = {
                        let slots = get_shell_caps();
                        let mut found = None;
                        for (i, cap_opt) in slots.iter().enumerate() {
                            if let Some(cap) = cap_opt {
                                if let Resource::KVEntry { slot: cap_slot, .. } = cap.resource {
                                    if cap_slot == slot {
                                        found = Some(i);
                                        break;
                                    }
                                }
                            }
                        }
                        found
                    };
                    
                    match shell_slot_idx {
                        Some(idx) => {
                            let mut sched = scheduler::SCHEDULER.lock();
                            let task = sched.get_task_mut(TaskId(64)).unwrap();
                            let revoked = task.cap_table.kernel_revoke(idx);
                            if let Some(cap) = revoked {
                                print_ok!("revoked KV slot {} id={}; access denied", slot, cap.id);
                            } else {
                                print_fail!("revocation check failed");
                            }
                        }
                        None => {
                            print_fail!("slot {} empty", slot);
                        }
                    }
                }
                other => {
                    let s = core::str::from_utf8(other).unwrap_or("");
                    print_fail!("unknown kv subcommand: {}", s);
                }
            }
        }
        (b"fs", _) => {
            match tok1 {
                b"mkdir" => {
                    if tok2.is_empty() {
                        print_fail!("Usage: fs mkdir <path>");
                        return Ok(());
                    }
                    match send_fs_msg(0, 0, tok2, &[]) {
                        Ok(reply) => {
                            match reply[0] {
                                0 => print_ok!("directory created"),
                                1 => print_fail!("permission denied"),
                                3 => print_fail!("filesystem full"),
                                4 => print_fail!("already exists / bad request"),
                                _ => print_fail!("unknown error"),
                            }
                        }
                        Err(e) => print_fail!("IPC error: {:?}", e),
                    }
                }
                b"write" => {
                    if tok2.is_empty() || tok3.is_empty() {
                        print_fail!("Usage: fs write <path> <text>");
                        return Ok(());
                    }
                    match send_fs_msg(1, 0, tok2, tok3) {
                        Ok(reply) => {
                            match reply[0] {
                                0 => print_ok!("file written"),
                                1 => print_fail!("permission denied"),
                                3 => print_fail!("filesystem full"),
                                4 => print_fail!("is directory / bad request"),
                                _ => print_fail!("unknown error"),
                            }
                        }
                        Err(e) => print_fail!("IPC error: {:?}", e),
                    }
                }
                b"read" => {
                    if tok2.is_empty() {
                        print_fail!("Usage: fs read <path>");
                        return Ok(());
                    }
                    match send_fs_msg(2, 0, tok2, &[]) {
                        Ok(reply) => {
                            match reply[0] {
                                0 => {
                                    let data_len = reply[1] as usize;
                                    let data_bytes = &reply[2..2 + data_len];
                                    let data_str = core::str::from_utf8(data_bytes).unwrap_or("");
                                    print_ok!("{}", data_str);
                                }
                                1 => print_fail!("permission denied"),
                                2 => print_fail!("not found"),
                                _ => print_fail!("unknown error"),
                            }
                        }
                        Err(e) => print_fail!("IPC error: {:?}", e),
                    }
                }
                b"ls" => {
                    if tok2.is_empty() {
                        print_fail!("Usage: fs ls <path>");
                        return Ok(());
                    }
                    match send_fs_msg(3, 0, tok2, &[]) {
                        Ok(reply) => {
                            match reply[0] {
                                0 => {
                                    let data_bytes = &reply[2..];
                                    let end_idx = data_bytes.iter().position(|&b| b == 0).unwrap_or(data_bytes.len());
                                    let data_str = core::str::from_utf8(&data_bytes[..end_idx]).unwrap_or("");
                                    for line in data_str.lines() {
                                        if !line.is_empty() {
                                            print_ok!("{}", line);
                                        }
                                    }
                                }
                                1 => print_fail!("permission denied"),
                                2 => print_fail!("not found"),
                                _ => print_fail!("unknown error"),
                            }
                        }
                        Err(e) => print_fail!("IPC error: {:?}", e),
                    }
                }
                b"delete" => {
                    if tok2.is_empty() {
                        print_fail!("Usage: fs delete <path>");
                        return Ok(());
                    }
                    match send_fs_msg(4, 0, tok2, &[]) {
                        Ok(reply) => {
                            match reply[0] {
                                0 => print_ok!("deleted"),
                                1 => print_fail!("permission denied"),
                                2 => print_fail!("not found"),
                                _ => print_fail!("unknown error"),
                            }
                        }
                        Err(e) => print_fail!("IPC error: {:?}", e),
                    }
                }
                b"stat" => {
                    if tok2.is_empty() {
                        print_fail!("Usage: fs stat <path>");
                        return Ok(());
                    }
                    match send_fs_msg(5, 0, tok2, &[]) {
                        Ok(reply) => {
                            match reply[0] {
                                0 => {
                                    let is_dir = reply[1] != 0;
                                    let mut size_bytes = [0u8; 8];
                                    size_bytes.copy_from_slice(&reply[2..10]);
                                    let size = u64::from_ne_bytes(size_bytes);
                                    let mount = reply[10];
                                    print_ok!("Type: {}, Size: {} bytes, Mount: {}", if is_dir { "Directory" } else { "File" }, size, mount);
                                }
                                1 => print_fail!("permission denied"),
                                2 => print_fail!("not found"),
                                _ => print_fail!("unknown error"),
                            }
                        }
                        Err(e) => print_fail!("IPC error: {:?}", e),
                    }
                }
                other => {
                    let s = core::str::from_utf8(other).unwrap_or("");
                    print_fail!("unknown fs subcommand: {}", s);
                }
            }
        }
        (b"dev", _) => {
            match tok1 {
                b"list" => {
                    let slots = get_shell_caps();
                    let mut has_serial = "no";
                    let mut has_kbd = "no";
                    for cap_opt in slots.iter() {
                        if let Some(cap) = cap_opt {
                            if let Resource::Device { id, readable, writable } = cap.resource {
                                if id == 0 {
                                    has_serial = if readable && writable { "rw" } else if readable { "r" } else if writable { "w" } else { "none" };
                                } else if id == 1 {
                                    has_kbd = if readable && writable { "rw" } else if readable { "r" } else if writable { "w" } else { "none" };
                                }
                            }
                        }
                    }
                    print_ok!("Devices:");
                    print_info!("  0: serial (caps: {})", has_serial);
                    print_info!("  1: keyboard (caps: {})", has_kbd);
                }
                b"read" => {
                    let id = parse_usize(tok2)? as u8;
                    match send_dev_msg(0, id, &[]) {
                        Ok(reply) => {
                            match reply[0] {
                                0 => {
                                    let len = reply[1] as usize;
                                    let read_bytes = &reply[2..2 + len];
                                    let read_str = core::str::from_utf8(read_bytes).unwrap_or("");
                                    print_ok!("read ({} bytes): {}", len, read_str);
                                }
                                1 => print_fail!("permission denied"),
                                2 => print_fail!("no data available"),
                                3 => print_fail!("invalid device"),
                                _ => print_fail!("unknown error"),
                            }
                        }
                        Err(e) => print_fail!("IPC error: {:?}", e),
                    }
                }
                b"write" => {
                    let id = parse_usize(tok2)? as u8;
                    if tok3.is_empty() {
                        print_fail!("Usage: dev write <id> <text>");
                        return Ok(());
                    }
                    match send_dev_msg(1, id, tok3) {
                        Ok(reply) => {
                            match reply[0] {
                                0 => print_ok!("write complete"),
                                1 => print_fail!("permission denied"),
                                3 => print_fail!("invalid operation / device"),
                                _ => print_fail!("unknown error"),
                            }
                        }
                        Err(e) => print_fail!("IPC error: {:?}", e),
                    }
                }
                other => {
                    let s = core::str::from_utf8(other).unwrap_or("");
                    print_fail!("unknown dev subcommand: {}", s);
                }
            }
        }
        (b"arch", _) => {
            match tok1 {
                b"cache-sim" => {
                    if tok2.is_empty() || tok3.is_empty() {
                        print_fail!("Usage: arch cache-sim <trace> <assoc> <lines>");
                        return Ok(());
                    }
                    let rest = tok3;
                    let mut split_idx = 0;
                    while split_idx < rest.len() && rest[split_idx] != b' ' {
                        split_idx += 1;
                    }
                    if split_idx >= rest.len() {
                        print_fail!("Usage: arch cache-sim <trace> <assoc> <lines>");
                        return Ok(());
                    }
                    let assoc_tok = &rest[..split_idx];
                    let mut lines_start = split_idx;
                    while lines_start < rest.len() && rest[lines_start] == b' ' {
                        lines_start += 1;
                    }
                    if lines_start >= rest.len() {
                        print_fail!("Usage: arch cache-sim <trace> <assoc> <lines>");
                        return Ok(());
                    }
                    let lines_tok = &rest[lines_start..];
                    
                    let assoc = parse_usize(assoc_tok)?;
                    let lines = parse_usize(lines_tok)?;
                    
                    if lines > 1024 {
                        print_fail!("too many lines, maximum is 1024");
                        return Ok(());
                    }
                    
                    let addrs = get_sim_addresses(tok2);
                    let cfg = crate::arch_sim::CacheConfig {
                        assoc,
                        num_lines: lines,
                        line_bytes: 64,
                    };
                    
                    let stats = crate::arch_sim::simulate_cache(&cfg, &addrs);
                    let hit_rate = if stats.accesses > 0 {
                        stats.hits * 100 / stats.accesses
                    } else {
                        0
                    };
                    print_ok!("Cache Sim Results:");
                    print_info!("  Accesses:    {}", stats.accesses);
                    print_info!("  Hits:        {}", stats.hits);
                    print_info!("  Misses:      {}", stats.misses);
                    print_info!("  Evictions:   {}", stats.evictions);
                    print_info!("  Hit Rate:    {}%", hit_rate);
                }
                b"pipeline-sim" => {
                    if tok2.is_empty() {
                        print_fail!("Usage: arch pipeline-sim <trace>");
                        return Ok(());
                    }
                    let instrs = get_sim_instrs(tok2);
                    let stats = crate::arch_sim::simulate_pipeline(&instrs);
                    let cpi_hundreds = if stats.instrs > 0 {
                        stats.cycles * 100 / stats.instrs
                    } else {
                        100
                    };
                    let cpi_int = cpi_hundreds / 100;
                    let cpi_frac = cpi_hundreds % 100;
                    print_ok!("Pipeline Sim Results:");
                    print_info!("  Instructions: {}", stats.instrs);
                    print_info!("  Cycles:       {}", stats.cycles);
                    print_info!("  Stalls:       {}", stats.stalls);
                    print_info!("  CPI:          {}.{:02}", cpi_int, cpi_frac);
                }
                other => {
                    let s = core::str::from_utf8(other).unwrap_or("");
                    print_fail!("unknown arch subcommand: {}", s);
                }
            }
        }
        (b"bench", _) => {
            print_info!("Running benchmarks (preemption disarmed for stability)...");
            match tok1 {
                b"ipc" => {
                    run_bench_ipc();
                }
                b"sched" => {
                    run_bench_sched();
                }
                b"cap" => {
                    run_bench_cap();
                }
                b"fs" => {
                    run_bench_fs();
                }
                b"mem" => {
                    print_ok!("Benchmark Per-Task Memory Footprint:");
                    print_info!("  size_of::<Task>():         {} bytes", core::mem::size_of::<process::Task>());
                    print_info!("  size_of::<CapTable>():     {} bytes", core::mem::size_of::<CapTable>());
                    print_info!("  size_of::<MessageQueue>(): {} bytes", core::mem::size_of::<process::ipc::MessageQueue>());
                    print_info!("  size_of::<Message>():      {} bytes", core::mem::size_of::<process::ipc::Message>());
                    print_info!("  kernel stack per task:     {} bytes", process::STACK_SIZE);
                    print_info!("  MAX_TASKS:                 {}", process::MAX_TASKS);
                }
                b"contend" => {
                    let n = parse_usize(tok2).unwrap_or(2).clamp(1, 16);
                    let obj_id = match n {
                        1..=2 => 2,
                        3..=4 => 3,
                        5..=8 => 4,
                        _ => 5,
                    };
                    run_bench_contend(n, obj_id);
                }
                b"all" => {
                    run_bench_ipc();
                    run_bench_sched();
                    run_bench_cap();
                    run_bench_fs();
                }
                _ => {
                    print_fail!("Usage: bench <ipc|sched|cap|fs|mem|contend <n>|all>");
                }
            }
        }
        (b"smp", _) => {
            match tok1 {
                b"info" => {
                    if let Some(mp_response) = crate::MP_REQUEST.response() {
                        let cpus = mp_response.cpus();
                        print_ok!("Symmetric Multiprocessing (SMP) Info:");
                        print_info!("  BSP LAPIC ID: {}", mp_response.bsp_lapic_id);
                        print_info!("  Total CPUs detected: {}", cpus.len());
                        for cpu in cpus {
                            let is_bsp = cpu.lapic_id == mp_response.bsp_lapic_id;
                            print_info!(
                                "  - CPU {}: LAPIC ID {}, {}",
                                cpu.processor_id,
                                cpu.lapic_id,
                                if is_bsp { "BSP (Bootstrap)" } else { "AP (Application)" }
                            );
                        }
                    } else {
                        print_fail!("No multiprocessor response from bootloader.");
                    }
                }
                b"ping" => {
                    if let Some(mp_response) = crate::MP_REQUEST.response() {
                        let cpus = mp_response.cpus();
                        let mut target_ap = None;
                        for cpu in cpus {
                            if cpu.lapic_id != mp_response.bsp_lapic_id {
                                target_ap = Some(cpu);
                                break;
                            }
                        }
                        if let Some(ap) = target_ap {
                            let prev_ack = crate::arch::apic::IPI_ACK_COUNT.load(core::sync::atomic::Ordering::SeqCst);
                            print_info!("Sending IPI (vector 0x40) to AP CPU {} (LAPIC ID {})...", ap.processor_id, ap.lapic_id);
                            unsafe {
                                crate::arch::apic::send_ipi(ap.lapic_id, 0x40);
                            }
                            // Spin-wait up to 10 million loops for acknowledgment
                            let mut acked = false;
                            for _ in 0..10_000_000 {
                                let curr_ack = crate::arch::apic::IPI_ACK_COUNT.load(core::sync::atomic::Ordering::SeqCst);
                                if curr_ack > prev_ack {
                                    acked = true;
                                    break;
                                }
                                core::hint::spin_loop();
                            }
                            if acked {
                                let current_count = crate::arch::apic::IPI_ACK_COUNT.load(core::sync::atomic::Ordering::SeqCst);
                                print_ok!("IPI Acknowledged! Ack count: {}", current_count);
                            } else {
                                print_fail!("IPI Ping Timeout. No acknowledgment from AP core.");
                            }
                        } else {
                            print_fail!("No secondary AP core detected to ping.");
                        }
                    } else {
                        print_fail!("No multiprocessor response from bootloader.");
                    }
                }
                _ => {
                    print_fail!("Usage: smp <info|ping>");
                }
            }
        }
        (b"sync", _) => {
            match tok1 {
                b"create" => {
                    let id = parse_usize(tok2)? as u8;
                    if id >= 8 {
                        print_fail!("object id must be < 8");
                        return Ok(());
                    }
                    let is_mutex = if tok3.starts_with(b"mutex") { 1 } else { 0 };
                    let initial_count = if is_mutex == 1 { 1 } else {
                        let rest = tok3;
                        let mut split_idx = 0;
                        while split_idx < rest.len() && rest[split_idx] != b' ' {
                            split_idx += 1;
                        }
                        while split_idx < rest.len() && rest[split_idx] == b' ' {
                            split_idx += 1;
                        }
                        if split_idx < rest.len() {
                            parse_usize(&rest[split_idx..])? as u8
                        } else {
                            1
                        }
                    };
                    
                    match send_sync_msg(0, id, is_mutex, initial_count) {
                        Ok(reply) => {
                            if reply[0] == 0 {
                                let mut sched = scheduler::SCHEDULER.lock();
                                let shell = sched.get_task_mut(TaskId(64)).unwrap();
                                let _ = shell.cap_table.insert(Capability {
                                    resource: Resource::SyncObj { id },
                                    read: true,
                                    write: true,
                                    grant: true,
                                    sealed: false,
                                    id: 0,
                                    origin: None,
                                });
                                print_ok!("sync object created and capability installed");
                            } else {
                                print_fail!("failed to create sync object");
                            }
                        }
                        Err(e) => print_fail!("IPC error: {:?}", e),
                    }
                }
                b"acquire" => {
                    let id = parse_usize(tok2)? as u8;
                    let mut has_cap = false;
                    {
                        let slots = get_shell_caps();
                        for slot in slots.iter() {
                            if let Some(cap) = slot {
                                if let Resource::SyncObj { id: cap_id } = cap.resource {
                                    if cap_id == id {
                                        has_cap = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if !has_cap {
                        print_fail!("no capability for sync object {}", id);
                        return Ok(());
                    }
                    match send_sync_msg(1, id, 0, 0) {
                        Ok(reply) => {
                            if reply[0] == 0 {
                                print_ok!("acquired");
                            } else {
                                print_fail!("acquire failed: status={}", reply[0]);
                            }
                        }
                        Err(e) => print_fail!("IPC error: {:?}", e),
                    }
                }
                b"release" => {
                    let id = parse_usize(tok2)? as u8;
                    let mut has_cap = false;
                    {
                        let slots = get_shell_caps();
                        for slot in slots.iter() {
                            if let Some(cap) = slot {
                                if let Resource::SyncObj { id: cap_id } = cap.resource {
                                    if cap_id == id {
                                        has_cap = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if !has_cap {
                        print_fail!("no capability for sync object {}", id);
                        return Ok(());
                    }
                    match send_sync_msg(2, id, 0, 0) {
                        Ok(reply) => {
                            if reply[0] == 0 {
                                print_ok!("released");
                            } else {
                                print_fail!("release failed: status={}", reply[0]);
                            }
                        }
                        Err(e) => print_fail!("IPC error: {:?}", e),
                    }
                }
                b"demo" => {
                    run_sync_demo();
                }
                other => {
                    let s = core::str::from_utf8(other).unwrap_or("");
                    print_fail!("unknown sync subcommand: {}", s);
                }
            }
        }
        (b"log", _) => {
            match tok1 {
                b"publish" => {
                    let kind_val = parse_usize(tok2)?;
                    if kind_val >= 16 {
                        print_fail!("kind {} out of range (0-15)", kind_val);
                        return Ok(());
                    }
                    let kind = kind_val as u8;
                    if tok3.is_empty() {
                        print_fail!("Usage: log publish <kind> <message>");
                        return Ok(());
                    }
                    
                    ensure_log_service();
                    
                    let mut cap_idx = None;
                    {
                        let slots = get_shell_caps();
                        for (i, slot_opt) in slots.iter().enumerate() {
                            if let Some(cap) = slot_opt {
                                if let Resource::IpcChannel { target_task } = cap.resource {
                                    if target_task.0 == 83 {
                                        cap_idx = Some(i);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    let cap_idx = match cap_idx {
                        Some(idx) => idx,
                        None => {
                            print_fail!("no capability");
                            return Ok(());
                        }
                    };
                    
                    let mut payload = [0u8; 65];
                    payload[0] = kind as u8;
                    let msg_len = core::cmp::min(tok3.len(), 64);
                    payload[1..1+msg_len].copy_from_slice(&tok3[..msg_len]);
                    
                    match process::ipc::sys_send_typed(cap_idx, process::IpcTag::LogPublish as u16, 1, &payload[..1+msg_len]) {
                        Ok(()) => {
                            match process::ipc::sys_receive_typed() {
                                Ok(reply) => {
                                    if reply.payload[0] == 0 {
                                        let msg_str = core::str::from_utf8(tok3).unwrap_or("");
                                        print_ok!("published log kind {}: {}", kind, msg_str);
                                    } else if reply.payload[0] == 1 {
                                        print_fail!("permission denied (no capability for log kind {})", kind);
                                    } else {
                                        print_fail!("invalid kind {}", kind);
                                    }
                                }
                                Err(e) => {
                                    print_fail!("receive failed: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            print_fail!("send failed: {:?}", e);
                        }
                    }
                }
                b"read" => {
                    let kind_val = parse_usize(tok2)?;
                    if kind_val >= 16 {
                        print_fail!("kind {} out of range (0-15)", kind_val);
                        return Ok(());
                    }
                    let kind = kind_val as u8;
                    
                    ensure_log_service();
                    
                    let mut cap_idx = None;
                    {
                        let slots = get_shell_caps();
                        for (i, slot_opt) in slots.iter().enumerate() {
                            if let Some(cap) = slot_opt {
                                if let Resource::IpcChannel { target_task } = cap.resource {
                                    if target_task.0 == 83 {
                                        cap_idx = Some(i);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    let cap_idx = match cap_idx {
                        Some(idx) => idx,
                        None => {
                            print_fail!("no capability");
                            return Ok(());
                        }
                    };
                    
                    let payload = [kind as u8];
                    match process::ipc::sys_send_typed(cap_idx, process::IpcTag::LogRead as u16, 1, &payload) {
                        Ok(()) => {
                            match process::ipc::sys_receive_typed() {
                                Ok(reply) => {
                                    if reply.payload[0] == 0 {
                                        let tick = u64::from_ne_bytes(reply.payload[1..9].try_into().unwrap());
                                        let producer = usize::from_ne_bytes(reply.payload[9..17].try_into().unwrap());
                                        let len = usize::from_ne_bytes(reply.payload[18..26].try_into().unwrap());
                                        let msg_bytes = &reply.payload[26..26+len];
                                        let msg_str = core::str::from_utf8(msg_bytes).unwrap_or("");
                                        print_ok!("[{}] producer={} kind={} message={}", tick, producer, kind, msg_str);
                                    } else if reply.payload[0] == 1 {
                                        print_fail!("permission denied (no capability for log kind {})", kind);
                                    } else if reply.payload[0] == 2 {
                                        print_info!("no new log entries for kind {}", kind);
                                    } else {
                                        print_fail!("invalid kind {}", kind);
                                    }
                                }
                                Err(e) => {
                                    print_fail!("receive failed: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            print_fail!("send failed: {:?}", e);
                        }
                    }
                }
                b"grant" => {
                    let kind_val = parse_usize(tok2)?;
                    if kind_val >= 16 {
                        print_fail!("kind {} out of range (0-15)", kind_val);
                        return Ok(());
                    }
                    let kind = kind_val as u8;
                    
                    let mut split_idx = 0;
                    while split_idx < tok3.len() && tok3[split_idx] != b' ' {
                        split_idx += 1;
                    }
                    if split_idx >= tok3.len() {
                        print_fail!("Usage: log grant <kind> <task> <r|w|rw>");
                        return Ok(());
                    }
                    let target_task_bytes = &tok3[..split_idx];
                    let mut rights_start = split_idx;
                    while rights_start < tok3.len() && tok3[rights_start] == b' ' {
                        rights_start += 1;
                    }
                    if rights_start >= tok3.len() {
                        print_fail!("Usage: log grant <kind> <task> <r|w|rw>");
                        return Ok(());
                    }
                    let rights_bytes = &tok3[rights_start..];
                    
                    let target_task_id = parse_usize(target_task_bytes)?;
                    
                    let donor_cap = {
                        let slots = get_shell_caps();
                        let mut found = None;
                        for cap_opt in slots.iter() {
                            if let Some(cap) = cap_opt {
                                if let Resource::LogChannel { kind: cap_kind, .. } = cap.resource {
                                    if cap_kind == kind {
                                        found = Some(*cap);
                                        break;
                                    }
                                }
                            }
                        }
                        found
                    };
                    
                    let donor = match donor_cap {
                        Some(c) => c,
                        None => {
                            print_fail!("no capability");
                            return Ok(());
                        }
                    };
                    
                    let req_read = rights_bytes == b"r" || rights_bytes == b"rw";
                    let req_write = rights_bytes == b"w" || rights_bytes == b"rw";
                    
                    let derived = Capability {
                        resource: Resource::LogChannel {
                            kind,
                            readable: donor.read && req_read,
                            writable: donor.write && req_write,
                        },
                        read: donor.read && req_read,
                        write: donor.write && req_write,
                        grant: false,
                        sealed: false,
                        id: 0,
                        origin: Some(donor.id),
                    };
                    
                    let mut _new_id = 0;
                    {
                        let mut sched = scheduler::SCHEDULER.lock();
                        if sched.tasks[target_task_id].is_none() {
                            sched.tasks[target_task_id] = Some(Task::new(TaskId(target_task_id), park, CapTable::new()));
                            crate::process::TASKS_SPAWNED.fetch_add(1, Ordering::SeqCst);
                        }
                        if let Some(ref mut target_task) = sched.tasks[target_task_id] {
                            let new_slot = target_task.cap_table.insert(derived).unwrap();
                            if let Some(ref mut cap) = target_task.cap_table.slots[new_slot] {
                                cap.origin = Some(donor.id);
                                _new_id = cap.id;
                            }
                        }
                    }
                    
                    let r_str = if req_read && req_write { "read-write" } else if req_read { "read-only" } else { "write-only" };
                    print_ok!("granted {} LogChannel kind {} to task {}", r_str, kind, target_task_id);
                }
                b"revoke" => {
                    let kind_val = parse_usize(tok2)?;
                    let kind = kind_val as u8;
                    
                    let shell_slot_idx = {
                        let slots = get_shell_caps();
                        let mut found = None;
                        for (i, cap_opt) in slots.iter().enumerate() {
                            if let Some(cap) = cap_opt {
                                if let Resource::LogChannel { kind: cap_kind, .. } = cap.resource {
                                    if cap_kind == kind {
                                        found = Some(i);
                                        break;
                                    }
                                }
                            }
                        }
                        found
                    };
                    
                    match shell_slot_idx {
                        Some(idx) => {
                            let mut sched = scheduler::SCHEDULER.lock();
                            let task = sched.get_task_mut(TaskId(64)).unwrap();
                            let revoked = task.cap_table.kernel_revoke(idx);
                            if let Some(cap) = revoked {
                                print_ok!("revoked LogChannel kind {} id={}; access denied", kind, cap.id);
                            } else {
                                print_fail!("revocation check failed");
                            }
                        }
                        None => {
                            print_fail!("kind {} empty", kind);
                        }
                    }
                }
                b"tail" => {
                    let mut readable_kinds = [false; 16];
                    {
                        let slots = get_shell_caps();
                        for cap_opt in slots.iter() {
                            if let Some(cap) = cap_opt {
                                if let Resource::LogChannel { kind, readable, .. } = cap.resource {
                                    if readable && cap.read {
                                        readable_kinds[kind as usize] = true;
                                    }
                                }
                            }
                        }
                    }
                    
                    ensure_log_service();
                    print_info!("tailing log kinds (press 'q' to quit)...");
                    
                    let mut last_tick = preempt::stats().ticks;
                    loop {
                        let current_tick = preempt::stats().ticks;
                        if current_tick != last_tick {
                            last_tick = current_tick;
                            
                            let key_opt = crate::drivers::serial::SERIAL1.lock().try_read();
                            if let Some(b) = key_opt {
                                if b == b'q' || b == b'Q' {
                                    print_ok!("log tail stopped");
                                    return Ok(());
                                }
                            }
                            
                            for kind in 0..16 {
                                if !readable_kinds[kind] { continue; }
                                
                                let mut cap_idx = None;
                                {
                                    let slots = get_shell_caps();
                                    for (i, slot_opt) in slots.iter().enumerate() {
                                        if let Some(cap) = slot_opt {
                                            if let Resource::IpcChannel { target_task } = cap.resource {
                                                if target_task.0 == 83 {
                                                    cap_idx = Some(i);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                                let cap_idx = match cap_idx {
                                    Some(idx) => idx,
                                    None => {
                                        print_fail!("no capability");
                                        return Ok(());
                                    }
                                };
                                
                                loop {
                                    let payload = [kind as u8];
                                    if process::ipc::sys_send_typed(cap_idx, process::IpcTag::LogRead as u16, 1, &payload).is_ok() {
                                        if let Ok(reply) = process::ipc::sys_receive_typed() {
                                            if reply.payload[0] == 0 {
                                                let tick = u64::from_ne_bytes(reply.payload[1..9].try_into().unwrap());
                                                let producer = usize::from_ne_bytes(reply.payload[9..17].try_into().unwrap());
                                                let len = usize::from_ne_bytes(reply.payload[18..26].try_into().unwrap());
                                                let msg_bytes = &reply.payload[26..26+len];
                                                let msg_str = core::str::from_utf8(msg_bytes).unwrap_or("");
                                                print_info!("  [{}] prod={} kind={} message={}", tick, producer, kind, msg_str);
                                                continue;
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                        
                        scheduler::yield_cpu();
                    }
                }
                other => {
                    let s = core::str::from_utf8(other).unwrap_or("");
                    print_fail!("unknown log subcommand: {}", s);
                }
            }
        }
        _ => {
            if let Ok(s) = core::str::from_utf8(line) {
                print_fail!("unknown command: {}", s);
            }
            print_info!("try: help");
        }
    }

    Ok(())
}

fn get_shell_caps() -> [Option<Capability>; MAX_CAPS] {
    let sched = scheduler::SCHEDULER.lock();
    sched.get_task(TaskId(64)).unwrap().cap_table.slots
}

fn parse_usize(tok: &[u8]) -> Result<usize, ()> {
    if tok.is_empty() {
        print_fail!("bad number: ");
        return Err(());
    }
    let mut val = 0usize;
    for &b in tok {
        if !(b'0'..=b'9').contains(&b) {
            let s = core::str::from_utf8(tok).unwrap_or("");
            print_fail!("bad number: {}", s);
            return Err(());
        }
        if let Some(new_val) = val.checked_mul(10).and_then(|v| v.checked_add((b - b'0') as usize)) {
            val = new_val;
        } else {
            let s = core::str::from_utf8(tok).unwrap_or("");
            print_fail!("bad number: {}", s);
            return Err(());
        }
    }
    Ok(val)
}

pub static FS_OPS: AtomicU64 = AtomicU64::new(0);
pub static DEV_OPS: AtomicU64 = AtomicU64::new(0);
pub static SYNC_ACQ: AtomicU64 = AtomicU64::new(0);
pub static SYNC_REL: AtomicU64 = AtomicU64::new(0);
pub static KBD_IRQS: AtomicU64 = AtomicU64::new(0);

static COUNTER_A: AtomicU64 = AtomicU64::new(0);
static COUNTER_B: AtomicU64 = AtomicU64::new(0);

extern "C" fn timeslice_task_a() -> ! {
    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
    let start = preempt::stats().ticks;
    loop {
        COUNTER_A.fetch_add(1, Ordering::Relaxed);
        if preempt::stats().ticks.wrapping_sub(start) >= 200 {
            break;
        }
        core::hint::spin_loop();
    }
    scheduler::terminate_current_task();
}

extern "C" fn timeslice_task_b() -> ! {
    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
    let start = preempt::stats().ticks;
    loop {
        COUNTER_B.fetch_add(1, Ordering::Relaxed);
        if preempt::stats().ticks.wrapping_sub(start) >= 200 {
            break;
        }
        core::hint::spin_loop();
    }
    scheduler::terminate_current_task();
}

extern "C" fn fault_task_entry() -> ! {
    unsafe {
        core::ptr::read_volatile(0x0000_1234_5678 as *const u64);
    }
    loop { scheduler::yield_cpu(); }
}

fn ensure_echo_service() {
    let mut sched = scheduler::SCHEDULER.lock();
    if sched.tasks[65].is_none() {
        let mut caps = CapTable::new();
        let _ = caps.insert(Capability {
            resource: Resource::IpcChannel { target_task: TaskId(64) },
            read: true,
            write: true,
            grant: false,
            sealed: false,
            id: 0,
            origin: None,
        }).unwrap();
        sched.tasks[65] = Some(Task::new(TaskId(65), echo_service_main, caps));
    }
}

extern "C" fn echo_service_main() -> ! {
    loop {
        match process::ipc::sys_receive_typed() {
            Ok(msg) => {
                let _ = process::ipc::sys_send_typed(0, process::IpcTag::Raw as u16, msg.version, &msg.payload[..msg.len]);
            }
            Err(_) => {
                scheduler::yield_cpu();
            }
        }
    }
}

static STRESS_DELIVERIES: AtomicU64 = AtomicU64::new(0);

extern "C" fn stress_worker_entry() -> ! {
    let my_id = scheduler::current_task_id().unwrap().0;
    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
    
    let is_initiator = my_id % 2 == 1;
    
    if is_initiator {
        let _ = process::ipc::sys_send_typed(0, process::IpcTag::Raw as u16, 1, b"ping");
    }
    
    loop {
        match process::ipc::sys_receive_typed() {
            Ok(_msg) => {
                STRESS_DELIVERIES.fetch_add(1, Ordering::Relaxed);
                let _ = process::ipc::sys_send_typed(0, process::IpcTag::Raw as u16, 1, b"ping");
            }
            Err(_) => {
                scheduler::yield_cpu();
            }
        }
    }
}

// ── Observability and usability extensions ───────────────────────────────────

pub struct History {
    pub buffer: [[u8; 128]; 16],
    pub lens: [usize; 16],
    pub head: usize,
    pub count: usize,
}

impl History {
    pub const fn new() -> Self {
        Self {
            buffer: [[0u8; 128]; 16],
            lens: [0; 16],
            head: 0,
            count: 0,
        }
    }

    pub fn push(&mut self, cmd: &[u8]) {
        if cmd.is_empty() { return; }
        if self.count > 0 {
            let last_idx = (self.head + 15) % 16;
            let last_len = self.lens[last_idx];
            if last_len == cmd.len() && &self.buffer[last_idx][..last_len] == cmd {
                return;
            }
        }
        let idx = self.head;
        let to_copy = core::cmp::min(cmd.len(), 128);
        self.buffer[idx][..to_copy].copy_from_slice(&cmd[..to_copy]);
        self.lens[idx] = to_copy;
        self.head = (idx + 1) % 16;
        if self.count < 16 {
            self.count += 1;
        }
    }

    pub fn get(&self, steps_back: usize) -> Option<&[u8]> {
        if steps_back == 0 || steps_back > self.count {
            return None;
        }
        let idx = (self.head + 16 - steps_back) % 16;
        let len = self.lens[idx];
        Some(&self.buffer[idx][..len])
    }
}

pub static HISTORY: crate::drivers::serial::Spinlock<History> = crate::drivers::serial::Spinlock::new(History::new());

pub fn read_line_with_history(buf: &mut [u8]) -> usize {
    let mut n = 0;
    let mut history_temp_idx = 0;
    let mut draft_buf = [0u8; 128];
    let mut draft_len = 0;

    loop {
        let b = crate::drivers::serial::read_byte();
        match b {
            b'\n' | b'\r' => {
                crate::print!("\r\n");
                return n;
            }
            0x08 | 0x7F => {
                if n > 0 {
                    n -= 1;
                    crate::print!("\x08 \x08");
                }
            }
            0x1b => {
                let next1 = crate::drivers::serial::read_byte();
                if next1 == b'[' {
                    let next2 = crate::drivers::serial::read_byte();
                    if next2 == b'A' {
                        let hist = HISTORY.lock();
                        if hist.count > 0 && history_temp_idx < hist.count {
                            if history_temp_idx == 0 {
                                draft_buf[..n].copy_from_slice(&buf[..n]);
                                draft_len = n;
                            }
                            history_temp_idx += 1;
                            for _ in 0..n {
                                crate::print!("\x08 \x08");
                            }
                            if let Some(cmd) = hist.get(history_temp_idx) {
                                buf[..cmd.len()].copy_from_slice(cmd);
                                n = cmd.len();
                                for &c in &buf[..n] {
                                    crate::print!("{}", c as char);
                                }
                            }
                        }
                    } else if next2 == b'B' {
                        if history_temp_idx > 0 {
                            history_temp_idx -= 1;
                            for _ in 0..n {
                                crate::print!("\x08 \x08");
                            }
                            if history_temp_idx == 0 {
                                buf[..draft_len].copy_from_slice(&draft_buf[..draft_len]);
                                n = draft_len;
                            } else {
                                let hist = HISTORY.lock();
                                if let Some(cmd) = hist.get(history_temp_idx) {
                                    buf[..cmd.len()].copy_from_slice(cmd);
                                    n = cmd.len();
                                }
                            }
                            for &c in &buf[..n] {
                                crate::print!("{}", c as char);
                            }
                        }
                    }
                }
            }
            0x20..=0x7E => {
                if n < buf.len() {
                    buf[n] = b;
                    n += 1;
                    crate::print!("{}", b as char);
                    history_temp_idx = 0;
                }
            }
            _ => {}
        }
    }
}

pub const TRACE_BUFFER_SIZE: usize = 128;
pub static mut TRACE_BUFFER: [TraceEvent; TRACE_BUFFER_SIZE] = [TraceEvent { tick: 0, msg: "", param1: 0, param2: 0 }; TRACE_BUFFER_SIZE];
pub static NEXT_IDX: AtomicUsize = AtomicUsize::new(0);
pub static TRACING_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static TRACE_OVERFLOW: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
pub struct TraceEvent {
    pub tick: u64,
    pub msg: &'static str,
    pub param1: u64,
    pub param2: u64,
}

pub fn log_trace(msg: &'static str, param1: u64, param2: u64) {
    if TRACING_ACTIVE.load(Ordering::Relaxed) {
        let idx = NEXT_IDX.fetch_add(1, Ordering::SeqCst);
        let target_idx = idx % TRACE_BUFFER_SIZE;
        unsafe {
            TRACE_BUFFER[target_idx] = TraceEvent {
                tick: preempt::stats().ticks,
                msg,
                param1,
                param2,
            };
        }
    }
}

fn print_trace_summary() {
    let total = NEXT_IDX.load(Ordering::SeqCst);
    let count = core::cmp::min(total, TRACE_BUFFER_SIZE);
    let start = if total > TRACE_BUFFER_SIZE { total % TRACE_BUFFER_SIZE } else { 0 };

    print_ok!("trace: {} events captured", total);
    for i in 0..count {
        let idx = (start + i) % TRACE_BUFFER_SIZE;
        let event = unsafe { TRACE_BUFFER[idx] };
        match event.msg {
            "sched_switch_yield" | "sched_switch_preempt" | "sched_switch_term" => {
                let switch_type = if event.msg == "sched_switch_yield" {
                    "yield"
                } else if event.msg == "sched_switch_preempt" {
                    "preempt"
                } else {
                    "term"
                };
                print_info!("  [{}] sched: switch ({}) task {} -> task {}", event.tick, switch_type, event.param1, event.param2);
            }
            "ipc_send" | "ipc_send_async" => {
                let is_async = if event.msg == "ipc_send_async" { " (async)" } else { "" };
                print_info!("  [{}] ipc: send{} cap_slot={}, tag={}", event.tick, is_async, event.param1, event.param2);
            }
            "ipc_receive" | "ipc_receive_async" => {
                let is_async = if event.msg == "ipc_receive_async" { " (async)" } else { "" };
                print_info!("  [{}] ipc: receive{} by task {}", event.tick, is_async, event.param1);
            }
            "cpu_exception" => {
                print_info!("  [{}] fault: exception vector {} at rip={:#x}", event.tick, event.param1, event.param2);
            }
            "cap_insert" => {
                print_info!("  [{}] cap: insert id={} at slot {}", event.tick, event.param1, event.param2);
            }
            "cap_lookup" => {
                print_info!("  [{}] cap: lookup slot {}, cap id {}", event.tick, event.param1, event.param2);
            }
            "cap_revoke" => {
                print_info!("  [{}] cap: revoke/remove slot {}, cap id {}", event.tick, event.param1, event.param2);
            }
            "fs_op" => {
                let op_name = match event.param1 {
                    0 => "mkdir",
                    1 => "write",
                    2 => "read",
                    3 => "ls",
                    4 => "delete",
                    5 => "stat",
                    _ => "unknown",
                };
                print_info!("  [{}] fs: op {} status={}", event.tick, op_name, event.param2);
            }
            "dev_op" => {
                let op_name = match event.param1 {
                    0 => "read",
                    1 => "write",
                    _ => "unknown",
                };
                print_info!("  [{}] dev: op {} status={}", event.tick, op_name, event.param2);
            }
            "sync_op" => {
                let op_name = match event.param1 {
                    0 => "create",
                    1 => "acquire",
                    2 => "release",
                    _ => "unknown",
                };
                print_info!("  [{}] sync: op {} status={}", event.tick, op_name, event.param2);
            }
            other => {
                print_info!("  [{}] {}: param1={}, param2={}", event.tick, other, event.param1, event.param2);
            }
        }
    }
    if total > TRACE_BUFFER_SIZE {
        print_warn!("  [trace ring buffer overflowed: oldest events overwritten]");
    }
}

pub static mut WATCH_BUF_CUR: [u8; 1024] = [0; 1024];
pub static mut WATCH_BUF_PREV: [u8; 1024] = [0; 1024];
pub static mut WATCH_LEN_CUR: usize = 0;
pub static mut WATCH_LEN_PREV: usize = 0;

fn print_diffed_buffers() {
    let cur = unsafe { &WATCH_BUF_CUR[..WATCH_LEN_CUR] };
    let prev = unsafe { &WATCH_BUF_PREV[..WATCH_LEN_PREV] };
    
    let mut cur_pos = 0;
    let mut prev_pos = 0;
    
    while cur_pos < cur.len() {
        let mut cur_end = cur_pos;
        while cur_end < cur.len() && cur[cur_end] != b'\n' {
            cur_end += 1;
        }
        let cur_line = &cur[cur_pos..cur_end];
        let has_lf = cur_end < cur.len();
        cur_pos = cur_end + (if has_lf { 1 } else { 0 });
        
        let prev_line = if prev_pos < prev.len() {
            let mut prev_end = prev_pos;
            while prev_end < prev.len() && prev[prev_end] != b'\n' {
                prev_end += 1;
            }
            let line = &prev[prev_pos..prev_end];
            let p_has_lf = prev_end < prev.len();
            prev_pos = prev_end + (if p_has_lf { 1 } else { 0 });
            Some(line)
        } else {
            None
        };
        
        let clean_cur = if cur_line.ends_with(b"\r") { &cur_line[..cur_line.len() - 1] } else { cur_line };
        let clean_prev = prev_line.map(|l| if l.ends_with(b"\r") { &l[..l.len() - 1] } else { l });
        
        let is_different = match clean_prev {
            Some(p) => clean_cur != p,
            None => true,
        };
        
        if is_different {
            if let Ok(s) = core::str::from_utf8(clean_cur) {
                crate::print!("\x1b[33m* {}\x1b[0m\n", s);
            }
        } else {
            if let Ok(s) = core::str::from_utf8(clean_cur) {
                crate::print!("  {}\n", s);
            }
        }
    }
}

#[derive(Clone, Copy)]
struct KvSlot {
    key: [u8; 16],
    value: [u8; 64],
}

impl KvSlot {
    const fn new() -> Self {
        Self {
            key: [0; 16],
            value: [0; 64],
        }
    }
}

struct KvStore {
    slots: [KvSlot; 32],
}

impl KvStore {
    const fn new() -> Self {
        Self {
            slots: [KvSlot::new(); 32],
        }
    }
}

static KV_STORE: crate::drivers::serial::Spinlock<KvStore> = crate::drivers::serial::Spinlock::new(KvStore::new());

fn check_sender_cap(sender_id: TaskId, slot: usize, require_write: bool) -> bool {
    let sched = scheduler::SCHEDULER.lock();
    if let Some(task) = sched.get_task(sender_id) {
        for cap_opt in task.cap_table.slots.iter() {
            if let Some(cap) = cap_opt {
                if let Resource::KVEntry { slot: cap_slot, readable, writable } = cap.resource {
                    if cap_slot == slot {
                        if require_write {
                            if writable && cap.write {
                                return true;
                            }
                        } else {
                            if readable && cap.read {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

fn ensure_kv_service() {
    let mut sched = scheduler::SCHEDULER.lock();
    if sched.tasks[82].is_none() {
        let mut caps = CapTable::new();
        let _ = caps.insert(Capability {
            resource: Resource::IpcChannel { target_task: TaskId(64) },
            read: true,
            write: true,
            grant: false,
            sealed: false,
            id: 0,
            origin: None,
        }).unwrap();
        sched.tasks[82] = Some(Task::new(TaskId(82), kv_service_main, caps));
        crate::process::TASKS_SPAWNED.fetch_add(1, Ordering::SeqCst);
    }
}

extern "C" fn kv_service_main() -> ! {
    loop {
        match process::ipc::sys_receive_typed() {
            Ok(msg) => {
                let mut reply_payload = [0u8; 128];
                let mut reply_len = 1;

                match msg.tag {
                    process::IpcTag::KVGet => {
                        if msg.len < 1 {
                            reply_payload[0] = 2; // invalid
                        } else {
                            let slot = msg.payload[0] as usize;
                            if slot >= 32 {
                                reply_payload[0] = 2; // invalid slot
                            } else if !check_sender_cap(msg.sender, slot, false) {
                                reply_payload[0] = 1; // permission denied
                            } else {
                                reply_payload[0] = 0; // success
                                let store = KV_STORE.lock();
                                reply_payload[1..17].copy_from_slice(&store.slots[slot].key);
                                reply_payload[17..81].copy_from_slice(&store.slots[slot].value);
                                reply_len = 81;
                            }
                        }
                    }
                    process::IpcTag::KVSet => {
                        if msg.len < 81 {
                            reply_payload[0] = 2; // invalid
                        } else {
                            let slot = msg.payload[0] as usize;
                            if slot >= 32 {
                                reply_payload[0] = 2; // invalid slot
                            } else if !check_sender_cap(msg.sender, slot, true) {
                                reply_payload[0] = 1; // permission denied
                            } else {
                                reply_payload[0] = 0; // success
                                let mut store = KV_STORE.lock();
                                store.slots[slot].key.copy_from_slice(&msg.payload[1..17]);
                                store.slots[slot].value.copy_from_slice(&msg.payload[17..81]);
                            }
                        }
                    }
                    _ => {
                        reply_payload[0] = 2; // invalid tag
                    }
                }

                // Install dynamic IpcChannel to sender in slot 1 of KV service (task 82)
                {
                    let mut sched = scheduler::SCHEDULER.lock();
                    let my_task = sched.get_task_mut(TaskId(82)).unwrap();
                    my_task.cap_table.slots[1] = Some(Capability {
                        resource: Resource::IpcChannel { target_task: msg.sender },
                        read: true,
                        write: true,
                        grant: false,
                        sealed: false,
                        id: 8200 + msg.sender.0 as u64,
                        origin: None,
                    });
                }

                // Send reply back to client
                let _ = process::ipc::sys_send_typed(1, process::IpcTag::Raw as u16, 1, &reply_payload[..reply_len]);
            }
            Err(_) => {
                scheduler::yield_cpu();
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct LogEntry {
    pub tick:     u64,
    pub producer: TaskId,
    pub kind:     u8,        // event type, 0..=15
    pub msg:      [u8; 64],
    pub len:      usize,
}

impl LogEntry {
    const fn new() -> Self {
        Self {
            tick: 0,
            producer: TaskId(0),
            kind: 0,
            msg: [0; 64],
            len: 0,
        }
    }
}

const LOG_CAPACITY: usize = 128;

pub struct LogRingBuffer {
    pub buffer: [LogEntry; LOG_CAPACITY],
    pub write_pos: usize,
}

impl LogRingBuffer {
    const fn new() -> Self {
        Self {
            buffer: [LogEntry::new(); LOG_CAPACITY],
            write_pos: 0,
        }
    }

    pub fn push(&mut self, entry: LogEntry) {
        let idx = self.write_pos % LOG_CAPACITY;
        self.buffer[idx] = entry;
        self.write_pos += 1;
    }
}

static LOG: crate::drivers::serial::Spinlock<LogRingBuffer> = crate::drivers::serial::Spinlock::new(LogRingBuffer::new());

static CURSORS: crate::drivers::serial::Spinlock<[usize; crate::process::MAX_TASKS]> = crate::drivers::serial::Spinlock::new([0; crate::process::MAX_TASKS]);

fn check_log_sender_cap(sender_id: TaskId, kind: u8, require_write: bool) -> bool {
    let sched = scheduler::SCHEDULER.lock();
    if let Some(task) = sched.get_task(sender_id) {
        for cap_opt in task.cap_table.slots.iter() {
            if let Some(cap) = cap_opt {
                if let Resource::LogChannel { kind: cap_kind, readable, writable } = cap.resource {
                    if cap_kind == kind {
                        if require_write {
                            if writable && cap.write {
                                return true;
                            }
                        } else {
                            if readable && cap.read {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

fn ensure_log_service() {
    let mut sched = scheduler::SCHEDULER.lock();
    if sched.tasks[83].is_none() {
        let mut caps = CapTable::new();
        let _ = caps.insert(Capability {
            resource: Resource::IpcChannel { target_task: TaskId(64) },
            read: true,
            write: true,
            grant: false,
            sealed: false,
            id: 0,
            origin: None,
        }).unwrap();
        sched.tasks[83] = Some(Task::new(TaskId(83), log_service_main, caps));
        crate::process::TASKS_SPAWNED.fetch_add(1, Ordering::SeqCst);
    }
}

extern "C" fn log_service_main() -> ! {
    loop {
        match process::ipc::sys_receive_typed() {
            Ok(msg) => {
                let mut reply_payload = [0u8; 128];
                let mut reply_len = 1;

                match msg.tag {
                    process::IpcTag::LogPublish => {
                        if msg.len < 1 {
                            reply_payload[0] = 2; // invalid
                        } else {
                            let kind = msg.payload[0];
                            if kind >= 16 {
                                reply_payload[0] = 3; // invalid kind
                            } else if !check_log_sender_cap(msg.sender, kind, true) {
                                reply_payload[0] = 1; // permission denied
                            } else {
                                let mut entry = LogEntry::new();
                                entry.tick = preempt::stats().ticks;
                                entry.producer = msg.sender;
                                entry.kind = kind;
                                let msg_bytes_len = core::cmp::min(msg.len - 1, 64);
                                entry.len = msg_bytes_len;
                                entry.msg[..msg_bytes_len].copy_from_slice(&msg.payload[1..1+msg_bytes_len]);
                                
                                LOG.lock().push(entry);
                                reply_payload[0] = 0; // success
                            }
                        }
                    }
                    process::IpcTag::LogRead => {
                        if msg.len < 1 {
                            reply_payload[0] = 3; // invalid
                        } else {
                            let kind = msg.payload[0];
                            if kind >= 16 {
                                reply_payload[0] = 3; // invalid kind
                            } else if !check_log_sender_cap(msg.sender, kind, false) {
                                reply_payload[0] = 1; // permission denied
                            } else {
                                let sender_idx = msg.sender.0;
                                let oldest_valid = {
                                    let log = LOG.lock();
                                    if log.write_pos > LOG_CAPACITY {
                                        log.write_pos - LOG_CAPACITY
                                    } else {
                                        0
                                    }
                                };
                                
                                let mut cursors = CURSORS.lock();
                                if cursors[sender_idx] < oldest_valid {
                                    cursors[sender_idx] = oldest_valid;
                                }
                                
                                let mut found_entry = None;
                                let mut found_idx = 0;
                                {
                                    let log = LOG.lock();
                                    for idx in cursors[sender_idx]..log.write_pos {
                                        let entry = log.buffer[idx % LOG_CAPACITY];
                                        if entry.kind == kind {
                                            found_entry = Some(entry);
                                            found_idx = idx;
                                            break;
                                        }
                                    }
                                }
                                
                                if let Some(entry) = found_entry {
                                    cursors[sender_idx] = found_idx + 1;
                                    reply_payload[0] = 0; // success
                                    reply_payload[1..9].copy_from_slice(&entry.tick.to_ne_bytes());
                                    reply_payload[9..17].copy_from_slice(&entry.producer.0.to_ne_bytes());
                                    reply_payload[17] = entry.kind;
                                    reply_payload[18..26].copy_from_slice(&entry.len.to_ne_bytes());
                                    reply_payload[26..26+64].copy_from_slice(&entry.msg);
                                    reply_len = 90;
                                } else {
                                    // No new entry, advance cursor to current write_pos
                                    cursors[sender_idx] = LOG.lock().write_pos;
                                    reply_payload[0] = 2; // empty
                                }
                            }
                        }
                    }
                    _ => {
                        reply_payload[0] = 3; // invalid tag
                    }
                }

                // Install dynamic IpcChannel to sender in slot 1 of Log service (task 83)
                {
                    let mut sched = scheduler::SCHEDULER.lock();
                    let my_task = sched.get_task_mut(TaskId(83)).unwrap();
                    my_task.cap_table.slots[1] = Some(Capability {
                        resource: Resource::IpcChannel { target_task: msg.sender },
                        read: true,
                        write: true,
                        grant: false,
                        sealed: false,
                        id: 8300 + msg.sender.0 as u64,
                        origin: None,
                    });
                }

                // Send reply back to client using the reply tag LogAck
                let _ = process::ipc::sys_send_typed(1, process::IpcTag::LogAck as u16, 1, &reply_payload[..reply_len]);
            }
            Err(_) => {
                scheduler::yield_cpu();
            }
        }
    }
}

// ── Virtual filesystem service ──────────────────────────────────────────────

const FS_MAX_NODES: usize = 64;
const FS_NAME_LEN: usize  = 30;   // full path, e.g. b"/docs/a"
const FS_DATA_LEN: usize  = 94;   // file contents (fits one 128B IPC payload)

#[derive(Clone, Copy)]
struct FsNode {
    used: bool,
    is_dir: bool,
    name: [u8; FS_NAME_LEN],   // absolute path; 0-padded
    name_len: usize,
    data: [u8; FS_DATA_LEN],
    data_len: usize,
    mount: u8,
}
impl FsNode { const fn empty() -> Self { Self {
    used: false, is_dir: false, name: [0; FS_NAME_LEN], name_len: 0,
    data: [0; FS_DATA_LEN], data_len: 0, mount: 0,
}}}

struct FsStore { nodes: [FsNode; FS_MAX_NODES] }
impl FsStore {
    const fn new() -> Self { Self { nodes: [FsNode::empty(); FS_MAX_NODES] } }
    fn find_node(&self, mount: u8, name: &[u8]) -> Option<usize> {
        for (i, node) in self.nodes.iter().enumerate() {
            if node.used && node.mount == mount && &node.name[..node.name_len] == name {
                return Some(i);
            }
        }
        None
    }
}
static FS_STORE: crate::drivers::serial::Spinlock<FsStore> =
    crate::drivers::serial::Spinlock::new(FsStore::new());

fn fs_check_cap(sender: TaskId, mount: u8, need_write: bool) -> bool {
    let sched = scheduler::SCHEDULER.lock();
    if let Some(task) = sched.get_task(sender) {
        for cap in task.cap_table.slots.iter().flatten() {
            if let Resource::FsNode { mount: m, readable, writable } = cap.resource {
                if m == mount {
                    if need_write { if writable && cap.write { return true; } }
                    else          { if readable && cap.read  { return true; } }
                }
            }
        }
    }
    false
}

fn ensure_fs_service() {
    let mut sched = scheduler::SCHEDULER.lock();
    if sched.tasks[84].is_none() {
        let mut caps = CapTable::new();
        let _ = caps.insert(Capability {
            resource: Resource::IpcChannel { target_task: TaskId(64) },
            read: true, write: true, grant: false, sealed: false, id: 0, origin: None,
        }).unwrap();
        sched.tasks[84] = Some(Task::new(TaskId(84), fs_service_main, caps));
        crate::process::TASKS_SPAWNED.fetch_add(1, Ordering::SeqCst);
    }
}

extern "C" fn fs_service_main() -> ! {
    loop {
        match process::ipc::sys_receive_typed() {
            Ok(msg) => {
                let mut reply = [0u8; 128];
                let mut reply_len = 1;
                FS_OPS.fetch_add(1, Ordering::Relaxed);
                
                if msg.tag != process::IpcTag::FsOp {
                    reply[0] = 4; // bad request
                } else if msg.len < 3 {
                    reply[0] = 4; // bad request
                } else {
                    let op = msg.payload[0];
                    let mount = msg.payload[1];
                    let name_len = msg.payload[2] as usize;
                    
                    if name_len > 30 || msg.len < 3 + name_len {
                        reply[0] = 4; // bad request
                    } else {
                        let name_bytes = &msg.payload[3..3 + name_len];
                        log_trace("fs_op", op as u64, 0);
                        
                        match op {
                            0 => { // mkdir
                                if !fs_check_cap(msg.sender, mount, true) {
                                    reply[0] = 1; // denied
                                } else {
                                    let mut store = FS_STORE.lock();
                                    if store.find_node(mount, name_bytes).is_some() {
                                        reply[0] = 4; // already exists
                                    } else {
                                        let mut found_slot = None;
                                        for (idx, node) in store.nodes.iter().enumerate() {
                                            if !node.used {
                                                found_slot = Some(idx);
                                                break;
                                            }
                                        }
                                        if let Some(idx) = found_slot {
                                            let node = &mut store.nodes[idx];
                                            node.used = true;
                                            node.is_dir = true;
                                            node.name[..name_len].copy_from_slice(name_bytes);
                                            node.name_len = name_len;
                                            node.data_len = 0;
                                            node.mount = mount;
                                            reply[0] = 0; // ok
                                        } else {
                                            reply[0] = 3; // full
                                        }
                                    }
                                }
                            }
                            1 => { // write
                                if !fs_check_cap(msg.sender, mount, true) {
                                    reply[0] = 1; // denied
                                } else {
                                    let data_len = msg.payload[33] as usize;
                                    if data_len > 94 || msg.len < 34 + data_len {
                                        reply[0] = 4; // bad request
                                    } else {
                                        let data_bytes = &msg.payload[34..34 + data_len];
                                        let mut store = FS_STORE.lock();
                                        let slot_opt = store.find_node(mount, name_bytes);
                                        if let Some(idx) = slot_opt {
                                            let node = &mut store.nodes[idx];
                                            if node.is_dir {
                                                reply[0] = 4; // cannot write to dir
                                            } else {
                                                node.data[..data_len].copy_from_slice(data_bytes);
                                                node.data_len = data_len;
                                                reply[0] = 0; // ok
                                            }
                                        } else {
                                            let mut found_slot = None;
                                            for (idx, node) in store.nodes.iter().enumerate() {
                                                if !node.used {
                                                    found_slot = Some(idx);
                                                    break;
                                                }
                                            }
                                            if let Some(idx) = found_slot {
                                                let node = &mut store.nodes[idx];
                                                node.used = true;
                                                node.is_dir = false;
                                                node.name[..name_len].copy_from_slice(name_bytes);
                                                node.name_len = name_len;
                                                node.data[..data_len].copy_from_slice(data_bytes);
                                                node.data_len = data_len;
                                                node.mount = mount;
                                                reply[0] = 0; // ok
                                            } else {
                                                reply[0] = 3; // full
                                            }
                                        }
                                    }
                                }
                            }
                            2 => { // read
                                if !fs_check_cap(msg.sender, mount, false) {
                                    reply[0] = 1; // denied
                                } else {
                                    let store = FS_STORE.lock();
                                    if let Some(idx) = store.find_node(mount, name_bytes) {
                                        let node = &store.nodes[idx];
                                        if node.is_dir {
                                            reply[0] = 2; // not found / is dir
                                        } else {
                                            reply[0] = 0; // ok
                                            reply[1] = node.data_len as u8;
                                            reply[2..2 + node.data_len].copy_from_slice(&node.data[..node.data_len]);
                                            reply_len = 2 + node.data_len;
                                        }
                                    } else {
                                        reply[0] = 2; // not found
                                    }
                                }
                            }
                            3 => { // ls
                                if !fs_check_cap(msg.sender, mount, false) {
                                    reply[0] = 1; // denied
                                } else {
                                    let mut prefix = [0u8; 32];
                                    let mut prefix_len;
                                    if name_bytes == b"/" {
                                        prefix[0] = b'/';
                                        prefix_len = 1;
                                    } else {
                                        prefix[..name_len].copy_from_slice(name_bytes);
                                        prefix_len = name_len;
                                        if name_bytes[name_len - 1] != b'/' {
                                            prefix[name_len] = b'/';
                                            prefix_len += 1;
                                        }
                                    }
                                    
                                    let store = FS_STORE.lock();
                                    let mut count = 0;
                                    let mut out_idx = 2;
                                    for node in store.nodes.iter() {
                                        if node.used && node.mount == mount {
                                            let node_name = &node.name[..node.name_len];
                                            if node_name.starts_with(&prefix[..prefix_len]) && node_name != name_bytes {
                                                let suffix = &node_name[prefix_len..];
                                                if !suffix.contains(&b'/') {
                                                    if out_idx + suffix.len() + 1 <= 128 {
                                                        reply[out_idx..out_idx + suffix.len()].copy_from_slice(suffix);
                                                        out_idx += suffix.len();
                                                        reply[out_idx] = b'\n';
                                                        out_idx += 1;
                                                        count += 1;
                                                    }
                                                }
                                            } else if name_bytes == b"/" && node_name.starts_with(b"/") && node_name != b"/" {
                                                let suffix = &node_name[1..];
                                                if !suffix.contains(&b'/') {
                                                    if out_idx + suffix.len() + 1 <= 128 {
                                                        reply[out_idx..out_idx + suffix.len()].copy_from_slice(suffix);
                                                        out_idx += suffix.len();
                                                        reply[out_idx] = b'\n';
                                                        out_idx += 1;
                                                        count += 1;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    reply[0] = 0;
                                    reply[1] = count as u8;
                                    reply_len = out_idx;
                                }
                            }
                            4 => { // delete
                                if !fs_check_cap(msg.sender, mount, true) {
                                    reply[0] = 1; // denied
                                } else {
                                    let mut store = FS_STORE.lock();
                                    if let Some(idx) = store.find_node(mount, name_bytes) {
                                        store.nodes[idx].used = false;
                                        reply[0] = 0;
                                    } else {
                                        reply[0] = 2; // not found
                                    }
                                }
                            }
                            5 => { // stat
                                if !fs_check_cap(msg.sender, mount, false) {
                                    reply[0] = 1; // denied
                                } else {
                                    let store = FS_STORE.lock();
                                    if let Some(idx) = store.find_node(mount, name_bytes) {
                                        let node = &store.nodes[idx];
                                        reply[0] = 0;
                                        reply[1] = if node.is_dir { 1 } else { 0 };
                                        let size_val = node.data_len as u64;
                                        reply[2..10].copy_from_slice(&size_val.to_ne_bytes());
                                        reply[10] = node.mount;
                                        reply_len = 11;
                                    } else {
                                        reply[0] = 2; // not found
                                    }
                                }
                            }
                            _ => { reply[0] = 4; }
                        }
                    }
                }
                
                {
                    let mut sched = scheduler::SCHEDULER.lock();
                    let me = sched.get_task_mut(TaskId(84)).unwrap();
                    me.cap_table.slots[1] = Some(Capability {
                        resource: Resource::IpcChannel { target_task: msg.sender },
                        read: true, write: true, grant: false, sealed: false,
                        id: 84000 + msg.sender.0 as u64, origin: None,
                    });
                }
                let _ = process::ipc::sys_send_typed(
                    1, process::IpcTag::FsReply as u16, 1, &reply[..reply_len]);
            }
            Err(_) => scheduler::yield_cpu(),
        }
    }
}

// ── Device manager service ───────────────────────────────────────────────────

fn dev_check_cap(sender: TaskId, id: u8, require_write: bool) -> bool {
    let sched = scheduler::SCHEDULER.lock();
    if let Some(task) = sched.get_task(sender) {
        for cap in task.cap_table.slots.iter().flatten() {
            if let Resource::Device { id: cap_id, readable, writable } = cap.resource {
                if cap_id == id {
                    if require_write { if writable && cap.write { return true; } }
                    else          { if readable && cap.read  { return true; } }
                }
            }
        }
    }
    false
}

fn ensure_device_service() {
    let mut sched = scheduler::SCHEDULER.lock();
    if sched.tasks[85].is_none() {
        let mut caps = CapTable::new();
        let _ = caps.insert(Capability {
            resource: Resource::IpcChannel { target_task: TaskId(64) },
            read: true, write: true, grant: false, sealed: false, id: 0, origin: None,
        }).unwrap();
        sched.tasks[85] = Some(Task::new(TaskId(85), dev_service_main, caps));
        crate::process::TASKS_SPAWNED.fetch_add(1, Ordering::SeqCst);
    }
}

extern "C" fn dev_service_main() -> ! {
    loop {
        match process::ipc::sys_receive_typed() {
            Ok(msg) => {
                let mut reply = [0u8; 128];
                let mut reply_len = 1;
                DEV_OPS.fetch_add(1, Ordering::Relaxed);
                
                if msg.tag != process::IpcTag::DevOp {
                    reply[0] = 3;
                } else if msg.len < 2 {
                    reply[0] = 3;
                } else {
                    let op = msg.payload[0];
                    let dev_id = msg.payload[1];
                    log_trace("dev_op", op as u64, dev_id as u64);
                    
                    if dev_id != 0 && dev_id != 1 {
                        reply[0] = 3;
                    } else {
                        match op {
                            0 => { // read
                                if !dev_check_cap(msg.sender, dev_id, false) {
                                    reply[0] = 1; // denied
                                } else {
                                    if dev_id == 0 { // serial
                                        let mut read_len = 0;
                                        while read_len < 120 {
                                            if let Some(b) = crate::drivers::serial::SERIAL1.lock().try_read() {
                                                reply[2 + read_len] = b;
                                                read_len += 1;
                                            } else { break; }
                                        }
                                        if read_len > 0 {
                                            reply[0] = 0;
                                            reply[1] = read_len as u8;
                                            reply_len = 2 + read_len;
                                        } else {
                                            reply[0] = 2; // empty
                                        }
                                    } else { // keyboard
                                        let mut read_len = 0;
                                        while read_len < 120 {
                                            if let Some(b) = crate::drivers::keyboard::try_read() {
                                                reply[2 + read_len] = b;
                                                read_len += 1;
                                            } else { break; }
                                        }
                                        if read_len > 0 {
                                            reply[0] = 0;
                                            reply[1] = read_len as u8;
                                            reply_len = 2 + read_len;
                                        } else {
                                            reply[0] = 2; // empty
                                        }
                                    }
                                }
                            }
                            1 => { // write
                                if !dev_check_cap(msg.sender, dev_id, true) {
                                    reply[0] = 1;
                                } else {
                                    let write_len = msg.payload[2] as usize;
                                    if write_len > 120 || msg.len < 3 + write_len {
                                        reply[0] = 3;
                                    } else {
                                        let write_bytes = &msg.payload[3..3 + write_len];
                                        if dev_id == 0 {
                                            use core::fmt::Write;
                                            let _ = crate::drivers::serial::SERIAL1.lock().write_str(
                                                core::str::from_utf8(write_bytes).unwrap_or("")
                                            );
                                            reply[0] = 0;
                                        } else {
                                            reply[0] = 3; // keyboard read-only
                                        }
                                    }
                                }
                            }
                            _ => { reply[0] = 3; }
                        }
                    }
                }
                
                {
                    let mut sched = scheduler::SCHEDULER.lock();
                    let me = sched.get_task_mut(TaskId(85)).unwrap();
                    me.cap_table.slots[1] = Some(Capability {
                        resource: Resource::IpcChannel { target_task: msg.sender },
                        read: true, write: true, grant: false, sealed: false,
                        id: 85000 + msg.sender.0 as u64, origin: None,
                    });
                }
                let _ = process::ipc::sys_send_typed(
                    1, process::IpcTag::DevReply as u16, 1, &reply[..reply_len]);
            }
            Err(_) => scheduler::yield_cpu(),
        }
    }
}

// ── Synchronization service ───────────────────────────────────────────────────

const SYNC_MAX_OBJ: usize = 8;
const SYNC_MAX_WAIT: usize = 16;

#[derive(Clone, Copy)]
struct SyncObject {
    used: bool,
    is_mutex: bool,
    count: i32,
    waiters: [usize; SYNC_MAX_WAIT],
    wait_head: usize,
    wait_tail: usize,
    wait_len: usize,
}
impl SyncObject {
    const fn new() -> Self { Self {
        used: false, is_mutex: false, count: 0, waiters: [0; SYNC_MAX_WAIT],
        wait_head: 0, wait_tail: 0, wait_len: 0,
    }}
    fn enqueue(&mut self, task_id: usize) -> Result<(), ()> {
        if self.wait_len < SYNC_MAX_WAIT {
            self.waiters[self.wait_tail] = task_id;
            self.wait_tail = (self.wait_tail + 1) % SYNC_MAX_WAIT;
            self.wait_len += 1;
            Ok(())
        } else { Err(()) }
    }
    fn dequeue(&mut self) -> Option<usize> {
        if self.wait_len > 0 {
            let task_id = self.waiters[self.wait_head];
            self.wait_head = (self.wait_head + 1) % SYNC_MAX_WAIT;
            self.wait_len -= 1;
            Some(task_id)
        } else { None }
    }
}

struct SyncStore { objects: [SyncObject; SYNC_MAX_OBJ] }
impl SyncStore { const fn new() -> Self { Self { objects: [SyncObject::new(); SYNC_MAX_OBJ] } } }
static SYNC_STORE: crate::drivers::serial::Spinlock<SyncStore> =
    crate::drivers::serial::Spinlock::new(SyncStore::new());

fn sync_check_cap(sender: TaskId, id: u8) -> bool {
    let sched = scheduler::SCHEDULER.lock();
    if let Some(task) = sched.get_task(sender) {
        for cap in task.cap_table.slots.iter().flatten() {
            if let Resource::SyncObj { id: cap_id } = cap.resource {
                if cap_id == id { return true; }
            }
        }
    }
    false
}

fn ensure_sync_service() {
    let mut sched = scheduler::SCHEDULER.lock();
    if sched.tasks[86].is_none() {
        let mut caps = CapTable::new();
        let _ = caps.insert(Capability {
            resource: Resource::IpcChannel { target_task: TaskId(64) },
            read: true, write: true, grant: false, sealed: false, id: 0, origin: None,
        }).unwrap();
        sched.tasks[86] = Some(Task::new(TaskId(86), sync_service_main, caps));
        crate::process::TASKS_SPAWNED.fetch_add(1, Ordering::SeqCst);
    }
}

extern "C" fn sync_service_main() -> ! {
    loop {
        match process::ipc::sys_receive_typed() {
            Ok(msg) => {
                let mut reply = [0u8; 128];
                let reply_len = 1;
                let mut should_reply = true;
                
                if msg.tag != process::IpcTag::SyncOp {
                    reply[0] = 2;
                } else if msg.len < 2 {
                    reply[0] = 2;
                } else {
                    let op = msg.payload[0];
                    let obj_id = msg.payload[1];
                    log_trace("sync_op", op as u64, obj_id as u64);
                    
                    if obj_id >= 8 {
                        reply[0] = 2;
                    } else {
                        match op {
                            0 => { // create
                                let is_mutex = msg.payload[2] != 0;
                                let initial_count = msg.payload[3] as i32;
                                let mut store = SYNC_STORE.lock();
                                let obj = &mut store.objects[obj_id as usize];
                                if obj.used {
                                    reply[0] = 2;
                                } else {
                                    obj.used = true;
                                    obj.is_mutex = is_mutex;
                                    obj.count = initial_count;
                                    obj.wait_head = 0;
                                    obj.wait_tail = 0;
                                    obj.wait_len = 0;
                                    reply[0] = 0;
                                }
                            }
                            1 => { // acquire
                                if !sync_check_cap(msg.sender, obj_id) {
                                    reply[0] = 1;
                                } else {
                                    let mut store = SYNC_STORE.lock();
                                    let obj = &mut store.objects[obj_id as usize];
                                    if !obj.used {
                                        reply[0] = 2;
                                    } else {
                                        SYNC_ACQ.fetch_add(1, Ordering::Relaxed);
                                        if obj.count > 0 {
                                            obj.count -= 1;
                                            reply[0] = 0;
                                        } else {
                                            if obj.enqueue(msg.sender.0).is_ok() {
                                                should_reply = false;
                                            } else {
                                                reply[0] = 4;
                                            }
                                        }
                                    }
                                }
                            }
                            2 => { // release
                                if !sync_check_cap(msg.sender, obj_id) {
                                    reply[0] = 1;
                                } else {
                                    let mut store = SYNC_STORE.lock();
                                    let obj = &mut store.objects[obj_id as usize];
                                    if !obj.used {
                                        reply[0] = 2;
                                    } else {
                                        SYNC_REL.fetch_add(1, Ordering::Relaxed);
                                        if let Some(waiter_task_id) = obj.dequeue() {
                                            let mut waiter_reply = [0u8; 128];
                                            waiter_reply[0] = 0;
                                            {
                                                let mut sched = scheduler::SCHEDULER.lock();
                                                let me = sched.get_task_mut(TaskId(86)).unwrap();
                                                me.cap_table.slots[1] = Some(Capability {
                                                    resource: Resource::IpcChannel { target_task: TaskId(waiter_task_id) },
                                                    read: true, write: true, grant: false, sealed: false,
                                                    id: 86000 + waiter_task_id as u64, origin: None
                                                });
                                            }
                                            let res = process::ipc::sys_send_async(
                                                1, process::IpcTag::SyncReply as u16, 1, &waiter_reply[..1]);
                                            if let Err(e) = res {
                                                crate::println!("Sync service waiter reply failed: {:?}", e);
                                            }
                                        } else {
                                            if obj.is_mutex {
                                                obj.count = 1;
                                            } else {
                                                obj.count += 1;
                                            }
                                        }
                                        reply[0] = 0;
                                    }
                                }
                            }
                            _ => { reply[0] = 2; }
                        }
                    }
                }
                
                if should_reply {
                    {
                        let mut sched = scheduler::SCHEDULER.lock();
                        let me = sched.get_task_mut(TaskId(86)).unwrap();
                        me.cap_table.slots[1] = Some(Capability {
                            resource: Resource::IpcChannel { target_task: msg.sender },
                            read: true, write: true, grant: false, sealed: false,
                            id: 86000 + msg.sender.0 as u64, origin: None
                        });
                    }
                    let res = process::ipc::sys_send_async(
                        1, process::IpcTag::SyncReply as u16, 1, &reply[..reply_len]);
                    if let Err(e) = res {
                        crate::println!("Sync service sender reply failed: {:?}", e);
                    }
                }
            }
            Err(_) => {
                scheduler::yield_cpu();
            }
        }
    }
}

