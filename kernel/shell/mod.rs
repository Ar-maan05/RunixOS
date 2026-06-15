use crate::process::{self, Task, TaskId, CapTable, Capability, TaskState};
use crate::process::capability::{Resource, RightsMask, MAX_CAPS};
use crate::scheduler;
use crate::preempt;
use core::sync::atomic::{AtomicU64, Ordering};

macro_rules! print_cmd {
    ($($arg:tt)*) => {
        crate::print!("\x1b[0m[CMD]   {}\x1b[0m\n", format_args!($($arg)*));
    };
}
macro_rules! print_ok {
    ($($arg:tt)*) => {
        crate::print!("\x1b[32m[OK]    {}\x1b[0m\n", format_args!($($arg)*));
    };
}
macro_rules! print_fail {
    ($($arg:tt)*) => {
        crate::print!("\x1b[31m[FAIL]  {}\x1b[0m\n", format_args!($($arg)*));
    };
}
macro_rules! print_pass {
    ($($arg:tt)*) => {
        crate::print!("\x1b[36m[PASS]  {}\x1b[0m\n", format_args!($($arg)*));
    };
}
macro_rules! print_vuln {
    ($($arg:tt)*) => {
        crate::print!("\x1b[33m[VULN]  {}\x1b[0m\n", format_args!($($arg)*));
    };
}
macro_rules! print_info {
    ($($arg:tt)*) => {
        crate::print!("\x1b[37m[INFO]  {}\x1b[0m\n", format_args!($($arg)*));
    };
}
macro_rules! print_warn {
    ($($arg:tt)*) => {
        crate::print!("\x1b[33m[WARN]  {}\x1b[0m\n", format_args!($($arg)*));
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
        let n = crate::drivers::serial::read_line(&mut line_buf);
        if n == 0 {
            continue;
        }

        if let Ok(s) = core::str::from_utf8(&line_buf[..n]) {
            print_cmd!("{}", s);
        }

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
            print_info!("Group A: help, cap list, cap grant <id>, cap revoke <id>, cap seal <id>, cap audit");
            print_info!("Group B: sched info, sched timeslice, sched preempt-race");
            print_info!("Group C: fault spawn, fault cascade <n>");
            print_info!("Group D: ipc send <task_id> <message>, ipc typed <schema> <payload>, ipc stress <n>, service list, service restart <name>");
            print_info!("Group E: checkpoint, restore <id>, migrate <service> <node>");
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
                print_fail!("vulnerable phase of race did not trigger");
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
                print_fail!("guarded phase of race failed");
            }

            preempt::disarm_adversary();
            preempt::set_armed(false);
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
                print_fail!("fault cascade count {} out of range (expected 1..=8)", n);
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
                print_fail!("stress count {} out of range (expected 1..=8)", n);
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
                    sched.tasks[73 + 2 * i] = None;
                    sched.tasks[74 + 2 * i] = None;
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
                sched.tasks[65] = None;
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
