use crate::shell::TraceEvent;

pub struct CacheConfig {
    pub assoc: usize,
    pub num_lines: usize,
    pub line_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    pub accesses: u64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

#[derive(Clone, Copy)]
struct SimCacheLine {
    valid: bool,
    tag: u64,
    lru: u64,
}

pub fn simulate_cache(cfg: &CacheConfig, addrs: &[u64]) -> CacheStats {
    let mut stats = CacheStats { accesses: 0, hits: 0, misses: 0, evictions: 0 };
    if cfg.assoc == 0 || cfg.num_lines == 0 || cfg.assoc > cfg.num_lines {
        return stats;
    }
    
    let num_sets = cfg.num_lines / cfg.assoc;
    if num_sets == 0 {
        return stats;
    }
    
    let num_lines = core::cmp::min(cfg.num_lines, 1024);
    let mut cache = [SimCacheLine { valid: false, tag: 0, lru: 0 }; 1024];
    
    let mut lru_counter = 0u64;
    
    for &addr in addrs {
        stats.accesses += 1;
        lru_counter += 1;
        
        let line_addr = addr / (cfg.line_bytes as u64);
        let set_idx = (line_addr % (num_sets as u64)) as usize;
        let tag = line_addr / (num_sets as u64);
        
        let set_start = set_idx * cfg.assoc;
        let set_end = set_start + cfg.assoc;
        let mut hit = false;
        
        for idx in set_start..set_end {
            if idx < num_lines && cache[idx].valid && cache[idx].tag == tag {
                cache[idx].lru = lru_counter;
                stats.hits += 1;
                hit = true;
                break;
            }
        }
        
        if !hit {
            stats.misses += 1;
            let mut lru_idx = set_start;
            let mut min_lru = u64::MAX;
            let mut empty_idx = None;
            
            for idx in set_start..set_end {
                if idx < num_lines {
                    if !cache[idx].valid {
                        empty_idx = Some(idx);
                        break;
                    } else if cache[idx].lru < min_lru {
                        min_lru = cache[idx].lru;
                        lru_idx = idx;
                    }
                }
            }
            
            if let Some(idx) = empty_idx {
                if idx < num_lines {
                    cache[idx].valid = true;
                    cache[idx].tag = tag;
                    cache[idx].lru = lru_counter;
                }
            } else if lru_idx < num_lines {
                cache[lru_idx].tag = tag;
                cache[lru_idx].lru = lru_counter;
                stats.evictions += 1;
            }
        }
    }
    stats
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstrKind { Alu, Load, Store, Branch }

#[derive(Clone, Copy, Debug)]
pub struct SimInstr {
    pub kind: InstrKind,
    pub rd: u8,
    pub rs1: u8,
    pub rs2: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct PipeStats {
    pub instrs: u64,
    pub cycles: u64,
    pub stalls: u64,
}

pub fn simulate_pipeline(prog: &[SimInstr]) -> PipeStats {
    let mut stats = PipeStats { instrs: 0, cycles: 0, stalls: 0 };
    if prog.is_empty() {
        return stats;
    }
    
    let mut if_stage: Option<SimInstr> = None;
    let mut id_stage: Option<SimInstr> = None;
    let mut ex_stage: Option<SimInstr> = None;
    let mut mem_stage: Option<SimInstr> = None;
    
    let mut pc = 0;
    
    while pc < prog.len() || if_stage.is_some() || id_stage.is_some() || ex_stage.is_some() || mem_stage.is_some() {
        stats.cycles += 1;
        
        if let Some(_instr) = mem_stage {
            stats.instrs += 1;
        }
        
        mem_stage = ex_stage;
        ex_stage = None;
        
        let mut stall = false;
        if let Some(id_instr) = id_stage {
            let mut raw_hazard = false;
            
            if let Some(ex_instr) = ex_stage {
                if ex_instr.rd != 0 && (ex_instr.rd == id_instr.rs1 || ex_instr.rd == id_instr.rs2) {
                    raw_hazard = true;
                }
            }
            if let Some(mem_instr) = mem_stage {
                if mem_instr.rd != 0 && (mem_instr.rd == id_instr.rs1 || mem_instr.rd == id_instr.rs2) {
                    raw_hazard = true;
                }
            }
            
            if raw_hazard {
                stall = true;
                stats.stalls += 1;
            } else {
                ex_stage = Some(id_instr);
                id_stage = None;
            }
        }
        
        if !stall {
            id_stage = if_stage;
            if_stage = None;
            
            if pc < prog.len() {
                if_stage = Some(prog[pc]);
                pc += 1;
            }
        }
    }
    
    stats
}

pub fn hash_event_to_addr(event: &TraceEvent) -> u64 {
    let mut h = 0u64;
    for &b in event.msg.as_bytes() {
        h = h.wrapping_add(b as u64);
    }
    h = h.wrapping_add(event.param1).wrapping_add(event.param2);
    let line_idx = h % 12; // working set of 12 cache lines
    line_idx * 64
}

pub fn event_to_instr(event: &TraceEvent) -> SimInstr {
    let mut h = 0xcbf29ce484222325u64;
    for &b in event.msg.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3u64);
    }
    h ^= event.param1;
    h = h.wrapping_mul(0x100000001b3u64);
    h ^= event.param2;
    h = h.wrapping_mul(0x100000001b3u64);

    let kind = match event.msg {
        "sched_switch_yield" | "sched_switch_preempt" | "sched_switch_term" => InstrKind::Branch,
        "ipc_send" | "ipc_send_async" => InstrKind::Store,
        "ipc_receive" | "ipc_receive_async" => InstrKind::Load,
        _ => InstrKind::Alu,
    };
    
    // Use 1..=8 registers to ensure hazard stalls are generated realistically
    let rd = ((h & 7) + 1) as u8;
    let rs1 = (((h >> 3) & 7) + 1) as u8;
    let rs2 = (((h >> 6) & 7) + 1) as u8;
    
    SimInstr { kind, rd, rs1, rs2 }
}
