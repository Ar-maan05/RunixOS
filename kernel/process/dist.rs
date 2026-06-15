// RunixOS distribution substrate -- Phase 10 (Parts 4-8)
//
// This layer demonstrates network-transparent IPC, distributed capabilities,
// and service migration *at the architecture level*. The programming model is
// the spec's invariant: a client always does "send to a capability"; whether the
// target service is local or on another node -- and whether it just migrated -- is
// invisible to the client.
//
// HONEST BOUNDARY: there is no physical NIC in this build. A "remote node" is a
// logical domain inside the same kernel image, and the `Transport` is an
// in-memory queue. The `Transport` is written as a narrow interface (serialize a
// message + hand it to a node) precisely so a real virtio-net/e1000 backend
// could later implement it without changing the routing, capability, or
// migration logic above it. What is demonstrated here is the routing/migration
// machinery and programming-model invariance -- not wire I/O.
//
// Mapping to OS_PLAN Phase 10:
//   Part 4 network-transparent IPC : `route_send` resolves a ServiceId to a
//                                     Location and delivers locally or via the
//                                     transport; callers never branch on it.
//   Part 5 distributed capabilities: a capability carries `Resource::Service{id}`
//                                     (a service id, not a machine address);
//                                     `origin`/`id` lineage still applies.
//   Part 6 service migration        : `migrate` moves a service's checkpoint to a
//                                     remote node and re-points the route; the
//                                     client's capability stays valid.
//   Part 7 persistent migration     : migration carries the service's serialized
//                                     state (a `TaskCheckpoint`) and restores it
//                                     on the destination.
//   Part 8 distributed fault toler. : `failover` re-binds a service's route to a
//                                     restored replica after a node "fails".

use crate::process::TaskId;
use crate::process::capability::{CapTable, Capability, Resource};
use crate::process::ipc::{Message, MessageQueue, IpcTag};
use crate::process::snapshot::TaskCheckpoint;
use crate::drivers::serial::Spinlock;

/// Identifies a node in the (simulated) distributed system. Node 0 is the local
/// kernel; higher ids are remote domains reached over the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeId(pub usize);

/// A location-independent service identity. Capabilities reference this, not a
/// task or a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceId(pub usize);

pub const LOCAL_NODE: NodeId = NodeId(0);

/// Where a service currently lives. Migration mutates this; the capability that
/// names the `ServiceId` is unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    /// Served by a local task on this node.
    Local(TaskId),
    /// Served on a remote node, reached via the transport.
    Remote(NodeId),
}

const MAX_SERVICES: usize = 16;
const REMOTE_INBOX_CAP: usize = 16;

/// The routing table: `ServiceId -> Location`. The single piece of state the
/// distribution layer consults on every send; updated atomically on migration.
struct ServiceRegistry {
    entries: [Option<(ServiceId, Location)>; MAX_SERVICES],
}

impl ServiceRegistry {
    const fn new() -> Self {
        Self { entries: [None; MAX_SERVICES] }
    }

    fn resolve(&self, svc: ServiceId) -> Option<Location> {
        self.entries
            .iter()
            .flatten()
            .find(|(s, _)| *s == svc)
            .map(|(_, loc)| *loc)
    }

    fn set(&mut self, svc: ServiceId, loc: Location) {
        for e in self.entries.iter_mut() {
            if let Some((s, l)) = e {
                if *s == svc {
                    *l = loc;
                    return;
                }
            }
        }
        for e in self.entries.iter_mut() {
            if e.is_none() {
                *e = Some((svc, loc));
                return;
            }
        }
    }
}

/// A simulated remote node: an inbox of messages delivered "over the wire" plus
/// the checkpoints of services that have migrated here. A real implementation
/// would replace the inbox with NIC RX and run these services as live tasks.
struct RemoteNode {
    id: NodeId,
    inbox: MessageQueue,
    services: [Option<(ServiceId, TaskCheckpoint)>; MAX_SERVICES],
    delivered: usize,
}

impl RemoteNode {
    const fn new(id: NodeId) -> Self {
        Self {
            id,
            inbox: MessageQueue::new(),
            services: [None; MAX_SERVICES],
            delivered: 0,
        }
    }

    fn host(&mut self, svc: ServiceId, cp: TaskCheckpoint) {
        for e in self.services.iter_mut() {
            if e.is_none() {
                *e = Some((svc, cp));
                return;
            }
        }
    }

    fn caps_of(&self, svc: ServiceId) -> Option<usize> {
        self.services
            .iter()
            .flatten()
            .find(|(s, _)| *s == svc)
            .map(|(_, cp)| count_caps(&cp.cap_table))
    }
}

fn count_caps(t: &CapTable) -> usize {
    t.slots.iter().flatten().count()
}

static REGISTRY: Spinlock<ServiceRegistry> = Spinlock::new(ServiceRegistry::new());
static REMOTE: Spinlock<RemoteNode> = Spinlock::new(RemoteNode::new(NodeId(1)));

/// Outcome of a transparent send -- reported only for the demo; a real client
/// never inspects this (the point is it does not need to).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Routed {
    Local(TaskId),
    Remote(NodeId),
    Unknown,
}

/// Registers a service at a location.
pub fn register(svc: ServiceId, loc: Location) {
    REGISTRY.lock().set(svc, loc);
}

/// Network-transparent send (Part 4). Resolves the capability's `ServiceId` to
/// its current `Location` and delivers either to the local task or across the
/// transport to the hosting node. The caller passes a capability and a payload --
/// identical whether the service is local, remote, or just migrated.
pub fn route_send(cap: &Capability, payload: &[u8]) -> Routed {
    let svc = match cap.resource {
        Resource::Service { id } => ServiceId(id),
        _ => return Routed::Unknown,
    };

    let loc = match REGISTRY.lock().resolve(svc) {
        Some(l) => l,
        None => return Routed::Unknown,
    };

    let mut msg_payload = [0u8; 128];
    let n = core::cmp::min(payload.len(), 128);
    msg_payload[..n].copy_from_slice(&payload[..n]);
    let msg = Message {
        sender: crate::scheduler::current_task_id().unwrap_or(TaskId(usize::MAX)),
        tag: IpcTag::Raw,
        version: 1,
        payload: msg_payload,
        len: n,
    };

    match loc {
        Location::Local(tid) => {
            let mut sched = crate::scheduler::SCHEDULER.lock();
            if let Some(t) = sched.get_task_mut(tid) {
                let _ = t.msg_queue.enqueue(msg);
            }
            Routed::Local(tid)
        }
        Location::Remote(node) => {
            // Hand to the transport (here: the remote node's inbox).
            transport_send(node, msg);
            Routed::Remote(node)
        }
    }
}

/// The transport boundary. A real backend would serialize `msg` and DMA it to a
/// NIC TX ring addressed to `node`; here it enqueues into the simulated remote
/// node's inbox.
fn transport_send(node: NodeId, msg: Message) {
    let mut remote = REMOTE.lock();
    if remote.id == node {
        let _ = remote.inbox.enqueue(msg);
    }
}

/// Migrates a service from its local task to a remote node (Parts 6 & 7).
///
/// 1. Checkpoint the local task's serializable state (capabilities + IPC + meta).
/// 2. Transfer the checkpoint to the destination node and restore it there.
/// 3. Re-point the route to `Remote(dest)` -- atomically, so the next send goes
///    over the transport without the client's capability changing.
/// 4. Tear down the local task instance.
///
/// Returns the number of capabilities carried across, or `Err(())`.
pub fn migrate(svc: ServiceId, dest: NodeId) -> Result<usize, ()> {
    // 1. Checkpoint the local task backing this service.
    let local_tid = match REGISTRY.lock().resolve(svc) {
        Some(Location::Local(tid)) => tid,
        _ => return Err(()),
    };

    let checkpoint = {
        let sched = crate::scheduler::SCHEDULER.lock();
        let t = sched.get_task(local_tid).ok_or(())?;
        TaskCheckpoint {
            id: t.id,
            state: t.state,
            cap_table: t.cap_table,
            ipc_buffer: t.ipc_buffer,
            msg_queue: t.msg_queue,
        }
    };
    let caps = count_caps(&checkpoint.cap_table);

    // 2. Transfer + restore on the destination node.
    REMOTE.lock().host(svc, checkpoint);

    // 3. Re-point the route. The capability that names `svc` is untouched.
    REGISTRY.lock().set(svc, Location::Remote(dest));

    // 4. Tear down the local instance.
    {
        let mut sched = crate::scheduler::SCHEDULER.lock();
        sched.tasks[local_tid.0] = None;
    }

    Ok(caps)
}

/// Drains the simulated remote node's inbox -- the "remote kernel" delivering
/// queued transport messages to the migrated service. Returns how many it
/// processed; prints each so the demo can show they arrived on the other node.
pub fn pump_remote() -> usize {
    let mut remote = REMOTE.lock();
    let mut count = 0;
    while let Some(msg) = remote.inbox.dequeue() {
        let text = core::str::from_utf8(&msg.payload[..msg.len]).unwrap_or("<binary>");
        crate::println!("  node1/transport received: \"{}\"", text);
        remote.delivered += 1;
        count += 1;
    }
    count
}

/// Distributed fault tolerance (Part 8): the hosting node has failed; re-bind the
/// service's route to a restored local replica built from the migrated
/// checkpoint, so capability holders keep working. Returns the replica's
/// capability count.
pub fn failover(svc: ServiceId, replica_tid: TaskId) -> Result<usize, ()> {
    // Recover the last checkpoint held for this service on the (failed) node.
    let cp = {
        let remote = REMOTE.lock();
        remote
            .services
            .iter()
            .flatten()
            .find(|(s, _)| *s == svc)
            .map(|(_, cp)| *cp)
            .ok_or(())?
    };
    let caps = count_caps(&cp.cap_table);

    // Restore the replica's capability state onto a local task and re-bind.
    {
        let mut sched = crate::scheduler::SCHEDULER.lock();
        if let Some(t) = sched.get_task_mut(replica_tid) {
            t.cap_table = cp.cap_table;
            t.ipc_buffer = cp.ipc_buffer;
            t.msg_queue = cp.msg_queue;
        } else {
            return Err(());
        }
    }
    REGISTRY.lock().set(svc, Location::Local(replica_tid));
    Ok(caps)
}

/// Phase 10 Parts 4-8 demonstration. Registers a service locally, shows
/// transparent local delivery, migrates it to a remote node, shows the SAME
/// capability now routing transparently over the transport, proves state was
/// carried across, then fails the node over to a local replica.
///
/// `backing` is a scratch local task that stands in as the service instance, and
/// `replica` is a scratch local task used for failover. Neither needs to run.
pub fn demo(service_id: usize, backing: TaskId, replica: TaskId) {
    let svc = ServiceId(service_id);

    crate::println!("[dist] Phase 10 Parts 4-8: transparent IPC, migration, failover.");
    crate::println!("[dist]   (nodes are simulated logical domains; transport is in-kernel)");

    // The client holds a capability that names the SERVICE, not a machine.
    let client_cap = Capability {
        resource: Resource::Service { id: service_id },
        read: true,
        write: true,
        grant: false,
        sealed: false,
        id: 0,
        origin: None,
    };

    // Register the service as local, backed by `backing`.
    register(svc, Location::Local(backing));
    crate::println!("[dist] service #{} registered as Local(task {}).", service_id, backing.0);

    // Transparent sends while local.
    for m in ["alpha", "beta"] {
        match route_send(&client_cap, m.as_bytes()) {
            Routed::Local(t) => { crate::println!("[dist] client send \"{}\" -> LOCAL delivery (task {}).", m, t.0); }
            other => { crate::println!("[dist] client send \"{}\" -> unexpected {:?}.", m, other); }
        }
    }

    // Migrate to node 1 (checkpoint + transfer + restore + re-point route).
    crate::println!("[dist] migrating service #{}: node 0 -> node 1 ...", service_id);
    let migrated_caps = match migrate(svc, NodeId(1)) {
        Ok(c) => c,
        Err(()) => { crate::println!("[dist] FAIL: migration failed."); return; }
    };
    let remote_caps = REMOTE.lock().caps_of(svc).unwrap_or(usize::MAX);
    crate::println!(
        "[dist]   checkpoint transferred: {} cap(s) carried; restored on node 1 ({} cap(s) present).",
        migrated_caps, remote_caps
    );

    // Transparent sends AFTER migration -- SAME capability, no client change.
    for m in ["gamma", "delta"] {
        match route_send(&client_cap, m.as_bytes()) {
            Routed::Remote(n) => { crate::println!("[dist] client send \"{}\" -> REMOTE via transport (node {}), client unaware.", m, n.0); }
            other => { crate::println!("[dist] client send \"{}\" -> unexpected {:?}.", m, other); }
        }
    }

    // The remote node processes what the transport delivered.
    crate::println!("[dist] node 1 transport pump:");
    let delivered = pump_remote();

    let migration_ok = migrated_caps == remote_caps && delivered == 2;
    if migration_ok {
        crate::println!(
            "[dist] PASS: capability stable across migration; {} cap(s) preserved; {} msg(s) delivered remotely; client code unchanged.",
            remote_caps, delivered
        );
    } else {
        crate::println!(
            "[dist] FAIL: migrated_caps={} remote_caps={} delivered={}.",
            migrated_caps, remote_caps, delivered
        );
    }

    // Part 8: node 1 fails; re-bind to a local replica from the checkpoint.
    crate::println!("[dist] Part 8: simulating node 1 failure -> failover re-bind ...");
    match failover(svc, replica) {
        Ok(c) => {
            // Prove the same capability now routes locally again.
            let routed = route_send(&client_cap, b"epsilon");
            if let Routed::Local(t) = routed {
                crate::println!(
                    "[dist] PASS: failover re-bound service #{} to local replica (task {}, {} cap(s)); capability still valid.",
                    service_id, t.0, c
                );
            } else {
                crate::println!("[dist] FAIL: post-failover routing = {:?}.", routed);
            }
        }
        Err(()) => { crate::println!("[dist] FAIL: failover could not restore replica."); }
    }
}
