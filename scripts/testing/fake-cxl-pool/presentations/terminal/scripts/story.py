#!/usr/bin/env python3
"""The story: CXL memory from a pool, with Kubernetes DRA.

    python3 story.py              render every frame into ../rendered/
    python3 story.py --check      render in memory and verify every frame
    python3 story.py --help       all options

Every frame is a call to s.frame(); everything before it (entities, states, messages, caption)
is what that frame shows. Inserting a frame means inserting such a block: numbering, the
message sequence and the file names follow on the next run. Facts come from the e2e tests
test10-13 of n4-cxl-shared-2 and their recorded traces; see PLAN.md.
"""

import sys

sys.dont_write_bytecode = True   # no __pycache__ next to the scripts

import layouts as L               # noqa: E402
from stageplay import Stage       # noqa: E402

TITLE = "CXL memory from a pool, with Kubernetes DRA"
# TEXT in the boxes stands for the tagged string that a test writes into CXL memory, in test13:
# 'dra-one-writer <timestamp>: written by the exclusive writer'

s = Stage(TITLE, L.SINGLE, short_title="CXL memory pool + Kubernetes DRA")

POOL_DEV = {
    "shared0": "shared0  serial 0xc1ae0001  256M  shared   ",
    "pooled0": "pooled0  serial 0xc1ee0001  512M  exclusive",
}


def dev(name, state):
    """One device line of the pool manager: fixed columns, so that only the state animates."""
    return f"{POOL_DEV[name]}  {state}"


def api(**rows):
    """Change rows of the Kubernetes API box; each row starts with the kind of object it lists."""
    s.set("api", **{kind: f"{kind}: {text}" for kind, text in rows.items()})


def pool(shared0=None, pooled0=None):
    """Change the state of one or both pool devices."""
    rows = {}
    if shared0 is not None:
        rows["shared0"] = dev("shared0", shared0)
    if pooled0 is not None:
        rows["pooled0"] = dev("pooled0", pooled0)
    s.set("pool", **rows)


# =============================================================================== chapter 0
s.chapter(0, "Title and cast", "title and cast", heading=TITLE, body=[
    "Pods that claim memory from a CXL memory pool:",
    "  - as a NUMA node, or as a DAX device (/dev/daxX.Y) that programs map,",
    "  - when the pod starts (a ResourceClaim), or while it already runs (a lease),",
    "  - for one node at a time, or shared by several nodes, read-write or read-only.",
    "",
    "How to read the frames",
    "  The picture on top keeps every component in its place. ★ marks what is new or changed in this frame.",
    "  The arrow is this frame's message; its number (n) is its row in the MESSAGE SEQUENCE below the picture,",
    "  which grows frame by frame and starts over in each chapter. Names in parentheses are the real",
    "  component names of the e2e tests these frames follow.",
    "",
    "  In less:  :n next frame   :p previous frame   j / k scroll down to the sequence   G its newest rows",
], source="Sources: nri-plugins e2e tests n4-cxl-shared-2/test10-13 and their recorded traces")

s.entity("pool", "pool", "Memory pool manager",
         "fake-cxl-pool-server on the host, REST API :9909; hot-plugs cxl-type3 devices into the qemu VMs over QMP",
         dev("shared0", "free"), dev("pooled0", "free"), name="Pool manager", rows=("shared0", "pooled0"))
s.caption("A CXL memory pool is a box of memory cabled to many servers; its manager attaches a device to a server",
          "and detaches it again. Here a fake one hot-plugs devices into qemu VMs. pooled0 is for one node at a",
          "time; shared0 can be attached to several nodes at once, and they all see the same bytes.")
s.frame("cast-pool", "the memory pool")

s.entity("hw_b", "hw_b", "CXL memory seen by the node", "/sys/bus/cxl: memN regionN daxX.Y, NUMA nodes",
         "no CXL memory devices; auto_online_blocks = offline: the kernel never onlines CXL memory by itself",
         name="CXL memory (node-b)")
s.caption("What one node sees: a hot-plugged device appears as memN, with the device's serial number. Software",
          "on the node turns it into a region, and then either into system RAM (a new NUMA node, used like DRAM)",
          "or into a /dev/daxX.Y device that programs map.")
s.frame("cast-node-hw", "what a node sees")

s.entity("sched", "sched", "Scheduler", "kube-scheduler", "idle", name="Scheduler")
s.entity("api", "api", "Kubernetes API + objects", "kube-apiserver: slices, claims, pods",
         "slices: no CXL offers yet", "claims: none", "pods: none", rows=("slices", "claims", "pods"),
         name="Kubernetes API")
s.entity("ctrl", "ctrl", "Pool controller", "fake-cxl-pool-controller", "connected to the pool",
         "(2 devices)", name="Pool controller")
s.caption("Kubernetes words used here: a ResourceSlice is an offer list of devices, a DeviceClass a kind of device,",
          "a ResourceClaim a request for a device (and, once allocated, what was granted), a Pod the workload. The",
          "scheduler picks devices and nodes; the pool controller is the pool's agent in the cluster.")
s.frame("cast-cluster", "the cluster-wide parts")

s.entity("runner_b", "runner_b", "Pod runner", ("kubelet + containerd", "kubelet"), "runs the pods of node-b",
         name="Pod runner (node-b)")
s.entity("agent_b", "agent_b", "Node's CXL agent", "kubelet-cxl-plugin",
         "DRA plugins: cxl.generic (node memory), cxl-pool.generic (pool devices)",
         "NRI plugin (changes running containers), lease broker (container requests)",
         name="CXL agent (node-b)")
s.caption("The Pod runner (kubelet with containerd) starts the pods of its node. Next to it runs one CXL agent per",
          "node: it prepares claims for kubelet (DRA plugins), publishes the node's own memory, changes running",
          "containers through NRI (containerd's plugin interface), and answers requests from containers.")
s.frame("cast-node-sw", "the node's software")

s.entity("demo", "b1", "demo / app", "a container of a pod", "env, /dev/daxX.Y, NUMA nodes",
         "cxl-request, if it opts in", name="demo/app")
s.caption("Inside a container (double lines). The workload never talks to the pool: it gets environment variables,",
          "a device node, or more NUMA nodes in its cpuset.mems. A container that opted in with a token claim can",
          "also ask for memory itself, with the cxl-request command.")
s.frame("cast-container", "the workload")

s.caption("Where things run: at the top anywhere in the cluster (one of each per cluster); in the middle one node,",
          "its containers in double lines; at the bottom the pool's manager, outside the cluster (here on the VM",
          "host). A second node, node-a, joins in chapter 4.")
s.frame("cast-zones", "where things run")

s.card("cast-recap", "Cast and chapters", [
    "Cast (box title = what it does; in parentheses = what it is called in the code)",
    "  Memory pool manager          fake-cxl-pool-server: owns the devices, hot-plugs them into nodes",
    "  Pool controller              fake-cxl-pool-controller: the cluster side of DRA driver cxl-pool.generic",
    "  Kubernetes API + objects     kube-apiserver: ResourceSlices, DeviceClasses, ResourceClaims, Pods",
    "  Scheduler                    kube-scheduler: picks a device and a node for every claim of a pod",
    "  Pod runner                   kubelet + containerd: prepares the claims of a pod, starts its containers",
    "  Node's CXL agent             kubelet-cxl-plugin: DRA plugins, NRI plugin, lease broker",
    "  CXL memory seen by the node  /sys/bus/cxl: memN, regionN, daxX.Y; NUMA nodes",
    "  <pod> / <container>          a container of a workload pod, for example reader-a / main",
    "  request tool                 cxl-request / cxl-release in the container, socket /run/cxl/cxl.sock",
    "",
    "Chapters",
    "  1  a pod claims pooled memory as a NUMA node                  e2e test10-dra-pooling",
    "  2  the same device as a DAX device                            test13, part H2",
    "  3  memory for a container that is already running            test12-dra-live-attach",
    "  4  sharing: one device, several nodes                         test11-dra-sharing",
    "  5  one exclusive writer, many read-only readers               test13-dra-shared-one-writer-many-readers",
])

# =============================================================================== chapter 1
s.chapter(1, "A pod claims pooled memory as a NUMA node", "NUMA node claim", body=[
    "The usual way: the memory is part of the pod's spec, so it is in place before the pod's containers start.",
    "",
    "  1. offer     the pool controller publishes the pool's devices; the node's agent publishes the node's memory",
    "  2. claim     a ResourceClaim asks for 512Mi of DeviceClass cxl-pool-memory; a Pod uses the claim",
    "  3. attach    the scheduler picks pooled0 and node-b and waits; the controller has the pool attach it",
    "  4. prepare   kubelet asks the node's agent to prepare the claim: region, system RAM, a new NUMA node",
    "  5. use       the container starts with environment variables that name the NUMA node",
    "  6. release   pod deleted: the agent takes the memory offline, then the controller detaches the device",
    "",
    "All of chapters 1-3 happen on one node, node-b.",
], source="Source: e2e test10-dra-pooling and its recorded trace; driver doc/cxl/POOL.md")
s.state("agent_b", "idle")
s.state("runner_b", "idle")
s.settle()

s.send("ctrl", "pool", "GET /api/v1/devices?scope=pool", draw=False)
s.reply("pool", "ctrl", "200: pooled0 512M exclusive free, shared0 256M shared free", draw=False)
s.send("ctrl", "api", "create ResourceSlice (driver cxl-pool.generic, pool fake-cxl-pool, allNodes): pooled0 {serial "
       "0xc1ee0001, shared false, size 536870912, capacity memory 512Mi}, shared0 {serial 0xc1ae0001, shared true, "
       "capacity hosts 4, valid 1 or 4}; every device: bindsToNode, bindingConditions [cxl-pool.generic/Attached]",
       short="create the pool's ResourceSlice: pooled0, shared0")
api(slices="pool (pooled0, shared0)")
s.state("ctrl", "published 2 devices", "watching claims, nodes", "and the pool's events")
s.caption("The controller turns the pool's device list into an offer list. The devices are on no node yet:",
          "bindsToNode plus a binding condition tell the scheduler: pick a node, then wait until I say Attached.")
s.frame("publish-pool", "the pool becomes an offer list")

s.send("agent_b", "api", "publish ResourceSlice (driver cxl.generic, node node-b): dram (NUMA nodes 0-1), dynamic "
       "(the token device: no capacity, any number of claims)", short="publish node-b's ResourceSlice: dram, dynamic")
api(slices="pool (pooled0, shared0), node-b")
s.set("agent_b", l1="published node-b's slice: dram (NUMA nodes 0-1), dynamic (a token device)")
s.caption("The node's agent publishes the node's own memory in a slice of its own; the 'dynamic' token device is",
          "for chapter 3. The scheduler always tries node-local offers first: they need no binding wait.")
s.frame("publish-node", "the node's own offer list")

s.note("kubectl apply: ResourceClaim pooled-memory {deviceClassName cxl-pool-memory, capacity.requests.memory 512Mi} "
       "and Pod pooled-consumer {resourceClaims: pooled -> pooled-memory; container consumer lists the claim}",
       short="kubectl apply: claim pooled-memory, pod pooled-consumer")
api(claims="pooled-memory (512Mi) unallocated", pods="pooled-consumer Pending")
s.caption("DeviceClass cxl-pool-memory = devices of driver cxl-pool.generic with shared == false. The pod names",
          "neither a device nor a node: the scheduler picks both.")
s.frame("claim-and-pod", "a claim and a pod")

s.send("sched", "api", "write claim.status.allocation: device pooled0 (driver cxl-pool.generic, pool fake-cxl-pool), "
       "nodeSelector node-b; pod event BindingConditionsPending", short="allocate pooled0 @ node-b; binding wait")
s.state("sched", "pooled-memory:", "pooled0 @ node-b", "waiting for Attached")
api(claims="pooled-memory -> pooled0 @ node-b", pods="pooled-consumer Pending (binding)")
s.caption("pooled0 is the only exclusive device with 512Mi. The scheduler pins the claim to a node, here node-b,",
          "and then polls the claim until its binding condition Attached is True (for at most 600 s).")
s.frame("scheduler-allocates", "the scheduler picks device and node")

s.send("ctrl", "pool", "POST /api/v1/devices/pooled0/attachments {host: node-b, owner: k8s:resourceclaim/<claim uid>, "
       "wait: true, timeout: 1m0s, exclusive: false}", short="POST attach pooled0 {host: node-b, owner: the claim}")
s.state("ctrl", "attach pooled0 -> node-b", "host = Node's systemUUID", "owner: claim pooled-memory")
pool(pooled0="attaching to node-b")
s.caption("The controller saw the allocation and asks the pool to attach pooled0. It finds the node's pool host by",
          "the Node's systemUUID (the VM's qemu -uuid). The claim owns the attachment.")
s.frame("ctrl-attaches", "the controller asks the pool")

s.send("pool", "hw_b", "hot-plug over QMP: object-add memory-backend-file (id fcp_pooled0.hp1, mem-path pooled0.raw, "
       "share=on) + device_add cxl-type3 (bus cxlsw_ds0_usrp0hb0, serial 0xc1ee0001)",
       short="hot-plug cxl-type3 serial 0xc1ee0001 (fcp_pooled0.hp1)")
s.set("hw_b", l1="mem0  serial 0xc1ee0001  512M  appears (udev: add .../mem0 (cxl))")
pool(pooled0="attached to node-b as qemu device fcp_pooled0.hp1")
s.caption("In a real pool the fabric manager connects the device to the server; here qemu hot-plugs a CXL memory",
          "device into the VM. The node's kernel sees a new memory device, mem0, with the serial.")
s.frame("pool-hot-plugs", "the device arrives in the node")

s.reply("pool", "ctrl", "201 Created: attachment pooled0@node-b attached", draw=False)
s.send("ctrl", "api", "UpdateStatus claim.status.devices[pooled0]: condition cxl-pool.generic/Attached=True 'pooled0 "
       "attached to node-b (slot cxlsw_ds0_usrp0hb0)', data {serial 0xc1ee0001, shared false, size 536870912, host, "
       "hostUUID, attachment, qemuDeviceId, exclusive}; event Attached",
       short="claim status: Attached=True + data {serial, size, ...}")
api(claims="pooled-memory -> pooled0, Attached")
s.state("ctrl", "attached pooled0 -> node-b", "status Attached written", "owner: claim pooled-memory")
s.caption("The claim status now carries exactly what the node will need to find the device: its serial. That was",
          "0.6 s after the claim was created, in the recorded run.")
s.frame("attached-condition", "the claim says Attached")

s.send("sched", "api", "bind pod pooled-consumer to node-b (event Scheduled)", short="bind pooled-consumer -> node-b")
s.state("sched", "idle")
api(pods="pooled-consumer -> node-b, creating")
s.caption("The scheduler's next poll saw Attached and bound the pod, 5.1 s after the claim was created: the poll",
          "interval, not the attach, sets this delay.")
s.frame("scheduler-binds", "the pod gets its node")

s.send("runner_b", "agent_b", "NodePrepareResources(claim pooled-memory) on "
       "/var/lib/kubelet/plugins/cxl-pool.generic/dra.sock", short="NodePrepareResources(pooled-memory)")
s.state("runner_b", "pod pooled-consumer", "preparing its claim")
s.state("agent_b", "cxl-pool.generic: claim pooled-memory -> serial 0xc1ee0001 (its status)",
        "no PoolDeviceConfig: an exclusive device becomes a NUMA node (mode numa)")
s.caption("kubelet prepares a pod's claims before it creates the containers. The agent's pool plugin reads the",
          "serial from the claim status. The claim sets no options: the default of an exclusive device, a NUMA node.")
s.frame("kubelet-prepares", "kubelet asks the node's agent")

s.send("agent_b", "hw_b", "wait for the memdev with serial 0xc1ee0001 (mem0); cxl create-region -t ram -d decoder0.0 "
       "-m mem0; daxctl reconfigure-device --mode=system-ram (driver kmem); online every memory block "
       "online_movable", short="create-region on mem0; kmem; online_movable -> node 2")
s.set("hw_b", l1="mem0 -> region0 -> dax0.0 (kmem) -> NUMA node 2: 512 MB online_movable, no CPUs")
s.state("agent_b", "prepared pooled0 (serial 0xc1ee0001) as mem0, region0, dax0.0: NUMA node 2")
s.caption("Movable, so that the memory can be taken away again later. The node now has a third NUMA node with",
          "512 MB and no CPUs (numactl -H shows it).")
s.frame("agent-region", "a new NUMA node")

s.reply("agent_b", "runner_b", "PrepareResult: CDI device generic/cxl=pool-c1ee0001: env CXL_POOL_NODE_C1EE0001=2, "
        "CXL_POOL_SIZE_C1EE0001=536870912, CXL_POOL_SERIAL_C1EE0001=0xc1ee0001",
        short="CDI pool-c1ee0001: env CXL_POOL_NODE_C1EE0001=2, ...")
s.set("agent_b", l2="claim kept in preparedPoolClaims.json; region0 left out of the node's slice")
s.caption("CDI (Container Device Interface) = edits to the container, here three environment variables. The agent",
          "keeps region0 out of its own slice, so that the same memory is not offered twice.")
s.frame("agent-cdi", "what the container will get")

s.send("runner_b", "consumer", "create and start container consumer; containerd applies the CDI edits",
       short="start container consumer (with the CDI env)")
s.entity("consumer", "b1", "pooled-consumer / consumer", "pod pooled-consumer, node-b",
         "CXL_POOL_NODE_C1EE0001=2", "sees node2: MemTotal 512 MB", name="pooled-consumer/consumer")
api(pods="pooled-consumer Running (6.2 s)")
s.state("runner_b", "pod pooled-consumer", "running")
s.caption("The app uses node 2 with numactl or mbind. Its cpuset.mems is not changed (a container allowed only",
          "movable memory could not even start), so nothing keeps other containers off node 2 yet: an open TODO.")
s.frame("container-runs", "the container runs")

s.note("kubectl delete pod pooled-consumer")
s.send("runner_b", "consumer", "SIGTERM: container consumer stops", draw=False)
s.send("runner_b", "agent_b", "NodeUnprepareResources(claim pooled-memory)", short="NodeUnprepareResources(pooled-memory)")
s.remove("consumer")
s.state("runner_b", "pod pooled-consumer", "terminating: unprepare")
api(pods="pooled-consumer Terminating")
s.caption("kubelet unprepares the claims while the pod terminates, before the pod object is gone.")
s.frame("delete-pod", "the pod is deleted")

s.send("agent_b", "hw_b", "offline memory202-205; cxl disable-region region0; cxl destroy-region region0; "
       "cxl disable-memdev mem0", short="offline; disable + destroy region0; disable mem0")
s.set("hw_b", l1="mem0  serial 0xc1ee0001  512M  disabled: no region, NUMA node 2 gone")
s.state("agent_b", "released mem0 (serial 0xc1ee0001); unprepared claim pooled-memory")
s.state("runner_b", "idle")
api(claims="pooled-memory deallocated", pods="pooled-consumer Completed, gone")
s.caption("Release before detach: the memory is offline and the region destroyed, so the device can leave without",
          "the kernel still using it. No pod reserves the claim any more, so Kubernetes deallocates it.")
s.frame("agent-releases", "the node lets go of the memory")

s.send("ctrl", "pool", "DELETE /api/v1/devices/pooled0/attachments/node-b?wait=true&timeout=1m0s",
       short="DELETE attachment pooled0@node-b", draw=True)
s.send("pool", "hw_b", "hot-remove over QMP: device_del fcp_pooled0.hp1 ... event DEVICE_DELETED (6 s later) ... "
       "object-del", short="hot-remove: device_del ... DEVICE_DELETED", draw=True)
s.note("kubectl delete resourceclaim pooled-memory")
s.set("hw_b", l1="no CXL memory devices")
pool(pooled0="free")
s.state("ctrl", "detached pooled0@node-b", "event Detached", "")
api(claims="none", pods="none")
s.caption("The controller detaches only devices that no allocated claim wants; qemu says DEVICE_DELETED after 6 s.")
s.frame("ctrl-detaches", "back to the pool")

s.card("recap", "Recap: a pod claims pooled memory as a NUMA node", [
    "What happened, and who did it                                            (recorded run: seconds after apply)",
    "",
    "  1. offer     pool controller: one ResourceSlice for the whole pool; node agent: one per node",
    "  2. claim     you: a ResourceClaim (DeviceClass cxl-pool-memory, 512Mi) and a Pod that uses it      0.0",
    "  3. attach    scheduler: pooled0 @ node-b, then it waits for Attached                                0.08",
    "               pool controller + pool manager: hot-plug, then claim status Attached=True              0.6",
    "  4. prepare   scheduler binds the pod at its next poll                                               5.1",
    "               kubelet -> node agent: region, kmem, online_movable: NUMA node 2                       5.6",
    "  5. use       container consumer runs with CXL_POOL_NODE_C1EE0001=2                                  6.2",
    "  6. release   pod deleted: unprepare (offline, destroy region), deallocate, detach    10.3, 10.7, 11.0, 11.5",
    "               qemu reports the device removed (DEVICE_DELETED)                                       17.6",
    "",
    "The pool never learns what the node does with the device; the node never talks to the pool.",
])

# =============================================================================== chapter 2
s.chapter(2, "The same device as a DAX device", "DAX device claim", body=[
    "Options travel in the claim as an opaque config of the driver: PoolDeviceConfig {mode: numa | dax, readOnly}.",
    "The pool and the scheduler ignore it; only the node's agent reads it (a claim's config beats its class's).",
    "",
    "    pool device   claim says                      the container gets",
    "    exclusive     (nothing)                       a NUMA node                                  chapter 1",
    "    exclusive     mode: dax                       a /dev/daxX.Y device of its own              this chapter",
    "    shared        (nothing)                       a /dev/daxX.Y device, shared with others     chapter 4",
    "    shared        capacity.requests.hosts: \"4\"    a /dev/daxX.Y device, nobody else has it     chapter 5",
    "    any dax       readOnly: true                  the dax device, read-only                    chapter 5",
    "",
    "A dax device is memory that the kernel never uses itself: programs map it, and its bytes stay in the device.",
], source="Source: e2e test13 part H2 (it ran on node-a; shown on node-b here); driver doc/cxl/POOL.md")
s.state("agent_b", "idle")
s.state("ctrl", "idle")
s.settle()

s.note("kubectl apply: ResourceClaim pooled-dax {deviceClassName cxl-pool-memory, capacity.requests.memory 512Mi, "
       "config: opaque {driver cxl-pool.generic, parameters {apiVersion cxl-pool.generic/v1alpha1, kind "
       "PoolDeviceConfig, mode: dax}}} and Pod dax-claimer (container main lists the claim)",
       short="kubectl apply: claim pooled-dax, pod dax-claimer")
api(claims="pooled-dax (mode: dax) unallocated", pods="dax-claimer Pending")
s.state("ctrl", "idle")
s.caption("The option is an opaque config of the driver, in the claim (or in its DeviceClass). The pool and the",
          "scheduler ignore it: only the node's agent reads it.")
s.frame("dax-claim", "a claim with an option")

s.send("sched", "api", "allocate pooled0 @ node-b; event BindingConditionsPending", draw=False)
s.send("ctrl", "pool", "POST /api/v1/devices/pooled0/attachments {host: node-b, owner: k8s:resourceclaim/<uid>}",
       short="POST attach pooled0 {host: node-b}", draw=False)
s.send("pool", "hw_b", "hot-plug cxl-type3 serial 0xc1ee0001", draw=True)
s.reply("pool", "ctrl", "201 Created: attached", draw=False)
s.send("ctrl", "api", "claim status: Attached=True, data {serial 0xc1ee0001, shared false, size 536870912, ...}",
       short="claim status: Attached=True + data", draw=False)
s.send("sched", "api", "bind dax-claimer -> node-b", draw=False)
s.send("runner_b", "agent_b", "NodePrepareResources(claim pooled-dax)", draw=False)
s.set("hw_b", l1="mem0  serial 0xc1ee0001  512M  appears (udev: add .../mem0 (cxl))")
pool(pooled0="attached to node-b as qemu device fcp_pooled0.hp1")
api(claims="pooled-dax -> pooled0, Attached", pods="dax-claimer -> node-b, creating")
s.state("ctrl", "attached pooled0 -> node-b", "status Attached written")
s.state("runner_b", "pod dax-claimer", "preparing its claim")
s.state("agent_b", "cxl-pool.generic: claim pooled-dax -> serial 0xc1ee0001, shared false",
        "PoolDeviceConfig in the claim: mode dax")
s.caption("Fast-forward: everything up to here is the same as in chapter 1. The pool does not know how the node",
          "will use the device.")
s.frame("same-as-chapter-1", "fast-forward: attach and prepare")

s.send("agent_b", "hw_b", "cxl create-region -t ram -d decoder0.0 -m mem0; daxctl reconfigure-device --mode=devdax "
       "(driver device_dax); the memory is NEVER onlined", short="create-region; daxctl --mode=devdax -> /dev/dax0.0")
s.set("hw_b", l1="mem0 -> region0 -> /dev/dax0.0 (device_dax, char device 252:0); no NUMA node: online size 0")
s.state("agent_b", "prepared pooled0 (serial 0xc1ee0001, mode dax) as mem0, region0, dax0.0")
s.caption("The same region, another driver: device_dax instead of kmem. The kernel does not use this memory",
          "itself; programs map /dev/dax0.0.")
s.frame("agent-devdax", "a dax device instead of a NUMA node")

s.reply("agent_b", "runner_b", "PrepareResult: CDI device generic/cxl=pool-c1ee0001: deviceNodes [/dev/dax0.0, type c, "
        "252:0], env CXL_POOL_DAX_C1EE0001=/dev/dax0.0, CXL_POOL_SIZE_C1EE0001=536870912, "
        "CXL_POOL_SERIAL_C1EE0001=0xc1ee0001", short="CDI pool-c1ee0001: device node /dev/dax0.0 + env")
s.set("agent_b", l2="CDI: device node /dev/dax0.0, env CXL_POOL_DAX_C1EE0001=/dev/dax0.0, ...")
s.caption("A device node in the container, plus a device cgroup rule that lets the container open it: that is what",
          "a CDI device node means. No CXL_POOL_NODE variable this time.")
s.frame("agent-device-node", "a device node for the container")

s.send("runner_b", "daxer", "create and start container main (with /dev/dax0.0)", short="start container main")
s.entity("daxer", "b1", "dax-claimer / main", "pod dax-claimer, node-b", "/dev/dax0.0 (read-write)",
         "mmap(MAP_SHARED): write, read", name="dax-claimer/main")
api(pods="dax-claimer Running")
s.state("runner_b", "pod dax-claimer", "running")
s.caption("Programs map the device with mmap(MAP_SHARED), 2 MiB aligned. The bytes stay in the device: test13 found,",
          "in such a claim on node-a, the text that a lease on node-b had written into pooled0 just before.")
s.frame("dax-runs", "the container maps the device")

s.caption("The other option, readOnly: true, gives the CDI device pool-<serial>-ro: the same device node with",
          "permissions r, and one more variable, ..._READONLY_<SERIAL>=1. The container's device cgroup then lets it",
          "open the node for reading only, root or not (privileged containers excepted). Chapter 5 uses it.")
s.frame("read-only-option", "the read-only option")

s.note("kubectl delete pod dax-claimer")
s.send("runner_b", "agent_b", "NodeUnprepareResources(claim pooled-dax)", draw=False)
s.send("agent_b", "hw_b", "cxl disable-region region0; cxl destroy-region region0; cxl disable-memdev mem0 "
       "(nothing to offline)", short="disable + destroy region0; disable mem0", draw=False)
s.send("ctrl", "pool", "DELETE /api/v1/devices/pooled0/attachments/node-b?wait=true&timeout=1m0s",
       short="DELETE attachment pooled0@node-b", draw=True)
s.send("pool", "hw_b", "hot-remove: device_del fcp_pooled0.hp1 ... DEVICE_DELETED ... object-del", draw=False)
s.note("kubectl delete resourceclaim pooled-dax")
s.remove("daxer")
s.set("hw_b", l1="no CXL memory devices")
pool(pooled0="free")
api(claims="none", pods="none")
s.state("agent_b", "released mem0 (serial 0xc1ee0001); unprepared claim pooled-dax")
s.state("runner_b", "idle")
s.state("ctrl", "detached pooled0@node-b", "event Detached")
s.caption("The same release chain as in chapter 1: unprepare, deallocate, detach. Nothing to take offline this",
          "time, because nothing was onlined.")
s.frame("dax-release", "fast-forward: release")

# =============================================================================== chapter 3
s.chapter(3, "Memory for a container that is already running", "borrow while running", body=[
    "A pod's claims are fixed when it is created: neither the scheduler nor kubelet add devices to a running pod.",
    "So a running container BORROWS pool memory through the node's CXL agent instead:",
    "",
    "  1. opt in at creation:  claim the token device 'dynamic' (DeviceClass cxl-dynamic): a socket and a CLI appear",
    "  2. ask from inside:     cxl-request memory 512Mi        -> a NUMA node added to this container's cpuset.mems",
    "                          cxl-request shared 0xc1ae0001   -> an open /dev/daxX.Y file descriptor, no device node",
    "  3. give back:           cxl-release <lease>             -> pages move to DRAM, device goes back to the pool",
    "",
    "Behind the scenes the agent creates a companion pod and claim, cxl-lease-<id>, on the container's behalf;",
    "from there on it is chapter 1 again. Lease ids are those of the recorded run.",
], source="Source: e2e test12-dra-live-attach and its recorded trace; driver doc/cxl/POOL.md")
s.state("agent_b", "idle")
s.state("ctrl", "idle")
s.settle()

s.note("kubectl apply: ResourceClaimTemplate cxl-lease-token {deviceClassName cxl-dynamic} and Pod borrower "
       "{resourceClaims: cxl -> template cxl-lease-token; containers main (lists the claim) and idle (does not)}",
       short="kubectl apply: token claim template, pod borrower")
api(claims="borrower's token unallocated", pods="borrower Pending")
s.state("ctrl", "idle")
s.state("agent_b", "published node-b's slice: dram (NUMA nodes 0-1), dynamic (the token device)")
s.caption("The token device 'dynamic' of the node's slice has no capacity, and any number of pods may claim it:",
          "a permission slip to ask for memory later. The template makes one token claim per pod.")
s.frame("token-claim", "opting in: a token claim")

s.send("sched", "api", "allocate dynamic @ node-b (node-local: no binding wait); bind borrower -> node-b",
       short="allocate dynamic @ node-b (no wait); bind borrower", draw=False)
s.send("runner_b", "agent_b", "NodePrepareResources(token claim) [driver cxl.generic]",
       short="NodePrepareResources(token claim)", draw=False)
s.reply("agent_b", "runner_b", "CDI device generic/cxl=lease-<claim uid>: mount "
        "/var/lib/kubelet/plugins/cxl.generic/leases/<claim uid> -> /run/cxl (rbind, rw); mount the static cxl-request "
        "-> /usr/local/bin/cxl-request and cxl-release (ro); env CXL_LEASE_SOCKET=/run/cxl/cxl.sock, CXL_CLAIM_<uid>=1",
        short="CDI lease-<uid>: /run/cxl, cxl-request, CXL_LEASE_SOCKET")
s.set("agent_b", l2="lease broker: listening on leases/<claim uid>/cxl.sock (socket 0666)")
api(claims="borrower's token -> dynamic, node-b", pods="borrower -> node-b, creating")
s.state("runner_b", "pod borrower", "preparing its claim")
s.caption("The agent opens a unix socket per token claim and mounts its directory, not the socket itself, so that",
          "a restarted agent can create the socket again under the running container.")
s.frame("token-prepared", "a socket for the pod")

s.send("runner_b", "main", "start container main (with /run/cxl and cxl-request)", short="start container main",
       draw=True)
s.send("runner_b", "idle", "start container idle (no claim: no CDI edits)", short="start container idle", draw=True)
s.entity("main", "b1", "borrower / main", "pod borrower, node-b", "/run/cxl/cxl.sock + CLI",
         "cpuset.mems unset: all nodes", name="borrower/main")
s.entity("idle", "b2", "borrower / idle", "pod borrower, node-b", "no claim: no socket, no CLI",
         "cpuset.mems unset: all nodes", name="borrower/idle")
api(pods="borrower Running (2.0 s)")
s.state("runner_b", "pod borrower", "running")
s.caption("The pod starts at once: no pool device yet. Only main, which lists the token claim, gets the socket + CLI.")
s.frame("borrower-runs", "a running pod, no CXL memory yet")

s.send("main", "agent_b", "cxl-request memory 512Mi  =  {\"op\":\"lease\",\"kind\":\"memory\",\"size\":\"512Mi\","
       "\"wait\":\"120s\"} on /run/cxl/cxl.sock", short="cxl-request memory 512Mi")
s.state("agent_b", "lease 0c822f6e Creating: stored in leases.json before any API object exists",
        "caller: socket -> token claim -> pod borrower; SO_PEERCRED -> main")
s.set("main", l1="cxl-request memory 512Mi ...")
s.caption("The socket tells which claim, and so which pod, is asking; the kernel tells which process (SO_PEERCRED),",
          "and its cgroup which container. No credentials and no Kubernetes access inside the pod.")
s.frame("request-memory", "a container asks for memory")

s.send("agent_b", "api", "create ResourceClaim cxl-lease-0c822f6e {deviceClassName cxl-pool-memory, memory 512Mi, config "
       "LendConfig {lease 0c822f6e, pod borrower, container main}; ownerReference: pod borrower} and Pod "
       "cxl-lease-0c822f6e {pause:3.10, cpu 100m, memory 8Mi, node affinity node-b, tolerates everything, "
       "resourceClaims: lease -> the claim}", short="create claim + companion pod cxl-lease-0c822f6e")
s.state("agent_b", "lease 0c822f6e Pending: companion claim and pod cxl-lease-0c822f6e created",
        "caller: borrower/main")
api(claims="token; cxl-lease-0c822f6e waiting", pods="borrower; cxl-lease-0c822f6e Pending")
s.caption("A companion pod holds the claim on the container's behalf: pinned to this node, owned by the pod",
          "borrower (garbage-collected with it), a pause container that uses nothing. From here on it is chapter 1.")
s.frame("companion", "a companion pod and claim")

s.send("sched", "api", "allocate pooled0 @ node-b; event BindingConditionsPending", draw=False)
s.send("ctrl", "pool", "POST /api/v1/devices/pooled0/attachments {host: node-b, owner: "
       "k8s:resourceclaim/<companion claim uid>}", short="POST attach pooled0 {host: node-b}", draw=False)
s.send("pool", "hw_b", "hot-plug cxl-type3 serial 0xc1ee0001", draw=True)
s.reply("pool", "ctrl", "201 Created: attached", draw=False)
s.send("ctrl", "api", "claim status: Attached=True, data {serial 0xc1ee0001, ...}", draw=False)
s.send("sched", "api", "bind cxl-lease-0c822f6e -> node-b", draw=False)
s.send("runner_b", "agent_b", "NodePrepareResources(cxl-lease-0c822f6e)", draw=False)
s.set("hw_b", l1="mem0  serial 0xc1ee0001  512M  appears (udev: add .../mem0 (cxl))")
pool(pooled0="attached to node-b, owner: claim cxl-lease-0c822f6e")
s.entity("companion", "b3", "cxl-lease-0c822f6e / pause", "companion pod, node-b", "claim: cxl-lease-0c822f6e",
         "pause:3.10, 100m CPU, 8Mi", name="companion")
api(claims="token; cxl-lease-0c822f6e Attached", pods="borrower; cxl-lease-0c822f6e bound")
s.state("ctrl", "attached pooled0 -> node-b", "status Attached written")
s.state("runner_b", "pod cxl-lease-0c822f6e", "preparing its claim")
s.caption("Fast-forward: the scheduler, the controller and the pool see an ordinary claim. The companion pod is",
          "bound to node-b, so kubelet asks the agent to prepare its claim.")
s.frame("companion-attached", "fast-forward: an ordinary claim")

s.send("agent_b", "hw_b", "cxl create-region; daxctl --mode=system-ram (kmem); online_movable -> NUMA node 2",
       short="create-region; kmem; online_movable -> node 2")
s.set("hw_b", l1="mem0 -> region0 -> dax0.0 (kmem) -> NUMA node 2: 512 MB online_movable, no CPUs")
s.state("agent_b", "lease 0c822f6e Lending: its LendConfig matches lease, pod, container",
        "prepared pooled0 as NUMA node 2 for the companion's claim")
s.state("runner_b", "pod cxl-lease-0c822f6e", "starting pause")
api(pods="borrower; cxl-lease-0c822f6e Running")
s.caption("The agent accepts a LendConfig only from a claim, for a lease that it knows, for the same pod and",
          "container: a tenant cannot lend memory to someone else's container.")
s.frame("lend-checked", "the memory is ready to lend")

s.send("agent_b", "runner_b", "NRI UpdateContainers(borrower/main): cpuset.mems = 0-1,2",
       short="NRI UpdateContainers(main): cpuset.mems 0-1,2")
s.set("main", l2="cpuset.mems 0-2 (2 is lent)")
s.set("agent_b", l1="lease 0c822f6e Ready: NUMA node 2 lent to borrower/main")
s.state("runner_b", "NRI: main's cpuset.mems", "-> 0-1,2")
s.caption("Only the calling container's cpuset.mems is written (idle's stays unset: it may use any node). Through",
          "NRI, so containerd keeps the value; a direct cgroupfs write would be undone by the next container update.")
s.frame("agent-lends", "node 2 is lent to one container")

s.reply("agent_b", "main", "{\"lease\":\"0c822f6e\",\"state\":\"Ready\",\"kind\":\"memory\",\"mode\":\"numa\","
        "\"node\":2,\"size\":536870912,\"serial\":\"0xc1ee0001\"}",
        short="{\"lease\":\"0c822f6e\",\"state\":\"Ready\",\"node\":2,...}")
s.set("main", l1="lease 0c822f6e Ready: node 2")
s.caption("cxl-request prints the JSON and exits 0; the test's numa-touch then puts 256 MiB on node 2 (numactl,",
          "mbind). Ready 5.7 s after the request, mostly the scheduler's poll. Lent memory counts against memory.max.")
s.frame("lease-ready", "the lease is Ready")

s.send("main", "agent_b", "cxl-release 0c822f6e  =  {\"op\":\"release\",\"lease\":\"0c822f6e\"}",
       short="cxl-release 0c822f6e", draw=False)
s.send("agent_b", "runner_b", "NRI UpdateContainers(borrower/main): cpuset.mems = 0-1",
       short="NRI UpdateContainers(main): cpuset.mems 0-1")
s.set("agent_b", l1="lease 0c822f6e Releasing: node 2 revoked from borrower/main")
s.set("main", l1="cxl-release 0c822f6e ...", l2="cpuset.mems 0-1 (pages moved)")
s.state("runner_b", "NRI: main's cpuset.mems", "-> 0-1")
s.caption("Shrinking cpuset.mems makes the kernel move the container's pages from node 2 to DRAM. numa-touch keeps",
          "running and never notices.")
s.frame("release-revoke", "giving it back while running")

s.send("agent_b", "api", "delete Pod and ResourceClaim cxl-lease-0c822f6e", short="delete companion cxl-lease-0c822f6e",
       draw=True)
s.send("runner_b", "agent_b", "NodeUnprepareResources(cxl-lease-0c822f6e)", draw=False)
s.send("agent_b", "hw_b", "offline the memory blocks; destroy region0; disable mem0",
       short="offline; destroy region0; disable mem0", draw=False)
s.note("claim cxl-lease-0c822f6e deallocated and deleted")
s.send("ctrl", "pool", "DELETE /api/v1/devices/pooled0/attachments/node-b", short="DELETE attachment pooled0@node-b",
       draw=False)
s.send("pool", "hw_b", "hot-remove: device_del ... DEVICE_DELETED", draw=False)
s.reply("agent_b", "main", "{\"lease\":\"0c822f6e\",\"state\":\"Released\"}", draw=False)
s.remove("companion")
s.set("hw_b", l1="no CXL memory devices")
pool(pooled0="free")
s.state("agent_b", "no leases", "lease broker: listening on leases/<claim uid>/cxl.sock")
s.set("main", l1="lease 0c822f6e released")
api(claims="borrower's token", pods="borrower Running")
s.state("ctrl", "detached pooled0@node-b", "event Detached")
s.state("runner_b", "pod borrower", "running")
s.caption("Fast-forward: 8.7 s after the release nothing of the lease remains: no companion, no claim, no",
          "attachment, no region. The next request gets a new lease id.")
s.frame("release-chain", "fast-forward: nothing left")

s.send("main", "agent_b", "cxl-request shared 0xc1ae0001 --exec python3 dax-rw.py --fd 3 write 0 TEXT  =  "
       "{\"op\":\"lease\",\"kind\":\"shared\",\"serial\":\"0xc1ae0001\",\"wait\":\"120s\"}",
       short="cxl-request shared 0xc1ae0001 --exec dax-rw.py ...", draw=False)
s.send("agent_b", "api", "create claim cxl-lease-d301f49a {deviceClassName cxl-shared-memory, selector serial == "
       "\"0xc1ae0001\", configs LendConfig + PoolDeviceConfig {mode: dax}} and its companion pod",
       short="create claim + companion cxl-lease-d301f49a (dax)", draw=True)
s.state("agent_b", "lease d301f49a Pending: shared 0xc1ae0001, mode dax; companion created",
        "caller: borrower/main")
s.set("main", l1="cxl-request shared ... --exec")
api(claims="token; cxl-lease-d301f49a waiting", pods="borrower; cxl-lease-d301f49a Pending")
s.caption("A shared device is always a dax device. --exec: once the lease is Ready, run this command with the",
          "device's open file descriptor as fd 3. (TEXT stands for the tagged string that the test writes.)")
s.frame("shared-request", "asking for the shared device")

s.send("sched", "api", "allocate shared0 @ node-b (hosts: 1 of 4); BindingConditionsPending",
       short="allocate shared0 @ node-b (hosts 1 of 4)", draw=False)
s.send("ctrl", "pool", "POST /api/v1/devices/shared0/attachments {host: node-b, owner: the companion claim}",
       short="POST attach shared0 {host: node-b}", draw=False)
s.send("pool", "hw_b", "hot-plug cxl-type3 serial 0xc1ae0001", draw=True)
s.reply("pool", "ctrl", "201 Created: attached", draw=False)
s.send("ctrl", "api", "claim status: Attached=True", draw=False)
s.send("sched", "api", "bind cxl-lease-d301f49a -> node-b", draw=False)
s.send("runner_b", "agent_b", "NodePrepareResources(cxl-lease-d301f49a)", draw=False)
s.send("agent_b", "hw_b", "cxl create-region; daxctl --mode=devdax -> /dev/dax0.0", draw=False)
s.set("hw_b", l1="mem0  serial 0xc1ae0001  256M -> region0 -> /dev/dax0.0 (device_dax); never onlined")
pool(shared0="attached to node-b, owner: claim cxl-lease-d301f49a")
s.entity("companion", "b3", "cxl-lease-d301f49a / pause", "companion pod, node-b", "claim: cxl-lease-d301f49a",
         "pause:3.10, 100m CPU, 8Mi", name="companion")
s.set("agent_b", l1="lease d301f49a Ready: shared0 prepared as mem0, region0, dax0.0 (mode dax)")
api(claims="token; cxl-lease-d301f49a Attached", pods="borrower; cxl-lease-d301f49a Running")
s.state("ctrl", "attached shared0 -> node-b", "status Attached written")
s.caption("Fast-forward: the same chain as for the memory lease, now for shared0, and with device_dax instead of",
          "kmem: the memory is never onlined.")
s.frame("shared-attached", "fast-forward: shared0 arrives")

s.reply("agent_b", "main", "open /dev/dax0.0 O_RDWR; {\"lease\":\"d301f49a\",\"state\":\"Ready\",\"kind\":\"shared\","
        "\"mode\":\"dax\",\"dax\":\"/dev/dax0.0\",\"size\":268435456,\"serial\":\"0xc1ae0001\"} + the open fd "
        "(SCM_RIGHTS)", short="Ready + the open /dev/dax0.0 fd (SCM_RIGHTS)")
s.set("main", l1="fd 3 = /dev/dax0.0 (no node)", l2="wrote TEXT at 0 through fd 3")
pool(shared0="attached to node-b; shared0.raw on the host holds TEXT")
s.caption("The device cgroup is checked only at open(): a passed fd needs no device node and no rule. A node made",
          "with mknod in the container still fails to open (EPERM). The host finds TEXT in the backing file.")
s.frame("fd-passed", "a file descriptor instead of a device")

s.send("main", "agent_b", "cxl-request fd d301f49a --exec dax-rw.py --fd 3 read 0  =  {\"op\":\"fd\",\"lease\":"
       "\"d301f49a\"}", short="cxl-request fd d301f49a --exec dax-rw.py read", draw=False)
s.reply("agent_b", "main", "the fd again (SCM_RIGHTS); dax-rw.py reads TEXT", draw=False)
s.send("main", "agent_b", "cxl-release --all  =  {\"op\":\"release\",\"all\":true}", short="cxl-release --all",
       draw=True)
s.send("agent_b", "api", "delete companion pod and claim cxl-lease-d301f49a", draw=False)
s.send("runner_b", "agent_b", "NodeUnprepareResources(cxl-lease-d301f49a)", draw=False)
s.send("agent_b", "hw_b", "destroy region0; disable mem0", draw=False)
s.send("ctrl", "pool", "DELETE /api/v1/devices/shared0/attachments/node-b", short="DELETE attachment shared0@node-b",
       draw=False)
s.send("pool", "hw_b", "hot-remove: device_del ... DEVICE_DELETED", draw=False)
s.reply("agent_b", "main", "{\"lease\":\"d301f49a\",\"state\":\"Released\"}", draw=False)
s.remove("companion")
s.set("main", l1="read TEXT again via a new fd", l2="then released: no lease")
s.set("hw_b", l1="no CXL memory devices")
pool(shared0="free")
s.state("agent_b", "no leases", "lease broker: listening on leases/<claim uid>/cxl.sock")
api(claims="borrower's token", pods="borrower Running")
s.state("ctrl", "detached shared0@node-b", "event Detached")
s.state("runner_b", "pod borrower", "running")
s.caption("Fast-forward: the fd can be asked for again while the lease lives (a restarted process has lost it).",
          "test12 lends, gives back and shares four times like this, with new lease ids and nothing left over.")
s.frame("fd-again-release", "fast-forward: once more, then release")

s.send("main", "agent_b", "cxl-request memory 512Mi  (lease c9a6afb3 ... Ready, node 2)",
       short="cxl-request memory 512Mi -> lease c9a6afb3 Ready", draw=False)
s.send("main", "agent_b", "cxl-request shared 0xc1ae0001  (lease 945a8e2a ... Ready, /dev/dax2.0)",
       short="cxl-request shared 0xc1ae0001 -> lease 945a8e2a Ready", draw=True)
s.set("main", l1="leases c9a6afb3 + 945a8e2a", l2="cpuset.mems 0-2 (2 is lent)")
s.state("agent_b", "leases c9a6afb3 (memory, node 2), 945a8e2a (shared, /dev/dax2.0): Ready",
        "caller: borrower/main")
s.set("hw_b", l1="mem0 (pooled0) -> region0 -> NUMA node 2;  mem1 (shared0) -> region2 -> /dev/dax2.0")
pool(shared0="attached to node-b, owner: claim cxl-lease-945a8e2a",
     pooled0="attached to node-b, owner: claim cxl-lease-c9a6afb3")
s.entity("companion", "b3", "two companions / pause", "pods cxl-lease-<id>, node-b", "cxl-lease-c9a6afb3: pooled0",
         "cxl-lease-945a8e2a: shared0", name="companions")
api(claims="token; 2 companion claims", pods="borrower; 2 companions Running")
s.state("ctrl", "attached pooled0, shared0", "-> node-b", "status Attached written")
s.caption("Fast-forward: the last round of test12 takes two leases at once, a NUMA node and a shared device, and",
          "then deletes the pod while both leases are alive.")
s.frame("two-leases", "fast-forward: two leases alive")

s.note("kubectl delete pod borrower (2 leases alive)")
s.send("runner_b", "agent_b", "NRI StopContainer borrower/main", draw=False)
s.send("agent_b", "api", "requester container gone, pod deleted: delete companions cxl-lease-c9a6afb3 and "
       "cxl-lease-945a8e2a", short="delete both companions", draw=True)
s.send("runner_b", "agent_b", "NodeUnprepareResources(both companion claims): released mem0, mem1",
       short="NodeUnprepareResources x2: release mem0, mem1", draw=False)
s.send("runner_b", "agent_b", "NodeUnprepareResources(token claim): socket and directory removed",
       short="NodeUnprepareResources(token claim)", draw=False)
s.send("ctrl", "pool", "DELETE attachments pooled0@node-b, shared0@node-b", draw=False)
s.send("pool", "hw_b", "hot-remove both: device_del ... DEVICE_DELETED", draw=False)
s.remove("main")
s.remove("idle")
s.remove("companion")
s.state("agent_b", "no leases; the token claim's socket and its directory are removed")
s.set("hw_b", l1="no CXL memory devices")
pool(shared0="free", pooled0="free")
api(claims="none", pods="none")
s.state("ctrl", "detached pooled0, shared0", "from node-b")
s.state("runner_b", "idle")
s.caption("Every path ends in the same chain: unprepare, deallocate, detach. The agent released both leases as soon",
          "as the container was gone for good (Kubernetes would delete the companions too). Clean 14.6 s later.")
s.frame("pod-deleted", "the pod goes, its leases go")

s.card("recap", "Recap: borrowing memory while running", [
    "Lease states (in leases.json of the node's agent)",
    "  Creating -> Pending -> Lending -> Ready -> Releasing -> Released        (Failed: timeout or a lend error)",
    "    Creating   stored before any API object exists",
    "    Pending    companion claim and pod created; waiting for the scheduler and the pool",
    "    Lending    the companion's claim is being prepared on this node",
    "    Ready      NUMA node added to the container's cpuset.mems, or the dax fd passed",
    "    Releasing  node revoked, companion deleted, waiting until it is gone",
    "",
    "Commands in the container (each prints the JSON response; exit code 3 = Failed or not Ready in time)",
    "  cxl-request memory <size> [--dax [--read-only]] [--wait D] [--exec CMD...]   a NUMA node, or a dax fd",
    "  cxl-request shared <serial> [--exclusive] [--read-only] [--wait D] [--exec CMD...]",
    "  cxl-request fd <lease> --exec CMD...      cxl-release <lease> | --all      cxl-request list",
    "",
    "Limits: lent memory counts against the container's memory limit; release is cooperative; lending is",
    "exclusive only where containers have cpuset.mems set. A lease took 5.7 s (mostly the scheduler's poll),",
    "giving it back 8.4-10.4 s, in the recorded run.",
])

# =============================================================================== chapter 4
s.chapter(4, "Sharing: one device, several nodes", "sharing", layout=L.TWO_NODES, body=[
    "node-a (VM1, a worker) joins node-b (VM2, the control plane) in one cluster, with one pool controller.",
    "(e2e test11 used two single-node clusters that share one pool server: the mechanics are the same.)",
    "",
    "  - shared0 has no memory capacity to hand out, but a 'hosts' capacity of 4: how many nodes may have it",
    "  - one claim per node, one attachment per node: the same serial, the same backing file, the same bytes",
    "  - shared memory is always a dax device: two kernels that both online the same bytes as RAM would corrupt",
    "    each other silently. That is also why auto_online_blocks must be offline on every node.",
], source="Source: e2e test11-dra-sharing; shown in the two-node cluster of test13")
s.state("agent_b", "published node-b's slice", "no leases")
s.state("runner_b", "idle")
s.state("sched", "idle")
api(claims="none", pods="none")
s.settle()

s.entity("runner_a", "runner_a", "Pod runner", ("kubelet + containerd", "kubelet"), "idle", name="Pod runner (node-a)")
s.entity("agent_a", "agent_a", "Node's CXL agent", "kubelet-cxl-plugin", "published node-a's slice",
         "no leases", name="CXL agent (node-a)")
s.entity("hw_a", "hw_a", "CXL memory seen by the node", "/sys/bus/cxl: memN regionN daxX.Y, NUMA nodes",
         "no CXL memory devices", name="CXL memory (node-a)")
s.state("ctrl", "pool hosts of the nodes:", "node-a = VM1, node-b = VM2", "(by systemUUID)")
api(slices="pool, node-a, node-b")
pool(shared0="free: 4 'hosts', each node takes 1")

s.caption("shared0 offers no memory capacity (every node would get all of it) but a 'hosts' capacity of 4: how",
          "many nodes may have it at once. A claim takes 1 by default; a claim that takes all 4 has it alone.")
s.frame("two-nodes", "two nodes, one pool")

s.note("kubectl apply: ResourceClaim shared-memory {deviceClassName cxl-shared-memory, selector "
       "device.attributes[\"cxl-pool.generic\"].serial == \"0xc1ae0001\"} and Pod writer (on node-a)",
       short="kubectl apply: claim + pod writer (node-a)")
s.send("sched", "api", "allocate shared0 @ node-a (consumedCapacity hosts 1, a shareID); BindingConditionsPending",
       short="allocate shared0 @ node-a (hosts 1)", draw=False)
s.send("ctrl", "pool", "POST /api/v1/devices/shared0/attachments {host: node-a, owner: k8s:resourceclaim/<uid>}",
       short="POST attach shared0 {host: node-a}", draw=False)
s.send("pool", "hw_a", "hot-plug cxl-type3 serial 0xc1ae0001", draw=True)
s.reply("pool", "ctrl", "201 Created: attached", draw=False)
s.send("ctrl", "api", "claim status: Attached=True, data {serial 0xc1ae0001, shared true, size 268435456, ...}",
       short="claim status: Attached=True + data", draw=False)
s.state("sched", "shared-memory:", "shared0 @ node-a", "hosts: 1/4")
api(claims="shared-memory Attached (node-a)", pods="writer -> node-a, creating")
s.state("ctrl", "attached shared0 -> node-a", "status Attached written")
pool(shared0="attached to node-a")
s.set("hw_a", l1="mem0  serial 0xc1ae0001  256M  appears (udev)")
s.caption("Fast-forward: the writer's claim on node-a takes 1 of shared0's 4 hosts; then the same chain as in",
          "chapter 1.")
s.frame("writer-claim", "fast-forward: the writer's claim")

s.send("runner_a", "agent_a", "NodePrepareResources(shared-memory)", draw=False)
s.send("agent_a", "hw_a", "cxl create-region; daxctl --mode=devdax -> /dev/dax0.0", draw=False)
s.reply("agent_a", "runner_a", "CDI pool-c1ae0001: device node /dev/dax0.0, env CXL_SHARED_DAX_C1AE0001=/dev/dax0.0, "
        "CXL_SHARED_SIZE_C1AE0001=268435456, CXL_SHARED_SERIAL_C1AE0001=0xc1ae0001",
        short="CDI pool-c1ae0001: /dev/dax0.0, CXL_SHARED_DAX_...", draw=False)
s.send("runner_a", "writer", "start container writer", draw=True)
s.entity("writer", "a1", "writer / writer", "pod writer, node-a", "wrote at offset 0:", "'hello from node-a'",
         name="writer/writer")
s.set("hw_a", l1="mem0 -> region0 -> /dev/dax0.0 (device_dax)")
s.state("agent_a", "prepared shared0: dax0.0", "no leases")
s.state("runner_a", "pod writer", "running")
api(pods="writer Running (node-a)")
pool(shared0="attached to node-a; shared0.raw holds 'hello from node-a'")
s.caption("A shared device always becomes a dax device. The environment variables say CXL_SHARED_ instead of",
          "CXL_POOL_. (The test writes a string with a timestamp; 'hello from node-a' stands for it here.)")
s.frame("writer-writes", "node-a writes")

s.note("kubectl apply: ResourceClaim shared-memory-b (the same selector) and Pod reader (on node-b)",
       short="kubectl apply: claim + pod reader (node-b)")
s.send("sched", "api", "allocate shared0 @ node-b (hosts: 2 of 4 now); BindingConditionsPending",
       short="allocate shared0 @ node-b (hosts 2 of 4)", draw=False)
s.send("ctrl", "pool", "POST /api/v1/devices/shared0/attachments {host: node-b, owner: claim shared-memory-b}",
       short="POST attach shared0 {host: node-b}", draw=False)
s.send("pool", "hw_b", "hot-plug the SAME backing file as cxl-type3 serial 0xc1ae0001",
       short="hot-plug the same backing file, serial 0xc1ae0001", draw=True)
s.reply("pool", "ctrl", "201 Created: attached", draw=False)
s.send("ctrl", "api", "claim status: Attached=True", draw=False)
s.state("sched", "shared-memory-b:", "shared0 @ node-b", "hosts: 2/4")
api(claims="shared-memory (a), -b (b) Attached", pods="writer Running; reader Pending")
s.state("ctrl", "attached shared0 -> node-b", "status Attached written")
pool(shared0="attached to node-a and node-b: one attachment each")
s.set("hw_b", l1="mem0  serial 0xc1ae0001  256M  appears (udev)")
s.caption("Fast-forward: the same serial in every node; that is how each node's agent finds the device. Two",
          "attachments of one device, each owned by its claim.")
s.frame("reader-claim", "fast-forward: node-b's claim")

s.send("runner_b", "agent_b", "NodePrepareResources(shared-memory-b)", draw=False)
s.send("agent_b", "hw_b", "cxl create-region; daxctl --mode=devdax -> /dev/dax0.0", draw=False)
s.reply("agent_b", "runner_b", "CDI pool-c1ae0001: /dev/dax0.0, CXL_SHARED_DAX_C1AE0001=/dev/dax0.0, ...",
        short="CDI pool-c1ae0001: /dev/dax0.0, CXL_SHARED_DAX_...", draw=False)
s.send("runner_b", "reader", "start container reader", draw=True)
s.entity("reader", "b1", "reader / reader", "pod reader, node-b", "read at offset 0:", "'hello from node-a'",
         name="reader/reader")
s.set("hw_b", l1="mem0 -> region0 -> /dev/dax0.0 (device_dax)")
s.state("agent_b", "prepared shared0: dax0.0", "no leases")
s.state("runner_b", "pod reader", "running")
api(pods="writer (a), reader (b) Running")
s.caption("The same bytes, no network in between: both VMs map the same backing file. The agent refuses mode numa",
          "for a shared device: two kernels must never online the same memory.")
s.frame("reader-reads", "node-b reads the same bytes")

s.note("kubectl delete pod writer, resourceclaim shared-memory (node-a)")
s.send("runner_a", "agent_a", "NodeUnprepareResources(shared-memory)", draw=False)
s.send("agent_a", "hw_a", "destroy region0; disable mem0", draw=False)
s.send("ctrl", "pool", "DELETE /api/v1/devices/shared0/attachments/node-a", short="DELETE attachment shared0@node-a",
       draw=True)
s.send("pool", "hw_a", "hot-remove: device_del ... DEVICE_DELETED", draw=False)
s.remove("writer")
s.set("hw_a", l1="no CXL memory devices")
s.state("agent_a", "released mem0", "no leases")
s.state("runner_a", "idle")
pool(shared0="attached to node-b")
s.state("sched", "shared0 hosts: 1/4")
api(claims="shared-memory-b (b) Attached", pods="reader (b) Running")
s.state("ctrl", "detached shared0@node-a")
s.set("reader", l1="reads again at 0:")
s.caption("Each node releases on its own: node-b keeps its attachment and still reads the bytes. Then node-b",
          "releases too, the same way, and shared0 is free again.")
s.frame("independent", "each node lets go on its own")

# =============================================================================== chapter 5
s.chapter(5, "One exclusive writer, many read-only readers", "writer and readers", body=[
    "The plot, by the sections of e2e test13 (one cluster of two nodes)",
    "  B   a writer on node-a gets shared0 EXCLUSIVELY, through a lease, and writes TEXT into it",
    "  C   meanwhile three readers ask for it read-only, two on node-b and one on node-a: they wait",
    "  D   the writer exits: all three readers get the device at once and read TEXT",
    "  E2  a late exclusive request fails cleanly; nobody loses the memory",
    "  F   a fourth reader on node-a uses a read-only claim from its creation",
    "  G   everybody finishes, and the device goes back to the pool",
    "",
    "  exclusive = request ALL 4 'hosts' of the shared device: the scheduler can give it to nobody else, and the",
    "              pool refuses to attach it to any other host (also those of other clusters)",
    "  read-only = an fd opened O_RDONLY (lease) or a device node with permissions r (claim): kernel-enforced",
], source="Source: e2e test13-dra-shared-one-writer-many-readers and its recorded trace (its lease ids)")

s.state("sched", "idle")
s.state("ctrl", "idle")
api(claims="none", pods="none")
s.state("agent_a", "no leases")
s.state("agent_b", "no leases")
s.state("runner_a", "idle")
s.state("runner_b", "idle")
s.set("hw_b", l1="no CXL memory devices")
pool(shared0="free", pooled0="free")
s.settle()

s.note("kubectl apply: Pod writer (node-a, restartPolicy Never) {claim cxl -> template cxl-lease-token; container "
       "main runs: cxl-request shared 0xc1ae0001 --exclusive --wait 120s --exec sh -c 'dax-rw.py --fd 3 write 0 "
       "TEXT; echo written; wait for /tmp/done'}", short="kubectl apply: pod writer (node-a), token claim")
s.send("sched", "api", "allocate dynamic @ node-a; bind writer -> node-a", draw=False)
s.send("runner_a", "agent_a", "NodePrepareResources(the writer's token claim)",
       short="NodePrepareResources(token claim)", draw=False)
s.reply("agent_a", "runner_a", "CDI lease-<claim uid>: /run/cxl (the socket), cxl-request, CXL_LEASE_SOCKET",
        short="CDI lease-<uid>: /run/cxl, cxl-request")
s.entity("writer", "a1", "writer / main", "pod writer, node-a", "socket + cxl-request", "starting", name="writer/main")
s.state("agent_a", "lease socket for writer", "no leases")
s.state("runner_a", "pod writer", "starting")
api(claims="writer's token -> dynamic @ node-a", pods="writer -> node-a, starting")
s.caption("The writer opts in like the borrower of chapter 3: a token claim from the template cxl-lease-token.",
          "TEXT is the string it will write: 'dra-one-writer <timestamp>: written by the exclusive writer'.")
s.frame("writer-pod", "the writer opts in")

s.send("writer", "agent_a", "cxl-request shared 0xc1ae0001 --exclusive  =  {\"op\":\"lease\",\"kind\":\"shared\","
       "\"serial\":\"0xc1ae0001\",\"exclusive\":true,\"wait\":\"120s\"}",
       short="cxl-request shared 0xc1ae0001 --exclusive", draw=False)
s.send("agent_a", "api", "read the pool's ResourceSlice: shared0 has capacity hosts = 4",
       short="read the pool slice: shared0 hosts = 4", draw=True)
s.state("agent_a", "lease 36c2ee71 Creating", "shared0, dax, exclusive")
s.state("writer", "request: exclusive", "waiting ...")
s.state("runner_a", "pod writer", "running")
s.caption("Exclusive = ask for ALL hosts of the device. The agent reads how many there are from the pool's offer",
          "list (valid values: 1 or 4) and asks for 4.")
s.frame("exclusive-request", "the writer asks for all of it")

s.send("agent_a", "api", "create claim cxl-lease-36c2ee71 {deviceClassName cxl-shared-memory, selector serial == "
       "\"0xc1ae0001\", capacity.requests.hosts: \"4\", configs LendConfig + PoolDeviceConfig {mode: dax, readOnly: "
       "false}} and its companion pod (node-a)", short="create claim (hosts: 4) + companion cxl-lease-36c2ee71",
       draw=False)
s.send("sched", "api", "allocate shared0 @ node-a, consumedCapacity hosts 4; BindingConditionsPending",
       short="allocate shared0 @ node-a (hosts 4 of 4)", draw=True)
api(claims="cxl-lease-36c2ee71 -> shared0 (4/4)", pods="writer; cxl-lease-36c2ee71 Pending")
s.state("sched", "cxl-lease-36c2ee71:", "shared0 @ node-a", "hosts: 4/4 taken")
s.set("agent_a", l1="lease 36c2ee71 Pending")
s.caption("While this claim exists, the scheduler can give shared0 to nobody else: no 'hosts' capacity is left.")
s.frame("writer-companion", "all four hosts taken")

s.send("ctrl", "pool", "POST /api/v1/devices/shared0/attachments {host: node-a, owner: k8s:resourceclaim/<uid>, "
       "wait: true, exclusive: true}", short="POST attach shared0 {host: node-a, exclusive: true}", draw=False)
s.send("pool", "hw_a", "hot-plug cxl-type3 serial 0xc1ae0001 (qemu device fcp_shared0.hp1)",
       short="hot-plug cxl-type3 serial 0xc1ae0001 (hp1)", draw=True)
s.reply("pool", "ctrl", "201 Created: attached, exclusive", draw=False)
s.send("ctrl", "api", "claim status: Attached=True, data {serial 0xc1ae0001, shared true, size 268435456, exclusive "
       "true}", short="claim status: Attached=True, exclusive true", draw=False)
pool(shared0="attached to node-a, EXCLUSIVE: other hosts get 409 Conflict")
s.set("hw_a", l1="mem0  serial 0xc1ae0001  256M  appears (udev)")
s.state("ctrl", "attached shared0 -> node-a", "exclusive: true", "status Attached written")
api(claims="cxl-lease-36c2ee71 Attached")
s.caption("The pool enforces it too: an exclusive attachment refuses every other host, including the nodes of",
          "other clusters that share this pool.")
s.frame("exclusive-attach", "the pool keeps everybody else out")

s.send("sched", "api", "bind cxl-lease-36c2ee71 -> node-a", draw=False)
s.send("runner_a", "agent_a", "NodePrepareResources(cxl-lease-36c2ee71)", draw=False)
s.send("agent_a", "hw_a", "cxl create-region; daxctl --mode=devdax -> /dev/dax0.0", draw=False)
s.reply("agent_a", "writer", "open /dev/dax0.0 O_RDWR; {\"lease\":\"36c2ee71\",\"state\":\"Ready\",\"kind\":\"shared\","
        "\"mode\":\"dax\",\"exclusive\":true,\"dax\":\"/dev/dax0.0\",\"size\":268435456} + the fd",
        short="Ready, exclusive + the fd (O_RDWR)")
s.set("hw_a", l1="mem0 -> region0 -> /dev/dax0.0 (device_dax)")
s.state("writer", "lease Ready: fd 3 rw", "wrote TEXT; waits")
s.state("agent_a", "lease 36c2ee71 Ready, excl.", "fd O_RDWR passed to writer")
s.state("sched", "shared0 hosts: 4/4", "(the writer's lease)")
api(pods="writer; cxl-lease-36c2ee71 Running")
pool(shared0="attached to node-a, EXCLUSIVE; shared0.raw holds TEXT")
s.caption("Ready 5.2 s after the request (6.3 s after the pod was created). The writer prints 'written' and waits",
          "for the file /tmp/done; the test checks on the host that the backing file holds TEXT.")
s.frame("writer-writes", "the writer writes")

s.note("kubectl apply: Pods reader-a, reader-b (node-b) and reader-c (node-a), each with a token claim; main runs: "
       "cxl-request shared 0xc1ae0001 --read-only --wait 300s --exec sh -c 'dax-rw.py --fd 3 check-ro 0; dax-rw.py "
       "--fd 3 watch 0 /tmp/stop'", short="kubectl apply: readers a, b (node-b), c (node-a)")
s.send("runner_b", "agent_b", "NodePrepareResources(token claims of reader-a and reader-b)",
       short="NodePrepareResources(token claims a, b)", draw=False)
s.send("reader_a", "agent_b", "{\"op\":\"lease\",\"kind\":\"shared\",\"serial\":\"0xc1ae0001\",\"readOnly\":true,"
       "\"wait\":\"300s\"}", short="cxl-request shared 0xc1ae0001 --read-only", draw=True)
s.send("agent_b", "api", "create claim cxl-lease-2562aeca {hosts: the default 1, PoolDeviceConfig {mode: dax, "
       "readOnly: true}} and its companion pod (node-b)", short="create cxl-lease-2562aeca (read-only) + companion",
       draw=False)
s.entity("reader_a", "b1", "reader-a / main", "pod reader-a, node-b", "lease 2562aeca", "Pending, read-only",
         name="reader-a/main")
s.state("agent_b", "lease 2562aeca Pending ro")
s.state("runner_b", "reader-a, -b:", "tokens ready")
api(claims="writer's Attached; reader-a's new")
s.caption("Read-only, with the default share of 1 host. The companion claim carries PoolDeviceConfig {mode: dax,",
          "readOnly: true}.")
s.frame("reader-a-asks", "a reader asks")

s.send("reader_b", "agent_b", "the same request, read-only", draw=False)
s.send("agent_b", "api", "create claim cxl-lease-e5597c7f + companion pod (node-b)",
       short="create cxl-lease-e5597c7f (read-only) + companion", draw=False)
s.send("runner_a", "agent_a", "NodePrepareResources(reader-c's token claim)", draw=False)
s.send("reader_c", "agent_a", "the same request, read-only", draw=True)
s.send("agent_a", "api", "create claim cxl-lease-ce5ef151 + companion pod (node-a)",
       short="create cxl-lease-ce5ef151 (read-only) + companion", draw=False)
s.entity("reader_b", "b2", "reader-b / main", "pod reader-b, node-b", "lease e5597c7f", "Pending, read-only",
         name="reader-b/main")
s.entity("reader_c", "a2", "reader-c / main", "pod reader-c, node-a", "lease ce5ef151", "Pending, read-only",
         name="reader-c/main")
s.state("agent_a", "lease 36c2ee71 Ready, excl.", "lease ce5ef151 Pending ro")
s.state("agent_b", "leases 2562aeca, e5597c7f", "Pending, read-only")
s.state("runner_a", "runs writer", "and reader-c")
api(claims="writer's Attached; 3 readers' new", pods="3 companions Pending")
s.caption("reader-b asks on node-b, reader-c on node-a: every lease gets a companion claim and pod of its own.")
s.frame("readers-b-c", "two more readers")

s.note("10 s pass: nothing moves")
s.state("sched", "shared0 hosts: 4/4", "3 reader claims wait", "FailedScheduling")
api(pods="3 companions FailedScheduling")
pool(shared0="attached to node-a, EXCLUSIVE; never asked for the readers")
s.caption("The scheduler cannot allocate: all 4 hosts are taken (event FailedScheduling: '... cannot allocate all",
          "claims'). The pool is not even asked. The readers' cxl-request calls block (--wait 300s).")
s.frame("readers-wait", "the readers wait")

s.note("touch /tmp/done in the writer: its command exits, cxl-request exits 0, container main exits: pod writer "
       "Succeeded (restartPolicy Never)", short="touch /tmp/done: the writer exits, pod Succeeded")
s.send("runner_a", "agent_a", "NRI StopContainer writer/main", draw=True)
s.remove("writer", "(exited)")
s.state("agent_a", "lease 36c2ee71 Releasing", "lease ce5ef151 Pending ro")
s.state("runner_a", "writer exited", "runs reader-c")
api(pods="writer Completed; 3 Pending")
s.caption("The agent releases the leases of a container that stopped for good (pod finished or deleted, or",
          "restartPolicy Never); otherwise it keeps them for the container's restart.")
s.frame("writer-exits", "the writer exits")

s.send("agent_a", "api", "delete companion pod and claim cxl-lease-36c2ee71",
       short="delete companion cxl-lease-36c2ee71", draw=True)
s.send("runner_a", "agent_a", "NodeUnprepareResources(cxl-lease-36c2ee71)", draw=False)
s.send("agent_a", "hw_a", "destroy region0; disable mem0 (the device stays attached)",
       short="destroy region0; disable mem0 (still attached)", draw=False)
s.note("claim cxl-lease-36c2ee71 deallocated and deleted: all 4 hosts of shared0 are free",
       short="claim cxl-lease-36c2ee71 gone: 4 hosts free")
s.send("sched", "api", "allocate the 3 reader claims: shared0, 1 host each; node-b, node-b, node-a; "
       "BindingConditionsPending x3", short="allocate 3 reader claims (1 host each)", draw=False)
s.set("hw_a", l1="mem0  serial 0xc1ae0001  256M  no region")
api(claims="3 readers' -> shared0 @ b, b, a", pods="3 companions in binding wait")
s.state("sched", "allocated 3 readers", "shared0 hosts: 3/4", "waiting for Attached")
s.state("agent_a", "lease 36c2ee71 released", "lease ce5ef151 Pending ro")
s.state("runner_a", "pod reader-c", "running")
s.caption("Fast-forward: as soon as the writer's claim is gone, the scheduler allocates all three readers, one",
          "host each: two on node-b, one on node-a.")
s.frame("writer-cleanup", "fast-forward: the writer's lease goes")

s.send("ctrl", "pool", "DELETE /api/v1/devices/shared0/attachments/node-a?wait=true (at that instant no claim "
       "wanted it)", short="DELETE attachment shared0@node-a", draw=False)
s.send("pool", "hw_a", "hot-remove over QMP: device_del fcp_shared0.hp1 ... event DEVICE_DELETED about 6 s later ... "
       "object-del", short="hot-remove: device_del ... DEVICE_DELETED (6 s)", draw=True)
s.reply("pool", "ctrl", "200: detached", draw=False)
pool(shared0="free (for a moment)")
s.set("hw_a", l1="no CXL memory devices")
s.state("ctrl", "detached shared0@node-a", "event Detached")
s.caption("The controller reconciled in the instant between 'the writer's claim is gone' and 'the readers' claims",
          "are allocated', and detached. (It can also just clear an attachment's exclusive flag; not in this run.)")
s.frame("ctrl-detaches", "a detour: detached for a moment")

s.send("ctrl", "pool", "POST /api/v1/devices/shared0/attachments {host: node-a, owner: claim cxl-lease-ce5ef151}",
       short="POST attach shared0 {host: node-a}", draw=False)
s.send("pool", "hw_a", "hot-plug cxl-type3 serial 0xc1ae0001 (fcp_shared0.hp2)", draw=True)
s.reply("pool", "ctrl", "201 Created: attached", draw=False)
s.send("ctrl", "pool", "POST /api/v1/devices/shared0/attachments {host: node-b, owner: claim cxl-lease-2562aeca}",
       short="POST attach shared0 {host: node-b}", draw=False)
s.send("pool", "hw_b", "hot-plug cxl-type3 serial 0xc1ae0001 (fcp_shared0.hp1)", draw=True)
s.reply("pool", "ctrl", "201 Created: attached", draw=False)
s.send("ctrl", "api", "claim status Attached=True: cxl-lease-2562aeca, cxl-lease-ce5ef151, cxl-lease-e5597c7f",
       short="Attached=True for the 3 reader claims", draw=False)
pool(shared0="attached to node-a and node-b (not exclusive)")
s.set("hw_a", l1="mem0  serial 0xc1ae0001  256M  appears (udev)")
s.set("hw_b", l1="mem0  serial 0xc1ae0001  256M  appears (udev)")
s.state("ctrl", "attached shared0 -> a, b", "Attached written x3")
api(claims="3 readers' -> shared0, Attached")
s.caption("One attachment per node serves all claims there (reader-a and reader-b share node-b's); same backing file.")
s.frame("attached-to-both", "shared0 into both nodes")

s.send("sched", "api", "bind the 3 companion pods", draw=False)
s.send("runner_a", "agent_a", "NodePrepareResources(cxl-lease-ce5ef151)", draw=False)
s.send("agent_a", "hw_a", "cxl create-region; daxctl --mode=devdax -> /dev/dax0.0",
       short="create-region; devdax -> /dev/dax0.0", draw=True)
s.send("runner_b", "agent_b", "NodePrepareResources(cxl-lease-2562aeca, cxl-lease-e5597c7f)",
       short="NodePrepareResources(2562aeca, e5597c7f)", draw=False)
s.send("agent_b", "hw_b", "cxl create-region; daxctl --mode=devdax -> /dev/dax0.0 (one region, reused for the second "
       "claim)", short="create-region (once, reused); devdax -> /dev/dax0.0", draw=True)
s.set("hw_a", l1="mem0 -> region0 -> /dev/dax0.0 (device_dax)")
s.set("hw_b", l1="mem0 -> region0 -> /dev/dax0.0 (device_dax)")
s.state("agent_a", "lease ce5ef151 Lending ro")
s.state("agent_b", "leases 2562aeca, e5597c7f", "Lending, read-only")
s.state("runner_b", "2 companions:", "prepared")
s.state("sched", "idle", "shared0 hosts: 3/4")
api(pods="3 companions Running")
s.caption("Both nodes prepare the same serial. On node-b one region serves two claims, released with the last one.")
s.frame("readers-prepared", "both nodes prepare the device")

s.reply("agent_b", "reader_a", "open /dev/dax0.0 O_RDONLY; {\"lease\":\"2562aeca\",\"state\":\"Ready\",\"kind\":"
        "\"shared\",\"mode\":\"dax\",\"readOnly\":true,\"dax\":\"/dev/dax0.0\",...} + the fd",
        short="Ready, read-only + the fd (O_RDONLY)", draw=True)
s.reply("agent_b", "reader_b", "the same for lease e5597c7f", draw=False)
s.state("reader_a", "lease 2562aeca Ready", "read-only: holds TEXT")
s.state("reader_b", "lease e5597c7f Ready", "read-only: holds TEXT")
s.state("agent_b", "leases 2562aeca, e5597c7f", "Ready, read-only fds")
s.caption("CXL_LEASE_READONLY=1. A read-only fd allows only read-only mappings: dax-rw.py check-ro gets EACCES",
          "for a writable one. The kernel enforces it, whatever the container's capabilities.")
s.frame("read-only-fds", "read-only file descriptors")

s.reply("agent_a", "reader_c", "open /dev/dax0.0 O_RDONLY; Ready + the fd (lease ce5ef151)",
        short="Ready, read-only + the fd (O_RDONLY)")
s.state("reader_c", "lease ce5ef151 Ready", "read-only: holds TEXT")
s.state("agent_a", "lease ce5ef151 Ready ro")
pool(shared0="attached to node-a and node-b; shared0.raw still holds TEXT")
s.caption("13.2 s after the writer's exit all three readers hold the memory (9.4 s in another run): about 6 s of",
          "hot-remove and about 5 s of scheduler poll. They read what the writer wrote.")
s.frame("all-readers-hold", "three readers hold the memory")

s.send("reader_a", "agent_b", "cxl-request shared 0xc1ae0001 --exclusive --wait 15s (in reader-a's container)",
       short="cxl-request shared 0xc1ae0001 --exclusive --wait 15s", draw=False)
s.send("agent_b", "api", "create claim cxl-lease-98dee186 {hosts: 4} and its companion pod",
       short="create cxl-lease-98dee186 (hosts: 4) + companion", draw=False)
s.note("scheduler: FailedScheduling (only 1 of 4 hosts free); 15 s pass",
       short="FailedScheduling (1 of 4 hosts free); 15 s pass")
s.send("agent_b", "api", "timeout: delete companion pod and claim cxl-lease-98dee186",
       short="timeout: delete companion cxl-lease-98dee186", draw=False)
s.reply("agent_b", "reader_a", "{\"lease\":\"98dee186\",\"state\":\"Failed\",\"error\":\"timeout: not Ready after "
        "15s\"}", short="{\"lease\":\"98dee186\",\"state\":\"Failed\",...}", draw=True)
s.note("cxl-request exits 3")
s.state("agent_b", "leases 2562aeca, e5597c7f", "98dee186: Failed, released")
s.state("sched", "cxl-lease-98dee186:", "needs 4, 1 host free", "FailedScheduling")
s.caption("A new exclusive request cannot take the device from the readers: it waits, times out, cleans up after",
          "itself, and cxl-request exits 3. Nobody lost a mapping.")
s.frame("late-exclusive", "a late exclusive request fails cleanly")

s.note("kubectl apply: ResourceClaim shared-read-only {deviceClassName cxl-shared-memory, selector serial == "
       "\"0xc1ae0001\", config PoolDeviceConfig {readOnly: true}} and Pod reader-d (node-a) that uses it",
       short="kubectl apply: claim + pod reader-d (node-a)")
s.send("sched", "api", "allocate shared0 @ node-a (hosts: 4 of 4 now); BindingConditionsPending",
       short="allocate shared0 @ node-a (hosts 4 of 4)", draw=False)
s.send("ctrl", "api", "claim status Attached=True: shared0 is already attached to node-a, no pool call",
       short="Attached=True (already attached: no pool call)", draw=True)
api(claims="readers + shared-read-only Attached", pods="reader-d -> node-a, binding")
s.state("ctrl", "no pool call: already", "attached to node-a", "status Attached written")
s.state("sched", "shared-read-only:", "shared0 @ node-a", "shared0 hosts: 4/4")
s.caption("A claim at pod creation, on a node that has the device already: the controller only writes the status",
          "(0.1 s). Now all 4 hosts are taken: two readers per node.")
s.frame("reader-d-claim", "a fourth reader, with a claim")

s.send("sched", "api", "bind reader-d -> node-a", draw=False)
s.send("runner_a", "agent_a", "NodePrepareResources(shared-read-only)", draw=False)
s.reply("agent_a", "runner_a", "CDI generic/cxl=pool-c1ae0001-ro: deviceNodes [/dev/dax0.0 permissions r], env "
        "CXL_SHARED_DAX_C1AE0001=/dev/dax0.0, CXL_SHARED_SIZE_C1AE0001=268435456, CXL_SHARED_SERIAL_C1AE0001="
        "0xc1ae0001, CXL_SHARED_READONLY_C1AE0001=1 (region0 reused)",
        short="CDI pool-c1ae0001-ro: /dev/dax0.0 permissions r + env", draw=False)
s.send("runner_a", "reader_d", "start container main", draw=True)
s.entity("reader_d", "a1", "reader-d / main", "pod reader-d, node-a", "rw open -> EPERM", "read TEXT",
         name="reader-d/main")
s.state("runner_a", "runs reader-c", "and reader-d")
api(pods="reader-d Running (node-a)")
s.caption("Four readers, two per node, read the same bytes at the same time: three through a passed fd (no device",
          "node at all), one through a read-only device node (open for writing: EPERM; writable map: EACCES).")
s.frame("reader-d-runs", "four readers at once")

s.note("touch /tmp/stop in reader-a, -b, -c: they print 'final: TEXT', cxl-request exits 0, then cxl-release --all",
       short="touch /tmp/stop in readers a, b, c; release all")
s.send("reader_a", "agent_b", "{\"op\":\"release\",\"all\":true}", short="cxl-release --all", draw=False)
s.send("reader_b", "agent_b", "{\"op\":\"release\",\"all\":true}", short="cxl-release --all", draw=False)
s.send("reader_c", "agent_a", "{\"op\":\"release\",\"all\":true}", short="cxl-release --all", draw=False)
s.send("agent_b", "api", "delete companions cxl-lease-2562aeca and cxl-lease-e5597c7f",
       short="delete companions 2562aeca, e5597c7f", draw=True)
s.send("agent_a", "api", "delete companion cxl-lease-ce5ef151", draw=False)
s.send("runner_b", "agent_b", "NodeUnprepareResources x2: first 'serial 0xc1ae0001 is still used by another claim', "
       "then release mem0", short="unprepare x2: 'still used', then release mem0", draw=False)
s.note("kubectl delete pod reader-d, resourceclaim shared-read-only", short="kubectl delete pod + claim of reader-d")
s.send("runner_a", "agent_a", "NodeUnprepareResources x2: reader-c's ('still used by another claim'), then reader-d's: "
       "release mem0", short="unprepare x2: 'still used', then release mem0", draw=False)
s.state("reader_a", "lease released", "final: TEXT")
s.state("reader_b", "lease released", "final: TEXT")
s.state("reader_c", "lease released", "final: TEXT")
s.remove("reader_d")
s.set("hw_a", l1="mem0  serial 0xc1ae0001  256M  no region")
s.set("hw_b", l1="mem0  serial 0xc1ae0001  256M  no region")
s.state("agent_a", "released mem0", "no leases")
s.state("agent_b", "released mem0", "no leases")
s.state("runner_b", "unprepared 2", "companions")
s.state("runner_a", "pod reader-c", "running")
api(claims="the readers' token claims only", pods="reader-a, -b, -c Running")
s.caption("Fast-forward: release is cooperative. The readers unmap and release; each agent destroys its region",
          "with the last claim. The device is still attached until the controller acts.")
s.frame("readers-finish", "fast-forward: the readers finish")

s.send("ctrl", "pool", "DELETE /api/v1/devices/shared0/attachments/node-b?wait=true",
       short="DELETE attachment shared0@node-b", draw=False)
s.send("pool", "hw_b", "hot-remove: device_del fcp_shared0.hp1 ... DEVICE_DELETED (about 6 s)",
       short="hot-remove: device_del ... DEVICE_DELETED", draw=True)
s.send("ctrl", "pool", "DELETE /api/v1/devices/shared0/attachments/node-a?wait=true",
       short="DELETE attachment shared0@node-a", draw=False)
s.send("pool", "hw_a", "hot-remove: device_del fcp_shared0.hp2 ... DEVICE_DELETED (about 6 s)",
       short="hot-remove: device_del ... DEVICE_DELETED", draw=True)
pool(shared0="free", pooled0="free")
s.set("hw_a", l1="no CXL memory devices")
s.set("hw_b", l1="no CXL memory devices")
s.state("ctrl", "detached shared0 from", "node-b, then node-a", "idle")
s.state("runner_b", "runs reader-a", "and reader-b")
s.state("sched", "idle")
api(claims="no CXL claims left", pods="reader-a, -b, -c Running")
s.caption("Back where we started. The controller detaches one node at a time, waiting for each hot-remove (6 s).")
s.frame("pool-free", "back to the pool")

s.card("recap", "Recap: what enforced what", [
    "exclusive     the scheduler: a claim that consumes all 4 'hosts' of shared0 leaves nothing to allocate,",
    "              AND the pool: an exclusive attachment refuses every other host, also those of other clusters",
    "read-only     a lease: the fd is opened O_RDONLY; a claim: the CDI device node has permissions r",
    "              (device cgroup). Both are enforced by the kernel, root or not",
    "sharing       a dax device only, the same serial on every node, one attachment per node",
    "cleanup       always: unprepare -> deallocate -> detach; the agent releases the leases of a container",
    "              that stopped for good, a timed-out lease cleans up after itself",
    "",
    "Timings of the recorded run (test13)",
    "  exclusive lease Ready                5.2 s after cxl-request, 6.3 s after the writer pod was created",
    "  writer exit -> all 3 readers hold    13.2 s (9.4 s in another run): ~6 s hot-remove, ~5 s scheduler poll",
    "  late exclusive request               Failed after its --wait 15s, nothing left behind",
    "  read-only claim on an attached node  Attached 0.1 s after the claim",
    "",
    "test13 goes on with pooled0 as a dax device: through a lease (cxl-request memory 256Mi --dax) on node-b,",
    "and through a claim with mode: dax on node-a, which found the bytes that the lease had written (chapter 2).",
])

s.card("the-end", "Where to look", [
    "nri-plugins, scripts/testing/fake-cxl-pool/",
    "  README.md                       the fake pool: server, client, controller",
    "  plan-2-dra/10-contract.md       the contract between the pool controller and the node's agent",
    "",
    "intel-resource-drivers-for-kubernetes",
    "  doc/cxl/POOL.md                 the DRA driver's pool support: claims, options, leases, cxl-request",
    "  deployments/cxl/pool/           DeviceClasses and example claims and pods",
    "",
    "nri-plugins, test/e2e/memory.test-suite/memory-policy/n4-cxl-shared-2/",
    "  test10-dra-pooling              chapter 1",
    "  test11-dra-sharing              chapter 4",
    "  test12-dra-live-attach          chapter 3",
    "  test13-dra-shared-one-writer-many-readers   chapters 2 and 5",
    "  each run writes trace-summary.txt: every component's log on one clock (dra-trace-summary)",
    "",
    "On screen node-a = VM1 n4-cxl-shared-1-fedora-43-containerd, node-b = VM2 n4-cxl-shared-2-fedora-43-containerd.",
])

s.finish()
