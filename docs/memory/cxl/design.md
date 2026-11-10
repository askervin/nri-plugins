# Design of the CXL DRA driver

CAUTION: experimental. Interfaces may change.

This page tells how `nri-dra-driver-cxl` works inside: the objects it
keeps, how a claim becomes memory that a container uses, how a restart
of the driver finds its way back, and which files it keeps on the node.
It is written for users who want to know what the driver does with their
devices and for maintainers who change it. [usage.md](usage.md) tells
how to deploy and use the driver; [states.md](states.md), generated from
the code, lists every state of every record and every transition that
the driver allows, with its trigger, guard and effects. This page links
to it for every state that it names.

- [The parts of the driver](#the-parts-of-the-driver)
- [The objects](#the-objects)
- [How a claim becomes memory](#how-a-claim-becomes-memory)
- [How memory is released](#how-memory-is-released)
- [How a restart recovers](#how-a-restart-recovers)
- [Files on the node](#files-on-the-node)

## The parts of the driver

One process on every node has these parts:

- Two kubelet plugins of one kind: `cxl.nri.io` for the memory of the
  node (local memdevs, regions, DRAM, the lease device) and the pool
  driver (`cxl-pool.nri.io` by default) for the devices of a CXL memory
  pool. They differ only in a few source rules: where the serial and the
  facts of a device come from (the node's own ResourceSlice for local
  devices, the claim status that the pool controller writes for pool
  devices), where their node mounts live, and whether they publish.
- The publisher, which writes the ResourceSlice of `cxl.nri.io` for the
  node. The pool driver publishes nothing: the pool controller does.
- The device engine, the one owner of every CXL kernel object that the
  driver makes on the node, for both drivers: regions, dax devices and
  their drivers, memory blocks, namespaces, block device flags, node
  mounts, loop devices and lease binds. Nothing else in the driver
  changes them. It reads and changes the kernel through one package that
  observes sysfs and runs the `cxl` and `ndctl` tools; dax devices are
  bound to their drivers through sysfs.
- The NRI plugin, the one writer of the `cpuset.mems` of containers:
  it keeps containers off the CXL memory that they did not claim
  (fencing), starts the steering of the containers that opt in, and
  lends NUMA nodes to running containers.
- The lease broker: the sockets of lease claims, the leases that running
  containers ask for on them, and the companion claims and pods that
  hold the memory of the leases.
- The provenance watcher, which tells pool devices from local memdevs by
  their serials.
- The store: one document, `state.json`, that holds every record of the
  driver that must outlive the process.

```
  kubelet --> cxl.nri.io plugin --+                 +--> kernel: sysfs, cxl, ndctl,
  kubelet --> pool plugin --------+--> engine ------+    mounts
                  |                     |  ^
                  |                     v  |
  runtime --> NRI plugin ------------> store (state.json)
                  ^                     ^
  container --> lease broker -----------+--> Kubernetes API: companions,
                                        |    ResourceSlices, ResourceClaims
  uevents, lists --> provenance --------+
```

## The objects

The driver's words for its objects, and how they relate. The kernel's
objects keep the kernel's words: memdev, region, dax device, memory
block, NUMA node, namespace, block device, mount.

### Memdev

A memdev is a CXL memory device of the node, `memN`, known by its serial
(the name `memN` changes with the probe order). The driver keeps a
[Memdev](states.md#memdev) record while it uses one: with its facts (RAM
and persistent capacity, shared, persistent, block size, host bridge),
the regions of the driver on it and its grants. A memdev with grants is
[ACTIVE](states.md#memdevstate); one whose region is kept without grants
(a configured shared device, a persistent device below newer regions) is
IDLE_KEPT; one that went away while grants exist (a pool device detached
under its claims) is GONE. A memdev of no grant and no region of the
driver has no record. How the kernel shows it is
[Memdev (kernel)](states.md#memdev-kernel).

### Region

A region maps the memory of one or more memdevs into the address space
of the host. The driver keeps a [Region](states.md#region) record of
every region on the memdevs it uses. A region of its own goes through
the [states](states.md#regionstate) NOTED (the name that
`cxl create-region` will give is written down first), CREATING, OWNED,
KEPT (disabled and kept: its release would leave a hole in the decoders
of a port, or it waits for the claim whose Prepare did not finish) and
HOLLOW_OWNED (its memdev went; deleted when its memory is offline). A
region that the driver did not create is never touched: it is published
as a `region` device when it is online RAM, and its memdevs are not
published as memdevs. On a memdev that the driver uses it gets a FOREIGN
record (a Prepare that it refuses, or a start, records it), and the
record goes with the region.

Linux commits the decoders of a CXL port in order: destroying a region
below a newer region of another memdev on the same host bridge or switch
leaves a hole, and no new region goes through that port until the
regions above are gone. So the release of a region follows a release
policy per kind of memdev, described in
[How memory is released](#how-memory-is-released).

### Dax device

A dax device (`daxN.M`) is a part of a region. The driver keeps it in
the region's record as a [DaxDevice](states.md#daxdevice) with the
grants that use it: the slice of one claim of a local memdev, or the
whole device of a shared memdev that every claim maps. Bound to `kmem`
its memory is system RAM of a NUMA node
([KMEM_ONLINE](states.md#daxdevicestate)); bound to `device_dax` it is a
device node that a container maps (DEVICE_DAX). `daxN.0` of a sliced
region stays as the SEED at size 0, which the kernel never deletes.

### Mount and bind

A mount is a node mount of the filesystem on the block device of a
persistent region, one per access (`direct` or `cached`), with the grants
that use it ([Mount](states.md#mount)). Containers of claims get a bind
of it at their `path`. It is read-write while a writer grant uses it and
read-only otherwise ([MOUNTED_RO, MOUNTED_RW](states.md#mountstate)). A
bind is the bind of a node mount into the `lease-fs` directory of a
lease claim, the lend of an `fs` lease ([Bind](states.md#bind)). A bind
whose unmount is busy (a file of it is mapped) is STALE and is unmounted
again later. A node mount whose unmount is busy fails the release, and
kubelet retries it.

### Grant

A grant is the memory that one allocation result of a claim gets on one
memdev ([Grant](states.md#grant)). It has three parts: what the result
asks for (mode, read-only, access, filesystem type, path, size, shares
or exclusive), its intent (what the driver may create for it: the noted
region name, the namespace, the mount path, the bind target, the lend)
and what it got (the region, the dax device, the NUMA node, the
namespace and block device, the mount, the bind, the lend). A grant
references the region, dax device and mount that it uses; those list
the grant among their users, so that several grants can share one
object. Its [states](states.md#grantstate): JOURNALED (the intent is
written), REALISING (kernel work in progress), REALISED (usable),
REALISED_UNRESTORED (its mount, dax or block device did not verify at a
start), RELEASING; a released grant is gone from the store.

### Preparation

A preparation is the record of one claim as one driver prepares it
([Preparation](states.md#preparation)), the record that kubelet's
prepared flag of the claim refers to. Its results say what each
allocation result of the driver got: a grant on a memdev, the capacity
of a region, the DRAM nodes, or a lease claim. The CDI devices, the
environment variables of the containers and the NUMA nodes that a
container has claimed are derived from the results. Its
[states](states.md#preparationstate): PREPARING (written before any
kernel object is touched), PREPARED, PREPARED_UNRESTORED, PREPARED_STALE
(prepared in another boot), UNPREPARING, and KEPT (not prepared, but a
region is kept for the claim).

### Leases and lease claims

A lease claim is a claim on the `lease` device of `cxl.nri.io`
([LeaseClaim](states.md#leaseclaim)): its socket, which its containers
have at `/run/cxl/cxl.sock`, its `lease-fs` directory, which they have at
`/run/cxl/fs`, and the pods it is reserved for. A lease is one request of
a running container for memory on that socket ([Lease](states.md#lease)),
known by 8 hex digits. Its memory comes from a companion claim
`cxl-lease-<id>` of a companion pod, which a driver prepares like any
claim; the lease owns its lend: the NUMA node lent to the requester's
`cpuset.mems`, the file descriptor passed to it, or the bind in its
`lease-fs` directory. The companion's grant records the lend too, so
that an Unprepare can revoke it also after the lease record is gone.

### Container and fence

The NRI plugin keeps a record of every container of the node in memory
([Container (in memory)](states.md#container-in-memory)): how the plugin
manages its memory (STEERED, FENCED or NONE, decided once when the
container is created), its own NUMA nodes, the nodes of its results and
the nodes lent to it. The record is built again from the runtime after a
restart. The fence is the set of NUMA nodes on which the driver onlined
CXL memory since it started: a FENCED container has its own nodes
without the fenced ones, plus the nodes of its results and leases. A
node joins the fence before its memory goes online, and the running
containers are updated before that (an update that takes longer than
the fence deadline finishes in the background); it leaves the fence
only when the driver restarts. A container whose memory a steering manager of the
driver writes has a [Steered](states.md#steered) record in the store, so
that the next process releases exactly the containers that its managers
throttled.

### Provenance

A memdev on the node is either a device of the node or a device of a
memory pool that a pool controller attached. The Kubernetes API does not
always tell: a pool controller deletes its ResourceSlices when it stops,
while its devices stay attached. The provenance of a serial
([Provenance](states.md#provenance)) is the driver's sticky knowledge of
it: POOL once a ResourceSlice or a claim of the pool driver names it (it
stays POOL until the serial was observed absent for 24 hours), LOCAL for
a device of the node, HELD for a new memdev whose source is uncertain,
which is not published for a while. The pools whose ResourceSlices the
driver has listed are kept as [ListedPool](states.md#listedpool)
records. An operator removes the provenance of a serial with
`--forget-pool-serial` ([local.md](local.md#what-the-plugin-publishes)).

### Probe

The address line probe runs on every new region of a local memdev of RAM
and finds memory that aliases. Its result, the usable size of the
memdev, is a fact about the hardware ([Probe](states.md#probe)), kept in
a file of its own, `localProbes.json`, outside the document.

### How they relate

```
  Preparation (claim uid, driver)
    results: grant | region | dram | lease claim
                |                         |
                v                         v
  Grant (claim uid, result index)     LeaseClaim (claim uid)
    serial --> Memdev                    <-- Lease (id): requester container,
    got:   --> Region                            companion claim, lend
                 dax devices, mounts
                 (users: grants)
  Provenance (serial): may a local grant use the memdev?
  Container: the NUMA nodes of the grants of its results and of its
             leases; the fence: the nodes kept away from the others
```

## How a claim becomes memory

Every Prepare of either driver goes the same way:

1. Validate. The `MemoryConfig` of every result is resolved and checked;
   the device must be in the last ResourceSlice that `cxl.nri.io`
   published (local devices) or have the status data that the pool
   controller wrote (pool devices). The companion claim of a lease must
   pass the companion gate: its name, namespace and owner must be those
   of the lease, and its device that of the lease. A refusal here touches
   nothing.
2. Write the intent. The preparation is committed as PREPARING with its
   results, durably, before any kernel object is touched.
3. Realise the grants. For each grant the engine first commits its
   intent (JOURNALED), then does the kernel work (REALISING), and commits
   every object it made before the next step that depends on it. A
   grant that is REALISED already and still verifies is reused, so that
   a Prepare again after a cut continues where the first one stopped.
4. Open the lease claim of a `lease` result: its socket and directories.
5. Write the CDI spec of the claim, and commit the preparation as
   PREPARED. Only then kubelet gets the result.

Then kubelet creates the containers. The CDI device of every result has
a marker variable; at CreateContainer the NRI plugin finds the results
of the container by their markers and sets its `cpuset.mems` or starts
its steering. A marker of a claim of another namespace, or of a lease
claim whose recorded `reservedFor` does not have the pod, is ignored with
a warning: a container cannot take the memory of another pod's claim by
setting the variable itself.

A Prepare that fails rolls back: it releases what its grants made, with
the release policy of a rollback. A region that it cannot release
without leaving a hole in the decoders stays for the claim, and the
preparation is KEPT: a Prepare again of the claim reuses the region,
its Unprepare releases it.

### A local memdev

On the first claim of a sliced memdev the engine notes the name of the
region to come, creates a RAM region over the memdev and, with
`verifyAddressing`, runs the address line probe on it (a region whose
memory aliases is made again with the usable size). Every claim gets a
slice of its own: a dax device of the region on whole memory blocks.
Mode `numa`: the NUMA node of the region joins the fence (the running
containers are updated first), the slice is bound to `kmem` and its
memory blocks are onlined movable. Mode `dax`: the slice is bound to
`device_dax` and zeroed before the claim gets it. A shared local device
has one dax device over the whole region, bound to `device_dax` and
zeroed once when the region is made; every claim maps it. Before any
kernel work on a local memdev, the engine checks that the memdev is not
a pool device: its provenance is not POOL or HELD, a fresh list of the
pool driver's ResourceSlices does not name it, and no pool grant uses
it. [local.md](local.md#what-prepare-does) has the details.

### A pool device

The pool controller attaches the device to the node before the claim is
prepared. The grant's intent and the POOL provenance of its serial are
committed together. The engine waits for the memdev to appear
(`--pool-prepare-timeout`), enables it when it has no driver after a
short grace, and creates a region over it. Mode `numa`: the node joins
the fence, and the memory blocks of the region are onlined movable as a
new NUMA node. Mode `dax`: the region's dax device is bound to
`device_dax`; the memory is never onlined and never zeroed (a shared
device has the same bytes on every host that has it).
[pool.md](pool.md#what-the-node-plugin-does) has the details.

### A persistent device

A persistent pool device and a persistent local memdev are prepared by
the same code. The engine creates a region of persistent memory, waits
for its nvdimm region, finds the fsdax namespace (a writable `block`
claim creates one when there is none) and its block device, which stays
read-only unless a writer grant uses it. Mode `block`: the container
gets the block device. Mode `fs`: the filesystem is mounted on the node,
once per access, at `mounts/<serial hex>-<access>` in the data directory
of the claim's driver, only when its type is in `fsTypes`; a `direct`
mount is verified to map the device's memory. The container gets a bind
of the node mount. A writer is allowed only when no other host may
write the device, or with a cluster filesystem on coherent memory. A
persistent device is never zeroed: its data and namespace labels outlive
the claims. [usage.md](usage.md#persistent-memory) has the rules.

### A lease

A container with a claim on `cxl-lease` asks on its socket with
`cxl-request`. The broker finds the requester's container from the
process id of the peer (through the container table of the NRI plugin,
for every request), checks the limits of the claim and the pod, and
commits the lease as CREATING before it creates any API object. Then it
creates the companion claim and pod (PENDING); the scheduler allocates
the claim, and kubelet asks the driver of the device to prepare it. The
companion gate passes the claim to the lease (LENDING), the grant is
realised like that of any claim, and at the end of the Prepare the lend
is made and the lease is READY: the NUMA node of a `numa` lease is added
to the requester's `cpuset.mems` through NRI, the file descriptor of a
`dax` or `block` lease is passed to the client, the node mount of an
`fs` lease is bound into the claim's `lease-fs` directory, where the
container sees it at `/run/cxl/fs/<name>`.
[leases.md](leases.md#flow) has the protocol and the flow.

### Regions and DRAM

A result on a `region` or the `dram` device needs no device work: the
claim consumes capacity, and its containers get the NUMA nodes for their
`cpuset.mems` or their steering.

## How memory is released

kubelet's Unprepare of a claim first closes its lease claims (their
leases are released) and, for a companion claim, revokes the lend and
unbinds the bind. Then the preparation is committed as UNPREPARING and
the engine releases each grant: it unmounts the node mounts that no other
grant needs (or makes a mount read-only when its last writer goes),
offlines the memory blocks of the grant, deletes its dax device, and,
when the grant was the last of its memdev, releases the region by the
release policy. A pool memdev is disabled after its region is
destroyed, so that the pool can hot-remove it. A step that fails (memory
that cannot be offlined, a busy mount) fails the Unprepare with every
record as it was; kubelet retries, and the retry finds out from the
kernel what still exists. A record is removed only by a successful write
of the document without it.

The release policy, by kind of memdev:

- A sliced local memdev: its region is destroyed with its last slice. A
  rollback or a recovery releases it in order only: one below a newer
  region of another memdev stays for its claim.
- A shared local device: its region stays while the device is in
  `sharedDevices`, zeroed only when it was made; once the device is no
  longer in `sharedDevices`, its region is destroyed with its last claim.
- A persistent local memdev: its region stays idle while regions of
  other memdevs lie above it, and is destroyed otherwise.
- A pool device: its region is destroyed with its last grant, also below
  newer regions, because a kept region would block the hot-removal of
  the device; the hole closes when the regions above go.

## How a restart recovers

A stop of the process cuts what is running: a Prepare between two of its
steps, a release, a lease request. Because every record is written
before the kernel objects it names are made, the next start knows what
may exist and finishes or undoes it. The start goes in this order:

1. Read the boot id and open the store: lock `state.lock`, read
   `state.json` (or `state.json.prev` when `state.json` cannot be read).
   At a first start, the state files of an older version are moved
   aside, or the start is refused when they name regions that exist
   ([usage.md](usage.md#upgrade)).
2. Recovery, phase 1, before NRI and before kubelet can call: observe
   the kernel; mount again the node mounts of the prepared claims, found
   by the identity of their block device, and verify their dax and block
   devices (a mismatch makes the claim PREPARED_UNRESTORED); bind the
   binds of prepared `fs` companions again; release what the grants of
   the Prepares that did not finish made, the top-most region first, or
   keep it by the release policy (the preparation stays PREPARING or
   becomes KEPT); unmount the mounts and binds under the driver's
   directories that no prepared claim lists; delete the dax devices of
   the driver's regions that no grant uses, and its hollow regions;
   write the CDI specs again from the records.
3. The first list of the pool driver's ResourceSlices, which gates the
   publication of local memdevs, and the fence: the NUMA nodes of the
   claims prepared in this boot.
4. The lease broker: the lease claims and leases of this boot, their
   sockets listened again.
5. The NRI plugin connects and synchronizes: the container records are
   built again from the runtime; the steering of running containers is
   not restarted, and the containers that the previous process steered
   get their `memory.high` back. The lends are wired, and phase 2 of the
   recovery keeps the `numa` companions whose Prepare did not finish for
   kubelet's Unprepare or Prepare again.
6. The kubelet plugins register, the ResourceSlice is published, the
   watchers and the periodic passes start (stale binds are unmounted
   again, the `cpuset.mems` of fenced containers repaired).

What a restart keeps, and what a reboot changes:

| record | restart of the driver | reboot of the node |
|:-------|:----------------------|:-------------------|
| preparation | kept; one whose Prepare did not finish stays PREPARING (or KEPT) for kubelet's retry | becomes PREPARED_STALE |
| grant | kept, verified | keeps what it asked for, forgets what it got |
| memdev, region | kept, matched with the kernel | dropped: nothing of them survives a reboot, and region names are given anew |
| lease | kept | dropped; the first reconcile deletes the companions |
| lease claim | kept, socket listened again | kept: kubelet prepares the claim again |
| provenance, listed pools | kept | kept |
| steered container | its container gets its `memory.high` back at the first Synchronize, which keeps the records of the new process's managers only | dropped at the first Synchronize: the containers are gone |
| probe results | kept (own file) | kept (own file) |

A stale preparation is the record of a claim prepared in another boot:
nothing of what its Prepare made exists any more, and the new boot gives
the names and numbers of those devices to other devices. It has no CDI
device and no NUMA node in the fence, and nothing is released for it at
start. kubelet prepares the claim again before it starts the pod's
containers, which makes a new preparation; or it unprepares it (the pod
went during the reboot), which disables a pool memdev that no claim of
this boot uses.

When neither `state.json` nor `state.json.prev` can be read, the driver
starts LOST instead of crash-looping: it writes nothing, releases
nothing, recovers nothing, fails every Prepare with the error of the
loss, starts the lease broker without leases, and holds back new
memdevs, since it does not know which are pool devices. An operator
starts it once with `--new-state` to begin with a new document
([usage.md](usage.md#upgrade)).

## Files on the node

Only the driver writes its files; do not edit them, and do not copy
them to another node. The flags `--forget-pool-serial`,
`--discard-old-state` and `--new-state` are the changes that an operator
makes. [usage.md](usage.md#files-on-the-node) lists every file with its
path.

- `state.json` in the plugin data directory of `cxl.nri.io` is the one
  document of both drivers. A change is a function of the document; the
  writer applies the pending changes in groups and writes each group
  once: a synced temporary file, the current file linked to
  `state.json.prev`, a rename, a synced directory. What must be on the
  disk before something happens outside (a response to kubelet or to a
  lease client, an NRI update, a kernel command that creates something)
  waits for that write; the rest does not. A failed write discards the
  group, and the driver never acts on what is not on the disk. The
  document has a schema number and is read strictly: a document of
  another schema, or with a field the driver does not know, cannot be
  read.
- `state.json.prev` is the document before the last write, read when
  `state.json` cannot be. `state.json.bad`, `state.json.lost` and
  `state.json.prev.lost` are documents that could not be read, kept for
  diagnosis.
- `state.lock` is locked by the running driver, so that a second
  process (the new pod of a rolling update) waits for the first one to
  exit.
- The view files of earlier versions (`preparedClaims.json`,
  `preparedClaimsInfo.json`, `localDevices.json`, `leases.json`, and
  `preparedPoolClaims.json` of the pool driver), marked with
  `"viewOf": "state.json"`, are removed at start; the driver writes no
  views. Tests and operators read `state.json`.
- `localProbes.json` holds the results of the address line probe, facts
  about the hardware that outlive every state of the driver.
- `leases/<claim uid>/cxl.sock` are the lease sockets and
  `lease-fs/<claim uid>` the directories of the binds of `fs` leases,
  owned by the lease broker; `mounts/` in the data directory of each
  driver holds its node mounts of mode `fs`. The start removes the
  directories that no record names, and unmounts what no prepared claim
  lists.
- The CDI specs `cxl-claims`, `cxl-leases` and `cxl-pool` in the CDI
  root are written from the records, and again at every start.
