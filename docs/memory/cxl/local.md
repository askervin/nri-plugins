# Local CXL memory devices

CAUTION: experimental. Interfaces may change.

A CXL memory device (memdev) attached to a node, at boot or by hotplug,
holds no usable memory until a region is created on it. The `cxl.nri.io`
driver of nri-dra-driver-cxl publishes such free devices in the node's
ResourceSlice and creates and destroys their regions on demand: every
claim gets a slice of a device, as memory of a NUMA node or as a devdax
device, slices of both kinds share a device, and a running container can
lease local memory and give it back
(`cxl-request request --source local --size 64Mi`, see
[leases.md](leases.md)). A device that the configuration declares shared
is not sliced: all its claims and leases map the same bytes, see
[Shared local devices](#shared-local-devices).

Regions that exist already (created by the BIOS or an admin, onlined as
RAM) are published as `region` devices
([usage.md](usage.md#devices-of-cxlnriio)); this document is about the
devices the plugin manages itself.

## What the plugin publishes

A memdev is published as a device of type `memdev` when it is enabled
(bound to the `cxl_mem` driver; the kernel enables a hotplugged memdev,
and the plugin never disables a local one), has RAM capacity, is not a
pool device (prepared by the pool driver, see [pool.md](pool.md)), is not
excluded by `ignoreDevices` (name, `cxl/memN`, `major:minor` or serial)
and has no region that the plugin did not create itself. A memdev listed
in `sharedDevices` is published as a shared device instead; the sections
up to [Shared local devices](#shared-local-devices) describe sliced
memdevs. A memdev with a
foreign region is left alone: its RAM region is a `region` device, a
foreign devdax region is not published. Destroy the region to let the
plugin manage the device.

Local and pool devices are told apart by serial. A memdev is a pool
device when the pool driver prepares it for a claim, or when its serial
is the `serial` attribute (or `<driver>/serial`) of a device in a
ResourceSlice of any DRA driver other than `cxl.nri.io`: a pool
controller publishes its devices before it attaches one to a node, so a
pool device is never offered as a local one, not even between its attach
and its Prepare, or when its pod never starts. The plugin lists the
ResourceSlices at every scan. When a list fails it keeps the serials of
the last successful one; until a list has succeeded it publishes no
`memdev` device at all (regions are published as usual), and it tries
again every 30 seconds while the list fails.

```yaml
- name: memdev-c100e2e1               # "memdev-" + serial in lower-case hex
  attributes:
    type:            {string: memdev}
    source:          {string: local}
    serial:          {string: "0xc100e2e1"}
    shared:          {bool: false}
    size:            {int: 1073741824}
    nodeAffinity:    {int: 0}
    memoryBlockSize: {int: 134217728}
  capacity:
    memory:
      value: 1Gi
      requestPolicy:
        default: 1Gi                  # the whole device
        validRange: {min: 128Mi, step: 128Mi}   # the memory block size
  allowMultipleAllocations: true
  nodeAllocatableResources: {memory: {mapping: {capacityKey: memory, capacityMultiplier: "1"}}}
```

| Attribute | |
|:--|:--|
| `type` | `memdev` |
| `source` | `local` (pool devices have `source: pool`) |
| `serial` | serial of the memdev, `0x` and lower-case hex, as the pool controller publishes serials |
| `shared` | `false`: every claim gets a slice of its own (`true` for a [shared local device](#shared-local-devices)) |
| `size` | RAM capacity of the memdev in bytes |
| `nodeAffinity` | CPU NUMA node of the memdev; absent if unknown |
| `memoryBlockSize` | memory block size of the node in bytes: every slice is a multiple of it |

Every slice, `numa` or `dax`, is a multiple of the memory block size of
the node, `/sys/devices/system/memory/block_size_bytes` (hex without
`0x`: `8000000` is 128 MiB; 128 MiB in the e2e VMs, up to 2 GiB on servers
with much RAM), and lies on whole memory blocks. Capacity `memory` is
what whole blocks of the device's region are sure to hold: the RAM
capacity rounded down to whole blocks. With blocks larger than 256 MiB
(the alignment of CXL regions in their window) a region can start up to
block size - 256 MiB after a block boundary, so that head is subtracted
first: floor((RAM - (block size - 256 MiB)) / block size) blocks. The
request policy makes the scheduler account exactly what the plugin
carves: requests are rounded up to the block size
(`requestPolicy.validRange` min and step); a request without an amount
consumes `requestPolicy.default`, the whole capacity. The API server
requires a `default` with a `validRange`, and a range needs room for its
`min` and one `step`: a capacity of one block has `validValues: [<block
size>]` instead. A memdev without the room for one whole block is not
published, and no memdev is published while the block size cannot be
read. `nodeAllocatableResources` maps the capacity to the node's memory as
for `region` devices (with the `DRANodeAllocatableResources` feature
gate only).

The option `manageMemdevs: false` of the
[configuration file](usage.md#configuration-file) (`-f`, the `config`
value of the Helm chart) turns all of this off: free memdevs are not
published and no regions are created.

## Modes

The DeviceClass `cxl-local` selects every local memdev that is not
shared (`shared == false`). Every claim of a
device gets a slice of its own, in one of two modes, and slices of both
modes share a device at the same time:

- `numa` (default): the slice is onlined as system RAM in movable memory
  blocks of the NUMA node N of the device. All `numa` slices of a device
  (and of the devices under one CXL host bridge) are on the same node N;
  the containers are isolated by NUMA node (`cpuset.mems`), not per slice.
- `dax`: the slice is a character device `/dev/daxX.Y` of its own.

The mode, and `readOnly` for `dax` slices, is a `DeviceConfig` of the
claim ([usage.md](usage.md#deviceconfig)):

```yaml
config:
- opaque:
    driver: cxl.nri.io
    parameters:
      apiVersion: cxl.nri.io/v1alpha1
      kind: DeviceConfig
      mode: dax          # numa (default) or dax
      readOnly: true     # dax only: the device node allows reads only
```

### Slices and memory blocks

A slice is a dax device of the device's devdax region. Memory that is
onlined as RAM must start and end at memory block boundaries (the kernel's
kmem driver adds only the whole blocks of a dax device). Because every
slice is a multiple of the block size, the kernel's first-fit placement of
dax devices keeps every slice and every free gap of a block-aligned region
block-aligned, also after releases (a slice larger than any gap gets
several ranges, each block-aligned). The plugin checks every range of
every slice, `dax` slices too, before it binds a driver
(`daxX.Y/mappingN`). A slice that first-fit placed across a block boundary
(a region that does not start at a block boundary) is deleted and created
again on the first whole free blocks of the region, combining several
free ranges if one is not enough (`daxX.Y/mapping`), so that the head and
tail of such a region are never used and no slice splits a block. The
plugin logs it, and a region that does not start at a block boundary when
it is created:

```
local: memdev mem1 (serial 0xc100e2e1): claim <uid>: slice dax0.2 at [0x...] is not aligned to the memory block size 536870912, placing it explicitly
local: memdev mem1 (serial 0xc100e2e1): region0 at 0x250000000-0x2cfffffff does not start at a memory block boundary (block size 536870912): slices use only its 1610612736 bytes of whole blocks
```

### Node size

The memory of node N is the sum of the online `numa` slices: N grows by
the block size for every block of a `numa` slice that is prepared, and
shrinks when the slice is released (N disappears from `numactl -H` or
has 0 kB when the last `numa` slice is gone). `dax` slices add nothing to
N. Capacity that no claim has stays offline. The containers whose claims
or leases are on N share it; `memory.max` and cgmpolmgr's quota of each
container (the slice size of its claims) bound what a container uses.

All regions under one CXL host bridge share one NUMA node (the node of
the host bridge's memory window): two memdevs under one host bridge are
one node to the containers.

### Claims

| | claim on `cxl-local` |
|:--|:--|
| 128Mi as NUMA memory | `exactly: {deviceClassName: cxl-local, capacity: {requests: {memory: 128Mi}}}` |
| a 128Mi dax slice | the same and a `DeviceConfig` with `mode: dax` |
| a read-only slice | a `DeviceConfig` with `mode: dax, readOnly: true` |
| a specific device | add `selectors: [{cel: {expression: 'device.attributes["cxl.nri.io"].serial == "0xc100e2e1"'}}]` |
| the whole device | no capacity request |
| a slice shared by pods | one ResourceClaim (not a template) that several pods reference |

Requests are rounded up to the memory block size (64Mi gets a 128Mi slice
with 128 MiB blocks). Pods that reference the same ResourceClaim land on
the node of the claim's device; kubelet prepares the claim once, so all of
them get the same slice.

Examples in [`deployment/samples/dra-driver-cxl`](tree:/deployment/samples/dra-driver-cxl):
[`local-numa.yaml`](blob:/deployment/samples/dra-driver-cxl/local-numa.yaml),
[`local-dax-readonly.yaml`](blob:/deployment/samples/dra-driver-cxl/local-dax-readonly.yaml),
[`local-dax-shared-claim.yaml`](blob:/deployment/samples/dra-driver-cxl/local-dax-shared-claim.yaml)
(two pods, one claim).

## What Prepare does

For every allocated `memdev` device of a claim:

1. The mode and read-only setting come from the `DeviceConfig`, the
   size from the allocation's consumed capacity (the whole device if
   there is none), rounded up to a multiple of the memory block size
   (the block size is read again for every slice). A region the plugin
   left without claims (after a restart) is destroyed first.
2. The first claim of a device creates a devdax region on the memdev.
3. The claim's slice: the region's dax device `daxX.0` when no slice uses
   it and kmem does not have it, else a new dax device of the dax region,
   placed first-fit by the kernel and checked for whole blocks (see
   above). A dax region with less free memory than the slice fails the
   Prepare with "no room for the slice" (the scheduler accounts the
   capacity: this is not expected).
4. `numa`: the slice is bound to kmem through sysfs, its memory blocks
   are onlined movable, and N is the slice's `target_node`. The claim has
   node N with the slice size as its total and consumed bytes: containers
   that reference it are steered to N exactly as for `region` devices
   ([usage.md](usage.md#steering)).
5. `dax`: the slice is bound to `device_dax`. The plugin writes zeros to
   the whole slice before the claim gets it, so a claim never reads what
   an earlier claim left there (this takes size / memory write bandwidth,
   about 30 ms for 64 MiB and 120 ms for 256 MiB of DRAM). A read-only
   slice has device node permissions `r`: the device cgroup refuses opens
   for writing, whatever the container's capabilities. Applications
   `mmap` the device (`MAP_SHARED`, aligned to the device alignment,
   2 MiB) and agree on the layout of the memory themselves.
6. The slice's CDI device `nri.io/cxl=claim-<claim uid>-<n>` (spec file
   `cxl-claims`, n the index of the allocation result in the claim) has
   the claim marker `CXL_CLAIM_<uid>=1`, the device node of a `dax` slice
   and the variables of [usage.md](usage.md#environment-variables):

   ```
   CXL_<KEY>_SERIAL=0x<serial>
   CXL_<KEY>_SHARED=0
   CXL_<KEY>_MODE=numa                (or dax)
   CXL_<KEY>_SIZE=<slice bytes>
   CXL_<KEY>_NODE=<N>                 (numa)
   CXL_<KEY>_DAX=/dev/daxX.Y          (dax)
   CXL_<KEY>_READONLY=0|1             (dax)
   ```

   `<KEY>` is the serial in upper-case hex without `0x`, `<serial>` in
   lower-case hex; the second and later slices of the same memdev in the
   claim have `<KEY>_2`, `<KEY>_3`, ... A container gets the devices of
   the requests it references only: of a claim with a read-write and a
   read-only request, a container that references the read-only one
   gets only the read-only device node.

A Prepare that fails releases what it took for the claim. Preparing a
claim that is prepared already touches no device. The plugin's use of the
devices is stored in `localDevices.json` in the `cxl.nri.io` plugin data
directory, with the mode of every slice.

Unprepare: a `numa` slice's memory blocks are offlined (only the blocks
of that slice), then the slice is unbound, set to size 0 and deleted
(`daxX.0` is kept with size 0); a `dax` slice is deleted the same way.
When the last slice of a device is gone, of either mode, its region is
destroyed. The memdev stays enabled (unlike a pool device): the device is
back in its initial state. An offline that
fails because pages cannot move fails the Unprepare and keeps the slice;
kubelet retries (the pages of other containers on the movable node
migrate on a later try). kmem is never unbound from memory that is not
offline: the kernel could not remove it, and it would stay online until a
reboot.

A slice whose release fails where no claim is left to retry it (a
restart's release of a claim that is not prepared, the rollback of a
failed Prepare, a dax device that belongs to no slice) is kept in the
state under the owner `-` (no claim UID is `-`). Such a slice is never
handed out again; the next Prepare on the device releases it first, and
fails with the release error while it cannot, and so does every restart.
The region stays while such a slice exists.

The plugin logs every step of a slice with its dax device, mode, size and
duration:

```
local: memdev mem1 (serial 0xc100e2e1): created region0 (devdax, dax dax0.0, node 2) in 112.031ms
local: memdev mem1 (serial 0xc100e2e1): claim <uid>: created slice dax0.1 mode numa size 134217728 at [0x258000000-0x25fffffff] in 3.208ms
local: memdev mem1 (serial 0xc100e2e1): claim <uid>: onlined slice dax0.1 mode numa size 134217728 blocks [75] node 2 in 41.002ms
local: memdev mem1 (serial 0xc100e2e1): claim <uid>: zeroed slice dax0.0 mode dax size 134217728 in 60.415ms
local: memdev mem1 (serial 0xc100e2e1): claim <uid>: offlined slice dax0.1 mode numa size 134217728 blocks [75] in 20.117ms
local: memdev mem1 (serial 0xc100e2e1): claim <uid>: deleted slice dax0.1 mode numa size 134217728 in 5.420ms
local: memdev mem1 (serial 0xc100e2e1): released region0 in 90.733ms
```

Restart: the state file is read again; regions are found by the memdev
serial and slices by name; a slice that is gone is dropped, the slices of
claims that are not in the prepared claims (`preparedClaimsInfo.json`)
are released (`numa` slices offlined first), and so are the slices of the
owner `-`, dax devices of the region that belong to no slice are deleted,
and a region of the plugin without claims is destroyed.
Regions do not survive a node reboot: the state file records the boot id
of the kernel (`/proc/sys/kernel/random/boot_id`), and the state of
another boot is dropped without touching any region, so that a region
that firmware or an admin created under the same name is never taken for
the plugin's. A `dax` slice that is gone gets no device node and no
`CXL_<KEY>_DAX` in its CDI device.

## Shared local devices

A local memdev that the [configuration file](usage.md#configuration-file)
lists in `sharedDevices` is not sliced. It is one devdax device of the
whole memdev that every claim and lease of the device maps: the same
bytes, zeroed by the plugin only when it creates the device's region,
mode `dax` only. A claim without a
`shares` request has the device exclusively (the writer of single-writer
data sharing); a claim with `shares: "1"` is one of its sharers (the
readers, usually `readOnly: true`). This is the model of shared pool
devices ([pool.md](pool.md)) on one node.

### Configuration

```yaml
sharedDevices: ["0xc100e2e1"]   # as ignoreDevices: memN, cxl/memN, major:minor, serial
```

An entry is matched as in `ignoreDevices`. The serial is the stable
form; `memN` changes with the probe order of the devices. A memdev
matched by more than one setting is used by the first of
`ignoreDevices`, pool device (its serial is in a pool ResourceSlice, or
the pool driver prepared it), `sharedDevices`, and is otherwise sliced. A
device of `sharedDevices` that is not published shared is logged with the
reason, once per memdev and reason when it is ignored or a pool device,
at verbosity 4 at every scan otherwise (no RAM capacity, disabled,
regions that the plugin did not create, slices of prepared claims):

```
- not publishing memory device "<memN>" as a shared local device: <reason>
```

The configuration is read at start: a change of `sharedDevices` takes
effect with a restart of the plugin (the Helm chart restarts the
DaemonSet when its `config` value changes). A device switches between
sliced and shared use only when it is idle: while claims of the other
use are prepared, the device is not published at all, and the plugin
keeps serving those claims ([Life cycle](#life-cycle-of-a-shared-local-device)).

### The published device

```yaml
- name: memdev-c100e2e1               # "memdev-" + serial, as every memdev
  attributes:
    type:         {string: memdev}
    source:       {string: local}
    serial:       {string: "0xc100e2e1"}
    shared:       {bool: true}
    size:         {int: 1073741824}   # RAM capacity of the memdev
    nodeAffinity: {int: 0}            # absent if unknown
  allowMultipleAllocations: true
  capacity:
    shares: {value: 1M}               # no requestPolicy: no request = all, "1" = one share
```

A shared device has no `memory` capacity (every allocation would consume
it), no `memoryBlockSize` (it has no slices) and no
`nodeAllocatableResources` (nothing is onlined). It is published when it
is enabled, has RAM capacity, is not a pool device, is not ignored, has
no region that the plugin did not create, and no slices of prepared
claims; the memory block size does not matter. `shares` has no request
policy: a claim that requests no shares consumes the whole value and is
the only holder of the device, a claim that requests `shares: "1"` is
one of up to 1M holders. Nobody needs to know the value.

### Claims of shared local devices

The DeviceClass `cxl-local-shared` selects shared local devices
(`cxl.nri.io`, `type == "memdev"`, `shared == true`); `cxl-local` never
offers them.

| | claim on `cxl-local-shared` |
|:--|:--|
| the device exclusively (the writer) | `exactly: {deviceClassName: cxl-local-shared}` and a `serial` selector, no capacity request |
| one share | the same and `capacity: {requests: {shares: "1"}}` |
| one share, read-only (a reader) | the same and a `DeviceConfig` with `readOnly: true` |
| one share for several pods | one ResourceClaim (not a template) that the pods reference |

The mode is `dax` with or without a `DeviceConfig` that says so. While an
exclusive claim holds the device, the scheduler allocates the device to
no other claim: the pods of waiting claims stay Pending. The environment
of each case is in [usage.md](usage.md#example-claims) (examples 13-15);
[local-shared-writer-readers.yaml](blob:/deployment/samples/dra-driver-cxl/local-shared-writer-readers.yaml)
has a writer and three readers. A running container leases the device
with `cxl-request request --serial 0xc100e2e1` (exclusively) or
`--serial 0xc100e2e1 --shared --read-only` (one read-only share), see
[leases.md](leases.md#cxl-request).

### What Prepare does for a shared device

1. The mode (`dax`) and `readOnly` come from the `DeviceConfig`; the size
   is that of the device's dax device. A claim that consumed less than one share is refused
   before any device is touched
   ([usage.md](usage.md#deviceconfig)).
2. The first claim of the device creates its devdax region. The region's
   dax device `daxX.0` is the shared device: bound to `device_dax`, the
   size of the region, never resized. The plugin writes zeros to the
   whole device when it creates the region, so that the first sharer
   never reads what earlier tenants of the memdev (slices, or the memory
   before a reboot) left there; this makes the first claim of a large
   device slower. When the zeroing fails, the new region is released
   again and the claim gets nothing. A region that exists already, kept
   from earlier claims, is used again and not zeroed.
3. The claim is recorded on the device in `localDevices.json`, with the
   dax device, mode, size and `readOnly`; the device entry says
   `"shared": true`.
4. The claim's CDI device `nri.io/cxl=claim-<claim uid>-<n>` has the
   claim marker, the variables of
   [usage.md](usage.md#environment-variables) with
   `CXL_<KEY>_SHARED=1` and `CXL_<KEY>_SIZE` the size of `daxX.0` (the
   region of the whole memdev), and
   the device node `/dev/daxX.0`, with permissions `r` for a read-only
   claim. Every claim of the device on the node has a CDI device of its
   own for the same device node.

Unprepare drops the claim and nothing else: the region, `daxX.0` and the
bytes stay. Pods that reference one claim share one share (kubelet
prepares the claim once); every claim of the device is a share of its
own, with its own `readOnly`.

The plugin logs every claim of a shared device (the last word is
`exclusive`, `1 share` or `<n> shares`), its release, and an idle device
whose region it keeps, the zeroing of a new region, and a region that
disappeared while the plugin ran:

```
local: memdev mem1 (serial 0xc100e2e1): zeroed new shared dax0.0 size 1073741824 in <t>
local: memdev mem1 (serial 0xc100e2e1): region0 of the shared device is gone, forgetting it and its claims [<uids>]
local: memdev mem1 (serial 0xc100e2e1): claim <uid> request mem: shared dax0.0 size 1073741824 read-only false exclusive
local: memdev mem1 (serial 0xc100e2e1): claim <uid>: released shared dax0.0, claims left [<uids>]
local: memdev mem1 (serial 0xc100e2e1): keeping region0 and dax0.0 of the idle shared device
```

and at start:

```
local: memdev mem1 (serial 0xc100e2e1): keeping shared region0 and dax0.0, claims [<uids>]
local: memdev mem1 (serial 0xc100e2e1): claim <uid> of the shared device is not prepared, dropping it
local: memdev mem1 (serial 0xc100e2e1): not configured shared any more: keeping region0 for claims [<uids>], not publishing the memdev until they are gone
local: memdev mem1 (serial 0xc100e2e1): not configured shared any more, releasing its region
```

Errors of the Prepare about shared use. The last three come from stale
allocations only: the scheduler never allocates such claims, because a
device is not published while it changes between sliced and shared use.
The two errors about the other use are prefixed with
`claim <ns>/<name>: device memdev-<hex>: `:

| case | error |
|:-----|:------|
| zeroing the new region of a shared device fails | `memdev <memN> (serial 0x<hex>): zeroing new shared dax0.0: <cause>` |
| a claim that consumed shares of a memdev that is not configured shared any more | `claim <ns>/<name>: request <req>: device 0x<serial>: allocated as a shared device, which it is not any more` |
| a claim of a shared device whose state has slices | `memdev <memN> (serial 0x<hex>): used as slices by claims [<uids>]; a shared device cannot be sliced` |
| a claim of a sliced device whose state is shared | `memdev <memN> (serial 0x<hex>): used shared by claims [<uids>]; a sliced device cannot be shared` |

### Life cycle of a shared local device

| event | what happens |
|:------|:-------------|
| the device appears, listed in `sharedDevices` | published shared; no region yet |
| first claim or lease | the devdax region is created, `daxX.0` bound to `device_dax` and zeroed once; mapped by the claim's containers or passed as an fd |
| more claims | the same `daxX.0`, each with its own CDI device or fd and its own `readOnly` |
| the region disappears while the plugin runs | the plugin forgets the region and its claims; the next claim creates a new region and zeroes it |
| an exclusive claim (no `shares` request) | no other claim is allocated until it is gone; waiting claims are Pending (Unschedulable) |
| the last claim is gone | the claim is dropped; the region, `daxX.0` and the bytes stay; the ResourceSlice is unchanged; `cxl list` shows the region on an idle node |
| plugin start, the device in `sharedDevices` | the state file of the same boot names the device shared with its region: the region is found by serial, `daxX.0` by name, both kept; claims that are not prepared are dropped. Without state nothing happens until the first claim |
| plugin start, the device not in `sharedDevices` | the state says shared: with prepared claims the device stays as it is and serves them, and is not published; without claims the region is destroyed, the state entry dropped, and the device is published as a sliced memdev at the next scan |
| plugin restart | as plugin start (the same boot) |
| node reboot | the region and the bytes are gone (volatile); the state of another boot is dropped without touching any region; the first claim creates the region again and zeroes it |
| hot-remove | refused by the kernel while the region exists: remove the device from `sharedDevices` and restart the plugin first; a device that is gone anyway is forgotten |
| the device joins `sharedDevices` | after the restart: not published while slices of prepared claims exist; published shared when idle, with no region until the first claim |

The memdev stays enabled. A shared device has no memory blocks and no
alignment rule of its own: it is the whole region as one `device_dax`
device, mapped with the 2 MiB alignment of devdax devices, and it does
not return to its initial state when idle.

## Limitations

- One region per device, no interleaving across devices.
- `numa` capacity is online per claim but not isolated per claim:
  `cpuset.mems` is per node, all containers with `numa` claims or leases
  on the node share its memory; `memory.max` and cgmpolmgr bound each.
- Slice sizes are multiples of the memory block size, also for `dax`
  slices: a 64Mi dax claim gets 128Mi with 128 MiB blocks, 2Gi with 2 GiB
  blocks.
- The memory of node N can be a little less than its `numa` slices when
  the kernel takes the struct pages of hotplugged memory from the memory
  itself (`memory_hotplug.memmap_on_memory`).
- With memory blocks larger than 256 MiB a device publishes one block
  less than its RAM capacity (for a RAM capacity of whole blocks): its
  region may start after a block boundary, and only whole blocks hold
  slices. An unaligned end needs no such room: it holds less than a block,
  which the rounding down excludes already.
- Two claims of one device in one container set the same
  `CXL_<KEY>_*` names (the device nodes of `dax` slices differ).
- With `DRANodeAllocatableResources`, a dax claim raises the container's
  memory limit by the slice size although dax memory is not charged to
  the cgroup.
- Leases of local memory have the limitations of every lease
  ([leases.md](leases.md#limitations)): memory limits of the requester,
  no `numa` lease for a steered container, SIGBUS after a release of a
  mapped dax fd.
- A region that an admin creates on a memdev while the plugin uses it is
  not published as a `region` device until the plugin has released the
  memdev: the plugin hides every region of the memdevs it uses.
- A memdev that is shared with other hosts but not managed by a pool
  controller looks like a local device. Onlining it as RAM corrupts the
  other hosts' data: exclude it with `ignoreDevices`, or declare it in
  `sharedDevices`: the plugin then never onlines it and shares it dax
  only; exclusivity across hosts is not coordinated by one node's plugin.
- Hot-removing a local device that is in use is not supported; the kernel
  refuses to remove a device with an online region.
- Shared local devices: the sharers are whoever may create a claim of
  `cxl-local-shared` on the node, and `readOnly` guards against writes,
  not reads. The bytes are zeroed only when the region is created: a
  claim reads what the last writer left, also after the device was idle.
  The region of a shared
  device stays while the device is configured shared, also with no
  claims. A shared device is `dax` only (a `numa` `DeviceConfig` fails),
  is never sliced and is volatile: modes `block` and `fs` are for pool
  devices of persistent memory only.

## Node requirements

- Kernel with CXL regions (`CONFIG_CXL_REGION`), `CONFIG_DEV_DAX`,
  `CONFIG_DEV_DAX_KMEM`, `CONFIG_MEMORY_HOTREMOVE`, and `CONFIG_FS_DAX`
  for the `dax` mode (without it every devdax `mmap` fails).
- The `cxl` (ndctl) tool. `daxctl` is optional: dax drivers are switched
  with `daxctl` when it is installed, else through sysfs; slices are made
  through sysfs. The container image of the driver has both; a host
  process needs them installed on the node.
- `/sys/devices/system/memory/auto_online_blocks` should be `offline`:
  the plugin onlines the blocks of `numa` slices movable itself (kmem is
  bound through sysfs, not with `daxctl`). Region creation also adds the
  whole region through kmem for a moment (the kernel binds the dax device
  of a new RAM region to kmem) before the plugin switches it to
  `device_dax`: with `online` the kernel onlines the whole region in a
  kernel zone, and the offline before the switch can fail.
- No udev rule that onlines hot-added memory, such as `40-redhat.rules`
  of RHEL, CentOS Stream and Fedora (override it, see
  [usage.md](usage.md#requirements)). Such a rule onlines the blocks of a
  new region after the plugin offlined them: the plugin offlines them
  again until they stay offline for 500 ms (logging `memoryN: online again
  after offlining it (auto-onlined by udev?)`) and fails the Prepare after
  30 s. The plugin never destroys a region whose memory is online after
  it is disabled (the kernel could not remove it): online memory without
  its region would read garbage.
