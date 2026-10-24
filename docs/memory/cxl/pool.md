# CXL memory pools: the cxl-pool.nri.io driver

CAUTION: experimental. Interfaces may change.

A CXL memory pool (a CXL switch with memory devices behind it, managed by
a fabric manager) can hot-add a memory device to a host and hot-remove it
again. With Dynamic Resource Allocation, such devices can be allocated to
pods like any other device: the scheduler picks a device and a node, a
*pool controller* attaches the device to that node, and the node plugin
makes the memory usable for the pod.

This document is the contract between the two sides:

- a **pool controller** (cluster level, one per pool): publishes the pool
  devices, attaches and detaches them, and reports the result in the
  claim status. It talks to the pool's management interface, so it is
  specific to the pool product. This repository does not include one for
  a pool product.
- **nri-dra-driver-cxl** (node level): next to its `cxl.nri.io` driver for
  node-local CXL memory, it registers a second DRA driver,
  `cxl-pool.nri.io`, that prepares hotplugged pool devices. It knows
  nothing about the pool: it only needs the device serial that the
  controller writes into the claim status.

A reference controller, `fake-cxl-pool-controller`, drives a qemu based
fake pool in
[`scripts/testing/fake-cxl-pool`](tree:/scripts/testing/fake-cxl-pool);
the e2e tests and [e2e.md](e2e.md) use it.

## Overview

```
 pool controller
   publishes a ResourceSlice of pool devices (driver cxl-pool.nri.io),
   attaches a device to the node the scheduler picked, with the settings
   of the pool section of the claim's MemoryConfig,
   writes claim.status.devices[] (condition Attached=True + data),
   detaches the device after the claim is deallocated.
 kube-scheduler
   allocates a pool device, pins the claim to a node (bindsToNode),
   waits for the binding condition, binds the pod.
 nri-dra-driver-cxl, driver cxl-pool.nri.io
   waits for the memory device with the serial from the claim status,
   creates a region on it as the device section says, returns CDI edits;
   on unprepare, releases the device so that the pool can hot-remove it.
```

Kubernetes v1.37 or later. Device binding conditions
(`DRADeviceBindingConditions`), device status (`DRAResourceClaimDeviceStatus`)
and consumable capacity (`DRAConsumableCapacity`) are used; they are on by
default in v1.37. Pool devices do not use `nodeAllocatableResources`.

## What the pool controller publishes

One cluster-scoped ResourceSlice (no node name) per pool under driver
`cxl-pool.nri.io`. A cluster that spans several pools has one controller
per pool, each publishing its own pool name under the same driver; the
reference controller names the pool after its server and confines itself
to that pool (resourceslice `Options.ReconcilePoolWithName`: without it, a
controller removes the slices of pools it does not know).

```yaml
apiVersion: resource.k8s.io/v1
kind: ResourceSlice
spec:
  driver: cxl-pool.nri.io
  pool: {name: fake-cxl-pool, generation: N, resourceSliceCount: 1}
  # the nodes the pool can reach; allNodes: true if every node can
  nodeSelector:
    nodeSelectorTerms:
    - matchExpressions:
      - {key: kubernetes.io/hostname, operator: In, values: [node1, node2]}
  devices:
  - name: pooled0                # device name, a DNS label
    attributes:
      type:   {string: memdev}
      source: {string: pool}
      serial: {string: "0xc1ee0001"}       # /sys/bus/cxl/devices/memN/serial, lower-case hex
      shared: {bool: false}
      persistent: {bool: false}
      size:   {int: 536870912}             # bytes
    capacity:
      memory: {value: 512Mi}               # exclusive devices only
    bindsToNode: true
    bindingConditions: ["cxl-pool.nri.io/Attached"]
    bindingFailureConditions: ["cxl-pool.nri.io/AttachFailed"]
  - name: shared0
    attributes:
      type:   {string: memdev}
      source: {string: pool}
      serial: {string: "0xc1ae0001"}
      shared: {bool: true}
      persistent: {bool: false}
      size:   {int: 268435456}
    allowMultipleAllocations: true
    capacity:
      shares: {value: 1M}                  # no requestPolicy
    bindsToNode: true
    bindingConditions: ["cxl-pool.nri.io/Attached"]
    bindingFailureConditions: ["cxl-pool.nri.io/AttachFailed"]
  - name: llm0                   # a shared device of persistent memory
    attributes:
      type:   {string: memdev}
      source: {string: pool}
      serial: {string: "0xc1ae0002"}
      shared: {bool: true}
      persistent: {bool: true}
      size:   {int: 536870912}
    allowMultipleAllocations: true
    capacity:
      shares: {value: 1M}
    bindsToNode: true
    bindingConditions: ["cxl-pool.nri.io/Attached"]
    bindingFailureConditions: ["cxl-pool.nri.io/AttachFailed"]
```

| attribute | value | |
|:----------|:------|:-|
| `type` | `memdev` | required |
| `source` | `pool` | required |
| `serial` | `0x` and lower-case hex | required: `/sys/bus/cxl/devices/memN/serial` of the device on the hosts |
| `shared` | bool | required: whether several hosts may have the device attached at a time; a shared device has a `shares` capacity |
| `persistent` | bool | required on every device: whether the device is persistent memory (the DeviceClasses test it, and a CEL selector that reads an attribute a device lacks fails) |
| `size` | bytes | required |

These are the attributes that `cxl.nri.io` publishes for local memdevs
too ([usage.md](usage.md#devices-of-cxlnriio)), so that selectors and
environment variables are the same for both sources, plus `persistent`.
The DeviceClasses select pool devices by `type`, `shared` and
`persistent`, the lease broker finds a
device by `serial` and reads its `shared`, and `cxl.nri.io`
never publishes a memdev whose serial a pool device has. A controller may
publish further attributes under a domain of its own (for example
`pool.example.com/model`); the reference controller publishes none.

- *Exclusive* devices (`shared: false`) are attached to one node at a
  time. Their size is the `memory` capacity, so claims can request an
  amount.
- *Shared* devices (`shared: true`) can be attached to several nodes at
  once; all of them see the same bytes. Never put the size of a shared
  device into `capacity`: every allocation would consume it. The size is
  an attribute. The capacity is `shares` without a `requestPolicy`, with
  the value 1M (`1000000`) when the pool has no limit of its own; a
  controller for devices with a head limit publishes the number of heads.
- `bindsToNode` makes the scheduler pin the claim to the node it picked.
  One claim covers one node, so N nodes sharing a device means N claims.
- A claim of a shared device without a `shares` request consumes the
  whole value and has the device exclusively: the scheduler allocates the
  device to no other claim until it is deallocated, and the controller
  attaches it exclusively, so that no other cluster sharing the pool gets
  it either (the reference controller makes an exclusive attachment of
  fake-cxl-pool). That is the writer of single-writer data sharing, see
  [Options of pool devices](#options-of-pool-devices). A claim with
  `capacity.requests.shares: "1"` is one host's share; nobody needs to
  know the value.
- *Persistent* devices (`persistent: true`), shared or not, keep their
  data and their namespace labels while no host has them attached. Every
  host that attaches a persistent device must see the same label storage
  area (LSA) as well as the same data: a host with a label storage of its
  own sees no namespace, or another one. fake-cxl-pool gives a persistent
  device a data file and an LSA file, both shared by every qemu that
  attaches it (`cxl-type3` with `persistent-memdev=` and `lsa=`).

## DeviceClasses and claims

Three classes of
[`templates/deviceclasses.yaml`](blob:/deployment/helm/dra-driver-cxl/templates/deviceclasses.yaml)
of the Helm chart select pool devices:

| class | selects | gets |
|:------|:--------|:-----|
| `cxl-pool` | `type == "memdev"`, `shared == false`, `persistent == false` | a whole exclusive pool device: a new NUMA node (default) or a devdax device (`mode: dax`) |
| `cxl-pool-shared` | `type == "memdev"`, `shared == true`, `persistent == false` | a shared pool device as devdax: exclusively (no capacity request), or one share with `capacity.requests.shares: "1"` |
| `cxl-pool-persistent` | `type == "memdev"`, `persistent == true` | a pool device of persistent memory, shared or not: its block device (`mode: block`) or a read-only erofs filesystem (`mode: fs`), see [usage.md](usage.md#persistent-memory) |

Claims:

```yaml
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata: {name: pooled-memory}
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: cxl-pool
        capacity: {requests: {memory: 512Mi}}     # a device with at least this much
---
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata: {name: shared-memory}
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: cxl-pool-shared
        selectors:
        - cel: {expression: 'device.attributes["cxl-pool.nri.io"].serial == "0xc1ae0001"'}
        capacity: {requests: {shares: "1"}}       # one share; without it: exclusive
```

Complete examples with pods:
[pool-numa.yaml](blob:/deployment/samples/dra-driver-cxl/pool-numa.yaml),
[pool-dax.yaml](blob:/deployment/samples/dra-driver-cxl/pool-dax.yaml),
[pool-shared-writer-readers.yaml](blob:/deployment/samples/dra-driver-cxl/pool-shared-writer-readers.yaml),
[pool-persistent-erofs.yaml](blob:/deployment/samples/dra-driver-cxl/pool-persistent-erofs.yaml),
[local-then-pool-dax.yaml](blob:/deployment/samples/dra-driver-cxl/local-then-pool-dax.yaml)
(local memory if a local memdev has room, else pool memory).

### Options of pool devices

An opaque configuration of driver `cxl-pool.nri.io`, kind `MemoryConfig`
(apiVersion `cxl.nri.io/v1alpha1`, the same as for `cxl.nri.io`, see
[usage.md](usage.md#opaque-configurations)), has three sections: `device`
selects how the node plugin prepares a pool device, `container` how the
containers that use it are managed (steering, as for local memory), and
`pool` the settings of the pool controller
([Configuration of a pool controller](#configuration-of-a-pool-controller)).
Entries of the DeviceClass and of the claim merge field by field, the
claim's last, and apply to the requests they list, or to all requests of
the driver ([usage.md](usage.md#merge-order)):

```yaml
spec:
  devices:
    requests: [...]
    config:
    - opaque:
        driver: cxl-pool.nri.io
        parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, device: {mode: dax, readOnly: true}}
```

An opaque configuration of `cxl-pool.nri.io` of another kind fails the
Prepare with `unknown kind "..." (MemoryConfig)`.

| field | values | |
|---|---|---|
| `device.mode` | `numa`, `dax`, `block`, `fs` | `numa`: the memory becomes a NUMA node (exclusive devices only, their default). `dax`: a devdax device `/dev/daxX.Y` that containers `mmap` (the default and only mode of shared devices). Devices of persistent memory have `block` and `fs` only, and no default ([usage.md](usage.md#persistent-memory)). |
| `device.readOnly` | `false`, `true` | `dax`, `block`: the container gets the device node with CDI permissions `r`, so its device cgroup lets it open the device for reading only. `fs`: required. |
| `device.access` | `direct`, `cached` | `fs` only, default `direct`: file pages in the device (DAX) or in the page cache of the node |
| `device.path` | absolute path | `fs` only, default `/run/cxl-fs/<KEY>`: where the filesystem is in the container |
| `container.steering` | | mode `numa`: the steering of the containers that use the device, default policy `none` ([usage.md](usage.md#steering)) |
| `pool.opaque.<key>` | an object | the settings of the pool controllers with controller key `<key>`, for example `fake-cxl-pool: {numaNode: 1}` ([Configuration of a pool controller](#configuration-of-a-pool-controller)) |

So every pool device can be used as a dax device: shared devices always,
exclusive devices with `mode: dax`. A claim of a shared device without a
capacity request has it exclusively; a share is `shares: "1"`:

| pool device | claim | gets |
|---|---|---|
| exclusive | (nothing) | a NUMA node |
| exclusive | `device.mode: dax` | a dax device of its own |
| shared | `capacity.requests.shares: "1"` | a dax device, shared with the other claims of the device |
| shared | (nothing) | a dax device, nobody else has the device meanwhile |
| shared or exclusive dax | `device.readOnly: true` | the dax device, read-only |

Read-only is enforced by the kernel for every process of the container,
whatever its capabilities, except in privileged containers (their device
cgroup allows everything). It is a property of the claim, not of the
device: another claim of the same device may write, and the readers see
it. It keeps readers from writing by mistake; consistency of the data is
the job of exclusive access. Pool appliances have no read-only attach
either (UnifabriX Maxview 2.0 has none): whatever a host attaches, it can
write.

Single-writer data sharing: the writer claims the shared device without
a capacity request (exclusively) and writes; the readers claim one share
each (`shares: "1"`) with `device.readOnly: true`. A
reader that asks while the writer has the device waits (its pod or lease
stays pending) until the writer's claim is deallocated: the writer's pod
has finished or is deleted, or its lease is released.
[e2e.md](e2e.md#example-f-a-shared-file-one-writer-three-readers) shows it
with a file that one writer stores in a shared device and three readers
read in place.

## What the scheduler does

Nothing to configure. The scheduler tries pools without binding
conditions first, so node-local `cxl.nri.io` devices win when they
satisfy a request. Devices of a pool are considered on the nodes of its
nodeSelector only, so a pod whose claim can be satisfied by several pools
lands on a node that reaches one of them with a free device. It writes
`status.allocation` (results with driver, pool, device and the binding
conditions; `shareID` and `consumedCapacity` for shared devices) with
`nodeSelector` = the picked node, emits the pod event
`BindingConditionsPending` and checks the claim every few seconds until
the binding timeout (default 600 s). If a failure condition becomes True
or the timeout expires, the claim is deallocated and allocated again.

## What the pool controller writes

After the pool has attached the device to the node, the controller adds
an entry to `claim.status.devices` (`UpdateStatus` on the `/status`
subresource):

```yaml
status:
  devices:
  - driver: cxl-pool.nri.io
    pool: fake-cxl-pool
    device: shared0
    shareID: <from the allocation result, shared devices only>
    conditions:
    - type: cxl-pool.nri.io/Attached
      status: "True"
      reason: Attached
      message: "shared0 attached to node1"
      lastTransitionTime: <now>
    data:
      serial: "0xc1ae0001"       # REQUIRED: string, 0x hex or decimal
      shared: true               # REQUIRED
      size: 268435456            # REQUIRED, bytes
      # anything else is informational; the reference controller adds:
      host: node1
      hostUUID: <the host's uuid>
      attachment: shared0@node1
      qemuDeviceId: <qemu device id>
      exclusive: true            # only when the allocation consumed the whole shares value
      persistent: true           # only for a device of persistent memory
```

The node plugin matches the entry by (driver, pool, device): several
pools under one driver need no change. It reads
only `serial`, `shared`, `size`, `exclusive` and `persistent` from
`data`; a missing `exclusive` or `persistent` is `false`. `exclusive`
lets a `block` claim of a shared persistent device write; `persistent`
selects modes `block` and `fs`.

On failure the controller sets `cxl-pool.nri.io/AttachFailed` to True
instead (reasons used by the reference controller: `NoHost`,
`AttachError`, `Timeout`, `Conflict`; `InvalidConfig` for an invalid
`MemoryConfig` or controller object, which every controller uses, see
[Configuration of a pool controller](#configuration-of-a-pool-controller))
and detaches anything that was half attached for the result. A result
whose status entry is `Attached` already keeps its attachment, also when
its configuration is found invalid (the device may be in use); otherwise
the controller detaches a device only after the claim has been
deallocated.

RBAC of the controller:

```yaml
rules:
- {apiGroups: [resource.k8s.io], resources: [resourceslices], verbs: [get, list, watch, create, update, patch, delete]}
- {apiGroups: [resource.k8s.io], resources: [resourceclaims], verbs: [get, list, watch]}
- {apiGroups: [resource.k8s.io], resources: [resourceclaims/status], verbs: [get, patch, update]}
- {apiGroups: [resource.k8s.io], resources: [resourceclaims/driver], verbs: ["arbitrary-node:patch", "arbitrary-node:update"], resourceNames: ["cxl-pool.nri.io"]}
- {apiGroups: [""], resources: [nodes], verbs: [get, list, watch]}
- {apiGroups: [""], resources: [events], verbs: [create, patch]}
```

## Configuration of a pool controller

A claim configures its pool controller in the `pool` section of the
`MemoryConfig` entries of the pool driver. This section is for
implementers of pool controllers other than the reference
fake-cxl-pool-controller.

**Where.** The configuration of an allocation result is in
`claim.status.allocation.devices.config`: the entries with
`opaque.driver` = the controller's driver (`cxl-pool.nri.io`), copied
there by the scheduler from the DeviceClass (`source: FromClass`) and the
claim (`source: FromClaim`). Entries of other drivers are not the
controller's.

**Resolution.** For each allocation result of its pool, the controller
takes the entries of its driver whose `requests` are empty, list the
result's request, or list the main request `r` of a subrequest `r/s`;
class entries first, then claim entries, each in list order. Each entry is
decoded strictly (kind `MemoryConfig`, apiVersion `cxl.nri.io/v1alpha1`,
no unknown fields), and the parameters merge as a JSON merge patch
(objects field by field, scalars and lists replace, `null` removes). This
is the same rule as the node driver's,
[usage.md](usage.md#merge-order).

**The controller key.** `pool.opaque` is a map from controller key to an
object that the controller with that key defines:

```yaml
pool:
  opaque:
    fake-cxl-pool: {numaNode: 1}       # the reference controller
    example.com/appliance: {port: 3}   # another implementation
```

A controller has one key (a flag or setting of its own, unique per
implementation; all controllers of one implementation share it), reads
only the object under it, and ignores the other keys: a claim may carry
settings for several implementations. The objects merge per key across
the class and claim entries, so a class may give defaults that a claim
overrides field by field. Version the object yourself if it needs a
version (a field in it); the outer apiVersion stays `cxl.nri.io/v1alpha1`.
No generic field next to `opaque` exists yet; the node driver refuses
unknown ones and never looks into the objects.

**Not yours.** The `device` and `container` sections belong to the node
driver (how the device is prepared, how containers are managed). A
controller does not interpret them.

**Errors.** An invalid `MemoryConfig` entry of the driver (also one of
another request of the claim, which fails the node's Prepare anyway) or
an invalid object under the controller's key attaches nothing. The status
entry of the result gets `<driver>/AttachFailed=True` with reason
`InvalidConfig` and the error as the message; the scheduler deallocates
and allocates again until the binding timeout, as for other attach
failures. Leave no attachment behind for the result, and do not let the
failure flap: the allocation, and so its configuration, does not change,
so the same answer is given on every reconcile. A configuration error is
final for the allocation; because the condition goes away with the
deallocation, an event on the claim with the same message helps users.

**Go.** Controllers in Go call pkg/cxl/config
([source](tree:/pkg/cxl/config)):

```go
import "github.com/containers/nri-plugins/pkg/cxl/config"

type Settings struct { // the controller's object, decoded strictly
	Slot     string `json:"slot,omitempty"`
	NumaNode *int   `json:"numaNode,omitempty"`
}

// for each allocation result r of the pool
if err := config.CheckEntries(claim, driver); err != nil { ... } // every entry of the driver
res, err := config.Resolve(claim, driver, r.Request)               // the merged MemoryConfig of the result
var s Settings
found, err := config.PoolOpaque(res, key, &s)                     // pool.opaque.<key>, other keys ignored
// any err: AttachFailed=True, reason InvalidConfig, message err.Error()
```

The error texts start with `MemoryConfig: `, for example
`MemoryConfig: FromClaim config 1: json: unknown field "x"` or
`MemoryConfig: pool.opaque.fake-cxl-pool: json: unknown field "port"`.
`Resolve` also validates the values of the `container` section (an
invalid steering policy fails it); it checks no device fields.

**The reference controller.** fake-cxl-pool-controller has the key
`fake-cxl-pool` (flag `-config-key`) and the object:

| field | type | |
|:--|:--|:--|
| `slot` | string | an exact CXL slot (bus name) of the host, as the pool server lists them; the server refuses another one (`AttachError`) and an occupied one (`Conflict`) |
| `numaNode` | integer >= 0 | prefer the free slots of host bridges on that NUMA node of the host |

Both go into the server's attach request. A claim that wants its pool
memory near NUMA node 1 of the host:

```yaml
spec:
  devices:
    requests:
    - name: mem
      exactly: {deviceClassName: cxl-pool}
    config:
    - requests: [mem]
      opaque:
        driver: cxl-pool.nri.io
        parameters:
          apiVersion: cxl.nri.io/v1alpha1
          kind: MemoryConfig
          pool:
            opaque:
              fake-cxl-pool: {numaNode: 1}
```

An invalid object, such as `fake-cxl-pool: {port: 3}`, gives
`AttachFailed` reason `InvalidConfig`, message `MemoryConfig:
pool.opaque.fake-cxl-pool: json: unknown field "port"`, a Warning event
`AttachFailed` with that message on the claim, and the controller log
line `ERROR: claim <ns>/<name>: request <request> device <device>: invalid
configuration: <error>`. The settings place a new attachment only: an
attachment that exists already (a shared device attached for another
claim on the node, or found after a restart) stays in its slot, because
the device may be in use; the `Attached` message names the slot.

## What the node plugin does

nri-dra-driver-cxl registers the `cxl-pool.nri.io` driver with kubelet
(socket `/var/lib/kubelet/plugins/cxl-pool.nri.io/dra.sock`). It never
publishes ResourceSlices.

| Flag | Environment | Default | |
|:-----|:------------|:--------|:-|
| `--pool-driver-name` | `POOL_DRIVER_NAME` | `cxl-pool.nri.io` | empty disables the pool driver (Helm value `pool.driverName`) |
| `--pool-prepare-timeout` | `POOL_PREPARE_TIMEOUT` | `30s` | how long to wait for the memory device to appear (Helm value `pool.prepareTimeout`) |

NodePrepareResources, for each allocated device of the driver:

1. Read `serial`, `shared`, `size`, `exclusive` and `persistent` from
   the claim status entry. A missing entry or missing data is an error;
   kubelet retries. An allocation of a shared device that consumed less
   than one share fails ([usage.md](usage.md#configuration-errors)).
2. Resolve the `MemoryConfig` of the result: the entries of the driver
   in the class and the claim that apply to its request, merged
   ([usage.md](usage.md#merge-order)); an invalid one fails the Prepare
   ([usage.md](usage.md#configuration-errors)). The plugin reads the
   `device` and `container` sections, and checks only the structure of
   `pool`.
3. Wait until a CXL memory device with the serial appears
   (`/sys/bus/cxl/devices/memN/serial`).
4. Mode `numa` (exclusive devices): create a ram region on it under the
   root decoder of its host bridge, bind the dax device to `kmem`, online
   all memory blocks `online_movable` (movable, so that the memory can be
   removed again). The memory becomes a new NUMA node N.

   A container that uses the device is steered to N like to local CXL
   memory when it opts in (`container.steering`, quota the device size,
   [usage.md](usage.md#steering)). Otherwise its memory policy is left
   alone: with `defaults.container.fencing` `allowed-mems` (the default),
   N is added to its `cpuset.mems` next to its other nodes (a container
   whose cgroup allows only ZONE_MOVABLE memory cannot start), and the
   other containers do not get N; they are updated before the memory
   goes online. With `none` no `cpuset.mems` is changed, and every
   container without its own `cpuset.mems` may allocate from N
   ([usage.md](usage.md#containers-without-claims)). Workloads use the
   node number from the environment, for example with `numactl` or
   `mbind`.

   Mode `dax` (shared devices, and exclusive devices with `mode: dax`):
   create a ram region, bind the dax device to `device_dax`. The memory
   is never onlined: two kernels using the same bytes as RAM would corrupt
   each other. The container gets the device node `/dev/daxX.Y`, with
   permissions `r` for a read-only claim. Applications `mmap` the device
   (`MAP_SHARED`, aligned to the device alignment, typically 2 MiB) and
   agree on the layout of the memory themselves.

   Modes `block` and `fs` (devices of persistent memory): create a pmem
   region under a root decoder for persistent memory, find the fsdax
   namespace with map `mem` of its nvdimm region (a writable `block` claim
   creates it if there is none), and give the container its block device
   or the read-only bind of the node mount of its erofs, see
   [usage.md](usage.md#persistent-memory).
5. Return the device's CDI device `nri.io/cxl-pool=claim-<claim uid>-<n>`
   (spec file `cxl-pool`, n the index of the allocation result in the
   claim) with the marker `CXL_CLAIM_<uid>_<n>=1`, the device node of a
   `dax` device and the variables of
   [usage.md](usage.md#environment-variables):

   ```
   CXL_<KEY>_SERIAL=0x<serial>
   CXL_<KEY>_SHARED=0|1
   CXL_<KEY>_MODE=numa|dax
   CXL_<KEY>_SIZE=<bytes>
   CXL_<KEY>_NODE=<N>                 (numa)
   CXL_<KEY>_DAX=/dev/daxX.Y          (dax)
   CXL_<KEY>_PATH=/dev/pmemK|<dir>    (block, fs)
   CXL_<KEY>_ACCESS=direct|cached     (fs)
   CXL_<KEY>_READONLY=0|1             (dax, block, fs)
   ```

   `<KEY>` is the serial in upper-case hex without `0x` (`<KEY>_2`, ...
   for a second device with the same serial in the claim), `<serial>` in
   lower-case hex. A container gets the devices of the requests it
   references only; by the marker the NRI plugin finds the results that
   a container uses, and their settings and memory. A companion
   claim of a lease gets no CDI device ([leases.md](leases.md)). The
   prepared claim is stored in
   `/var/lib/kubelet/plugins/cxl-pool.nri.io/preparedPoolClaims.json`.
   A repeated prepare of a prepared claim returns the stored result; a
   region that already exists on the device (another claim on this node
   for the same shared device, or a restart) is reused. A claim that wants
   a device in another mode than another claim on the node prepared it
   (or as exclusive when it is shared) fails. If preparing one
   device of a claim fails, the devices prepared for it are released
   again.

NodeUnprepareResources: unmount the node mount of mode `fs` that no other
prepared claim on the node uses (a busy mount fails, kubelet retries);
when no other prepared claim on the node uses the device, wait until
nothing holds the block device of a persistent device, offline its
memory (mode `numa`), disable and destroy its region and disable the
memory device. This is what lets the pool hot-remove it.
A device that is already gone is not an error.

The `cxl.nri.io` driver publishes neither a memory device that the pool
driver prepared or whose serial a pool controller publishes, nor a region
on such a device, so pool memory is not offered twice
([local.md](local.md#what-the-plugin-publishes)).

## Leases

A running container can lease a pool device without a claim of its own:
`cxl-request request --source pool --size 512Mi` in a container with a
claim on `cxl-lease` makes the node plugin allocate the device for a
companion pod and lend it to the container, as a NUMA node or as an open
dax file descriptor. A device of persistent memory is lent in mode
`block`, as an open file descriptor of its block device
(`cxl-request request --serial ... --mode block`, the writer, or
`--shared --read-only --mode block`), or in mode `fs`: its read-only erofs
filesystem is mounted into the running container at `/run/cxl/fs/<name>`
(`cxl-request request --serial ... --shared --read-only --mode fs`). See
[leases.md](leases.md).

## Node requirements

- `cxl` (ndctl) and `daxctl` command line tools, and `ndctl` for devices
  of persistent memory. The container image of the driver includes them;
  a host process
  ([usage.md](usage.md#as-a-host-process)) needs them installed on the
  node.
- Kernel with CXL regions (`CONFIG_CXL_REGION`), `CONFIG_DEV_DAX`,
  `CONFIG_DEV_DAX_KMEM`, `CONFIG_FS_DAX` (devdax mmap) and
  `CONFIG_MEMORY_HOTREMOVE`; for devices of persistent memory
  `CONFIG_CXL_PMEM`, `CONFIG_LIBNVDIMM`, `CONFIG_BLK_DEV_PMEM`,
  `CONFIG_ND_PFN`, `CONFIG_EROFS_FS` and `CONFIG_BLK_DEV_LOOP`.
- `/sys/devices/system/memory/auto_online_blocks` should be `offline`,
  so that the kernel never onlines shared devices as RAM on its own, and
  no udev rule may online hot-added memory (`40-redhat.rules` of RHEL and
  its derivatives does, see [usage.md](usage.md#requirements)).

## Ordering and failure semantics

- Attach before bind: the controller sets Attached only after the pool
  confirmed the attachment. NodePrepare then normally finds the memory
  device already present, or waits for it briefly.
- Release before detach: kubelet calls NodeUnprepare while it terminates
  the pod, before the pod object is gone; the claim is deallocated only
  after that, and the controller detaches only deallocated devices.
- **Force deletion hazard**: `kubectl delete pod --force --grace-period=0`
  removes the pod object at once. The claim may then be deallocated and
  the device detached while the node still uses the memory. The host
  cannot complete the hot-remove; the device stays half removed until the
  host reboots. This is not handled; do not force-delete pods that use
  pool memory.
- A second exclusive claim while all devices are taken stays pending in
  the scheduler (no device); it is not a failure.
- Controller restart: the controller recomputes the attachments from the
  claims and the pool, and re-confirms existing ones.
- Node plugin restart: the prepared claims file restores the prepared
  devices; regions are found again by serial.
- `cxl create-region` right after a hotplug can fail once with
  "add_dev() failed"; the pool driver retries a region creation once
  after 3 s.
