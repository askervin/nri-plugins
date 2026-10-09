# WS1: the cxl-pool.generic contract (node plugin <-> pool controller)

Status: v1 2026-10-06 (Fable). Agent A copies this, edited for an external
reader, to intel-resource-drivers-for-kubernetes/doc/cxl/POOL.md. Agents A, B
and C implement exactly this; deviations are recorded here as "Deviations".
Background: ../plan/10-design-pooling-dra.md sections 4 and 5 (the design),
../plan/11-research-cohdi-kep5007.md sections 1.2-1.7 (verified API facts).

## 1. Actors

```
 pool controller (any: fake-cxl-pool-controller, Maxview based, CoHDI based)
   publishes a cluster-scoped ResourceSlice of pool devices under driver
   cxl-pool.generic, attaches a device to the node the scheduler picked,
   writes claim.status.devices[] (Attached=True + data), detaches when the
   claim is deallocated.
 kube-scheduler
   allocates a pool device, pins the claim to a node (bindsToNode), waits
   for the binding condition, binds the pod.
 kubelet-cxl-plugin (node)
   helper 1, driver cxl.generic: node-local regions and DRAM (unchanged).
   helper 2, driver cxl-pool.generic: waits for the hotplugged memdev with
   the serial from the claim status, creates its region, returns CDI edits;
   releases the device in Unprepare so that the pool can hot-remove it.
```

## 2. ResourceSlice published by the controller

```yaml
apiVersion: resource.k8s.io/v1
kind: ResourceSlice
spec:
  driver: cxl-pool.generic
  pool: {name: fake-cxl-pool, generation: N, resourceSliceCount: 1}
  allNodes: true                 # or a nodeSelector; never nodeName
  devices:
  - name: pooled0                # pool device name, as a DNS label
    attributes:
      source: {string: pool}
      pool:   {string: default}            # the server-side pool
      serial: {string: "0xc1ee0001"}       # /sys/bus/cxl/devices/memN/serial, lower-case hex
      shared: {bool: false}
      size:   {int: 536870912}             # bytes
    capacity:
      memory: {value: 512Mi}               # exclusive devices only
    bindsToNode: true
    bindingConditions: ["cxl-pool.generic/Attached"]
    bindingFailureConditions: ["cxl-pool.generic/AttachFailed"]
  - name: shared0
    attributes:
      source: {string: pool}
      pool:   {string: default}
      serial: {string: "0xc1ae0001"}
      shared: {bool: true}
      size:   {int: 268435456}
    allowMultipleAllocations: true
    capacity:
      hosts: {value: "4", requestPolicy: {default: "1", validValues: ["1"]}}  # max attached nodes
    bindsToNode: true
    bindingConditions: ["cxl-pool.generic/Attached"]
    bindingFailureConditions: ["cxl-pool.generic/AttachFailed"]
```

Rules: a shared device never puts its memory size into `capacity` (every
allocation would consume it); size is an attribute. One claim covers one
node (bindsToNode), so N nodes sharing a device means N claims, each taking
one `hosts` unit. Device names: lower-case, `[a-z0-9-]`, max 63 chars.

## 3. DeviceClasses (shipped in the driver repository)

```yaml
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata: {name: cxl-pool-memory}
spec:
  selectors:
  - cel: {expression: 'device.driver == "cxl-pool.generic" && device.attributes["cxl-pool.generic"].shared == false'}
---
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata: {name: cxl-shared-memory}
spec:
  selectors:
  - cel: {expression: 'device.driver == "cxl-pool.generic" && device.attributes["cxl-pool.generic"].shared == true'}
```

Example claims:

```yaml
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata: {name: pooled-memory}
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: cxl-pool-memory
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
        deviceClassName: cxl-shared-memory
        selectors:
        - cel: {expression: 'device.attributes["cxl-pool.generic"].serial == "0xc1ae0001"'}
```

A pod references the claim in `spec.resourceClaims[].resourceClaimName` and
`containers[].resources.claims[].name` as usual.

## 4. What the scheduler does (Kubernetes 1.37, nothing to configure)

Allocates the device (pools without binding conditions first, so node-local
cxl.generic devices win when they satisfy the request), writes
`status.allocation` with `devices.results[]` (driver, pool, device,
bindingConditions copied from the slice, shareID and consumedCapacity for
shared devices) and `nodeSelector: matchFields metadata.name In [<node>]`,
`reservedFor=[pod]`, emits pod event `BindingConditionsPending`, polls the
claim every 5 s until `bindingTimeout` (default 600 s). Failure condition
True or timeout: PreBind fails, the next cycle deallocates the claim and
allocates again.

## 5. Claim status written by the controller

After the pool has attached the device to the node's VM (qemu accepted
device_add; the controller does not wait for the guest):

```yaml
status:
  devices:
  - driver: cxl-pool.generic
    pool: fake-cxl-pool
    device: shared0
    shareID: <copied from the allocation result, shared devices only>
    conditions:
    - type: cxl-pool.generic/Attached
      status: "True"
      reason: Attached
      message: "shared0 attached to n4-cxl-shared-2-fedora-43-containerd (slot cxlsw_ds0_usrp0hb0)"
      lastTransitionTime: <now>
    data:
      serial: "0xc1ae0001"       # REQUIRED by the node plugin
      shared: true               # REQUIRED
      size: 268435456            # REQUIRED, bytes
      host: n4-cxl-shared-2-fedora-43-containerd
      hostUUID: 1b6d55a2-ae4a-52f8-bbba-2e3f9adca1b1
      attachment: shared0@n4-cxl-shared-2-fedora-43-containerd
      qemuDeviceId: fcp_shared0.hp1
```

On failure (node is not a pool host, server error, timeout, 409):
`cxl-pool.generic/AttachFailed` True, reason one of `NoHost`, `AttachError`,
`Timeout`, `Conflict`, message = the error. The controller detaches anything
half attached. The entry is matched by (driver, pool, device); shareID is
copied for completeness (the scheduler does not compare it).

Status writes use `UpdateStatus` on the `/status` subresource with
conflict retry. RBAC (controller ServiceAccount):

```yaml
rules:
- {apiGroups: [resource.k8s.io], resources: [resourceslices], verbs: [get, list, watch, create, update, patch, delete]}
- {apiGroups: [resource.k8s.io], resources: [resourceclaims], verbs: [get, list, watch]}
- {apiGroups: [resource.k8s.io], resources: [resourceclaims/status], verbs: [get, patch, update]}
- {apiGroups: [resource.k8s.io], resources: [resourceclaims/driver], verbs: ["arbitrary-node:patch", "arbitrary-node:update"], resourceNames: ["cxl-pool.generic"]}
- {apiGroups: [""], resources: [nodes], verbs: [get, list, watch]}
- {apiGroups: [""], resources: [events], verbs: [create, patch]}
```

## 6. Node plugin: cxl-pool.generic helper

Registered by kubelet-cxl-plugin in the same process as cxl.generic:
`kubeletplugin.Start(ctx, poolHelper, KubeClient, NodeName, DriverName("cxl-pool.generic"), RegistrarDirectoryPath(<registry>), PluginDataDirectoryPath(<plugins>/cxl-pool.generic))`.
It never publishes ResourceSlices. Flags: `--pool-driver-name` (default
cxl-pool.generic, empty disables the helper), `--pool-prepare-timeout`
(default 30s, the wait for the memdev to appear).

PrepareResourceClaims, for each `status.allocation.devices.results[]` with
`driver == cxl-pool.generic`:
1. Find the `status.devices[]` entry with the same driver, pool, device.
   Parse `data`: serial (string, 0x hex or decimal), shared (bool), size
   (int). Missing entry or data -> error (kubelet retries).
2. Wait until `/sys/bus/cxl/devices/mem*/serial == serial` (memctl
   WaitMemdev, timeout from the flag). Timeout -> error.
3. shared == false: create a ram region on the memdev under the root
   decoder of its host bridge, bind the dax device to kmem, online all
   memory blocks of the region `online_movable` (tolerate blocks that are
   already online). Result: a NUMA node N. CDI device `generic/cxl=pool-<serialhex>`
   with env `CXL_POOL_NODE_<SERIALHEX>=N`, `CXL_POOL_SIZE_<SERIALHEX>=<bytes>`,
   `CXL_POOL_SERIAL_<SERIALHEX>=0x<serialhex>`. No memory steering (D24).
   shared == true: create a ram region, bind the dax device to device_dax
   (never kmem, never online: two kernels using the same bytes as RAM
   corrupt each other). CDI device `generic/cxl=pool-<serialhex>` with
   deviceNodes `[{path: /dev/daxX.Y, type: c, major, minor}]` (from
   /sys/bus/dax/devices/daxX.Y/dev) and env `CXL_SHARED_DAX_<SERIALHEX>=/dev/daxX.Y`,
   `CXL_SHARED_SIZE_<SERIALHEX>=<bytes>`, `CXL_SHARED_SERIAL_<SERIALHEX>=0x<serialhex>`.
   SERIALHEX is the serial in upper-case hex without 0x (env-name safe),
   serialhex lower-case for CDI names.
4. Return `kubeletplugin.Device{Requests, PoolName, DeviceName, CDIDeviceIDs}`
   per result. Persist (claim uid -> devices: request, device, serial,
   shared, size, memdev, region, dax, node) in
   `<plugin data dir>/preparedPoolClaims.json`; a repeated Prepare of a
   prepared claim returns the stored result.
5. A region on a memdev that already exists (another claim on this node for
   the same shared device, or a restart) is reused.

UnprepareResourceClaims: for each device of the claim: if no other prepared
claim on this node uses the serial: offline the region's memory blocks (if
kmem), `cxl disable-region`, `cxl destroy-region`, `cxl disable-memdev`
(memctl Release; a memdev that is already gone is not an error). Remove the
CDI device, drop the claim from the state file. Idempotent. This is what
lets qemu complete the hot-remove that the controller requests next.

Double advertising (D29): the cxl.generic publisher never offers a region
whose memdev serial is in the pool helper's prepared set.

Requirements on the node: `cxl` (ndctl) and `daxctl` CLIs, a kernel with
CXL region, DEV_DAX, DEV_DAX_KMEM, FS_DAX (devdax mmap), MEMORY_HOTREMOVE;
`/sys/devices/system/memory/auto_online_blocks` should be `offline` so
that shared devices are never auto-onlined as RAM.

## 7. Ordering and failure semantics

- Attach before bind: the controller sets Attached only after the pool
  server confirmed the attachment; NodePrepare then finds the memdev
  already in sysfs (or waits briefly for udev).
- Release before detach: kubelet calls NodeUnprepare while terminating the
  pod, before the pod object disappears; the resourceclaim controller
  deallocates the claim only after that, and the controller detaches only
  deallocated devices. So in the normal flow the guest has released the
  device before device_del. Known hazard: `kubectl delete --force
  --grace-period=0` removes the pod object immediately; the claim may be
  deallocated while the node still holds the memory, and qemu then cannot
  complete the hot-remove (zombie device until the VM restarts, server
  reports the attachment `failed`). Not handled; documented.
- Second exclusive claim while the first holds the only device: stays
  Pending at the scheduler (no device), never AttachFailed.
- Controller restart: the reconcile recomputes desired/actual from the API
  and the server; an existing attachment is only re-confirmed in status.
- Node plugin restart: preparedPoolClaims.json restores the prepared set;
  regions are found again by serial.

## 8. Deviations
- WS-B (2026-10-06): the fake-cxl-pool REST API `Attachment` has a new field
  `owner`: the owner of the attach request that created it (persisted in the
  state file). Without it the controller could not tell its attachments
  (`k8s:` prefix, D22) from CLI or adopted ones. plan/20-rest-api.md does
  not list it yet.
- WS-B, section 7: the controller sends one detach request per attachment
  (state `attached`). An attachment the guest has not released stays
  `detaching` on the server, which keeps waiting for DEVICE_DELETED in the
  background; the controller only logs it on every reconcile and never
  sends device_del again. `failed` attachments are logged once per state
  change and never retried (D14).
- WS-B, section 5: an attach that is still `attaching` after the attach
  timeout (HTTP 202) writes no condition; the next reconcile writes
  Attached when it completes. `Timeout` is used when the request deadline
  passed or the server's attach run timed out.
- WS-B, section 5: an attach that gets 409 for an exclusive device which
  this controller still has attached to another of its nodes, and that no
  claim wants there any more (a claim re-allocated to another node), writes
  no AttachFailed: the old attachment is detached in the same reconcile and
  the next one attaches. Without this a node move always cost a failed
  binding cycle.
- WS-A, section 6 step 4: the returned `kubeletplugin.Device` also carries
  `ShareID` copied from the allocation result (nil for exclusive devices).
- WS-A, section 6 step 1: `shared` and `size` are checked for presence,
  not defaulted: a missing `shared` would otherwise mean exclusive, and
  onlining a shared device as RAM corrupts the other hosts' view.
- WS-A, section 6: a claim whose `shared` differs from the one of an
  already prepared claim on the same serial fails Prepare.
- WS-A, section 6: a failed Prepare releases what it touched (including
  `cxl disable-memdev`, unless another prepared claim uses the serial).
  On the retry the memdev is present but has no driver; Prepare then waits
  only 2 s for a driver and lets memctl.CreateRegion `cxl enable-memdev` it,
  instead of waiting the full prepare timeout.
- WS-A, D29: the serials hidden from cxl.generic include devices being
  prepared (inflight), so a udev rescan between region creation and the
  end of Prepare cannot publish the region. The pool helper's state file is
  loaded before the first cxl.generic scan; its kubelet plugin is started
  after the cxl.generic one.
- WS-A, section 6 step 4: the state file also stores daxDevice, daxMajor and
  daxMinor (shared) so that the CDI spec can be rebuilt after a restart
  without reading sysfs.
