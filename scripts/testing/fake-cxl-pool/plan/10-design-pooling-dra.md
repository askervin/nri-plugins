# WS1: CXL memory pooling and sharing: high-level design

Status: v1 2026-10-02 (Fable), finalized with plan/11-research-cohdi-kep5007.md
(KEP-5007 fields verified against Kubernetes v1.37.0 source, CoHDI repos at
current main). Open items in section 8.

## 1. Problem and scope

A CXL memory pool (here: fake-cxl-pool-server on the qemu host) owns memory
devices that can be attached to hosts (qemu VMs = Kubernetes nodes) at
runtime, exclusively (pooling) or concurrently (sharing). A pod asks for pooled
or shared CXL memory through DRA. The chain designed here, exactly:

  pod + claim -> scheduler allocates a pool device and picks a node -> pool
  attaches the device to that node's VM -> controller marks the claim's
  binding condition True -> pod binds -> node driver (kubelet-cxl-plugin)
  waits for the hotplugged memdev, makes it usable, prepares the claim -> pod
  runs -> pod/claim deleted -> node driver releases -> pool detaches.

Implemented in this task: pool server and client (WS5), qemu and test
framework support (WS3, WS4), an e2e test driving attach/share/detach with the
client from inside a VM (WS6). Designed here, implemented next in the DRA
driver repository (~/github.com/intel/intel-resource-drivers-for-kubernetes):
cxl-pool-controller and the kubelet-cxl-plugin extension (section 4, 7).

## 2. Vocabulary (mapped to Maxview and CoHDI)

| fake-cxl-pool | Maxview (UnifabriX MAX) | CoHDI | Kubernetes |
|---|---|---|---|
| Pool (dir + capacity) | memory resource | fabric resource pool | - |
| Device (backing file, size, serial, shared?) | viewport (shared, persistent) + allocation | resource / device | ResourceSlice device |
| Host (qemu VM, name + SMBIOS uuid) | host; port + HDM | machine (machine_uuid in providerID) | Node (nodeInfo.systemUUID) |
| Slot (free cxl-downstream/cxl-rp bus) | HDM on a port | - | - |
| Attachment (device@host) | viewport attached to port/HDM | attach via ComposabilityRequest | status.devices[].conditions Attached=True |
| Allocation (owner) | - | ComposabilityRequest | ResourceClaim status.allocation |

## 3. Components

```
 +------------------------------------------------------------- host ------------------+
 |  fake-cxl-pool-server  (REST :9909; QMP/HMP to each qemu; backing files /tmp/..)    |
 |        ^ REST                 ^ REST                 ^ QMP: object-add/device_add   |
 |        |                      |                      |      device_del/object-del   |
 | +------+------- VM1 --------+ | +------+------- VM2 --------+                        |
 | | fake-cxl-pool-client      | | | fake-cxl-pool-client     |                        |
 | | kubelet-cxl-plugin (DRA)  | | | kubelet-cxl-plugin (DRA) |                        |
 | | cxl-pool-controller*      | | |                          |                        |
 | | kernel: cxl_mem, region,  | | | kernel ...               |                        |
 | |   dax (device_dax | kmem) | | |                          |                        |
 | +---------------------------+ | +--------------------------+                        |
 +-------------------------------------------------------------------------------------+
   * one Deployment, anywhere in the cluster; uses the Go client library
```

- fake-cxl-pool-server: knows nothing about Kubernetes. Inventory of devices
  and hosts, attach/detach via qemu monitors, allocation bookkeeping,
  discovery of qemu VMs (20-rest-api.md).
- fake-cxl-pool-client: Go library + CLI. `--self` resolves the VM it runs in
  (SMBIOS uuid, then hostname). `guest` subcommands make a hotplugged device
  usable (region, devdax or system-ram, online) and release it.
- cxl-pool-controller (new, section 4): publishes pool devices as a
  cluster-scoped ResourceSlice, watches ResourceClaims, attaches/detaches
  through the pool server, writes the binding conditions. It replaces what
  CoHDI splits across composable-dra-driver, dynamic-device-scaler and
  composable-resource-operator; no CRDs: the ResourceClaim is the request and
  `claim.status.devices[]` holds the attachment state.
- kubelet-cxl-plugin (exists): node-local DRA driver `cxl.generic`. Extended
  with a second kubeletplugin helper registered as `cxl-pool.generic` whose
  NodePrepare handles pool devices (section 4.4).

## 4. The exact path

### 4.1 Publishing pool devices (cxl-pool-controller)
One unowned `resourceslice.Controller` publishes pool `fake-cxl-pool` under
driver name **`cxl-pool.generic`** (decision D8: separate driver name, option
B of the research: clean RBAC scoping, no reconcile interaction with the
node-owned `cxl.generic` slices, NodePrepare tells pool claims apart by
driver; cost: a claim mixing local and pool devices gets two NodePrepare
calls). Slice node selection: `nodeSelector` on label
`cxl-pool.generic/attachable=true`, which the controller sets on every Node
whose systemUUID (or name) resolves to a pool Host; `allNodes: true` as the
simple fallback.

Exclusive (pooled) device:
```yaml
- name: pooled0
  attributes:
    source: {string: pool}
    serial: {string: "0xc1f00001"}      # guest-visible identity: /sys/bus/cxl/devices/memN/serial
    shared: {bool: false}
    size:   {int: 536870912}
  capacity: {memory: {value: 512Mi}}
  bindsToNode: true
  bindingConditions: ["cxl-pool.generic/Attached"]
  bindingFailureConditions: ["cxl-pool.generic/AttachFailed"]
```
Shared device (one backing file, attachable to several VMs, section 5):
```yaml
- name: shared0
  attributes: {source: {string: pool}, serial: {string: "0xc1f0ee00"}, shared: {bool: true}, size: {int: 268435456}}
  allowMultipleAllocations: true
  capacity:
    hosts: {value: "4", requestPolicy: {default: "1", validValues: ["1"]}}   # max attached VMs
  bindsToNode: true
  bindingConditions: ["cxl-pool.generic/Attached"]
  bindingFailureConditions: ["cxl-pool.generic/AttachFailed"]
```
Never put the memory size of a shared device in `capacity`: every allocation
would consume it (the full value by default). Size is an attribute.

DeviceClass examples:
```yaml
kind: DeviceClass ; metadata.name: cxl-pool-memory
spec.selectors: [{cel: {expression: 'device.driver == "cxl-pool.generic" && device.attributes["cxl-pool.generic"].shared == false'}}]
kind: DeviceClass ; metadata.name: cxl-shared-memory
spec.selectors: [{cel: {expression: 'device.driver == "cxl-pool.generic" && device.attributes["cxl-pool.generic"].shared == true'}}]
```
A claim for a specific shared region adds
`device.attributes["cxl-pool.generic"].serial == "0xc1f0ee00"`.

Feature gates: none to set. `DRADeviceBindingConditions` (beta, on),
`DRAResourceClaimDeviceStatus` (beta, on), `DRAConsumableCapacity` (on) in
v1.37.0. Optional: scheduler `DynamicResourcesArgs.bindingTimeout` (default
600s) lowered to e.g. 120s for tests.

### 4.2 Claim and scheduling (Kubernetes, unchanged)
Filter tries pools without binding conditions first (node-local `cxl.generic`
regions), then `fake-cxl-pool`. Reserve; `pod.status.nominatedNodeName`.
PreBind `bindClaim()` writes `status.allocation` (results[] with driver,
pool, device, bindingConditions copied from the slice, `shareID` and
`consumedCapacity` for shared devices), `allocation.nodeSelector` =
`matchFields metadata.name In [<node>]` (because `bindsToNode`),
`allocationTimestamp`, `reservedFor=[pod]`, emits event
`BindingConditionsPending`, then polls every 5s until `bindingTimeout`.

### 4.3 Attach (cxl-pool-controller)
Watch ResourceClaims. For each `status.allocation.devices.results[]` with
`driver == cxl-pool.generic`, `pool == fake-cxl-pool`, non-empty
`bindingConditions`, `reservedFor` non-empty, and no True condition in the
matching `status.devices[]` entry (matched by driver, pool, device; the
controller also writes `shareID`):
1. node := `allocation.nodeSelector.nodeSelectorTerms[0].matchFields[0].values[0]`.
   host := Host whose `uuid == node.status.nodeInfo.systemUUID`, else whose
   `name == node.metadata.name`. Ambiguous or none -> `AttachFailed=True`.
2. Exclusive device: `PUT /devices/{d}/allocation {owner: "k8s:resourceclaim/<claim uid>"}`
   (409 from another owner -> AttachFailed). Shared device: no allocation;
   the controller refcounts shares per (device, node) itself.
3. `POST /devices/{d}/attachments {host, owner, wait: true}`; idempotent per
   (device, host): a second claim for the same shared device on the same node
   finds it attached.
4. On success patch (SSA on `/status`, RBAC `resourceclaims/driver`
   `arbitrary-node:patch` for `cxl-pool.generic`):
```yaml
status:
  devices:
  - driver: cxl-pool.generic
    pool: fake-cxl-pool
    device: shared0
    shareID: <from the result, shared devices>
    conditions:
    - {type: cxl-pool.generic/Attached, status: "True", reason: Attached, message: "shared0 -> n4-cxl-shared-2-fedora-43-containerd slot cxlsw_ds0_usrp0hb0", lastTransitionTime: <now>}
    data: {host: <name>, hostUUID: <uuid>, serial: "0xc1f0ee00", attachment: "shared0@<host>", qemuDeviceId: "fcp_shared0.hp1"}
```
   On REST error or timeout: `cxl-pool.generic/AttachFailed=True` with the
   error in `message`; detach anything half-attached; optionally a
   DeviceTaintRule so the device is not picked again immediately.
5. Scheduler sees all binding conditions True -> binds the pod.

Decision D9: the controller sets `Attached=True` right after the pool server
reports the attachment (qemu accepted device_add), not after the guest has
onlined the memory. The guest-side wait moves into NodePrepare (4.4). This is
the "happy path" the research recommends over CoHDI's reschedule trick (set a
failure condition, let the pod be rescheduled onto the now node-local device),
which costs a scheduling cycle and races with other pods.

### 4.4 Node side (kubelet-cxl-plugin extension)
- Start a second `kubeletplugin.Helper` with `DriverName("cxl-pool.generic")`
  in the same process (separate sockets
  /var/lib/kubelet/plugins/cxl-pool.generic/dra.sock and
  plugins_registry/cxl-pool.generic-reg.sock). It does not PublishResources.
- NodePrepareResources (pool driver) for each result: serial := from the pool
  ResourceSlice device attributes (list ResourceSlices of driver
  `cxl-pool.generic`, or from `status.devices[].data.serial`). Wait (udev
  watcher already exists; timeout e.g. 60s) until
  `/sys/bus/cxl/devices/mem*/serial == serial`. Then:
  - shared device: `cxl create-region -t ram -d <HB decoder> -m memN`,
    ensure the dax device is bound to `device_dax` (not kmem). Prepare returns
    CDI edits: device node `/dev/daxX.Y` and env
    `CXL_SHARED_DAX_<serial>=/dev/daxX.Y`, `CXL_SHARED_SIZE_<serial>=<bytes>`.
    Applications mmap it and agree on a layout themselves.
  - exclusive device: region, dax -> kmem, `online_movable` all blocks (keeps
    kernel allocations off it so hot-remove works). Then the existing path:
    region -> NUMA node -> memory policy (cgmpolmgr via NRI) steers the
    container to that node. Decide later whether the pod memory cgroup limit
    grows by the attached amount (`nodeAllocatableResources` is alpha and
    blocks sharing; keep it off pool devices).
- Double advertising: the `cxl.generic` publisher must not offer memory that
  arrived from the pool as a free local `cxl-node` device. Recognise it by
  serial: regions whose memdevs' serials appear in `cxl-pool.generic`
  ResourceSlices are skipped (or `IgnoreDevices` by serial).
- NodeUnprepareResources: when the last pool claim on this node for the device
  is gone: offline blocks (exclusive mode) / check the dax device is unused,
  `cxl disable-region`, `cxl destroy-region`, `cxl disable-memdev memN`. This
  is what lets qemu complete the hot-remove.

### 4.5 Release and detach (cxl-pool-controller)
Trigger: the claim's allocation disappears (pod terminal or deleted, the claim
controller clears `reservedFor`/`allocation`/`status.devices`; or the claim is
deleted; or the scheduler deallocates after `AttachFailed`/timeout). The
controller reconciles from `status.devices[].data` and its own attachment
cache: for each (device, node) with no remaining share:
`DELETE /devices/{d}/attachments/{host}?wait=true&timeout=60s`. The server
issues device_del and waits for DEVICE_DELETED; if the node has not released
the device yet (NodeUnprepare may still be running: the API gives no ordering
guarantee), the server answers 409 and keeps the attachment "detaching"; the
controller retries with backoff until it is detached, then
`DELETE /devices/{d}/allocation` for exclusive devices. Shared devices stay
attached to other nodes.

### 4.6 Identifying the VM (decision D3 revised)
Primary key: SMBIOS system UUID. The test framework starts every VM with
`-uuid uuid5(NAMESPACE_DNS, vm_name)` (WS4); kubelet reports it as
`node.status.nodeInfo.systemUUID`; the guest reads
/sys/class/dmi/id/product_uuid; the pool server parses `-uuid` from the qemu
command line. Fallback: `Host.name == node name == hostname == vagrant machine
name` (the `.vagrant/machines/<name>/` component of the `-drive file=`).
providerID (`fake-cxl-pool://<uuid>`) is the CoHDI-compatible alternative if
their components should ever be reused; not set now. Never key on
/etc/machine-id (cloned images).

### 4.7 Sequence
```
User   apiserver/scheduler            cxl-pool-controller          fake-cxl-pool-server     qemu(VM)      kubelet-cxl-plugin(VM)
 |-- create pod+claim --->|
 |                        |-- Filter/Reserve: pool device, node N; PreBind writes allocation(nodeSelector N), reservedFor, waits
 |                        |<--------------- watch claim -----------|
 |                        |                                        |-- PUT allocation(owner) (exclusive) -->|
 |                        |                                        |-- POST attach(host N) ---------------->|-- object-add + device_add -->| (udev: memN, serial S)
 |                        |<-- PATCH status.devices[Attached=True, data{host,serial}] --|
 |                        |-- bind pod to N ------------------------------------------------------------------------------>| NodePrepare(cxl-pool.generic):
 |                        |                                                                                                |  wait serial S, region, dax/kmem, online, CDI
 |                        |                                                                                                |  pod runs
 |-- delete pod --------->|------------------------------------------------------------------------------------------------>| NodeUnprepare: offline, destroy region, disable memdev
 |                        |-- claim controller clears allocation/reservedFor/status.devices
 |                        |<--------------- watch claim -----------|
 |                        |                                        |-- DELETE attachment (retry on 409) --->|-- device_del, DEVICE_DELETED, object-del
 |                        |                                        |-- DELETE allocation ------------------>|
Failure: attach error -> AttachFailed=True -> PreBind fails -> next cycle: claim marked unavailable, PostFilter deallocates -> controller detaches leftovers -> re-allocation.
Timeout: allocationTimestamp + bindingTimeout -> same deallocation path.
```

## 5. Sharing semantics and safety

- Shared device: one backing file, N attachments, the same serial in every
  VM. Two kernels must never both use it as system RAM: each would allocate
  pages from the same physical memory and corrupt the other (WS3 Q9: silent
  corruption, verified). Sharing mode is devdax in every guest; the kernel
  never allocates from it; applications mmap /dev/daxX.Y (needs
  CONFIG_FS_DAX in the guest kernel; after `cxl create-region` the dax device
  binds to kmem by default, `daxctl reconfigure-device --mode=devdax`
  switches it). Verified host-to-host at ~7 GB/s, i.e. KVM maps it directly.
- Exclusive device: one attachment at a time. system-ram with
  online_movable (default) or devdax. Movable keeps kernel allocations off the
  memory so it can be hot-removed; it does not make concurrent use safe.
- In Kubernetes: a `bindsToNode` allocation covers one node, so sharing one
  device across N nodes means N claims (one per node) each taking one unit of
  the `hosts` capacity of the same `allowMultipleAllocations` device; several
  pods on one node share by referencing the same claim (`reservedFor` <= 256)
  or by separate claims (the controller attaches once per (device, node)).
- The server enforces attachment counts and exclusive ownership; guest mode is
  enforced by kubelet-cxl-plugin / the client, and verified by WS6.

## 6. Alternatives considered
- Pre-declaring every shareable backend on every VM command line (today's
  beram_* objects): limits the pool to what was known at VM start. Rejected
  for pool devices in favour of runtime object-add (WS3 Q2); kept as "local
  devices" and for the static shared device of the shared topologies.
- Identify clients by TCP source: impossible behind slirp (all VMs are
  127.0.0.1). uuid/hostname resolve chosen.
- Same driver name `cxl.generic` for pool devices (option A): smallest change
  (replace the `Pool != NodeName` skip at node_state.go:472), but the
  controller's `arbitrary-node` RBAC would cover node-local devices too and
  cluster-scoped publishers under one driver need `ReconcilePoolWithName`.
  Kept as fallback if two helpers in one process prove awkward.
- CoHDI's reschedule path (set a failure condition after attach so the pod
  lands on the node-local device): extra scheduling cycle, racy. Rejected.
- CRDs (ComposabilityRequest/ComposableResource): not needed, the claim is
  the request.

## 7. Follow-up implementation (DRA driver repository)
1. kubelet-cxl-plugin: second helper `cxl-pool.generic`; NodePrepare/Unprepare
   for pool devices (wait for serial, region, devdax|kmem, CDI); skip pool
   serials in the `cxl.generic` publisher.
2. cxl-pool-controller: `cmd/cxl-pool-controller`: config (pool server URL,
   driver name, pool name, label), resourceslice.Controller publisher from
   `GET /devices` (+ `/hosts` for the node label), claim informer + workqueue,
   attach/detach reconcile, status patch, RBAC manifests, DeviceClasses.
3. Demo: extend test/e2e/cxl/dra-demo-cxl.sh with a pooled and a shared claim
   across two VMs (needs the n4-cxl-shared-1/2 VMs to form one cluster, or two
   single-node clusters each with its own controller: the pool server does not
   care).

## 8. Open items
- (WS3 answered) CXL memory needs no maxmem; QMP sn is an integer; slots via
  qom-list/qom-get; DEVICE_DELETED only after the guest released the device,
  otherwise the device is a zombie until the VM restarts: the node driver's
  NodeUnprepare must complete before the controller detaches, and the
  controller treats a failed detach as a node-local problem (event on the
  Node, attachment stays failed, device quarantined until the VM restarts).
- Whether the pod memory cgroup should grow by attached pool memory
  (`nodeAllocatableResources` is alpha and blocks multi-pod sharing).
- Multi-node cluster in the test framework (today each topology is a
  single-node cluster) for the DRA demo in 7.3.
