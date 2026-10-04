# WS7 (follow-up task spec): Kubernetes integration of fake-cxl-pool

Status: task spec written 2026-10-02 (Fable). Not started. Target repository:
~/github.com/intel/intel-resource-drivers-for-kubernetes (branch 5fC-cxl or
newer), package cmd/kubelet-cxl-plugin and a new cmd/cxl-pool-controller.
Design: plan/10-design-pooling-dra.md (sections 4, 5, 7); verified Kubernetes
facts: plan/11-research-cohdi-kep5007.md (sections 1.2-1.7, 5.1-5.5).
Pool API and Go client: scripts/testing/fake-cxl-pool/pkg/{api,client} in
nri-plugins (README.md there).

## Deliverable 1: kubelet-cxl-plugin extension

1. Register a second kubeletplugin helper in the same process:
   `kubeletplugin.Start(ctx, poolDriver, DriverName("cxl-pool.generic"), NodeName(...), RegistrarDirectoryPath(...), PluginDataDirectoryPath(<dir>/cxl-pool.generic))`.
   It never calls PublishResources. Flags: `--pool-driver-name` (default
   cxl-pool.generic), `--pool-prepare-timeout` (default 60s).
2. PrepareResourceClaims (pool driver) per allocation result with
   `Driver == cxl-pool.generic`:
   - serial := attribute `serial` of the device in the ResourceSlice of the
     result's pool (informer on ResourceSlices with field selector
     spec.driver=cxl-pool.generic), fallback `claim.status.devices[].data.serial`.
   - wait until a memdev with that serial exists in sysfs (reuse the udev
     watcher + nricxl.DevicesFromSysfs), timeout -> error (kubelet retries).
   - shared (attribute `shared == true`): create region (`cxl create-region
     -t ram -d <decoder of the memdev's host bridge> -m memN`; decoder choice
     as pkg/guest in fake-cxl-pool does), bind the dax device to device_dax
     (daxctl reconfigure-device --mode=devdax, or sysfs unbind/bind), return
     CDI device: deviceNode /dev/daxX.Y, env CXL_SHARED_DAX_<serialhex>=/dev/daxX.Y,
     CXL_SHARED_SIZE_<serialhex>=<bytes>.
   - exclusive: create region, kmem, online all blocks `online_movable`;
     then the existing cxl.generic preparation path for that region's NUMA
     node (memory policy via cgmpolmgr/NRI). Persist prepared pool claims in
     preparedClaimsInfo.json with serial, memdev, region, dax device, mode.
3. UnprepareResourceClaims (pool driver): when the last prepared claim on this
   node for the serial goes away: exclusive: offline all blocks of the region;
   both: `cxl disable-region`, `cxl destroy-region`, `cxl disable-memdev`.
   Idempotent; errors are retried by kubelet.
4. Double advertising: the cxl.generic publisher skips regions whose memdev
   serials appear in cxl-pool.generic ResourceSlices (set maintained from the
   informer) or that it prepared as pool devices.
5. Tests: unit tests with fake sysfs (existing testability config) for the
   serial wait, mode handling, idempotent unprepare; e2e in the n4-cxl-shared
   VMs (deliverable 3).

## Deliverable 2: cmd/cxl-pool-controller (new, one Deployment)

Config: pool server URL (default http://192.168.76.2:9909 in the e2e VMs),
driver name (cxl-pool.generic), pool name (fake-cxl-pool), node label
(cxl-pool.generic/attachable), poll interval, attach timeout.

1. Publisher: `resourceslice.StartController` (unowned,
   `ReconcilePoolWithName` not needed with a dedicated driver name) from
   `GET /api/v1/devices` filtered scope=pool: one Device per pool device as in
   plan/10 section 4.1 (exclusive: capacity memory; shared:
   allowMultipleAllocations + capacity `hosts` with requestPolicy default 1,
   validValues ["1"], value = max attachments e.g. "4"; attributes source,
   serial, shared, size, pool; bindsToNode true; bindingConditions
   ["cxl-pool.generic/Attached"]; bindingFailureConditions
   ["cxl-pool.generic/AttachFailed"]). Slice nodeSelector: label
   cxl-pool.generic/attachable=true. Re-publish on /events or every poll.
2. Node labeler: for every Node, resolve `status.nodeInfo.systemUUID` (then
   name) with `GET /api/v1/hosts/resolve?uuid=&hostname=`; label attachable
   nodes; remove the label when the host disappears.
3. Claim reconciler (informer on ResourceClaims, workqueue keyed by claim):
   for each `status.allocation.devices.results[]` of our driver and pool with
   bindingConditions, `reservedFor` non-empty and no Attached/AttachFailed
   True in the matching `status.devices[]` entry (match driver, pool, device;
   write shareID from the result):
   - node from `allocation.nodeSelector.nodeSelectorTerms[0].matchFields[0].values[0]`
     -> host (uuid, else name); none/ambiguous -> AttachFailed.
   - exclusive: `PUT /devices/{d}/allocation {owner: "k8s:resourceclaim/<uid>"}`
     (409 other owner -> AttachFailed).
   - `POST /devices/{d}/attachments {host, owner, wait: true}` (idempotent).
   - patch status.devices[] (SSA, field manager cxl-pool-controller):
     Attached=True, data {host, hostUUID, serial, attachment, qemuDeviceId}.
   - on error: AttachFailed=True with message; detach leftovers.
   On claims whose allocation is gone, deleted claims, or AttachFailed:
   for each (device, node) the controller recorded (own cache + state file
   under /var/lib/cxl-pool-controller, rebuilt from status.devices[].data on
   start) with no remaining share: `DELETE /devices/{d}/attachments/{host}?wait=true&timeout=60s`;
   409 -> retry with backoff (the node may still be unpreparing); on
   `failed` attachment (guest never released): Node event
   "CXLPoolDetachFailed", keep retrying only after the host restarts
   (Host.pid changes). Then `DELETE /devices/{d}/allocation` (exclusive).
4. RBAC (plan/11 section 1.5): resourceslices CRUD; resourceclaims
   get/list/watch; resourceclaims/status get/patch/update; resourceclaims/driver
   verbs arbitrary-node:patch, arbitrary-node:update with resourceNames
   ["cxl-pool.generic"]; nodes get/list/watch/patch (label); events create.
5. Manifests: deployments/cxl-pool/{namespace,rbac,deployment,device-classes}.yaml,
   DeviceClasses cxl-pool-memory (shared == false) and cxl-shared-memory
   (shared == true); example claims (plan/10 section 4.1). Optional
   KubeSchedulerConfiguration snippet lowering bindingTimeout to 120s.
6. Tests: unit tests with a fake pool server (httptest) and fake clientset
   for the reconciler state machine; envtest optional.

## Deliverable 3: demo / e2e

Extend test/e2e/cxl/dra-demo-cxl.sh (or add dra-demo-pool.sh): run against
n4-cxl-shared-2-fedora-43-containerd (single-node cluster) with the pool
server on the host: deploy kubelet-cxl-plugin (new build) + cxl-pool-controller,
create a pod with a cxl-pool-memory claim, show the pod waits with event
BindingConditionsPending, the server attaches, the claim gets Attached=True,
the pod runs with the memory (numactl -H inside shows the new node, or
/dev/daxX.Y for a shared claim), delete the pod, show detach in the server.
Two-node variant (both shared VMs in one cluster: needs a multi-node
option in the test framework, see 00-overview open items) demonstrates one
shared device claimed from both nodes.

## Acceptance
- A pod requesting cxl-pool-memory on a fresh single-node cluster runs with
  hotplugged memory without any manual step; deleting it detaches the device
  (server shows it free) within 60s.
- A second claim for the same exclusive device while the first holds it stays
  pending (scheduler: device unavailable), not AttachFailed.
- Controller restart during an attach does not duplicate attachments
  (idempotent attach; state rebuilt from claim status).
