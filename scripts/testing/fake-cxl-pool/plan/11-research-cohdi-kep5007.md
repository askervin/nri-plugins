# 11 - Research: KEP-5007 (DRA device binding conditions) and CoHDI, applied to fake-cxl-pool

Date: 2026-10-02. Everything below was read from source, not from summaries, unless marked
"(docs)" or "(KEP text)". Sources and the revisions read:

| Source | Revision read |
|---|---|
| kubernetes/enhancements `keps/sig-scheduling/5007-device-attach-before-pod-scheduled/{README.md,kep.yaml}` | `master` (raw.githubusercontent.com) |
| kubernetes/kubernetes | tag `v1.37.0` (also `release-1.34` .. `release-1.37` for feature-gate history) |
| kubernetes.io DRA docs (`.../resource-management/dynamic-resource-allocation/_print/`, `.../dra-features/`, hardening guide) | v1.37 site, last modified 2026-07-27 |
| CoHDI/composable-dra-driver | `fa9cd04` (2026-07-10) |
| CoHDI/dynamic-device-scaler | `239690b` (2026-09-08) |
| CoHDI/composable-resource-operator | `3931018` (2026-09-05) |
| CoHDI/cohdi-manager-mock, CoHDI/cohdi-ci-mock, CoHDI/cohdi-chart | `main` (cohdi-manager-mock `65dfaef`, 2026-08-17) |
| local intel-resource-drivers-for-kubernetes `cmd/kubelet-cxl-plugin` | branch `5fC-cxl` |

Fetch notes: the GitHub REST API (`api.github.com/.../git/trees`) answered "API rate limit
exceeded", so I shallow-cloned the CoHDI repositories (`git clone --depth 1`) and fetched
Kubernetes files from raw.githubusercontent.com. `usageRestrictedToNode` appears neither in the
KEP nor in v1.37.0 `resource/v1/types.go`. It is not a real field.


## 0. Key findings

1. In v1.37.0, `DRADeviceBindingConditions` is **Beta and on by default** (alpha 1.34, beta 1.36).
   It depends on `DRAResourceClaimDeviceStatus` (beta, on since 1.33). kep.yaml targets
   **stable in v1.38**. Our 1.37 cluster needs no feature-gate flags.
2. The scheduler reads conditions from `claim.status.devices[]`: the entry whose (driver, pool,
   device) matches the allocation result, field `.conditions[]`. The KEP prose and the docs say
   "`.status.conditions` of the ResourceClaim", but the field docstrings ("per-device status
   conditions") and the code use the per-device entry.
3. `bindsToNode: true` makes the allocator write
   `status.allocation.nodeSelector = {matchFields: [{key: metadata.name, operator: In, values: [<node>]}]}`.
   This is how the external controller learns the target node. The pod is **not bound yet**:
   `pod.spec.nodeName` is still empty. `pod.status.nominatedNodeName` is also set
   (`NominatedNodeNameForExpectation`, beta and on since 1.35).
4. Order inside PreBind: the scheduler first writes the allocation, `reservedFor=[pod]` and
   `allocationTimestamp`, and only then waits. It polls every 5 s until the binding timeout
   (`DynamicResourcesArgs.bindingTimeout`, default **600 s**). A failure condition or the timeout
   leads, in the next scheduling cycle, to the claim being deallocated: `allocation`,
   `reservedFor` and `status.devices` are all set to nil.
5. Within a node, the allocator tries **pools without binding conditions before pools with
   them**, regardless of name (`pools_incubating.go`). Local devices therefore win automatically.
6. Writing `status.devices` is authorised through the synthetic subresource
   `resourceclaims/driver` (`DRAResourceClaimGranularStatusAuthorization`, beta and on since 1.36).
   A cluster-level controller needs the verbs `arbitrary-node:patch` and `arbitrary-node:update`
   with `resourceNames: [<driver>]`. The CoHDI chart grants exactly this.
7. **CoHDI does not use the happy path.** Its pool ResourceSlice is published under the
   *vendor* driver name (`gpu.nvidia.com`). It is a count of anonymous devices that kubelet never
   prepares. The dynamic-device-scaler attaches a real GPU and waits until the vendor kubelet
   plugin publishes it in the node-local slice. It then sets the **failure** condition
   `FabricDeviceReschedule=True`, which forces the scheduler to deallocate and reschedule. The
   rescheduled pod gets the node-local device. `FabricDeviceReady` is never set to True.
8. Kubelet sends `NodePrepareResources` to the plugin registered under
   `allocation.devices.results[].driver`. If no plugin is registered under that name, the pod
   fails with `DRA driver X is not registered`. Our kubelet-cxl-plugin registers as
   **`cxl.generic`**, uses pool name = node name, and today *ignores* allocated devices from any
   other pool (`node_state.go:472`).
9. Sharing in 1.37: `allowMultipleAllocations` plus `capacity[*].requestPolicy`
   (`DRAConsumableCapacity`, beta and on since 1.36). Each share gets a `shareID` and a
   `consumedCapacity`. Because a `bindsToNode` allocation is pinned to one node, sharing one
   device across N nodes takes N claims (one per node), each holding a share of the same device.


## 1. KEP-5007 and the v1.37.0 implementation

### 1.1 Stage and feature gates (`pkg/features/kube_features.go`)

| Gate | 1.34 | 1.35 | 1.36 | 1.37.0 |
|---|---|---|---|---|
| `DRADeviceBindingConditions` | alpha, off | alpha, off | **beta, on** | beta, on |
| `DRAResourceClaimDeviceStatus` | beta, on (since 1.33) | = | = | = |
| `DRAConsumableCapacity` | alpha, off | alpha, off | beta, on | beta, on |
| `DRAPartitionableDevices` | alpha | alpha | beta, on | beta, on |
| `DRADeviceTaints` | alpha | alpha | beta, on | beta, on |
| `DRAResourceClaimGranularStatusAuthorization` | - | - | beta, on | beta, on |
| `NominatedNodeNameForExpectation` | alpha | beta, on | = | = |
| `DRAOptionalNodeOperations` (`skipNodeOperations`) | - | - | - | alpha, off |
| `DRANodeAllocatableResources` | - | - | alpha, off | alpha, off |

- Dependency map in v1.37.0: `DRADeviceBindingConditions: {DynamicResourceAllocation, DRAResourceClaimDeviceStatus}`.
- kep.yaml: `milestone: {alpha: "v1.34", beta: "v1.36", stable: "v1.38"}`, `stage: stable`,
  `latest-milestone: "v1.38"`. The `feature-gates` list in kep.yaml names only `kube-scheduler`.
  The KEP's PRR section and the docs name kube-apiserver and kube-scheduler.
- Metrics: `scheduler_dra_bindingconditions_allocations_total` (label `status`:
  success/failure/timeout) and `scheduler_dra_bindingconditions_prebind_duration_seconds`.

### 1.2 ResourceSlice fields (`staging/src/k8s.io/api/resource/v1/types.go`, v1.37.0)

`ResourceSliceSpec`: `driver`, `pool{name, generation, resourceSliceCount}`. Exactly one of
`nodeName`, `nodeSelector` (exactly one term), `allNodes`, `perDeviceNodeSelection` must be set.
Also `devices[]` (max 128, or 64 if taints/counters are used), `sharedCounters[]` (max 8),
`skipNodeOperations[]` (alpha).

`Device` fields relevant here (json names):

```go
Name                     string                                  `json:"name"`            // DNS label
Attributes               map[QualifiedName]DeviceAttribute      `json:"attributes"`      // attrs+capacity <= 32
Capacity                 map[QualifiedName]DeviceCapacity       `json:"capacity"`
ConsumesCounters         []DeviceCounterConsumption             `json:"consumesCounters"`// <= 2 per device
NodeName/NodeSelector/AllNodes                                    // per-device, only with spec.perDeviceNodeSelection=true
Taints                   []DeviceTaint                          `json:"taints"`
BindsToNode              *bool    `json:"bindsToNode"`               // beta, DRADeviceBindingConditions+DRAResourceClaimDeviceStatus
BindingConditions        []string `json:"bindingConditions"`         // max 4, valid condition types
BindingFailureConditions []string `json:"bindingFailureConditions"`  // max 4, valid condition types
AllowMultipleAllocations *bool    `json:"allowMultipleAllocations"`  // DRAConsumableCapacity
NodeAllocatableResources map[v1.ResourceName]NodeAllocatableResource `json:"nodeAllocatableResources"` // alpha
```

Docstrings (verbatim):
- `BindsToNode`: "indicates if the usage of an allocation involving this device has to be limited
  to exactly the node that was chosen when allocating the claim. If set to true, the scheduler will
  set the ResourceClaim.Status.Allocation.NodeSelector to match the node where the allocation was made."
- `BindingConditions`: "All of these conditions must be set in the per-device status conditions
  with a value of True to proceed with binding the pod to the node".
- `AllowMultipleAllocations`: "If AllowMultipleAllocations is set to true, the device can be
  allocated more than once, and all of its capacity is consumable, regardless of whether the
  requestPolicy is defined or not."

`DeviceCapacity{value, requestPolicy}`. `CapacityRequestPolicy{default, validValues[] (<=10, sorted) | validRange{min, max, step}}`.
A `requestPolicy` is allowed only when `allowMultipleAllocations: true`.

### 1.3 ResourceClaim fields set by the scheduler and by the external controller

The scheduler writes these during PreBind `bindClaim()`, through `UpdateStatus`:

```yaml
status:
  allocation:
    allocationTimestamp: <set if nil>      # basis of the timeout, shared by all pods of the claim
    nodeSelector:                          # with bindsToNode: exactly this form (allocator_incubating.go:1759)
      nodeSelectorTerms: [{matchFields: [{key: metadata.name, operator: In, values: [<node>]}]}]
    devices:
      results:
      - request: <req>
        driver: <slice.spec.driver>        # selects the kubelet plugin on the node
        pool: <slice.spec.pool.name>
        device: <device.name>
        bindingConditions: [...]           # copied from the slice at allocation time
        bindingFailureConditions: [...]
        shareID: <uuid>                    # only for allowMultipleAllocations devices
        consumedCapacity: {<cap>: <qty>}   # only for allowMultipleAllocations devices
  reservedFor: [{resource: pods, name: <pod>, uid: <uid>}]   # written BEFORE the wait
```

The external controller writes `status.devices[]` (`AllocatedDeviceStatus`). It is a list map
keyed by `driver, device, pool, shareID`:

```yaml
status:
  devices:
  - driver: <driver>
    pool: <pool>
    device: <device>
    shareID: <same as allocation result, if any>
    conditions:                     # metav1.Condition, max 8
    - {type: <bindingCondition>, status: "True", reason: ..., message: ..., lastTransitionTime: ...}
    data: {...}                     # RawExtension <= 10Ki, free-form driver data
```

Readiness check (`dynamicresources.go:isClaimReadyForBinding`): for each result with
`bindingConditions`, find `status.devices[]` with matching (Device, Driver, Pool). ShareID is
**not** compared (`getAllocatedDeviceStatus`). If any `bindingFailureConditions` entry is True,
return `ErrDeviceBindingFailed`. Ready when every `bindingConditions` entry is True. A missing
status entry means "not ready".

### 1.4 Scheduler flow (v1.37.0 `pkg/scheduler/framework/plugins/dynamicresources/dynamicresources.go`)

1. **Filter.** The allocator copies `BindingConditions`/`BindingFailureConditions` into the
   result (`allocator_incubating.go:393-395`). If the feature is off, devices with binding
   conditions are skipped. Per node, pool order is: pools without binding conditions, sorted by
   ID, then pools with binding conditions, sorted by ID (`pools_incubating.go:128-201`).
   The docs say the same: "pools without binding conditions are always evaluated before those
   with binding conditions, regardless of their names."
2. **Score.** Only for prioritized lists (`firstAvailable`). There is no scoring by binding
   conditions.
3. **Reserve**, then the scheduler patches `pod.status.nominatedNodeName` when PreBind will do
   work (`schedule_one.go:412-422`).
4. **PreBind.** `bindClaim()` adds the finalizer `resource.kubernetes.io/delete-protection`, then
   writes allocation, reservedFor and `allocationTimestamp`. If any result has binding conditions,
   it emits the pod event `BindingConditionsPending` ("waiting for binding conditions for device
   on node %s") and runs `wait.PollUntilContextTimeout(ctx, 5*time.Second, pl.bindingTimeout, ...)`,
   re-reading claims from the informer cache.
5. **Failure or timeout.** PreBind returns an error and the pod is retried. In that attempt,
   Filter marks the claim "unavailable" when a failure condition is True or when
   `allocationTimestamp + bindingTimeout` has passed. **PostFilter**
   (`deallocateOrDeletePodClaims`) then clears `ReservedFor`, `Allocation` and `Devices`, but only
   if `reservedFor` is empty or holds just this pod. It returns Unschedulable and the next cycle
   allocates again.
6. Scheduler config (docs, verified against `DynamicResourcesArgs.BindingTimeout`, default
   `DynamicResourcesBindingTimeoutDefault = 600 * time.Second`, valid values >= 1s):

```yaml
apiVersion: kubescheduler.config.k8s.io/v1
kind: KubeSchedulerConfiguration
profiles:
- schedulerName: default-scheduler
  pluginConfig:
  - name: DynamicResources
    args: {apiVersion: kubescheduler.config.k8s.io/v1, kind: DynamicResourcesArgs, bindingTimeout: 60s}
```

KEP failure-handling guidance (KEP text): after setting a failure condition, the controller
"should also ensure that the device is not picked again". Options are removing it from the
ResourceSlice, adding a device taint, or changing the slice-level or per-device node selector.

### 1.5 RBAC for status writes (docs: Hardening Guide - DRA; beta 1.36)

- `resourceclaims/binding` (update, patch): needed to change `status.allocation`/`reservedFor`
  (scheduler).
- `resourceclaims/driver`: needed to change `status.devices`, checked per driver.
  `associated-node:<verb>` is for node-local drivers. `arbitrary-node:<verb>` is for
  control-plane controllers.

```yaml
rules:
- {apiGroups: [resource.k8s.io], resources: [resourceclaims/status], verbs: [get, patch, update]}
- {apiGroups: [resource.k8s.io], resources: [resourceclaims/driver],
   verbs: ["arbitrary-node:patch", "arbitrary-node:update"], resourceNames: ["<driver>"]}
```

CoHDI's chart (`charts/dynamic-device-scaler/templates/deployment.yaml`) grants exactly this,
with `resourceNames: ["gpu.nvidia.com"]`.

### 1.6 Sharing building blocks (v1.37.0)

- **Consumable capacity** (docs example, verified against types): `allowMultipleAllocations: true`
  plus `capacity.<n>.{value, requestPolicy}`. The claim uses
  `requests[].exactly.capacity.requests: {<n>: <qty>}`, or the same inside `firstAvailable[]`.
  The result carries `consumedCapacity` and `shareID`, and the sum stays at or below `value`.
  Capacity a request does not name defaults to `requestPolicy.default`, or to the **full value**
  without a policy. CEL `device.allowMultipleAllocations == true` forces shareable devices.
- **One claim, many pods.** `reservedFor` holds at most 256 entries. All pods are confined to
  `allocation.nodeSelector`, so with `bindsToNode` they all run on one node.
- **Partitions.** `sharedCounters[]`/`consumesCounters[]` model alternative partitions.
  `perDeviceNodeSelection` gives each device its own node selection.
- `skipNodeOperations` (alpha) is not wanted: the node must online the memory.
  `nodeAllocatableResources.mapping` (alpha) "blocks sharing mapped device claims across multiple pods".

### 1.7 Node-side facts that constrain the design (v1.37.0)

- Kubelet groups claim devices by `results[].driver` and calls
  `draPlugins.GetPlugin(driverName)`. If none is registered, the error is
  `DRA driver %s is not registered` (`pkg/kubelet/cm/dra/manager.go:336`,
  `plugin/dra_plugin_manager.go:280`).
- When a driver registers, kubelet wipes ResourceSlices with field selector
  `spec.nodeName=<node>[,spec.driver=<d>]` (`wipeResourceSlices`). Cluster-scoped pool slices
  (nodeSelector/allNodes) are left alone.
- `resourceslice.Controller` field selector: `spec.driver=<d>,spec.nodeName=""` for unowned
  controllers. For Node owners it is `spec.nodeName=<node>`, unless the `ReconcilePoolWithName`
  option is set. Consequence: an unowned controller deletes cluster-scoped slices of *its
  driver* whose pools it does not know. Two cluster-scoped publishers under one driver name will
  fight unless they use `ReconcilePoolWithName`. A node-owned kubelet plugin never touches
  cluster-scoped slices.
- `kubeletplugin.Start` uses per-driver paths: `/var/lib/kubelet/plugins/<driver>/dra.sock` and
  `/var/lib/kubelet/plugins_registry/<driver>-reg.sock`. One process can therefore run two
  helpers for two driver names.


## 2. CoHDI composable-dra-driver ("CDI DRA")

Repo layout: `main.go`, `pkg/client/{client,request,token,types}.go`, `pkg/config/config.go`,
`pkg/kube_utils/kube_utils.go`, `pkg/manager/manager.go`, `deployment.yaml`,
`doc/Usecase_and_feedback_for_BindingCondition.md`. It is a single Deployment
(`namespace: composable-dra`, SA `cdi-dra`), **not** a kubelet plugin.

**Configuration** (`main.go` flags and env vars):
- `SCAN_INTERVAL`: default 1m, range 5s..86400s; the chart sets 5s.
- `TENANT_ID`: UUID, required. `CLUSTER_ID`: UUID, required when `USE_CM` is set.
- `CDI_ENDPOINT`: must start with `https://`.
- `USE_CAPI_BMH`: take the machine UUID from a Metal3 BareMetalHost.
- `USE_CM`: read min/max device counts from the Cluster Manager.

- ConfigMap `composable-dra/composable-dra-dds` (shared with DDS). Key `label-prefix` (chart:
  `cohdi.io`), key `fabric-id-range` (DDS only), and key `device-info`, a YAML list of
  `{index, cdi-model-name, dra-attributes{productName (required), ...}, driver-name,
  k8s-device-name (DNS label <= 50), cannot-coexist-with: [index...]}`. Chart example:
  `{cdi-model-name: a100, dra-attributes: {productName: "NVIDIA A100 80GB PCIe", type: gpu, uuid: ""},
  driver-name: gpu.nvidia.com, k8s-device-name: nvidia-a100-80, cannot-coexist-with: [2,3]}`.
- Secret `composable-dra/composable-dra-secret`: keys `username`, `password`, `realm`,
  `client_id`, `client_secret`, and `certificate` (the CA PEM for TLS).

**CDI manager REST calls** (`pkg/client/client.go`). Every call except the token call sends
`Authorization: Bearer <token>`, with a 60 s timeout:

| Purpose | Method + path | Query / body | Response fields used |
|---|---|---|---|
| token | `POST id_manager/realms/<realm>/protocol/openid-connect/token` | form `client_id, client_secret, username, password, scope=openid, grant_type=password` | `access_token`, `expires_in` (cached until exp-30s) |
| machines | `GET fabric_manager/api/v1/machines` | `tenant_uuid` | `data.machines[].{mach_uuid, fabric_id}` |
| free devices | `GET fabric_manager/api/v1/machines/<muuid>/available-reserved-resources` | `tenant_uuid, res_type=gpu, condition={"column":"model","operator":"eq","value":<model>}` | `reserved_res_num_per_fabric` (max 128) |
| node groups (CM) | `GET cluster_manager/cluster_autoscaler/v2/tenants/<t>/clusters/<c>/nodegroups[/<uuid>]` | - | `nodegroups[].{uuid,name}`, `mach_ids[]` |
| min/max (CM) | `GET cluster_manager/cluster_autoscaler/v3/tenants/<t>/clusters/<c>/machines/<muuid>` | - | `data.cluster.machine.resspecs[].{min_resspec_count,max_resspec_count, selector.expression.conditions}` |

**Node to machine mapping** (`manager.getMachineUUIDs`, `kube_utils`). The driver indexes Nodes
by `spec.providerID`, normalised to the **substring after the last "/"**. Without CAPI/BMH, that
string *is* the machine UUID (for example `fsas-cdi://<uuid>` gives `<uuid>`). With
`USE_CAPI_BMH`, it finds the BareMetalHost whose `metadata.uid` equals that string and reads the
annotation `cluster-manager.cdi.io/machine`. Nodes without a providerID are skipped with a warning.

**ResourceSlices** (`manager.generatePool`, published with `resourceslice.StartController`, one
controller per `driver-name`, **no Owner**):
- `spec.driver` = the **vendor driver name** from `device-info` (for example `gpu.nvidia.com`).
- Pool name `<k8s-device-name>-fabric<fabricID>`. There is one pool per (model, fabric), and
  `generation++` whenever the available count changes.
- Node selection uses `nodeSelector` (not allNodes):
  `<label-prefix>/<k8s-device-name> In ["true"]` AND `<label-prefix>/fabric In ["<fabricID>"]`.
- Devices are `<k8s-device-name>-<i>` for i < available count. They are anonymous; the count is
  all that matters.

```go
d := resourceapi.Device{ Name: fmt.Sprintf("%s-%d", k8sDeviceName, i), Attributes: <dra-attributes as strings>,
    BindsToNode: ptr.To(true),
    BindingConditions:        []string{"FabricDeviceReady"},
    BindingFailureConditions: []string{"FabricDeviceReschedule", "FabricDeviceFailed"} }
```
- On shutdown it deletes its slices, listed by `spec.driver=<d>,spec.nodeName=""` and filtered by
  its own pool names.

**Node labels written by the driver**: `<prefix>/fabric=<fabricID>`, and with `USE_CM` also
`<prefix>/<k8s-device-name>-size-max` / `-size-min`. DDS writes the label
`<prefix>/<k8s-device-name>=true|<deleted>` (section 3).

**Coordination** (doc/Usecase_and_feedback_for_BindingCondition.md): "devices in the resource pool
cannot be directly passed to DRA drivers (kubelet plugin) provided by device vendors. In this use
case, instead of waiting for BindingCondition to be met, we wait for BindingFailureCondition to be
met." The same driver name and the same attributes (`productName`, `type`, `uuid: ""`) let one
DeviceClass or CEL selector match both pool and node-local devices.


## 3. CoHDI dynamic-device-scaler (DDS)

A controller-runtime Deployment. Reconcile is triggered by watches on `ResourceClaim` and
`ResourceSlice`, plus `RequeueAfter: SCAN_INTERVAL`. Env vars (`cmd/main.go`, 0..86400 s):
`SCAN_INTERVAL` (default 60), `DEVICE_NO_REMOVAL_DURATION` (600),
`DEVICE_NO_ALLOCATION_DURATION` (60). It reads the same ConfigMap with `clientset` (`device-info`,
`label-prefix`, `fabric-id-range`).

**Detection** (`utils.GetResourceClaimInfo`). It lists *all* ResourceClaims with no field
selector and keeps those with `len(status.reservedFor) > 0 && status.allocation != nil`, plus
results with `len(BindingConditions) > 0`. The model comes from the pool name, by stripping
`-fabric\d+$` and looking up `k8s-device-name`. The node is
`getNodeName(status.allocation.nodeSelector)`, i.e. the first `matchFields` entry with
`key == "metadata.name" && operator == "In"`. That is the `bindsToNode` result. Per-device state:
`Preparing` (no status.devices entry, or no condition True yet), `Reschedule`
(`FabricDeviceReschedule=True`), or `Failed` (`FabricDeviceFailed=True`).

**Per node, per model** (`handleNodes` -> `handleDevices`):
- `GetConfiguredDeviceCount` = count of Preparing+Reschedule pool devices allocated to this node,
  plus Online `ComposableResource`s on this node that are in use. "In use" means: visible in a
  node-local ResourceSlice through the attribute `uuid` == `ComposableResource.status.device_id`
  (`driverUUIDAttrMap = {"gpu.nvidia.com": "uuid"}`) **and** referenced by some claim allocation.
  The count is clamped by the max/min node labels (default max 50).
- Attach/detach is done **only** through `ComposabilityRequest` (cluster-scoped,
  `cro.hpsys.ibm.ie.com/v1alpha1`). DDS creates one per (model, node) with
  `generateName: composability-` and `spec.resource{type, model, size, target_node}`. Afterwards
  it JSON-patches `/spec/resource/size`. `type` comes from `GetDriverType`: `gpu.nvidia.com`
  maps to `gpu`, anything else to "".
- **Reschedule** (`RescheduleNotification`). Once enough `ComposableResource`s with
  `status.state == Online` on the target node are visible in node-local slices, unused, and past
  `DEVICE_NO_ALLOCATION_DURATION` since the annotation `<prefix>/last-used-time`, DDS patches
  `status.devices[]` of the claim. It creates entries from the allocation results if there are
  none, sets `{type: FabricDeviceReschedule, status: True, reason: DeviceConditionUpdated}`
  (merge patch on `/status`), and stamps the annotation.
- **Failure** (`RescheduleFailedNotification`): `FabricDeviceFailed=True` when models cannot
  coexist (`cannot-coexist-with`) or when the max count would be exceeded.
- **Detach** (`DynamicDetach`/`getNextSize`). When the configured count drops below
  `cr.spec.resource.size`, it lowers `size`. It keeps every Online/Attaching resource whose
  `<prefix>/last-used-time` (or creationTimestamp) is younger than `DEVICE_NO_REMOVAL_DURATION`.
  Detach is therefore lazy: about 10 minutes after the last use, never tied to pod deletion events.
- Node label `<prefix>/<k8s-device-name>` is set to `"true"` unless a coexistence conflict or a
  max=0 forbids it. This label gates the pool slice's nodeSelector.
- Timeouts: DDS has none of its own for attach. It relies on the scheduler's bindingTimeout
  (600 s) and on the operator's 30 s requeues.


## 4. CoHDI composable-resource-operator (CRO) and the mocks

**CRDs** (cluster-scoped, group `cro.hpsys.ibm.ie.com`, version `v1alpha1`):

```go
type ComposabilityRequestSpec struct{ Resource ScalarResourceDetails `json:"resource"` }
type ScalarResourceDetails struct {
  Type string `json:"type"`                          // enum "gpu";"cxlmemory"
  Model string `json:"model"`; Size int64 `json:"size"` // size >= 0
  ForceDetach bool `json:"force_detach,omitempty"`
  AllocationPolicy string `json:"allocation_policy,omitempty"` // "samenode"(default)|"differentnode"
  TargetNode string `json:"target_node,omitempty"`
  OtherSpec *NodeSpec `json:"other_spec,omitempty"` }  // milli_cpu, memory, ephemeral_storage, allowed_pod_number
type ComposabilityRequestStatus struct { State, Error string; Resources map[string]ScalarResourceStatus; ScalarResource ScalarResourceDetails }
type ScalarResourceStatus struct { State, DeviceID /*device_id*/, CDIDeviceID /*cdi_device_id*/, NodeName /*node_name*/, Error string }
type ComposableResourceSpec   struct { Type, Model, TargetNode /*target_node*/ string; ForceDetach bool }
type ComposableResourceStatus struct { State, Error, DeviceID /*device_id*/, CDIDeviceID /*cdi_device_id*/ string }
```

`cxlmemory` exists only in the enum. The README's supported-types table lists only `gpu`, and the
code paths are GPU-specific (nvidia-smi, restarting the NVIDIA DRA kubelet plugin pod, matching
by the `uuid` attribute).

**State machines.** ComposabilityRequest: `"" -> NodeAllocating -> Updating -> Running`, then
`Cleaning -> Deleting` on delete. In Updating it creates one `ComposableResource` per unit of
`size`, labelled `app.kubernetes.io/managed-by=<request>`. ComposableResource:
`None -> Attaching -> Online -> Detaching -> Deleting` (finalizer).
- **Attaching** calls `CDIProvider.AddResource()`. On `ErrWaitingDeviceAttaching` it requeues
  after 30 s. It then stores `status.device_id`/`cdi_device_id`. With DRA it runs nvidia-smi and
  deletes the vendor kubelet-plugin pod on the node so the plugin rescans. It polls
  `CheckGPUVisible` every 30 s (any ResourceSlice device with attribute `uuid == device_id`)
  before going `Online`.
- **Online** calls `CheckResource()` every 30 s, which only records errors.
- **Detaching**: unless `force_detach`, it checks for GPU load. With DRA it creates a
  `DeviceTaintRule` named `<cr>-taint`, selecting the device by `{driver, pool, device}`, with
  taint `{key: k8s.io/device-uuid, value: <device_id>, effect: NoSchedule}`. It then drains,
  calls `RemoveResource()`, restarts the plugin, waits until the device is no longer visible
  (3 s requeue), and deletes the taint rule.
- `upstreamsyncer_controller.go`: every 1 min it calls `GetResources()`. A device seen upstream
  without a ComposableResource for more than 10 min gets a detach CR with labels
  `cohdi.io/ready-to-detach-device-id` / `-cdi-device-id`.

**CDI provider interface** (`internal/cdi/client.go`). The env var `CDI_PROVIDER_TYPE` selects
`SUNFISH`, `NEC` or `FTI_CDI` (with `FTI_CDI_API_TYPE=CM|FM`). `DEVICE_RESOURCE_TYPE` is
`DEVICE_PLUGIN` or `DRA`.

```go
AddResource(*ComposableResource) (deviceID, CDIDeviceID string, err error)
RemoveResource(*ComposableResource) error
CheckResource(*ComposableResource) error
GetResources() ([]DeviceInfo /*NodeName, MachineUUID, DeviceType, Model, DeviceID, CDIDeviceID*/, error)
```

**FTI Fabric Manager client** (`internal/cdi/fti/fm/client.go`). Env vars: `FTI_CDI_ENDPOINT`,
`FTI_CDI_TENANT_ID`, `FTI_CDI_CLUSTER_ID`. HTTP timeout 180 s, OAuth2 token from the Secret
`credentials` (`username, password, client_id, client_secret, realm`):

| Op | Method + path (`?tenant_uuid=<t>`) | Body | Completion |
|---|---|---|---|
| attach | `PATCH fabric_manager/api/v1/machines/<muuid>/update` | `{"tenants":{"tenant_uuid":t,"machines":[{"mach_uuid":m,"resources":[{"res_specs":[{"res_type":type,"res_spec":{"condition":[{"column":"model","operator":"eq","value":model}]},"res_num":1}]}]}]}}` | **synchronous**: 200 with `data.machines[0].resources[0].{res_uuid, res_serial_num, res_op_status, res_spec}`. `res_op_status[0]` "0"=ok, "1"=warning (accepted), "2"=critical (error). `res_serial_num` becomes device_id, `res_uuid` becomes cdi_device_id |
| detach | `DELETE .../machines/<muuid>/update` | `{"tenants":{..."machines":[{"mach_uuid":m,"resources":[{"res_specs":[{"res_type":type,"res_uuid":<cdi_device_id>,"res_num":1}]}]}]}}` | 200 or 204. First checks with GET that the resource exists |
| get | `GET .../machines/<muuid>` | - | `data.machines[0].resources[].{res_uuid,res_type,res_op_status,res_serial_num,res_spec}` |

Waiting for completion happens through operator requeues (30 s) and the K8s-side visibility
check, not by polling the REST API. The CM variant uses
`POST cluster_manager/cluster_autoscaler/v3/tenants/<t>/clusters/<c>/machines/<m>/actions/resize`.
Sunfish uses `PATCH http://<ep>/redfish/v1/Systems/System`.

Machine UUID in CRO (`getNodeMachineID`):
- Without a cluster ID: `strings.CutPrefix(node.spec.providerID, "fsas-cdi://")`; any other
  format is an error.
- With a cluster ID: Node annotation `machine.openshift.io/machine` -> Metal3Machine annotation
  `metal3.io/BareMetalHost` -> BMH annotation `cluster-manager.cdi.io/machine`.

**cohdi-manager-mock `app.py`** (Flask, HTTPS on port 443, serving JSON files under `./in`):

| Route | Method | Behaviour |
|---|---|---|
| `/fabric_manager/api/v1/machines` | GET | `in/machines/list.json` |
| `/fabric_manager/api/v1/machines/<m>` | GET | `in/machines/<m>/fm_get_response.json` |
| `/fabric_manager/api/v1/machines/<m>/available-reserved-resources` | GET | `available.json` (`{"reserved_res_num_per_fabric":5}`) |
| `/fabric_manager/api/v1/machines/<m>/update` | PATCH | moves the first `fm_patch_response/*.json` to `allocated/` and returns it; 404 `no_available_resources` when empty |
| `/fabric_manager/api/v1/machines/<m>/update` | DELETE | always `{"status":"success"}` |
| `/cluster_manager/cluster_autoscaler/v3/.../machines/<m>` (GET), `.../actions/resize` (POST), `/cluster_manager/cluster_autoscaler/v2/.../nodegroups[/<ng>]` (GET) | | `detail.json`; `{"status":"success"}`; `nodegroups/list.json`, `<ng>/detail.json` |
| `/id_manager/realms/<realm>/protocol/openid-connect/token` | POST | static JWT (`exp` 32503680000), `expires_in: 300` |

`cohdi-ci-mock` implements the same FM routes for real nodes. It maps machine to node by
providerID (`rsplit("/",1)[-1]` when the ID contains `://`). PATCH runs
`echo 1 > /sys/bus/pci/rescan` in a pod on the node to "attach"; DELETE hides the resource.


## 5. Implications for fake-cxl-pool

### 5.0 Our existing node plugin (facts)

`kubelet-cxl-plugin` on branch `5fC-cxl` calls `kubeletplugin.Start(... NodeName(node),
DriverName(device.DriverName))` with `DriverName = "cxl.generic"`. It publishes one node-owned
pool named after the node. Its devices have type `cxl-node`/`dram`, `capacity.memory`,
`allowMultipleAllocations: true` and `nodeAllocatableResources`. In
`PrepareResourceClaims` (`node_state.go:470-475`) it skips any result where
`Driver != "cxl.generic" || Pool != <nodeName>` ("ignoring claim allocation device"). A pool device
would therefore be silently left unprepared until this check is changed.

### 5.1 (a) Minimal objects and controllers for attach-before-bind on k8s 1.37

No feature-gate changes are needed: `DRADeviceBindingConditions`, `DRAResourceClaimDeviceStatus`,
`DRAConsumableCapacity` and granular status authorization are all on by default. Optionally tune
`bindingTimeout` (default 600 s). The full set:

1. **fake-cxl-pool server** (host, REST, no Kubernetes dependency). It plays the part of the
   CoHDI "CDI manager" / Maxview. Required verbs: list devices (id, size, shareable, max sharers,
   current attachments), list VMs (id), attach(device, vm) and detach(device, vm), each
   idempotent and keyed by a client-supplied attachment id, plus a GET to poll attachment state.
2. **cxl-pool-controller** (one Deployment, a new component). It merges what CoHDI splits across
   composable-dra-driver, DDS and CRO. There is no need for ComposabilityRequest/
   ComposableResource CRs: the ResourceClaim *is* the request, and the attachment state lives in
   `claim.status.devices[]`. It has two jobs.
   - Publish the pool ResourceSlice(s) with `resourceslice.StartController` (unowned), with
     `ReconcilePoolWithName` if the driver name is shared (5.2).
   - Watch ResourceClaims and act on any result with `driver == <D>`, `pool == <pool>` and
     `bindingConditions` set, where `reservedFor` is non-empty, `allocation.nodeSelector` is set,
     and no condition is True yet. Map the node to a VM (5.3), call attach, and patch
     `status.devices[]`. On deallocation or deletion, call detach.
3. **kubelet-cxl-plugin** (exists; needs the extension in 5.2). In NodePrepare for pool devices
   it waits for the hotplugged memory, onlines it, applies policy and returns CDI devices. In
   NodeUnprepare it offlines the memory.
4. API objects: the pool `ResourceSlice`, a `DeviceClass` (for example
   `cxl-pool.generic`, CEL `device.driver == "<D>" && device.attributes["<D>"].source == "pool"`),
   user `ResourceClaim`/`ResourceClaimTemplate`, and RBAC for the controller:
   - `resourceslices`: get, list, watch, create, update, patch, delete
   - `resourceclaims`: get, list, watch
   - `resourceclaims/status`: get, patch, update
   - `resourceclaims/driver`: `arbitrary-node:patch`, `arbitrary-node:update`, `resourceNames: [<D>]`
   - `nodes`: get, list, watch
   - optionally `devicetaintrules`, to keep a failed device from being picked again
5. Optional node label, CoHDI style, to restrict the pool to VMs the server can hotplug into:
   `fake-cxl-pool.generic/attachable=true`, used in the slice `nodeSelector`. Without it, use
   `allNodes: true`.

Pool device example:

```yaml
apiVersion: resource.k8s.io/v1
kind: ResourceSlice
metadata: {generateName: cxl-pool-}
spec:
  driver: cxl.generic                 # or a separate name, see 5.2
  pool: {name: fake-cxl-pool, generation: 3, resourceSliceCount: 1}
  nodeSelector: {nodeSelectorTerms: [{matchExpressions: [{key: fake-cxl-pool.generic/attachable, operator: In, values: ["true"]}]}]}
  devices:
  - name: mem0
    attributes: {source: {string: pool}, type: {string: cxl-pool-mem}, poolDevice: {string: mem0}, size: {int: 268435456}}
    capacity: {memory: {value: 256Mi}}
    bindsToNode: true
    bindingConditions: ["cxl.generic/attached"]
    bindingFailureConditions: ["cxl.generic/attach-failed"]
```

The controller patch that releases the scheduler (merge or SSA on `/status`, using the
`resourceclaims/driver` permission):

```yaml
status:
  devices:
  - {driver: cxl.generic, pool: fake-cxl-pool, device: mem0, shareID: <from result, if any>,
     conditions: [{type: cxl.generic/attached, status: "True", reason: Attached, message: "mem0 -> vm n4-cxl-shared-2", lastTransitionTime: <now>}],
     data: {vm: <vm-id>, attachmentID: <claim-uid>/<shareID>, poolDevice: mem0, sizeBytes: 268435456}}
```

**Recommended path: the happy path.** Set `attached=True` after the attach finishes, and let
kubelet prepare the pool device. CoHDI's reschedule path (attach, wait for the node-local slice,
set the failure condition, reschedule) costs an extra scheduling cycle with backoff. It also opens
a race where another pod takes the freshly published node-local device, and it needs the
node-local slice to show hotplugged memory with an identity attribute. We control the node plugin,
so the happy path is cleaner. **Required either way:** after a hotplug, kubelet-cxl-plugin must
**not** advertise the attached pool memory as a free node-local `cxl-node` device. Otherwise the
same bytes are offered twice. Recognise it by serial/`poolDevice` and skip it, or publish it tainted.

### 5.2 (b) Who publishes the pool slice, and under which driver name

The pool slice must be published by the cluster-level cxl-pool-controller: cluster-scoped, no
`nodeName`. The node plugin cannot publish it, because a node-owned controller filters
`spec.nodeName=<node>` and kubelet wipes node-named slices on registration. The driver name
decides which kubelet plugin receives NodePrepareResources (1.7). There are two correct options.

- **A. Same driver name `cxl.generic`, different pool name (`fake-cxl-pool`).**
  - Kubelet already routes `cxl.generic` to kubelet-cxl-plugin. One NodePrepare call covers the
    local and pool devices of a claim.
  - The node plugin's node-owned slices and the controller's unowned slices cannot delete each
    other, because their field selectors are disjoint.
  - Changes needed:
    - replace the `Pool != NodeName` skip with a pool-device code path
    - the controller must use `ReconcilePoolWithName("fake-cxl-pool")` if anything else ever
      publishes cluster-scoped `cxl.generic` slices
    - the controller's `arbitrary-node` RBAC on `cxl.generic` would also let it write status
      for node-local devices
- **B. Separate driver name (for example `pool.cxl.generic`).**
  - kubelet-cxl-plugin starts a **second** `kubeletplugin.Helper` with
    `DriverName("pool.cxl.generic")`. Socket and registry paths are per driver, so this works.
    The second helper does not call `PublishResources`.
  - Without that registration, pods fail with `DRA driver pool.cxl.generic is not registered`.
  - Gains: clean RBAC scoping, no slice-reconcile interaction, and NodePrepare can tell pool
    claims apart by driver name.
  - Cost: a claim with both local and pool devices gets two NodePrepare calls.

Recommendation: **B** for production-like clarity, matching the earlier design doc
`cxl-dra-driver.stage-2.architecture.md`, which the KEP's GA section cites. **A** is the smallest
change for a test harness. CoHDI uses neither. It publishes under the vendor name and never lets
the kubelet see pool devices.

### 5.3 (c) Identifying a node (QEMU VM) to the pool

What the controller gets from the claim is the **node name**
(`allocation.nodeSelector...matchFields[metadata.name].values[0]`). Both CoHDI components then
resolve Node -> `spec.providerID` -> machine UUID: the substring after the last `/`, or
`fsas-cdi://<uuid>`. Options for our VMs:

1. **SMBIOS system UUID.** Start each QEMU with `-uuid <uuid>`. Kubelet reports it as
   `node.status.nodeInfo.systemUUID` (read from DMI product_uuid), with no kubelet configuration
   change. The server learns the UUID from the QEMU command line it already parses, and the
   in-VM client can read `/sys/class/dmi/id/product_uuid`. **Recommended** as the pool's VM key.
2. **providerID** `fake-cxl-pool://<uuid>`, set through kubelet `--provider-id` or the
   KubeletConfiguration `providerID`. It is immutable once the node has registered. This is
   CoHDI-compatible: the same last-segment rule works. Use it if you want the CoHDI components or
   mocks to work unchanged.
3. Node name to VM name through server config. Simple, but fragile.

Avoid `nodeInfo.machineID` (`/etc/machine-id`): cloned images can duplicate it. Our latency-bench
history already had a node-identity confusion. Whatever key you pick, the controller should
refuse to attach when the Node to VM lookup is ambiguous, and should set `attach-failed`.

### 5.4 (d) Expressing sharing across pods and nodes

- **Exclusive pooling** (one device, one node at a time): leave out `allowMultipleAllocations`.
  The allocation then takes the whole device.
- **Several pods on the same node sharing one attachment**: one ResourceClaim referenced by
  several pods (`reservedFor` <= 256). The first pod triggers attach. Later pods find the claim
  already allocated with conditions True, are pinned to the node by `allocation.nodeSelector`, and
  bind without waiting.
- **One memory device shared by N VMs** (the `share=on` backend attached to several QEMUs). A
  `bindsToNode` allocation covers one node only, so each node needs **its own claim**, and every
  claim takes a *share* of the same device:

```yaml
devices:
- name: shared0
  allowMultipleAllocations: true
  attributes: {source: {string: pool}, region: {string: shared0}, size: {int: 268435456}, shareable: {bool: true}}
  capacity:
    hosts: {value: "4", requestPolicy: {default: "1", validValues: ["1"]}}   # at most 4 attached VMs
  bindsToNode: true
  bindingConditions: ["cxl.generic/attached"]
  bindingFailureConditions: ["cxl.generic/attach-failed"]
```

  Do **not** put the region size into `capacity` on a shared device. Every allocation would
  consume it, and by default the full value. Each claim selects the region with CEL
  `device.attributes["cxl.generic"].region == "shared0"`. matchAttribute only works within one
  claim. Each result carries a distinct `shareID`. The controller must write `status.devices[]`
  with that `shareID`, and must attach once per (device, node). The device stays attached while
  any share for that node exists. Because PostFilter only deallocates a claim reserved for at
  most the failing pod, a failure on one node never pulls a share from another node.
- **Carving one big device into exclusive slices**: `allowMultipleAllocations: true` with
  `capacity.memory: {value: 1Gi, requestPolicy: {default: 256Mi, validRange: {min: 256Mi, step: 256Mi}}}`,
  and claims requesting `capacity.requests.memory`. This needs DCD-style partial attach in the
  fake server, so it is a later phase. `sharedCounters`/`consumesCounters` is the other way to
  model fixed partitions.
- Keep `nodeAllocatableResources.mapping` off pool devices for now. The feature is alpha and off,
  and mapped claims cannot be shared across pods. Whether the pod's memory cgroup must grow by the
  attached amount is an open question for the node plugin.

### 5.5 (e) Sequence: allocate -> attach -> bind -> prepare -> run -> delete -> detach

```text
User        kube-apiserver   resourceclaim-ctrl   kube-scheduler         cxl-pool-controller        fake-cxl-pool (host)     kubelet + kubelet-cxl-plugin (VM nodeX)
 |-- create Pod (+ResourceClaimTemplate) ->|
 |                |<-- create ResourceClaim from template --|
 |                |------------------------------------> Filter: local cxl.generic pools first, then
 |                |                                       pool "fake-cxl-pool" (has bindingConditions)
 |                |                                       Reserve; patch pod.status.nominatedNodeName=nodeX
 |                |<------------------------------------ PreBind/bindClaim: finalizer; status.allocation
 |                |   {devices.results[{driver,pool,device,shareID,bindingConditions,...}],
 |                |    nodeSelector{metadata.name In [nodeX]}, allocationTimestamp}; reservedFor=[pod]
 |                |                                       event BindingConditionsPending; poll 5s / 600s
 |                |-- watch event -------------------------------------------> result has bindingConditions,
 |                |                                                            none True, node=nodeX
 |                |<-- GET Node nodeX (systemUUID / providerID) ---------------|
 |                |                                                            |-- POST attach {device, vm,
 |                |                                                            |   attachmentID=claimUID/shareID} -->|
 |                |                                                            |                       QMP device_add (cxl-type3
 |                |                                                            |                       on free root port) ------>| ACPI hotplug,
 |                |                                                            |<-- 202; GET .../attachments/<id> -> attached --| memory appears
 |                |<-- PATCH status.devices[{...,conditions:[attached=True], data:{vm,attachmentID}}] (resourceclaims/driver)
 |                |------------------------------------> isPodReadyForBinding == true -> Bind pod to nodeX
 |                |-------------------------------------------------------------------------------------------------> kubelet: NodePrepareResources
 |                |                                                                                                    (driver = results[].driver):
 |                |                                                                                                    wait for hotplugged node, verify
 |                |                                                                                                    size, online, policy, CDI spec
 |                |                                                                                                    -> containers start (Running)
 |-- delete Pod ->|-------------------------------------------------------------------------------------------------> stop containers;
 |                |                                                                                                    NodeUnprepareResources: offline memory
 |                |<-- pod terminal/gone: drop reservedFor, allocation=nil, finalizer removed, delete generated claim
 |                |-- watch: allocation gone / claim deleted ----------------> |-- POST detach {attachmentID} --------->| QMP device_del ----------> eject
 |                |                                                            |<-- detached ---------------------------|
Failure: attach error -> controller sets attach-failed=True (optionally DeviceTaintRule or drops device from the slice)
  -> PreBind returns ErrDeviceBindingFailed -> next cycle Filter marks claim unavailable -> PostFilter clears
     allocation/reservedFor/status.devices -> re-allocation; the controller must detach anything half-attached.
Timeout: allocationTimestamp + bindingTimeout passed -> same deallocation path; the controller sees the allocation
  vanish and detaches. Make attach idempotent per attachmentID, because the scheduler may re-pick the same device and node.
```

Details to get right:
- **Detach ordering.** The API gives no guarantee that NodeUnprepare finished before the claim is
  deallocated. The claim controller deallocates when the pod reaches a terminal phase
  (`isPodDone`) or disappears. The controller should therefore make detach retryable and have the
  server refuse or retry while the guest still has the memory online. Alternatively, the node
  plugin can set a `cxl.generic/offlined` condition in NodeUnprepare, but that entry is lost when
  the scheduler or claim controller clears `status.devices`.
- **Pods sharing a claim.** For later pods, the scheduler does not wait in PreBind
  (`IsReservedForPod`). They still get NodePrepare on the node.
- **Restart safety.** A scheduler restart re-evaluates from API state. The controller must
  reconcile from claims and `status.devices[].data`, not from memory.
