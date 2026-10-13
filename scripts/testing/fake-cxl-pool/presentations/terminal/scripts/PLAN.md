# Terminal presentation: CXL memory from a pool, with Kubernetes DRA

Plan for a Python renderer that writes a series of UTF-8 text "frames" into
`presentations/terminal/rendered/`, to be shown with `less *` (`:n` / `:p`).
Nothing in this plan is implemented yet; the engineer implementing it should
re-check every fact against the file:line references in section A, and the
recorded e2e runs (section 0.2) whenever this plan and the code seem to
disagree. Where documentation and code disagree, the code wins (section H).

Contents

- 0 Scope, sources, ground truth
- A Fact sheet (components, messages, states, file:line)
- B Naming map (descriptive label -> technical label)
- C Screen design (width, height, mock frame, mock card, conventions, glyphs)
- D Arrow strategy
- E Storyboard (all frames, by chapter)
- F Python DSL / API design
- G Open questions and assumptions
- H Documentation vs code disagreements found
- Implementation notes (where the implementation deviates from this plan)


## 0 Scope, sources, ground truth

### 0.1 What the presentation shows

1. Normal case: a pod's ResourceClaim is resolved when the pod is created.
   The pool device becomes a NUMA node (exclusive device, mode `numa`, the
   default) or a devdax device `/dev/daxX.Y` (mode `dax`). Release on pod
   deletion.
2. Dynamic case: a running container borrows pool memory through the node's
   agent ("lease"): as a NUMA node added to its own cpuset.mems, or as an
   open devdax file descriptor passed over a unix socket. Release while
   running; cleanup when the pod is deleted with leases alive.
3. Sharing: one shared device attached to several nodes, same bytes, devdax
   only; one claim per node.
4. Finale (e2e test13): one exclusive writer (all "hosts" capacity of the
   shared device), three read-only readers on two nodes waiting and then
   holding the memory at the same time, a late exclusive request that fails
   cleanly, a fourth reader with a read-only claim, teardown.

### 0.2 Sources, in order of authority

1. Recorded e2e runs (real message order and timings), untracked in the main
   checkout:
   `/home/akervine/github.com/containers/nri-plugins/test/e2e/n4-cxl-shared-2-fedora-43-containerd/memory.test-suite/memory-policy/test1{0,1,2,3}-*/trace-summary.txt`
   (test13: 613 lines, PASS, "writer exit until all readers hold: 13.18 s").
2. Code. nri-plugins worktree (branch cxl-presentation):
   `scripts/testing/fake-cxl-pool/` (server, client, controller) and
   `pkg/cxl/memctl/memctl.go`; e2e tests
   `test/e2e/memory.test-suite/memory-policy/n4-cxl-shared-2/test1{0,1,2,3}-*/code.var.sh`,
   `pool.source.sh`, `pool-dax-rw.py`, `numa-touch.py`, and
   `test/e2e/memory.test-suite/memory-policy/dra.source.sh`.
   DRA driver (read only): `/home/akervine/github.com/intel/intel-resource-drivers-for-kubernetes`
   `cmd/kubelet-cxl-plugin/{pool,broker,dynamic,lend,nri,driver,node_state,lease_store,main}.go`,
   `cmd/cxl-request/main.go`, `pkg/cxl/device/device.go`,
   `deployments/cxl/pool/*.yaml`, `deployments/cxl/pool/examples/*.yaml`.
3. Docs: driver `doc/cxl/POOL.md` (the contract), nri-plugins
   `scripts/testing/fake-cxl-pool/README.md`, `plan-3-cxl-live-attach/03-summary.txt`,
   untracked notes `5jS-*.txt`, `5jW-*.txt`, `5jY-*.txt`,
   `plan-4-multinode/02-implementation-status.txt`,
   `plan-3-cxl-live-attach/cxl-request-daxfile/00-STATUS.txt`.

Paths below: `driver/` = the DRA driver repo, `pool/` =
`scripts/testing/fake-cxl-pool/`, `e2e/` =
`test/e2e/memory.test-suite/memory-policy/`.

### 0.3 Names used on screen

| on screen | real thing |
|---|---|
| node-a | VM1 = `n4-cxl-shared-1-fedora-43-containerd`, worker in test13 |
| node-b | VM2 = `n4-cxl-shared-2-fedora-43-containerd`, control plane in test13; the single node of test10/test12 |
| pooled0 | exclusive pool device, serial `0xc1ee0001`, 512M (`0xc1ee` = e..e of "exclusive") |
| shared0 | shared pool device, serial `0xc1ae0001`, 256M (`0xc1ae` = a..e of "share") |
| C1EE0001 / C1AE0001 | the serials as they appear in environment variable names |
| TEXT | the string the writer writes, e.g. `dra-one-writer 2026-10-12T15:41:03...: written by the exclusive writer` |

Chapters 1-3 happen on node-b alone (that is where test10 and test12 ran);
node-a joins in chapter 4.


## A Fact sheet

Zones: CLUSTER = anywhere in the cluster; NODE = specific to one node;
CONTAINER = inside the CXL-using workload container; OUTSIDE = possibly
outside the cluster.

### A.1 Memory pool manager -- `fake-cxl-pool-server` (OUTSIDE)

- Runs on the host next to qemu; listens `127.0.0.1:9909`; VMs reach it at
  `http://192.168.76.2:9909` (`pool/pkg/api/routes.go:23-26`). Stands in for
  a CXL fabric manager / appliance (real ones have a REST API too, e.g.
  Maxview; none has a read-only attach, `driver/doc/cxl/POOL.md:197-201`).
- Owns devices = backing files in pool directories; attaches a device by
  hot-plugging a `cxl-type3` qemu device into the node's VM over QMP, and
  detaches by hot-removing it (`pool/README.md:3-19`).
- REST API `/api/v1` (`pool/pkg/api/routes.go:32-54`): used by the
  controller: `GET /devices?scope=pool`, `GET /hosts`, `GET /attachments`,
  `POST /devices/{name}/attachments` body
  `{host, owner, wait, timeout, exclusive}` (`pool/pkg/api/types.go:189-202`),
  `DELETE /devices/{name}/attachments/{host}?wait=&timeout=`,
  `GET /events` (SSE; the controller reconciles on every event,
  `pool/pkg/controller/controller.go:242-266`).
- Attach responses: 201 attached, 200 already attached (an attach of an
  attached device only updates its `exclusive` flag), 202 attaching, 409
  conflicts, 503 qemu error (`pool/README.md:253-258`; `pool/pkg/server/ops.go:630-830`).
- Attach sequence to qemu (`pool/pkg/server/ops.go:768-776`, `pool/pkg/qemu/qmp.go:368-396`):
  `object-add memory-backend-file {id, size, mem-path, share=on}` then
  `device_add cxl-type3 {id, bus, volatile-memdev, serial}`; qemu device id
  `fcp_<device>.hp<n>` (`ops.go:741`). The guest kernel then sees a new
  `memN` with that serial (udev `add .../memN (cxl)`).
- Detach sequence (`ops.go:921-1049`): `device_del <id>` -> wait for the
  QMP event `DEVICE_DELETED` (about 5-6 s, PCIe hot-remove in the guest) ->
  `object-del` of the backend -> attachment `detached`. If the guest still
  uses the memory, `DEVICE_DELETED` never comes: attachment `failed`, device
  `error`, "release before detach" (`pool/README.md:160-168`).
- Exclusive attach rules (`ops.go:491-510`, `833-850`): an exclusive attach
  is refused (409) while the device is attached to another host; any attach
  to another host is refused while an exclusive attachment exists; this
  also keeps out other clusters sharing the pool.
- Device states: `free`, `attaching`, `attached`, `detaching`, `error`
  (`types.go:130-136`). Attachment states: `attaching`, `attached`,
  `detaching`, `detached`, `failed` (`types.go:205-211`); an attachment has
  `owner` (controller writes `k8s:resourceclaim/<claim uid>`) and
  `exclusive` (`types.go:214-233`).
- Shown in the e2e config: pool `default` in `/tmp/fake-cxl-pool`, devices
  `shared0` (256M shared) and `pooled0` (512M exclusive), `detachTimeout: 15s`
  (`e2e/n4-cxl-shared-2/pool.source.sh:303-318`, test13 `code.var.sh:236-246`).

### A.2 Pool controller -- `fake-cxl-pool-controller` (CLUSTER)

- The cluster side of DRA driver `cxl-pool.generic`; one per cluster; in the
  e2e it runs as a transient systemd unit on the control-plane VM with the
  admin kubeconfig (`e2e/dra.source.sh:233-236`). Stateless
  (`pool/README.md:203-206`).
- Defaults (`pool/pkg/controller/controller.go:46-57`): driver
  `cxl-pool.generic`, pool name `fake-cxl-pool`, sync 10 s, attach/detach
  timeout 60 s, shared hosts 4, owner prefix `k8s:`, debounce 500 ms.
  Watches ResourceClaims and Nodes (informers, `controller.go:151-162`) and
  the server event stream.
- Publishes ONE cluster-scoped ResourceSlice (`allNodes`, no owner; deleted
  on shutdown) with one device per pool device (`publisher.go:53-94`,
  `141-174`, `185-203`):
  attributes `source=pool`, `pool=<server pool>`, `serial="0x..."` (lower
  case), `shared` (bool), `size` (bytes); `bindsToNode: true`,
  `bindingConditions: [cxl-pool.generic/Attached]`,
  `bindingFailureConditions: [cxl-pool.generic/AttachFailed]`.
  Exclusive device: `capacity.memory = size`. Shared device:
  `allowMultipleAllocations: true`, `capacity.hosts = 4` with
  `requestPolicy {default: 1, validValues: ["1", "4"]}`. Devices in state
  `error` are not published (`publisher.go:107-110`).
- Node -> pool host: the host whose uuid equals the Node's
  `status.nodeInfo.systemUUID` (qemu `-uuid`), else the host with the node's
  name (`pool/pkg/controller/hosts.go:27-61`).
- Reconcile (`reconciler.go:122-239`): desired attachments = allocated
  claims of the driver (node from `allocation.nodeSelector` matchFields
  `metadata.name`, `reconciler.go:106-117`); exclusive if the result's
  `consumedCapacity.hosts >= 4` (`reconciler.go:62-69`). Existing
  attachments are processed before new ones (`reconciler.go:195-201`). An
  attachment whose `exclusive` flag differs from what its claims want gets
  a new attach request that only flips the flag (`reconciler.go:204`).
- Attach request (`reconciler.go:261-267`):
  `POST /devices/<dev>/attachments {host, owner: k8s:resourceclaim/<uid>, wait: true, timeout: "1m0s", exclusive}`.
  Log: `attached <dev> to <host> (node ..., slot ..., qemu device ..., owner ..., exclusive ...)`.
- Claim status write (`reconciler.go:305-359`, `status.go:102-167`):
  `UpdateStatus` of `claim.status.devices[]` entry (driver, pool, device,
  shareID) with condition `cxl-pool.generic/Attached=True`, reason
  `Attached`, message `<dev> attached to <host> (slot <bus>)`, and `data`
  `{serial, shared, size, host, hostUUID, attachment, qemuDeviceId, exclusive}`
  (`status.go:48-57`). Written only when the attachment is `attached` and
  its exclusive flag matches (`reconciler.go:328`). Event `Attached` on the
  claim. Failure: `cxl-pool.generic/AttachFailed=True` with reason `NoHost`,
  `AttachError`, `Timeout` or `Conflict` (`status.go:31-36`).
- Detach (`reconciler.go:379-428`): when no allocated claim wants the
  attachment any more: `DELETE /devices/<dev>/attachments/<host>?wait=true&timeout=1m0s`;
  event `Detached` on the claim (or the Node). Only `attached` attachments
  are detached; `detaching`/`failed` are logged.
- States worth showing: `publishing N devices`; `attach <dev> -> <node>`;
  `attached`; `Attached=True written`; `detach <dev>@<node>`; `idle`.

### A.3 Kubernetes API + objects -- `kube-apiserver` (CLUSTER)

Objects of this story (all `resource.k8s.io/v1` unless noted):

- DeviceClass `cxl-pool-memory`: CEL `device.driver == "cxl-pool.generic" && device.attributes["cxl-pool.generic"].shared == false`;
  `cxl-shared-memory`: same with `shared == true`
  (`driver/deployments/cxl/pool/device-classes.yaml`). `cxl-dynamic`:
  `device.driver == "cxl.generic" && device.attributes["cxl.generic"].type == "dynamic"`
  (`device-class-dynamic.yaml`).
- ResourceSlice of the pool (A.2) and one per node from the node agent
  (A.5): driver `cxl.generic`, devices `dram` (type `dram`), `cxl-node`
  regions, and the token `dynamic` (attributes `type=dynamic`,
  `name=dynamic`, no capacity, `allowMultipleAllocations`;
  `driver/cmd/kubelet-cxl-plugin/node_state.go:354-365`).
- ResourceClaim: `spec.devices.requests[].exactly {deviceClassName, capacity.requests, selectors[].cel}`,
  `spec.devices.config[].opaque {driver, parameters}`; `status.allocation`
  (written by the scheduler: `devices.results[] {driver, pool, device, request, shareID, consumedCapacity, bindingConditions...}`,
  `nodeSelector`), `status.reservedFor` (the pod), `status.devices[]`
  (written by the controller, A.2). Examples used: `pooled-memory`
  (test10 `code.var.sh:109-122`), `pooled-dax` (test13 `475-493`),
  `shared-memory` (test11 `46-65`), `shared-read-only` (test13 `395-413`),
  companion claims `cxl-lease-<id>` (A.5).
- Pod: `spec.resourceClaims[] {name, resourceClaimName|resourceClaimTemplateName}`,
  `containers[].resources.claims[]` (only listed containers get the CDI
  edits). Pods used: `pooled-consumer`, `dax-claimer`, `borrower`
  (containers `main`, `idle`), `writer`, `reader-a/b/c/d`, companions
  `cxl-lease-<id>` (pause).
- Events: `BindingConditionsPending` (pod, scheduler), `Attached`,
  `Detached` (claim, controller), `FailedScheduling "0/2 nodes are available: 1 cannot allocate all claims, 1 node(s) didn't satisfy plugin(s) [NodeAffinity]"`
  (companions waiting for capacity, test13 trace +9.8 s).

### A.4 Scheduler -- `kube-scheduler` (CLUSTER)

- Allocates a device for every unallocated claim of a pending pod: tries
  slices without binding conditions first (node-local `cxl.generic`), picks
  pool devices by DeviceClass CEL, capacity (`memory >= request`,
  `hosts` default 1 or all 4) and selectors; writes `status.allocation`
  with `nodeSelector` = the picked node (`bindsToNode`), emits the pod event
  `BindingConditionsPending "waiting for binding conditions for device on node <node>"`,
  then polls the claim (every few seconds, up to 600 s) until
  `cxl-pool.generic/Attached` is True and binds the pod (`POOL.md:208-217`;
  test10 trace: allocation +0.08 s, Attached +0.6 s, `Scheduled` +5.1 s).
- A shared device with all 4 hosts consumed cannot be allocated: the pod
  stays Pending / `PodScheduled=False, Unschedulable` (test13 `code.var.sh:318-326`,
  trace `FailedScheduling ... cannot allocate all claims`).
- Nothing to configure (Kubernetes >= 1.37: `DRADeviceBindingConditions`,
  `DRAResourceClaimDeviceStatus`, `DRAConsumableCapacity` on by default,
  `POOL.md:45-48`).

### A.5 Node's CXL agent -- `kubelet-cxl-plugin` (NODE)

One host process per node (e2e: systemd unit `kubelet-cxl-plugin` with
`--node-name`, `KUBECONFIG`, `--cxl-request-bin /usr/local/bin/cxl-request -v 4`,
`e2e/dra.source.sh:303-314`). It must run with host pid namespace and the
NRI socket (`POOL.md:607-609`). Composition (`driver/cmd/kubelet-cxl-plugin/driver.go:240-330`,
`401-433`):

1. DRA kubelet plugin `cxl.generic` (node-local memory; publishes the node
   slice; prepares DRAM/CXL claims and token claims).
2. DRA kubelet plugin `cxl-pool.generic` ("pool helper", `pool.go`): socket
   `/var/lib/kubelet/plugins/cxl-pool.generic/dra.sock` (`POOL.md:271`,
   `dra.source.sh:357`); never publishes slices; state file
   `preparedPoolClaims.json` (`pool.go:58`).
3. NRI plugin (`nri.go`, `lend.go`): tracks containers (pid, cgroup,
   `cpuset.mems.effective`), lends/revokes NUMA nodes with
   `UpdateContainers(cpuset.mems)` (`lend.go:535-553`).
4. Lease broker (`broker.go`, `dynamic.go`, `lease_store.go`): unix socket
   per token claim, creates companion claims and pods, passes dax fds.
   Lease table `leases.json` (`lease_store.go:28`).

Pool helper, `NodePrepareResources` (`pool.go:304-421`):
- Reads `claim.status.devices[]` data `serial`, `shared`, `size`
  (`pool.go:627-655`; missing -> error, kubelet retries), and the
  `PoolDeviceConfig` (`pool.go:455-494`, kind `PoolDeviceConfig`, apiVersion
  `cxl-pool.generic/v1alpha1`, fields `mode: numa|dax`, `readOnly`; claim
  config beats class config). Mode rules (`pool.go:496-516`): shared ->
  dax only; exclusive default numa; readOnly needs dax.
- Waits for the memdev with the serial (`/sys/bus/cxl/devices/memN/serial`),
  up to `--pool-prepare-timeout` 30 s (`pool.go:61`, `657-671`).
- Mode numa (`pool.go:708-722`; `memctl.go:471-544`, `572-590`):
  `cxl enable-memdev` if needed, `cxl create-region -t ram -d <root decoder> -m memN`,
  bind dax to `kmem` (`daxctl reconfigure-device --mode=system-ram --no-online`),
  online every block `online_movable` -> a new NUMA node N. CDI device
  `generic/cxl=pool-<serial>` with env `CXL_POOL_NODE_<SERIAL>=N`,
  `CXL_POOL_SIZE_<SERIAL>=<bytes>`, `CXL_POOL_SERIAL_<SERIAL>=0x<serial>`
  (`pool.go:855-859`). cpuset.mems is NOT changed (`POOL.md:297-302`,
  open TODO there: nothing keeps other containers off the node).
- Mode dax (`pool.go:692-706`): `cxl create-region -t ram ...`, then bind
  the dax device to `device_dax` (`daxctl reconfigure-device --mode=devdax`),
  memory never onlined. CDI device `generic/cxl=pool-<serial>` (or
  `pool-<serial>-ro`): device node `/dev/daxX.Y` (`c major:minor`,
  permissions `r` when readOnly) and env `CXL_POOL_DAX_<SERIAL>=/dev/daxX.Y`,
  `CXL_POOL_SIZE_`, `CXL_POOL_SERIAL_` for exclusive devices, the same with
  prefix `CXL_SHARED_` for shared devices, plus `..._READONLY_<SERIAL>=1`
  when readOnly (`pool.go:829-862`). CDI spec file name `cxl-pool`
  (`device.go:54`).
- A region that already exists on the memdev is reused (second claim of the
  same shared device on the node; `memctl.go:481-485`); a claim wanting
  another mode than the one prepared fails (`pool.go:596-610`).
- Companion claims carry a `LendConfig` (`pool.go:423-453`): then the
  helper lends numa nodes (`pool.go:538-551`, `LendNode`) and tells the
  broker `OnLending`/`OnPrepared` (`pool.go:72-85`).
- Log line to quote: `cxl-pool.generic: claim <ns>/<name>: prepared <dev> (serial 0x..., shared ..., mode ..., read-only ...) as memN regionN dax daxX.Y node N`.
- The `cxl.generic` publisher never advertises a region of a prepared pool
  device (`node_state.go:216` log `ignoring region device "region0": pool device`).

Pool helper, `NodeUnprepareResources` (`pool.go:757-802`): revoke lent nodes
first (`pool.go:772-783`), then, unless another prepared claim uses the
serial (`still used by another claim`), release (`memctl.go:595-622`):
offline blocks (numa), `cxl disable-region`, `cxl destroy-region`,
`cxl disable-memdev`. A memdev that is gone is fine. Log:
`released memN (serial 0x...)`, `unprepared claim ...`.

Token claims (`dynamic.go`): prepare of a claim on device `dynamic` creates
`/var/lib/kubelet/plugins/cxl.generic/leases/<claim uid>/cxl.sock` (dir
0755, socket 0666, SELinux `container_file_t` best effort,
`dynamic.go:237-279`) and returns CDI device `generic/cxl=lease-<claim uid>`
(spec `cxl-leases`): bind mount of the directory at `/run/cxl` (rbind, rw),
bind mounts (ro) of the static CLI at `/usr/local/bin/cxl-request` and
`/usr/local/bin/cxl-release`, env `CXL_LEASE_SOCKET=/run/cxl/cxl.sock`
(`dynamic.go:98-126`); plus the marker env `CXL_CLAIM_<uid>=1` of every
`cxl.generic` claim (`node_state.go:51-52`). Unprepare releases all leases
of the claim first ("still releasing N leases, retry") then removes socket
and directory (`dynamic.go:192-233`).

Lease broker protocol (`broker.go:96-130`; `POOL.md:480-529`): SOCK_STREAM
unix socket, one JSON object per line. Requests:
`{"op":"lease","kind":"memory","size":"512Mi","wait":"120s"[,"mode":"dax","readOnly":true]}`,
`{"op":"lease","kind":"shared","serial":"0xc1ae0001"[,"exclusive":true][,"readOnly":true]}`,
`{"op":"release","lease":"<id>"}` / `{"op":"release","all":true}`,
`{"op":"list"}`, `{"op":"fd","lease":"<id>"}`. Response:
`{"lease":"<8 hex>","state":...,"kind","mode","exclusive","readOnly","node":N,"size","serial","dax","error"}`;
the response of a Ready dax lease carries the open fd as SCM_RIGHTS on the
same write (`broker.go:391-422`). Caller authentication (`broker.go:425-450`):
the socket identifies the token claim -> its pod(s) (`reservedFor`);
`SO_PEERCRED` gives the pid -> `/proc/<pid>/cgroup` -> container (NRI
table). Lease states (`lease_store.go:33-41`): `Creating` (stored before
any API object), `Pending` (companion claim+pod exist), `Lending`
(companion claim being prepared), `Ready`, `Releasing`, `Failed`, `Released`
(response only). `wait` default 120 s (`main.go:62`, `--lease-wait-default`);
at timeout the lease is released and reported `Failed` with error
`timeout: not Ready after <wait>` (`broker.go:718-748`).

Companion objects (`broker.go:855-962`, `966-999`), both named
`cxl-lease-<id>`, in the requester's namespace, labels
`cxl-pool.generic/lease=<id>`, `cxl-pool.generic/requester-uid=<pod uid>`,
`cxl-pool.generic/node=<node>`, annotation
`cxl-pool.generic/requester=<ns>/<pod>/<container>`, ownerReference to the
requester pod (claim: `controller: true`):
- ResourceClaim: request `lease`: memory lease -> `deviceClassName: cxl-pool-memory, capacity.requests.memory: <size>`;
  shared lease -> `deviceClassName: cxl-shared-memory, selectors: [cel: device.attributes["cxl-pool.generic"].serial == "<serial>"]`,
  and for an exclusive lease `capacity.requests.hosts: "4"` (the value read
  from the pool ResourceSlice, `broker.go:574-604`). Opaque configs: always
  `LendConfig {lease, pod{namespace,name,uid}, container}`; for a dax lease
  also `PoolDeviceConfig {mode: dax, readOnly}`.
- Pod: one container `pause` (`registry.k8s.io/pause:3.10`), requests =
  limits cpu 100m / memory 8Mi (Guaranteed), required node affinity
  `metadata.name In [<node>]`, `tolerations: [{operator: Exists}]`,
  `restartPolicy: Always`, `resourceClaims: [{name: lease, resourceClaimName: cxl-lease-<id>}]`,
  no `resources.claims` (kubelet prepares a pod's claims anyway).

Lend / revoke: `LendNode` -> NRI `UpdateContainers` with
`cpuset.mems = base + lent nodes` of THAT container only
(`lend.go:452-553`); refused for containers steered by a local CXL claim
(`lend.go:82`). `RevokeNode` shrinks cpuset.mems: the kernel migrates the
pages to DRAM, the process lives on (test12 `code.var.sh:356-382`). Dax
leases: the broker opens `/dev/daxX.Y` `O_RDWR`, or `O_RDONLY` for
`readOnly` (`broker.go:1429-1432`) and sends the fd.

Release (`broker.go:1022-1086`): `Releasing` -> revoke node (memory lease)
-> delete companion pod and claim -> wait until both are gone -> drop the
lease (`released`). Kubelet unprepares the companion claim in between.
Requester container stops (`broker.go:1135-1184`): leases are released if
the pod is deleted, Succeeded/Failed, or has `restartPolicy: Never`
(the writer of test13); otherwise kept for a restart. Companion deleted
behind the broker's back -> lease `Failed "companion claim unprepared"`
(`broker.go:1409-1425`). Reconcile every 60 s.

### A.6 Pod runner on the node -- `kubelet` (+ containerd, NRI) (NODE)

- Watches pods bound to the node; calls the DRA plugins over their sockets:
  `NodePrepareResources(claims)` before the sandbox/containers are created,
  `NodeUnprepareResources` while the pod terminates (before the pod object
  is gone; `POOL.md:361-363`; test10 trace: offline at +10.7 s, pod
  Completed +10.96 s, claim deallocated +11.0 s).
- Starts containers through containerd, which applies the CDI edits (env,
  device nodes, mounts) and runs NRI plugins (the agent) on
  Create/Start/Stop/Remove; NRI `UpdateContainers` from the agent changes
  cpuset.mems of a running container (`lend.go:19-32`).

### A.7 CXL memory seen by the node (NODE, hardware view)

- `/sys/bus/cxl/devices/memN` (serial), `regionN`, `dax_regionN/daxX.Y`,
  dax driver `kmem` (system RAM) or `device_dax` (`/dev/daxX.Y`), memory
  blocks `/sys/devices/system/memory/memoryK` (`online_movable`/`offline`),
  NUMA node `/sys/devices/system/node/nodeN` (`pool-cxl-dump` in the e2e;
  test10 trace: `add .../mem0 (cxl)`, `add .../region0`, `add dax0.0`,
  `add node2`, `online memory202..205`).
- `auto_online_blocks` must be `offline` (`pool.source.sh:212`): the
  kernel must never online a shared device as RAM by itself.
- Two VMs that online the same memory as RAM corrupt each other silently;
  devdax mmap needs `CONFIG_FS_DAX` (`pool/README.md:145-147`).
- Numbers in the recorded runs: pooled0 -> `mem0 region0 dax0.0 node 2`
  (512 MB online, 4 blocks); shared0 -> `mem0 region0 dax0.0` (`OnlineSize 0`).

### A.8 Workload container and `cxl-request` (CONTAINER)

- Claim at pod creation, numa: env `CXL_POOL_NODE_C1EE0001=2`,
  `CXL_POOL_SIZE_C1EE0001=536870912`, `CXL_POOL_SERIAL_C1EE0001=0xc1ee0001`;
  the container sees `/sys/devices/system/node/node2/meminfo` and (if its
  cpuset is unrestricted) `Mems_allowed_list 0-2` (test10 `code.var.sh:142-146`, `190-198`).
- Claim, dax: device node `/dev/dax0.0` (permissions `r` when readOnly),
  env `CXL_POOL_DAX_C1EE0001=/dev/dax0.0` (exclusive) or
  `CXL_SHARED_DAX_C1AE0001=/dev/dax0.0`, `..._SIZE_`, `..._SERIAL_`,
  `CXL_SHARED_READONLY_C1AE0001=1`; apps `mmap(MAP_SHARED, 2 MiB aligned)`
  (`pool-dax-rw.py:30-34`). Read-only: `open(O_RDWR)` -> `EPERM` (device
  cgroup), `mmap(PROT_WRITE)` -> `EACCES` (test13 `code.var.sh:420-422`).
- Token claim: `/run/cxl/cxl.sock`, `/usr/local/bin/cxl-request`,
  `/usr/local/bin/cxl-release`, env `CXL_LEASE_SOCKET`; the other container
  of the pod (`idle`) has none of it (test12 `code.var.sh:511-521`).
- `cxl-request` (`driver/cmd/cxl-request/main.go:22-39`, `98-110`):
  `cxl-request memory <size> [--wait D] [--request-id ID]`,
  `cxl-request memory <size> --dax [--read-only] [--exec CMD...]`,
  `cxl-request shared <serial> [--exclusive] [--read-only] [--wait D] [--exec CMD...]`,
  `cxl-request fd <lease> --exec CMD...`, `cxl-release <lease>|--all`,
  `cxl-request list`. Prints the JSON response line. With `--exec`, CMD runs
  with the dax fd as fd 3 and env `CXL_LEASE_FD=3`, `CXL_LEASE=<id>`,
  `CXL_LEASE_DAX=/dev/daxX.Y` (host path, informational),
  `CXL_LEASE_SIZE=<bytes>`, `CXL_LEASE_READONLY=0|1` (`main.go:413-419`).
  Exit codes 0 ok, 1 error, 2 usage, 3 lease Failed / not Ready in time
  (`main.go:59-66`, `297-324`).
- Memory lease: `cpuset.mems` of the calling container grows by node N
  (test12: `0-1` -> `0-1,2` for `main`, `idle` unchanged, `code.var.sh:317-324`);
  lent memory counts against the container's `memory.max` (`POOL.md:580-583`).
- Shared/dax lease: no `/dev/dax*` in the container, device cgroup
  unchanged, a node made with `mknod` cannot be opened (EPERM), the passed
  fd works (test12 `code.var.sh:429-447`); `/proc/<pid>/fd/3` cannot be
  reopened either (`plan-4-multinode/02-implementation-status.txt` section 7).

### A.9 Timings worth quoting (recorded runs)

- test10: claim allocated +0.08 s, pool attached +0.6 s, Attached written
  +0.6 s, `Scheduled` +5.1 s (scheduler poll), region/node online +5.6 s,
  container Running +6.2 s; delete: Terminating +10.3 s, memory offline
  +10.7 s, claim deallocated +11.0 s, `device_del` +11.5 s, `DEVICE_DELETED`
  +17.6 s (hot-remove about 6 s).
- test12: a lease is Ready about 5-7 s after `cxl-request`, a release takes
  about 8 s (`POOL.md:598-599`); pod deleted with 2 leases alive: clean in
  < 90 s.
- test13: writer exit until all three readers hold: 13.2 s (this run; 9.4 s
  in another), of which about 6 s hot-remove and about 5 s scheduler poll.


## B Naming map

Box title = descriptive label; first line inside the box = technical label
in parentheses. Short forms for 26-wide boxes in the right column.

| descriptive label (box title) | technical label (line 1) | short |
|---|---|---|
| Memory pool manager | fake-cxl-pool-server, on the host, REST :9909 | pool |
| Pool controller | fake-cxl-pool-controller (cluster side of DRA driver cxl-pool.generic) | ctrl |
| Kubernetes API + objects | kube-apiserver: slices, claims, pods | API |
| Scheduler | kube-scheduler | schd |
| Pod runner | kubelet, containerd, NRI | kblt |
| Node's CXL agent | kubelet-cxl-plugin: DRA plugins cxl.generic + cxl-pool.generic, NRI plugin, lease broker | agnt |
| CXL memory seen by the node | /sys/bus/cxl: memN regionN daxX.Y, NUMA nodes | HW |
| `<pod> / <container>` (double-line box) | pod `<pod>`, container `<container>` | Pod |
| request tool in the container | cxl-request / cxl-release CLI, unix socket /run/cxl/cxl.sock | |
| pool device, exclusive | pooled0, serial 0xc1ee0001, 512M, capacity memory 512Mi | |
| pool device, shared | shared0, serial 0xc1ae0001, 256M, capacity hosts 4 (default 1, valid 1 or 4) | |
| offer list of the pool | ResourceSlice, driver cxl-pool.generic, pool fake-cxl-pool, allNodes | slice |
| offer list of a node | ResourceSlice, driver cxl.generic, node-local: dram, cxl-node, dynamic | |
| kind of device wanted | DeviceClass cxl-pool-memory / cxl-shared-memory / cxl-dynamic | class |
| memory request | ResourceClaim (spec.devices.requests; status.allocation; status.devices[]) | claim |
| permission slip for later requests | token device "dynamic" (claim on DeviceClass cxl-dynamic) | token |
| attach order of the controller | attachment `<device>@<host>` {owner, exclusive, state} | |
| memory lease | lease `<8 hex>` {kind memory/shared, mode numa/dax, exclusive, readOnly, state} | |
| companion pod / claim | cxl-lease-`<id>` (pause container holding the claim) | |
| device options | PoolDeviceConfig {mode: numa/dax, readOnly} | |
| lend ticket | LendConfig {lease, pod, container} | |
| container edits | CDI device generic/cxl=pool-`<serial>`[-ro], generic/cxl=lease-`<claim uid>` | |
| binding wait | binding condition cxl-pool.generic/Attached (failure: AttachFailed) | |


## C Screen design

### C.1 Width and height

- Width: 120 columns. 80 cannot hold two nodes side by side; 100 leaves 20
  characters per workload box, not enough for `lease ce5ef151 Pending`
  plus a marker. 120 is what a 1080p projector shows at a 24 pt monospace
  font (about 16 px per cell), which is the largest font a presenter would
  use; wider risks `less` wrapping lines, which destroys the picture.
  Every output line is at most 120 characters (checked).
- Height: the diagram is lines 0-29 (30 lines), legend line 29 included,
  caption lines 30-32, blank line 33, message sequence from line 34. The
  diagram+caption (34 lines) fits a 1080p terminal at 24 pt (about 33-34
  lines) and leaves 6+ sequence rows visible at 40 lines. The diagram
  region has the same height in every frame (checked), so nothing jumps
  between `:n` presses; the sequence grows below and is scrolled when wanted.
- Two layouts share every row: `SINGLE` (chapters 0-3: one node, node-b,
  spanning columns 4-115, wide boxes) and `TWO_NODES` (chapters 4-5). A
  layout changes only at a chapter card.

### C.2 Column map (TWO_NODES)

```
cols   0-3    left edge gutter   (0-1 badge, 2 wire, 3 spacer)
cols   4-57   node-a column      (54 wide)
cols  58-61   middle gutter      (never used by arrows; spacing only)
cols  62-115  node-b column      (54 wide)
cols 116-119  right edge gutter  (116 spacer, 117 wire, 118-119 badge)
cluster row:  Scheduler 4-32 (29) | gap 33-35 | API 36-83 (48) | gap 84-86 | Pool controller 87-115 (29)
workload row: a1 4-29, a2 32-57 (26 each) | b1 62-87, b2 90-115
runner/agent: Pod runner 4-21 (18), agent 24-57 (34) | 62-79, 82-115
hardware row: 4-57 (54) | 62-115 (54)
pool row:     4-115 (112)
```
SINGLE: node-b takes columns 4-115: workload slots b1 4-39, b2 42-77,
b3 80-115 (36 each); Pod runner 4-33 (30), agent 36-115 (80); hardware
4-115. Cluster and pool rows are identical in both layouts.

Text budget inside a box = width - 3 (one border, one space, one border):
29 -> 26, 48 -> 45, 26 -> 23, 18 -> 15, 34 -> 31, 54 -> 51, 112 -> 109,
36 -> 33, 30 -> 27, 80 -> 77. The renderer refuses longer state lines.

### C.3 Row map (both layouts)

```
 0  title bar: "<presentation> │ Ch N <chapter> │ N.MM <frame title> │ frame k/K"
 1  zone rule   ─ ANYWHERE IN THE CLUSTER ───   (cols 4-115)
 2-6  cluster row boxes (5 lines: title border, 3 inner lines, bottom border; inner line 1 is the technical name)
 7  zone rule / gutter   ─ ONE NODE: node-a (VM1, worker) ───   ─ ONE NODE: node-b (VM2, control plane) ───
 8-12 workload boxes (double line, 5 lines: title, "(pod x, node)", 2 state lines, border)
13  gutter
14-18 Pod runner + Node's CXL agent boxes (5 lines)
19  gutter
20-23 CXL memory seen by the node (4 lines: title, technical name, 1 state line, border)
24  zone rule / gutter   ─ OUTSIDE THE CLUSTER ───
25-28 Memory pool manager (4 lines: title, technical name, device line, border)
29  legend line
30-32 caption: line 30 = "★<step> <from> -> <to>: <message>", lines 31-32 narration
33  blank
34  MESSAGE SEQUENCE header
35  lane labels, 36 lane groups, 37.. one row per step (newest last)
```
The cluster boxes have 3 inner lines: technical name + 2 state lines (the
mock shows how little that is; the API box carries the most text and the
story must keep it to two lines, e.g. one line of claims and one of pods).
If the implementer finds 2 state lines too few for the API box, grow the
cluster row to 6 lines and the diagram to 31 lines; the row map is a
single table in `layouts.py`.

### C.4 Mock of one full frame (TWO_NODES, finale frame 5.11)

Machine-generated at exactly 120 columns (every line <= 120; four
overlong strings of the generator were shortened by hand; the renderer's
`--check` enforces the budget).

```
CXL memory from a pool, with Kubernetes DRA │ Ch 5 one writer, many readers │ 5.11 shared0 into node-b │ frame 61/78
    ─ ANYWHERE IN THE CLUSTER ──────────────────────────────────────────────────────────────────────────────────────
    ┌─ Scheduler ───────────────┐   ┌─ Kubernetes API + objects ───────────────────┐   ┌─ Pool controller ─────────┐
    │ (kube-scheduler)          │   │ (kube-apiserver: slices, claims, pods)       │   │ (fake-cxl-pool-controller)│
    │ ★ allocated 3 readers     │   │ ★ cxl-lease-2562aeca, -e5597c7f: node-b      │   │ attached shared0 -> node-a│
    │ shared0 hosts: 3/4 in use │   │ ★ cxl-lease-ce5ef151: node-a  (all Pending)  │   │ ★ attach shared0 -> node-b│
    └───────────────────────────┘   └──────────────────────────────────────────────┘   └───────────────────────────┘
    ─ ONE NODE: node-a (VM1, worker) ─────────────────────    ─ ONE NODE: node-b (VM2, control plane) ──────────────
                                ╔═ reader-c / main ══════╗    ╔═ reader-a / main ══════╗  ╔═ reader-b / main ══════╗
                                ║ (pod reader-c, node-a) ║    ║ (pod reader-a, node-b) ║  ║ (pod reader-b, node-b) ║
                                ║ lease ce5ef151 Pending ║    ║ lease 2562aeca Pending ║  ║ lease e5597c7f Pending ║
                                ║ cxl-request shared --ro║    ║ cxl-request shared --ro║  ║ cxl-request shared --ro║
                                ╚════════════════════════╝    ╚════════════════════════╝  ╚════════════════════════╝

    ┌─ Pod runner ───┐  ┌─ Node's CXL agent ─────────────┐    ┌─ Pod runner ───┐  ┌─ Node's CXL agent ─────────────┐
    │ (kubelet, NRI) │  │ (kubelet-cxl-plugin)           │    │ (kubelet, NRI) │  │ (kubelet-cxl-plugin)           │
    │ idle           │  │ lease ce5ef151 Pending ro      │    │ idle           │  │ leases 2562aeca e5597c7f Pend. │
    │                │  │ pool claims: none prepared     │    │                │  │ pool claims: none prepared     │
    └────────────────┘  └────────────────────────────────┘    └────────────────┘  └────────────────────────────────┘

    ┌─ CXL memory seen by the node ──────────────────────┐    ┌─ CXL memory seen by the node ──────────────────────┐
    │ (/sys/bus/cxl: memN regionN daxX.Y, NUMA nodes)    │    │ (/sys/bus/cxl: memN regionN daxX.Y, NUMA nodes)    │
    │ mem0 sn 0xc1ae0001 shared0 256M: present, no region│    │ ★ mem0 sn 0xc1ae0001 shared0 256M appears (udev)   │
    └────────────────────────────────────────────────────┘    └─────────────────────────▲──────────────────────────┘
    ─ OUTSIDE THE CLUSTER ─────────────────────────────────┌────────────(51)────────────┘───────────────────────────
    ┌─ Memory pool manager ────────────────────────────────┴───────────────────────────────────────────────────────┐
    │ (fake-cxl-pool-server on the host, REST :9909; hot-plugs cxl-type3 devices into the nodes (qemu, QMP))       │
    │ shared0 0xc1ae0001 256M shared: attached node-a, ★node-b (not excl.)  │  pooled0 0xc1ee0001 512M excl: free  │
    └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
★ changed now   ╔═╗ inside a container   ┄┄ not yet / just gone   (n) step n in the sequence below   ▲►◄▼ this step
★51 pool -> node-b HW: hot-plug shared0 = object-add memory-backend-file(share=on) + device_add cxl-type3(sn 0xc1ae0001)
    The same backing file is now a CXL memory device in both nodes. node-a got it back a moment ago (step 47): the
    controller detached it when the writer left (nothing wanted it) and re-attached it once the readers were allocated.

MESSAGE SEQUENCE  chapter 5, steps 41-51   (earlier chapters: see their last frames)                 ★ = this frame
 Pod agnt kblt  HW  schd  API ctrl pool  HW  kblt agnt  Pod      #  message
  ----- node-a -----     --- cluster ---   pool   ----- node-b -----
  │    │    │    │    │    │    │    │    │    │    │    │     41  -- writer companion unprepared; claim deallocated+del
  │    │    │    │    ├────►    │    │    │    │    │    │     42  allocate 3 reader claims (hosts 1 each; b, b, a)
  │    │    │    │    │    │    ├────►    │    │    │    │     43  DELETE /devices/shared0/attachments/node-a
  │    │    │    ◄───────────────────┤    │    │    │    │     44  device_del fcp_shared0.hp1 ... DEVICE_DELETED (~6 s)
  │    │    │    │    │    │    ◄╌╌╌╌┤    │    │    │    │     45  200 detached
  │    │    │    │    │    │    ├────►    │    │    │    │     46  POST /devices/shared0/attachments {host: node-a}
  │    │    │    ◄───────────────────┤    │    │    │    │     47  object-add + device_add cxl-type3 sn 0xc1ae0001
  │    │    │    │    │    │    ◄╌╌╌╌┤    │    │    │    │     48  201 attached
  │    │    │    │    │    │    ├────►    │    │    │    │     49  POST /devices/shared0/attachments {host: node-b}
  │    │    │    │    │    │    │    ├────►    │    │    │   ★ 51  object-add + device_add cxl-type3 sn 0xc1ae0001
```

Notes on the mock: the empty slot a1 (the writer is gone) is simply blank;
the arrow of the frame leaves the pool's top border at its N port (`┴`),
runs in the zone-rule gutter with its badge `(51)`, and ends with `▲` on
the bottom border of node-b's hardware box. The message sequence (MSC) has
12 lanes of 5 columns (lifeline at `2 + 5*i`), then `★`/space, the step
number, and a label of at most 53 characters; the full message text is
always in the caption of the frame that introduced the step. Replies use
`╌` shafts; notes (no communication, e.g. `kubectl apply`, a kernel event)
are rows with intact lifelines and a `-- ` label. Step numbers are global
over the presentation; the MSC itself is reset at every chapter card
(header says `chapter N, steps a-b`), which keeps it to at most about 25
rows per chapter.

### C.5 Mock of a chapter title card

```
                                                                                                                        
                                                                                                                        
    ════════════════════════════════════════════════════════════════════════════════════════════════════════════════
    Chapter 3    Memory for a container that is already running
    ════════════════════════════════════════════════════════════════════════════════════════════════════════════════

    A pod's claims are fixed when it is created: neither the scheduler nor kubelet add devices to a running pod.
    So a running container BORROWS pool memory through the node's CXL agent instead:

      1. opt in at creation: claim the token device "dynamic" (DeviceClass cxl-dynamic) -> a socket and a CLI appear
      2. ask from inside:    cxl-request memory 512Mi        -> a NUMA node, in this container's cpuset.mems only
                             cxl-request shared 0xc1ae0001   -> an open /dev/daxX.Y file descriptor, no device node
      3. give back:          cxl-release <lease>             -> pages migrate to DRAM, device goes back to the pool

    Behind the scenes the agent creates a companion pod + claim named cxl-lease-<id> on your behalf; from there it
    is chapter 1 again.  Source: e2e test12-dra-live-attach, driver doc/cxl/POOL.md "Lending to running containers".

    Cast on stage: node-b only.                                                                   frames 3.01 - 3.16
```
Cards use the same 120 columns, 30 lines of "diagram region" (the card
text is vertically centered in it), an empty caption and no MSC. Cards
reset the MSC, may switch the layout, and may hide all workload slots.

### C.6 Visual conventions

- Changed in this frame: `★ ` prefix on every state line whose text
  differs from the previous frame (computed by the renderer, not by the
  author), on a box title that appeared in this frame, and on the new MSC
  rows. Nothing else carries `★`. (No bold/inverse in plain text.)
- Arrow of this frame: drawn in the diagram with `─ │ ┌ ┐ └ ┘` plus heads
  `► ◄ ▲ ▼`, a badge `(n)` with the step number; one frame normally has
  one arrow, at most two (section D). Past communications are not drawn in
  the diagram; they are in the MSC.
- Zones: horizontal rules with a label at the left end
  (`─ ANYWHERE IN THE CLUSTER ─`, `─ ONE NODE: node-b (VM2, control plane) ─`,
  `─ OUTSIDE THE CLUSTER ─`). Workload (inside the container) boxes use
  double lines `╔ ═ ╗ ║ ╚ ╝`; everything else single lines.
- Not yet introduced: infrastructure boxes (scheduler, API, controller,
  runner, agent, hardware, pool) are drawn as dotted placeholders
  (`┌┄┄┐`, `┆`) with only their descriptive title and `(not yet in the story)`
  until the cast chapter introduces them; after that they are always
  drawn. Workload slots are hidden (blank) when empty.
- Just gone: an entity removed in this frame is drawn once more with dotted
  borders and a last line `(gone)` / `(exited)`, then disappears.
- Fast-forward frames (several steps at once, e.g. "same as chapter 1 up
  to here") draw only the last step's arrow; all steps get MSC rows and
  `★`.
- Legend line (line 29) is identical in every frame.

### C.7 Allowed characters

ASCII 0x20-0x7E; box drawing `─ │ ┌ ┐ └ ┘ ├ ┤ ┬ ┴ ┼` (U+2500 2502 250C 2510
2514 2518 251C 2524 252C 2534 253C), double `═ ║ ╔ ╗ ╚ ╝` (U+2550 2551 2554
2557 255A 255D), dotted `┄ ┆ ╌` (U+2504 2506 254C); geometric `► ◄ ▲ ▼`
(U+25BA 25C4 25B2 25BC) and `★` (U+2605). All of these are single-width in
Western locales; they are "East Asian ambiguous" by the Unicode data, so
a CJK locale with ambiguous=wide would double them: `--ascii` renders the
same frames with `- | + + + + > < ^ v *` and `=` for double lines. Not
used: `▶ ◀` (U+25B6/25C0, emoji presentation in some fonts), `→ … »`,
any emoji, tabs. `--check` rejects any character outside the set.


## D Arrow strategy

Fixed grid, orthogonal routes in gutters only, one or two arrows per frame,
drawn last over empty gutter cells; past arrows live in the MSC. No search:
three deterministic cases.

Ports: every box has four ports, the middle cell of each border (N, S, W,
E), overridable per slot in the layout table (used to keep scheduler's S
port at column 29, right of the zone label). An arrow leaves a box by
replacing the port's border character with a tee (`┬` on a bottom border
for a wire going down, `┴` on a top border going up, `├`/`┤` on side
borders) and enters the target by replacing the target's border cell with
the head (`▼ ▲ ► ◄` pointing into the box).

Case 1, neighbours in one row (Scheduler <-> API, API <-> Pool controller,
Pod runner <-> agent, two workload boxes of one node): a straight run
through the 2-3 column gap at the middle height: `──►` / `◄──`; the badge
`(n)` goes into the gutter directly below the gap.

Case 2, boxes in adjacent rows (workload <-> agent/runner, agent <->
hardware, hardware <-> pool, cluster boxes <-> workload boxes): the wire
leaves the S port (or N port), uses the one-line gutter between the rows
for the horizontal offset and enters the N (or S) port of the target:
```
 ─────┬─────            source bottom border, tee at its S port
      └────(n)────┐     gutter: turn, run with badge, turn
 ─────────────────▼──   target top border, head at its N port
```
If both ports are in the same column the gutter cell is `│` and the badge
sits right of it. Zone rules are gutters too: the wire overwrites the
`─` of the rule (see the mock); zone labels occupy columns 4-~45 and all
ports that can land in a rule gutter are declared at columns >= 29 for the
cluster row and >= 30 for the node rows, which `--check` verifies (a wire
cell over a label character is an error).

Case 3, everything else (controller -> pool manager, runner/agent <-> API,
scheduler -> anything below the cluster row, pool -> a box that is not in
the hardware row): the wire goes via the edge gutter of the side it is on:
leave S (or N) into the adjacent gutter, run to column 2 (left half) or 117
(right half), vertical along the edge wire column through any number of
rows (zone rules stop at columns 4 and 115, so nothing is crossed), run
back in the target's gutter, enter the target's N or S port. The badge is
placed on the longest horizontal segment, or, if none is long enough, on
the vertical segment using the 2 badge columns (`0-1` / `118-119`, then as
a bare two-digit number). Example, controller -> pool:
```
                                        ┌─ Pool controller ──┐
                                        │ ...                │
                                        └───────────┬────────┘
    ─ ONE NODE ... ─────────────────────────────────└──(12)──┐
                                                             │   <- column 117, through the node rows
    ...                                                      │
    ─ OUTSIDE THE CLUSTER ───────────────────────────────────┘ ... no: enters at the pool's N port:
    ─ OUTSIDE THE CLUSTER ──────────────────────────┌────────┘
    ┌─ Memory pool manager ─────────────────────────▼────────────────────────────────────────────┐
```
(The implementer draws the turn `┘` in the rule gutter at column 117 and
the run back to the pool's N port at column 59; same cells, same glyph
rules as case 2.)

Two arrows in one frame are allowed when they share no cell except
possibly the source port and the first gutter cell (a fan-out such as the
pool hot-removing from both nodes: `┌──(n)──┬──(n+1)──┐` with `┬` as the
junction under the pool's N port). The renderer computes both paths,
checks overlaps cell by cell (allowed: identical glyph, or a junction whose
arms are the union of both wires), and fails `--check` otherwise; the
author then splits the frame.

MSC ties: every drawn arrow has the step number of its MSC row in its
badge, the same number is in the caption `★<n>`, and the MSC row is marked
`★`. Replies (`kind="reply"`) are drawn like requests in the diagram and
with `╌` in the MSC.


## E Storyboard

Format of a frame entry:

```
N.MM slug
  state:  entity: "new state line"; ...            (★ is automatic)
  send:   from -> to  "message"  [reply] [note]    (one MSC row each; the last listed is drawn, unless "draw:" says otherwise)
  text:   caption line(s)
```
Entities: `sched`, `api`, `ctrl`, `pool`, `runner_a`, `agent_a`, `hw_a`,
`runner_b`, `agent_b`, `hw_b`, workload slots `a1 a2 b1 b2` (TWO_NODES) or
`b1 b2 b3` (SINGLE). MSC lanes: SINGLE = `Pod agnt kblt HW schd API ctrl pool`
(8 lanes, 7 columns each); TWO_NODES = the 12 lanes of the mock. "user"
actions (`kubectl apply/delete/exec`) are MSC notes, not arrows.
Lease ids and uids in chapter 5 are those of the recorded run; in chapter
3 they are illustrative (`1a2b3c4d`, `5e6f7a8b`).

### Chapter 0: title and cast (layout SINGLE, 8 frames)

```
0.01 title            card: "CXL memory from a pool, with Kubernetes DRA" / "pods that claim memory from a CXL
                      memory pool: as a NUMA node or a DAX device, when the pod starts or while it runs,
                      exclusively or shared" / how to read: picture on top (★ = changed), the message sequence
                      below grows; less: :n next, :p previous, j/k scroll.
0.02 cast-pool        state: pool introduced: "(fake-cxl-pool-server on the host, REST :9909; hot-plugs cxl-type3
                      devices into the nodes (qemu, QMP))" / "shared0 0xc1ae0001 256M shared: free  │  pooled0
                      0xc1ee0001 512M excl: free". All other boxes dotted placeholders.
                      text: A CXL memory pool is a box of memory cabled to many servers; its manager attaches a
                      device to a server and detaches it again. Here: a fake one that hot-plugs into qemu VMs. Two
                      devices: pooled0 (one server at a time) and shared0 (several servers, same bytes).
0.03 cast-node-hw     state: hw_b introduced: "(/sys/bus/cxl: memN regionN daxX.Y, NUMA nodes)" / "no CXL memory
                      devices (auto_online_blocks = offline)".
                      text: What a node sees: a hot-plugged device appears as memN with its serial; the node turns
                      it into a region, then either system RAM (a NUMA node) or a /dev/daxX.Y device.
0.04 cast-cluster     state: sched "(kube-scheduler)" "idle"; api "(kube-apiserver: slices, claims, pods)" "no CXL
                      objects yet"; ctrl "(fake-cxl-pool-controller)" "connected to the pool: 2 devices".
                      text: Kubernetes words used here: ResourceSlice = an offer list of devices; DeviceClass = the
                      kind of device I want; ResourceClaim = my request and what I got; Pod = the workload. The
                      scheduler allocates; the pool controller is the pool's agent in the cluster.
0.05 cast-node-sw     state: runner_b "(kubelet, containerd, NRI)" "runs the pods of the node"; agent_b
                      "(kubelet-cxl-plugin)" "DRA plugins cxl.generic + cxl-pool.generic" "NRI plugin, lease broker".
                      text: One process per node: it prepares claims for kubelet (DRA), publishes the node's own
                      memory, adjusts running containers through NRI, and answers requests from containers.
0.06 cast-container   state: b1 "demo / app" "(a pod's container)" "env, /dev/daxX.Y, cpuset.mems from the agent"
                      "cxl-request CLI (with a token claim)".
                      text: The workload never talks to the pool. It gets environment variables, device nodes or
                      a bigger cpuset.mems; with a token claim it can also ask for memory with cxl-request.
0.07 cast-zones       no state change; text: where things run: cluster-wide (top), on one node (middle; the
                      double-line boxes are inside containers), outside the cluster (bottom: the pool).
                      Two nodes appear in chapter 4.
0.08 cast-recap       card: cast list (B table, first 9 rows) + "chapters: 1 NUMA node claim, 2 DAX claim,
                      3 borrow while running, 4 sharing between nodes, 5 one writer, many readers".
```

### Chapter 1: a pod claims pooled memory as a NUMA node (test10, SINGLE, 17 frames)

Source: `e2e/n4-cxl-shared-2/test10-dra-pooling/code.var.sh`, its
trace-summary. Node: node-b. Remove the demo workload of 0.06 at the card.

```
1.00 ch1-card         card: "A pod claims pooled memory as a NUMA node" / the 6 steps: offer, claim, attach,
                      prepare, use, release / source test10.
1.01 publish-pool     send: ctrl -> pool "GET /api/v1/devices?scope=pool"; pool -> ctrl "[pooled0 512M excl free,
                      shared0 256M shared free]" reply; ctrl -> api "create ResourceSlice cxl-pool.generic/
                      fake-cxl-pool (allNodes): pooled0 {serial 0xc1ee0001, shared false, size 512Mi,
                      capacity memory 512Mi}, shared0 {shared true, hosts 4 (1|4)}; bindsToNode, bindingConditions
                      [Attached]" (drawn)
                      state: api "slice pool: pooled0 512Mi excl, shared0 shared(hosts 4)"; ctrl "publishing 2
                      devices; watching claims and nodes".
                      text: The controller turns the pool's device list into an offer list. The devices are on no
                      node yet: bindsToNode + a binding condition tell the scheduler "pick a node, then wait
                      until I say Attached".
1.02 publish-node     send: agent_b -> api "publish ResourceSlice cxl.generic/node-b: dram (nodes 0-1), dynamic
                      (token)".
                      state: api "slice node-b: dram, dynamic"; agent_b "published node slice".
                      text: The node agent publishes the node's own memory separately. The 'dynamic' token is for
                      chapter 3. The scheduler always tries node-local offers first (no binding wait).
1.03 claim-and-pod    send: note "kubectl apply: ResourceClaim pooled-memory {class cxl-pool-memory, memory 512Mi}
                      + Pod pooled-consumer {resourceClaims pooled -> pooled-memory; container consumer uses it}".
                      state: api "claim pooled-memory: unallocated" / "pod pooled-consumer: Pending".
                      text: DeviceClass cxl-pool-memory = driver cxl-pool.generic && shared == false. The pod
                      does not say which device or node.
1.04 scheduler-alloc  send: sched -> api "claim.status.allocation: pooled0 (cxl-pool.generic/fake-cxl-pool),
                      nodeSelector node-b; pod event BindingConditionsPending".
                      state: sched "pooled-memory: pooled0 @ node-b" / "waiting for cxl-pool.generic/Attached";
                      api "claim pooled-memory: pooled0 @ node-b, not attached" / "pod: Pending (binding wait)".
                      text: Only pooled0 has 512Mi. The scheduler pins the claim to node-b and polls the claim
                      until the binding condition is True (timeout 600 s).
1.05 ctrl-attaches    send: ctrl -> pool "POST /api/v1/devices/pooled0/attachments {host: node-b, owner:
                      k8s:resourceclaim/<uid>, wait: true, timeout: 1m0s}".
                      state: ctrl "attach pooled0 -> node-b (host = node's systemUUID)"; pool "pooled0: attaching
                      -> node-b".
                      text: The controller saw the allocation. Node -> pool host by the Node's systemUUID
                      (the VM's qemu -uuid). The attachment is owned by the claim.
1.06 pool-hotplugs    send: pool -> hw_b "hot-plug: object-add memory-backend-file(id fcp_pooled0.hp1, share=on,
                      pooled0.raw) + device_add cxl-type3(bus cxlsw_ds0_usrp0hb0, serial 0xc1ee0001)".
                      state: hw_b "mem0 sn 0xc1ee0001 pooled0 512M appears (udev add)"; pool "pooled0: attached
                      node-b (fcp_pooled0.hp1)".
                      text: In a real pool this is the fabric manager cabling the device to the server; here qemu
                      hot-plugs it. The node's kernel sees a new CXL memory device with the serial.
1.07 attached-cond    send: pool -> ctrl "201 Created {pooled0@node-b attached}" reply; ctrl -> api "UpdateStatus
                      claim.status.devices[pooled0]: Attached=True 'pooled0 attached to node-b (slot ...)', data
                      {serial 0xc1ee0001, shared false, size 536870912, host, hostUUID, attachment, qemuDeviceId}"
                      (drawn).
                      state: api "claim pooled-memory: pooled0 @ node-b, Attached"; ctrl "Attached written".
                      text: The claim status carries exactly what the node will need: the serial. 0.6 s after the
                      claim was created in the recorded run.
1.08 scheduler-binds  send: sched -> api "bind pod pooled-consumer -> node-b (event Scheduled)".
                      state: sched "idle"; api "pod pooled-consumer: node-b, ContainerCreating".
                      text: The scheduler's poll noticed Attached (about 5 s later in the recorded run) and
                      bound the pod.
1.09 kubelet-prepare  send: runner_b -> agent_b "NodePrepareResources(claim pooled-memory) on
                      /var/lib/kubelet/plugins/cxl-pool.generic/dra.sock".
                      state: runner_b "pooled-consumer: preparing claims"; agent_b "cxl-pool.generic: pooled-memory
                      -> serial 0xc1ee0001, shared false" / "mode numa (default of an exclusive device)".
                      text: kubelet prepares a pod's claims before it creates containers. No PoolDeviceConfig in
                      the claim: an exclusive device becomes a NUMA node.
1.10 agent-region     send: agent_b -> hw_b "find memN with serial 0xc1ee0001; cxl create-region -t ram -d
                      decoder0.0 -m mem0; daxctl reconfigure-device --mode=system-ram (kmem); online_movable all
                      blocks".
                      state: hw_b "mem0 -> region0 -> dax0.0 (kmem) -> NUMA node 2: 512 MB online_movable";
                      agent_b "prepared pooled0 as region0, node 2".
                      text: Movable, so the memory can be removed again later. The node now has a third NUMA node
                      with 512 MB and no CPUs (numactl -H shows it).
1.11 agent-cdi        send: agent_b -> runner_b "PrepareResult: CDI generic/cxl=pool-c1ee0001 -> env
                      CXL_POOL_NODE_C1EE0001=2, CXL_POOL_SIZE_C1EE0001=536870912, CXL_POOL_SERIAL_C1EE0001=
                      0xc1ee0001" reply.
                      state: agent_b "preparedPoolClaims.json: pooled-memory"; agent_b line 2 "cxl.generic slice:
                      region0 not advertised (pool device)".
                      text: The agent remembers the claim in preparedPoolClaims.json and keeps region0 out of
                      its own offer list, so the memory is not offered twice.
1.12 container-runs   send: runner_b -> b1 "start container consumer (containerd applies the CDI env)".
                      state: b1 "pooled-consumer / consumer" "(pod pooled-consumer, node-b)" "CXL_POOL_NODE_
                      C1EE0001=2  SIZE=536870912" "sees node2 MemTotal 512 MB; Mems_allowed 0-2"; api "pod
                      pooled-consumer: Running (6.2 s after apply)".
                      text: The app uses node 2 with numactl/mbind. Nothing restricts the container to node 2 and
                      nothing keeps others off it (open TODO in POOL.md); cpuset.mems is untouched because a
                      cgroup allowed ONLY movable memory could not start.
1.13 delete-pod       send: note "kubectl delete pod pooled-consumer"; runner_b -> b1 "SIGTERM, container stops";
                      runner_b -> agent_b "NodeUnprepareResources(claim pooled-memory)" (drawn).
                      state: b1 dotted "(gone)"; runner_b "pooled-consumer: terminating, unpreparing".
                      text: Unprepare happens while the pod terminates, before the pod object is gone.
1.14 agent-releases   send: agent_b -> hw_b "offline memory202-205; cxl disable-region region0; cxl destroy-region
                      region0; cxl disable-memdev mem0".
                      state: hw_b "mem0 sn 0xc1ee0001: present, disabled, no region, node 2 gone"; agent_b
                      "released mem0; unprepared pooled-memory".
                      text: Release before detach: the memory is offline and the region gone, so the device can
                      leave without the kernel still using it.
1.15 ctrl-detaches    send: note "claim pooled-memory deallocated, kubectl delete resourceclaim"; ctrl -> pool
                      "DELETE /api/v1/devices/pooled0/attachments/node-b?wait=true&timeout=1m0s"; pool -> hw_b
                      "hot-remove: device_del fcp_pooled0.hp1 -> DEVICE_DELETED (~6 s) -> object-del" (drawn,
                      two arrows: case 3 + case 2).
                      state: api "no claims, no pods"; ctrl "detached pooled0 from node-b"; pool "pooled0: free";
                      hw_b "no CXL memory devices".
                      text: The controller detaches only deallocated devices. Force-deleting the pod would skip
                      the unprepare and leave a half-removed device until the node reboots (not handled).
1.16 ch1-recap        card: the six steps with the component that does each; timings from the recorded run
                      (Attached 0.6 s, Running 6.2 s, detached 6.4 s after delete).
```

### Chapter 2: the same memory as a DAX device (test13 H2 "pooled-dax", SINGLE, 8 frames)

Source: test13 `code.var.sh:473-519` (the recorded run did this on node-a;
presented here on node-b for continuity, noted in G), `driver/deployments/cxl/pool/examples/pooled-dax-pod.yaml`,
`pool.go:692-706`, `829-853`.

```
2.00 ch2-card         card: "Options: PoolDeviceConfig {mode: numa|dax, readOnly}" / table POOL.md:185-192:
                      exclusive+nothing = NUMA node; exclusive+mode dax = own dax device; shared = dax always;
                      readOnly = dax device the container can only read.
2.01 dax-claim        send: note "kubectl apply: ResourceClaim pooled-dax {class cxl-pool-memory, memory 512Mi,
                      config opaque cxl-pool.generic {apiVersion cxl-pool.generic/v1alpha1, kind PoolDeviceConfig,
                      mode: dax}} + Pod dax-claimer".
                      state: api "claim pooled-dax: unallocated, config mode dax" / "pod dax-claimer: Pending".
                      text: The option is an opaque config of the driver, in the claim (or its DeviceClass). The
                      pool and the scheduler ignore it; only the node agent reads it.
2.02 same-as-ch1      fast-forward: sched -> api "allocate pooled0 @ node-b; BindingConditionsPending"; ctrl ->
                      pool "POST attach pooled0 {host node-b, owner ...}"; pool -> hw_b "hot-plug cxl-type3 sn
                      0xc1ee0001" (drawn); pool -> ctrl "201" reply; ctrl -> api "Attached=True + data"; sched ->
                      api "bind dax-claimer -> node-b"; runner_b -> agent_b "NodePrepareResources(pooled-dax)".
                      state: hw_b "mem0 sn 0xc1ee0001 appears"; pool "pooled0: attached node-b"; api "claim
                      pooled-dax: pooled0 @ node-b Attached; pod bound".
                      text: Identical to chapter 1 up to here: the pool does not know how the node will use it.
2.03 agent-devdax     send: agent_b -> hw_b "cxl create-region -t ram -d decoder0.0 -m mem0; daxctl
                      reconfigure-device --mode=devdax (device_dax); memory NEVER onlined".
                      state: hw_b "mem0 -> region0 -> /dev/dax0.0 (device_dax, 252:0); no NUMA node, OnlineSize 0";
                      agent_b "prepared pooled0 mode dax".
                      text: Same region, other driver: device_dax instead of kmem. The kernel does not use the
                      memory; programs map it.
2.04 agent-devnode    send: agent_b -> runner_b "PrepareResult: CDI generic/cxl=pool-c1ee0001: deviceNodes
                      [/dev/dax0.0 c 252:0], env CXL_POOL_DAX_C1EE0001=/dev/dax0.0, CXL_POOL_SIZE_C1EE0001=
                      536870912, CXL_POOL_SERIAL_C1EE0001=0xc1ee0001" reply.
                      text: A device node in the container plus a device cgroup rule for it: that is what CDI
                      deviceNodes means.
2.05 dax-runs         send: runner_b -> b1 "start container main".
                      state: b1 "dax-claimer / main" "(pod dax-claimer, node-b)" "/dev/dax0.0 rw; CXL_POOL_DAX_
                      C1EE0001=/dev/dax0.0" "mmap MAP_SHARED 2M-aligned: write/read TEXT".
                      text: No CXL_POOL_NODE variable this time. The bytes stay in the device: the next claim of
                      pooled0, on any node, finds them (test13 H2 found the lease's text from H1).
2.06 readonly-option  no send. state: api line "PoolDeviceConfig readOnly: true -> CDI pool-<serial>-ro,
                      device node permissions r, env ..._READONLY_<SERIAL>=1".
                      text: readOnly is a property of the claim, not of the device: the runtime's device cgroup
                      lets the container open the node for reading only, root or not (except privileged pods).
                      Used by the readers in chapter 5.
2.07 dax-release      fast-forward: note "kubectl delete pod dax-claimer, resourceclaim pooled-dax"; runner_b ->
                      agent_b "NodeUnprepareResources"; agent_b -> hw_b "disable-region, destroy-region,
                      disable-memdev"; ctrl -> pool "DELETE attachment pooled0@node-b" (drawn); pool -> hw_b
                      "device_del -> DEVICE_DELETED".
                      state: b1 gone; hw_b "no CXL memory devices"; pool "pooled0: free"; api empty.
                      text: Same release chain as chapter 1; nothing to offline because nothing was onlined.
```

### Chapter 3: memory for a container that is already running (test12, SINGLE, 16 frames)

Source: test12 `code.var.sh`, `broker.go`, `dynamic.go`, `lend.go`,
`POOL.md:377-614`, `plan-3-cxl-live-attach/03-summary.txt`.

```
3.00 ch3-card         card as in C.5.
3.01 token-device     state: api "slice node-b (cxl.generic): dram, dynamic {type dynamic, no capacity,
                      allowMultipleAllocations}" / "DeviceClass cxl-dynamic: driver cxl.generic && type ==
                      dynamic".
                      send: note "kubectl apply: ResourceClaimTemplate cxl-lease-token {class cxl-dynamic} + Pod
                      borrower {containers main (claims it), idle (does not)}".
                      text: The token costs nothing and any number of pods can claim it. It is the permission slip
                      to ask later.
3.02 token-prepare    send: sched -> api "allocate dynamic @ node-b (node-local, no binding wait); bind borrower";
                      runner_b -> agent_b "NodePrepareResources(token claim) [cxl.generic]"; agent_b -> runner_b
                      "CDI generic/cxl=lease-<claim uid>: mount /var/lib/kubelet/plugins/cxl.generic/leases/<uid>
                      -> /run/cxl (rbind rw); mount cxl-request -> /usr/local/bin/cxl-request and cxl-release (ro);
                      env CXL_LEASE_SOCKET=/run/cxl/cxl.sock, CXL_CLAIM_<uid>=1" reply (drawn).
                      state: agent_b "listening on leases/<uid>/cxl.sock (0666)"; api "pod borrower: node-b".
                      text: The agent opens a socket per token claim and mounts its directory (not the socket) so
                      a restarted agent can recreate the socket under the running container.
3.03 borrower-runs    send: runner_b -> b1 "start main"; runner_b -> b2 "start idle".
                      state: b1 "borrower / main" "(pod borrower, node-b)" "/run/cxl/cxl.sock, cxl-request"
                      "cpuset.mems 0-1 (DRAM); no CXL memory"; b2 "borrower / idle" "(pod borrower, node-b)" "no
                      socket, no CLI" "cpuset.mems 0-1"; pool "both devices free".
                      text: The pod started at once: no pool device is involved yet. Only the container that lists
                      the claim got the socket.
3.04 request-memory   send: b1 -> agent_b "cxl-request memory 512Mi  ==  {\"op\":\"lease\",\"kind\":\"memory\",
                      \"size\":\"512Mi\",\"wait\":\"120s\"} on /run/cxl/cxl.sock".
                      state: agent_b "lease 1a2b3c4d Creating (leases.json)" / "caller: SO_PEERCRED pid ->
                      /proc/pid/cgroup -> borrower/main; pod via claim.reservedFor"; b1 "cxl-request memory 512Mi
                      ... waiting".
                      text: The socket names the claim and so the pod; the kernel tells which process called
                      (SO_PEERCRED). No token, no RBAC inside the pod.
3.05 companion        send: agent_b -> api "create ResourceClaim cxl-lease-1a2b3c4d {class cxl-pool-memory, memory
                      512Mi, config LendConfig{lease, pod borrower, container main}; ownerRef borrower} + Pod
                      cxl-lease-1a2b3c4d {pause:3.10, 100m/8Mi, nodeAffinity node-b, tolerate all, claim lease}".
                      state: agent_b "lease 1a2b3c4d Pending"; api "claim cxl-lease-1a2b3c4d: unallocated; pod
                      cxl-lease-1a2b3c4d: Pending".
                      text: A companion pod holds the claim on the container's behalf, pinned to this node, owned
                      by the borrower (garbage-collected with it). From here it is chapter 1 again.
3.06 companion-ff     fast-forward: sched -> api "allocate pooled0 @ node-b; BindingConditionsPending"; ctrl ->
                      pool "POST attach pooled0 node-b (owner k8s:resourceclaim/<companion uid>)"; pool -> hw_b
                      "hot-plug cxl-type3 sn 0xc1ee0001" (drawn); ctrl -> api "Attached=True"; sched -> api "bind
                      companion"; runner_b -> agent_b "NodePrepareResources(cxl-lease-1a2b3c4d)".
                      state: hw_b "mem0 sn 0xc1ee0001 appears"; pool "pooled0: attached node-b"; b3 "cxl-lease-
                      1a2b3c4d / pause" "(companion pod, node-b)" "holds claim cxl-lease-1a2b3c4d" "100m / 8Mi".
                      text: The pool and the scheduler see an ordinary claim.
3.07 agent-region     send: agent_b -> hw_b "create-region, kmem, online_movable -> NUMA node 2".
                      state: hw_b "mem0 -> region0 -> dax0.0 (kmem) -> node 2, 512 MB"; agent_b "LendConfig ok ->
                      lease 1a2b3c4d Lending".
                      text: The LendConfig is accepted only from the claim, for a lease this agent knows, for the
                      same pod and container: a tenant cannot lend to someone else's container.
3.08 agent-lends      send: agent_b -> runner_b "NRI UpdateContainers(borrower/main): cpuset.mems = 0-1,2".
                      state: b1 "cpuset.mems 0-1,2"; b2 unchanged "cpuset.mems 0-1"; agent_b "lease 1a2b3c4d Ready
                      node 2".
                      text: Only the calling container grows. Through NRI, so containerd keeps the value; writing
                      cgroupfs directly would be undone by the next container update.
3.09 lease-ready      send: agent_b -> b1 "{\"lease\":\"1a2b3c4d\",\"state\":\"Ready\",\"kind\":\"memory\",
                      \"mode\":\"numa\",\"node\":2,\"size\":536870912,\"serial\":\"0xc1ee0001\"}" reply.
                      state: b1 "lease 1a2b3c4d Ready: node 2" "numa-touch 256 MiB preferred node 2 -> on node 2".
                      text: cxl-request prints the JSON and exits 0; the app allocates on node 2 (numactl, mbind).
                      About 5-7 s, mostly the scheduler's binding poll. Lent memory still counts against the
                      container's memory limit.
3.10 release-revoke   send: b1 -> agent_b "cxl-release 1a2b3c4d  ==  {\"op\":\"release\",\"lease\":\"1a2b3c4d\"}";
                      agent_b -> runner_b "NRI UpdateContainers(main): cpuset.mems = 0-1" (drawn).
                      state: agent_b "lease 1a2b3c4d Releasing"; b1 "cpuset.mems 0-1; 256 MiB migrated to DRAM,
                      numa-touch still runs".
                      text: Shrinking cpuset.mems makes the kernel move the pages to DRAM; the process never
                      notices.
3.11 release-chain    fast-forward: agent_b -> api "delete Pod + ResourceClaim cxl-lease-1a2b3c4d" (drawn);
                      runner_b -> agent_b "NodeUnprepareResources(companion)"; agent_b -> hw_b "offline, destroy
                      region0, disable mem0"; note "claim deallocated and gone"; ctrl -> pool "DELETE attachment
                      pooled0@node-b"; pool -> hw_b "device_del -> DEVICE_DELETED"; agent_b -> b1
                      "{\"lease\":\"1a2b3c4d\",\"state\":\"Released\"}" reply.
                      state: b3 gone; hw_b "no CXL memory devices"; pool "pooled0: free"; agent_b "no leases";
                      b1 "no lease".
                      text: About 8 s. Nothing of the lease remains: no companion, no claim, no attachment, no
                      region. A new request gets a new lease id.
3.12 shared-request   send: b1 -> agent_b "cxl-request shared 0xc1ae0001 --exec python3 dax-rw.py --fd 3 write 0
                      TEXT  ==  {\"op\":\"lease\",\"kind\":\"shared\",\"serial\":\"0xc1ae0001\",\"wait\":\"120s\"}";
                      agent_b -> api "create cxl-lease-5e6f7a8b: claim {class cxl-shared-memory, selector serial ==
                      0xc1ae0001, configs LendConfig + PoolDeviceConfig{mode dax}} + companion pod" (drawn).
                      state: agent_b "lease 5e6f7a8b Pending (shared, dax)"; api "claim cxl-lease-5e6f7a8b".
                      text: A shared device is always dax. --exec: run this command with the device when it is
                      there.
3.13 shared-ff        fast-forward: sched/ctrl/pool as before for shared0 (pool -> hw_b "hot-plug cxl-type3 sn
                      0xc1ae0001" drawn); runner_b -> agent_b "NodePrepareResources"; agent_b -> hw_b "create-
                      region; daxctl --mode=devdax".
                      state: hw_b "mem1 sn 0xc1ae0001 -> region1 -> /dev/dax1.0 (device_dax)"; pool "shared0:
                      attached node-b"; b3 "cxl-lease-5e6f7a8b / pause"; agent_b "lease 5e6f7a8b Ready dax
                      /dev/dax1.0".
3.14 fd-passed        send: agent_b -> b1 "open(/dev/dax1.0, O_RDWR); {\"lease\":\"5e6f7a8b\",\"state\":\"Ready\",
                      \"kind\":\"shared\",\"mode\":\"dax\",\"dax\":\"/dev/dax1.0\",\"size\":268435456,\"serial\":
                      \"0xc1ae0001\"} + the fd (SCM_RIGHTS)" reply.
                      state: b1 "fd 3 -> /dev/dax1.0 (no /dev/dax* node; device cgroup unchanged)" "CXL_LEASE_FD=3
                      CXL_LEASE=5e6f7a8b CXL_LEASE_SIZE=268435456 READONLY=0" "wrote TEXT at offset 0"; pool
                      "shared0.raw on the host now holds TEXT".
                      text: The device cgroup is checked only at open(): a passed fd needs no node and no rule.
                      mknod+open inside the container still fails (EPERM). The host sees TEXT in the backing file.
3.15 fd-again-release fast-forward: b1 -> agent_b "{\"op\":\"fd\",\"lease\":\"5e6f7a8b\"} (cxl-request fd 5e6f7a8b
                      --exec dax-rw.py --fd 3 read 0 -> TEXT)"; agent_b -> b1 "fd again" reply; b1 -> agent_b
                      "cxl-release --all" (drawn); then the release chain (companion deleted, unprepare, detach).
                      state: b1 "no lease"; b3 gone; hw_b "no CXL memory devices"; pool "shared0: free".
                      text: The fd can be asked for again as long as the lease lives (a restarted process has lost
                      it). test12 does lend/give-back/share four times without leftovers.
3.16 pod-deleted      state before: b1 "lease (memory) Ready node 2; lease (shared) Ready fd" (set via a short
                      fast-forward: "cxl-request memory 512Mi; cxl-request shared 0xc1ae0001" with no drawn arrow).
                      send: note "kubectl delete pod borrower (2 leases alive)"; runner_b -> agent_b
                      "NodeUnprepareResources(token claim)"; agent_b -> api "release all leases of the pod: delete
                      companions (Kubernetes GC would too: ownerReference)" (drawn); then unprepare/detach for both.
                      state: b1, b2, b3 gone; agent_b "no leases; socket dir removed"; pool "both free"; hw_b
                      "no CXL memory devices".
                      text: Every path ends in the same unprepare -> deallocate -> detach chain. Clean in < 90 s in
                      the recorded run.
3.17 ch3-recap        card: lease states Creating -> Pending -> Lending -> Ready -> Releasing -> Released (Failed
                      on timeout or lend error); commands; limits (memory.max, cooperative release, ~5-7 s).
```
(Chapter 3 is 18 files including card and recap; the "16 frames" above
counts story frames.)

### Chapter 4: sharing, one device on several nodes (test11 mechanics, TWO_NODES, 7 frames)

Source: test11 `code.var.sh` (two single-node clusters sharing one pool
server), `publisher.go:67-87`. Presented in the two-node cluster of test13
(G.2); the mechanics are identical: one claim per node, one attachment
per node, the same backing file.

```
4.00 ch4-card         card: "Sharing: one device, several nodes" / node-a (VM1, worker) joins node-b (VM2, control
                      plane) in one cluster (test13 setup; test11 used two single-node clusters sharing the pool,
                      same mechanics) / shared memory is devdax only: two kernels onlining the same bytes as RAM
                      corrupt each other silently.  Layout switches to TWO_NODES; all boxes introduced.
4.01 two-nodes        state: api "slices: pool {shared0 hosts 4 (1|4), pooled0}, node-a {dram, dynamic}, node-b
                      {dram, dynamic}"; ctrl "pool hosts of nodes: node-a=VM1 node-b=VM2"; hw_a, hw_b "no CXL
                      memory devices"; pool "shared0 free, pooled0 free".
                      text: shared0 has no memory capacity to consume (every node would get all of it) but a
                      'hosts' capacity: 4 = how many nodes may attach it at once. A claim takes 1 by default;
                      a claim that takes all 4 has the device alone (chapter 5).
4.02 writer-claim     send: note "kubectl apply on node-a: ResourceClaim shared-memory {class cxl-shared-memory,
                      selector serial == 0xc1ae0001} + Pod writer"; sched -> api "allocate shared0 @ node-a
                      (consumedCapacity hosts 1, shareID); BindingConditionsPending"; ctrl -> pool "POST attach
                      shared0 {host node-a, owner k8s:resourceclaim/<uid>}"; pool -> hw_a "hot-plug cxl-type3 sn
                      0xc1ae0001" (drawn); ctrl -> api "Attached=True, data {serial, shared true, size 268435456}".
                      state: api "claim shared-memory(a): shared0 @ node-a Attached; shared0 hosts 1/4"; pool
                      "shared0: attached node-a"; hw_a "mem0 sn 0xc1ae0001 appears".
4.03 writer-writes    send: runner_a -> agent_a "NodePrepareResources"; agent_a -> hw_a "create-region, devdax";
                      agent_a -> runner_a "CDI pool-c1ae0001: /dev/dax0.0, CXL_SHARED_DAX_C1AE0001=/dev/dax0.0,
                      CXL_SHARED_SIZE_C1AE0001=268435456, CXL_SHARED_SERIAL_C1AE0001=0xc1ae0001" reply; runner_a ->
                      a1 "start writer" (drawn).
                      state: hw_a "mem0 -> region0 -> /dev/dax0.0 (device_dax)"; a1 "writer / writer" "(pod
                      writer, node-a)" "/dev/dax0.0 rw" "wrote 'hello from node-a' at 0"; pool "shared0.raw holds
                      'hello from node-a'".
4.04 reader-claim     send: note "kubectl apply on node-b: ResourceClaim shared-memory-b (same selector) + Pod
                      reader"; sched -> api "allocate shared0 @ node-b (hosts 2/4)"; ctrl -> pool "POST attach
                      shared0 {host node-b}"; pool -> hw_b "hot-plug the SAME backing file, serial 0xc1ae0001"
                      (drawn); ctrl -> api "Attached=True".
                      state: pool "shared0: attached node-a, node-b"; hw_b "mem0 sn 0xc1ae0001 appears"; api
                      "shared0 hosts 2/4".
                      text: Same serial in every node: that is how the agent finds it. Two attachments, each owned
                      by its claim.
4.05 reader-reads     send: runner_b -> agent_b "NodePrepareResources"; agent_b -> hw_b "create-region, devdax";
                      runner_b -> b1 "start reader" (drawn).
                      state: hw_b "mem0 -> region0 -> /dev/dax0.0 (device_dax)"; b1 "reader / reader" "(pod
                      reader, node-b)" "/dev/dax0.0 rw" "read at 0: 'hello from node-a'".
                      text: Same bytes, no network in between. The agent refuses mode numa for a shared device.
4.06 independent      fast-forward: note "node-a: delete pod writer + claim"; runner_a -> agent_a "unprepare";
                      agent_a -> hw_a "destroy region0, disable mem0"; ctrl -> pool "DELETE attachment
                      shared0@node-a" (drawn); pool -> hw_a "device_del -> DEVICE_DELETED".
                      state: a1 gone; hw_a "no CXL memory devices"; pool "shared0: attached node-b"; b1 "still
                      reads 'hello from node-a'".
                      text: Each node releases independently; node-b keeps reading. (Then node-b releases too and
                      shared0 is free again: next card.)
```

### Chapter 5: one exclusive writer, many read-only readers, attached while running (test13, TWO_NODES, 22 frames)

Source: test13 `code.var.sh` and its trace-summary (times are +s from the
first trace line of that run). Both nodes have the token DeviceClass and
the template `cxl-lease-token`; the controller runs on node-b, agents on
both. Start state: shared0 free, pooled0 free, no pods.

```
5.00 ch5-card         card: the plot in 5 lines (B writer exclusive; C readers wait; D writer exits, readers get
                      it; E2 late exclusive fails; F fourth reader with a claim; G teardown) / "exclusive =
                      request all 4 'hosts'; read-only = an O_RDONLY fd (lease) or a device node with
                      permissions r (claim), both kernel-enforced".
5.01 writer-pod       send: note "kubectl apply: Pod writer on node-a {claim cxl -> template cxl-lease-token; main:
                      cxl-request shared 0xc1ae0001 --exclusive --wait 120s --exec sh -c 'dax-rw.py --fd 3 write 0
                      TEXT; wait for /tmp/done'}"; runner_a -> agent_a "NodePrepareResources(token claim)";
                      agent_a -> runner_a "CDI lease-<uid>: /run/cxl, cxl-request" reply (drawn).
                      state: a1 "writer / main" "(pod writer, node-a)" "/run/cxl/cxl.sock, cxl-request" "running";
                      agent_a "token socket for writer".
5.02 excl-request     send: a1 -> agent_a "{\"op\":\"lease\",\"kind\":\"shared\",\"serial\":\"0xc1ae0001\",
                      \"exclusive\":true,\"wait\":\"120s\"}"; agent_a -> api "list ResourceSlices of
                      cxl-pool.generic -> shared0 capacity hosts = 4" (drawn).
                      state: agent_a "lease 36c2ee71 Creating: shared, dax, exclusive, hosts 4".
                      text: Exclusive = ask for ALL hosts of the device. The agent reads how many from the pool's
                      offer list (validValues: 1 or 4).
5.03 writer-companion send: agent_a -> api "create claim cxl-lease-36c2ee71 {class cxl-shared-memory, selector
                      serial == 0xc1ae0001, capacity.requests.hosts: 4, configs LendConfig + PoolDeviceConfig
                      {mode dax, readOnly false}} + companion pod (node-a)"; sched -> api "allocate shared0 @ node-a,
                      consumedCapacity hosts 4; BindingConditionsPending" (drawn).
                      state: api "cxl-lease-36c2ee71: shared0 @ node-a, hosts 4/4 taken"; sched "shared0: 0 of 4
                      hosts free"; agent_a "lease 36c2ee71 Pending".
                      text: While this claim exists, the scheduler can give shared0 to nobody else.
5.04 excl-attach      send: ctrl -> pool "POST /devices/shared0/attachments {host node-a, owner k8s:resourceclaim/
                      <uid>, exclusive: true}"; pool -> hw_a "hot-plug cxl-type3 sn 0xc1ae0001 (fcp_shared0.hp1)"
                      (drawn); pool -> ctrl "201 attached, exclusive" reply; ctrl -> api "Attached=True, data
                      {serial, shared true, size, exclusive true}".
                      state: pool "shared0: attached node-a (EXCLUSIVE); any other host -> 409"; hw_a "mem0 sn
                      0xc1ae0001 appears"; ctrl "attached shared0 -> node-a exclusive".
                      text: The pool enforces it too: an exclusive attachment refuses every other host, including
                      nodes of other clusters that share this pool.
5.05 writer-writes    send: runner_a -> agent_a "NodePrepareResources(cxl-lease-36c2ee71)"; agent_a -> hw_a
                      "create-region, devdax -> /dev/dax0.0"; agent_a -> a1 "{\"lease\":\"36c2ee71\",\"state\":
                      \"Ready\",\"kind\":\"shared\",\"mode\":\"dax\",\"exclusive\":true,\"dax\":\"/dev/dax0.0\",
                      \"size\":268435456} + fd (O_RDWR)" reply (drawn).
                      state: hw_a "mem0 -> region0 -> /dev/dax0.0 (device_dax)"; a1 "lease 36c2ee71 Ready excl rw"
                      "fd 3; wrote TEXT at 0; 'written'; waiting for /tmp/done"; agent_a "lease 36c2ee71 Ready";
                      pool "shared0.raw holds TEXT (the host checks it)".
                      text: 6.3 s after the request in the recorded run.
5.06 reader-a-asks    send: note "kubectl apply: Pods reader-a, reader-b on node-b, reader-c on node-a, each: cxl-
                      request shared 0xc1ae0001 --read-only --wait 300s --exec sh -c 'dax-rw.py --fd 3 check-ro 0;
                      dax-rw.py --fd 3 watch 0 /tmp/stop'"; runner_b -> agent_b "prepare token claims"; b1 ->
                      agent_b "{\"op\":\"lease\",\"kind\":\"shared\",\"serial\":\"0xc1ae0001\",\"readOnly\":true,
                      \"wait\":\"300s\"}" (drawn); agent_b -> api "create cxl-lease-2562aeca {hosts default 1,
                      PoolDeviceConfig {dax, readOnly true}} + companion".
                      state: b1 "reader-a / main" "(pod reader-a, node-b)" "cxl-request shared --ro ... waiting";
                      agent_b "lease 2562aeca Pending ro"; api "cxl-lease-2562aeca: unallocated".
5.07 readers-b-c      fast-forward: b2 -> agent_b "same, read-only"; agent_b -> api "create cxl-lease-e5597c7f";
                      a2 -> agent_a "same, read-only" (drawn); agent_a -> api "create cxl-lease-ce5ef151".
                      state: b2 "reader-b / main" "lease e5597c7f Pending"; a2 "reader-c / main" "(pod reader-c,
                      node-a)" "lease ce5ef151 Pending"; agent_a "lease ce5ef151 Pending ro"; agent_b "leases
                      2562aeca e5597c7f Pend.".
5.08 readers-wait     no send (one MSC note: "10 s pass: nothing moves").
                      state: sched "shared0: 0 of 4 hosts free; 3 claims unallocatable"; api "companion pods
                      Pending: FailedScheduling 'cannot allocate all claims'"; pool "attachments: node-a
                      (exclusive) only; never asked for the readers".
                      text: The scheduler cannot allocate: all 4 hosts are consumed. The pool was never even
                      asked. The readers' cxl-request calls block (wait 300 s).
5.09 writer-exits     send: note "touch /tmp/done in writer -> CMD exits -> cxl-request exit 0 -> container main
                      exits -> pod writer Succeeded (restartPolicy Never)"; runner_a -> agent_a "NRI StopContainer
                      writer/main" (drawn).
                      state: a1 dotted "(exited)"; agent_a "writer gone and will not restart -> lease 36c2ee71
                      Releasing"; api "pod writer: Completed".
                      text: The agent releases the leases of a container that stopped for good (pod finished,
                      deleted, or restartPolicy Never); otherwise it keeps them for a restart.
5.10 writer-cleanup   fast-forward: agent_a -> api "delete companion pod + claim cxl-lease-36c2ee71" (drawn);
                      runner_a -> agent_a "NodeUnprepareResources(companion)"; agent_a -> hw_a "destroy region0,
                      disable mem0 (device still attached)"; note "claim cxl-lease-36c2ee71 deallocated, deleted:
                      shared0 hosts 4/4 free"; sched -> api "allocate the 3 reader claims: hosts 1 each; node-b,
                      node-b, node-a; BindingConditionsPending x3".
                      state: hw_a "mem0 sn 0xc1ae0001: present, disabled, no region"; api "cxl-lease-2562aeca,
                      -e5597c7f: node-b; -ce5ef151: node-a (Pending)"; sched "allocated 3 readers; hosts 3/4";
                      agent_a "lease 36c2ee71 released".
                      text: As soon as the writer's claim is gone the scheduler allocates all three readers.
5.11 ctrl-detaches    send: ctrl -> pool "DELETE /devices/shared0/attachments/node-a (no claim wanted it at that
                      instant)"; pool -> hw_a "device_del fcp_shared0.hp1 ... DEVICE_DELETED after ~6 s" (drawn);
                      pool -> ctrl "200 detached" reply.
                      state: pool "shared0: free (for a moment)"; hw_a "no CXL memory devices"; ctrl "detached
                      shared0 from node-a".
                      text: The controller reconciled in the gap between 'writer claim gone' and 'reader claims
                      allocated' and detached. (The code can also just clear the exclusive flag of an existing
                      attachment, reconciler.go:204; the recorded run took the detach path. Either way the
                      readers get the device.)
5.12 ctrl-attaches-2  send: ctrl -> pool "POST attach shared0 {host node-a, owner k8s:resourceclaim/<ce5ef151 uid>}";
                      pool -> hw_a "hot-plug cxl-type3 sn 0xc1ae0001 (fcp_shared0.hp2)"; pool -> ctrl "201" reply;
                      ctrl -> pool "POST attach shared0 {host node-b, owner k8s:resourceclaim/<2562aeca uid>}";
                      pool -> hw_b "hot-plug cxl-type3 sn 0xc1ae0001 (fcp_shared0.hp1)" (drawn; this is the mock
                      frame of C.4); pool -> ctrl "201" reply; ctrl -> api "Attached=True for cxl-lease-2562aeca,
                      -ce5ef151, -e5597c7f".
                      state: pool "shared0: attached node-a, node-b (not exclusive)"; hw_a "mem0 sn 0xc1ae0001
                      appears"; hw_b "mem0 sn 0xc1ae0001 appears"; ctrl "attached x2, Attached written x3"; api
                      "3 reader claims Attached".
                      text: One attachment per node serves all claims of that node (reader-a and reader-b share
                      node-b's).
5.13 readers-prepared send: runner_a -> agent_a "NodePrepareResources(cxl-lease-ce5ef151)"; agent_a -> hw_a
                      "create-region, devdax -> /dev/dax0.0"; runner_b -> agent_b "NodePrepareResources(cxl-lease-
                      2562aeca, cxl-lease-e5597c7f)"; agent_b -> hw_b "create-region, devdax -> /dev/dax0.0 (one
                      region, reused for the second claim)" (drawn; two arrows: agent_a -> hw_a and agent_b ->
                      hw_b, different columns).
                      state: hw_a "mem0 -> region0 -> /dev/dax0.0 (device_dax)"; hw_b same; agent_a "lease
                      ce5ef151 Ready ro"; agent_b "leases 2562aeca e5597c7f Ready ro".
                      text: Both nodes prepare the same serial. On node-b one region serves two claims; the agent
                      releases it only when the last claim is unprepared.
5.14 readonly-fds-b   send: agent_b -> b1 "open(/dev/dax0.0, O_RDONLY) -> {\"lease\":\"2562aeca\",\"state\":
                      \"Ready\",\"readOnly\":true,\"dax\":\"/dev/dax0.0\",...} + fd" reply (drawn); agent_b -> b2
                      "same for e5597c7f" reply.
                      state: b1 "lease 2562aeca Ready ro; fd 3 (O_RDONLY)" "check-ro: writable mapping refused
                      EACCES; read: TEXT; holding"; b2 same with e5597c7f.
                      text: CXL_LEASE_READONLY=1. A read-only fd allows PROT_READ mappings only; PROT_WRITE ->
                      EACCES, a store -> SIGSEGV, re-opening via /proc/self/fd -> EPERM. Kernel-enforced, root
                      or not.
5.15 readonly-fd-a    send: agent_a -> a2 "O_RDONLY fd for ce5ef151" reply (drawn).
                      state: a2 "lease ce5ef151 Ready ro; fd 3" "EACCES on write map; read: TEXT; holding"; pool
                      "shared0.raw still holds TEXT".
                      text: 13.2 s after the writer's exit all three hold the memory (9.4 s in another run):
                      about 6 s hot-remove plus about 5 s scheduler poll. They read what the writer wrote.
5.16 late-exclusive   send: b1 -> agent_b "cxl-request shared 0xc1ae0001 --exclusive --wait 15s"; agent_b -> api
                      "create cxl-lease-98dee186 {hosts 4}"; note "scheduler: FailedScheduling, 1 of 4 hosts free;
                      15 s pass"; agent_b -> api "delete companion 98dee186 (timeout)"; agent_b -> b1
                      "{\"lease\":\"98dee186\",\"state\":\"Failed\",\"error\":\"timeout: not Ready after 15s\"}"
                      reply (drawn); note "cxl-request exit 3".
                      state: agent_b "lease 98dee186 Failed -> released; no leftovers"; api "no cxl-lease-98dee186";
                      b1, b2, a2 unchanged "holding".
                      text: A new exclusive request cannot take the device from the readers: it waits, times out,
                      and cleans up after itself. Nobody lost their mapping.
5.17 reader-d-claim   send: note "kubectl apply: ResourceClaim shared-read-only {class cxl-shared-memory, selector
                      serial == 0xc1ae0001, config PoolDeviceConfig {readOnly: true}} + Pod reader-d on node-a";
                      sched -> api "allocate shared0 @ node-a (hosts 4/4 now); BindingConditionsPending"; ctrl ->
                      api "Attached=True (shared0 is already attached to node-a: no pool call)" (drawn).
                      state: api "claim shared-read-only: shared0 @ node-a Attached; shared0 hosts 4/4"; ctrl
                      "already attached, status written"; sched "shared0: 0 of 4 hosts free".
                      text: A claim at pod creation on a node that already has the device: the controller only
                      writes the status. 0.1 s.
5.18 reader-d-runs    send: runner_a -> agent_a "NodePrepareResources(shared-read-only)"; agent_a -> runner_a "CDI
                      generic/cxl=pool-c1ae0001-ro: deviceNodes [/dev/dax0.0 permissions r], env CXL_SHARED_DAX_
                      C1AE0001=/dev/dax0.0, CXL_SHARED_SIZE_C1AE0001=268435456, CXL_SHARED_SERIAL_C1AE0001=
                      0xc1ae0001, CXL_SHARED_READONLY_C1AE0001=1 (region0 reused)" reply; runner_a -> a1 "start
                      reader-d" (drawn).
                      state: a1 "reader-d / main" "(pod reader-d, node-a; claim)" "/dev/dax0.0 r: open O_RDWR ->
                      EPERM; write map -> EACCES" "read: TEXT".
                      text: Four readers, two per node, read the same bytes at the same time: three through a
                      passed fd (no device node), one through a read-only device node from its claim.
5.19 readers-finish   fast-forward: note "touch /tmp/stop in reader-a/b/c -> 'final: TEXT' -> cxl-request exit 0 ->
                      cxl-release --all"; b1 -> agent_b "{\"op\":\"release\",\"all\":true}"; b2 -> agent_b same;
                      a2 -> agent_a same; agent_b -> api "delete companions 2562aeca, e5597c7f" (drawn); agent_a ->
                      api "delete companion ce5ef151"; note "kubectl delete pod reader-d, claim shared-read-only";
                      runner_b -> agent_b "unprepare x2: first 'serial still used by another claim', then release
                      mem0"; runner_a -> agent_a "unprepare x2: same, release mem0 after reader-d".
                      state: b1 "lease released; final: TEXT"; b2 same; a2 same; a1 gone; hw_a "mem0: disabled,
                      no region"; hw_b same; agents "no leases".
                      text: Release is cooperative: the readers unmap and release, then the agents destroy the
                      regions. The device is still attached until the controller acts.
5.20 pool-free        send: ctrl -> pool "DELETE attachment shared0@node-b"; pool -> hw_b "device_del ->
                      DEVICE_DELETED (~6 s)"; ctrl -> pool "DELETE attachment shared0@node-a"; pool -> hw_a
                      "device_del -> DEVICE_DELETED (~6 s)" (drawn as a fan-out: pool -> hw_a and pool -> hw_b
                      sharing the pool's N port, see D).
                      state: pool "shared0: free; pooled0: free"; hw_a, hw_b "no CXL memory devices"; api "no
                      claims, no cxl-lease-* objects"; ctrl "idle".
                      text: Back where we started: no claims, no companions, no attachments, no regions, no
                      qemu devices. (test13 goes on to use pooled0 as a dax device through a lease and a claim:
                      chapter 2 showed the claim; `cxl-request memory 256Mi --dax` is the lease form.)
5.21 finale-recap     card: what enforced what: exclusivity = the scheduler (all 4 hosts consumed) AND the pool
                      (exclusive attachment refuses other hosts/clusters); read-only = O_RDONLY fd or CDI device
                      node 'r' (device cgroup), kernel-enforced; sharing = devdax only, same serial on every
                      node; cleanup = always unprepare -> deallocate -> detach; timings.
5.22 end              card: where to look: nri-plugins scripts/testing/fake-cxl-pool (README.md,
                      plan-2-dra/10-contract.md), driver doc/cxl/POOL.md, examples under deployments/cxl/pool,
                      e2e tests test10-13 and their trace-summary.txt (dra-trace-summary merges every component's
                      log on one clock).
```

Frame count: 8 + 17 + 8 + 18 + 7 + 23 = 81 files (cards and recaps
included; about 68 story frames). Chapter 4 is deliberately short; if the
total must shrink, drop 0.07, 1.16, 2.06, 3.15 and merge 5.14/5.15.


## F Python DSL / API design

### F.1 Module layout (`presentations/terminal/scripts/`)

```
stageplay.py   reusable library: Glyphs, Layout/Slot, Stage, Entity, Router, MSC, Renderer, Checker, output files
layouts.py     the two layouts (SINGLE, TWO_NODES): slot table declared once (name, x, y, w, h, style, ports, zone,
               msc lane), row map, zone rules, MSC lane sets, legend text
story.py       the story: cast, chapters, frames (sections E), using only stageplay's API; `python3 story.py ...`
README.md      (optional, one screen) how to render and present
```
No third-party dependencies (Python 3.9+). `story.py` must stay free of
coordinates: it refers to slots by name only.

### F.2 Classes and signatures

```python
# layouts.py
@dataclass(frozen=True)
class Slot:
    name: str            # "sched", "api", "ctrl", "pool", "runner_a", "agent_a", "hw_a", ..., "a1", "a2", "b1", "b2"/"b3"
    x: int; y: int; w: int; h: int
    zone: str            # "cluster" | "node-a" | "node-b" | "container-a" | "container-b" | "outside"
    style: str = "single"   # "single" | "double" (containers)
    ports: dict = field(default_factory=dict)  # {"N": col, "S": col, "W": row, "E": row} absolute; defaults = midpoints
    placeholder: str | None = None   # descriptive title to draw dotted before introduction; None = hidden when empty
    lane: str | None = None          # MSC lane name, e.g. "agnt-b"

@dataclass(frozen=True)
class Layout:
    name: str; width: int; diagram_lines: int           # 120, 30
    slots: dict[str, Slot]
    rules: list[tuple[int, int, int, str]]              # (y, x0, x1, label)
    gutters: list[int]                                  # y of every horizontal gutter (rules included)
    edge_wire_cols: tuple[int, int]                     # (2, 117)
    badge_cols: tuple[tuple[int,int], tuple[int,int]]   # ((0,1), (118,119))
    msc_lanes: list[str]                                # ["Pod-a","agnt-a","kblt-a","HW-a","schd","API","ctrl","pool","HW-b",...]
    msc_lane_width: int                                 # 5 (TWO_NODES) or 7 (SINGLE)
    legend: str

SINGLE: Layout; TWO_NODES: Layout
```

```python
# stageplay.py
class Stage:
    def __init__(self, title: str, out_dir: Path, layout: Layout, glyphs: Glyphs = UNICODE): ...

    # --- structure
    def chapter(self, number: int, title: str, body: list[str], layout: Layout | None = None,
                clear_workloads: bool = True) -> None
        """Writes a title card frame, resets the MSC (step numbers continue), optionally switches layout."""
    def card(self, slug: str, heading: str, body: list[str]) -> None     # recap / glossary card (no MSC reset)

    # --- entities (state)
    def entity(self, id: str, slot: str, title: str, tech: str, lines: list[str] = ()) -> None
        """Create or re-create an entity in a slot. tech = technical name shown as line 1 in parentheses."""
    def state(self, id: str, *lines: str) -> None          # replace all state lines (★ computed by diff)
    def line(self, id: str, index: int, text: str) -> None # replace one state line
    def remove(self, id: str, epitaph: str = "(gone)") -> None   # dotted once with epitaph, then hidden/placeholder

    # --- communications
    def send(self, src: str, dst: str, label: str, short: str | None = None,
             kind: str = "request", draw: bool = True) -> int
        """Record an MSC row (returns the global step number); kind in {"request","reply"}; short (<=53 chars)
        is the MSC label, label is the full text for the caption; draw=False records without an arrow."""
    def note(self, text: str, short: str | None = None) -> int   # MSC row without arrow (user action, kernel event)
    def fast_forward(self, steps: list[tuple], draw_last: bool = True) -> list[int]
        """steps = [(src, dst, label[, short[, kind]]) | ("note", text)]; only the last arrow is drawn."""

    # --- frame
    def caption(self, *lines: str) -> None                 # up to 2 narration lines (<= 116 chars each, wrapped if longer)
    def frame(self, slug: str, title: str | None = None) -> Path
        """Render: title bar, diagram (entities, placeholders, arrows of this frame), legend, caption
        (auto line 1 = '★<n> <src> -> <dst>: <label>' of the drawn step(s)), blank, MSC of the chapter.
        Writes NNN-chC-slug.txt, clears per-frame markers (★, arrows), returns the path."""

    # --- end
    def finish(self) -> None                               # writes 000-index.txt, removes stale files, prints summary
```
Helpers: `Stage.step` (current step number), `Stage.frames` (list of
(seq, chapter, slug, title) for the index), `Stage.layout`.

Renderer internals (not part of the story API): `Canvas(width, lines)`
with `put`/`box`/`rule`; `Router.route(src_slot, dst_slot) -> list[(x, y, glyph)]`
implementing the three cases of D and the junction merge; `MSC.render(rows) -> list[str]`;
`Checker.check(frame_text, layout)`.

### F.3 Entity state and ★

`Stage` keeps `entities[id] = Entity(slot, title, tech, lines, introduced_in_frame)`
and a snapshot of the previous frame's rendered lines per entity. At
`frame()`, every state line whose text differs from the snapshot (or
belongs to an entity created since) gets `★ ` prefixed; a box title gets
`★` when the entity is new. Authors never type `★`. The checker refuses
`★` in author text.

### F.4 File naming, cleaning, index

- Files: `rendered/NNN-chC-slug.txt`, `NNN` = 3-digit global sequence
  starting at 001 (cards included), `C` = chapter number (0-5), slug =
  `[a-z0-9-]+` from the author. Inserting a frame renumbers everything
  automatically on the next run; no numbers in `story.py`.
- `000-index.txt`: table of contents (frame number, chapter, slug, title,
  drawn step numbers), shown first by `less *`.
- `finish()` removes from `rendered/` every file matching
  `[0-9][0-9][0-9]-*.txt` that this run did not write (and nothing else),
  after rendering into a temporary directory and moving the files in, so a
  failed run leaves the previous output intact.
- All files UTF-8, LF, no trailing spaces, no tabs, lines <= 120.

### F.5 Self-check (`--check`) and partial rendering

`python3 story.py [--out DIR] [--check] [--chapter N] [--frame NNN|slug] [--ascii] [--list] [--width 120]`

- Default: render everything to `../rendered/` (relative to `scripts/`).
- `--check`: render in memory and verify for every frame: every line <= width;
  every character in the allowed set (C.7; `--ascii` set when given); the
  diagram region is exactly `layout.diagram_lines` lines in every frame and
  the caption block exactly 3 lines, so frames never jump; no arrow cell
  overwrites a box, a zone label or another arrow (except permitted
  junctions); all state lines fit their box (`w - 3`); MSC short labels
  <= 53 characters (<= 61 in SINGLE); ports of boxes adjacent to a rule
  gutter are right of the rule's label; every `send` names existing
  entities whose slots are visible in the current layout; a frame has at
  most 2 drawn arrows; slugs unique per chapter. Exit code 1 with a list
  of `frame NNN slug: problem`.
- `--chapter N`: simulate all frames (state must be complete) but write
  only chapter N's files; does not delete other files. `--frame X`: same
  for one frame. `--list`: print the index without writing.
- `--ascii`: glyph table `- | + + + + + + + + +`, `=` for double lines,
  `> < ^ v` heads, `*` for ★, `:` for dotted. Same geometry.

### F.6 Sketch of `story.py` (chapter 1, first frames)

```python
from stageplay import Stage
import layouts as L

s = Stage("CXL memory from a pool, with Kubernetes DRA", out_dir=Path(__file__).parent.parent / "rendered",
          layout=L.SINGLE)
# chapter 0 ... (cast)
s.chapter(1, "A pod claims pooled memory as a NUMA node", body=[...])
s.state("pool", "shared0 0xc1ae0001 256M shared: free  │  pooled0 0xc1ee0001 512M excl: free")
n1 = s.send("ctrl", "pool", "GET /api/v1/devices?scope=pool", draw=False)
n2 = s.send("pool", "ctrl", "[pooled0 512M exclusive free, shared0 256M shared free]", kind="reply", draw=False)
s.send("ctrl", "api", "create ResourceSlice cxl-pool.generic/fake-cxl-pool (allNodes): pooled0 {serial 0xc1ee0001, "
                      "shared false, size 512Mi -> capacity memory 512Mi}, shared0 {shared true, hosts 4 (1|4)}; "
                      "bindsToNode, bindingConditions [cxl-pool.generic/Attached]",
       short="create ResourceSlice pool: pooled0, shared0")
s.state("api", "slice pool: pooled0 512Mi excl, shared0 shared (hosts 4)", "no claims, no pods")
s.state("ctrl", "publishing 2 devices", "watching claims and nodes")
s.caption("The controller turns the pool's device list into an offer list. The devices are on no node yet:",
          "bindsToNode + a binding condition tell the scheduler: pick a node, then wait until I say Attached.")
s.frame("publish-pool", "the pool becomes an offer list")
...
s.finish()
```


## G Open questions and assumptions

1. Node names: `node-a`/`node-b` on screen, real VM names in the fact sheet
   and the end card. Assumed acceptable.
2. Chapter 2 (dax claim) is shown on node-b for continuity although test13
   H2 ran it on node-a (VM1). Chapter 4 presents test11's two-cluster
   sharing inside the two-node cluster of test13 (one controller) and says
   so on its card. Both are simplifications of where, not of what.
3. Lease ids in chapter 3 are illustrative; chapter 5 uses the ids of the
   recorded run (36c2ee71, 2562aeca, e5597c7f, ce5ef151, 98dee186).
4. The finale follows the recorded trace (detach, then re-attach to both
   nodes). Frame 5.11's caption mentions the alternative code path (flag
   cleared in place). If the user prefers the "designed" path, 5.11 and
   5.12 collapse into one frame with no hot-remove.
5. `cxl-request memory 256Mi --dax` (test13 H1) is only mentioned (5.20);
   add a frame after 3.11 if wanted.
6. The API box has two state lines; the author must summarize (one line
   claims, one line pods/companions). If that proves too tight, the row
   map in `layouts.py` grows the cluster row by one line (diagram 31 lines).
7. Terminal assumption: >= 120 columns, >= 40 lines, UTF-8, a font where
   box drawing and `► ◄ ▲ ▼ ★` are single width; `--ascii` otherwise.
   Suggest `less -S` is NOT needed (no line exceeds 120) and that `less`
   is started as `less *` in `rendered/` with `--chop-long-lines` off.
8. No colors (plain files). If the presenter wants them later, the Glyphs
   table can carry ANSI sequences without changing the story.
9. The companion pod of chapter 3 is shown as a workload slot (b3) to make
   "a pause pod holds the claim" visible; in chapter 5 companions appear
   only in the API/agent state lines (no free slots).


## H Documentation vs code disagreements found (code wins)

1. `POOL.md:244` shows the Attached message as `shared0 attached to node1`;
   the controller writes `<dev> attached to <host> (slot <bus>)`
   (`reconciler.go:356`; trace: `... (slot cxlsw_ds0_usrp0hb0)`).
2. `POOL.md:239-244` lists status data `serial, shared, size, host, attachment`;
   the controller also writes `hostUUID`, `qemuDeviceId` and `exclusive`
   (`status.go:48-57`), and test13 asserts `data.exclusive == true`.
3. `plan-4-multinode/02-implementation-status.txt` section 4 says that
   when the writer leaves, "a reader on the writer's node drops the flag
   before the readers of the other node attach". The code supports that
   (`reconciler.go:195-204`), but the recorded test13 run detached shared0
   from node-a (`DEVICE_DELETED` at +35.9 s) and re-attached it (`hp2`)
   together with node-b (`hp1`) at +36.5 s: the reconcile ran while no
   claim wanted the attachment. The storyboard follows the trace.
4. test12 `code.var.sh:206-207` comment says the companion is "Guaranteed
   with 1m CPU"; the assertion (`:209`) and the code (`broker.go:920-930`)
   say 100m (1m made the pause container take ~12 s to start).
5. `plan-3-cxl-live-attach/03-summary.txt` describes the socket protocol as
   "HTTP/JSON ... POST /v1/leases" and re-sending the fd as
   `cxl-request shared --lease <id>`; the code uses newline-delimited JSON
   over SOCK_STREAM (`broker.go:113-130`, `cxl-request/main.go:328-371`) and
   `cxl-request fd <lease> --exec` (`main.go:207-209`). `POOL.md:480-545`
   matches the code.
6. `pool/README.md:17-19` frames exclusive devices as "used as system RAM"
   and shared ones as devdax; since the last driver commit an exclusive
   device can also be a dax device (`PoolDeviceConfig mode: dax`,
   `pool.go:496-516`, test13 H1/H2). Not wrong, incomplete.
7. `POOL.md:301-302` keeps a `??? TODO` about restricting other containers
   from a claim's NUMA node: the presentation says so explicitly (1.12)
   rather than implying isolation.
8. The memory note `fake-cxl-pool-task-state.md` describes n4-cxl-shared-1/-2
   as two separate single-node clusters; `vm-k8s-reinit` (plan-4) makes
   them one two-node cluster for test13 and restores them afterwards. The
   presentation uses the two-node shape.


## Implementation notes

Implemented in `scripts/stageplay.py` (library), `scripts/layouts.py` (all
coordinates), `scripts/story.py` (the script); `README.md` one level up.
Where the implementation deviates from this plan, and why:

Screen and boxes
1. Row map. The cluster row has 6 lines (3 state lines, C.3 allowed it): the
   API box needs one line each for slices, claims and pods. To keep the
   picture at 30 lines, the legend moved below the caption (line 33; then a
   blank line, the sequence from line 35), and the pool box carries its
   technical name in its bottom border, leaving two state lines, one per
   device. Rows: 0 title, 1 rule, 2-7 cluster, 8 rule, 9-13 workloads, 14
   gutter, 15-19 runner/agent, 20 gutter, 21-24 hardware, 25 rule, 26-29
   pool, 30-32 caption. Picture plus caption is 33 lines.
2. Columns. Cluster row Scheduler 4-28, API 33-80, controller 85-115: 4-column
   gaps hold a `(nn)` badge under a straight arrow, and the controller's
   technical name fits. SINGLE workloads are 34 wide with 5-column gaps (b1
   4-37, b2 43-76, b3 82-115), so a wire can pass between them without
   touching a border; Pod runner 4-31, agent 36-115. TWO_NODES: Pod runner
   18, agent 32 (lease lines did not fit 34/18 the other way round).
3. Text budget. A box line is border, marker column, space, text, border:
   the `★` sits in a fixed marker column instead of being prefixed, so text
   never shifts when it is marked; a new box has `★` instead of the first
   dash of its title border. State lines keep one space before the right
   border (budget width - 5); the technical-name line may touch it (width - 4).
4. Story-side helpers `api(...)` (rows prefixed `slices:`, `claims:`,
   `pods:`) and `pool(...)` (fixed device columns, only the state animates).
   Allowed characters gained `╤ ╧ ╟ ╢` (a single wire leaving a double-line
   container box).
5. Chapter cards are frame N.00, so chapter 0 is 0.00 (title card), 0.01-0.06
   (cast), 0.07 (cast list). The plan's "frames N.01 - N.MM" footer, the
   title bar's `frame k/K` and all numbering are computed at render time.

Arrows (section D)
6. One deterministic shortest-path search replaces the three fixed cases:
   Dijkstra over the cells, cost = length + turns + running along a box side
   + distance of each end from the middle of its side (heads count double) +
   a penalty for side ports between boxes of different rows (except on the
   screen's outer edge) and for ports facing away from the other box. Rules
   kept from D: wires only in free cells, zone rules crossed vertically and
   never followed (a wire along a rule looks like the rule), no turn on a
   rule, labels and boxes never crossed, tee on the source border, head on
   the target border. Gaps of at most 4 columns between neighbours of one
   zone are horizontal-only. Cases 1-3 come out of the costs; the middle
   gutter of TWO_NODES does carry agent <-> API wires (D said never).
7. The controller -> pool example of D contradicts itself; resolved: the wire
   runs down the right edge (column 117), and the `OUTSIDE THE CLUSTER` rule
   ends at column 108 so the wire can turn into the pool's top border. Arrows
   enter the pool only from the top: a side arrow pointed at one device's line.
8. Side arrows point at the box's technical-name line, not into a state line.
9. Fan-out is two separate arrows from one box (the second routed around the
   first), no shared `┬` junction: pool -> both nodes (5.12, 5.20), Pod runner
   -> main and idle (3.03).
10. Badges: inline on a long horizontal run, else beside a vertical run (also
    on a rule line, as in the mock), else above or below; a bare number when
    `(n)` does not fit.

Captions and message sequence
11. Step numbers restart in every chapter (as the sequence does): badges stay
    within two digits. Chapter 5 has 77 steps.
12. Caption: line 1 is `★n from -> to: message` of the drawn step (the short
    form if the full text does not fit), with `(steps a-b below)` on
    fast-forwards; two-arrow frames have two step lines and one narration
    line. The full message text is not in the caption (it would not fit
    three lines) but in the sequence row of the frame that adds it, wrapped
    under its lifelines; older rows show `short=` or a cut label (`--check`
    warns about the cut ones). The whole chapter stays in the sequence (no
    window); README says `G` jumps to the newest rows.
13. Caption names of components: "Pod runner (node-b)", "CXL agent (node-a)",
    "CXL memory (node-b)", "Pool manager", ... (descriptive, with the node).

Storyboard (section E)
14. Chapter 1 uses the pool of test12/13 (pooled0 + shared0); test10 had
    pooled0 + pooled1. "The only exclusive device with 512Mi" holds for both.
15. Chapter 3 uses the lease ids of the recorded test12 run (0c822f6e,
    d301f49a; c9a6afb3, 945a8e2a), not illustrative ones. Corrections from
    the run: the shared lease was prepared as mem0/region0/dax0.0 (pooled0
    had left), not mem1/region1/dax1.0; container idle has cpuset.mems unset
    (it inherits every node, so lending is exclusive only where cpuset.mems is
    set: said in 3.08 and the recap); with the pod deleted, the agent released
    both leases when the container stopped ("requester container gone").
    Release took 8.4-10.4 s; the pod-deleted cleanup 14.6 s.
16. Chapter 3 has 19 files: the plan's 3.16 became "two leases alive" and
    "the pod goes, its leases go".
17. 2.06 (readOnly option) has no state change, only narration.
18. Chapter 4 shows the test's tagged string as 'hello from node-a' and says so.
19. 5.05: the exclusive lease was Ready 5.2 s after cxl-request (6.3 s after
    the writer pod was created; the plan said 6.3 s after the request).
20. 5.12 and 5.20 draw both hot-plugs / hot-removes; 5.20's caption says that
    the controller detached one node after the other (+77 s, +84 s).
21. 5.16 shows the scheduler's FailedScheduling for the late exclusive claim.

Command line (F.5)
22. `--width` is not implemented: the layouts are 120 columns by
    construction and `--check` verifies it. `--check` also verifies that the
    legend is on its fixed line (so picture and caption heights never change)
    and that no line has trailing spaces. `--frame` takes NNN or a slug.
23. A normal render runs the same checks and writes nothing if one fails;
    it renders into a temporary directory and moves the files in.
24. `s.settle()` (new): the current state counts as already shown; chapters
    reset boxes with it, so the first frame of a chapter marks only its own
    changes.
