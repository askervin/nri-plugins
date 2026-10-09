# WS-B: fake-cxl-pool-controller + serial scheme in the server

Status: spec written 2026-10-06 (Fable). Owner: Opus agent B.
Repository: ~/github.com/containers/nri-plugins (branch 5jQ-cxl),
scripts/testing/fake-cxl-pool. Contract: 10-contract.md sections 2, 5, 7.
Read first: 00-overview.md (D20-D33), 10-contract.md, ../plan/10 sections
4.1, 4.3, 4.5, ../plan/11 sections 1.3-1.7 and 5.5, pkg/api/types.go,
pkg/client/client.go, pkg/server/config.go, the e2e helper
test/e2e/memory.test-suite/memory-policy/n4-cxl-shared-2/pool.source.sh
(how the server is started in tests), README.md.

Agent A concurrently moves pkg/guest to pkg/cxl/memctl and edits
cmd/fake-cxl-pool-client; do not touch those. Build and test your own
packages (`go build ./scripts/testing/fake-cxl-pool/cmd/fake-cxl-pool-controller`,
`go test ./scripts/testing/fake-cxl-pool/pkg/controller/... ./scripts/testing/fake-cxl-pool/pkg/server/... ./scripts/testing/fake-cxl-pool/pkg/pool/...`),
not `./...` of the whole repo while A is mid-move.

## 1. Binary and layout

- cmd/fake-cxl-pool-controller/main.go: flags (stdlib flag, like the
  server): `-server` (default api.DefaultServerURL, env FAKE_CXL_POOL_SERVER),
  `-kubeconfig` (default "" = in-cluster, env KUBECONFIG),
  `-driver-name` cxl-pool.generic, `-pool-name` fake-cxl-pool,
  `-sync-interval` 10s, `-attach-timeout` 60s, `-detach-timeout` 60s,
  `-shared-hosts` 4 (the `hosts` capacity of shared devices),
  `-owner-prefix` "k8s:", `-v`. Logging: stdlib log with a "controller: "
  prefix style consistent with the server (every attach, detach, status
  write and error is one line; -v adds reconcile details).
- pkg/controller: publisher.go, reconciler.go, status.go, hosts.go,
  controller_test.go. Dependencies already in go.mod: k8s.io/api,
  apimachinery, client-go (informers, fake clientset, tools/record,
  util/retry), dynamic-resource-allocation/resourceslice. No go.mod edits
  expected; if one is needed, keep it minimal and say so in Status.
- Makefile: `bin/fake-cxl-pool-controller` built static for amd64 like the
  client (it runs in the VMs), part of `all`; `make test lint` cover it.

## 2. Publisher (publisher.go)

`resourceslice.StartController(ctx, resourceslice.Options{DriverName, KubeClient, Owner: nil, Resources: initial, ErrorHandler: log})`.
Every sync interval, and on each server event (client.Events, reconnect
with backoff; fall back to polling if the stream fails):
`client.Devices(ctx, DeviceListOptions{Scope: pool})` -> one
`resourceslice.Pool{Slices: [{Devices}]}` keyed by pool name, NodeSelector
nil (allNodes). `Controller.Update` only when the device list changed
(compare the built []resourceapi.Device with reflect.DeepEqual). Device
conversion exactly as 10-contract.md section 2; sanitize names to DNS
labels (lower-case, non [a-z0-9-] -> '-', trim, max 63, log and skip
duplicates). Devices in state `error` (quarantined) are not published.
Exclusive devices that are attached by someone else (manual client use)
are still published (the scheduler sees no state); attaching them fails
with 409 -> AttachFailed, which is the right signal.

## 3. Reconciler (reconciler.go, hosts.go)

Informers: ResourceClaims (all namespaces) and Nodes, from a shared
informer factory; informer events only trigger `requestReconcile()`
(debounced ~500 ms); a ticker at sync interval does the same. One goroutine
runs `reconcile(ctx)`:

1. hosts: `client.Hosts(ctx)`. For each Node in the lister: host whose UUID
   equals `node.Status.NodeInfo.SystemUUID` (compare lower-case without
   dashes), else host whose Name == node name. Build node->host and
   host->node maps; log changes. A node without host is "not a pool host".
2. desired: for each claim with `Status.Allocation != nil`, for each
   `Allocation.Devices.Results[i]` with Driver == driver-name and Pool ==
   pool-name: node = `Allocation.NodeSelector.NodeSelectorTerms[0].MatchFields[0].Values[0]`
   (key metadata.name); record want{device, node, claim, result index}.
   Group by (device, host).
3. actual: `client.Attachments(ctx, "", "")` filtered: not Adopted, host in
   host->node map, Owner has owner-prefix. Keyed by (device, host). States
   attaching/attached/detaching/failed are all "present".
4. attach: for each desired (device, host) without an attachment:
   `client.Attach(ctx, device, AttachRequest{Host: host, Owner: "k8s:resourceclaim/<claim uid>", Wait: true, Timeout: attach-timeout})`.
   201/200 -> ok. Errors -> remember failure for status (step 5), log.
   A desired entry whose node has no host -> failure reason NoHost.
5. status: for every want: if its (device, host) attachment is attached (or
   was attached in step 4) and the claim's status entry does not have
   Attached=True -> write Attached=True + data (10-contract.md section 5).
   If step 4 failed -> write AttachFailed=True with reason/message unless
   already present with the same message. Both through
   `setClaimDeviceStatus(ctx, claim, result, condition, data)`:
   get fresh claim, find/append the `status.devices[]` entry by (driver,
   pool, device), copy ShareID from the result (string of the UID), set the
   condition with meta.SetStatusCondition (clear the opposite condition),
   set Data (json.RawMessage), `UpdateStatus`, `retry.RetryOnConflict`.
   Emit an Event on the claim (record.EventRecorder, component
   fake-cxl-pool-controller): Normal "Attached" / Warning "AttachFailed" /
   Normal "Detached".
6. detach: for each actual attachment with no desired entry:
   `client.Detach(ctx, device, host, DetachOptions{Wait: true, Timeout: detach-timeout})`.
   200 -> log + event (on the Node if the claim is gone). 409/failed (guest
   has not released): log at every reconcile, do not escalate (D14 /
   contract section 7), the attachment stays and is retried next time
   unless the server reports it `failed` (then only log once per state
   change). Never detach attachments without our owner prefix or on hosts
   that are not our nodes.
Reconcile is serial; steps use the attach/detach timeouts as request
contexts; a long attach of one claim must not block status writes of
others more than necessary (fine: attach normally takes ~30 ms).

## 4. Unit tests (controller_test.go)

Fake pool server with net/http/httptest implementing GET /api/v1/hosts,
/devices, /attachments, POST /devices/{d}/attachments, DELETE
/devices/{d}/attachments/{h} over an in-memory map (reuse pkg/api types;
the real server package has a fake monitor too, but a small httptest
handler is simpler and independent). Fake clientset
(k8s.io/client-go/kubernetes/fake) with Nodes (systemUUID set) and claims.
Cases: (1) publish: exclusive and shared devices convert as in the
contract, error-state device skipped, name sanitized; (2) allocated claim
on a known node -> attach request with owner, Attached=True + data in
status; (3) node without host -> AttachFailed NoHost; (4) attach 409 ->
AttachFailed Conflict; (5) allocation removed -> detach; (6) restart:
attachment already exists, status missing -> only status written, no
second attach; (7) two claims, same shared device, same node -> one
attachment, detach only when both gone; (8) attachments with another owner
or on a foreign host are never detached. Run with -race.

## 5. Serial scheme in the server (D27)

- pkg/server/config.go: `SharedSerialBase` (default 0xc1ae0000) and
  `ExclusiveSerialBase` (default 0xc1ee0000) replace `SerialBase`
  (`serialBase` in YAML stays accepted as an alias for exclusiveSerialBase
  with a deprecation log line, or is removed if simpler: your call, say
  which). pkg/pool serials: auto-assigned serial = next free in the base of
  the device's kind; uniqueness checked over all devices as today.
- config.example.yaml, README.md (serial examples 0xc1f00001 -> 0xc1ee0001,
  shared examples 0xc1ae....; add a short "Serial numbers" paragraph
  explaining 0xc1 = CXL, 00 = boot-time, ae = shared, ee = exclusive, and
  that 0xc100e2e0+i are the e2e topology's local devices). Update the
  server/pool unit tests that expect 0xc1f0....
- Do not edit test/e2e files (agent C does) nor ../plan files; record the
  change in Status here.

## 6. Manifests and README

- scripts/testing/fake-cxl-pool/deploy/fake-cxl-pool-controller.yaml:
  Namespace fake-cxl-pool, ServiceAccount, ClusterRole with the RBAC of
  10-contract.md section 5, ClusterRoleBinding, Deployment (1 replica,
  hostNetwork: true so that it reaches 192.168.76.2, image placeholder
  `localhost/fake-cxl-pool-controller:testing`, args -server
  http://192.168.76.2:9909). Not used by the e2e tests (D26), used by test18
  later; note that in a comment.
- README.md: a "fake-cxl-pool-controller" section: what it does, flags,
  node->host mapping rule, owner convention, that each cluster runs one and
  several clusters may share one server, and a pointer to 10-contract.md /
  doc/cxl/POOL.md in the driver repo.

## 7. Smoke test against VM2, then clean up completely

Only after unit tests pass. VM2 = test/e2e/n4-cxl-shared-2-fedora-43-containerd
(ssh -F <dir>/.ssh-config node sudo bash -l). Steps:
1. On the host: `make -C scripts/testing/fake-cxl-pool`, start the server
   like pool-server-start does (copy its YAML with devices
   `pooled0 512M exclusive serial 0xc1ee0001`, discovery names of the two
   shared VMs, `-state /tmp/fcp-smoke.state.json -v`, log to a file under
   /tmp). Check `curl -s 127.0.0.1:9909/api/v1/hosts` lists both VMs. If
   port 9909 is busy, someone else is testing: stop and report.
2. Copy bin/fake-cxl-pool-controller and bin/fake-cxl-pool-client to the
   VM /usr/local/bin. Run
   `systemd-run --unit fcp-controller-smoke /usr/local/bin/fake-cxl-pool-controller -kubeconfig /root/.kube/config -v`.
   `kubectl get resourceslices -o yaml` shows the cxl-pool.generic slice
   with pooled0 as in the contract.
3. Apply the DeviceClasses (contract section 3), a claim `pooled-memory`
   (512Mi) and a busybox pod using it. Expect: pod event
   BindingConditionsPending, server attachment pooled0@VM2 with owner
   k8s:resourceclaim/..., claim status Attached=True with data, and the pod
   leaving Pending. Without the node plugin kubelet then fails with
   "DRA driver cxl-pool.generic is not registered" (ContainerCreating):
   that is expected and ends the smoke test. (If agent A's binary is
   already in /usr/local/bin/kubelet-cxl-plugin you may NOT start it; C
   owns that integration.)
4. Cleanup, in this order: `fake-cxl-pool-client guest release 0xc1ee0001`
   in the VM (no region exists, this only disables the memdev; needed
   before detach, see README "Release in the guest before detach");
   `kubectl delete pod ...; kubectl delete resourceclaim pooled-memory`;
   wait until the controller logs the detach and the server shows pooled0
   free and `info qtree -b` of VM2 qemu has no cxl-type3 (use
   `(cd <vmdir> && socat STDIO unix-connect:monitor.sock) <<< "info qtree -b"`,
   never qmp.sock); delete the DeviceClasses; `systemctl stop fcp-controller-smoke;
   systemctl reset-failed`; `kubectl get resourceslices` shows none of
   cxl-pool.generic (the unowned slice is NOT garbage collected: delete it
   with kubectl if the controller did not remove it on shutdown, and make
   the controller delete its slices on SIGTERM); stop the server; remove
   /tmp/fcp-smoke.state.json. Report the final state: no attachments, no
   cxl-type3 in qemu, no pool slices, port free.

## 8. Report

Append "Status" and "Findings": files, test results, smoke test excerpts
(the server log lines of attach/detach, the claim status YAML), deviations
from 10-contract.md (also add to its Deviations section), open issues.

## Status

Done 2026-10-06 (Opus agent B). Sections 1-7 implemented, unit tests pass,
smoke test against VM2 passed end to end, cleanup complete. Not committed.

Files (all under scripts/testing/fake-cxl-pool):
- new: cmd/fake-cxl-pool-controller/main.go; pkg/controller/{controller.go,
  publisher.go, reconciler.go, status.go, hosts.go, controller_test.go}
  (controller.go is extra: Config, New, Run loop, server event watcher,
  shutdown); deploy/fake-cxl-pool-controller.yaml.
- changed: Makefile (bin/fake-cxl-pool-controller, static amd64, in `all`;
  `test`/`lint` cover it through $(PKG)/...); pkg/api/types.go
  (Attachment.Owner); pkg/server/{config.go, server.go, ops.go, state.go}
  (serial scheme, attachment owner); pkg/pool/pool.go (two bases);
  tests pkg/server/{server_test.go, regression_test.go,
  example_config_test.go}, pkg/pool/pool_test.go; config.example.yaml;
  README.md (intro, build, "Serial numbers", "fake-cxl-pool-controller"
  section, REST owner note, Layout lines for the controller, pkg/controller,
  deploy/, plan-2-dra/; agent A's pkg/cxl/memctl Layout line untouched).
- go.mod: no change (k8s.io/* v0.34.11, k8s.io/utils/ptr already there).

Choices where the spec left one:
- `serialBase` is removed, not aliased: the server config is parsed
  strictly, so an old config fails with "unknown field serialBase". No
  config in test/e2e used it (grep). Agent C: the topology's static shared
  device is still `..._sn_0xc1f0ee00` in the n4-cxl-shared Vagrantfiles and
  test01's fake-cxl-pool.yaml still has `serial: 0xc1f0ee01` (D27 renames
  them; explicit serials keep working, they are not checked against bases).
- Serial kind: a device's kind is decided when its serial is assigned
  (create, config device without serial, state file device with a bad
  serial). Local devices without a serial in their backend id: shared base
  if file-backed, else exclusive. `PATCH shared` keeps the serial.
- Detach only for state `attached`; `detaching` is waited for by the server
  (logged each reconcile), `failed` logged once per state change. This keeps
  a not-released device from blocking the serial reconcile for
  detach-timeout on every pass (10-contract.md Deviations).
- Attach 202 (still attaching) writes nothing; exclusive device moving
  between our nodes does not write AttachFailed (10-contract.md Deviations).
- Reconcile, publish and status writes run in one goroutine (Run). Triggers:
  claim/node informer events and server events (debounced 500 ms) and the
  sync ticker. The server event stream reconnects with backoff 1 s..30 s;
  polling continues meanwhile. The first reconcile waits for the informer
  caches (a reconcile on empty caches would detach everything).
- The ResourceSlice controller is started on the first successful device
  list, so a server that is down at startup does not wipe an existing slice.
- On SIGTERM/SIGINT the controller stops the slice controller and deletes
  the slices with spec.driver = driver, pool = pool name and no nodeName.
- `-owner-prefix ""` means the default `k8s:` (an empty prefix would claim
  every attachment).
- Duplicate sanitized names and names with nothing left are logged once
  per device and skipped. Status entries are re-checked on a fresh GET
  before UpdateStatus, so a stale lister never causes a second write.
- Events: Normal Attached / Warning AttachFailed on the claim; Normal
  Detached on the claim, else on the Node (events of Nodes land in
  namespace default).

Test results:
- `go test -race ./scripts/testing/fake-cxl-pool/pkg/controller/` ok (12.7 s):
  TestPublish (1: exclusive + shared conversion, error device skipped,
  sanitized name, update on change, slice deleted on shutdown),
  TestDeviceName, TestDuplicateNamesSkipped, TestMapHosts,
  TestAttachAndStatus (2, plus steady state: no new request, same
  resourceVersion), TestNoHost (3), TestAttachConflict (4, then Attached
  replaces AttachFailed), TestDetachOnDeallocation (5, incl. 409/detaching:
  one request only), TestRestartWithExistingAttachment (6),
  TestSharedTwoClaimsOneNode (7), TestForeignAttachmentsKept (8: other
  owner, adopted, other cluster's host, failed), TestExclusiveMovesBetweenNodes.
- pkg/server, pkg/pool with -race: ok (new: shared device gets 0xc1ae0001,
  cross-kind uniqueness, attachment owners survive a restart).
- `make -C scripts/testing/fake-cxl-pool`, `make ... test`, `make ... lint`:
  all ok at 14:59-15:00 (agent A's client built fine then).

Smoke test (VM2 n4-cxl-shared-2-fedora-43-containerd, server on the host
with pooled0 512M 0xc1ee0001, controller as systemd-run unit
fcp-controller-smoke). Host clock = VM clock + 3 h.
- Slice: `cxl-pool.generic-8885n`, allNodes, pool fake-cxl-pool gen 1,
  pooled0 exactly as contract section 2 (memory 512Mi, serial "0xc1ee0001").
- Controller log:
  ```
  12:01:57.072303 publishing pool fake-cxl-pool: 1 devices [pooled0]
  12:01:57.093413 pool hosts of nodes: [n4-cxl-shared-2-fedora-43-containerd=n4-cxl-shared-2-fedora-43-containerd]
  12:02:37.441440 attached pooled0 to n4-cxl-shared-2-fedora-43-containerd (node ..., slot cxlsw_ds0_usrp0hb0, qemu device fcp_pooled0.hp1, owner k8s:resourceclaim/6fdcf97b-97fd-4157-a1b9-d0aaacfb614f) for default/pooled-memory
  12:02:37.455602 status of claim default/pooled-memory device pooled0 node ...: cxl-pool.generic/Attached=True reason Attached: pooled0 attached to n4-cxl-shared-2-fedora-43-containerd (slot cxlsw_ds0_usrp0hb0)
  12:04:11.318711 detached pooled0 from n4-cxl-shared-2-fedora-43-containerd (node ..., owner k8s:resourceclaim/6fdcf97b-...)
  12:04:30.592084 deleted ResourceSlice cxl-pool.generic-8885n
  ```
- Server log:
  ```
  15:02:37.641648 attachment pooled0@n4-cxl-shared-2-fedora-43-containerd: attaching to slot cxlsw_ds0_usrp0hb0 as fcp_pooled0.hp1 (backend fcp_pooled0.hp1, serial 0xc1ee0001)
  15:02:37.675645 attachment pooled0@n4-cxl-shared-2-fedora-43-containerd: attached
  15:02:37.675940 http 127.0.0.1:56480 POST /api/v1/devices/pooled0/attachments -> 201 (53ms)
  15:04:05.442709 attachment pooled0@...: detaching qemu device fcp_pooled0.hp1
  15:04:11.544436 qmp ...: event DEVICE_DELETED {"device": "fcp_pooled0.hp1", ...}
  15:04:11.552728 attachment pooled0@...: detached (qemu device fcp_pooled0.hp1)
  15:04:11.553102 http 127.0.0.1:56480 DELETE /api/v1/devices/pooled0/attachments/n4-cxl-shared-2-fedora-43-containerd?timeout=1m0s -> 200 (6.11s)
  ```
- Events: `BindingConditionsPending pod/fcp-smoke waiting for binding
  conditions for device on node ...` (12:02:36), `Attached
  resourceclaim/pooled-memory pooled0 attached to ... (slot
  cxlsw_ds0_usrp0hb0)`, then Scheduled 5 s later (the scheduler's poll).
- Claim status:
  ```yaml
  devices:
  - conditions:
    - lastTransitionTime: "2026-10-06T12:02:37Z"
      message: pooled0 attached to n4-cxl-shared-2-fedora-43-containerd (slot cxlsw_ds0_usrp0hb0)
      reason: Attached
      status: "True"
      type: cxl-pool.generic/Attached
    data:
      attachment: pooled0@n4-cxl-shared-2-fedora-43-containerd
      host: n4-cxl-shared-2-fedora-43-containerd
      hostUUID: 1b6d55a2-ae4a-52f8-bbba-2e3f9adca1b1
      qemuDeviceId: fcp_pooled0.hp1
      serial: "0xc1ee0001"
      shared: false
      size: 536870912
    device: pooled0
    driver: cxl-pool.generic
    pool: fake-cxl-pool
  ```
- Unexpected but good: agent A had started its own `kubelet-cxl-plugin-smoke`
  unit in VM2 at 12:02:33, between my preflight check and the pod creation.
  So the pod did not stop at "driver not registered": NodePrepare created
  the region and the pod ran with `CXL_POOL_NODE_C1EE0001=2`,
  `CXL_POOL_SIZE_C1EE0001=536870912`, `CXL_POOL_SERIAL_C1EE0001=0xc1ee0001`.
  The full allocate -> attach -> bind -> prepare -> unprepare -> detach
  cycle worked. I did not touch A's unit.
- Cleanup deviated from step 7.4 because of that: `guest release` before
  the pod deletion would have pulled the memory out from under the running
  container and A's prepared state. Instead I deleted the pod, A's plugin
  released the device in NodeUnprepare (`cxl-pool.generic: released mem0
  (serial 0xc1ee0001)` 12:04:04.597), the claim was deallocated and the
  controller detached it 0.8 s later (DEVICE_DELETED after 6.1 s). Then:
  claim and DeviceClasses deleted, unit stopped (it deleted its slice),
  server stopped (SIGTERM, "shutting down"), state file, config and
  /tmp/fake-cxl-pool/pooled0.raw removed.
- Final state: GET /attachments `[]`, pooled0 free; VM2 `info qtree -b`
  (monitor.sock) has 8 cxl-downstream and 0 cxl-type3; no cxl-pool.generic
  slices (only A's node-local cxl.generic slice remains); port 9909 free;
  no DeviceClasses or claims. Left in place: /usr/local/bin/fake-cxl-pool-controller
  and the rebuilt fake-cxl-pool-client in VM2 (step 2 installs them), the
  host log /tmp/fcp-smoke-server.log.

## Findings

- The API had no attachment owner, so "Owner has owner-prefix" (step 3)
  was not implementable as written; `api.Attachment.Owner` was added and is
  set from the attach request (10-contract.md Deviations). For a shared
  device attached by two claims on one node, the owner is the first claim;
  the controller does not care (it refcounts by desired claims), but a
  human reading /attachments sees only one claim uid.
- Retrying a detach of a `detaching` attachment with wait=true would block
  the serial reconcile for detach-timeout (60 s) on every pass while a
  guest holds memory; the server already waits in the background, so the
  controller only re-reads the state.
- Attach before detach in one reconcile made an exclusive device moving
  between two nodes of one cluster fail its first binding with Conflict;
  handled (Deviations).
- The controller keeps retrying attach on every reconcile while a claim is
  allocated and failed; the scheduler deallocates after AttachFailed, so in
  practice it is one or two retries. No DeviceTaintRule (KEP guidance "do
  not pick it again") yet.
- Seen in A's plugin log, not ours: the cxl.generic publisher reports
  `some fields were dropped by the apiserver, probably because these
  features are disabled: unknown` for its node slice on every update.
- Exclusive devices attached elsewhere (CLI, other cluster) are still
  published: the scheduler can pick them and gets AttachFailed Conflict, as
  the spec intends. With two clusters sharing one server this can cost
  binding cycles; a later improvement is to leave exclusive devices that
  are attached by a non-matching owner out of the slice.
- Unit tests take ~1 s each because informer caches sync on a 100 ms poll
  and every test builds its own controller; acceptable (12.7 s total).
- With `-v` every server event logs one line; the attach of one device
  produces about four, which is noisy but useful in traces (D28).
