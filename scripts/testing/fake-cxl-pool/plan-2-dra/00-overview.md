# plan-2-dra: CXL DRA driver extension, fake-cxl-pool-controller, e2e demos

Task: scripts/testing/fake-cxl-pool/5jW-task-dra-driver-cxl-controller.txt
(follow-up of 5jS, results in ../plan). Started 2026-10-06. Top-level design:
Fable 5.1. Coding/testing: Opus agents, one per workstream, each keeps the
"Status" section of its own file current. These files are checkpoints: a new
session resumes from them.

## Workstreams

| WS | File | Owner | Depends on | Status |
|----|------|-------|------------|--------|
| 1 | 10-contract.md | Fable | ../plan/10, ../plan/70 | written |
| A | 20-kubelet-cxl-plugin.md | Opus agent A | WS1 | done 2026-10-06: pkg/cxl/memctl, pool helper, tests, POOL.md, manifests; smoke test ran the full cycle with B's controller |
| B | 30-fake-cxl-pool-controller.md | Opus agent B | WS1 | done 2026-10-06: controller + tests + smoke (full cycle with A's plugin by accident); api.Attachment.Owner added |
| C | 40-e2e-tests.md | Opus agent C | A and B binaries for running | done 2026-10-06: test10 PASS 66 s, test11 PASS 107 s, test01 PASS 77 s afterwards; one memctl bug fixed (D34) |
| D | 50-realistic-tests.md | Fable (plan), later agents | C | plan written (test12-test20), not implemented in this task |

```
10-contract.md ──> A: kubelet-cxl-plugin pool helper (DRA repo) + pkg/cxl/memctl (nri-plugins)
               └─> B: fake-cxl-pool-controller (nri-plugins) + serial scheme in the server
A + B binaries ───> C: dra.source.sh, trace helper, test10-dra-pooling, test11-dra-sharing
C ────────────────> D: test12+ realistic tests
```

## Where the pieces live (decision D20)

The task asked to reconsider whether "cxl-pool-controller" belongs in the
production DRA driver repository. It does not. The controller must speak the
fake-cxl-pool REST protocol (pkg/client), resolve Kubernetes Nodes to qemu
VMs through the server's /hosts/resolve, and knows that the server lives at
the slirp gateway 192.168.76.2. None of that belongs in
intel-resource-drivers-for-kubernetes. So:

- nri-plugins/scripts/testing/fake-cxl-pool/cmd/**fake-cxl-pool-controller**:
  publishes the pool ResourceSlice, attaches on allocation, detaches on
  deallocation, writes binding conditions (30-fake-cxl-pool-controller.md).
- intel-resource-drivers-for-kubernetes cmd/kubelet-cxl-plugin: a second
  kubeletplugin helper for driver name `cxl-pool.generic` whose NodePrepare
  makes an already hotplugged device usable. It is protocol agnostic: it
  only needs the device serial, which any pool controller (fake, Maxview,
  CoHDI based) writes into the claim status. The contract between the two
  sides is 10-contract.md, to be shipped as doc/cxl/POOL.md in the driver
  repository (20-kubelet-cxl-plugin.md).
- nri-plugins/pkg/cxl/memctl (moved from scripts/testing/fake-cxl-pool/pkg/guest):
  the node-side library both the pool client and the driver use (D25).

## Decisions (continuing ../plan/00-overview.md numbering)

- D20 Controller name and home: fake-cxl-pool-controller in nri-plugins (above).
- D21 Sharing demo = two single-node clusters. n4-cxl-shared-1 and -2 are
  separate control planes (both 192.168.76.9 behind slirp, they cannot
  reach each other), so one multi-node cluster is not available. Each VM
  runs its own kubelet-cxl-plugin and fake-cxl-pool-controller; both
  controllers use the one server on the host. This is a realistic case
  too: several clusters sharing one memory pool.
- D22 The controller is a level-triggered, stateless reconciler. Desired
  attachments are computed from ResourceClaims (allocation results of our
  driver and pool, node from allocation.nodeSelector). Actual attachments
  come from the server (GET /attachments), filtered to owners with prefix
  `k8s:` and to hosts that are Nodes of this cluster. Missing ones are
  attached, extra ones detached. No state file, no PUT /allocation: the
  attach itself enforces exclusivity (409 when attached elsewhere). The
  attachment owner is `k8s:resourceclaim/<claim uid>`.
- D23 The node plugin reads serial, shared and size from
  `claim.status.devices[].data` (written by the controller together with
  the Attached condition). No ResourceSlice lookup: the status entry is
  what released the binding, so it is there whenever NodePrepare runs.
  Missing data is an error (kubelet retries).
- D24 Exclusive pool devices become system RAM onlined `online_movable`
  (removable) and are NOT fed into NRI memory steering: a cgroup whose
  cpuset.mems holds only ZONE_MOVABLE memory cannot start a container
  (verified in the driver's test/e2e/cxl/dra-demo-cxl.sh, which moves CXL
  memory to ZONE_NORMAL for that reason). The container instead gets CDI
  env vars CXL_POOL_NODE_<serial>=<numa node>, CXL_POOL_SIZE_<serial>.
  Shared pool devices become devdax: CDI device node /dev/daxX.Y plus
  CXL_SHARED_DAX_<serial>, CXL_SHARED_SIZE_<serial>. Steering pooled
  memory together with DRAM is realistic-test material (test17).
- D25 pkg/guest moves to nri-plugins/pkg/cxl/memctl (type Manager). It
  needs the `cxl` and `daxctl` CLIs on the node, so the e2e runs the
  driver as a host process (D26). A sysfs-only implementation is a later
  improvement, noted in doc/cxl/POOL.md. During development the driver
  repository uses `replace github.com/containers/nri-plugins => <local
  path>` + `go mod vendor`; before merging, push the fork and pin a commit.
- D26 In the e2e tests kubelet-cxl-plugin and fake-cxl-pool-controller run
  in the VMs as transient systemd units (systemd-run) with the admin
  kubeconfig, like dra-demo-cxl.sh runs the driver. A Deployment with
  ServiceAccount/RBAC is realistic-test material (test18), manifests are
  shipped anyway.
- D27 Serial scheme (task wish): `0xc100....` boot-time present devices
  (local beram devices stay 0xc100e2e0+i: "e2e"), `0xc1ae....` shared
  pool devices ("share"), `0xc1ee....` exclusive pool devices
  ("exclusive"). Server config: `sharedSerialBase: 0xc1ae0000`,
  `exclusiveSerialBase: 0xc1ee0000` replace `serialBase`. Topology static
  shared device 0xc1f0ee00 -> 0xc1ae0000, test01 shared0 -> 0xc1ae0001.
- D28 Trace helper `dra-trace-*` in dra.source.sh: every component's log
  stream (server log on the host; controller, driver, kube-scheduler,
  events, claim/pod watches, udevadm monitor in each VM) is read on the
  host, each line prefixed with the host clock, merged and sorted into one
  trace.txt, plus a grep summary. One clock, no VM clock skew issues.
- D29 Double advertising: the cxl.generic publisher skips regions whose
  memdev serial is in the set of serials the pool helper has prepared
  (persisted in its own state file, so a driver restart keeps the set).
  Regions on pool devices exist only between the pool helper's Prepare and
  Unprepare, so this set is complete without a ResourceSlice informer.
- D30 Pool ResourceSlice: `allNodes` (nil NodeSelector). The attachable
  node label of ../plan/10 4.1 is left out; a node that is not a pool host
  gets AttachFailed, which is correct and visible. Label support is an
  optional later feature.
- D31 Names: driver `cxl-pool.generic`; conditions `cxl-pool.generic/Attached`,
  `cxl-pool.generic/AttachFailed`; DeviceClasses `cxl-pool-memory`
  (exclusive) and `cxl-shared-memory` (shared); pool name = the server's
  identity, default `fake-cxl-pool`.
- D32 No `nodeAllocatableResources` on pool devices (alpha; the gate is off
  in the shared VMs, verified `kubernetes_feature_enabled{DRANodeAllocatableResources} 0`).
- D33 The pool helper keeps its own prepared-claims state (file
  `preparedPoolClaims.json`, CDI spec `cxl-pool`), separate from the
  cxl.generic state: a claim mixing both drivers gets one Prepare per
  driver and each helper prepares its own devices.

- D34 (found by the first e2e runs) memctl.CreateRegion must wait until the
  kmem probe has added all memory blocks of a ram region before it switches
  the dax driver or returns: the kernel binds the dax device to kmem by
  itself and the driver link appears before the blocks do (udev order:
  region add, dax add, memory blocks add, dax bind). Without the wait the
  first NodePrepare failed ("no memory blocks found" / daxctl ENOENT) and
  kubelet's retry cost ~85 s. Fixed in pkg/cxl/memctl with two unit tests.

## Environment facts (verified 2026-10-06)

- VMs running: n4-cxl-shared-1/2-fedora-43-containerd (patched qemu, FS_DAX
  kernel 7.3.0-rc4), n4-cxl-fedora-43-{containerd,crio}, others. Shared VMs:
  Kubernetes v1.37.1 single-node control planes, containerd 2.4.1, kubectl
  as root with /root/.kube/config, tools: udevadm, journalctl, numactl,
  python3, jq, cxl, daxctl. Feature gates (apiserver metrics):
  DRADeviceBindingConditions 1, DRAConsumableCapacity 1,
  DRAResourceClaimDeviceStatus 1, DRANodeAllocatableResources 0.
  /var/lib/kubelet/plugins is empty, /etc/cdi and /var/run/cdi do not exist
  (the driver creates them), NRI socket /var/run/nri/nri.sock. No busybox
  or python images cached in containerd yet.
- VM identity: product_uuid == VM_UUID (b6a78455-... for shared-1,
  1b6d55a2-... for shared-2); kubelet systemUUID matches.
- nri-plugins go.mod: k8s.io/{api,client-go,dynamic-resource-allocation}
  v0.34.11; resource/v1 has BindsToNode, BindingConditions,
  AllowMultipleAllocations, CapacityRequestPolicy, ShareID,
  ConsumedCapacity; resourceslice.Controller supports Owner == nil. No
  go.mod change needed for the controller.
- DRA driver repo: branch 5fC-cxl, clean tree, vendor/ is gitignored (not
  committed; `go mod vendor` must be rerun after nri-plugins changes), go 1.26,
  replace nri-plugins => github.com/askervin/nri-plugins afb1ef141d95 (an
  ancestor of nri-plugins HEAD on 5jQ-cxl). Build:
  `CGO_ENABLED=0 go build -mod vendor -o bin/kubelet-cxl-plugin ./cmd/kubelet-cxl-plugin`.
  Driver name cxl.generic; its PrepareResourceClaims skips results of
  other drivers/pools (node_state.go ~472). kubeletplugin.Start uses per
  driver socket paths, so two helpers in one process work (../plan/11 1.7).
- e2e: run_tests.sh enumerates TOPOLOGY_DIR/test* in name order and sources
  *.source.sh of suite, policy (memory-policy), topology and test dirs.
  pool.source.sh (n4-cxl-shared-2) has the VM1 helpers (pool-vm-command,
  pool-server-start, pool-cleanup EXIT trap, pool-assert...).
- Kubelet DRA gRPC timeout is 45 s: NodePrepare must finish well within it;
  the memdev is normally already in sysfs when NodePrepare runs.

## Resume notes
- Agent reports and findings go into the "Status"/"Findings" sections of
  20/30/40. Decisions that change the design are appended here as D34+.

## Final state 2026-10-06 (end of the session; nothing committed)

Verified by the orchestrator after the agents finished: `go test -race` of
nri-plugins pkg/cxl/... and scripts/testing/fake-cxl-pool/... passes, `make
lint` passes; in the driver repo `go mod vendor && go vet && go test -race
./cmd/kubelet-cxl-plugin/... ./pkg/cxl/...` passes and bin/kubelet-cxl-plugin
builds.

nri-plugins (branch 5jQ-cxl), working tree:
- pkg/cxl/memctl (moved from scripts/testing/fake-cxl-pool/pkg/guest, D25, D34)
- scripts/testing/fake-cxl-pool: cmd/fake-cxl-pool-controller, pkg/controller,
  deploy/fake-cxl-pool-controller.yaml, serial scheme in pkg/server + pkg/pool
  (D27), api.Attachment.Owner, Makefile, README, config.example.yaml
- test/e2e: memory.test-suite/memory-policy/dra.source.sh (install, kubectl
  helpers, dra-trace-*), n4-cxl-shared-2/test10-dra-pooling,
  n4-cxl-shared-2/test11-dra-sharing, serial scheme in both shared topologies,
  test00-up, test01-shared-cxl, lib/topology2qemuopts.py docstring
- plan-2-dra/ (this directory)

intel-resource-drivers-for-kubernetes (branch 5fC-cxl), working tree:
- cmd/kubelet-cxl-plugin/pool.go, pool_test.go, main.go (flags), driver.go
  (second helper, D29), node_state.go (skip pool regions), pkg/cxl/device
  constants, doc/cxl/POOL.md, deployments/cxl/pool/
- go.mod: `replace github.com/containers/nri-plugins => /home/akervine/github.com/containers/nri-plugins`
  (LOCAL PATH: push the nri-plugins changes to github.com/askervin/nri-plugins
  and pin that commit before merging; vendor/ is gitignored, rerun
  `go mod vendor`)

Run: `cd test/e2e && ./run_tests.sh memory.test-suite/memory-policy/n4-cxl-shared-2/test10-dra-pooling`
(then test11-dra-sharing). Output incl. trace.txt and trace-summary.txt under
test/e2e/n4-cxl-shared-2-fedora-43-containerd/memory.test-suite/memory-policy/<test>/.
Reference logs and traces of the passing runs: ~/.claude/jobs/ws-c/.

Left open:
- test00-up of n4-cxl-shared-1/-2 fails on the current VMs (created with the
  old static serial 0xc1f0ee00) until they are recreated; test01/10/11 do
  not depend on it.
- test12-test20 (50-realistic-tests.md) are planned, not implemented.
- The driver container image has no cxl/daxctl (doc/cxl/POOL.md); e2e runs
  the driver as a host process (D26).
- plan/20-rest-api.md does not yet list Attachment.owner.
- journalctl -f streams reach the trace 100-300 ms after the event (seen as
  controller lines after the claim status they caused); the summary header
  says "a few ms", which understates it for journal sources.
