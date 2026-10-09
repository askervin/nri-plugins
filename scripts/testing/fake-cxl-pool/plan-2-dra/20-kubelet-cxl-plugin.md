# WS-A: kubelet-cxl-plugin pool helper + pkg/cxl/memctl

Status: spec written 2026-10-06 (Fable). Owner: Opus agent A.
Repositories: ~/github.com/intel/intel-resource-drivers-for-kubernetes (branch
5fC-cxl, clean) and ~/github.com/containers/nri-plugins (branch 5jQ-cxl).
Contract to implement: 10-contract.md section 6 (plus doc, section 3 YAML).
Read first: 00-overview.md (decisions D20-D33), 10-contract.md,
../plan/10-design-pooling-dra.md 4.4, the driver sources
cmd/kubelet-cxl-plugin/{main,driver,node_state,nri,udev}.go, and
scripts/testing/fake-cxl-pool/pkg/guest/guest.go.

Do not run anything in the VMs except the short smoke test in step 7, and
clean it up: agents B and C work on the same VMs.

## 1. nri-plugins: move pkg/guest to pkg/cxl/memctl (D25)

- `git mv scripts/testing/fake-cxl-pool/pkg/guest pkg/cxl/memctl`, package
  `memctl`, type `Guest` -> `Manager` (`memctl.New()` returns `*Manager`),
  package doc: "Package memctl makes hotplugged CXL memory devices usable
  and releases them again: find a memdev by serial, create a region in
  devdax or system-ram mode, online or offline its memory, destroy the
  region and disable the memdev. It drives sysfs and the cxl and daxctl
  CLIs." Keep the API otherwise (Memdevs, FindMemdev, WaitMemdev,
  RootDecoder, DaxDevices, DaxDriver, TargetNode, RegionBlocks,
  SetBlocksState, SetDaxDriver, Info, CreateRegion, Online, Release,
  RegionInfo, ModeDevDax/ModeRAM, DriverDeviceDax/DriverKmem, ErrNotFound).
- Online/SetBlocksState: skip blocks already in the requested state
  (writing "online_movable" to an online block fails with EINVAL).
- Add `func (m *Manager) DaxDevNumbers(dax string) (major, minor int, err error)`
  reading /sys/bus/dax/devices/<dax>/dev ("major:minor").
- Update imports in scripts/testing/fake-cxl-pool/cmd/fake-cxl-pool-client,
  README.md Layout section ("pkg/guest" -> "pkg/cxl/memctl in nri-plugins").
  `make -C scripts/testing/fake-cxl-pool test lint` and
  `go test ./pkg/cxl/...` pass.

## 2. DRA repository: use the local nri-plugins

go.mod: `replace github.com/containers/nri-plugins => /home/akervine/github.com/containers/nri-plugins`,
then `go mod tidy && go mod vendor` (vendor/ is committed; big diff is
expected). Note in Status that the replace must be changed back to a
pushed commit of github.com/askervin/nri-plugins before merging. Build:
`CGO_ENABLED=0 go build -mod vendor -o bin/kubelet-cxl-plugin ./cmd/kubelet-cxl-plugin`.
If newer nri-plugins packages (pkg/cxl, cgmpolmgr) break the build, fix the
driver to the new API (the fork commit is an ancestor of HEAD, so changes are
the user's own).

## 3. Pool helper (cmd/kubelet-cxl-plugin/pool.go, new)

```go
type poolDriver struct {
    name       string                 // cxl-pool.generic
    helper     *kubeletplugin.Helper
    mem        *memctl.Manager
    cdi        *cdiapi.Cache          // the shared default cache
    stateFile  string                 // <plugin data dir>/preparedPoolClaims.json
    timeout    time.Duration
    mu         sync.Mutex
    prepared   map[string]*preparedPoolClaim   // claim uid -> ...
}
type preparedPoolDevice struct {
    Request, Device, Pool string
    Serial uint64; SerialHex string; Shared bool; Size uint64
    Memdev, Region, Dax string; Node int
    CDIDeviceID string
}
type preparedPoolClaim struct {
    ClaimName string; Devices []preparedPoolDevice
    Result kubeletplugin.PrepareResult  // what Prepare returned
}
func (p *poolDriver) PrepareResourceClaims(ctx, claims) (map[types.UID]kubeletplugin.PrepareResult, error)
func (p *poolDriver) UnprepareResourceClaims(ctx, claims) (map[types.UID]error, error)
func (p *poolDriver) HandleError(ctx, err, msg)          // log like driver.HandleError
func (p *poolDriver) WatchHealthStatus(...) error         // ErrHealthNotSupported
func (p *poolDriver) Serials() map[uint64]bool            // for D29
```

- Data parsing: `poolDeviceData{Serial string; Shared bool; Size uint64}`
  from `claim.Status.Devices[i].Data.Raw` (JSON; serial "0x..." or decimal
  via strconv.ParseUint with base 0). Match the status entry by driver,
  pool, device.
- Prepare per result exactly as 10-contract.md section 6 steps 1-5. Exclusive:
  `CreateRegion(ctx, memdev, memctl.ModeRAM, "")` then `Online(memdev, true)`;
  node = RegionInfo.Node (TargetNode of the dax device; if < 0, read
  /sys/bus/cxl/devices/<region>/.. via nricxl or the dax target_node after
  onlining). Shared: `CreateRegion(ctx, memdev, memctl.ModeDevDax, "")`,
  device node path RegionInfo.Device, major/minor via DaxDevNumbers.
- CDI: one spec file `cxl-pool` (name passed to CdiCache.WriteSpec), kind
  `generic/cxl`, device name `pool-<serialhex>`, ContainerEdits.Env and,
  for shared, DeviceNodes [{Path, Type: "c", Major, Minor}]. Rebuild the
  spec from the prepared map on every change (same approach as
  buildClaimMarkerSpec), remove the spec when empty. The CDI device ID
  returned is `generic/cxl=pool-<serialhex>`. Do NOT add the CXL_CLAIM_
  marker (D24: no NRI steering for pool devices).
- Errors: return PrepareResult{Err} for that claim; partial preparation of a
  claim is rolled back (release what this Prepare created, unless another
  prepared claim uses the serial).
- Unprepare: refcount by serial over the prepared map; last user ->
  `mem.Release(ctx, memdev)` where memdev is looked up by serial (gone ->
  fine). Unknown claim uid -> nil.
- Persist after every change (0600, MarshalIndent). Load at start; a device
  whose memdev is gone stays in the map until Unprepare (log it).

## 4. Wire it in

- main.go: flags `--pool-driver-name` (env POOL_DRIVER_NAME, default
  "cxl-pool.generic") and `--pool-prepare-timeout` (env POOL_PREPARE_TIMEOUT,
  default "30s") in CXLFlags.
- driver.go newDriver: after the cxl.generic helper starts, if the pool
  driver name is not empty: create poolDriver (plugin data dir
  `filepath.Join(filepath.Dir(config.CommonFlags.KubeletPluginDir), poolName)`,
  MkdirAll), `kubeletplugin.Start(ctx, poolDriver, KubeClient, NodeName,
  DriverName(poolName), RegistrarDirectoryPath(same registry dir),
  PluginDataDirectoryPath(that dir))`. Store in driver.pool; Shutdown stops
  it. Log "pool helper registered as <name>".
- D29: scanDevices/buildDevInfos get the pool serial set (driver.pool.Serials(),
  nil when disabled) and skip regions whose memdev serial is in it with
  ignoreReason "pool device (cxl-pool.generic)". The udev rescan path uses
  the same function, so no extra work there.
- pkg/cxl/device/device.go: `PoolDriverName = "cxl-pool.generic"`,
  `DeviceTypeCXLPool = "cxl-pool"`, `PoolCDISpecName = "cxl-pool"`.

## 5. Unit tests (cmd/kubelet-cxl-plugin/pool_test.go)

Use a temp dir as SysRoot with a fake sysfs tree (mem0/serial, dax
devices, memory blocks) and a fake Exec/LookPath in memctl.Manager, like
pkg/cxl/memctl's own tests. Cover: data parsing (hex, decimal, missing
entry, wrong device); exclusive Prepare builds env + node and persists;
shared Prepare builds device node with major/minor; second claim on the
same serial reuses the region and Unprepare of one keeps the device,
Unprepare of both releases; restart (new poolDriver on the same state
file) returns the stored result for a prepared claim; buildDevInfos skips
a region whose memdev serial is in the pool set. `go test ./cmd/kubelet-cxl-plugin/... ./pkg/cxl/...`
and `go vet` pass.

## 6. Docs and manifests (driver repository)

- doc/cxl/POOL.md: 10-contract.md rewritten for an external reader (what a
  pool controller must publish and write, what the node plugin does, node
  requirements, the force-delete hazard, the fake-cxl-pool-controller in
  nri-plugins/scripts/testing/fake-cxl-pool as a reference implementation).
  Link it from doc/cxl/README.md.
- deployments/cxl/pool/device-classes.yaml (section 3 of the contract),
  deployments/cxl/pool/examples/{pooled-memory-pod.yaml,shared-memory-pod.yaml}
  (claim + pod; the pooled pod prints its CXL_POOL_* env and
  /sys/devices/system/node/node*/meminfo MemTotal; the shared pod image
  python:3-alpine mmaps the dax device, see 40-e2e-tests.md for the
  script).
- doc/cxl/POOL.md notes that the container image of the driver would need
  cxl and daxctl (not added now; the e2e runs the driver as a host process).

## 7. Smoke test in VM2 (n4-cxl-shared-2-fedora-43-containerd) and cleanup

ssh: `ssh -F ~/github.com/containers/nri-plugins/test/e2e/n4-cxl-shared-2-fedora-43-containerd/.ssh-config node sudo bash -l`.
Copy bin/kubelet-cxl-plugin to /usr/local/bin in the VM, run
`systemd-run --unit kubelet-cxl-plugin-smoke -E NODE_NAME=$(hostname) -E KUBECONFIG=/root/.kube/config /usr/local/bin/kubelet-cxl-plugin --node-name $(hostname) -c '{}' -v 4`,
check `journalctl -u kubelet-cxl-plugin-smoke`, that
/var/lib/kubelet/plugins/cxl.generic/dra.sock and
/var/lib/kubelet/plugins/cxl-pool.generic/dra.sock exist, that
`kubectl get resourceslices` shows the node's cxl.generic slice (dram
device), and that kubelet logged no plugin registration errors
(`journalctl -u kubelet --since -2min | grep -i dra`). Then
`systemctl stop kubelet-cxl-plugin-smoke; systemctl reset-failed`, and
`kubectl get resourceslices` must be empty again (kubelet wipes the node
slices of an unregistered driver; if not, delete them). Leave the binary
in /usr/local/bin (C overwrites it). No claims, no pods, no pool devices.

## 8. Report

Append "Status" and "Findings" here: files changed in both repos, test
results, smoke test output excerpts, anything that deviates from
10-contract.md (and add it to its Deviations section), open problems.

## Status

Done 2026-10-06 (Opus agent A): sections 1-7. Nothing committed.

nri-plugins (branch 5jQ-cxl):
- `git mv scripts/testing/fake-cxl-pool/pkg/guest pkg/cxl/memctl`, files
  renamed to memctl.go / memctl_test.go (staged as renames). Package
  `memctl`, `Guest` -> `Manager`, receiver `mc`, package doc as specified.
  New `DaxDevNumbers(dax)` (+ test). SetBlocksState already skipped blocks
  that are in the requested state (and checks the zone for
  online_movable); no change needed there.
- scripts/testing/fake-cxl-pool/cmd/fake-cxl-pool-client/main.go: import
  pkg/cxl/memctl, `*memctl.Manager`.
- scripts/testing/fake-cxl-pool/README.md: the Layout line only.
- Tests: `go vet` + `go test -race ./pkg/cxl/... ./scripts/testing/fake-cxl-pool/cmd/fake-cxl-pool-client/...`
  ok; `make -C scripts/testing/fake-cxl-pool lint test` ok (run once, with
  agent B's tree as it was at that moment).

intel-resource-drivers-for-kubernetes (branch 5fC-cxl):
- go.mod: `replace github.com/containers/nri-plugins => /home/akervine/github.com/containers/nri-plugins`
  (go.sum: 2 lines less). **Before merging, change the replace back to a
  pushed commit of github.com/askervin/nri-plugins** (that has pkg/cxl/memctl)
  and re-run `go mod tidy && go mod vendor`.
- cmd/kubelet-cxl-plugin/pool.go (new): poolDriver as specified.
- cmd/kubelet-cxl-plugin/pool_test.go (new): fake sysfs + fake cxl/daxctl.
  Tests: TestPoolDeviceData (hex, decimal, upper-case hex, missing fields,
  bad serial), TestPoolDataFor (match, wrong device, no entry, no data),
  TestPoolPrepareExclusive (region, online_movable, CDI env, state file
  0600, Unprepare release commands, re-prepare enables the disabled memdev),
  TestPoolPrepareSharedTwoClaims (device_dax, CDI device node 251:3, second
  claim reuses the region, shared/exclusive conflict, first Unprepare keeps,
  second releases), TestPoolRestart (stored result, no commands, CDI spec
  rewritten, gone memdev kept until Unprepare), TestPoolPrepareErrors
  (no entry, memdev timeout, rollback of a partially prepared claim),
  TestBuildDevInfosSkipsPoolDevices (pool region skipped, its node not
  counted as DRAM).
- cmd/kubelet-cxl-plugin/main.go: `--pool-driver-name` (POOL_DRIVER_NAME,
  default cxl-pool.generic), `--pool-prepare-timeout` (POOL_PREPARE_TIMEOUT,
  default 30s, a DurationFlag).
- cmd/kubelet-cxl-plugin/driver.go: newPoolHelper (state loaded before the
  first scan), startPoolHelper (after cxl.generic: rewrites the CDI spec,
  kubeletplugin.Start with DriverName/RegistrarDirectoryPath/PluginDataDirectoryPath
  `<plugins>/cxl-pool.generic`), driver.pool, Shutdown stops it,
  scanDevices(..., poolSerials) also on the udev rescan path.
- cmd/kubelet-cxl-plugin/node_state.go: buildDevInfos(..., poolSerials),
  poolIgnoreReason: "pool device (cxl-pool.generic), memory device serial 0x...".
- cmd/kubelet-cxl-plugin/driver_test.go: new buildDevInfos argument.
- pkg/cxl/device/device.go: PoolDriverName, DeviceTypeCXLPool, PoolCDISpecName.
- doc/cxl/POOL.md (new), doc/cxl/README.md (link).
- deployments/cxl/pool/device-classes.yaml,
  deployments/cxl/pool/examples/{pooled-memory-pod.yaml,shared-memory-pod.yaml}
  (the shared pod has an inline python mmap writer/reader; it finds the
  device from the CXL_SHARED_DAX_* env, so it works for any serial).
- Build `CGO_ENABLED=0 go build -mod vendor -o bin/kubelet-cxl-plugin ./cmd/kubelet-cxl-plugin`
  ok (sha256 4b317380...f69f, installed in VM2 /usr/local/bin).
  `go vet` and `go test -race -count=1 ./cmd/kubelet-cxl-plugin/... ./pkg/cxl/...` ok.

Choices where the spec left room:
- preparedPoolDevice has extra fields DaxDevice, DaxMajor, DaxMinor; the
  CDI spec is rebuilt from the state alone.
- poolDeviceData uses `*bool`/`*uint64` so that missing shared/size are
  errors (contract: REQUIRED).
- Serials() is a snapshot under its own mutex, including inflight serials;
  a rescan never waits for a Prepare that waits for udev.
- Node fallback when the dax target_node is < 0: the `nodeN` link of the
  region's memory blocks.
- The state file is written via tmp + rename.
- The memdev wait: a memdev that is already present gets 2 s to have a
  driver (then CreateRegion enables it); otherwise WaitMemdev with the
  prepare timeout. CreateRegion/Online/Release use the kubelet request
  context (45 s gRPC deadline).

## Findings

- Smoke test (VM2, 12:02-12:05 UTC) turned into an end-to-end test: agent B
  ran its controller smoke test (unit fcp-controller-smoke, claim
  default/pooled-memory, pod fcp-smoke) at the same time, and kubelet sent
  its NodePrepare to my plugin. Excerpts:
  ```
  pool.go:161] pool helper registered as cxl-pool.generic
  nonblockinggrpcserver.go:90] "GRPC server started" logger="dra" endpoint="/var/lib/kubelet/plugins/cxl-pool.generic/dra.sock"
  ... endpoint="/var/lib/kubelet/plugins_registry/cxl-pool.generic-reg.sock"
  12:02:42.329929 memctl: mem0: created region0 under decoder0.0
  12:02:42.419071 memctl: dax0.0: bound to kmem
  12:02:42.455204 memctl: memory202: online_movable   (... memory205)
  12:02:42.469086 pool.go:267] cxl-pool.generic: claim default/pooled-memory: prepared pooled0 (serial 0xc1ee0001, shared false) as mem0 region0 dax dax0.0 node 2
  12:02:42.679253 node_state.go:213] - ignoring region device "region0": pool device (cxl-pool.generic), memory device serial 0xc1ee0001
  12:04:04.385735 memctl: memory202: offline   (... memory205)
  12:04:04.585874 memctl: mem0: destroyed region0
  12:04:04.597664 memctl: mem0: disabled
  12:04:04.597734 pool.go:472] cxl-pool.generic: unprepared claim default/pooled-memory (6fdcf97b-...)
  ```
  /etc/cdi/cxl-pool.yaml had device pool-c1ee0001 with
  CXL_POOL_NODE_C1EE0001=2, CXL_POOL_SIZE_C1EE0001=536870912,
  CXL_POOL_SERIAL_C1EE0001=0xc1ee0001, and `kubectl logs fcp-smoke` printed
  exactly these three. D29 worked: the udev rescan after onlining skipped
  region0 and the cxl.generic slice kept only `dram`. After B deleted its
  pod/claim the memdev was gone from the VM, preparedPoolClaims.json `{}`,
  cxl-pool.yaml removed. Both dra.sock files and both -reg.sock files
  existed; `kubectl get resourceslices` showed the node's cxl.generic slice
  with device `dram`. No kubelet DRA registration errors. I waited for B's
  claim to be gone before stopping my unit (stopping earlier would have
  left B's pool device unreleasable). After `systemctl stop
  kubelet-cxl-plugin-smoke; systemctl reset-failed`, kubelet removed the
  sockets and, within ~45 s, the cxl.generic slice: `No resources found`.
  Left in VM2: /usr/local/bin/kubelet-cxl-plugin, the empty state files in
  /var/lib/kubelet/plugins/{cxl.generic,cxl-pool.generic}/, and
  /etc/cdi/generic-cxl.yaml (written by cxl.generic at every start).
- The cxl.generic publisher logs "some fields were dropped by the
  apiserver" at every publish: nodeAllocatableResources with the
  DRANodeAllocatableResources gate off (D32). Pre-existing, harmless noise;
  it is not the pool helper (which publishes nothing).
- The kubelet calls WatchHealthStatus on both plugins and logs
  "device health reporting is not supported" (Unimplemented) once per
  plugin; expected.
- vendor/ is in .gitignore of the driver repository (not committed, unlike
  00-overview.md says), so the go.mod/go.sum replace is the whole diff;
  `go mod vendor` must be re-run after every nri-plugins change that the
  driver uses (pkg/cxl/memctl, pkg/cxl).
- newNodeState (cdihelpers.AddDetectedDevicesToCDIRegistry) deletes every
  generic/cxl CDI spec at startup, including cxl-pool.yaml and
  cxl-claims.yaml. The pool helper therefore rewrites its spec in start();
  a restart with prepared pool claims keeps working.
- golangci-lint (repo config) on ./cmd/kubelet-cxl-plugin/... ./pkg/cxl/...:
  pre-existing issues only (cyclop buildDevInfos 28, TestPreparedClaimsInfo_Persistence 16,
  unused containerDevfsRoot), plus newDriver cyclop 18 (was 16 before,
  already over 15). The pool code itself is clean.
- The pool helper, like the existing driver, is not stopped if newDriver
  fails after it started; harmless for a process that then exits.

Open problems:
- The replace in go.mod points at the local checkout (see Status).
- The DaemonSet image has no cxl/daxctl; documented in POOL.md, the e2e
  runs the driver as a host process (D26).
- A shared device that is mapped by a running container when its last
  claim is unprepared: Release only offlines kmem memory, so for devdax it
  goes straight to `cxl disable-region`, which the kernel refuses while
  the dax device is mapped (error, kubelet retries). Not seen in tests;
  normally the container is gone before NodeUnprepare.

## Fixed by C (2026-10-06, e2e phase 2)

- pkg/cxl/memctl/memctl.go (nri-plugins), CreateRegion: wait until every
  memory block of the region exists (new waitRegionBlocks; regionBlocks
  also returns the expected count) whenever the dax device is bound to
  kmem, before switching it to device_dax or returning for Online. The
  kernel binds a ram region's dax device to kmem by itself and creates the
  driver link before dev_dax_kmem_probe has added the memory, so the first
  NodePrepare failed: exclusive with "no memory blocks found for region0"
  (test10), shared with "daxctl reconfigure-device: No such file or
  directory" (test11, VM2); kubelet retried after ~85 s. Unit tests
  TestRegionRAMWaitsForBlocks and TestRegionDevDaxWaitsForKmemProbe in
  memctl_test.go. The driver picks it up with `go mod vendor` (replace to
  the local checkout); no driver source change. Details: 40-e2e-tests.md
  "Findings (phase 2)" 1-2.
