# WS5: fake-cxl-pool server and client implementation

Status: DONE 2026-10-02 agent C; review fixes (plan/51) done, see Findings. Server, client library + CLI (incl. guest commands),
tests (63 pass), README, config.example.yaml; live-verified on n4-cxl-fedora-43-containerd
(stock, HMP) and n4-cxl-shared-1/2 (patched, QMP+HMP). See Findings; deviations in 20-rest-api.md. Agent C: append "Findings"/"Status". API spec: 20-rest-api.md (authoritative; if you must
deviate, record the deviation there under a "Deviations" heading).

## Layout (inside module github.com/containers/nri-plugins)
scripts/testing/fake-cxl-pool/
  README.md                         usage, config, architecture, API summary
  Makefile                          build: bin/fake-cxl-pool-server bin/fake-cxl-pool-client; test; lint (go vet)
  config.example.yaml
  cmd/fake-cxl-pool-server/main.go  flags: -config FILE, -listen ADDR (overrides), -v
  cmd/fake-cxl-pool-client/main.go  CLI from 20-rest-api.md
  pkg/api/                          JSON types + route path constants shared by server and client
  pkg/client/                       Go client library: New(url), Status(), Hosts(), Resolve(), Devices(), CreateDevice(), Attach(), Detach(), ... (context aware)
  pkg/server/                       http handlers (net/http, Go 1.22+ pattern routing), state, attach/detach state machine, persistence of state to a JSON file (statefile in config, default next to pool dir) so restarts keep attachments
  pkg/qemu/                         Monitor interface { ObjectAdd, ObjectDel, DeviceAdd, DeviceDel, WaitDeviceDeleted, QueryMemdevs, QueryTree(slots), Version }; qmp.go (JSON, capabilities handshake, event demux), hmp.go (text protocol, as test/e2e/lib/vm.bash vm-monitor does: connect, send line, read until "(qemu)" prompt, strip \r and the readline echo garbage), discovery.go (scan /proc/[0-9]*/cmdline for qemu-system-*; parse -drive .vagrant/machines/<name>/, -qmp unix:PATH, -monitor unix:PATH, -chardev socket,id=X,path=P + -mon chardev=X, -object memory-backend-*, -device cxl-*, -M cxl-fmw.*; relative paths resolve against /proc/PID/cwd), fake.go (in-memory fake monitor for unit tests)
  pkg/pool/                         pools and backing files: create/truncate <dir>/<name>.raw of size, capacity accounting, serial allocation
Use only stdlib + sigs.k8s.io/yaml (already in go.mod). No new deps. Keep
`go vet ./...` and `go build ./...` clean from the repo root (the directory is
part of the main module). gofmt everything.

## Behaviour details
- Slot discovery: parse `info qtree -b` (HMP text, also reachable over QMP via
  human-monitor-command) to find buses of cxl-downstream and cxl-rp devices and
  the cxl-type3 children. Agent A (30-qemu-shared-backend.md Q7) may find a
  native QMP way; until then implement the qtree parser (robust to the
  indentation format, see vm-cxl-hw in test/e2e/lib/vm.bash for the awk
  patterns) and keep the Monitor interface so it can be swapped.
- Attach: choose slot (request.slot, else first free slot, prefer numaNode);
  qemuObjectId = "fcp_<device>" (pool devices; object-add
  memory-backend-file share=true mem-path=path size=bytes), or the existing
  beram_* id for local devices; qemuDeviceId = "fcp_<device>.hp<N>" with a
  per-host monotonically increasing N persisted in state (qemu refuses reuse
  of a device id, see vm-cxl-hotplug). sn = serial (check how QMP wants it:
  agent A Q2; HMP accepts "sn=0x..."). Guest sees the serial.
- Detach: device_del; QMP: wait for DEVICE_DELETED with matching device id
  (events arrive on the same QMP connection: keep one long-lived connection
  per host with a reader goroutine demuxing responses and events); HMP: poll
  `info qtree -b` every 500ms until the device id is gone. Then object-del
  (pool devices only). Timeout -> keep attachment in "detaching", return 409,
  continue waiting in the background (max 1h) and finalize when it completes.
- Local devices (beram_cxl_memdevN__bus_B__sn_S): discovered per host from
  qemu -object args/query-memdev; attach only to that host, to bus B, with
  serial S; never object-add/del them. This makes the server useful for the
  existing n4-cxl VM over HMP.
- Host identity: Host.name from .vagrant/machines/<name>/ in the -drive path;
  config hosts override/add. /hosts/resolve matches name == hostname, or
  name == first label of hostname.
- Persistence: state file with devices (dynamic ones), allocations,
  attachments, hotplug counters. On start, reconcile with qemu (query the
  qtree: attachments whose device id is gone become detached; hosts whose pid
  is gone become stopped).
- Logging: log every qemu command and its result at -v; default logs attach/
  detach lifecycle lines.
- Concurrency: one mutex per host for monitor operations; server-wide RW
  mutex for state.

## Tests
- go test ./scripts/testing/fake-cxl-pool/...: unit tests with the fake monitor
  for the attach/detach state machine, shared vs exclusive rules, idempotency,
  allocation ownership, slot selection, qtree parser (use a real `info qtree
  -b` dump: capture one from the live VM with
  `cd test/e2e/n4-cxl-fedora-43-containerd && echo 'info qtree -b' | socat STDIO unix-connect:monitor.sock | sed 's/\r//g'`
  and also `info memdev`), discovery cmdline parser (use the real cmdline of
  pid $(pgrep -f n4-cxl-fedora-43-containerd) from /proc), HTTP handlers via
  httptest with the client library.
- Live smoke test (only when the VM n4-cxl-fedora-43-containerd is running and
  no run_tests.sh is running; agent A may halt it briefly early on, check
  `cd test/e2e/n4-cxl-fedora-43-containerd && vagrant status`): start the server
  with discovery on, `fake-cxl-pool-client hosts` must show the VM with its
  local devices and free slots; attach a free local device (one that is not
  plugged; `info qtree -b` shows which are) to it, check in the guest
  (ssh -F test/e2e/n4-cxl-fedora-43-containerd/.ssh-config vagrant@node
  'ls /sys/bus/cxl/devices/') that a new memN appeared with the serial, then
  detach after `sudo cxl disable-memdev memN` in the guest (device must be
  released, otherwise detach times out - that is expected behaviour, test it
  too: detach without release -> 409 after a short --timeout, then release,
  then the attachment finalizes). Leave the VM as you found it (the device
  cxl_memdev2.hp3 that is plugged now stays plugged).
  Note stock qemu 11.1.1 runs that VM: after a detach the same local device
  cannot be re-attached until qemu restarts; do not try.

## Deliverables
- Code + tests + README; `make -C scripts/testing/fake-cxl-pool` builds both binaries into scripts/testing/fake-cxl-pool/bin/.
- Findings here: what was verified live (commands + outputs), open issues,
  deviations from the API spec.

## Findings
(agent C appends here)

### Live check against n4-cxl-shared-1/2 (patched qemu 11.1.50, QMP), 2026-10-02 17:12-17:14
Server: `bin/fake-cxl-pool-server -config $W/shared.yaml -v` (W=/home/akervine/.claude/jobs/5b6674cf/tmp/ws5,
pool dir /tmp/fake-cxl-pool-ws5, `discovery.names: ["n4-cxl-shared-*"]`); log $W/server-shared.log.
- `hosts`: both running, control qmp on <outdir>/qmp.sock (qmp-e2e.sock skipped), qemu
  "11.1.50 v11.1.0-1741-gff076b1e6c", uuid b6a78455-... / 1b6d55a2-..., FREE-SLOTS 6/8
  (cxlsw_ds2/ds3_usrp0hb0 reservedFor static-shared0 / <vm>.memdev1), fmw 8G per host bridge.
- devices: static-shared0 (befile_, scope local, shared, localHosts both VMs, sn 0xc1f0ee00),
  <vm>.memdev1 (beram_, 0xc100e2e1) per VM.
- `create --size 256M --shared --name live-shared0` -> serial 0xc1f00001, file
  /tmp/fake-cxl-pool-ws5/live-shared0.raw; `attach live-shared0 --host <vm>` for both: 201 in
  ~60 ms, slot cxlsw_ds0_usrp0hb0, qemu ids fcp_live-shared0.hp1 (object and device).
- In each guest (client scp'd to /usr/local/bin, default URL http://192.168.76.2:9909 works
  from the VM): `guest wait live-shared0` -> mem0; /sys/bus/cxl/devices/mem0/serial = 0xc1f00001
  in BOTH guests; `whoami` resolves the VM (no DMI in the guest: uuid from /etc/machine-id).
- shared-1: `sudo fake-cxl-pool-client guest region create live-shared0 --mode devdax` ->
  region0 under decoder0.0 (auto: host bridge uid 12 from pci0000:0c), dax0.0 bound to
  device_dax (daxctl), /dev/dax0.0, node 2.
- shared-2: `guest region create --mode ram` -> kmem, blocks memory202..203 offline;
  `guest online --movable` -> online_movable, `numactl -H`: node 2 size 256 MB.
- `guest release live-shared0` in both (offline blocks, disable+destroy region0, disable-memdev).
- `detach live-shared0 --host <vm>`: 6.53 s / 6.21 s, server log shows
  `event DEVICE_DELETED {"device": "fcp_live-shared0.hp1", ...}` then `object-del ... {}`.
- Re-attach to shared-1 with `--numa 1` -> cxlsw_ds0_usrp0hb1, fcp_live-shared0.hp2, guest mem0
  serial 0xc1f00001 again; release; detach 6.13 s; `delete live-shared0` -> file removed.
- Guests back to their baseline except decoder2.0 (the host bridge decoder the kernel creates
  at the first hotplug).

### Live smoke test on n4-cxl-fedora-43-containerd (stock qemu 11.1.1, HMP only), 2026-10-02 17:25-17:27
Baseline (after agent A restarted the VM at 16:35): no cxl-type3 plugged (`info qtree -b`), guest
/sys/bus/cxl/devices = decoder0.0 decoder0.1 nvdimm-bridge0 port1 port2 root0, no -uuid on the
cmdline, no /sys/class/dmi in the guest. (Before the restart memdev0.hp1, memdev1.hp2,
memdev2.hp3 were plugged; agent A's restart cleared them.)
Server: `bin/fake-cxl-pool-server -config $W/n4.yaml -v` (`discovery.names: [n4-cxl-fedora-43-containerd]`),
log $W/server-n4.log.
- Discovery: control hmp on <outdir>/monitor.sock (qemu cwd is "/", resolved via the vagrant
  project dir), 10 local devices <vm>.memdev0..9 (beram_*), all 10 slots reservedFor them
  (FREE-SLOTS 0/10), fmw 4G per host bridge via HMP `qom-get /machine cxl-fmw`, and
  `qom-get .../cxlsw_ds7_usrp0hb1 power_controller_present` -> "Error: Property
  'cxl-downstream.power_controller_present' not found" -> hotRemoveCapable=false, WARNING logged.
- In the guest: `fake-cxl-pool-client attach n4-cxl-fedora-43-containerd.memdev9 --self`
  (resolved by hostname; HMP `device_add cxl-type3,bus=cxlsw_ds7_usrp0hb1,volatile-memdev=beram_cxl_memdev9__bus_cxlsw_ds7_usrp0hb1__sn_0xc100e2e9,id=fcp_n4-cxl-fedora-43-containerd.memdev9.hp1,sn=0xc100e2e9`)
  -> attached; `guest wait` -> mem0, /sys/bus/cxl/devices/mem0/serial = 0xc100e2e9.
- `guest region create --mode devdax` (no daxctl in this VM: sysfs path) -> region1 under
  decoder0.1 (host bridge uid 24), dax1.0 kmem -> unbind -> device_dax new_id, /dev/dax1.0;
  `guest release`; `guest region create --mode ram` -> kmem (found device_dax first because of
  the leftover new_id: fixed afterwards with remove_id), `guest online --movable` ->
  memory330..331 online_movable, `numactl -H`: node 3 size 256 MB; `guest release` (offline,
  disable/destroy region1, disable-memdev).
- `detach ... --self`: guest `pci 0000:22:00.0: device released` after ~5 s, but stock qemu keeps
  `fcp_...memdev9.hp1` in the qtree forever -> after 15 s: HTTP 409, CLI exit 3, attachment
  "failed", device state "error". `detach --force` forgot the record.
- BUG found and fixed: the next reconcile re-adopted the zombie as "attached" (it is still in
  the qtree). Now the server remembers, per qemu instance and persisted, the device ids it sent
  device_del for, and never adopts them (TestZombieNotAdopted). The timeout error text for stock
  qemu now says that qemu (not the guest) cannot complete the hot-remove.
- Left in the VM: the zombie device fcp_n4-cxl-fedora-43-containerd.memdev9.hp1 on
  cxlsw_ds7_usrp0hb1 (unavoidable with stock qemu; slot and beram_cxl_memdev9 unusable until the
  VM restarts; test01-pkg-cxl uses memdev0..2 only). The guest is clean (only decoder1.0, the host
  bridge decoder, added). Client binary left in /usr/local/bin of the VM.

### Live check against the RECREATED n4-cxl-shared-1/2 (FS_DAX/DMI kernel, hdm_for_passthrough=on), 2026-10-02 17:38-17:41
Logs: $W/server-shared2.log (QMP on both), $W/server-shared-hmp.log (shared-2 with `control: hmp`).
- QMP hosts now use the QOM tree (qom-list /machine/peripheral + parent_bus/sn/volatile-memdev/
  numa_node; no "info qtree" fallback in the log): 8 slots, NUMA 0/1, fmw 8G from
  `qom-get /machine cxl-fmw`, hotRemoveCapable=true (power_controller_present).
- Guests now have /sys/class/dmi/id/product_uuid = the qemu -uuid; `whoami` resolves by uuid.
- devdax sharing end to end: `create --size 256M --shared --name live-shared1`, attach to both
  (`--numa 1` -> cxlsw_ds0_usrp0hb1), in both `guest wait` + `guest region create --mode devdax`
  (region1/dax1.0, node 3). proto/guest-dax-rw.py: A writes FROM-WS5-A@0,1,100,255M, B reads all
  four; B writes @1M,@255M, A reads `FROM-WS5-B@255M`; host file at 255M holds FROM-WS5-B.
  HMP `info mtree` (read-only on monitor.sock) shows
  `alias cxl-direct-mapping-alias-0 @fcp_live-shared1.hp1 0000000000000000-000000000fffffff`,
  the exact format BackendMappedIn matches (leak detection).
- release + detach both: 6.19 s / 6.24 s, DEVICE_DELETED + object-del.
- Late completion: attach (no release, memdev enabled, no region), `detach --timeout 2s` -> 409,
  exit 3, attachment "failed"; qemu DEVICE_DELETED at ~6 s; the background check finalized it at
  7.3 s (object-del, device free).
- HMP on the patched build (shared-2 `control: hmp`): `object_add memory-backend-file,id=fcp_live-shared1.hp2,size=268435456,share=on,mem-path=/tmp/fake-cxl-pool-ws5/live-shared1.raw`
  and `device_add cxl-type3,bus=cxlsw_ds0_usrp0hb0,...,sn=0xc1f00001` OK; ram region + online
  movable (node 2 256 MB); release; detach 6.58 s (qtree polling), mtree check, `object_del` OK.
- Static befile_ device: `attach static-shared0` to shared-1 (QMP) and shared-2 (HMP) reuses
  befile_cxl_memdev0__bus_cxlsw_ds2_usrp0hb0__sn_0xc1f0ee00 on its own bus, serial 0xc1f0ee00 in
  both guests; release; detach 6.20 s / 6.57 s; no object-add/del for it.
- Server state persisted across the restart between the two runs (1 device, 2 hosts, counters:
  next ids .hp2/.hp3). Everything deleted/detached at the end; both guests have no memdevs, no
  CXL NUMA node. Client binary + /tmp/guest-dax-rw.py left in the VMs (/usr/local/bin, /tmp).

### Tests
`go test -race ./scripts/testing/fake-cxl-pool/...`: 47 tests PASS (pkg/qemu: parsers on the live
fixtures in pkg/qemu/testdata (raw socat captures of info qtree [-b], info memdev, info version,
cmdlines), HMP client against a fake readline monitor, QMP client against a fake QMP server
(events, idle close, QOM tree, sn as integer), long socket paths; pkg/server: 19 state machine
tests with the fake monitor over httptest + pkg/client; pkg/guest: fake sysfs + fake cxl/daxctl;
pkg/pool; CLI exit codes). `go vet`/gofmt clean for fake-cxl-pool; `go build ./...` clean from the
repo root. Root `go vet ./...` fails ONLY in cmd/plugins/balloons/policy/podresourcehints_test.go
(TestPodResourceDeviceName redeclared; an untracked file that predates this work, not WS5).

### Usage summary
```
make -C scripts/testing/fake-cxl-pool                 # bin/fake-cxl-pool-server, bin/fake-cxl-pool-client (static amd64)
bin/fake-cxl-pool-server [-config FILE] [-v]          # 127.0.0.1:9909, discovery of all e2e qemus
FAKE_CXL_POOL_SERVER=http://127.0.0.1:9909 bin/fake-cxl-pool-client hosts       # on the host
fake-cxl-pool-client attach DEV --self ; sudo fake-cxl-pool-client guest wait DEV   # in a VM
```

### Open issues / notes for WS6
- Stock qemu (n4-cxl-fedora-43-containerd): a detached device stays as a zombie
  (fcp_n4-cxl-fedora-43-containerd.memdev9.hp1 on cxlsw_ds7_usrp0hb1 is there now, until that VM
  restarts). WS6 must use the patched qemu VMs (hotRemoveCapable=true).
- The server owns qmp.sock (persistent connection): anything else connecting to qmp.sock hangs
  while the server runs; use qmp-e2e.sock (vm-qmp). HMP monitor.sock is used only for HMP hosts,
  one short connection per command.
- Leak detection (device gone, `cxl-direct-mapping-alias` to its backend still in info mtree)
  is unit tested and the alias format is verified live, but the leak itself was not provoked
  live (it leaves guest memory stuck online until reboot).
- `guest region create` picks the first root decoder whose target_list has the host bridge uid
  (pci bus number of the memdev's PCI root = pxb-cxl bus_nr); interleaved multi-target windows
  are not handled specially. With hdm_for_passthrough=on several regions per host bridge work.
- Detach always takes >= ~6 s (guest pciehp 5 s attention button delay).
- Not implemented: smbios serial matching (D3 "later"); /events is implemented and unit tested
  but not exercised live.
- Deviations from 20-rest-api.md: see its "## Deviations" section.
- Note: while capturing HMP error-format fixtures at the start, agent C sent `device_del
  nonexistent_fcp_test` and `object_del nonexistent_fcp_test` to the n4-cxl-fedora-43-crio VM's
  monitor.sock (both no-ops: "Error: Device 'nonexistent_fcp_test' not found" / "Error: object
  'nonexistent_fcp_test' not found"). Nothing else was sent to that VM except read-only info
  commands; the WS5 servers never ran with that VM in discovery.

### Fixes after the code review (plan/51-code-review.md), 2026-10-02 agent C
Regression tests: pkg/server/regression_test.go (14 tests), pkg/qemu TestQMPCloseIsFinal and
TestNumaUnassignedAndInterleave, pkg/guest L5 case, cmd TestCLI help/flag cases. 63 tests pass
with -race (-count=2); go vet/gofmt clean; go build ./... clean; bin/ rebuilt (VMs still have
the old client in /usr/local/bin: copy the new one).
- H1: per-host attachment generation; stale trees are not stored/reconciled; adoption respects exclusive devices; an attach whose record a host restart dropped fails instead of 201.
- M1: QMP/HMP Close is final (ErrClosed, no redial); attach checks the host monitor did not change.
- M2: Detach (and GET /hosts, rescan refreshes) ignore the request context; BackendMapped errors mean "unknown" (kept, retried, 202), not "not mapped".
- M3: attachment copies are taken under s.mu in Attach/Detach (race detector clean).
- M4: config devices persist only allocation (+ auto serial); shared/labels come from the config; local devices persist them only after a PATCH.
- M5: serial order config-explicit -> state dynamic -> config-auto (persisted, stable); devices are never dropped from the state silently; orphan attachments are logged and dropped after the first refresh.
- L1: hotplug counter seeded from fcp_*.hpN ids in the tree and memdevs.
- L2: device_del "not found" runs the leak check.
- L3: interleaved fmw split per target. L4: NUMA 128 -> -1. L5: online --movable refuses blocks online in another zone.
- L6: local serials are per host; pool vs local serial collisions -> 409 (create, attach).
- L7: reserved slots rank below NUMA preference.
- L9: CLI global flag errors print usage; `guest --help` prints usage (WS6 nit); client dial timeout 10 s; region create timeout exits 3.
- L10: negative intervals rejected; deleting an allocated device needs force. Not fixed: L8, rest of L10.
