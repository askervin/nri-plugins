# 51: Code review of fake-cxl-pool (server, qemu, pool, api, client, guest, cmd)

Reviewer: read-only review agent, 2026-10-02. I did not modify any source file.

## Tool results (from the repo root)
- `go vet ./scripts/testing/fake-cxl-pool/...`: clean (exit 0).
- `go test -race -count=1 ./scripts/testing/fake-cxl-pool/...`: all packages ok
  (client cmd 1.2s, guest 1.1s, pool 1.1s, qemu 1.7s, server 3.5s). api, client and
  cmd/server have no tests.
- Reproductions: I wrote throw-away tests in /tmp/fcp-review/*.go and injected them with
  `go test -overlay /tmp/fcp-review/overlay.json` (and overlay3.json), so no file in the
  repo was touched. Every finding marked "REPRODUCED" fails one of those tests as
  described. To rerun them:
  `go test -race -count=1 -overlay /tmp/fcp-review/overlay.json -run TestReview -v ./scripts/testing/fake-cxl-pool/pkg/{server,qemu}/`

## Findings, ranked by severity

### H1 (high) A reconcile with a stale tree drops a just-attached device, and an exclusive device can then be attached twice. REPRODUCED
- Where: pkg/server/server.go:375-451 (`queryHosts`: `mon.QueryTree` runs without `h.opMu`,
  and line 447 stores the result as `h.tree`) together with server.go:796-866 (`reconcile`:
  lines 817-822 finalize every `attached` attachment that is missing from `h.tree`; lines
  824-857 adopt devices with no exclusivity check). Attach phase 2 (ops.go:726-761) takes
  `h.opMu` but nothing ties it to the tree snapshot.
- Failure scenario: GET /hosts (also `hosts NAME`, `rescan`, or the periodic 10 s Refresh)
  takes its tree snapshot. A concurrent POST attach then runs object-add and device_add
  (about 60 ms), sets the attachment to `attached` and returns 201. After that, queryHosts
  stores the old tree and reconcile finds the attachment "gone". `completeDetach` sees no
  mtree alias yet, so `finalizeDetach` sends object-del, which qemu refuses ("is in use"),
  and the attachment is deleted. The device now shows `free` while it is plugged in the
  VM. A second host can attach the exclusive device (allowed: 201). The next refresh
  re-adopts the first VM's device. Result: two `attached` attachments of a non-shared
  device, i.e. two guests using the same backing file. Test output:
  `attachment pooled0@vm1 state=attached adopted=true` and `pooled0@vm2 state=attached`.
- The same thing happens without a refresh race in one more case. device_add times out on
  the server side but qemu completes it. ops.go:746-751 deletes the record, and a later
  reconcile adopts the device.
- Fix: give each host a generation counter (or timestamp). Bump it under `s.mu` on every
  attach or detach state change. Record it in queryHosts before `QueryTree`. In reconcile,
  skip finalize/adopt for that host if the generation changed (or skip attachments with
  `Updated` after the snapshot time). Taking `h.opMu` around `QueryTree` alone is NOT
  enough: phase 2 can still finish between the snapshot and reconcile. Also make adoption
  refuse, or mark `failed`, a non-shared device that already has an attachment on another
  host.
- **Fixed in pkg/server/server.go (agent C, 2026-10-02): per-host attachment generation `gen` bumped in publishAttachmentLocked (every attachment change); queryHosts records it before QueryTree and stores the tree only if unchanged (`storeTreeLocked`, `treeGen`); reconcile skips a host whose `treeGen != gen`; adoption refuses an exclusive device attached to another host (warned once). Tests: TestStaleTreeKeepsNewAttachment, TestStaleTreeNoDoubleExclusiveAttach, TestAdoptionRespectsExclusive (pkg/server/regression_test.go). Also: an attach whose record was dropped by a host restart now fails instead of returning 201.**

### M1 (medium) `QMP.Close()` does not end the monitor. A captured monitor redials and holds qmp.sock forever. REPRODUCED
- Where: pkg/qemu/qmp.go:630-642 (Close only drops `q.conn`), qmp.go:227-265 (`acquire`
  redials whenever `q.conn == nil`), with the server's `IdleTimeout = 0`
  (server.go:198). The server closes monitors in setMonitorLocked (server.go:617-620) and
  hostGoneLocked (server.go:641-644), but goroutines that are still running keep their
  own `mon` reference: Detach's `WaitDeviceDeleted` polls every 2 s for up to the detach
  timeout (ops.go:952-953), and so do completeDetach/finalizeDetach, Attach `run`, and
  queryHosts goroutines.
- Failure scenario: a detach is waiting while the VM is restarted (test teardown,
  `vagrant reload`). Discovery sees the new pid, calls hostGoneLocked, closes the old QMP
  and creates a new one. The waiting detach's next `DeviceExists` call redials and
  connects to the NEW qemu's qmp.sock. It finds the device absent and returns, but the
  connection stays open (idle timeout 0, nothing closes it again). The new monitor gets
  "no greeting ... (is another client connected?)", and the host stays `unreachable`
  until the server restarts. The repro test shows exactly this: `closed QMP redialed;
  conns=2 closed=1`, and the replacement monitor gets a greeting timeout.
- A related effect: an attach that is still running when hostGone fires finishes on a
  record that was already dropped, and the client gets 201 for an attachment that does
  not exist.
- Fix: add a `closed` flag set in Close(); `acquire`/`Execute` return an error once it
  is set. Optionally, ops should re-check `s.hosts[name].mon == mon` before each step.
- **Fixed in pkg/qemu/qmp.go, hmp.go: Close sets `closed`; acquire/Command return `qemu.ErrClosed` afterwards, WaitDeviceDeleted and the polling loop stop on it. Attach phase 1 also checks that the host monitor is still the one it started with. Test: TestQMPCloseIsFinal (pkg/qemu/monitor_test.go).**

### M2 (medium) Detach is bound to the HTTP request context. A client disconnect marks the attachment failed and can skip object-del and the leak check. REPRODUCED
- Where: pkg/server/ops.go:852-980. `DeviceDel(dctx)` (914), `WaitDeviceDeleted(wctx)`
  (952-953), `completeDetach(ctx, a)` (956) and `finalizeDetach` (929) all derive from
  `r.Context()`. Attach uses `context.WithoutCancel` (ops.go:774); Detach does not.
- Failure scenario: a client gives up after 100 ms (curl `--max-time`, a Go client with
  `http.Client.Timeout`, Ctrl-C), and the guest has not released the device yet. The
  attachment becomes `failed` with "guest did not release the device within 15s"
  (observed after 101 ms), and an exclusive device goes to `error` until the background
  poll sees qemu delete it. If the cancel lands after WaitDeviceDeleted succeeded,
  `BackendMapped` fails on the cancelled context. That error is treated as "not mapped"
  (server.go:905-907), so the leak check is skipped and object-del also fails ("left in
  qemu"). A leaked backend is then reported as `detached`/free.
- Fix: put `ctx = context.WithoutCancel(ctx)` at the top of Detach (the wait is already
  bounded by opts.Timeout). Run completeDetach/finalizeDetach with s.ctx-derived
  contexts. Treat a BackendMapped error as "unknown" (keep `failed`), not as "not mapped".
- **Fixed in pkg/server/ops.go: Detach starts with `ctx = context.WithoutCancel(ctx)` (waits are bounded by the timeout and command timeouts); Hosts/Host/Rescan detach their refresh from the request too. completeDetach returns done/leaked/unknown: a BackendMapped error is "unknown" (attachment kept, retried by reconcile and the background waiter; the request gets 202), never "not mapped". Test: TestDetachIgnoresClientCancel. Note: the reviewer's TestReviewDetachClientCancel still "fails" by design: its guest never releases, so the detach now correctly runs to its real 15 s timeout and reports failed.**

### M3 (medium) Attachment fields are read after `s.mu` is released. A real data race. REPRODUCED with -race
- Where: pkg/server/ops.go:633-641 (`existing.State` / `existing.Attachment` read after
  `s.mu.Unlock()`), ops.go:665-671, ops.go:876-878 (Detach of an `attaching`
  attachment), ops.go:894-897.
- Failure scenario: POST attach `wait=false`, then DELETE (or a second POST) while phase 2
  is running. The race detector reports `Write at ops.go:745/754 (run)` against
  `Previous read at ops.go:878`. Torn copies of `api.Attachment` (strings, time) can go
  out in responses, and `go test -race` on any such test will flag it.
- Fix: copy `att := a.Attachment` (and the state) while the lock is held, then unlock
  and return the copy.
- **Fixed in pkg/server/ops.go: Attach and Detach copy `a.Attachment` (and the state, qemu id) while holding s.mu; results after unlock come from copies or are read under the lock. Test: TestConcurrentAttachDetachNoRace (-race clean).**

### M4 (medium) The state file silently overrides `shared` and labels of config devices. REPRODUCED
- Where: pkg/server/state.go:202-205 (saveStateLocked writes an override with `Shared`
  and `Labels` for EVERY non-dynamic device) and state.go:149-155 (loadState applies it
  over the freshly parsed config device without validation).
- Failure scenario: config `cfg0: shared: true`, run once, change it to `shared: false`,
  restart: the device is still `shared=true`. The same goes for label edits. The override
  also skips the "pool is not sharable" check (ops.go:286). With the default state file
  /tmp/fake-cxl-pool.state.json, a config edit can appear to have no effect.
- Fix: persist only what the API changed (allocation; labels/shared only after a
  PATCH, e.g. keep a "patched" flag), or let the config win for static devices and
  re-validate `shared` against the pool.
- **Fixed in pkg/server/state.go: config devices persist only the allocation (and an auto-assigned serial); shared and labels always come from the config, so the pool sharable check of the config applies. Local devices persist shared/labels only after a PATCH (`patched`). Test: TestConfigWinsOverState.**

### M5 (medium) Config serials are assigned before the state is loaded, so adding a config device can delete a dynamic device on restart. REPRODUCED
- Where: pkg/server/server.go:180-187 (`addStaticDevice` takes `serials.Next` before
  `loadState`), state.go:120-123 (`Use` fails, and the dynamic device is dropped with
  only a log line).
- Failure scenario: `create dyn0` gets 0xc1f00001. Then a config device without a serial
  is added and the server restarts: the config device gets 0xc1f00001, and dyn0 is gone
  ("serial 0xc1f00001 is already used by device cfg0"). Its attachments stay in `s.atts`
  pointing at a missing device, which DELETE cannot remove (404 "device not found"). Its
  backing file is left behind. A config device's serial can also change between runs when
  the order of config devices changes, while a VM still holds the old serial.
- Fix: two passes. First register config devices with explicit serials, then the state
  file's devices, and only then `Next()` for config devices without a serial. Or persist
  the serials given to config devices, or allocate dynamic serials from a separate range.
- **Fixed in pkg/server/server.go, state.go: config devices with explicit serials are registered first, then the state file's dynamic devices, and only then config devices without a serial get one, preferring the serial persisted for them (stable across config reordering). loadState never drops a device: a missing pool or a duplicate/invalid serial is logged as ERROR and the device kept; attachments of devices that are unknown after the first refresh are logged and dropped (nothing could detach them). Tests: TestStateSerials, TestStateKeepsAttachedDeviceOfRemovedPool.**

### L1 (low) The hotplug counter is not seeded from qemu
- Where: pkg/server/ops.go:690-691. `h.counter` only comes from the state file.
- Failure scenario: with `stateFile: "-"`, a lost state file, or a host forgotten at the
  first scan, the counter restarts at 0 on a qemu that still holds `fcp_<dev>.hp1`
  (a stock-qemu zombie, or an object whose object-del failed). The next attach of that
  device to that VM fails with a duplicate id (503), once for each colliding N.
- Fix: whenever a tree or memdev list is read, set `counter = max(counter, N)` over the
  `fcp_*.hpN` ids found. `QueryMemdevs` already exists and is unused.
- **Fixed in pkg/server/server.go: `seedCounterLocked` raises the hotplug counter above every `fcp_*.hpN` device or backend id seen in a tree, and in QueryMemdevs at first contact. Test: TestHotplugCounterSeededFromQemu.**

### L2 (low) A device_del "not found" result skips the leak check
- Where: ops.go:928-932 calls `finalizeDetach` directly.
- Scenario: the device was already removed (by a guest surprise removal or by another
  tool) while the backend is still mapped. The attachment is reported as detached and the
  device as free. Fix: call `completeDetach`.
- **Fixed in pkg/server/ops.go: device_del "not found" goes through completeDetach (leak check). Test: TestDeviceDelNotFoundChecksLeak.**

### L3 (low) Interleaved fixed memory windows are counted once per target
- Where: server.go:403-409 (`fmw[t] += w.Size` for every target).
- Scenario: a 4G window interleaved over cxlhb0 and cxlhb1 gives each host bridge 4G
  (8G in total), so attach admits twice the real capacity, and the guest's
  `create-region` then fails. Fix: divide by `len(Targets)`, or account per window.
- **Fixed in pkg/server/server.go and pkg/qemu/discovery.go (Process.FMWSize): a window counts size/len(targets) per target. Tests: TestInterleavedFMW, TestNumaUnassignedAndInterleave.**

### L4 (low) An unassigned pxb-cxl NUMA node shows up as node 128
- Where: qmp.go:476-479. qemu's pxb `numa_node` defaults to NUMA_NODE_UNASSIGNED
  (= MAX_NODES = 128), not -1; the qtree path parses it the same way.
- Scenario: host bridges without `numa_node=` report NUMA 128 in the API and CLI.
  Fix: map values >= 128 to -1.
- **Fixed in pkg/qemu (qtree, QOM, cmdline): numa_node >= 128 (NUMA_NODE_UNASSIGNED) is -1. Test: TestNumaUnassignedAndInterleave.**

### L5 (low) `guest online --movable` accepts blocks that are already online in another zone
- Where: pkg/guest/guest.go:322-330 (`want` drops `_movable`, so a block that is already
  `online` counts as done).
- Scenario: a udev rule or `auto_online_blocks=online` puts the blocks in ZONE_NORMAL.
  `online --movable` reports success, and a later `guest release` may fail to offline
  them (unmovable allocations), so detach leaks. Fix: check `valid_zones`, or offline
  and re-online as movable, or fail.
- **Fixed in pkg/guest/guest.go: online_movable of a block that is already online fails if its valid_zones is not Movable. Test: TestRegionRAMOnlineRelease.**

### L6 (low) Serial collisions with local devices are only logged
- Where: server.go:744-749.
- Scenario: a pool device created with an explicit serial (or a config serial) that
  equals the `__sn_` of a VM discovered later. Both devices keep the same serial. If both
  are in one guest, `FindMemdev` (guest.go:151-158) returns whichever memN comes first.
  Fix: give local devices a namespace keyed by host, and refuse cross-scope collisions
  (pool device vs local device in the same host).
- **Fixed in pkg/server: local devices no longer register in the pool serial allocator (namespace per host, VMs may repeat serials); pool serial allocation skips local serials; POST /devices with the serial of a local device -> 409; attaching a device to a host where a local device has the same serial -> 409; a local device that collides with a pool serial is warned at discovery. Test: TestSerialCollisionWithLocalDevice.**

### L7 (low) Slot scoring puts NUMA preference above slot reservations
- Where: ops.go:586-592 (NUMA +4 outweighs unreserved +2).
- Scenario: `--numa 1` takes a slot that is `reservedFor` a local device while free
  unreserved slots exist on node 0, contrary to the Deviations text ("used for other
  devices only when nothing else is free"). That local device then cannot attach
  (409 slot occupied). Fix: score unreserved slots above NUMA, or document the order.
- **Fixed in pkg/server/ops.go: unreserved (+4) now outranks the NUMA preference (+2). Test: TestReservedSlotBeforeNuma.**

### L8 (low) DEVICE_UNPLUG_GUEST_ERROR is recorded but never used
- Where: qmp.go:219-222 and 574-580 (`UnplugError`, `DeletedEventSeen` have no callers).
- Scenario: qemu reports that the guest refused the unplug, but the server still waits
  the full timeout and gives the generic message. Fix: in WaitDeviceDeleted, return early
  with the event data when that event arrives.
- **Not fixed (DEVICE_UNPLUG_GUEST_ERROR is still only recorded).**

### L9 (low) CLI and client details
- cmd/fake-cxl-pool-client/main.go:103-109: a parse error in a global flag
  (`--sever URL`) exits 2 with no message, because the FlagSet output is
  `io.Discard`. Print the error and usage, as subcommands do.
- pkg/client/client.go:61: the bare `http.Transport{}` has no dial timeout or
  keep-alive. Together with a CLI context that has no deadline, an unreachable
  192.168.76.2 hangs for the kernel's SYN retry time (about 2 min).
- `guest region create` timeout (guest.go:479-480) does not wrap `ctx.Err()`, so it
  exits 1, not 3.
- **Fixed: global flag errors print the error and usage (exit 2); `guest --help`, `guest -h`, `guest region --help` print usage (exit 0, the WS6 nit); the client transport has a 10 s dial timeout; the guest region create timeout wraps ctx.Err() (exit 3). Test: TestCLI.**

### L10 (low) Other edge cases (verified by reading)
- ops.go:302-352: DeleteDevice ignores the allocation, so anyone can delete an allocated
  (unattached) device.
- server.go:284: a negative `discovery.interval` makes `time.NewTicker` panic at Start
  (no validation in config.go:199-201).
- discovery.go:251-274: if `/proc/PID/cwd` is unreadable and there is no vagrant
  project dir, a relative socket path is returned unchanged and resolved against the
  server's own cwd.
- qmp.go:242-251: `acquire` holds `q.mu` while dialing (up to the command timeout when
  another client holds qmp.sock), which blocks every other call on that monitor,
  including `DeletedEventSeen`.
- plan/60-e2e-test.md step D creates `--size 128M`. The server rejects sizes that are not
  multiples of 256M (ops.go:197-199), so that step fails with 400/exit 1. Use 256M.
- **Partly fixed: negative discovery.interval / detachTimeout are config errors (TestConfigErrors); DeleteDevice of an allocated device needs force (TestDeleteAllocatedDevice). Not changed: unresolvable relative socket paths, acquire holding q.mu while dialing; the 128M size in plan/60 is WS6's.**

## Checked and found OK
- QMP demux: response channels are buffered, cancelled waits remove their pending id, an
  event that arrives before the waiter registers is caught by `q.deleted` in
  `DeviceExists`, and losing the connection while waiting falls back to polling.
- Lock order: opMu then s.mu everywhere, and nothing takes opMu while holding s.mu, so
  there is no deadlock. refreshMu is taken only by Refresh.
- Attach slot reservation: the attachment is put in `s.atts` (`attaching`) in phase 1, so
  concurrent attaches see the slot as busy and the bytes as used under the host bridge.
- Zombie handling: `h.unplugged` (persisted, reset when the qemu instance changes)
  prevents re-adoption; a repeated device_del is never sent.
- The leaked flag is not persisted, but it is rebuilt at the first reconcile after a
  restart (BackendMapped is checked again).
- Backing files: only created or extended, never truncated or shrunk; device names are
  validated (`[a-z0-9.-]`, no `/`); deletes are restricted to the pool dir.
- HMP: one connection per command under a mutex, the prompt/echo handling matches the
  fixtures, and errors are detected from `Error:` lines.
- Cmdline parsing: -chardev/-mon pairing is independent of order, server/nowait flags,
  befile_/beram_ regex, -uuid lowercasing, and the starttime field index (19 after
  `)`) are all correct.

## Nice-to-have simplifications
1. One "monitor generation" per host: replace `h.mon` captures with
   `s.monitor(h)`, which returns the current monitor or an error, and make QMP
   Close terminal (fixes M1 and part of H1).
2. Fold the per-attachment background pollers (server.go:1004-1057, up to 1 h each) into
   reconcile, which already finalizes `detaching`/`failed` attachments that are missing
   from the tree. Run reconcile every 2 s only while something is `detaching`.
3. Make `GET /hosts` cached by default and add `?refresh=true`. Today every list call
   queries every VM's QOM tree, which costs monitor traffic and widens H1's window.
4. Remove unused API surface, or start using it: `Monitor.QueryMemdevs`
   (use it to seed the counter, L1), `QMP.DeletedEventSeen`/`UnplugError` (L8), and
   `ParseInfoMemdev`.
5. Detach and Attach should share one helper for "run monitor ops detached from the
   request, bounded by a timeout" (fixes M2 consistently).
6. Persist an explicit "serial" for every device, config devices included, and load
   serials before allocating any (M5); then `Serials.Next` never collides.
7. Return copies from every exported Server method through one `attView(a)` helper that
   is always called under the lock (M3).
8. `decodeJSON`: use `DisallowUnknownFields` so typos (`"numa": 1` instead of
   `"numaNode"`) become 400 instead of being ignored.
9. `chooseSlotLocked`: build the slot list once (free, reserved, numa, fits) and sort
   it with an explicit comparator instead of additive scores (L7 becomes a visible
   ordering choice).
10. `BackendMappedIn`: compile the regex once per call site or match with
    `strings.Contains(" @"+objID)` plus a word-boundary check. It runs up to 3 times
    per finalize against the full `info mtree`.

## Summary
The code is well structured, vet-clean and race-test-clean. The QMP demux, the
zombie/unplugged bookkeeping and the backing-file handling are sound. The serious
problems are at the boundaries between concurrent activities rather than inside any
one component. The most important is H1: device-tree refreshes are not ordered against
attach, so a reconcile with a stale tree can forget a device that was just attached.
With adoption ignoring exclusivity, that lets an exclusive device end up in two VMs. I
reproduced this with the fake monitor; a `hosts` call at the wrong moment, or the
periodic refresh, triggers it. Next come lifetime issues: QMP.Close is not terminal, so
an in-flight detach can permanently take qmp.sock from the replacement monitor after a
VM restart (M1), and Detach depends on the client's connection (M2). Then a real data
race on attachment copies (M3), and two persistence issues where the state file either
overrides config edits (M4) or loses dynamic devices after a config edit (M5). All five
have small, local fixes; H1 and M1 should be fixed before WS6 relies on concurrent
clients or VM restarts. The low findings are edge cases (FMW interleave, NUMA 128,
online_movable zone, CLI messages), plus one plan inconsistency: WS6 step D uses a
128M device, which the server rejects.
