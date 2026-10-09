# WS-C: dra.source.sh, trace helper, test10-dra-pooling, test11-dra-sharing

Status: spec written 2026-10-06 (Fable). Owner: Opus agent C.
Repository: ~/github.com/containers/nri-plugins (branch 5jQ-cxl), test/e2e.
Read first: 00-overview.md (D21, D24, D26-D28, environment facts),
10-contract.md, .github/skills/run-e2e-tests/SKILL.md, test/e2e/lib/vm.bash
(vm-command, vm-put-file, retry-until in lib/test.bash),
memory.test-suite/memory-policy/n4-cxl-shared-2/{pool.source.sh,test00-up,test01-shared-cxl},
memory.test-suite/memory-policy/n4-cxl/cxl.source.sh, ../plan/60-e2e-test.md
(how test01 was built and run), and the driver's demo
~/github.com/intel/intel-resource-drivers-for-kubernetes/test/e2e/cxl/dra-demo-cxl.sh
(how the driver is started as a process, how feature gates are checked).

Audience of test10/test11: people who want to understand CXL pooling and
sharing with DRA and try it themselves. Each test is a readable story:
short `echo "### ..."` sections, one idea per section, YAML shown as it is
applied, assertions phrased as facts, and at the end the merged trace
summary of what every component did, in order.

Phase 1 (start now, no dependency on agents A/B): sections 1, 2, 3, 6.
Phase 2 (after A and B report done; the orchestrator tells you): sections
4, 5, 7. Do not start kubelet-cxl-plugin or fake-cxl-pool-controller in
the VMs before phase 2; A and B run short smoke tests there.

## 1. dra.source.sh (memory.test-suite/memory-policy/dra.source.sh)

Sourced for every memory-policy topology (n4-cxl too), so it only defines
functions and variables. Helpers take VMDIR first, like pool.source.sh, and
dispatch through `pool-vm-command`/`pool-vm-put-file` when those exist,
else `vm-command`/`vm-put-file` (define `dra-vm-command VMDIR CMD` etc.).

Variables: `DRA_DRIVER_SRC="${CXL_DRA_DRIVER_SRC:-$HOME/github.com/intel/intel-resource-drivers-for-kubernetes}"`,
`DRA_DRIVER_BIN="$DRA_DRIVER_SRC/bin/kubelet-cxl-plugin"`,
`DRA_CONTROLLER_BIN="$nri_resource_policy_src/scripts/testing/fake-cxl-pool/bin/fake-cxl-pool-controller"`,
`DRA_POOL_DRIVER=cxl-pool.generic`, `DRA_LOCAL_DRIVER=cxl.generic`,
`DRA_NS=cxl-pool-demo` (namespace of test objects), `DRA_INSTALLED_VMS=()`.

Functions (script API comments like the other libs):
- `dra-build`: `CGO_ENABLED=0 go build -mod vendor -o bin/kubelet-cxl-plugin ./cmd/kubelet-cxl-plugin`
  in DRA_DRIVER_SRC (error with a hint if the directory is missing),
  `make -C scripts/testing/fake-cxl-pool` (server, client, controller).
- `dra-install VMDIR`: copy both binaries to /usr/local/bin; write
  /etc/kubelet-cxl-plugin.yaml (`{}`); `systemctl stop` + `reset-failed` of
  old units if present; start
  `systemd-run --unit kubelet-cxl-plugin --property=Restart=no -E NODE_NAME=<vm name> -E KUBECONFIG=/root/.kube/config /usr/local/bin/kubelet-cxl-plugin --node-name <vm name> -f /etc/kubelet-cxl-plugin.yaml -v 4`
  and
  `systemd-run --unit fake-cxl-pool-controller -E KUBECONFIG=/root/.kube/config /usr/local/bin/fake-cxl-pool-controller -server $POOL_GUEST_URL -v`;
  apply `$DRA_DRIVER_SRC/deployments/cxl/pool/device-classes.yaml`; create
  namespace DRA_NS; wait (retry-until 60 s) until `kubectl get resourceslices -o json`
  has a slice with spec.driver == cxl-pool.generic and one with
  spec.driver == cxl.generic and nodeName == <vm name>, and
  /var/lib/kubelet/plugins/cxl-pool.generic/dra.sock exists. Record VMDIR
  in DRA_INSTALLED_VMS. Set the EXIT trap to `dra-cleanup; pool-cleanup`
  (pool-server-start set `pool-cleanup`; chain, do not lose it).
- `dra-uninstall VMDIR`: `kubectl delete namespace $DRA_NS --wait=true --timeout=120s`
  (ignore not found), wait until no resourceclaims remain in it, stop both
  units, reset-failed, `kubectl delete resourceslices -l ''`? No: delete
  only slices of driver cxl-pool.generic (jsonpath over names) if the
  controller left any; delete the DeviceClasses; remove
  /var/lib/kubelet/plugins/cxl-pool.generic/preparedPoolClaims.json only if
  the VM has no CXL regions left.
- `dra-cleanup`: for VMDIR in DRA_INSTALLED_VMS: dra-uninstall; then
  dra-trace-stop if a trace is running. Must leave the VMs without CXL
  memdevs (check with pool-cxl-dump; if a device is still attached, the
  pool-cleanup that follows releases and detaches it).
- `dra-kubectl VMDIR ARGS...` (vm-command "kubectl ARGS" in that VM, output
  in COMMAND_OUTPUT), `dra-apply VMDIR` (reads YAML from stdin, shows it,
  `kubectl apply -f -` in the VM via a heredoc), `dra-delete VMDIR KIND NAME`.
- `dra-json VMDIR KUBECTL-GET-ARGS` -> JSON in COMMAND_OUTPUT (`-o json`),
  `dra-assert JSON PYEXPR`, `dra-value JSON PYEXPR` (python, j = document;
  same shape as pool-assert; self-contained, do not depend on pool-py),
  `dra-wait VMDIR LABEL "KUBECTL-GET-ARGS" PYEXPR [TIMEOUT]` (retry-until
  over dra-json + dra-assert; on timeout print the JSON and fail).
- `dra-claim-conditions VMDIR CLAIM` prints `type=status reason` lines of
  status.devices[].conditions (used in the stories).
- `dra-pod-wait VMDIR POD PHASE [TIMEOUT]`.
- `dra-trace-start [VMDIR...]`, `dra-trace-stop`, `dra-trace-summary`: section 3.
- `dra-pull-images VMDIR IMAGE...`: `crictl pull` so that pod start times
  are not dominated by pulls (busybox, python:3-alpine).

## 2. The dax read/write pod tool

Shared memory in a container is a devdax device, usable only through
mmap. Use image `docker.io/library/python:3-alpine` and the existing
memory-policy/n4-cxl-shared-2/pool-dax-rw.py delivered as a ConfigMap
`dax-rw` (key dax-rw.py) in DRA_NS, mounted at /tools. Pod command:
`python3 /tools/dax-rw.py write $CXL_SHARED_DAX_<SERIALHEX> 0 "<text>" && sleep infinity`
or `read ... 0`. The env name carries the serial: write the pod YAML with
the serial known to the test (`CXL_SHARED_DAX_C1AE0001`). Verify in phase 1
that python:3-alpine pulls in both VMs (`crictl pull`); if it does not
(proxy), fall back to copying python3 from the VM through a hostPath mount
of /usr/bin and /usr/lib64 is NOT acceptable; report instead.

## 3. Trace helper (D28)

`dra-trace-start VMDIR...` starts background collectors on the host, each
piping into a line stamper that prefixes `<host epoch seconds.micro> <tag> `
(python3 -u, one line per input line, stdbuf -oL / unbuffered everywhere),
writing to `$TEST_OUTPUT_DIR/trace/<tag>.log`. Collectors:
- host: `tail -n0 -F $POOL_SERVER_LOG` (tag `server`).
- per VM (tag prefix `vm`/`vm1` from pool-vm-label, via `ssh -F <vmdir>/.ssh-config node sudo ...`):
  `journalctl -f -n0 -o cat -u fake-cxl-pool-controller` (`<vm>.controller`),
  `journalctl -f -n0 -o cat -u kubelet-cxl-plugin` (`<vm>.driver`),
  `kubectl -n kube-system logs -f --tail=0 kube-scheduler-<vm name>` (`<vm>.scheduler`),
  `kubectl get events -A --watch-only -o custom-columns=NS:.metadata.namespace,KIND:.involvedObject.kind,NAME:.involvedObject.name,REASON:.reason,MSG:.message --no-headers` (`<vm>.events`),
  `kubectl get resourceclaims -A -w -o json | python3 -u -c '<one line per claim update: name, allocated device, node, conditions type=status>'` (`<vm>.claims`),
  `kubectl get pods -A -w --no-headers` (`<vm>.pods`),
  `udevadm monitor -k -u -s cxl -s dax -s memory -s node` (`<vm>.udev`),
  `journalctl -f -n0 -o cat -u kubelet | grep --line-buffered -iE 'dra|resourceclaim|cxl'` (`<vm>.kubelet`).
Keep PIDs in a file; `dra-trace-stop` kills them (pkill -P the ssh
processes too), merges `sort -s -k1,1n trace/*.log > trace.txt` (drop the
numeric prefix in a readable copy: `trace.txt` lines like
`12:03:04.123456 vm.controller  attach pooled0 -> ...`), and
`dra-trace-summary` greps the markers that tell the story (claim created,
BindingConditionsPending, attach in server, Attached condition, udev add
of mem*/region*/dax, pod Running, pod deleted, release/destroy in driver
log, DEVICE_DELETED in server, claim gone) into `trace-summary.txt` and
prints it. Both files are what the audience reads. The ssh connection adds
a few ms; that is the only skew. Note in the summary header that times
are host clock receipt times.

## 4. test10-dra-pooling (memory-policy/n4-cxl-shared-2/test10-dra-pooling/code.var.sh)

Fedora only (SKIP otherwise), header comment: what pooling is, what the
components are, what the reader will see. VM2 only.
Preconditions (same pattern as test01): pool-vm-require, pool-vm-tools-install,
pool-vm-reset, cxl-dump no-devices; `pool-server-start` with devices
`pooled0 512M serial 0xc1ee0001` and `pooled1 256M serial 0xc1ee0002`;
pool-client-install; dra-build; dra-install VM2; dra-pull-images busybox;
dra-trace-start VM2.
A. "The pool is visible in Kubernetes": kubectl get resourceslices; assert
   the cxl-pool.generic slice has pooled0 (shared false, size 536870912,
   capacity memory 512Mi, bindingConditions, bindsToNode) and pooled1; the
   node's cxl.generic slice has a dram device and no cxl-node device.
   `fake-cxl-pool-client devices` shows both free.
B. "A pod asks for 512Mi of pooled CXL memory": dra-apply claim
   `pooled-memory` (class cxl-pool-memory, memory 512Mi) and pod
   `pooled-consumer` (busybox; command: `env | grep ^CXL_ | sort; echo; grep -H . /sys/devices/system/node/node*/meminfo | grep MemTotal; grep Mems_allowed_list /proc/self/status; sleep infinity`).
C. "The scheduler waits for the attachment": dra-wait for the pod event
   BindingConditionsPending (events JSON), then for claim
   status.devices[0].conditions Attached=True; show
   dra-claim-conditions and the claim's allocation (device pooled0, node
   selector = VM2). Server: `fake-cxl-pool-client attachments` shows
   pooled0@VM2 owner k8s:resourceclaim/<uid>.
D. "The node makes the memory usable": dra-pod-wait Running; pool-cxl-wait
   `by_serial(0xc1ee0001) is not None`, one region, enabled, OnlineSize ==
   536870912, node id >= 2; VM `numactl -H` shows the new node with 512 MB;
   pod log shows CXL_POOL_NODE_C1EE0001=<node>, CXL_POOL_SIZE_C1EE0001=536870912
   and node<node> MemTotal. Double advertising: `kubectl get resourceslices`
   still has no cxl-node device in the cxl.generic slice (dra-wait a few
   seconds for the udev rescan, then assert).
E. "Delete the pod and the claim, the memory returns to the pool":
   kubectl delete pod (grace 2 s), kubectl delete resourceclaim; dra-wait
   claim gone; pool-cxl-wait `memdevs == []`; server shows pooled0 free
   and no attachments; qemu `info qtree -b` has no cxl-type3 (via
   pool-vm-monitor); driver log shows the release, server log shows
   DEVICE_DELETED.
F. dra-trace-stop; dra-trace-summary printed; `trap - EXIT` after explicit
   dra-cleanup and pool-cleanup like test01 ends.

## 5. test11-dra-sharing (memory-policy/n4-cxl-shared-2/test11-dra-sharing/code.var.sh)

Two clusters (D21): VM2 = cluster of the test, VM1 driven over ssh via the
pool-* helpers. Preconditions as test10 for both VMs (pool-host-wait VM1
with the test00-up hint, require, tools, reset), server devices
`shared0 256M shared serial 0xc1ae0001`, dra-install both, dra-pull-images
python:3-alpine in both, ConfigMap dax-rw in both, trace both.
A. "Both clusters see the same shared device": both resourceslices show
   shared0 (shared true, size 268435456, allowMultipleAllocations,
   capacity hosts 4, default 1).
B. "Cluster 1 writes": in VM1: claim `shared-memory` (class
   cxl-shared-memory, selector serial == 0xc1ae0001) + pod `writer`
   (python:3-alpine, writes "<TAG> from cluster 1" at offset 0, then
   sleeps). Wait Attached, Running; VM1 has the memdev, region OnlineSize
   0, dax device bound to device_dax.
C. "Cluster 2 reads the same bytes": in VM2: claim + pod `reader` that
   reads offset 0 and prints it, then sleeps. Wait Running; pod log ==
   "<TAG> from cluster 1". Server: shared0 attached to both hosts, each
   with its k8s: owner. Host: pool-file-string of the backing file at 0 is
   the TAG.
D. "Each cluster releases independently": delete writer pod + claim in
   VM1; wait: VM1 memdev gone, server shows shared0 attached only to VM2,
   VM2's reader still Running and `kubectl exec reader -- python3 /tools/dax-rw.py read ... 0`
   still returns the TAG. Then delete in VM2; shared0 free; no cxl-type3 in
   either qemu.
E. trace stop + summary (both VMs' streams interleaved in one timeline is
   the point of this test), cleanup as test10.

## 6. Serial scheme in e2e files (D27, phase 1)

- topology.var.json of n4-cxl-shared-1 and -2: `"sn": "0xc1f0ee00"` -> `"0xc1ae0000"`.
- test00-up (both): expect `cxl_memdev0 sn=0xc1ae0000`; the error text says
  the VM was created from an older topology and how to recreate it (the
  running VMs were created with 0xc1f0ee00; do not recreate them in this
  task, say so in Status).
- test01-shared-cxl: SHARED_SERIAL 0xc1ae0001 and its comment; excl0 is
  auto-assigned (0xc1ee0001 after agent B's server change; the test reads
  it from the output, assert only that it starts with 0xc1ee once B is
  done).
- lib/topology2qemuopts.py docstring example 0xc1f0ee00 -> 0xc1ae0000 and
  a one-line note on the scheme (0xc100 boot-time, 0xc1ae shared pool,
  0xc1ee exclusive pool). Regenerate nothing else; the Vagrantfiles of
  existing VMs are untouched.
- pool.source.sh comments mentioning serials, if any.

## 7. Runs

From test/e2e: `./run_tests.sh memory.test-suite/memory-policy/n4-cxl-shared-2/test10-dra-pooling`
then test11. Keep logs under ~/.claude/jobs/<something>/ or $TEST_OUTPUT_DIR
(test/e2e/n4-cxl-shared-2-fedora-43-containerd/memory.test-suite/memory-policy/<test>/).
Then run test01-shared-cxl once more to prove the DRA components left the
VMs clean. Each test should finish in a few minutes on prepared VMs. If a
VM ends up with a zombie cxl-type3 (detach without release), pool-vm-reset
restarts it on the next run; note every such event in Findings with the
cause. Debug driver/controller problems in their logs first; if a fix is
needed in the driver or the controller, make it (small, documented in the
Status of 20/30 as "fixed by C"); if the problem is a design problem, stop
and report it instead of working around it.

## 8. Report

Append Status and Findings: files, run logs, timings (attach, Attached,
pod Running, detach), the trace-summary of one passing run of each test,
problems and fixes, what was left out.

## Status (phase 1)

2026-10-06, Opus agent C. Phase 1 done (sections 1, 2, 3, 6); test10 and
test11 written as complete drafts, NOT run. Nothing committed. No
kubelet-cxl-plugin or fake-cxl-pool-controller was started by C.

Files (all under test/e2e/):
- memory.test-suite/memory-policy/dra.source.sh (new, ~840 lines): variables
  of section 1 (+ DRA_DEVICE_CLASSES, DRA_DAX_TOOL, DRA_JSON, DRA_TRACE_*);
  dra-vm-command/-q/-put-file/-label/-name (dispatch to pool-vm-* when
  pool.source.sh is sourced, else vm-* for $OUTPUT_DIR only), dra-build,
  dra-install, dra-uninstall, dra-cleanup, dra-kubectl, dra-apply,
  dra-delete, dra-json, dra-assert, dra-value, dra-py, dra-wait,
  dra-claim-conditions, dra-pod-wait, dra-pull-images,
  dra-dax-tool-install (ConfigMap dax-rw), dra-trace-start/-stop/-summary.
- memory.test-suite/memory-policy/n4-cxl-shared-2/test10-dra-pooling/code.var.sh (new, draft, sections A-F).
- memory.test-suite/memory-policy/n4-cxl-shared-2/test11-dra-sharing/code.var.sh (new, draft, sections A-E).
- Serial scheme (section 6): n4-cxl-shared-{1,2}/topology.var.json sn
  0xc1f0ee00 -> 0xc1ae0000; n4-cxl-shared-{1,2}/test00-up/code.var.sh expect
  `cxl_memdev0 sn=0xc1ae0000` and give a dedicated error with recreate
  instructions when the VM still has 0xc1f0ee00; test01-shared-cxl
  SHARED_SERIAL=0xc1ae0001 (+ comment on the scheme) and asserts the
  auto-assigned excl0 serial starts with 0xc1ee; lib/topology2qemuopts.py
  docstring example + one-line scheme note; pool.source.sh: scheme note in
  the pool-server-start comment (it had no serial values).
- The running shared VMs were created with 0xc1f0ee00 and were NOT
  recreated: test00-up of n4-cxl-shared-1/-2 now FAILS on them by design
  (with the recreate hint) until they are recreated. test01/test10/test11
  do not use the static device, so they are unaffected. Vagrantfiles of
  the existing VMs are untouched (vm-setup does not regenerate them).

Verified:
- bash -n on all changed scripts; shellcheck -s bash (excluding SC2034,
  SC2154, SC1090, SC2016) clean on dra.source.sh, test10, test11. The
  remaining info-level findings in test00-up/pool.source.sh are old lines.
- Image pull (section 2): `crictl pull docker.io/library/python:3-alpine`
  and `docker.io/library/busybox:latest` succeed in BOTH shared VMs
  (through the VM proxy, ~3 s each, "Image is up to date": both images are
  now cached in both VMs; python 3-alpine sha256:5e80f9e3093d...,
  busybox sha256:aaef90e06523...). No fallback needed.
- Test YAML (pooled claim + busybox pod; shared claim + python writer pod
  with ConfigMap volume) passes `kubectl apply --dry-run=server` in VM2.
- dra-py helpers and every dra-assert expression of test10/test11 were run
  against synthetic ResourceSlice/claim JSON shaped like 10-contract.md;
  dra-claim-conditions output checked.
- Trace helper against VM2 for a few seconds (all 8 VM collectors + the
  server-log tail on a scratch file): pid files appear, lines stamped,
  merged trace.txt and trace-summary.txt written; after dra-trace-stop no
  remote collector (journalctl -f, kubectl watch, udevadm monitor) and no
  host stamper/ssh left; /run/dra-trace removed from VM2 afterwards. The
  claims JSON-stream parser was tested on a real
  `kubectl get ... -w --output-watch-events -o json` capture (one-line
  events) and on its pretty-printed form.
- Scratch harness for trying helpers outside run.sh: /tmp/dra-harness/harness.sh.

## Findings

- Trace design details (deviations from section 3 wording, same intent):
  - Each collector uses its own ssh connection (`-o ControlMaster=no
    -o ControlPath=none`): 8 permanent sessions on the shared
    ControlMaster would leave only 2 of sshd's default MaxSessions=10 for
    the test's own vm-command calls.
  - The remote command runs under `setsid -w` and writes its process group
    id to /run/dra-trace/<tag>.pid; dra-trace-stop kills those groups in
    the VM (killing the local ssh would leave journalctl/kubectl/udevadm
    running in the VM: no pty, no SIGHUP), then waits for the host
    pipelines to drain, then kills their process groups (each started with
    setsid). The server-log `tail -F` is stopped with `pkill -g <pgid> -x tail`
    so its stamper flushes.
  - The claims summarizer (`one line per claim update`) runs on the host in
    the stamper (stamp.py, written into trace/ at start) instead of a
    `python3 -c` in the VM: no third quoting level. It uses
    `--output-watch-events` and prints ADDED/MODIFIED/DELETED, allocated
    driver/pool/device, node, reservedFor, per-device conditions and
    data.serial; unchanged MODIFIED updates are dropped.
  - Pods watch uses `--output-watch-events` too, so "pod deleted" is an
    explicit DELETED line.
  - Files: trace/<tag>.log (raw, epoch-stamped), trace/merged.txt
    (`LC_ALL=C sort -s -k1,1n`), $TEST_OUTPUT_DIR/trace.txt (readable
    `HH:MM:SS.micro tag text`), $TEST_OUTPUT_DIR/trace-summary.txt (adds
    `+seconds` since the first summary line; header says times are host
    receipt times, ssh adds a few ms).
  - Summary filters per tag are first guesses, to tune in phase 2 against
    real logs: server = attaching/attached/detaching/detached/failed,
    DEVICE_DELETED, device created/deleted; driver = lines containing
    `cxl-pool.generic` (agent A's pool helper prefixes every log line with
    its name: prepared/released/unprepared) or `pool device`, errors;
    controller = attach/detach/condition/status/publish/slice/error (may be
    too broad with -v); udev = KERNEL lines of cxl/dax/node/memory only;
    events/claims all (not kube-system); pods only of $DRA_NS.
- dra-install also: removes preparedPoolClaims.json before starting the
  plugin when the VM has no CXL regions (stale state of an earlier boot),
  and recreates namespace $DRA_NS empty after the driver is up (so that the
  driver can unprepare leftovers of an aborted run). Pods are always
  deleted gracefully (--grace-period=2), never --force (contract section 7
  hazard). dra-uninstall waits (60 s) until the server shows no `k8s:`
  attachments on the node before stopping the controller; pool-cleanup
  handles anything left.
- dra-cleanup / dra-uninstall never call error/command-error: they run in
  the EXIT trap before pool-cleanup, and an exit there would skip it.
- dra-apply must not be used at the end of a pipeline (subshell: error()
  would not stop the test); test11 uses `dra-apply VM <<< "$(yaml-func)"`.
- Driver flags: dra-install uses `-f /etc/kubelet-cxl-plugin.yaml` as the
  spec says; agent A's smoke test used `-c '{}'`. main.go says -f and -c are
  mutually exclusive while -c has a default value: check in phase 2 that
  -f is accepted (the old dra-demo-cxl.sh uses -f, so it should be).
- Not mine, observed while working (other agents' smoke tests, left as
  they are): a ResourceClaim `pooled-memory` existed in namespace default of
  VM2 at ~15:03 (server dry-run said "configured"), gone again by ~15:05;
  unit kubelet-cxl-plugin-smoke.service running in VM2 at ~15:05.

Open questions for phase 2:
1. Do the controller's and driver's log lines match the summary patterns
   (tune after the first run)? Does the scheduler at its default verbosity
   log anything about binding conditions (else the scheduler stream is
   empty, the BindingConditionsPending event carries the story)?
2. Is BindingConditionsPending an Event on the pod (test10 C waits for
   events('BindingConditionsPending', 'pooled-consumer'))? If it is on the
   claim or has another reason string, adjust.
3. Does the pool ResourceSlice exist when the server has zero devices?
   dra-install waits for one; both tests start the server with devices, so
   this only matters for other users.
4. test10 D sleeps 10 s before the "no cxl-node device" assertion (a
   negative cannot be waited for); replace with a positive signal if the
   driver logs the rescan that skipped the pool device (D29 log
   "pool device (cxl-pool.generic)").
5. Is /sys/bus/dax/devices/<dax>/size readable in the python:3-alpine
   container (pool-dax-rw.py reads it)? Containers get a read-only sysfs,
   so it should be; if not, pass the size from CXL_SHARED_SIZE_<serial>.
6. test00-up of the shared topologies fails on the current VMs until they
   are recreated with 0xc1ae0000 (user's decision when).

## Status (phase 2)

2026-10-06 15:10-15:29, Opus agent C. test10-dra-pooling and
test11-dra-sharing PASS on the prepared VMs, then test01-shared-cxl PASS
once more after them: the DRA components leave the VMs clean. Nothing
committed.

Final runs (from test/e2e, one after the other, logs in
~/.claude/jobs/ws-c/):
- test10-dra-pooling: PASS, 66 s (test10-dra-pooling-final.log)
- test11-dra-sharing: PASS, 107 s (test11-dra-sharing-final.log)
- test01-shared-cxl: PASS, 77 s (test01-shared-cxl-final.log)
Earlier runs: test10-run1.log PASS but with a failed first NodePrepare
(bug 1 below), test10-run2.log PASS after fix 1, test11-run1.log PASS but
with a failed first NodePrepare in VM2 (bug 2), test11-run2.log PASS
after fix 2. The final traces have no FailedPrepareDynamicResources.
Trace files of the final runs: ~/.claude/jobs/ws-c/test1{0,1}-*-final.trace{,-summary}.txt
(also in the test output dirs until the next run).

After the final runs: neither qemu has a cxl-type3 device (monitor.sock
`info qtree -b`), the guests have no mem*/region*, no ResourceSlices,
ResourceClaims, DeviceClasses or cxl-pool-demo namespace in either
cluster, no kubelet-cxl-plugin/fake-cxl-pool-controller units, no
preparedPoolClaims.json, no /etc/cdi/cxl-pool.yaml (only the
generic-cxl.yaml that cxl.generic writes on every start), no
/run/dra-trace, port 9909 free, no host collectors. No zombie cxl-type3 at
any time; pool-vm-reset never had to restart a VM.

Timings (final runs, host clock, from trace-summary.txt):

| step | test10 (VM2, pooled0 512M) | test11 VM1 (writer) | test11 VM2 (reader) |
|------|------|------|------|
| claim created -> BindingConditionsPending | 0.06 s | 0.50 s | 0.49 s |
| claim created -> server attached | 0.56 s | 0.57 s | 0.56 s |
| server attached -> claim Attached (event) | 0.03 s | 0.03 s | 0.03 s |
| Attached -> Scheduled (scheduler poll) | 4.5 s | 4.9 s | 4.9 s |
| Scheduled -> prepared (node plugin) | 0.65 s | 0.71 s | 0.65 s |
| claim created -> pod Running | 6.05 s | 6.38 s | 6.59 s |
| pod Terminating -> released (node plugin) | 0.90 s | 0.90 s | 0.53 s |
| released -> detaching (controller) | 0.30 s | 0.30 s | 0.60 s |
| detaching -> DEVICE_DELETED | 6.27 s | 6.07 s | 6.15 s |

The attach itself (qemu object-add + device_add) takes ~30 ms; the
scheduler's 5 s binding-condition poll dominates the time to Running, and
pciehp's 5 s button delay dominates detach.

Changes in phase 2:
- dra.source.sh: dra-build runs `go mod vendor` before the driver build
  (vendor/ is gitignored in the driver repo); trace-summary filters tuned
  against the real logs (driver: `cxl-pool.generic`, `pool device`,
  `rescanAndPublish`, errors; noise excluded: "some fields were dropped by
  the apiserver" (D32), "udev event triggered rescan", cxl CLI follow-up
  lines, controller "server event" lines; server GET lines excluded);
  dra-trace-stop also removes /run/dra-trace in the VMs.
- test10: step D waits for "rescanAndPublish: published updated
  resources" after "cxl-pool.generic: claim ...: prepared pooled0" in the
  kubelet-cxl-plugin journal (no more sleep), then asserts no cxl-node
  device.
- test10/test11 pods: `trap "exit 0" TERM; sleep infinity & wait`, so a
  deleted pod ends Completed instead of Error (exit 143) in the story.
- Fixes by C in pkg/cxl/memctl (nri-plugins, agent A's package; recorded
  in the Status of 20-kubelet-cxl-plugin.md), see Findings 1-2.

## Findings (phase 2)

1. Bug, fixed by C (pkg/cxl/memctl, CreateRegion): exclusive Prepare
   failed on the first try with `mem0: no memory blocks found for region0`,
   and the rollback failed with `cxl disable-region region0: ... unable to
   offline dax0.0: No such file or directory`. Kubelet retried after ~85 s,
   so test10 still passed but the pod took 93.7 s to run. Cause: in the
   VM's kernel a ram region's dax device is bound to kmem by the kernel
   itself, and the driver link of a device exists before its probe runs
   (really_probe: driver_sysfs_add, then probe). CreateRegion's "dax device
   bound to a driver" wait returned while dev_dax_kmem_probe was still
   adding the memory blocks (udev: region0 add, dax0.0 add, memory202-205
   add, then dax0.0 bind; memctl ran 2 ms after "created region0").
   Fix: new waitRegionBlocks (every block of the region exists) when the
   dax device is on kmem, before switching drivers or returning; regionBlocks
   returns the expected block count too. New unit test
   TestRegionRAMWaitsForBlocks.
2. Bug, same cause, fixed by C: shared Prepare in VM2 failed with `daxctl
   reconfigure-device ...: error reconfiguring devices: No such file or
   directory` (switching the kmem-bound dax device to device_dax during the
   kmem probe); VM1 got lucky. Fix: the wait of 1 runs whenever the dax
   device is on kmem, also in devdax mode. New unit test
   TestRegionDevDaxWaitsForKmemProbe. `go test -race ./pkg/cxl/memctl`
   and the driver's `go test ./cmd/kubelet-cxl-plugin/` pass (after `go
   mod vendor`). No change in the driver or the controller themselves.
3. Not a bug, worth knowing: between Attached and Scheduled there are
   always ~5 s: the scheduler polls binding conditions every 5 s (contract
   section 4). Attach is ~30 ms.
4. pool-dax-rw.py works unchanged in python:3-alpine: /sys/bus/dax is
   visible in the container (it reads the size from there), the CDI device
   node /dev/dax0.0 is mmappable. The writer's env:
   CXL_SHARED_DAX_C1AE0001=/dev/dax0.0, CXL_SHARED_SERIAL_C1AE0001=0xc1ae0001,
   CXL_SHARED_SIZE_C1AE0001=268435456. The bytes written in cluster 1 were
   read in cluster 2, found by the host in /tmp/fake-cxl-pool/shared0.raw,
   and were still readable in cluster 2 (kubectl exec) after cluster 1 had
   released and detached the device.
5. Both clusters run their own controller against one server; each only
   detached its own attachment (owners k8s:resourceclaim/<uid> of the two
   different claims), as D22 says.
6. The scheduler stream (kube-scheduler logs at default verbosity) and the
   kubelet stream carry little: the BindingConditionsPending/Scheduled
   events tell that part of the story. Kept in trace.txt.
7. Left out / not tested: force deletion hazard (contract section 7),
   AttachFailed paths, a second exclusive claim waiting for a busy device,
   driver/controller restarts with prepared claims: test12+ (50-realistic-tests.md).

### Trace summary, test10-dra-pooling (final run)
```
# What every component did in test10-dra-pooling, in order.
# Times are host clock receipt times: the host stamped each line when it
# arrived. Lines from the VMs come over ssh, which adds a few ms; there is
# no VM clock skew. +s is seconds since the first line below.
# Tags: server = fake-cxl-pool-server on the host; <vm>.controller =
# fake-cxl-pool-controller, <vm>.driver = kubelet-cxl-plugin, <vm>.scheduler,
# <vm>.kubelet, <vm>.events, <vm>.claims (ResourceClaim changes), <vm>.pods,
# <vm>.udev (kernel uevents) of the VMs: vm = n4-cxl-shared-2-fedora-43-containerd .
# The full trace is trace.txt.
15:25:00.938416    +0.000s vm.claims      ADDED claim cxl-pool-demo/pooled-memory uid=fbafbd77 allocated=- node=- reservedFor=- status=-
15:25:00.954427    +0.016s vm.pods        ADDED      cxl-pool-demo   pooled-consumer                                                0/1   Pending   0               0s
15:25:00.970345    +0.032s vm.pods        MODIFIED   cxl-pool-demo   pooled-consumer                                                0/1   Pending   0               0s
15:25:00.986700    +0.048s vm.claims      MODIFIED claim cxl-pool-demo/pooled-memory uid=fbafbd77 allocated=cxl-pool.generic/fake-cxl-pool/pooled0 node=n4-cxl-shared-2-fedora-43-containerd reservedFor=pooled-consumer status=-
15:25:00.997973    +0.060s vm.events      cxl-pool-demo   Pod   pooled-consumer   BindingConditionsPending   waiting for binding conditions for device on node n4-cxl-shared-2-fedora-43-containerd
15:25:01.468982    +0.531s server         fake-cxl-pool: 2026/10/06 15:25:01.468867 attachment pooled0@n4-cxl-shared-2-fedora-43-containerd: attaching to slot cxlsw_ds0_usrp0hb0 as fcp_pooled0.hp1 (backend fcp_pooled0.hp1, serial 0xc1ee0001)
15:25:01.497728    +0.559s server         fake-cxl-pool: 2026/10/06 15:25:01.497613 attachment pooled0@n4-cxl-shared-2-fedora-43-containerd: attached
15:25:01.520040    +0.582s vm.claims      MODIFIED claim cxl-pool-demo/pooled-memory uid=fbafbd77 allocated=cxl-pool.generic/fake-cxl-pool/pooled0 node=n4-cxl-shared-2-fedora-43-containerd reservedFor=pooled-consumer status=pooled0:cxl-pool.generic/Attached=True,pooled0:serial=0xc1ee0001
15:25:01.530080    +0.592s vm.events      cxl-pool-demo   ResourceClaim   pooled-memory     Attached                   pooled0 attached to n4-cxl-shared-2-fedora-43-containerd (slot cxlsw_ds0_usrp0hb0)
15:25:01.636456    +0.698s vm.controller  fake-cxl-pool-controller: 2026/10/06 12:25:01.265393 attached pooled0 to n4-cxl-shared-2-fedora-43-containerd (node n4-cxl-shared-2-fedora-43-containerd, slot cxlsw_ds0_usrp0hb0, qemu device fcp_pooled0.hp1, owner k8s:resourceclaim/fbafbd77-a942-461d-991e-683193da3256) for cxl-pool-demo/pooled-memory
15:25:01.636468    +0.698s vm.controller  fake-cxl-pool-controller: 2026/10/06 12:25:01.283688 status of claim cxl-pool-demo/pooled-memory device pooled0 node n4-cxl-shared-2-fedora-43-containerd: cxl-pool.generic/Attached=True reason Attached: pooled0 attached to n4-cxl-shared-2-fedora-43-containerd (slot cxlsw_ds0_usrp0hb0)
15:25:01.672050    +0.734s vm.udev        KERNEL[337680.133677] add      /devices/pci0000:0c/0000:0c:00.0/0000:0d:00.0/0000:0e:00.0/0000:0f:00.0/mem0 (cxl)
15:25:01.672868    +0.734s vm.udev        KERNEL[337680.133958] add      /devices/platform/ACPI0017:00/root0/port2/port3 (cxl)
15:25:01.676799    +0.738s vm.udev        KERNEL[337680.138686] bind     /devices/platform/ACPI0017:00/root0/port2/port3 (cxl)
15:25:01.699825    +0.761s vm.udev        KERNEL[337680.161703] add      /devices/platform/ACPI0017:00/root0/port2/port3/decoder3.0 (cxl)
15:25:01.699970    +0.762s vm.udev        KERNEL[337680.161933] add      /devices/platform/ACPI0017:00/root0/port2/port3/decoder3.1 (cxl)
15:25:01.700131    +0.762s vm.udev        KERNEL[337680.162115] add      /devices/platform/ACPI0017:00/root0/port2/port3/decoder3.2 (cxl)
15:25:01.700365    +0.762s vm.udev        KERNEL[337680.162341] add      /devices/platform/ACPI0017:00/root0/port2/port3/decoder3.3 (cxl)
15:25:01.700911    +0.762s vm.udev        KERNEL[337680.162870] add      /devices/platform/ACPI0017:00/root0/port2/port3/endpoint4 (cxl)
15:25:01.732867    +0.794s vm.udev        KERNEL[337680.194666] add      /devices/platform/ACPI0017:00/root0/port2/port3/endpoint4/decoder4.0 (cxl)
15:25:01.733201    +0.795s vm.udev        KERNEL[337680.195000] add      /devices/platform/ACPI0017:00/root0/port2/port3/endpoint4/decoder4.1 (cxl)
15:25:01.735565    +0.797s vm.udev        KERNEL[337680.195650] add      /devices/platform/ACPI0017:00/root0/port2/port3/endpoint4/decoder4.2 (cxl)
15:25:01.735604    +0.797s vm.udev        KERNEL[337680.197136] add      /devices/platform/ACPI0017:00/root0/port2/port3/endpoint4/decoder4.3 (cxl)
15:25:01.735615    +0.797s vm.udev        KERNEL[337680.197436] bind     /devices/platform/ACPI0017:00/root0/port2/port3/endpoint4 (cxl)
15:25:01.735771    +0.797s vm.udev        KERNEL[337680.197688] bind     /devices/pci0000:0c/0000:0c:00.0/0000:0d:00.0/0000:0e:00.0/0000:0f:00.0/mem0 (cxl)
15:25:02.351636    +1.413s vm.driver      I1006 12:25:01.702528  122109 driver.go:485] rescanAndPublish: published updated resources (1 devices)
15:25:05.997369    +5.059s vm.pods        MODIFIED   cxl-pool-demo   pooled-consumer                                                0/1   Pending   0               5s
15:25:06.005394    +5.067s vm.events      cxl-pool-demo   Pod             pooled-consumer   Scheduled                  Successfully assigned cxl-pool-demo/pooled-consumer to n4-cxl-shared-2-fedora-43-containerd
15:25:06.015098    +5.077s vm.pods        MODIFIED   cxl-pool-demo   pooled-consumer                                                0/1   ContainerCreating   0               5s
15:25:06.350953    +5.413s vm.udev        KERNEL[337684.812546] add      /devices/platform/ACPI0017:00/root0/decoder0.0/region0 (cxl)
15:25:06.374619    +5.436s vm.udev        KERNEL[337684.836273] add      /devices/platform/ACPI0017:00/root0/decoder0.0/region0/dax_region0 (cxl)
15:25:06.374691    +5.436s vm.udev        KERNEL[337684.836474] bind     /devices/platform/ACPI0017:00/root0/decoder0.0/region0 (cxl)
15:25:06.375905    +5.437s vm.udev        KERNEL[337684.837758] add      /devices/platform/ACPI0017:00/root0/decoder0.0/region0/dax_region0/dax0.0 (dax)
15:25:06.402307    +5.464s vm.udev        KERNEL[337684.864161] bind     /devices/platform/ACPI0017:00/root0/decoder0.0/region0/dax_region0/dax0.0 (dax)
15:25:06.402457    +5.464s vm.udev        KERNEL[337684.864367] bind     /devices/platform/ACPI0017:00/root0/decoder0.0/region0/dax_region0 (cxl)
15:25:06.451823    +5.513s vm.udev        KERNEL[337684.913677] unbind   /devices/platform/ACPI0017:00/root0/decoder0.0/region0/dax_region0/dax0.0 (dax)
15:25:06.453105    +5.515s vm.udev        KERNEL[337684.914964] add      /devices/system/node/node2 (node)
15:25:06.453555    +5.515s vm.udev        KERNEL[337684.915402] add      /devices/system/memory/memory202 (memory)
15:25:06.454474    +5.516s vm.udev        KERNEL[337684.915762] add      /devices/system/memory/memory203 (memory)
15:25:06.454489    +5.516s vm.udev        KERNEL[337684.915971] add      /devices/system/memory/memory204 (memory)
15:25:06.454499    +5.516s vm.udev        KERNEL[337684.916149] add      /devices/system/memory/memory205 (memory)
15:25:06.454509    +5.516s vm.udev        KERNEL[337684.916387] bind     /devices/platform/ACPI0017:00/root0/decoder0.0/region0/dax_region0/dax0.0 (dax)
15:25:06.485450    +5.547s vm.udev        KERNEL[337684.947244] online   /devices/system/memory/memory202 (memory)
15:25:06.490287    +5.552s vm.udev        KERNEL[337684.952088] online   /devices/system/memory/memory203 (memory)
15:25:06.494776    +5.556s vm.udev        KERNEL[337684.956638] online   /devices/system/memory/memory204 (memory)
15:25:06.499038    +5.561s vm.udev        KERNEL[337684.960921] online   /devices/system/memory/memory205 (memory)
15:25:06.651007    +5.713s vm.driver      I1006 12:25:06.263787  122109 pool.go:267] cxl-pool.generic: claim cxl-pool-demo/pooled-memory: prepared pooled0 (serial 0xc1ee0001, shared false) as mem0 region0 dax dax0.0 node 2
15:25:06.812443    +5.874s vm.events      cxl-pool-demo   Pod             pooled-consumer   Pulled                     Container image "docker.io/library/busybox:latest" already present on machine and can be accessed by the pod
15:25:06.821333    +5.883s vm.pods        MODIFIED   cxl-pool-demo   pooled-consumer                                                0/1   ContainerCreating   0               6s
15:25:06.865897    +5.927s vm.events      cxl-pool-demo   Pod             pooled-consumer   Created                    Container created
15:25:06.912834    +5.974s vm.driver      I1006 12:25:06.471823  122109 node_state.go:213] - ignoring region device "region0": pool device (cxl-pool.generic), memory device serial 0xc1ee0001
15:25:06.912915    +5.974s vm.driver      I1006 12:25:06.471965  122109 driver.go:485] rescanAndPublish: published updated resources (1 devices)
15:25:06.977827    +6.039s vm.events      cxl-pool-demo   Pod             pooled-consumer   Started                    Container started
15:25:06.991097    +6.053s vm.pods        MODIFIED   cxl-pool-demo   pooled-consumer                                                1/1   Running             0               6s
15:25:10.765243    +9.827s vm.pods        MODIFIED   cxl-pool-demo   pooled-consumer                                                1/1   Terminating         0               10s
15:25:10.773093    +9.835s vm.events      cxl-pool-demo   Pod             pooled-consumer   Killing                    Stopping container consumer
15:25:10.781965    +9.844s vm.pods        MODIFIED   cxl-pool-demo   pooled-consumer                                                1/1   Terminating         0               10s
15:25:11.165328   +10.227s vm.udev        KERNEL[337689.627001] offline  /devices/system/memory/memory202 (memory)
15:25:11.167062   +10.229s vm.udev        KERNEL[337689.628964] offline  /devices/system/memory/memory203 (memory)
15:25:11.168915   +10.230s vm.udev        KERNEL[337689.630697] offline  /devices/system/memory/memory204 (memory)
15:25:11.220809   +10.282s vm.udev        KERNEL[337689.682572] offline  /devices/system/memory/memory205 (memory)
15:25:11.240251   +10.302s vm.udev        KERNEL[337689.701975] remove   /devices/system/memory/memory202 (memory)
15:25:11.240719   +10.302s vm.udev        KERNEL[337689.702547] remove   /devices/system/memory/memory203 (memory)
15:25:11.241097   +10.303s vm.udev        KERNEL[337689.702929] remove   /devices/system/memory/memory204 (memory)
15:25:11.241276   +10.303s vm.udev        KERNEL[337689.703160] remove   /devices/system/memory/memory205 (memory)
15:25:11.243535   +10.305s vm.udev        KERNEL[337689.704287] remove   /devices/system/node/node2 (node)
15:25:11.243546   +10.305s vm.udev        KERNEL[337689.704611] unbind   /devices/platform/ACPI0017:00/root0/decoder0.0/region0/dax_region0/dax0.0 (dax)
15:25:11.243561   +10.305s vm.udev        KERNEL[337689.704731] remove   /devices/platform/ACPI0017:00/root0/decoder0.0/region0/dax_region0/dax0.0 (dax)
15:25:11.243571   +10.305s vm.udev        KERNEL[337689.704844] unbind   /devices/platform/ACPI0017:00/root0/decoder0.0/region0/dax_region0 (cxl)
15:25:11.243583   +10.305s vm.udev        KERNEL[337689.704960] remove   /devices/platform/ACPI0017:00/root0/decoder0.0/region0/dax_region0 (cxl)
15:25:11.243594   +10.305s vm.udev        KERNEL[337689.705154] unbind   /devices/platform/ACPI0017:00/root0/decoder0.0/region0 (cxl)
15:25:11.332727   +10.394s vm.udev        KERNEL[337689.793797] remove   /devices/platform/ACPI0017:00/root0/decoder0.0/region0 (cxl)
15:25:11.352566   +10.414s vm.udev        KERNEL[337689.814328] remove   /devices/platform/ACPI0017:00/root0/port2/port3/endpoint4/decoder4.3 (cxl)
15:25:11.353173   +10.415s vm.udev        KERNEL[337689.815002] remove   /devices/platform/ACPI0017:00/root0/port2/port3/endpoint4/decoder4.2 (cxl)
15:25:11.353686   +10.415s vm.udev        KERNEL[337689.815562] remove   /devices/platform/ACPI0017:00/root0/port2/port3/endpoint4/decoder4.1 (cxl)
15:25:11.353754   +10.415s vm.udev        KERNEL[337689.815722] remove   /devices/platform/ACPI0017:00/root0/port2/port3/endpoint4/decoder4.0 (cxl)
15:25:11.354096   +10.416s vm.udev        KERNEL[337689.816044] unbind   /devices/platform/ACPI0017:00/root0/port2/port3/endpoint4 (cxl)
15:25:11.354363   +10.416s vm.udev        KERNEL[337689.816349] remove   /devices/platform/ACPI0017:00/root0/port2/port3/endpoint4 (cxl)
15:25:11.356111   +10.418s vm.udev        KERNEL[337689.818019] remove   /devices/platform/ACPI0017:00/root0/port2/port3/decoder3.3 (cxl)
15:25:11.357450   +10.419s vm.udev        KERNEL[337689.819097] remove   /devices/platform/ACPI0017:00/root0/port2/port3/decoder3.2 (cxl)
15:25:11.357484   +10.419s vm.udev        KERNEL[337689.819223] remove   /devices/platform/ACPI0017:00/root0/port2/port3/decoder3.1 (cxl)
15:25:11.357528   +10.419s vm.udev        KERNEL[337689.819440] remove   /devices/platform/ACPI0017:00/root0/port2/port3/decoder3.0 (cxl)
15:25:11.357543   +10.419s vm.udev        KERNEL[337689.819548] unbind   /devices/platform/ACPI0017:00/root0/port2/port3 (cxl)
15:25:11.357944   +10.420s vm.udev        KERNEL[337689.819657] remove   /devices/platform/ACPI0017:00/root0/port2/port3 (cxl)
15:25:11.357958   +10.420s vm.udev        KERNEL[337689.819939] unbind   /devices/pci0000:0c/0000:0c:00.0/0000:0d:00.0/0000:0e:00.0/0000:0f:00.0/mem0 (cxl)
15:25:11.413460   +10.475s vm.pods        MODIFIED   cxl-pool-demo   pooled-consumer                                                0/1   Completed           0               11s
15:25:11.428314   +10.490s vm.claims      MODIFIED claim cxl-pool-demo/pooled-memory uid=fbafbd77 allocated=- node=- reservedFor=- status=-
15:25:11.660242   +10.722s vm.driver      I1006 12:25:11.122495  122109 pool.go:437] cxl-pool.generic: released mem0 (serial 0xc1ee0001)
15:25:11.660257   +10.722s vm.driver      I1006 12:25:11.122551  122109 pool.go:472] cxl-pool.generic: unprepared claim cxl-pool-demo/pooled-memory (fbafbd77-a942-461d-991e-683193da3256)
15:25:11.660346   +10.722s vm.driver      I1006 12:25:11.326382  122109 driver.go:485] rescanAndPublish: published updated resources (1 devices)
15:25:11.719608   +10.781s vm.pods        MODIFIED   cxl-pool-demo   pooled-consumer                                                0/1   Completed           0               11s
15:25:11.727643   +10.789s vm.pods        DELETED    cxl-pool-demo   pooled-consumer                                                0/1   Completed           0               11s
15:25:11.959739   +11.021s server         fake-cxl-pool: 2026/10/06 15:25:11.959544 attachment pooled0@n4-cxl-shared-2-fedora-43-containerd: detaching qemu device fcp_pooled0.hp1
15:25:12.118088   +11.180s vm.claims      DELETED claim cxl-pool-demo/pooled-memory uid=fbafbd77 allocated=- node=- reservedFor=- status=-
15:25:17.198704   +16.260s vm.udev        KERNEL[337695.660281] remove   /devices/pci0000:0c/0000:0c:00.0/0000:0d:00.0/0000:0e:00.0/0000:0f:00.0/mem0 (cxl)
15:25:17.577265   +16.639s vm.driver      I1006 12:25:17.165008  122109 driver.go:485] rescanAndPublish: published updated resources (1 devices)
15:25:18.232959   +17.295s server         fake-cxl-pool: 2026/10/06 15:25:18.232417 qmp /home/akervine/github.com/containers/nri-plugins/test/e2e/n4-cxl-shared-2-fedora-43-containerd/qmp.sock: event DEVICE_DELETED {"device": "fcp_pooled0.hp1", "path": "/machine/peripheral/fcp_pooled0.hp1"}
15:25:18.241610   +17.303s server         fake-cxl-pool: 2026/10/06 15:25:18.241477 attachment pooled0@n4-cxl-shared-2-fedora-43-containerd: detached (qemu device fcp_pooled0.hp1)
15:25:18.253376   +17.315s vm.events      cxl-pool-demo   ResourceClaim   pooled-memory     Detached                   pooled0 detached from n4-cxl-shared-2-fedora-43-containerd (node n4-cxl-shared-2-fedora-43-containerd)
15:25:18.497853   +17.559s vm.controller  fake-cxl-pool-controller: 2026/10/06 12:25:18.007617 detached pooled0 from n4-cxl-shared-2-fedora-43-containerd (node n4-cxl-shared-2-fedora-43-containerd, owner k8s:resourceclaim/fbafbd77-a942-461d-991e-683193da3256)
```

### Trace summary, test11-dra-sharing (final run, udev lines left out here; full file test11-dra-sharing-final.trace-summary.txt)
```
# What every component did in test11-dra-sharing, in order.
# Times are host clock receipt times: the host stamped each line when it
# arrived. Lines from the VMs come over ssh, which adds a few ms; there is
# no VM clock skew. +s is seconds since the first line below.
# Tags: server = fake-cxl-pool-server on the host; <vm>.controller =
# fake-cxl-pool-controller, <vm>.driver = kubelet-cxl-plugin, <vm>.scheduler,
# <vm>.kubelet, <vm>.events, <vm>.claims (ResourceClaim changes), <vm>.pods,
# <vm>.udev (kernel uevents) of the VMs: vm = n4-cxl-shared-2-fedora-43-containerd vm1 = n4-cxl-shared-1-fedora-43-containerd .
# The full trace is trace.txt.
15:26:22.346620    +0.000s vm1.claims      ADDED claim cxl-pool-demo/shared-memory uid=40fdd370 allocated=- node=- reservedFor=- status=-
15:26:22.808199    +0.462s vm1.pods        ADDED      cxl-pool-demo   writer                                                         0/1   Pending   0               0s
15:26:22.821943    +0.475s vm1.pods        MODIFIED   cxl-pool-demo   writer                                                         0/1   Pending   0               0s
15:26:22.838128    +0.492s vm1.claims      MODIFIED claim cxl-pool-demo/shared-memory uid=40fdd370 allocated=cxl-pool.generic/fake-cxl-pool/shared0 node=n4-cxl-shared-1-fedora-43-containerd reservedFor=writer status=-
15:26:22.846750    +0.500s vm1.events      cxl-pool-demo   Pod   writer   BindingConditionsPending   waiting for binding conditions for device on node n4-cxl-shared-1-fedora-43-containerd
15:26:22.886902    +0.540s server          fake-cxl-pool: 2026/10/06 15:26:22.886767 attachment shared0@n4-cxl-shared-1-fedora-43-containerd: attaching to slot cxlsw_ds0_usrp0hb0 as fcp_shared0.hp1 (backend fcp_shared0.hp1, serial 0xc1ae0001)
15:26:22.918828    +0.572s server          fake-cxl-pool: 2026/10/06 15:26:22.918696 attachment shared0@n4-cxl-shared-1-fedora-43-containerd: attached
15:26:22.945817    +0.599s vm1.claims      MODIFIED claim cxl-pool-demo/shared-memory uid=40fdd370 allocated=cxl-pool.generic/fake-cxl-pool/shared0 node=n4-cxl-shared-1-fedora-43-containerd reservedFor=writer status=shared0:cxl-pool.generic/Attached=True,shared0:serial=0xc1ae0001
15:26:22.952107    +0.605s vm1.events      cxl-pool-demo   ResourceClaim   shared-memory   Attached                   shared0 attached to n4-cxl-shared-1-fedora-43-containerd (slot cxlsw_ds0_usrp0hb0)
15:26:23.068000    +0.721s vm1.controller  fake-cxl-pool-controller: 2026/10/06 12:26:22.688363 attached shared0 to n4-cxl-shared-1-fedora-43-containerd (node n4-cxl-shared-1-fedora-43-containerd, slot cxlsw_ds0_usrp0hb0, qemu device fcp_shared0.hp1, owner k8s:resourceclaim/40fdd370-bb6f-446c-a8be-d4e03f782a52) for cxl-pool-demo/shared-memory
15:26:23.068041    +0.721s vm1.controller  fake-cxl-pool-controller: 2026/10/06 12:26:22.708636 status of claim cxl-pool-demo/shared-memory device shared0 node n4-cxl-shared-1-fedora-43-containerd: cxl-pool.generic/Attached=True reason Attached: shared0 attached to n4-cxl-shared-1-fedora-43-containerd (slot cxlsw_ds0_usrp0hb0)
15:26:23.567121    +1.221s vm1.driver      I1006 12:26:23.153957   71289 driver.go:485] rescanAndPublish: published updated resources (1 devices)
15:26:27.849097    +5.502s vm1.pods        MODIFIED   cxl-pool-demo   writer                                                         0/1   Pending   0               5s
15:26:27.855094    +5.508s vm1.events      cxl-pool-demo   Pod             writer          Scheduled                  Successfully assigned cxl-pool-demo/writer to n4-cxl-shared-1-fedora-43-containerd
15:26:27.870311    +5.524s vm1.pods        MODIFIED   cxl-pool-demo   writer                                                         0/1   ContainerCreating   0               5s
15:26:28.561165    +6.215s vm1.driver      I1006 12:26:28.014129   71289 pool.go:267] cxl-pool.generic: claim cxl-pool-demo/shared-memory: prepared shared0 (serial 0xc1ae0001, shared true) as mem0 region0 dax dax0.0 node -1
15:26:28.561223    +6.215s vm1.driver      I1006 12:26:28.212912   71289 node_state.go:213] - ignoring region device "region0": pool device (cxl-pool.generic), memory device serial 0xc1ae0001
15:26:28.561276    +6.215s vm1.driver      I1006 12:26:28.213052   71289 driver.go:485] rescanAndPublish: published updated resources (1 devices)
15:26:28.572464    +6.226s vm1.events      cxl-pool-demo   Pod             writer          Pulled                     Container image "docker.io/library/python:3-alpine" already present on machine and can be accessed by the pod
15:26:28.579387    +6.233s vm1.pods        MODIFIED   cxl-pool-demo   writer                                                         0/1   ContainerCreating   0               6s
15:26:28.621275    +6.275s vm1.events      cxl-pool-demo   Pod             writer          Created                    Container created
15:26:28.714898    +6.368s vm1.events      cxl-pool-demo   Pod             writer          Started                    Container started
15:26:28.728899    +6.382s vm1.pods        MODIFIED   cxl-pool-demo   writer                                                         1/1   Running             0               6s
15:26:31.915981    +9.569s vm.claims       ADDED claim cxl-pool-demo/shared-memory uid=bcc69879 allocated=- node=- reservedFor=- status=-
15:26:32.369976   +10.023s vm.pods         ADDED      cxl-pool-demo   reader                                                         0/1   Pending   0               0s
15:26:32.380247   +10.034s vm.pods         MODIFIED   cxl-pool-demo   reader                                                         0/1   Pending   0               0s
15:26:32.394555   +10.048s vm.claims       MODIFIED claim cxl-pool-demo/shared-memory uid=bcc69879 allocated=cxl-pool.generic/fake-cxl-pool/shared0 node=n4-cxl-shared-2-fedora-43-containerd reservedFor=reader status=-
15:26:32.403945   +10.057s vm.events       cxl-pool-demo   Pod   reader   BindingConditionsPending   waiting for binding conditions for device on node n4-cxl-shared-2-fedora-43-containerd
15:26:32.458538   +10.112s server          fake-cxl-pool: 2026/10/06 15:26:32.458365 attachment shared0@n4-cxl-shared-2-fedora-43-containerd: attaching to slot cxlsw_ds0_usrp0hb0 as fcp_shared0.hp1 (backend fcp_shared0.hp1, serial 0xc1ae0001)
15:26:32.478137   +10.132s server          fake-cxl-pool: 2026/10/06 15:26:32.477626 attachment shared0@n4-cxl-shared-2-fedora-43-containerd: attached
15:26:32.500644   +10.154s vm.claims       MODIFIED claim cxl-pool-demo/shared-memory uid=bcc69879 allocated=cxl-pool.generic/fake-cxl-pool/shared0 node=n4-cxl-shared-2-fedora-43-containerd reservedFor=reader status=shared0:cxl-pool.generic/Attached=True,shared0:serial=0xc1ae0001
15:26:32.509733   +10.163s vm.events       cxl-pool-demo   ResourceClaim   shared-memory   Attached                   shared0 attached to n4-cxl-shared-2-fedora-43-containerd (slot cxlsw_ds0_usrp0hb0)
15:26:32.632220   +10.286s vm.controller   fake-cxl-pool-controller: 2026/10/06 12:26:32.244958 attached shared0 to n4-cxl-shared-2-fedora-43-containerd (node n4-cxl-shared-2-fedora-43-containerd, slot cxlsw_ds0_usrp0hb0, qemu device fcp_shared0.hp1, owner k8s:resourceclaim/bcc69879-83ee-4f62-bc7f-00782c509a30) for cxl-pool-demo/shared-memory
15:26:32.632257   +10.286s vm.controller   fake-cxl-pool-controller: 2026/10/06 12:26:32.264571 status of claim cxl-pool-demo/shared-memory device shared0 node n4-cxl-shared-2-fedora-43-containerd: cxl-pool.generic/Attached=True reason Attached: shared0 attached to n4-cxl-shared-2-fedora-43-containerd (slot cxlsw_ds0_usrp0hb0)
15:26:33.126446   +10.780s vm.driver       I1006 12:26:32.710698  129348 driver.go:485] rescanAndPublish: published updated resources (1 devices)
15:26:37.405456   +15.059s vm.pods         MODIFIED   cxl-pool-demo   reader                                                         0/1   Pending   0               5s
15:26:37.410238   +15.064s vm.events       cxl-pool-demo   Pod             reader          Scheduled                  Successfully assigned cxl-pool-demo/reader to n4-cxl-shared-2-fedora-43-containerd
15:26:37.423108   +15.076s vm.pods         MODIFIED   cxl-pool-demo   reader                                                         0/1   ContainerCreating   0               5s
15:26:38.060672   +15.714s vm.driver       I1006 12:26:37.778965  129348 node_state.go:213] - ignoring region device "region0": pool device (cxl-pool.generic), memory device serial 0xc1ae0001
15:26:38.060730   +15.714s vm.driver       I1006 12:26:37.779126  129348 driver.go:485] rescanAndPublish: published updated resources (1 devices)
15:26:38.060754   +15.714s vm.driver       I1006 12:26:37.782849  129348 pool.go:267] cxl-pool.generic: claim cxl-pool-demo/shared-memory: prepared shared0 (serial 0xc1ae0001, shared true) as mem0 region0 dax dax0.0 node -1
15:26:38.319911   +15.973s vm.driver       I1006 12:26:37.985778  129348 node_state.go:213] - ignoring region device "region0": pool device (cxl-pool.generic), memory device serial 0xc1ae0001
15:26:38.319977   +15.973s vm.driver       I1006 12:26:37.985908  129348 driver.go:485] rescanAndPublish: published updated resources (1 devices)
15:26:38.333297   +15.987s vm.events       cxl-pool-demo   Pod             reader          Pulled                     Container image "docker.io/library/python:3-alpine" already present on machine and can be accessed by the pod
15:26:38.337165   +15.991s vm.pods         MODIFIED   cxl-pool-demo   reader                                                         0/1   ContainerCreating   0               6s
15:26:38.387558   +16.041s vm.events       cxl-pool-demo   Pod             reader          Created                    Container created
15:26:38.491064   +16.144s vm.events       cxl-pool-demo   Pod             reader          Started                    Container started
15:26:38.504009   +16.157s vm.pods         MODIFIED   cxl-pool-demo   reader                                                         1/1   Running             0               6s
15:26:42.228373   +19.882s vm1.pods        MODIFIED   cxl-pool-demo   writer                                                         1/1   Terminating         0               19s
15:26:42.236134   +19.890s vm1.events      cxl-pool-demo   Pod             writer          Killing                    Stopping container writer
15:26:42.245739   +19.899s vm1.pods        MODIFIED   cxl-pool-demo   writer                                                         1/1   Terminating         0               20s
15:26:42.888860   +20.542s vm1.pods        MODIFIED   cxl-pool-demo   writer                                                         0/1   Completed           0               20s
15:26:42.904119   +20.557s vm1.claims      MODIFIED claim cxl-pool-demo/shared-memory uid=40fdd370 allocated=- node=- reservedFor=- status=-
15:26:43.128787   +20.782s vm1.driver      I1006 12:26:42.592937   71289 pool.go:437] cxl-pool.generic: released mem0 (serial 0xc1ae0001)
15:26:43.128801   +20.782s vm1.driver      I1006 12:26:42.592987   71289 pool.go:472] cxl-pool.generic: unprepared claim cxl-pool-demo/shared-memory (40fdd370-bb6f-446c-a8be-d4e03f782a52)
15:26:43.128894   +20.782s vm1.driver      I1006 12:26:42.797343   71289 driver.go:485] rescanAndPublish: published updated resources (1 devices)
15:26:43.357327   +21.011s vm1.pods        MODIFIED   cxl-pool-demo   writer                                                         0/1   Completed           0               21s
15:26:43.362411   +21.016s vm1.pods        DELETED    cxl-pool-demo   writer                                                         0/1   Completed           0               21s
15:26:43.431230   +21.085s server          fake-cxl-pool: 2026/10/06 15:26:43.430671 attachment shared0@n4-cxl-shared-1-fedora-43-containerd: detaching qemu device fcp_shared0.hp1
15:26:43.758137   +21.412s vm1.claims      DELETED claim cxl-pool-demo/shared-memory uid=40fdd370 allocated=- node=- reservedFor=- status=-
15:26:48.859664   +26.513s vm1.driver      I1006 12:26:48.428261   71289 driver.go:485] rescanAndPublish: published updated resources (1 devices)
15:26:49.496197   +27.150s server          fake-cxl-pool: 2026/10/06 15:26:49.495992 qmp /home/akervine/github.com/containers/nri-plugins/test/e2e/n4-cxl-shared-1-fedora-43-containerd/qmp.sock: event DEVICE_DELETED {"device": "fcp_shared0.hp1", "path": "/machine/peripheral/fcp_shared0.hp1"}
15:26:49.504632   +27.158s server          fake-cxl-pool: 2026/10/06 15:26:49.504490 attachment shared0@n4-cxl-shared-1-fedora-43-containerd: detached (qemu device fcp_shared0.hp1)
15:26:49.517985   +27.171s vm1.events      cxl-pool-demo   ResourceClaim   shared-memory   Detached                   shared0 detached from n4-cxl-shared-1-fedora-43-containerd (node n4-cxl-shared-1-fedora-43-containerd)
15:26:49.748141   +27.402s vm1.controller  fake-cxl-pool-controller: 2026/10/06 12:26:49.270768 detached shared0 from n4-cxl-shared-1-fedora-43-containerd (node n4-cxl-shared-1-fedora-43-containerd, owner k8s:resourceclaim/40fdd370-bb6f-446c-a8be-d4e03f782a52)
15:26:51.049926   +28.703s vm.pods         MODIFIED   cxl-pool-demo   reader                                                         1/1   Terminating         0               18s
15:26:51.065748   +28.719s vm.events       cxl-pool-demo   Pod             reader          Killing                    Stopping container reader
15:26:51.081986   +28.735s vm.pods         MODIFIED   cxl-pool-demo   reader                                                         1/1   Terminating         0               18s
15:26:51.580274   +29.234s vm.driver       I1006 12:26:51.343668  129348 pool.go:437] cxl-pool.generic: released mem0 (serial 0xc1ae0001)
15:26:51.580285   +29.234s vm.driver       I1006 12:26:51.343724  129348 pool.go:472] cxl-pool.generic: unprepared claim cxl-pool-demo/shared-memory (bcc69879-83ee-4f62-bc7f-00782c509a30)
15:26:51.629415   +29.283s vm.pods         MODIFIED   cxl-pool-demo   reader                                                         0/1   Completed           0               19s
15:26:51.650110   +29.303s vm.claims       MODIFIED claim cxl-pool-demo/shared-memory uid=bcc69879 allocated=- node=- reservedFor=- status=-
15:26:51.864512   +29.518s vm.driver       I1006 12:26:51.546017  129348 driver.go:485] rescanAndPublish: published updated resources (1 devices)
15:26:52.140810   +29.794s vm.pods         MODIFIED   cxl-pool-demo   reader                                                         0/1   Completed           0               19s
15:26:52.145524   +29.799s vm.pods         DELETED    cxl-pool-demo   reader                                                         0/1   Completed           0               19s
15:26:52.180068   +29.833s server          fake-cxl-pool: 2026/10/06 15:26:52.179890 attachment shared0@n4-cxl-shared-2-fedora-43-containerd: detaching qemu device fcp_shared0.hp1
15:26:52.542538   +30.196s vm.claims       DELETED claim cxl-pool-demo/shared-memory uid=bcc69879 allocated=- node=- reservedFor=- status=-
15:26:57.650259   +35.304s vm.driver       I1006 12:26:57.265367  129348 driver.go:485] rescanAndPublish: published updated resources (1 devices)
15:26:58.328785   +35.982s server          fake-cxl-pool: 2026/10/06 15:26:58.328365 qmp /home/akervine/github.com/containers/nri-plugins/test/e2e/n4-cxl-shared-2-fedora-43-containerd/qmp.sock: event DEVICE_DELETED {"device": "fcp_shared0.hp1", "path": "/machine/peripheral/fcp_shared0.hp1"}
15:26:58.336965   +35.990s server          fake-cxl-pool: 2026/10/06 15:26:58.336825 attachment shared0@n4-cxl-shared-2-fedora-43-containerd: detached (qemu device fcp_shared0.hp1)
15:26:58.351147   +36.005s vm.events       cxl-pool-demo   ResourceClaim   shared-memory   Detached                   shared0 detached from n4-cxl-shared-2-fedora-43-containerd (node n4-cxl-shared-2-fedora-43-containerd)
15:26:58.553500   +36.207s vm.controller   fake-cxl-pool-controller: 2026/10/06 12:26:58.103409 detached shared0 from n4-cxl-shared-2-fedora-43-containerd (node n4-cxl-shared-2-fedora-43-containerd, owner k8s:resourceclaim/bcc69879-83ee-4f62-bc7f-00782c509a30)
```
