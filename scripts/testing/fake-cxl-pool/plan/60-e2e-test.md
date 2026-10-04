# WS6: e2e test memory.test-suite/memory-policy/n4-cxl-shared-2/test01-shared-cxl

Status: DONE 2026-10-02 18:08 agent E. Steps A-H automated (I dropped, see precondition 7);
PASS twice in a row (runs 3 and 4 below), failure cleanup and VM restart path verified. See Findings.

## Goal
From a test running against VM2 (n4-cxl-shared-2-fedora-43-containerd), use
fake-cxl-pool-client *inside VM2* to attach one shared pool device to both
VM1 (n4-cxl-shared-1-fedora-43-containerd) and VM2, prove the memory is shared
(write in VM1, read in VM2 via devdax), then detach from both.

## Preconditions handled by the test (code.var.sh)
1. VM1 must be up: check `test/e2e/n4-cxl-shared-1-fedora-43-containerd/.ssh-config`
   exists and `ssh -F ... vagrant@node true` works; otherwise try
   `(cd test/e2e/n4-cxl-shared-1-fedora-43-containerd && vagrant up --no-provision)`
   and wait for ssh; if the directory does not exist: error with the message
   "create VM1 first: ./run_tests.sh memory.test-suite/memory-policy/n4-cxl-shared-1/test00-up".
   Helper: `vm2-command` style wrapper = `ssh -F <vm1 ssh-config> vagrant@node sudo bash -c ...`
   (or generalize: a `vm-other-command VMDIR CMD` helper in cxl.source.sh).
2. Patched qemu: `vm-monitor "info version"` on both VMs; require the version
   string of the patched build (contains "v11.1.0-1740" or later / "-dirty"
   is acceptable); else error with instructions (qemu_bin=...).
3. Server: build with `make -C scripts/testing/fake-cxl-pool`; start
   `bin/fake-cxl-pool-server -config $TEST_OUTPUT_DIR/fake-cxl-pool.yaml`
   in the background on the host (log to $TEST_OUTPUT_DIR/fake-cxl-pool-server.log),
   config: pool dir /tmp/fake-cxl-pool, discovery on, one static shared device
   `shared0` 256M serial 0xc1f0ee01 (distinct from the topology's static
   device 0xc1f0ee00, which this test does not use). Kill it at the end (trap).
   `curl -s http://127.0.0.1:9909/api/v1/hosts` must list both VMs.
4. Client: build GOARCH=amd64 CGO_ENABLED=0, vm-put-file to both VMs
   (/usr/local/bin/fake-cxl-pool-client). In both VMs: `fake-cxl-pool-client whoami`
   must return the VM's own name (proves hostname-based resolve and that the
   guest reaches 192.168.76.2:9909).
5. Guest tools: cxl, daxctl installed (cxl-tools-install + dnf install daxctl);
   both VMs start with no CXL memdevs (cxl-reset equivalent on both).
6. Guest kernel has CONFIG_FS_DAX=y (devdax mmap needs it; see
   plan/30 Q4) and the VMs were created with "hdm-for-passthrough": true
   (several regions per host bridge). Check /boot/config-$(uname -r) and
   `vm-qmp qom-get '{"path":"/machine/peripheral/cxlhb0","property":"hdm_for_passthrough"}'`
   (or the Vagrantfile) and error out with recreation instructions otherwise.
7. Detach contract: always `guest release` before `detach`; a detach without
   release leaves a zombie device in qemu until the VM restarts (step I below
   therefore must be the LAST step and must end by restarting that VM with
   vm-reboot, or be dropped: decide to drop I from the automated test and
   document it instead).

## Test steps
A. `fake-cxl-pool-client devices` in VM2 shows shared0 free, shared=true.
B. VM2: `fake-cxl-pool-client attach shared0 --self` -> attached; `guest wait shared0`;
   `cxl-dump`/`cxl list -M` shows mem0 with serial 0xc1f0ee01.
C. VM2: `fake-cxl-pool-client attach shared0 --host n4-cxl-shared-1-fedora-43-containerd`
   -> attached (second attachment of a shared device). In VM1: memdev with the
   same serial appears (`guest wait shared0` run in VM1).
D. Negative: create an exclusive device (`create --size 128M --name excl0`),
   attach to VM2, then attach to VM1 -> exit code 3 / 409 Conflict. Detach,
   delete excl0 (after `guest release excl0` in VM2).
E. Both VMs: `guest region create shared0 --mode devdax` -> /dev/daxX.Y exists,
   bound to device_dax, size 256M.
F. Data: VM1 writes a pattern (python3 mmap of /dev/daxX.Y, e.g. 64 bytes with
   the string "fake-cxl-pool <date> from VM1" at offsets 0 and 128M); VM2 reads
   the same offsets and compares. Then VM2 writes at offset 64M, VM1 reads.
   Also verify on the host: `strings /tmp/fake-cxl-pool/shared0.raw | grep fake-cxl-pool`.
G. Release and detach: both VMs `guest release shared0` (destroy region, disable
   memdev); VM2: `detach shared0 --self` and `detach shared0 --host VM1` ->
   detached; both VMs show no memdevs; server shows shared0 free.
H. Re-attach shared0 to VM2 again and detach (proves the patched qemu's
   re-hotplug path), release first.
I. (dropped from automation, see precondition 7) Negative detach without
   release: qemu never completes it; the attachment becomes "failed" after the
   timeout and the device is quarantined until the VM restarts.

## Output
$TEST_OUTPUT_DIR: server log, client outputs, cxl-dump json from both VMs at
each step (reuse cxl-dump helpers; for VM1 add a label suffix).

## Notes for the implementer
- Follow the style of n4-cxl/test01-pkg-cxl/code.var.sh (echo "### step",
  cxl-assert, error on failure). Keep steps idempotent where cheap.
- The two VMs are on the same host network (slirp) so they cannot talk to each
  other, only to the host; that is why the server is on the host and the test
  drives VM1 through ssh from the host.

## Findings
(agent E, 2026-10-02)

### Files (not committed)
- test/e2e/memory.test-suite/memory-policy/n4-cxl-shared-2/pool.source.sh: topology-level
  helpers. run_tests.sh sources `*.source` and `*.source.*` of the suite, policy, topology and
  test dirs, in that order (source-source-files), so it is sourced for every test of
  n4-cxl-shared-2 (with cxl.source.sh, the symlink to n4-cxl's). Helpers take VMDIR, the output
  dir of a VM: $OUTPUT_DIR = VM2, $POOL_VM1_DIR = VM1 (derived: sibling dir
  n4-cxl-shared-1<suffix of $VM_HOSTNAME>, can be overridden). Script API:
  other-vm-command/-q/other-vm-put-file VMDIR (ssh -F VMDIR/.ssh-config node sudo bash -l,
  command-start/-end like vm-command, prompt root@vm1>, files commands/NNNN-vm1);
  pool-vm-command/-q/-put-file/-qmp/-monitor VMDIR (dispatch to vm-* for VM2; vm-qmp/vm-monitor
  with VM_QMP/VM_MONITOR pointed at VMDIR); pool-host-wait VMDIR HINT (ssh true, else
  vagrant up --no-provision with mkdir of mem-path dirs, wait ssh; error HINT if no VM; checks
  hostname == dir name); pool-vm-restart VMDIR (VM2: vm-reboot; other: shutdown via ssh, poll
  vagrant status, vagrant halt fallback, vagrant up --no-provision); pool-vm-require VMDIR
  TOPOLOGY (preconditions 2 and 6); pool-vm-tools-install; pool-vm-reset VMDIR (restart if qemu
  has any cxl-type3 or the guest any mem*/region*; auto_online_blocks=offline);
  pool-cxl-dump/pool-cxl-wait VMDIR LABEL (VM1 files get suffix .vm1: cxl-dump.LABEL.vm1.json,
  cxl-sysfs..., memory...; cxl-assert works on the last dump of either VM);
  pool-server-start DEVICES_YAML / pool-server-stop / pool-cleanup (EXIT trap);
  pool-client-install VMDIR...; pool-client VMDIR ARGS (client as root in the VM; --server only
  if FAKE_CXL_POOL_PORT != 9909); pool-host-client ARGS; pool-snapshot LABEL (hosts, devices,
  attachments -> pool.LABEL.json); pool-assert/pool-value JSON EXPR (python, j = document);
  pool-file-string FILE OFFSET (host side read of a backing file).
- test/e2e/memory.test-suite/memory-policy/n4-cxl-shared-2/pool-dax-rw.py: `write DEV OFFSET
  TEXT` / `read DEV OFFSET` (NUL-terminated string, offsets with K/M/G), whole device mmapped
  MAP_SHARED; copied to /usr/local/bin of both VMs by pool-client-install.
- test/e2e/memory.test-suite/memory-policy/n4-cxl-shared-2/test01-shared-cxl/code.var.sh: the
  test (replaces the SKIP placeholder).

### Server as the test runs it
`make -C scripts/testing/fake-cxl-pool`, then
`bin/fake-cxl-pool-server -config $TEST_OUTPUT_DIR/fake-cxl-pool.yaml -state $TEST_OUTPUT_DIR/fake-cxl-pool.state.json -v`
(state removed first), log $TEST_OUTPUT_DIR/fake-cxl-pool-server.log. Config: listen
127.0.0.1:${FAKE_CXL_POOL_PORT:-9909}, pool default /tmp/fake-cxl-pool 8G sharable, static
device shared0 256M shared serial 0xc1f0ee01, discovery.names = the two shared VMs only (the
server never touches the QMP sockets of other VMs), detachTimeout 15s. Port busy (bash
/dev/tcp probe) -> error naming FAKE_CXL_POOL_PORT. EXIT trap pool-cleanup: for each
non-adopted attachment `guest release <serial>` in its VM + `detach --host`, `delete --force`
of non-static pool devices, then SIGTERM (SIGKILL after 10 s).

### What the test does (code.var.sh), all assertions as in the spec except where noted
- Preconditions: pool-host-wait VM1 (error "create VM1 first: ./run_tests.sh
  memory.test-suite/memory-policy/n4-cxl-shared-1/test00-up"); pool-vm-require both:
  `vm-qmp qom-get cxlsw_ds0_usrp0hb0 power_controller_present` == true (instead of the
  version string of precondition 2, D16), `qom-get cxlhb0|cxlhb1 hdm_for_passthrough` == true,
  `grep -x CONFIG_FS_DAX=y /boot/config-$(uname -r)`, each failure with fix/recreate
  instructions; tools (cxl-tools-install in VM2, cxl-dump copied to VM1, cxl/daxctl/numactl);
  pool-vm-reset both + cxl-dump no-devices (memdevs == regions == endpoints == []); server up,
  /hosts = both VMs, running, qmp, no error, hotRemoveCapable, 2 host bridges, no attachments;
  client in both VMs, `whoami` = own name.
- A-H as specified. Deviation in D: the spec's 128M is not a valid size (D15): the test checks
  that `create --size 128M` fails (exit 1, "InvalidArgument: size 128M is not a multiple of
  256M"), then uses 256M (serial 0xc1f00001), attach to VM2, attach to VM1 -> exit 3 "Conflict:
  device "excl0" is not shared and it is attached to ...", guest wait + release, detach, delete
  (backing file removed), VM1 never saw it. E also asserts region OnlineSize == 0 (never system
  RAM) and dax size == 256M in both. F: tag "fake-cxl-pool <date+ns>", VM1 writes @0 and @128M,
  VM2 reads both, VM2 writes @64M, VM1 reads it and @0 again; host reads the three strings at
  the same byte offsets of /tmp/fake-cxl-pool/shared0.raw and `strings | grep -F TAG` = 3
  lines. G asserts the memdev is disabled and region gone before detach, no cxl-type3 left in
  either qemu after. H re-attaches with `--slot <slot of B>` (cxlsw_ds0_usrp0hb0): new qemu id
  fcp_shared0.hp3, same slot. End: no attachments, >= 4 `event DEVICE_DELETED` in the server
  log, server stopped, port free.

### Runs (from test/e2e, `./run_tests.sh memory.test-suite/memory-policy/n4-cxl-shared-2/test01-shared-cxl`)
Logs in /home/akervine/.claude/jobs/ws6/run{1,2-injected,3,4}.log.
1. 17:59 PASS on the first try, 77 s.
2. 18:02 temporary `error "WS6 INJECTED FAILURE after step E"` (both VMs attached, devdax
   regions): FAIL as intended; the EXIT trap released shared0 in VM1 and VM2, detached both,
   stopped the server. Afterwards both qemus had 0 cxl-type3, guests no mem*/region*/dax, port
   9909 free. Injection removed (file restored from a copy, diffed).
3. 18:04 leftover device plugged by hand in VM1 qemu (HMP device_add of its own
   beram_cxl_memdev1 as ws6_leftover.hp1, guest mem0): pool-vm-reset restarted VM1
   (`shutdown -h 0` over ssh, vagrant status polled, vagrant up --no-provision, ssh wait,
   ~36 s), then PASS, 113 s.
4. 18:06 PASS, 78 s, nothing to reset. Kept output:
   test/e2e/n4-cxl-shared-2-fedora-43-containerd/memory.test-suite/memory-policy/test01-shared-cxl/
   (run.sh.output, fake-cxl-pool-server.log, fake-cxl-pool.yaml, fake-cxl-pool.state.json,
   pool.{start,shared0-attached,end}.json, cxl-dump/cxl-sysfs/memory.*[.vm1].* per step).
Final lines of run 4:
```
detach excl0 --self took 6.46 s
detach shared0 --self took 6.45 s
detach shared0 --host n4-cxl-shared-1-fedora-43-containerd took 6.49 s
detach shared0 --self took 6.51 s
DEVICE_DELETED events in .../test01-shared-cxl/fake-cxl-pool-server.log: 4
pool-server-stop: stopped fake-cxl-pool-server pid 1898310
Test verdict: PASS
Tests summary:
PASS memory-policy/n4-cxl-shared-2/test01-shared-cxl
```
After run 4: both qemus 0 cxl-type3, guests without mem*/region*, no server process, port
free, state file saved with no devices/attachments. VM1 was restarted once (run 3, on
purpose); no zombie device at any time, no vm-reboot of VM2 needed.

### Problems / notes
- No bug in fake-cxl-pool blocked the test; its code is unchanged.
- Minor: `fake-cxl-pool-client guest --help` prints `error: unknown guest command "--help"`
  (exit 2) instead of the usage; `fake-cxl-pool-client --help` works.
- Server log at start: `local device n4-cxl-shared-2-...memdev1: serial 0xc100e2e1 is already
  used by device "n4-cxl-shared-1-...memdev1"`: the identical topologies give their local beram
  devices the same serial; harmless (local devices of different VMs), informational.
- vm-put-file --cleanup sets `trap ... RETURN EXIT`, which would replace pool-cleanup's EXIT
  trap: the helpers never use --cleanup.
- Timings: detach 6.3-6.5 s each (pciehp 5 s button delay), attach ~30 ms, the whole test
  ~78 s on prepared VMs.
