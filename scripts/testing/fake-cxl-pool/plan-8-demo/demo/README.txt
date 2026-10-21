CXL memory sharing: the live demo (presenter's guide)
=====================================================
One sentence: "a container asks for CXL memory while it runs; the
scheduler gives it a share of a device only when the rules allow; the
node maps the device into the container; every sharer sees the same
bytes; readers cannot write". Two scripts tell it, each with one writer
and three readers:
  local  all four pods on vm2 share vm2's own CXL memory device (1Gi);
  pool   the writer on vm1, readers on vm2 and vm1 share shared0 (256Mi)
         of the memory pool, hot-plugged into the nodes as needed.
The design is ../03-demo-design.txt; this file says how to run it.
"demo" below is bin/demo of this directory (alias demo=$PWD/bin/demo).

1. Prerequisites (once, before the day)
---------------------------------------
- The three VMs, one cluster (vm2 = n4-cxl-shared-2, control plane; vm1 =
  n4-cxl-shared-1 and vm0 = n4-cxl-shared-0, workers), in N/test/e2e
  (N = the nri-plugins tree). vm0 is the second worker; the demo's pool
  (pool A) is cabled to vm1 and vm2 only, vm0 stays idle for it:
    cd N/test/e2e
    ./run_tests.sh memory.test-suite/dra-driver-cxl/n4-cxl-shared-1/test00-up
    ./run_tests.sh memory.test-suite/dra-driver-cxl/n4-cxl-shared-0/test00-up
    ./run_tests.sh memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/test00-up
  (the patched qemu, see .github/skills/run-e2e-tests/SKILL.md, qemu_bin).
- The driver image with shared local devices (sharedDevices, plan-9):
    cd N && make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images
- Nothing else runs on the VMs: no run_tests.sh, no other
  fake-cxl-pool-server (port 9909). demo refuses to start a setup while
  run_tests.sh runs.
- Host tools: bash, python3, ssh, curl (nothing to install).
- Desk check of this directory: "demo selftest" renders every view from
  testdata/ and checks that it fits 50 x 10.

2. Setup, teardown, reset
-------------------------
  demo setup local      (or: demo setup pool) about 2-4 minutes
  demo teardown         about 1-2 minutes; leaves all VMs clean
  demo reset local      (or pool) deletes the demo pods and their leases:
                        start the script again from step 1
Setup runs the e2e framework (run_tests.sh on e2e/demo.test-suite, whose
helper files are links to memory.test-suite/dra-driver-cxl): it checks
the cluster shape (now three nodes; vm0 is the second worker, pool A
reaches vm1 and vm2 only), starts fake-cxl-pool-server on the host
(local: vm2's local device attached; pool: the device shared0), installs
the driver on every node with helm (local: sharedDevices: [<the serial
of vm2's device>]), starts the pool controller, pulls the images, creates the
ConfigMap demo-tools (/demo/write, /demo/read, /demo/hold, /demo/env in
the pods), copies the manifests to /root/demo in vm2, labels the nodes
cxl-demo/node=vm1|vm2 and starts the trace. Everything stays up until
teardown; run/state.env says what runs. Its log: run/test90-demo-setup.log.
One demo at a time: to switch, "demo teardown" then "demo setup pool".
A failed setup cleans up after itself (the EXIT traps of the e2e helpers).
Teardown unconfigures vm2's shared device first (the driver restarted
without sharedDevices destroys its region), then removes the rest and
checks that neither VM has CXL memory devices left.

3. The screen: 2 columns x 3 rows, each terminal 50 x 10
--------------------------------------------------------
  +---------- T1 ----------+  +---------- T2 ----------+
  | PRESENTER: the steps   |  | PODS & LEASES          |
  +---------- T3 ----------+  +---------- T4 ----------+
  | SCHEDULER: devices and |  | NODES: CXL in the      |
  | claims                 |  | kernel of each node    |
  +---------- T5 ----------+  +---------- T6 ----------+
  | TRACE: one line per    |  | MEMORY (local), POOL   |
  | event                  |  | server (pool)          |
  +------------------------+  +------------------------+
Open six terminals, size each to 50 columns x 10 rows (a title line
ends exactly at column 50), and start (demo commands prints them):
  T1  demo local          (or: demo pool)
  T2  demo view t2
  T3  demo view t3
  T4  demo view t4
  T5  demo view t5
  T6  demo view t6
The views refresh once a second, show the clock in their title and mark
it "stale" when a refresh fails (the last good picture stays). Color is
on in a terminal; "--no-color" (or NO_COLOR=1) turns it off: green
Ready/allocated, yellow waiting, red refused. Ctrl-C stops a view.
Reading order: the right column from the application down to the memory
(T2 -> T4 -> T6), the left column from the action down to why (T1 -> T3
-> T5). Small screen (2 x 2): T1, T2, T3 and T4; zoom the rest.

Emacs alternative (requires installed multi-vterm and a working vterm):
from this demo directory, launch
  emacs --geometry 106x40 -l bin/demo-terminals.el -f cxl-demo-terminals
or M-x load-file bin/demo-terminals.el, then M-x cxl-demo-terminals in
an existing Emacs. For terminal Emacs (-nw), enlarge the outer terminal
first; each pane needs at least 50 columns x 10 content rows, plus Emacs
mode lines and window separators. Larger frames give larger panes.
The command replaces the selected frame's window layout, not its other
buffers. It creates *T1 PRESENTER*, *T2 PODS & LEASES*, *T3 SCHEDULER*,
*T4 NODES*, *T5 TRACE* and *T6 MEMORY / POOL* in the layout above, leaving
T1 selected. Running it again reuses those terminal buffers. New shells
start in this demo directory; run ./bin/demo local (or pool) in T1 and
./bin/demo view t2 through ./bin/demo view t6 in T2-T6. Nothing starts
automatically, so setup and the presenter's steps remain under your
control.

4. T1: running the steps
------------------------
Each step shows its caption and the real command (it runs in vm2, in
/root/demo, whose kubeconfig has the demo namespace cxl-demo):
  Enter  run it          s  skip it        z  zoom (type e.g. "claim reader-a")
  q      stop
then a one or two line result and the time it took. After the result,
Enter goes on, q stops. "demo local 6" runs step 6 alone, "demo local 6-"
from step 6 on. The result lines come from looking at the cluster after
the command (e.g. waiting until the pods Run); the command itself is
never hidden. Full outputs: run/steps.log ("demo zoom last").
Rehearsal: "demo local --auto" runs all steps with pauses
(DEMO_AUTO_PAUSE=2 s) and appends the step timings to run/timings.txt.

5. Script 1: local (S = the serial of vm2's device, e.g. 0xc100e2e1)
---------------------------------------------------------------------
L1 "a writer starts on vm2; it has no CXL memory yet"
   $ kubectl apply -f local/writer.yaml
   Point at: T2 writer Running, lease "-". T3 the device memdev-<S> @vm2
   1Gi shared, "no claims". T4 vm2 mem0 (with region0/dax0.0 if an
   earlier run left them: a shared device keeps them). T6 the bytes there.
L2 "the writer asks for the whole device, exclusively"
   $ kubectl exec writer -- cxl-request request --serial S --mode dax
   T2 writer "dax rw excl". T3 "exclusive: writer rw". T4 region0,
   dax0.0 device_dax. T5 drv "writer asks dax rw excl", api "allocated",
   kern "add region0 dax0.0", drv "zeroed new dax0.0 (once)", drv "lease
   Ready dax0.0". T6 zeros: the driver zeroes a shared device once, when
   it creates its region; a re-run before teardown finds the old line
   (the region is kept while the device is configured shared).
   Say: the lease became a claim (its "companion"), the scheduler
   allocated it like any claim, the node made the device.
L3 "the writer writes a line into the device"
   $ kubectl exec writer -- /demo/write "Hello from the writer, $(date +%T)"
   T6 the line appears. T4 "mapped: writer rw" for 3 seconds (while it
   writes: the tool keeps its mapping that long).
L4 "three readers start"
   $ kubectl apply -f local/readers.yaml
   T2 reader-a..c Running, lease "-".
L5 "readers ask for a read-only share: they must wait"
   $ for r in reader-a reader-b reader-c; do kubectl exec $r -- cxl-request
     request --serial S --shared --read-only --wait 0s; done
   T2 three "waiting". T3 "waiting: reader-a reader-b reader-c". T5 sched
   "reader-a waits: cannot allocate" three times.
   Pause here: the writer holds the device exclusively; nothing moves
   however long we wait. Zooms: "pod reader-a" (the scheduler's
   message), "claim reader-a" (shares: "1", readOnly).
L6 "the writer is done and releases the device"
   $ kubectl exec writer -- cxl-request release --all
   T3 "shared: reader-a ro, reader-b ro, reader-c ro". T2 three "dax ro
   share". T4 dax0.0 stays (the region is kept while the device is
   configured shared). T6 the line is still there.
L7 "each reader reads the line and keeps it mapped"
   $ for r in reader-a reader-b reader-c; do kubectl exec $r -- /demo/read;
     kubectl exec $r -- /demo/hold; done
   T1 "3 readers read at 0: ...". T4 "mapped: reader-a ro, reader-b ro,
   reader-c ro": the kernel's own record (/proc/PID/maps, r--s).
L8 "a reader tries to write: the kernel refuses"
   $ kubectl exec reader-a -- /demo/write "overwrite"
   T1 "refused: read-only (EACCES)" (the step expects the failure). T6
   unchanged. Say: the fd of a read-only lease is opened O_RDONLY; a
   writable mapping is refused whatever the container's privileges.
L9 "everything goes away"
   $ kubectl delete -f local/
   T2 empty. T3 "no claims". T4 region0 and dax0.0 stay, "mapped: -".
   T6 the bytes stay: the next writer finds them (no zeroing).

6. Script 2: pool (shared0, 256Mi, serial 0xc1ae0001)
-----------------------------------------------------
The same nine steps with pool/ manifests and S = 0xc1ae0001: the writer
on vm1, reader-a and reader-b on vm2, reader-c on vm1. T6 is the pool
server: the device, where it is attached, and its bytes as the
"appliance" (the backing file on the host) holds them. What is new:
L1 T6 "shared0 256Mi shared free", "attached: nowhere"; T4 no CXL memory.
L2 the device is hot-plugged into vm1: T6 "attached: vm1 exclusive",
   T4 vm1 mem0 c1ae0001 region0 dax0.0, T5 ctrl "attach shared0 to vm1
   excl", pool "shared0 attached to vm1", kern "vm1 add mem0 ...". The
   lease takes 5-10 s (the scheduler waits for the attach: T5 sched
   "waits for the attach").
L3 T6 shows the line from the host's side: the bytes are in the pool.
L5 T3 "waiting: ..." for readers on both nodes.
L6 shared0 stays on vm1 (now shared) and is attached to vm2 as well
   (about 10 s until all three leases are Ready, the attach included):
   T6 "attached: vm1, vm2", T4 mem0 in both nodes.
L7 T4 "mapped: reader-c ro" on vm1, "reader-a ro, reader-b ro" on vm2.
L9 the device is detached from both nodes: T6 "attached: nowhere",
   state free, the bytes still there.

7. Zooms (in T1: z, or any terminal: demo zoom ...), paged with less
--------------------------------------------------------------------
  demo zoom slice [DEVICE]   the ResourceSlice entry: attributes, the
                             shares capacity (1M, no request policy)
  demo zoom claim POD        the companion claim of POD's lease: request
                             (class, selector, shares), allocation
                             (device, node, consumed shares), config
  demo zoom pod POD          why POD's lease waits (PodScheduled message)
  demo zoom env POD          the CXL_* variables of POD's leases
  demo zoom cdi vm1|vm2      the CDI specs of the node's claims, leases
  demo zoom driver vm1|vm2 [N]  the last N lines of the driver's log
  demo zoom kernel vm1|vm2   dmesg lines of cxl, dax, memory
  demo zoom cxl vm1|vm2      cxl list -M -R -X (memdevs, regions, dax)
  demo zoom pool             the pool server's devices and attachments
  demo zoom bytes            hex dump of the first 256 bytes
  demo zoom last             the full output of the last step

8. When something hangs or goes wrong
-------------------------------------
- A view says "stale": its ssh or kubectl call failed or took over 4 s;
  it retries every second. A view that stays stale: Ctrl-C and start it
  again; check "ssh -F N/test/e2e/n4-cxl-shared-2-fedora-43-containerd/.ssh-config
  node true".
- T3 "drivers: vm2 restarting": the driver pod restarts; wait. The trace
  (T5) of that node's driver stops at a restart (its collector follows
  one pod); the other lines go on.
- A step does not finish: every command has a timeout of 300 s, every
  result check 180 s. Ctrl-C in T1 stops the runner; "demo zoom last"
  shows what the command printed; "demo local N" runs a step again.
- Readers stay "waiting" after L6: "demo zoom pod reader-a" (the
  scheduler's reason), "demo zoom driver vm2".
- Start over in front of the audience: "demo reset local", then
  "demo local" (from L1).
- Anything else: "demo teardown" and "demo setup local" (minutes);
  a teardown that failed can be run again. If a VM is left with CXL
  memory devices, test00-up of that VM (or pool-vm-reset in any e2e
  test) restarts it.

9. Timings and load (rehearsals 2026-10-20, two --auto runs each)
------------------------------------------------------------------
  setup about 1 min, teardown 35-50 s; a whole --auto run 63-67 s.
  local L1-L9: 2.2 0.4-1.1 3.9 2.0 0.7 2.2 2.9-3.1 0.5 2.4-3.1 s
  pool  L1-L9: 2.0-2.2 5.6 4.0 2.0 0.7 10.3 3.2 0.5 1.6-2.0 s
  (L3 includes the writer's 3 s hold; pool L6 the attach to vm2.)
  The four ssh views (T2, T3, T4, T6) at 1 s cost VM2 about 1.1 of its 8
  CPUs (idle: 0.08), mostly kubectl; no refresh went stale during the
  rehearsals. "demo view tN --interval 2" halves a view's share.
  "demo capture LABEL" writes each view once to captures/; captures/ has
  those of the rehearsals at L2, L5, L6, L8 (CASE-runN-LN-tN.txt).

10. Files
---------
  bin/demo            the entry point (bash)
  bin/demo-terminals.el  the Emacs multi-vterm layout
  bin/views.py        the views T2-T6; bin/probe.py runs in the VMs (sent
                      over ssh stdin, one call per node per refresh)
  bin/steps.py        the step runner (T1), bin/zoom.py the zooms
  bin/tools/          the tools in the pods (ConfigMap demo-tools)
  bin/selftest.py     the desk check; testdata/ its samples
                      (make-samples.py writes them; captured-test13/ is
                      a trace and objects of a real e2e run)
  manifests/local, manifests/pool  the pods and the lease claim template
  e2e/                the setup (test90) and teardown (test91) tests
  run/                state, logs and timings of the current demo
