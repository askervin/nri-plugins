CXL memory sharing: the live demo (presenter's guide)
=====================================================
One sentence: "a container asks for CXL memory while it runs; the
scheduler gives it a share of a device only when the rules allow; the
node maps the device into the container; every sharer sees the same
bytes; readers cannot write". Four scripts tell it, each with one writer
and three readers:
  local  all four pods on vm2 share vm2's own CXL memory device (1Gi);
  pool   the writer on vm1, readers on vm2 and vm1 share shared0 (256Mi)
         of the memory pool, hot-plugged into the nodes as needed;
  pool-shared-fs  the same pods and nodes, shared0 persistent: the writer
         puts an erofs with hello.txt on it as a block device, the readers
         get the file system mounted into their running containers;
  pool-fs  the same pods and nodes, fs0 (512Mi) persistent: the writer
         makes an ext4 (or xfs, btrfs) on it and mounts it read-write;
         vm1's reader shares it at once, vm2's readers wait until the
         writer leaves (ReadWriteOnce).
A wizard shows the rest: every kind of device that the driver offers
(local and pool, volatile and persistent), any claim or lease of it that
the driver accepts, its YAML, created and deleted (section 6d).
The design is N/scripts/testing/fake-cxl-pool/plan-8-demo/03-demo-design.txt
(pool-shared-fs: 12-fs-demo-design.txt there, pool-fs: section 3 of
22-official-design.txt, the wizard: section 4 there; N = the nri-plugins
tree);
this file says how to run it.
This directory is N/test/e2e/memory.test-suite/dra-driver-cxl/
n4-cxl-shared-2/demo01-share-write-read. It is no test: run_tests.sh runs
only the test* directories of a topology, so a run of the suite or of
n4-cxl-shared-2 leaves it alone (its setup leaves the demo up).
"demo" below is bin/demo of this directory (alias demo=$PWD/bin/demo); it
finds N by itself (the nearest directory above with the go.mod of
github.com/containers/nri-plugins), or NRI_PLUGINS_SRC=N.

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
- Host tools: bash, python3, ssh, curl (nothing to install); for
  pool-shared-fs and pool-fs also docker (as for the driver image): setup
  builds the demo image localhost/cxl-demo-tools from image/Dockerfile
  (python:3-alpine with erofs-utils, e2fsprogs, xfsprogs and btrfs-progs,
  through the proxies of
  ~/.docker/config.json) and imports it into vm1 and vm2. The first setup
  takes 20-40 s longer for that; the image is kept on the host and in the
  VMs (the import is skipped when they have it).
- Desk check of this directory: "demo selftest" renders every view from
  testdata/ and checks that it fits 50 x 10.

2. Setup, teardown, reset
-------------------------
  demo setup local      (or: demo setup pool, demo setup pool-shared-fs,
                        demo setup pool-fs [ext4|xfs|btrfs], default ext4,
                        demo setup wizard)
                        about 2-4 minutes (wizard: more, section 6d)
  demo teardown         about 1-2 minutes; leaves all VMs clean
  demo reset local      (or pool, pool-shared-fs, pool-fs) deletes the demo pods and
                        their leases: start the script again from step 1;
                        reset wizard is demo wizard delete --all
Setup runs the e2e framework (run_tests.sh on e2e/demo.test-suite, whose
helper files are links to memory.test-suite/dra-driver-cxl, made again by
every setup and teardown; e2e/lib links to N/test/e2e/lib): it checks
the cluster shape (now three nodes; vm0 is the second worker, pool A
reaches vm1 and vm2 only), starts fake-cxl-pool-server on the host
(local: vm2's local device attached; pool: the device shared0;
pool-shared-fs: shared0 persistent, its files /tmp/fake-cxl-pool/shared0.raw
and shared0.lsa removed first, so that it has no file system; pool-fs:
fs0 persistent, 512Mi, its files fs0.raw and fs0.lsa removed first;
wizard: the devices of section 6d, a second server local-pmem for lp0),
installs
the driver on every node with helm (local: sharedDevices: [<the serial
of vm2's device>]; pool-fs: fsTypes: [erofs, <type>], with the trust note
of section 6c; wizard: fsTypes: [erofs, ext4, xfs, btrfs], the trust note
of section 6d), starts the pool controller, pulls the images
(pool-shared-fs, pool-fs, wizard: imports the demo image), creates the ConfigMap
demo-tools (/demo/write, /demo/read, /demo/hold, /demo/env, /demo/mkfs,
/demo/fswrite in the pods; wizard: /demo/cxl-wizard.py),
copies the manifests to /root/demo in vm2, labels the nodes
cxl-demo/node=vm1|vm2 and starts the trace. Everything stays up until
teardown; run/state.env says what runs. Its log: run/test90-demo-setup.log.
One demo at a time: to switch, "demo teardown" then "demo setup pool".
A failed setup cleans up after itself (the EXIT traps of the e2e helpers).
Teardown unconfigures vm2's shared device first (the driver restarted
without sharedDevices destroys its region), then removes the rest and
checks that neither VM has CXL memory devices left. Before it detaches a
pool device it checks that no filesystem mount, lease bind or loop device
over pmem is left in the VMs: if one is, it stops with a WARNING and the
manual cleanup (releasing a region under a live filesystem can crash the
guest); "demo teardown" again goes on from there. It removes the files of
the persistent shared0 or fs0 at the end (wizard: also of lp0; it detaches
the local devices of both VMs and stops local-pmem).

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
Open six terminals, size each to 50 columns x 10 rows (a view fits the
size of its terminal; captures and the selftest are 50 x 10), and start
(demo commands prints them):
  T1  demo local          (or: demo pool, demo pool-shared-fs, demo pool-fs,
                          demo wizard)
  T2  demo view t2
  T3  demo view t3
  T4  demo view t4
  T5  demo view t5
  T6  demo view t6
The views refresh once a second, show the clock in their title and mark
it "stale" when a refresh fails (the last good picture stays). T5 is a
sequence: it prints its title and the last events once, then each new
event below them, so the terminal scrolls (its scrollback keeps them); a
teardown and a new setup are one line each ("--- 12:00:01 no demo ...",
"--- 12:01:05 new trace: setup pool"), never a new screen. Color is
on in a terminal; "--no-color" (or NO_COLOR=1) turns it off: green
Ready/allocated, yellow waiting, red refused. Ctrl-C stops a view.
Reading order: the right column from the application down to the memory
(T2 -> T4 -> T6), the left column from the action down to why (T1 -> T3
-> T5). Small screen (2 x 2): T1, T2, T3 and T4; zoom the rest.
In pool-shared-fs the steps are F1-F9 (T1 title "F3/9"), in pool-fs
R1-R11 ("R3/11"), L1-L9 in the other two.

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
   message), "claim reader-a" (shares: "1", MemoryConfig device mode dax,
   readOnly true).
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
   T6 "at 0:" shows what the backing file holds from before (setup keeps
   the file of shared0; an e2e test may have left a line there).
L2 the device is hot-plugged into vm1: T6 "attached: vm1 exclusive",
   T4 vm1 mem0 c1ae0001 region0 dax0.0, T5 ctrl "attach shared0 to vm1
   excl", pool "shared0 attached to vm1", kern "vm1 add mem0 ...". The
   lease takes 5-10 s (the scheduler waits for the attach: T5 sched
   "waits for the attach").
L3 T6 shows the line from the host's side: the bytes are in the pool.
L5 T3 "waiting: ..." for readers on both nodes.
L6 shared0 stays on vm1 (now shared) and is attached to vm2 as well
   (about 10 s until all three leases are Ready, the attach included;
   meanwhile T2 "attaching" and T3 "attaching: reader-a reader-b" for the
   readers allocated shared0 whose node does not have it yet):
   T6 "attached: vm1, vm2", T4 mem0 in both nodes, T5 drv "vm1 released
   mem0" (vm1 disables the memdev of the writer), pool "shared0 on vm1:
   not exclusive", "shared0 attached to vm2", ctrl "reader-c: shared0 on
   vm1 already", kern "vm1 bind mem0" (enabled again for reader-c).
L7 T4 "mapped: reader-c ro" on vm1, "reader-a ro, reader-b ro" on vm2.
L9 the drivers release the device ("vm2 released mem0" in T5; T4
   "mem0 c1ae0001 256M  disabled, no region" on both nodes, T6
   "detaching"), then it is detached from both nodes: T6 "attached:
   nowhere", state free, the bytes still there.

6b. Script 3: pool-shared-fs (shared0 persistent, 256Mi, serial 0xc1ae0001)
-----------------------------------------------------------------------------
The pool script once more, with a file system instead of bytes at 0: the
writer gets the device as a block device (an fd of /dev/pmem0, no device
node), makes an erofs with hello.txt and writes it into the device; the
readers ask for the file system read-only and find it mounted at
/run/cxl/fs/hello in their running containers. The pods use the demo
image (mkfs.erofs). S = 0xc1ae0001, the writer on vm1, reader-a and
reader-b on vm2, reader-c on vm1.
F1 "a writer starts on vm1; it has no CXL memory yet"
   $ kubectl apply -f pool-shared-fs/writer.yaml
   T2 writer Running, lease "-". T3 "shared0 @pool 256Mi shared
   persistent", "no claims" (persistent: the pool keeps the bytes in a
   file, the node sees a pmem device). T4 no CXL memory. T6 free,
   "attached: nowhere", "no file system (zeros)".
F2 "the writer asks for the device as a block device"
   $ kubectl exec writer -- cxl-request request --serial S --mode block
   T1 "lease L Ready block rw (exclusive)", "block /dev/pmem0". T2 writer
   "block rw excl". T3 "exclusive: writer rw". T4 vm1 "mem0 c1ae0001
   256M  region0 pmem 256M", "pmem0 254M no file system (block rw)" (on
   a re-run before teardown: "erofs", the device kept the last one; "block
   rw": the writer's node keeps the block device writable). T5 "writer
   asks block rw excl", ctrl and pool attach lines, kern "vm1 add mem0",
   then "vm1 add region0 pmem0", drv "writer: prepared pmem0 rw",
   "writer: lease Ready block pmem0". T6 "attached: vm1 exclusive". The
   lease takes about 5.5 s (attach, region, namespace).
   Say: the lease is a claim of the whole device (exclusive); the node
   made a pmem region and a namespace; the writer got an fd of the block
   device, no device node in the container.
F3 "the writer makes a file system with hello.txt"
   $ kubectl exec writer -- /demo/mkfs "Hello from the writer, $(date +%T)"
   T1 'wrote erofs (8192 bytes) with hello.txt: "Hello from the writer,
   12:01:12"'. T4 "pmem0 254M erofs (block rw)", "open: writer rw" for 3
   seconds (the tool keeps the fd that long), "mounted: -". T6 "erofs:
   hello.txt 32 bytes" and the text: read from the backing file on the host, the
   bytes are in the pool (the block device starts 2 MiB into the device,
   after the namespace's pfn info block; "demo zoom fs" says where).
   Say: mkfs.erofs writes a file; the tool copies it through the fd
   (/proc/self/fd/3 cannot be opened again in the container; the tool
   works in /tmp: /run/cxl of the container is read-only).
F4 "three readers start: two on vm2, one on vm1"
   $ kubectl apply -f pool-shared-fs/readers.yaml
F5 "readers ask for the file system: they must wait"
   $ for r in reader-a reader-b reader-c; do kubectl exec $r -- cxl-request
     request --serial S --shared --read-only --mode fs --name hello
     --wait 0s; done
   T2 three "waiting". T3 "waiting: reader-a reader-b reader-c". T5
   "reader-a waits: cannot allocate" three times. Pause: the writer holds
   the device exclusively. Zoom "claim reader-a" (class
   cxl-pool-persistent, shares "1", config MemoryConfig
   cxl.nri.io/v1alpha1 with device mode fs, readOnly true; access and
   fsType only when the lease asks for them).
F6 "the writer is done and releases the device"
   $ kubectl exec writer -- cxl-request release --all
   T1 "readers' leases Ready after N s". T3 "shared: reader-a ro,
   reader-b ro, reader-c ro". T2 three "fs ro share". T4 both nodes
   "region0 pmem", "pmem0 254M erofs (block ro)" (a node without a writer
   has the block device read-only), "mounted: reader-c (dax)" on vm1,
   "mounted: reader-a reader-b (dax)" on vm2. T5 "vm1 released mem0",
   "shared0 on vm1: not exclusive" (shared0 stays on vm1), the attach to
   vm2, "vm1 bind mem0", "vm2 pmem0
   read-only", "vm2 node mount pmem0
   erofs ro", "reader-a: prepared erofs direct", "reader-a: mounted
   hello", "reader-a: lease Ready fs hello". T6 "attached: vm1, vm2", the
   file system still there.
   Say: each node mounted the erofs once (dax=always: the pages of
   hello.txt are the device's memory) and bound it into the running
   containers at /run/cxl/fs/hello. Zooms "mounts vm2", "fs".
F7 "each reader reads hello.txt from its mount"
   $ for r in reader-a reader-b reader-c; do kubectl exec $r -- cat
     /run/cxl/fs/hello/hello.txt; done
   T1 '3 readers read: "Hello from the writer, 12:01:12"'.
F8 "a reader tries to write: read-only file system"
   $ kubectl exec reader-a -- sh -c 'echo overwrite > /run/cxl/fs/hello/hello.txt'
   T1 "sh: can't create /run/cxl/fs/hello/hello.txt: Read-only file
   system" (the step expects the failure). T6 unchanged.
F9 "everything goes away"
   $ kubectl delete -f pool-shared-fs/
   T2 empty. T3 "no claims". T4 both nodes first "mem0 c1ae0001 256M
   disabled, no region" (released, T6 "detaching"), then "no CXL
   memory". T6 "attached: nowhere", free, "erofs: hello.txt" still
   there: the file system stays
   in the pool's device for the next reader. If a reader still has a file
   of the mount open, T5 says "reader-a: unmount busy, retry" until it is
   closed (kubelet retries the release). T5 "vm2 node mount unmounted"
   when the last reader of a node is gone.

6c. Script 4: pool-fs (fs0 persistent, 512Mi, serial 0xc1ae0001)
-----------------------------------------------------------------
Any filesystem, read-write: the writer formats fs0 with ext4 (or xfs,
btrfs: "demo setup pool-fs xfs") through a block lease, then mounts it
read-write through an fs lease and writes hello.txt; the readers ask for
it read-only. A reader on the writer's node shares its superblock at
once; the readers of the other node wait while the writer writes
(ReadWriteOnce): a single-host filesystem written on one host and read on
another corrupts or misleads. When the writer leaves, its node turns the
filesystem read-only and the other node mounts it. The pods use the demo
image (mkfs.ext4, mkfs.xfs, mkfs.btrfs). S = 0xc1ae0001, the writer on
vm1, reader-a and reader-b on vm2, reader-c on vm1; the filesystem is at
/run/cxl/fs/data in the containers. fs0 has 512Mi because mkfs.xfs needs
300 MB; its block device has 510 MiB (the pfn info block takes 2 MiB).
Trust: setup configures the driver with fsTypes: [erofs, ext4] (the
default is erofs only). ext4, xfs and btrfs are not hardened against
crafted images: a node that mounts them trusts every party that can write
the device raw (a read-write block claim or lease of it, as the writer's
in R2, on any node of any cluster that shares the pool, and a read-write
fs claim). erofs alone trusts nobody (docs/memory/cxl/usage.md,
Filesystems). Setup prints this note.
T2 labels the writer's lease "fs rw (vm1 only)": it is one share of fs0
(readers of vm1 can share it), and the pool attaches fs0 to vm1 alone
while it writes (singleHost in its claim status). "excl" in the other
scripts is a lease of the whole device.
R1 "a writer starts on vm1; it has no CXL memory yet"
   $ kubectl apply -f pool-fs/writer.yaml
   T3 "fs0 @pool 512Mi shared persistent", "no claims". T4 no CXL memory.
   T6 "fs0 512Mi shared persistent free", "attached: nowhere", "no file
   system (zeros)" (setup removed its files; a re-run finds the last
   filesystem).
R2 "the writer asks for the device as a block device"
   $ kubectl exec writer -- cxl-request request --serial S --mode block
   As F2: T1 "lease L Ready block rw (exclusive)", "block /dev/pmem0"; T2
   "block rw excl"; T3 "exclusive: writer rw"; T4 vm1 "mem0 c1ae0001 512M
   region0 pmem 512M", "pmem0 510M no file system (block rw)"; T6
   "attached: vm1 exclusive".
R3 "the writer makes an empty ext4 filesystem on it"
   $ kubectl exec writer -- /demo/mkfs --type ext4
   T1 "wrote an empty ext4 of 510 MiB in 2.1 s". T4 "pmem0 510M ext4
   (block rw)", "open: writer rw" for 3 seconds. T6 'ext4 "demo" 510M,
   clean': read from the backing file on the host, 2 MiB into the device
   ("demo zoom fs").
   Say: mkfs.ext4 makes an image file of the block device's size in the
   container; the tool writes all of it through the fd of the lease (the
   container has no device node) and checks the superblock on the device.
R4 "the writer mounts it read-write instead"
   $ kubectl exec writer -- sh -c 'cxl-request release --all && cxl-request
     request --serial S --shared --mode fs --read-write --name data'
   T1 "lease L Ready ext4 rw (direct)", "path /run/cxl/fs/data", "attached
   to vm1 only (ReadWriteOnce)". T2 writer "fs rw (vm1 only)". T3 "writer
   on vm1 only: writer rw". T4 vm1 "node mount ext4 rw (dax)", "mounted:
   writer (dax rw)". T5 "vm1 writer asks fs rw share", "writer: fs0 excl:
   rw filesystem" (the controller attaches fs0 to vm1 exclusively for a
   read-write filesystem claim; it names the claim's fsType, and the
   lease declares none: the node detects ext4), the release of the block
   lease detaches fs0 from vm1 and the fs lease attaches it again, "vm1
   node mount pmem0 ext4 rw", "vm1 writer: prepared
   ext4 rw direct", "vm1 writer: mounted data", "vm1 writer: lease Ready
   fs data". T6 "attached: vm1 exclusive", 'ext4 ... needs recovery' (the
   journal is in use while a node has it read-write).
   Say: the lease is one share of fs0, so readers can share it; the
   attachment is the node's alone: no other host gets fs0 while vm1
   writes.
R5 "the writer writes hello.txt"
   $ kubectl exec writer -- /demo/fswrite "Hello from the writer, $(date +%T)"
   T1 'wrote /run/cxl/fs/data/hello.txt: "Hello from the writer,
   12:01:30"'. T6 unchanged: the view reads the superblock only, never
   the files of ext4.
R6 "three readers start: two on vm2, one on vm1"
   $ kubectl apply -f pool-fs/readers.yaml
R7 "readers ask to read: vm1's reader at once, vm2's must wait"
   $ for r in reader-a reader-b reader-c; do kubectl exec $r -- cxl-request
     request --serial S --shared --mode fs --name data --wait 0s; done
   T1 "reader-c Ready on vm1, next to the writer", "reader-a reader-b
   waiting: Conflict (N s)". T2 reader-c "fs ro share", reader-a and
   reader-b "waiting (Conflict)". T3 "shared: reader-c ro", "waiting
   (Conflict): reader-a reader-b". T4 vm1 "mounted: reader-c (dax),
   writer (dax rw)" (one superblock: reader-c's bind is read-only), vm2
   no CXL memory. T5 "reader-a: fs0 not on vm2: Conflict" once per
   reader: the scheduler allocates their claims again every 7 seconds
   and the attach to vm2 fails each time; the trace shows it once (the
   reason comes from the controller's AttachFailed condition and Event;
   between the attempts, deallocated or allocated again, "waiting
   (Conflict)" says how the last attempt ended). T6 "attached: vm1
   exclusive".
   Pause here: nothing reaches vm2 while vm1 writes. Zooms "claim
   reader-a" (no allocation, or the AttachFailed condition during an
   attempt), "pod reader-a".
R8 "the writer adds a line; vm1's reader sees it at once"
   $ kubectl exec writer -- /demo/fswrite --append "A second line,
     $(date +%T)"; kubectl exec reader-c -- cat /run/cxl/fs/data/hello.txt
   T1 'reader-c reads it at once: "A second line, 12:02:10"'.
   Say: one node, one superblock: the reader sees what the writer wrote,
   through a read-only bind.
R9 "the writer is done: vm1 turns the filesystem read-only, vm2's readers mount it"
   $ kubectl exec writer -- cxl-request release --all
   T1 "released: L Released", "readers' leases Ready after N s", "vm1:
   ext4 read-only, pmem0 read-only". T2 three "fs ro share". T3 "shared:
   reader-a ro, reader-b ro, reader-c ro". T4 both nodes "pmem0 510M ext4
   (block ro)", "node mount ext4 ro (dax)"; vm2 "mounted: reader-a
   reader-b (dax)". T5 "vm1 writer: unmounted data", "vm1 node mount now
   read-only", "vm1 pmem0 read-only", "fs0 on vm1: not exclusive",
   "reader-a waits: claim deallocated" (the end of the attempt before),
   "reader-c: fs0 on vm1 already" (vm1's attachment kept, no longer
   exclusive), the attach to vm2, "vm2 pmem0 read-only", "vm2 node mount
   pmem0 ext4 ro", "vm2 reader-a: lease Ready fs data" (about 6 s after
   the release). T6 "attached: vm1, vm2", 'ext4 ... clean'.
   Say: the writer's release synced the ext4 and made it read-only on
   vm1 (block device too) before the controller let another host in;
   vm2 reads what vm1 wrote.
R10 "each reader reads hello.txt; a write fails"
   $ for r in reader-a reader-b reader-c; do kubectl exec $r -- cat
     /run/cxl/fs/data/hello.txt; done; kubectl exec reader-a -- sh -c
     'echo x >> /run/cxl/fs/data/hello.txt'
   T1 "3 readers read the same 2 lines", "sh: can't create
   /run/cxl/fs/data/hello.txt: Read-only file system" (the step expects
   the failure).
R11 "everything goes away"
   $ kubectl delete -f pool-fs/
   T2 empty. T3 "no claims". T4 both nodes "no CXL memory" (first
   "disabled, no region" as in F9). T6 "attached: nowhere", free, 'ext4
   "demo" 510M, clean' stays for the next run.
xfs: as ext4 (access direct, dax), T6 'xfs "demo" 510M'. btrfs: no DAX,
so access cached: T4 "node mount btrfs rw (cached loop0)", "mounted:
reader-c (cached), writer (cached rw)", T5 "node mount loop0 btrfs rw",
"vm1 writer: prepared btrfs rw" (the access left out to fit), in R9 also
"vm1 loop0 read-only"; T6 'btrfs "demo" 510M, generation N': the
device's, so a write of the cached access shows when btrfs commits it
(the generation grew from 8 to 9 only at the downgrade of R9).

6d. The wizard: every kind of device, any claim or lease of it
--------------------------------------------------------------
Not a script but a wizard: a few questions choose a pod and its claim (or
lease) among the combinations that the driver accepts, show the YAML,
create it in the demo namespace and delete it again; to demonstrate a
case, and to show what its YAML looks like. "demo setup wizard" makes
every kind of device:
  vm2's local 1Gi and vm1's local 256Mi CXL memory devices: sliced, a
      claim gets a slice of its own (or the whole device); both have the
      serial 0xc100e2e1 (the VMs' topologies), so a claim of that serial
      gets the device of its pod's node;
  lp0 (0xc100f5e1): a persistent local memdev of vm2, 512Mi, through a
      second fake-cxl-pool-server (local-pmem, port 9912) that has no
      pool controller, so the node's driver publishes it as local;
  pool A (cabled to vm1 and vm2): pooled0 (512Mi, exclusive, volatile,
      0xc1ee0001), shared0 (256Mi, shared, volatile, 0xc1ae0001), fs0
      (512Mi, shared, persistent, 0xc1ae0002).
Setup formats fs0 and lp0 with an ext4 holding hello.txt (a block writer
pod of the demo image, manifests/wizard/formatter.yaml), so that fs
claims find something, and configures the driver with fsTypes: [erofs,
ext4, xfs, btrfs]. Trust: ext4, xfs and btrfs are not hardened against
crafted images: a node that mounts them trusts every party that can write
the device raw (a read-write block claim or lease of it, on any node of
any cluster that shares the pool, and a read-write fs claim); erofs alone,
the default, trusts nobody (docs/memory/cxl/usage.md, Filesystems).
Setup prints this note.
T1 runs "demo wizard": fifteen questions, each with its choices numbered,
the default marked "*" (Enter takes it), and the choices that the driver
refuses with the reason ("- numa, dax: a persistent device needs mode
block or fs"); q stops. Then what it asks for in words, the warnings
(the pod will wait, and why), the same as a command line, and "Enter
create, y the YAML, q quit". The same without questions:
  demo wizard new [OPTIONS] [--dry-run]   (--dry-run prints the YAML)
  demo wizard list                        name, kind, state, node,
                                          device, mode, access
  demo wizard yaml NAME                   run/wizard/NAME.yaml
  demo wizard delete NAME...|--all        its pods, claims, leases gone
The options, in the order of the questions ("demo wizard new --help"):
  --kind claim|lease     the pod has a ResourceClaim of the device, or a
                         lease claim, and the wizard runs cxl-request in it
  --source local|pool|any        any: firstAvailable, local then pool
  --memory volatile|persistent
  --sharing exclusive|shared     shared: capacity shares "1"
  --mode numa|dax|block|fs
  --size whole|SIZE              a slice of a local memdev, or the least
                                 size of an exclusive pool device
  --serial any|SERIAL            the published devices that fit are listed
  --read-only|--read-write       dax, block, fs (fs: read-only unless asked)
  --fs-type detect|TYPE  --access default|direct|cached
  --path default|PATH            fs, claims
  --steering none|auto|first-dram|...   numa, claims
  --node vm1|vm2|any             any: a demo node, vm1 or vm2 (a required
                                 node affinity on the label cxl-demo/node);
                                 vm0 is left out: it has no demo image,
                                 no pool cable and no view, although it
                                 publishes a lease device and DRAM too
  --command idle|env|read|write TEXT|mkfs TYPE   (/demo/cxl-wizard.py;
                         mkfs makes an image of the device's size in
                         the container and writes it whole through the
                         device (mkfs on a block device node needs
                         privileges); it puts hello.txt into erofs, ext4
                         and btrfs;
                         an xfs is empty: mkfs.xfs of the demo image
                         crashes with -p, so a read-write fs claim writes
                         hello.txt into it)
  --name NAME                    default w<N>
The rules are the driver's (docs/memory/cxl, pkg/cxl/config/device.go):
- volatile local (sliced): numa (default) or dax, readOnly with dax only,
  a slice of SIZE (rounded up to memory blocks) or the whole device;
- volatile pool, exclusive device (pooled0): numa or dax, the whole
  device, SIZE its least size;
- volatile pool, shared device (shared0): dax only, exclusively (by its
  serial) or one share;
- persistent (lp0, fs0): block or fs only, the whole device, exclusively
  or one share; block read-write only exclusively; fs read-only by
  default, read-write by opt-in (not erofs); a shared persistent device is
  read-write on one node at a time: a pod of another node waits
  (AttachFailed Conflict); access direct for erofs, ext4 and xfs only;
- a lease: the same rules through cxl-request (no path: its filesystem is
  at /run/cxl/fs/NAME; no steering; a request needs a size, a serial or a
  share; a local device only in a pod of its node).
A choice that the devices cannot satisfy now is taken with a warning, and
the pod (or lease) waits: that is how waiting is shown. The YAML of every
object is in run/wizard/NAME.yaml: a comment header that says in words
what it asks for, a ResourceClaim (or the lease's ResourceClaimTemplate)
and a Pod, labels app=cxl-demo-wizard and cxl-demo/wizard=NAME. A claim's
pod runs its command at start (its log has the output); a lease's pod
idles, and the wizard runs cxl-request request ... --wait 0s in it, then
the same with --exec of the command in the background (the pod's log).
demo wizard new waits until the command has ended ("cxl-wizard exit N" in
the pod's log) and ends with "NAME: Running; mkfs xfs exit 0": delete an
object only after that, or a mkfs stops half way and leaves no filesystem.
Point at: T1 the question screens and the YAML header; T2 the wizard's
pods with "claim" or the lease id and what it got ("numa 256Mi c100e2e1",
"dax rw excl shared0", "fs rw share fs0", "block rw excl lp0", "waiting
(Conflict)"); T3 every device with its holders and the waiting claims; T4
both nodes, a row per memdev (region, kmem node, dax device, pmem block
device with its filesystem and ro/rw) and who uses it; T5 the trace; T6
both pool servers: devices, attachments (exclusive), the filesystem state
of fs0 and lp0 in their backing files ("ext4 clean", "ext4 needs
recovery" while a node writes it).
A walk (bin/wizard-rules.sh runs one for every rule and checks each result):
  demo wizard new --name w1 --source local --mode numa --size 256Mi --node vm2
      -> w1: Running; T2 "numa 256Mi c100e2e1", T4 "region0 256M kmem node2"
  demo wizard new --name w12 --source pool --mode dax --serial 0xc1ae0001
      --node vm1 --command write "Hello"
  demo wizard new --name w13 --kind lease --source pool --sharing shared
      --read-only --serial 0xc1ae0001 --node vm2 --command read
      -> w13: waiting: cannot allocate (w12 has shared0 exclusively)
  demo wizard delete w12   -> w13 Ready, its pod's log reads "Hello"
  demo wizard new --name w18 --source pool --memory persistent --sharing
      shared --mode fs --read-write --serial 0xc1ae0002 --node vm1
      -> waits while another node has fs0 (AttachFailed Conflict), then
         vm1 alone has it read-write (T6 "vm1 exclusive; ext4 needs recovery")
  demo wizard yaml w18     -> its claim and pod
  demo wizard delete --all
"demo reset wizard" is "demo wizard delete --all". "demo wizard check"
runs the wizard's desk checks (part of demo selftest).

7. Zooms (in T1: z, or any terminal: demo zoom ...), paged with less
--------------------------------------------------------------------
  demo zoom slice [DEVICE]   the ResourceSlice entry: attributes, the
                             shares capacity (1M, no request policy)
  demo zoom claim POD        the companion claim of POD's lease: request
                             (class, selector, shares), allocation
                             (device, node, consumed shares), config
                             (MemoryConfig cxl.nri.io/v1alpha1); of a
                             pod of the wizard also its ResourceClaim
  demo zoom pod POD          why POD's lease waits (PodScheduled message);
                             of a pod of the wizard also why the pod waits
  demo zoom env POD          the CXL_* variables of POD's leases (fs:
                             CXL_<KEY>_FSTYPE too); of a pod of the wizard
                             also those of its container
  demo zoom cdi vm1|vm2      the CDI specs of the node's claims, leases
  demo zoom driver vm1|vm2 [N]  the last N lines of the driver's log
  demo zoom kernel vm1|vm2   the kernel lines of cxl, dax, memory since
                             demo setup (the journal, the host's clock)
  demo zoom cxl vm1|vm2      cxl list -M -R -X -i (memdevs, also disabled
                             ones, regions, dax)
  demo zoom pool             the pool server's devices and attachments
  demo zoom fs               the erofs in the pool device's backing file:
                             superblock (magic, block size, inodes,
                             blocks, root nid) and the files of the root
                             directory with size and first bytes; in
                             pool-fs the superblock of the ext4, xfs or
                             btrfs (type, size, label, uuid; ext4 state,
                             needs_recovery, mount count and last write
                             time as dumpe2fs says them, features; btrfs
                             generation), no files; in the wizard
                             that of fs0
  demo zoom mounts vm1|vm2   the mounts of the node's pmem block devices
                             (findmnt: mount point and superblock
                             options, ro or rw), the read-only flags of
                             the block devices, loop devices (losetup -l)
                             and lease binds (lease-fs/<lease claim
                             uid>/<name>)
  demo zoom bytes [OFFSET]   hex dump of 256 bytes from OFFSET (default 0);
                             in pool-shared-fs, pool-fs and wizard of the block
                             device in the backing file (1024 is the erofs
                             and the ext4 superblock)
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
- pool-shared-fs: a reader's lease stays "releasing" and T5 says "unmount
  busy, retry": a process of the reader has a file of /run/cxl/fs/hello
  open; it ends with the pod. "demo zoom mounts vm2" shows the mounts.
  Setup says "docker is needed ...": install or start docker on the host.
- pool-fs: readers stay "waiting (Conflict)" after R9: the writer's
  release has not finished (T1 says so); "demo zoom mounts vm1" shows the
  superblock still rw while a file of the writer is open; "demo zoom pod
  reader-a" shows the scheduler's reason.
- pool-fs: R3 says "mkfs.xfs failed" or R4 does not mount: the kernel of
  the VMs lacks a feature of the image's mkfs ("demo zoom kernel vm1",
  "demo zoom driver vm1").
- wizard: a pod stays Pending or "waiting": the warning of "demo wizard
  new" said why; "demo zoom pod wN" (the scheduler), "demo zoom claim wN"
  (the claim and its allocation), "kubectl logs wN" in vm2 (the tool's
  output; of a lease pod that of the background cxl-request). "demo
  wizard delete wN" waits until its leases are gone.
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
  pool-shared-fs (rehearsals 2026-10-22, three --auto runs, s):
        F1-F9: 2.0-2.2 5.6-5.8 3.8-4.0 2.0 0.7-0.8 10.1-10.3 0.6-0.7 0.3-0.4 1.6-2.8
  (F3 includes the writer's 3 s hold of the fd; F6 the attach to vm2.)
  A whole --auto run 73 s; setup 63-67 s
  (the demo image cached), teardown 38 s. No view went stale.
  2026-11-03 (one run each from this directory, driver b0a0eb6c6c91, s):
    local L1-L9  2.1 2.0 3.9 2.1 0.9 2.3 3.2 0.5 3.2; setup 74, teardown 50
    pool  L1-L9  2.1 6.4 4.0 2.2 0.8 11.8 3.3 0.5 2.1; setup 61, teardown 38
    pool-shared-fs F1-F9  2.1 5.6 3.8 2.1 0.9 10.4 0.7 0.4 2.2; setup 65,
                 teardown 36
    pool-fs R1-R11 (ext4 twice, xfs, btrfs; s):
                 2.1 5.6-5.7 6.0-6.1 12.7-12.8 0.5 2.1-2.2 8.0-8.1 0.7
                 5.2-7.9 0.9-1.0 2.0-3.0; setup 65-69, teardown 38
                 (R3: the 510 MiB written in 2.0-2.1 s and the 3 s hold;
                 R4: the block lease's detach and the fs lease's attach;
                 R9: the attach to vm2, ext4 7.9, xfs and btrfs 5.2-5.3)
  The four ssh views (T2, T3, T4, T6) at 1 s cost VM2 about 1.1 of its 8
  CPUs (idle: 0.08), mostly kubectl; no refresh went stale during the
  rehearsals. "demo view tN --interval 2" halves a view's share.
  "demo capture LABEL" writes each view once (50 x 10) to
  captures/CASE-LABEL-tN.txt; "demo truth LABEL" writes the ground truth
  of the moment to captures/CASE-LABEL-truth.txt (kubectl objects, cxl
  list, dax devices, pmem block devices, mounts, mappings and fds of the
  pod processes of both nodes, the pool server and its backing file, the
  trace lines since the last step began), to check every view line
  against; "demo capture LABEL --truth" takes both at the same moment.
  captures/ has those of the pool-shared-fs rehearsals at F2, F3, F5, F6,
  F8 (pool-shared-fs-runN-FN-tN.txt).

10. Files
---------
  bin/demo            the entry point (bash)
  bin/demo-terminals.el  the Emacs multi-vterm layout
  bin/views.py        the views T2-T6; bin/probe.py runs in the VMs (sent
                      over ssh stdin, one call per node per refresh)
  bin/steps.py        the step runner (T1), bin/zoom.py the zooms,
                      bin/truth.py the ground truth (demo truth)
  bin/tools/          the tools in the pods (ConfigMap demo-tools)
  bin/fsinfo.py       the superblock of ext4, xfs, btrfs or erofs at the
                      start of a block device (T6 and zoom fs of pool-fs)
  bin/wizard.py       the wizard (demo wizard); bin/wizard_views.py its
                      views T2, T3, T4, T6; bin/wizard_check.py its desk
                      checks (demo wizard check, part of selftest);
                      bin/wizard-rules.sh the scripted set of every rule
                      (live, or --dry-run at the desk); bin/tools/
                      cxl-wizard.py the tool of its pods
  image/Dockerfile    the demo image of pool-shared-fs and pool-fs
                      (mkfs.erofs, mkfs.ext4, mkfs.xfs, mkfs.btrfs)
  bin/selftest.py     the desk check; testdata/ its samples
                      (make-samples.py writes them with the objects and
                      log lines of the current driver, make-samples-pool-
                      fs.py those of pool-fs; hello.erofs.hex a real
                      image of mkfs.erofs, pool-fs-super.json the
                      superblocks of real empty ext4, xfs and btrfs;
                      make-wizard-samples.py those of the wizard)
  manifests/local, manifests/pool, manifests/pool-shared-fs, manifests/pool-fs
                      the pods and the lease claim template
  manifests/wizard/formatter.yaml
                      the formatter of fs0 and lp0 of demo setup wizard
  e2e/                the setup (test90) and teardown (test91) tests
  run/                state, logs and timings of the current demo
                      (step.env: the last step and its start; wizard/:
                      the YAML of each object of the wizard)
  captures/           demo capture and demo truth
  .gitignore          run/ and captures/ out of git, testdata/ and
                      bin/tools/ in
