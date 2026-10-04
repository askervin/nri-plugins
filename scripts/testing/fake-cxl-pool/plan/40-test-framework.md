# WS4: test framework changes for shared CXL topologies

Status: DONE (recreated) 2026-10-02 17:40 agent B. Both VMs recreated with the
FS_DAX/DMI/evdev kernel and hdm_for_passthrough=on; test00-up PASS on both.
Agent B: append "Findings" and keep "Status" current.

## Goal
Make test/e2e able to launch two VMs (n4-cxl-shared-1, n4-cxl-shared-2) whose
qemu has (a) empty CXL hotplug slots for fake-cxl-pool, (b) optionally a
statically declared shared memory-backend-file device (same file and serial in
both VMs), (c) a QMP socket next to the HMP one, (d) the patched qemu binary.
Keep every existing topology's generated command line byte-identical (verify
with topology2qemuopts.py on the existing topology.var.json files before/after).

## Changes

### 1. test/e2e/lib/topology2qemuopts.py (qemucxlopts)
New optional properties of a CXL memory device entry (`{"mem": "256M", ...}`):
- `"present": false` (exists) - device object created, not plugged at boot.
- `"file": "/abs/path.raw"` - use `memory-backend-file,id=<id>,share=on,mem-path=<file>,size=<mem>` instead
  of memory-backend-ram. Backend id prefix `befile_` instead of `beram_`
  (keep the `__bus_<bus>__sn_<sn>` suffix so vm-cxl-hw keeps working: update
  its regexp to accept both prefixes). Create nothing on the host here; qemu
  creates/extends the file. Document that the directory must exist.
- `"sn": "0x..."` - explicit serial (default stays 0xc100e2e0+N). Needed so
  two VMs expose the same serial for the same file.
- `"shared": true` - documentation/intent flag; implies share=on (already
  always on). Also exported in a machine-readable way if easy (e.g. include
  `__shared` in the id? no: keep ids stable; just document).
New entry kind in a root port list or a switch list:
- `{"pool-slot": "1G"}` - creates only the cxl-downstream (in a switch) or an
  empty cxl-rp (at root port level) with no memory object and no device. The
  size string is added to the maxmem/slots computation (keep the existing
  rule that total CXL memory is added to maxmem; WS3 Q3 will tell if that is
  really needed - if not needed, keep adding it anyway, harmless).
Update the module docstring (the "CXL structures" section) with the new keys
and an example of two VMs sharing one file.

### 2. test/e2e/lib/vm.bash
- Add `"-qmp", "unix:qmp.sock,server,nowait"` to EXTRA_ARGS next to
  "-monitor" (both relative to qemu cwd = output dir). Add `VM_QMP` path
  variable and a `vm-qmp` helper (send one QMP command JSON, print response;
  implement with python3 or socat, handle the capabilities handshake).
- vm-cxl-hw: accept befile_ backends too.
- Wire `qemu_bin`: if env `qemu_bin` is set at VM creation, write
  `qemu.qemu_bin = "<path>"` into the generated Vagrantfile (vagrant-qemu
  0.3.12 supports qemu.qemu_bin; see
  ~/.vagrant.d/gems/3.3.8/gems/vagrant-qemu-0.3.12/lib/vagrant-qemu/driver.rb:85).
  Check test/e2e/files/Vagrantfile.in and the sed in vm.bash that instantiates
  it; add a QEMU_BIN placeholder. Record it in the output dir `env` file so
  `vagrant up` later uses the same binary. Also mention it in
  .github/skills/run-e2e-tests/SKILL.md (already lists qemu_bin; make the
  description accurate).
- A topology may require a qemu binary: support an optional
  `qemu_bin.var.sh`?? No - keep it simple: tests for shared topologies check
  `vm-monitor "info version"` and error out with instructions if the qemu is
  not >= the patched build (WS6 decides the exact check). Nothing to do here
  beyond qemu_bin wiring.

### 3. New topologies
test/e2e/memory.test-suite/memory-policy/n4-cxl-shared-1/ and .../n4-cxl-shared-2/:
- topology.var.json: same CPU/mem as n4-cxl (2 packages, 1 node each, 4G per
  node), CXL: host bridge 0 with a switch of 4 ports: 2x {"pool-slot": "1G"}
  and one statically shared device {"mem": "256M", "present": false,
  "file": "/tmp/fake-cxl-pool/static-shared0.raw", "sn": "0xc1f0ee00", "shared": true}
  and one local {"mem": "256M", "present": false}; host bridge 1 with a
  switch of 4 {"pool-slot": "1G"}. Identical in both topologies.
- kernel_config.var.sh and kernel_getsource.var.sh copied from n4-cxl (same
  content => cached kernel tarball is reused, no rebuild).
- cxl.source.sh: symlink or copy of n4-cxl/cxl.source.sh (prefer: move the
  shared helper functions into memory.test-suite/memory-policy/cxl.source.sh?
  Check how *.source.sh files are discovered (run_tests.sh export-and-source-dir
  walks suite -> policy -> topology -> test dirs). If a policy-level file is
  sourced for all topologies, move it there and leave n4-cxl working.)
- n4-cxl-shared-1/test00-up/code.var.sh: boots the VM (framework does), installs
  kernel pkgs (vm-kernel-pkgs-install), cxl + daxctl tools, verifies
  `vm-qmp '{"execute":"query-version"}'` works and that `vm-cxl-hw` lists the
  static shared device, and that the VM sees no CXL memdevs. Prints the
  qemu binary path and version. PASS criteria: those checks.
- n4-cxl-shared-2/test00-up/code.var.sh: same.
- n4-cxl-shared-2/test01-shared-cxl/: placeholder code.var.sh that SKIPs with
  "implemented in WS6" (do not implement the pool test here).

### 4. Creating the VMs
Run (never in parallel with another run_tests.sh):
  cd test/e2e && qemu_bin=/home/akervine/github.com/qemu/qemu/build/qemu-system-x86_64 \
    ./run_tests.sh memory.test-suite/memory-policy/n4-cxl-shared-1/test00-up
then the same for n4-cxl-shared-2. Make sure /tmp/fake-cxl-pool exists before
(mkdir -p; the test could do it on the host in code.var.sh before vm-setup?
No: the VM is created before the test runs. Put `mkdir -p /tmp/fake-cxl-pool`
into vm.bash where the Vagrantfile is generated if the topology contains
"file" backends: topology2qemuopts.py can emit a `MKDIR:` hint or vm.bash can
grep the generated args for mem-path= and mkdir -p their dirnames. Choose the
grep approach, it is simplest.)
Check the patched qemu runs the VM (ps args), that qmp.sock exists in the
output dir, and that both VMs are up at the same time (ssh via .ssh-config).
Provisioning a VM from the cached box takes a while; the kernel install
reboot is handled by vm-kernel-pkgs-install.

### 5. Do not break
- run existing generator on every topology.var.json under test/e2e and diff
  output before/after your change (store diffs in plan/40-generator-diff.txt;
  must be empty).
- Do not touch running VMs n4c16-*, n4-cxl-fedora-43-crio. The VM
  n4-cxl-fedora-43-containerd may be halted/restarted by agent A (WS3); do
  not use it.

## Deliverables
- Code changes above (not committed; leave in working tree).
- Both VMs created and running with qmp.sock, the patched qemu, and the
  static shared device declared.
- Findings here: exact run_tests.sh commands, timings, the generated qemu
  command lines (copy from ps), problems hit.

## Findings
(agent B appends here)

### Implementation (2026-10-02, agent B)
Files changed (not committed):
- test/e2e/lib/topology2qemuopts.py: CXL mem device keys "file", "sn",
  "shared" (+ validation: unknown keys, absolute comma-free "file", "shared"
  requires "file", 64-bit "sn", duplicate serials); entry {"pool-slot": SIZE}
  in switch and root port lists. Docstring documents all, with a two-VM
  sharing example. File backend: memory-backend-file,id=befile_cxl_memdevN__bus_<bus>__sn_<sn>,share=on,mem-path=<file>,size=<mem>.
  Explicit "sn" is normalized to lowercase "0x%x". Pool slots add their size
  to total CXL memory (=> cxl-fmw.N.size and maxmem) but no -m slots: checked
  in qemu source, cxl-type3 is a plain PCI device, not a TYPE_MEMORY_DEVICE,
  and the fmw is mapped above the device-memory (maxmem) region, so neither
  slots nor maxmem are needed for CXL; maxmem keeps including CXL as before.
- test/e2e/lib/vm.bash:
  - EXTRA_ARGS: "-qmp unix:qmp.sock,server,nowait" AND
    "-qmp unix:qmp-e2e.sock,server,nowait". Reason for two: a qemu QMP
    socket serves ONE client at a time (verified: a 2nd client gets no
    greeting until the 1st disconnects). qmp.sock is for long-lived clients
    (fake-cxl-pool-server), qmp-e2e.sock for vm-qmp, so tests can use QMP
    while the server is connected.
  - "-uuid <uuid5(NAMESPACE_DNS, vm name)>" (coordinator request; if it
    starts with "ec2", hash "<name>-1", "-2", ...). Recorded as VM_UUID= in
    the output dir env file.
  - VM_QMP=$output_dir/qmp-e2e.sock and vm-qmp (script API): `vm-qmp CMD
    [ARGS_JSON]` or `vm-qmp '{"execute":...}'`; python3; does the
    capabilities handshake, skips events, prints the response as one JSON
    line, exit 1 on {"error"}, `error` (test fails) on connect/timeout
    (qmp_timeout, default 30s). Connects with a relative path after chdir:
    absolute socket paths in output dirs are ~107 chars, near the 108 limit.
  - qemu_bin: must be an absolute path of an executable; written to the env
    file as QEMU_BIN="..." when the env file is created (VM creation);
    Vagrantfile.in reads ENV['QEMU_BIN'] (Dotenv, like SSH_PORT) and sets
    qemu.qemu_bin only if non-empty. Warning if qemu_bin is given for an
    existing VM with a different QEMU_BIN. To switch qemu of an existing VM:
    edit QEMU_BIN in <outdir>/env, vagrant halt; vagrant up --no-provision.
  - Before every `vagrant up` in vm-setup: mkdir -p the dirname of every
    mem-path= in the Vagrantfile (on every start, not only at creation:
    /tmp is a tmpfs that a host reboot empties).
  - vm-cxl-hw: accepts be(ram|file)_cxl_memdev* backends.
- test/e2e/files/Vagrantfile.in: QEMU_BIN from env, qemu.qemu_bin.
- test/e2e/files/env.in: QEMU_BIN=, VM_UUID=.
  NOTE: both files are in BOX_RECIPE_FILES, so the change invalidates
  cached boxes (e2e_vm_cache=yes) once; the cache is off by default.
- test/e2e/run_tests.sh: topology filter matches the whole dir name instead
  of a substring. Without this `./run_tests.sh memory.test-suite/memory-policy/n4-cxl`
  would also run (and create VMs for) n4-cxl-shared-1 and -2. TESTS_DIR must
  be an existing dir, so the filter is always a full name anyway; matches
  the documented "execute tests only under TESTS_DIR". Policy and test
  filters left as substring matches (no clashes).
- .github/skills/run-e2e-tests/SKILL.md: qemu_bin description, monitor
  sockets (monitor.sock, qmp-e2e.sock, qmp.sock).
- New: test/e2e/memory.test-suite/memory-policy/n4-cxl-shared-{1,2}/
  topology.var.json (identical), kernel_*.var.sh (copies of n4-cxl),
  cxl.source.sh -> ../n4-cxl/cxl.source.sh (symlink, NOT moved to the policy
  level: n4-cxl/cxl.source.sh is untracked work in progress used by the
  agent running n4-cxl-fedora-43-containerd; moving it under a running
  test would break it. Move later if wanted.), test00-up/code.var.sh (same
  in both), n4-cxl-shared-2/test01-shared-cxl/code.var.sh (SKIP placeholder,
  "Test verdict: SKIP (implemented in WS6)").

Qemu ids in n4-cxl-shared-{1,2} (same in both):
- HB0 (NUMA 0) switch cxlsw_usrp0hb0: cxlsw_ds0_usrp0hb0, cxlsw_ds1_usrp0hb0
  = pool slots (1G); cxlsw_ds2_usrp0hb0 = static shared cxl_memdev0, backend
  befile_cxl_memdev0__bus_cxlsw_ds2_usrp0hb0__sn_0xc1f0ee00
  (/tmp/fake-cxl-pool/static-shared0.raw, 256M); cxlsw_ds3_usrp0hb0 = local
  cxl_memdev1, backend beram_cxl_memdev1__bus_cxlsw_ds3_usrp0hb0__sn_0xc100e2e1.
- HB1 (NUMA 1) switch cxlsw_usrp0hb1: cxlsw_ds{0..3}_usrp0hb1 = pool slots (1G).
- cxl-fmw.0.size=cxl-fmw.1.size=8G, -m size=8G,slots=8,maxmem=15G.
- Buses named in be*_cxl_memdevN__bus_<bus> ids are reserved for those
  declared devices; a pool server should use the other free ports.

Verification before VM creation:
- generator diff empty (40-generator-diff.txt).
- throwaway qemu (patched build, -machine with generated CXL opts, -S): the
  befile_ backend created /tmp/.../x.raw (256M, sparse); vm-qmp
  query-version/query-memdev/qom-list ok while another client held
  qmp.sock; error response -> rv 1; busy socket -> timeout -> error;
  vm-cxl-hw lists befile_ and beram_ devices; vm-cxl-hotplug cxl_memdev0
  (file-backed) -> plugged.
- dry run of vm-setup with stubbed make/vagrant: generated env/Vagrantfile;
  `vagrant validate` ok.

### Late additions (after the first findings above)
- Coordinator request: "-uuid <uuid5(NAMESPACE_DNS, VM name)>" in
  EXTRA_ARGS, VM_UUID= in env (implemented, see Implementation above).
- vm-qemu-pid [VAGRANTDIR] (script API, vm.bash): pid of the qemu of an
  output dir, found as the qemu-system* process whose cmdline contains
  "<outdir>/.vagrant/machines/". Reason, found while creating the VMs:
  * every e2e qemu binds the RELATIVE names monitor.sock (and now qmp.sock,
    qmp-e2e.sock), so `lsof monitor.sock` / `lsof -t <abs path>` cannot
    tell VMs apart: lsof by name lists ALL qemus (35150 41380 747642 ...),
    by absolute path none.
  * qemu -daemonize chdirs to "/" after binding the sockets: readlink
    /proc/PID/cwd is "/" for every e2e qemu.
  => EXISTING BUG FIXED: vm-reboot's SIGTERM/SIGKILL fallback did
     `kill $(lsof -Fp monitor.sock)`, i.e. would have killed every e2e VM on
     the host. It now kills only vm-qemu-pid "$_vagrantdir".
  => WS5 discovery: do NOT resolve relative socket paths with
     /proc/PID/cwd. Take the output dir from the -drive
     file=<outdir>/.vagrant/machines/<name>/qemu/... argument and resolve
     qmp.sock/monitor.sock against <outdir>. Connect with chdir(<outdir>) +
     relative name (or a short symlink): absolute paths are ~103-107 chars,
     sun_path max is 108.

### VM creation (section 4)
Commands (from test/e2e, one at a time, /tmp/fake-cxl-pool created first;
vm-setup also mkdirs it on every vagrant up):
  qemu_bin=/home/akervine/github.com/qemu/qemu/build/qemu-system-x86_64 \
    ./run_tests.sh memory.test-suite/memory-policy/n4-cxl-shared-1/test00-up
  qemu_bin=/home/akervine/github.com/qemu/qemu/build/qemu-system-x86_64 \
    ./run_tests.sh memory.test-suite/memory-policy/n4-cxl-shared-2/test00-up
Timings: shared-1 5m43s (provision + kernel install + reboot), then FAIL in
the test's qemu pid lookup (old lsof code, see above), re-run 18s PASS;
shared-2 5m26s PASS. Full provisioning from the Fedora 43 box, no box cache;
kernel rpms came from the cached kernel tarball (same config as n4-cxl), no
kernel build. Logs: /home/akervine/.claude/jobs/5b6674cf/tmp/ws4/run-shared-{1,1b,2}.log;
test output: test/e2e/<vm>/memory.test-suite/memory-policy/test00-up/
(run.sh.output, qemu-cmdline.txt, cxl-dump.no-devices.json).

VMs (both running at the same time, k8s v1.37.1 Ready, guest kernel
7.3.0-rc4, cxl, daxctl, numactl, cxl-dump installed, no CXL memdevs):
| VM | output dir (test/e2e/...) | ssh port | VM_UUID | qemu pid |
| n4-cxl-shared-1-fedora-43-containerd | n4-cxl-shared-1-fedora-43-containerd/ | 51069 | b6a78455-edb1-558d-8cf1-01a259f76e97 | 1616213 |
| n4-cxl-shared-2-fedora-43-containerd | n4-cxl-shared-2-fedora-43-containerd/ | 50972 | 1b6d55a2-ae4a-52f8-bbba-2e3f9adca1b1 | 1626283 |
ssh: ssh -F test/e2e/<vm>/.ssh-config vagrant@node
QMP: test/e2e/<vm>/qmp.sock (for fake-cxl-pool-server), qmp-e2e.sock (vm-qmp);
HMP: test/e2e/<vm>/monitor.sock.
Qemu: /home/akervine/github.com/qemu/qemu/build/qemu-system-x86_64,
query-version 11.1.50, package "v11.1.0-1741-gff076b1e6c" (= ff076b1e6c).
Both qemus map /tmp/fake-cxl-pool/static-shared0.raw (same inode 155148,
rw-s, 256M, created by the first qemu with mode 0640).

ps -o args of n4-cxl-shared-1 (shared-2 differs only in ssh port, vq_ id
paths and -uuid):
/home/akervine/github.com/qemu/qemu/build/qemu-system-x86_64 -machine q35,kernel-irqchip=split,cxl=on,accel=kvm -cpu host,x2apic=on -smp cpus=8,threads=2,sockets=2,maxcpus=8 -m size=8G,slots=8,maxmem=15G -device virtio-net-pci,netdev=net0 -netdev user,id=net0,hostfwd=tcp::51069-:22,net=192.168.76.0/24,dhcpstart=192.168.76.9 -drive if=none,id=disk0,id=disk0,format=qcow2,file=/home/akervine/github.com/containers/nri-plugins/test/e2e/n4-cxl-shared-1-fedora-43-containerd/.vagrant/machines/n4-cxl-shared-1-fedora-43-containerd/qemu/vq_LML7R699Bwg/linked-box.img -chardev socket,id=mon0,path=/home/akervine/.vagrant.d/tmp/vagrant-qemu/vq_LML7R699Bwg/qemu_socket,server=on,wait=off -mon chardev=mon0,mode=readline -chardev socket,id=ser0,path=/home/akervine/.vagrant.d/tmp/vagrant-qemu/vq_LML7R699Bwg/qemu_socket_serial,server=on,wait=off -serial chardev:ser0 -pidfile /home/akervine/.vagrant.d/tmp/vagrant-qemu/vq_LML7R699Bwg/qemu.pid -daemonize -parallel null -monitor none -display none -vga none -device pcie-root-port,id=rp_disk,bus=pcie.0,port=0x9,chassis=5 -device virtio-blk-pci,drive=disk0,id=virtio_disk0,bus=rp_disk -numa node,nodeid=0,memdev=membuiltin_0_node_0,cpus=0-3 -numa node,nodeid=1,memdev=membuiltin_1_node_1,cpus=4-7 -numa dist,src=0,dst=1,val=21 -numa dist,src=1,dst=0,val=21 -device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxlhb0,numa_node=0 -device cxl-rp,port=0,bus=cxlhb0,id=cxlrp0hb0,chassis=193,slot=0 -device cxl-upstream,bus=cxlrp0hb0,id=cxlsw_usrp0hb0 -device cxl-downstream,port=1,bus=cxlsw_usrp0hb0,id=cxlsw_ds0_usrp0hb0,chassis=193,slot=1 -device cxl-downstream,port=2,bus=cxlsw_usrp0hb0,id=cxlsw_ds1_usrp0hb0,chassis=193,slot=2 -device cxl-downstream,port=3,bus=cxlsw_usrp0hb0,id=cxlsw_ds2_usrp0hb0,chassis=193,slot=3 -device cxl-downstream,port=4,bus=cxlsw_usrp0hb0,id=cxlsw_ds3_usrp0hb0,chassis=193,slot=4 -device pxb-cxl,bus_nr=24,bus=pcie.0,id=cxlhb1,numa_node=1 -device cxl-rp,port=5,bus=cxlhb1,id=cxlrp0hb1,chassis=193,slot=5 -device cxl-upstream,bus=cxlrp0hb1,id=cxlsw_usrp0hb1 -device cxl-downstream,port=6,bus=cxlsw_usrp0hb1,id=cxlsw_ds0_usrp0hb1,chassis=193,slot=6 -device cxl-downstream,port=7,bus=cxlsw_usrp0hb1,id=cxlsw_ds1_usrp0hb1,chassis=193,slot=7 -device cxl-downstream,port=8,bus=cxlsw_usrp0hb1,id=cxlsw_ds2_usrp0hb1,chassis=193,slot=8 -device cxl-downstream,port=9,bus=cxlsw_usrp0hb1,id=cxlsw_ds3_usrp0hb1,chassis=193,slot=9 -M cxl-fmw.0.targets.0=cxlhb0,cxl-fmw.0.size=8G,cxl-fmw.1.targets.0=cxlhb1,cxl-fmw.1.size=8G -object memory-backend-ram,size=4G,id=membuiltin_0_node_0 -object memory-backend-ram,size=4G,id=membuiltin_1_node_1 -object memory-backend-file,id=befile_cxl_memdev0__bus_cxlsw_ds2_usrp0hb0__sn_0xc1f0ee00,share=on,mem-path=/tmp/fake-cxl-pool/static-shared0.raw,size=256M -object memory-backend-ram,id=beram_cxl_memdev1__bus_cxlsw_ds3_usrp0hb0__sn_0xc100e2e1,share=on,size=256M -monitor unix:monitor.sock,server,nowait -qmp unix:qmp.sock,server,nowait -qmp unix:qmp-e2e.sock,server,nowait -uuid b6a78455-edb1-558d-8cf1-01a259f76e97

### Notes for WS5/WS6
- The guest kernel (playbook/files/qemu-cxl-kernel.config) has CONFIG_DMI
  unset: NO /sys/class/dmi/id/product_uuid in the guest. kubelet's
  node.status.nodeInfo.systemUUID is then the UUID as 32 hex digits without
  dashes (e.g. b6a78455edb1558d8cf101a259f76e97), equal to /etc/machine-id
  (systemd set machine-id from the SMBIOS UUID at first boot, stock kernel).
  Match UUIDs after removing dashes and lowercasing. Enabling DMI would
  change the kernel config hash -> kernel rebuild for n4-cxl too; not done.
- befile_* backends are declared (static) devices like beram_*: never
  object-add/del them; their buses (cxlsw_ds2_usrp0hb0, cxlsw_ds3_usrp0hb0)
  are reserved. Pool slots: cxlsw_ds{0,1}_usrp0hb0 (NUMA 0) and
  cxlsw_ds{0..3}_usrp0hb1 (NUMA 1).
- qmp.sock is single-client: whoever holds it blocks other QMP clients;
  tests use qmp-e2e.sock via vm-qmp.
- `cxl-reset` (n4-cxl/cxl.source.sh) restarts qemu via vm-reboot when a
  device is plugged; with the patched qemu that is no longer necessary for
  re-plugging, but it is still what the helper does.
- The tmpfs file outlives the VMs; a host reboot removes it (qemu recreates
  it empty on the next vagrant up, vm-setup recreates the directory).
- test/e2e/run_tests.sh is read incrementally by bash: do not edit it while
  a run_tests.sh is running (none was running when I changed it).
- Agent A may rebuild the qemu binary in place while these VMs run; the
  running qemus keep the old inode only if the linker replaces (unlinks) the
  file. Restart (vagrant halt; vagrant up --no-provision) after a rebuild.

### Follow-up: kernel rebuild, hdm-for-passthrough, VM recreation (agent B)
Requested after WS3 found: no CONFIG_FS_DAX (devdax mmap fails "vma is not
DAX capable"), no CONFIG_DMI (no product_uuid), no evdev (`vagrant halt`
ignored), one region per host bridge without pxb-cxl hdm_for_passthrough=on.

Kernel config + RPMs:
- New script scripts/testing/fake-cxl-pool/proto/build-kernel-rpms.sh:
  copies test/e2e/playbook/files/qemu-cxl-kernel.config, in a
  registry.fedoraproject.org/fedora:43 podman container (rootless,
  --security-opt label=disable, source tree bind-mounted read-only,
  make O=<work>/build) installs the custom-kernel-fedora.yaml build deps
  + rpm-build bc diffutils findutils hostname kmod cpio rsync python3 tar xz,
  `scripts/config --enable` FS_DAX FS_DAX_PMD DMI DMIID INPUT INPUT_EVDEV
  ACPI_BUTTON, `make olddefconfig` (checks each is =y), `make -j256
  binrpm-pkg`, checks the build did not change .config, tars
  rpmbuild/RPMS/x86_64/kernel-*.rpm like the playbook, copies the
  effective .config back to the repo file and stores the tarball in the
  cache. Source: /home/akervine/.claude/jobs/5b6674cf/tmp/ws3/linux-src
  (7.3.0-rc4, git archive of a guest's ~/linux). Build time 2m28s total.
- CACHE KEY: custom-kernel.yaml line 28 hashes `lookup('file', kernel_config)`,
  and Ansible's file lookup strips trailing whitespace. So the key is
  sha256 of the content WITHOUT the final newline, not `sha256sum FILE`
  (verified: the old cached d5e425... = rstrip hash, sha256sum gave e67a22...).
  New: ~/.cache/nri-plugins/e2e/kernel.getsource_vanilla.config_783f70a2efa40a9aa52f12827971d136ec548cf21a1b49840e8446458e0ef8ed.rpms.tar
  (kernel-7.3.0_rc4-1.fc43.x86_64.rpm, kernel-devel-..., kernel-headers-...).
- qemu-cxl-kernel.config is now the full effective 7.3.0-rc4 config (was a
  6.19.0-rc4 one that the in-VM build upgraded silently). Compared with the
  effective config of the old RPMs (/boot/config-7.3.0-rc4 of a guest) the
  only differences are: +DEV_DAX_FSDEV +DMIID +DMI_SCAN_MACHINE_NON_EFI_FALLBACK
  +DMI +FS_DAX_PMD +FS_DAX +FUSE_DAX +INPUT_EVDEV +INTERVAL_TREE
  +MOUSE_PS2_LIFEBOOK, PAHOLE_VERSION 130 -> 132. INPUT and ACPI_BUTTON were
  already =y.
- CAVEAT: the RPM file names are the same as the old kernel's
  (kernel-7.3.0_rc4-1.fc43...). vm-kernel-pkgs-install skips installation
  when the tarball lists the same files as ~/.vm-kernel-pkgs.installed_packages,
  so EXISTING VMs (n4-cxl-*) keep the old kernel silently; new VMs get the
  new one. Upgrade an existing VM by removing that file in it (or recreate).
  test00-up's error messages say this.

Topology: new key "hdm-for-passthrough": true next to "cxl" (same group)
appends ",hdm_for_passthrough=on" to every pxb-cxl; must be a bool; error if
used without "cxl". Enabled in both n4-cxl-shared-* topologies. Generator
diff re-run: still empty (40-generator-diff.txt content unchanged).

test00-up (both): daxctl install was already there; new checks:
CONFIG_FS_DAX=y in /boot/config-$(uname -r), /sys/class/dmi/id/product_uuid
== VM_UUID of the env file (case-insensitive), two pxb-cxl with
hdm_for_passthrough=on in the qemu cmdline. Failures name the expected
cache tarball (computed like the playbook) and the build script.

VM recreation (2026-10-02 17:18-17:38):
- Waited for plan/50 Status "shared-VM live check DONE". Powered both VMs
  off from inside (`sudo systemctl poweroff`: the old kernel ignored the
  ACPI button, and vagrant-qemu's stop only sends system_powerdown and
  does not wait, so destroy would have deleted the disk of a running qemu),
  `vagrant destroy --force`, then MOVED the output dirs aside to
  /home/akervine/.claude/jobs/5b6674cf/tmp/ws4/old-vms/ (vm-setup writes
  Vagrantfile and env only if they are missing, so a destroy alone would
  keep the old Vagrantfile without hdm_for_passthrough). Removed
  /tmp/fake-cxl-pool/static-shared0.raw (no process mapped it).
- `qemu_bin=... ./run_tests.sh memory.test-suite/memory-policy/n4-cxl-shared-1/test00-up`:
  5m33s PASS; same for -2: 10m02s PASS (slower dnf). The playbook found
  and pushed the new cached kernel (no build in the VM).
- Results, both VMs: uname 7.3.0-rc4, CONFIG_FS_DAX=y, product_uuid ==
  VM_UUID, daxctl 85, /dev/input/event0..2, 0 CXL memdevs, vm-cxl-hw lists
  cxl_memdev0 sn=0xc1f0ee00 (befile) and cxl_memdev1 sn=0xc100e2e1, 2x
  pxb-cxl hdm_for_passthrough=on, k8s Ready.
- vagrant halt on shared-2: stopped after 2 s (power button works now);
  vagrant up --no-provision: 26 s. Note: `vagrant halt` returns at once,
  poll `vagrant status` before `vagrant up`.
- New ssh ports: shared-1 50509, shared-2 50479. UUIDs unchanged
  (b6a78455-edb1-558d-8cf1-01a259f76e97, 1b6d55a2-ae4a-52f8-bbba-2e3f9adca1b1).
- Other VMs untouched (n4c16-*, n4-cxl-fedora-43-crio/-containerd pids
  unchanged).

ps -o args of the recreated n4-cxl-shared-1:
/home/akervine/github.com/qemu/qemu/build/qemu-system-x86_64 -machine q35,kernel-irqchip=split,cxl=on,accel=kvm -cpu host,x2apic=on -smp cpus=8,threads=2,sockets=2,maxcpus=8 -m size=8G,slots=8,maxmem=15G -device virtio-net-pci,netdev=net0 -netdev user,id=net0,hostfwd=tcp::50509-:22,net=192.168.76.0/24,dhcpstart=192.168.76.9 -drive if=none,id=disk0,id=disk0,format=qcow2,file=/home/akervine/github.com/containers/nri-plugins/test/e2e/n4-cxl-shared-1-fedora-43-containerd/.vagrant/machines/n4-cxl-shared-1-fedora-43-containerd/qemu/vq_50Qxd1bqhg0/linked-box.img -chardev socket,id=mon0,path=/home/akervine/.vagrant.d/tmp/vagrant-qemu/vq_50Qxd1bqhg0/qemu_socket,server=on,wait=off -mon chardev=mon0,mode=readline -chardev socket,id=ser0,path=/home/akervine/.vagrant.d/tmp/vagrant-qemu/vq_50Qxd1bqhg0/qemu_socket_serial,server=on,wait=off -serial chardev:ser0 -pidfile /home/akervine/.vagrant.d/tmp/vagrant-qemu/vq_50Qxd1bqhg0/qemu.pid -daemonize -parallel null -monitor none -display none -vga none -device pcie-root-port,id=rp_disk,bus=pcie.0,port=0x9,chassis=5 -device virtio-blk-pci,drive=disk0,id=virtio_disk0,bus=rp_disk -numa node,nodeid=0,memdev=membuiltin_0_node_0,cpus=0-3 -numa node,nodeid=1,memdev=membuiltin_1_node_1,cpus=4-7 -numa dist,src=0,dst=1,val=21 -numa dist,src=1,dst=0,val=21 -device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxlhb0,numa_node=0,hdm_for_passthrough=on -device cxl-rp,port=0,bus=cxlhb0,id=cxlrp0hb0,chassis=193,slot=0 -device cxl-upstream,bus=cxlrp0hb0,id=cxlsw_usrp0hb0 -device cxl-downstream,port=1,bus=cxlsw_usrp0hb0,id=cxlsw_ds0_usrp0hb0,chassis=193,slot=1 -device cxl-downstream,port=2,bus=cxlsw_usrp0hb0,id=cxlsw_ds1_usrp0hb0,chassis=193,slot=2 -device cxl-downstream,port=3,bus=cxlsw_usrp0hb0,id=cxlsw_ds2_usrp0hb0,chassis=193,slot=3 -device cxl-downstream,port=4,bus=cxlsw_usrp0hb0,id=cxlsw_ds3_usrp0hb0,chassis=193,slot=4 -device pxb-cxl,bus_nr=24,bus=pcie.0,id=cxlhb1,numa_node=1,hdm_for_passthrough=on -device cxl-rp,port=5,bus=cxlhb1,id=cxlrp0hb1,chassis=193,slot=5 -device cxl-upstream,bus=cxlrp0hb1,id=cxlsw_usrp0hb1 -device cxl-downstream,port=6,bus=cxlsw_usrp0hb1,id=cxlsw_ds0_usrp0hb1,chassis=193,slot=6 -device cxl-downstream,port=7,bus=cxlsw_usrp0hb1,id=cxlsw_ds1_usrp0hb1,chassis=193,slot=7 -device cxl-downstream,port=8,bus=cxlsw_usrp0hb1,id=cxlsw_ds2_usrp0hb1,chassis=193,slot=8 -device cxl-downstream,port=9,bus=cxlsw_usrp0hb1,id=cxlsw_ds3_usrp0hb1,chassis=193,slot=9 -M cxl-fmw.0.targets.0=cxlhb0,cxl-fmw.0.size=8G,cxl-fmw.1.targets.0=cxlhb1,cxl-fmw.1.size=8G -object memory-backend-ram,size=4G,id=membuiltin_0_node_0 -object memory-backend-ram,size=4G,id=membuiltin_1_node_1 -object memory-backend-file,id=befile_cxl_memdev0__bus_cxlsw_ds2_usrp0hb0__sn_0xc1f0ee00,share=on,mem-path=/tmp/fake-cxl-pool/static-shared0.raw,size=256M -object memory-backend-ram,id=beram_cxl_memdev1__bus_cxlsw_ds3_usrp0hb0__sn_0xc100e2e1,share=on,size=256M -monitor unix:monitor.sock,server,nowait -qmp unix:qmp.sock,server,nowait -qmp unix:qmp-e2e.sock,server,nowait -uuid b6a78455-edb1-558d-8cf1-01a259f76e97
