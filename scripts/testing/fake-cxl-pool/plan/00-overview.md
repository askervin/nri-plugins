# fake-cxl-pool: workstream overview and checkpoints

Task: scripts/testing/fake-cxl-pool/5jS-task-cxl-pool.txt
Started: 2026-10-02. Top-level design: Fable 5.1 session. Coding/testing: Opus agents.

These plan files are checkpoints. Every agent appends findings, decisions and
status to its own file and keeps the "Status" section current, so that a new
session can resume from them.

## Workstreams

| WS | File | Owner | Depends on | Status |
|----|------|-------|------------|--------|
| 1 | 10-design-pooling-dra.md | Fable (design) | 11-research-cohdi-kep5007.md | v1 written |
| 1r | 11-research-cohdi-kep5007.md | Opus research agent | - | done |
| 2 | 20-rest-api.md | Fable (design) | Maxview guide, CoHDI, DRA | v1 spec written |
| 3 | 30-qemu-shared-backend.md | Opus agent A | patched qemu build, n4-cxl VM disk | done: Q1-Q9 answered, Recipes section |
| 4 | 40-test-framework.md | Opus agent B | WS3 for final qemu options | done (recreated): VMs on FS_DAX/DMI kernel, hdm_for_passthrough=on |
| 5 | 50-server-client.md | Opus agent C | WS2 spec; WS3 facts for live tests | done: 47 unit tests, live on 3 VMs, devdax sharing verified |
| 6 | 60-e2e-test.md | Opus agent E | WS4 VMs + WS5 binaries | done: PASS x2 (~78s), cleanup verified |
| 5r | 51-code-review.md | Opus reviewer | WS5 code | done: H1, M1-M5 and most low findings fixed, 63 race tests pass |
| 7 | 70-dra-driver-followup.md | Fable (design) | WS1 | task spec written (implementation in the DRA driver repo) |

## Dependency graph

```
Maxview/CoHDI/DRA research ──> WS1 design ──> (DRA controller: design only in this task)
                          └──> WS2 REST API ──> WS5 server+client ──┐
WS3 qemu shared backend ──┬──> WS4 topology + qemu options ──> VMs ─┼──> WS6 e2e test
                          └──> WS5 qemu control facts (QMP) ────────┘
```

## Key facts established on 2026-10-02 (host: this machine, 256 CPUs, 251G RAM)

- Test framework: test/e2e/run_tests.sh -> run.sh -> lib/vm.bash -> vagrant-qemu.
  CXL topology JSON ("cxl" tree in topology.var.json) is turned into qemu
  -object/-device args by test/e2e/lib/topology2qemuopts.py (qemucxlopts()).
  Each VM gets "-monitor unix:monitor.sock,server,nowait" (HMP, relative to
  qemu cwd = test output dir, e.g. test/e2e/n4-cxl-fedora-43-containerd/).
  vm-cxl-hotplug/vm-cxl-hotremove in lib/vm.bash drive HMP device_add/device_del
  of cxl-type3 with pre-declared memory-backend-ram objects named
  beram_cxl_memdevN__bus_<downstream bus id>__sn_<serial>.
- VM name == hostname == vagrant machine dir name, e.g.
  n4-cxl-fedora-43-containerd (topology dir basename + distro + runtime).
  Qemu cmdline contains .vagrant/machines/<vm_name>/qemu/... in -drive, so a
  host-side server can map qemu PID -> VM name without extra config.
- Guest network: slirp user networking, net=192.168.76.0/24; guest reaches
  the host loopback at the gateway address 192.168.76.2 (verified: TCP RST
  from 192.168.76.2:1). NO_PROXY in VMs covers 192.168.76.0/24.
- Guest kernel (n4-cxl): 7.3.0-rc4 custom build, CONFIG_CXL_REGION,
  DEV_DAX, DEV_DAX_CXL, DEV_DAX_KMEM, MEMORY_HOTREMOVE. cxl tool installed,
  daxctl NOT installed (dnf install daxctl). Kubernetes v1.37.0 with
  --feature-gates=DRANodeAllocatableResources=true.
- Qemu: stock /usr/bin/qemu-system-x86_64 11.1.1 runs the VMs today. Patched
  build ~/github.com/qemu/qemu/build/qemu-system-x86_64 (branch
  5jL-fix-cxl-hot-remove, commit ff076b1e6c: cxl-downstream advertises power
  controller + cxl-type3 unmaps backends on unplug) is needed for
  hot-remove -> hotplug again. Binary dated Sep 24, commit Sep 25: rebuild.
- Qemu supports runtime "object_add memory-backend-file,..." (HMP) and
  "object-add" (QMP), so a pool server can attach arbitrary backing files to
  any VM that has a free cxl-downstream/cxl-rp slot. Hot-remove completion is
  signalled by the QMP DEVICE_DELETED event.
- The framework does not wire a custom qemu binary (SKILL.md mentions
  qemu_bin but nothing in run.sh/vm.bash uses it; vagrant-qemu supports
  qemu.qemu_bin). WS4 adds it.
- Kernel packages are cached per (getsource, config hash) in
  ~/.cache/nri-plugins/e2e/kernel.getsource_vanilla.config_<sha>.rpms.tar, so
  new topologies reusing n4-cxl's kernel_config.var.sh and
  kernel_getsource.var.sh do not rebuild the kernel.
- Maxview (UnifabriX MAX) REST API concepts: memory_resources (pool capacity),
  viewports (allocations, shared/persistent), ports/HDM (host attach points),
  attach/detach/allocate/free, port 9999, /api/v1/...
- CoHDI: pool ResourceSlice of free devices + KEP-5007 binding conditions:
  scheduler picks node, external controller attaches, sets condition, pod binds.

## Decisions log

- D1 Code lives in scripts/testing/fake-cxl-pool/{cmd,pkg} inside the main Go
  module github.com/containers/nri-plugins (stdlib + sigs.k8s.io/yaml only).
- D2 Server listens on 127.0.0.1:9909 by default; clients in VMs use
  http://192.168.76.2:9909 (env FAKE_CXL_POOL_SERVER or --server).
- D3 Hosts (VMs) are identified primarily by SMBIOS system UUID (qemu -uuid,
  deterministic uuid5 of the VM name; kubelet nodeInfo.systemUUID; guest
  /sys/class/dmi/id/product_uuid), with name == hostname == vagrant machine
  name as fallback. Clients send both to /hosts/resolve.
- D4 Qemu control: QMP (-qmp unix:qmp.sock,server,nowait) is primary; HMP
  (-monitor unix:monitor.sock) is a fallback so the server works with VMs that
  exist today. Backends are object-add'ed at attach time, object-del'ed after
  DEVICE_DELETED.
- D5 Sharing mode in guests: shared devices are meant to be used as devdax
  (/dev/daxX.Y, apps mmap) in every guest. system-ram (online_movable) is for
  exclusively attached (pooled, not shared) devices. The server does not
  enforce guest mode; the client "guest" helpers and the e2e test do.
- D6 Topology: new cxl "mem" properties "file", "sn", "shared" for statically
  declared shared backends, and "pool-slot" for empty hotplug slots. See
  40-test-framework.md.
- D7 Pool device identity: name (unique in server) + serial (uint64, guest
  visible in /sys/bus/cxl/devices/memN/serial). Same serial in every VM a
  shared device is attached to.
- D8 Pool devices are published to Kubernetes under a separate DRA driver name
  cxl-pool.generic (second kubeletplugin helper in kubelet-cxl-plugin), pool
  name fake-cxl-pool, with bindsToNode + bindingConditions
  cxl-pool.generic/Attached and bindingFailureConditions
  cxl-pool.generic/AttachFailed. See 10-design-pooling-dra.md 4.1.
- D9 cxl-pool-controller sets Attached=True as soon as the pool server reports
  the attachment; kubelet-cxl-plugin NodePrepare waits for the serial to show
  up in sysfs. No CRDs; the ResourceClaim is the request.
- D10 Shared devices in Kubernetes: allowMultipleAllocations with a `hosts`
  capacity (max attached VMs), size as an attribute; one claim per node.
- D11 run_tests.sh topology filter: exact match when the filter names an
  existing topology directory (so n4-cxl no longer also selects
  n4-cxl-shared-*), substring match otherwise (old behaviour kept).
- D12 VMs get two QMP sockets: qmp.sock for the pool server (one long-lived
  client), qmp-e2e.sock for the test framework's vm-qmp. qemu's cwd is "/", so
  socket paths are derived from the -drive path's output dir, not /proc/PID/cwd.

## Follow-ups noted
- Guest kernel config lacks CONFIG_DMI: no /sys/class/dmi/id/product_uuid in
  the VM. kubelet systemUUID comes from /etc/machine-id, which Fedora's first
  boot (stock kernel) derived from the qemu -uuid, so it happens to match.
  Add CONFIG_DMI=y to test/e2e/files/qemu-cxl-kernel.config at the next
  kernel rebuild (changes the cached-kernel hash: ~1h rebuild).
- D13 (WS3 results) Sharing mode is devdax, mandatory: both guests onlining the
  same device as system-ram corrupts silently (Q9). devdax needs CONFIG_FS_DAX
  in the guest kernel: added to qemu-cxl-kernel.config with CONFIG_DMI/DMIID
  (product_uuid) and INPUT/ACPI_BUTTON (vagrant halt), RPMs built on the host
  in a fedora:43 podman container and seeded into the kernel cache.
- D14 Detach contract: the guest must release the device (offline, destroy
  region or devdax unused, disable memdev) before detach. If DEVICE_DELETED
  does not arrive in 15s the attachment is "failed" and qemu keeps a zombie
  device until that VM restarts; no retry, no background wait. Exclusive
  devices in that state are quarantined until the qemu pid is gone.
- D15 Device sizes are multiples of 256M; per host bridge the attached total
  must fit the cxl-fmw size; pxb-cxl needs hdm_for_passthrough=on for more
  than one region per host bridge (topology key "hdm-for-passthrough": true,
  enabled in n4-cxl-shared-*). CXL memory does not count against -m/maxmem.
- D16 QMP sn is an integer; slots are enumerated with qom-list/qom-get (no
  qtree parsing needed on QMP hosts); patched qemu detected via
  power_controller_present on a cxl-downstream.
- Kernel cache key: Ansible's file lookup strips the trailing newline before
  sha256; the tarball name hash is NOT `sha256sum file`. New cached kernel:
  kernel.getsource_vanilla.config_783f70a2....rpms.tar (FS_DAX, DMI, EVDEV).
  RPM names are unchanged (kernel-7.3.0_rc4-1.fc43), so vm-kernel-pkgs-install
  keeps the old kernel on existing VMs (n4-cxl-*): remove
  ~/.vm-kernel-pkgs.installed_packages in the VM or recreate it to upgrade.
  Build script: proto/build-kernel-rpms.sh (fedora:43 podman, 2.5 min).
- Shared VMs after recreation: ssh ports shared-1 50509, shared-2 50479;
  names, UUIDs, socket paths unchanged. Old output dirs moved to
  /home/akervine/.claude/jobs/5b6674cf/tmp/ws4/old-vms/.

## Final state 2026-10-02 (end of the design session)

Everything is in the working tree of branch 5jQ-cxl, nothing committed:
- scripts/testing/fake-cxl-pool/: server, client (Go, ~11k lines incl. tests),
  README.md, config.example.yaml, Makefile, proto/ scripts, plan/ (this dir).
  `make -C scripts/testing/fake-cxl-pool` builds bin/; `go test -race` passes.
- test/e2e: lib/topology2qemuopts.py (file/sn/shared/pool-slot,
  hdm-for-passthrough), lib/vm.bash (-qmp x2, -uuid, qemu_bin, vm-qmp,
  vm-qemu-pid, mem-path dirs, vm-reboot kill fix), files/Vagrantfile.in,
  files/env.in, run_tests.sh (topology filter), playbook/files/qemu-cxl-kernel.config
  (FS_DAX, DMI, EVDEV; full effective config), .github/skills/run-e2e-tests/SKILL.md,
  memory.test-suite/memory-policy/n4-cxl-shared-{1,2}/ (topologies, test00-up,
  pool.source.sh, pool-dax-rw.py, test01-shared-cxl).
- VMs running: n4-cxl-shared-1/2-fedora-43-containerd (patched qemu, FS_DAX
  kernel), n4-cxl-fedora-43-containerd (stock qemu; has a zombie cxl-type3
  fcp_...memdev9.hp1 on cxlsw_ds7_usrp0hb1 from the WS5 smoke test until its
  next restart; cxl-reset in the n4-cxl tests restarts it anyway).
- Verified: ./run_tests.sh memory.test-suite/memory-policy/n4-cxl-shared-2/test01-shared-cxl
  PASS (79 s) on the final code; devdax data written in one VM read in the
  other and present in the host backing file.

Next: plan/70-dra-driver-followup.md (Kubernetes integration in the DRA
driver repository); the "Follow-ups noted" above (multi-node cluster in the
framework; L8/L10 leftovers in 51-code-review.md).
