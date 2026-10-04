# WS3: Qemu shared CXL memory backend prototyping

Status: 2026-10-02 17:12 agent A: DONE. Q1-Q9 answered (Findings + Recipes). Direct qemus killed;
n4-cxl-fedora-43-containerd running again (vagrant up --no-provision). ACTION for WS4:
guest kernel needs CONFIG_FS_DAX=y (devdax mmap), pxb-cxl hdm_for_passthrough=on. Agent A: append
"Findings" and keep "Status" current. Record exact commands that worked.

## Goal
Prove, with the patched qemu build, that one memory backing file can serve as
the volatile memory of a cxl-type3 device in two concurrently running KVM VMs,
that the device can be hotplugged/hot-removed at runtime with backends created
by object_add, and that data written in VM A through the CXL device is visible
in VM B. Produce the exact qemu command line fragments and QMP command
sequences that WS4 (test framework) and WS5 (server) will use.

## Environment
- Patched qemu: ~/github.com/qemu/qemu (branch 5jL-fix-cxl-hot-remove,
  HEAD ff076b1e6c). Rebuild first: `cd ~/github.com/qemu/qemu && ninja -C build qemu-system-x86_64`
  (binary build/qemu-system-x86_64 is older than the commit).
- Guest disk with CXL kernel 7.3.0-rc4 and the cxl tool: the vagrant VM
  n4-cxl-fedora-43-containerd (test/e2e/n4-cxl-fedora-43-containerd). Its disk
  is .vagrant/machines/n4-cxl-fedora-43-containerd/qemu/vq_*/linked-box.img
  (qcow2 with a backing file). Procedure: `vagrant halt` in that dir, then
  `qemu-img convert -O qcow2 linked-box.img $WORK/base.qcow2` (flattened copy),
  then `vagrant up --no-provision` to give the VM back. Then make two overlays
  `qemu-img create -f qcow2 -b $WORK/base.qcow2 -F qcow2 $WORK/vmA.qcow2` (and vmB).
  Never run qemu directly on linked-box.img. The vagrant VM may be running a
  previous test's leftovers (cxl_memdev2.hp3 plugged); that is fine.
  SSH key: .vagrant/machines/n4-cxl-fedora-43-containerd/qemu/private_key,
  user vagrant (passwordless sudo). Both overlays boot with the same hostname;
  that is fine for this prototype.
- Work dir: /home/akervine/.claude/jobs/5b6674cf/tmp/ws3 (create it). Backing
  files for shared memory: /dev/shm or /tmp (tmpfs, 126G) e.g. /tmp/fake-cxl-pool-ws3/shared0.raw.
- Reference command line of the vagrant VM (host bridges, switch, ports, fmw):
  see `ps -o args -p $(pgrep -f n4-cxl-fedora-43-containerd)` or
  test/e2e/n4-cxl-fedora-43-containerd/Vagrantfile. Minimal direct launch:
  -machine q35,kernel-irqchip=split,cxl=on,accel=kvm -cpu host -smp 4 -m 4G
  -numa node,nodeid=0,memdev=m0,cpus=0-3 -object memory-backend-ram,id=m0,size=4G
  -device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxlhb0,numa_node=0
  -device cxl-rp,port=0,bus=cxlhb0,id=cxlrp0hb0,chassis=193,slot=0
  -device cxl-upstream,bus=cxlrp0hb0,id=cxlsw_usrp0hb0
  -device cxl-downstream,port=1,bus=cxlsw_usrp0hb0,id=cxlsw_ds0_usrp0hb0,chassis=193,slot=1
  -device cxl-downstream,port=2,bus=cxlsw_usrp0hb0,id=cxlsw_ds1_usrp0hb0,chassis=193,slot=2
  -M cxl-fmw.0.targets.0=cxlhb0,cxl-fmw.0.size=4G
  -drive if=none,id=disk0,format=qcow2,file=$WORK/vmA.qcow2
  -device pcie-root-port,id=rp_disk,bus=pcie.0,port=0x9,chassis=5
  -device virtio-blk-pci,drive=disk0,bus=rp_disk
  -device virtio-net-pci,netdev=net0 -netdev user,id=net0,hostfwd=tcp::PORT-:22
  -qmp unix:$WORK/vmA.qmp,server,nowait -monitor unix:$WORK/vmA.hmp,server,nowait
  -display none -vga none -serial file:$WORK/vmA.serial -daemonize -pidfile $WORK/vmA.pid
  Use distinct hostfwd ports (e.g. 52201, 52202), -smp 4 -m 4G each.

## Questions to answer (each with evidence: command + output excerpt)
Q1 Static sharing: both VMs started with the same
   `-object memory-backend-file,id=shared0,share=on,mem-path=/tmp/.../shared0.raw,size=256M`
   and `-device cxl-type3,bus=cxlsw_ds0_usrp0hb0,volatile-memdev=shared0,id=cxl_shared0,sn=0xc1f0ee00`
   (present at boot). Does each guest see mem0 with serial 0xc1f0ee00? Does
   qemu accept the same file in two processes (share=on; any locking issues)?
   Does the file need to pre-exist / be truncated to size / prealloc?
Q2 Runtime attach: VM started with empty downstream ports (no -object for the
   shared memory). Over QMP: object-add {"qom-type":"memory-backend-file","id":"shared0","share":true,"mem-path":...,"size":268435456}
   then device_add {"driver":"cxl-type3","bus":"cxlsw_ds0_usrp0hb0","volatile-memdev":"shared0","id":"cxl_shared0.hp1","sn":...}.
   Does the guest see it (dmesg, /sys/bus/cxl/devices/mem0/serial)? Note "sn"
   type in QMP (int or string?). Record exact JSON that works. Also record the
   HMP equivalents (object_add/device_add text) since today's VMs only have HMP.
Q3 Does CXL memory count against -m maxmem / slots? Try -m 4G (no maxmem)
   with 2x256M hotplugged devices. If hotplug fails without maxmem headroom,
   record the required relation (WS4 needs it for "pool-slot" sizes).
Q4 Data sharing via devdax: in each guest `cxl create-region -t ram -d decoder0.0 -m mem0`;
   find the dax device (/sys/bus/cxl/devices/region0/dax_region0/dax0.0),
   ensure it is bound to device_dax (not kmem): `dnf install -y daxctl` then
   `daxctl reconfigure-device --mode=devdax dax0.0` or sysfs unbind/bind
   (/sys/bus/dax/drivers/{kmem,device_dax}). Record which driver it binds to by
   default on this kernel and the exact commands to switch. Then in VM A
   python3 mmap /dev/dax0.0 (MAP_SHARED, 2M aligned) write a pattern at
   offsets 0, 1M, 100M, 255M; in VM B mmap and read: identical? Also
   write from B, read in A. Check `md5sum` of the host backing file shows the
   data (host view). Measure a rough bandwidth of a 256M memcpy in the guest to
   confirm KVM is mapping it (not emulation): expect GB/s, not MB/s.
Q5 system-ram mode: in VM A `daxctl reconfigure-device --mode=system-ram --no-online dax0.0`
   (or kmem bind) then online_movable all blocks (as test01-pkg-cxl does via
   /sys/devices/system/memory/memoryN/state). Can VM A use it as RAM
   (numactl --membind=<node> memhog or dd to a tmpfs)? Then offline + release
   (offline blocks, cxl disable-region/destroy-region, cxl disable-memdev) and
   hot-remove over QMP (device_del + wait DEVICE_DELETED event, then
   object-del). Then re-attach the same backend again to the same slot: works
   with the patched qemu? (This is the whole point of the patch.) Also show
   what stock /usr/bin/qemu-system-x86_64 does on re-attach (one run) so the
   e2e test can require the patched build.
Q6 Hot-remove while the guest still uses the device (region not destroyed):
   what happens? (Expected: DEVICE_DELETED never comes; device_del returns
   immediately.) Can the request be cancelled? Does a later guest release
   complete it? WS5 needs the exact behaviour to model the "detaching" state.
Q7 Slot enumeration over QMP: find a QMP-only way to list cxl-downstream /
   cxl-rp buses and whether a cxl-type3 is attached (candidates: query-pci,
   qom-list /machine/peripheral, qom-list-properties, qom-get on
   /machine/peripheral/<id>/…). If none is clean, record that
   human-monitor-command "info qtree -b" is the way and give a parse recipe.
   Also: query-memdev output for object-add'ed backends, and how to see the
   fmw sizes (query-machines? qom-get /machine cxl-fmw.0.size?).
Q8 Memory placement for both VMs and the backing file: does
   memory-backend-file share=on on tmpfs work with prealloc=off? Any
   "mem-path" alignment constraint (align=2M)? Is `discard-data` relevant?
Q9 Both guests online the same shared region as system-ram simultaneously:
   do not do data integrity tests, just note what happens on both sides
   (expected: both believe they own it; corruption risk). One quick try is
   enough; this is to document why devdax is the sharing mode.

## Deliverables
1. Findings appended to this file, with a final "Recipes" section:
   - qemu command line fragment for a statically shared device
   - QMP JSON sequences: attach (object-add + device_add), detach (device_del,
     DEVICE_DELETED, object-del), list slots, list memdevs; HMP equivalents
   - guest command sequences: devdax sharing, system-ram pooling, release
   - maxmem rule, serial type/format, failure strings seen
2. Scripts kept in /home/akervine/.claude/jobs/5b6674cf/tmp/ws3/ and copied to
   scripts/testing/fake-cxl-pool/proto/ (launch-vm.sh, qmp.py or qmp.sh, guest-dax-rw.py) so they can be reused.
3. Leave the vagrant VM n4-cxl-fedora-43-containerd running at the end
   (vagrant up --no-provision) and kill your direct qemus; remove the big
   base.qcow2 copy only if disk space is a problem (417G free: keep it).

## Findings
(agent A appends here)

### Setup (2026-10-02, agent A)

- Patched qemu rebuilt: `ninja -C build qemu-system-x86_64` (6 steps, 3 s) ->
  `QEMU emulator version 11.1.50 (v11.1.0-1741-gff076b1e6c)`.
- `vagrant halt` does NOT stop n4-cxl-fedora-43-containerd: vagrant-qemu only
  sends HMP `system_powerdown` and the custom 7.3.0-rc4 kernel has no
  /dev/input (no evdev), so logind never sees the ACPI power button
  ("Power Button [PWRF]" is registered, nothing reacts). Workaround used:
  `ssh ... sudo systemctl poweroff`, then `vagrant status` -> stopped.
  WS4: anything relying on `vagrant halt`/`vagrant reload` for this kernel
  will hang/no-op; power off from inside the guest or add CONFIG_INPUT_EVDEV.
- Flattened disk: `qemu-img convert -p -O qcow2 .../linked-box.img $W/base.qcow2`
  (8 s, 5.3G), then `vagrant up --no-provision` (27 s) -> running.
  Overlays: `qemu-img create -f qcow2 -b $W/base.qcow2 -F qcow2 $W/vmA.qcow2`.
- Direct launch: scripts in $W = /home/akervine/.claude/jobs/5b6674cf/tmp/ws3
  (launch-vm.sh, vm-ssh.sh, qmp.py, guest-dax-rw.py; copied to ../proto/).
  Gotcha: with pxb-cxl on the command line, `-device virtio-net-pci` without
  `bus=pcie.0` is auto-placed on the pxb-cxl bus and qemu fails with
  "PCI: Only PCI/PCIe bridges can be plugged into pxb-cxl". Always give
  explicit bus= for NICs/disks (the vagrant VM works only because the NIC
  comes before pxb-cxl in its args). Guest ssh is up ~10 s after launch.

### Q1 static sharing: YES

Both VMs launched with (file did NOT exist before vmA started):
```
-object memory-backend-file,id=shared0,share=on,mem-path=/tmp/fake-cxl-pool-ws3/shared0.raw,size=256M
-device cxl-type3,bus=cxlsw_ds0_usrp0hb0,volatile-memdev=shared0,id=cxl_shared0,sn=0xc1f0ee00
```
- qemu creates the file (sparse, `stat`: size 268435456, 0 blocks, mode 0640)
  and ftruncates it to size; no prealloc needed, no pre-creation needed. The
  second qemu opens the same file; no locking (memory-backend-file takes no
  lock): `lsof` shows both qemus with fd+`rw-s` (MAP_SHARED) mapping of the
  same inode.
- Both guests: `cat /sys/bus/cxl/devices/mem0/serial` -> `0xc1f0ee00`,
  `cxl list -M` -> `"memdev":"mem0","ram_size":"256.00 MiB","serial":"0xc1f0ee00","numa_node":0`.

### Q2 runtime attach: YES (QMP and HMP, switch downstream port and root port)

VM with empty slots, QMP (sn MUST be a JSON integer):
```
{"execute":"object-add","arguments":{"qom-type":"memory-backend-file","id":"shared1","share":true,"mem-path":"/tmp/fake-cxl-pool-ws3/shared1.raw","size":268435456}}
{"execute":"device_add","arguments":{"driver":"cxl-type3","bus":"cxlsw_ds1_usrp0hb0","volatile-memdev":"shared1","id":"cxl_shared1.hp1","sn":3253792257}}
```
both `{"return": {}}`; guest dmesg: pciehp slot event, `cxl_pci 0000:10:00.0: enabling device`,
then `/sys/bus/cxl/devices/mem1/serial` = `0xc1f0ee01` (within 3 s).
- `"sn":"0xc1f0ee02"` (string) -> `{"error":{"class":"GenericError","desc":"Parameter 'sn' expects uint64"}}`.
  qom-get returns it as an integer too (`3253792256`). Serial format for
  humans/guest sysfs: lowercase hex `0x%x` (cxl tool prints "0xc1f0ee00").
- HMP (text, works on today's monitor.sock; hex sn accepted):
  `object_add memory-backend-file,id=shared2,share=on,mem-path=/tmp/fake-cxl-pool-ws3/shared2.raw,size=256M`
  `device_add cxl-type3,bus=cxlrp0hb1,volatile-memdev=shared2,id=cxl_shared2.hp1,sn=0xc1f0ee02`
  -> guest mem2 serial 0xc1f0ee02. Attaching directly to a cxl-rp (no switch)
  works too (`bus=cxlrp0hb1`, a root port of a 2nd pxb-cxl).
- object-add creates the file if missing (same as Q1).

### Q3 maxmem: CXL memory does NOT count against -m/maxmem/slots

`-m 4G` (no slots, no maxmem) + 1 static + 2 hotplugged 256M cxl-type3: all
work. `query-memory-size-summary` -> `{"base-memory": 4294967296, "plugged-memory": 0}`;
`query-memory-devices` -> `[]`. CXL memory lives in the CFMW windows
(`-M cxl-fmw.N.size`), which qemu maps above RAM. So the framework's
`maxmem = mem + nvmem + cxlmem` and `slots += len(objectparams)` in
topology2qemuopts.py are unnecessary for cxl (harmless). The real limits:
- sum of region sizes on a host bridge <= that host bridge's cxl-fmw size
  (and fmw size must be a multiple of 256M);
- HDM decoders (next item).

**Decoder limit (important for WS4/WS5):** a pxb-cxl with a single root port
has NO HDM decoders by default ("passthrough"); the kernel emulates one
(decoder1.0/decoder2.0 above). So only ONE region per host bridge. Evidence,
mem0 already in region0, then mem1 (other downstream port, same host bridge):
```
$ cxl create-region -t ram -d decoder0.0 -m mem1
cxl region: create_region: region2: failed to set target0 to mem1
dmesg: cxl_port endpoint5: failed to attach decoder5.0 to region2: -16
```
Fix (qemu option): `-device pxb-cxl,...,hdm_for_passthrough=on` gives the host
bridge 4 real HDM decoders (switch USP and endpoints already have 4).
Verified below (see Q3b). Alternative: one host bridge per independently
used device.

### Q6 hot-remove while in use (system-ram online, memhog running): LEAK

Device cxl_shared2.hp1 on cxlrp0hb1, region1 kmem, both blocks online_movable,
`numactl --membind=2 memhog -r1000000 200M` running. `device_del` returns
`{"return": {}}` immediately; DEVICE_DELETED never arrives (waited 20 s, and
again later during the guest release). Guest side, with the PATCHED qemu:
```
[411.61] pciehp: Slot(0-1): Button press: will power off in 5 sec
[416.72] pciehp_unconfigure_device: domain:bus:dev = 0000:19:00
[416.72] removing memory fails, because memory [0x290000000-0x297ffffff] is onlined
[416.72] kmem dax1.0: mapping0: 0x290000000-0x29fffffff stuck online until reboot
[416.73] pci 0000:19:00.0: device released
[416.73] pciehp_power_off_slot: SLOTCTRL 8c write cmd 400
```
i.e. Linux removes the PCI device unconditionally (PCI remove cannot fail),
the memory stays online in the guest and memhog keeps running. In qemu the
device disappears from /machine/peripheral and the slot looks free
(`qmp.py slots`: `cxlrp0hb1 cxl-rp -`), but the device is a zombie: its HDM
decoder stays committed, so `info mtree` still shows
`0000000290000000-000000029fffffff (prio 0, ram): alias cxl-direct-mapping-alias-0 @shared2`
inside the cxl-fixed-memory-region. DEVICE_DELETED is sent from
device_finalize (hw/core/qdev.c), which never runs while that alias holds a
reference. `object-del shared2` then SUCCEEDS but the file stays mmapped and
the guest keeps reading/writing it. A later guest release does not help:
memory offline worked after killing memhog, `cxl disable-region region1` OK,
`cxl destroy-region region1` fails ("error locating decoder for target0",
the memdev is gone), `echo region1 > /sys/bus/cxl/devices/decoder0.1/delete_region`
removes it from sysfs, but the qemu alias remains; the guest HPA range stays
reserved ("stuck online until reboot") and the next region on that window got
the next HPA (0x2a0000000). Replugging a new device (shared3) into the same
slot works and the data goes to shared3 (no aliasing). Only a qemu restart
cleans up.
- Cancel: impossible. A second `device_del` within the 5 s window ->
  `{"error":{"class":"GenericError","desc":"Device cxl_shared1.hp2 is already in the process of unplug"}}`.
  There is no QMP cancel; the guest-side "Button cancel" needs a second
  attention-button press, which qemu refuses to send.
- Clean case for comparison (memdev disabled / no region): DEVICE_DELETED
  arrives 6.1 s after device_del (5 s pciehp button delay + ~1 s):
  `{"event":"DEVICE_DELETED","data":{"device":"cxl_shared1.hp1","path":"/machine/peripheral/cxl_shared1.hp1"}}`.
- WS5 model: attached -> detaching (device_del ok) -> detached on
  DEVICE_DELETED (expect ~6 s; use >= 15 s timeout) -> object-del. On timeout
  the slot may already look free in QOM but the backend is still mapped and
  possibly written by that guest: mark the backend "leaked/in use by <vm>
  until VM restart", never hand it to another VM exclusively, and do not
  reuse the slot's old HPA assumptions. Release in the guest BEFORE detach.
- Also seen: after a clean DEVICE_DELETED + object-del, qemu still keeps the
  backing file mmapped and the fd open (checked 35 s later; /proc/PID/maps
  `rw-s ... shared1.raw`). It is dropped at a later object-add (the new
  mapping got the same address). Harmless for re-attach of the same file,
  but tmpfs pages of an unlinked backing file are not freed immediately.

### Q7 slot enumeration over QMP: clean, QOM only

- `qom-list {"path":"/machine/peripheral"}` -> names + types, e.g.
  `cxlsw_ds0_usrp0hb0 child<cxl-downstream>`, `cxlrp0hb1 child<cxl-rp>`,
  `cxl_shared0 child<cxl-type3>` (pxb-cxl = child<pxb-cxl>, cxl-upstream).
- The bus a port provides has the port's id: `/machine/peripheral/<port>/<port>`.
  `qom-list` on it shows `child[0]: link<cxl-type3>` when occupied, only
  type/acpi-pcihp-bsel/realized/hotplug-handler when free.
- For a cxl-type3 `<dev>`: `qom-get parent_bus` ->
  `"/machine/peripheral/cxlsw_ds0_usrp0hb0/cxlsw_ds0_usrp0hb0"`, `sn` ->
  `3253792256`, `volatile-memdev` -> `"/objects/shared0"`, `hotplugged` ->
  false/true. Port props: `power_controller_present` (true on patched
  cxl-downstream and on cxl-rp), `hotplug` true, `slot`, `chassis`.
  A cxl-rp that has a cxl-upstream below it is not a free slot (check the
  child type).
- `query-pci` also works and includes qdev_id (class 1282 = 0x0502 CXL mem)
  but bus numbers depend on guest enumeration; prefer QOM.
- `qmp.py SOCK slots` parses `info qtree -b` (HMP fallback):
  `cxlsw_ds0_usrp0hb0 cxl-downstream cxl-type3:cxl_shared0` / `cxlrp0hb1 cxl-rp -`.
- `query-memdev` lists object-add'ed backends (`id, size, share, prealloc,
  ...`) but NOT mem-path; use `qom-get {"path":"/objects/shared0","property":"mem-path"}`.
  `qom-list /objects` lists all object ids.
- fmw sizes: `qom-get {"path":"/machine","property":"cxl-fmw"}` ->
  `[{"targets":["cxlhb0"],"size":4294967296},{"targets":["cxlhb1"],"size":4294967296}]`.
- QMP socket accepts ONE client at a time; a 2nd connection gets no greeting
  until the 1st closes (tested). Events go only to the connected client. So
  the server must own a persistent QMP connection per VM (and wait for
  DEVICE_DELETED on it), or open/close per operation and poll QOM.

### Blocker found for Q4: guest kernel lacks CONFIG_FS_DAX

After `daxctl reconfigure-device --mode=devdax dax0.0`, mmap(/dev/dax0.0,
MAP_SHARED, 256M) fails with EINVAL; dmesg:
`device_dax dax0.0: python3: dax_mmap_prepare: fail, vma is not DAX capable`.
In 7.3 drivers/dax/device.c `__check_vma()` requires `file_is_dax()`, i.e.
IS_DAX(inode), and include/linux/fs.h has `#define S_DAX 0` when
CONFIG_FS_DAX is unset. /boot/config-7.3.0-rc4 (= test/e2e/playbook/files/qemu-cxl-kernel.config):
`# CONFIG_FS_DAX is not set`. **WS4: set CONFIG_FS_DAX=y in
qemu-cxl-kernel.config** (olddefconfig then also adds FS_DAX_PMD,
DEV_DAX_FSDEV, FUSE_DAX); devdax sharing is impossible without it.
Workaround here: built the guest's own tree (vagrant ~/linux, 7.3-rc4) on the
host with FS_DAX=y (`make O=... -j200 bzImage`, 41 s) and boot the direct VMs
with `-kernel` (see launch-vm.sh KERNEL=).

### Rerun with the FS_DAX kernel (vmA, vmB, both patched qemu)

```
KERNEL=$W/kernel/bzImage-7.3.0-rc4-fsdax HBOPT=",hdm_for_passthrough=on" ./launch-vm.sh vmA 52201 \
  -object memory-backend-file,id=shared0,share=on,mem-path=/tmp/fake-cxl-pool-ws3/shared0.raw,size=256M \
  -device cxl-type3,bus=cxlsw_ds0_usrp0hb0,volatile-memdev=shared0,id=cxl_shared0,sn=0xc1f0ee00
```
(same for vmB 52202). `uname -a`: `7.3.0-rc4 #1 SMP PREEMPT Fri Oct 2 16:42:48 EEST 2026`.
With hdm_for_passthrough=on the host bridge port shows decoder2.0..decoder2.3.

### Q3b: hdm_for_passthrough=on gives several regions per host bridge: YES

mem0 in region0 (decoder2.0), then mem1 hotplugged to cxlsw_ds1_usrp0hb0:
`cxl create-region -t ram -d decoder0.0 -m mem1` -> `created 1 region`, region2;
`decoder2.0 region=region0`, `decoder2.1 region=region2`. Both regions of one
CFMW window get the same guest NUMA node (dax target_node 1 for both).

### Q4 data sharing via devdax: YES (with CONFIG_FS_DAX=y)

- Default driver after `cxl create-region -t ram`: **kmem** (daxctl mode
  "system-ram", online_memblocks 0 because auto_online_blocks=offline,
  CONFIG_MHP_DEFAULT_ONLINE_TYPE_OFFLINE=y). While bound to kmem,
  open("/dev/dax0.0") fails with ENXIO.
- Switch: `daxctl reconfigure-device --mode=devdax dax0.0` (works when the
  blocks are offline) -> driver device_dax; the reverse is
  `daxctl reconfigure-device --mode=system-ram dax0.0`, which ONLINES the
  blocks (movable) unless `--no-online` is given. sysfs alternative:
  `echo dax0.0 > /sys/bus/dax/drivers/kmem/unbind; echo dax0.0 > /sys/bus/dax/drivers/device_dax/bind`
  (not needed, daxctl worked every time). dax align is 2M.
- `guest-dax-rw.py write /dev/dax0.0 FROM-A` (offsets 0,1,100,255 M) in A,
  `read` in B: `0M: b'FROM-A@0M' 1M: b'FROM-A@1M' 100M: b'FROM-A@100M' 255M: b'FROM-A@255M'`.
  B writes 1M and 255M, A reads `FROM-A@0M, FROM-B@1M, FROM-A@100M, FROM-B@255M`.
  Host `dd if=shared0.raw bs=1M skip=N` shows the same strings; md5sum of
  the file changes with every write (1f50... -> 98f2... -> 3c1e...).
- Bandwidth (python mmap slice copy, 254M, guest):
  devdax pass0 write 0.78 GB/s (first touch faults), pass1 write 7.43 GB/s,
  read 5.0 GB/s; guest anonymous RAM: write 7.54 GB/s, read 5.1 GB/s. So
  KVM maps it directly (`info mtree -f`: `shared0 KVM`, via the
  `cxl-direct-mapping-alias-0` that qemu maps into the CFMW when the HDM
  decoder is committed).
- Runtime-attached sharing (the pool server flow): the same new file
  object-add'ed in both VMs (`id pool5, size 536870912`), device_add on
  cxlrp0hb1 with sn 3253792261 in both; guest names differ (A: mem2/region1/dax1.0,
  B: mem1/region3/dax3.0) but the serial matches; A writes, B reads and vice
  versa: identical. `guest-dax-rw.py find 0xc1f0ee05` maps serial -> mem,
  region, dax; `serial:0x...` can be given instead of a /dev path.

### Q5 system-ram pooling and re-attach: YES with the patched qemu

- region2 (mem1, shared1) kmem, `echo online_movable > /sys/devices/system/memory/memoryN/state`
  for its 2 blocks (block size 128M) -> `valid_zones Movable`,
  `numactl -H`: node 1 256 MB. `numactl --membind=1 memhog 200M` rc 0;
  tmpfs `mount -t tmpfs -o size=200M,mpol=bind:1` + dd 150M: node 1 MemFree
  262036 kB -> 108516 kB; host shared1.raw grew to 417792 blocks.
- Release + detach (exact sequence that works):
  ```
  for b in 52 53; do echo offline > /sys/devices/system/memory/memory$b/state; done
  cxl disable-region region2 && cxl destroy-region region2
  cxl disable-memdev mem1
  QMP device_del {"id":"cxl_shared1.hp1"} -> DEVICE_DELETED after 6.09 s
  QMP object-del {"id":"shared1"} -> {}
  ```
- Re-attach same file, same slot, same sn: object-add shared1 + device_add
  id cxl_shared1.hp2 -> guest mem1 serial 0xc1f0ee01, region created again.
  The old device id can be reused too after DEVICE_DELETED (device_add
  id=cxl_shared1.hp1 again -> ok), so the `.hpN` suffix workaround in
  vm-cxl-hotplug is only needed for stock qemu. Data in the file survives
  detach/attach: "PERSIST@0M/200M" written before detach read back after
  re-attach.
- Stock /usr/bin/qemu-system-x86_64 (11.1.1 openSUSE), same VM setup (vmC):
  - cxl-downstream slot: guest says `Button press: will power off in 5 sec`
    and `pci 0000:10:00.0: device released`, but DEVICE_DELETED never comes
    (20 s), the device stays in the qtree, and then
    `device_add ... bus=cxlsw_ds1_usrp0hb0` -> `PCI: slot 0 function 0 already occupied by cxl-type3, new func cxl-type3 cannot be exposed to guest.`
    and `object-del stock0` -> `Cannot delete host memory backend 'stock0' which is mapped`.
  - cxl-rp slot (root port has a power controller in stock qemu too):
    DEVICE_DELETED in 6.26 s and the slot can take a NEW backend, but the old
    backend stays "mapped" forever (`Cannot delete host memory backend 'stock2' which is mapped`),
    so it can never be attached again (`memory backend X can't be used multiple times.`).
  - Detection of the patched build (QMP, no guest needed):
    `qom-get {"path":"/machine/peripheral/<any cxl-downstream id>","property":"power_controller_present"}`
    -> `true` on the patched build, error
    `Property 'cxl-downstream.power_controller_present' not found` on stock.

### Q6b hot-remove while a process has the devdax device mmapped: completes

vmB, pool device on cxlrp0hb1, devdax, guest-dax-hold.py writing every 1 s.
`device_del` -> DEVICE_DELETED after 6.23 s, `info mtree` no longer has the
alias, the slot is free. The guest process gets SIGBUS
(`coredumpctl`: `SIG SIGBUS ... /usr/bin/python3.14`) at removal; its last
write is in the host file. Guest leftovers: an orphan region (`regionN`,
commit 0, `cxl destroy-region` fails with ENXIO); remove it with
`echo regionN > /sys/bus/cxl/devices/decoder0.X/delete_region`; afterwards
a new device in the same slot gets a region again.
Summary of Q6: online system-ram -> zombie, never DEVICE_DELETED (qemu
restart needed); devdax (mapped or not), or no region -> DEVICE_DELETED in
~6 s; users of devdax die with SIGBUS. Release first, then detach.

### Q8 backend options

- share=on on tmpfs with prealloc=off: works (Q1, Q4); the file stays sparse
  until touched. prealloc=true: the whole file is allocated at object-add
  (524288 blocks for 256M).
- align: `"align":2097152` and `"align":1073741824` are accepted for a tmpfs
  file; not needed (devdax align 2M is a guest property, the window
  mapping is 256M-aligned anyway).
- discard-data: MUST stay false (default). With `"discard-data":true` the
  file was PUNCHED at object-del (pre-written host data gone, 0 blocks) even
  though no device used it: it would wipe a shared device under the other
  VMs. With false the data stayed.
- Size rules: device size must be a multiple of 256 MiB. qemu accepts 128M
  and 384M backends for cxl-type3, but the guest cxl_pci binds no driver
  (no memN appears; CXL_CAPACITY_MULTIPLIER = SZ_256M). 512M works. fmw
  sizes must be multiples of 256MiB (qemu error text "Size of a CXL fixed
  memory window must be a multiple of 256MiB").
- Existing file smaller than size: `mm536870912 backing store size 0x10000000 is too small for 'size' option 0x20000000 plus 'offset' option 0x0`;
  bigger than size: ok (first size bytes used). The file is never shrunk.
- File not writable (0444): `can't open backing store /tmp/fake-cxl-pool-ws3/ro.raw for guest RAM: Permission denied`.
- mem-path pointing to a DIRECTORY is accepted but qemu then creates an
  unlinked private temp file there: NOT shared. Always give a file path.
- Other failure strings: duplicate object id ->
  `attempt to add duplicate property 'shared0' to object (type 'container')`;
  backend already used -> `memory backend shared0 can't be used multiple times.`;
  missing backend -> `{"class":"DeviceNotFound","desc":"Device 'nope' not found"}`;
  bad bus -> `Bus 'nosuchbus' not found`; occupied slot -> `PCI: slot 0 function 0 already occupied by cxl-type3, new func cxl-type3 cannot be exposed to guest.`;
  object-del of a backend in use -> `Cannot delete host memory backend 'shared0' which is mapped`;
  device_del unknown -> `{"class":"DeviceNotFound","desc":"Device 'nosuch' not found"}`;
  second device_del during unplug -> `Device X is already in the process of unplug`.
- Host NUMA placement: pages of a shared tmpfs file land where the first
  toucher faults them (or per tmpfs mpol mount option); policy/host-nodes of
  the backend object only affect that qemu's mapping. Not relevant for the
  e2e test.

### Q9 both guests online the same shared region as system-ram

Both: `daxctl reconfigure-device --mode=system-ram dax0.0` (onlines both
blocks, movable), each `numactl -H` shows node 1 256 MB free. A writes a
150M random file into a tmpfs bound to node 1 (A node 1 MemFree 106724 kB),
B still sees 262144 kB free and runs `numactl --membind=1 memhog 200M`
(rc 0). A's file md5 changes 5ebfe2cd... -> aad990e3... No kernel message in
either guest: silent corruption. Also the kernel makes the CXL node a
demotion target ("Demotion targets for Node 0: preferred: 1"), so memory
tiering could put pages there behind the user's back. This is why shared
devices must be devdax only.

### Q-extra: HMP equivalents that do not need qtree parsing

HMP has `qom-list` and `qom-get` (same data as QMP):
```
(qemu) qom-list /machine/peripheral        -> "cxlsw_ds1_usrp0hb0 (child<cxl-downstream>)" ...
(qemu) qom-get /machine/peripheral/cxl_shared0 sn         -> 3253792256
(qemu) qom-get /machine/peripheral/cxl_shared0 parent_bus -> "/machine/peripheral/cxlsw_ds0_usrp0hb0/cxlsw_ds0_usrp0hb0"
(qemu) info memdev                          -> "memory backend: shared0" + size/share/...
```
Raw `socat - UNIX-CONNECT:monitor.sock` echoes readline editing escape
sequences; the result follows the echoed command line and ends at the next
"(qemu)" prompt (vm-monitor strips only \r). HMP gives no events: poll
`qom-list /machine/peripheral` for the device id disappearing after device_del.

## Recipes

### qemu command line
```
-machine q35,kernel-irqchip=split,cxl=on,accel=kvm -m 4G        # no maxmem/slots needed for CXL
-device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxlhb0,numa_node=0,hdm_for_passthrough=on
-device cxl-rp,port=0,bus=cxlhb0,id=cxlrp0hb0,chassis=193,slot=0
-device cxl-upstream,bus=cxlrp0hb0,id=cxlsw_usrp0hb0
-device cxl-downstream,port=1,bus=cxlsw_usrp0hb0,id=cxlsw_ds0_usrp0hb0,chassis=193,slot=1   # slot
-device cxl-downstream,port=2,bus=cxlsw_usrp0hb0,id=cxlsw_ds1_usrp0hb0,chassis=193,slot=2   # slot
-M cxl-fmw.0.targets.0=cxlhb0,cxl-fmw.0.size=4G            # >= sum of regions, multiple of 256M
-qmp unix:qmp.sock,server,nowait                           # one client at a time
# statically shared device (identical in every VM sharing it):
-object memory-backend-file,id=shared0,share=on,mem-path=/tmp/fake-cxl-pool/shared0.raw,size=256M
-device cxl-type3,bus=cxlsw_ds0_usrp0hb0,volatile-memdev=shared0,id=cxl_shared0,sn=0xc1f0ee00
```
Give NICs/disks an explicit bus= (pcie.0 / a pcie-root-port). Patched qemu
required for re-attach to cxl-downstream slots.

### QMP
```
# attach
{"execute":"object-add","arguments":{"qom-type":"memory-backend-file","id":"pool5","share":true,"mem-path":"/tmp/fake-cxl-pool/pool5.raw","size":536870912}}
{"execute":"device_add","arguments":{"driver":"cxl-type3","bus":"cxlrp0hb1","volatile-memdev":"pool5","id":"cxl_pool5","sn":3253792261}}
# detach (guest must have released it: no online blocks; region destroyed or devdax)
{"execute":"device_del","arguments":{"id":"cxl_pool5"}}
  ... wait on the SAME connection for
{"event":"DEVICE_DELETED","data":{"device":"cxl_pool5","path":"/machine/peripheral/cxl_pool5"}}   # ~6 s; timeout 15-30 s
{"execute":"object-del","arguments":{"id":"pool5"}}
# list slots / devices
{"execute":"qom-list","arguments":{"path":"/machine/peripheral"}}        # child<cxl-downstream>, child<cxl-rp>, child<cxl-type3>
{"execute":"qom-list","arguments":{"path":"/machine/peripheral/<port>/<port>"}}   # "child[0]" link<cxl-type3> if occupied
{"execute":"qom-get","arguments":{"path":"/machine/peripheral/<dev>","property":"parent_bus"}}  # "/machine/peripheral/<port>/<port>"
{"execute":"qom-get","arguments":{"path":"/machine/peripheral/<dev>","property":"sn"}}          # integer
{"execute":"qom-get","arguments":{"path":"/machine/peripheral/<dev>","property":"volatile-memdev"}}  # "/objects/<id>"
# list memdevs
{"execute":"query-memdev"}                                                # id,size,share,prealloc (no path)
{"execute":"qom-get","arguments":{"path":"/objects/<id>","property":"mem-path"}}
{"execute":"qom-get","arguments":{"path":"/machine","property":"cxl-fmw"}}  # [{"targets":["cxlhb0"],"size":...}]
# patched build check
{"execute":"qom-get","arguments":{"path":"/machine/peripheral/<cxl-downstream>","property":"power_controller_present"}}
```
### HMP
```
object_add memory-backend-file,id=pool5,share=on,mem-path=/tmp/fake-cxl-pool/pool5.raw,size=512M
device_add cxl-type3,bus=cxlrp0hb1,volatile-memdev=pool5,id=cxl_pool5,sn=0xc1f0ee05
device_del cxl_pool5              # then poll: qom-list /machine/peripheral (id gone) or info qtree -b
object_del pool5
qom-list /machine/peripheral ; qom-get /machine/peripheral/cxl_pool5 sn ; info memdev
```
### guest: devdax sharing (every VM attached to a shared device)
```
dnf install -y daxctl                        # + kernel with CONFIG_FS_DAX=y
echo offline > /sys/devices/system/memory/auto_online_blocks   # already the default here
M=$(grep -l '^0xc1f0ee05$' /sys/bus/cxl/devices/mem*/serial | cut -d/ -f6)
cxl create-region -t ram -d decoder0.N -m $M  # N = root decoder (CFMW) of the host bridge
daxctl reconfigure-device --mode=devdax daxR.0   # kmem is the default
# apps: open /dev/daxR.0 O_RDWR, mmap MAP_SHARED, length multiple of 2M
# release:
cxl disable-region regionR && cxl destroy-region regionR ; cxl disable-memdev $M
```
### guest: system-ram pooling (exclusive device only)
```
cxl create-region -t ram -d decoder0.N -m $M
for b in <region blocks: resource/block_size .. (resource+size)/block_size-1>; do
  echo online_movable > /sys/devices/system/memory/memory$b/state; done
# (or daxctl reconfigure-device --mode=system-ram daxR.0, which onlines movable)
# release:
for b in ...; do echo offline > /sys/devices/system/memory/memory$b/state; done
cxl disable-region regionR && cxl destroy-region regionR ; cxl disable-memdev $M
```
### guest: after a surprise removal
`echo regionR > /sys/bus/cxl/devices/decoder0.N/delete_region` (orphan region).
Memory that was online stays "stuck online until reboot".

### rules
- CXL memory does not count against -m maxmem/slots.
- Device size: multiple of 256 MiB; fmw size >= sum of regions, multiple of 256M.
- One region per host bridge with a single cxl-rp unless its pxb-cxl has
  hdm_for_passthrough=on (then 4 HDM decoders = 4 regions).
- sn: QMP uint64 integer; HMP/cmdline accept 0x hex; guest prints 0x%x.
- discard-data must be false; mem-path must be a file, not a directory.
- Guest kernel needs CONFIG_FS_DAX=y for devdax mmap.
- One QMP client per socket; DEVICE_DELETED only on the connection that is open.
- No DEVICE_DELETED in ~15 s = guest still had the memory online: backend
  leaked until qemu restart; do not give it to anyone else.
