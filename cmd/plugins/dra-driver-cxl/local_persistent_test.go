// Copyright The NRI Plugins Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

const (
	localPmemSerial     = 0xc100f5e1
	localPmemDeviceName = "memdev-c100f5e1"
	localPmemBlockRW    = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"block"}}`
	localPmemBlockRO    = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"block","readOnly":true}}`
	localPmemFsRW       = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","readOnly":false}}`
	localPmemFsRO       = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs"}}`
	// the shares of an exclusive claim and of a share
	localPmemAll, localPmemShare = "1M", "1"
	// localPmemPath is the default path of mode fs of the memdev.
	localPmemPath = "/run/cxl-fs/C100F5E1"
	// localAboveSerial is a memdev of RAM under the host bridge of the
	// persistent memdev that the driver does not use.
	localAboveSerial = 0xc100f5e2
)

// pmemTestEnv is a localTestEnv with the local memdev localPmemSerial of
// 512 MiB of persistent memory, every filesystem type that the plugin
// knows allowed.
type pmemTestEnv struct {
	*localTestEnv
	// above are the regions of other memdevs that the test made.
	above []string
	// blockDevice is the block device of the memdev that formatted made.
	blockDevice string
}

// newPmemTestEnv returns a pmemTestEnv, not started.
func newPmemTestEnv(t *testing.T) *pmemTestEnv {
	t.Helper()
	e := &pmemTestEnv{localTestEnv: newLocalTestEnv(t, fakeMemdevSpecPmem(localPmemSerial))}
	e.config.FsTypes = slices.Clone(config.KnownFsTypes)
	return e
}

// formatted makes the fsdax namespace of the memdev with a filesystem of
// the types on it, as a writer on another host leaves it, and returns its
// block device.
func (e *pmemTestEnv) formatted(types ...string) string {
	e.t.Helper()
	return e.formatPmem(localPmemSerial, types...)
}

// memdev returns the name of the memdev in the kernel.
func (e *pmemTestEnv) memdev() string {
	return e.k.Memdev(localPmemSerial)
}

// region returns the region of the memdev, "" for none.
func (e *pmemTestEnv) region() string {
	if rs := e.regions(localPmemSerial); len(rs) > 0 {
		return rs[0]
	}
	return ""
}

// namespace returns the fsdax namespace of the region of the memdev in the
// kernel, nil if there is none.
func (e *pmemTestEnv) namespace() *kernel.Namespace {
	k := e.k.Kernel()
	nd, err := k.NdRegionOf(e.region())
	if err != nil {
		return nil
	}
	nss, _, err := k.ProbeNamespaces(nd)
	if err != nil {
		return nil
	}
	return kernel.FsdaxNamespace(nss)
}

// nodeMount returns the node mount of the memdev with the access.
func (e *pmemTestEnv) nodeMount(access string) string {
	return filepath.Join(e.dir, mountsDirName, "c100f5e1-"+access)
}

// mounted returns the mount at target in the mount namespace of the
// driver, nil if there is none.
func (e *pmemTestEnv) mounted(target string) *kernel.MountInfo {
	e.t.Helper()
	mi, err := e.k.Kernel().Mounted(target)
	noErr(e.t, err)
	return mi
}

// used tells whether the engine has a record of the memdev.
func (e *pmemTestEnv) used() bool {
	return e.localSnapshot().InUse(localPmemSerial)
}

// published returns the memdev as a scan publishes it now, nil if it does
// not.
func (e *pmemTestEnv) published() *resourcev1.Device {
	e.t.Helper()
	e.rescan()
	for _, d := range e.publisher.Resources().Pools[testNode].Slices[0].Devices {
		if d.Name == localPmemDeviceName {
			return &d
		}
	}
	return nil
}

// wantPmemCDIDevice checks the env, the device nodes and the mounts of a
// CDI device of the claims spec.
func (e *pmemTestEnv) wantPmemCDIDevice(name string, env []string, nodes []*cdiSpecs.DeviceNode, mounts []*cdiSpecs.Mount) {
	e.t.Helper()
	d := cdiDeviceByName(e.cdiSpec(), name)
	same := func(a, b any, n int) bool { return n == 0 || reflect.DeepEqual(a, b) }
	if d == nil || !slices.Equal(d.ContainerEdits.Env, env) ||
		len(d.ContainerEdits.DeviceNodes) != len(nodes) || !same(d.ContainerEdits.DeviceNodes, nodes, len(nodes)) ||
		len(d.ContainerEdits.Mounts) != len(mounts) || !same(d.ContainerEdits.Mounts, mounts, len(mounts)) {
		var got any = d
		if d != nil {
			got = d.ContainerEdits
		}
		e.t.Fatalf("CDI device %s: %+v, expected env %v nodes %+v mounts %+v", name, got, env, nodes, mounts)
	}
}

// wantRegions checks how many times the driver created a region of the
// memdev and destroyed one, and that it never disabled a memdev.
func (e *pmemTestEnv) wantRegions(created, destroyed int) {
	e.t.Helper()
	cmds := e.commands()
	c, d := 0, 0
	for _, l := range strings.Split(cmds, "\n") {
		switch {
		case strings.HasPrefix(l, "cxl create-region ") && strings.HasSuffix(l, " -m "+e.memdev()):
			c++
		case strings.HasPrefix(l, "cxl destroy-region ") && !slices.Contains(e.above, strings.TrimPrefix(l, "cxl destroy-region ")):
			d++
		}
	}
	if c != created || d != destroyed {
		e.t.Fatalf("region created %d and destroyed %d times, expected %d and %d:\n%s", c, d, created, destroyed, cmds)
	}
	if strings.Contains(cmds, "disable-memdev") {
		e.t.Fatalf("a memdev was disabled:\n%s", cmds)
	}
}

// wantNoViolations fails the test on a violation of the rules of
// persistent devices in the kernel.
func (e *pmemTestEnv) wantNoViolations() {
	e.t.Helper()
	if v := e.k.Violations(); len(v) > 0 {
		e.t.Fatalf("violations %v", v)
	}
}

// keepIdle prepares and unprepares a reader of the memdev below a region
// of another memdev, which keeps the region of the idle device, and
// returns its block device.
func (e *pmemTestEnv) keepIdle() string {
	e.t.Helper()
	e.mustPrepare(pmemClaim("keep", localPmemShare, localPmemFsRO))
	e.regionAbove()
	e.mustUnprepare("keep")
	ns := e.namespace()
	if ns == nil || !e.used() {
		e.t.Fatalf("no idle region with a namespace: %v", e.regions(localPmemSerial))
	}
	return ns.BlockDevice
}

// plugAbove plugs the memdev localAboveSerial, which no claim of the
// driver uses.
func (e *pmemTestEnv) plugAbove() {
	e.k.Plug(fake.MemdevSpec{Serial: localAboveSerial, HostBridge: 24})
	e.base = e.k.Commands()
}

// regionAbove makes a region on the memdev localAboveSerial, above the
// region of the memdev in the decoders of their host bridge, and returns
// it.
func (e *pmemTestEnv) regionAbove() string {
	e.t.Helper()
	k := e.k.Kernel()
	memdev := e.k.Memdev(localAboveSerial)
	d, err := k.RootDecoder(memdev, kernel.RegionRAM)
	noErr(e.t, err)
	region, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: memdev, Decoder: d, Type: kernel.RegionRAM})
	noErr(e.t, err)
	e.above = append(e.above, region)
	return region
}

// releaseAbove releases the regions that regionAbove made.
func (e *pmemTestEnv) releaseAbove() {
	e.t.Helper()
	for _, region := range e.above {
		noErr(e.t, e.k.Kernel().ReleaseRegion(context.Background(), region))
	}
}

// infoOf returns the info of the first device of a prepared claim.
func (e *pmemTestEnv) infoOf(uid string) PreparedDeviceInfo {
	e.t.Helper()
	info := e.s.ClaimInfo(uid)
	if info == nil || len(info.Devices) == 0 {
		e.t.Fatalf("claim %s is not prepared", uid)
	}
	return info.Devices[0]
}

// mountCallsSince returns the system calls of the mount table after the
// first n but the reads of superblocks.
func (e *pmemTestEnv) mountCallsSince(n int) []string {
	return slices.DeleteFunc(slices.Clone(e.k.MountCalls("")[n:]), func(c string) bool { return strings.HasPrefix(c, "superblocks ") })
}

// wantMountCalls checks the system calls of the mount table after the
// first n.
func (e *pmemTestEnv) wantMountCalls(n int, want ...string) {
	e.t.Helper()
	if got := e.mountCallsSince(n); !slices.Equal(got, want) {
		e.t.Fatalf("calls %q, expected %q", got, want)
	}
}

// pmemClaim returns a claim allocated the persistent memdev for request
// "mem" with the consumed shares ("": none), and opaque cxl.nri.io claim
// configs.
func pmemClaim(uid, shares string, configs ...string) *resourcev1.ResourceClaim {
	c := memdevClaim(uid, localPmemDeviceName, 0, configs...)
	if shares != "" {
		c.Status.Allocation.Devices.Results[0].ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse(shares)}
	}
	return c
}

// pmemCompanion returns pmemClaim as the companion claim of lease l1.
func pmemCompanion(uid, shares string, configs ...string) *resourcev1.ResourceClaim {
	c := pmemClaim(uid, shares, configs...)
	c.ObjectMeta = companionClaim("l1").ObjectMeta
	c.UID = types.UID(uid)
	return c
}

// pmemEnv returns the env of a CDI device of the persistent memdev.
func pmemEnv(uid string, kv ...string) []string {
	env := []string{"CXL_CLAIM_" + uid + "_0=1"}
	for _, s := range kv {
		env = append(env, "CXL_C100F5E1_"+s)
	}
	slices.Sort(env)
	return env
}

// pmemFsConfig returns a MemoryConfig of mode fs, read-only or not, with
// the access and the fsType ("": none).
func pmemFsConfig(readOnly bool, access, fsType string) string {
	extra := []string{}
	if access != "" {
		extra = append(extra, `"access":"`+access+`"`)
	}
	if fsType != "" {
		extra = append(extra, `"fsType":"`+fsType+`"`)
	}
	cfg := memoryConfig(api.ModeFs, readOnly, strings.Join(extra, ","))
	if !readOnly {
		cfg = strings.Replace(cfg, `"mode":"fs"`, `"mode":"fs","readOnly":false`, 1)
	}
	return cfg
}

// The life cycle of a persistent local memdev: readers refused before a
// block writer makes the namespace, fs writers and readers of one node mount.
func TestLocalPersistentLifeCycle(t *testing.T) {
	e := newPmemTestEnv(t)
	e.start()
	if d := e.published(); d == nil || !*d.Attributes["persistent"].BoolValue || *d.Attributes["shared"].BoolValue {
		t.Fatalf("published %+v", d)
	}

	// readers before a writer: refused, the region goes again
	wantErr(t, e.prepare(pmemClaim("r1", localPmemShare, localPmemFsRO)),
		"claim demo/claim-r1: request mem: device 0xc100f5e1: no fsdax namespace in region0: has a writer written the device?")
	wantErr(t, e.prepare(pmemClaim("r1", localPmemShare, localPmemBlockRO)), "no fsdax namespace in region0")
	e.wantRegions(2, 2)
	if strings.Contains(e.commands(), "ndctl") || e.used() {
		t.Fatalf("a reader made a namespace or holds the device:\n%s", e.commands())
	}

	// the configuration rules, before the device is touched
	before := e.commands()
	wantErr(t, e.prepare(pmemClaim("w0", localPmemShare, localPmemBlockRW)),
		"claim demo/claim-w0: request mem: MemoryConfig: device.mode block: a persistent local device is writable only exclusively (no shares request)")
	wantErr(t, e.prepare(pmemClaim("w0", localPmemShare)), "MemoryConfig: device: a persistent device needs mode block or fs")
	wantErr(t, e.prepare(pmemClaim("w0", "0", localPmemBlockRW)), "device 0xc100f5e1: consumed shares \"0\" is less than 1")
	claim := pmemClaim("w0", "", localPmemBlockRW)
	claim.Status.Allocation.Devices.Results[0].ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{device.CapacityMemory: resource.MustParse("1Gi")}
	wantErr(t, e.prepare(claim), "claim demo/claim-w0: request mem: device 0xc100f5e1: allocated as a device of volatile memory, which it is not any more")
	if e.commands() != before {
		t.Fatalf("a refused claim touched the device:\n%s", strings.TrimPrefix(e.commands(), before))
	}

	// the block writer has the device alone and makes the namespace
	e.mustPrepare(pmemClaim("w1", localPmemAll, localPmemBlockRW))
	if !strings.Contains(e.commands(), "ndctl create-namespace -f -r region0 -m fsdax -M mem") {
		t.Fatalf("no namespace made:\n%s", e.commands())
	}
	ns := e.namespace()
	if ns == nil {
		t.Fatal("no fsdax namespace")
	}
	pmem := ns.BlockDevice
	e.wantPmemCDIDevice("claim-w1-0",
		pmemEnv("w1", "MODE=block", "PATH="+pmem, "READONLY=0", "SERIAL=0xc100f5e1", "SHARED=0", "SIZE=534773760"),
		[]*cdiSpecs.DeviceNode{{Path: pmem, Type: "b", Major: int64(ns.Major), Minor: int64(ns.Minor)}}, nil)
	if e.k.IsReadOnly(pmem) {
		t.Fatal("the block device of a writer is read-only")
	}
	info := e.infoOf("w1")
	if !info.Persistent || info.Mode != api.ModeBlock || info.BlockDevice != pmem || info.Namespace != "namespace0.0" || info.TotalBytes != fakePmemBytes || info.ReadOnly {
		t.Fatalf("prepared %+v", info)
	}
	// the writer writes an ext4
	e.k.SetImage(pmem, fsImage("ext4"))
	e.mustUnprepare("w1")
	e.wantRegions(3, 3)
	if e.used() || e.published() == nil {
		t.Fatal("the idle device is used or not published")
	}

	// fs writers and a reader of one node mount
	e.mustPrepare(pmemClaim("rw1", localPmemShare, localPmemFsRW))
	e.mustPrepare(pmemClaim("rw2", localPmemShare, localPmemFsRW))
	e.mustPrepare(pmemClaim("ro1", localPmemShare, localPmemFsRO))
	e.wantRegions(4, 3)
	pmem = e.namespace().BlockDevice
	mnt := e.nodeMount("direct")
	for uid, ro := range map[string]bool{"rw1": false, "rw2": false, "ro1": true} {
		readOnly, opts := "0", []string{"bind", "nosuid", "nodev"}
		if ro {
			readOnly, opts = "1", []string{"bind", "ro", "nosuid", "nodev"}
		}
		e.wantPmemCDIDevice("claim-"+uid+"-0",
			pmemEnv(uid, "ACCESS=direct", "FSTYPE=ext4", "MODE=fs", "PATH="+localPmemPath, "READONLY="+readOnly, "SERIAL=0xc100f5e1", "SHARED=0", "SIZE=534773760"),
			nil, []*cdiSpecs.Mount{{HostPath: mnt, ContainerPath: localPmemPath, Type: "bind", Options: opts}})
	}
	if mi := e.mounted(mnt); mi == nil || mi.FsType != "ext4" || mi.SuperReadOnly() || len(e.k.MountTable()) != 1 {
		t.Fatalf("node mount %+v of mounts %+v", mi, e.k.MountTable())
	}
	// the last writer goes: the superblock and the block device turn
	// read-only, the reader stays
	e.mustUnprepare("rw1")
	if mi := e.mounted(mnt); mi == nil || mi.SuperReadOnly() {
		t.Fatalf("after one writer: %+v", mi)
	}
	e.mustUnprepare("rw2")
	if mi := e.mounted(mnt); mi == nil || !mi.SuperReadOnly() || !e.k.IsReadOnly(pmem) {
		t.Fatalf("after the writers: %+v, read-only %v", mi, e.k.IsReadOnly(pmem))
	}
	// a held block device keeps the region and the claim for kubelet's
	// retry
	e.k.SetHolder(pmem, "in use")
	wantErr(t, e.unprepare("ro1"), "device 0xc100f5e1: "+pmem+" is still in use")
	e.wantRegions(4, 3)
	if e.preparation("ro1") == nil {
		t.Fatal("the claim is gone after a failed release")
	}
	e.k.SetHolder(pmem, "")
	e.mustUnprepare("ro1")
	e.wantRegions(4, 4)
	if len(e.k.MountTable()) != 0 || e.cdiSpec() != nil || e.used() {
		t.Fatalf("left: mounts %+v", e.k.MountTable())
	}
	e.wantClean()
	e.wantNoViolations()
}

// Restarts mount the node mounts again as their uses derive and sweep the
// unwanted ones; a reboot drops the claims of the other boot untouched.
func TestLocalPersistentRestart(t *testing.T) {
	e := newPmemTestEnv(t)
	pmem := e.formatted("ext4")
	e.start()
	e.mustPrepare(pmemClaim("rw1", localPmemShare, localPmemFsRW))
	e.mustPrepare(pmemClaim("ro1", localPmemShare, localPmemFsRO))
	mnt := e.nodeMount("direct")

	// a restart with the node mount in place: nothing changes
	before, n := e.k.Commands(), len(e.k.MountCalls(""))
	e.restart()
	if mi := e.mounted(mnt); mi == nil || mi.SuperReadOnly() || e.k.CommandsSince(before) != "" {
		t.Fatalf("after a restart: %+v\n%s", mi, e.k.CommandsSince(before))
	}
	for _, c := range e.mountCallsSince(n) {
		if !strings.HasPrefix(c, "blkroget") {
			t.Fatalf("the restart touched the mounts: %q", e.mountCallsSince(n))
		}
	}
	if cdiDeviceByName(e.cdiSpec(), "claim-rw1-0") == nil || cdiDeviceByName(e.cdiSpec(), "claim-ro1-0") == nil {
		t.Fatal("CDI devices lost in a restart")
	}

	// the node mount is gone: mounted again read-write for the writer
	noErr(t, e.k.Kernel().Unmount(mnt))
	e.restart()
	if mi := e.mounted(mnt); mi == nil || mi.SuperReadOnly() || e.k.IsReadOnly(pmem) {
		t.Fatalf("not mounted again read-write: %+v", mi)
	}

	// the writer goes: the superblock turns read-only; a start mounts the
	// node mount of the reader again read-only
	e.mustUnprepare("rw1")
	if mi := e.mounted(mnt); mi == nil || !mi.SuperReadOnly() || !e.k.IsReadOnly(pmem) {
		t.Fatalf("writer gone: %+v", mi)
	}
	noErr(t, e.k.Kernel().Unmount(mnt))
	e.restart()
	if mi := e.mounted(mnt); mi == nil || !mi.SuperReadOnly() || !e.k.IsReadOnly(pmem) {
		t.Fatalf("not mounted again read-only: %+v", mi)
	}
	if use, _ := e.localSnapshot().Use(localPmemSerial); !slices.Equal(use.Claims, []string{"ro1"}) {
		t.Fatalf("uses %+v", use)
	}

	// the last claim releases the device; a mount in the mounts directory
	// that no claim lists is swept at the start
	e.mustUnprepare("ro1")
	e.wantRegions(1, 1)
	stray := e.nodeMount("cached")
	noErr(t, os.MkdirAll(stray, 0o755))
	noErr(t, e.k.Kernel().Mount("tmpfs", stray, "tmpfs", 0, ""))
	e.restart()
	if len(e.k.MountTable()) != 0 || e.used() {
		t.Fatalf("left: %+v", e.k.MountTable())
	}

	// a reboot: the claims of the other boot are kept PREPARED_STALE
	// untouched; their Unprepare releases nothing and removes the record
	e.mustPrepare(pmemClaim("ro2", localPmemShare, localPmemFsRO))
	before = e.k.Commands()
	e.reboot()
	if p := e.preparation("ro2"); e.k.CommandsSince(before) != "" || e.used() || e.s.ClaimInfo("ro2") != nil ||
		p == nil || p.State != state.PreparationStale {
		t.Fatalf("a reboot touched the device or did not keep the claim stale (%+v):\n%s", p, e.k.CommandsSince(before))
	}
	e.mustUnprepare("ro2")
	if e.k.CommandsSince(before) != "" || e.preparation("ro2") != nil {
		t.Fatalf("the Unprepare of a stale claim:\n%s", e.k.CommandsSince(before))
	}
	e.wantNoViolations()
}

// A node mount that the start cannot mount again: no CDI devices until a
// Prepare again mounts it; the Unprepare releases the device.
func TestLocalPersistentUnrestored(t *testing.T) {
	t.Run("mount error", func(t *testing.T) {
		e := newPmemTestEnv(t)
		pmem := e.formatted("ext4")
		e.start()
		e.mustPrepare(pmemClaim("ro1", localPmemShare, localPmemFsRO))
		mnt := e.nodeMount("direct")
		// the mount fails at the start: the Prepare again mounts it
		noErr(t, e.k.Kernel().Unmount(mnt))
		e.k.SetMountError(pmem, syscall.EIO, "")
		e.restart()
		if cdiDeviceByName(e.cdiSpec(), "claim-ro1-0") != nil {
			t.Fatal("a CDI device of an unrestored claim")
		}
		e.k.SetMountError(pmem, nil, "")
		e.mustPrepare(pmemClaim("ro1", localPmemShare, localPmemFsRO))
		why := e.s.Unrestored()["ro1"]
		if cdiDeviceByName(e.cdiSpec(), "claim-ro1-0") == nil || why != nil {
			t.Fatalf("no CDI device after the Prepare again mounted the node mount: %v", why)
		}
		e.mustUnprepare("ro1")
		e.wantRegions(1, 1)
		e.wantClean()
		e.wantNoViolations()
	})
	t.Run("another block device", func(t *testing.T) {
		e := newPmemTestEnv(t)
		pmem := e.formatted("ext4")
		e.start()
		e.mustPrepare(pmemClaim("ro1", localPmemShare, localPmemFsRO))
		// the namespace is another one now: unrestored until the Unprepare
		noErr(t, e.k.Kernel().Unmount(e.nodeMount("direct")))
		e.k.RenamePmem(e.region(), filepath.Base(pmem), "259:7")
		e.restart()
		if cdiDeviceByName(e.cdiSpec(), "claim-ro1-0") != nil {
			t.Fatal("a CDI device of an unrestored claim")
		}
		wantErr(t, e.prepare(pmemClaim("ro1", localPmemShare, localPmemFsRO)), "unprepare the claim (delete its pods) to prepare it anew")
		e.mustUnprepare("ro1")
		e.wantRegions(1, 1)
		e.wantClean()
		e.wantNoViolations()
	})
}

// A writer's Unprepare that a failed downgrade stops (EBUSY, superblocks
// unreadable) keeps the claim and the read-write superblock for the retry.
func TestLocalPersistentFailedDowngrade(t *testing.T) {
	e := newPmemTestEnv(t)
	pmem := e.formatted("ext4")
	e.start()
	mnt := e.nodeMount("direct")
	e.mustPrepare(pmemClaim("rw1", localPmemShare, localPmemFsRW))
	e.mustPrepare(pmemClaim("ro1", localPmemShare, localPmemFsRO))
	e.k.SetWriting(mnt, true)
	wantErr(t, e.unprepare("rw1"), "device 0xc100f5e1: remounting "+mnt+" read-only: device or resource busy")
	if mi := e.mounted(mnt); mi == nil || mi.SuperReadOnly() || e.k.IsReadOnly(pmem) || e.preparation("rw1") == nil {
		t.Fatalf("after a failed downgrade: %+v, read-only %v, preparation %+v", mi, e.k.IsReadOnly(pmem), e.preparation("rw1"))
	}
	// the Unprepare did not finish: the claim stays UNPREPARING and its
	// grant RELEASING through the start, which leaves the node mount as it
	// is for kubelet's retry
	unfinished := func(what string) {
		t.Helper()
		if p, g := e.preparation("rw1"), e.grant("rw1", 0); p == nil || p.State != state.PreparationUnpreparing || g == nil || g.State != state.GrantReleasing {
			t.Fatalf("%s: preparation %+v, grant %+v", what, p, g)
		}
	}
	unfinished("after a failed downgrade")
	n := len(e.k.MountCalls(""))
	e.restart()
	unfinished("after the restart")
	if mi := e.mounted(mnt); mi == nil || mi.SuperReadOnly() || e.k.IsReadOnly(pmem) {
		t.Fatalf("the start changed the node mount of the unfinished Unprepare: %+v, read-only %v", mi, e.k.IsReadOnly(pmem))
	}
	if calls := e.mountCallsSince(n); len(calls) > 0 {
		t.Errorf("the start made the calls %q on the node mount of the unfinished Unprepare", calls)
	}
	e.k.SetWriting(mnt, false)
	e.mustUnprepare("rw1")
	if mi := e.mounted(mnt); mi == nil || !mi.SuperReadOnly() || !e.k.IsReadOnly(pmem) {
		t.Fatalf("writer gone: %+v", mi)
	}
	// fail closed when the superblocks cannot be read
	e.mustPrepare(pmemClaim("rw2", localPmemShare, localPmemFsRW))
	e.k.HideProc(true)
	err := unprepareOn(context.Background(), e.s, "rw2")
	e.k.HideProc(false)
	wantErr(t, err, "device 0xc100f5e1: not making "+pmem+" read-only: its superblocks: ")
	e.check("superblocks unreadable")
	e.mustUnprepare("rw2")
	e.mustUnprepare("ro1")
	e.wantClean()
	e.wantNoViolations()
}

// The idle device keeps its region below a region of another memdev for
// its next claim; the start releases it when nothing lies above.
func TestLocalPersistentDecoderOrder(t *testing.T) {
	e := newPmemTestEnv(t)
	e.plugAbove()
	e.formatted("ext4")
	e.start()
	e.mustPrepare(pmemClaim("ro1", localPmemShare, localPmemFsRO))
	e.regionAbove()
	e.mustUnprepare("ro1")
	e.wantRegions(1, 0)
	if !e.used() || e.published() == nil {
		t.Fatal("the idle device with its kept region is not published")
	}
	e.mustPrepare(pmemClaim("ro2", localPmemShare, localPmemFsRO))
	e.wantRegions(1, 0)
	e.mustUnprepare("ro2")
	e.releaseAbove()
	e.restart()
	e.wantRegions(1, 1)
	if e.used() {
		t.Fatal("idle device not released")
	}
	e.wantClean()
	e.wantNoViolations()
}

// A creation of the region cut by a process stop: the start releases it,
// or keeps it below another region for the idle device; a Prepare uses it.
func TestLocalPersistentCutCreation(t *testing.T) {
	for _, above := range []bool{false, true} {
		t.Run(map[bool]string{false: "alone", true: "below another region"}[above], func(t *testing.T) {
			e := newPmemTestEnv(t)
			e.plugAbove()
			e.formatted("ext4")
			e.start()
			e.k.CutAfter("cxl create-region")
			if !e.cut(func() { _ = prepareOn(context.Background(), e.s, pmemClaim("ro1", localPmemShare, localPmemFsRO)) }) {
				t.Fatal("the Prepare was not cut")
			}
			if d := e.localDevice(localPmemSerial); d == nil || d.Region != "" || d.Creating != "region0" {
				t.Fatalf("record of the cut creation %+v", d)
			}
			if above {
				e.regionAbove()
			}
			e.restart()
			if above {
				e.wantRegions(1, 0)
				d := e.localDevice(localPmemSerial)
				if d == nil || d.Region != "region0" || d.NdRegion != "" {
					t.Fatalf("kept region %+v", d)
				}
				if _, ok := d.Claims["ro1"]; !ok {
					t.Fatalf("the region is not kept for the cut claim ro1: claims %v", d.Claims)
				}
				e.mustPrepare(pmemClaim("ro1", localPmemShare, localPmemFsRO))
				e.wantRegions(1, 0)
				e.mustUnprepare("ro1")
				e.releaseAbove()
				e.restart()
				e.wantRegions(1, 1)
				e.wantClean()
				e.wantNoViolations()
				return
			}
			e.wantRegions(1, 1)
			if e.used() {
				t.Fatal("the device of the cut creation is still used")
			}
			e.mustPrepare(pmemClaim("ro1", localPmemShare, localPmemFsRO))
			e.wantRegions(2, 1)
			e.mustUnprepare("ro1")
			e.wantRegions(2, 2)
			e.wantClean()
			e.wantNoViolations()
		})
	}
}

// injectMemdev makes the scan's device of the memdev one of persistent
// memory or of RAM, shared or not, as a stale allocation finds it.
func (e *pmemTestEnv) injectMemdev(persistent, shared bool) {
	e.t.Helper()
	devs, err := e.allocatable()
	noErr(e.t, err)
	m := &device.Memdev{Name: e.memdev(), Serial: localPmemSerial, Size: 512 * mib, NodeAffinity: 0, Shared: shared, Persistent: persistent}
	if !persistent {
		m.BlockSize = localBlockSize
	}
	devs[localPmemDeviceName] = &device.DeviceInfo{Name: localPmemDeviceName, Dev: m}
}

// A memdev in sharedDevices has no block writer and no fs writer but of a
// cluster filesystem; a change of sharedDevices while it is used unpublishes it.
func TestLocalPersistentShared(t *testing.T) {
	e := newPmemTestEnv(t)
	e.config.SharedDevices = []string{"0xc100f5e1"}
	e.shared[localPmemSerial] = true
	e.formatted("ext4")
	e.start()
	if d := e.published(); d == nil || !*d.Attributes["shared"].BoolValue || !*d.Attributes["persistent"].BoolValue {
		t.Fatalf("published %+v", d)
	}
	wantErr(t, e.prepare(pmemClaim("w1", localPmemAll, localPmemBlockRW)), "MemoryConfig: device.mode block: other hosts may use the device: it is not written in mode block")
	wantErr(t, e.prepare(pmemClaim("w1", localPmemShare, localPmemFsRW)), "MemoryConfig: device.readOnly: false: other hosts may use the device")
	e.mustPrepare(pmemClaim("ro1", localPmemShare, localPmemFsRO))
	e.wantPmemCDIDevice("claim-ro1-0",
		pmemEnv("ro1", "ACCESS=direct", "FSTYPE=ext4", "MODE=fs", "PATH="+localPmemPath, "READONLY=1", "SERIAL=0xc100f5e1", "SHARED=1", "SIZE=534773760"),
		nil, []*cdiSpecs.Mount{{HostPath: e.nodeMount("direct"), ContainerPath: localPmemPath, Type: "bind", Options: []string{"bind", "ro", "nosuid", "nodev"}}})
	// sharedDevices changes while the claim is prepared: the device is not
	// published until it is idle, and a stale allocation is refused
	e.config.SharedDevices = nil
	e.shared = map[uint64]bool{}
	e.restart()
	if e.published() != nil {
		t.Fatal("published with the other sharing while in use")
	}
	wantErr(t, e.prepare(pmemClaim("ro2", localPmemShare, localPmemFsRO)), "could not find allocatable device "+localPmemDeviceName)
	t.Run("the device of a stale allocation", func(t *testing.T) {
		e.injectMemdev(true, false)
		err := e.prepare(pmemClaim("ro2", localPmemShare, localPmemFsRO))
		wantErr(t, err, "memdev "+e.memdev()+" (serial 0xc100f5e1): used as a shared persistent device by claims [ro1]")
		if want := "it is not shared now (sharedDevices)"; !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal says %q, expected %q", err, want)
		}
	})
	e.rescan()
	e.mustUnprepare("ro1")
	if d := e.published(); d == nil || *d.Attributes["shared"].BoolValue {
		t.Fatalf("published %+v", d)
	}
	e.wantClean()
	e.wantNoViolations()
}

// A memdev is used as one kind of device at a time.
func TestLocalPersistentConflicts(t *testing.T) {
	e := newPmemTestEnv(t)
	e.formatted("ext4")
	e.start()
	e.mustPrepare(pmemClaim("ro1", localPmemShare, localPmemFsRO))
	before := e.commands()
	e.injectMemdev(false, false)
	wantErr(t, e.prepare(pmemClaim("s1", "", localDaxConfig)),
		"memdev "+e.memdev()+" (serial 0xc100f5e1): used as a persistent device by claims [ro1]; a sliced device cannot be a persistent device")
	e.injectMemdev(false, true)
	wantErr(t, e.prepare(pmemClaim("s1", localPmemShare, localDaxConfig)), "used as a persistent device by claims [ro1]; a shared device cannot be a persistent device")
	if e.commands() != before || e.preparation("s1") != nil {
		t.Fatalf("a refused kind touched the device:\n%s", strings.TrimPrefix(e.commands(), before))
	}
	e.rescan()
	e.mustUnprepare("ro1")
	e.wantClean()
}

// Leases of a persistent local memdev: the lease bind of an fs lease, bound
// again and swept by a start; a block lease is lent the block device.
func TestLocalPersistentLease(t *testing.T) {
	e := newPmemTestEnv(t)
	pmem := e.formatted("ext4")
	hooks := &fakeHooks{fsDir: filepath.Join(e.dir, leaseFsDirName, "lc1"), name: "models"}
	noErr(t, os.MkdirAll(hooks.fsDir, 0o755))
	e.start()
	e.s.Lender().Set(newFakeLender(), hooks)
	e.mustPrepare(pmemCompanion("c1", localPmemShare, localPmemFsRO))
	target := filepath.Join(hooks.fsDir, "models")
	if mi := e.mounted(target); mi == nil || !slices.Contains(mi.MountFlags, "ro") {
		t.Fatalf("lease bind %+v", mi)
	}
	if rec := e.s.ClaimInfo("c1").Lend; rec == nil || !slices.Equal(rec.Mounts, []string{target}) {
		t.Fatalf("lend %+v", rec)
	}
	if len(hooks.devs) != 1 || hooks.devs[0].Mode != api.ModeFs || hooks.devs[0].NodeMount != e.nodeMount("direct") || hooks.devs[0].FsType != "ext4" ||
		hooks.devs[0].BlockDevice != pmem || !hooks.devs[0].ReadOnly || hooks.devs[0].Source != api.SourceLocal {
		t.Fatalf("lent %+v", hooks.devs)
	}
	if cdiDeviceByName(e.cdiSpec(), "claim-c1-0") != nil {
		t.Fatal("CDI device of a companion claim")
	}
	// the sweep of the binds at the start unmounts a bind that no claim
	// lists, and keeps the lease's
	stale := filepath.Join(e.dir, leaseFsDirName, "lc9", "old")
	noErr(t, os.MkdirAll(stale, 0o755))
	noErr(t, e.k.Kernel().Mount(e.nodeMount("direct"), stale, "", unix.MS_BIND, ""))
	e.restart()
	e.s.Lender().Set(newFakeLender(), hooks)
	if mi := e.mounted(stale); mi != nil {
		t.Fatal("stale lease bind not swept")
	}
	if mi := e.mounted(target); mi == nil {
		t.Fatal("the lease bind was swept")
	}
	// a restart binds it again
	noErr(t, e.k.Kernel().Unmount(target))
	e.restart()
	e.s.Lender().Set(newFakeLender(), hooks)
	if mi := e.mounted(target); mi == nil {
		t.Fatal("lease bind not bound again")
	}
	e.mustUnprepare("c1")
	if mi := e.mounted(target); mi != nil || len(e.k.MountTable()) != 0 {
		t.Fatalf("left: %+v", e.k.MountTable())
	}
	e.wantRegions(1, 1)

	e.mustPrepare(pmemCompanion("c2", localPmemAll, localPmemBlockRW))
	if len(hooks.devs) != 1 || hooks.devs[0].Mode != api.ModeBlock || hooks.devs[0].BlockDevice != e.namespace().BlockDevice || hooks.devs[0].ReadOnly {
		t.Fatalf("lent %+v", hooks.devs)
	}
	e.mustUnprepare("c2")
	e.wantClean()
	e.wantNoViolations()
}

// The record of a persistent device in the state file localDevices.json.
func TestLocalPersistentStateFile(t *testing.T) {
	e := newPmemTestEnv(t)
	pmem := e.formatted("ext4")
	e.start()
	e.mustPrepare(pmemClaim("rw1", localPmemShare, localPmemFsRW))
	data, err := os.ReadFile(filepath.Join(e.dir, localStateFileName))
	noErr(t, err)
	for _, want := range []string{`"persistent": true`, `"ndRegion": "region0"`, `"namespace": "namespace0.0"`, `"blockDevice": "` + pmem + `"`,
		`"mode": "fs"`, `"access": "direct"`, `"fsType": "ext4"`, `"nodeMount": "` + e.nodeMount("direct") + `"`, `"path": "` + localPmemPath + `"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("state file lacks %s:\n%s", want, data)
		}
	}
	e.mustUnprepare("rw1")
	e.wantClean()
}

// Two results of one claim on the device: one node mount, the env keys and
// default paths of the second have _2.
func TestLocalPersistentTwoResults(t *testing.T) {
	e := newPmemTestEnv(t)
	e.formatted("ext4")
	e.start()
	claim := pmemClaim("ro1", localPmemShare, localPmemFsRO)
	r := claim.Status.Allocation.Devices.Results[0]
	r.Request = "mem2"
	claim.Status.Allocation.Devices.Results = append(claim.Status.Allocation.Devices.Results, r)
	e.mustPrepare(claim)
	mnt := e.nodeMount("direct")
	ro := []string{"bind", "ro", "nosuid", "nodev"}
	e.wantPmemCDIDevice("claim-ro1-1",
		[]string{"CXL_C100F5E1_2_ACCESS=direct", "CXL_C100F5E1_2_FSTYPE=ext4", "CXL_C100F5E1_2_MODE=fs", "CXL_C100F5E1_2_PATH=/run/cxl-fs/C100F5E1_2",
			"CXL_C100F5E1_2_READONLY=1", "CXL_C100F5E1_2_SERIAL=0xc100f5e1", "CXL_C100F5E1_2_SHARED=0", "CXL_C100F5E1_2_SIZE=534773760", "CXL_CLAIM_ro1_1=1"},
		nil, []*cdiSpecs.Mount{{HostPath: mnt, ContainerPath: "/run/cxl-fs/C100F5E1_2", Type: "bind", Options: ro}})
	if len(e.k.MountTable()) != 1 {
		t.Fatalf("mounts %+v", e.k.MountTable())
	}
	e.mustUnprepare("ro1")
	e.wantRegions(1, 1)
	if len(e.k.MountTable()) != 0 {
		t.Fatalf("left %+v", e.k.MountTable())
	}
	e.wantNoViolations()
}

// A release sets the read-only flag of the block device of the remaining
// uses only while it is the device's (not after it was renumbered).
func TestLocalPersistentReleaseVerifiedDevice(t *testing.T) {
	e := newPmemTestEnv(t)
	pmem := e.formatted("ext4")
	e.start()
	for _, uid := range []string{"r1", "r2", "r3"} {
		e.mustPrepare(pmemClaim(uid, localPmemShare, localPmemBlockRO))
	}
	// the flag was cleared meanwhile: the release sets it again
	_, err := e.k.Kernel().SetBlockDeviceReadOnly(pmem, false)
	noErr(t, err)
	n := len(e.k.MountCalls("blkroset"))
	e.mustUnprepare("r1")
	if c := e.k.MountCalls("blkroset")[n:]; !slices.Equal(c, []string{"blkroset " + pmem + " 1"}) {
		t.Fatalf("release of the verified device: %q", c)
	}
	// the records do not hold for the renumbered device: no invariant
	// checks until the device is released
	e.k.RenamePmem(e.region(), filepath.Base(pmem), "259:7")
	_, err = e.k.Kernel().SetBlockDeviceReadOnly(pmem, false)
	noErr(t, err)
	n = len(e.k.MountCalls("blkroset"))
	noErr(t, unprepareOn(context.Background(), e.s, "r2"))
	if c := e.k.MountCalls("blkroset")[n:]; len(c) != 0 {
		t.Fatalf("release changed the flag of another device's block device: %q", c)
	}
	noErr(t, unprepareOn(context.Background(), e.s, "r3"))
	e.check("released")
	e.wantRegions(1, 1)
	e.wantClean()
	e.wantNoViolations()
}

// A superblock that no claim explains (another mount namespace) refuses a
// writer; a container's copy of the node mount is explained.
func TestLocalPersistentUnexplainedSuperblock(t *testing.T) {
	e := newPmemTestEnv(t)
	e.plugAbove()
	e.formatted("ext4")
	e.start()
	pmem := e.keepIdle()
	e.k.AddForeign(4242, pmem, "/mnt/x", "ext4", false)
	wantErr(t, e.prepare(pmemClaim("rw1", localPmemShare, localPmemFsRW)),
		"device 0xc100f5e1: "+pmem+" has a superblock that no claim of this node explains ("+pmem+" mounted rw in pid 4242 at /mnt/x): it is not used until that mount is gone")
	wantErr(t, e.prepare(pmemClaim("w1", localPmemAll, localPmemBlockRW)), "has a superblock that no claim of this node explains")
	e.k.RemoveForeign(4242)
	e.mustPrepare(pmemClaim("rw1", localPmemShare, localPmemFsRW))
	// a container's copy of the node mount (the same source) is explained
	e.k.AddForeign(4243, pmem, localPmemPath, "ext4", false)
	e.mustPrepare(pmemClaim("rw2", localPmemShare, localPmemFsRW))
	e.k.RemoveForeign(4243)
	e.mustUnprepare("rw2")
	e.mustUnprepare("rw1")
	e.releaseAbove()
	e.restart()
	cmds := e.commands()
	if c, d := strings.Count(cmds, "cxl create-region"), strings.Count(cmds, "cxl destroy-region"); c != d || e.used() || len(e.k.MountTable()) != 0 {
		t.Fatalf("left: regions created %d destroyed %d, mounts %+v", c, d, e.k.MountTable())
	}
	e.wantClean()
	e.wantNoViolations()
}

// fsTypes of the driver configuration: erofs only by default, the listed
// types, none for an empty list; a refused type is not mounted.
func TestLocalPersistentFsTypes(t *testing.T) {
	e := newPmemTestEnv(t)
	e.formatted("ext4")
	for _, tc := range []struct{ config, err string }{
		{"", "claim demo/claim-ro1: request mem: device 0xc100f5e1: filesystem type ext4 is not allowed on this node (fsTypes: erofs)"},
		{"fsTypes: [erofs, ext4]", ""},
		{"fsTypes: []", "filesystem type ext4 is not allowed on this node (fsTypes: none)"},
	} {
		cfg, err := newDriverConfigFromString(tc.config)
		noErr(t, err)
		e.config.FsTypes = cfg.FsTypes
		e.start()
		if tc.err == "" {
			e.mustPrepare(pmemClaim("ro1", localPmemShare, localPmemFsRO))
			e.mustUnprepare("ro1")
			continue
		}
		wantErr(t, e.prepare(pmemClaim("ro1", localPmemShare, localPmemFsRO)), tc.err)
		if len(e.k.MountTable()) != 0 || e.used() {
			t.Fatalf("%q: a refused type was mounted or holds the device: %+v", tc.config, e.k.MountTable())
		}
	}
	e.wantClean()
	e.wantNoViolations()
}

// Two writers and a reader of one ext4 share one read-write superblock,
// downgraded by the last writer, upgraded by a new one, unmounted at last.
func TestPersistentWritersAndReaders(t *testing.T) {
	e := newPmemTestEnv(t)
	pmem := e.formatted("ext4")
	e.start()
	direct := e.nodeMount("direct")
	n := len(e.k.MountCalls(""))
	e.mustPrepare(pmemClaim("a", localPmemShare, localPmemFsRW))
	if a := e.infoOf("a"); a.Access != api.AccessDirect || a.FsType != "ext4" || a.NodeMount != direct || a.LoopDevice != "" || a.ReadOnly {
		t.Fatalf("use %+v", a)
	}
	e.wantMountCalls(n, "fsmount "+pmem+" "+direct+" ext4 rw dax=always")
	e.mustPrepare(pmemClaim("b", localPmemShare, pmemFsConfig(false, api.AccessDirect, "ext4")))
	e.mustPrepare(pmemClaim("c", localPmemShare, localPmemFsRO))
	e.wantMountCalls(n, "fsmount "+pmem+" "+direct+" ext4 rw dax=always")
	if mi := e.mounted(direct); mi == nil || mi.SuperReadOnly() || e.k.IsReadOnly(pmem) {
		t.Fatalf("node mount %+v, block device read-only %v", mi, e.k.IsReadOnly(pmem))
	}

	n = len(e.k.MountCalls(""))
	e.mustUnprepare("a")
	e.wantMountCalls(n)
	e.mustUnprepare("b")
	e.wantMountCalls(n, "syncfs "+direct, "reconfigure "+direct+" ro", "blkroset "+pmem+" 1")
	if mi := e.mounted(direct); mi == nil || !mi.SuperReadOnly() {
		t.Fatalf("not downgraded: %+v", mi)
	}

	// a writer again upgrades in place
	n = len(e.k.MountCalls(""))
	e.mustPrepare(pmemClaim("d", localPmemShare, localPmemFsRW))
	e.wantMountCalls(n, "blkroset "+pmem+" 0", "reconfigure "+direct+" rw")
	e.mustUnprepare("c")

	// the last use unmounts the node mount (TestLocalPersistentFailedDowngrade
	// has the downgrade that a file open for writing fails)
	e.mustPrepare(pmemClaim("r", localPmemShare, localPmemFsRO))
	e.mustUnprepare("d")
	n = len(e.k.MountCalls(""))
	e.mustUnprepare("r")
	e.wantMountCalls(n, "umount "+direct)
	if _, err := os.Stat(direct); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("node mount directory left: %v", err)
	}
	e.wantClean()
	e.wantNoViolations()
}

// An upgrade that the filesystem refuses leaves both block devices of a
// cached xfs read-only again; a read-only xfs is mounted with nouuid.
func TestPersistentUpgradeFails(t *testing.T) {
	e := newPmemTestEnv(t)
	pmem := e.formatted("xfs")
	e.start()
	cached := e.nodeMount("cached")
	e.mustPrepare(pmemClaim("r", localPmemShare, pmemFsConfig(true, api.AccessCached, "")))
	loop := e.infoOf("r").LoopDevice
	if c := e.k.MountCalls("fsmount"); loop == "" || !slices.Equal(c, []string{"fsmount " + loop + " " + cached + " xfs ro dax=never,nouuid"}) {
		t.Fatalf("mounts %q, loop device %q", c, loop)
	}
	e.k.SetReconfigureError(cached, unix.EINVAL)
	wantErr(t, e.prepare(pmemClaim("w", localPmemShare, pmemFsConfig(false, api.AccessCached, ""))),
		"device 0xc100f5e1: remounting "+cached+" read-write: invalid argument")
	if !e.k.IsReadOnly(pmem) || !e.k.IsReadOnly(loop) {
		t.Fatal("block devices writable after a failed upgrade")
	}
	if mi := e.mounted(cached); mi == nil || !mi.SuperReadOnly() {
		t.Fatalf("node mount %+v", mi)
	}
	e.mustUnprepare("r")
	e.wantClean()
	e.wantNoViolations()
}

// The default access of each filesystem type, mount(2) for read-only types,
// nouuid for xfs, and the read-only flag of block readers and writers.
func TestPersistentDefaults(t *testing.T) {
	for image, access := range map[string]string{"erofs": api.AccessDirect, "ext4": api.AccessDirect, "xfs": api.AccessDirect,
		"btrfs": api.AccessCached, "squashfs": api.AccessCached} {
		t.Run(image, func(t *testing.T) {
			e := newPmemTestEnv(t)
			e.formatted(image)
			e.start()
			e.mustPrepare(pmemClaim("r", localPmemShare, localPmemFsRO))
			if u := e.infoOf("r"); u.Access != access || u.FsType != image {
				t.Errorf("%s: %+v", image, u)
			}
			// read-only types keep mount(2) with ro,nosuid,nodev
			if config.FsTypeReadOnly(image) && len(e.k.MountCalls("mount ")) != 1 || !config.FsTypeReadOnly(image) && len(e.k.MountCalls("fsmount ")) != 1 {
				t.Errorf("%s: calls %q", image, e.k.MountCalls(""))
			}
			e.mustUnprepare("r")
			e.wantClean()
		})
	}
	t.Run("xfs both accesses", func(t *testing.T) {
		e := newPmemTestEnv(t)
		e.formatted("xfs")
		e.start()
		e.mustPrepare(pmemClaim("d", localPmemShare, pmemFsConfig(true, api.AccessDirect, "")))
		e.mustPrepare(pmemClaim("c", localPmemShare, pmemFsConfig(true, api.AccessCached, "")))
		if c := e.k.MountCalls("fsmount"); len(c) != 2 || !strings.HasSuffix(c[0], "ro dax=always,nouuid") || !strings.HasSuffix(c[1], "ro dax=never,nouuid") {
			t.Fatalf("mounts %q", c)
		}
		e.mustUnprepare("d")
		e.mustUnprepare("c")
		e.wantClean()
	})
	t.Run("block", func(t *testing.T) {
		e := newPmemTestEnv(t)
		pmem := e.formatted()
		e.start()
		e.mustPrepare(pmemClaim("r", localPmemShare, localPmemBlockRO))
		if !e.k.IsReadOnly(pmem) {
			t.Fatal("block reader on a writable device")
		}
		e.mustUnprepare("r")
		e.mustPrepare(pmemClaim("w", localPmemAll, localPmemBlockRW))
		if e.k.IsReadOnly(e.namespace().BlockDevice) {
			t.Fatal("block writer on a read-only device")
		}
		e.mustUnprepare("w")
		e.wantClean()
	})
}

// The refusals of the rules of a persistent device before anything of it
// is mounted, with their texts, and the rules that let a claim through.
func TestPersistentRules(t *testing.T) {
	// coherent makes the memdev shared with other hosts on coherent memory
	coherent := func(e *pmemTestEnv) {
		e.config.SharedDevices = []string{"0xc100f5e1"}
		e.config.MemdevSettings = []MemdevSetting{{Device: "0xc100f5e1", Coherent: true}}
		e.shared[localPmemSerial] = true
	}
	// notCoherent makes it shared with other hosts on memory that is not
	// coherent
	notCoherent := func(e *pmemTestEnv) {
		e.config.SharedDevices = []string{"0xc100f5e1"}
		e.shared[localPmemSerial] = true
	}
	claim := func(uid string, readOnly bool, access, fsType string) *resourcev1.ResourceClaim {
		return pmemClaim(uid, localPmemShare, pmemFsConfig(readOnly, access, fsType))
	}
	reader := func(uid, access string) func(e *pmemTestEnv) {
		return func(e *pmemTestEnv) { e.mustPrepare(claim(uid, true, access, "")) }
	}
	for _, tc := range []struct {
		name   string
		image  []string
		config func(e *pmemTestEnv)
		setup  func(e *pmemTestEnv)
		claim  *resourcev1.ResourceClaim
		err    string
	}{
		{name: "P4", image: []string{"ext4"}, claim: claim("x", true, "", ""),
			config: func(e *pmemTestEnv) { e.config.FsTypes = []string{"erofs", "squashfs"} },
			err:    "device 0xc100f5e1: filesystem type ext4 is not allowed on this node (fsTypes: erofs, squashfs)"},
		{name: "P4 none", image: []string{"erofs"}, claim: claim("x", true, "", ""),
			config: func(e *pmemTestEnv) { e.config.FsTypes = []string{} },
			err:    "device 0xc100f5e1: filesystem type erofs is not allowed on this node (fsTypes: none)"},
		{name: "P4 default erofs only", image: []string{"ext4"}, claim: claim("x", true, "", ""),
			config: func(e *pmemTestEnv) { e.config.FsTypes = nil },
			err:    "device 0xc100f5e1: filesystem type ext4 is not allowed on this node (fsTypes: erofs)"},
		{name: "P5", claim: claim("x", true, "", "tmpfs"),
			config: func(e *pmemTestEnv) { e.config.FsTypes = append(e.config.FsTypes, "tmpfs") },
			err:    "device 0xc100f5e1: filesystem type tmpfs does not mount a block device"},
		{name: "P6", image: []string{"erofs"}, claim: claim("x", false, "", ""),
			err: "device 0xc100f5e1: erofs is a read-only filesystem: set readOnly: true"},
		{name: "P7", image: []string{"btrfs"}, claim: claim("x", true, api.AccessDirect, ""),
			err: "device 0xc100f5e1: btrfs has no DAX: use access cached"},
		{name: "P8 single-host", image: []string{"ext4"}, claim: claim("x", false, "", ""), config: coherent,
			err: "MemoryConfig: device.readOnly: false: other hosts may use the device: read-write needs it on this node only"},
		{name: "P8 lock_nolock", image: []string{"gfs2-nolock"}, claim: claim("x", false, "", "gfs2"), config: coherent,
			err: "device 0xc100f5e1: read-write on several hosts needs a cluster filesystem on coherent memory: gfs2 with lock_nolock is a single-host filesystem"},
		{name: "P8 coherence", image: []string{"gfs2"}, claim: claim("x", false, "", "gfs2"), config: notCoherent,
			err: "MemoryConfig: device.readOnly: false: other hosts may use the device: read-write needs it on this node only"},
		{name: "P8 cluster", image: []string{"gfs2"}, claim: claim("x", false, "", "gfs2"), config: coherent},
		{name: "P9a", image: []string{"ext4"}, claim: claim("x", true, api.AccessCached, ""),
			setup: func(e *pmemTestEnv) { e.mustPrepare(claim("w", false, api.AccessDirect, "")) },
			err:   "device 0xc100f5e1: it is mounted read-write with access direct on this node: access cached would mount it a second time"},
		{name: "P9b", image: []string{"ext4"}, claim: claim("x", false, api.AccessDirect, ""),
			setup: func(e *pmemTestEnv) { reader("r1", api.AccessDirect)(e); reader("r2", api.AccessCached)(e) },
			err:   "device 0xc100f5e1: it is mounted with access direct and cached on this node: a read-write claim needs one access only"},
		{name: "P9d", image: []string{"ext4"}, claim: claim("x", false, api.AccessDirect, ""), setup: reader("r", api.AccessCached),
			err: "device 0xc100f5e1: it is mounted with access cached only on this node: a read-write claim with access direct would mount it a second time"},
		{name: "P9c block writer first", image: []string{"ext4"}, claim: claim("x", true, "", ""),
			setup: func(e *pmemTestEnv) { e.mustPrepare(pmemClaim("b", localPmemAll, localPmemBlockRW)) },
			err:   "device 0xc100f5e1: mode block read-write needs the device alone on this node"},
		{name: "P9c block writer second", image: []string{"ext4"}, claim: pmemClaim("x", localPmemAll, localPmemBlockRW), setup: reader("r", ""),
			err: "device 0xc100f5e1: mode block read-write needs the device alone on this node"},
		{name: "P9e", image: []string{"btrfs"}, claim: claim("x", false, "", ""), setup: reader("r", ""),
			err: "device 0xc100f5e1: btrfs is mounted read-only on this node and cannot be remounted read-write: a read-write claim waits until the read-only claims of the node are gone"},
		{name: "P10 ext4", image: []string{"ext4-dirty"}, claim: claim("x", true, "", ""),
			err: "device 0xc100f5e1: ext4 on $PMEM needs recovery (it was not unmounted cleanly): a read-only mount cannot recover it, a read-write claim on one node does"},
		{name: "P10 EROFS", image: []string{"xfs"}, claim: claim("x", true, "", ""),
			setup: func(e *pmemTestEnv) {
				// the block device is there while a block reader holds the device
				e.mustPrepare(pmemClaim("b", localPmemShare, localPmemBlockRO))
				e.k.SetDirty(e.namespace().BlockDevice, true)
			},
			err: "device 0xc100f5e1: xfs on $PMEM needs recovery (it was not unmounted cleanly)"},
		{name: "P10 a writer recovers", image: []string{"ext4-dirty"}, claim: claim("x", false, "", "")},
		{name: "P11", image: []string{"ext4"}, claim: claim("x", true, "", ""),
			config: func(e *pmemTestEnv) {
				e.k.SetMountError(e.blockDevice, unix.EINVAL, "e ext4: unsupported blocksize for DAX")
			},
			err: "device 0xc100f5e1: $PMEM has no ext4 filesystem: invalid argument: e ext4: unsupported blocksize for DAX"},
		{name: "P12", image: []string{"ext4"}, claim: claim("x", true, "", ""),
			config: func(e *pmemTestEnv) { e.k.SetSuperOpts(e.blockDevice, "ro", "dax=never") },
			err:    "device 0xc100f5e1: ext4 on $PMEM was mounted without DAX"},
		{name: "P1", claim: claim("x", true, "", ""),
			err: "device 0xc100f5e1: $PMEM has no filesystem of a type that the plugin knows (erofs, squashfs, ext4, xfs, btrfs or gfs2): set device.fsType"},
		{name: "P3 of a node mount", image: []string{"ext4"}, claim: claim("x", true, "", "xfs"), setup: reader("r", ""),
			err: "device 0xc100f5e1: $PMEM has a filesystem of type ext4, not xfs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPmemTestEnv(t)
			pmem := e.formatted(tc.image...)
			e.blockDevice = pmem
			if tc.config != nil {
				tc.config(e)
			}
			e.start()
			if tc.setup != nil {
				tc.setup(e)
			}
			before := len(e.k.MountTable())
			err := e.prepare(tc.claim)
			if tc.err == "" {
				noErr(t, err)
				e.mustUnprepare(string(tc.claim.UID))
			} else {
				wantErr(t, err, strings.ReplaceAll(tc.err, "$PMEM", pmem))
				if len(e.k.MountTable()) != before {
					t.Fatalf("mounts after a refusal: %+v", e.k.MountTable())
				}
			}
			for _, uid := range []string{"r", "r1", "r2", "w", "b"} {
				e.mustUnprepare(uid)
			}
			entries, _ := os.ReadDir(filepath.Join(e.dir, mountsDirName))
			if len(e.k.MountTable()) != 0 || len(e.k.Kernel().LoopDevices()) != 0 || len(entries) != 0 {
				t.Fatalf("left: mounts %+v loops %v dirs %v", e.k.MountTable(), e.k.Kernel().LoopDevices(), entries)
			}
			e.wantClean()
		})
	}
}

// The CDI mounts of mode fs (a read-only bind for a reader, a read-write
// one for a writer) and the device node of a block reader, read-only.
func TestPersistentCDI(t *testing.T) {
	if m := fsCDIMount("/n", "/c", true); !slices.Equal(m.Options, []string{"bind", "ro", "nosuid", "nodev"}) || m.HostPath != "/n" || m.ContainerPath != "/c" || m.Type != "bind" {
		t.Errorf("read-only %+v", m)
	}
	if m := fsCDIMount("/n", "/c", false); !slices.Equal(m.Options, []string{"bind", "nosuid", "nodev"}) {
		t.Errorf("read-write %+v", m)
	}
	if d := blockDeviceNode("/dev/pmem0", 259, 1, true); *d != (cdiSpecs.DeviceNode{Path: "/dev/pmem0", Type: "b", Major: 259, Minor: 1, Permissions: "r"}) {
		t.Errorf("block %+v", d)
	}
	e := newPmemTestEnv(t)
	pmem := e.formatted("ext4")
	e.start()
	e.mustPrepare(pmemClaim("w", localPmemShare, pmemFsConfig(false, "", "")))
	e.mustPrepare(pmemClaim("r", localPmemShare, pmemFsConfig(true, "", "")))
	mnt := e.nodeMount("direct")
	for uid, opts := range map[string][]string{"w": {"bind", "nosuid", "nodev"}, "r": {"bind", "ro", "nosuid", "nodev"}} {
		d := cdiDeviceByName(e.cdiSpec(), "claim-"+uid+"-0")
		want := []*cdiSpecs.Mount{{HostPath: mnt, ContainerPath: localPmemPath, Type: "bind", Options: opts}}
		if d == nil || !reflect.DeepEqual(d.ContainerEdits.Mounts, want) || len(d.ContainerEdits.DeviceNodes) != 0 {
			t.Fatalf("CDI device of %s: %+v", uid, d)
		}
	}
	e.mustUnprepare("w")
	e.mustUnprepare("r")
	e.mustPrepare(pmemClaim("b", localPmemShare, localPmemBlockRO))
	ns := e.namespace()
	d := cdiDeviceByName(e.cdiSpec(), "claim-b-0")
	want := []*cdiSpecs.DeviceNode{{Path: pmem, Type: "b", Major: int64(ns.Major), Minor: int64(ns.Minor), Permissions: "r"}}
	if d == nil || !reflect.DeepEqual(d.ContainerEdits.DeviceNodes, want) || len(d.ContainerEdits.Mounts) != 0 {
		t.Fatalf("CDI device of the block reader: %+v", d)
	}
	e.mustUnprepare("b")
	e.wantClean()
}

// Superblocks that no use explains refuse a reader and an upgrade, a bind of
// the node mount elsewhere is explained, unreadable ones refuse a use.
func TestPersistentUnexplainedSuperblocks(t *testing.T) {
	unexplained := func(pmem, src, ro, where string) string {
		return "device 0xc100f5e1: " + pmem + " has a superblock that no claim of this node explains (" + src + " mounted " + ro + " in " + where +
			"): it is not used until that mount is gone"
	}
	t.Run("read-write superblock elsewhere", func(t *testing.T) {
		e := newPmemTestEnv(t)
		e.plugAbove()
		e.formatted("ext4")
		e.start()
		pmem := e.keepIdle()
		e.k.AddForeign(4242, pmem, "/run/cxl/fs/rw", "ext4", false)
		n := len(e.k.MountCalls("blkroset"))
		wantErr(t, e.prepare(pmemClaim("r", localPmemShare, localPmemFsRO)), unexplained(pmem, pmem, "rw", "pid 4242 at /run/cxl/fs/rw"))
		if c := e.k.MountCalls("blkroset")[n:]; len(c) != 0 {
			t.Fatalf("calls %q", c)
		}
		// the refused reader keeps the region below the other region
		e.k.RemoveForeign(4242)
		e.releaseAbove()
		e.mustUnprepare("r")
		e.wantClean()
	})
	t.Run("loop device elsewhere", func(t *testing.T) {
		e := newPmemTestEnv(t)
		pmem := e.formatted("ext4")
		e.start()
		e.mustPrepare(pmemClaim("r", localPmemShare, pmemFsConfig(true, api.AccessDirect, "")))
		loop, err := e.k.Kernel().AttachLoop(pmem, false)
		noErr(t, err)
		e.k.AddForeign(77, loop.Path(), "/mnt/old", "ext4", true)
		wantErr(t, e.prepare(pmemClaim("w", localPmemShare, pmemFsConfig(false, api.AccessDirect, ""))),
			unexplained(pmem, loop.Path(), "ro", "pid 77 at /mnt/old"))
		if mi := e.mounted(e.nodeMount("direct")); mi == nil || !mi.SuperReadOnly() {
			t.Fatalf("node mount %+v", mi)
		}
		e.k.RemoveForeign(77)
		noErr(t, loop.Release(true))
		// a bind of the node mount in another namespace is its superblock
		e.k.AddForeign(78, pmem, "/run/cxl/fs/ro", "ext4", true)
		e.mustPrepare(pmemClaim("w", localPmemShare, pmemFsConfig(false, api.AccessDirect, "")))
		e.k.RemoveForeign(78)
		e.mustUnprepare("w")
		e.mustUnprepare("r")
		e.wantClean()
	})
	t.Run("superblocks unreadable", func(t *testing.T) {
		e := newPmemTestEnv(t)
		e.formatted("ext4")
		e.start()
		e.k.HideProc(true)
		wantErr(t, e.prepare(pmemClaim("w", localPmemShare, localPmemFsRW)), "mountinfo: no such file or directory")
		if len(e.k.MountTable()) != 0 {
			t.Fatalf("mounted without the superblocks: %+v", e.k.MountTable())
		}
		e.k.HideProc(false)
		e.wantClean()
	})
}
