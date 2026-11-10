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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	resourceapi "k8s.io/api/resource/v1"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"golang.org/x/sys/unix"
)

// fsMountFlags are the flags of the node mounts of read-only filesystem
// types (mount(2)) that the engine mounts.
const fsMountFlags = unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV

const (
	// a shared persistent device with one share, and exclusive
	persistentData = `{"serial":"0xc1ae0001","shared":true,"size":536870912,"persistent":true}`
	writerData     = `{"serial":"0xc1ae0001","shared":true,"size":536870912,"persistent":true,"exclusive":true}`
	blockConfig    = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"block"}}`
	blockROConfig  = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"block","readOnly":true}}`
)

// fsConfig returns a MemoryConfig of mode fs with the access and path.
func fsConfig(access, path string) string {
	return fmt.Sprintf(`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","readOnly":true,"access":%q,"path":%q}}`, access, path)
}

func persistentClaim(uid, data, config string) *resourceapi.ResourceClaim {
	return withConfig(poolClaim(uid, "c-"+uid, "llm0", data), resourceapi.AllocationConfigSourceClaim, nil, config)
}

func TestPoolPersistentWriter(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plugPmem(0xc1ae0001)
	p := e.driver(t)

	res := prepare(t, p, persistentClaim("w1", writerData, blockConfig))
	noErr(t, res.Err)
	e.wantCommand(t, "cxl create-region -t pmem -d decoder0.2 -m mem0")
	e.wantCommand(t, "ndctl create-namespace -f -r region0 -m fsdax -M mem")
	cd := e.wantCDIDevice(t, "claim-w1-0", []string{"CXL_C1AE0001_MODE=block", "CXL_C1AE0001_PATH=" + e.pmem, "CXL_C1AE0001_READONLY=0",
		"CXL_C1AE0001_SERIAL=0xc1ae0001", "CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=534773760", "CXL_CLAIM_w1_0=1"})
	if want := []*cdiSpecs.DeviceNode{{Path: e.pmem, Type: "b", Major: 259, Minor: 0}}; !reflect.DeepEqual(cd.ContainerEdits.DeviceNodes, want) ||
		len(cd.ContainerEdits.Mounts) != 0 {
		t.Fatalf("CDI device %+v", cd.ContainerEdits)
	}
	if d := e.device(p, "w1", 0); !d.Persistent || d.NdRegion != "region0" || d.Namespace != "namespace0.0" || d.BlockDevice != e.pmem ||
		d.BlockMajor != 259 || d.Mode != api.ModeBlock {
		t.Fatalf("device %+v", d)
	}
	noErr(t, unprepare(t, p, "w1"))
	e.wantReleased(t, "region0", "mem0")
	e.wantClean(t, p)

	// a second writer reuses the namespace of the labels
	noErr(t, prepare(t, p, persistentClaim("w2", writerData, blockConfig)).Err)
	if n := strings.Count(e.commands(), "ndctl"); n != 1 {
		t.Fatalf("ndctl ran %d times:\n%s", n, e.commands())
	}
	noErr(t, unprepare(t, p, "w2"))

	// a read-only block claim: device node "r", never creates a namespace
	noErr(t, prepare(t, p, persistentClaim("r1", persistentData, blockROConfig)).Err)
	cd = e.wantCDIDevice(t, "claim-r1-0", []string{"CXL_C1AE0001_MODE=block", "CXL_C1AE0001_PATH=" + e.pmem, "CXL_C1AE0001_READONLY=1",
		"CXL_C1AE0001_SERIAL=0xc1ae0001", "CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=534773760", "CXL_CLAIM_r1_0=1"})
	if cd.ContainerEdits.DeviceNodes[0].Permissions != "r" {
		t.Fatalf("read-only device node %+v", cd.ContainerEdits.DeviceNodes[0])
	}
	noErr(t, unprepare(t, p, "r1"))
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
	if strings.Contains(e.commands(), "destroy-namespace") {
		t.Fatalf("a namespace was destroyed:\n%s", e.commands())
	}
}

func TestPoolPersistentReaders(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plugPersistent(0xc1ae0001, "erofs") // written by a writer earlier
	p := e.driver(t)
	direct := e.nodeMount(0xc1ae0001, "direct")
	cached := e.nodeMount(0xc1ae0001, "cached")
	if want := filepath.Join(e.dir, "mounts", "c1ae0001-direct"); direct != want {
		t.Fatalf("node mount %s, expected %s", direct, want)
	}

	noErr(t, prepare(t, p, persistentClaim("d1", persistentData, fsConfig("", ""))).Err)
	noErr(t, prepare(t, p, persistentClaim("d2", persistentData, fsConfig("direct", "/models"))).Err)
	noErr(t, prepare(t, p, persistentClaim("c1", persistentData, fsConfig("cached", ""))).Err)
	noErr(t, prepare(t, p, persistentClaim("c2", persistentData, fsConfig("cached", ""))).Err)
	if n := strings.Count(e.commands(), "create-region"); n != 1 || strings.Contains(e.commands(), "ndctl") {
		t.Fatalf("unexpected commands:\n%s", e.commands())
	}
	// one mount per access, shared by the claims
	wantCalls := []string{
		fmt.Sprintf("mount %s %s erofs 0x%x dax=always", e.pmem, direct, fsMountFlags),
		"loop " + e.loop(0) + " " + e.pmem,
		fmt.Sprintf("mount %s %s erofs 0x%x dax=never", e.loop(0), cached, fsMountFlags),
		"loop-release " + e.loop(0) + " detach=false",
	}
	if got := slices.Concat(e.k.MountCalls("mount"), e.k.MountCalls("loop")); !reflect.DeepEqual(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(wantCalls))) {
		t.Fatalf("mount calls %q, expected %q", got, wantCalls)
	}
	if fsMountFlags != unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV {
		t.Fatalf("mount flags 0x%x", fsMountFlags)
	}
	mount := func(host, ctr string) []*cdiSpecs.Mount {
		return []*cdiSpecs.Mount{{HostPath: host, ContainerPath: ctr, Type: "bind", Options: []string{"bind", "ro", "nosuid", "nodev"}}}
	}
	env := func(uid, path, access string) []string {
		return []string{"CXL_C1AE0001_ACCESS=" + access, "CXL_C1AE0001_FSTYPE=erofs", "CXL_C1AE0001_MODE=fs", "CXL_C1AE0001_PATH=" + path, "CXL_C1AE0001_READONLY=1",
			"CXL_C1AE0001_SERIAL=0xc1ae0001", "CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=534773760", "CXL_CLAIM_" + uid + "_0=1"}
	}
	for _, c := range []struct{ uid, host, path, access string }{
		{"d1", direct, "/run/cxl-fs/C1AE0001", "direct"},
		{"d2", direct, "/models", "direct"},
		{"c1", cached, "/run/cxl-fs/C1AE0001", "cached"},
	} {
		cd := e.wantCDIDevice(t, "claim-"+c.uid+"-0", env(c.uid, c.path, c.access))
		if !reflect.DeepEqual(cd.ContainerEdits.Mounts, mount(c.host, c.path)) || len(cd.ContainerEdits.DeviceNodes) != 0 {
			t.Fatalf("%s: CDI device %+v", c.uid, cd.ContainerEdits)
		}
	}
	if d := e.device(p, "c1", 0); d.Access != "cached" || d.NodeMount != cached || d.LoopDevice != e.loop(0) || d.Path != "/run/cxl-fs/C1AE0001" {
		t.Fatalf("prepared device %+v", d)
	}

	// the last claim of an access unmounts it, the other access stays
	noErr(t, unprepare(t, p, "d1"))
	noErr(t, unprepare(t, p, "c1"))
	if len(e.k.MountCalls("umount")) != 0 {
		t.Fatalf("unmounted while in use: %q", e.k.MountCalls(""))
	}
	noErr(t, unprepare(t, p, "d2"))
	if got := e.k.MountCalls("umount"); !slices.Equal(got, []string{"umount " + direct}) || strings.Contains(e.commands(), "disable-region") {
		t.Fatalf("after the last direct claim: %q\n%s", got, e.commands())
	}
	// a busy mount fails the Unprepare, the claim stays prepared
	e.k.SetBusy(cached, true)
	wantErr(t, unprepare(t, p, "c2"), "device 0xc1ae0001: unmounting "+cached+": device or resource busy")
	if e.preparation("c2") == nil || strings.Contains(e.commands(), "disable-region") {
		t.Fatalf("busy Unprepare released the device:\n%s", e.commands())
	}
	// a holder of the block device (a container's bind mount) fails it too
	e.k.SetBusy(cached, false)
	e.k.SetHolder(e.pmem, "in use")
	wantErr(t, unprepare(t, p, "c2"), "device 0xc1ae0001: "+e.pmem+" is still in use")
	if e.preparation("c2") == nil || strings.Contains(e.commands(), "disable-region") || len(e.loops()) != 0 {
		t.Fatalf("held device released:\n%s\nloops %v", e.commands(), e.loops())
	}
	e.k.SetHolder(e.pmem, "")
	noErr(t, unprepare(t, p, "c2"))
	e.wantReleased(t, "region0", "mem0")
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
}

func TestPoolPersistentSamePreparation(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plugPersistent(0xc1ae0001, "erofs")
	p := e.driver(t)
	noErr(t, prepare(t, p, persistentClaim("r1", persistentData, blockROConfig)).Err)
	noErr(t, prepare(t, p, persistentClaim("r2", persistentData, fsConfig("cached", "/models"))).Err)
	// a volatile preparation of the serial never meets them
	wantErr(t, prepare(t, p, poolClaim("v1", "c-v1", "llm0", sharedPersistentAsVolatile)).Err, "mode dax, but another claim prepared it in mode ")
	// two results of one claim on the serial: one mount, unmounted with it
	claim := persistentClaim("r3", persistentData, fsConfig("direct", ""))
	claim.Status.Allocation.Devices.Results = append(claim.Status.Allocation.Devices.Results,
		resourceapi.DeviceRequestAllocationResult{Request: "mem2", Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: "llm0", ConsumedCapacity: poolConsumed(persistentData)})
	noErr(t, prepare(t, p, claim).Err)
	e.wantCDIDevice(t, "claim-r3-2", []string{"CXL_C1AE0001_2_ACCESS=direct", "CXL_C1AE0001_2_FSTYPE=erofs", "CXL_C1AE0001_2_MODE=fs", "CXL_C1AE0001_2_PATH=/run/cxl-fs/C1AE0001_2",
		"CXL_C1AE0001_2_READONLY=1", "CXL_C1AE0001_2_SERIAL=0xc1ae0001", "CXL_C1AE0001_2_SHARED=1", "CXL_C1AE0001_2_SIZE=534773760", "CXL_CLAIM_r3_2=1"})
	if n := len(e.k.MountCalls("mount ")); n != 2 {
		t.Fatalf("%d mounts: %q", n, e.k.MountCalls(""))
	}
	for _, uid := range []string{"r3", "r2", "r1"} {
		noErr(t, unprepare(t, p, uid))
	}
	e.wantReleased(t, "region0", "mem0")
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
}

const sharedPersistentAsVolatile = `{"serial":"0xc1ae0001","shared":true,"size":536870912}`

func TestPoolPersistentRestart(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plugPersistent(0xc1ae0001, "erofs")
	p := e.driver(t)
	noErr(t, prepare(t, p, persistentClaim("d1", persistentData, fsConfig("direct", ""))).Err)
	noErr(t, prepare(t, p, persistentClaim("c1", persistentData, fsConfig("cached", ""))).Err)
	noErr(t, prepare(t, p, persistentClaim("c2", persistentData, fsConfig("cached", ""))).Err)
	nmounts := len(e.k.MountCalls("mount "))

	// a restart keeps the mounts
	e.driver(t)
	if len(e.k.MountCalls("mount ")) != nmounts || len(e.k.MountCalls("umount")) != 0 {
		t.Fatalf("restart touched the mounts: %q", e.k.MountCalls(""))
	}
	// missing mounts are mounted again, a mount of no claim is unmounted
	direct, cached := e.nodeMount(0xc1ae0001, "direct"), e.nodeMount(0xc1ae0001, "cached")
	k := e.k.Kernel()
	for _, mnt := range []string{direct, cached} {
		noErr(t, k.Unmount(mnt))
	}
	stale := e.nodeMount(0xc1ee0002, "direct")
	noErr(t, os.MkdirAll(stale, 0o755))
	p = e.driver(t)
	for _, mnt := range []string{direct, cached} {
		if mi, _ := e.mountedErr(mnt); mi == nil {
			t.Fatalf("%s not mounted again", mnt)
		}
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale mount directory left: %v", err)
	}
	// the new loop device is in the state
	if d := e.device(p, "c2", 0); d.LoopDevice != e.loop(1) {
		t.Fatalf("loop device %q after the restart", d.LoopDevice)
	}
	p = e.driver(t)
	if d := e.device(p, "c1", 0); d.LoopDevice != e.loop(1) {
		t.Fatalf("loop device %q not saved", d.LoopDevice)
	}
	for _, uid := range []string{"d1", "c1", "c2"} {
		noErr(t, unprepare(t, p, uid))
	}
	e.wantReleased(t, "region0", "mem0")
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
}

// newPoolLeaseEnv returns a pool test env with the persistent device of
// persistentData written by a writer, a pool driver with a lease-fs root,
// and fake hooks that give the lend records of companion claims the
// lease-fs directory of the lease claim lc1 and the name models.
func newPoolLeaseEnv(t *testing.T) (*poolTestEnv, *dra.Plugin, *fakeHooks) {
	t.Helper()
	e := newPoolTestEnv(t)
	e.leaseFsRoot = filepath.Join(e.dir, "lease-fs")
	e.plugPersistent(0xc1ae0001, "erofs")
	hooks := &fakeHooks{fsDir: filepath.Join(e.leaseFsRoot, "lc1"), name: "models"}
	noErr(t, os.MkdirAll(hooks.fsDir, 0o755))
	return e, e.leaseDriver(t, hooks), hooks
}

// leaseDriver returns a new pool driver, as after a restart, that lends
// companion claims with the hooks.
func (e *poolTestEnv) leaseDriver(t *testing.T, hooks *fakeHooks) *dra.Plugin {
	t.Helper()
	p := e.driver(t)
	p.Lender().Set(newFakeLender(), hooks)
	return p
}

// fsCompanion returns the companion claim of lease id of mode fs with the
// access on the persistent device, as the broker writes its MemoryConfig.
func fsCompanion(id, access string) *resourceapi.ResourceClaim {
	cfg := fmt.Sprintf(`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","readOnly":true,"access":%q}}`, access)
	c := persistentClaim("uid-"+companionName(id), persistentData, cfg)
	c.ObjectMeta = companionClaim(id).ObjectMeta
	return c
}

// TestPoolLeaseBind prepares the companion claim of an fs lease: the node
// mount, then its bind in the lease-fs directory before the broker hears
// of it; the Unprepare unmounts the bind before the node mount and the
// region, and fails while the bind is busy.
func TestPoolLeaseBind(t *testing.T) {
	e, p, hooks := newPoolLeaseEnv(t)
	direct := e.nodeMount(0xc1ae0001, "direct")
	target := filepath.Join(hooks.fsDir, "models")
	uid := "uid-cxl-lease-l1"
	bound := false
	hooks.onPrepared = func(string) {
		mi, _ := e.mountedErr(target)
		bound = mi != nil
	}
	r := prepare(t, p, fsCompanion("l1", "direct"))
	noErr(t, r.Err)
	e.wantNoCDIDevices(t, r)
	if !bound {
		t.Fatal("the bind did not exist when the broker was told that the companion is prepared")
	}
	// a plain bind of the node mount, which inherits its flags
	wantCalls := []string{fmt.Sprintf("mount %s %s erofs 0x%x dax=always", e.pmem, direct, fsMountFlags), bindCall(direct, target)}
	if got := e.k.MountCalls("mount"); !slices.Equal(got, wantCalls) {
		t.Fatalf("mount calls %q, expected %q", got, wantCalls)
	}
	if mi, _ := e.mountedErr(target); mi == nil || mi.FsType != "erofs" || mi.Source != e.pmem || !slices.Equal(mi.MountFlags, []string{"ro", "nosuid", "nodev"}) {
		t.Fatalf("bind %+v", mi)
	}
	// recorded in the lend
	if rec := lendOf(e.st.Snapshot(), e.preparation(uid)); rec.FsDir != hooks.fsDir || rec.Name != "models" || !slices.Equal(rec.Mounts, []string{target}) {
		t.Fatalf("lend record %+v", rec)
	}
	// the broker gets the access and the node mount
	if d := hooks.devs[0]; d.Mode != api.ModeFs || d.Access != api.AccessDirect || d.NodeMount != direct || d.BlockDevice != e.pmem || d.Serial != "0xc1ae0001" ||
		d.TotalBytes != fakePmemBytes || !d.ReadOnly || len(d.NUMANodes) != 0 || hooks.source != state.SourcePool {
		t.Fatalf("lent device %+v", d)
	}
	if log := hooks.log(); log != "lending l1 cxl-lease-l1\nprepared l1" {
		t.Fatalf("hooks:\n%s", log)
	}

	// the borrower has files of the bind open: the Unprepare fails, the
	// claim, the node mount and the region stay
	e.k.SetBusy(target, true)
	wantErr(t, unprepare(t, p, uid), "cxl-pool.nri.io: unpreparing claim demo/cxl-lease-l1: lease l1: unmounting "+target+": device or resource busy")
	if e.preparation(uid) == nil || strings.Contains(e.commands(), "disable-region") {
		t.Fatalf("busy bind: claim %v, commands:\n%s", e.preparation(uid), e.commands())
	}
	for _, mnt := range []string{target, direct} {
		if mi, _ := e.mountedErr(mnt); mi == nil {
			t.Fatalf("%s unmounted while the bind is busy", mnt)
		}
	}
	// kubelet retries: the bind, then the node mount, then the region
	e.k.SetBusy(target, false)
	noErr(t, unprepare(t, p, uid))
	if got := e.k.MountCalls("umount"); !slices.Equal(got, []string{"umount " + target, "umount " + target, "umount " + direct}) {
		t.Fatalf("umount calls %q", got)
	}
	e.wantReleased(t, "region0", "mem0")
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bind directory left: %v", err)
	}
	if _, err := os.Stat(hooks.fsDir); err != nil {
		t.Fatalf("the lease-fs directory of the lease claim is the broker's: %v", err)
	}
	if log := hooks.log(); !strings.HasSuffix(log, "releasing l1\nreleasing l1") {
		t.Fatalf("hooks:\n%s", log)
	}

	// a static claim of the same device and access keeps the node mount
	// and the region when the companion is unprepared
	noErr(t, prepare(t, p, persistentClaim("d1", persistentData, fsConfig("direct", ""))).Err)
	noErr(t, prepare(t, p, fsCompanion("l2", "direct")).Err)
	noErr(t, unprepare(t, p, "uid-cxl-lease-l2"))
	if mi, _ := e.mountedErr(target); mi != nil {
		t.Fatalf("bind left %+v", mi)
	}
	if mi, _ := e.mountedErr(direct); mi == nil || strings.Count(e.commands(), "disable-region") != 1 {
		t.Fatalf("the static claim lost its node mount or region:\n%s", e.commands())
	}
	noErr(t, unprepare(t, p, "d1"))
	e.wantReleased(t, "region0", "mem0")
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
}

// TestPoolLeaseBindErrors refuses the Prepare of companion claims of fs
// leases whose bind cannot be made before any device is touched, and tells
// the broker (TestPoolLeaseBindChecks has the binds that fail).
func TestPoolLeaseBindErrors(t *testing.T) {
	e, p, hooks := newPoolLeaseEnv(t)
	target := filepath.Join(hooks.fsDir, "models")
	checkClean := func(what string) {
		t.Helper()
		e.wantClean(t, p)
		e.wantNoMounts(t, p)
		// refused before any device is touched
		if strings.Contains(e.commands(), "create-region") {
			t.Fatalf("%s: a device was touched:\n%s", what, e.commands())
		}
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: bind directory left: %v", what, err)
		}
	}

	// E1: a lease claim of an older driver
	hooks.fsDir = ""
	wantErr(t, prepare(t, p, fsCompanion("l1", "direct")).Err,
		"cxl-pool.nri.io: preparing claim demo/cxl-lease-l1: lease l1: its lease claim has no filesystem directory")
	if !strings.Contains(hooks.log(), "failed l1: lease l1: its lease claim has no filesystem directory") {
		t.Fatalf("lend failure not told:\n%s", hooks.log())
	}
	checkClean("E1")
	hooks.fsDir = filepath.Join(e.leaseFsRoot, "lc1")

	// E2: two fs devices
	c := fsCompanion("l2", "direct")
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
		resourceapi.DeviceRequestAllocationResult{Request: "mem2", Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: "llm0", ConsumedCapacity: poolConsumed(persistentData)})
	wantErr(t, prepare(t, p, c).Err, "lease l2: more than one filesystem device")
	checkClean("E2")
}
