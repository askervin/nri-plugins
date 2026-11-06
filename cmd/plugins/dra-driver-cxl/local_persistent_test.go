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
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	nricxl "github.com/containers/nri-plugins/pkg/cxl"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
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
)

// pmemTestState is the node state of cxl.nri.io with a local memdev of
// persistent memory (mem0, the pmem of fakePoolSys) and a fake mounter.
type pmemTestState struct {
	*nodeState
	f      *fakePoolSys
	m      *fakeMounter
	dir    string
	cdiDir string
	shared bool // the memdev is in sharedDevices
	// fsTypes are the filesystem types of the persistent node: the known
	// ones unless a test says otherwise
	fsTypes []string
}

func newPmemTestState(t *testing.T) *pmemTestState {
	t.Helper()
	f := newFakePoolSys(t)
	f.plugPersistent("0xc100f5e1")
	m := newFakeMounter()
	m.images["/dev/pmem0"] = fsImage("ext4")
	dir := t.TempDir()
	e := &pmemTestState{f: f, m: m, dir: dir, cdiDir: filepath.Join(dir, "cdi"), fsTypes: config.KnownFsTypes}
	noErr(t, os.MkdirAll(e.cdiDir, 0o755))
	noErr(t, os.WriteFile(filepath.Join(dir, "filesystems"), []byte("nodev\ttmpfs\n\text4\n\txfs\n\terofs\n\tbtrfs\n"), 0o644))
	e.start(t, "boot-1")
	return e
}

// start starts the node state again on the env's files and sysfs, as
// after a restart of the plugin (another boot: a reboot), with the
// allocator reconciled with the prepared claims.
func (e *pmemTestState) start(t *testing.T, boot string) {
	t.Helper()
	restartStore(e.dir, boot)
	a, err := newLocalAllocator(e.f.manager(), filepath.Join(e.dir, localStateFileName), boot)
	noErr(t, err)
	a.retryDelay = time.Millisecond
	a.SetPersistent(newPersistentNode(persistentConfig{
		Driver:      device.DriverName,
		Mounter:     e.m,
		MountsDir:   filepath.Join(e.dir, mountsDirName),
		LeaseFsRoot: filepath.Join(e.dir, leaseFsDirName),
		Filesystems: filepath.Join(e.dir, "filesystems"),
		HolderWait:  50 * time.Millisecond,
		FsTypes:     e.fsTypes,
	}))
	claimsFile := filepath.Join(e.dir, device.PreparedClaimsFileName)
	prepared, infos, _, _, err := loadPreparedClaims(claimsFile)
	noErr(t, err)
	forgetOtherBoot(prepared, infos, boot)
	uids := map[string]bool{}
	for uid := range infos {
		uids[uid] = true
	}
	a.Reconcile(testContext(t), uids, nil)
	cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(e.cdiDir), cdiapi.WithAutoRefresh(false))
	noErr(t, err)
	cfg := &DriverConfig{IgnoreDRAMNodes: true}
	if e.shared {
		cfg.SharedDevices = []string{"0xc100f5e1"}
	}
	var lending *companionLender
	if e.nodeState != nil {
		lending = e.lending
	} else {
		lending = newCompanionLender(device.DriverName)
	}
	e.nodeState = &nodeState{
		baseState: &baseState{
			CdiCache:               cache,
			Prepared:               prepared,
			PreparedClaimsFilePath: claimsFile,
			NodeName:               testNode,
		},
		config:         cfg,
		preparedClaims: infos,
		claimsFilePath: filepath.Join(e.dir, preparedClaimsInfoFileName),
		podClaims:      map[string]map[string]bool{},
		local:          a,
		lending:        lending,
		locks:          &nodeLocks{},
		bootID:         boot,
		unrestored:     map[string]error{},
	}
	noErr(t, e.restore())
	e.rescan()
}

// memdev returns the memdev as the device scan finds it.
func (e *pmemTestState) memdev() *nricxl.MemoryDevice {
	return &nricxl.MemoryDevice{Name: "mem0", DevName: "cxl/mem0", PmemSize: 0x20000000, Serial: localPmemSerial, NodeAffinity: 0, Driver: "cxl_mem", Enabled: true}
}

// rescan scans the devices again.
func (e *pmemTestState) rescan() {
	memdev := e.memdev()
	devs := &nricxl.Devices{MemoryDevices: []*nricxl.MemoryDevice{memdev}}
	for _, r := range e.local.mem.Regions("mem0") {
		devs.RegionDevices = append(devs.RegionDevices, &nricxl.RegionDevice{Name: r, Size: 0x20000000, Mode: "pmem", Node: -1, Memories: []*nricxl.MemoryDevice{memdev}})
	}
	infos, _ := buildDevInfos(e.config, devs, nil, e.local.Snapshot())
	e.Lock()
	e.Allocatable = infos
	e.Unlock()
}

// published returns the persistent memdev as published, nil if it is not.
func (e *pmemTestState) published() *resourcev1.Device {
	e.rescan()
	for _, d := range e.GetResources().Pools[testNode].Slices[0].Devices {
		if d.Name == localPmemDeviceName {
			return &d
		}
	}
	return nil
}

// cdiSpec returns the CDI spec of the claims, nil if there is none.
func (e *pmemTestState) cdiSpec(t *testing.T) *cdiSpecs.Spec {
	t.Helper()
	return (&localTestState{cdiDir: e.cdiDir}).cdiSpec(t)
}

// nodeMount returns the node mount of the access.
func (e *pmemTestState) nodeMount(access string) string {
	return filepath.Join(e.dir, mountsDirName, "c100f5e1-"+access)
}

// wantCDIDevice checks the env, device nodes and mounts of a CDI device.
func (e *pmemTestState) wantCDIDevice(t *testing.T, name string, env []string, nodes []*cdiSpecs.DeviceNode, mounts []*cdiSpecs.Mount) {
	t.Helper()
	d := cdiDeviceByName(e.cdiSpec(t), name)
	if d == nil || !slices.Equal(d.ContainerEdits.Env, env) || !reflect.DeepEqual(d.ContainerEdits.DeviceNodes, nodes) || !reflect.DeepEqual(d.ContainerEdits.Mounts, mounts) {
		var got any = d
		if d != nil {
			got = d.ContainerEdits
		}
		t.Fatalf("CDI device %s: %+v, expected env %v nodes %+v mounts %+v", name, got, env, nodes, mounts)
	}
}

// wantRegions checks how many times region0 was created and destroyed,
// and that the memdev was never disabled.
func (e *pmemTestState) wantRegions(t *testing.T, created, destroyed int) {
	t.Helper()
	cmds := e.f.commands()
	if c, d := strings.Count(cmds, "cxl create-region"), strings.Count(cmds, "cxl destroy-region"); c != created || d != destroyed {
		t.Fatalf("region created %d and destroyed %d times, expected %d and %d:\n%s", c, d, created, destroyed, cmds)
	}
	if strings.Contains(cmds, "disable-memdev") {
		t.Fatalf("a local memdev was disabled:\n%s", cmds)
	}
}

// pmemClaim returns a claim allocated the persistent memdev for request
// "mem" with the consumed shares, and opaque cxl.nri.io claim configs.
func pmemClaim(uid, shares string, configs ...string) *resourcev1.ResourceClaim {
	c := localClaim(uid, 0, configs...)
	r := &c.Status.Allocation.Devices.Results[0]
	r.Device = localPmemDeviceName
	if shares != "" {
		r.ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse(shares)}
	}
	return c
}

// pmemCompanion returns the companion claim of lease l1 of the persistent
// memdev.
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

// formatted makes the device have an fsdax namespace with an ext4 on it,
// as a block writer leaves it.
func (e *pmemTestState) formatted() {
	e.f.labels = true
}

// The life cycle of a persistent local memdev: readers refused before a
// writer made the namespace, a block writer that makes it, fs writers and
// readers of one ext4 on one node mount, the downgrade when the writer
// goes and the release of the region with the last claim; the memdev stays
// enabled.
func TestLocalPersistentLifeCycle(t *testing.T) {
	e := newPmemTestState(t)
	ctx := testContext(t)
	if d := e.published(); d == nil || *d.Attributes["persistent"].BoolValue != true || *d.Attributes["shared"].BoolValue {
		t.Fatalf("published %+v", d)
	}

	// readers before a writer: refused, the region goes again
	wantErr(t, e.Prepare(ctx, pmemClaim("r1", localPmemShare, localPmemFsRO)),
		"claim demo/claim-r1: request mem: device 0xc100f5e1: no fsdax namespace in region0: has a writer written the device?")
	wantErr(t, e.Prepare(ctx, pmemClaim("r1", localPmemShare, localPmemBlockRO)), "no fsdax namespace in region0")
	e.wantRegions(t, 2, 2)
	if strings.Contains(e.f.commands(), "ndctl") || e.local.Snapshot().uses(localPmemSerial) {
		t.Fatalf("a reader made a namespace or holds the device:\n%s", e.f.commands())
	}

	// the configuration rules, before the device is touched
	before := e.f.commands()
	wantErr(t, e.Prepare(ctx, pmemClaim("w0", localPmemShare, localPmemBlockRW)),
		"claim demo/claim-w0: request mem: MemoryConfig: device.mode block: a persistent local device is writable only exclusively (no shares request)")
	wantErr(t, e.Prepare(ctx, pmemClaim("w0", localPmemShare)), "MemoryConfig: device: a persistent device needs mode block or fs")
	wantErr(t, e.Prepare(ctx, pmemClaim("w0", "0", localPmemBlockRW)), "device 0xc100f5e1: consumed shares \"0\" is less than 1")
	claim := pmemClaim("w0", "", localPmemBlockRW)
	claim.Status.Allocation.Devices.Results[0].ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{device.CapacityMemory: resource.MustParse("1Gi")}
	wantErr(t, e.Prepare(ctx, claim), "claim demo/claim-w0: request mem: device 0xc100f5e1: allocated as a device of volatile memory, which it is not any more")
	if e.f.commands() != before {
		t.Fatalf("a refused claim touched the device:\n%s", e.f.commandsSince(before))
	}

	// the block writer has the device alone and makes the namespace
	noErr(t, e.Prepare(ctx, pmemClaim("w1", localPmemAll, localPmemBlockRW)))
	e.f.wantCommand(t, "ndctl create-namespace -f -r region0 -m fsdax -M mem")
	e.wantCDIDevice(t, "claim-w1-0",
		pmemEnv("w1", "MODE=block", "PATH=/dev/pmem0", "READONLY=0", "SERIAL=0xc100f5e1", "SHARED=0", "SIZE=534773760"),
		[]*cdiSpecs.DeviceNode{{Path: "/dev/pmem0", Type: "b", Major: 259, Minor: 0}}, nil)
	if e.m.isRO("/dev/pmem0") {
		t.Fatal("the block device of a writer is read-only")
	}
	info := e.preparedClaims["w1"].Devices[0]
	if !info.Persistent || info.Mode != api.ModeBlock || info.BlockDevice != "/dev/pmem0" || info.Namespace != "namespace0.0" || info.TotalBytes != fakePmemBytes || info.ReadOnly {
		t.Fatalf("prepared %+v", info)
	}
	noErr(t, e.Unprepare(ctx, "w1"))
	e.wantRegions(t, 3, 3)
	if e.local.Snapshot().uses(localPmemSerial) || e.published() == nil {
		t.Fatal("the idle device is used or not published")
	}

	// fs writers and a reader of one node mount
	noErr(t, e.Prepare(ctx, pmemClaim("rw1", localPmemShare, localPmemFsRW)))
	noErr(t, e.Prepare(ctx, pmemClaim("rw2", localPmemShare, localPmemFsRW)))
	noErr(t, e.Prepare(ctx, pmemClaim("ro1", localPmemShare, localPmemFsRO)))
	e.wantRegions(t, 4, 3)
	mnt := e.nodeMount("direct")
	for uid, ro := range map[string]bool{"rw1": false, "rw2": false, "ro1": true} {
		readOnly, opts := "0", []string{"bind", "nosuid", "nodev"}
		if ro {
			readOnly, opts = "1", []string{"bind", "ro", "nosuid", "nodev"}
		}
		e.wantCDIDevice(t, "claim-"+uid+"-0",
			pmemEnv(uid, "ACCESS=direct", "FSTYPE=ext4", "MODE=fs", "PATH=/run/cxl-fs/C100F5E1", "READONLY="+readOnly, "SERIAL=0xc100f5e1", "SHARED=0", "SIZE=534773760"),
			nil, []*cdiSpecs.Mount{{HostPath: mnt, ContainerPath: "/run/cxl-fs/C100F5E1", Type: "bind", Options: opts}})
	}
	mi, err := e.m.Mounted(mnt)
	noErr(t, err)
	if mi == nil || mi.FsType != "ext4" || mi.superReadOnly() || len(e.m.mounts) != 1 {
		t.Fatalf("node mount %+v of %d mounts", mi, len(e.m.mounts))
	}
	// the last writer goes: the superblock and the block device turn
	// read-only, the reader stays
	noErr(t, e.Unprepare(ctx, "rw1"))
	if mi, _ := e.m.Mounted(mnt); mi == nil || mi.superReadOnly() {
		t.Fatalf("after one writer: %+v", mi)
	}
	noErr(t, e.Unprepare(ctx, "rw2"))
	if mi, _ := e.m.Mounted(mnt); mi == nil || !mi.superReadOnly() || !e.m.isRO("/dev/pmem0") {
		t.Fatalf("after the writers: %+v, read-only %v", mi, e.m.isRO("/dev/pmem0"))
	}
	// a held block device keeps the region and the claim for kubelet's
	// retry
	e.m.holders["/dev/pmem0"] = "in use"
	wantErr(t, e.Unprepare(ctx, "ro1"), "device 0xc100f5e1: /dev/pmem0 is still in use")
	e.wantRegions(t, 4, 3)
	delete(e.m.holders, "/dev/pmem0")
	noErr(t, e.Unprepare(ctx, "ro1"))
	e.wantRegions(t, 4, 4)
	if len(e.m.mounts) != 0 || e.cdiSpec(t) != nil || e.local.Snapshot().uses(localPmemSerial) {
		t.Fatalf("left: mounts %+v", e.m.mounts)
	}
	e.m.wantNoViolations(t)
}

// Restarts and a reboot: the node mounts of the prepared claims are
// mounted again with the state their uses derive, the uses of claims that
// are not prepared are dropped, the unwanted mounts swept and an idle
// device released; a reboot drops the state without touching the device.
func TestLocalPersistentRestart(t *testing.T) {
	e := newPmemTestState(t)
	ctx := testContext(t)
	e.formatted()
	noErr(t, e.Prepare(ctx, pmemClaim("rw1", localPmemShare, localPmemFsRW)))
	noErr(t, e.Prepare(ctx, pmemClaim("ro1", localPmemShare, localPmemFsRO)))
	mnt := e.nodeMount("direct")

	// a restart with the node mount in place: nothing changes
	before := e.f.commands()
	e.start(t, "boot-1")
	if mi, _ := e.m.Mounted(mnt); mi == nil || mi.superReadOnly() || e.f.commandsSince(before) != "" {
		t.Fatalf("after a restart: %+v\n%s", mi, e.f.commandsSince(before))
	}
	if cdiDeviceByName(e.cdiSpec(t), "claim-rw1-0") == nil || cdiDeviceByName(e.cdiSpec(t), "claim-ro1-0") == nil {
		t.Fatal("CDI devices lost in a restart")
	}

	// the node mount is gone: mounted again read-write for the writer
	noErr(t, e.m.Unmount(mnt))
	e.start(t, "boot-1")
	if mi, _ := e.m.Mounted(mnt); mi == nil || mi.superReadOnly() || e.m.isRO("/dev/pmem0") {
		t.Fatalf("not mounted again read-write: %+v", mi)
	}

	// the writer is not prepared any more (lost in its Unprepare): its use
	// goes, the superblock turns read-only
	e.forgetClaim(t, "rw1")
	e.start(t, "boot-1")
	if mi, _ := e.m.Mounted(mnt); mi == nil || !mi.superReadOnly() || !e.m.isRO("/dev/pmem0") {
		t.Fatalf("writer gone: %+v", mi)
	}
	if uses := e.local.Snapshot().Uses[localPmemSerial]; !slices.Equal(uses.Claims, []string{"ro1"}) {
		t.Fatalf("uses %+v", uses)
	}

	// no prepared claim: the mount is swept, the region released
	e.forgetClaim(t, "ro1")
	e.start(t, "boot-1")
	e.wantRegions(t, 1, 1)
	if len(e.m.mounts) != 0 || e.local.Snapshot().uses(localPmemSerial) {
		t.Fatalf("left: %+v", e.m.mounts)
	}

	// a reboot: the state of the other boot is dropped untouched
	noErr(t, e.Prepare(ctx, pmemClaim("ro2", localPmemShare, localPmemFsRO)))
	e.m.mounts = nil // the node mount does not survive a reboot
	before = e.f.commands()
	e.start(t, "boot-2")
	if e.f.commandsSince(before) != "" || e.local.Snapshot().uses(localPmemSerial) || e.preparedClaims["ro2"] != nil {
		t.Fatalf("a reboot touched the device or kept the claim:\n%s", e.f.commandsSince(before))
	}
	e.m.wantNoViolations(t)
}

// forgetClaim removes a claim from the files of the prepared claims, as a
// plugin that stopped in its Unprepare leaves them.
func (e *pmemTestState) forgetClaim(t *testing.T, uid string) {
	t.Helper()
	e.forget(uid)
	noErr(t, e.persist())
}

// A node mount that the start cannot mount again (the namespace is another
// one now): the claims of it have no CDI devices until a Prepare again
// mounts it, and their Unprepare releases the device.
func TestLocalPersistentUnrestored(t *testing.T) {
	e := newPmemTestState(t)
	ctx := testContext(t)
	e.formatted()
	noErr(t, e.Prepare(ctx, pmemClaim("ro1", localPmemShare, localPmemFsRO)))
	mnt := e.nodeMount("direct")
	// the mount fails at the start: the Prepare again mounts it
	noErr(t, e.m.Unmount(mnt))
	e.m.mountErr["/dev/pmem0"] = syscall.EIO
	e.start(t, "boot-1")
	if cdiDeviceByName(e.cdiSpec(t), "claim-ro1-0") != nil {
		t.Fatal("a CDI device of an unrestored claim")
	}
	delete(e.m.mountErr, "/dev/pmem0")
	noErr(t, e.Prepare(ctx, pmemClaim("ro1", localPmemShare, localPmemFsRO)))
	if cdiDeviceByName(e.cdiSpec(t), "claim-ro1-0") == nil || e.unrestored["ro1"] != nil {
		t.Fatal("no CDI device after the Prepare again mounted the node mount")
	}
	// the namespace is another one now: unrestored until the Unprepare
	noErr(t, e.m.Unmount(mnt))
	e.f.pmemDev = "259:7"
	e.f.fsdax()
	e.start(t, "boot-1")
	if cdiDeviceByName(e.cdiSpec(t), "claim-ro1-0") != nil {
		t.Fatal("a CDI device of an unrestored claim")
	}
	wantErr(t, e.Prepare(ctx, pmemClaim("ro1", localPmemShare, localPmemFsRO)), "unprepare the claim (delete its pods) to prepare it anew")
	noErr(t, e.Unprepare(ctx, "ro1"))
	e.wantRegions(t, 1, 1)
	e.m.wantNoViolations(t)
}

// The release of the last claim in decoder order: while a region of
// another memdev lies above the region of the device, the idle device
// keeps it, reused by its next claim; the release of idle devices releases
// it when nothing lies above.
func TestLocalPersistentDecoderOrder(t *testing.T) {
	e := newPmemTestState(t)
	ctx := testContext(t)
	e.formatted()
	noErr(t, e.Prepare(ctx, pmemClaim("ro1", localPmemShare, localPmemFsRO)))
	e.f.stackPorts("region0", "region9")
	noErr(t, e.Unprepare(ctx, "ro1"))
	e.wantRegions(t, 1, 0)
	if !e.local.Snapshot().uses(localPmemSerial) || e.published() == nil {
		t.Fatal("the idle device with its kept region is not published")
	}
	noErr(t, e.Prepare(ctx, pmemClaim("ro2", localPmemShare, localPmemFsRO)))
	e.wantRegions(t, 1, 0)
	noErr(t, e.Unprepare(ctx, "ro2"))
	e.f.stackPorts("region0")
	e.local.ReleaseIdle(ctx)
	e.wantRegions(t, 1, 1)
	if e.local.Snapshot().uses(localPmemSerial) {
		t.Fatal("idle device not released")
	}
	e.m.wantNoViolations(t)
}

// A creation of the region cut by a restart: the start releases what it
// left, or keeps it for the claim when a region lies above it; the
// Prepare again uses it.
func TestLocalPersistentCutCreation(t *testing.T) {
	for _, above := range []bool{false, true} {
		e := newPmemTestState(t)
		ctx := testContext(t)
		e.formatted()
		e.f.cutAfter = "cxl create-region"
		cut(t, func() { _ = e.Prepare(ctx, pmemClaim("ro1", localPmemShare, localPmemFsRO)) })
		if d := e.local.devices[localPmemSerial]; d == nil || d.Region != "" || d.Creating != "region0" {
			t.Fatalf("above %v: record of the cut creation %+v", above, d)
		}
		if above {
			e.f.stackPorts("region0", "region9")
		}
		e.start(t, "boot-1")
		if above {
			e.wantRegions(t, 1, 0)
			if d := e.local.devices[localPmemSerial]; d == nil || d.Region != "region0" || d.NdRegion != "" {
				t.Fatalf("kept region %+v", d)
			}
			noErr(t, e.Prepare(ctx, pmemClaim("ro1", localPmemShare, localPmemFsRO)))
			e.wantRegions(t, 1, 0)
			noErr(t, e.Unprepare(ctx, "ro1"))
			continue
		}
		e.wantRegions(t, 1, 1)
		if e.local.Snapshot().uses(localPmemSerial) {
			t.Fatal("the device of the cut creation is still used")
		}
		noErr(t, e.Prepare(ctx, pmemClaim("ro1", localPmemShare, localPmemFsRO)))
		e.wantRegions(t, 2, 1)
		noErr(t, e.Unprepare(ctx, "ro1"))
		e.wantRegions(t, 2, 2)
		e.m.wantNoViolations(t)
	}
}

// A memdev in sharedDevices: other hosts may use it, so read-write fs
// needs a cluster filesystem on coherent memory, and mode block is never
// written; it is shared in the env and the attributes.
func TestLocalPersistentShared(t *testing.T) {
	e := newPmemTestState(t)
	e.shared = true
	e.start(t, "boot-1")
	ctx := testContext(t)
	e.formatted()
	if d := e.published(); d == nil || !*d.Attributes["shared"].BoolValue || !*d.Attributes["persistent"].BoolValue {
		t.Fatalf("published %+v", d)
	}
	wantErr(t, e.Prepare(ctx, pmemClaim("w1", localPmemAll, localPmemBlockRW)), "MemoryConfig: device.mode block: other hosts may use the device: it is not written in mode block")
	wantErr(t, e.Prepare(ctx, pmemClaim("w1", localPmemShare, localPmemFsRW)), "MemoryConfig: device.readOnly: false: other hosts may use the device")
	noErr(t, e.Prepare(ctx, pmemClaim("ro1", localPmemShare, localPmemFsRO)))
	e.wantCDIDevice(t, "claim-ro1-0",
		pmemEnv("ro1", "ACCESS=direct", "FSTYPE=ext4", "MODE=fs", "PATH=/run/cxl-fs/C100F5E1", "READONLY=1", "SERIAL=0xc100f5e1", "SHARED=1", "SIZE=534773760"),
		nil, []*cdiSpecs.Mount{{HostPath: e.nodeMount("direct"), ContainerPath: "/run/cxl-fs/C100F5E1", Type: "bind", Options: []string{"bind", "ro", "nosuid", "nodev"}}})
	// sharedDevices changes while the claim is prepared: the device is not
	// published until it is idle, and a stale allocation is refused
	e.shared = false
	e.start(t, "boot-1")
	if e.published() != nil {
		t.Fatal("published with the other sharing while in use")
	}
	wantErr(t, e.Prepare(ctx, pmemClaim("ro2", localPmemShare, localPmemFsRO)), "could not find allocatable device "+localPmemDeviceName)
	_, err := e.local.AcquirePersistent(ctx, "ro2", "mem", localPmemSerial, false, config.DeviceFacts{Persistent: true, SingleHost: true, Local: true},
		persistentWant{UID: "ro2", Mode: api.ModeFs, ReadOnly: true}, "/data")
	wantErr(t, err, "memdev mem0 (serial 0xc100f5e1): used as a shared persistent device by claims [ro1]; it is not shared now (sharedDevices)")
	noErr(t, e.Unprepare(ctx, "ro1"))
	if d := e.published(); d == nil || *d.Attributes["shared"].BoolValue {
		t.Fatalf("published %+v", d)
	}
	e.m.wantNoViolations(t)
}

// A memdev is used as one kind of device at a time.
func TestLocalPersistentConflicts(t *testing.T) {
	e := newPmemTestState(t)
	ctx := testContext(t)
	e.formatted()
	noErr(t, e.Prepare(ctx, pmemClaim("ro1", localPmemShare, localPmemFsRO)))
	_, _, err := e.local.Acquire(ctx, "s1", "mem", localPmemSerial, api.ModeDax, 1<<28, false)
	wantErr(t, err, "memdev mem0 (serial 0xc100f5e1): used as a persistent device by claims [ro1]; a sliced device cannot be a persistent device")
	_, err = e.local.AcquireShared(ctx, "s1", "mem", localPmemSerial, false, "exclusive")
	wantErr(t, err, "used as a persistent device by claims [ro1]; a shared device cannot be a persistent device")
	noErr(t, e.Unprepare(ctx, "ro1"))
}

// Leases of a persistent local memdev: a read-only fs lease gets a bind of
// the node mount before it is lent, unbound before the release; a block
// lease is lent the block device.
func TestLocalPersistentLease(t *testing.T) {
	e := newPmemTestState(t)
	hooks := &fakeHooks{fsDir: filepath.Join(e.dir, leaseFsDirName, "lc1"), name: "models"}
	e.lending.set(newFakeLender(), hooks)
	ctx := testContext(t)
	e.formatted()
	noErr(t, e.Prepare(ctx, pmemCompanion("c1", localPmemShare, localPmemFsRO)))
	target := filepath.Join(hooks.fsDir, "models")
	if mi, _ := e.m.Mounted(target); mi == nil || !slices.Contains(mi.MountFlags, "ro") {
		t.Fatalf("lease bind %+v", mi)
	}
	if rec := e.preparedClaims["c1"].Lend; rec == nil || !slices.Equal(rec.Mounts, []string{target}) {
		t.Fatalf("lend %+v", rec)
	}
	if len(hooks.devs) != 1 || hooks.devs[0].Mode != api.ModeFs || hooks.devs[0].NodeMount != e.nodeMount("direct") || hooks.devs[0].FsType != "ext4" ||
		hooks.devs[0].BlockDevice != "/dev/pmem0" || !hooks.devs[0].ReadOnly || hooks.devs[0].Source != api.SourceLocal {
		t.Fatalf("lent %+v", hooks.devs)
	}
	if cdiDeviceByName(e.cdiSpec(t), "claim-c1-0") != nil {
		t.Fatal("CDI device of a companion claim")
	}
	// the sweep of both drivers' binds after the start unmounts a bind
	// that no claim lists, and keeps the lease's
	stale := filepath.Join(e.dir, leaseFsDirName, "lc9", "old")
	noErr(t, os.MkdirAll(stale, 0o755))
	noErr(t, e.m.Mount(e.nodeMount("direct"), stale, "", unix.MS_BIND, ""))
	sweepStaleLeaseBinds(ctx, e.nodeState, nil)
	if mi, _ := e.m.Mounted(stale); mi != nil {
		t.Fatal("stale lease bind not swept")
	}
	if mi, _ := e.m.Mounted(target); mi == nil {
		t.Fatal("the lease bind was swept")
	}
	// a restart binds it again
	noErr(t, e.m.Unmount(target))
	e.start(t, "boot-1")
	if mi, _ := e.m.Mounted(target); mi == nil {
		t.Fatal("lease bind not bound again")
	}
	noErr(t, e.Unprepare(ctx, "c1"))
	if mi, _ := e.m.Mounted(target); mi != nil || len(e.m.mounts) != 0 {
		t.Fatalf("left: %+v", e.m.mounts)
	}
	e.wantRegions(t, 1, 1)

	noErr(t, e.Prepare(ctx, pmemCompanion("c2", localPmemAll, localPmemBlockRW)))
	if len(hooks.devs) != 1 || hooks.devs[0].Mode != api.ModeBlock || hooks.devs[0].BlockDevice != "/dev/pmem0" || hooks.devs[0].ReadOnly {
		t.Fatalf("lent %+v", hooks.devs)
	}
	noErr(t, e.Unprepare(ctx, "c2"))
	e.m.wantNoViolations(t)
}

// The record of a persistent device in the state file.
func TestLocalPersistentStateFile(t *testing.T) {
	e := newPmemTestState(t)
	ctx := testContext(t)
	e.formatted()
	noErr(t, e.Prepare(ctx, pmemClaim("rw1", localPmemShare, localPmemFsRW)))
	data, err := os.ReadFile(filepath.Join(e.dir, localStateFileName))
	noErr(t, err)
	for _, want := range []string{`"persistent": true`, `"ndRegion": "region0"`, `"namespace": "namespace0.0"`, `"blockDevice": "/dev/pmem0"`,
		`"mode": "fs"`, `"access": "direct"`, `"fsType": "ext4"`, `"nodeMount": "` + e.nodeMount("direct") + `"`, `"path": "/run/cxl-fs/C100F5E1"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("state file lacks %s:\n%s", want, data)
		}
	}
	noErr(t, e.Unprepare(ctx, "rw1"))
}

// Two results of one claim on the device: one node mount, the env keys and
// default paths of the second have _2.
func TestLocalPersistentTwoResults(t *testing.T) {
	e := newPmemTestState(t)
	ctx := testContext(t)
	e.formatted()
	claim := pmemClaim("ro1", localPmemShare, localPmemFsRO)
	r := claim.Status.Allocation.Devices.Results[0]
	r.Request = "mem2"
	claim.Status.Allocation.Devices.Results = append(claim.Status.Allocation.Devices.Results, r)
	noErr(t, e.Prepare(ctx, claim))
	mnt := e.nodeMount("direct")
	ro := []string{"bind", "ro", "nosuid", "nodev"}
	e.wantCDIDevice(t, "claim-ro1-1",
		[]string{"CXL_C100F5E1_2_ACCESS=direct", "CXL_C100F5E1_2_FSTYPE=ext4", "CXL_C100F5E1_2_MODE=fs", "CXL_C100F5E1_2_PATH=/run/cxl-fs/C100F5E1_2",
			"CXL_C100F5E1_2_READONLY=1", "CXL_C100F5E1_2_SERIAL=0xc100f5e1", "CXL_C100F5E1_2_SHARED=0", "CXL_C100F5E1_2_SIZE=534773760", "CXL_CLAIM_ro1_1=1"},
		nil, []*cdiSpecs.Mount{{HostPath: mnt, ContainerPath: "/run/cxl-fs/C100F5E1_2", Type: "bind", Options: ro}})
	if len(e.m.mounts) != 1 {
		t.Fatalf("mounts %+v", e.m.mounts)
	}
	noErr(t, e.Unprepare(ctx, "ro1"))
	e.wantRegions(t, 1, 1)
	if len(e.m.mounts) != 0 {
		t.Fatalf("left %+v", e.m.mounts)
	}
	e.m.wantNoViolations(t)
}

// A release changes the read-only flag of the block device of the
// remaining uses only while it is the device's: after the namespace got
// other numbers (/dev/pmem0 is another device's now), no BLKROSET (A18).
func TestLocalPersistentReleaseVerifiedDevice(t *testing.T) {
	e := newPmemTestState(t)
	ctx := testContext(t)
	e.formatted()
	for _, uid := range []string{"r1", "r2", "r3"} {
		noErr(t, e.Prepare(ctx, pmemClaim(uid, localPmemShare, localPmemBlockRO)))
	}
	// the flag was cleared meanwhile: the release sets it again
	e.m.ro["/dev/pmem0"] = false
	n := len(e.m.callsOf("blkroset"))
	noErr(t, e.Unprepare(ctx, "r1"))
	if c := e.m.callsOf("blkroset")[n:]; !slices.Equal(c, []string{"blkroset /dev/pmem0 1"}) {
		t.Fatalf("release of the verified device: %q", c)
	}
	e.f.pmemDev = "259:7"
	e.f.fsdax()
	e.m.ro["/dev/pmem0"] = false
	n = len(e.m.callsOf("blkroset"))
	noErr(t, e.Unprepare(ctx, "r2"))
	if c := e.m.callsOf("blkroset")[n:]; len(c) != 0 {
		t.Fatalf("release changed the flag of another device's block device: %q", c)
	}
	noErr(t, e.Unprepare(ctx, "r3"))
	e.wantRegions(t, 1, 1)
	e.m.wantNoViolations(t)
}

// Superblocks that no claim of the node explains (another mount namespace
// has /dev/pmemK mounted) refuse a writer of a local persistent memdev; a
// lease bind of its node mount in a container is explained (A17).
func TestLocalPersistentUnexplainedSuperblock(t *testing.T) {
	e := newPmemTestState(t)
	ctx := testContext(t)
	e.formatted()
	e.m.addForeign(4242, "/dev/pmem0", "/mnt/x", "ext4", false)
	wantErr(t, e.Prepare(ctx, pmemClaim("rw1", localPmemShare, localPmemFsRW)),
		"device 0xc100f5e1: /dev/pmem0 has a superblock that no claim of this node explains (/dev/pmem0 mounted rw in pid 4242 at /mnt/x): it is not used until that mount is gone")
	wantErr(t, e.Prepare(ctx, pmemClaim("w1", localPmemAll, localPmemBlockRW)), "has a superblock that no claim of this node explains")
	e.m.foreign = map[int][]mountInfo{}
	noErr(t, e.Prepare(ctx, pmemClaim("rw1", localPmemShare, localPmemFsRW)))
	// a container's copy of the node mount (the same source) is explained
	e.m.addForeign(4243, "/dev/pmem0", "/run/cxl-fs/C100F5E1", "ext4", false)
	noErr(t, e.Prepare(ctx, pmemClaim("rw2", localPmemShare, localPmemFsRW)))
	e.m.foreign = map[int][]mountInfo{}
	noErr(t, e.Unprepare(ctx, "rw2"))
	noErr(t, e.Unprepare(ctx, "rw1"))
	cmds := e.f.commands()
	if c, d := strings.Count(cmds, "cxl create-region"), strings.Count(cmds, "cxl destroy-region"); c != d || e.local.Snapshot().uses(localPmemSerial) || len(e.m.mounts) != 0 {
		t.Fatalf("left: regions created %d destroyed %d, mounts %+v", c, d, e.m.mounts)
	}
	e.m.wantNoViolations(t)
}

// fsTypes of the driver configuration: the default mounts erofs only, so
// an ext4 is refused (P4) before it is mounted; an explicit list allows
// the types it lists, and an empty one none.
func TestLocalPersistentFsTypes(t *testing.T) {
	e := newPmemTestState(t)
	ctx := testContext(t)
	e.formatted()
	cfg, err := newDriverConfigFromString("")
	noErr(t, err)
	e.fsTypes = cfg.fsTypes()
	e.start(t, "boot-1")
	wantErr(t, e.Prepare(ctx, pmemClaim("ro1", localPmemShare, localPmemFsRO)),
		"claim demo/claim-ro1: request mem: device 0xc100f5e1: filesystem type ext4 is not allowed on this node (fsTypes: erofs)")
	if len(e.m.mounts) != 0 || e.local.Snapshot().uses(localPmemSerial) {
		t.Fatalf("a refused type was mounted or holds the device: %+v", e.m.mounts)
	}
	cfg, err = newDriverConfigFromString("fsTypes: [erofs, ext4]")
	noErr(t, err)
	e.fsTypes = cfg.fsTypes()
	e.start(t, "boot-1")
	noErr(t, e.Prepare(ctx, pmemClaim("ro1", localPmemShare, localPmemFsRO)))
	noErr(t, e.Unprepare(ctx, "ro1"))
	cfg, err = newDriverConfigFromString("fsTypes: []")
	noErr(t, err)
	e.fsTypes = cfg.fsTypes()
	e.start(t, "boot-1")
	wantErr(t, e.Prepare(ctx, pmemClaim("ro1", localPmemShare, localPmemFsRO)), "filesystem type ext4 is not allowed on this node (fsTypes: none)")
	e.m.wantNoViolations(t)
}

// The pool driver gets the fsTypes of the driver configuration, erofs
// only by default.
func TestLoadPoolDriverFsTypes(t *testing.T) {
	for _, tc := range []struct {
		config string
		want   []string
	}{
		{"", []string{"erofs"}},
		{"fsTypes: [erofs, xfs]", []string{"erofs", "xfs"}},
	} {
		cfg, err := newDriverConfigFromString(tc.config)
		noErr(t, err)
		dir := t.TempDir()
		pc := &pluginConfig{KubeletPluginDir: filepath.Join(dir, device.DriverName)}
		noErr(t, os.MkdirAll(pc.KubeletPluginDir, 0o750))
		flags := &CXLFlags{PoolDriverName: device.PoolDriverName, PoolPrepareTimeout: time.Second}
		st, err := store.Open(context.Background(), store.Options{Dir: pc.KubeletPluginDir, PoolDir: filepath.Join(dir, device.PoolDriverName),
			PoolDriver: device.PoolDriverName, BootID: "boot-1"})
		noErr(t, err)
		p, err := loadPoolDriver(context.Background(), pc, flags, dir, nil, "boot-1", cfg.fsTypes(), st)
		noErr(t, err)
		if !slices.Equal(p.fsTypes, tc.want) {
			t.Fatalf("config %q: pool fsTypes %v, expected %v", tc.config, p.fsTypes, tc.want)
		}
		noErr(t, st.Close())
	}
}
