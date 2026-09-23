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
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	resourceapi "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// numaCompanion returns the companion claim of the numa lease id on the
// pool device pooled0.
func numaCompanion(id string) *resourceapi.ResourceClaim {
	c := poolClaim("uid-"+companionName(id), companionName(id), "pooled0", exclusiveData)
	c.ObjectMeta = companionClaim(id).ObjectMeta
	return c
}

// recordedLender is a fake lender that records whether the memory of a
// region is online at each revoke, and stops the process after a lend when
// cut is set.
type recordedLender struct {
	*fakeLender
	e      *poolTestEnv
	region string
	mu     sync.Mutex
	online []bool
	cut    bool
}

func (l *recordedLender) LendNode(ctx context.Context, podUID, name string, node int, holder string) error {
	err := l.fakeLender.LendNode(ctx, podUID, name, node, holder)
	if l.cut {
		panic(errCut)
	}
	return err
}

func (l *recordedLender) RevokeNode(ctx context.Context, podUID, name string, node int, holder string) error {
	l.mu.Lock()
	l.online = append(l.online, l.e.onlineBlocks(l.region) > 0)
	l.mu.Unlock()
	return l.fakeLender.RevokeNode(ctx, podUID, name, node, holder)
}

// revokes returns whether the memory was online at each revoke so far.
func (l *recordedLender) revokes() []bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.online)
}

// keptClaim prepares the claim u1 of pooled0 whose Prepare a process stop
// cuts after cxl create-region, below a region that another memdev gets
// then: the start keeps it (KEPT). It returns the driver and the region
// above.
func keptClaim(t *testing.T, e *poolTestEnv) (*dra.Plugin, string) {
	t.Helper()
	e.plug(0xc1ee0001)
	other := e.plug(0xc1ee0002)
	p := e.driver(t)
	e.k.CutAfter("cxl create-region")
	cutPrepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData))
	k := e.k.Kernel()
	d, err := k.RootDecoder(other, kernel.RegionRAM)
	noErr(t, err)
	above, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: other, Decoder: d, Type: kernel.RegionRAM})
	noErr(t, err)
	e.base = e.k.Commands()
	p = e.driver(t)
	if prep := e.preparation("u1"); prep == nil || prep.State != state.PreparationKept {
		t.Fatalf("preparation %+v", prep)
	}
	return p, above
}

// A KEPT claim whose Prepare again is refused (no status data) stays KEPT
// with its record and its kept region; the Prepare again with the data
// reuses the region.
func TestPoolKeptRefused(t *testing.T) {
	e := newPoolTestEnv(t)
	p, above := keptClaim(t, e)
	kept := e.k.Kernel().Regions("mem0")
	wantErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", "")).Err, "no entry")
	if prep := e.preparation("u1"); prep == nil || prep.State != state.PreparationKept || len(prep.Results) != 1 {
		t.Fatalf("preparation %+v", prep)
	}
	if strings.Contains(e.commands(), "destroy-region") || !slices.Equal(e.k.Kernel().Regions("mem0"), kept) {
		t.Fatalf("the refused Prepare released the kept region:\n%s", e.commands())
	}
	noErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err)
	if g := e.records().Grant(state.GrantRef{Claim: "u1"}); g == nil || len(kept) != 1 || g.Got.Region != state.RegionRef(kept[0]) {
		t.Fatalf("the kept region %v is not reused: %+v", kept, g)
	}
	noErr(t, unprepare(t, p, "u1"))
	noErr(t, e.k.Kernel().ReleaseRegion(context.Background(), above))
	e.wantClean(t, p)
}

// A rollback that cannot release everything keeps the claim's record
// (KEPT) with the grants left, says so; the claim's Unprepare releases
// them.
func TestPoolRollbackKept(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ee0001)
	foreign := e.plug(0xc1ee0002)
	k := e.k.Kernel()
	d, err := k.RootDecoder(foreign, kernel.RegionRAM)
	noErr(t, err)
	region, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: foreign, Decoder: d, Type: kernel.RegionRAM})
	noErr(t, err)
	e.base = e.k.Commands()
	p := e.driver(t)
	// the second device has a region that the driver did not make; the
	// rollback of the first one cannot disable its memdev
	e.k.FailCommand("cxl disable-memdev", syscall.EBUSY)
	claim := addPoolDevice(poolClaim("u1", "c1", "pooled0", exclusiveData), "mem2", "pooled1", `{"serial":"0xc1ee0002","shared":false,"size":268435456}`)
	logs := captureKlog(t)
	wantErr(t, prepare(t, p, claim).Err, "that the plugin did not create")
	want := "rollback: claim default/c1 (u1): not everything was released: keeping its record in " + filepath.Join(e.dir, store.FileName) +
		" for its Unprepare or its next Prepare"
	if !strings.Contains(logs(), want) {
		t.Fatalf("no %q in\n%s", want, logs())
	}
	prep := e.preparation("u1")
	if prep == nil || prep.State != state.PreparationKept || len(prep.Results) != 1 || prep.Results[0].Index != 0 {
		t.Fatalf("preparation %+v", prep)
	}
	if g := e.grant("u1", 0); g == nil || g.Serial != 0xc1ee0001 {
		t.Fatalf("grant %+v", g)
	}
	// the foreign region goes; the Unprepare forgets its record
	noErr(t, k.ReleaseRegion(context.Background(), region))
	noErr(t, unprepare(t, p, "u1"))
	e.wantClean(t, p)
}

// A Prepare again refused by validation or by the companion gate rolls
// nothing back: the claim that a stop cut keeps what it made with its
// record for kubelet's retry or Unprepare.
func TestPoolRefusedPrepareAgain(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ee0001)
	p := e.driver(t)
	hooks := &fakeHooks{}
	p.Lender().Set(newFakeLender(), hooks)
	e.k.CutAfter("write devices/system/memory/memory")
	cutPrepare(t, p, numaCompanion("l1"))
	p = e.driver(t)
	p.Lender().Set(newFakeLender(), hooks)
	uid := "uid-cxl-lease-l1"
	before := e.commands()
	// the companion gate refuses it (the lease went while the driver was
	// down)
	hooks.lendingErr = errors.New("lease l1 is gone")
	wantErr(t, prepare(t, p, numaCompanion("l1")).Err, "lease l1 is gone")
	// a MemoryConfig that the driver refuses
	hooks.lendingErr = nil
	wantErr(t, prepare(t, p, withConfig(numaCompanion("l1"), resourceapi.AllocationConfigSourceClaim, nil, roConfig)).Err,
		"device.readOnly needs mode dax, block or fs")
	if cmds := strings.TrimPrefix(e.commands(), before); strings.Contains(cmds, "region") {
		t.Fatalf("a refused Prepare released what the cut Prepare made:\n%s", cmds)
	}
	if prep := e.preparation(uid); prep == nil || prep.State != state.PreparationPreparing || e.records().Grant(state.GrantRef{Claim: uid}) == nil {
		t.Fatalf("preparation %+v", prep)
	}
	noErr(t, prepare(t, p, numaCompanion("l1")).Err)
	noErr(t, unprepare(t, p, uid))
	e.wantClean(t, p)
}

// The NUMA nodes of the claims whose Prepare did not finish are fenced at
// a start (numaNodes), they have no results for the NRI plugin.
func TestPoolUnfinishedNodes(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ee0001)
	p := e.driver(t)
	e.k.CutAfter("write devices/system/memory/memory")
	claim := numaCompanion("l1")
	hooks := &fakeHooks{}
	p.Lender().Set(newFakeLender(), hooks)
	cutPrepare(t, p, claim)
	p = e.driver(t)
	uid := "uid-cxl-lease-l1"
	node := state.NumaNodeOf(e.records().Region("region0").NumaNode)
	if node < 0 || !slices.Equal(poolNumaNodes(p), []int{node}) || p.ClaimResults(uid) != nil {
		t.Fatalf("numa nodes %v (region on %d), results %v", poolNumaNodes(p), node, p.ClaimResults(uid))
	}
	p.Lender().Set(newFakeLender(), hooks)
	noErr(t, unprepare(t, p, uid))
	if poolNumaNodes(p) != nil {
		t.Fatalf("numa nodes %v", poolNumaNodes(p))
	}
	e.wantClean(t, p)
}

// The Unprepare of a companion of a numa lease revokes the node it lends
// with its memory online, then releases it; before the lender is set up
// it fails. A process stop after the lend: the start keeps the companion,
// its Unprepare revokes the node.
func TestPoolCompanionRevoke(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ee0001)
	p := e.driver(t)
	hooks := &fakeHooks{}
	lender := &recordedLender{fakeLender: newFakeLender(), e: e, region: "region0"}
	p.Lender().Set(lender, hooks)
	uid := "uid-cxl-lease-l1"
	noErr(t, prepare(t, p, numaCompanion("l1")).Err)
	if !strings.Contains(lender.callLog(), "lend ") {
		t.Fatalf("lender calls:\n%s", lender.callLog())
	}
	// the lend recorded with the node of the memory of the device
	if rec, node := lendOf(e.st.Snapshot(), e.preparation(uid)), e.k.Kernel().TargetNode("dax0.0"); rec == nil || rec.Lease != "l1" ||
		node < 0 || !slices.Equal(rec.NumaNodes, []int{node}) {
		t.Fatalf("lend %+v, the memory on node %d", rec, node)
	}
	noErr(t, unprepare(t, p, uid))
	if got := lender.revokes(); !slices.Equal(got, []bool{true}) {
		t.Fatalf("revokes with the memory online: %v", got)
	}
	e.wantClean(t, p)

	// a process stop after the lend
	lender.cut = true
	cutPrepare(t, p, numaCompanion("l1"))
	lender.cut = false
	p = e.driver(t)
	wantErr(t, unprepare(t, p, uid), "lending is not set up yet")
	if prep := e.preparation(uid); prep == nil {
		t.Fatal("the companion is gone")
	}
	p.Lender().Set(lender, hooks)
	p.Engine().RecoverCompanions()
	noErr(t, unprepare(t, p, uid))
	if got := lender.revokes(); !slices.Equal(got, []bool{true, true}) {
		t.Fatalf("revokes with the memory online: %v", got)
	}
	e.wantClean(t, p)
}

// A companion whose lend succeeded and whose CDI spec cannot be written is
// revoked with its memory online, then released and forgotten.
func TestPoolCompanionRollbackRevokes(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ae0001)
	e.plug(0xc1ee0001)
	p := e.driver(t)
	hooks := &fakeHooks{}
	lender := &recordedLender{fakeLender: newFakeLender(), e: e, region: "region1"}
	p.Lender().Set(lender, hooks)
	// a claim with a CDI device, then a CDI directory that cannot be
	// written
	noErr(t, prepare(t, p, poolClaim("s1", "c-s1", "shared0", sharedData)).Err)
	noErr(t, os.RemoveAll(e.cdiDir))
	noErr(t, os.WriteFile(e.cdiDir, nil, 0o644))
	wantErr(t, prepare(t, p, numaCompanion("l1")).Err, "CDI spec")
	if got := lender.revokes(); !slices.Equal(got, []bool{true}) {
		t.Fatalf("revokes with the memory online: %v", got)
	}
	if prep := e.preparation("uid-cxl-lease-l1"); prep != nil || strings.Contains(hooks.log(), "prepared l1") {
		t.Fatalf("the companion kept: %+v\n%s", prep, hooks.log())
	}
	if rs := e.k.Kernel().Regions("mem1"); len(rs) != 0 {
		t.Fatalf("regions %v of the companion left", rs)
	}
	noErr(t, os.Remove(e.cdiDir))
	noErr(t, os.MkdirAll(e.cdiDir, 0o755))
	noErr(t, unprepare(t, p, "s1"))
}

// The claims of a node mount that the start could not mount again have no
// CDI device; they get them back when the node mount is mounted again: by
// the Prepare again of one of them, or by the Prepare of a new claim.
func TestPoolRemountCDI(t *testing.T) {
	for _, how := range []string{"prepare again", "new claim"} {
		t.Run(how, func(t *testing.T) {
			e := newPoolTestEnv(t)
			_, pmem := e.plugPersistent(0xc1ae0001, "erofs")
			p := e.driver(t)
			direct := e.nodeMount(0xc1ae0001, "direct")
			noErr(t, prepare(t, p, persistentClaim("d1", persistentData, fsConfig("direct", "/models"))).Err)
			noErr(t, prepare(t, p, persistentClaim("d2", persistentData, fsConfig("direct", "/models"))).Err)
			// a new mount namespace where the device cannot be mounted
			noErr(t, e.k.Kernel().Unmount(direct))
			e.k.SetMountError(pmem, syscall.EIO, "")
			p = e.driver(t)
			for _, uid := range []string{"d1", "d2"} {
				if prep := e.preparation(uid); prep.State != state.PreparationUnrestored || cdiDeviceByName(e.cdiSpec(t), "claim-"+uid+"-0") != nil {
					t.Fatalf("%s: %+v, CDI spec %+v", uid, prep, e.cdiSpec(t))
				}
			}
			wantErr(t, prepare(t, p, persistentClaim("d1", persistentData, fsConfig("direct", "/models"))).Err,
				"its node mount "+direct+" is not mounted and cannot be mounted again")
			e.k.SetMountError(pmem, nil, "")
			if how == "prepare again" {
				noErr(t, prepare(t, p, persistentClaim("d1", persistentData, fsConfig("direct", "/models"))).Err)
			} else {
				noErr(t, prepare(t, p, persistentClaim("d3", persistentData, fsConfig("direct", "/models"))).Err)
			}
			for _, uid := range []string{"d1", "d2"} {
				cd := cdiDeviceByName(e.cdiSpec(t), "claim-"+uid+"-0")
				if prep := e.preparation(uid); prep.State != state.PreparationPrepared || cd == nil || len(cd.ContainerEdits.Mounts) != 1 ||
					cd.ContainerEdits.Mounts[0].HostPath != direct || cd.ContainerEdits.Mounts[0].ContainerPath != "/models" {
					t.Fatalf("%s: %+v, CDI device %+v", uid, prep, cd)
				}
			}
			for _, uid := range []string{"d1", "d2", "d3"} {
				noErr(t, unprepare(t, p, uid))
			}
			e.wantClean(t, p)
		})
	}
}

// A Prepare refused before any device is touched retries the stale lease
// binds as a failed Prepare does: the bind that a busy Unprepare left is
// unmounted, the companion released after it.
func TestPoolRefusedPrepareRetriesStaleBinds(t *testing.T) {
	e, p, hooks := newPoolLeaseEnv(t)
	target := filepath.Join(hooks.fsDir, "models")
	uid := "uid-cxl-lease-l1"
	noErr(t, prepare(t, p, fsCompanion("l1", "direct")).Err)
	e.k.SetBusy(target, true)
	wantErr(t, unprepare(t, p, uid), "device or resource busy")
	e.k.SetBusy(target, false)
	logs := captureKlog(t)
	wantErr(t, prepare(t, p, poolClaim("x1", "c-x1", "pooled9", "")).Err, "no entry")
	if want := "unbound stale lease bind " + target; !strings.Contains(logs(), want) {
		t.Fatalf("no %q in\n%s", want, logs())
	}
	if mi := e.mounted(target); mi != nil {
		t.Fatalf("the stale bind is mounted: %+v", mi)
	}
	noErr(t, unprepare(t, p, uid))
	e.wantClean(t, p)
}

// Companions of another boot: a stale numa companion's Unprepare revokes
// nothing, also before the lender is set up; its Prepare again refused at
// the lease keeps it STALE; a stale fs companion's Unprepare removes the
// directory of its lease bind.
func TestPoolOtherBootCompanion(t *testing.T) {
	t.Run("numa", func(t *testing.T) {
		e := newPoolTestEnv(t)
		e.plug(0xc1ee0001)
		p := e.driver(t)
		hooks := &fakeHooks{}
		lender := newFakeLender()
		p.Lender().Set(lender, hooks)
		uid := "uid-cxl-lease-l1"
		noErr(t, prepare(t, p, numaCompanion("l1")).Err)
		e.k.Reboot()
		p = e.driver(t)
		if prep := e.preparation(uid); prep == nil || prep.State != state.PreparationStale {
			t.Fatalf("preparation %+v", prep)
		}
		p.Lender().Set(lender, &fakeHooks{lendingErr: errors.New("lease l1 is gone")})
		wantErr(t, prepare(t, p, numaCompanion("l1")).Err, "lease l1 is gone")
		if prep := e.preparation(uid); prep == nil || prep.State != state.PreparationStale {
			t.Fatalf("preparation %+v", prep)
		}
		p = e.driver(t)
		calls := lender.callLog()
		noErr(t, unprepare(t, p, uid))
		if lender.callLog() != calls {
			t.Fatalf("a stale companion revoked:\n%s", strings.TrimPrefix(lender.callLog(), calls))
		}
		e.wantClean(t, p)
	})
	t.Run("fs", func(t *testing.T) {
		e, p, hooks := newPoolLeaseEnv(t)
		target := filepath.Join(hooks.fsDir, "models")
		uid := "uid-cxl-lease-l1"
		noErr(t, prepare(t, p, fsCompanion("l1", "direct")).Err)
		e.k.Reboot()
		p = e.leaseDriver(t, hooks)
		if _, err := os.Stat(target); err != nil {
			t.Fatalf("bind directory after the reboot: %v", err)
		}
		noErr(t, unprepare(t, p, uid))
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("bind directory left: %v", err)
		}
		e.wantClean(t, p)
	})
}

// The lease bind of a companion of mode fs: a mount that is there already
// and is not the bind of its node mount is neither used nor unmounted, and
// the lease fails; a new bind without the flags or the root of the node
// mount is unmounted again; a bind of another lease is not used; a bind of
// the node mount there from a Prepare that a stop cut is used; another
// mount stacked on a bind stops its unbind.
func TestPoolLeaseBindChecks(t *testing.T) {
	e, p, hooks := newPoolLeaseEnv(t)
	direct := e.nodeMount(0xc1ae0001, "direct")
	target := filepath.Join(hooks.fsDir, "models")
	k := e.k.Kernel()

	// a foreign mount at the target
	noErr(t, os.MkdirAll(target, 0o755))
	noErr(t, k.Mount("tmpfs", target, "tmpfs", 0, ""))
	wantErr(t, prepare(t, p, fsCompanion("l3", "direct")).Err, target+" is a tmpfs mount of tmpfs, not of "+direct)
	if !strings.Contains(hooks.log(), "failed l3: ") {
		t.Fatalf("lend failure not told:\n%s", hooks.log())
	}
	if mi := e.mounted(target); mi == nil || mi.FsType != "tmpfs" {
		t.Fatalf("the foreign mount was used or unmounted: %+v", mi)
	}
	noErr(t, k.Unmount(target))
	e.wantClean(t, p)

	// a bind without the flags of the node mount, of another root
	for _, bind := range []struct {
		root  string
		flags []string
	}{{"", []string{"ro", "relatime"}}, {"/sub", nil}} {
		e.k.SetBind(bind.root, bind.flags)
		wantErr(t, prepare(t, p, fsCompanion("l4", "direct")).Err, "the bind of "+direct+" at "+target+" is not a read-only nosuid nodev erofs mount")
		if mi := e.mounted(target); mi != nil {
			t.Fatalf("the bad bind stays: %+v", mi)
		}
		e.k.SetBind("", nil)
		e.wantClean(t, p)
	}

	// the bind of another lease
	noErr(t, prepare(t, p, fsCompanion("l5", "direct")).Err)
	wantErr(t, prepare(t, p, fsCompanion("l6", "direct")).Err, target+" is the bind of another lease")
	noErr(t, unprepare(t, p, "uid-cxl-lease-l5"))

	// a bind of the node mount that is there already is used
	noErr(t, prepare(t, p, persistentClaim("d1", persistentData, fsConfig("direct", ""))).Err)
	noErr(t, os.MkdirAll(target, 0o755))
	noErr(t, k.Mount(direct, target, "", syscall.MS_BIND, ""))
	logs := captureKlog(t)
	noErr(t, prepare(t, p, fsCompanion("l7", "direct")).Err)
	if want := "lease l7: " + direct + " is bound at " + target + " already"; !strings.Contains(logs(), want) {
		t.Fatalf("no %q in\n%s", want, logs())
	}
	noErr(t, unprepare(t, p, "d1"))

	// another mount on the bind stops its unbind
	noErr(t, k.Mount("tmpfs", target, "tmpfs", 0, ""))
	wantErr(t, unprepare(t, p, "uid-cxl-lease-l7"), target+" is a tmpfs mount of tmpfs, not a lease bind")
	noErr(t, k.Unmount(target))
	noErr(t, unprepare(t, p, "uid-cxl-lease-l7"))
	e.wantClean(t, p)

	// the names of the lend
	for _, c := range []struct{ name, err string }{
		{"..", `lease l8: invalid name ".."`},
		{"", "lease l8: the device is of mode fs, the lease is not"},
	} {
		hooks.name = c.name
		wantErr(t, prepare(t, p, fsCompanion("l8", "direct")).Err, c.err)
	}
	hooks.name = "models"
	e.wantClean(t, p)
}

// The refusals of a Prepare of a persistent device: a memdev without
// persistent memory, a filesystem that does not mount, a superblock
// without DAX (and the loop device of a cached Prepare is detached).
func TestPoolPersistentErrors(t *testing.T) {
	t.Run("no persistent memory", func(t *testing.T) {
		e := newPoolTestEnv(t)
		memdev := e.plug(0xc1ae0001)
		p := e.driver(t)
		wantErr(t, prepare(t, p, persistentClaim("x", persistentData, fsConfig("direct", ""))).Err,
			"device 0xc1ae0001: "+memdev+" has no persistent memory")
		e.wantClean(t, p)
	})
	t.Run("mount", func(t *testing.T) {
		e := newPoolTestEnv(t)
		_, pmem := e.plugPersistent(0xc1ae0001, "erofs")
		p := e.driver(t)
		e.k.SetMountError(pmem, syscall.EINVAL, "")
		wantErr(t, prepare(t, p, persistentClaim("x", persistentData, fsConfig("direct", ""))).Err,
			pmem+" has no erofs filesystem: invalid argument")
		e.k.SetMountError(pmem, nil, "")
		e.k.SetMountError(e.loop(0), syscall.EINVAL, "")
		wantErr(t, prepare(t, p, persistentClaim("y", persistentData, fsConfig("cached", ""))).Err, "invalid argument")
		if ls := e.loops(); len(ls) != 0 {
			t.Fatalf("loop devices %+v left", ls)
		}
		e.wantClean(t, p)
	})
	t.Run("no DAX", func(t *testing.T) {
		e := newPoolTestEnv(t)
		_, pmem := e.plugPersistent(0xc1ae0001, "erofs")
		p := e.driver(t)
		e.k.SetSuperOpts(pmem, "ro")
		wantErr(t, prepare(t, p, persistentClaim("x", persistentData, fsConfig("direct", ""))).Err,
			"erofs on "+pmem+" was mounted without DAX")
		e.wantClean(t, p)
	})
}
