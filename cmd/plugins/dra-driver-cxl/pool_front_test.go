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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	resourceapi "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/klogtest"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
)

// numaCompanion returns the companion claim of the numa lease id on the
// pool device pooled0.
func numaCompanion(id string) *resourceapi.ResourceClaim {
	c := poolClaim("uid-"+companionName(id), companionName(id), "pooled0", exclusiveData)
	c.ObjectMeta = companionClaim(id).ObjectMeta
	return c
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
	if node < 0 || !slices.Equal(poolNumaNodes(p), []int{node}) || p.ClaimInfo(uid) != nil {
		t.Fatalf("numa nodes %v (region on %d), results %v", poolNumaNodes(p), node, p.ClaimInfo(uid))
	}
	p.Lender().Set(newFakeLender(), hooks)
	noErr(t, unprepare(t, p, uid))
	if poolNumaNodes(p) != nil {
		t.Fatalf("numa nodes %v", poolNumaNodes(p))
	}
	e.wantClean(t, p)
}

// A companion claim of mode fs whose node mount and lease bind a new mount
// namespace lost: its Prepare again fails, without telling the broker,
// while the device cannot be mounted, and then mounts the node mount and
// binds it again before the broker hears of the companion.
func TestPoolRemountCompanion(t *testing.T) {
	e, p, hooks := newPoolLeaseEnv(t)
	direct := e.nodeMount(0xc1ae0001, "direct")
	target := filepath.Join(hooks.fsDir, "models")
	uid := "uid-cxl-lease-l1"
	noErr(t, prepare(t, p, fsCompanion("l1", "direct")).Err)
	k := e.k.Kernel()
	noErr(t, k.Unmount(target))
	noErr(t, k.Unmount(direct))
	e.k.SetMountError(e.pmem, syscall.EIO, "")
	p = e.leaseDriver(t, hooks)
	if prep := e.preparation(uid); prep.State != state.PreparationUnrestored {
		t.Fatalf("preparation %+v", prep)
	}
	calls := hooks.log()
	wantErr(t, prepare(t, p, fsCompanion("l1", "direct")).Err, "its node mount "+direct+" is not mounted and cannot be mounted again")
	if log := hooks.log(); log != calls {
		t.Fatalf("the broker heard of an unrestored companion:\n%s", strings.TrimPrefix(log, calls))
	}
	e.k.SetMountError(e.pmem, nil, "")
	bound := false
	hooks.onPrepared = func(string) {
		mi, _ := e.mountedErr(target)
		bound = mi != nil
	}
	noErr(t, prepare(t, p, fsCompanion("l1", "direct")).Err)
	if prep := e.preparation(uid); prep.State != state.PreparationPrepared || !bound {
		t.Fatalf("preparation %+v, bound before the broker heard: %v", prep, bound)
	}
	if log := strings.TrimPrefix(hooks.log(), calls); log != "\nlending l1 cxl-lease-l1\nprepared l1" {
		t.Fatalf("hooks:\n%s", log)
	}
	noErr(t, unprepare(t, p, uid))
	e.wantClean(t, p)
}

// A companion claim refused after the gate of the broker: the lease fails
// at once when the MemoryConfig of the claim does not fit its device, not
// while the pool has not written the status data of its device yet.
func TestPoolCompanionRefused(t *testing.T) {
	e := newPoolTestEnv(t)
	p := e.driver(t)
	hooks := &fakeHooks{}
	p.Lender().Set(newFakeLender(), hooks)
	c := numaCompanion("l1")
	c.Status.Devices = nil
	wantErr(t, prepare(t, p, c).Err, "not attached by the pool controller yet")
	c = persistentClaim("uid-"+companionName("l2"), exclusiveData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs"}}`)
	c.ObjectMeta = companionClaim("l2").ObjectMeta
	mismatch := "device llm0 serial 0xc1ee0001: MemoryConfig: device.mode fs needs a persistent device"
	wantErr(t, prepare(t, p, c).Err, mismatch)
	if log := hooks.log(); log != "lending l1 cxl-lease-l1\nlending l2 cxl-lease-l2\nfailed l2: "+mismatch {
		t.Fatalf("hooks:\n%s", log)
	}
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
	logs := klogtest.Capture(t, 3)
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
