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

package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// rawRegion creates a ram region on the memdev through the kernel, as
// another tool would, and returns it.
func rawRegion(t *testing.T, v *env, memdev string) string {
	t.Helper()
	k := v.f.Kernel()
	d, err := k.RootDecoder(memdev, kernel.RegionRAM)
	if err != nil {
		t.Fatal(err)
	}
	name, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: memdev, Decoder: d, Type: kernel.RegionRAM})
	if err != nil {
		t.Fatal(err)
	}
	return name
}

// regionAboveNext makes a ram region on the memdev right after the next cxl
// create-region, above the region that it created.
func regionAboveNext(t *testing.T, v *env, memdev string) {
	v.f.After("cxl create-region", func() {
		v.f.After("cxl create-region", func() {})
		rawRegion(t, v, memdev)
	})
}

// dropRaw destroys a region that rawRegion made.
func dropRaw(t *testing.T, v *env, region string) {
	t.Helper()
	if err := v.f.Kernel().ReleaseRegion(context.Background(), region); err != nil {
		t.Fatal(err)
	}
}

// wantLog fails the test unless the log has every line of want.
func wantLog(t *testing.T, logs string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(logs, w) {
			t.Errorf("no %q in the log:\n%s", w, logs)
		}
	}
}

// wantRegion fails the test unless the record of the region is in the
// state, nil for none.
func wantRegion(t *testing.T, v *env, region string, want state.RegionState) *state.Region {
	t.Helper()
	reg := v.records().Region(state.RegionRef(region))
	switch {
	case want == "" && reg != nil:
		t.Fatalf("%s: %+v", region, reg)
	case want != "" && (reg == nil || reg.State != want):
		t.Fatalf("%s: %+v, want %s", region, reg, want)
	}
	return reg
}

// wantPreparation fails the test unless the preparation of the claim uid of
// the driver is in the state, "" for none.
func wantPreparation(t *testing.T, v *env, driver, uid string, want state.PreparationState) {
	t.Helper()
	p := v.records().Preparation(driver, uid)
	switch {
	case want == "" && p != nil:
		t.Fatalf("preparation %s: %+v", uid, p)
	case want != "" && (p == nil || p.State != want):
		t.Fatalf("preparation %s: %+v, want %s", uid, p, want)
	}
}

// The release policy of a local sliced memdev: its Unprepare destroys the
// region also below a newer region of another memdev (a hole); a rollback
// and a recovery keep it below one (KEPT, the grant JOURNALED, the
// preparation KEPT).
func TestLocalPolicySliced(t *testing.T) {
	t.Run("unprepare destroys below a newer region", func(t *testing.T) {
		v := newEnv(t, stackSpecs...)
		v.mustPrepare(localDriver, "l", sliceReq("l", 0, state.ModeDax, 256*mib))
		v.mustPrepare(poolDriver, "b", poolReq("b", 0, serialB, state.ModeDax, state.KindExclusive))
		wantStack(t, v, serialL, serialB)
		v.mustUnprepare(localDriver, "l")
		wantStack(t, v, 0, serialB)
		if m := v.records().Memdev(serialL); m != nil {
			t.Fatalf("memdev %+v", m)
		}
		v.mustUnprepare(poolDriver, "b")
		v.clean("unprepared")
	})
	t.Run("rollback keeps below a newer region", func(t *testing.T) {
		v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib}, fake.MemdevSpec{Serial: serialB})
		regionAboveNext(t, v, "mem1")
		v.f.FailWrite("bus/dax/devices/dax0.0/size", errBusy)
		logs := captureKlog(t)
		if err := v.prepare(localDriver, "k", sliceReq("k", 0, state.ModeDax, 256*mib)); err == nil {
			t.Fatal("the Prepare succeeded")
		}
		v.check("rolled back")
		reg := wantRegion(t, v, "region0", state.RegionKept)
		if reg.SetUp || reg.Zeroed {
			t.Fatalf("kept region %+v", reg)
		}
		if g := v.grant("k", 0); g.State != state.GrantJournaled || g.Intent.Region != "region0" || g.Got.Region != "" {
			t.Fatalf("grant %+v", g)
		}
		wantPreparation(t, v, localDriver, "k", state.PreparationKept)
		wantLog(t, logs(), "local: memdev mem0 (serial 0x11): keeping region0 for claims [k], whose Prepare did not finish: region1 lie above it")
		dropRaw(t, v, "region1")
		v.mustPrepare(localDriver, "k", sliceReq("k", 0, state.ModeDax, 256*mib))
		if g := v.grant("k", 0); g.Got.Region != "region0" {
			t.Fatalf("grant %+v", g.Got)
		}
		v.mustUnprepare(localDriver, "k")
		v.clean("unprepared")
	})
	t.Run("recovery keeps below a newer region", func(t *testing.T) {
		v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib}, fake.MemdevSpec{Serial: serialB})
		// cut after the commit of the part, before the claim is prepared
		cutWhenRealised(v, "n")
		if !v.cut(func() { _ = v.prepare(localDriver, "n", sliceReq("n", 0, state.ModeDax, 256*mib)) }) {
			t.Fatal("not cut")
		}
		above := rawRegion(t, v, "mem1")
		out := v.restart()
		if !slices.Equal(out.Kept, []state.GrantRef{{Claim: "n"}}) || len(out.Released) > 0 {
			t.Fatalf("recovered %+v", out)
		}
		wantRegion(t, v, "region0", state.RegionKept)
		if g := v.grant("n", 0); g.State != state.GrantJournaled || g.Intent.Region != "region0" || g.Got.Dax != "" {
			t.Fatalf("grant %+v", g)
		}
		if size := v.f.DaxSize("dax0.0"); size != 0 {
			t.Fatalf("the part of the claim is left: dax0.0 of %d bytes", size)
		}
		wantPreparation(t, v, localDriver, "n", state.PreparationKept)
		dropRaw(t, v, above)
		v.mustPrepare(localDriver, "n", sliceReq("n", 0, state.ModeDax, 256*mib))
		v.mustUnprepare(localDriver, "n")
		v.clean("unprepared")
	})
}

// The release policy of a local memdev configured shared whose region is
// established: its Unprepare, a rollback and a recovery keep the region for
// the idle memdev (IDLE_KEPT), the Whole device stays, and the next grant
// does not zero it again.
func TestLocalPolicySharedConfigured(t *testing.T) {
	shared := func(v *env, o *Options) { o.Shared = func(state.Serial) bool { return true } }
	newShared := func(t *testing.T) *env {
		v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib}, fake.MemdevSpec{Serial: serialA, HostBridge: 24})
		v.configure(func(o *Options) { shared(v, o) })
		return v
	}
	idleKept := func(t *testing.T, v *env) {
		t.Helper()
		if m := v.records().Memdev(serialL); m == nil || m.State != state.MemdevIdleKept {
			t.Fatalf("memdev %+v", m)
		}
		reg := wantRegion(t, v, "region0", state.RegionOwned)
		if d := reg.WholeDevice(); d == nil || d.Name != "dax0.0" || d.State != state.DaxDeviceDax || len(d.Users) > 0 || !reg.Zeroed {
			t.Fatalf("region %+v", reg)
		}
		if v.f.DaxDriver("dax0.0") != kernel.DriverDeviceDax {
			t.Fatalf("dax0.0 is bound to %q", v.f.DaxDriver("dax0.0"))
		}
	}
	notZeroedAgain := func(t *testing.T, v *env) {
		t.Helper()
		v.mustPrepare(localDriver, "s9", sharedReq("s9"))
		if z := v.f.Zeroed(); len(z) != 1 {
			t.Fatalf("zeroed %v", z)
		}
		v.mustUnprepare(localDriver, "s9")
		releaseIdleShared(v)
		v.clean("released")
	}
	t.Run("unprepare", func(t *testing.T) {
		v := newShared(t)
		v.mustPrepare(localDriver, "s1", sharedReq("s1"))
		logs := captureKlog(t)
		v.mustUnprepare(localDriver, "s1")
		idleKept(t, v)
		wantLog(t, logs(), "local: memdev mem0 (serial 0x11): claim s1: released shared dax0.0, claims left []",
			"local: memdev mem0 (serial 0x11): keeping region0 and dax0.0 of the idle shared device")
		notZeroedAgain(t, v)
	})
	t.Run("rollback", func(t *testing.T) {
		v := newShared(t)
		v.mustPrepare(localDriver, "s1", sharedReq("s1"))
		v.mustUnprepare(localDriver, "s1")
		v.f.FailCommand("cxl create-region", errors.New("cxl region: cmd_create_region: failed"))
		if err := v.prepare(localDriver, "s2", sharedReq("s2"), poolReq("s2", 1, serialA, state.ModeDax, state.KindExclusive)); err == nil {
			t.Fatal("the Prepare succeeded")
		}
		wantPreparation(t, v, localDriver, "s2", "")
		v.check("rolled back")
		idleKept(t, v)
		notZeroedAgain(t, v)
	})
	t.Run("recovery", func(t *testing.T) {
		v := newShared(t)
		v.mustPrepare(localDriver, "s1", sharedReq("s1"))
		cutWhenRealised(v, "s2")
		if !v.cut(func() { _ = v.prepare(localDriver, "s2", sharedReq("s2")) }) {
			t.Fatal("not cut")
		}
		logs := captureKlog(t)
		out := v.restart()
		if !slices.Equal(out.Released, []state.GrantRef{{Claim: "s2"}}) || len(out.Kept) > 0 {
			t.Fatalf("recovered %+v", out)
		}
		wantLog(t, logs(), "local: memdev mem0 (serial 0x11): claim s2 of the shared device is not prepared, dropping it",
			"local: memdev mem0 (serial 0x11): keeping shared region0 and dax0.0, claims [s1]")
		v.mustUnprepare(localDriver, "s1")
		idleKept(t, v)
		// the recovery of the idle memdev keeps it too
		v.restart()
		idleKept(t, v)
		notZeroedAgain(t, v)
	})
}

// A new region of a local shared memdev whose set-up or zeroing failed is
// released by the rollback in order (KEPT for the claim below a newer
// region of another memdev); the next Prepare zeroes it again.
func TestLocalPolicySharedNew(t *testing.T) {
	zeroErr := errors.New("zeroing failed")
	t.Run("released", func(t *testing.T) {
		v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
		v.configure(func(o *Options) { o.Shared = func(state.Serial) bool { return true } })
		v.f.ZeroErr = zeroErr
		err := v.prepare(localDriver, "s1", sharedReq("s1"))
		if err == nil || !strings.Contains(err.Error(), "memdev mem0 (serial 0x11): zeroing new shared dax0.0: ") {
			t.Fatalf("error %v", err)
		}
		v.check("rolled back")
		v.clean("rolled back")
		v.f.ZeroErr = nil
		v.mustPrepare(localDriver, "s1", sharedReq("s1"))
		if z := v.f.Zeroed(); len(z) != 1 {
			t.Fatalf("zeroed %v", z)
		}
		v.mustUnprepare(localDriver, "s1")
		releaseIdleShared(v)
		v.clean("released")
	})
	t.Run("kept below a newer region", func(t *testing.T) {
		v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib}, fake.MemdevSpec{Serial: serialB})
		v.configure(func(o *Options) { o.Shared = func(state.Serial) bool { return true } })
		regionAboveNext(t, v, "mem1")
		v.f.ZeroErr = zeroErr
		if err := v.prepare(localDriver, "s1", sharedReq("s1")); err == nil {
			t.Fatal("the Prepare succeeded")
		}
		v.check("rolled back")
		reg := wantRegion(t, v, "region0", state.RegionKept)
		if reg.Zeroed || reg.SetUp {
			t.Fatalf("region %+v", reg)
		}
		if g := v.grant("s1", 0); g.State != state.GrantJournaled || g.Intent.Region != "region0" {
			t.Fatalf("grant %+v", g)
		}
		wantPreparation(t, v, localDriver, "s1", state.PreparationKept)
		v.f.ZeroErr = nil
		v.mustPrepare(localDriver, "s1", sharedReq("s1"))
		if z := v.f.Zeroed(); len(z) != 1 {
			t.Fatalf("zeroed %v", z)
		}
		dropRaw(t, v, "region1")
		v.mustUnprepare(localDriver, "s1")
		releaseIdleShared(v)
		v.clean("released")
	})
	t.Run("set-up failed", func(t *testing.T) {
		v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
		v.configure(func(o *Options) { o.Shared = func(state.Serial) bool { return true } })
		v.f.FailWrite("bus/dax/drivers/kmem/unbind", errBusy)
		if err := v.prepare(localDriver, "s1", sharedReq("s1")); err == nil {
			t.Fatal("the Prepare succeeded")
		}
		v.check("rolled back")
		v.clean("rolled back")
	})
	t.Run("cut after its zeroing", func(t *testing.T) {
		v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
		v.configure(func(o *Options) { o.Shared = func(state.Serial) bool { return true } })
		v.cutZeroing(true)
		if !v.cut(func() { _ = v.prepare(localDriver, "s1", sharedReq("s1")) }) {
			t.Fatal("not cut")
		}
		out := v.restart()
		if !slices.Equal(out.Released, []state.GrantRef{{Claim: "s1"}}) {
			t.Fatalf("recovered %+v", out)
		}
		wantRegion(t, v, "region0", "")
		v.mustPrepare(localDriver, "s1", sharedReq("s1"))
		if z := v.f.Zeroed(); len(z) != 2 {
			t.Fatalf("zeroed %v", z)
		}
		v.mustUnprepare(localDriver, "s1")
		releaseIdleShared(v)
		v.clean("released")
	})
}

// A local memdev used shared that is not configured shared any more: the
// Unprepare of its last claim and the recovery destroy its region, also
// below a newer region of another memdev.
func TestLocalPolicyUnshared(t *testing.T) {
	t.Run("unprepare", func(t *testing.T) {
		v := newEnv(t, stackSpecs...)
		shared := true
		v.e.opts.Shared = func(state.Serial) bool { return shared }
		v.mustPrepare(localDriver, "s1", sharedReq("s1"))
		v.mustPrepare(poolDriver, "b", poolReq("b", 0, serialB, state.ModeDax, state.KindExclusive))
		shared = false
		v.mustUnprepare(localDriver, "s1")
		wantStack(t, v, 0, serialB)
		v.mustUnprepare(poolDriver, "b")
		v.clean("unprepared")
	})
	t.Run("recovery", func(t *testing.T) {
		v := newEnv(t, stackSpecs...)
		v.configure(func(o *Options) { o.Shared = func(state.Serial) bool { return true } })
		v.mustPrepare(localDriver, "s1", sharedReq("s1"))
		v.mustUnprepare(localDriver, "s1")
		v.mustPrepare(poolDriver, "b", poolReq("b", 0, serialB, state.ModeDax, state.KindExclusive))
		v.configure(nil)
		cutWhenRealised(v, "s2")
		if !v.cut(func() { _ = v.prepare(localDriver, "s2", sharedReq("s2")) }) {
			t.Fatal("not cut")
		}
		out := v.restart()
		if !slices.Equal(out.Released, []state.GrantRef{{Claim: "s2"}}) {
			t.Fatalf("recovered %+v", out)
		}
		wantStack(t, v, 0, serialB)
		if m := v.records().Memdev(serialL); m != nil {
			t.Fatalf("memdev %+v", m)
		}
		v.mustUnprepare(poolDriver, "b")
		finish(t, v, "finished")
	})
}

// The release policy of a local persistent memdev: its Unprepare releases
// the region in order, kept for the idle memdev below a newer region of
// another memdev; a rollback keeps it there for the claim (KEPT); a
// recovery releases it in order, kept for the idle memdev.
func TestLocalPolicyPersistent(t *testing.T) {
	newPmem := func(t *testing.T) *env {
		v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib}, fake.MemdevSpec{Serial: serialB})
		v.formatPmem("mem0", "ext4")
		return v
	}
	idle := func(t *testing.T, v *env) {
		t.Helper()
		if m := v.records().Memdev(serialP); m == nil || m.State != state.MemdevIdleKept || len(m.Grants) > 0 {
			t.Fatalf("memdev %+v", m)
		}
		wantRegion(t, v, "region0", state.RegionOwned)
	}
	t.Run("unprepare", func(t *testing.T) {
		v := newPmem(t)
		v.mustPrepare(localDriver, "w", localPmemReq("w", 0, state.ModeFs, false, ""))
		above := rawRegion(t, v, "mem1")
		logs := captureKlog(t)
		v.mustUnprepare(localDriver, "w")
		idle(t, v)
		wantLog(t, logs(), "local: memdev mem0 (serial 0x91): keeping region0 of the idle persistent device: "+above+" lie above it")
		dropRaw(t, v, above)
		// the start releases the idle region in order
		v.restart()
		wantRegion(t, v, "region0", "")
		v.clean("released")
	})
	t.Run("rollback", func(t *testing.T) {
		v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib}, fake.MemdevSpec{Serial: serialB})
		regionAboveNext(t, v, "mem1")
		// a reader of a device that no writer formatted fails
		if err := v.prepare(localDriver, "r", localPmemReq("r", 0, state.ModeFs, true, "")); err == nil {
			t.Fatal("the Prepare succeeded")
		}
		v.check("rolled back")
		wantRegion(t, v, "region0", state.RegionKept)
		if g := v.grant("r", 0); g.State != state.GrantJournaled || g.Intent.Region != "region0" {
			t.Fatalf("grant %+v", g)
		}
		wantPreparation(t, v, localDriver, "r", state.PreparationKept)
		dropRaw(t, v, "region1")
		v.mustUnprepare(localDriver, "r")
		v.clean("unprepared")
	})
	t.Run("recovery", func(t *testing.T) {
		v := newPmem(t)
		cutWhenRealised(v, "w")
		if !v.cut(func() { _ = v.prepare(localDriver, "w", localPmemReq("w", 0, state.ModeFs, false, "")) }) {
			t.Fatal("not cut")
		}
		above := rawRegion(t, v, "mem1")
		out := v.restart()
		if !slices.Equal(out.Released, []state.GrantRef{{Claim: "w"}}) || len(out.Kept) > 0 {
			t.Fatalf("recovered %+v", out)
		}
		idle(t, v)
		wantPreparation(t, v, localDriver, "w", state.PreparationPreparing)
		dropRaw(t, v, above)
		v.mustUnprepare(localDriver, "w")
		idle(t, v)
		// the next start releases the idle region
		v.restart()
		v.clean("released")
	})
}

// The release policy of the pool devices is not changed by the local
// cells: a rollback destroys the region also below a newer region of
// another memdev.
func TestPoolPolicyRollbackDestroysBelow(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA}, fake.MemdevSpec{Serial: serialB})
	port := v.f.Kernel().Memdev(serialA).Ports[0]
	regionAboveNext(t, v, "mem1")
	v.f.FailWrite("bus/dax/drivers/kmem/unbind", errBusy)
	if err := v.prepare(poolDriver, "a", poolReq("a", 0, serialA, state.ModeDax, state.KindExclusive)); err == nil {
		t.Fatal("the Prepare succeeded")
	}
	v.check("rolled back")
	if rs := v.f.Kernel().Regions("mem0"); len(rs) > 0 {
		t.Fatalf("regions %v left", rs)
	}
	wantPreparation(t, v, poolDriver, "a", "")
	if got := v.f.Stack(port); !slices.Equal(got, []string{"", "region1"}) {
		t.Fatalf("stack %q", got)
	}
	dropRaw(t, v, "region1")
	v.clean("rolled back")
}
