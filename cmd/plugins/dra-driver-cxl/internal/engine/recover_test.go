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
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// The rows of the recovery table: a PREPARED claim whose grants verify is
// left as it is.
func TestRecoverPreparedVerifies(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.f.Plug(fake.MemdevSpec{Serial: serialA})
	v.mustPrepare(poolDriver, "n", poolReq("n", 0, serialA, state.ModeNUMA, state.KindExclusive))
	v.mustPrepare(poolDriver, "w", fsGrant("w", false, ""))
	before := v.f.Commands()
	out := v.restart()
	v.check("restarted")
	if len(out.Released)+len(out.Kept)+len(out.Unrestored) > 0 || v.f.CommandsSince(before) != "" {
		t.Fatalf("recovered %+v, commands %q", out, v.f.CommandsSince(before))
	}
	// the node mount is mounted again when it is gone (a new mount namespace)
	direct := v.grant("w", 0).Got.MountPath
	if err := v.f.Kernel().Unmount(direct); err != nil {
		t.Fatal(err)
	}
	if out := v.restart(); len(out.Unrestored) > 0 {
		t.Fatalf("recovered %+v", out)
	}
	if mi, _ := v.f.Kernel().Mounted(direct); mi == nil {
		t.Fatal("not mounted again")
	}
	v.check("mounted again")
	v.mustUnprepare(poolDriver, "w")
	v.mustUnprepare(poolDriver, "n")
}

// A PREPARED claim whose block device is another one now: its grant is
// REALISED_UNRESTORED and its preparation PREPARED_UNRESTORED; a Prepare
// again fails while it does not verify, its Unprepare releases it.
func TestRecoverUnrestored(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.mustPrepare(poolDriver, "w", fsGrant("w", false, ""))
	direct := v.grant("w", 0).Got.MountPath
	if err := v.f.Kernel().Unmount(direct); err != nil {
		t.Fatal(err)
	}
	v.f.RenamePmem("region0", "pmem3", "259:9")
	out := v.restart()
	if !slices.Equal(out.Unrestored, []state.GrantRef{{Claim: "w"}}) {
		t.Fatalf("recovered %+v", out)
	}
	if g := v.grant("w", 0); g.State != state.GrantUnrestored {
		t.Fatalf("grant %s", g.State)
	}
	if p := v.records().Preparation(poolDriver, "w"); p.State != state.PreparationUnrestored {
		t.Fatalf("preparation %s", p.State)
	}
	if m := v.records().Region("region0").Mount(state.AccessDirect); m.State != state.MountUnrestored {
		t.Fatalf("mount %+v", m)
	}
	v.check("unrestored")
	if _, err := v.e.PrepareGrants(context.Background(), []GrantRequest{fsGrant("w", false, "")}); err == nil ||
		!strings.Contains(err.Error(), "cannot be mounted again") {
		t.Fatalf("Prepare again: %v", err)
	}
	v.mustUnprepare(poolDriver, "w")
	v.clean("unprepared")
}

// A PREPARED claim cut in its Unprepare: the grant is RELEASING at the
// start, nothing is released then, kubelet's Unprepare retry finishes it.
func TestRecoverCutUnprepare(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	v.mustPrepare(poolDriver, "c", poolReq("c", 0, serialA, state.ModeNUMA, state.KindExclusive))
	v.cutAfter(1)
	if !v.cut(func() { _ = v.unprepare(poolDriver, "c") }) {
		t.Fatal("not cut")
	}
	out := v.restart()
	if len(out.Released)+len(out.Kept) > 0 {
		t.Fatalf("recovered %+v", out)
	}
	if g := v.grant("c", 0); g.State != state.GrantReleasing {
		t.Fatalf("grant %s", g.State)
	}
	v.mustUnprepare(poolDriver, "c")
	v.clean("unprepared")
}

// A PREPARING claim cut after its region was made: released at the start,
// the preparation stays PREPARING for kubelet's retry, which prepares anew.
func TestRecoverCutPrepare(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	v.f.After("cxl create-region", func() { panic(fake.ErrCut) })
	if !v.cut(func() { _ = v.prepare(poolDriver, "c", poolReq("c", 0, serialA, state.ModeNUMA, state.KindExclusive)) }) {
		t.Fatal("not cut")
	}
	v.f.After("cxl create-region", func() {})
	out := v.restart()
	if !slices.Equal(out.Released, []state.GrantRef{{Claim: "c"}}) {
		t.Fatalf("recovered %+v", out)
	}
	if p := v.records().Preparation(poolDriver, "c"); p == nil || p.State != state.PreparationPreparing {
		t.Fatalf("preparation %+v", p)
	}
	v.check("recovered")
	v.mustPrepare(poolDriver, "c", poolReq("c", 0, serialA, state.ModeNUMA, state.KindExclusive))
	v.mustUnprepare(poolDriver, "c")
	v.clean("unprepared")
}

// A cut pool Prepare whose region lies below a region of another memdev is
// kept at the start (KEPT), its Unprepare releases it.
func TestRecoverCutPrepareBelow(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA}, fake.MemdevSpec{Serial: serialB})
	v.cutAfter(4)
	if !v.cut(func() { _ = v.prepare(poolDriver, "c", poolReq("c", 0, serialA, state.ModeDax, state.KindExclusive)) }) {
		t.Fatal("not cut")
	}
	k := v.f.Kernel()
	d, _ := k.RootDecoder("mem1", kernel.RegionRAM)
	if _, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: "mem1", Decoder: d, Type: kernel.RegionRAM}); err != nil {
		t.Fatal(err)
	}
	out := v.restart()
	if !slices.Equal(out.Kept, []state.GrantRef{{Claim: "c"}}) {
		t.Fatalf("recovered %+v", out)
	}
	if p := v.records().Preparation(poolDriver, "c"); p.State != state.PreparationKept {
		t.Fatalf("preparation %s", p.State)
	}
	if g := v.grant("c", 0); g.State != state.GrantJournaled {
		t.Fatalf("grant %s", g.State)
	}
	v.mustUnprepare(poolDriver, "c")
	if r := v.records(); len(r.Grants)+len(r.Regions) > 0 {
		t.Fatalf("records %+v", r)
	}
}

// A PREPARING claim with a REALISED grant (cut before the claim was
// PREPARED) is released at the start, a companion of mode numa kept.
func TestRecoverRealisedOfPreparing(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA}, fake.MemdevSpec{Serial: serialC, HostBridge: 24})
	if _, err := v.e.PrepareGrants(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	companion := poolReq("comp", 0, serialC, state.ModeNUMA, state.KindExclusive)
	companion.Lend = &state.GrantLend{Lease: "0123abcd", Container: "c"}
	for _, c := range []struct {
		uid string
		req GrantRequest
	}{{"plain", poolReq("plain", 0, serialA, state.ModeNUMA, state.KindExclusive)}, {"comp", companion}} {
		if err := v.st.Commit(context.Background(), store.Durable, func(doc *store.Document) error {
			doc.Preparations = append(doc.Preparations, state.Preparation{UID: c.uid, Driver: poolDriver, BootID: v.f.BootID(),
				State: state.PreparationPreparing, Results: []state.Result{grantResult(c.uid, 0)}})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := v.e.PrepareGrants(context.Background(), []GrantRequest{c.req}); err != nil {
			t.Fatal(err)
		}
	}
	out := v.restart()
	if !slices.Equal(out.Released, []state.GrantRef{{Claim: "plain"}}) || !slices.Equal(out.Companions, []state.GrantRef{{Claim: "comp"}}) {
		t.Fatalf("recovered %+v", out)
	}
	if got := v.e.RecoverCompanions(); !slices.Equal(got, out.Companions) {
		t.Fatalf("phase 2 %v", got)
	}
	if g := v.grant("comp", 0); g.State != state.GrantRealised {
		t.Fatalf("companion %s", g.State)
	}
	v.mustUnprepare(poolDriver, "comp")
	v.mustUnprepare(poolDriver, "plain")
	v.clean("unprepared")
}

// An UNPREPARING claim at the start: nothing is done, no remount; its
// Unprepare retry finishes.
func TestRecoverUnpreparing(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.mustPrepare(poolDriver, "w", fsGrant("w", false, ""))
	v.cutAfter(1)
	if !v.cut(func() { _ = v.unprepare(poolDriver, "w") }) {
		t.Fatal("not cut")
	}
	direct := v.grant("w", 0).Got.MountPath
	if err := v.f.Kernel().Unmount(direct); err != nil {
		t.Fatal(err)
	}
	if p := v.records().Preparation(poolDriver, "w"); p.State != state.PreparationUnpreparing {
		t.Fatalf("preparation %s", p.State)
	}
	before := v.f.MountCalls("")
	v.restart()
	if after := v.f.MountCalls(""); len(after) != len(before) {
		t.Fatalf("mount calls at the start %v", after[len(before):])
	}
	v.mustUnprepare(poolDriver, "w")
	v.clean("unprepared")
}

// A claim prepared in another boot: PREPARED_STALE by the store, nothing
// released at the start; its Unprepare disables the pool memdev; a Prepare
// again of another prepares anew.
func TestRecoverStale(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA}, fake.MemdevSpec{Serial: serialB})
	v.mustPrepare(poolDriver, "a", poolReq("a", 0, serialA, state.ModeDax, state.KindExclusive))
	v.mustPrepare(poolDriver, "b", poolReq("b", 0, serialB, state.ModeNUMA, state.KindExclusive))
	v.f.Reboot()
	before := v.f.Commands()
	out := v.restart()
	if len(out.Released)+len(out.Kept) > 0 || v.f.CommandsSince(before) != "" {
		t.Fatalf("recovered %+v, commands %q", out, v.f.CommandsSince(before))
	}
	for _, uid := range []string{"a", "b"} {
		if p := v.records().Preparation(poolDriver, uid); p.State != state.PreparationStale {
			t.Fatalf("preparation %s %s", uid, p.State)
		}
	}
	v.check("stale")
	v.mustUnprepare(poolDriver, "a")
	if !strings.Contains(v.f.CommandsSince(before), "disable-memdev mem0") {
		t.Fatalf("commands %q", v.f.CommandsSince(before))
	}
	v.mustPrepare(poolDriver, "b", poolReq("b", 0, serialB, state.ModeNUMA, state.KindExclusive))
	if g := v.grant("b", 0); g.State != state.GrantRealised || g.Got.Region == "" {
		t.Fatalf("prepared anew %+v", g)
	}
	v.mustUnprepare(poolDriver, "b")
	v.clean("unprepared")
}

// A local sliced claim whose rollback finds a region of another memdev
// above its region keeps it (KEPT); its Prepare again reuses it, its
// Unprepare destroys it.
func TestRecoverKept(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib}, fake.MemdevSpec{Serial: serialB})
	v.f.After("cxl create-region", func() {
		v.f.After("cxl create-region", func() {})
		k := v.f.Kernel()
		d, _ := k.RootDecoder("mem1", kernel.RegionRAM)
		go func() {}()
		if _, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: "mem1", Decoder: d, Type: kernel.RegionRAM}); err != nil {
			t.Error(err)
		}
	})
	v.f.FailWrite("bus/dax/devices/dax0.0/size", errBusy)
	if err := v.prepare(localDriver, "k", localReq("k", 0, serialL, state.ModeDax, state.KindExclusive, 256*mib)); err == nil {
		t.Fatal("the Prepare succeeded")
	}
	if p := v.records().Preparation(localDriver, "k"); p == nil || p.State != state.PreparationKept {
		t.Fatalf("preparation %+v", p)
	}
	if reg := v.records().Region("region0"); reg == nil || reg.State != state.RegionKept {
		t.Fatalf("region %+v", reg)
	}
	v.mustPrepare(localDriver, "k", localReq("k", 0, serialL, state.ModeDax, state.KindExclusive, 256*mib))
	if g := v.grant("k", 0); g.Got.Region != "region0" {
		t.Fatalf("grant %+v", g.Got)
	}
	v.mustUnprepare(localDriver, "k")
	if reg := v.records().Region("region0"); reg != nil {
		t.Fatalf("region %+v", reg)
	}
}

// A memdev absent at the start: its records are kept (GONE) for kubelet's
// Unprepare, which deletes its hollow region; also those of a cut Prepare.
func TestRecoverMemdevGone(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA}, fake.MemdevSpec{Serial: serialB})
	v.mustPrepare(poolDriver, "c", poolReq("c", 0, serialA, state.ModeDax, state.KindExclusive))
	v.f.CutAfter("cxl create-region")
	if !v.cut(func() {
		_ = v.prepare(poolDriver, "cut", poolReq("cut", 0, serialB, state.ModeDax, state.KindExclusive))
	}) {
		t.Fatal("not cut")
	}
	v.f.Unplug(serialA)
	v.f.Unplug(serialB)
	out := v.restart()
	if !slices.Equal(out.Absent, []state.GrantRef{{Claim: "cut"}}) || len(out.Released) > 0 {
		t.Fatalf("recovered %+v", out)
	}
	for _, serial := range []uint64{serialA, serialB} {
		if m := v.records().Memdev(state.Serial(serial)); m == nil || m.State != state.MemdevGone || len(m.Grants) != 1 {
			t.Fatalf("memdev %+v", m)
		}
	}
	if p := v.records().Preparation(poolDriver, "cut"); p == nil || p.State != state.PreparationPreparing {
		t.Fatalf("preparation %+v", p)
	}
	v.mustUnprepare(poolDriver, "c")
	v.mustUnprepare(poolDriver, "cut")
	v.clean("unprepared")
}

// A memdev that is back at a later start: its records ACTIVE again.
func TestRecoverMemdevBack(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	v.mustPrepare(poolDriver, "c", poolReq("c", 0, serialA, state.ModeDax, state.KindExclusive))
	v.f.Unplug(serialA)
	v.restart()
	if m := v.records().Memdev(serialA); m.State != state.MemdevGone {
		t.Fatalf("memdev %+v", m)
	}
	v.f.Plug(fake.MemdevSpec{Serial: serialA})
	v.restart()
	if m := v.records().Memdev(serialA); m.State != state.MemdevActive {
		t.Fatalf("memdev %+v", m)
	}
	v.mustUnprepare(poolDriver, "c")
}

// A noted region that a cut cxl create-region left hollow: HOLLOW_OWNED at
// the start, deleted then (its memory is offline).
func TestRecoverHollowNoted(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	v.f.CutBefore("cxl create-region")
	if !v.cut(func() { _ = v.prepare(poolDriver, "c", poolReq("c", 0, serialA, state.ModeDax, state.KindExclusive)) }) {
		t.Fatal("not cut")
	}
	reg := v.records().Regions[0]
	if reg.State != state.RegionNoted {
		t.Fatalf("region %+v", reg)
	}
	if name := v.f.HollowRegion(reg.Decoder, 256*mib); name != reg.NotedName {
		t.Fatalf("hollow %s, noted %s", name, reg.NotedName)
	}
	v.restart()
	v.check("recovered")
	finish(t, v, "recovered")
	if strings.Contains(v.f.Commands(), "create-region") || !strings.Contains(v.f.Commands(), "delete_region") {
		t.Fatalf("commands %s", v.f.Commands())
	}
}

// The lease bind of a realised companion grant is bound again at a start
// when it is gone.
func TestRecoverBind(t *testing.T) {
	v := pmemEnv(t, "ext4")
	req := fsGrant("c", true, "")
	req.BindTarget = filepath.Join(v.dir, localDriver, "lease-fs", "lc1", "data")
	v.mustPrepare(poolDriver, "c", req)
	if err := v.f.Kernel().Unmount(req.BindTarget); err != nil {
		t.Fatal(err)
	}
	v.restart()
	if mi, _ := v.f.Kernel().Mounted(req.BindTarget); mi == nil {
		t.Fatal("not bound again")
	}
	v.check("bound again")
	v.mustUnprepare(poolDriver, "c")
}

// Something else mounted at the node mount of a grant at a start: the mount
// is FOREIGN, never used or unmounted, the grant REALISED_UNRESTORED; the
// release of the device waits for it to go.
func TestRecoverForeignMount(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.mustPrepare(poolDriver, "r", fsGrant("r", true, state.AccessCached))
	g := v.grant("r", 0)
	k := v.f.Kernel()
	if err := k.Unmount(g.Got.MountPath); err != nil {
		t.Fatal(err)
	}
	if err := k.FsMount(g.Got.BlockDevice.Name, g.Got.MountPath, "ext4", false, []string{"dax=never"}); err != nil {
		t.Fatal(err)
	}
	out := v.restart()
	if len(out.Unrestored) != 1 {
		t.Fatalf("recovered %+v", out)
	}
	if m := v.records().Region(g.Got.Region).Mount(g.Got.Mount); m.State != state.MountForeign {
		t.Fatalf("mount %+v", m)
	}
	if err := v.unprepare(poolDriver, "r"); err == nil || !strings.Contains(err.Error(), "is still in use") {
		t.Fatalf("unprepare: %v", err)
	}
	if mi, _ := k.Mounted(g.Got.MountPath); mi == nil || mi.Source != g.Got.BlockDevice.Name {
		t.Fatalf("the foreign mount was touched: %+v", mi)
	}
	if err := k.Unmount(g.Got.MountPath); err != nil {
		t.Fatal(err)
	}
	v.mustUnprepare(poolDriver, "r")
	v.clean("unprepared")
}

// An unrestored grant is mounted again by a Prepare again once its block
// device is the one prepared (REALISED, its mount MOUNTED_RW), or at the
// next start (a reader, MOUNTED_RO).
func TestRecoverRestored(t *testing.T) {
	for _, writer := range []bool{true, false} {
		v := pmemEnv(t, "ext4")
		v.mustPrepare(poolDriver, "c", fsGrant("c", !writer, ""))
		g := v.grant("c", 0)
		if err := v.f.Kernel().Unmount(g.Got.MountPath); err != nil {
			t.Fatal(err)
		}
		v.f.RenamePmem("region0", "pmem3", "259:9")
		if out := v.restart(); len(out.Unrestored) != 1 {
			t.Fatalf("recovered %+v", out)
		}
		v.f.RenamePmem("region0", "pmem0", "259:1")
		if writer {
			if _, err := v.e.PrepareGrants(context.Background(), []GrantRequest{fsGrant("c", false, "")}); err != nil {
				t.Fatal(err)
			}
		} else if out := v.restart(); len(out.Restored) != 1 {
			t.Fatalf("restored %+v", out)
		}
		want := state.MountedRO
		if writer {
			want = state.MountedRW
		}
		if g := v.grant("c", 0); g.State != state.GrantRealised {
			t.Fatalf("grant %s", g.State)
		}
		if m := v.records().Region(g.Got.Region).Mount(g.Got.Mount); m.State != want {
			t.Fatalf("mount %+v", m)
		}
		v.mustUnprepare(poolDriver, "c")
	}
}

// A local sliced claim cut after its grant was REALISED (the preparation
// PREPARING), below a newer pool region: the recovery releases the part and
// keeps the region in order for the claim (RELEASING -> JOURNALED).
func TestRecoverRealisedKeptInOrder(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib}, fake.MemdevSpec{Serial: serialB})
	if err := v.st.Commit(context.Background(), store.Durable, func(doc *store.Document) error {
		doc.Preparations = append(doc.Preparations, state.Preparation{UID: "n", Driver: localDriver, BootID: v.f.BootID(),
			State: state.PreparationPreparing, Results: []state.Result{grantResult("n", 0)}})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.e.PrepareGrants(context.Background(), []GrantRequest{localReq("n", 0, serialL, state.ModeDax, state.KindExclusive, 256*mib)}); err != nil {
		t.Fatal(err)
	}
	v.mustPrepare(poolDriver, "p", poolReq("p", 0, serialB, state.ModeDax, state.KindExclusive))
	out := v.restart()
	if !slices.Equal(out.Kept, []state.GrantRef{{Claim: "n"}}) {
		t.Fatalf("recovered %+v", out)
	}
	if g := v.grant("n", 0); g.State != state.GrantJournaled || g.Intent.Region == "" || g.Got.Dax != "" {
		t.Fatalf("grant %+v", g)
	}
	if p := v.records().Preparation(localDriver, "n"); p.State != state.PreparationKept {
		t.Fatalf("preparation %s", p.State)
	}
	finish(t, v, "finished")
}

// A cut Prepare of another boot (PREPARED_STALE) is not released at the
// start: nothing of that boot is left; its Unprepare releases by serial.
func TestRecoverStaleCut(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	v.f.CutAfter("cxl create-region")
	if !v.cut(func() { _ = v.prepare(poolDriver, "c", poolReq("c", 0, serialA, state.ModeDax, state.KindExclusive)) }) {
		t.Fatal("not cut")
	}
	v.f.Reboot()
	before := v.f.Commands()
	v.restart()
	if cmds := v.f.CommandsSince(before); cmds != "" {
		t.Fatalf("commands at the start %q", cmds)
	}
	if p := v.records().Preparation(poolDriver, "c"); p.State != state.PreparationStale {
		t.Fatalf("preparation %s", p.State)
	}
	finish(t, v, "finished")
}

// The node mounts are restored before the cut grants are released: the
// release of a cut claim on another memdev finds the prepared claim's node
// mount mounted again.
func TestRecoverRestoreBeforeRelease(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.f.Plug(fake.MemdevSpec{Serial: serialA})
	v.mustPrepare(poolDriver, "r", fsGrant("r", true, ""))
	direct := v.grant("r", 0).Got.MountPath
	v.f.CutAfter("cxl create-region")
	if !v.cut(func() { _ = v.prepare(poolDriver, "c", poolReq("c", 0, serialA, state.ModeDax, state.KindExclusive)) }) {
		t.Fatal("not cut")
	}
	k := v.f.Kernel()
	if err := k.Unmount(direct); err != nil {
		t.Fatal(err)
	}
	released := false
	v.f.Before("cxl destroy-region", func() {
		released = true
		if mi, _ := k.Mounted(direct); mi == nil {
			t.Error("a cut grant released before the node mounts were restored")
		}
	})
	v.restart()
	if !released {
		t.Fatal("the cut grant was not released")
	}
	finish(t, v, "finished")
}
