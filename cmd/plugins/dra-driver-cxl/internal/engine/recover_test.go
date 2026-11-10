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
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
	"golang.org/x/sys/unix"
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
	direct := v.mount("w", 0).Path
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
	direct := v.mount("w", 0).Path
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
	if g := v.grant("w", 0); g.State != state.GrantUnrestored {
		t.Fatalf("the Prepare again released the grant: %s", g.State)
	}
	// the release waits for the holders of the block device of the region
	// now, not of the one as prepared
	logs := captureKlog(t)
	v.mustUnprepare(poolDriver, "w")
	want := fmt.Sprintf("claim ns/w: its node mount %s was not mounted again at start; the release of device 0x91 waits for the holders of %s, the block device of its region now, not of %s",
		direct, filepath.Join(v.f.DevRoot(), "pmem3"), filepath.Join(v.f.DevRoot(), "pmem0"))
	if out := logs(); !strings.Contains(out, want) {
		t.Fatalf("no %q in\n%s", want, out)
	}
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

// A process stop inside a rollback: the grant that the rollback left
// RELEASING is released at the start, the preparation stays PREPARING for
// kubelet's retry.
func TestRecoverCutRollback(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib}, fake.MemdevSpec{Serial: serialA})
	v.formatPmem("mem0", "ext4")
	v.f.FailCommand("cxl create-region", nil, errors.New("cxl region: cmd_create_region: failed"))
	ref := state.GrantRef{Claim: "c"}
	v.e.afterCommit = func() {
		if g := v.records().Grant(ref); g != nil && g.State == state.GrantReleasing {
			panic(fake.ErrCut)
		}
	}
	reqs := []GrantRequest{fsGrant("c", true, ""), poolReq("c", 1, serialA, state.ModeDax, state.KindExclusive)}
	if !v.cut(func() { _ = v.prepare(poolDriver, "c", reqs...) }) {
		t.Fatal("not cut")
	}
	out := v.restart()
	if !slices.Contains(out.Released, ref) || v.records().Grant(ref) != nil {
		t.Fatalf("recovered %+v, grant %+v", out, v.records().Grant(ref))
	}
	if p := v.records().Preparation(poolDriver, "c"); p == nil || p.State != state.PreparationPreparing {
		t.Fatalf("preparation %+v", p)
	}
	if rs := v.f.Kernel().Regions("mem0"); len(rs) > 0 {
		t.Fatalf("regions %v left", rs)
	}
	v.mustPrepare(poolDriver, "c", reqs...)
	v.mustUnprepare(poolDriver, "c")
	v.clean("unprepared")
}

// The keep decision of a cut claim is per memdev: of a claim on two
// memdevs, the one whose region lies below a region of another memdev is
// kept and the other released at the start, the preparation KEPT; its
// Prepare again realises the released part anew and reuses the kept
// region.
func TestRecoverClaimKeptInPart(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA}, fake.MemdevSpec{Serial: serialB}, fake.MemdevSpec{Serial: serialC, HostBridge: 24})
	free := poolReq("c", 0, serialC, state.ModeDax, state.KindExclusive)
	below := poolReq("c", 1, serialA, state.ModeDax, state.KindExclusive)
	if err := v.st.Commit(context.Background(), store.Durable, func(doc *store.Document) error {
		doc.Preparations = append(doc.Preparations, state.Preparation{UID: "c", Driver: poolDriver, ClaimName: "ns/c",
			BootID: v.f.BootID(), State: state.PreparationPreparing, Results: []state.Result{grantResult("c", 0), grantResult("c", 1)}})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.e.PrepareGrants(context.Background(), []GrantRequest{free}); err != nil {
		t.Fatal(err)
	}
	// cut after the region of the second one was made
	v.cutAfter(4)
	if !v.cut(func() { _, _ = v.e.PrepareGrants(context.Background(), []GrantRequest{below}) }) {
		t.Fatal("not cut")
	}
	k := v.f.Kernel()
	d, _ := k.RootDecoder("mem1", kernel.RegionRAM)
	above, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: "mem1", Decoder: d, Type: kernel.RegionRAM})
	if err != nil {
		t.Fatal(err)
	}
	kept := k.Regions("mem0")
	logs := captureKlog(t)
	out := v.restart()
	if !slices.Equal(out.Released, []state.GrantRef{{Claim: "c"}}) || !slices.Equal(out.Kept, []state.GrantRef{{Claim: "c", Result: 1}}) {
		t.Fatalf("recovered %+v", out)
	}
	lines := logs()
	for _, want := range []string{
		"claim ns/c (c), whose Prepare did not finish: releasing devices 0xc1\n",
		"claim ns/c (c): not releasing its devices at start: " + above + " lie above their regions",
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("no %q in\n%s", want, lines)
		}
	}
	if strings.Contains(lines, "released, its Prepare again") {
		t.Errorf("the claim is released whole:\n%s", lines)
	}
	if p := v.records().Preparation(poolDriver, "c"); p.State != state.PreparationKept {
		t.Fatalf("preparation %s", p.State)
	}
	if g := v.grant("c", 1); g.State != state.GrantJournaled || len(kept) != 1 || g.Intent.Region != state.RegionRef(kept[0]) {
		t.Fatalf("grant %+v, kept %v", g, kept)
	}
	if rs := k.Regions("mem2"); len(rs) > 0 {
		t.Fatalf("the released part has %v", rs)
	}
	v.mustPrepare(poolDriver, "c", free, below)
	if g := v.grant("c", 1); g.Got.Region != state.RegionRef(kept[0]) {
		t.Fatalf("the kept region %v is not reused: %+v", kept, g)
	}
	if rs := k.Regions("mem2"); len(rs) != 1 || v.grant("c", 0).Got.Region != state.RegionRef(rs[0]) {
		t.Fatalf("the released part is not realised anew: %v", rs)
	}
	if err := k.ReleaseRegion(context.Background(), above); err != nil {
		t.Fatal(err)
	}
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
	direct := v.mount("w", 0).Path
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
	if name := v.f.HollowRegion("decoder0.0", 256*mib); name != reg.NotedName {
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
	g, mnt := v.grant("r", 0), v.mount("r", 0).Path
	k := v.f.Kernel()
	if err := k.Unmount(mnt); err != nil {
		t.Fatal(err)
	}
	if err := k.FsMount(g.Got.BlockDevice.Name, mnt, "ext4", false, []string{"dax=never"}); err != nil {
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
	if mi, _ := k.Mounted(mnt); mi == nil || mi.Source != g.Got.BlockDevice.Name {
		t.Fatalf("the foreign mount was touched: %+v", mi)
	}
	if err := k.Unmount(mnt); err != nil {
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
		g, mnt := v.grant("c", 0), v.mount("c", 0).Path
		if err := v.f.Kernel().Unmount(mnt); err != nil {
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

// A pool claim prepared and a pool claim whose cut Prepare the recovery
// released (PREPARING without its grant record) are both PREPARED_STALE
// after a reboot; the records satisfy the invariants after the load and
// the recovery, after the Unprepare of the prepared claim and after the
// Prepare again of the cut one.
func TestRecoverRebootAfterReleasedCut(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA}, fake.MemdevSpec{Serial: serialB})
	v.mustPrepare(poolDriver, "p", poolReq("p", 0, serialA, state.ModeNUMA, state.KindExclusive))
	v.f.CutAfter("cxl create-region")
	if !v.cut(func() { _ = v.prepare(poolDriver, "c", poolReq("c", 0, serialB, state.ModeNUMA, state.KindExclusive)) }) {
		t.Fatal("not cut")
	}
	out := v.restart()
	if len(out.Released) != 1 || v.records().Grant(state.GrantRef{Claim: "c"}) != nil {
		t.Fatalf("recovered %+v, grant %+v", out, v.records().Grant(state.GrantRef{Claim: "c"}))
	}
	if p := v.records().Preparation(poolDriver, "c"); p == nil || p.State != state.PreparationPreparing {
		t.Fatalf("preparation of the released cut %+v", p)
	}
	v.f.Reboot()
	v.restart()
	for _, uid := range []string{"p", "c"} {
		if p := v.records().Preparation(poolDriver, uid); p == nil || p.State != state.PreparationStale {
			t.Fatalf("preparation %s %+v", uid, p)
		}
	}
	v.mustUnprepare(poolDriver, "p")
	v.mustPrepare(poolDriver, "c", poolReq("c", 0, serialB, state.ModeNUMA, state.KindExclusive))
	if g := v.grant("c", 0); g.State != state.GrantRealised || g.Got.Region == "" {
		t.Fatalf("prepared anew %+v", g)
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
	direct := v.mount("r", 0).Path
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

// Recover leaves the records of a source that the engine does not own (an
// adapter's local claim cut in its Prepare, its region recorded) as they
// are.
func TestRecoverOtherSources(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA}, fake.MemdevSpec{Serial: serialL}, fake.MemdevSpec{Serial: serialP, Pmem: gib})
	v.formatPmem("mem2", "ext4")
	v.sources = []state.Source{state.SourcePool}
	ref := state.GrantRef{Claim: "l"}
	// the node mount directory of a local claim (no Mount record lists it)
	// and a stale lease bind of a local memdev
	localMount := filepath.Join(v.dir, localDriver, "mounts", "11-direct")
	staleBind := filepath.Join(v.dir, localDriver, "lease-fs", "lc9", "data")
	for _, d := range []string{localMount, staleBind} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fsRef := state.GrantRef{Claim: "lfs"}
	if err := v.st.Commit(context.Background(), store.Durable, func(doc *store.Document) error {
		doc.Preparations = append(doc.Preparations, state.Preparation{UID: "l", Driver: localDriver, BootID: v.f.BootID(),
			State: state.PreparationPreparing, Results: []state.Result{grantResult("l", 0)}},
			state.Preparation{UID: "lfs", Driver: localDriver, BootID: v.f.BootID(),
				State: state.PreparationPrepared, Results: []state.Result{grantResult("lfs", 0)}})
		doc.Memdevs = append(doc.Memdevs, state.Memdev{Serial: serialL, Source: state.SourceLocal, State: state.MemdevActive,
			Grants: []state.GrantRef{ref, fsRef}, Regions: []state.RegionRef{"region7"},
			Stale: []state.StalePath{{Path: staleBind, Kind: state.StaleBind}}})
		doc.Grants = append(doc.Grants, state.Grant{Ref: ref, Serial: serialL, State: state.GrantJournaled,
			Asked: state.Asked{Source: state.SourceLocal, Mode: state.ModeDax, Kind: state.KindExclusive}},
			state.Grant{Ref: fsRef, Serial: serialL, State: state.GrantRealised,
				Asked: state.Asked{Source: state.SourceLocal, Mode: state.ModeFs, Kind: state.KindPersistent}})
		doc.Regions = append(doc.Regions, state.Region{Name: "region7", Mode: state.RegionRam, Targets: []state.Serial{serialL},
			Owner: state.OwnerOurs, State: state.RegionOwned})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	local := func() string {
		doc := v.st.Snapshot()
		var out []string
		for _, m := range doc.Memdevs {
			if m.Source == state.SourceLocal {
				out = append(out, fmt.Sprintf("%+v", m))
			}
		}
		for _, g := range doc.Grants {
			if g.Asked.Source == state.SourceLocal {
				out = append(out, fmt.Sprintf("%+v", g))
			}
		}
		out = append(out, fmt.Sprintf("%+v %+v", doc.Region("region7"), doc.Preparation(localDriver, "l")))
		return strings.Join(out, "\n")
	}
	before := local()
	v.restart()
	if after := local(); after != before {
		t.Fatalf("the records of the local source changed:\n%s\n->\n%s", before, after)
	}
	err := v.e.ReleaseGrants(context.Background(), []state.GrantRef{ref}, ReleaseUnprepare)
	if err == nil || !strings.Contains(err.Error(), "are not the engine's") {
		t.Fatalf("release of another source: %v", err)
	}
	gen := v.st.Snapshot().Generation
	_, err = v.e.PrepareGrants(context.Background(), []GrantRequest{localReq("l2", 0, serialL, state.ModeDax, state.KindExclusive, 256*mib)})
	if err == nil || !strings.Contains(err.Error(), "are not the engine's") || v.st.Snapshot().Generation != gen {
		t.Fatalf("prepare of another source: %v (generation %d -> %d)", err, gen, v.st.Snapshot().Generation)
	}
	// a release of the pool retries the stale lease binds of its own
	// memdevs only
	v.mustPrepare(poolDriver, "r", fsGrant("r", true, ""))
	v.mustUnprepare(poolDriver, "r")
	if after := local(); after != before {
		t.Fatalf("the records of the local source changed:\n%s\n->\n%s", before, after)
	}
	for _, d := range []string{localMount, staleBind} {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("a directory of the local source: %v", err)
		}
	}
}

// At a start, the device of a node mount mounted there with other options
// is still the grant's: it stays REALISED (logged) and its release
// unmounts it.
func TestRecoverOwnDeviceOtherOptions(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.mustPrepare(poolDriver, "r", fsGrant("r", true, ""))
	g, mnt := v.grant("r", 0), v.mount("r", 0).Path
	k := v.f.Kernel()
	if err := k.Unmount(mnt); err != nil {
		t.Fatal(err)
	}
	if err := k.FsMount(g.Got.BlockDevice.Name, mnt, "ext4", false, []string{"dax=never"}); err != nil {
		t.Fatal(err)
	}
	logs := captureKlog(t)
	if out := v.restart(); len(out.Unrestored) > 0 {
		t.Fatalf("recovered %+v", out)
	}
	if out := logs(); !strings.Contains(out, "was mounted without DAX") {
		t.Fatalf("not logged:\n%s", out)
	}
	if g := v.grant("r", 0); g.State != state.GrantRealised {
		t.Fatalf("grant %s", g.State)
	}
	v.mustUnprepare(poolDriver, "r")
	if mi, _ := k.Mounted(mnt); mi != nil {
		t.Fatalf("still mounted: %+v", mi)
	}
	v.clean("unprepared")
}

// A cached node mount that the start mounts again on another loop device
// records that one; a Prepare again that mounts an unrestored node mount
// again makes its other grants REALISED too.
func TestRecoverLoopRecorded(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.mustPrepare(poolDriver, "r1", fsGrant("r1", true, state.AccessCached))
	v.mustPrepare(poolDriver, "r2", fsGrant("r2", true, state.AccessCached))
	mnt := v.mount("r1", 0).Path
	k := v.f.Kernel()
	if err := k.Unmount(mnt); err != nil {
		t.Fatal(err)
	}
	// another loop device takes the number of the old one
	if _, err := k.AttachLoop(filepath.Join(v.dir, "filesystems"), false); err != nil {
		t.Fatal(err)
	}
	v.restart()
	g := v.grant("r1", 0)
	m := v.records().Region(g.Got.Region).Mount(g.Got.Mount)
	if mi, _ := k.Mounted(mnt); mi == nil || mi.Source != m.Loop || m.Path != mnt {
		t.Fatalf("mounted %+v, mount %+v, grant %+v", mi, m, g.Got)
	}
	// unrestored: a block device that is not the one prepared
	if err := k.Unmount(mnt); err != nil {
		t.Fatal(err)
	}
	v.f.RenamePmem("region0", "pmem3", "259:9")
	if out := v.restart(); len(out.Unrestored) != 2 {
		t.Fatalf("recovered %+v", out)
	}
	v.f.RenamePmem("region0", "pmem0", "259:1")
	if _, err := v.e.PrepareGrants(context.Background(), []GrantRequest{fsGrant("r1", true, state.AccessCached)}); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{"r1", "r2"} {
		if g := v.grant(uid, 0); g.State != state.GrantRealised {
			t.Fatalf("grant %s: %s", uid, g.State)
		}
	}
	// the preparation of r1 is the front-end's, after PrepareGrants
	if p := v.records().Preparation(poolDriver, "r2"); p.State != state.PreparationPrepared {
		t.Fatalf("preparation r2: %s", p.State)
	}
	v.mustUnprepare(poolDriver, "r1")
	v.mustUnprepare(poolDriver, "r2")
	v.clean("unprepared")
}

// The start logs what it does with each claim whose Prepare did not
// finish, and keeps a companion claim of mode numa with a line.
func TestRecoverClaimLines(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA}, fake.MemdevSpec{Serial: serialC, HostBridge: 24},
		fake.MemdevSpec{Serial: serialP, Pmem: gib})
	v.formatPmem("mem2", "ext4")
	companion := poolReq("comp", 0, serialC, state.ModeNUMA, state.KindExclusive)
	companion.Lend = &state.GrantLend{Lease: "0123abcd", Container: "c"}
	target := filepath.Join(v.dir, localDriver, "lease-fs", "lc1", "data")
	for _, c := range []struct {
		uid string
		req GrantRequest
	}{
		{"plain", poolReq("plain", 0, serialA, state.ModeNUMA, state.KindExclusive)},
		{"comp", companion},
		// a companion of mode fs is released at the start, its bind too
		{"fscomp", bindReq("fscomp", target)},
	} {
		if err := v.st.Commit(context.Background(), store.Durable, func(doc *store.Document) error {
			doc.Preparations = append(doc.Preparations, state.Preparation{UID: c.uid, Driver: poolDriver, ClaimName: "ns/" + c.uid,
				BootID: v.f.BootID(), State: state.PreparationPreparing, Results: []state.Result{grantResult(c.uid, 0)}})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := v.e.PrepareGrants(context.Background(), []GrantRequest{c.req}); err != nil {
			t.Fatal(err)
		}
	}
	if mi, _ := v.f.Kernel().Mounted(target); mi == nil {
		t.Fatal("the lease bind is not mounted")
	}
	logs := captureKlog(t)
	recovered := v.restart()
	out := logs()
	for _, want := range []string{
		"claim ns/comp (comp) is a companion claim: its Unprepare releases its devices, its Prepare again reuses them",
		"claim ns/plain (plain), whose Prepare did not finish: releasing devices 0xa1",
		"claim ns/plain (plain): released, its Prepare again prepares its devices anew",
		"claim ns/fscomp (fscomp), whose Prepare did not finish: releasing devices 0x91",
		"claim ns/fscomp (fscomp): released, its Prepare again prepares its devices anew",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "claim ns/fscomp (fscomp) is a companion claim") {
		t.Errorf("the fs companion is kept:\n%s", out)
	}
	if !slices.Contains(recovered.Released, state.GrantRef{Claim: "fscomp"}) || v.records().Grant(state.GrantRef{Claim: "fscomp"}) != nil {
		t.Errorf("the fs companion is not released: %+v", recovered)
	}
	if mi, _ := v.f.Kernel().Mounted(target); mi != nil {
		t.Errorf("the lease bind of the released companion is mounted: %+v", mi)
	}
	v.mustUnprepare(poolDriver, "fscomp")
	v.mustUnprepare(poolDriver, "comp")
	v.mustUnprepare(poolDriver, "plain")
	v.clean("unprepared")
}

// An engine that owns the pool's records only sweeps a lease bind that no
// prepared claim lists by its node mount in the pool's mounts directory:
// the binds are swept before the node mounts, so that the node mount still
// tells whose the bind is.
func TestRecoverSweepsBindsBeforeNodeMounts(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.sources = []state.Source{state.SourcePool}
	k := v.f.Kernel()
	node := filepath.Join(v.dir, poolDriver, "mounts", "a1-direct")
	bind := filepath.Join(v.dir, localDriver, "lease-fs", "lc4", "data")
	for _, dir := range []string{node, bind} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := k.FsMount(filepath.Join(v.e.devRoot(), "pmem6"), node, "ext4", true, nil); err != nil {
		t.Fatal(err)
	}
	if err := k.Mount(node, bind, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	v.restart()
	for _, path := range []string{bind, node} {
		if mi, _ := k.Mounted(path); mi != nil {
			t.Errorf("%s is mounted: %+v", path, mi)
		}
	}
}

// A lease bind whose node mount is gone belongs to no memdev: the start
// unmounts it, and when that fails, every release tries again until it is
// gone.
func TestRecoverOrphanBind(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.f.Plug(fake.MemdevSpec{Serial: serialA})
	k := v.f.Kernel()
	gone := filepath.Join(v.dir, "gone")
	orphan := filepath.Join(v.dir, localDriver, "lease-fs", "lc3", "x")
	for _, dir := range []string{gone, orphan} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := k.FsMount(filepath.Join(v.e.devRoot(), "pmem6"), gone, "ext4", true, nil); err != nil {
		t.Fatal(err)
	}
	if err := k.Mount(gone, orphan, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	if err := k.Unmount(gone); err != nil {
		t.Fatal(err)
	}
	v.f.SetBusy(orphan, true)
	logs := captureKlog(t)
	v.restart()
	wantLog(t, logs(), orphan+" belongs to no prepared claim, unmounting it",
		"unmounting "+orphan+": device or resource busy; trying again at the next release")
	if mi, _ := k.Mounted(orphan); mi == nil {
		t.Fatal("the busy bind is gone")
	}
	// a release while it is busy keeps it, the next one unmounts it
	v.mustPrepare(poolDriver, "p", poolReq("p", 0, serialA, state.ModeDax, state.KindExclusive))
	v.mustUnprepare(poolDriver, "p")
	wantLog(t, logs(), "unmounting stale lease bind "+orphan+": device or resource busy")
	if mi, _ := k.Mounted(orphan); mi == nil {
		t.Fatal("the busy bind is gone")
	}
	v.f.SetBusy(orphan, false)
	v.mustPrepare(poolDriver, "p", poolReq("p", 0, serialA, state.ModeDax, state.KindExclusive))
	v.mustUnprepare(poolDriver, "p")
	wantLog(t, logs(), "unbound stale lease bind "+orphan)
	if mi, _ := k.Mounted(orphan); mi != nil {
		t.Fatalf("the orphan bind is still mounted: %+v", mi)
	}
}

// A start between the failed Unprepare of a companion on its busy lease
// bind and its Unprepare again keeps the companion's node mount and bind.
func TestRecoverKeepsNodeMountOfBusyCompanion(t *testing.T) {
	v := pmemEnv(t, "erofs")
	mnt, target := busyCompanionNextToReader(t, v)
	v.mustUnprepare(poolDriver, "r")
	v.restart()
	v.mustBeMounted("after the start", mnt, target)
	v.f.SetBusy(target, false)
	v.mustUnprepare(poolDriver, "c")
	v.mustNotBeMounted("after the Unprepare again of c", mnt, target)
	v.clean("unprepared")
}

// A pool block grant whose block device is not the one of its region at a
// start is REALISED_UNRESTORED (every grant kind is verified), its
// preparation PREPARED_UNRESTORED; a Prepare again once the block device is
// the prepared one again restores it.
func TestRecoverPoolBlockChanged(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
	v.mustPrepare(poolDriver, "b", poolReq("b", 0, serialP, state.ModeBlock, state.KindPersistent))
	v.f.RenamePmem("region0", "pmem3", "259:9")
	out := v.restart()
	if !slices.Equal(out.Unrestored, []state.GrantRef{{Claim: "b"}}) || out.Why[state.GrantRef{Claim: "b"}] == nil {
		t.Fatalf("recovered %+v", out)
	}
	if g := v.grant("b", 0); g.State != state.GrantUnrestored {
		t.Fatalf("grant %s", g.State)
	}
	wantPreparation(t, v, poolDriver, "b", state.PreparationUnrestored)
	req := poolReq("b", 0, serialP, state.ModeBlock, state.KindPersistent)
	if _, err := v.e.PrepareGrants(context.Background(), []GrantRequest{req}); err == nil || !strings.Contains(err.Error(), "as prepared") {
		t.Fatalf("Prepare again with another block device: %v", err)
	}
	v.f.RenamePmem("region0", "pmem0", "259:0")
	if _, err := v.e.PrepareGrants(context.Background(), []GrantRequest{req}); err != nil {
		t.Fatalf("Prepare again: %v", err)
	}
	if g := v.grant("b", 0); g.State != state.GrantRealised {
		t.Fatalf("grant %s after the Prepare again", g.State)
	}
	v.mustUnprepare(poolDriver, "b")
	v.clean("unprepared")
}

// A cut Prepare of a pool claim whose memdev has another tool's region
// below a region of another memdev made nothing to keep: the start
// releases its grant, the claim stays PREPARING and the other tool's
// regions are left alone.
func TestRecoverCutPrepareOnForeignBelow(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA}, fake.MemdevSpec{Serial: serialB})
	below := rawRegion(t, v, "mem1")
	above := rawRegion(t, v, "mem0")
	v.cutAfter(1)
	if !v.cut(func() { _ = v.prepare(poolDriver, "c", poolReq("c", 0, serialB, state.ModeDax, state.KindExclusive)) }) {
		t.Fatal("not cut")
	}
	out := v.restart()
	if len(out.Kept) > 0 || !slices.Equal(out.Released, []state.GrantRef{{Claim: "c"}}) {
		t.Fatalf("recovered %+v", out)
	}
	wantPreparation(t, v, poolDriver, "c", state.PreparationPreparing)
	if m := v.records().Memdev(serialB); m != nil {
		t.Fatalf("memdev %+v", m)
	}
	for _, region := range []string{below, above} {
		if _, err := v.f.Kernel().Region(region); err != nil {
			t.Fatalf("%s: %v", region, err)
		}
	}
	dropRaw(t, v, above)
	dropRaw(t, v, below)
	finish(t, v, "finished")
}
