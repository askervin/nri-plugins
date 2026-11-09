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
	"time"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/compat"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// logLine returns the first message of the klog output that contains
// text, without the klog header, "" for none.
func logLine(logs, text string) string {
	for _, l := range strings.Split(logs, "\n") {
		if _, msg, ok := strings.Cut(l, "] "); ok && strings.Contains(msg, text) {
			return msg
		}
	}
	return ""
}

// cutWhenRealised makes the process stop after the commit that makes the
// grant of result 0 of the claim uid REALISED.
func cutWhenRealised(v *env, uid string) {
	v.e.afterCommit = func() {
		if g := v.records().Grant(state.GrantRef{Claim: uid}); g != nil && g.State == state.GrantRealised {
			panic(fake.ErrCut)
		}
	}
}

// The start keeps the region of a local memdev configured shared, with
// claims or idle; one not configured shared any more stays for its claims
// (a warning), and is released when it is idle, its record dropped.
func TestLocalRecoverShared(t *testing.T) {
	for _, c := range []struct {
		name     string
		claims   bool
		shared   bool
		want     string
		released bool
	}{
		{"configured with claims", true, true, "local: memdev mem0 (serial 0x11): keeping shared region0 and dax0.0, claims [s1]", false},
		{"configured idle", false, true, "local: memdev mem0 (serial 0x11): keeping shared region0 and dax0.0, claims []", false},
		{"not configured with claims", true, false, "local: memdev mem0 (serial 0x11): not configured shared any more: keeping region0 for " +
			"claims [s1], not publishing the memdev until they are gone", false},
		{"not configured idle", false, false, "local: memdev mem0 (serial 0x11): not configured shared any more, releasing its region", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
			v.configure(func(o *Options) { o.Shared = func(state.Serial) bool { return true } })
			v.mustPrepare(localDriver, "s1", sharedReq("s1"))
			if !c.claims {
				v.mustUnprepare(localDriver, "s1")
			}
			if !c.shared {
				v.tune = nil
			}
			logs := captureKlog(t)
			v.restart()
			out := logs()
			line := logLine(out, c.want)
			if line == "" {
				t.Fatalf("no %q in\n%s", c.want, out)
			}
			switch {
			case c.shared && !compat.Matches(compat.LogSerialDRALocalSerialKeepingSharedSharedRegionAndSharedDaxClaims, line):
				t.Errorf("line %q does not match the e2e tests", line)
			case c.released && !compat.Matches(compat.LogSerialDRALocalSerialNotConfiguredSharedAnyMoreReleasing, line):
				t.Errorf("line %q does not match the e2e tests", line)
			}
			if c.released {
				released := logLine(out, "released region0 in ")
				if ok, err := compat.MatchesRegexp(compat.LogZeroedNewSharedReleasingItsRegionReleasedSharedRegion, released); err != nil || !ok {
					t.Errorf("line %q does not match the e2e tests (%v)", released, err)
				}
				v.clean("released")
				return
			}
			wantRegion(t, v, "region0", state.RegionOwned)
			v.mustUnprepare(localDriver, "s1")
			releaseIdleShared(v)
			v.clean("released")
		})
	}
}

// The start keeps the region of a persistent local memdev with claims, and
// releases an idle one in order when nothing holds its block device: kept
// while a region of another memdev lies above it or a holder holds it.
func TestLocalRecoverPersistent(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib}, fake.MemdevSpec{Serial: serialB})
	v.formatPmem("mem0", "ext4")
	v.mustPrepare(localDriver, "w", localPmemReq("w", 0, state.ModeFs, false, ""))
	logs := captureKlog(t)
	v.restart()
	wantLog(t, logs(), "local: memdev mem0 (serial 0x91): keeping persistent region0, claims [w]")
	above := rawRegion(t, v, "mem1")
	v.mustUnprepare(localDriver, "w")
	// idle below a region of another memdev
	logs = captureKlog(t)
	v.restart()
	wantLog(t, logs(), "local: memdev mem0 (serial 0x91): keeping region0 of the idle persistent device: "+above+" lie above it")
	if m := v.records().Memdev(serialP); m == nil || m.State != state.MemdevIdleKept {
		t.Fatalf("memdev %+v", m)
	}
	dropRaw(t, v, above)
	// idle and held
	pmem := filepath.Join(v.f.DevRoot(), "pmem0")
	v.f.SetHolder(pmem, "dm-0")
	logs = captureKlog(t)
	v.restart()
	wantLog(t, logs(), "local: memdev mem0 (serial 0x91): keeping region0 of the idle persistent device: device 0x91: "+pmem+" is still in use",
		localDriver+": device 0x91: "+pmem+" is held: in use")
	wantRegion(t, v, "region0", state.RegionOwned)
	v.f.SetHolder(pmem, "")
	logs = captureKlog(t)
	v.restart()
	wantLog(t, logs(), "local: memdev mem0 (serial 0x91): released region0 in ")
	v.clean("released")
}

// The start releases the region of a sliced local memdev without claims,
// and deletes the parts that belong to no claim first.
func TestLocalRecoverSlicedIdle(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
	v.mustPrepare(localDriver, "d", sliceReq("d", 0, state.ModeDax, 256*mib))
	// the claim is forgotten (another front-end), its part left
	ref := state.GrantRef{Claim: "d"}
	if err := v.st.Commit(context.Background(), store.Durable, func(doc *store.Document) error {
		removeRecord(&doc.Grants, func(g *state.Grant) bool { return g.Ref == ref })
		removeRecord(&doc.Preparations, func(p *state.Preparation) bool { return p.UID == "d" })
		m := doc.Memdev(serialL)
		m.Grants, m.State = nil, state.MemdevIdleKept
		d := doc.Region("region0").DaxDevice("dax0.0")
		d.Users = nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	logs := captureKlog(t)
	v.restart()
	wantLog(t, logs(), "local: memdev mem0 (serial 0x11): dax0.0 (mode dax, 268435456 bytes) belongs to no claim, deleting it",
		"local: memdev mem0 (serial 0x11): released region0 in ")
	v.clean("released")
}

// The start forgets the parts of prepared claims whose dax device is gone
// or has another size: the grant keeps its region without the device, and
// a device of another size is deleted as belonging to no claim.
func TestLocalRecoverGoneParts(t *testing.T) {
	for _, c := range []struct {
		name string
		do   func(t *testing.T, v *env)
		want []string
	}{
		{"gone", func(t *testing.T, v *env) {
			if err := v.f.Kernel().DeleteDaxDevice(context.Background(), "region0", "dax0.1"); err != nil {
				t.Fatal(err)
			}
		}, nil},
		{"another size", func(t *testing.T, v *env) {
			if err := v.f.Kernel().ResizeDaxDevice(context.Background(), "dax0.1", 128*mib); err != nil {
				t.Fatal(err)
			}
		}, []string{"local: memdev mem0 (serial 0x11): dax0.1 (mode dax, 134217728 bytes) belongs to no claim, deleting it"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
			v.mustPrepare(localDriver, "d1", sliceReq("d1", 0, state.ModeDax, 256*mib))
			v.mustPrepare(localDriver, "d2", sliceReq("d2", 0, state.ModeDax, 256*mib))
			if g := v.grant("d2", 0); g.Got.Dax != "dax0.1" {
				t.Fatalf("grant %+v", g.Got)
			}
			c.do(t, v)
			logs := captureKlog(t)
			v.restart()
			wantLog(t, logs(), append([]string{
				"local: memdev mem0 (serial 0x11): claim d2: slice dax0.1 of 268435456 bytes is gone, dropping it",
				"claim d2: no device node for the dax slice " + filepath.Join(v.f.DevRoot(), "dax0.1") + ": the slice is gone",
			}, c.want...)...)
			if g := v.grant("d2", 0); g.Got.Dax != "" || g.Got.Region != "region0" || g.State != state.GrantRealised {
				t.Fatalf("grant %+v", g)
			}
			if d := v.records().Region("region0").DaxDevice("dax0.1"); d != nil {
				t.Fatalf("record of dax0.1 %+v", d)
			}
			if v.f.DaxExists("dax0.1") {
				t.Fatal("dax0.1 is left")
			}
			if g := v.grant("d1", 0); g.Got.Dax != "dax0.0" {
				t.Fatalf("grant %+v", g)
			}
			v.mustUnprepare(localDriver, "d2")
			v.mustUnprepare(localDriver, "d1")
			v.clean("unprepared")
		})
	}
}

// The uses of a prepared local persistent memdev whose block device is not
// the one of its region now (also of mode block) have no CDI device: the
// grants REALISED_UNRESTORED, the preparations PREPARED_UNRESTORED, the
// node mount left as it is and released with them; a Prepare again stays
// unrestored with the error.
func TestLocalRecoverBadBlocks(t *testing.T) {
	for _, c := range []struct {
		name   string
		req    GrantRequest
		format bool
	}{
		{"mode fs", localPmemReq("w", 0, state.ModeFs, false, ""), true},
		{"mode block", localPmemReq("w", 0, state.ModeBlock, false, ""), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
			if c.format {
				v.formatPmem("mem0", "ext4")
			}
			v.mustPrepare(localDriver, "w", c.req)
			mount := ""
			if m := v.records().MountOf(v.grant("w", 0)); m != nil {
				mount = m.Path
			}
			v.f.RenamePmem("region0", "pmem3", "259:9")
			logs := captureKlog(t)
			out := v.restart()
			if !slices.Equal(out.Unrestored, []state.GrantRef{{Claim: "w"}}) || out.Why[state.GrantRef{Claim: "w"}] == nil {
				t.Fatalf("recovered %+v", out)
			}
			if line := logLine(logs(), "local: memdev mem0 (serial 0x91): "); line == "" {
				t.Fatalf("no error line in\n%s", logs())
			}
			if g := v.grant("w", 0); g.State != state.GrantUnrestored {
				t.Fatalf("grant %s", g.State)
			}
			wantPreparation(t, v, localDriver, "w", state.PreparationUnrestored)
			if mount != "" {
				if mi, _ := v.f.Kernel().Mounted(mount); mi == nil {
					t.Fatalf("%s is not mounted", mount)
				}
			}
			why := out.Why[state.GrantRef{Claim: "w"}].Error()
			if _, err := v.e.PrepareGrants(context.Background(), []GrantRequest{c.req}); err == nil || err.Error() != why {
				t.Fatalf("Prepare again: %v, want %q", err, why)
			}
			if g := v.grant("w", 0); g.State != state.GrantUnrestored {
				t.Fatalf("the Prepare again changed the grant: %s", g.State)
			}
			v.mustUnprepare(localDriver, "w")
			if mount != "" {
				if mi, _ := v.f.Kernel().Mounted(mount); mi != nil {
					t.Fatalf("%s is left mounted", mount)
				}
			}
			v.clean("unprepared")
		})
	}
}

// ForgetLocal forgets the records of a local memdev whose region was being
// created (NOTED) and that is a pool device now, without touching the
// region; a local memdev whose region is made stays.
func TestLocalForgetLocal(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib}, fake.MemdevSpec{Serial: serialB})
	v.mustPrepare(localDriver, "b", localReq("b", 0, serialB, state.ModeDax, state.KindExclusive, 256*mib))
	v.f.CutAfter("cxl create-region")
	if !v.cut(func() { _ = v.prepare(localDriver, "l", sliceReq("l", 0, state.ModeDax, 256*mib)) }) {
		t.Fatal("not cut")
	}
	if reg := v.records().Region("region1"); reg == nil || reg.State != state.RegionNoted {
		t.Fatalf("region %+v", reg)
	}
	_ = v.st.Close()
	v.open()
	before := v.f.Commands()
	logs := captureKlog(t)
	if err := v.e.ForgetLocal(context.Background(), []state.Serial{serialL, serialB, serialA}); err != nil {
		t.Fatal(err)
	}
	wantLog(t, logs(), "local: memdev mem0 (serial 0x11): its region was being created, and it is a pool device now: forgetting it without "+
		"touching its regions [region1]")
	r := v.records()
	if r.Memdev(serialL) != nil || r.Region("region1") != nil || r.Grant(state.GrantRef{Claim: "l"}) != nil {
		t.Fatalf("records %+v", r)
	}
	if r.Memdev(serialB) == nil || r.Grant(state.GrantRef{Claim: "b"}) == nil {
		t.Fatalf("records of serial 0xb1 %+v", r)
	}
	if cmds := v.f.CommandsSince(before); cmds != "" {
		t.Fatalf("commands %q", cmds)
	}
	if rs := v.f.Kernel().Regions("mem0"); !slices.Equal(rs, []string{"region1"}) {
		t.Fatalf("regions of mem0 %v", rs)
	}
	if _, err := v.e.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rs := v.f.Kernel().Regions("mem0"); !slices.Equal(rs, []string{"region1"}) {
		t.Fatalf("regions of mem0 after the recovery %v", rs)
	}
	dropRaw(t, v, "region1")
	finish(t, v, "finished")
}

// The start releases the cut Prepares of local memdevs as the recovery
// cells say, with the line of each kind: a part released, a new shared
// region released, an established one kept idle, a persistent region
// released.
func TestLocalRecoverCutPrepares(t *testing.T) {
	shared := func(v *env) { v.configure(func(o *Options) { o.Shared = func(state.Serial) bool { return true } }) }
	realised := func(v *env) { cutWhenRealised(v, "c") }
	for _, c := range []struct {
		name    string
		specs   []fake.MemdevSpec
		setup   func(v *env)
		cut     func(v *env)
		req     GrantRequest
		line    string
		regions int
	}{
		{"sliced", []fake.MemdevSpec{{Serial: serialL, Ram: gib}}, nil, realised, sliceReq("c", 0, state.ModeNUMA, 256*mib),
			"local: memdev mem0 (serial 0x11): claim c is not prepared, releasing it", 0},
		{"shared new", []fake.MemdevSpec{{Serial: serialL, Ram: gib}}, shared, func(v *env) { v.cutZeroing(true) }, sharedReq("c"),
			"local: memdev mem0 (serial 0x11): claim c of the shared device is not prepared, dropping it", 0},
		{"shared established", []fake.MemdevSpec{{Serial: serialL, Ram: gib}}, func(v *env) {
			shared(v)
			v.mustPrepare(localDriver, "s", sharedReq("s"))
			v.mustUnprepare(localDriver, "s")
		}, realised, sharedReq("c"), "local: memdev mem0 (serial 0x11): claim c of the shared device is not prepared, dropping it", 1},
		{"persistent", []fake.MemdevSpec{{Serial: serialP, Pmem: gib}}, func(v *env) { v.formatPmem("mem0", "ext4") }, realised,
			localPmemReq("c", 0, state.ModeFs, true, ""), "local: memdev mem0 (serial 0x91): claim c of the persistent device is not prepared, dropping it", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := newEnv(t, c.specs...)
			if c.setup != nil {
				c.setup(v)
			}
			c.cut(v)
			if !v.cut(func() { _ = v.prepare(localDriver, "c", c.req) }) {
				t.Fatal("not cut")
			}
			logs := captureKlog(t)
			out := v.restart()
			if !slices.Equal(out.Released, []state.GrantRef{{Claim: "c"}}) || len(out.Kept) > 0 {
				t.Fatalf("recovered %+v", out)
			}
			wantLog(t, logs(), c.line, localDriver+": claim ns/c (c): released, its Prepare again prepares its devices anew")
			if rs := v.f.Kernel().Regions("mem0"); len(rs) != c.regions {
				t.Fatalf("regions %v", rs)
			}
			wantPreparation(t, v, localDriver, "c", state.PreparationPreparing)
			// kubelet's retry prepares anew
			v.mustPrepare(localDriver, "c", c.req)
			v.mustUnprepare(localDriver, "c")
			if c.name != "sliced" && c.name != "persistent" {
				releaseIdleShared(v)
			}
			v.clean("unprepared")
		})
	}
}

// A cut Prepare of a local persistent memdev after its namespace was made,
// whose block device something holds at the start: the recovery waits for
// the holder until the holder deadline and keeps the claim (KEPT) with its
// region; once nothing holds the block device, the Unprepare releases them.
func TestLocalRecoverHeldBlockDevice(t *testing.T) {
	const holder = 200 * time.Millisecond
	v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
	v.configure(func(o *Options) { o.Timeouts.Holder = holder })
	v.f.CutAfter("ndctl create-namespace")
	if !v.cut(func() { _ = v.prepare(localDriver, "b", localPmemReq("b", 0, state.ModeBlock, false, "")) }) {
		t.Fatal("not cut")
	}
	pmem := filepath.Join(v.f.DevRoot(), "pmem0")
	v.f.SetHolder(pmem, "dm-0")
	logs := captureKlog(t)
	start := time.Now()
	out := v.restart()
	took := time.Since(start)
	if !slices.Equal(out.Kept, []state.GrantRef{{Claim: "b"}}) || len(out.Released) > 0 {
		t.Fatalf("recovered %+v", out)
	}
	if took < holder || took > 10*holder {
		t.Fatalf("the start took %v, the holder deadline is %v", took, holder)
	}
	lines := logs()
	kept := logLine(lines, "claim ns/b (b): not everything was released at start (")
	if ok, err := compat.MatchesRegexp(compat.ObserverLogCountInUse, kept); err != nil || !ok {
		t.Fatalf("line %q does not match the observer's (%v) in\n%s", kept, err, lines)
	}
	wantLog(t, lines, localDriver+": device 0x91: "+pmem+" is held: in use")
	wantPreparation(t, v, localDriver, "b", state.PreparationKept)
	if g := v.grant("b", 0); g.Intent.Region != "region0" {
		t.Fatalf("grant %+v", g)
	}
	wantRegion(t, v, "region0", state.RegionOwned)
	if rs := v.f.Kernel().Regions("mem0"); !slices.Equal(rs, []string{"region0"}) {
		t.Fatalf("regions %v", rs)
	}
	// the holder is gone: the Unprepare releases the region
	v.f.SetHolder(pmem, "")
	logs = captureKlog(t)
	v.mustUnprepare(localDriver, "b")
	wantLog(t, logs(), "local: memdev mem0 (serial 0x91): released region0 in ")
	v.clean("unprepared")
}

// localBusyCompanionNextToReader prepares the fs claim r and the fs lease
// companion c on the node mount of the shared persistent local memdev
// serialP, then fails the Unprepare of c on its busy lease bind. It returns
// the node mount and the bind.
func localBusyCompanionNextToReader(t *testing.T, v *env) (string, string) {
	t.Helper()
	target := companionTarget(v)
	r := localPmemReq("r", 0, state.ModeFs, true, "")
	r.Facts.Shared = true
	c := localPmemReq("c", 0, state.ModeFs, true, "")
	c.Facts.Shared = true
	c.BindTarget = target
	c.Lend = &state.GrantLend{Lease: "0123abcd", Name: "data"}
	v.mustPrepare(localDriver, "r", r)
	v.mustPrepare(localDriver, "c", c)
	mnt := mountPathOf(v.records(), v.grant("c", 0))
	if mnt == "" || mnt != mountPathOf(v.records(), v.grant("r", 0)) {
		t.Fatalf("node mounts %q and %q, want one", mnt, mountPathOf(v.records(), v.grant("r", 0)))
	}
	v.f.SetBusy(target, true)
	if err := v.unprepare(localDriver, "c"); err == nil {
		t.Fatal("a busy unbind succeeded")
	}
	return mnt, target
}

// localPmemEnvShared returns a node with the persistent local memdev
// serialP, configured shared, of erofs.
func localPmemEnvShared(t *testing.T) *env {
	v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
	v.configure(func(o *Options) { o.Shared = func(state.Serial) bool { return true } })
	v.formatPmem("mem0", "erofs")
	return v
}

// A local companion whose Unprepare failed on its busy lease bind still uses
// its node mount: the Unprepare of another fs claim of the node mount keeps
// it; the Unprepare again of the companion unbinds and unmounts.
func TestLocalReleaseKeepsNodeMountOfBusyCompanion(t *testing.T) {
	v := localPmemEnvShared(t)
	mnt, target := localBusyCompanionNextToReader(t, v)
	v.mustUnprepare(localDriver, "r")
	v.mustBeMounted("after the Unprepare of r", mnt, target)
	v.f.SetBusy(target, false)
	v.mustUnprepare(localDriver, "c")
	v.mustNotBeMounted("after the Unprepare again of c", mnt, target)
}

// A start between the failed Unprepare of a local companion and its
// Unprepare again keeps the companion's node mount and bind.
func TestLocalRecoverKeepsNodeMountOfBusyCompanion(t *testing.T) {
	v := localPmemEnvShared(t)
	mnt, target := localBusyCompanionNextToReader(t, v)
	v.mustUnprepare(localDriver, "r")
	v.restart()
	v.mustBeMounted("after the start", mnt, target)
	v.f.SetBusy(target, false)
	v.mustUnprepare(localDriver, "c")
	v.mustNotBeMounted("after the Unprepare again of c", mnt, target)
}
