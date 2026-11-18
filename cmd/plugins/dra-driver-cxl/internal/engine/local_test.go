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
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/klogtest"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// The parts of a local sliced memdev: the first one is daxN.0 of the region
// (its Whole device resized), the next ones new dax devices; numa parts
// online movable on the fenced node, dax parts device_dax and zeroed; the
// Unprepare of the last part destroys the region.
func TestLocalSliced(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
	v.mustPrepare(localDriver, "n1", localReq("n1", 0, serialL, state.ModeNUMA, state.KindExclusive, 256*mib))
	g := v.grant("n1", 0)
	if g.Got.Dax != "dax0.0" || state.NumaNodeOf(g.Got.NumaNode) != 2 || v.f.DaxDriver("dax0.0") != kernel.DriverKmem {
		t.Fatalf("numa part %+v", g.Got)
	}
	if !slices.Contains(v.fenced, 2) {
		t.Fatalf("fenced %v", v.fenced)
	}
	v.mustPrepare(localDriver, "d1", localReq("d1", 0, serialL, state.ModeDax, state.KindExclusive, 200*mib))
	g = v.grant("d1", 0)
	if g.Got.Dax != "dax0.1" || g.Got.Size != 256*mib || v.f.DaxDriver("dax0.1") != kernel.DriverDeviceDax {
		t.Fatalf("dax part %+v", g.Got)
	}
	if z := v.f.Zeroed(); len(z) != 1 || !strings.HasPrefix(z[0], fmt.Sprintf("%d:%d ", v.records().DaxDevOf(g).Major, v.records().DaxDevOf(g).Minor)) {
		t.Fatalf("zeroed %v", z)
	}
	v.mustUnprepare(localDriver, "n1")
	if d := v.records().Region("region0").DaxDevice("dax0.0"); d == nil || d.State != state.DaxSeed {
		t.Fatalf("dax0.0 after its part went: %+v", d)
	}
	// the seed is sized again for the next part
	v.mustPrepare(localDriver, "n2", localReq("n2", 0, serialL, state.ModeNUMA, state.KindExclusive, 128*mib))
	if g := v.grant("n2", 0); g.Got.Dax != "dax0.0" {
		t.Fatalf("part of the seed %+v", g.Got)
	}
	v.mustUnprepare(localDriver, "d1")
	v.mustUnprepare(localDriver, "n2")
	v.clean("unprepared")
	if strings.Contains(v.f.Commands(), "disable-memdev") {
		t.Fatal("a local memdev was disabled")
	}
}

// A local memdev configured shared: the Whole device of its region,
// device_dax and zeroed once, for every claim; it is kept while it is
// configured shared, released at the last claim otherwise.
func TestLocalShared(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
	shared := true
	v.e.opts.Shared = func(state.Serial) bool { return shared }
	v.mustPrepare(localDriver, "s1", localReq("s1", 0, serialL, state.ModeDax, state.KindShared, gib))
	v.mustPrepare(localDriver, "s2", localReq("s2", 0, serialL, state.ModeDax, state.KindShared, gib))
	if z := v.f.Zeroed(); len(z) != 1 {
		t.Fatalf("zeroed %v", z)
	}
	if d := v.records().Region("region0").DaxDevice("dax0.0"); !d.Whole || len(d.Users) != 2 || d.State != state.DaxDeviceDax {
		t.Fatalf("whole device %+v", d)
	}
	v.mustUnprepare(localDriver, "s1")
	v.mustUnprepare(localDriver, "s2")
	if m := v.records().Memdev(serialL); m == nil || m.State != state.MemdevIdleKept {
		t.Fatalf("memdev %+v", m)
	}
	v.check("idle shared")
	// configured shared again later: the kept region, not zeroed again
	v.mustPrepare(localDriver, "s3", localReq("s3", 0, serialL, state.ModeDax, state.KindShared, gib))
	if z := v.f.Zeroed(); len(z) != 1 {
		t.Fatalf("zeroed again %v", z)
	}
	shared = false
	v.mustUnprepare(localDriver, "s3")
	v.clean("not configured shared any more")
}

// A local grant on a pool serial is refused before anything is touched.
func TestLocalGuard(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	if err := v.st.Commit(context.Background(), 0, func(doc *storeDocument) error {
		doc.Provenance = append(doc.Provenance, state.Provenance{Serial: serialA, State: state.ProvenancePool})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := v.f.Commands()
	err := v.prepare(localDriver, "l1", localReq("l1", 0, serialA, state.ModeDax, state.KindExclusive, 256*mib))
	if err == nil || !strings.Contains(err.Error(), "pool device") {
		t.Fatalf("error %v", err)
	}
	if cmds := v.f.CommandsSince(before); cmds != "" {
		t.Fatalf("commands %q", cmds)
	}
	v.clean("refused")
}

// Parts of a region that does not start at a memory block boundary are
// placed on whole blocks: a part that first-fit put across a boundary is
// deleted (daxN.0 back to the seed) and made again through the mapping.
func TestLocalSlicesOnWholeBlocks(t *testing.T) {
	v := newEnv(t)
	v.f.SetBlockSize(512 * mib)
	v.f.Plug(fake.MemdevSpec{Serial: serialL, Ram: 4 * gib})
	v.mustPrepare(localDriver, "n1", localReq("n1", 0, serialL, state.ModeNUMA, state.KindExclusive, 512*mib))
	v.mustPrepare(localDriver, "n2", localReq("n2", 0, serialL, state.ModeDax, state.KindExclusive, 512*mib))
	for _, uid := range []string{"n1", "n2"} {
		g := v.grant(uid, 0)
		for _, r := range v.f.DaxRanges(g.Got.Dax) {
			if !r.Aligned(512 * mib) {
				t.Fatalf("%s: %s at %v", uid, g.Got.Dax, r)
			}
		}
	}
	v.mustUnprepare(localDriver, "n1")
	v.mustUnprepare(localDriver, "n2")
	v.clean("unprepared")
}

// A new part that first-fit put across a block boundary (another dax
// device took the memory before it) is deleted and placed on the first
// whole free blocks.
func TestLocalNewSliceMisplaced(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
	v.mustPrepare(localDriver, "n1", localReq("n1", 0, serialL, state.ModeDax, state.KindExclusive, 128*mib))
	k := v.f.Kernel()
	ctx := context.Background()
	stray, err := k.CreateDaxDevice(ctx, "region0", 64*mib)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.prepare(localDriver, "n2", localReq("n2", 0, serialL, state.ModeDax, state.KindExclusive, 128*mib)); err != nil {
		t.Fatal(err)
	}
	g := v.grant("n2", 0)
	for _, r := range v.f.DaxRanges(g.Got.Dax) {
		if !r.Aligned(128 * mib) {
			t.Fatalf("%s at %v", g.Got.Dax, r)
		}
	}
	if err := k.DeleteDaxDevice(ctx, "region0", stray); err != nil {
		t.Fatal(err)
	}
	v.check("placed")
	v.mustUnprepare(localDriver, "n2")
	v.mustUnprepare(localDriver, "n1")
	v.clean("unprepared")
}

// daxTrail records the states of the record of a dax device of a region
// after each commit of the engine of the node, one entry per change:
// "<state> whole|part users=<n> size=<kernel size>".
type daxTrail struct {
	region state.RegionRef
	dax    string
	steps  []string
}

// trail starts the trail of the dax device of the region on the engine of
// the node.
func (v *env) trail(region, dax string) *daxTrail {
	tr := &daxTrail{region: state.RegionRef(region), dax: dax}
	prev := v.e.afterCommit
	v.e.afterCommit = func() {
		step := "none"
		if reg := v.records().Region(tr.region); reg != nil {
			if d := reg.DaxDevice(tr.dax); d != nil {
				kind := "part"
				if d.Whole {
					kind = "whole"
				}
				step = fmt.Sprintf("%s %s users=%d size=%d", d.State, kind, len(d.Users), v.f.DaxSize(tr.dax))
			}
		}
		if n := len(tr.steps); n == 0 || tr.steps[n-1] != step {
			tr.steps = append(tr.steps, step)
		}
		prev()
	}
	return tr
}

// want fails the test unless the trail has the steps want in order, and
// starts it again.
func (tr *daxTrail) want(t *testing.T, want ...string) {
	t.Helper()
	i := 0
	for _, s := range tr.steps {
		if i < len(want) && s == want[i] {
			i++
		}
	}
	if i < len(want) {
		t.Fatalf("%s of %s: steps\n  %s\nwant in order\n  %s", tr.dax, tr.region, strings.Join(tr.steps, "\n  "), strings.Join(want, "\n  "))
	}
	tr.steps = nil
}

// The Whole device rows of the local paths, by the records after each
// commit: daxN.0 of a new region KMEM_OFFLINE, set up for device_dax
// (through SIZED) as the Whole device; the first part reuses it
// (DEVICE_DAX -> SIZED), its release makes it the seed (SEED), the next
// part sizes the seed again (SEED -> SIZED); the first device of a KEPT
// region that a cut resize left smaller is spanned again by its set-up.
func TestLocalWholeDeviceRows(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib}, fake.MemdevSpec{Serial: serialB})
	tr := v.trail("region0", "dax0.0")
	v.mustPrepare(localDriver, "d1", sliceReq("d1", 0, state.ModeDax, 256*mib))
	tr.want(t, "KMEM_OFFLINE whole users=0 size=1073741824", "DEVICE_DAX whole users=0 size=1073741824",
		"SIZED part users=1 size=268435456", "DEVICE_DAX part users=1 size=268435456")
	if reg := v.records().Region("region0"); !reg.SetUp || reg.WholeDevice() != nil {
		t.Fatalf("region %+v", reg)
	}
	v.mustPrepare(localDriver, "d2", sliceReq("d2", 0, state.ModeDax, 256*mib))
	v.mustUnprepare(localDriver, "d1")
	tr.want(t, "SEED part users=0 size=0")
	v.mustPrepare(localDriver, "n3", sliceReq("n3", 0, state.ModeNUMA, 256*mib))
	tr.want(t, "SIZED part users=1 size=268435456", "KMEM_OFFLINE part users=1 size=268435456", "KMEM_ONLINE part users=1 size=268435456")
	v.mustUnprepare(localDriver, "n3")
	v.mustUnprepare(localDriver, "d2")
	v.clean("unprepared")

	// a cut after the resize of the first part, below a newer region: KEPT
	// with daxN.0 smaller, unbound
	v.f.CutAfter("write bus/dax/devices/dax0.0/size")
	if !v.cut(func() { _ = v.prepare(localDriver, "k", sliceReq("k", 0, state.ModeDax, 256*mib)) }) {
		t.Fatal("not cut")
	}
	above := rawRegion(t, v, "mem1")
	if out := v.restart(); !slices.Equal(out.Kept, []state.GrantRef{{Claim: "k"}}) {
		t.Fatalf("recovered %+v", out)
	}
	wantRegion(t, v, "region0", state.RegionKept)
	if size, drv := v.f.DaxSize("dax0.0"), v.f.DaxDriver("dax0.0"); size != 256*mib || drv != "" {
		t.Fatalf("dax0.0 of %d bytes, driver %q", size, drv)
	}
	logs := klogtest.Capture(t, 3)
	tr = v.trail("region0", "dax0.0")
	v.mustPrepare(localDriver, "k", sliceReq("k", 0, state.ModeDax, 256*mib))
	tr.want(t, "DEVICE_DAX whole users=0 size=1073741824", "SIZED part users=1 size=268435456")
	wantLog(t, logs(), "engine: local memdev 0x11 (mem0): set up kept region0 (devdax, dax dax0.0, node 2) in ")
	dropRaw(t, v, above)
	v.mustUnprepare(localDriver, "k")
	v.clean("unprepared")
}

// The local grants of a release are released by the serial of their
// memdev, the last result of a claim on a memdev first; the others stay
// where they are.
func TestLocalOrder(t *testing.T) {
	r := &state.Records{}
	add := func(uid string, n int, serial state.Serial, source state.Source) state.GrantRef {
		ref := state.GrantRef{Claim: uid, Result: n}
		r.Grants = append(r.Grants, state.Grant{Ref: ref, Serial: serial, Asked: state.Asked{Source: source}})
		return ref
	}
	p0 := add("p", 0, serialA, state.SourcePool)
	c0 := add("c", 0, 0x22, state.SourceLocal)
	c1 := add("c", 1, serialL, state.SourceLocal)
	p1 := add("p", 1, serialB, state.SourcePool)
	c2 := add("c", 2, 0x22, state.SourceLocal)
	c3 := add("c", 3, serialL, state.SourceLocal)
	gone := state.GrantRef{Claim: "x"}
	got := localOrder(r, []state.GrantRef{p0, c0, c1, p1, gone, c2, c3})
	if want := []state.GrantRef{p0, c3, c1, p1, gone, c2, c0}; !slices.Equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}

// The release of a claim with parts on two local memdevs, by the kernel:
// the memdev of the lower serial first, the last part of a memdev first.
func TestLocalReleaseOrder(t *testing.T) {
	const serialM = 0x22
	v := newEnv(t, fake.MemdevSpec{Serial: serialM, Ram: gib, HostBridge: 24}, fake.MemdevSpec{Serial: serialL, Ram: gib})
	reqs := []GrantRequest{
		localReq("c", 0, serialM, state.ModeDax, state.KindExclusive, 256*mib),
		localReq("c", 1, serialL, state.ModeDax, state.KindExclusive, 256*mib),
		localReq("c", 2, serialM, state.ModeDax, state.KindExclusive, 256*mib),
		localReq("c", 3, serialL, state.ModeDax, state.KindExclusive, 256*mib),
	}
	v.mustPrepare(localDriver, "c", reqs...)
	part := func(n int) string {
		g := v.grant("c", n)
		return fmt.Sprintf("%s %s", g.Got.Region, g.Got.Dax)
	}
	parts := []string{part(3), part(1), part(2), part(0)}
	logs := klogtest.Capture(t, 3)
	before := v.f.Commands()
	v.mustUnprepare(localDriver, "c")
	var deleted []string
	for _, l := range linesWithPrefix(logs(), "engine: local memdev ") {
		if _, rest, ok := strings.Cut(l, ": claim c: deleted slice "); ok {
			dax, _, _ := strings.Cut(rest, " ")
			deleted = append(deleted, dax)
		}
	}
	var want []string
	for _, p := range parts {
		want = append(want, strings.Fields(p)[1])
	}
	if !slices.Equal(deleted, want) {
		t.Fatalf("deleted %v, want %v (parts %v)", deleted, want, parts)
	}
	// the region of the memdev of the lower serial first
	cmds := v.f.CommandsSince(before)
	regL, regM := strings.Fields(parts[0])[0], strings.Fields(parts[2])[0]
	if l, m := strings.Index(cmds, "destroy-region "+regL), strings.Index(cmds, "destroy-region "+regM); l < 0 || m < l {
		t.Fatalf("commands %s", cmds)
	}
	v.clean("unprepared")
}

// A local grant on a memdev that grants of other claims use in another way
// is refused before anything is touched, with the words of the refusal.
func TestLocalKindConflicts(t *testing.T) {
	sharedPmem := func(uid string, shared bool) GrantRequest {
		req := localPmemReq(uid, 0, state.ModeFs, true, "")
		req.Facts.Shared = shared
		return req
	}
	for _, c := range []struct {
		name  string
		spec  fake.MemdevSpec
		first GrantRequest
		req   GrantRequest
		want  string
	}{
		{"sliced on shared", fake.MemdevSpec{Serial: serialL, Ram: gib}, sharedReq("u1"), sliceReq("x", 0, state.ModeDax, 256*mib),
			"memdev mem0 (serial 0x11): used shared by claims [u1]; a sliced device cannot be shared"},
		{"shared on sliced", fake.MemdevSpec{Serial: serialL, Ram: gib}, sliceReq("n1", 0, state.ModeNUMA, 256*mib), sharedReq("x"),
			"memdev mem0 (serial 0x11): used as slices by claims [n1]; a shared device cannot be sliced"},
		{"sliced on persistent", fake.MemdevSpec{Serial: serialP, Pmem: gib}, sharedPmem("w", false),
			localReq("x", 0, serialP, state.ModeDax, state.KindExclusive, 256*mib),
			"memdev mem0 (serial 0x91): used as a persistent device by claims [w]; a sliced device cannot be a persistent device"},
		{"shared on persistent", fake.MemdevSpec{Serial: serialP, Pmem: gib}, sharedPmem("w", false),
			localReq("x", 0, serialP, state.ModeDax, state.KindShared, gib),
			"memdev mem0 (serial 0x91): used as a persistent device by claims [w]; a shared device cannot be a persistent device"},
		{"persistent on sliced", fake.MemdevSpec{Serial: serialL, Ram: gib}, sliceReq("n1", 0, state.ModeNUMA, 256*mib),
			localReq("x", 0, serialL, state.ModeBlock, state.KindPersistent, 0),
			"memdev mem0 (serial 0x11): used as slices by claims [n1]; a persistent device cannot be used so"},
		{"persistent on shared", fake.MemdevSpec{Serial: serialL, Ram: gib}, sharedReq("u1"),
			localReq("x", 0, serialL, state.ModeBlock, state.KindPersistent, 0),
			"memdev mem0 (serial 0x11): used shared by claims [u1]; a persistent device cannot be used so"},
		{"unshared on shared persistent", fake.MemdevSpec{Serial: serialP, Pmem: gib}, sharedPmem("w", true), sharedPmem("x", false),
			"memdev mem0 (serial 0x91): used as a shared persistent device by claims [w]; it is not shared now (sharedDevices)"},
		{"shared on unshared persistent", fake.MemdevSpec{Serial: serialP, Pmem: gib}, sharedPmem("w", false), sharedPmem("x", true),
			"memdev mem0 (serial 0x91): used as a not shared persistent device by claims [w]; it is shared now (sharedDevices)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := newEnv(t, c.spec)
			v.configure(func(o *Options) { o.Shared = func(state.Serial) bool { return true } })
			if c.spec.Pmem > 0 {
				v.formatPmem("mem0", "ext4")
			}
			v.mustPrepare(localDriver, c.first.Ref.Claim, c.first)
			before := v.f.Commands()
			gen := v.st.Snapshot().Generation
			_, err := v.e.PrepareGrants(context.Background(), []GrantRequest{c.req})
			var kind *localKindError
			if !errors.As(err, &kind) || err.Error() != c.want {
				t.Fatalf("error %v, want %q", err, c.want)
			}
			if cmds := v.f.CommandsSince(before); cmds != "" || v.st.Snapshot().Generation != gen {
				t.Fatalf("commands %q, generation %d -> %d", cmds, gen, v.st.Snapshot().Generation)
			}
			v.check("refused")
			v.mustUnprepare(localDriver, c.first.Ref.Claim)
			releaseIdleShared(v)
			v.clean("unprepared")
		})
	}
}

// A local memdev that no grant uses but whose region is of another kind
// (an idle shared one) is released first, its record dropped, for a grant
// of another kind.
func TestLocalKindIdleReleasedFirst(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
	v.configure(func(o *Options) { o.Shared = func(state.Serial) bool { return true } })
	v.mustPrepare(localDriver, "s", sharedReq("s"))
	v.mustUnprepare(localDriver, "s")
	if m := v.records().Memdev(serialL); m == nil || m.State != state.MemdevIdleKept {
		t.Fatalf("memdev %+v", m)
	}
	logs := klogtest.Capture(t, 3)
	v.mustPrepare(localDriver, "n", sliceReq("n", 0, state.ModeDax, 256*mib))
	out := logs()
	wantLog(t, out, "engine: local memdev 0x11 (mem0): released region0 in ", "engine: local memdev 0x11 (mem0): created region0 ")
	if i, j := strings.Index(out, "released region0 in "), strings.Index(out, "created region0 "); j < i {
		t.Fatalf("the region was not released first:\n%s", out)
	}
	if m := v.records().Memdev(serialL); m.Facts.Shared || m.State != state.MemdevActive {
		t.Fatalf("memdev %+v", m)
	}
	if z := v.f.Zeroed(); len(z) != 2 {
		t.Fatalf("zeroed %v", z)
	}
	v.mustUnprepare(localDriver, "n")
	v.clean("unprepared")
}

// stepTime is the time of a step in a log line.
var stepTime = regexp.MustCompile(`in [0-9]+\.[0-9]+ms`)

// wantMessages fails the test unless every wanted line is a message of the
// log; "in <t>" in a wanted line stands for the time of a step.
func wantMessages(t *testing.T, logs string, want ...string) {
	t.Helper()
	var msgs []string
	for _, l := range strings.Split(logs, "\n") {
		if _, msg, ok := strings.Cut(l, "] "); ok {
			msgs = append(msgs, stepTime.ReplaceAllString(msg, "in <t>"))
		}
	}
	for _, w := range want {
		if !slices.Contains(msgs, w) {
			t.Errorf("no %q in\n  %s", w, strings.Join(msgs, "\n  "))
		}
	}
}

// The log lines of the local grants, as the documentation quotes them:
// the region created, the parts created, zeroed, onlined (the rounded
// size), offlined and deleted, the region released; a shared device zeroed
// once, released with the claims left and kept idle; a persistent device
// released with the claims left, kept at a start and kept idle below a
// newer region.
func TestLocalLogLines(t *testing.T) {
	const memdev = "engine: local memdev 0x11 (mem0): "
	t.Run("sliced", func(t *testing.T) {
		v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
		logs := klogtest.Capture(t, 3)
		v.mustPrepare(localDriver, "d", sliceReq("d", 0, state.ModeDax, 128*mib))
		v.mustPrepare(localDriver, "n", sliceReq("n", 0, state.ModeNUMA, 100*mib))
		v.mustUnprepare(localDriver, "n")
		v.mustUnprepare(localDriver, "d")
		out := logs()
		wantMessages(t, out,
			memdev+"created region0 (devdax, dax dax0.0, node 2) in <t>",
			memdev+"released region0 in <t>",
			memdev+"claim d: zeroed slice dax0.0 mode dax size 134217728 in <t>",
			memdev+"claim d: created slice dax0.0 mode dax size 134217728 at [0x250000000-0x257ffffff] in <t>",
			memdev+"claim d: deleted slice dax0.0 mode dax size 134217728 in <t>",
			memdev+"claim n: created slice dax0.1 mode numa size 134217728 at [0x258000000-0x25fffffff] in <t>",
			memdev+"claim n: onlined slice dax0.1 mode numa size 134217728 blocks [75] node 2 in <t>",
			memdev+"claim n: offlined slice dax0.1 mode numa size 134217728 blocks [75] in <t>",
			memdev+"claim n: deleted slice dax0.1 mode numa size 134217728 in <t>",
			memdev+"claim n: slice of 104857600 bytes rounded up to 134217728 (memory block size 134217728, align 2097152)")
	})
	t.Run("shared", func(t *testing.T) {
		v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
		v.configure(func(o *Options) { o.Shared = func(state.Serial) bool { return true } })
		logs := klogtest.Capture(t, 3)
		v.mustPrepare(localDriver, "s1", sharedReq("s1"))
		v.mustPrepare(localDriver, "s2", sharedReq("s2"))
		v.mustUnprepare(localDriver, "s1")
		v.mustUnprepare(localDriver, "s2")
		out := logs()
		wantMessages(t, out,
			memdev+"zeroed new shared dax0.0 size 1073741824 in <t>",
			memdev+"keeping region0 and dax0.0 of the idle shared device",
			memdev+"claim s1: released shared dax0.0, claims left [s2]",
			memdev+"claim s2: released shared dax0.0, claims left []")
		if n := strings.Count(out, "zeroed new shared "); n != 1 {
			t.Errorf("%d lines of the zeroing", n)
		}
		releaseIdleShared(v)
		v.clean("released")
	})
	t.Run("persistent", func(t *testing.T) {
		v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib}, fake.MemdevSpec{Serial: serialB})
		v.formatPmem("mem0", "ext4")
		pmem := filepath.Join(v.f.DevRoot(), "pmem0")
		const memdev = "engine: local memdev 0x91 (mem0): "
		logs := klogtest.Capture(t, 3)
		v.mustPrepare(localDriver, "w", localPmemReq("w", 0, state.ModeFs, false, ""))
		v.mustPrepare(localDriver, "r", localPmemReq("r", 0, state.ModeFs, true, ""))
		v.mustUnprepare(localDriver, "w")
		v.restart()
		above := rawRegion(t, v, "mem1")
		v.mustUnprepare(localDriver, "r")
		out := logs()
		wantMessages(t, out,
			memdev+"claim w: released persistent "+pmem+", claims left [r]",
			memdev+"keeping persistent region0, claims [r]",
			memdev+"keeping region0 of the idle persistent device: region1 lie above it, its release would leave a hole in the decoders of their ports")
		if strings.Contains(out, "claim r: released persistent") {
			t.Errorf("the release of the last claim says the claims left:\n%s", out)
		}
		dropRaw(t, v, above)
		v.restart()
		v.clean("released")
	})
	t.Run("persistent region created", func(t *testing.T) {
		v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
		v.formatPmem("mem0", "ext4")
		logs := klogtest.Capture(t, 3)
		v.mustPrepare(localDriver, "w", localPmemReq("w", 0, state.ModeFs, false, ""))
		wantMessages(t, logs(), "engine: local memdev 0x91 (mem0): created region0 (pmem, nvdimm region0) in <t>")
		v.mustUnprepare(localDriver, "w")
		v.clean("unprepared")
	})
}

// Timeouts.LocalSettle bounds the wait of a local grant for the kernel to
// set up its region (the nd region of a pmem region, the dax device of a
// ram region bound to its driver); a pool grant waits for Timeouts.Settle.
func TestLocalSettle(t *testing.T) {
	t.Run("pmem", func(t *testing.T) {
		v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
		v.formatPmem("mem0", "ext4")
		v.configure(func(o *Options) { o.Timeouts.LocalSettle = 50 * time.Millisecond })
		if got := v.e.opts.Timeouts; got.LocalSettle != 50*time.Millisecond || got.Settle != 5*time.Second {
			t.Fatalf("timeouts %+v", got)
		}
		v.f.PmemDelay = 200 * time.Millisecond
		start := time.Now()
		err := v.prepare(localDriver, "w", localPmemReq("w", 0, state.ModeFs, false, ""))
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
			t.Fatalf("error %v after %v", err, time.Since(start))
		}
		v.f.PmemDelay = 0
		v.check("rolled back")
		v.clean("rolled back")
		// the pool grant of the same device waits longer
		v.f.PmemDelay = 100 * time.Millisecond
		v.mustPrepare(poolDriver, "p", fsGrant("p", false, ""))
		v.mustUnprepare(poolDriver, "p")
		v.clean("unprepared")
	})
	t.Run("ram", func(t *testing.T) {
		v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib}, fake.MemdevSpec{Serial: serialA})
		v.configure(func(o *Options) { o.Timeouts.LocalSettle = 50 * time.Millisecond })
		// the kernel binds daxN.0 of a new ram region to kmem after cxl
		// create-region returns: its driver link is removed then, and made
		// again by bind
		const link = "bus/dax/devices/dax0.0/driver"
		bind := func() { v.f.LinkTo(link, "bus/dax/drivers/kmem") }
		v.f.After("cxl create-region", func() {
			v.f.Remove(link)
			// bound when the rollback releases the region
			v.f.Before("cxl disable-region", bind)
		})
		start := time.Now()
		err := v.prepare(localDriver, "n", sliceReq("n", 0, state.ModeNUMA, 256*mib))
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "no dax device bound to a driver appeared in region0") ||
			time.Since(start) > 2*time.Second {
			t.Fatalf("error %v after %v", err, time.Since(start))
		}
		v.check("rolled back")
		v.clean("rolled back")
		// the pool grant waits longer: bound after 100 ms
		v.f.After("cxl create-region", func() {
			v.f.Remove(link)
			time.AfterFunc(100*time.Millisecond, bind)
		})
		start = time.Now()
		v.mustPrepare(poolDriver, "p", poolReq("p", 0, serialA, state.ModeNUMA, state.KindExclusive))
		if took := time.Since(start); took < 100*time.Millisecond {
			t.Fatalf("the pool grant was prepared in %v, before its dax device was bound", took)
		}
		v.mustUnprepare(poolDriver, "p")
		v.clean("unprepared")
	})
}

// The numa part of a companion claim that a process stop cut is kept at
// the start; the Prepare again reuses it when it went online (the same dax
// device and node, no second part), and deletes it for a new part when it
// did not.
func TestLocalCutCompanionPart(t *testing.T) {
	companion := func() GrantRequest {
		req := sliceReq("comp", 0, state.ModeNUMA, 256*mib)
		req.Lend = &state.GrantLend{Lease: "0123abcd", Container: "c"}
		return req
	}
	ref := state.GrantRef{Claim: "comp"}
	t.Run("online", func(t *testing.T) {
		v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
		v.mustPrepare(localDriver, "n", sliceReq("n", 0, state.ModeDax, 256*mib))
		v.e.afterCommit = func() {
			r := v.records()
			if g := r.Grant(ref); g != nil && g.Got.Dax != "" {
				if d := r.Region(g.Got.Region).DaxDevice(g.Got.Dax); d != nil && d.State == state.DaxKmemOnline {
					panic(fake.ErrCut)
				}
			}
		}
		if !v.cut(func() { _ = v.prepare(localDriver, "comp", companion()) }) {
			t.Fatal("not cut")
		}
		v.restart()
		v.mustKeepCut(ref.Claim)
		dax := v.grant("comp", 0).Got.Dax
		devices := v.f.Kernel().DaxDevices("region0")
		logs := klogtest.Capture(t, 3)
		v.mustPrepare(localDriver, "comp", companion())
		g := v.grant("comp", 0)
		if g.Got.Dax != dax || state.NumaNodeOf(g.Got.NumaNode) != 2 || g.State != state.GrantRealised {
			t.Fatalf("grant %+v, the part was %s", g, dax)
		}
		if got := v.f.Kernel().DaxDevices("region0"); !slices.Equal(got, devices) {
			t.Fatalf("dax devices %v, were %v", got, devices)
		}
		if out := logs(); strings.Contains(out, "claim comp: created slice") || strings.Contains(out, "claim comp: deleted slice") {
			t.Fatalf("a second part:\n%s", out)
		}
		v.mustUnprepare(localDriver, "comp")
		v.mustUnprepare(localDriver, "n")
		v.clean("unprepared")
	})
	t.Run("not online", func(t *testing.T) {
		v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
		v.mustPrepare(localDriver, "n", sliceReq("n", 0, state.ModeDax, 256*mib))
		v.f.CutAfter("write bus/dax/drivers/kmem/bind")
		if !v.cut(func() { _ = v.prepare(localDriver, "comp", companion()) }) {
			t.Fatal("not cut")
		}
		v.restart()
		v.mustKeepCut(ref.Claim)
		dax := v.grant("comp", 0).Got.Dax
		if dax == "" || v.f.DaxDriver(dax) != kernel.DriverKmem {
			t.Fatalf("the cut part %q (%s)", dax, v.f.DaxDriver(dax))
		}
		logs := klogtest.Capture(t, 3)
		v.mustPrepare(localDriver, "comp", companion())
		out2 := logs()
		deleted, created := strings.Index(out2, "claim comp: deleted slice "+dax+" "), strings.Index(out2, "claim comp: created slice ")
		if deleted < 0 || created < deleted {
			t.Fatalf("the cut part is not deleted before a new one:\n%s", out2)
		}
		if g := v.grant("comp", 0); v.f.DaxDriver(g.Got.Dax) != kernel.DriverKmem || g.State != state.GrantRealised {
			t.Fatalf("grant %+v", g)
		}
		v.mustUnprepare(localDriver, "comp")
		v.mustUnprepare(localDriver, "n")
		v.clean("unprepared")
	})
}

// A numa companion whose Prepare a process stop cut before its region was
// made (the start kept it) holds no region: the region that another claim
// of the memdev makes goes with that claim, cut or unprepared.
func TestLocalCutCompanionHoldsNoNewRegion(t *testing.T) {
	for _, cut := range []bool{true, false} {
		t.Run(map[bool]string{true: "cut", false: "unprepared"}[cut], func(t *testing.T) {
			v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
			req := sliceReq("comp", 0, state.ModeNUMA, 256*mib)
			req.Lend = &state.GrantLend{Lease: "0123abcd", Container: "c"}
			v.f.CutBefore("cxl create-region")
			if !v.cut(func() { _ = v.prepare(localDriver, "comp", req) }) {
				t.Fatal("not cut")
			}
			v.restart()
			v.mustKeepCut("comp")
			if cut {
				v.f.CutAfter("cxl create-region")
				if !v.cut(func() { _ = v.prepare(localDriver, "n", sliceReq("n", 0, state.ModeDax, 256*mib)) }) {
					t.Fatal("not cut")
				}
				v.restart()
			} else {
				v.mustPrepare(localDriver, "n", sliceReq("n", 0, state.ModeDax, 256*mib))
				v.mustUnprepare(localDriver, "n")
			}
			if regions := v.f.Kernel().Regions(v.f.Memdev(serialL)); len(regions) > 0 {
				t.Fatalf("regions left %v", regions)
			}
			v.mustUnprepare(localDriver, "n")
			v.mustUnprepare(localDriver, "comp")
			v.clean("unprepared")
		})
	}
}

// The Unprepare of a numa companion whose Prepare a process stop cut after
// its region was made, or set up, before it got its part (the start kept
// it) fails: the region's whole dax device counts as used by the releasing
// grant, whether a record names it yet (set up, cxl destroy-region fails)
// or not (made, cxl disable-region fails), and the retry releases
// everything.
func TestLocalCutCompanionRegionReleaseFails(t *testing.T) {
	for _, setUp := range []bool{false, true} {
		t.Run(map[bool]string{false: "made", true: "set up"}[setUp], func(t *testing.T) {
			v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
			req := sliceReq("comp", 0, state.ModeNUMA, 256*mib)
			req.Lend = &state.GrantLend{Lease: "0123abcd", Container: "c"}
			if setUp {
				v.e.afterCommit = func() {
					if reg := v.records().Region("region0"); reg != nil && reg.SetUp {
						panic(fake.ErrCut)
					}
				}
			} else {
				v.f.CutAfter("cxl create-region")
			}
			if !v.cut(func() { _ = v.prepare(localDriver, "comp", req) }) {
				t.Fatal("not cut")
			}
			v.restart()
			v.mustKeepCut("comp")
			v.f.FailCommand(map[bool]string{false: "cxl disable-region", true: "cxl destroy-region"}[setUp], errors.New("failed"))
			if err := v.unprepare(localDriver, "comp"); err == nil {
				t.Fatal("the release did not fail")
			}
			v.check("the release failed")
			v.mustUnprepare(localDriver, "comp")
			v.clean("unprepared")
		})
	}
}

// A numa companion whose Prepare enabled again a region that a failed
// release left disabled and a process stop cut before its set-up (the
// start kept it): the region's whole dax device, recorded as the seed,
// counts as used.
func TestLocalCutCompanionEnabledRegion(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
	v.mustPrepare(localDriver, "n", sliceReq("n", 0, state.ModeNUMA, 256*mib))
	v.f.FailCommand("cxl destroy-region", errors.New("failed"))
	if err := v.unprepare(localDriver, "n"); err == nil {
		t.Fatal("the release did not fail")
	}
	req := sliceReq("comp", 0, state.ModeNUMA, 256*mib)
	req.Lend = &state.GrantLend{Lease: "0123abcd", Container: "c"}
	v.e.afterCommit = func() {
		r := v.records()
		if reg := r.Region("region0"); reg != nil && reg.State == state.RegionOwned && !reg.SetUp && r.Grant(state.GrantRef{Claim: "comp"}) != nil {
			panic(fake.ErrCut)
		}
	}
	if !v.cut(func() { _ = v.prepare(localDriver, "comp", req) }) {
		t.Fatal("not cut")
	}
	v.restart()
	v.mustKeepCut("comp")
	v.mustUnprepare(localDriver, "comp")
	v.mustUnprepare(localDriver, "n")
	v.clean("unprepared")
}

// The Unprepare of a numa companion whose Prepare a process stop cut while
// it made its part next to another claim's (the start kept it, its dax
// device CREATING) rolls that part back and releases everything.
func TestLocalCutCompanionCreatingPart(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib})
	v.mustPrepare(localDriver, "n", sliceReq("n", 0, state.ModeDax, 256*mib))
	req := sliceReq("comp", 0, state.ModeNUMA, 256*mib)
	req.Lend = &state.GrantLend{Lease: "0123abcd", Container: "c"}
	v.e.afterCommit = func() {
		for _, reg := range v.records().Regions {
			for _, d := range reg.DaxDevices {
				if d.State == state.DaxCreating {
					panic(fake.ErrCut)
				}
			}
		}
	}
	if !v.cut(func() { _ = v.prepare(localDriver, "comp", req) }) {
		t.Fatal("not cut")
	}
	v.restart()
	v.mustKeepCut("comp")
	v.mustUnprepare(localDriver, "comp")
	v.mustUnprepare(localDriver, "n")
	v.clean("unprepared")
}
