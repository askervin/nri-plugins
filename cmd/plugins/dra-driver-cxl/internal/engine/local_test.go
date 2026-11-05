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
	"fmt"
	"slices"
	"strings"
	"testing"

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
	if z := v.f.Zeroed(); len(z) != 1 || !strings.HasPrefix(z[0], fmt.Sprintf("%d:%d ", g.Got.DaxDev.Major, g.Got.DaxDev.Minor)) {
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
