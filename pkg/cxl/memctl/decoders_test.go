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

package memctl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	cxlRootPath = "devices/platform/ACPI0017:00/root0"
	hbPortPath  = cxlRootPath + "/port2"    // host bridge pci0000:0c
	swPortPath  = hbPortPath + "/port3"     // switch 0000:0d:00.0
	ep6Path     = swPortPath + "/endpoint6" // endpoint of mem2
	mem2Path    = "devices/pci0000:0c/0000:0c:00.0/0000:0d:00.0/0000:0e:02.0/0000:11:00.0/mem2"
)

// portDecoders writes the decoders of a port: regions[i] is the region of
// decoderP.i ("" none), committed is the port's decoders_committed.
func (f *fakeSys) portDecoders(path string, id string, committed int, regions ...string) {
	f.write(path+"/decoders_committed", itoa(committed))
	for i, r := range regions {
		f.write(path+"/decoder"+id+"."+itoa(i)+"/region", r)
	}
	f.link("bus/cxl/devices/port"+id, "../../../"+path)
}

// holeSys is VM0 of bug-02 after an out-of-order release: regions 0, 2 and
// 3 on decoders 0-2 of the host bridge and the switch, region2 destroyed,
// and mem2 (whose region it was) still there, without a region.
func holeSys(t *testing.T, hole bool) *fakeSys {
	f := newFakeSys(t)
	mid := "region2"
	if hole {
		mid = ""
	}
	f.portDecoders(hbPortPath, "2", 3, "region0", mid, "region3", "")
	f.portDecoders(swPortPath, "3", 3, "region0", mid, "region3", "")
	f.write(mem2Path+"/serial", "0xc1ee9003")
	f.link("bus/cxl/devices/mem2", "../../../"+mem2Path)
	f.link(mem2Path+"/driver", "../../../../../../../bus/cxl/drivers/cxl_mem")
	f.write(ep6Path+"/decoders_committed", "0")
	f.write(ep6Path+"/decoder6.0/region", "")
	f.link(ep6Path+"/uport", "../../../../../../"+mem2Path)
	f.link("bus/cxl/devices/endpoint6", "../../../"+ep6Path)
	return f
}

func TestDecoderHoles(t *testing.T) {
	f := holeSys(t, true)
	got := f.manager().DecoderHoles("mem2")
	want := []DecoderHole{
		{Port: "port2", Committed: 3, Free: []string{"decoder2.1"}, Blocking: []string{"region3"}},
		{Port: "port3", Committed: 3, Free: []string{"decoder3.1"}, Blocking: []string{"region3"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DecoderHoles(mem2) = %+v, want %+v", got, want)
	}
	if got := got[1].String(); got != "port3 has 3 committed decoders, decoder3.1 without a region below region3" {
		t.Errorf("String() = %q", got)
	}

	// In order (nothing released, or the top one: the kernel reaps it and
	// decoders_committed drops): no hole.
	if got := holeSys(t, false).manager().DecoderHoles("mem2"); got != nil {
		t.Errorf("in-order decoders: DecoderHoles = %+v, want none", got)
	}
	// No endpoint: no hole.
	if got := f.manager().DecoderHoles("mem9"); got != nil {
		t.Errorf("unknown memdev: DecoderHoles = %+v, want none", got)
	}
}

// TestRegionsAbove: the regions of other memdevs above those of a memdev
// in its ports (bug-02's VM0 before the release: region2 of mem2 between
// region0 and region3), none when its region is the top one or it has
// none.
func TestRegionsAbove(t *testing.T) {
	for _, tc := range []struct {
		name, region string
		want         []string
	}{
		{"middle", "region2", []string{"region3"}},
		{"bottom", "region0", []string{"region2", "region3"}},
		{"top", "region3", nil},
		{"no region", "", nil},
	} {
		f := holeSys(t, false)
		if tc.region != "" {
			f.write("bus/cxl/devices/"+tc.region+"/target0", "decoder6.0")
		}
		if got := f.manager().RegionsAbove("mem2"); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: RegionsAbove(mem2) = %v, want %v", tc.name, got, tc.want)
		}
	}
	// a hole above the memdev's region is no region
	f := holeSys(t, true)
	f.write("bus/cxl/devices/region0/target0", "decoder6.0")
	if got := f.manager().RegionsAbove("mem2"); !reflect.DeepEqual(got, []string{"region3"}) {
		t.Errorf("below a hole: RegionsAbove(mem2) = %v, want [region3]", got)
	}
	if got := f.manager().RegionsAbove("mem9"); got != nil {
		t.Errorf("unknown memdev: RegionsAbove = %v, want none", got)
	}
}

func TestCreateRegionExplainsDecoderHole(t *testing.T) {
	for _, hole := range []bool{true, false} {
		f := holeSys(t, hole)
		ebusy := errors.New("cxl create-region -t ram -d decoder0.0 -m mem2: exit status 1: cxl region: create_region: region2: failed to set target0 to mem2")
		g := f.manager()
		g.Exec = func(ctx context.Context, name string, args ...string) (string, error) {
			if name == "cxl" && args[0] == "create-region" {
				return "", ebusy
			}
			return f.exec(ctx, name, args...)
		}
		_, err := g.CreateRegion(context.Background(), "mem2", ModeDax, "decoder0.0")
		if !errors.Is(err, ebusy) {
			t.Fatalf("hole %v: CreateRegion error %v, want it to wrap %v", hole, err, ebusy)
		}
		explained := strings.Contains(err.Error(), "released out of order")
		if explained != hole {
			t.Errorf("hole %v: error %q explains a hole: %v", hole, err, explained)
		}
		if hole && !strings.Contains(err.Error(), "port2 has 3 committed decoders, decoder2.1 without a region below region3; port3 has") ||
			hole && !strings.HasSuffix(err.Error(), "until region3 is destroyed)") {
			t.Errorf("hole: error %q", err)
		}
	}
}

// hollowRegion makes region<id> under root decoder decoder0.1 as the e2e
// VMs of plan-13 bug-12 show it after its memdev was removed: commit 0,
// target0 empty, its address range kept.
func (f *fakeSys) hollowRegion(id string) {
	dir := "bus/cxl/devices/decoder0.1/region" + id
	for file, value := range map[string]string{
		"commit": "0", "devtype": "cxl_region", "interleave_ways": "1", "mode": "pmem",
		"resource": "0x85" + id + "0000000", "size": "0x10000000", "target0": "", "uuid": "675e71d7-179f-4beb-ab43-55f82e02b39" + id,
	} {
		f.write(dir+"/"+file, value)
	}
	f.link("bus/cxl/devices/region"+id, "decoder0.1/region"+id)
}

// deleteRegionWrites makes the manager's writes of delete_region do what
// the kernel does, and records them.
func (f *fakeSys) deleteRegionWrites(g *Manager, deleted *[]string) {
	g.WriteFile = func(path, val string) error {
		if filepath.Base(path) != "delete_region" {
			return f.writeAttr(path, val)
		}
		decoder := filepath.Base(filepath.Dir(path))
		*deleted = append(*deleted, decoder+" "+val)
		if _, err := os.Stat(f.p("bus/cxl/devices/" + decoder + "/" + val)); err != nil {
			return syscall.ENODEV
		}
		_ = os.RemoveAll(f.p("bus/cxl/devices/" + decoder + "/" + val))
		_ = os.Remove(f.p("bus/cxl/devices/" + val))
		return nil
	}
}

func TestHollowRegion(t *testing.T) {
	f := newFakeSys(t)
	f.hollowRegion("1")
	f.hollowRegion("2")
	f.write("bus/cxl/devices/decoder0.1/region2/target0", "decoder4.0") // set up
	g := f.manager()
	var deleted []string
	f.deleteRegionWrites(g, &deleted)

	if !g.HollowRegion("region1") || g.HollowRegion("region2") || g.HollowRegion("region9") {
		t.Fatalf("hollow: region1 %v, region2 %v, region9 %v", g.HollowRegion("region1"), g.HollowRegion("region2"), g.HollowRegion("region9"))
	}
	if d, err := g.RegionRootDecoder("region1"); err != nil || d != "decoder0.1" {
		t.Fatalf("root decoder of region1: %q %v", d, err)
	}
	// committed: not hollow
	f.write("bus/cxl/devices/decoder0.1/region1/commit", "1")
	if g.HollowRegion("region1") {
		t.Fatal("a committed region is hollow")
	}
	f.write("bus/cxl/devices/decoder0.1/region1/commit", "0")

	// a region with a target is not deleted, nor one that is not under a
	// root decoder
	if err := g.DeleteHollowRegion("region2"); err == nil || !strings.Contains(err.Error(), "not hollow") {
		t.Fatalf("delete of region2: %v", err)
	}
	f.write("bus/cxl/devices/region3/commit", "0")
	f.write("bus/cxl/devices/region3/target0", "")
	if err := g.DeleteHollowRegion("region3"); err == nil || !strings.Contains(err.Error(), "not a root decoder") {
		t.Fatalf("delete of region3: %v", err)
	}
	if len(deleted) != 0 {
		t.Fatalf("deleted %v", deleted)
	}

	// cxl destroy-region cannot remove it, delete_region can
	if err := g.DeleteHollowRegion("region1"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(deleted, []string{"decoder0.1 region1"}) || g.HollowRegion("region1") {
		t.Fatalf("deleted %v", deleted)
	}
	// gone: not an error
	if err := g.DeleteHollowRegion("region1"); err != nil || len(deleted) != 1 {
		t.Fatalf("delete of a gone region: %v, deleted %v", err, deleted)
	}

	// a region that a creation of the process is setting up (it holds
	// the lock) is looked at after the creation: it has its target then
	f.hollowRegion("4")
	regionCreateMu.Lock()
	done := make(chan error, 1)
	go func() { done <- g.DeleteHollowRegion("region4") }()
	time.Sleep(20 * time.Millisecond)
	f.write("bus/cxl/devices/decoder0.1/region4/target0", "decoder4.0")
	regionCreateMu.Unlock()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "not hollow") {
		t.Fatalf("delete of a region being set up: %v", err)
	}

	// a hollow region over memory blocks that are online is kept
	f.hollowRegion("5")
	f.write("bus/cxl/devices/decoder0.1/region5/resource", "0x250000000")
	f.write("devices/system/memory/memory75/state", "online")
	if err := g.DeleteHollowRegion("region5"); err == nil || !strings.Contains(err.Error(), "memory blocks [75] of its address range are not offline") {
		t.Fatalf("delete of a region with online memory: %v", err)
	}
	f.write("devices/system/memory/memory75/state", "offline")
	if err := g.DeleteHollowRegion("region5"); err != nil || len(deleted) != 2 {
		t.Fatalf("delete of region5: %v, deleted %v", err, deleted)
	}
	// a region without an address range yet (resource all ones, size 0)
	f.hollowRegion("6")
	f.write("bus/cxl/devices/decoder0.1/region6/resource", "0xffffffffffffffff")
	f.write("bus/cxl/devices/decoder0.1/region6/size", "0x0")
	if err := g.DeleteHollowRegion("region6"); err != nil || len(deleted) != 3 {
		t.Fatalf("delete of region6: %v, deleted %v", err, deleted)
	}
}

// The name of the next region of the root decoder is noted before cxl
// create-region runs, under the creation lock, and the name it created
// after it; an error of the first note creates nothing.
func TestCreateRegionNoted(t *testing.T) {
	f := newFakeSys(t)
	f.plug("0xc1ee0001")
	f.write("bus/cxl/devices/decoder0.0/create_ram_region", "region0")
	g := f.manager()
	var notes []string
	note := func(region, decoder string, created bool) error {
		if regionCreateMu.TryLock() {
			regionCreateMu.Unlock()
			if !created {
				t.Error("the note before the creation without the lock")
			}
		}
		notes = append(notes, fmt.Sprintf("%s %s %v", region, decoder, created))
		return nil
	}
	if _, err := g.CreateRegionNoted(context.Background(), "mem0", ModeDax, "", 0, note); err != nil {
		t.Fatal(err)
	}
	if want := []string{"region0 decoder0.0 false", "region0 decoder0.0 true"}; !reflect.DeepEqual(notes, want) {
		t.Fatalf("notes %q, expected %q", notes, want)
	}
	// a region that exists is reused without a note
	notes = nil
	if _, err := g.CreateRegionNoted(context.Background(), "mem0", ModeDax, "", 0, note); err != nil || notes != nil {
		t.Fatalf("reuse: %v, notes %q", err, notes)
	}
	// a note that fails: no create-region
	if err := g.Release(context.Background(), "mem0"); err != nil {
		t.Fatal(err)
	}
	ncmds := strings.Count(f.commands(), "create-region")
	_, err := g.CreateRegionNoted(context.Background(), "mem0", ModeDax, "", 0, func(string, string, bool) error { return errors.New("no room") })
	if err == nil || err.Error() != "no room" || strings.Count(f.commands(), "create-region") != ncmds {
		t.Fatalf("a failed note: %v\n%s", err, f.commands())
	}
}
