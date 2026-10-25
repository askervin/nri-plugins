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
	"reflect"
	"strings"
	"testing"
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
