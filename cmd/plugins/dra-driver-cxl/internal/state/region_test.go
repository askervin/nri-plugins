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

package state

import (
	"testing"
)

func TestRegionTable(t *testing.T) {
	checkTable(t, &RegionTable)
}

func TestRegionSetUpTable(t *testing.T) {
	checkTable(t, &RegionSetUpTable)
}

func TestDaxDeviceTable(t *testing.T) {
	checkTable(t, &DaxDeviceTable)
}

func TestMountTable(t *testing.T) {
	checkTable(t, &MountTable)
}

func TestRegionIsNotedBeforeCreation(t *testing.T) {
	for _, tr := range Triggers {
		if RegionTable.Allows(RegionNone, RegionCreating, tr) || RegionTable.Allows(RegionNone, RegionOwned, tr) {
			t.Errorf("a region is created without its note on %s", tr)
		}
	}
	s := RegionNone
	for i, to := range []RegionState{RegionNoted, RegionCreating, RegionOwned, RegionKept, RegionOwned, RegionNone} {
		on := TriggerPrepare
		if to == RegionKept || to == RegionNone {
			on = TriggerUnprepare
		}
		if err := Apply(&RegionTable, &s, to, on); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
}

func TestForeignRegionNeverOurs(t *testing.T) {
	for _, s := range RegionTable.States {
		for _, tr := range Triggers {
			if s != RegionNone && RegionTable.Allows(RegionForeign, s, tr) {
				t.Errorf("FOREIGN -> %s allowed on %s", s, tr)
			}
		}
	}
}

func TestDaxDeviceNeverOnlineWithoutFence(t *testing.T) {
	for _, tr := range Triggers {
		if DaxDeviceTable.Allows(DaxSized, DaxKmemOnline, tr) {
			t.Errorf("SIZED -> KMEM_ONLINE allowed on %s", tr)
		}
	}
	s := DaxAbsent
	for i, to := range []DaxDeviceState{DaxCreating, DaxSized, DaxKmemOffline, DaxKmemOnline} {
		if err := Apply(&DaxDeviceTable, &s, to, TriggerPrepare); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
}

func TestRegionRef(t *testing.T) {
	r := Region{NotedName: "region3"}
	if r.Ref() != "region3" {
		t.Errorf("noted region ref %q", r.Ref())
	}
	r.Name = "region4"
	if r.Ref() != "region4" {
		t.Errorf("created region ref %q", r.Ref())
	}
}
