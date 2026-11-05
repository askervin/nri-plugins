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

package store

import (
	"context"
	"reflect"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state/statetest"
)

// fixture returns the document of the test records in boot boot.
func fixture(boot string) *Document {
	return &Document{Schema: Schema, Generation: 7, BootID: boot, Records: statetest.Records()}
}

func TestBootOfAnotherBoot(t *testing.T) {
	doc := fixture(statetest.BootID)
	orig := doc.Clone()
	changed, err := applyBoot(doc, "boot-2", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || doc.BootID != "boot-2" {
		t.Errorf("changed %v, boot %s", changed, doc.BootID)
	}
	for _, p := range doc.Preparations {
		if p.State != state.PreparationStale {
			t.Errorf("preparation %s %s after a reboot", p.UID, p.State)
		}
		o := orig.Preparation(p.Driver, p.UID)
		if p.BootID != o.BootID || !reflect.DeepEqual(p.Results, o.Results) {
			t.Errorf("preparation %s changed beyond its state", p.UID)
		}
	}
	for _, g := range doc.Grants {
		o := orig.Grant(g.Ref)
		if g.Got != (state.Got{}) || g.Intent != (state.Intent{}) {
			t.Errorf("grant %s keeps Got or Intent after a reboot", g.Ref)
		}
		if g.Serial != o.Serial || g.Asked != o.Asked || g.State != o.State {
			t.Errorf("grant %s lost Serial, Asked or its state", g.Ref)
		}
	}
	if doc.Leases != nil || doc.Memdevs != nil || doc.Regions != nil {
		t.Errorf("leases, memdevs or regions of another boot kept")
	}
	if !reflect.DeepEqual(doc.LeaseClaims, orig.LeaseClaims) || !reflect.DeepEqual(doc.Provenance, orig.Provenance) ||
		!reflect.DeepEqual(doc.Steered, orig.Steered) {
		t.Errorf("lease claims, provenance or steering records changed")
	}
	for _, v := range state.Check(&doc.Records) {
		t.Errorf("after the reboot: %s", v)
	}
}

func TestBootDropsTheRecordsOfADriver(t *testing.T) {
	for _, tc := range []struct {
		name string
		drop func(driver string) bool
	}{
		{"cxl.nri.io dropped", func(driver string) bool { return driver == statetest.LocalDriver }},
		{"both kept", func(string) bool { return false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := fixture(statetest.BootID)
			orig := doc.Clone()
			if _, err := applyBoot(doc, "boot-2", tc.drop); err != nil {
				t.Fatal(err)
			}
			for _, p := range orig.Preparations {
				dropped := tc.drop(p.Driver)
				if got := doc.Preparation(p.Driver, p.UID); (got == nil) != dropped {
					t.Errorf("preparation %s of %s: kept %v, dropped %v", p.UID, p.Driver, got != nil, dropped)
				}
				for _, r := range p.Results {
					if r.Grant != nil && (doc.Grant(*r.Grant) == nil) != dropped {
						t.Errorf("grant %s of %s: dropped %v", r.Grant, p.Driver, doc.Grant(*r.Grant) == nil)
					}
				}
			}
			for _, v := range state.Check(&doc.Records) {
				t.Errorf("after the reboot: %s", v)
			}
		})
	}
}

func TestBootDropsAStalePreparationOfAnOlderBoot(t *testing.T) {
	doc := fixture(statetest.BootID)
	dropLocal := func(driver string) bool { return driver == statetest.LocalDriver }
	if _, err := applyBoot(doc, statetest.BootID, dropLocal); err != nil {
		t.Fatal(err)
	}
	if p := doc.Preparation(statetest.LocalDriver, statetest.ClaimStale); p != nil {
		t.Errorf("a stale preparation of an older boot is kept: %+v", p)
	}
	if g := doc.Grant(state.GrantRef{Claim: statetest.ClaimStale}); g != nil {
		t.Errorf("its grant is kept")
	}
	if p := doc.Preparation(statetest.LocalDriver, statetest.ClaimDax); p == nil || p.State != state.PreparationPrepared {
		t.Errorf("a preparation of this boot changed: %+v", p)
	}
}

func TestBootOfThisBoot(t *testing.T) {
	doc := fixture(statetest.BootID)
	orig := doc.Clone()
	changed, err := applyBoot(doc, statetest.BootID, nil)
	if err != nil || changed {
		t.Errorf("changed %v, %v", changed, err)
	}
	if !reflect.DeepEqual(doc, orig) {
		t.Errorf("a document of this boot changed")
	}
}

func TestBootUnknown(t *testing.T) {
	doc := fixture(statetest.BootID)
	orig := doc.Clone()
	if changed, err := applyBoot(doc, "", nil); err != nil || changed || !reflect.DeepEqual(doc, orig) {
		t.Errorf("an unknown running boot changed the document: %v %v", changed, err)
	}
}

func TestBootWithoutBootID(t *testing.T) {
	doc := fixture("")
	for i := range doc.Preparations {
		if doc.Preparations[i].UID == statetest.ClaimDax {
			doc.Preparations[i].BootID = ""
		}
	}
	changed, err := applyBoot(doc, statetest.BootID, nil)
	if err != nil || !changed {
		t.Errorf("changed %v, %v", changed, err)
	}
	if doc.BootID != statetest.BootID {
		t.Errorf("document boot %q", doc.BootID)
	}
	if p := doc.Preparation(statetest.LocalDriver, statetest.ClaimDax); p.BootID != statetest.BootID || p.State != state.PreparationPrepared {
		t.Errorf("a preparation without a boot id: %s %s", p.BootID, p.State)
	}
	if len(doc.Memdevs) == 0 || len(doc.Leases) == 0 {
		t.Errorf("a document without a boot id lost its records")
	}
}

func TestOpenAppliesTheBoot(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, nil, func(o *Options) { o.BootID = statetest.BootID })
	err := s.Commit(context.Background(), Durable, func(doc *Document) error {
		doc.Records = statetest.Records()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	closeStore(t, s)
	s = open(t, dir, nil, func(o *Options) { o.BootID = "boot-2" })
	closeStore(t, s)
	doc, err := readDocument(dir + "/" + FileName)
	if err != nil {
		t.Fatal(err)
	}
	if doc.BootID != "boot-2" || len(doc.Leases) != 0 {
		t.Errorf("the reboot was not written: boot %s, %d leases", doc.BootID, len(doc.Leases))
	}
	if p := doc.Preparation(statetest.LocalDriver, statetest.ClaimNUMA); p == nil || p.State != state.PreparationStale {
		t.Errorf("preparation after the reboot: %+v", p)
	}
}
