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
	changed, err := applyBoot(doc, "boot-2")
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
		lend := g.Intent.Lend
		if g.Got != (state.Got{}) || g.Intent.Region != "" || g.Intent.MountPath != "" || (lend != nil && lend.NumaNode != nil) {
			t.Errorf("grant %s keeps Got or Intent after a reboot: %+v", g.Ref, g.Intent)
		}
		if ol := o.Got.Lend; ol != nil && (lend == nil || lend.Lease != ol.Lease || lend.Pod != ol.Pod) {
			t.Errorf("grant %s lost the identity of its lend", g.Ref)
		}
		if ob := o.Got.Bind; ob != nil && g.Intent.BindTarget != ob.Target {
			t.Errorf("grant %s lost the target of its lease bind", g.Ref)
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

// The preparations of both drivers of another boot are kept PREPARED_STALE
// with their grants: those of cxl.nri.io are not dropped.
func TestBootKeepsThePreparationsOfBothDrivers(t *testing.T) {
	doc := fixture(statetest.BootID)
	orig := doc.Clone()
	if _, err := applyBoot(doc, "boot-2"); err != nil {
		t.Fatal(err)
	}
	for _, p := range orig.Preparations {
		got := doc.Preparation(p.Driver, p.UID)
		if got == nil || got.State != state.PreparationStale {
			t.Errorf("preparation %s of %s: %+v, want PREPARED_STALE", p.UID, p.Driver, got)
		}
		for _, r := range p.Results {
			if r.Grant != nil && doc.Grant(*r.Grant) == nil {
				t.Errorf("grant %s of %s dropped", r.Grant, p.Driver)
			}
		}
	}
	for _, v := range state.Check(&doc.Records) {
		t.Errorf("after the reboot: %s", v)
	}
}

// A stale preparation of an older boot stays as it is in a load of the
// boot of the document.
func TestBootKeepsAStalePreparationOfAnOlderBoot(t *testing.T) {
	doc := fixture(statetest.BootID)
	before := doc.Preparation(statetest.LocalDriver, statetest.ClaimStale).Clone()
	if _, err := applyBoot(doc, statetest.BootID); err != nil {
		t.Fatal(err)
	}
	if p := doc.Preparation(statetest.LocalDriver, statetest.ClaimStale); p == nil || !reflect.DeepEqual(*p, before) {
		t.Errorf("a stale preparation of an older boot changed: %+v", p)
	}
	if g := doc.Grant(state.GrantRef{Claim: statetest.ClaimStale}); g == nil {
		t.Errorf("its grant is dropped")
	}
	if p := doc.Preparation(statetest.LocalDriver, statetest.ClaimDax); p == nil || p.State != state.PreparationPrepared {
		t.Errorf("a preparation of this boot changed: %+v", p)
	}
}

func TestBootOfThisBoot(t *testing.T) {
	doc := fixture(statetest.BootID)
	orig := doc.Clone()
	changed, err := applyBoot(doc, statetest.BootID)
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
	if changed, err := applyBoot(doc, ""); err != nil || changed || !reflect.DeepEqual(doc, orig) {
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
	changed, err := applyBoot(doc, statetest.BootID)
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
