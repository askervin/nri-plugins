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
	"slices"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
)

// otherBoot tells whether a record of the boot recorded is of another boot
// than the running one. A record without a boot id, and every record when
// the running boot id is unknown, are of this boot.
func otherBoot(recorded, running string) bool {
	return recorded != "" && running != "" && recorded != running
}

// applyBoot changes the records of doc as a load in the boot running
// requires, and returns whether it changed the document. Nothing of a
// record of another boot exists in the kernel any more: its preparations
// become PREPARED_STALE (kubelet prepares them again or unprepares them),
// or are dropped with their grants when drop(driver) is true; the grants of
// a stale preparation keep Serial, Source and Asked and lose Got and
// Intent; the memdev and region records and the leases are dropped (the
// first reconcile deletes the leases' companions); lease claims,
// provenance and steering records are kept. A preparation without a boot
// id is of the boot of the document.
func applyBoot(doc *Document, running string, drop func(driver string) bool) (bool, error) {
	if running == "" {
		return false, nil
	}
	changed, err := stalePreparations(doc, running, drop)
	if err != nil {
		return changed, err
	}
	if otherBoot(doc.BootID, running) {
		dropped, err := dropOtherBoot(doc, running)
		if err != nil {
			return changed, err
		}
		changed = changed || dropped
	}
	if doc.BootID != running {
		doc.BootID = running
		changed = true
	}
	return changed, nil
}

// stalePreparations makes the preparations of another boot than running
// PREPARED_STALE, or drops them with their grants when drop(driver), and
// gives the preparations without a boot id of this boot the running one.
// It returns whether it changed the document.
func stalePreparations(doc *Document, running string, drop func(driver string) bool) (bool, error) {
	changed := false
	kept := doc.Preparations[:0]
	for i := range doc.Preparations {
		p := doc.Preparations[i]
		boot := p.BootID
		if boot == "" {
			boot = doc.BootID
		}
		switch {
		case !otherBoot(boot, running):
			if p.BootID == "" {
				p.BootID = running
				changed = true
			}
			kept = append(kept, p)
			continue
		case drop != nil && drop(p.Driver):
			klog.Warningf("store: claim %s (%s) of %s was prepared in boot %s, this is %s: forgotten",
				p.ClaimName, p.UID, p.Driver, boot, running)
			if err := dropPreparation(doc, &p); err != nil {
				return changed, err
			}
			changed = true
			continue
		case p.State != state.PreparationStale:
			klog.Warningf("store: claim %s (%s) of %s was prepared in boot %s, this is %s: not prepared any more",
				p.ClaimName, p.UID, p.Driver, boot, running)
			changed = true
		}
		if err := state.Apply(&state.PreparationTable, &p.State, state.PreparationStale, state.TriggerLoad); err != nil {
			return changed, err
		}
		cleared, err := clearGrants(doc, &p)
		if err != nil {
			return changed, err
		}
		changed = changed || cleared
		kept = append(kept, p)
	}
	doc.Preparations = kept
	return changed, nil
}

// clearGrants clears Got and Intent of the grants of a stale preparation
// and returns whether it changed one.
func clearGrants(doc *Document, p *state.Preparation) (bool, error) {
	changed := false
	for _, res := range p.Results {
		if res.Grant == nil {
			continue
		}
		g := doc.Grant(*res.Grant)
		if g == nil || (g.Got == state.Got{} && g.Intent == state.Intent{}) {
			continue
		}
		if err := state.GrantTable.Check(g.State, g.State, state.TriggerLoad); err != nil {
			return changed, err
		}
		g.Got, g.Intent = state.Got{}, state.Intent{}
		changed = true
	}
	return changed, nil
}

// dropPreparation checks that the preparation and its grants may be
// dropped at the load, and removes its grants and every reference to them
// from the document.
func dropPreparation(doc *Document, p *state.Preparation) error {
	if err := state.PreparationTable.Check(p.State, state.PreparationUnknown, state.TriggerLoad); err != nil {
		return err
	}
	gone := map[state.GrantRef]bool{}
	for _, res := range p.Results {
		if res.Grant == nil {
			continue
		}
		if g := doc.Grant(*res.Grant); g != nil {
			if err := state.GrantTable.Check(g.State, state.GrantReleased, state.TriggerLoad); err != nil {
				return err
			}
			gone[g.Ref] = true
		}
	}
	doc.Grants = slices.DeleteFunc(doc.Grants, func(g state.Grant) bool { return gone[g.Ref] })
	isGone := func(ref state.GrantRef) bool { return gone[ref] }
	for i := range doc.Memdevs {
		doc.Memdevs[i].Grants = slices.DeleteFunc(doc.Memdevs[i].Grants, isGone)
	}
	for i := range doc.Regions {
		reg := &doc.Regions[i]
		for j := range reg.DaxDevices {
			reg.DaxDevices[j].Users = slices.DeleteFunc(reg.DaxDevices[j].Users, isGone)
		}
		for j := range reg.Mounts {
			reg.Mounts[j].Users = slices.DeleteFunc(reg.Mounts[j].Users, isGone)
		}
	}
	return nil
}

// dropOtherBoot drops the leases and the memdev and region records of a
// document of another boot than running, and returns whether it dropped
// one.
func dropOtherBoot(doc *Document, running string) (bool, error) {
	for i := range doc.Leases {
		if err := state.LeaseTable.Check(doc.Leases[i].State, state.LeaseNone, state.TriggerLoad); err != nil {
			return false, err
		}
	}
	for i := range doc.Memdevs {
		if err := state.MemdevTable.Check(doc.Memdevs[i].State, state.MemdevUnused, state.TriggerLoad); err != nil {
			return false, err
		}
	}
	for i := range doc.Regions {
		if err := state.RegionTable.Check(doc.Regions[i].State, state.RegionNone, state.TriggerLoad); err != nil {
			return false, err
		}
	}
	if len(doc.Leases) == 0 && len(doc.Memdevs) == 0 && len(doc.Regions) == 0 {
		return false, nil
	}
	klog.Warningf("store: the document is of boot %s, this is %s: dropping %d leases, %d memdevs and %d regions",
		doc.BootID, running, len(doc.Leases), len(doc.Memdevs), len(doc.Regions))
	doc.Leases, doc.Memdevs, doc.Regions = nil, nil, nil
	return true, nil
}
