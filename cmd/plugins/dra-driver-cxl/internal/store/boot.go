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
	"fmt"
	"reflect"
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
// become PREPARED_STALE (kubelet prepares them again or unprepares them);
// the grants of a stale preparation keep Serial, Source and Asked, and of
// Got and Intent only the lease and requester of a lend and the target of a
// lease bind; the memdev and region records, the grants that no preparation names and
// the leases are dropped (the first reconcile deletes the leases'
// companions); lease claims, provenance and steering records are kept. A
// preparation without a boot id is of the boot of the document.
func applyBoot(doc *Document, running string) (bool, error) {
	if running == "" {
		return false, nil
	}
	changed, err := stalePreparations(doc, running)
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
// PREPARED_STALE, and gives the preparations without a boot id of this boot the running one.
// It returns whether it changed the document.
func stalePreparations(doc *Document, running string) (bool, error) {
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
		case p.State == state.PreparationStale && !otherBoot(doc.BootID, running):
			kept = append(kept, p)
			continue
		case p.State != state.PreparationStale:
			klog.Warningf("store: claim %s (%s) of %s was prepared in boot %s, this is %s: not prepared any more",
				p.ClaimName, p.UID, p.Driver, boot, running)
		}
		p.Reason = staleReason(&p, boot, running)
		if err := state.Apply(&state.PreparationTable, &p.State, state.PreparationStale, state.TriggerLoad); err != nil {
			return changed, err
		}
		changed = true
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

// staleReason returns why a preparation of the boot boot is not prepared
// in the boot running, in the words of the pool driver's records.
func staleReason(p *state.Preparation, boot, running string) string {
	if p.State == state.PreparationPrepared {
		return fmt.Sprintf("prepared in another boot (%s, this is %s)", boot, running)
	}
	return fmt.Sprintf("its Prepare did not finish in another boot (%s)", boot)
}

// clearGrants clears Got and Intent of the grants of a stale preparation
// but the lease and requester of a lend and the target of a lease bind,
// and returns whether it changed one.
func clearGrants(doc *Document, p *state.Preparation) (bool, error) {
	changed := false
	for _, res := range p.Results {
		if res.Grant == nil {
			continue
		}
		g := doc.Grant(*res.Grant)
		if g == nil {
			continue
		}
		if err := state.GrantTable.Check(g.State, g.State, state.TriggerLoad); err != nil {
			return changed, err
		}
		kept := state.Intent{BindTarget: g.Intent.BindTarget, Lend: g.Intent.Lend}
		if kept.Lend == nil {
			kept.Lend = g.Got.Lend
		}
		if g.Got.Bind != nil && kept.BindTarget == "" {
			kept.BindTarget = g.Got.Bind.Target
		}
		if kept.Lend != nil {
			l := *kept.Lend
			l.NumaNode = nil
			kept.Lend = &l
		}
		if g.Got == (state.Got{}) && reflect.DeepEqual(g.Intent, kept) {
			continue
		}
		g.Got, g.Intent = state.Got{}, kept
		changed = true
	}
	return changed, nil
}

// checkDrops returns the error of the first lease, memdev or region record
// whose table refuses its drop on load.
func checkDrops(doc *Document) error {
	for i := range doc.Leases {
		if err := state.LeaseTable.Check(doc.Leases[i].State, state.LeaseNone, state.TriggerLoad); err != nil {
			return err
		}
	}
	for i := range doc.Memdevs {
		if err := state.MemdevTable.Check(doc.Memdevs[i].State, state.MemdevUnused, state.TriggerLoad); err != nil {
			return err
		}
	}
	for i := range doc.Regions {
		if err := state.RegionTable.Check(doc.Regions[i].State, state.RegionNone, state.TriggerLoad); err != nil {
			return err
		}
	}
	return nil
}

// namedGrants returns the grants that a result of a preparation names.
func namedGrants(doc *Document) map[state.GrantRef]bool {
	named := map[state.GrantRef]bool{}
	for i := range doc.Preparations {
		for _, r := range doc.Preparations[i].Results {
			if r.Grant != nil {
				named[*r.Grant] = true
			}
		}
	}
	return named
}

// dropOtherBoot drops the leases and the memdev and region records of a
// document of another boot than running, and returns whether it dropped
// one.
func dropOtherBoot(doc *Document, running string) (bool, error) {
	if err := checkDrops(doc); err != nil {
		return false, err
	}
	named := namedGrants(doc)
	grants := slices.DeleteFunc(slices.Clone(doc.Grants), func(g state.Grant) bool { return !named[g.Ref] })
	for i := range doc.Grants {
		if g := &doc.Grants[i]; !named[g.Ref] {
			if err := state.GrantTable.Check(g.State, state.GrantReleased, state.TriggerLoad); err != nil {
				return false, err
			}
		}
	}
	unnamed := len(doc.Grants) - len(grants)
	if len(doc.Leases) == 0 && len(doc.Memdevs) == 0 && len(doc.Regions) == 0 && unnamed == 0 {
		return false, nil
	}
	klog.Warningf("store: the document is of boot %s, this is %s: dropping %d leases, %d memdevs, %d regions and %d grants of no claim",
		doc.BootID, running, len(doc.Leases), len(doc.Memdevs), len(doc.Regions), unnamed)
	doc.Leases, doc.Memdevs, doc.Regions, doc.Grants = nil, nil, nil, grants
	return true, nil
}
