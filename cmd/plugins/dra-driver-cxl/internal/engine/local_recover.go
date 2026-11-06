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
	"path/filepath"
	"slices"
	"time"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
)

// The start of the local memdevs, after the release of the cut Prepares:
// the parts of prepared claims whose dax device is gone are forgotten, and
// every local memdev is kept or released as its use and the configuration
// say: a shared one is kept while configured shared (and while claims use
// it), a persistent one without claims released in order when nothing
// holds its block device, a sliced one without claims released.

// forgetGoneParts forgets the dax devices of the realised grants of
// prepared claims of local memdevs that are gone or have another size than
// recorded (a reboot that the boot ids do not tell, another tool): the
// grant keeps its region without a device node, which no container gets;
// a dax device of another size there belongs to no grant then.
func (e *Engine) forgetGoneParts(ctx context.Context) {
	r := e.records()
	var gone []state.GrantRef
	for i := range r.Grants {
		g := &r.Grants[i]
		d := e.ownPart(r, g)
		if d == nil {
			continue
		}
		if size, err := e.k.DaxDeviceSize(g.Got.Dax); err == nil && size == d.Size {
			continue
		}
		klog.Warningf("local: memdev %s (serial %s): claim %s: slice %s of %d bytes is gone, dropping it", e.memdevName(g.Serial),
			serialText(g.Serial), g.Ref.Claim, g.Got.Dax, d.Size)
		if g.Asked.Mode == state.ModeDax {
			klog.Warningf("claim %s: no device node for the dax slice %s: the slice is gone", g.Ref.Claim, filepath.Join(e.devRoot(), g.Got.Dax))
		}
		gone = append(gone, g.Ref)
	}
	if len(gone) == 0 {
		return
	}
	present := map[string]bool{}
	for _, ref := range gone {
		g := r.Grant(ref)
		_, err := e.k.DaxDevice(g.Got.Dax)
		present[g.Got.Dax] = err == nil
	}
	if err := e.commit(ctx, func(r *state.Records) error { return forgotParts(r, gone, present) }); err != nil {
		klog.Errorf("engine: %v", err)
	}
}

// ownPart returns the dax device of its own of a realised grant of a
// prepared claim on a sliced local memdev, nil for another grant.
func (e *Engine) ownPart(r *state.Records, g *state.Grant) *state.DaxDevice {
	p := r.PreparationOf(g.Ref)
	if g.Asked.Source != state.SourceLocal || !e.owns(g.Asked.Source) || g.Asked.Kind != state.KindExclusive || g.Got.Dax == "" ||
		!prepared(g) || p == nil || !p.Prepared() {
		return nil
	}
	reg := r.Region(g.Got.Region)
	if reg == nil {
		return nil
	}
	if d := reg.DaxDevice(g.Got.Dax); d != nil && !d.Whole {
		return d
	}
	return nil
}

// forgotParts records the dax devices of the grants gone forgotten: the
// grants without them, a device that the kernel has (present) without
// users, one that it has not dropped.
func forgotParts(r *state.Records, gone []state.GrantRef, present map[string]bool) error {
	for _, ref := range gone {
		g := r.Grant(ref)
		reg := r.Region(g.Got.Region)
		dax := g.Got.Dax
		g.Got.Dax, g.Got.DaxDev = "", state.DevNumbers{}
		d := reg.DaxDevice(dax)
		if d == nil {
			continue
		}
		d.Users = removeRef(d.Users, ref)
		if len(d.Users) > 0 || present[dax] {
			continue
		}
		if err := state.Apply(&state.DaxDeviceTable, &d.State, state.DaxAbsent, state.TriggerRecover); err != nil {
			return err
		}
		removeRecord(&reg.DaxDevices, func(x *state.DaxDevice) bool { return x.Name == dax })
	}
	return nil
}

// recoverLocal keeps or releases every local memdev after the release of
// the cut Prepares (see the top of the file). Errors are logged.
func (e *Engine) recoverLocal(ctx context.Context) {
	if !e.owns(state.SourceLocal) {
		return
	}
	for _, m := range slices.Clone(e.records().Memdevs) {
		if m.Source != state.SourceLocal || m.State == state.MemdevGone {
			continue
		}
		var err error
		switch {
		case m.Facts.Persistent:
			err = e.recoverPersistent(ctx, &m)
		case m.Facts.Shared:
			err = e.recoverShared(ctx, &m)
		case len(m.Grants) == 0:
			err = e.releaseIdleLocal(ctx, &m, Destroy, "")
		}
		if err != nil {
			klog.Errorf("local: %v", err)
		}
	}
}

// localRegionNames returns the region of ours of a local memdev and its
// first dax device, "" for none.
func (e *Engine) localRegionNames(m *state.Memdev) (string, string) {
	r := e.records()
	for _, ref := range m.Regions {
		if reg := r.Region(ref); reg != nil && reg.Ours() {
			return string(reg.Ref()), reg.FirstDax()
		}
	}
	return "", ""
}

// recoverShared keeps the region of a shared local memdev while it is
// configured shared, or while claims use it, and releases it otherwise.
func (e *Engine) recoverShared(ctx context.Context, m *state.Memdev) error {
	region, dax := e.localRegionNames(m)
	if region == "" {
		return nil
	}
	memdev, s := e.memdevName(m.Serial), serialText(m.Serial)
	claims := otherClaims(m, "")
	if claims == nil {
		claims = []string{}
	}
	switch {
	case e.opts.Shared != nil && e.opts.Shared(m.Serial):
		klog.Infof("local: memdev %s (serial %s): keeping shared %s and %s, claims %v", memdev, s, region, dax, claims)
	case len(claims) > 0:
		klog.Warningf("local: memdev %s (serial %s): not configured shared any more: keeping %s for claims %v, not publishing the memdev until they are gone",
			memdev, s, region, claims)
	default:
		klog.Infof("local: memdev %s (serial %s): not configured shared any more, releasing its region", memdev, s)
		return e.releaseIdleLocal(ctx, m, Destroy, "")
	}
	return nil
}

// recoverPersistent keeps the region of a persistent local memdev that
// claims use, and releases one without claims in order when nothing holds
// its block device now (an idle memdev keeps its region while regions of
// other memdevs lie above it).
func (e *Engine) recoverPersistent(ctx context.Context, m *state.Memdev) error {
	region, _ := e.localRegionNames(m)
	if len(m.Grants) > 0 {
		klog.Infof("local: memdev %s (serial %s): keeping persistent %s, claims %v", e.memdevName(m.Serial), serialText(m.Serial), region, otherClaims(m, ""))
		return nil
	}
	return e.releaseIdleLocal(ctx, m, InOrderIdle, region)
}

// releaseIdleLocal releases the regions of a local memdev without grants
// in its queue by decision, and drops its record when nothing is left of
// it. A persistent one is released only when nothing holds its block
// device now (region names its region for the log line).
func (e *Engine) releaseIdleLocal(ctx context.Context, m *state.Memdev, decision Decision, region string) error {
	leave, err := e.acquire(ctx, m.Serial)
	if err != nil {
		return err
	}
	defer leave()
	return e.releaseIdleQueued(ctx, m, decision, region, state.TriggerRecover)
}

// releaseIdleQueued is releaseIdleLocal with the queue of the memdev held.
func (e *Engine) releaseIdleQueued(ctx context.Context, m *state.Memdev, decision Decision, region string, trigger state.Trigger) error {
	memdev, err := e.k.FindMemdev(uint64(m.Serial))
	if err != nil {
		return err
	}
	if dev := e.currentBlockDevice(m.Serial); m.Facts.Persistent && dev != "" {
		if err := e.waitNoHolder(ctx, m.Source, m.Serial, dev, time.Now(), trigger); err != nil {
			klog.Warningf("local: memdev %s (serial %s): keeping %s of the idle persistent device: %v", memdev, serialText(m.Serial), region, err)
			return nil
		}
	}
	g := &state.Grant{Serial: m.Serial, Asked: state.Asked{Source: m.Source, Kind: kindOfFacts(m.Facts)}}
	if _, err := e.releaseRegions(ctx, g, memdev, decision, false, trigger); err != nil {
		return fmt.Errorf("memdev %s (serial %s): releasing its region: %w", memdev, serialText(m.Serial), err)
	}
	return e.commit(ctx, func(r *state.Records) error {
		if m := r.Memdev(m.Serial); m != nil && unused(m) {
			return dropMemdev(r, m.Serial, trigger)
		}
		return nil
	})
}

// ForgetLocal forgets the records of the local memdevs with the serials
// whose region was being made, without touching their regions: they are
// pool devices now. A region is being made while it is NOTED or CREATING,
// and while no grant of the memdev got anything of it (a part or a block
// device), all of them of Prepares that the process stop cut; those grants
// go with the records.
func (e *Engine) ForgetLocal(ctx context.Context, serials []state.Serial) error {
	r := e.records()
	var forget []state.Serial
	for _, serial := range serials {
		if m := r.Memdev(serial); m == nil || m.Source != state.SourceLocal || !regionInMaking(r, m) {
			continue
		}
		memdev, _ := e.k.FindMemdev(uint64(serial))
		klog.Warningf("local: memdev %s (serial %s): its region was being created, and it is a pool device now: forgetting it without touching its regions %v",
			memdev, serialText(serial), e.k.Regions(memdev))
		forget = append(forget, serial)
	}
	if len(forget) == 0 {
		return nil
	}
	return e.commit(ctx, func(r *state.Records) error {
		for _, serial := range forget {
			if err := forgetMemdev(r, serial); err != nil {
				return err
			}
		}
		return nil
	})
}

// regionInMaking tells whether a region of the memdev is being made
// (state.Records.RegionInMaking).
func regionInMaking(r *state.Records, m *state.Memdev) bool {
	return slices.ContainsFunc(m.Regions, func(ref state.RegionRef) bool {
		reg := r.Region(ref)
		return reg != nil && r.RegionInMaking(m, reg)
	})
}

// forgetMemdev removes the record of the memdev with the serial, its
// grants and its region records, at a start.
func forgetMemdev(r *state.Records, serial state.Serial) error {
	m := r.Memdev(serial)
	for _, ref := range m.Grants {
		if g := r.Grant(ref); g != nil {
			if err := state.Apply(&state.GrantTable, &g.State, state.GrantReleased, state.TriggerRecover); err != nil {
				return err
			}
			removeRecord(&r.Grants, func(x *state.Grant) bool { return x.Ref == ref })
		}
	}
	for _, ref := range append(slices.Clone(m.Regions), m.Hollow...) {
		reg := r.Region(ref)
		if reg == nil {
			continue
		}
		if err := state.Apply(&state.RegionTable, &reg.State, state.RegionNone, state.TriggerRecover); err != nil {
			return err
		}
		removeRecord(&r.Regions, func(x *state.Region) bool { return x.Ref() == ref })
	}
	m.Grants, m.Regions, m.Hollow = nil, nil, nil
	return dropMemdev(r, serial, state.TriggerRecover)
}
