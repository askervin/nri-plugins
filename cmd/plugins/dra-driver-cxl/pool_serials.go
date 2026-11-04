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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
	"github.com/containers/nri-plugins/pkg/cxl/api"
)

// A pool controller deletes its ResourceSlices when it stops gracefully,
// and a pool device stays attached to the node meanwhile. So the serials
// of the current ResourceSlices do not tell all pool devices on the node.
// The driver remembers every serial it has seen in a pool slice, prepared
// by the pool driver or in the status of a pool claim of the node (a pool
// serial) and every memdev it has taken as a local one, in
// poolSerials.json of its data directory:
//
//   - a pool serial is never a local memdev, whatever the ResourceSlices
//     say; it is forgotten only after it has been observed absent (in no
//     pool slice, not prepared, not on the node) for poolSerialRetention;
//   - a memdev that is neither a pool serial nor a remembered local memdev
//     (new) is held back, not published at all, while a pool claim of the
//     node is not attached yet (no serial in its status): it may be its
//     device; and while the pool slices cannot be listed yet;
//   - otherwise a new memdev is taken as local at once, unless a pool that
//     the driver remembers has been observed without ResourceSlices for
//     less than poolMissingWindow, the list fails, or the file was lost:
//     then it is held back for newMemdevHoldBack, or until the pool is
//     back; if the pool's slices list it, it is a pool device.
//
// Absence is observed: the pool watch (poolWatch) lists the pool slices and
// scans the memdevs at least every poolSlicesPoll (plus a tick), also
// without udev events. An absence counts from the first observation that
// missed it, over observations no more than poolObservationGap apart: a
// longer gap (a stopped driver, a starved process, a failing list, a step
// of the clock) starts it again. Absence is not kept in the file: after a
// restart it starts again.

// poolSerialsFileName is the file of the remembered serials in the data
// directory of cxl.nri.io.
const poolSerialsFileName = "poolSerials.json"

var (
	// poolSerialRetention is how long a serial is remembered after it was
	// first observed absent.
	poolSerialRetention = 24 * time.Hour
	// poolMissingWindow is how long a pool observed without ResourceSlices
	// (or a lost file) holds back new memdevs.
	poolMissingWindow = time.Hour
	// newMemdevHoldBack is how long a new memdev is held back at most
	// while a pool is missing.
	newMemdevHoldBack = 5 * time.Minute
	// poolSerialsRefresh is how often the file is written at most when
	// only the times of last sight changed.
	poolSerialsRefresh = time.Hour
	// poolObservationGap is the longest time between two observations
	// over which an absence continues.
	poolObservationGap = 5 * time.Minute
)

// serialRecord is a remembered serial.
type serialRecord struct {
	Serial string `json:"serial"` // 0x<lower-case hex>
	// Pool is <driver>/<pool> of the ResourceSlice or claim that listed
	// it last, "" when it was not listed (prepared or local).
	Pool string `json:"pool,omitempty"`
	// Local is true for a memdev taken as a local one: it was never in a
	// pool slice or prepared by the pool driver.
	Local bool `json:"local,omitempty"`
	// Seen is when it was last seen in a pool slice, prepared or on the
	// node (for information: the rules use observed absence).
	Seen time.Time `json:"seen"`
}

// poolSerialsFile is the content of poolSerials.json.
type poolSerialsFile struct {
	Serials []*serialRecord `json:"serials"`
	// Pools are the pools with serials in their ResourceSlices, with the
	// time of the last list that had them.
	Pools map[string]time.Time `json:"pools,omitempty"`
}

// loadRecords loads the remembered serials and pools from the file. A
// missing file has none. A file that cannot be read or parsed has lost
// them: lost is set, which holds back new memdevs for poolMissingWindow.
func (p *poolSlices) loadRecords() {
	p.records, p.pools = map[uint64]*serialRecord{}, map[string]time.Time{}
	if p.file == "" {
		return
	}
	data, err := os.ReadFile(p.file)
	if os.IsNotExist(err) {
		klog.Infof("pool serials: no %s: no remembered serials", p.file)
		return
	}
	var f poolSerialsFile
	if err == nil {
		err = json.Unmarshal(data, &f)
	}
	if err != nil {
		p.lost = err.Error()
		klog.Errorf("pool serials: %s: %v: the remembered pool serials are lost; new memory devices are held back for up to %v each in the next %v",
			p.file, err, newMemdevHoldBack, poolMissingWindow)
		return
	}
	for _, r := range f.Serials {
		if r == nil {
			klog.Warningf("pool serials: %s: skipping a null record", p.file)
			continue
		}
		s, err := api.ParseSerial(r.Serial)
		if err != nil {
			klog.Warningf("pool serials: %s: %v", p.file, err)
			continue
		}
		p.records[s] = r
	}
	for pool, t := range f.Pools {
		p.pools[pool] = t
	}
	klog.Infof("pool serials: loaded %d serials (%d pool serials) and %d pools from %s",
		len(p.records), len(p.poolSerialsLocked()), len(p.pools), p.file)
}

// saveLocked writes the file if the remembered serials changed, or if
// only times changed and the file is older than poolSerialsRefresh. Called
// with p.mu held.
func (p *poolSlices) saveLocked(changed bool, now time.Time) {
	if p.file == "" || (!changed && (!p.dirty || now.Sub(p.saved) < poolSerialsRefresh)) {
		return
	}
	f := poolSerialsFile{Pools: p.pools}
	for _, s := range slices.Sorted(maps.Keys(p.records)) {
		f.Serials = append(f.Serials, p.records[s])
	}
	if err := writeJSONFile(p.file, &f); err != nil {
		klog.Errorf("pool serials: %v", err)
		return
	}
	p.saved, p.dirty = now, false
}

// recordLocked returns the record of a serial, a new one (and changed)
// if there is none. Called with p.mu held.
func (p *poolSlices) recordLocked(serial uint64) (*serialRecord, bool) {
	if r := p.records[serial]; r != nil {
		return r, false
	}
	r := &serialRecord{Serial: fmt.Sprintf("0x%x", serial)}
	p.records[serial] = r
	return r, true
}

// notePoolLocked remembers a pool serial seen now, listed in pool (""
// when prepared). It returns whether the records changed. Called with
// p.mu held.
func (p *poolSlices) notePoolLocked(serial uint64, pool string, now time.Time) bool {
	r, changed := p.recordLocked(serial)
	if r.Local {
		klog.Infof("pool serials: memdev serial 0x%x is a pool device now (%s)", serial, orPrepared(pool))
		r.Local, changed = false, true
	}
	if pool != "" && r.Pool != pool {
		r.Pool, changed = pool, true
	}
	r.Seen, p.dirty = now, true
	delete(p.absent, serial)
	return changed
}

// notePoolsLocked remembers the pools of a successful list at now, and
// observes the absence of the others: a pool is forgotten after
// poolSerialRetention of observed absence. It returns whether the pools
// changed. Called with p.mu held.
func (p *poolSlices) notePoolsLocked(listed map[string]bool, now time.Time) bool {
	changed := false
	continuous := observedSince(p.lastList, now)
	for pool := range listed {
		if _, ok := p.pools[pool]; !ok {
			changed = true
		}
		p.pools[pool], p.dirty = now, true
		delete(p.poolAbsent, pool)
	}
	for pool := range p.pools {
		if listed[pool] {
			continue
		}
		since, ok := p.poolAbsent[pool]
		switch {
		case !ok || !continuous:
			p.poolAbsent[pool] = now
		case now.Sub(since) > poolSerialRetention:
			klog.Infof("pool serials: forgetting pool %s (observed without ResourceSlices since %s)", pool, since.Format(time.RFC3339))
			delete(p.pools, pool)
			delete(p.poolAbsent, pool)
			changed = true
		}
	}
	p.lastList = now
	return changed
}

// observedSince tells whether an observation at now continues the one at
// last: there was one, and no more than poolObservationGap ago.
func observedSince(last, now time.Time) bool {
	return !last.IsZero() && !now.Before(last) && now.Sub(last) <= poolObservationGap
}

func orPrepared(pool string) string {
	if pool == "" {
		return "prepared by the pool driver"
	}
	return "in a ResourceSlice of " + pool
}

// poolSerialsLocked returns the remembered pool serials. Called with p.mu
// held.
func (p *poolSlices) poolSerialsLocked() map[uint64]bool {
	out := map[uint64]bool{}
	for s, r := range p.records {
		if !r.Local {
			out[s] = true
		}
	}
	return out
}

// NotePrepared remembers the serials that the pool driver prepares as
// pool serials.
func (p *poolSlices) NotePrepared(serials map[uint64]bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prepared = maps.Clone(serials)
	if len(serials) == 0 {
		return
	}
	now, changed := p.now(), false
	for s := range serials {
		changed = p.notePoolLocked(s, "", now) || changed
	}
	p.saveLocked(changed, now)
}

// uncertainLocked returns why a new memdev cannot be taken as local now
// but may be after newMemdevHoldBack: the list fails, pools have been
// observed without ResourceSlices for less than poolMissingWindow, or the
// file was lost less than poolMissingWindow ago. "" if it can. Called with
// p.mu held.
func (p *poolSlices) uncertainLocked(now time.Time) string {
	if p.failing || !p.known {
		return "the ResourceSlices of pool controllers cannot be listed"
	}
	var why []string
	if p.lost != "" {
		if p.lostAt.IsZero() {
			p.lostAt = now
		}
		if now.Sub(p.lostAt) < poolMissingWindow {
			why = append(why, fmt.Sprintf("the remembered pool serials are lost (%s)", p.lost))
		}
	}
	var missing []string
	for pool := range p.pools {
		if since, ok := p.poolAbsent[pool]; ok && !p.listed[pool] && now.Sub(since) < poolMissingWindow {
			missing = append(missing, pool)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		why = append(why, "pools without ResourceSlices: "+strings.Join(missing, ", "))
	}
	return strings.Join(why, "; ")
}

// claimEvidence is what the pool claims of the node tell about the pool
// devices on the node.
type claimEvidence struct {
	// serials are the serials in the status of pool claims allocated to
	// the node, with <driver>/<pool> of their results.
	serials map[uint64]string
	// attaching are the pool claims allocated to the node with a result
	// whose status has neither a serial nor a failed attach: its device
	// may be on the node already.
	attaching []string
}

// claimEvidence lists the ResourceClaims and returns the evidence of the
// pool claims allocated to the node (bindsToNode).
func (p *poolSlices) claimEvidence(ctx context.Context) (*claimEvidence, error) {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	claims, err := p.claims(ctx)
	if err != nil {
		return nil, err
	}
	ev := &claimEvidence{serials: map[uint64]string{}}
	for i := range claims {
		c := &claims[i]
		a := c.Status.Allocation
		if a == nil || allocationNode(a) != p.nodeName {
			continue
		}
		attaching := false
		for j := range a.Devices.Results {
			r := &a.Devices.Results[j]
			if r.Driver != p.driver {
				continue
			}
			if data, err := poolDataFor(c, r); err == nil {
				ev.serials[data.Serial] = r.Driver + "/" + r.Pool
			} else if !attachFailed(c, r) {
				attaching = true
			}
		}
		if attaching {
			ev.attaching = append(ev.attaching, c.Namespace+"/"+c.Name)
		}
	}
	slices.Sort(ev.attaching)
	return ev, nil
}

// allocationNode returns the node of an allocation that binds to a node
// (matchFields metadata.name In [node]), "" for another one.
func allocationNode(a *resourceapi.AllocationResult) string {
	ns := a.NodeSelector
	if ns == nil || len(ns.NodeSelectorTerms) != 1 {
		return ""
	}
	for _, f := range ns.NodeSelectorTerms[0].MatchFields {
		if f.Key == "metadata.name" && len(f.Values) == 1 {
			return f.Values[0]
		}
	}
	return ""
}

// attachFailed tells whether the status of a result of a pool claim has
// the condition <driver>/AttachFailed True: nothing was attached for it.
func attachFailed(c *resourceapi.ResourceClaim, r *resourceapi.DeviceRequestAllocationResult) bool {
	for _, st := range c.Status.Devices {
		if st.Driver == r.Driver && st.Pool == r.Pool && st.Device == r.Device {
			return meta.IsStatusConditionPresentAndEqual(st.Conditions, r.Driver+"/AttachFailed", metav1.ConditionTrue)
		}
	}
	return false
}

// Gate takes the memdevs of a scan. It returns the pool serials (those of
// poolSerials, the remembered ones and those in the status of pool claims
// of the node) and the new memdevs that are held back, which the scan does
// not publish, and remembers the memdevs that it takes as local. local has
// the memdevs that the local allocator uses: they are local unless they
// are pool serials. A scan is an observation of the memdevs on the node.
func (p *poolSlices) Gate(ctx context.Context, devs *nricxl.Devices, poolSerials map[uint64]bool, local *localSnapshot) (map[uint64]bool, map[uint64]bool) {
	if p == nil || devs == nil {
		return poolSerials, nil
	}
	// The pool claims are listed only for new memdevs, without p.mu.
	p.mu.Lock()
	isNew := func(s uint64) bool { return !poolSerials[s] && p.records[s] == nil && !local.uses(s) }
	anyNew := slices.ContainsFunc(devs.MemoryDevices, func(m *nricxl.MemoryDevice) bool { return isNew(m.Serial) })
	p.mu.Unlock()
	var ev *claimEvidence
	var evErr error
	if anyNew && p.claims != nil && p.nodeName != "" {
		if ev, evErr = p.claimEvidence(ctx); evErr != nil {
			klog.Warningf("pool serials: listing the pool claims of the node: %v", evErr)
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	now, changed := p.now(), false
	out := maps.Clone(poolSerials)
	if out == nil {
		out = map[uint64]bool{}
	}
	held := map[uint64]bool{}
	uncertain := p.uncertainLocked(now)
	if evErr != nil && uncertain == "" {
		uncertain = "the pool claims of the node cannot be listed"
	}
	present := map[uint64]bool{}
	for _, m := range devs.MemoryDevices {
		s := m.Serial
		present[s] = true
		r := p.records[s]
		claimPool, inClaim := "", false
		if ev != nil {
			claimPool, inClaim = ev.serials[s]
		}
		switch {
		case poolSerials[s] || (r != nil && !r.Local) || inClaim:
			// a pool device on the node
			changed = p.notePoolLocked(s, claimPool, now) || changed
			out[s] = true
			delete(p.held, s)
			if local.uses(s) && !p.conflicts[s] {
				p.conflicts[s] = true
				klog.Errorf("pool serials: memdev %s (serial 0x%x) is a pool device, but local claims use it: it is no longer published, and no local claim is prepared on it; release the local claims (%v) and check its memory",
					m.Name, s, local.Uses[s].Claims)
			}
			continue
		case r != nil || local.uses(s):
			// a local memdev
		default:
			reason, expires := uncertain, true
			switch {
			case !p.known:
				reason, expires = "the ResourceSlices of pool controllers were never listed", false
			case ev != nil && len(ev.attaching) > 0:
				reason, expires = "pool claims of the node are not attached yet: "+strings.Join(ev.attaching, ", "), false
			}
			if reason == "" {
				if _, ok := p.held[s]; ok {
					klog.Infof("pool serials: publishing memdev %s (serial 0x%x) as a local memory device: no pool is missing now", m.Name, s)
				}
				break
			}
			first, ok := p.held[s]
			if !ok {
				klog.Warningf("pool serials: holding back new memdev %s (serial 0x%x): it may be a pool device: %s",
					m.Name, s, reason)
			}
			if !ok || !expires {
				// the hold-back time counts while it may expire
				first = now
				p.held[s] = now
			}
			if !expires || now.Sub(first) < newMemdevHoldBack {
				held[s] = true
				continue
			}
			klog.Warningf("pool serials: publishing memdev %s (serial 0x%x) as a local memory device after holding it back for %v (%s)",
				m.Name, s, newMemdevHoldBack, reason)
		}
		delete(p.held, s)
		r, created := p.recordLocked(s)
		if created {
			r.Local = true
			changed = true
			klog.Infof("pool serials: memdev %s (serial 0x%x) is a local memory device", m.Name, s)
		}
		r.Seen, p.dirty = now, true
		delete(p.absent, s)
	}
	changed = p.observeAbsenceLocked(present, now) || changed
	for s := range p.held {
		if !present[s] {
			delete(p.held, s)
		}
	}
	p.saveLocked(changed, now)
	return out, held
}

// observeAbsenceLocked observes the absence of the remembered serials that
// are not on the node (present), not in the pool slices of the last list
// and not prepared, when that list is current, and forgets those observed
// absent for poolSerialRetention. It returns whether the records changed.
// Called with p.mu held.
func (p *poolSlices) observeAbsenceLocked(present map[uint64]bool, now time.Time) bool {
	if !p.known || p.failing || !observedSince(p.lastList, now) {
		return false // the slices are not observed now
	}
	continuous := observedSince(p.lastObs, now)
	p.lastObs = now
	changed := false
	for s, r := range p.records {
		if present[s] || p.serials[s] || p.prepared[s] {
			delete(p.absent, s)
			continue
		}
		since, ok := p.absent[s]
		switch {
		case !ok || !continuous:
			p.absent[s] = now
		case now.Sub(since) > poolSerialRetention:
			klog.Infof("pool serials: forgetting serial 0x%x (pool %v, observed absent since %s)", s, !r.Local, since.Format(time.RFC3339))
			delete(p.records, s)
			delete(p.absent, s)
			changed = true
		}
	}
	return changed
}

// Holding tells whether a new memdev is held back.
func (p *poolSlices) Holding() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.held) > 0
}

// CheckLocal returns an error if the memdev with the serial must not be
// used as a local memory device: it is a remembered pool serial, in a
// current pool slice (listed now; the serials of the last list if that
// fails) or held back. The local allocator checks this before it creates
// a region on a memdev or onlines its memory.
func (p *poolSlices) CheckLocal(ctx context.Context, serial uint64) error {
	if p == nil {
		return nil
	}
	serials, _ := p.Serials(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if serials[serial] {
		pool := "a pool device"
		if r := p.records[serial]; r != nil && r.Pool != "" {
			pool += " of " + r.Pool
		}
		return fmt.Errorf("memory device serial 0x%x is %s: it is not used as a local memory device", serial, pool)
	}
	if _, ok := p.held[serial]; ok {
		return fmt.Errorf("memory device serial 0x%x is held back as a possible pool device: it is not used as a local memory device yet", serial)
	}
	return nil
}
