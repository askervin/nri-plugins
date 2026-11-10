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

package provenance

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// Provenance of a serial (state.Provenance): which memdevs are devices of
// a memory pool.
//
// Purpose: a pool controller deletes its ResourceSlices when it stops
// gracefully, and a pool device stays attached to the node meanwhile, so
// the serials of the current ResourceSlices do not tell all pool devices
// on the node. The watcher remembers every serial that it has seen in a
// pool ResourceSlice, prepared by the pool driver or in the status of a
// pool claim of the node (POOL), and every memdev that it has taken as a
// local one (LOCAL):
//   - a POOL serial is never a local memdev, whatever the ResourceSlices
//     say; it is forgotten only after it has been observed absent (in no
//     pool slice, not prepared, not on the node) for Retention;
//   - a memdev that is neither POOL nor LOCAL (new) is HELD, not published
//     at all, while a pool claim of the node is not attached yet (no serial
//     in its status): it may be its device; and while the pool slices
//     cannot be listed yet;
//   - otherwise a new memdev is LOCAL at once, unless a pool that the
//     watcher remembers has been observed without ResourceSlices for less
//     than MissingWindow, the list fails, or the records were lost: then it
//     is HELD for HoldBack, or until the pool is back; if the pool's slices
//     list it, it is POOL.
//
// Absence is observed: the watch scans at least every Poll (plus a tick),
// also without udev events. An absence counts from the first observation
// that missed it, over observations no more than ObservationGap apart: a
// longer gap (a stopped driver, a starved process, a failing list, a step
// of the clock) starts it again. Absence and holds are not committed:
// after a restart they start again.
//
// Identity: the serial.
//
// States: state.ProvenanceState; UNKNOWN is no entry.
//
// Transitions: see the table state.ProvenanceTable (internal/state and
// docs/memory/cxl/states.md); a transition not in it is refused.
//
// Invariants: POOL never turns LOCAL; a HELD memdev has no record in the
// store.
//
// Persistence: POOL and LOCAL entries are the Provenance records of the
// store with Pool and LastSeen, and the listed pools its ListedPools; a
// commit when they change, or at most every Refresh when only LastSeen
// does; durable when a serial turned POOL or the operator removed a record.
//
// Locks and waits: Watcher.mu.

var (
	// Retention is how long a serial is remembered after it was first
	// observed absent.
	Retention = 24 * time.Hour
	// MissingWindow is how long a pool observed without ResourceSlices (or
	// lost records) holds new memdevs.
	MissingWindow = time.Hour
	// HoldBack is how long a new memdev is held at most while a pool is
	// missing.
	HoldBack = 5 * time.Minute
	// Refresh is how often the records are committed at most when only the
	// times of last sight changed.
	Refresh = time.Hour
	// ObservationGap is the longest time between two observations over
	// which an absence continues.
	ObservationGap = 5 * time.Minute
	// commitTimeout bounds a commit of the records.
	commitTimeout = time.Minute
)

// The triggers of the transitions that the watcher applies.
const (
	triggerList    = state.TriggerList
	triggerPrepare = state.TriggerPrepare
	triggerObserve = state.TriggerObserve
	triggerExpire  = state.TriggerExpire
	triggerLoad    = state.TriggerLoad
)

// entry is the provenance of one serial.
type entry struct {
	rec state.Provenance
}

// held tells whether the memdev of the entry is HELD.
func (e *entry) held() bool {
	return e.rec.State == state.ProvenanceHeld
}

// recorded tells whether the entry is a record of the store: POOL or
// LOCAL.
func (e *entry) recorded() bool {
	return e.rec.State == state.ProvenancePool || e.rec.State == state.ProvenanceLocal
}

// pool tells whether the serial of the entry is POOL.
func (e *entry) pool() bool {
	return e.rec.State == state.ProvenancePool
}

// apply moves the entry to the state on the trigger, as the table allows;
// a refused transition is logged and leaves the entry as it is.
func (e *entry) apply(to state.ProvenanceState, trigger state.Trigger) bool {
	if err := state.Apply(&state.ProvenanceTable, &e.rec.State, to, trigger); err != nil {
		klog.Errorf("pool serials: serial %s: %v", e.rec.Serial, err)
		return false
	}
	return true
}

// newEntry returns the entry of a serial without provenance (UNKNOWN).
func newEntry(serial uint64) *entry {
	return &entry{rec: state.Provenance{Serial: state.Serial(serial), State: state.ProvenanceUnknown}}
}

// load loads the POOL, LOCAL and HELD records and the listed pools of the
// store: a hold goes on from its HeldSince.
// The records of a LOST store are lost: lost is set, which holds new
// memdevs for MissingWindow.
func (w *Watcher) load() {
	st := w.opts.Store
	if st == nil {
		return
	}
	if err := st.Lost(); err != nil {
		w.lost = err.Error()
		klog.Errorf("pool serials: %s: %v: the remembered pool serials are lost; new memory devices are held back for up to %v each in the next %v",
			w.opts.Name, err, HoldBack, MissingWindow)
		return
	}
	doc := st.Snapshot()
	for _, p := range doc.Provenance {
		switch p.State {
		case state.ProvenancePool, state.ProvenanceLocal:
			w.entries[uint64(p.Serial)] = &entry{rec: state.Provenance{Serial: p.Serial, State: p.State, Pool: p.Pool, LastSeen: p.LastSeen}}
		case state.ProvenanceHeld:
			w.entries[uint64(p.Serial)] = &entry{rec: state.Provenance{Serial: p.Serial, State: p.State, HeldSince: p.HeldSince,
				HeldReason: p.HeldReason}}
		default:
			klog.Warningf("pool serials: %s: skipping the record of serial %s in state %s", w.opts.Name, p.Serial, p.State)
		}
	}
	for _, lp := range doc.ListedPools {
		w.pools[lp.Pool] = lp.Listed
	}
	recorded, held := 0, 0
	for _, e := range w.entries {
		if e.held() {
			held++
		} else {
			recorded++
		}
	}
	klog.Infof("pool serials: loaded %d serials (%d pool serials) and %d pools from %s",
		recorded, len(w.poolSerialsLocked()), len(w.pools), w.opts.Name)
	if held > 0 {
		klog.Infof("pool serials: %d memdevs held back before the restart stay held", held)
	}
}

// forget removes the records of the serials, as the operator orders with
// --forget-pool-serial.
func (w *Watcher) forget(serials []uint64) {
	if len(serials) == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	changed := false
	for _, s := range serials {
		e := w.entries[s]
		if e == nil || !e.recorded() {
			klog.Warningf("pool serials: --forget-pool-serial %s: no record of the serial", api.FormatSerial(s))
			continue
		}
		old := e.rec.State
		if !e.apply(state.ProvenanceUnknown, triggerLoad) {
			continue
		}
		klog.Infof("pool serials: forgetting serial 0x%x (%s, --forget-pool-serial)", s, old)
		delete(w.entries, s)
		delete(w.absent, s)
		changed, w.durable = true, true
	}
	w.saveLocked(changed, w.opts.Now())
}

// saveLocked commits the records if they changed, or if only times changed
// and the last commit is older than Refresh. A LOST store refuses every
// commit, which load has logged: the records stay in memory. Called with
// w.mu held.
func (w *Watcher) saveLocked(changed bool, now time.Time) {
	if w.opts.Store == nil || w.lost != "" || (!changed && (!w.dirty || now.Sub(w.saved) < Refresh)) {
		return
	}
	var recs []state.Provenance
	for _, s := range slices.Sorted(maps.Keys(w.entries)) {
		switch e := w.entries[s]; {
		case e.recorded():
			recs = append(recs, state.Provenance{Serial: e.rec.Serial, State: e.rec.State, Pool: e.rec.Pool, LastSeen: e.rec.LastSeen})
		case e.held():
			recs = append(recs, state.Provenance{Serial: e.rec.Serial, State: e.rec.State, HeldSince: e.rec.HeldSince,
				HeldReason: e.rec.HeldReason})
		}
	}
	var pools []state.ListedPool
	for _, pool := range slices.Sorted(maps.Keys(w.pools)) {
		pools = append(pools, state.ListedPool{Pool: pool, Listed: w.pools[pool]})
	}
	durability := store.Lazy
	if w.durable {
		durability = store.Durable
	}
	ctx, cancel := context.WithTimeout(context.Background(), commitTimeout)
	defer cancel()
	err := w.opts.Store.Commit(ctx, durability, func(doc *store.Document) error {
		doc.Provenance, doc.ListedPools = recs, pools
		return nil
	})
	if err != nil {
		klog.Errorf("pool serials: writing %s: %v", w.opts.Name, err)
		return
	}
	w.saved, w.dirty, w.durable = now, false, false
}

// notePoolLocked makes a serial seen now POOL, listed in pool ("" when
// prepared), on the trigger. It returns whether the records changed.
// Called with w.mu held.
func (w *Watcher) notePoolLocked(serial uint64, pool string, now time.Time, trigger state.Trigger) bool {
	e, changed := w.entries[serial], false
	switch {
	case e == nil:
		e = newEntry(serial)
		w.entries[serial] = e
		changed = e.apply(state.ProvenancePool, trigger)
	case e.rec.State == state.ProvenanceLocal:
		klog.Infof("pool serials: memdev serial 0x%x is a pool device now (%s)", serial, orPrepared(pool))
		changed = e.apply(state.ProvenancePool, trigger)
	case e.held():
		changed = e.apply(state.ProvenancePool, trigger)
		e.rec.HeldSince, e.rec.HeldReason = time.Time{}, ""
	default:
		e.apply(state.ProvenancePool, trigger)
	}
	if changed {
		w.durable = true
	}
	if pool != "" && e.rec.Pool != pool {
		e.rec.Pool, changed = pool, true
	}
	e.rec.LastSeen, w.dirty = now, true
	delete(w.absent, serial)
	return changed
}

// notePoolsLocked remembers the pools of a successful list at now, and
// observes the absence of the others: a pool is forgotten after Retention
// of observed absence. It returns whether the pools changed. Called with
// w.mu held.
func (w *Watcher) notePoolsLocked(listed map[string]bool, now time.Time) bool {
	changed := false
	continuous := observedSince(w.lastList, now)
	for pool := range listed {
		if _, ok := w.pools[pool]; !ok {
			changed = true
		}
		w.pools[pool], w.dirty = now, true
		delete(w.poolAbsent, pool)
	}
	for _, pool := range slices.Sorted(maps.Keys(w.pools)) {
		if listed[pool] {
			continue
		}
		since, ok := w.poolAbsent[pool]
		switch {
		case !ok || !continuous:
			w.poolAbsent[pool] = now
		case now.Sub(since) > Retention:
			klog.Infof("pool serials: forgetting pool %s (observed without ResourceSlices since %s)", pool, since.Format(time.RFC3339))
			delete(w.pools, pool)
			delete(w.poolAbsent, pool)
			changed = true
		}
	}
	w.lastList = now
	return changed
}

// observedSince tells whether an observation at now continues the one at
// last: there was one, and no more than ObservationGap ago.
func observedSince(last, now time.Time) bool {
	return !last.IsZero() && !now.Before(last) && now.Sub(last) <= ObservationGap
}

// orPrepared returns where a pool serial was seen for the log lines.
func orPrepared(pool string) string {
	if pool == "" {
		return "prepared by the pool driver"
	}
	return "in a ResourceSlice of " + pool
}

// poolSerialsLocked returns the POOL serials. Called with w.mu held.
func (w *Watcher) poolSerialsLocked() map[uint64]bool {
	out := map[uint64]bool{}
	for s, e := range w.entries {
		if e.pool() {
			out[s] = true
		}
	}
	return out
}

// uncertainLocked returns why a new memdev cannot be taken as local now but
// may be after HoldBack, and its reason: the list fails, pools have been
// observed without ResourceSlices for less than MissingWindow, or the
// records were lost less than MissingWindow ago. "" if it can. Called with
// w.mu held.
func (w *Watcher) uncertainLocked(now time.Time) (string, state.HeldReason) {
	if w.failing || !w.known {
		return "the ResourceSlices of pool controllers cannot be listed", state.HeldListFailing
	}
	var why []string
	var reason state.HeldReason
	if w.lost != "" {
		if w.lostAt.IsZero() {
			w.lostAt = now
		}
		if now.Sub(w.lostAt) < MissingWindow {
			why = append(why, fmt.Sprintf("the remembered pool serials are lost (%s)", w.lost))
			reason = state.HeldLost
		}
	}
	var missing []string
	for pool := range w.pools {
		if since, ok := w.poolAbsent[pool]; ok && !w.listed[pool] && now.Sub(since) < MissingWindow {
			missing = append(missing, pool)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		why = append(why, "pools without ResourceSlices: "+strings.Join(missing, ", "))
		if reason == "" {
			reason = state.HeldPoolMissing
		}
	}
	return strings.Join(why, "; "), reason
}

// Gate observes the memdevs of a snapshot. It returns the pool serials (those
// of poolSerials, the POOL records and those in the status of pool claims
// of the node) and the new memdevs that are HELD, which the scan does not
// publish, and makes LOCAL the memdevs that it takes as local. local has the
// claims of the local memdevs that the device engine has records of, by
// serial: they are local unless they are pool serials.
func (w *Watcher) Gate(ctx context.Context, snap *kernel.Snapshot, poolSerials map[uint64]bool, local map[uint64][]string) (map[uint64]bool, map[uint64]bool) {
	if w == nil || snap == nil {
		return poolSerials, nil
	}
	ev, evErr := w.evidence(ctx, snap, poolSerials, local)

	w.mu.Lock()
	defer w.mu.Unlock()
	g := &gateScan{ev: ev, poolSerials: poolSerials, local: local, now: w.opts.Now()}
	g.uncertain, g.reason = w.uncertainLocked(g.now)
	if evErr != nil && g.uncertain == "" {
		g.uncertain, g.reason = "the pool claims of the node cannot be listed", state.HeldClaimsNotListable
	}
	out := maps.Clone(poolSerials)
	if out == nil {
		out = map[uint64]bool{}
	}
	held, present, changed := map[uint64]bool{}, map[uint64]bool{}, false
	for i := range snap.Memdevs {
		m := &snap.Memdevs[i]
		present[m.Serial] = true
		pool, isHeld, ch := w.observeLocked(m, g)
		changed = ch || changed
		if pool {
			out[m.Serial] = true
		}
		if isHeld {
			held[m.Serial] = true
		}
	}
	changed = w.observeAbsenceLocked(present, g.now) || changed
	for _, s := range slices.Sorted(maps.Keys(w.entries)) {
		if e := w.entries[s]; e.held() && !present[s] && e.apply(state.ProvenanceUnknown, triggerObserve) {
			delete(w.entries, s)
			changed = true
		}
	}
	w.saveLocked(changed, g.now)
	return out, held
}

// gateScan is one observation of the memdevs of a scan: the pool serials
// and the local uses that the scan has, the evidence of the pool claims of
// the node (nil when they were not listed), the reason for doubt of a new
// memdev ("" for none) and the time.
type gateScan struct {
	ev          *claimEvidence
	poolSerials map[uint64]bool
	local       map[uint64][]string
	uncertain   string
	reason      state.HeldReason
	now         time.Time
}

// observeLocked observes the memdev m on the node in the scan g: a pool
// device (pool), a new memdev that stays HELD (held), else a local memdev;
// it returns whether the records changed. Called with w.mu held.
func (w *Watcher) observeLocked(m *kernel.MemdevInfo, g *gateScan) (pool, held, changed bool) {
	s := m.Serial
	e := w.entries[s]
	claimPool, inClaim := "", false
	if g.ev != nil {
		claimPool, inClaim = g.ev.serials[s]
	}
	claims, uses := g.local[s]
	switch {
	case g.poolSerials[s] || (e != nil && e.pool()) || inClaim:
		changed = w.notePoolLocked(s, claimPool, g.now, triggerList)
		if uses && !w.conflicts[s] {
			w.conflicts[s] = true
			klog.Errorf("pool serials: memdev %s (serial 0x%x) is a pool device, but local claims use it: it is no longer published, and no local claim is prepared on it; release the local claims (%v) and check its memory",
				m.Name, s, claims)
		}
		return true, false, changed
	case (e != nil && e.recorded()) || uses:
		return false, false, w.noteLocalLocked(m, g.now, triggerObserve)
	}
	return w.observeNewLocked(m, e, g)
}

// observeNewLocked observes a new memdev m (its entry e, nil or HELD) in
// the scan g: HELD while there is a reason for doubt (held), else LOCAL; it
// returns whether the records changed. Called with w.mu held.
func (w *Watcher) observeNewLocked(m *kernel.MemdevInfo, e *entry, g *gateScan) (pool, held, changed bool) {
	why, hold, expires := g.uncertain, g.reason, true
	switch {
	case !w.known:
		why, hold, expires = "the ResourceSlices of pool controllers were never listed", state.HeldNeverListed, false
	case g.ev != nil && len(g.ev.attaching) > 0:
		why, hold, expires = "pool claims of the node are not attached yet: "+strings.Join(g.ev.attaching, ", "), state.HeldAttaching, false
	}
	if why == "" {
		if e != nil && e.held() {
			klog.Infof("pool serials: publishing memdev %s (serial 0x%x) as a local memory device: no pool is missing now", m.Name, m.Serial)
		}
		return false, false, w.noteLocalLocked(m, g.now, triggerObserve)
	}
	if stays, changed := w.hold(m, e, why, hold, expires, g.now); stays {
		return false, true, changed
	}
	klog.Warningf("pool serials: publishing memdev %s (serial 0x%x) as a local memory device after holding it back for %v (%s)",
		m.Name, m.Serial, HoldBack, why)
	return false, false, w.noteLocalLocked(m, g.now, triggerExpire)
}

// evidence lists the pool claims of the node when a memdev of snap is new
// (no pool serial, no record, no local use), without w.mu.
func (w *Watcher) evidence(ctx context.Context, snap *kernel.Snapshot, poolSerials map[uint64]bool, local map[uint64][]string) (*claimEvidence, error) {
	w.mu.Lock()
	isNew := func(m kernel.MemdevInfo) bool {
		e := w.entries[m.Serial]
		_, uses := local[m.Serial]
		return !poolSerials[m.Serial] && (e == nil || !e.recorded()) && !uses
	}
	anyNew := slices.ContainsFunc(snap.Memdevs, isNew)
	w.mu.Unlock()
	if !anyNew || w.opts.Claims == nil || w.opts.NodeName == "" {
		return nil, nil
	}
	ev, err := w.claimEvidence(ctx)
	if err != nil {
		klog.Warningf("pool serials: listing the pool claims of the node: %v", err)
	}
	return ev, err
}

// hold holds the new memdev m (its entry e, nil for none) for the reason
// why (hold), and tells whether it stays HELD and whether its record
// changed (a new hold, another reason): a reason that does not expire
// holds it, one that expires holds it for HoldBack from the first hold.
// Called with w.mu held.
func (w *Watcher) hold(m *kernel.MemdevInfo, e *entry, why string, hold state.HeldReason, expires bool, now time.Time) (bool, bool) {
	s := m.Serial
	changed := e == nil || e.rec.HeldReason != hold
	if e == nil {
		klog.Warningf("pool serials: holding back new memdev %s (serial 0x%x): it may be a pool device: %s", m.Name, s, why)
		e = newEntry(s)
		w.entries[s] = e
		e.apply(state.ProvenanceHeld, triggerObserve)
		e.rec.HeldSince = now
	} else {
		e.apply(state.ProvenanceHeld, triggerObserve)
		if !expires {
			// the hold time counts while it may expire
			e.rec.HeldSince = now
		}
	}
	e.rec.HeldReason = hold
	return !expires || now.Sub(e.rec.HeldSince) < HoldBack, changed
}

// noteLocalLocked makes the memdev m seen now LOCAL on the trigger (a new
// or a HELD one), and returns whether the records changed. Called with
// w.mu held.
func (w *Watcher) noteLocalLocked(m *kernel.MemdevInfo, now time.Time, trigger state.Trigger) bool {
	s := m.Serial
	e, changed := w.entries[s], false
	switch {
	case e == nil:
		e = newEntry(s)
		w.entries[s] = e
		changed = e.apply(state.ProvenanceLocal, triggerObserve)
	case e.held():
		changed = e.apply(state.ProvenanceLocal, trigger)
		e.rec.HeldSince, e.rec.HeldReason = time.Time{}, ""
	}
	if changed {
		klog.Infof("pool serials: memdev %s (serial 0x%x) is a local memory device", m.Name, s)
	}
	e.rec.LastSeen, w.dirty = now, true
	delete(w.absent, s)
	return changed
}

// observeAbsenceLocked observes the absence of the recorded serials that
// are not on the node (present), not in the pool slices of the last list
// and not prepared, when that list is current, and forgets those observed
// absent for Retention. It returns whether the records changed. Called with
// w.mu held.
func (w *Watcher) observeAbsenceLocked(present map[uint64]bool, now time.Time) bool {
	if !w.known || w.failing || !observedSince(w.lastList, now) {
		return false // the slices are not observed now
	}
	continuous := observedSince(w.lastObs, now)
	w.lastObs = now
	changed := false
	for _, s := range slices.Sorted(maps.Keys(w.entries)) {
		e := w.entries[s]
		if !e.recorded() {
			continue
		}
		if present[s] || w.serials[s] || w.prepared[s] {
			delete(w.absent, s)
			continue
		}
		since, ok := w.absent[s]
		switch {
		case !ok || !continuous:
			w.absent[s] = now
		case now.Sub(since) > Retention:
			pool := e.pool()
			if !e.apply(state.ProvenanceUnknown, triggerExpire) {
				continue
			}
			klog.Infof("pool serials: forgetting serial 0x%x (pool %v, observed absent since %s)", s, pool, since.Format(time.RFC3339))
			delete(w.entries, s)
			delete(w.absent, s)
			changed = true
		}
	}
	return changed
}
