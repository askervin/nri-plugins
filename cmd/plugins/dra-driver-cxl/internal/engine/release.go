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
	"cmp"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// ReleaseGrants releases the grants refs as release says (Policy) and
// returns the errors of those that it could not release. First the stale
// lease binds of every memdev are unmounted again (retryAllStale). The
// grants of one memdev are released together in its queue (the uses that
// the other grants of the call have are not kept), in the order of the
// first of them; every holder wait of the call ends at one deadline, which
// starts at its first holder wait. A grant that is released is gone from
// the store; one whose release failed stays RELEASING with what it still
// has, and a retry finds out from the kernel what exists. A ref without a
// grant is not an error. A grant of a PREPARED_STALE preparation is
// released by its serial: a pool memdev that no grant of this boot uses is
// disabled.
func (e *Engine) ReleaseGrants(ctx context.Context, refs []state.GrantRef, release Release) error {
	ctx, end := e.Request(ctx)
	defer end()
	r := e.records()
	for _, ref := range refs {
		if g := r.Grant(ref); g != nil && !e.owns(g.Asked.Source) {
			return fmt.Errorf("engine: grant %s: the records of source %q are not the engine's", ref, g.Asked.Source)
		}
	}
	e.retryAllStale(ctx, triggerOf(release))
	refs = localOrder(r, refs)
	call := newReleaseCall(e, release, refs)
	var errs []error
	for _, group := range e.byMemdev(refs) {
		if err := e.releaseGroup(ctx, group, call); err != nil {
			errs = append(errs, err)
		}
	}
	e.verify(ctx, nil, triggerOf(release))
	return errors.Join(errs...)
}

// localOrder returns refs with the grants of local memdevs in the order of
// their release: by the serial of their memdev, the last result of a claim
// on a memdev first; the others where they are.
func localOrder(r *state.Records, refs []state.GrantRef) []state.GrantRef {
	local := func(ref state.GrantRef) *state.Grant {
		if g := r.Grant(ref); g != nil && g.Asked.Source == state.SourceLocal {
			return g
		}
		return nil
	}
	var idx []int
	var grants []*state.Grant
	for i, ref := range refs {
		if g := local(ref); g != nil {
			idx = append(idx, i)
			grants = append(grants, g)
		}
	}
	slices.SortStableFunc(grants, func(a, b *state.Grant) int {
		if a.Serial != b.Serial {
			return cmp.Compare(a.Serial, b.Serial)
		}
		return cmp.Compare(b.Ref.Result, a.Ref.Result)
	})
	out := slices.Clone(refs)
	for i, j := range idx {
		out[j] = grants[i].Ref
	}
	return out
}

// releaseCall is what the release of the grants of one call shares: its
// policy and trigger, its grants, the deadlines of its holder waits, and
// the results of the release of the uses of its grants per memdev.
type releaseCall struct {
	release Release
	trigger state.Trigger
	refs    map[state.GrantRef]bool
	// holder is the holder wait; perClaim makes a deadline per claim (the
	// recovery's), else the call has one.
	holder    time.Duration
	perClaim  bool
	deadlines map[string]time.Time
	uses      map[state.Serial]error
	// unrestored are the node mounts of the grants of the call that the
	// start did not mount again (UNRESTORED, FOREIGN), by grant.
	unrestored map[state.GrantRef]string
	// reasons are the Reasons of the grants of the call that are released
	// before they were realised, by grant.
	reasons map[state.GrantRef]string
}

// newReleaseCall returns the release call of the grants refs.
func newReleaseCall(e *Engine, release Release, refs []state.GrantRef) *releaseCall {
	c := &releaseCall{
		release:    release,
		trigger:    triggerOf(release),
		refs:       map[state.GrantRef]bool{},
		holder:     e.opts.Timeouts.Holder,
		deadlines:  map[string]time.Time{},
		uses:       map[state.Serial]error{},
		unrestored: map[state.GrantRef]string{},
		reasons:    map[state.GrantRef]string{},
	}
	for _, ref := range refs {
		c.refs[ref] = true
	}
	return c
}

// holderDeadline returns the deadline of the holder waits of the call for a
// grant of the claim: the holder wait from the first holder wait of the
// call, or of the claim when the call has a deadline per claim.
func (c *releaseCall) holderDeadline(claim string) time.Time {
	if !c.perClaim {
		claim = ""
	}
	d, ok := c.deadlines[claim]
	if !ok {
		d = time.Now().Add(c.holder)
		c.deadlines[claim] = d
	}
	return d
}

// releaseError is the error of the release of a memdev: held tells whether
// its block device stayed held (errHolder).
type releaseError struct {
	serial state.Serial
	held   bool
	err    error
}

// Error returns the error in words.
func (e *releaseError) Error() string {
	return fmt.Sprintf("releasing serial %s: %v", serialText(e.serial), e.err)
}

// Unwrap returns the cause.
func (e *releaseError) Unwrap() error {
	return e.err
}

// Is tells whether target is errHolder and the block device stayed held.
func (e *releaseError) Is(target error) bool {
	return target == errHolder && e.held
}

// triggerOf returns the trigger of the transitions of a release.
func triggerOf(release Release) state.Trigger {
	switch release {
	case ReleaseUnprepare:
		return state.TriggerUnprepare
	case ReleaseRollback:
		return state.TriggerPrepare
	}
	return state.TriggerRecover
}

// byMemdev groups the refs that have a grant by the memdev of their grants,
// in the order of the first ref of each memdev.
func (e *Engine) byMemdev(refs []state.GrantRef) [][]state.GrantRef {
	r := e.records()
	var order []state.Serial
	groups := map[state.Serial][]state.GrantRef{}
	for _, ref := range refs {
		g := r.Grant(ref)
		if g == nil || slices.Contains(groups[g.Serial], ref) {
			continue
		}
		if _, ok := groups[g.Serial]; !ok {
			order = append(order, g.Serial)
		}
		groups[g.Serial] = append(groups[g.Serial], ref)
	}
	out := make([][]state.GrantRef, 0, len(order))
	for _, serial := range order {
		out = append(out, groups[serial])
	}
	return out
}

// releaseGroup releases grants of one memdev, its queue held once: they are
// RELEASING together before the first of them is released.
func (e *Engine) releaseGroup(ctx context.Context, refs []state.GrantRef, call *releaseCall) error {
	g := e.records().Grant(refs[0])
	if g == nil {
		return nil
	}
	leave, err := e.acquire(ctx, g.Serial)
	if err != nil {
		return err
	}
	defer leave()
	if err := e.startReleases(ctx, refs, call); err != nil {
		return err
	}
	var errs []error
	for _, ref := range refs {
		if err := e.releaseGrant(ctx, ref, call); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// releaseGrant releases a grant, its memdev's queue held: RELEASING (unless
// it is), its lease bind unbound, its node mount and block device released
// next to the other grants of the memdev, its own dax device deleted, the
// region per Policy when it was the last grant of the memdev, then
// RELEASED. A grant of a cut Prepare (JOURNALED, REALISING) that the
// recovery releases goes to RELEASED directly. A region that the policy
// keeps for the claim (a rollback below a newer region of another memdev)
// is kept with the grant JOURNALED; the recovery decides what it keeps
// before (keepForRecovery).
func (e *Engine) releaseGrant(ctx context.Context, ref state.GrantRef, call *releaseCall) error {
	r := e.records()
	g := r.Grant(ref)
	if g == nil {
		return nil
	}
	if p := r.PreparationOf(ref); p != nil && p.State == state.PreparationStale {
		return e.releaseStale(ctx, ref, call.trigger)
	}
	if g.State != state.GrantReleasing {
		if err := e.startReleases(ctx, []state.GrantRef{ref}, call); err != nil {
			return err
		}
	}
	cur := e.records().Grant(ref).Clone()
	call.noteUnrestored(e.records(), &cur)
	if err := e.releaseObjects(ctx, &cur, call); err != nil {
		return err
	}
	return e.releaseLast(ctx, &cur, call)
}

// noteUnrestored remembers the node mount of a grant that the start did not
// mount again (UNRESTORED, FOREIGN).
func (c *releaseCall) noteUnrestored(r *state.Records, g *state.Grant) {
	if m := r.MountOf(g); m != nil && (m.State == state.MountUnrestored || m.State == state.MountForeign) {
		c.unrestored[g.Ref] = m.Path
	}
}

// releaseLast releases what the memdev of a grant whose own objects are
// released has when the grant is its last one of no other call, and
// records the grant RELEASED, or JOURNALED with the region that the policy
// keeps for its claim.
func (e *Engine) releaseLast(ctx context.Context, cur *state.Grant, call *releaseCall) error {
	ref, trigger := cur.Ref, call.trigger
	others, ofCall := e.memdevUsers(cur.Serial, ref, call)
	e.logReleased(cur, call.release)
	if others && !ofCall && cur.Asked.Source == state.SourcePool {
		e.logf(cur.Asked.Source, "serial %s is still used by another claim", serialText(cur.Serial))
	}
	if !others && !ofCall {
		kept, err := e.releaseMemdev(ctx, cur, call)
		if err != nil {
			return err
		}
		if kept {
			return e.keptForClaim(ctx, ref, trigger)
		}
	}
	if err := e.commit(ctx, func(r *state.Records) error { return releasedGrant(r, ref, trigger) }); err != nil {
		return err
	}
	e.forgetDevice(ref)
	return nil
}

// startReleases commits the grants refs RELEASING in one commit, but those
// that are released otherwise: of PREPARED_STALE preparations (by their
// serial), and of cut Prepares (JOURNALED, REALISING) that the recovery
// releases (RELEASED directly).
func (e *Engine) startReleases(ctx context.Context, refs []state.GrantRef, call *releaseCall) error {
	r := e.records()
	var start []state.GrantRef
	for _, ref := range refs {
		g := r.Grant(ref)
		p := r.PreparationOf(ref)
		switch {
		case g == nil, p != nil && p.State == state.PreparationStale:
		case call.release == ReleaseRecovery && (g.State == state.GrantJournaled || g.State == state.GrantRealising):
		default:
			start = append(start, ref)
		}
	}
	if len(start) == 0 {
		return nil
	}
	return e.commit(ctx, func(r *state.Records) error {
		for _, ref := range start {
			if g := r.Grant(ref); g != nil {
				realised := g.State != state.GrantJournaled && g.State != state.GrantRealising
				if err := state.Apply(&state.GrantTable, &g.State, state.GrantReleasing, call.trigger); err != nil {
					return err
				}
				if !realised {
					g.Reason = call.reasons[ref]
				}
			}
		}
		return nil
	})
}

// memdevUsers tells whether the memdev with the serial has grants but ref
// of other calls (others) and of the release call (ofCall).
func (e *Engine) memdevUsers(serial state.Serial, ref state.GrantRef, call *releaseCall) (others, ofCall bool) {
	if m := e.records().Memdev(serial); m != nil {
		for _, o := range m.Grants {
			others = others || (o != ref && !call.refs[o])
			ofCall = ofCall || (o != ref && call.refs[o])
		}
	}
	return others, ofCall
}

// keepForRecovery keeps the cut grants refs of one memdev whose region lies
// below a newer region of another memdev untouched (Policy ReleaseRecovery
// keeps), the memdev's queue held: its region KEPT, the grants JOURNALED
// (realised ones as they are).
func (e *Engine) keepForRecovery(ctx context.Context, serial state.Serial, refs []state.GrantRef) error {
	leave, err := e.acquire(ctx, serial)
	if err != nil {
		return err
	}
	defer leave()
	if err := e.keepMemdev(ctx, serial, state.TriggerRecover, true); err != nil {
		return err
	}
	for _, ref := range refs {
		if err := e.keptForClaim(ctx, ref, state.TriggerRecover); err != nil {
			return err
		}
	}
	return nil
}

// releaseObjects releases what a grant has of its own or shares: its lease
// bind, its node mount and block device next to the other grants of the
// memdev, its own dax device.
func (e *Engine) releaseObjects(ctx context.Context, g *state.Grant, call *releaseCall) error {
	if err := e.releaseBind(ctx, g, call.trigger); err != nil {
		return err
	}
	if err := e.releaseMount(ctx, g, call); err != nil {
		return err
	}
	return e.releaseDax(ctx, g, call.trigger)
}

// recoveryAbove returns the regions of other memdevs above the regions of
// the memdev of cut grants that the recovery keeps for their claim, none
// when it releases them: those are the last grants of the memdev, and the
// Policy (ReleaseRecovery) of their kind keeps a region below others.
func (e *Engine) recoveryAbove(serial state.Serial, refs []state.GrantRef) []string {
	r := e.records()
	m := r.Memdev(serial)
	if m == nil || slices.ContainsFunc(m.Grants, func(o state.GrantRef) bool { return !slices.Contains(refs, o) }) {
		return nil
	}
	g := r.Grant(refs[0])
	memdev, err := e.k.FindMemdev(uint64(serial))
	if err != nil || g == nil {
		return nil
	}
	above, err := e.k.RegionsAbove(memdev)
	if err != nil {
		above = []string{"(" + err.Error() + ")"}
	}
	if Policy(ReleaseRecovery, e.kindOf(g), above) != Keep {
		return nil
	}
	return above
}

// kindOf returns the row of the release policy of the memdev of the grant g
// now: shared as configured (Options.Shared), its region established or
// new.
func (e *Engine) kindOf(g *state.Grant) Kind {
	shared := e.opts.Shared != nil && e.opts.Shared(g.Serial)
	return kindOf(g.Asked, shared, established(e.records(), g))
}

// established tells whether the region of ours of the memdev of the grant g
// is set up (a ram region also zeroed) or kept by an earlier release, not
// one that a Prepare made and did not finish setting up.
func established(r *state.Records, g *state.Grant) bool {
	if g.Asked.Kind == state.KindPersistent {
		reg := ownRegion(r, g.Serial, state.RegionPmem)
		return reg != nil && (reg.State == state.RegionKept || reg.SetUp)
	}
	reg := ownRegion(r, g.Serial, state.RegionRam)
	return reg != nil && (reg.State == state.RegionKept || (reg.SetUp && reg.Zeroed))
}

// keptForClaim records a grant whose region is kept for its claim:
// JOURNALED again, holding the region by its intent; a realised grant of a
// cut Prepare that the recovery keeps stays as it is.
func (e *Engine) keptForClaim(ctx context.Context, ref state.GrantRef, trigger state.Trigger) error {
	return e.commit(ctx, func(r *state.Records) error {
		g := r.Grant(ref)
		if g == nil || g.State == state.GrantRealised {
			return nil
		}
		if err := state.Apply(&state.GrantTable, &g.State, state.GrantJournaled, trigger); err != nil {
			return err
		}
		g.Reason = ""
		if g.Got.Region != "" {
			g.Intent.Region = g.Got.Region
		}
		if reg := r.Region(g.Got.Region); reg != nil && g.Got.Dax != "" {
			if d := reg.DaxDevice(g.Got.Dax); d != nil {
				d.Users = removeRef(d.Users, ref)
			}
		}
		g.Got = state.Got{Bind: g.Got.Bind, Lend: g.Got.Lend}
		return nil
	})
}

// releasedGrant removes a released grant (RELEASING -> RELEASED) from the
// records and from its memdev, and the memdev record when nothing of it is
// left (UNUSED).
func releasedGrant(r *state.Records, ref state.GrantRef, trigger state.Trigger) error {
	g := r.Grant(ref)
	if g == nil {
		return nil
	}
	if err := state.Apply(&state.GrantTable, &g.State, state.GrantReleased, trigger); err != nil {
		return err
	}
	serial := g.Serial
	if err := leaveUsers(r, ref, trigger); err != nil {
		return err
	}
	removeRecord(&r.Grants, func(x *state.Grant) bool { return x.Ref == ref })
	m := r.Memdev(serial)
	if m == nil {
		return nil
	}
	m.Grants = removeRef(m.Grants, ref)
	switch {
	case len(m.Grants) > 0:
		if m.State == state.MemdevActive {
			return state.Apply(&state.MemdevTable, &m.State, state.MemdevActive, trigger)
		}
		return nil
	case unused(m):
		return dropMemdev(r, serial, trigger)
	case m.State == state.MemdevActive && len(m.Regions) > 0:
		return state.Apply(&state.MemdevTable, &m.State, state.MemdevIdleKept, trigger)
	}
	return nil
}

// unused tells whether nothing is left of a memdev record: no grant, no
// region of ours, no hollow region and no stale lease bind or node mount.
func unused(m *state.Memdev) bool {
	return len(m.Grants) == 0 && len(m.Regions) == 0 && len(m.Hollow) == 0 && len(m.Stale) == 0
}

// dropMemdev removes the record of the memdev with the serial (UNUSED).
func dropMemdev(r *state.Records, serial state.Serial, trigger state.Trigger) error {
	m := r.Memdev(serial)
	if m == nil {
		return nil
	}
	if err := state.Apply(&state.MemdevTable, &m.State, state.MemdevUnused, trigger); err != nil {
		return err
	}
	removeRecord(&r.Memdevs, func(x *state.Memdev) bool { return x.Serial == serial })
	return nil
}

// leaveUsers removes a released grant from the users of the dax devices of
// the regions.
func leaveUsers(r *state.Records, ref state.GrantRef, trigger state.Trigger) error {
	for i := range r.Regions {
		for j := range r.Regions[i].DaxDevices {
			d := &r.Regions[i].DaxDevices[j]
			if !slices.Contains(d.Users, ref) {
				continue
			}
			if d.State != state.DaxSized && d.State != state.DaxCreating {
				if err := state.Apply(&state.DaxDeviceTable, &d.State, d.State, trigger); err != nil {
					return err
				}
			}
			d.Users = removeRef(d.Users, ref)
		}
	}
	return nil
}

// releaseBind unbinds the lease bind of a companion grant. A bind that is
// busy (a file of it mapped) becomes STALE, recorded with its memdev, and
// the release fails.
func (e *Engine) releaseBind(ctx context.Context, g *state.Grant, trigger state.Trigger) error {
	b := g.Got.Bind
	if b == nil {
		return e.releaseCutBind(g)
	}
	if b.State != state.BindBound && b.State != state.BindStale {
		return nil
	}
	if e.bindUsed(b.Target, g.Ref) {
		e.warnf(g.Asked.Source, "%s: %s is the bind of another prepared claim, not unmounting it", bindWhat(g), b.Target)
		return e.commit(ctx, func(r *state.Records) error { return boundTo(r, g.Ref, b.Target, state.BindAbsent, trigger) })
	}
	err := e.unbind(g.Asked.Source, bindWhat(g), b.Target)
	to := state.BindAbsent
	if err != nil {
		if b.State == state.BindStale || !errors.Is(err, kernel.ErrEBUSY) {
			return err
		}
		to = state.BindStale
	}
	cerr := e.commit(ctx, func(r *state.Records) error { return boundTo(r, g.Ref, b.Target, to, trigger) })
	return errors.Join(err, cerr)
}

// bindWhat returns what the log lines of the lease bind of a grant name: its
// lease, else the grant.
func bindWhat(g *state.Grant) string {
	if l := g.Got.Lend; l != nil {
		return "lease " + l.Lease
	}
	if l := g.Intent.Lend; l != nil {
		return "lease " + l.Lease
	}
	return "grant " + g.Ref.String()
}

// releaseCutBind unbinds the lease bind that the intent of a grant of a cut
// Prepare names, when a lease bind is mounted there: the bind is made
// before the grant records it.
func (e *Engine) releaseCutBind(g *state.Grant) error {
	target := g.Intent.BindTarget
	if target == "" || (g.State != state.GrantJournaled && g.State != state.GrantRealising) {
		return nil
	}
	mi, err := e.k.Mounted(target)
	if err != nil || mi == nil || !e.leaseBindType(mi) {
		return err
	}
	return e.unbind(g.Asked.Source, bindWhat(g), target)
}

// boundTo records the lease bind of a grant in state to (ABSENT, or STALE
// with its memdev's Stale entry).
func boundTo(r *state.Records, ref state.GrantRef, target string, to state.BindState, trigger state.Trigger) error {
	rg := r.Grant(ref)
	if rg == nil || rg.Got.Bind == nil {
		return nil
	}
	if err := state.Apply(&state.BindTable, &rg.Got.Bind.State, to, trigger); err != nil {
		return err
	}
	if m := r.Memdev(rg.Serial); m != nil {
		stale := state.StalePath{Path: target, Kind: state.StaleBind}
		if to == state.BindStale {
			m.Stale = addRef(m.Stale, stale)
		} else {
			m.Stale = removeRef(m.Stale, stale)
		}
	}
	return nil
}

// RetryStale unmounts the stale lease binds of every memdev and the lease
// binds of no memdev again, as every release does first, and finishes the
// Unprepares that they kept from releasing (the periodic pass): the
// transitions are those of an Unprepare. Errors are logged.
func (e *Engine) RetryStale(ctx context.Context) {
	ctx, end := e.Request(ctx)
	defer end()
	e.retryAllStale(ctx, state.TriggerUnprepare)
}

// retryAllStale unmounts the stale lease binds of every memdev of the
// sources of the engine that no prepared grant lists again, in the queue of
// each memdev that no other request holds, and forgets those that are
// gone; then the grants of the memdev that a stale bind left RELEASING are
// released again when no other grant of a claim uses the memdev, and a
// pool memdev without grants is released (its holder wait, its region,
// disabled). Errors are logged.
func (e *Engine) retryAllStale(ctx context.Context, trigger state.Trigger) {
	for _, m := range e.records().Memdevs {
		if len(m.Stale) == 0 || !e.owns(m.Source) || !slices.ContainsFunc(m.Stale, func(sp state.StalePath) bool { return sp.Kind == state.StaleBind }) {
			continue
		}
		e.retryStale(ctx, m.Serial, trigger)
	}
	e.retryOrphanBinds()
}

// addOrphanBind keeps a lease bind of no memdev whose unmount failed, once,
// for the next release.
func (e *Engine) addOrphanBind(target string) {
	e.qmu.Lock()
	defer e.qmu.Unlock()
	if !slices.Contains(e.orphanBinds, target) {
		e.orphanBinds = append(e.orphanBinds, target)
	}
}

// retryOrphanBinds unmounts again the lease binds of no memdev that a start
// could not unmount, and forgets those that are gone or that a prepared
// grant lists again; the others are tried again at the next release.
func (e *Engine) retryOrphanBinds() {
	e.qmu.Lock()
	binds := e.orphanBinds
	e.orphanBinds = nil
	e.qmu.Unlock()
	var left []string
	for _, target := range binds {
		if e.bindUsed(target, state.GrantRef{}) {
			continue
		}
		if err := e.unbindStale(state.SourceLocal, target); err != nil {
			e.errorf(state.SourceLocal, "unmounting stale lease bind %s: %v", target, err)
			left = append(left, target)
		}
	}
	for _, target := range left {
		e.addOrphanBind(target)
	}
}

// retryStale unmounts the stale lease binds of the memdev with the serial
// in its queue, when no other request of the memdev is in progress (its
// next release tries again), and forgets those that are gone or that a
// prepared grant lists again; when none is left, the memdev is released
// after them.
func (e *Engine) retryStale(ctx context.Context, serial state.Serial, trigger state.Trigger) {
	leave := e.tryAcquire(serial)
	if leave == nil {
		return
	}
	defer leave()
	m := e.records().Memdev(serial)
	if m == nil {
		return
	}
	source := m.Source
	var forget []state.StalePath
	gone, left := false, false
	for _, sp := range m.Stale {
		if sp.Kind != state.StaleBind {
			continue
		}
		if e.bindUsed(sp.Path, state.GrantRef{}) {
			// a Prepare again bound it for its grant
			forget = append(forget, sp)
			continue
		}
		if err := e.unbindStale(source, sp.Path); err != nil {
			e.errorf(source, "unmounting stale lease bind %s: %v", sp.Path, err)
			left = true
			continue
		}
		forget = append(forget, sp)
		gone = true
	}
	if len(forget) == 0 {
		return
	}
	if err := e.commit(ctx, func(r *state.Records) error { return forgetStale(r, serial, forget, trigger) }); err != nil {
		e.errorf(source, "serial %s: %v", serialText(serial), err)
		return
	}
	if gone && !left {
		e.releaseAfterStale(ctx, serial, trigger)
	}
}

// releaseAfterStale releases the memdev with the serial after its stale
// lease binds are gone, its queue held, when no grant of a claim uses it
// any more: its RELEASING grants, each as the release that it was in, else
// the memdev itself; the record of a memdev of which nothing is left goes.
// Errors are logged.
func (e *Engine) releaseAfterStale(ctx context.Context, serial state.Serial, trigger state.Trigger) {
	r := e.records()
	m := r.Memdev(serial)
	if m == nil {
		return
	}
	var refs []state.GrantRef
	for _, ref := range m.Grants {
		if g := r.Grant(ref); g == nil || g.State != state.GrantReleasing {
			return
		}
		refs = append(refs, ref)
	}
	source := m.Source
	call := newReleaseCall(e, ReleaseUnprepare, refs)
	call.trigger = trigger
	var errs []error
	for _, ref := range refs {
		call.release = releaseOf(r.PreparationOf(ref))
		errs = append(errs, e.releaseGrant(ctx, ref, call))
	}
	switch {
	case len(refs) == 0 && source == state.SourcePool:
		errs = append(errs, e.releaseIdle(ctx, *m, call))
	case len(refs) == 0 && m.Facts.Persistent:
		region, _ := e.localRegionNames(m)
		errs = append(errs, e.releaseIdleQueued(ctx, m, InOrderIdle, region, trigger))
	}
	e.logAfterStale(source, serial, errs)
	if err := e.commit(ctx, func(r *state.Records) error {
		if m := r.Memdev(serial); m != nil && unused(m) {
			return dropMemdev(r, serial, trigger)
		}
		return nil
	}); err != nil {
		e.errorf(source, "serial %s: %v", serialText(serial), err)
	}
}

// releaseOf returns the release that a RELEASING grant of the preparation p
// was in: a rollback for a claim whose Prepare did not finish, else an
// Unprepare.
func releaseOf(p *state.Preparation) Release {
	if p != nil && (p.State == state.PreparationPreparing || p.State == state.PreparationKept) {
		return ReleaseRollback
	}
	return ReleaseUnprepare
}

// logAfterStale logs the errors of the release of the memdev with the
// serial after its stale lease binds: a block device that stayed held, and
// the other errors.
func (e *Engine) logAfterStale(source state.Source, serial state.Serial, errs []error) {
	var held, failed []error
	for _, err := range errs {
		if err == nil {
			continue
		}
		cause := err
		var re *releaseError
		if errors.As(err, &re) && re.serial == serial {
			cause = re.err
		}
		if errors.Is(err, errHolder) {
			held = append(held, cause)
		} else {
			failed = append(failed, cause)
		}
	}
	if len(held) > 0 {
		e.errorf(source, "not releasing serial %s after its stale lease bind: %v", serialText(serial), errors.Join(held...))
	}
	if len(failed) > 0 {
		e.errorf(source, "releasing serial %s after its stale lease bind: %v", serialText(serial), errors.Join(failed...))
	}
}

// releaseIdle releases a pool memdev without grants after its stale lease
// binds are gone: the holder wait of its block device, its regions,
// disabled.
func (e *Engine) releaseIdle(ctx context.Context, m state.Memdev, call *releaseCall) error {
	memdev, err := e.k.FindMemdev(uint64(m.Serial))
	if errors.Is(err, kernel.ErrNotFound) {
		return nil
	}
	if err != nil {
		return &releaseError{serial: m.Serial, err: err}
	}
	if dev := e.currentBlockDevice(m.Serial); dev != "" {
		if err := e.waitNoHolder(ctx, m.Source, m.Serial, dev, call.holderDeadline(""), call.trigger); err != nil {
			return &releaseError{serial: m.Serial, held: true, err: err}
		}
	}
	g := &state.Grant{Serial: m.Serial, Asked: state.Asked{Source: m.Source, Kind: state.KindPersistent}}
	if _, err := e.releaseRegions(ctx, g, memdev, Destroy, false, call.trigger); err != nil {
		return &releaseError{serial: m.Serial, err: err}
	}
	if err := e.disableMemdev(ctx, m.Source, m.Serial, memdev); err != nil {
		return &releaseError{serial: m.Serial, err: err}
	}
	return nil
}

// errHolder is the kind of the error of a holder wait that did not end.
var errHolder = errors.New("its block device is held")

// forgetStale removes the stale lease binds gone of the memdev with the
// serial, the binds of their grants that are STALE ABSENT (a BOUND one of
// a grant that lists it again stays).
func forgetStale(r *state.Records, serial state.Serial, gone []state.StalePath, trigger state.Trigger) error {
	m := r.Memdev(serial)
	if m == nil {
		return nil
	}
	for _, sp := range gone {
		m.Stale = removeRef(m.Stale, sp)
		for i := range r.Grants {
			if b := r.Grants[i].Got.Bind; b != nil && b.Target == sp.Path && b.State == state.BindStale {
				if err := state.Apply(&state.BindTable, &b.State, state.BindAbsent, trigger); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// releaseMount releases the uses of the block device or node mount of the
// persistent grants of the call on the memdev of a grant next to the other
// grants of the memdev, once, and removes those grants from the users of
// their node mount in one commit. The node mount of a grant that a cut
// Prepare left is the one of its intent when a mount of its device is
// there.
func (e *Engine) releaseMount(ctx context.Context, g *state.Grant, call *releaseCall) error {
	if g.Asked.Kind != state.KindPersistent {
		return nil
	}
	if err, done := call.uses[g.Serial]; done {
		return err
	}
	r := e.records()
	var remaining []use
	for _, u := range usesOf(r, g.Serial, g.Ref) {
		if !call.refs[u.ref] {
			remaining = append(remaining, u)
		}
	}
	var refs []state.GrantRef
	for _, o := range callGrants(r, g, call) {
		refs = append(refs, o.Ref)
	}
	err := e.releaseUses(g.Asked.Source, g.Serial, e.goneUses(r, g, call), remaining)
	if err != nil {
		err = fmt.Errorf("releasing %s (serial %s): %w", e.deviceOf(g.Ref), serialText(g.Serial), err)
	}
	call.uses[g.Serial] = err
	if err != nil {
		return err
	}
	return e.commit(ctx, func(r *state.Records) error { return leaveMount(r, refs, firstWriter(remaining) != nil, call.trigger) })
}

// goneUses returns the uses of the block device or node mount that the
// grants of a release call on the memdev of g give up, g first: none of a
// node mount that is not ours (UNRESTORED, FOREIGN).
func (e *Engine) goneUses(r *state.Records, g *state.Grant, call *releaseCall) []use {
	var gone []use
	for _, o := range callGrants(r, g, call) {
		u := useOf(r, o)
		if u.nodeMount == "" {
			u = e.cutMountUse(o, u)
		}
		if o.Got.BlockDevice == nil && u.nodeMount == "" {
			continue
		}
		if reg := r.Region(o.Got.Region); reg != nil && o.Got.Mount != "" {
			if m := reg.Mount(o.Got.Mount); m != nil && (m.State == state.MountUnrestored || m.State == state.MountForeign) {
				// nothing of ours mounted to release
				continue
			}
		}
		gone = append(gone, u)
	}
	return gone
}

// callGrants returns g and the other persistent grants of the release call
// on its memdev.
func callGrants(r *state.Records, g *state.Grant, call *releaseCall) []*state.Grant {
	grants := []*state.Grant{g}
	if m := r.Memdev(g.Serial); m != nil {
		for _, ref := range m.Grants {
			if o := r.Grant(ref); o != nil && ref != g.Ref && call.refs[ref] && o.Asked.Kind == state.KindPersistent {
				grants = append(grants, o)
			}
		}
	}
	return grants
}

// cutMountUse returns the use u of a grant of a cut Prepare with the node
// mount of its intent, when a mount of the block device of its region is
// there (the mount is made before the grant records it).
func (e *Engine) cutMountUse(g *state.Grant, u use) use {
	if g.Intent.MountPath == "" {
		return u
	}
	dev := e.currentBlockDevice(g.Serial)
	if dev == "" {
		return u
	}
	mi, err := e.k.Mounted(g.Intent.MountPath)
	if err != nil || mi == nil {
		return u
	}
	for _, a := range []string{string(state.AccessDirect), string(state.AccessCached)} {
		if ok, _ := e.isDeviceMount(mi, dev, a); ok {
			u.nodeMount, u.blockDevice = g.Intent.MountPath, dev
		}
	}
	return u
}

// leaveMount removes grants from the users of the node mounts that list
// them: a mount without users is gone (ABSENT), one without a writer left
// read-only.
func leaveMount(r *state.Records, refs []state.GrantRef, writer bool, trigger state.Trigger) error {
	for _, ref := range refs {
		if rg := r.Grant(ref); rg != nil {
			rg.Got.Mount = ""
		}
	}
	for i := range r.Regions {
		reg := &r.Regions[i]
		for j := 0; j < len(reg.Mounts); j++ {
			m := &reg.Mounts[j]
			if !slices.ContainsFunc(m.Users, func(u state.GrantRef) bool { return slices.Contains(refs, u) }) {
				continue
			}
			for _, ref := range refs {
				m.Users = removeRef(m.Users, ref)
			}
			gone, err := leftMount(m, writer, trigger)
			if err != nil {
				return err
			}
			if gone {
				reg.Mounts = slices.Delete(reg.Mounts, j, j+1)
				j--
			}
		}
	}
	return nil
}

// leftMount applies the transition of a node mount that users left: ABSENT
// without users (it is gone), read-only without a writer. A FOREIGN one
// stays: it goes with its region.
func leftMount(m *state.Mount, writer bool, trigger state.Trigger) (bool, error) {
	switch {
	case m.State == state.MountForeign:
	case len(m.Users) == 0:
		return true, state.Apply(&state.MountTable, &m.State, state.MountAbsent, trigger)
	case m.State == state.MountedRW && !writer:
		m.Writer = false
		return false, state.Apply(&state.MountTable, &m.State, state.MountedRO, trigger)
	case m.State == state.MountedRO || m.State == state.MountedRW:
		return false, state.Apply(&state.MountTable, &m.State, m.State, trigger)
	}
	return false, nil
}

// releaseDax releases the dax device of a grant: its own one (a part of a
// sliced memdev) offlined and deleted, or the grant removed from the users
// of a shared one.
func (e *Engine) releaseDax(ctx context.Context, g *state.Grant, trigger state.Trigger) error {
	if g.Got.Region == "" || g.Got.Dax == "" {
		return nil
	}
	reg := e.records().Region(g.Got.Region)
	if reg == nil {
		return nil
	}
	d := reg.DaxDevice(g.Got.Dax)
	if d == nil {
		return nil
	}
	if own := !d.Whole && len(d.Users) == 1 && d.Users[0] == g.Ref; !own {
		// a shared device: the grant leaves its users when it is released
		return nil
	}
	region, dax := string(g.Got.Region), g.Got.Dax
	memdev := e.memdevName(g.Serial)
	part := localPart{memdev: memdev, serial: g.Serial, claim: g.Ref.Claim, dax: dax, mode: g.Asked.Mode, size: d.Size}
	if err := e.offlineDax(ctx, &part); err != nil {
		return err
	}
	start := time.Now()
	if err := e.locked(func() error { return e.k.DeleteDaxDevice(ctx, region, dax) }); err != nil {
		return fmt.Errorf("memdev %s (serial %s): releasing slice %s: %w", memdev, serialText(g.Serial), dax, err)
	}
	part.logf("deleted", start, "")
	return e.commit(ctx, func(r *state.Records) error { return releasedDax(r, g.Ref, g.Got.Region, dax, trigger) })
}

// localPart names a part of a local memdev (a dax device of a grant) in the
// log lines and errors of its release.
type localPart struct {
	memdev     string
	serial     state.Serial
	claim, dax string
	mode       state.Mode
	size       uint64
}

// logf logs a step of the release of the part that began at start.
func (p *localPart) logf(step string, start time.Time, details string) {
	klog.InfofDepth(1, "local: memdev %s (serial %s): claim %s: %s slice %s mode %s size %d%s in %s",
		p.memdev, serialText(p.serial), p.claim, step, p.dax, p.mode, p.size, details, since(start))
}

// memdevName returns the name of the memdev with the serial: its record's,
// else the kernel's, else the serial.
func (e *Engine) memdevName(serial state.Serial) string {
	if m := e.records().Memdev(serial); m != nil && m.Name != "" {
		return m.Name
	}
	if name, err := e.k.FindMemdev(uint64(serial)); err == nil {
		return name
	}
	return serialText(serial)
}

// offlineDax offlines the memory blocks of the dax device of a part bound
// to kmem, under the engine lock.
func (e *Engine) offlineDax(ctx context.Context, p *localPart) error {
	if e.k.DaxDriver(p.dax) != kernel.DriverKmem {
		return nil
	}
	start := time.Now()
	bs, err := e.k.BlockSize()
	var blocks []int
	if err == nil {
		blocks, err = e.k.DaxDeviceBlocks(p.dax, bs)
	}
	if err == nil {
		err = e.locked(func() error { return e.k.OfflineBlocks(ctx, blocks, 0, 0) })
	}
	if err != nil {
		return fmt.Errorf("memdev %s (serial %s): releasing slice %s: cannot offline its memory (in use?): %w", p.memdev, serialText(p.serial), p.dax, err)
	}
	if p.claim != "" {
		p.logf("offlined", start, fmt.Sprintf(" blocks %v", blocks))
	}
	return nil
}

// releasedDax records the own dax device of a grant deleted: a device that
// a cut Prepare made goes (CREATING -> ABSENT), another one RELEASING, then
// the seed (daxN.0) or gone.
func releasedDax(r *state.Records, ref state.GrantRef, region state.RegionRef, dax string, trigger state.Trigger) error {
	reg := r.Region(region)
	d := reg.DaxDevice(dax)
	if rg := r.Grant(ref); rg != nil {
		rg.Got.Dax = ""
	}
	if d.State == state.DaxCreating {
		if err := state.Apply(&state.DaxDeviceTable, &d.State, state.DaxAbsent, trigger); err != nil {
			return err
		}
		removeRecord(&reg.DaxDevices, func(x *state.DaxDevice) bool { return x.Name == dax })
		return nil
	}
	if err := state.Apply(&state.DaxDeviceTable, &d.State, state.DaxReleasing, trigger); err != nil {
		return err
	}
	d.Users = nil
	if strings.HasSuffix(dax, ".0") {
		d.Driver, d.Size, d.Ranges, d.Dev = "", 0, nil, state.DevNumbers{}
		return state.Apply(&state.DaxDeviceTable, &d.State, state.DaxSeed, trigger)
	}
	if err := state.Apply(&state.DaxDeviceTable, &d.State, state.DaxAbsent, trigger); err != nil {
		return err
	}
	removeRecord(&reg.DaxDevices, func(x *state.DaxDevice) bool { return x.Name == dax })
	return nil
}

// since returns the time since start in milliseconds for logs ("12.345ms").
func since(start time.Time) string {
	return fmt.Sprintf("%.3fms", float64(time.Since(start))/float64(time.Millisecond))
}

// releaseMemdev releases what the memdev of a grant has when the grant is
// its last one: the holder wait of a persistent block device, the regions
// of ours per Policy, and a pool memdev disabled so that the pool can
// detach it. A memdev that is gone is not an error: its regions of ours
// that the kernel left hollow are deleted. It tells whether the region was
// kept for the claim of the grant (a rollback or a recovery below a newer
// region of another memdev).
func (e *Engine) releaseMemdev(ctx context.Context, g *state.Grant, call *releaseCall) (bool, error) {
	release, trigger := call.release, call.trigger
	source, serial := g.Asked.Source, g.Serial
	memdev, err := e.k.FindMemdev(uint64(serial))
	if errors.Is(err, kernel.ErrNotFound) {
		return false, e.releaseGone(ctx, g, trigger)
	}
	if err != nil {
		return false, &releaseError{serial: serial, err: err}
	}
	decision := e.decision(g, memdev, release)
	forClaim := decision.forClaim(release)
	if decision.keeps() {
		e.keptIdle(g, memdev, decision, release)
		return forClaim, e.keepMemdev(ctx, serial, trigger, forClaim)
	}
	if dev := e.blockDeviceOf(g, call); dev != "" {
		if err := e.waitNoHolder(ctx, source, serial, dev, call.holderDeadline(g.Ref.Claim), trigger); err != nil {
			return false, &releaseError{serial: serial, held: true, err: err}
		}
	}
	kept, err := e.releaseRegions(ctx, g, memdev, decision, forClaim, trigger)
	if err == nil && !kept && source == state.SourcePool {
		err = e.disableMemdev(ctx, source, serial, memdev)
	}
	if err != nil {
		return false, &releaseError{serial: serial, err: err}
	}
	if m := e.records().Memdev(serial); m != nil && len(m.Hollow) > 0 {
		why := "left by a Prepare of the claim that did not finish"
		if release == ReleaseRollback {
			why = "left by a cxl create-region of the claim"
		}
		if err := e.deleteHollow(ctx, serial, trigger, why); err != nil {
			return false, err
		}
	}
	return kept, nil
}

// releaseGone releases what is left of a memdev that is gone: its regions
// of ours that the kernel left hollow.
func (e *Engine) releaseGone(ctx context.Context, g *state.Grant, trigger state.Trigger) error {
	e.logf(g.Asked.Source, "memdev with serial %s is gone, nothing to release", serialText(g.Serial))
	return e.deleteHollow(ctx, g.Serial, trigger, "its memdev was removed before the region was destroyed")
}

// decision returns what the release does with the region of the memdev of
// the last grant g (Policy); decoders that cannot be read count as a
// region above.
func (e *Engine) decision(g *state.Grant, memdev string, release Release) Decision {
	kind := e.kindOf(g)
	var above []string
	var aboveErr error
	if release == ReleaseRecovery {
		above, aboveErr = e.k.RegionsAbove(memdev)
	}
	decision := Policy(release, kind, above)
	if aboveErr != nil && decision == Destroy {
		decision = Policy(release, kind, []string{"(" + aboveErr.Error() + ")"})
	}
	return decision
}

// releaseRegions releases the regions of ours of the memdev of the grant g
// by decision (Destroy, or InOrder), and tells whether a region was kept for
// the claim; one kept below newer regions of another memdev is KEPT for the
// claim (forClaim) or the memdev IDLE_KEPT with it.
func (e *Engine) releaseRegions(ctx context.Context, g *state.Grant, memdev string, decision Decision, forClaim bool, trigger state.Trigger) (bool, error) {
	source, serial := g.Asked.Source, g.Serial
	var regions []state.RegionRef
	if m := e.records().Memdev(serial); m != nil {
		regions = slices.Clone(m.Regions)
	}
	start := time.Now()
	for _, ref := range regions {
		name := string(ref)
		if _, err := e.k.Region(name); err != nil {
			if cerr := e.commit(ctx, func(r *state.Records) error { return dropRegion(r, ref, trigger) }); cerr != nil {
				return false, cerr
			}
			continue
		}
		var rs []string
		err := e.locked(func() error {
			if decision.inOrder() {
				var err error
				rs, err = e.k.ReleaseRegionInOrder(ctx, memdev, name)
				return err
			}
			return e.k.ReleaseRegion(ctx, name)
		})
		if err != nil {
			return false, err
		}
		if len(rs) > 0 {
			idle := "the idle device"
			if g.Asked.Kind == state.KindPersistent {
				idle = "the idle persistent device"
			}
			if forClaim {
				e.warnLocal(source, "memdev %s (serial %s): keeping %s for claims %v, whose Prepare did not finish: %s lie above it, its release would leave a hole in the decoders of their ports; their Unprepare releases it, their Prepare again reuses it",
					memdev, serialText(serial), name, []string{g.Ref.Claim}, strings.Join(rs, ", "))
			} else {
				e.warnLocal(source, "memdev %s (serial %s): keeping %s of %s: %s lie above it, its release would leave a hole in the decoders of their ports",
					memdev, serialText(serial), name, idle, strings.Join(rs, ", "))
			}
			return forClaim, e.keepMemdev(ctx, serial, trigger, forClaim)
		}
		if err := e.commit(ctx, func(r *state.Records) error { return dropRegion(r, ref, trigger) }); err != nil {
			return false, err
		}
		if source != state.SourcePool {
			// the pool logs the release of its memdev
			klog.Infof("local: memdev %s (serial %s): released %s in %s", memdev, serialText(serial), name, since(start))
		}
	}
	return false, nil
}

// disableMemdev disables a pool memdev so that the pool can detach it,
// unless it has a region that no record of the driver names (never
// touched; logged).
func (e *Engine) disableMemdev(ctx context.Context, source state.Source, serial state.Serial, memdev string) error {
	if rs := e.k.Regions(memdev); len(rs) > 0 {
		e.warnf(source, "memdev %s (serial %s): not disabling it: it has regions %v that no record of the driver names",
			memdev, serialText(serial), rs)
		return nil
	}
	if err := e.locked(func() error { return e.k.DisableMemdev(ctx, memdev) }); err != nil {
		return err
	}
	e.logf(source, "released %s (serial %s)", memdev, serialText(serial))
	return nil
}

// blockDeviceOf returns the block device whose holders the release of the
// last grant of a memdev, of the call, waits for: the recorded one unless
// the start did not mount its node mount again or it is not the one of its
// region now (checkBlockDevice: the region is gone, or its namespace has
// other numbers); then the recorded one may be another device's now, and
// the wait is for the current one of the region, none when the memdev has
// no region. The recorded one stays when the block device of the region is
// not known now: none would release it without the holder check. A grant
// of a cut Prepare waits for the current one.
func (e *Engine) blockDeviceOf(g *state.Grant, call *releaseCall) string {
	if g.Asked.Kind != state.KindPersistent {
		return ""
	}
	if g.Got.BlockDevice == nil {
		return e.currentBlockDevice(g.Serial)
	}
	recorded := g.Got.BlockDevice.Name
	var err error
	if path := call.unrestored[g.Ref]; path != "" {
		err = fmt.Errorf("its node mount %s was not mounted again at start", path)
	} else {
		err = e.checkBlockDevice(g)
	}
	if err == nil {
		return recorded
	}
	s, claim := serialText(g.Serial), e.claimNameOf(g.Ref)
	cur := e.currentBlockDevice(g.Serial)
	switch {
	case cur == "" && e.hasRegion(g.Serial) && e.otherBlockDevice(g.Got.BlockDevice):
		e.logf(g.Asked.Source, "claim %s: %v; %s is another block device now: the release of device %s waits for no holder of it",
			claim, err, recorded, s)
		return ""
	case cur == "" && e.hasRegion(g.Serial):
		e.warnf(g.Asked.Source, "claim %s: %v; the block device of the region of device %s is not known now: its release waits for the holders of %s as prepared",
			claim, err, s, recorded)
		return recorded
	case cur == "":
		e.logf(g.Asked.Source, "claim %s: %v; device %s has no region now: its release waits for no holder of %s", claim, err, s, recorded)
	default:
		e.logf(g.Asked.Source, "claim %s: %v; the release of device %s waits for the holders of %s, the block device of its region now, not of %s",
			claim, err, s, cur, recorded)
	}
	return cur
}

// otherBlockDevice tells whether the name of the recorded block device bd
// is a block device with other numbers now.
func (e *Engine) otherBlockDevice(bd *state.BlockDevice) bool {
	major, minor, _, err := e.k.BlockDeviceInfo(filepath.Base(bd.Name))
	return err == nil && (major != bd.Dev.Major || minor != bd.Dev.Minor)
}

// hasRegion tells whether the memdev with the serial has a region.
func (e *Engine) hasRegion(serial state.Serial) bool {
	memdev, err := e.k.FindMemdev(uint64(serial))
	return err == nil && len(e.k.Regions(memdev)) > 0
}

// claimNameOf returns the name of the claim of the grant ref (its
// preparation's), else its uid.
func (e *Engine) claimNameOf(ref state.GrantRef) string {
	if p := e.records().PreparationOf(ref); p != nil && p.ClaimName != "" {
		return p.ClaimName
	}
	return ref.Claim
}

// dropRegion removes a region of ours that is destroyed or gone from the
// records (its dax devices RELEASING -> ABSENT, the region -> NONE) and
// from its memdevs.
func dropRegion(r *state.Records, ref state.RegionRef, trigger state.Trigger) error {
	reg := r.Region(ref)
	if reg == nil {
		return nil
	}
	for i := range reg.DaxDevices {
		d := &reg.DaxDevices[i]
		if d.State != state.DaxReleasing && d.State != state.DaxSeed && d.State != state.DaxCreating {
			if err := state.Apply(&state.DaxDeviceTable, &d.State, state.DaxReleasing, trigger); err != nil {
				return err
			}
		}
	}
	if err := state.Apply(&state.RegionTable, &reg.State, state.RegionNone, trigger); err != nil {
		return err
	}
	removeRecord(&r.Regions, func(x *state.Region) bool { return x.Ref() == ref })
	for i := range r.Memdevs {
		r.Memdevs[i].Regions = removeRef(r.Memdevs[i].Regions, ref)
		r.Memdevs[i].Hollow = removeRef(r.Memdevs[i].Hollow, ref)
	}
	for i := range r.Grants {
		if r.Grants[i].Got.Region == ref {
			r.Grants[i].Got.Region, r.Grants[i].Got.Dax, r.Grants[i].Got.Mount = "", "", ""
		}
	}
	return nil
}

// keepMemdev records the regions of the memdev with the serial kept: KEPT
// (disabled, not set up) when kept for claims, as they are otherwise.
func (e *Engine) keepMemdev(ctx context.Context, serial state.Serial, trigger state.Trigger, forClaims bool) error {
	return e.commit(ctx, func(r *state.Records) error {
		m := r.Memdev(serial)
		if m == nil || !forClaims {
			return nil
		}
		for _, ref := range m.Regions {
			reg := r.Region(ref)
			if reg == nil || reg.State != state.RegionOwned {
				continue
			}
			if err := state.Apply(&state.RegionTable, &reg.State, state.RegionKept, trigger); err != nil {
				return err
			}
			// set up again, a kept region is zeroed again
			reg.Zeroed = false
			if reg.SetUp {
				if err := state.Apply(&state.RegionSetUpTable, &reg.SetUp, false, trigger); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// deleteHollow deletes the regions of ours of the memdev with the serial
// that the kernel left hollow (its memdev removed under them) and whose
// memory blocks are offline; one that cannot be deleted stays in the
// memdev's Hollow (logged with the command that deletes it).
func (e *Engine) deleteHollow(ctx context.Context, serial state.Serial, trigger state.Trigger, why string) error {
	m := e.records().Memdev(serial)
	if m == nil {
		return nil
	}
	source := m.Source
	for _, ref := range append(slices.Clone(m.Regions), m.Hollow...) {
		name := string(ref)
		if _, err := e.k.Region(name); err != nil {
			if err := e.commit(ctx, func(r *state.Records) error { return dropRegion(r, ref, trigger) }); err != nil {
				return err
			}
			continue
		}
		if !e.k.HollowRegion(name) {
			continue
		}
		e.warnf(source, "serial %s: %s has no target decoder (%s): deleting it", serialText(serial), name, why)
		if err := e.commit(ctx, func(r *state.Records) error { return hollowRegion(r, ref) }); err != nil {
			return err
		}
		if err := e.locked(func() error { return e.k.DeleteHollowRegion(name) }); err != nil {
			decoder, derr := e.k.RegionRootDecoder(name)
			if derr != nil {
				decoder = "<its root decoder>"
			}
			e.errorf(source, "serial %s: %v; it holds its address range until it is deleted, when none of its memory blocks is online: echo %s > /sys/bus/cxl/devices/%s/delete_region",
				serialText(serial), err, name, decoder)
			continue
		}
		e.logf(source, "serial %s: deleted hollow %s", serialText(serial), name)
		if err := e.commit(ctx, func(r *state.Records) error { return dropRegion(r, ref, trigger) }); err != nil {
			return err
		}
	}
	return nil
}

// hollowRegion records a region of ours whose memdev went under it
// (HOLLOW_OWNED), in the memdev's Hollow.
func hollowRegion(r *state.Records, ref state.RegionRef) error {
	reg := r.Region(ref)
	if reg == nil || reg.State == state.RegionHollowOwned {
		return nil
	}
	if err := state.Apply(&state.RegionTable, &reg.State, state.RegionHollowOwned, state.TriggerObserve); err != nil {
		return err
	}
	for _, serial := range reg.Targets {
		if m := r.Memdev(serial); m != nil {
			m.Regions = removeRef(m.Regions, ref)
			m.Hollow = addRef(m.Hollow, ref)
		}
	}
	return nil
}

// releaseStale releases a grant of a PREPARED_STALE preparation: nothing
// of it exists in this boot, so its memdev is released by its serial (a
// pool memdev that no grant of this boot uses is disabled when it has no
// region), the directory of its lease bind is removed when nothing is
// mounted there, and the grant is dropped.
func (e *Engine) releaseStale(ctx context.Context, ref state.GrantRef, trigger state.Trigger) error {
	r := e.records()
	g := r.Grant(ref)
	serial := g.Serial
	if target := g.Intent.BindTarget; target != "" {
		// the directory of the lease bind of another boot
		if mi, err := e.k.Mounted(target); err == nil && mi == nil {
			e.removeMountDir(g.Asked.Source, target)
		}
	}
	if g.Asked.Source == state.SourcePool && r.Memdev(serial) == nil {
		memdev, err := e.k.FindMemdev(uint64(serial))
		switch {
		case errors.Is(err, kernel.ErrNotFound):
			e.logf(g.Asked.Source, "memdev with serial %s is gone, nothing to release", serialText(serial))
		case err != nil:
			return err
		default:
			if err := e.disableMemdev(ctx, g.Asked.Source, serial, memdev); err != nil {
				return err
			}
		}
	}
	if err := e.commit(ctx, func(r *state.Records) error {
		g := r.Grant(ref)
		if g == nil {
			return nil
		}
		if err := state.Apply(&state.GrantTable, &g.State, state.GrantReleased, trigger); err != nil {
			return err
		}
		removeRecord(&r.Grants, func(x *state.Grant) bool { return x.Ref == ref })
		if m := r.Memdev(serial); m != nil {
			m.Grants = removeRef(m.Grants, ref)
		}
		return nil
	}); err != nil {
		return err
	}
	e.forgetDevice(ref)
	return nil
}
