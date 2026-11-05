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
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// ReleaseGrants releases the grants refs in their order as release says
// (Policy) and returns the errors of those that it could not release. A
// grant that is released is gone from the store; one whose release failed
// stays RELEASING with what it still has, and a retry finds out from the
// kernel what exists. A ref without a grant is not an error. A grant of a
// PREPARED_STALE preparation is released by its serial: a pool memdev that
// no grant of this boot uses is disabled.
func (e *Engine) ReleaseGrants(ctx context.Context, refs []state.GrantRef, release Release) error {
	trigger := triggerOf(release)
	var errs []error
	for _, ref := range refs {
		if err := e.releaseOne(ctx, ref, release, trigger); err != nil {
			errs = append(errs, err)
		}
	}
	e.verify(ctx, nil)
	return errors.Join(errs...)
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

// releaseOne releases a grant in the queue of its memdev.
func (e *Engine) releaseOne(ctx context.Context, ref state.GrantRef, release Release, trigger state.Trigger) error {
	g := e.records().Grant(ref)
	if g == nil {
		return nil
	}
	leave, err := e.acquire(ctx, g.Serial)
	if err != nil {
		return err
	}
	defer leave()
	return e.releaseGrant(ctx, ref, release, trigger)
}

// releaseGrant releases a grant, its memdev's queue held: RELEASING, its
// lease bind unbound, its node mount and block device released next to the
// other grants of the memdev, its own dax device deleted, the region per
// Policy when it was the last grant of the memdev, then RELEASED. A grant
// of a cut Prepare (JOURNALED, REALISING) that the recovery releases goes
// to RELEASED directly. A region that the policy keeps for the claim (a
// rollback or a recovery below a newer region of another memdev) is kept
// with the grant JOURNALED; the recovery keeps such a grant untouched.
func (e *Engine) releaseGrant(ctx context.Context, ref state.GrantRef, release Release, trigger state.Trigger) error {
	r := e.records()
	g := r.Grant(ref)
	if g == nil {
		return nil
	}
	if p := r.PreparationOf(ref); p != nil && p.State == state.PreparationStale {
		return e.releaseStale(ctx, ref, trigger)
	}
	if release == ReleaseRecovery && e.recoveryKeeps(g) {
		return e.keepForRecovery(ctx, g, trigger)
	}
	cut := release == ReleaseRecovery && (g.State == state.GrantJournaled || g.State == state.GrantRealising)
	if !cut {
		if err := e.commit(ctx, func(r *state.Records) error {
			g := r.Grant(ref)
			return state.Apply(&state.GrantTable, &g.State, state.GrantReleasing, trigger)
		}); err != nil {
			return err
		}
	}
	e.retryStale(ctx, g.Serial, trigger)
	cur := e.records().Grant(ref).Clone()
	if err := e.releaseObjects(ctx, &cur, trigger); err != nil {
		return err
	}
	last := true
	if m := e.records().Memdev(cur.Serial); m != nil {
		last = !slices.ContainsFunc(m.Grants, func(o state.GrantRef) bool { return o != ref })
	}
	if last {
		kept, err := e.releaseMemdev(ctx, &cur, release, trigger)
		if err != nil {
			return err
		}
		if kept {
			return e.keptForClaim(ctx, ref, trigger)
		}
	}
	return e.commit(ctx, func(r *state.Records) error { return releasedGrant(r, ref, trigger) })
}

// keepForRecovery keeps a cut grant whose region lies below a newer region
// of another memdev untouched (Policy ReleaseRecovery keeps): its region
// KEPT, the grant JOURNALED (a realised one as it is).
func (e *Engine) keepForRecovery(ctx context.Context, g *state.Grant, trigger state.Trigger) error {
	e.warnf(g.Asked.Source, "claim %s: not releasing its memdev %s at start: a region of another memdev lies above its region, a release would leave a hole in the decoders of their ports; its Unprepare releases it, its Prepare again reuses it",
		g.Ref.Claim, serialText(g.Serial))
	if err := e.keepMemdev(ctx, g.Serial, trigger, true); err != nil {
		return err
	}
	return e.keptForClaim(ctx, g.Ref, trigger)
}

// releaseObjects releases what a grant has of its own or shares: its lease
// bind, its node mount and block device next to the other grants of the
// memdev, its own dax device.
func (e *Engine) releaseObjects(ctx context.Context, g *state.Grant, trigger state.Trigger) error {
	if err := e.releaseBind(ctx, g, trigger); err != nil {
		return err
	}
	if err := e.releaseMount(ctx, g, trigger); err != nil {
		return err
	}
	return e.releaseDax(ctx, g, trigger)
}

// recoveryKeeps tells whether the recovery keeps the objects of a cut grant
// untouched: it is the last grant of its memdev, whose region lies below a
// region of another memdev (Policy ReleaseRecovery keeps).
func (e *Engine) recoveryKeeps(g *state.Grant) bool {
	r := e.records()
	if m := r.Memdev(g.Serial); m == nil || slices.ContainsFunc(m.Grants, func(o state.GrantRef) bool { return o != g.Ref }) {
		return false
	}
	memdev, err := e.k.FindMemdev(uint64(g.Serial))
	if err != nil {
		return false
	}
	above, err := e.k.RegionsAbove(memdev)
	if err != nil {
		above = []string{"(" + err.Error() + ")"}
	}
	shared := e.opts.Shared != nil && e.opts.Shared(g.Serial)
	return Policy(ReleaseRecovery, kindOf(g.Asked, shared), above) == Keep
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
	case len(m.Regions) == 0 && len(m.Hollow) == 0:
		if err := state.Apply(&state.MemdevTable, &m.State, state.MemdevUnused, trigger); err != nil {
			return err
		}
		removeRecord(&r.Memdevs, func(x *state.Memdev) bool { return x.Serial == serial })
		return nil
	case m.State == state.MemdevActive && len(m.Regions) > 0:
		return state.Apply(&state.MemdevTable, &m.State, state.MemdevIdleKept, trigger)
	}
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

// retryStale unmounts the stale lease binds of the memdev with the serial
// that no prepared grant lists again, and forgets those that are gone.
// Errors are logged.
func (e *Engine) retryStale(ctx context.Context, serial state.Serial, trigger state.Trigger) {
	m := e.records().Memdev(serial)
	if m == nil || len(m.Stale) == 0 {
		return
	}
	var gone []state.StalePath
	for _, sp := range m.Stale {
		if sp.Kind != state.StaleBind || e.bindUsed(sp.Path, state.GrantRef{}) {
			continue
		}
		if err := e.unbind(m.Source, "stale lease bind", sp.Path); err != nil {
			klog.Errorf("%s: %v", e.driver(m.Source), err)
			continue
		}
		gone = append(gone, sp)
	}
	if len(gone) == 0 {
		return
	}
	if err := e.commit(ctx, func(r *state.Records) error { return forgetStale(r, serial, gone, trigger) }); err != nil {
		klog.Errorf("engine: memdev %s: %v", serial, err)
	}
}

// forgetStale removes the stale lease binds gone of the memdev with the
// serial, their grants' binds ABSENT.
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

// releaseMount releases the use of the block device or node mount of a
// persistent grant next to the other grants of the memdev, and removes the
// grant from the users of its node mount. The node mount of a grant that a
// cut Prepare left is the one of its intent when a mount of its device is
// there.
func (e *Engine) releaseMount(ctx context.Context, g *state.Grant, trigger state.Trigger) error {
	if g.Asked.Kind != state.KindPersistent {
		return nil
	}
	r := e.records()
	remaining := usesOf(r, g.Serial, g.Ref)
	u := useOf(g)
	if u.nodeMount == "" {
		u = e.cutMountUse(g, u)
	}
	leave := func(r *state.Records) error { return leaveMount(r, g.Ref, firstWriter(remaining) != nil, trigger) }
	if g.Got.BlockDevice == nil && u.nodeMount == "" {
		return e.commit(ctx, leave)
	}
	gone := []use{u}
	if reg := r.Region(g.Got.Region); reg != nil && g.Got.Mount != "" {
		if m := reg.Mount(g.Got.Mount); m != nil && (m.State == state.MountUnrestored || m.State == state.MountForeign) {
			// nothing of ours mounted to release
			gone = nil
		}
	}
	if err := e.releaseUses(g.Asked.Source, g.Serial, gone, remaining); err != nil {
		return err
	}
	return e.commit(ctx, leave)
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

// leaveMount removes a grant from the users of the node mounts that list
// it: a mount without users is gone (ABSENT), one without a writer left
// read-only.
func leaveMount(r *state.Records, ref state.GrantRef, writer bool, trigger state.Trigger) error {
	if rg := r.Grant(ref); rg != nil {
		rg.Got.Mount, rg.Got.MountPath, rg.Got.Loop = "", "", ""
	}
	for i := range r.Regions {
		reg := &r.Regions[i]
		for j := 0; j < len(reg.Mounts); j++ {
			m := &reg.Mounts[j]
			if !slices.Contains(m.Users, ref) {
				continue
			}
			m.Users = removeRef(m.Users, ref)
			switch {
			case m.State == state.MountForeign:
				// never used or unmounted: it goes with its region
			case len(m.Users) == 0:
				if err := state.Apply(&state.MountTable, &m.State, state.MountAbsent, trigger); err != nil {
					return err
				}
				reg.Mounts = slices.Delete(reg.Mounts, j, j+1)
				j--
			case m.State == state.MountedRW && !writer:
				m.Writer = false
				if err := state.Apply(&state.MountTable, &m.State, state.MountedRO, trigger); err != nil {
					return err
				}
			case m.State == state.MountedRO || m.State == state.MountedRW:
				if err := state.Apply(&state.MountTable, &m.State, m.State, trigger); err != nil {
					return err
				}
			}
		}
	}
	return nil
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
	start := time.Now()
	if err := e.offlineDax(ctx, dax); err != nil {
		return fmt.Errorf("memdev %s: releasing %w", serialText(g.Serial), err)
	}
	if err := e.locked(func() error { return e.k.DeleteDaxDevice(ctx, region, dax) }); err != nil {
		return fmt.Errorf("memdev %s: releasing %s: %w", serialText(g.Serial), dax, err)
	}
	e.logf(g.Asked.Source, "memdev %s: claim %s: deleted %s mode %s size %d in %s", serialText(g.Serial), g.Ref.Claim, dax,
		g.Asked.Mode, d.Size, since(start))
	return e.commit(ctx, func(r *state.Records) error { return releasedDax(r, g.Ref, g.Got.Region, dax, trigger) })
}

// offlineDax offlines the memory blocks of a dax device bound to kmem, under
// the engine lock.
func (e *Engine) offlineDax(ctx context.Context, dax string) error {
	if e.k.DaxDriver(dax) != kernel.DriverKmem {
		return nil
	}
	bs, err := e.k.BlockSize()
	var blocks []int
	if err == nil {
		blocks, err = e.k.DaxDeviceBlocks(dax, bs)
	}
	if err == nil {
		err = e.locked(func() error { return e.k.OfflineBlocks(ctx, blocks, 0, 0) })
	}
	if err != nil {
		return fmt.Errorf("%s: cannot offline its memory (in use?): %w", dax, err)
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
func (e *Engine) releaseMemdev(ctx context.Context, g *state.Grant, release Release, trigger state.Trigger) (bool, error) {
	source, serial := g.Asked.Source, g.Serial
	memdev, err := e.k.FindMemdev(uint64(serial))
	if errors.Is(err, kernel.ErrNotFound) {
		return false, e.releaseGone(ctx, g, trigger)
	}
	if err != nil {
		return false, err
	}
	if m := e.records().Memdev(serial); m != nil && len(m.Hollow) > 0 {
		if err := e.deleteHollow(ctx, serial, trigger, "a cxl create-region of the grant did not finish"); err != nil {
			return false, err
		}
	}
	decision := e.decision(g, memdev, release)
	forClaim := release == ReleaseRollback || release == ReleaseRecovery
	if decision == Keep {
		return forClaim, e.keepMemdev(ctx, serial, trigger, forClaim)
	}
	if dev := e.blockDeviceOf(g); dev != "" {
		if err := e.waitNoHolder(ctx, source, serial, dev, time.Now().Add(e.opts.Timeouts.Holder), trigger); err != nil {
			return false, fmt.Errorf("releasing serial %s: %w", serialText(serial), err)
		}
	}
	kept, err := e.releaseRegions(ctx, g, memdev, decision, forClaim, trigger)
	if err != nil || kept {
		return kept, err
	}
	if source == state.SourcePool {
		return false, e.disableMemdev(ctx, source, serial, memdev)
	}
	return false, nil
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
	shared := e.opts.Shared != nil && e.opts.Shared(g.Serial)
	kind := kindOf(g.Asked, shared)
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
			if decision == InOrder {
				var err error
				rs, err = e.k.ReleaseRegionInOrder(ctx, memdev, name)
				return err
			}
			return e.k.ReleaseRegion(ctx, name)
		})
		if err != nil {
			return false, fmt.Errorf("memdev %s (serial %s): releasing its region: %w", memdev, serialText(serial), err)
		}
		if len(rs) > 0 {
			if forClaim {
				e.warnf(source, "memdev %s (serial %s): keeping %s for claims %v, whose Prepare did not finish: %s lie above it, its release would leave a hole in the decoders of their ports; their Unprepare releases it, their Prepare again reuses it",
					memdev, serialText(serial), name, []string{g.Ref.Claim}, strings.Join(rs, ", "))
			} else {
				e.warnf(source, "memdev %s (serial %s): keeping %s of the idle device: %s lie above it, its release would leave a hole in the decoders of their ports",
					memdev, serialText(serial), name, strings.Join(rs, ", "))
			}
			return forClaim, e.keepMemdev(ctx, serial, trigger, forClaim)
		}
		if err := e.commit(ctx, func(r *state.Records) error { return dropRegion(r, ref, trigger) }); err != nil {
			return false, err
		}
		e.logf(source, "released %s (serial %s)", name, serialText(serial))
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
// last grant of a memdev waits for: the recorded one when it is the one of
// the region now, else the current one of the region.
func (e *Engine) blockDeviceOf(g *state.Grant) string {
	if g.Asked.Kind != state.KindPersistent {
		return ""
	}
	if g.Got.BlockDevice != nil {
		if err := e.checkBlockDevice(g); err == nil {
			return g.Got.BlockDevice.Name
		}
	}
	return e.currentBlockDevice(g.Serial)
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
// region), and the grant is dropped.
func (e *Engine) releaseStale(ctx context.Context, ref state.GrantRef, trigger state.Trigger) error {
	r := e.records()
	g := r.Grant(ref)
	serial := g.Serial
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
	return e.commit(ctx, func(r *state.Records) error {
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
	})
}
