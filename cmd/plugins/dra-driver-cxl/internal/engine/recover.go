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
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// errForeignMount is the kind of the error of a node mount path where
// something else than the node mount of the grants is mounted.
var errForeignMount = errors.New("something else is mounted at the node mount")

// Recovered is what the first phase of the recovery did.
type Recovered struct {
	// Released are the grants of Prepares that a process stop cut whose
	// objects were released.
	Released []state.GrantRef
	// Kept are the grants of cut Prepares whose objects were kept: their
	// region lies below a newer region of another memdev, or their release
	// failed.
	Kept []state.GrantRef
	// Absent are the grants of cut Prepares whose memdev is absent, kept
	// for kubelet's Unprepare.
	Absent []state.GrantRef
	// Companions are the grants of cut Prepares of companion claims of mode
	// numa, kept for kubelet's Unprepare (which revokes, then releases)
	// and Prepare again (which reuses).
	Companions []state.GrantRef
	// Unrestored are the realised grants whose objects did not verify
	// (no CDI device for their claims), Restored those that verify again.
	Unrestored, Restored []state.GrantRef
	// Why are the reasons of the grants of prepared claims whose node
	// mount is not mounted after the start: the Unrestored ones and those
	// that were unrestored already.
	Why map[state.GrantRef]error
}

// Recover is the first phase of the recovery at the start of the process,
// before NRI and kubelet: the records of the store (of this boot, as the
// store left them at its load) are matched with the kernel, in this order:
//   - memdevs that are absent are GONE (their grants kept for kubelet's
//     Unprepare), noted regions are those of their name that exist on
//     their memdev (OWNED, HOLLOW_OWNED) or none, owned regions that are
//     gone are dropped;
//   - the node mounts of the realised grants of PREPARED and
//     PREPARED_UNRESTORED claims are mounted again by the identity of their
//     block device (else the grant
//     is REALISED_UNRESTORED and its preparation PREPARED_UNRESTORED), the
//     lease binds of realised companion grants bound again;
//   - the grants of Prepares that a process stop cut (JOURNALED, REALISING,
//     and the REALISED and RELEASING grants of PREPARING preparations: a
//     rollback that a stop cut; not of PREPARED_STALE ones), but those of
//     companion claims of mode numa and those of absent memdevs, are
//     released per Policy (ReleaseRecovery), the top-most region first
//     across memdevs, with a holder deadline per claim; a kept one makes
//     its preparation KEPT;
//   - the node mounts and lease binds under the driver's directories that
//     no realised grant of a prepared claim lists are unmounted, the dax
//     devices of our regions that no record names deleted, our hollow
//     regions deleted when their memory is offline.
func (e *Engine) Recover(ctx context.Context) (*Recovered, error) {
	out := &Recovered{Why: map[state.GrantRef]error{}}
	snap, err := e.Observe(ctx)
	if err != nil {
		return nil, err
	}
	if err := e.recoverMemdevs(ctx, snap); err != nil {
		return nil, err
	}
	if err := e.recoverRegions(ctx, snap); err != nil {
		return nil, err
	}
	if err := e.restoreGrants(ctx, out); err != nil {
		return nil, err
	}
	e.restoreBinds(ctx)
	e.releaseCut(ctx, out)
	if err := e.recoverPreparations(ctx, out); err != nil {
		return nil, err
	}
	e.sweepBinds(ctx)
	e.sweepNodeMounts()
	e.deleteUnowned(ctx)
	for _, m := range e.records().Memdevs {
		if len(m.Hollow) > 0 && e.owns(m.Source) {
			if err := e.deleteHollow(ctx, m.Serial, state.TriggerRecover, "its memdev was removed before the region was destroyed"); err != nil {
				klog.Errorf("engine: %v", err)
			}
		}
	}
	if err := e.commit(ctx, func(r *state.Records) error { return dropUnused(r, e.owns) }); err != nil {
		return nil, err
	}
	return out, nil
}

// dropUnused removes the memdev records of which nothing is left (UNUSED):
// no grant, no region of ours, no stale lease bind or node mount.
func dropUnused(r *state.Records, owns func(state.Source) bool) error {
	for i := range r.Memdevs {
		m := &r.Memdevs[i]
		if !owns(m.Source) || !unused(m) || m.State == state.MemdevIdleKept {
			continue
		}
		if err := state.Apply(&state.MemdevTable, &m.State, state.MemdevUnused, state.TriggerRecover); err != nil {
			return err
		}
	}
	removeRecord(&r.Memdevs, func(m *state.Memdev) bool { return m.State == state.MemdevUnused })
	return nil
}

// RecoverCompanions is the second phase of the recovery, once the lenders
// are wired: the grants of cut Prepares of companion claims of mode numa
// stay as they are for kubelet's Unprepare and Prepare again; it returns
// them.
func (e *Engine) RecoverCompanions() []state.GrantRef {
	var out []state.GrantRef
	r := e.records()
	for i := range r.Grants {
		if g := &r.Grants[i]; cutGrant(r, g) && numaCompanion(g) && e.owns(g.Asked.Source) {
			out = append(out, g.Ref)
		}
	}
	return out
}

// numaCompanion tells whether a grant is one of a companion claim of mode
// numa.
func numaCompanion(g *state.Grant) bool {
	return g.Intent.Lend != nil && g.Asked.Mode == state.ModeNUMA
}

// cutGrant tells whether a grant is one of a Prepare that a process stop
// cut: JOURNALED or REALISING, or REALISED or RELEASING (a rollback that the
// stop cut) of a PREPARING preparation.
func cutGrant(r *state.Records, g *state.Grant) bool {
	p := r.PreparationOf(g.Ref)
	if p != nil && p.State == state.PreparationStale {
		// nothing of another boot is left: released by its Unprepare
		return false
	}
	if g.State == state.GrantJournaled || g.State == state.GrantRealising {
		return true
	}
	return p != nil && p.State == state.PreparationPreparing && (g.State == state.GrantRealised || g.State == state.GrantReleasing)
}

// recoverMemdevs makes the memdev records of memdevs that are absent GONE,
// and those of memdevs that are back ACTIVE.
func (e *Engine) recoverMemdevs(ctx context.Context, snap *kernel.Snapshot) error {
	var gone, back []state.Serial
	for _, m := range e.records().Memdevs {
		if !e.owns(m.Source) {
			continue
		}
		present := snap.Memdev(uint64(m.Serial)).State != kernel.MemdevAbsent
		switch {
		case !present && m.State != state.MemdevGone:
			gone = append(gone, m.Serial)
		case present && m.State == state.MemdevGone && len(m.Grants) > 0:
			back = append(back, m.Serial)
		}
	}
	if len(gone)+len(back) == 0 {
		return nil
	}
	if err := e.commit(ctx, func(r *state.Records) error { return memdevsSeen(r, gone, back) }); err != nil {
		return err
	}
	for _, serial := range gone {
		if m := e.records().Memdev(serial); m != nil {
			klog.Warningf("%s: memdev with serial %s is absent: its records are kept for kubelet's Unprepare of its claims",
				e.driver(m.Source), serialText(serial))
		}
	}
	return nil
}

// memdevsSeen records the memdevs of the serials gone GONE and those of back
// ACTIVE again.
func memdevsSeen(r *state.Records, gone, back []state.Serial) error {
	for _, serial := range gone {
		if m := r.Memdev(serial); m != nil {
			if err := state.Apply(&state.MemdevTable, &m.State, state.MemdevGone, state.TriggerRecover); err != nil {
				return err
			}
		}
	}
	for _, serial := range back {
		if m := r.Memdev(serial); m != nil {
			if err := state.Apply(&state.MemdevTable, &m.State, state.MemdevActive, state.TriggerRecover); err != nil {
				return err
			}
		}
	}
	return nil
}

// recoverRegions matches the region records with the kernel: a noted region
// of that name on its memdev is OWNED (HOLLOW_OWNED when hollow), else the
// note is cleared; an OWNED or KEPT region that is gone is dropped (its
// grants keep the rest for kubelet), one whose memdev is gone is
// HOLLOW_OWNED.
func (e *Engine) recoverRegions(ctx context.Context, snap *kernel.Snapshot) error {
	seen := map[state.RegionRef]regionSeen{}
	r := e.records()
	for _, reg := range r.Regions {
		if !reg.Ours() || !e.ownsRegion(r, &reg) {
			continue
		}
		ri := snap.Region(string(reg.Ref()))
		exists := ri.State != kernel.RegionAbsent
		seen[reg.Ref()] = regionSeen{
			exists: exists,
			mine:   exists && len(reg.Targets) > 0 && slices.Contains(ri.Serials, uint64(reg.Targets[0])),
			hollow: ri.State == kernel.RegionHollow,
			info:   ri,
		}
	}
	var dropped []state.RegionRef
	if err := e.commit(ctx, func(r *state.Records) error {
		var err error
		dropped, err = regionsSeen(r, seen)
		return err
	}); err != nil {
		return err
	}
	for _, ref := range dropped {
		klog.Warningf("engine: %s is gone: its record is dropped, its grants kept for kubelet", ref)
	}
	return nil
}

// regionSeen is what the kernel has of a region record at a start.
type regionSeen struct {
	exists, mine, hollow bool
	info                 kernel.RegionInfo
}

// regionsSeen matches the region records with what the kernel has of them
// (seen) and returns the refs of the OWNED or KEPT records that it dropped
// because their region is gone.
func regionsSeen(r *state.Records, seen map[state.RegionRef]regionSeen) ([]state.RegionRef, error) {
	var dropped []state.RegionRef
	for _, ref := range regionRefs(r) {
		reg := r.Region(ref)
		k, ok := seen[ref]
		if !ok {
			continue
		}
		switch reg.State {
		case state.RegionNoted, state.RegionCreating:
			if err := recoverNoted(r, reg, k); err != nil {
				return nil, err
			}
		case state.RegionOwned, state.RegionKept:
			switch {
			case k.hollow:
				if err := hollowRecovered(r, ref); err != nil {
					return nil, err
				}
			case !k.exists || !k.mine:
				if err := dropRegion(r, ref, state.TriggerRecover); err != nil {
					return nil, err
				}
				dropped = append(dropped, ref)
			}
		}
	}
	return dropped, nil
}

// regionRefs returns the refs of the region records.
func regionRefs(r *state.Records) []state.RegionRef {
	var out []state.RegionRef
	for i := range r.Regions {
		out = append(out, r.Regions[i].Ref())
	}
	return out
}

// recoverNoted resolves a NOTED or CREATING region at a start: the region
// of its name exists on its memdev (OWNED), hollow (HOLLOW_OWNED), or not
// (the note cleared).
func recoverNoted(r *state.Records, reg *state.Region, k regionSeen) error {
	ref := reg.Ref()
	switch {
	case k.hollow:
		if err := state.Apply(&state.RegionTable, &reg.State, state.RegionHollowOwned, state.TriggerRecover); err != nil {
			return err
		}
		reg.Name = string(ref)
		for _, serial := range reg.Targets {
			if m := r.Memdev(serial); m != nil {
				m.Regions = removeRef(m.Regions, ref)
				m.Hollow = addRef(m.Hollow, ref)
			}
		}
	case k.mine:
		if err := state.Apply(&state.RegionTable, &reg.State, state.RegionOwned, state.TriggerRecover); err != nil {
			return err
		}
		reg.Name, reg.NotedName = string(ref), ""
		reg.NumaNode = state.NumaNodePtr(k.info.NumaNode)
		reg.Size = k.info.Range.Size()
	default:
		if err := state.Apply(&state.RegionTable, &reg.State, state.RegionNone, state.TriggerRecover); err != nil {
			return err
		}
		removeRecord(&r.Regions, func(x *state.Region) bool { return x.Ref() == ref })
		for i := range r.Memdevs {
			r.Memdevs[i].Regions = removeRef(r.Memdevs[i].Regions, ref)
		}
		for i := range r.Grants {
			if r.Grants[i].Intent.Region == ref {
				r.Grants[i].Intent.Region = ""
			}
		}
	}
	return nil
}

// hollowRecovered records a region of ours that a start finds hollow.
func hollowRecovered(r *state.Records, ref state.RegionRef) error {
	reg := r.Region(ref)
	if err := state.Apply(&state.RegionTable, &reg.State, state.RegionHollowOwned, state.TriggerRecover); err != nil {
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

// restoreGrants mounts again the node mounts of the realised grants of the
// prepared claims, by the identity of their block device, with the state
// of the superblock and the read-only flags that the grants of the device
// derive. A grant whose node mount cannot be mounted again is
// REALISED_UNRESTORED (its node mount UNRESTORED); an unrestored one that
// verifies again is REALISED.
func (e *Engine) restoreGrants(ctx context.Context, out *Recovered) error {
	r := e.records()
	serials := map[state.Serial]bool{}
	for i := range r.Grants {
		g := &r.Grants[i]
		if !e.owns(g.Asked.Source) {
			continue
		}
		if p := r.PreparationOf(g.Ref); p != nil && p.Prepared() && p.State != state.PreparationUnpreparing && prepared(g) {
			serials[g.Serial] = true
		}
	}
	for _, serial := range sortedKeys(serials) {
		failed, restored, loops := e.restoreSerial(serial, out.Why)
		if len(failed) == 0 && len(restored) == 0 && len(loops) == 0 {
			continue
		}
		if err := e.commit(ctx, func(r *state.Records) error {
			remounted(r, loops)
			return unrestored(r, failed, restored)
		}); err != nil {
			return err
		}
		for ref := range failed {
			out.Unrestored = append(out.Unrestored, ref)
		}
		out.Restored = append(out.Restored, restored...)
	}
	slices.SortFunc(out.Unrestored, state.GrantRef.Compare)
	return nil
}

// restoreSerial restores the node mounts of the realised grants of the
// memdev with the serial, and returns the grants that do not verify, with
// why (also in why with those that stay unrestored), and the unrestored
// ones that verify again.
func (e *Engine) restoreSerial(serial state.Serial, why map[state.GrantRef]error) (map[state.GrantRef]error, []state.GrantRef, map[string]string) {
	uses := e.preparedUses(serial)
	writer := firstWriter(uses) != nil
	byMount := e.restoreMounts(uses, writer)
	failed, restored := e.classifyRestored(serial, byMount, why)
	if dev := blockDeviceOf(uses); dev != "" && e.checkUseBlockDevice(serial, dev) == nil {
		e.restoreFlags(serial, dev, uses, writer)
	}
	loops := map[string]string{}
	for _, u := range uses {
		if rm, ok := byMount[u.nodeMount]; ok && rm.err == nil && rm.loop != u.loop && u.access == api.AccessCached {
			e.logf(u.source, "device %s: %s is on %s now, not %s", serialText(serial), u.nodeMount, rm.loop, u.loop)
			loops[u.nodeMount] = rm.loop
		}
	}
	return failed, restored, loops
}

// remounted records the loop devices of the cached node mounts that are on
// another one now (loops by node mount path) in their mounts and grants.
func remounted(r *state.Records, loops map[string]string) {
	for i := range r.Regions {
		for j := range r.Regions[i].Mounts {
			if m := &r.Regions[i].Mounts[j]; loops[m.Path] != "" {
				m.Loop = loops[m.Path]
			}
		}
	}
	for i := range r.Grants {
		if g := &r.Grants[i]; loops[mountPathOf(r, g)] != "" {
			g.Got.Loop = loops[mountPathOf(r, g)]
		}
	}
}

// preparedUses returns the uses of the memdev with the serial by the grants
// of PREPARED and PREPARED_UNRESTORED preparations: those that a start
// restores (not the grants of cut Prepares, not those being unprepared).
func (e *Engine) preparedUses(serial state.Serial) []use {
	r := e.records()
	var out []use
	for _, u := range usesOf(r, serial) {
		if p := r.PreparationOf(u.ref); p != nil && (p.State == state.PreparationPrepared || p.State == state.PreparationUnrestored) {
			out = append(out, u)
		}
	}
	return out
}

// restoreMounts restores the node mount of each of the uses and returns why
// each that is not mounted afterwards is not, by node mount.
func (e *Engine) restoreMounts(uses []use, writer bool) map[string]restoredMount {
	byMount := map[string]restoredMount{}
	for _, mnt := range nodeMounts(uses) {
		i := slices.IndexFunc(uses, func(u use) bool { return u.nodeMount == mnt })
		loop, err := e.restoreNodeMount(&uses[i], writer, nodeMounts(uses))
		switch {
		case err != nil && errors.Is(err, errForeignMount):
			e.errorf(uses[i].source, "%v: it is never used or unmounted by the driver", err)
		case err != nil:
			e.errorf(uses[i].source, "claim %s: %v", e.claimNameOf(uses[i].ref), err)
		}
		byMount[mnt] = restoredMount{loop: loop, err: err}
	}
	return byMount
}

// checkRestoredMount checks what is mounted at the node mount of the use u
// at a start, mi, and returns the loop device of a cached one and whether
// it verifies: an error of kind errForeignMount when it is not the device
// of the grants; the device of the grants with other options or another
// type, or a mount whose device cannot be told, is logged and stays theirs
// as it is (released with them).
func (e *Engine) checkRestoredMount(u *use, mi *kernel.MountInfo) (string, bool, error) {
	ok, err := e.isDeviceMount(mi, u.blockDevice, u.access)
	if err == nil && !ok {
		_, cerr := e.checkNodeMount(u.serial, u.blockDevice, u.access, u.fsType, mi)
		return "", false, fmt.Errorf("%w: %w", errForeignMount, cerr)
	}
	loop := ""
	if err == nil {
		loop, err = e.checkNodeMount(u.serial, u.blockDevice, u.access, u.fsType, mi)
	}
	if err != nil {
		e.errorf(u.source, "claim %s: %v", e.claimNameOf(u.ref), err)
		if u.access == api.AccessCached {
			loop = mi.Source
		}
		return loop, false, nil
	}
	return loop, true, nil
}

// restoredMount is the result of the restore of a node mount: its loop
// device now (cached), or the error that leaves its grants unrestored.
type restoredMount struct {
	loop string
	err  error
}

// classifyRestored returns the realised grants of prepared claims of the
// memdev with the serial whose node mount was not restored (byMount), with
// why (in why also those that stay unrestored), and the unrestored ones
// whose node mount is mounted again.
func (e *Engine) classifyRestored(serial state.Serial, byMount map[string]restoredMount, why map[state.GrantRef]error) (map[state.GrantRef]error, []state.GrantRef) {
	failed := map[state.GrantRef]error{}
	var restored []state.GrantRef
	r := e.records()
	for i := range r.Grants {
		g := &r.Grants[i]
		path := mountPathOf(r, g)
		if g.Serial != serial || !prepared(g) || path == "" {
			// only node mounts are verified at a start
			continue
		}
		rm, ok := byMount[path]
		err := rm.err
		if ok && err != nil {
			why[g.Ref] = err
		}
		switch {
		case !ok:
		case err != nil && g.State == state.GrantRealised:
			failed[g.Ref] = err
		case err == nil && g.State == state.GrantUnrestored:
			restored = append(restored, g.Ref)
		}
	}
	return failed, restored
}

// restoreFlags sets the read-only flags of the block device dev and of the
// loop devices of the node mounts of the uses as the uses derive. Errors
// are logged: the next Prepare or release of the device tries again.
func (e *Engine) restoreFlags(serial state.Serial, dev string, uses []use, writer bool) {
	source := uses[0].source
	var loops []string
	for _, mnt := range nodeMounts(uses) {
		if mi, err := e.k.Mounted(mnt); err == nil && mi != nil && e.loopOf(mi) != "" && !isReadOnlyType(mi.FsType) {
			loops = append(loops, e.loopOf(mi))
		}
	}
	var errs []error
	if writer {
		errs = append(errs, e.setReadOnly(source, serial, dev, false))
		for _, l := range loops {
			errs = append(errs, e.setReadOnly(source, serial, l, false))
		}
	} else {
		for _, l := range loops {
			errs = append(errs, e.setReadOnly(source, serial, l, true))
		}
		errs = append(errs, e.setReadOnly(source, serial, dev, true))
	}
	if err := errors.Join(errs...); err != nil {
		e.errorf(source, "%v", err)
	}
}

// restoreNodeMount returns the loop device of the node mount of a use after
// it mounted it again when it is missing and its block device is the one
// prepared, or checked the mount there; an existing superblock is made
// read-write for a writer of the device or read-only without one, a failure
// of that is logged. explained are the node mounts of the uses of the
// device.
func (e *Engine) restoreNodeMount(u *use, writer bool, explained []string) (string, error) {
	mi, err := e.k.Mounted(u.nodeMount)
	if err != nil {
		return "", err
	}
	if mi == nil {
		e.logf(u.source, "device %s: %s is not mounted, mounting it again", serialText(u.serial), u.nodeMount)
		if err := e.checkUseBlockDevice(u.serial, u.blockDevice); err != nil {
			e.removeMountDir(u.source, u.nodeMount)
			return "", fmt.Errorf("not mounting %s again: %w", u.nodeMount, err)
		}
		return e.mountNode(u.source, u.serial, u.blockDevice, u.access, u.fsType, u.nodeMount, writer, explained)
	}
	loop, verified, err := e.checkRestoredMount(u, mi)
	if err != nil || !verified {
		return loop, err
	}
	switch {
	case writer && mi.SuperReadOnly() && isUpgradable(mi.FsType):
		err = e.upgrade(u.source, u.serial, u.blockDevice, loop, u.nodeMount, explained)
	case writer && mi.SuperReadOnly():
		err = fmt.Errorf("device %s: %s is mounted read-only and cannot be remounted read-write (%s)", serialText(u.serial), u.nodeMount, mi.FsType)
	case !writer && !mi.SuperReadOnly():
		err = e.downgrade(u.source, u.serial, u.blockDevice, loop, u.nodeMount)
	}
	if err != nil {
		e.errorf(u.source, "%v", err)
	}
	return loop, nil
}

// unrestored records the grants that did not verify REALISED_UNRESTORED
// (their node mounts UNRESTORED, or FOREIGN when something else is mounted
// there; their preparations PREPARED_UNRESTORED) and those that verify
// again REALISED (their preparations PREPARED when every grant is).
func unrestored(r *state.Records, failed map[state.GrantRef]error, restored []state.GrantRef) error {
	for ref, why := range failed {
		if err := grantUnrestored(r, ref, why); err != nil {
			return err
		}
	}
	for _, ref := range restored {
		if err := grantRestored(r, ref); err != nil {
			return err
		}
	}
	for i := range r.Preparations {
		p := &r.Preparations[i]
		if p.State != state.PreparationUnrestored || !allRealised(r, p) {
			continue
		}
		if err := state.Apply(&state.PreparationTable, &p.State, state.PreparationPrepared, state.TriggerRecover); err != nil {
			return err
		}
	}
	return nil
}

// grantUnrestored records a grant whose node mount was not restored, for
// why.
func grantUnrestored(r *state.Records, ref state.GrantRef, why error) error {
	g := r.Grant(ref)
	if err := state.Apply(&state.GrantTable, &g.State, state.GrantUnrestored, state.TriggerRecover); err != nil {
		return err
	}
	if reg := r.Region(g.Got.Region); reg != nil && g.Got.Mount != "" {
		to := state.MountUnrestored
		if errors.Is(why, errForeignMount) {
			to = state.MountForeign
		}
		if m := reg.Mount(g.Got.Mount); m != nil && m.State != state.MountUnrestored && m.State != state.MountForeign {
			if err := state.Apply(&state.MountTable, &m.State, to, state.TriggerRecover); err != nil {
				return err
			}
			m.Writer = false
		}
	}
	if p := r.PreparationOf(ref); p != nil && p.State == state.PreparationPrepared {
		return state.Apply(&state.PreparationTable, &p.State, state.PreparationUnrestored, state.TriggerRecover)
	}
	return nil
}

// grantRestored records an unrestored grant whose node mount is mounted
// again.
func grantRestored(r *state.Records, ref state.GrantRef) error {
	g := r.Grant(ref)
	if err := state.Apply(&state.GrantTable, &g.State, state.GrantRealised, state.TriggerRecover); err != nil {
		return err
	}
	reg := r.Region(g.Got.Region)
	if reg == nil || g.Got.Mount == "" {
		return nil
	}
	m := reg.Mount(g.Got.Mount)
	if m == nil || m.State != state.MountUnrestored {
		return nil
	}
	want := state.MountedRO
	if mountWriter(r, m) {
		want, m.Writer = state.MountedRW, true
	}
	return state.Apply(&state.MountTable, &m.State, want, state.TriggerRecover)
}

// mountWriter tells whether a user of the node mount writes.
func mountWriter(r *state.Records, m *state.Mount) bool {
	for _, ref := range m.Users {
		if g := r.Grant(ref); g != nil && !g.Asked.ReadOnly {
			return true
		}
	}
	return false
}

// allRealised tells whether every grant result of a preparation is
// REALISED.
func allRealised(r *state.Records, p *state.Preparation) bool {
	for _, res := range p.Results {
		if res.Grant == nil {
			continue
		}
		if g := r.Grant(*res.Grant); g == nil || g.State != state.GrantRealised {
			return false
		}
	}
	return true
}

// restoreBinds binds again the lease binds of the realised companion
// grants of prepared claims whose node mount is mounted. Errors are
// logged.
func (e *Engine) restoreBinds(ctx context.Context) {
	r := e.records()
	for i := range r.Grants {
		g := &r.Grants[i]
		b := g.Got.Bind
		p := r.PreparationOf(g.Ref)
		if b == nil || b.State != state.BindBound || g.State != state.GrantRealised || p == nil || !p.Prepared() || !e.owns(g.Asked.Source) {
			continue
		}
		u := useOf(r, g)
		mi, err := e.k.Mounted(b.Target)
		if err != nil || mi != nil {
			continue
		}
		claim, what := e.claimNameOf(g.Ref), bindWhat(g)
		if node, err := e.k.Mounted(u.nodeMount); err != nil || node == nil {
			e.errorf(g.Asked.Source, "claim %s: %s: not binding %s again: %s is not mounted (%v)", claim, what, b.Target, u.nodeMount, err)
			continue
		}
		ref := g.Ref
		if _, err := e.bindLease(&u, b.Target, func(t string) bool { return e.bindUsed(t, ref) }); err != nil {
			e.errorf(g.Asked.Source, "claim %s: %s: not binding %s again: %v", claim, what, b.Target, err)
			continue
		}
		e.logf(g.Asked.Source, "claim %s: %s: bound %s at %s again", claim, what, u.nodeMount, b.Target)
		if err := e.commit(ctx, func(r *state.Records) error {
			rb := r.Grant(ref).Got.Bind
			return state.Apply(&state.BindTable, &rb.State, state.BindBound, state.TriggerRecover)
		}); err != nil {
			klog.Errorf("engine: %v", err)
		}
	}
}

// releaseCut releases the objects of the grants of cut Prepares per Policy
// (ReleaseRecovery), but those of companion claims of mode numa and of
// memdevs that are gone, the memdev whose regions are top-most first. The
// log lines name each claim: when its first memdev is released or kept,
// and when its last one is. Errors are logged; a grant that is not
// released is kept.
func (e *Engine) releaseCut(ctx context.Context, out *Recovered) {
	rctx, cancel := e.rollbackContext(ctx)
	defer cancel()
	cut := e.cutClaims(out)
	if len(cut.bySerial) == 0 {
		return
	}
	call := newReleaseCall(e, ReleaseRecovery, nil)
	call.perClaim = true
	for len(cut.bySerial) > 0 {
		serial := e.topMost(cut.bySerial)
		refs := cut.bySerial[serial]
		delete(cut.bySerial, serial)
		for _, ref := range refs {
			call.refs[ref] = true
		}
		if above := e.recoveryAbove(serial, refs); len(above) > 0 {
			for _, ref := range refs {
				cut.keep(e, ref, above)
			}
			if err := e.keepForRecovery(rctx, serial, refs); err != nil {
				e.errorf(e.sourceOf(refs[0]), "claim %s: %v", e.claimNameOf(refs[0]), err)
			}
			out.Kept = append(out.Kept, refs...)
			continue
		}
		cut.announce(e, serial, refs)
		err := e.releaseGroup(rctx, refs, call)
		for _, ref := range refs {
			if e.records().Grant(ref) == nil {
				out.Released = append(out.Released, ref)
				continue
			}
			out.Kept = append(out.Kept, ref)
			cut.failed(ref, err)
		}
		for _, ref := range refs {
			cut.done(e, ref)
		}
	}
}

// cutClaims are the claims of cut Prepares that the recovery releases:
// their grants by memdev, and per claim its grants that are left, the
// regions above those kept and the errors of their release.
type cutClaims struct {
	bySerial map[state.Serial][]state.GrantRef
	left     map[string][]state.GrantRef
	above    map[string][]string
	errs     map[string][]error
}

// cutClaims returns the cut claims that the recovery releases; the grants
// of numa companions are in out.Companions, those of memdevs that are
// gone in out.Absent.
func (e *Engine) cutClaims(out *Recovered) *cutClaims {
	c := &cutClaims{bySerial: map[state.Serial][]state.GrantRef{}, left: map[string][]state.GrantRef{},
		above: map[string][]string{}, errs: map[string][]error{}}
	r := e.records()
	companions := map[string]bool{}
	for i := range r.Grants {
		g := &r.Grants[i]
		if !cutGrant(r, g) || !e.owns(g.Asked.Source) {
			continue
		}
		switch m := r.Memdev(g.Serial); {
		case numaCompanion(g):
			out.Companions = append(out.Companions, g.Ref)
			if !companions[g.Ref.Claim] {
				companions[g.Ref.Claim] = true
				e.logf(g.Asked.Source, "claim %s (%s) is a companion claim: its Unprepare releases its devices, its Prepare again reuses them",
					e.claimNameOf(g.Ref), g.Ref.Claim)
			}
		case m != nil && m.State == state.MemdevGone:
			out.Absent = append(out.Absent, g.Ref)
		default:
			c.bySerial[g.Serial] = append(c.bySerial[g.Serial], g.Ref)
			c.left[g.Ref.Claim] = append(c.left[g.Ref.Claim], g.Ref)
		}
	}
	return c
}

// keep records that the grant ref is kept below the regions above.
func (c *cutClaims) keep(e *Engine, ref state.GrantRef, above []string) {
	for _, a := range above {
		if !slices.Contains(c.above[ref.Claim], a) {
			c.above[ref.Claim] = append(c.above[ref.Claim], a)
		}
	}
	c.done(e, ref)
}

// failed records the error of the release of the grant ref.
func (c *cutClaims) failed(ref state.GrantRef, err error) {
	if err == nil {
		err = fmt.Errorf("grant %s is not released", ref)
	}
	if !slices.ContainsFunc(c.errs[ref.Claim], func(x error) bool { return x == err }) {
		c.errs[ref.Claim] = append(c.errs[ref.Claim], err)
	}
}

// announce logs the release of the devices of the memdev with the serial
// for each claim of the grants refs of it.
func (c *cutClaims) announce(e *Engine, serial state.Serial, refs []state.GrantRef) {
	var claims []state.GrantRef
	for _, ref := range refs {
		if !slices.ContainsFunc(claims, func(o state.GrantRef) bool { return o.Claim == ref.Claim }) {
			claims = append(claims, ref)
		}
	}
	for _, ref := range claims {
		e.logf(e.sourceOf(ref), "claim %s (%s), whose Prepare did not finish: releasing devices %s", e.claimNameOf(ref), ref.Claim,
			serialText(serial))
	}
}

// done logs what the recovery did with the claim of ref once ref is its
// last grant that is left.
func (c *cutClaims) done(e *Engine, ref state.GrantRef) {
	claim := ref.Claim
	c.left[claim] = removeRef(c.left[claim], ref)
	if len(c.left[claim]) > 0 {
		return
	}
	delete(c.left, claim)
	name, source := e.claimNameOf(ref), e.sourceOf(ref)
	if above := c.above[claim]; len(above) > 0 {
		e.warnf(source, "claim %s (%s): not releasing its devices at start: %s lie above their regions, a release would leave a hole in the decoders of their ports; its Unprepare releases them, its Prepare again reuses them",
			name, claim, strings.Join(above, ", "))
	}
	switch {
	case len(c.errs[claim]) > 0:
		e.warnf(source, "claim %s (%s): not everything was released at start (%v): keeping its record in %s: its Unprepare releases its devices, its Prepare again reuses them",
			name, claim, errors.Join(c.errs[claim]...), e.recordName(source))
	case len(c.above[claim]) == 0:
		e.logf(source, "claim %s (%s): released, its Prepare again prepares its devices anew", name, claim)
	}
}

// sourceOf returns the source of the grant ref, the pool if it has none.
func (e *Engine) sourceOf(ref state.GrantRef) state.Source {
	if g := e.records().Grant(ref); g != nil {
		return g.Asked.Source
	}
	if p := e.records().PreparationOf(ref); p != nil && p.Driver != "" {
		for s, d := range e.opts.Drivers {
			if d == p.Driver {
				return s
			}
		}
	}
	return state.SourcePool
}

// recordName returns what the log lines call the record of a claim of the
// source whose Prepare did not finish (Options.Records), else "the store".
func (e *Engine) recordName(source state.Source) string {
	if n := e.opts.Records[source]; n != "" {
		return n
	}
	return "the store"
}

// ownsRegion tells whether the engine owns the record of a region: the
// source of the record of one of its memdevs, else of a grant that got it.
func (e *Engine) ownsRegion(r *state.Records, reg *state.Region) bool {
	if e.opts.Sources == nil {
		return true
	}
	for _, serial := range reg.Targets {
		if m := r.Memdev(serial); m != nil {
			return e.owns(m.Source)
		}
	}
	for i := range r.Grants {
		if r.Grants[i].Got.Region == reg.Ref() {
			return e.owns(r.Grants[i].Asked.Source)
		}
	}
	return false
}

// bindOrigin returns the serial and the source of the node mount in a
// mounts directory of an owned source that a lease bind of the device
// source binds, the serial by the name of the node mount.
func (e *Engine) bindOrigin(mounts []kernel.MountInfo, source string) (state.Serial, state.Source, bool) {
	dirs := map[string]state.Source{}
	for s, d := range e.opts.MountsDirs {
		if e.owns(s) {
			dirs[d] = s
		}
	}
	for i := range mounts {
		m := &mounts[i]
		owner, ok := dirs[filepath.Dir(m.Target)]
		if m.Source != source || !ok {
			continue
		}
		hex, _, _ := strings.Cut(filepath.Base(m.Target), "-")
		if serial, err := strconv.ParseUint(hex, 16, 64); err == nil {
			return state.Serial(serial), owner, true
		}
	}
	return 0, "", false
}

// topMost returns the serial of the grants whose memdev has no region of
// another memdev of the grants above its regions, the lowest serial of
// those (or of all, when every one has).
func (e *Engine) topMost(bySerial map[state.Serial][]state.GrantRef) state.Serial {
	serials := sortedKeys(bySerial)
	for _, serial := range serials {
		memdev, err := e.k.FindMemdev(uint64(serial))
		if err != nil {
			return serial
		}
		above, err := e.k.RegionsAbove(memdev)
		if err != nil {
			continue
		}
		blocked := false
		for _, name := range above {
			if ri, err := e.k.Region(name); err == nil {
				for _, s := range ri.Serials {
					_, cut := bySerial[state.Serial(s)]
					blocked = blocked || cut
				}
			}
		}
		if !blocked {
			return serial
		}
	}
	return serials[0]
}

// recoverPreparations makes a PREPARING preparation with a grant that the
// recovery kept KEPT, with the results of its grants that are left; the
// others stay PREPARING with their results for kubelet's retry.
func (e *Engine) recoverPreparations(ctx context.Context, out *Recovered) error {
	if len(out.Kept) == 0 && len(out.Released) == 0 {
		return nil
	}
	return e.commit(ctx, func(r *state.Records) error {
		for i := range r.Preparations {
			p := &r.Preparations[i]
			if p.State != state.PreparationPreparing {
				continue
			}
			kept, touched := false, false
			for _, res := range p.Results {
				if res.Grant == nil {
					continue
				}
				kept = kept || slices.Contains(out.Kept, *res.Grant)
				touched = touched || kept || slices.Contains(out.Released, *res.Grant)
			}
			switch {
			case kept:
				if err := state.Apply(&state.PreparationTable, &p.State, state.PreparationKept, state.TriggerRecover); err != nil {
					return err
				}
				p.Results = slices.DeleteFunc(p.Results, func(res state.Result) bool {
					return res.Grant != nil && r.Grant(*res.Grant) == nil
				})
			case touched:
				if err := state.Apply(&state.PreparationTable, &p.State, state.PreparationPreparing, state.TriggerRecover); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// listedMounts returns the node mounts and lease binds that the realised
// grants of prepared claims list, unrestored ones included (a mount there
// is not ours, or none is there).
func (e *Engine) listedMounts() (mounts, binds map[string]bool) {
	r := e.records()
	mounts, binds = map[string]bool{}, map[string]bool{}
	for i := range r.Grants {
		g := &r.Grants[i]
		p := r.PreparationOf(g.Ref)
		if !prepared(g) || p == nil || !p.Prepared() {
			continue
		}
		if path := mountPathOf(r, g); path != "" {
			mounts[path] = true
		}
		if g.Got.Bind != nil {
			binds[g.Got.Bind.Target] = true
		}
	}
	return mounts, binds
}

// sweepNodeMounts unmounts the mounts in the mounts directories that no
// realised grant of a prepared claim lists, and removes their directories.
// Errors are logged.
func (e *Engine) sweepNodeMounts() {
	listed, _ := e.listedMounts()
	for _, source := range sortedKeys(e.opts.MountsDirs) {
		if !e.owns(source) {
			continue
		}
		dir := e.opts.MountsDirs[source]
		entries, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			e.errorf(source, "%v", err)
		}
		for _, ent := range entries {
			mnt := filepath.Join(dir, ent.Name())
			if listed[mnt] {
				continue
			}
			e.logf(source, "%s belongs to no prepared claim, unmounting it", mnt)
			if mi, err := e.k.Mounted(mnt); err != nil || mi != nil {
				if err == nil {
					err = e.locked(func() error { return e.k.Unmount(mnt) })
				}
				if err != nil {
					e.errorf(source, "unmounting %s: %v", mnt, err)
					continue
				}
			}
			e.removeMountDir(source, mnt)
		}
	}
}

// sweepBinds unmounts, topmost first, the mounts under the lease-fs root
// that no realised grant of a prepared claim lists and that bind a node
// mount of an owned source (their source is that of a mount in its mounts
// directory), and forgets those that a memdev had as stale. One that
// cannot be unmounted is logged and recorded stale with the memdev of the
// node mount that it binds.
func (e *Engine) sweepBinds(ctx context.Context) {
	if e.opts.LeaseFsRoot == "" {
		return
	}
	_, listed := e.listedMounts()
	mounts, err := e.k.Mounts()
	if err != nil {
		klog.Errorf("engine: %v", err)
		return
	}
	for i := len(mounts) - 1; i >= 0; i-- {
		mi := &mounts[i]
		if !strings.HasPrefix(mi.Target, e.opts.LeaseFsRoot+"/") || listed[mi.Target] {
			continue
		}
		serial, source, ok := e.bindOrigin(mounts, mi.Source)
		if !ok {
			continue
		}
		e.logf(source, "%s belongs to no prepared claim, unmounting it", mi.Target)
		target := mi.Target
		if err := e.locked(func() error { return e.k.Unmount(target) }); err != nil {
			e.errorf(source, "unmounting %s: %v; trying again at the next release", target, err)
			e.addStale(serial, target, state.StaleBind)
			continue
		}
		e.removeMountDir(source, target)
		e.forgetSwept(ctx, serial, target)
	}
}

// forgetSwept forgets a lease bind that the sweep unmounted when the memdev
// with the serial had it as stale.
func (e *Engine) forgetSwept(ctx context.Context, serial state.Serial, target string) {
	sp := state.StalePath{Path: target, Kind: state.StaleBind}
	if m := e.records().Memdev(serial); m == nil || !slices.Contains(m.Stale, sp) {
		return
	}
	if err := e.commit(ctx, func(r *state.Records) error {
		return forgetStale(r, serial, []state.StalePath{sp}, state.TriggerRecover)
	}); err != nil {
		klog.Errorf("engine: memdev %s: forgetting stale %s: %v", serial, target, err)
	}
}

// deleteUnowned deletes the dax devices of our regions that no record
// names or that have no user and are not the Whole device (their memory
// offlined first). Errors are logged.
func (e *Engine) deleteUnowned(ctx context.Context) {
	r := e.records()
	for i := range r.Regions {
		reg := &r.Regions[i]
		if !reg.Ours() || reg.State != state.RegionOwned && reg.State != state.RegionKept || !e.ownsRegion(r, reg) {
			continue
		}
		name := string(reg.Ref())
		for _, dax := range e.k.DaxDevices(name) {
			d := reg.DaxDevice(dax)
			if d != nil && (d.Whole || len(d.Users) > 0 || d.State == state.DaxSeed) {
				continue
			}
			if d == nil && strings.HasSuffix(dax, ".0") {
				continue
			}
			if err := e.deleteDax(ctx, reg.Ref(), dax); err != nil {
				klog.Errorf("engine: %s: %v", name, err)
			}
		}
	}
}

// deleteDax offlines the memory of a dax device of a region of ours that
// no grant uses, deletes it and drops its record.
func (e *Engine) deleteDax(ctx context.Context, region state.RegionRef, dax string) error {
	if err := e.offlineDax(ctx, dax); err != nil {
		return err
	}
	if err := e.locked(func() error { return e.k.DeleteDaxDevice(ctx, string(region), dax) }); err != nil {
		return err
	}
	klog.Infof("engine: %s: deleted %s, which belongs to no grant", region, dax)
	return e.commit(ctx, func(r *state.Records) error {
		reg := r.Region(region)
		if reg == nil {
			return nil
		}
		d := reg.DaxDevice(dax)
		if d == nil {
			return nil
		}
		if err := state.Apply(&state.DaxDeviceTable, &d.State, state.DaxAbsent, state.TriggerRecover); err != nil {
			return err
		}
		removeRecord(&reg.DaxDevices, func(x *state.DaxDevice) bool { return x.Name == dax })
		return nil
	})
}

// restoreGrant mounts again the node mount of a REALISED_UNRESTORED grant
// for a Prepare again of its claim, and makes it REALISED (its node mount
// mounted); an error names why it stays unrestored.
func (e *Engine) restoreGrant(ctx context.Context, req *GrantRequest) error {
	g := e.records().Grant(req.Ref)
	uses := e.preparedUses(g.Serial)
	i := slices.IndexFunc(uses, func(u use) bool { return u.ref == g.Ref })
	if i < 0 || uses[i].nodeMount == "" {
		if err := e.verifyGrant(g); err != nil {
			return err
		}
	}
	loop := ""
	if i >= 0 && uses[i].nodeMount != "" {
		l, err := e.restoreNodeMount(&uses[i], firstWriter(uses) != nil, nodeMounts(uses))
		if err != nil {
			return fmt.Errorf("device %s: its node mount %s is not mounted and cannot be mounted again: %w; unprepare the claim (delete its pods) to prepare it anew",
				serialText(g.Serial), uses[i].nodeMount, err)
		}
		loop = l
	}
	return e.commit(ctx, func(r *state.Records) error {
		g := r.Grant(req.Ref)
		if err := state.Apply(&state.GrantTable, &g.State, state.GrantRealised, state.TriggerPrepare); err != nil {
			return err
		}
		reg := r.Region(g.Got.Region)
		if reg == nil || g.Got.Mount == "" {
			return nil
		}
		m := reg.Mount(g.Got.Mount)
		if m == nil {
			return nil
		}
		if loop != "" {
			m.Loop, g.Got.Loop = loop, loop
		}
		if m.State == state.MountUnrestored {
			want := state.MountedRO
			if mountWriter(r, m) {
				want, m.Writer = state.MountedRW, true
			}
			if err := state.Apply(&state.MountTable, &m.State, want, state.TriggerPrepare); err != nil {
				return err
			}
		}
		return remountedUsers(r, m, req.Ref)
	})
}

// isReadOnlyType tells whether a filesystem type is read-only.
func isReadOnlyType(fsType string) bool {
	return config.FsTypeReadOnly(fsType)
}

// isUpgradable tells whether a read-only superblock of the type can be made
// read-write.
func isUpgradable(fsType string) bool {
	return config.FsTypeUpgradable(fsType)
}
