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
	"time"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// ErrForeignRegion is the kind of the error of a grant on a memdev with a
// region that no record of the driver names: the driver never uses or
// touches it.
var ErrForeignRegion = errors.New("a region that the plugin did not create")

// foreignRegionError is the error of a grant on the memdev with a region
// that no record names.
type foreignRegionError struct {
	memdev, region string
}

// Error returns the refusal in words.
func (e *foreignRegionError) Error() string {
	return fmt.Sprintf("memdev %s has region %s that the plugin did not create", e.memdev, e.region)
}

// Is tells whether target is ErrForeignRegion.
func (e *foreignRegionError) Is(target error) bool {
	return target == ErrForeignRegion
}

// GrantError is the error of a grant that could not be realised.
type GrantError struct {
	Ref state.GrantRef
	Err error
}

// Error returns the error of the grant.
func (e *GrantError) Error() string {
	return e.Err.Error()
}

// Unwrap returns the error of the grant.
func (e *GrantError) Unwrap() error {
	return e.Err
}

// keptOnlineError is the error of memory blocks that keep coming online
// after offlining them.
type keptOnlineError struct {
	blocks []int
}

// Error returns the error in words.
func (e *keptOnlineError) Error() string {
	return fmt.Sprintf("memory blocks %v keep coming online after offlining them: is a udev rule onlining hot-added memory?", e.blocks)
}

// Is tells whether target is kernel.ErrBusyOnline.
func (e *keptOnlineError) Is(target error) bool {
	return target == kernel.ErrBusyOnline
}

// PrepareGrants realises the grants of reqs in their order and returns them
// as recorded, REALISED. A grant that is REALISED already and verifies is
// reused; one that a cut or failed Prepare left is realised further. On an
// error the grants of the claims of reqs that this or an earlier Prepare
// made are released as a rollback (Policy ReleaseRollback), on a context
// that the end of ctx does not end; what the rollback keeps stays recorded
// and is returned with the error.
func (e *Engine) PrepareGrants(ctx context.Context, reqs []GrantRequest) ([]state.Grant, error) {
	refs := make([]state.GrantRef, 0, len(reqs))
	for i := range reqs {
		if !e.owns(reqs[i].Asked.Source) {
			return nil, fmt.Errorf("engine: grant %s: the records of source %q are not the engine's", reqs[i].Ref, reqs[i].Asked.Source)
		}
	}
	e.setDevices(reqs)
	for i := range reqs {
		refs = append(refs, reqs[i].Ref)
		if err := e.prepareGrant(ctx, &reqs[i]); err != nil {
			rctx, cancel := e.rollbackContext(ctx)
			kept := e.rollback(rctx, reqs)
			e.verify(rctx, nil)
			cancel()
			return kept, &GrantError{Ref: reqs[i].Ref, Err: err}
		}
	}
	e.verify(ctx, refs)
	return e.grantsOf(refs), nil
}

// grantsOf returns the records of the grants refs that the store has.
func (e *Engine) grantsOf(refs []state.GrantRef) []state.Grant {
	r := e.records()
	var out []state.Grant
	for _, ref := range refs {
		if g := r.Grant(ref); g != nil {
			out = append(out, g.Clone())
		}
	}
	return out
}

// prepareGrant realises one grant in the queue of its memdev.
func (e *Engine) prepareGrant(ctx context.Context, req *GrantRequest) error {
	leave, err := e.acquire(ctx, req.Serial)
	if err != nil {
		return err
	}
	defer leave()
	if g := e.records().Grant(req.Ref); g != nil {
		switch g.State {
		case state.GrantRealised:
			if err := e.verifyGrant(g); err == nil {
				klog.V(3).Infof("engine: grant %s is realised and verifies: reused", req.Ref)
				return nil
			}
		case state.GrantUnrestored:
			return e.restoreGrant(ctx, req)
		case state.GrantReleasing:
			// a leftover of a failed release, on the context of a rollback
			rctx, cancel := e.rollbackContext(ctx)
			err := e.releaseGrant(rctx, req.Ref, newReleaseCall(e, ReleaseRollback, []state.GrantRef{req.Ref}))
			cancel()
			if err != nil {
				return err
			}
		}
	}
	if err := e.journal(ctx, req); err != nil {
		return err
	}
	return e.realise(ctx, req)
}

// journal commits the intent of the grant (REQUESTED -> JOURNALED), with
// its memdev record, before any kernel object of it is touched. A grant
// that is JOURNALED or REALISING already keeps its intent. The local guard
// refuses a local grant on a serial of the pool.
func (e *Engine) journal(ctx context.Context, req *GrantRequest) error {
	if req.Asked.Source == state.SourceLocal {
		if err := e.localGuard(ctx, req.Serial); err != nil {
			return err
		}
	}
	return e.commit(ctx, func(r *state.Records) error {
		if r.Region(state.RegionRef(req.BindTarget)) != nil {
			return fmt.Errorf("grant %s: %s is a region", req.Ref, req.BindTarget)
		}
		g := r.Grant(req.Ref)
		if g == nil {
			r.Grants = append(r.Grants, state.Grant{Ref: req.Ref, Serial: req.Serial, Asked: req.Asked, State: state.GrantRequested})
			g = &r.Grants[len(r.Grants)-1]
		}
		switch g.State {
		case state.GrantRequested:
			if err := state.Apply(&state.GrantTable, &g.State, state.GrantJournaled, state.TriggerPrepare); err != nil {
				return err
			}
		case state.GrantJournaled, state.GrantRealising, state.GrantRealised:
		default:
			return fmt.Errorf("grant %s is %s", req.Ref, g.State)
		}
		g.Asked = req.Asked
		g.Intent.BindTarget = req.BindTarget
		if req.Lend != nil {
			lend := *req.Lend
			g.Intent.Lend = &lend
		}
		return journalMemdev(r, req)
	})
}

// journalMemdev adds the grant to the record of its memdev, made ACTIVE.
func journalMemdev(r *state.Records, req *GrantRequest) error {
	m := r.Memdev(req.Serial)
	if m == nil {
		r.Memdevs = append(r.Memdevs, state.Memdev{Serial: req.Serial, Source: req.Asked.Source, State: state.MemdevUnused})
		m = &r.Memdevs[len(r.Memdevs)-1]
	}
	if m.Source != req.Asked.Source {
		return fmt.Errorf("memdev %s is a %s memdev, not %s", req.Serial, m.Source, req.Asked.Source)
	}
	switch m.State {
	case state.MemdevUnused, state.MemdevIdleKept:
		if err := state.Apply(&state.MemdevTable, &m.State, state.MemdevActive, state.TriggerPrepare); err != nil {
			return err
		}
	case state.MemdevActive:
		if !m.HasGrant(req.Ref) {
			if err := state.Apply(&state.MemdevTable, &m.State, state.MemdevActive, state.TriggerPrepare); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("memdev %s is %s", req.Serial, m.State)
	}
	m.Facts = mergeFacts(m.Facts, req.Facts)
	m.Grants = addRef(m.Grants, req.Ref)
	return nil
}

// mergeFacts returns the facts of a memdev record with those that a
// request knows.
func mergeFacts(old, req state.MemdevFacts) state.MemdevFacts {
	out := req
	if out.BlockSize == 0 {
		out.BlockSize = old.BlockSize
	}
	if out.Ram == 0 {
		out.Ram = old.Ram
	}
	if out.Pmem == 0 {
		out.Pmem = old.Pmem
	}
	if out.HostBridge == "" {
		out.HostBridge = old.HostBridge
	}
	if out.NumaAffinity == nil {
		out.NumaAffinity = old.NumaAffinity
	}
	return out
}

// localGuard returns an error if a local grant on the serial must not be
// made: the provenance of the serial is POOL or HELD, a pool grant uses
// it, or the front-end's guard refuses it.
func (e *Engine) localGuard(ctx context.Context, serial state.Serial) error {
	r := e.records()
	if p := r.ProvenanceOf(serial); p != nil && (p.State == state.ProvenancePool || p.State == state.ProvenanceHeld) {
		return fmt.Errorf("memdev %s is a pool device (%s): not used as a local memdev", serialText(serial), p.State)
	}
	if m := r.Memdev(serial); m != nil && m.Source == state.SourcePool {
		return fmt.Errorf("memdev %s is a pool device: not used as a local memdev", serialText(serial))
	}
	if e.opts.LocalGuard != nil {
		return e.opts.LocalGuard(ctx, serial)
	}
	return nil
}

// realise makes the kernel objects of a JOURNALED or REALISING grant and
// records them, the grant REALISED at the end.
func (e *Engine) realise(ctx context.Context, req *GrantRequest) error {
	memdev, err := e.memdevOf(ctx, req)
	if err != nil {
		return err
	}
	if err := e.commit(ctx, func(r *state.Records) error {
		g := r.Grant(req.Ref)
		if g.State == state.GrantJournaled {
			if err := state.Apply(&state.GrantTable, &g.State, state.GrantRealising, state.TriggerPrepare); err != nil {
				return err
			}
		}
		if m := r.Memdev(req.Serial); m != nil {
			m.Name = memdev
		}
		return nil
	}); err != nil {
		return err
	}
	switch {
	case req.Asked.Kind == state.KindPersistent:
		return e.realisePersistent(ctx, req, memdev)
	case req.Asked.Source == state.SourcePool:
		return e.realisePoolRam(ctx, req, memdev)
	case req.Asked.Kind == state.KindShared:
		return e.realiseLocalShared(ctx, req, memdev)
	}
	return e.realiseLocalSliced(ctx, req, memdev)
}

// memdevOf returns the name of the memdev of a grant. A pool grant waits
// for its memdev to appear (Timeouts.Memdev), or for the driver of a memdev
// that is present (Timeouts.ProbeGrace: a disabled memdev is enabled when
// its region is made); a local memdev must be present.
func (e *Engine) memdevOf(ctx context.Context, req *GrantRequest) (string, error) {
	serial := uint64(req.Serial)
	if req.Asked.Source != state.SourcePool {
		return e.k.FindMemdev(serial)
	}
	var name string
	err := e.waiting(req.Serial, state.TriggerPrepare, func() error {
		if found, err := e.k.FindMemdev(serial); err == nil {
			wctx, cancel := context.WithTimeout(ctx, e.opts.Timeouts.ProbeGrace)
			defer cancel()
			if n, err := e.k.WaitMemdev(wctx, serial, kernel.MemdevBound); err == nil {
				name = n
			} else {
				name = found
			}
			return nil
		}
		wctx, cancel := context.WithTimeout(ctx, e.opts.Timeouts.Memdev)
		defer cancel()
		n, err := e.k.WaitMemdev(wctx, serial, kernel.MemdevBound)
		name = n
		return err
	})
	return name, err
}

// ownRegion returns the region of ours of the memdev of the grant that a
// grant of mode uses (pmem for persistent grants, ram for the others),
// nil if there is none.
func ownRegion(r *state.Records, serial state.Serial, mode state.RegionMode) *state.Region {
	m := r.Memdev(serial)
	if m == nil {
		return nil
	}
	for _, ref := range m.Regions {
		if reg := r.Region(ref); reg != nil && reg.Mode == mode {
			return reg
		}
	}
	return nil
}

// ensureRegion returns the region of ours of the memdev of a grant for the
// region mode, made ready for set-up: an OWNED one as it is, a KEPT one
// enabled again, else a new one (noted before cxl create-region, one retry
// after Timeouts.RegionRetry when the memdev had no endpoint port yet). A
// region of the memdev that no record names refuses the memdev. The grant's
// intent and the memdev record name the region.
func (e *Engine) ensureRegion(ctx context.Context, req *GrantRequest, memdev string, mode state.RegionMode, size uint64) (string, error) {
	if err := e.locked(func() error { return e.k.EnableMemdev(ctx, memdev) }); err != nil {
		return "", err
	}
	if reg := ownRegion(e.records(), req.Serial, mode); reg != nil {
		return e.useRegion(ctx, req, memdev, reg)
	}
	for _, name := range e.k.Regions(memdev) {
		return "", &foreignRegionError{memdev: memdev, region: name}
	}
	name, err := e.createRegion(ctx, req, memdev, mode, size)
	if errors.Is(err, kernel.ErrEndpointNotReady) {
		e.warnf(req.Asked.Source, "claim %s: device %s: %v; retrying once in %v", req.claimName(), req.device(memdev), err,
			e.opts.Timeouts.RegionRetry)
		select {
		case <-ctx.Done():
		case <-time.After(e.opts.Timeouts.RegionRetry):
			name, err = e.createRegion(ctx, req, memdev, mode, size)
		}
	}
	return name, err
}

// useRegion returns the name of the recorded region of ours reg for a
// grant: KEPT is enabled again (OWNED, not set up), OWNED as it is. The
// region must exist and target the memdev.
func (e *Engine) useRegion(ctx context.Context, req *GrantRequest, memdev string, reg *state.Region) (string, error) {
	name := string(reg.Ref())
	ri, err := e.k.Region(name)
	if err != nil || !slices.Contains(ri.Memdevs, memdev) {
		return "", fmt.Errorf("memdev %s: its %s is gone (%v)", memdev, name, err)
	}
	switch reg.State {
	case state.RegionOwned:
		e.k.Logf("%s: reusing %s", memdev, name)
	case state.RegionKept:
		if err := e.locked(func() error { return e.k.EnableRegion(ctx, name) }); err != nil {
			return "", err
		}
		if req.Asked.Source == state.SourcePool {
			e.k.Logf("%s: reusing %s", memdev, name)
		}
		e.logf(req.Asked.Source, "memdev %s (serial %s): enabled kept %s", memdev, serialText(req.Serial), name)
		if err := e.commit(ctx, func(r *state.Records) error {
			rec := r.Region(state.RegionRef(name))
			if err := state.Apply(&state.RegionTable, &rec.State, state.RegionOwned, state.TriggerPrepare); err != nil {
				return err
			}
			return setIntentRegion(r, req.Ref, rec.Ref())
		}); err != nil {
			return "", err
		}
		return name, nil
	default:
		return "", fmt.Errorf("memdev %s: %s is %s", memdev, name, reg.State)
	}
	return name, e.commit(ctx, func(r *state.Records) error { return setIntentRegion(r, req.Ref, state.RegionRef(name)) })
}

// setIntentRegion sets the region of the intent of a grant.
func setIntentRegion(r *state.Records, ref state.GrantRef, region state.RegionRef) error {
	g := r.Grant(ref)
	if g == nil {
		return fmt.Errorf("grant %s has no record", ref)
	}
	if g.Intent.Region != "" && g.Intent.Region != region {
		g.Intent.Noted = addRef(g.Intent.Noted, g.Intent.Region)
	}
	g.Intent.Region = region
	return nil
}

// createRegion creates a region of the mode on the memdev of a grant under
// the engine lock: the name that it will get is committed (NONE -> NOTED)
// before cxl create-region runs, and the created region (OWNED) after it.
func (e *Engine) createRegion(ctx context.Context, req *GrantRequest, memdev string, mode state.RegionMode, size uint64) (string, error) {
	typ := kernel.RegionRAM
	if mode == state.RegionPmem {
		typ = kernel.RegionPmem
	}
	decoder, err := e.k.RootDecoder(memdev, typ)
	if err != nil {
		return "", err
	}
	noted, created := "", ""
	err = e.locked(func() error {
		var err error
		created, err = e.k.CreateRegion(ctx, kernel.CreateRegionRequest{Memdev: memdev, Decoder: decoder, Type: typ, Size: size,
			Note: func(next string) error {
				if next == "" {
					return nil
				}
				if err := e.commit(ctx, func(r *state.Records) error { return noteRegion(r, req, next, decoder, mode) }); err != nil {
					return fmt.Errorf("recording region %s: %w", next, err)
				}
				noted = next
				return nil
			}})
		return err
	})
	if err != nil {
		if noted != "" {
			e.clearNote(ctx, req, noted)
		}
		return "", err
	}
	ri, _ := e.k.Region(created)
	if err := e.commit(ctx, func(r *state.Records) error { return createdRegion(r, req, noted, created, decoder, mode, ri) }); err != nil {
		return "", err
	}
	return created, nil
}

// noteRegion records the region that a creation will make (NONE ->
// NOTED), named by the memdev and the grant's intent.
func noteRegion(r *state.Records, req *GrantRequest, name, decoder string, mode state.RegionMode) error {
	ref := state.RegionRef(name)
	if r.Region(ref) != nil {
		return fmt.Errorf("region %s has a record already", name)
	}
	reg := state.Region{NotedName: name, Mode: mode, Targets: []state.Serial{req.Serial}, Owner: state.OwnerOurs,
		Decoder: decoder, State: state.RegionNone}
	if err := state.Apply(&state.RegionTable, &reg.State, state.RegionNoted, state.TriggerPrepare); err != nil {
		return err
	}
	r.Regions = append(r.Regions, reg)
	if m := r.Memdev(req.Serial); m != nil {
		m.Regions = addRef(m.Regions, ref)
	}
	return setIntentRegion(r, req.Ref, ref)
}

// createdRegion records the region that a creation made (NOTED ->
// CREATING -> OWNED) under its name, which replaces the noted one.
func createdRegion(r *state.Records, req *GrantRequest, noted, created, decoder string, mode state.RegionMode, ri kernel.RegionInfo) error {
	if noted == "" {
		// the next name could not be read: recorded after the creation
		reg := state.Region{NotedName: created, Mode: mode, Targets: []state.Serial{req.Serial}, Owner: state.OwnerOurs,
			Decoder: decoder, State: state.RegionNone}
		if err := state.Apply(&state.RegionTable, &reg.State, state.RegionNoted, state.TriggerPrepare); err != nil {
			return err
		}
		r.Regions = append(r.Regions, reg)
		noted = created
	}
	reg := r.Region(state.RegionRef(noted))
	if reg == nil {
		return fmt.Errorf("region %s has no record", noted)
	}
	if err := state.Apply(&state.RegionTable, &reg.State, state.RegionCreating, state.TriggerPrepare); err != nil {
		return err
	}
	if err := state.Apply(&state.RegionTable, &reg.State, state.RegionOwned, state.TriggerPrepare); err != nil {
		return err
	}
	reg.Name, reg.NotedName = created, ""
	reg.NumaNode = state.NumaNodePtr(ri.NumaNode)
	reg.Size = ri.Range.Size()
	reg.Locked = ri.Locked
	if m := r.Memdev(req.Serial); m != nil {
		m.Regions = addRef(removeRef(m.Regions, state.RegionRef(noted)), state.RegionRef(created))
	}
	return setIntentRegion(r, req.Ref, state.RegionRef(created))
}

// clearNote clears the note of a region that a failed creation did not
// make (NOTED -> NONE); a region of the noted name that exists is left to
// the recovery.
func (e *Engine) clearNote(ctx context.Context, req *GrantRequest, noted string) {
	if _, err := e.k.Region(noted); err == nil {
		e.errorf(req.Asked.Source, "memdev %s: a failed cxl create-region left %s: the rollback releases it",
			serialText(req.Serial), noted)
		return
	}
	if err := e.commit(ctx, func(r *state.Records) error {
		ref := state.RegionRef(noted)
		reg := r.Region(ref)
		if reg == nil {
			return nil
		}
		if err := state.Apply(&state.RegionTable, &reg.State, state.RegionNone, state.TriggerPrepare); err != nil {
			return err
		}
		removeRecord(&r.Regions, func(x *state.Region) bool { return x.Ref() == ref })
		if m := r.Memdev(req.Serial); m != nil {
			m.Regions = removeRef(m.Regions, ref)
		}
		if g := r.Grant(req.Ref); g != nil && g.Intent.Region == ref {
			g.Intent.Region = ""
		}
		return nil
	}); err != nil {
		e.errorf(req.Asked.Source, "memdev %s: clearing the note of %s: %v", serialText(req.Serial), noted, err)
	}
}

// wholeDevice returns the first dax device of a ram region set up for the
// driver: it waits for the dax region and for the memory blocks that kmem
// adds, records daxN.0 as the region's Whole device, and binds it to driver
// (kmem with its memory offline, or device_dax with the memory offline for
// the settle time first). The region is SetUp afterwards.
func (e *Engine) wholeDevice(ctx context.Context, req *GrantRequest, region, driver string) (string, error) {
	reg := e.records().Region(state.RegionRef(region))
	if reg != nil && reg.SetUp {
		if d := reg.WholeDevice(); d != nil {
			return d.Name, nil
		}
		return "", nil
	}
	// set up before (a kept region): its first device may be unbound or
	// smaller after a cut resize or driver switch
	again := reg != nil && reg.WholeDevice() != nil
	ctx, cancel := context.WithTimeout(ctx, e.opts.Timeouts.Settle)
	defer cancel()
	dax, err := e.waitWhole(ctx, req, region, again)
	if err != nil {
		return "", err
	}
	if err := e.recordWhole(ctx, req, region, dax); err != nil {
		return "", err
	}
	if e.k.DaxDriver(dax) != driver {
		if err := e.switchWhole(ctx, req, region, dax, driver); err != nil {
			return "", err
		}
	}
	return dax, e.commitWhole(ctx, req, region, dax, driver)
}

// waitWhole returns the first dax device of a region, outside the engine
// lock with the memdev Busy: of a new region once it is bound to a driver
// and kmem added its memory blocks, of a region set up again (again) once it
// exists.
func (e *Engine) waitWhole(ctx context.Context, req *GrantRequest, region string, again bool) (string, error) {
	var dax string
	err := e.waiting(req.Serial, state.TriggerPrepare, func() error {
		var err error
		if again {
			dax, err = e.firstDax(ctx, region)
		} else {
			dax, err = e.k.WaitDaxRegion(ctx, region)
		}
		if err != nil {
			return err
		}
		if e.k.DaxDriver(dax) == kernel.DriverKmem {
			return e.k.WaitRegionBlocks(ctx, region)
		}
		return nil
	})
	return dax, err
}

// switchWhole binds the first dax device of a region to driver: from kmem
// with its memory offline for the settle time first, an unbound one given
// all of the memory of the region first; kmem's memory blocks waited for.
func (e *Engine) switchWhole(ctx context.Context, req *GrantRequest, region, dax, driver string) error {
	switch e.k.DaxDriver(dax) {
	case kernel.DriverKmem:
		blocks, _ := e.k.RegionBlocks(region)
		if err := e.offlineSettled(ctx, req, blocks); err != nil {
			return err
		}
	case "":
		if err := e.spanRegion(ctx, region, dax); err != nil {
			return err
		}
	}
	if err := e.locked(func() error { return e.k.BindDax(ctx, dax, driver) }); err != nil {
		return err
	}
	if driver != kernel.DriverKmem {
		return nil
	}
	return e.waiting(req.Serial, state.TriggerPrepare, func() error { return e.k.WaitRegionBlocks(ctx, region) })
}

// firstDax returns the first dax device of a region that is enabled again,
// waiting until the kernel made it.
func (e *Engine) firstDax(ctx context.Context, region string) (string, error) {
	for {
		if ds := e.k.DaxDevices(region); len(ds) > 0 {
			return ds[0], nil
		}
		if err := sleepCtx(ctx, e.pollInterval()); err != nil {
			return "", fmt.Errorf("no dax device appeared in %s: %w", region, err)
		}
	}
}

// spanRegion gives the unbound first dax device of a region all of the
// memory of the region that no other device has.
func (e *Engine) spanRegion(ctx context.Context, region, dax string) error {
	dr, err := e.k.DaxRegion(region)
	if err != nil {
		return err
	}
	cur, err := e.k.DaxDeviceSize(dax)
	if err != nil || dr.Available == 0 {
		return err
	}
	return e.locked(func() error { return e.k.ResizeDaxDevice(ctx, dax, cur+dr.Available) })
}

// recordWhole records the first dax device of a new region as observed:
// kmem with its memory offline, or device_dax by an id that another tool
// left. A region set up before keeps its record.
func (e *Engine) recordWhole(ctx context.Context, req *GrantRequest, region, dax string) error {
	driver := e.k.DaxDriver(dax)
	return e.commit(ctx, func(r *state.Records) error {
		reg := r.Region(state.RegionRef(region))
		if reg == nil {
			return fmt.Errorf("region %s has no record", region)
		}
		if reg.DaxDevice(dax) != nil {
			return nil
		}
		d := state.DaxDevice{Name: dax, State: state.DaxAbsent, Whole: true}
		to := state.DaxKmemOffline
		if driver == kernel.DriverDeviceDax {
			to = state.DaxDeviceDax
		}
		if err := state.Apply(&state.DaxDeviceTable, &d.State, to, state.TriggerPrepare); err != nil {
			return err
		}
		d.Driver = state.DaxDriver(driver)
		reg.DaxDevices = append(reg.DaxDevices, d)
		return nil
	})
}

// commitWhole records the Whole device of a region bound to driver, and
// the region SetUp.
func (e *Engine) commitWhole(ctx context.Context, req *GrantRequest, region, dax, driver string) error {
	info, _ := e.k.DaxDevice(dax)
	return e.commit(ctx, func(r *state.Records) error {
		reg := r.Region(state.RegionRef(region))
		d := reg.DaxDevice(dax)
		if d == nil {
			return fmt.Errorf("%s has no record of %s", region, dax)
		}
		if err := bindRecord(d, driver); err != nil {
			return err
		}
		d.Size, d.Dev, d.Ranges = info.Size, state.DevNumbers{Major: info.Major, Minor: info.Minor}, addressRanges(info.Ranges)
		if !reg.SetUp {
			return state.Apply(&state.RegionSetUpTable, &reg.SetUp, true, state.TriggerPrepare)
		}
		return nil
	})
}

// bindRecord applies the transitions of a dax device bound to driver: from
// the other driver (kmem offline, device_dax) or the seed through unbound,
// from unbound.
func bindRecord(d *state.DaxDevice, driver string) error {
	want := state.DaxDeviceDax
	if driver == kernel.DriverKmem {
		want = state.DaxKmemOffline
	}
	if d.State == want || (want == state.DaxKmemOffline && d.State == state.DaxKmemOnline) {
		d.Driver = state.DaxDriver(driver)
		return nil
	}
	switch d.State {
	case state.DaxKmemOffline, state.DaxSeed, state.DaxDeviceDax:
		// unbound from the other driver first
		if err := state.Apply(&state.DaxDeviceTable, &d.State, state.DaxSized, state.TriggerPrepare); err != nil {
			return err
		}
	}
	if err := state.Apply(&state.DaxDeviceTable, &d.State, want, state.TriggerPrepare); err != nil {
		return err
	}
	d.Driver = state.DaxDriver(driver)
	return nil
}

// addressRanges returns kernel ranges as record ranges.
func addressRanges(ranges []kernel.Range) []state.AddressRange {
	var out []state.AddressRange
	for _, r := range ranges {
		out = append(out, state.AddressRange{Start: r.Start, End: r.End})
	}
	return out
}

// offlineSettled offlines memory blocks under the engine lock and waits,
// outside it, until they stayed offline for Timeouts.OfflineSettle: a udev
// rule may online hot-added blocks after they were offlined. Blocks that
// come online are offlined again until Timeouts.Offline.
func (e *Engine) offlineSettled(ctx context.Context, req *GrantRequest, blocks []int) error {
	deadline := time.Now().Add(e.opts.Timeouts.Offline)
	for {
		if err := e.locked(func() error { return e.k.OfflineBlocks(ctx, blocks, 0, 0) }); err != nil {
			return err
		}
		onlined := -1
		err := e.waiting(req.Serial, state.TriggerPrepare, func() error {
			stable := time.Now().Add(e.opts.Timeouts.OfflineSettle)
			for time.Now().Before(stable) {
				if err := sleepCtx(ctx, e.pollInterval()); err != nil {
					return err
				}
				for _, b := range blocks {
					if e.k.MemoryBlock(b).State == kernel.BlockOnline {
						onlined = b
						return nil
					}
				}
			}
			return nil
		})
		if err != nil || onlined < 0 {
			return err
		}
		e.k.Logf("memory%d: online again after offlining it (auto-onlined by udev?)", onlined)
		if time.Now().After(deadline) {
			return &keptOnlineError{blocks: blocks}
		}
	}
}

// pollInterval returns the interval of the polls of the engine's waits.
func (e *Engine) pollInterval() time.Duration {
	if e.k.PollInterval > 0 {
		return e.k.PollInterval
	}
	return 200 * time.Millisecond
}

// sleepCtx sleeps for d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// fence fences a NUMA node before memory of it goes online, waiting at
// most Timeouts.Fence; the memory goes online anyway after that.
func (e *Engine) fence(ctx context.Context, node int) {
	if e.opts.Fence == nil || node < 0 {
		return
	}
	fctx, cancel := context.WithTimeout(ctx, e.opts.Timeouts.Fence)
	defer cancel()
	e.opts.Fence(fctx, node)
	if errors.Is(fctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		klog.Warningf("engine: fencing NUMA node %d did not finish in %v: its memory goes online anyway", node, e.opts.Timeouts.Fence)
	}
}

// realisePoolRam realises a pool grant of volatile memory: the region of
// the device with its Whole device, kmem with its memory online movable in
// mode numa (the node fenced first, and again when the node is known only
// after onlining), device_dax in mode dax (never onlined).
func (e *Engine) realisePoolRam(ctx context.Context, req *GrantRequest, memdev string) error {
	region, err := e.ensureRegion(ctx, req, memdev, state.RegionRam, 0)
	if err != nil {
		return err
	}
	driver := kernel.DriverDeviceDax
	if req.Asked.Mode == state.ModeNUMA {
		driver = kernel.DriverKmem
	}
	dax, err := e.wholeDevice(ctx, req, region, driver)
	if err != nil {
		return err
	}
	got := state.Got{Region: state.RegionRef(region), Dax: dax}
	if req.Asked.Mode == state.ModeNUMA {
		node, err := e.onlineRegion(ctx, req, memdev, region, dax)
		if err != nil {
			return err
		}
		got.NumaNode = state.NumaNodePtr(node)
	} else {
		if d := e.k.DaxDriver(dax); d != kernel.DriverDeviceDax {
			return fmt.Errorf("%s: %s is bound to %q, not %s", memdev, dax, d, kernel.DriverDeviceDax)
		}
		major, minor, err := e.k.DaxDevNumbers(dax)
		if err != nil {
			return err
		}
		got.DaxDev = state.DevNumbers{Major: major, Minor: minor}
	}
	got.Size = req.Asked.Size
	return e.realised(ctx, req, got)
}

// onlineRegion fences the node of the memory of a region of mode numa,
// onlines its memory blocks movable and returns its node.
func (e *Engine) onlineRegion(ctx context.Context, req *GrantRequest, memdev, region, dax string) (int, error) {
	fenced := e.k.TargetNode(dax)
	e.fence(ctx, fenced)
	blocks, err := e.k.RegionBlocks(region)
	if err != nil {
		return -1, err
	}
	if len(blocks) == 0 {
		return -1, fmt.Errorf("%s: no memory blocks found for %s", memdev, region)
	}
	if err := e.locked(func() error { return e.k.OnlineBlocks(blocks, true) }); err != nil {
		return -1, err
	}
	node := e.k.TargetNode(dax)
	if node < 0 {
		node = e.k.BlocksNode(blocks)
	}
	if node < 0 {
		return -1, fmt.Errorf("%s: cannot find the NUMA node of %s", memdev, region)
	}
	if e.opts.Fence != nil && node != fenced {
		klog.V(3).Infof("%s: %s: NUMA node %d of %s known only after onlining, fencing it late", e.driver(req.Asked.Source), memdev, node, region)
		e.fence(ctx, node)
	}
	return node, e.commit(ctx, func(r *state.Records) error {
		reg := r.Region(state.RegionRef(region))
		d := reg.DaxDevice(dax)
		if d.State == state.DaxKmemOffline {
			if err := state.Apply(&state.DaxDeviceTable, &d.State, state.DaxKmemOnline, state.TriggerPrepare); err != nil {
				return err
			}
		}
		reg.NumaNode = state.NumaNodePtr(node)
		return nil
	})
}

// realised records what a grant got and the grant REALISED, the grant a
// user of its dax device and node mount.
func (e *Engine) realised(ctx context.Context, req *GrantRequest, got state.Got) error {
	return e.commit(ctx, func(r *state.Records) error {
		g := r.Grant(req.Ref)
		if g == nil {
			return fmt.Errorf("grant %s has no record", req.Ref)
		}
		bind := g.Got.Bind
		g.Got = got
		if got.Bind == nil {
			g.Got.Bind = bind
		}
		if got.Region != "" {
			if err := setIntentRegion(r, req.Ref, got.Region); err != nil {
				return err
			}
			reg := r.Region(got.Region)
			if reg == nil {
				return fmt.Errorf("region %s has no record", got.Region)
			}
			if got.Dax != "" {
				if err := addDaxUser(reg, got.Dax, req.Ref); err != nil {
					return err
				}
				if !got.DaxDev.IsZero() {
					reg.DaxDevice(got.Dax).Dev = got.DaxDev
				}
			}
		}
		if g.State == state.GrantRealised {
			return nil
		}
		return state.Apply(&state.GrantTable, &g.State, state.GrantRealised, state.TriggerPrepare)
	})
}

// addDaxUser adds a grant to the users of a dax device of a region.
func addDaxUser(reg *state.Region, dax string, ref state.GrantRef) error {
	d := reg.DaxDevice(dax)
	if d == nil {
		return fmt.Errorf("%s has no record of %s", reg.Ref(), dax)
	}
	if slices.Contains(d.Users, ref) {
		return nil
	}
	if len(d.Users) > 0 && d.State != state.DaxSized {
		if err := state.Apply(&state.DaxDeviceTable, &d.State, d.State, state.TriggerPrepare); err != nil {
			return err
		}
	}
	d.Users = append(d.Users, ref)
	return nil
}

// rollback releases the grants of the claims of reqs that the store has,
// those of this Prepare and of earlier ones that did not finish (Policy
// ReleaseRollback), and returns those that it did not release (the
// front-end logs that it keeps their claim's record). The grants of a
// claim that is prepared (a Prepare again that failed) stay. Errors are
// logged.
func (e *Engine) rollback(ctx context.Context, reqs []GrantRequest) []state.Grant {
	r := e.records()
	var refs []state.GrantRef
	seen := map[state.GrantRef]bool{}
	add := func(ref state.GrantRef) {
		if !seen[ref] && r.Grant(ref) != nil {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}
	for i := range reqs {
		p := r.PreparationOf(reqs[i].Ref)
		if p != nil && p.Prepared() {
			continue
		}
		add(reqs[i].Ref)
		if p != nil {
			for _, res := range p.Results {
				if res.Grant != nil {
					add(*res.Grant)
				}
			}
		}
	}
	if len(refs) == 0 {
		return nil
	}
	source := r.Grant(refs[0]).Asked.Source
	e.revokeLends(ctx, refs)
	e.retryAllStale(ctx, state.TriggerPrepare)
	call := newReleaseCall(e, ReleaseRollback, refs)
	for _, group := range e.byMemdev(refs) {
		if err := e.releaseGroup(ctx, group, call); err != nil {
			e.errorf(source, "rollback: %v", err)
		}
	}
	return e.grantsOf(refs)
}

// revokeLends revokes the NUMA nodes that the grants refs lend (Got.Lend,
// recorded before the lend) through Options.Revoke before their memory goes
// offline. Errors are logged: the release goes on.
func (e *Engine) revokeLends(ctx context.Context, refs []state.GrantRef) {
	if e.opts.Revoke == nil {
		return
	}
	r := e.records()
	for _, ref := range refs {
		g := r.Grant(ref)
		if g == nil || g.Got.Lend == nil || g.Got.Lend.NumaNode == nil {
			continue
		}
		if err := e.opts.Revoke(ctx, ref, *g.Got.Lend); err != nil {
			e.errorf(g.Asked.Source, "rollback: claim %s: %v", e.claimNameOf(ref), err)
		}
	}
}

// RecordLend records the NUMA node that the realised grant ref of a
// companion claim lends, before it is lent: the node in the lend of its
// intent, and that lend as the grant's (Got.Lend), in one durable commit.
func (e *Engine) RecordLend(ctx context.Context, ref state.GrantRef, node int) error {
	return e.commit(ctx, func(r *state.Records) error {
		g := r.Grant(ref)
		if g == nil || g.Intent.Lend == nil {
			return fmt.Errorf("grant %s has no lend", ref)
		}
		g.Intent.Lend.NumaNode = state.NumaNodePtr(node)
		lend := *g.Intent.Lend
		g.Got.Lend = &lend
		return nil
	})
}

// verifyGrant returns an error if what a REALISED grant got is not what
// the kernel has now: its region, dax device numbers, block device and node
// mount.
func (e *Engine) verifyGrant(g *state.Grant) error {
	if g.Got.Region == "" {
		return fmt.Errorf("grant %s has no region", g.Ref)
	}
	ri, err := e.k.Region(string(g.Got.Region))
	if err != nil || !slices.Contains(ri.Serials, uint64(g.Serial)) {
		return fmt.Errorf("grant %s: %s is gone", g.Ref, g.Got.Region)
	}
	r := e.records()
	if dev := daxDevOf(r, g); g.Got.Dax != "" && !dev.IsZero() {
		major, minor, err := e.k.DaxDevNumbers(g.Got.Dax)
		if err != nil || major != dev.Major || minor != dev.Minor {
			return fmt.Errorf("grant %s: %s is not the dax device %d:%d as prepared", g.Ref, g.Got.Dax, dev.Major, dev.Minor)
		}
	}
	if path := mountPathOf(r, g); path != "" {
		mi, err := e.k.Mounted(path)
		if err != nil || mi == nil {
			return fmt.Errorf("grant %s: %s is not mounted", g.Ref, path)
		}
	}
	return nil
}
