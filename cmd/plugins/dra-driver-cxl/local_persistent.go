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
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/memctl"
)

// Persistent local memdevs: a local memdev of persistent memory gets one
// pmem region, created by its first claim on the node and released after
// its last one. Every allocation result of a claim is a use of the device
// (a localSlice of mode block or fs): the block device of the fsdax
// namespace of the region, or a filesystem on it through a node mount that
// the uses of the node share. The node mounts, the superblock state and the
// read-only flag of the block devices are the shared persistent code's
// (persistentNode), derived from the uses. See docs/memory/cxl/local.md.

const (
	// localPmemTimeout bounds the wait for the nvdimm region and the
	// namespaces of a pmem region.
	localPmemTimeout = 30 * time.Second
)

// SetPersistent sets the shared persistent code of the node mounts of the
// local driver, whose releases change the read-only flag only of block
// devices that checkUseBlockDevice verifies; nil leaves persistent memdevs
// unusable.
func (a *localAllocator) SetPersistent(pn *persistentNode) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pn = pn
	if pn != nil {
		// called by pn.Release, with a.mu held
		pn.SetCheck(a.checkUseBlockDevice)
	}
}

// persistentNode returns the shared persistent code of the local driver,
// nil for a nil allocator or none.
func (a *localAllocator) persistentNode() *persistentNode {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pn
}

// AcquirePersistent gives the persistent local memdev with the serial to an
// allocation result of a claim: the pmem region of the memdev (created if
// it has none), the fsdax namespace of its nvdimm region (created only by a
// writable block use) and, in mode fs, the node mount of its filesystem. It
// returns the use.
//   - claimUID, request: the claim and the request of the allocation result
//   - serial: the serial of the memdev
//   - shared: the memdev is published shared (sharedDevices)
//   - facts: the facts of the device for the allocation result
//   - w: what the allocation result asks of the device (w.UID claimUID)
//   - path: the directory of mode fs in the containers
func (a *localAllocator) AcquirePersistent(ctx context.Context, claimUID, request string, serial uint64, shared bool, facts config.DeviceFacts, w persistentWant, path string) (*localSlice, error) {
	if a == nil {
		return nil, errors.New("local memdevs are not managed (manageMemdevs: false)")
	}
	if err := a.checkPool(ctx, serial); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pn == nil {
		return nil, errors.New("internal error: no persistent node of the local driver")
	}
	d, err := a.persistentDevice(ctx, serial, shared, claimUID)
	if err != nil {
		return nil, err
	}
	s, err := a.addPersistentUse(ctx, d, facts, w, request, path)
	if err != nil {
		a.dropUnusedPersistent(ctx, d, claimUID)
		return nil, err
	}
	d.Claims[claimUID] = append(d.Claims[claimUID], s)
	klog.Infof("local: memdev %s (serial 0x%x) %s: claim %s request %s: persistent %s mode %s read-only %v access %q fs %q",
		d.Memdev, serial, d.Region, claimUID, request, d.BlockDevice, s.Mode, s.ReadOnly, s.Access, s.FsType)
	a.updateSnapshot()
	if err := a.save(); err != nil {
		return nil, err
	}
	return s, nil
}

// persistentDevice returns the persistent device with the serial for an
// Acquire of a claim, with its pmem region created or reused. A device that
// is used as slices or as a volatile shared device by claims is refused,
// one without claims is released first, and so is one used by claims as a
// persistent device of the other sharing. A region that is not set up (its
// creation failed or was cut, or it was kept for claims) is released when
// that leaves no hole in the decoders (releaseInOrder), else set up again.
// A new device records the claim before its region is created.
func (a *localAllocator) persistentDevice(ctx context.Context, serial uint64, shared bool, claimUID string) (*localDevice, error) {
	memdev, err := a.mem.FindMemdev(serial)
	if err != nil {
		return nil, err
	}
	ok, err := a.mem.Persistent(memdev)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("device %s: %s has no persistent memory", api.FormatSerial(serial), memdev)
	}
	d := a.devices[serial]
	if d != nil {
		d.Memdev = memdev
	}
	if d != nil && !d.Persistent {
		if uids := d.claimUIDs(); len(uids) > 0 {
			what := "as slices"
			if d.Shared {
				what = "shared"
			}
			return nil, fmt.Errorf("memdev %s (serial 0x%x): used %s by claims %v; a persistent device cannot be used so", memdev, serial, what, uids)
		}
		if err := a.releaseOrphans(ctx, d); err != nil {
			a.persist()
			return nil, err
		}
		if err := a.releaseRegion(ctx, d); err != nil {
			return nil, err
		}
		d = nil
	}
	if d != nil && d.Shared != shared {
		if uids := d.claimUIDs(); len(uids) > 0 {
			return nil, fmt.Errorf("memdev %s (serial 0x%x): used as a %s persistent device by claims %v; it is %s now (sharedDevices)", memdev, serial, sharedWord(d.Shared), uids, sharedWord(shared))
		}
		d.Shared = shared
	}
	if d != nil && d.Region != "" && !slices.Contains(a.mem.Regions(memdev), d.Region) {
		klog.Warningf("local: memdev %s (serial 0x%x): %s of the persistent device is gone, forgetting it and its claims %v", memdev, serial, d.Region, d.claimUIDs())
		delete(a.devices, serial)
		a.updateSnapshot()
		d = nil
	}
	if d != nil && (d.Region == "" || d.NdRegion == "") {
		// leftovers of a creation that failed or was cut, or a region
		// kept for claims
		a.adoptCreated(d)
		var above []string
		if d.Region != "" {
			above, err = a.releaseInOrder(ctx, d)
		} else {
			err = a.releaseRegion(ctx, d)
		}
		switch {
		case err != nil:
			return nil, err
		case len(above) > 0:
			if err := a.checkRegions(memdev, d); err != nil {
				return nil, err
			}
			if err := a.setUpPersistent(ctx, d); err != nil {
				a.persist()
				return nil, err
			}
			if _, ok := d.Claims[claimUID]; !ok {
				d.Claims[claimUID] = nil
			}
			return d, a.save()
		}
		d = nil
	}
	if err := a.checkRegions(memdev, d); err != nil {
		return nil, err
	}
	if d != nil {
		if _, ok := d.Claims[claimUID]; !ok {
			d.Claims[claimUID] = nil
		}
		return d, nil
	}
	d = &localDevice{
		Serial:     serial,
		SerialHex:  fmt.Sprintf("%x", serial),
		Memdev:     memdev,
		Node:       -1,
		Shared:     shared,
		Persistent: true,
		Claims:     map[string][]*localSlice{claimUID: nil},
	}
	a.devices[serial] = d
	a.updateSnapshot()
	err = a.save()
	if err == nil {
		err = a.createPmemRegion(ctx, d)
	}
	if err == nil {
		err = a.save()
	}
	if err != nil {
		// not set up: setUpPersistent if it is kept
		d.NdRegion = ""
		a.dropUnusedPersistent(ctx, d, claimUID)
		return nil, err
	}
	return d, nil
}

// createPmemRegion creates the pmem region of a device, and retries once
// after a transient failure. The name of the new region is recorded in the
// device before cxl create-region runs (regionNote).
func (a *localAllocator) createPmemRegion(ctx context.Context, d *localDevice) error {
	start := time.Now()
	pr, err := a.pmemRegion(ctx, d)
	if err != nil && isAddDevError(err) {
		klog.Warningf("local: memdev %s (serial 0x%x): %v; retrying once in %v", d.Memdev, d.Serial, err, a.retryDelay)
		select {
		case <-ctx.Done():
		case <-time.After(a.retryDelay):
			pr, err = a.pmemRegion(ctx, d)
		}
	}
	if err != nil {
		// the region that the failed creation left, if any
		a.adoptCreated(d)
		return fmt.Errorf("memdev %s (serial 0x%x): %w", d.Memdev, d.Serial, err)
	}
	d.Region, d.NdRegion, d.Creating = pr.Region, pr.NdRegion, ""
	klog.Infof("local: memdev %s (serial 0x%x): created %s (pmem, nvdimm %s) in %s", d.Memdev, d.Serial, d.Region, d.NdRegion, since(start))
	return nil
}

// pmemRegion returns the pmem region of the memdev of a device with its
// nvdimm region and namespaces, created if the memdev has none (telling
// regionNote), within localPmemTimeout.
func (a *localAllocator) pmemRegion(ctx context.Context, d *localDevice) (*memctl.PmemRegion, error) {
	wctx, cancel := context.WithTimeout(ctx, localPmemTimeout)
	defer cancel()
	return a.mem.CreatePmemRegionNoted(wctx, d.Memdev, "", a.regionNote(d))
}

// setUpPersistent sets up a pmem region that was kept for claims without
// being set up (NdRegion ""): its creation failed or was cut, or its last
// claims went and its release would have left a hole in the decoders. A
// region that a cut release disabled is enabled again.
func (a *localAllocator) setUpPersistent(ctx context.Context, d *localDevice) error {
	if _, err := a.mem.NdRegion(d.Region); err != nil {
		if err := a.mem.EnableRegion(ctx, d.Region); err != nil {
			return fmt.Errorf("memdev %s (serial 0x%x): setting up kept %s: %w", d.Memdev, d.Serial, d.Region, err)
		}
	}
	pr, err := a.pmemRegion(ctx, d)
	if err != nil {
		return fmt.Errorf("memdev %s (serial 0x%x): setting up kept %s: %w", d.Memdev, d.Serial, d.Region, err)
	}
	d.NdRegion = pr.NdRegion
	klog.Infof("local: memdev %s (serial 0x%x): set up kept %s (pmem, nvdimm %s)", d.Memdev, d.Serial, d.Region, d.NdRegion)
	return nil
}

// addPersistentUse prepares a use of the set-up region of a device for an
// allocation result: the fsdax namespace (pmemNamespace: only a writable
// block use creates one), then the use on the node next to the other uses
// of the device (persistentNode.Prepare), and returns it.
func (a *localAllocator) addPersistentUse(ctx context.Context, d *localDevice, facts config.DeviceFacts, w persistentWant, request, path string) (*localSlice, error) {
	pr, err := a.pmemRegion(ctx, d)
	if err != nil {
		return nil, fmt.Errorf("memdev %s (serial 0x%x): %w", d.Memdev, d.Serial, err)
	}
	wctx, cancel := context.WithTimeout(ctx, localPmemTimeout)
	defer cancel()
	ns, err := pmemNamespace(wctx, a.mem, d.Serial, pr, w.Mode, w.ReadOnly)
	if err != nil {
		return nil, err
	}
	d.Namespace, d.BlockDevice, d.BlockMajor, d.BlockMinor = ns.Name, ns.BlockDevice, ns.Major, ns.Minor
	target := persistentTarget{Serial: d.Serial, BlockDevice: d.BlockDevice, Facts: facts}
	use, err := a.pn.Prepare(ctx, target, w, a.persistentUses(d, ""))
	if err != nil {
		return nil, err
	}
	s := &localSlice{
		Request:  request,
		Result:   w.Result,
		Region:   d.Region,
		Mode:     use.Mode,
		Size:     ns.Size,
		ReadOnly: use.ReadOnly,
	}
	if use.Mode == api.ModeFs {
		s.Access, s.FsType, s.NodeMount, s.LoopDevice, s.Path = use.Access, use.FsType, use.NodeMount, use.LoopDevice, path
	}
	return s, nil
}

// persistentUses returns the uses of a persistent device of every claim but
// exceptUID ("" for none), in the order of the claim UIDs.
func (a *localAllocator) persistentUses(d *localDevice, exceptUID string) []persistentUse {
	var uses []persistentUse
	for _, uid := range slices.Sorted(maps.Keys(d.Claims)) {
		if uid == exceptUID {
			continue
		}
		uses = append(uses, d.uses(uid)...)
	}
	return uses
}

// uses returns the uses of a persistent device by a claim.
func (d *localDevice) uses(claimUID string) []persistentUse {
	var uses []persistentUse
	for _, s := range d.Claims[claimUID] {
		uses = append(uses, persistentUse{
			UID:         claimUID,
			Result:      s.Result,
			Serial:      d.Serial,
			Mode:        s.Mode,
			ReadOnly:    s.ReadOnly,
			Access:      s.Access,
			FsType:      s.FsType,
			BlockDevice: d.BlockDevice,
			NodeMount:   s.NodeMount,
			LoopDevice:  s.LoopDevice,
		})
	}
	return uses
}

// dropUnusedPersistent releases the region of a persistent device after a
// failed Acquire of a claim if no other claim uses it, when nothing holds
// its block device, and saves the state. When regions of other memdevs lie
// above it, it is kept for the claim instead (keepRegion).
func (a *localAllocator) dropUnusedPersistent(ctx context.Context, d *localDevice, claimUID string) {
	if len(d.Claims[claimUID]) == 0 {
		delete(d.Claims, claimUID)
	}
	if len(d.Claims) == 0 {
		ctx, cancel := rollbackContext(ctx)
		defer cancel()
		err := a.waitNoHolder(ctx, d, time.Now().Add(a.holderWait()))
		if err == nil {
			err = a.releaseOrKeep(ctx, d, []string{claimUID})
		}
		if err != nil {
			klog.Errorf("local: %v", err)
		}
	}
	a.persist()
}

// releasePersistent releases the uses of a claim of a persistent device
// (persistentNode.Release: node mounts, superblock state and read-only
// flags of the remaining uses), and the region of the device if the claim
// was its last one, when nothing holds its block device within the holder
// wait: by releaseOrKeep if keep, else by releaseInOrder, which keeps the
// region of the idle device while regions of other memdevs lie above it.
// On error the claim keeps what is not released yet.
func (a *localAllocator) releasePersistent(ctx context.Context, d *localDevice, claimUID string, keep bool) error {
	if gone := d.uses(claimUID); len(gone) > 0 && a.pn != nil {
		if err := a.pn.Release(ctx, d.Serial, gone, a.persistentUses(d, claimUID)); err != nil {
			return fmt.Errorf("memdev %s (serial 0x%x): %w", d.Memdev, d.Serial, err)
		}
	}
	if uids := d.claimUIDs(); len(uids) > 1 || (len(uids) == 1 && uids[0] != claimUID) {
		delete(d.Claims, claimUID)
		klog.Infof("local: memdev %s (serial 0x%x): claim %s: released persistent %s, claims left %v", d.Memdev, d.Serial, claimUID, d.BlockDevice, d.claimUIDs())
		return nil
	}
	// the claim holds the region until it is released
	d.Claims[claimUID] = nil
	if err := a.waitNoHolder(ctx, d, time.Now().Add(a.holderWait())); err != nil {
		return err
	}
	if keep {
		return a.releaseOrKeep(ctx, d, []string{claimUID})
	}
	if err := a.releaseIdle(ctx, d); err != nil {
		return err
	}
	delete(d.Claims, claimUID)
	return nil
}

// releaseIdle releases the region of a persistent device whose claims are
// gone, unless regions of other memdevs lie above it: the idle device
// keeps its region then (logged), which its next claim uses, and which a
// later release of idle devices releases (ReleaseIdle).
func (a *localAllocator) releaseIdle(ctx context.Context, d *localDevice) error {
	above, err := a.releaseInOrder(ctx, d)
	if err != nil {
		return err
	}
	if len(above) > 0 {
		klog.Warningf("local: memdev %s (serial 0x%x): keeping %s of the idle persistent device: %s lie above it, its release would leave a hole in the decoders of their ports",
			d.Memdev, d.Serial, d.Region, strings.Join(above, ", "))
	}
	return nil
}

// ReleaseIdle releases the regions of the persistent devices that have no
// claims and whose block device nothing holds now.
func (a *localAllocator) ReleaseIdle(ctx context.Context) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.releaseIdleDevices(ctx)
	a.persist()
}

// releaseIdleDevices releases the regions of the persistent devices that
// have no claims and whose block device nothing holds now (logged when
// something does). Called with a.mu held.
func (a *localAllocator) releaseIdleDevices(ctx context.Context) {
	for _, serial := range a.serials() {
		d := a.devices[serial]
		if !d.Persistent || len(d.Claims) > 0 {
			continue
		}
		if d.Region == "" {
			if err := a.releaseRegion(ctx, d); err != nil {
				klog.Errorf("local: %v", err)
			}
			continue
		}
		if err := a.waitNoHolder(ctx, d, time.Now()); err != nil {
			klog.Warningf("local: memdev %s (serial 0x%x): keeping %s of the idle persistent device: %v", d.Memdev, d.Serial, d.Region, err)
			continue
		}
		if err := a.releaseIdle(ctx, d); err != nil {
			klog.Errorf("local: %v", err)
		}
	}
}

// holderWait returns how long a release waits for the block device of a
// persistent device to have no holder.
func (a *localAllocator) holderWait() time.Duration {
	if a.pn != nil {
		return a.pn.HolderWait()
	}
	return defaultHolderWait
}

// waitNoHolder waits until the deadline until nothing holds the block
// device of a persistent device: the recorded one when it is the one of
// the fsdax namespace of its region now, else that one (none without a
// region).
func (a *localAllocator) waitNoHolder(ctx context.Context, d *localDevice, deadline time.Time) error {
	if a.pn == nil {
		return nil
	}
	dev := d.BlockDevice
	if dev == "" || checkPmemBlockDevice(a.mem, localPmemTimeout, d.Serial, d.Namespace, d.BlockDevice, d.BlockMajor, d.BlockMinor) != nil {
		dev = currentPmemBlockDevice(a.mem, localPmemTimeout, d.Serial)
	}
	if dev == "" {
		return nil
	}
	if err := a.pn.WaitNoHolder(ctx, d.Serial, dev, deadline); err != nil {
		return fmt.Errorf("memdev %s (serial 0x%x): %w", d.Memdev, d.Serial, err)
	}
	return nil
}

// reconcilePersistent drops the uses of the claims of a persistent device
// that are not in prepared (no device work: the restore of the node mounts
// and the release of idle devices follow, restorePersistent). Called with
// a.mu held.
func (a *localAllocator) reconcilePersistent(d *localDevice, prepared map[string]bool) {
	for _, uid := range slices.Sorted(maps.Keys(d.Claims)) {
		if !prepared[uid] {
			klog.Infof("local: memdev %s (serial 0x%x): claim %s of the persistent device is not prepared, dropping it", d.Memdev, d.Serial, uid)
			delete(d.Claims, uid)
		}
	}
	if uids := d.claimUIDs(); len(uids) > 0 {
		klog.Infof("local: memdev %s (serial 0x%x): keeping persistent %s, claims %v", d.Memdev, d.Serial, d.Region, uids)
	}
}

// restorePersistent mounts again the node mounts of the uses of the
// prepared claims of persistent devices with their derived state
// (persistentNode.RestoreMounts), sweeps the directory of node mounts,
// records the block
// devices that are not those of their namespaces now (unrestored), and then
// releases the idle devices. Called with a.mu held.
func (a *localAllocator) restorePersistent(ctx context.Context) {
	if a.pn == nil {
		return
	}
	a.badBlock = map[uint64]error{}
	var uses []persistentUse
	for _, serial := range a.serials() {
		d := a.devices[serial]
		if !d.Persistent {
			continue
		}
		uses = append(uses, a.persistentUses(d, "")...)
		if len(d.Claims) == 0 || d.BlockDevice == "" {
			continue
		}
		if err := a.checkBlockDevice(d); err != nil {
			klog.Errorf("local: memdev %s (serial 0x%x): %v", d.Memdev, d.Serial, err)
			a.badBlock[serial] = err
		}
	}
	restored := a.pn.RestoreMounts(uses, a.checkUseBlockDevice)
	for _, d := range a.devices {
		for _, own := range d.Claims {
			for _, s := range own {
				if r, ok := restored[s.NodeMount]; ok && s.NodeMount != "" && r.Err == nil {
					s.LoopDevice = r.Loop
				}
			}
		}
	}
	a.pn.SweepNodeMounts(uses)
	a.releaseIdleDevices(ctx)
}

// checkBlockDevice returns an error if the block device of a persistent
// device is not the one of the fsdax namespace of its region now.
func (a *localAllocator) checkBlockDevice(d *localDevice) error {
	return checkPmemBlockDevice(a.mem, localPmemTimeout, d.Serial, d.Namespace, d.BlockDevice, d.BlockMajor, d.BlockMinor)
}

// checkUseBlockDevice returns an error if blockDev is not the recorded
// block device of the persistent device with the serial, or not the one of
// the fsdax namespace of its region now (checkBlockDevice). Called with
// a.mu held.
func (a *localAllocator) checkUseBlockDevice(serial uint64, blockDev string) error {
	d := a.devices[serial]
	if d == nil || !d.Persistent {
		return fmt.Errorf("device %s: not a persistent local device", api.FormatSerial(serial))
	}
	if blockDev != d.BlockDevice {
		return fmt.Errorf("device %s: %s is not its block device %s", api.FormatSerial(serial), blockDev, d.BlockDevice)
	}
	return a.checkBlockDevice(d)
}

// PersistentRestored returns why the use of a persistent device by the
// allocation result of a prepared claim is not what the claim was prepared
// with, nil if it is: the allocator has no such use (the region is gone),
// the block device is not the one of the fsdax namespace of the region now
// (found at start), or its node mount is not mounted (the start could not
// mount it again).
func (a *localAllocator) PersistentRestored(claimUID string, serial uint64, result int) error {
	if a == nil {
		return errors.New("local memdevs are not managed")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.persistentRestored(claimUID, serial, result)
}

// persistentRestored is PersistentRestored with a.mu held.
func (a *localAllocator) persistentRestored(claimUID string, serial uint64, result int) error {
	d := a.devices[serial]
	if d == nil || !d.Persistent {
		return fmt.Errorf("device %s: the plugin has no region of it", api.FormatSerial(serial))
	}
	if err := a.badBlock[serial]; err != nil {
		return err
	}
	for _, s := range d.Claims[claimUID] {
		if s.Result != result {
			continue
		}
		if s.NodeMount == "" || a.pn == nil {
			return nil
		}
		if err, ok := a.pn.Unrestored(s.NodeMount); ok {
			return err
		}
		return nil
	}
	return fmt.Errorf("device %s: the plugin has no use of it for the claim", api.FormatSerial(serial))
}

// RemountPersistent mounts again the node mounts of the uses of a prepared
// claim that the start could not mount (persistentNode.Remount), and
// returns an error that names a use that stays unrestored.
func (a *localAllocator) RemountPersistent(claimUID string) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	changed := false
	defer func() {
		if changed {
			a.persist()
		}
	}()
	for _, serial := range a.serials() {
		d := a.devices[serial]
		if !d.Persistent {
			continue
		}
		for _, s := range d.Claims[claimUID] {
			if s.NodeMount == "" || a.pn == nil {
				continue
			}
			why, ok := a.pn.Unrestored(s.NodeMount)
			if !ok {
				continue
			}
			var mntUses []persistentUse
			for _, u := range a.persistentUses(d, "") {
				if u.NodeMount == s.NodeMount {
					mntUses = append(mntUses, u)
				}
			}
			loop, err := a.pn.Remount(s.NodeMount, mntUses, a.checkUseBlockDevice)
			if err != nil {
				return fmt.Errorf("device %s: its node mount %s is not mounted and cannot be mounted again: %w; unprepare the claim (delete its pods) to prepare it anew",
					api.FormatSerial(serial), s.NodeMount, err)
			}
			klog.Infof("local: claim %s: %s is mounted again (it was not: %v)", claimUID, s.NodeMount, why)
			for _, own := range d.Claims {
				for _, o := range own {
					if o.NodeMount == s.NodeMount {
						o.LoopDevice = loop
					}
				}
			}
			changed = true
		}
	}
	return nil
}

// notPersistent returns a device that is persistent, for an Acquire that
// uses its memdev as what (a sliced or a shared device): an error when
// claims use it as a persistent device, else nil after its region is
// released when nothing holds its block device.
func (a *localAllocator) notPersistent(ctx context.Context, d *localDevice, what string) (*localDevice, error) {
	if uids := d.claimUIDs(); len(uids) > 0 {
		return nil, fmt.Errorf("memdev %s (serial 0x%x): used as a persistent device by claims %v; %s cannot be a persistent device", d.Memdev, d.Serial, uids, what)
	}
	if err := a.waitNoHolder(ctx, d, time.Now()); err != nil {
		return nil, err
	}
	if err := a.releaseRegion(ctx, d); err != nil {
		return nil, err
	}
	return nil, nil
}

// prepareLocalPersistent gives a persistent local memdev to the allocation
// result n of a claim in mode block or fs as the device settings cfg say,
// and describes it in devInfo: the block device of the fsdax namespace of
// its region is its total and consumed bytes.
//   - key: the env key of the memory of the result, of the default path of
//     mode fs
func (s *nodeState) prepareLocalPersistent(ctx context.Context, claim *resourcev1.ResourceClaim, r *resourcev1.DeviceRequestAllocationResult, n int, key string, dev *device.Memdev, cfg config.Device, devInfo *PreparedDeviceInfo) error {
	fail := func(err error) error {
		return fmt.Errorf("claim %v/%v: request %s: %w", claim.Namespace, claim.Name, r.Request, err)
	}
	if _, ok := r.ConsumedCapacity[device.CapacityMemory]; ok {
		return fail(fmt.Errorf("device %s: allocated as a device of volatile memory, which it is not any more", api.FormatSerial(dev.Serial)))
	}
	shares, err := consumedShares(dev.Serial, r)
	if err != nil {
		return fail(err)
	}
	facts := config.DeviceFacts{
		Persistent: true,
		Shared:     dev.Shared,
		Exclusive:  shares >= device.SharesUnlimited,
		SingleHost: !dev.Shared,
		Coherent:   s.config.memdevCoherent(dev.Name, dev.Serial),
		Local:      true,
	}
	mode, err := cfg.PersistentMode(facts)
	if err != nil {
		return fail(err)
	}
	path := ""
	if mode == api.ModeFs {
		if path = cfg.Path; path == "" {
			path = defaultFsPath(key)
		}
	}
	uid := string(claim.UID)
	w := persistentWant{UID: uid, Result: n, Mode: mode, ReadOnly: cfg.IsReadOnly(), Access: cfg.Access, FsType: cfg.FsType}
	use, err := s.local.AcquirePersistent(ctx, uid, r.Request, dev.Serial, dev.Shared, facts, w, path)
	if err != nil {
		return fail(err)
	}
	blockDev, ns, major, minor := s.local.blockDevice(dev.Serial)
	devInfo.DeviceType = device.DeviceTypeMemdev
	devInfo.Mode = use.Mode
	devInfo.Serial = api.FormatSerial(dev.Serial)
	devInfo.Shared = dev.Shared
	devInfo.Persistent = true
	devInfo.SysfsPath = s.local.regionPath(use.Region)
	devInfo.TotalBytes = use.Size
	devInfo.ConsumedBytes = int64(use.Size)
	if dev.NodeAffinity >= 0 {
		devInfo.NodeAffinities = []int{dev.NodeAffinity}
	}
	devInfo.ReadOnly = use.ReadOnly
	devInfo.Namespace, devInfo.BlockDevice, devInfo.BlockMajor, devInfo.BlockMinor = ns, blockDev, major, minor
	devInfo.Access, devInfo.Path, devInfo.NodeMount, devInfo.LoopDevice, devInfo.FsType = use.Access, use.Path, use.NodeMount, use.LoopDevice, use.FsType
	return nil
}

// blockDevice returns the block device of the persistent device with the
// serial, its namespace and its numbers.
func (a *localAllocator) blockDevice(serial uint64) (dev, ns string, major, minor int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if d := a.devices[serial]; d != nil {
		return d.BlockDevice, d.Namespace, d.BlockMajor, d.BlockMinor
	}
	return "", "", 0, 0
}

// persistentUses returns the uses of the persistent local memdevs of a
// prepared claim, as the shared persistent code sees them.
func (info *PreparedClaimInfo) persistentUses(claimUID string) []persistentUse {
	var uses []persistentUse
	if info == nil {
		return nil
	}
	for _, d := range info.Devices {
		if !d.Persistent {
			continue
		}
		serial, err := api.ParseSerial(d.Serial)
		if err != nil {
			continue
		}
		uses = append(uses, persistentUse{
			UID:         claimUID,
			Result:      d.Result,
			Serial:      serial,
			Mode:        d.Mode,
			ReadOnly:    d.ReadOnly,
			Access:      d.Access,
			FsType:      d.FsType,
			BlockDevice: d.BlockDevice,
			NodeMount:   d.NodeMount,
			LoopDevice:  d.LoopDevice,
		})
	}
	return uses
}

// findUnrestored records the prepared claims whose persistent local memdevs
// are not what they were prepared with (localAllocator.PersistentRestored):
// they get no CDI devices.
func (s *nodeState) findUnrestored() {
	for _, uid := range slices.Sorted(maps.Keys(s.preparedClaims)) {
		info := s.preparedClaims[uid]
		if err := s.restoredError(uid, info); err != nil {
			s.unrestored[uid] = err
			if info.Lend == nil {
				klog.Errorf("claim %s (%s) has no CDI device: %v; a new container of it fails on its CDI device, its Prepare again tries to mount it again, its Unprepare releases the device",
					info.ClaimName, uid, err)
			}
		}
	}
}

// restoredError returns why a persistent local memdev of a prepared claim is
// not what the claim was prepared with, nil if none is.
func (s *nodeState) restoredError(uid string, info *PreparedClaimInfo) error {
	if info == nil {
		return nil
	}
	for _, d := range info.Devices {
		if !d.Persistent {
			continue
		}
		serial, err := api.ParseSerial(d.Serial)
		if err == nil {
			err = s.local.PersistentRestored(uid, serial, d.Result)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// remountUnrestored mounts again the node mounts of a prepared claim that
// is unrestored (findUnrestored) for kubelet's Prepare again of the claim,
// and rewrites the CDI spec when the claim is restored: it has its CDI
// devices again. An error names what stays unrestored.
func (s *nodeState) remountUnrestored(claim *resourcev1.ResourceClaim) error {
	uid := string(claim.UID)
	s.Lock()
	why := s.unrestored[uid]
	info := s.preparedClaims[uid]
	s.Unlock()
	if why == nil {
		return nil
	}
	err := s.local.RemountPersistent(uid)
	if err == nil {
		err = s.restoredError(uid, info)
	}
	if err != nil {
		return fmt.Errorf("claim %v/%v: %w; unprepare the claim (delete its pods) to prepare it anew", claim.Namespace, claim.Name, err)
	}
	klog.Infof("claim %v/%v (%s): its devices are restored: it has its CDI devices again", claim.Namespace, claim.Name, uid)
	s.Lock()
	delete(s.unrestored, uid)
	s.Unlock()
	return s.persist()
}

// otherBind returns the function that tells whether a prepared claim other
// than exceptUID has a lease bind at a target.
func (s *nodeState) otherBind(exceptUID string) func(target string) bool {
	return func(target string) bool {
		s.Lock()
		defer s.Unlock()
		for uid, info := range s.preparedClaims {
			if uid != exceptUID && info != nil && info.Lend != nil && slices.Contains(info.Lend.Mounts, target) {
				return true
			}
		}
		return false
	}
}

// bindLeases binds the node mount of the device of mode fs of a companion
// claim at the lease's directory and records the bind in rec (nothing for
// a claim without an fs device).
func (s *nodeState) bindLeases(claim *resourcev1.ResourceClaim, rec *lendRecord, info *PreparedClaimInfo) error {
	uses := info.persistentUses(string(claim.UID))
	pn := s.local.persistentNode()
	if pn == nil || !slices.ContainsFunc(uses, func(u persistentUse) bool { return u.Mode == api.ModeFs }) {
		return nil
	}
	if err := pn.BindLease(rec, uses, s.otherBind(string(claim.UID))); err != nil {
		return fmt.Errorf("claim %v/%v: %w", claim.Namespace, claim.Name, err)
	}
	return nil
}

// unbindLeases unmounts the lease binds of a lend of the claim uid.
func (s *nodeState) unbindLeases(rec *lendRecord, uid string) error {
	pn := s.local.persistentNode()
	if pn == nil || rec == nil || len(rec.Mounts) == 0 {
		return nil
	}
	return pn.UnbindLease(rec, s.otherBind(uid))
}

// unbindFailed unmounts the lease binds of a failed Prepare of the
// companion claim uid; a bind that cannot be unmounted is kept as a stale
// bind for a later release.
func (s *nodeState) unbindFailed(uid string, rec *lendRecord, info *PreparedClaimInfo) {
	pn := s.local.persistentNode()
	if pn == nil || rec == nil || len(rec.Mounts) == 0 {
		return
	}
	err := pn.UnbindLease(rec, s.otherBind(uid))
	if err == nil {
		return
	}
	klog.Errorf("lease %s: %v; trying again at the next release", rec.Lease, err)
	uses := info.persistentUses(uid)
	for i := range uses {
		if uses[i].Mode == api.ModeFs {
			pn.KeepStale(rec, &uses[i])
			return
		}
	}
	pn.KeepStale(rec, nil)
}

// unbindStale unmounts the stale lease binds that no prepared claim but
// exceptUID lists, and releases the idle persistent devices when one is
// gone.
func (s *nodeState) unbindStale(ctx context.Context, exceptUID string) {
	pn := s.local.persistentNode()
	if pn == nil {
		return
	}
	if gone := pn.UnbindStale(s.otherBind(exceptUID)); len(gone) > 0 {
		s.local.ReleaseIdle(ctx)
	}
}

// restoreLeaseBinds binds again the missing lease binds of the prepared
// companion claims of persistent local memdevs whose node mount is mounted.
func (s *nodeState) restoreLeaseBinds() {
	pn := s.local.persistentNode()
	if pn == nil {
		return
	}
	var claims []leaseBindClaim
	for _, uid := range slices.Sorted(maps.Keys(s.preparedClaims)) {
		info := s.preparedClaims[uid]
		if info == nil || info.Lend == nil || len(info.Lend.Mounts) == 0 {
			continue
		}
		claims = append(claims, leaseBindClaim{UID: uid, ClaimName: info.ClaimName, Lend: info.Lend, Uses: info.persistentUses(uid)})
	}
	pn.RestoreLeaseBinds(claims)
}

// leaseBinds returns the lease binds of the prepared companion claims.
func (s *nodeState) leaseBinds() map[string]bool {
	s.Lock()
	defer s.Unlock()
	out := map[string]bool{}
	for _, info := range s.preparedClaims {
		if info != nil && info.Lend != nil {
			for _, t := range info.Lend.Mounts {
				out[t] = true
			}
		}
	}
	return out
}
