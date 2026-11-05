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
	"strings"
	"time"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// Local memdevs: a sliced memdev gives each grant a part of its region (a
// dax device on whole memory blocks: kmem with its memory online movable in
// mode numa, device_dax zeroed in mode dax); a shared memdev gives every
// grant the Whole device of its region (device_dax, zeroed once when the
// region is new).

// realiseLocalShared realises a grant of a local memdev configured shared:
// the Whole device of its region, zeroed once for a new region.
func (e *Engine) realiseLocalShared(ctx context.Context, req *GrantRequest, memdev string) error {
	start := time.Now()
	region, err := e.ensureRegion(ctx, req, memdev, state.RegionRam, 0)
	if err != nil {
		return err
	}
	dax, err := e.wholeDevice(ctx, req, region, kernel.DriverDeviceDax)
	if err != nil {
		return err
	}
	reg := e.records().Region(state.RegionRef(region))
	if reg != nil && !reg.Zeroed {
		size, err := e.k.DaxDeviceSize(dax)
		if err == nil {
			err = e.waiting(req.Serial, state.TriggerPrepare, func() error { return e.k.Zero(ctx, dax) })
		}
		if err != nil {
			return fmt.Errorf("memdev %s (serial %s): zeroing new shared %s: %w", memdev, serialText(req.Serial), dax, err)
		}
		klog.Infof("local: memdev %s (serial %s): zeroed new shared %s size %d in %s", memdev, serialText(req.Serial), dax, size, since(start))
		if err := e.commit(ctx, func(r *state.Records) error {
			r.Region(state.RegionRef(region)).Zeroed = true
			return nil
		}); err != nil {
			return err
		}
	}
	major, minor, err := e.k.DaxDevNumbers(dax)
	if err != nil {
		return err
	}
	size, _ := e.k.DaxDeviceSize(dax)
	return e.realised(ctx, req, state.Got{Region: state.RegionRef(region), Dax: dax,
		DaxDev: state.DevNumbers{Major: major, Minor: minor}, Size: size})
}

// realiseLocalSliced realises a grant of a part of a local memdev: the
// region of the memdev (its Whole device bound to device_dax), a dax device
// of the asked size rounded up to whole memory blocks, placed on whole
// blocks, then kmem and online movable (mode numa, the node fenced first) or
// device_dax and zeroed (mode dax).
func (e *Engine) realiseLocalSliced(ctx context.Context, req *GrantRequest, memdev string) error {
	bs, err := e.k.BlockSize()
	if err != nil {
		return err
	}
	usable := req.Facts.Usable
	if ram, err := e.k.RamSize(memdev); err == nil && usable >= ram {
		usable = 0
	}
	created := ownRegion(e.records(), req.Serial, state.RegionRam) == nil
	start := time.Now()
	region, err := e.ensureRegion(ctx, req, memdev, state.RegionRam, usable)
	if err != nil {
		return err
	}
	whole, err := e.wholeDevice(ctx, req, region, kernel.DriverDeviceDax)
	if err != nil {
		return err
	}
	if created {
		klog.Infof("local: memdev %s (serial %s): created %s (devdax, dax %s, node %d) in %s", memdev, serialText(req.Serial),
			region, whole, e.k.TargetNode(whole), since(start))
		if r, err := e.k.RegionRange(region); err == nil && r.Start%bs != 0 {
			usable, end := uint64(0), (r.End+1)/bs*bs
			if start := roundUp(r.Start, bs); end > start {
				usable = end - start
			}
			klog.Warningf("local: memdev %s (serial %s): %s at %v does not start at a memory block boundary (block size %d): slices use only its %d bytes of whole blocks",
				memdev, serialText(req.Serial), region, r, bs, usable)
		}
	}
	dax, size, err := e.addSlice(ctx, req, memdev, region, bs)
	if err != nil {
		return err
	}
	got := state.Got{Region: state.RegionRef(region), Dax: dax, Size: size}
	if req.Asked.Mode == state.ModeNUMA {
		node, err := e.onlineSlice(ctx, req, memdev, region, dax, bs)
		if err != nil {
			return err
		}
		got.NumaNode = state.NumaNodePtr(node)
	} else {
		dev, err := e.bindSlice(ctx, req, memdev, region, dax, size)
		if err != nil {
			return err
		}
		got.DaxDev = dev
	}
	return e.realised(ctx, req, got)
}

// roundUp returns v rounded up to a multiple of step (v if step is 0).
func roundUp(v, step uint64) uint64 {
	if step == 0 || v%step == 0 {
		return v
	}
	return (v/step + 1) * step
}

// addSlice makes the dax device of a part of the memdev for a grant and
// returns it with its size: the unused Whole device daxN.0 or the seed
// resized, else a new device placed first-fit by the kernel, on the first
// whole free blocks instead when first-fit crossed a block boundary. The
// device is recorded SIZED with the grant its user.
func (e *Engine) addSlice(ctx context.Context, req *GrantRequest, memdev, region string, bs uint64) (string, uint64, error) {
	first, size, err := e.sliceRoom(req, memdev, region, bs)
	if err != nil {
		return "", 0, err
	}
	start := time.Now()
	dax := first
	if first != "" {
		err = e.locked(func() error { return e.k.ResizeDaxDevice(ctx, first, size) })
	} else {
		err = e.locked(func() error {
			var err error
			dax, err = e.k.CreateDaxDevice(ctx, region, size)
			return err
		})
	}
	if err != nil {
		return "", 0, err
	}
	if err := e.commit(ctx, func(r *state.Records) error { return sliceRecord(r, req.Ref, region, dax, first != "") }); err != nil {
		return "", 0, err
	}
	aligned, err := e.alignSlice(ctx, req, memdev, region, dax, size, bs)
	if err != nil {
		return "", 0, err
	}
	ranges, _ := e.k.DaxDeviceRanges(aligned)
	info, _ := e.k.DaxDevice(aligned)
	dev := state.DevNumbers{Major: info.Major, Minor: info.Minor}
	if err := e.commit(ctx, func(r *state.Records) error { return sizedSlice(r, req.Ref, region, aligned, size, ranges, dev) }); err != nil {
		return "", 0, err
	}
	klog.Infof("local: memdev %s (serial %s): claim %s: created slice %s mode %s size %d at %v in %s",
		memdev, serialText(req.Serial), req.Ref.Claim, aligned, req.Asked.Mode, size, ranges, since(start))
	return aligned, size, nil
}

// sliceRoom returns the device that a part of the memdev for a grant
// reuses (the unused daxN.0 that kmem does not have, "" for a new one) and
// the size of the part: the asked size rounded up to the memory block size
// bs and the align of the dax region; an error when the region has no room.
func (e *Engine) sliceRoom(req *GrantRequest, memdev, region string, bs uint64) (string, uint64, error) {
	dr, err := e.k.DaxRegion(region)
	if err != nil {
		return "", 0, err
	}
	size := req.Asked.Size
	if s := roundUp(roundUp(size, bs), dr.Align); s != size {
		klog.Warningf("local: memdev %s (serial %s): claim %s: slice of %d bytes rounded up to %d (memory block size %d, align %d)",
			memdev, serialText(req.Serial), req.Ref.Claim, size, s, bs, dr.Align)
		size = s
	}
	reg := e.records().Region(state.RegionRef(region))
	first := ""
	avail := dr.Available
	for _, dax := range dr.Devices {
		d := reg.DaxDevice(dax)
		if strings.HasSuffix(dax, ".0") && d != nil && len(d.Users) == 0 && e.k.DaxDriver(dax) != kernel.DriverKmem {
			first = dax
			cur, _ := e.k.DaxDeviceSize(dax)
			avail += cur
		}
	}
	if avail < size {
		return "", 0, fmt.Errorf("%w: %d bytes free in %s, the slice needs %d", kernel.ErrNoRoom, avail, region, size)
	}
	return first, size, nil
}

// sizedSlice records the dax device of a part placed: SIZED, with its
// size, memory and numbers, the grant its user.
func sizedSlice(r *state.Records, ref state.GrantRef, region, dax string, size uint64, ranges []kernel.Range, dev state.DevNumbers) error {
	d := r.Region(state.RegionRef(region)).DaxDevice(dax)
	if d.State == state.DaxCreating {
		if err := state.Apply(&state.DaxDeviceTable, &d.State, state.DaxSized, state.TriggerPrepare); err != nil {
			return err
		}
	}
	d.Size, d.Ranges, d.Users, d.Dev = size, addressRanges(ranges), []state.GrantRef{ref}, dev
	return nil
}

// sliceRecord records the dax device of a new part: the Whole device
// daxN.0 resized (DEVICE_DAX -> SIZED, no longer the Whole device), the
// seed sized again, or a new device (ABSENT -> CREATING).
func sliceRecord(r *state.Records, ref state.GrantRef, region, dax string, reused bool) error {
	reg := r.Region(state.RegionRef(region))
	d := reg.DaxDevice(dax)
	if d == nil {
		reg.DaxDevices = append(reg.DaxDevices, state.DaxDevice{Name: dax, State: state.DaxAbsent})
		d = &reg.DaxDevices[len(reg.DaxDevices)-1]
	}
	switch {
	case reused && (d.State == state.DaxDeviceDax || d.State == state.DaxSeed):
		if err := state.Apply(&state.DaxDeviceTable, &d.State, state.DaxSized, state.TriggerPrepare); err != nil {
			return err
		}
		d.Whole, d.Driver = false, ""
	case d.State == state.DaxAbsent:
		if err := state.Apply(&state.DaxDeviceTable, &d.State, state.DaxCreating, state.TriggerPrepare); err != nil {
			return err
		}
	}
	d.Users = []state.GrantRef{ref}
	if g := r.Grant(ref); g != nil {
		g.Got.Region, g.Got.Dax = state.RegionRef(region), dax
	}
	return nil
}

// alignSlice returns the dax device of a part of size bytes with memory
// on whole memory blocks of bs bytes: dax, or a new device on the first
// whole free blocks of the region, in address order, that replaces dax.
func (e *Engine) alignSlice(ctx context.Context, req *GrantRequest, memdev, region, dax string, size, bs uint64) (string, error) {
	ranges, err := e.k.DaxDeviceRanges(dax)
	if err != nil {
		return dax, err
	}
	aligned := len(ranges) > 0
	for _, r := range ranges {
		aligned = aligned && r.Aligned(bs)
	}
	if aligned {
		return dax, nil
	}
	klog.Warningf("local: memdev %s (serial %s): claim %s: slice %s at %v is not aligned to the memory block size %d, placing it explicitly",
		memdev, serialText(req.Serial), req.Ref.Claim, dax, ranges, bs)
	if err := e.locked(func() error { return e.k.DeleteDaxDevice(ctx, region, dax) }); err != nil {
		return dax, err
	}
	if err := e.commit(ctx, func(r *state.Records) error { return deletedSlice(r, req.Ref, region, dax) }); err != nil {
		return "", err
	}
	gaps, err := e.k.RegionFreeGaps(region)
	if err != nil {
		return "", err
	}
	whole := blockRanges(gaps, size, bs)
	if whole == nil {
		return "", fmt.Errorf("%w: no %d bytes of whole free memory blocks in %s (free %v, memory block size %d)", kernel.ErrNoRoom, size, region, gaps, bs)
	}
	var placed string
	if err := e.locked(func() error {
		var err error
		placed, err = e.k.CreateDaxDeviceRanges(ctx, region, whole)
		return err
	}); err != nil {
		return "", err
	}
	return placed, e.commit(ctx, func(r *state.Records) error { return sliceRecord(r, req.Ref, region, placed, false) })
}

// deletedSlice records the dax device of a part whose placement failed as
// deleted: the seed for daxN.0, else gone.
func deletedSlice(r *state.Records, ref state.GrantRef, region, dax string) error {
	reg := r.Region(state.RegionRef(region))
	d := reg.DaxDevice(dax)
	if d == nil {
		return nil
	}
	d.Users = nil
	if strings.HasSuffix(dax, ".0") {
		d.Size, d.Ranges = 0, nil
		return state.Apply(&state.DaxDeviceTable, &d.State, state.DaxSeed, state.TriggerPrepare)
	}
	if err := state.Apply(&state.DaxDeviceTable, &d.State, state.DaxAbsent, state.TriggerPrepare); err != nil {
		return err
	}
	removeRecord(&reg.DaxDevices, func(x *state.DaxDevice) bool { return x.Name == dax })
	if g := r.Grant(ref); g != nil && g.Got.Dax == dax {
		g.Got.Dax = ""
	}
	return nil
}

// blockRanges returns the parts of the ranges that are whole memory blocks
// of bs bytes, in address order, up to size bytes; nil if they have less.
func blockRanges(ranges []kernel.Range, size, bs uint64) []kernel.Range {
	var out []kernel.Range
	for _, r := range ranges {
		start, end := roundUp(r.Start, bs), (r.End+1)/bs*bs
		if start >= end || size == 0 {
			continue
		}
		n := min(end-start, size)
		out = append(out, kernel.Range{Start: start, End: start + n - 1})
		size -= n
	}
	if size > 0 {
		return nil
	}
	return out
}

// onlineSlice binds the dax device of a part of mode numa to kmem, onlines
// its memory blocks movable and returns the NUMA node of the memory. The
// node is fenced before the memory goes online when the dax device tells
// it, else right after.
func (e *Engine) onlineSlice(ctx context.Context, req *GrantRequest, memdev, region, dax string, bs uint64) (int, error) {
	start := time.Now()
	fenced := e.k.TargetNode(dax)
	e.fence(ctx, fenced)
	if err := e.locked(func() error { return e.k.BindDax(ctx, dax, kernel.DriverKmem) }); err != nil {
		return -1, err
	}
	if err := e.commit(ctx, func(r *state.Records) error {
		return bindRecord(r.Region(state.RegionRef(region)).DaxDevice(dax), kernel.DriverKmem)
	}); err != nil {
		return -1, err
	}
	if err := e.waiting(req.Serial, state.TriggerPrepare, func() error { return e.k.WaitDaxBlocks(ctx, dax) }); err != nil {
		return -1, err
	}
	blocks, err := e.k.DaxDeviceBlocks(dax, bs)
	if err != nil {
		return -1, err
	}
	if err := e.locked(func() error { return e.k.OnlineBlocks(blocks, true) }); err != nil {
		return -1, err
	}
	node := e.k.TargetNode(dax)
	if node < 0 {
		node = e.k.BlocksNode(blocks)
	}
	if node < 0 {
		return -1, fmt.Errorf("cannot find the NUMA node of %s", dax)
	}
	if e.opts.Fence != nil && node != fenced {
		klog.V(3).Infof("local: memdev %s (serial %s): claim %s: NUMA node %d of %s known only after onlining, fencing it late",
			memdev, serialText(req.Serial), req.Ref.Claim, node, dax)
		e.fence(ctx, node)
	}
	klog.Infof("local: memdev %s (serial %s): claim %s: onlined slice %s mode %s size %d blocks %v node %d in %s",
		memdev, serialText(req.Serial), req.Ref.Claim, dax, req.Asked.Mode, req.Asked.Size, blocks, node, since(start))
	return node, e.commit(ctx, func(r *state.Records) error {
		reg := r.Region(state.RegionRef(region))
		d := reg.DaxDevice(dax)
		reg.NumaNode = state.NumaNodePtr(node)
		return state.Apply(&state.DaxDeviceTable, &d.State, state.DaxKmemOnline, state.TriggerPrepare)
	})
}

// bindSlice binds the dax device of a part of mode dax to device_dax,
// zeroes it, and returns its device numbers.
func (e *Engine) bindSlice(ctx context.Context, req *GrantRequest, memdev, region, dax string, size uint64) (state.DevNumbers, error) {
	if err := e.locked(func() error { return e.k.BindDax(ctx, dax, kernel.DriverDeviceDax) }); err != nil {
		return state.DevNumbers{}, err
	}
	major, minor, err := e.k.DaxDevNumbers(dax)
	if err != nil {
		return state.DevNumbers{}, err
	}
	dev := state.DevNumbers{Major: major, Minor: minor}
	if err := e.commit(ctx, func(r *state.Records) error {
		d := r.Region(state.RegionRef(region)).DaxDevice(dax)
		d.Dev = dev
		return bindRecord(d, kernel.DriverDeviceDax)
	}); err != nil {
		return dev, err
	}
	start := time.Now()
	if err := e.waiting(req.Serial, state.TriggerPrepare, func() error { return e.k.Zero(ctx, dax) }); err != nil {
		return dev, fmt.Errorf("zeroing %s: %w", dax, err)
	}
	klog.Infof("local: memdev %s (serial %s): claim %s: zeroed slice %s mode %s size %d in %s",
		memdev, serialText(req.Serial), req.Ref.Claim, dax, req.Asked.Mode, size, since(start))
	return dev, nil
}
