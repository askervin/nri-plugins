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

package kernel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// DaxRegion and DaxDevice: the dax region of an enabled ram region
// (regionN/dax_regionN/dax_region: a dynamic dax region with the id of the
// region) and its dax devices daxN.M (/sys/bus/dax/devices).
//
// Identity: the name daxN.M; names are reused after a delete and across
// regions, so a dax device is recognized again only by its name and its
// memory. daxN.0 cannot be deleted: it is kept with size 0.
// Facts: size, the memory ranges (mappingK, 2 MiB aligned; first-fit
// placement by the kernel, or explicit through the mapping attribute),
// target_node (the NUMA node of its memory once online), the numbers of
// its character device, the memory blocks wholly in its memory.
// States (DaxState): SEED (size 0, unbound), UNBOUND (memory, no driver),
// DEVICE_DAX (a /dev/daxN.M character device), KMEM (its memory is memory
// blocks, offline or online), OTHER (another driver). Transitions:
// DaxTransitions.
// Hidden kernel state: each dax driver keeps a list of ids (new_id,
// remove_id) that sysfs does not show; a new_id makes the kernel attach the
// driver to every unbound dax device that it matches, by an id in its list
// or, kmem, by the type of the device (every dax device of a CXL ram region
// matches kmem). BindDax therefore never writes kmem's new_id, and removes
// the name of the device from the ids of a driver before every unbind and
// after every bind.
// Invariants: a bound dax device is never resized (EBUSY); kmem is never
// unbound from memory that is online (the kernel could not remove it).
// Waits: the driver link appears before the probe has finished: kmem is
// still adding the memory blocks (WaitDaxBlocks), device_dax has not added
// the character device yet (the opens of Sys retry ENXIO).

// Dax drivers.
const (
	DriverDeviceDax = "device_dax"
	DriverKmem      = "kmem"
)

// DaxState is the state of a dax device.
type DaxState int

const (
	// DaxAbsent: no dax device has the name.
	DaxAbsent DaxState = iota
	// DaxSeed: size 0, unbound.
	DaxSeed
	// DaxUnbound: memory, no driver.
	DaxUnbound
	// DaxDeviceDax: bound to device_dax.
	DaxDeviceDax
	// DaxKmem: bound to kmem.
	DaxKmem
	// DaxOther: bound to another driver.
	DaxOther
)

var daxStateNames = []string{"ABSENT", "SEED", "UNBOUND", "DEVICE_DAX", "KMEM", "OTHER"}

func (s DaxState) String() string { return stateText(daxStateNames, int(s)) }

// MarshalText returns the name of the state.
func (s DaxState) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText sets the state of its name.
func (s *DaxState) UnmarshalText(text []byte) error {
	v, err := parseState(daxStateNames, text)
	*s = DaxState(v)
	return err
}

// DaxTransitions are the changes of the state of a dax device.
var DaxTransitions = Table[DaxState]{
	{From: DaxAbsent, To: DaxKmem, Trigger: "CreateRegion (ram) or EnableRegion: the kernel binds daxN.0 over the whole region to kmem",
		Effect: "its memory blocks added, offline"},
	{From: DaxAbsent, To: DaxSeed, Trigger: "CreateDaxDevice (dax_region/create)", Guard: "room in the dax region"},
	{From: DaxSeed, To: DaxUnbound, Trigger: "CreateDaxDevice, ResizeDaxDevice (size or mapping)",
		Guard: "room in the dax region; a mapping of free memory"},
	{From: DaxUnbound, To: DaxSeed, Trigger: "ResizeDaxDevice to 0, DeleteDaxDevice of daxN.0"},
	{From: DaxUnbound, To: DaxUnbound, Trigger: "ResizeDaxDevice", Guard: "unbound"},
	{From: DaxUnbound, To: DaxDeviceDax, Trigger: "BindDax(device_dax): new_id and bind, remove_id after",
		Effect: "the character device appears asynchronously"},
	{From: DaxUnbound, To: DaxKmem, Trigger: "BindDax(kmem): bind, remove_id after",
		Effect: "its memory blocks are added asynchronously"},
	{From: DaxUnbound, To: DaxDeviceDax, Trigger: "a new_id of its name left in device_dax by another tool (driver_attach)"},
	{From: DaxUnbound, To: DaxOther, Trigger: "another driver bound by someone else"},
	{From: DaxDeviceDax, To: DaxUnbound, Trigger: "UnbindDax (remove_id, unbind), ResizeDaxDevice"},
	{From: DaxKmem, To: DaxUnbound, Trigger: "UnbindDax, ResizeDaxDevice", Guard: "every memory block offline",
		Effect: "its memory blocks removed"},
	{From: DaxOther, To: DaxUnbound, Trigger: "UnbindDax, ResizeDaxDevice"},
	{From: DaxSeed, To: DaxAbsent, Trigger: "DeleteDaxDevice", Guard: "not daxN.0"},
	{From: DaxSeed, To: DaxAbsent, Trigger: "DisableRegion, DestroyRegion, hot-remove of its memdev"},
	{From: DaxUnbound, To: DaxAbsent, Trigger: "DeleteDaxDevice, DisableRegion, DestroyRegion, hot-remove of its memdev",
		Guard: "DeleteDaxDevice: not daxN.0"},
	{From: DaxDeviceDax, To: DaxAbsent, Trigger: "DeleteDaxDevice, DisableRegion, DestroyRegion, hot-remove of its memdev",
		Guard: "DeleteDaxDevice: not daxN.0", Effect: "a holder of the character device gets SIGBUS"},
	{From: DaxKmem, To: DaxAbsent, Trigger: "DeleteDaxDevice, DisableRegion, DestroyRegion, hot-remove of its memdev",
		Guard:  "DeleteDaxDevice: not daxN.0, every memory block offline",
		Effect: "memory blocks that are offline go; online ones stay online until a reboot"},
	{From: DaxOther, To: DaxAbsent, Trigger: "DeleteDaxDevice, DisableRegion, DestroyRegion, hot-remove of its memdev",
		Guard: "DeleteDaxDevice: not daxN.0"},
	// changes that one call makes between two observations
	{From: DaxAbsent, To: DaxUnbound, Trigger: "CreateDaxDevice, CreateDaxDeviceRanges, observed across them"},
	{From: DaxAbsent, To: DaxDeviceDax, Trigger: "CreateRegion (ram) when device_dax has the name of daxN.0 as an id (left by another tool); the creation of a dax region and the switch of daxN.0 to device_dax, observed across them"},
	{From: DaxKmem, To: DaxSeed, Trigger: "ResizeDaxDevice to 0, DeleteDaxDevice of daxN.0", Guard: "every memory block offline"},
	{From: DaxDeviceDax, To: DaxSeed, Trigger: "ResizeDaxDevice to 0, DeleteDaxDevice of daxN.0"},
	{From: DaxOther, To: DaxSeed, Trigger: "ResizeDaxDevice to 0, DeleteDaxDevice of daxN.0"},
	{From: DaxKmem, To: DaxDeviceDax, Trigger: "BindDax(device_dax)", Guard: "every memory block offline"},
	{From: DaxDeviceDax, To: DaxKmem, Trigger: "BindDax(kmem)"},
	{From: DaxOther, To: DaxDeviceDax, Trigger: "BindDax(device_dax)"},
	{From: DaxOther, To: DaxKmem, Trigger: "BindDax(kmem)"},
}

// DaxRegion is the observation of the dax region of a region.
type DaxRegion struct {
	// Name is dax_regionN.
	Name string `json:"name"`
	// Region is the CXL region of the dax region.
	Region string `json:"region"`
	// Available is the memory that no dax device has, in bytes.
	Available uint64 `json:"available"`
	// Align is the alignment of the memory of its dax devices.
	Align uint64 `json:"align"`
	// Devices are its dax devices in natural order.
	Devices []string `json:"devices,omitempty"`
}

// DaxDeviceInfo is the observation of a dax device.
type DaxDeviceInfo struct {
	Name   string   `json:"name"`
	Region string   `json:"region"`
	State  DaxState `json:"state"`
	// Driver is the bound driver, "" for none.
	Driver string `json:"driver,omitempty"`
	Size   uint64 `json:"size"`
	// Ranges are its memory in address order.
	Ranges []Range `json:"ranges,omitempty"`
	// Major and Minor are the numbers of its character device.
	Major int `json:"major,omitempty"`
	Minor int `json:"minor,omitempty"`
	// TargetNode is the NUMA node of its memory, -1 if not known.
	TargetNode int `json:"targetNode"`
	// Blocks are the memory blocks wholly in its memory that exist, of
	// WholeBlocks such blocks.
	Blocks      []int `json:"blocks,omitempty"`
	WholeBlocks int   `json:"wholeBlocks,omitempty"`
}

// daxState returns the state of a dax device with its driver and size.
func daxState(driver string, size uint64) DaxState {
	switch {
	case driver == DriverDeviceDax:
		return DaxDeviceDax
	case driver == DriverKmem:
		return DaxKmem
	case driver != "":
		return DaxOther
	case size == 0:
		return DaxSeed
	}
	return DaxUnbound
}

// daxRegionDir returns the sysfs directory of the dax region attributes of
// a region (regionN/dax_regionN/dax_region).
func (k *Kernel) daxRegionDir(region string) string {
	if m, _ := filepath.Glob(k.cxlDev(region, "dax_region*", "dax_region")); len(m) > 0 {
		return m[0]
	}
	return k.cxlDev(region, "dax_"+region, "dax_region")
}

// DaxRegion returns the observation of the dax region of a region.
func (k *Kernel) DaxRegion(region string) (DaxRegion, error) {
	dir := k.daxRegionDir(region)
	d := DaxRegion{Name: filepath.Base(filepath.Dir(dir)), Region: region}
	var err error
	if d.Available, err = ReadUint(filepath.Join(dir, "available_size")); err != nil {
		return d, err
	}
	if d.Align, err = ReadUint(filepath.Join(dir, "align")); err != nil {
		return d, err
	}
	d.Devices = k.DaxDevices(region)
	return d, nil
}

// DaxDevices returns the dax devices of a region in natural order.
func (k *Kernel) DaxDevices(region string) []string {
	m, _ := filepath.Glob(k.cxlDev(region, "dax_region*", "dax*.*"))
	out := make([]string, 0, len(m))
	for _, p := range m {
		out = append(out, filepath.Base(p))
	}
	sortNat(out)
	return out
}

// DaxDevice returns the observation of a dax device, an error of kind
// ErrNotFound if it does not exist.
func (k *Kernel) DaxDevice(dax string) (DaxDeviceInfo, error) {
	d := DaxDeviceInfo{Name: dax, TargetNode: -1}
	real, err := filepath.EvalSymlinks(k.daxDev(dax))
	if err != nil {
		return d, errorf(ErrNotFound, "%s: %w", dax, err)
	}
	// .../regionN/dax_regionN/daxN.M
	d.Region = filepath.Base(filepath.Dir(filepath.Dir(real)))
	d.Driver = k.DaxDriver(dax)
	d.Size, _ = k.DaxDeviceSize(dax)
	d.State = daxState(d.Driver, d.Size)
	d.Ranges, _ = k.DaxDeviceRanges(dax)
	d.Major, d.Minor, _ = k.DaxDevNumbers(dax)
	d.TargetNode = k.TargetNode(dax)
	if bs, err := k.BlockSize(); err == nil {
		d.Blocks, d.WholeBlocks, _ = k.daxBlocks(dax, bs)
	}
	return d, nil
}

// DaxDriver returns the driver of a dax device, "" if none.
func (k *Kernel) DaxDriver(dax string) string {
	return driverOf(k.daxDev(dax))
}

// TargetNode returns the NUMA node of the memory of a dax device, -1 if
// not known.
func (k *Kernel) TargetNode(dax string) int {
	return readInt(k.daxDev(dax, "target_node"), -1)
}

// DaxDevNumbers returns the major and minor numbers of the character device
// of a dax device (/sys/bus/dax/devices/<dax>/dev, "major:minor").
func (k *Kernel) DaxDevNumbers(dax string) (major, minor int, err error) {
	v, err := ReadTrim(k.daxDev(dax, "dev"))
	if err != nil {
		return 0, 0, err
	}
	return parseDevNumbers(dax, v)
}

// DaxRegionInfo returns the free bytes and the allocation alignment of the
// dax region of a region, and the dax devices of the region.
func (k *Kernel) DaxRegionInfo(region string) (available, align uint64, devices []string, err error) {
	d, err := k.DaxRegion(region)
	if err != nil {
		return 0, 0, nil, err
	}
	return d.Available, d.Align, d.Devices, nil
}

// DaxDeviceSize returns the size of a dax device in bytes.
func (k *Kernel) DaxDeviceSize(dax string) (uint64, error) {
	return ReadUint(k.daxDev(dax, "size"))
}

// DaxDeviceRanges returns the physical address ranges of the memory of a
// dax device (its mappingN), in address order. Without mappings (kernels
// before 5.10) the device has one range from its resource and size. A
// device of size 0 has none.
func (k *Kernel) DaxDeviceRanges(dax string) ([]Range, error) {
	dirs, _ := filepath.Glob(k.daxDev(dax, "mapping[0-9]*"))
	if len(dirs) == 0 {
		size, err := k.DaxDeviceSize(dax)
		if err != nil || size == 0 {
			return nil, err
		}
		start, err := ReadUint(k.daxDev(dax, "resource"))
		if err != nil {
			return nil, err
		}
		return []Range{{Start: start, End: start + size - 1}}, nil
	}
	out := make([]Range, 0, len(dirs))
	for _, dir := range dirs {
		start, err := ReadUint(filepath.Join(dir, "start"))
		if err != nil {
			return nil, err
		}
		end, err := ReadUint(filepath.Join(dir, "end"))
		if err != nil {
			return nil, err
		}
		out = append(out, Range{Start: start, End: end})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, nil
}

// DaxDeviceBlocks returns the numbers of the memory blocks of a dax device
// that exist: the blocks of bs bytes that lie wholly in its memory, which
// kmem adds.
func (k *Kernel) DaxDeviceBlocks(dax string, bs uint64) ([]int, error) {
	blocks, _, err := k.daxBlocks(dax, bs)
	return blocks, err
}

// daxBlocks returns the numbers of the memory blocks of a dax device that
// exist, and how many blocks lie wholly in its memory.
func (k *Kernel) daxBlocks(dax string, bs uint64) ([]int, int, error) {
	if bs == 0 {
		return nil, 0, errors.New("memory block size 0")
	}
	ranges, err := k.DaxDeviceRanges(dax)
	if err != nil {
		return nil, 0, err
	}
	var out []int
	want := 0
	for _, r := range ranges {
		for _, b := range r.blocks(bs) {
			want++
			if k.blockExists(b) {
				out = append(out, b)
			}
		}
	}
	return out, want, nil
}

// WaitDaxBlocks waits until every memory block of a dax device that is
// bound to kmem exists.
func (k *Kernel) WaitDaxBlocks(ctx context.Context, dax string) error {
	bs, err := k.BlockSize()
	if err != nil {
		return err
	}
	var blocks []int
	var want int
	err = k.poll(ctx, func() (bool, error) {
		var err error
		if blocks, want, err = k.daxBlocks(dax, bs); err != nil {
			return false, err
		}
		if want == 0 {
			return false, fmt.Errorf("%s has no whole memory block of %d bytes", dax, bs)
		}
		return len(blocks) == want, nil
	})
	if err != nil && ctx.Err() != nil {
		return fmt.Errorf("%s: %d of %d memory blocks appeared: %w", dax, len(blocks), want, err)
	}
	return err
}

// WaitDaxRegion waits until the first dax device of a region exists and is
// bound to a driver (the kernel makes it asynchronously after the region is
// created or enabled), and returns its name.
func (k *Kernel) WaitDaxRegion(ctx context.Context, region string) (string, error) {
	var dax string
	err := k.poll(ctx, func() (bool, error) {
		if ds := k.DaxDevices(region); len(ds) > 0 && k.DaxDriver(ds[0]) != "" {
			dax = ds[0]
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return "", fmt.Errorf("no dax device bound to a driver appeared in %s: %w", region, err)
	}
	return dax, nil
}

// RegionFreeGaps returns the ranges of the memory of a region that none of
// its dax devices has, in address order.
func (k *Kernel) RegionFreeGaps(region string) ([]Range, error) {
	rr, err := k.RegionRange(region)
	if err != nil {
		return nil, err
	}
	var used []Range
	for _, dax := range k.DaxDevices(region) {
		ranges, err := k.DaxDeviceRanges(dax)
		if err != nil {
			return nil, err
		}
		used = append(used, ranges...)
	}
	sort.Slice(used, func(i, j int) bool { return used[i].Start < used[j].Start })
	var gaps []Range
	next := rr.Start
	for _, u := range used {
		if u.Start > next {
			gaps = append(gaps, Range{Start: next, End: u.Start - 1})
		}
		if u.End >= next {
			next = u.End + 1
		}
	}
	if next <= rr.End {
		gaps = append(gaps, Range{Start: next, End: rr.End})
	}
	return gaps, nil
}

// noRoom returns err with the kind ErrNoRoom when its cause says that the
// dax region has no room (ENOSPC, ENOMEM), else err.
func noRoom(err error) error {
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.ENOMEM) {
		return &kernelError{kind: ErrNoRoom, msg: err.Error(), err: errors.Unwrap(err)}
	}
	return err
}

// UnbindDax unbinds a dax device from its driver. A device that kmem has
// with memory blocks that are not offline is not unbound (ErrBusyOnline):
// the kernel could not remove that memory, it would stay online until a
// reboot.
//
// The name of the device is removed from the ids of the driver first, as
// daxctl does before it unbinds: a new_id of a dax driver, for any device,
// makes the kernel attach the driver to every unbound dax device that it
// matches, and an id that is left matches this device. It would be bound
// again while it is unbound for a resize, whose write of size then fails
// with EBUSY.
func (k *Kernel) UnbindDax(ctx context.Context, dax string) error {
	cur := k.DaxDriver(dax)
	if cur == "" {
		return nil
	}
	if cur == DriverKmem {
		if err := k.checkOffline(dax); err != nil {
			return err
		}
	}
	k.removeDaxID(cur, dax)
	if err := k.writeFile(k.daxDriver(cur, "unbind"), dax); err != nil {
		return fmt.Errorf("unbind %s from %s: %w", dax, cur, err)
	}
	if got := k.DaxDriver(dax); got != "" {
		return fmt.Errorf("%s is still bound to %q", dax, got)
	}
	k.logf("%s: unbound from %s", dax, cur)
	return nil
}

// RemoveDaxID removes the name of a dax device from the ids of a dax driver
// (remove_id; the kernel ignores a name that is not an id). A failure is
// logged only: the device is bound or unbound as asked anyway.
func (k *Kernel) RemoveDaxID(driver, dax string) {
	k.removeDaxID(driver, dax)
}

func (k *Kernel) removeDaxID(driver, dax string) {
	if err := k.writeFile(k.daxDriver(driver, "remove_id"), dax); err != nil {
		k.logf("%s: remove_id %s: %v", driver, dax, err)
	}
}

// checkOffline returns an error of kind ErrBusyOnline that lists the memory
// blocks of a dax device that are not offline, nil if there are none.
func (k *Kernel) checkOffline(dax string) error {
	bs, err := k.BlockSize()
	if err != nil {
		return fmt.Errorf("%s: %w", dax, err)
	}
	blocks, err := k.DaxDeviceBlocks(dax, bs)
	if err != nil {
		return err
	}
	if online := k.onlineBlocks(blocks); len(online) > 0 {
		return errorf(ErrBusyOnline, "%s: memory blocks %v are not offline, kmem keeps it", dax, online)
	}
	return nil
}

// ResizeDaxDevice unbinds a dax device from its driver and sets its size in
// bytes, a multiple of the align of its dax region. The device is left
// unbound.
func (k *Kernel) ResizeDaxDevice(ctx context.Context, dax string, size uint64) error {
	if err := k.UnbindDax(ctx, dax); err != nil {
		return err
	}
	if err := k.writeFile(k.daxDev(dax, "size"), strconv.FormatUint(size, 10)); err != nil {
		return noRoom(fmt.Errorf("%s: set size %d: %w", dax, size, err))
	}
	got, err := k.DaxDeviceSize(dax)
	if err != nil {
		return err
	}
	if got != size {
		return fmt.Errorf("%s: size is %d after setting %d", dax, got, size)
	}
	k.logf("%s: size %d", dax, size)
	return nil
}

// CreateDaxDevice creates a dax device of size bytes in the dax region of a
// region and returns its name; the kernel places its memory first-fit. The
// device is not bound to a driver. On a failure the new device is deleted
// again; no room is an error of kind ErrNoRoom.
func (k *Kernel) CreateDaxDevice(ctx context.Context, region string, size uint64) (string, error) {
	dax, err := k.newDaxDevice(region)
	if err != nil {
		return "", err
	}
	if err := k.ResizeDaxDevice(ctx, dax, size); err != nil {
		if derr := k.DeleteDaxDevice(ctx, region, dax); derr != nil {
			k.logf("%s: %v", region, derr)
		}
		return "", err
	}
	return dax, nil
}

// CreateDaxDeviceRanges creates a dax device in the dax region of a region
// with the memory of the ranges, and returns its name. The device is not
// bound to a driver. When the dax region does not give the device exactly
// that memory (memory that is taken: ErrNoRoom; a length that is not a
// multiple of the align of the region, which the kernel ignores without an
// error), the device is deleted and an error returned.
func (k *Kernel) CreateDaxDeviceRanges(ctx context.Context, region string, ranges []Range) (string, error) {
	if len(ranges) == 0 {
		return "", fmt.Errorf("%s: a dax device without memory", region)
	}
	want := slices.Clone(ranges)
	sort.Slice(want, func(i, j int) bool { return want[i].Start < want[j].Start })
	dax, err := k.newDaxDevice(region)
	if err != nil {
		return "", err
	}
	for _, r := range ranges {
		if err = k.writeFile(k.daxDev(dax, "mapping"), r.String()); err != nil {
			err = noRoom(fmt.Errorf("%s: map %s: %w", dax, r, err))
			break
		}
	}
	if err == nil {
		var got []Range
		got, err = k.DaxDeviceRanges(dax)
		if err == nil && !slices.Equal(got, want) {
			err = fmt.Errorf("%s: memory %v after mapping %v", dax, got, want)
		}
	}
	if err != nil {
		if derr := k.DeleteDaxDevice(ctx, region, dax); derr != nil {
			k.logf("%s: %v", region, derr)
		}
		return "", err
	}
	k.logf("%s: mapped %v", dax, want)
	return dax, nil
}

// newDaxDevice creates a dax device of size 0 in the dax region of a region
// and returns its name.
func (k *Kernel) newDaxDevice(region string) (string, error) {
	dir := k.daxRegionDir(region)
	if err := k.writeFile(filepath.Join(dir, "create"), "1"); err != nil {
		return "", noRoom(fmt.Errorf("%s: create a dax device: %w", region, err))
	}
	// reading create returns the youngest device of the dax region
	dax, err := ReadTrim(filepath.Join(dir, "create"))
	if err != nil {
		return "", err
	}
	if dax == "" {
		return "", fmt.Errorf("%s: no dax device was created", region)
	}
	k.logf("%s: created %s", region, dax)
	return dax, nil
}

// DeleteDaxDevice unbinds a dax device, sets its size to 0 and deletes it
// from the dax region of a region. The first dax device of a region
// (daxN.0) is kept with size 0. A device that does not exist is not an
// error.
func (k *Kernel) DeleteDaxDevice(ctx context.Context, region, dax string) error {
	if _, err := os.Lstat(k.daxDev(dax)); os.IsNotExist(err) {
		return nil
	}
	if err := k.ResizeDaxDevice(ctx, dax, 0); err != nil {
		return err
	}
	if strings.HasSuffix(dax, ".0") {
		return nil
	}
	if err := k.writeFile(filepath.Join(k.daxRegionDir(region), "delete"), dax); err != nil {
		return fmt.Errorf("%s: delete %s: %w", region, dax, err)
	}
	k.logf("%s: deleted %s", region, dax)
	return nil
}

// BindDax binds a dax device to device_dax or kmem through the sysfs
// attributes of the dax bus, after unbinding it from another driver (see
// UnbindDax). kmem matches the dax devices of CXL regions by their type, so
// it is bound with bind only: a new_id would make kmem probe every unbound
// dax device of the regions. device_dax does not match them by type: its
// new_id makes it match and probe the device, bind is a fallback if the id
// was there already. The id is removed again afterwards, also after a failed
// bind, so that a later device with the same name binds to its default
// driver and the driver does not take this device whenever it is unbound;
// kmem's too, which no one should have written. The memory blocks that kmem
// adds are offline unless auto_online_blocks or a udev rule onlines them.
func (k *Kernel) BindDax(ctx context.Context, dax, driver string) error {
	if k.DaxDriver(dax) == driver {
		return nil
	}
	if err := k.UnbindDax(ctx, dax); err != nil {
		return err
	}
	defer k.removeDaxID(driver, dax)
	if driver != DriverKmem {
		if err := k.writeFile(k.daxDriver(driver, "new_id"), dax); err != nil {
			k.logf("%s: new_id: %v", driver, err)
		}
	}
	if k.DaxDriver(dax) != driver {
		if err := k.writeFile(k.daxDriver(driver, "bind"), dax); err != nil {
			return fmt.Errorf("bind %s to %s: %w", dax, driver, err)
		}
	}
	return k.checkDaxDriver(dax, driver)
}

// checkDaxDriver returns an error if a dax device is not bound to driver,
// and logs the binding otherwise.
func (k *Kernel) checkDaxDriver(dax, driver string) error {
	if got := k.DaxDriver(dax); got != driver {
		return fmt.Errorf("%s is bound to %q, not %q", dax, got, driver)
	}
	k.logf("%s: bound to %s", dax, driver)
	return nil
}
