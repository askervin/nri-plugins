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

// Package memctl makes hotplugged CXL memory devices usable and releases
// them again: find a memdev by serial, create a region in mode numa (system
// RAM of a NUMA node) or dax (a dax character device), online or offline
// its memory, slice the dax region of a region into dax devices, create a
// region of persistent memory and an fsdax namespace in it, destroy the
// region and disable the memdev. It drives sysfs and the cxl, daxctl and
// ndctl CLIs through package kernel, which has the implementation of every
// step; memctl composes them into these flows for its callers, and binds
// dax devices with daxctl when it is installed (package kernel never runs
// it).
package memctl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// Region modes: how the memory of a region is used.
const (
	// ModeNUMA is memory onlined as system RAM of a NUMA node (kmem).
	ModeNUMA = api.ModeNUMA
	// ModeDax is memory used through a dax character device (device_dax).
	ModeDax = api.ModeDax
)

// ValidMode returns an error if mode is not ModeNUMA or ModeDax.
func ValidMode(mode string) error {
	if mode != ModeNUMA && mode != ModeDax {
		return fmt.Errorf("invalid mode %q (numa or dax)", mode)
	}
	return nil
}

// Dax drivers.
const (
	DriverDeviceDax = kernel.DriverDeviceDax
	DriverKmem      = kernel.DriverKmem
)

// ErrNotFound is returned when no memdev has the serial.
var ErrNotFound = errors.New("no CXL memory device with the serial")

// Manager accesses the CXL devices of the machine it runs on.
type Manager struct {
	// SysRoot is the sysfs mount point ("/sys").
	SysRoot string
	// DevRoot is the device directory ("/dev").
	DevRoot string
	// Exec runs a command and returns its combined output.
	Exec func(ctx context.Context, name string, args ...string) (string, error)
	// LookPath finds an executable.
	LookPath func(name string) (string, error)
	// Logf logs what is done ("" output if nil).
	Logf func(format string, args ...any)
	// WriteFile writes a value to a sysfs attribute (os.WriteFile if
	// nil).
	WriteFile func(path, val string) error
	// PollInterval for waits.
	PollInterval time.Duration
}

// New returns a Manager for the running system.
func New() *Manager {
	return &Manager{
		SysRoot:      "/sys",
		DevRoot:      "/dev",
		Exec:         kernel.RunCommand,
		LookPath:     exec.LookPath,
		PollInterval: 200 * time.Millisecond,
	}
}

// regionCreateMu serializes the region creations of the process (the pool
// driver and the local allocator, each with a Manager of its own) with
// DeleteHollowRegion, so that the name of the next region read before a
// creation is the one it gets (from this process), and a hollow region is
// never one that this process is setting up; and the last check of
// ReleaseRegionInOrder with its cxl destroy-region.
var regionCreateMu sync.Mutex

// serializeCreations runs fn holding regionCreateMu.
func serializeCreations(fn func() error) error {
	regionCreateMu.Lock()
	defer regionCreateMu.Unlock()
	return fn()
}

// kernel returns the kernel.Kernel of the Manager.
func (mc *Manager) kernel() *kernel.Kernel {
	return &kernel.Kernel{
		SysRoot:      mc.SysRoot,
		DevRoot:      mc.DevRoot,
		Exec:         mc.Exec,
		WriteFile:    mc.WriteFile,
		Sys:          &kernel.SysCalls{DevRoot: mc.DevRoot, Logf: mc.Logf},
		Logf:         mc.Logf,
		PollInterval: mc.PollInterval,
		Serialize:    serializeCreations,
	}
}

func (mc *Manager) logf(format string, args ...any) {
	if mc.Logf != nil {
		mc.Logf(format, args...)
	}
}

func (mc *Manager) cxlDev(p ...string) string {
	return filepath.Join(append([]string{mc.SysRoot, "bus", "cxl", "devices"}, p...)...)
}

// Memdev is a CXL memory device of the machine.
type Memdev struct {
	Name   string
	Serial uint64
}

// Memdevs lists the CXL memory devices.
func (mc *Manager) Memdevs() []Memdev {
	var out []Memdev
	for _, m := range mc.kernel().Memdevs() {
		out = append(out, Memdev{Name: m.Name, Serial: m.Serial})
	}
	return out
}

// FindMemdev returns the memN name of the device with the serial.
func (mc *Manager) FindMemdev(serial uint64) (string, error) {
	name, err := mc.kernel().FindMemdev(serial)
	if err != nil {
		return "", fmt.Errorf("%w 0x%x", ErrNotFound, serial)
	}
	return name, nil
}

// WaitMemdev waits until a device with the serial appears and its driver
// is bound.
func (mc *Manager) WaitMemdev(ctx context.Context, serial uint64) (string, error) {
	return mc.kernel().WaitMemdev(ctx, serial, kernel.MemdevBound)
}

// Regions returns the regions that have a target decoder of the memdev.
func (mc *Manager) Regions(memdev string) []string {
	return mc.kernel().Regions(memdev)
}

// RamSize returns the RAM capacity of a memdev in bytes.
func (mc *Manager) RamSize(memdev string) (uint64, error) {
	return mc.kernel().RamSize(memdev)
}

// DaxDevices returns the dax devices of a region, in lexical order.
func (mc *Manager) DaxDevices(region string) []string {
	out := mc.kernel().DaxDevices(region)
	sort.Strings(out)
	return out
}

// DaxDriver returns the driver of a dax device ("" if none).
func (mc *Manager) DaxDriver(dax string) string {
	return mc.kernel().DaxDriver(dax)
}

// TargetNode returns the NUMA node of the memory of a dax device.
func (mc *Manager) TargetNode(dax string) int {
	return mc.kernel().TargetNode(dax)
}

// DaxDevNumbers returns the major and minor numbers of the character
// device of a dax device (/sys/bus/dax/devices/<dax>/dev, "major:minor").
func (mc *Manager) DaxDevNumbers(dax string) (major, minor int, err error) {
	return mc.kernel().DaxDevNumbers(dax)
}

// DaxRegionInfo returns the free bytes and the allocation alignment of the
// dax region of a region, and the dax devices of the region.
func (mc *Manager) DaxRegionInfo(region string) (available, align uint64, devices []string, err error) {
	available, align, _, err = mc.kernel().DaxRegionInfo(region)
	if err != nil {
		return 0, 0, nil, err
	}
	return available, align, mc.DaxDevices(region), nil
}

// DaxDeviceSize returns the size of a dax device in bytes.
func (mc *Manager) DaxDeviceSize(dax string) (uint64, error) {
	return mc.kernel().DaxDeviceSize(dax)
}

// UnbindDax unbinds a dax device from its driver, after removing its name
// from the ids of the driver. A device that kmem has with memory blocks
// that are not offline is not unbound: the kernel could not remove that
// memory, it would stay online until a reboot (see kernel.UnbindDax).
func (mc *Manager) UnbindDax(ctx context.Context, dax string) error {
	return mc.kernel().UnbindDax(ctx, dax)
}

// ResizeDaxDevice unbinds a dax device from its driver and sets its size
// in bytes, a multiple of the align of its dax region. The device is left
// unbound.
func (mc *Manager) ResizeDaxDevice(ctx context.Context, dax string, size uint64) error {
	return mc.kernel().ResizeDaxDevice(ctx, dax, size)
}

// CreateDaxDevice creates a dax device of size bytes in the dax region of
// a region and returns its name. The device is not bound to a driver.
func (mc *Manager) CreateDaxDevice(ctx context.Context, region string, size uint64) (string, error) {
	return mc.kernel().CreateDaxDevice(ctx, region, size)
}

// CreateDaxDeviceRanges creates a dax device in the dax region of a region
// with the memory of the ranges, and returns its name. The device is not
// bound to a driver. When the dax region does not give the device exactly
// that memory, the device is deleted and an error returned.
func (mc *Manager) CreateDaxDeviceRanges(ctx context.Context, region string, ranges []Range) (string, error) {
	return mc.kernel().CreateDaxDeviceRanges(ctx, region, ranges)
}

// DeleteDaxDevice unbinds a dax device, sets its size to 0 and deletes it
// from the dax region of a region. The first dax device of a region
// (daxN.0) is kept with size 0. A device that does not exist is not an
// error.
func (mc *Manager) DeleteDaxDevice(ctx context.Context, region, dax string) error {
	return mc.kernel().DeleteDaxDevice(ctx, region, dax)
}

// Range is a range of physical addresses from Start to End, both
// included, as the kernel shows them.
type Range = kernel.Range

// MemoryBlockSize returns the size of the memory blocks of the system in
// bytes (devices/system/memory/block_size_bytes, hex without 0x).
func (mc *Manager) MemoryBlockSize() (uint64, error) {
	return mc.kernel().BlockSize()
}

// RegionRange returns the physical address range of a region.
func (mc *Manager) RegionRange(region string) (Range, error) {
	return mc.kernel().RegionRange(region)
}

// RegionBlocks returns the memory block numbers of a region.
func (mc *Manager) RegionBlocks(region string) ([]int, error) {
	return mc.kernel().RegionBlocks(region)
}

// DaxDeviceRanges returns the physical address ranges of the memory of a
// dax device (its mappingN), in address order. Without mappings (kernels
// before 5.10) the device has one range from its resource and size. A
// device of size 0 has none.
func (mc *Manager) DaxDeviceRanges(dax string) ([]Range, error) {
	return mc.kernel().DaxDeviceRanges(dax)
}

// DaxDeviceBlocks returns the numbers of the memory blocks of a dax device
// that exist: the blocks of bs bytes that lie wholly in its memory, which
// kmem adds.
func (mc *Manager) DaxDeviceBlocks(dax string, bs uint64) ([]int, error) {
	return mc.kernel().DaxDeviceBlocks(dax, bs)
}

// WaitDaxBlocks waits until every memory block of a dax device that is
// bound to kmem exists.
func (mc *Manager) WaitDaxBlocks(ctx context.Context, dax string) error {
	return mc.kernel().WaitDaxBlocks(ctx, dax)
}

// RegionFreeGaps returns the ranges of the memory of a region that none of
// its dax devices has, in address order.
func (mc *Manager) RegionFreeGaps(region string) ([]Range, error) {
	return mc.kernel().RegionFreeGaps(region)
}

// BlocksNode returns the NUMA node of online memory blocks
// (/sys/devices/system/memory/memoryN/nodeM), -1 if not found.
func (mc *Manager) BlocksNode(blocks []int) int {
	return mc.kernel().BlocksNode(blocks)
}

// SetBlocksState onlines ("online", "online_movable") or offlines
// ("offline") memory blocks, skipping blocks that are already there.
func (mc *Manager) SetBlocksState(blocks []int, state string) error {
	return mc.kernel().SetBlocksState(blocks, state)
}

func (mc *Manager) has(cmd string) bool {
	if mc.LookPath == nil {
		return false
	}
	_, err := mc.LookPath(cmd)
	return err == nil
}

// SetDaxDriver binds a dax device to device_dax or kmem, with daxctl
// reconfigure-device when it is installed, else through sysfs (see
// SetDaxDriverSysfs). Memory of kmem must be offline before switching
// away. daxctl binds with new_id and leaves the id in the driver; it is
// removed afterwards, as SetDaxDriverSysfs does: else the driver takes the
// device again whenever it is unbound and someone writes a new_id, and a
// later device of that name binds to it instead of its default driver.
func (mc *Manager) SetDaxDriver(ctx context.Context, dax, driver string) error {
	k := mc.kernel()
	if k.DaxDriver(dax) == driver {
		return nil
	}
	if !mc.has("daxctl") {
		return k.BindDax(ctx, dax, driver)
	}
	// the daxctl modes of device_dax and kmem
	args := []string{"reconfigure-device", "--mode=devdax", "--force", dax}
	if driver == DriverKmem {
		args = []string{"reconfigure-device", "--mode=system-ram", "--no-online", dax}
	}
	_, err := mc.Exec(ctx, "daxctl", args...)
	k.RemoveDaxID(driver, dax)
	if err != nil {
		return err
	}
	if got := k.DaxDriver(dax); got != driver {
		return fmt.Errorf("%s is bound to %q, not %q", dax, got, driver)
	}
	mc.logf("%s: bound to %s", dax, driver)
	return nil
}

// SetDaxDriverSysfs binds a dax device to device_dax or kmem through the
// sysfs attributes of the dax bus (kernel.BindDax). The memory blocks that
// kmem adds are offline unless auto_online_blocks onlines them.
func (mc *Manager) SetDaxDriverSysfs(ctx context.Context, dax, driver string) error {
	return mc.kernel().BindDax(ctx, dax, driver)
}

// RegionInfo describes a region of a memdev. Mode is ModeNUMA (kmem),
// ModeDax (device_dax) or "" (no or another driver).
type RegionInfo struct {
	Memdev string `json:"memdev"`
	Region string `json:"region"`
	Dax    string `json:"dax"`
	Driver string `json:"driver"`
	Mode   string `json:"mode"`
	Node   int    `json:"node"`
	Device string `json:"device,omitempty"` // /dev/daxX.Y in mode dax
	Blocks []int  `json:"blocks,omitempty"`
}

// Info returns the region info of a memdev (the first region).
func (mc *Manager) Info(memdev string) (*RegionInfo, error) {
	regions := mc.Regions(memdev)
	if len(regions) == 0 {
		return nil, fmt.Errorf("%s has no region", memdev)
	}
	ri := &RegionInfo{Memdev: memdev, Region: regions[0], Node: -1}
	if daxes := mc.DaxDevices(ri.Region); len(daxes) > 0 {
		ri.Dax = daxes[0]
		ri.Driver = mc.DaxDriver(ri.Dax)
		ri.Node = mc.TargetNode(ri.Dax)
	}
	switch ri.Driver {
	case DriverDeviceDax:
		ri.Mode = ModeDax
		ri.Device = filepath.Join(mc.DevRoot, ri.Dax)
	case DriverKmem:
		ri.Mode = ModeNUMA
	}
	ri.Blocks, _ = mc.RegionBlocks(ri.Region)
	return ri, nil
}

// settleOffline is how long the memory blocks of a new region must
// stay offline before its dax device is switched to device_dax.
var settleOffline = 500 * time.Millisecond

// RegionNote is told the region that a cxl create-region creates under a
// root decoder: before it runs (created false), the name of the next
// region of the decoder (its create_ram_region or create_pmem_region, ""
// if it cannot be read), and after it succeeded (created true), the name
// of the region it created. A caller records the name to find a region
// that a create-region which did not finish (the process killed) leaves
// hollow. An error of the first call is returned and no region is
// created; an error of the second call is logged.
type RegionNote func(region, decoder string, created bool) error

// createRegion runs cxl create-region for a region of the type (RegionRAM
// or RegionPmem) of size bytes (0: all of the capacity) on the memdev
// under the decoder, telling note (nil: none), and returns the region.
func (mc *Manager) createRegion(ctx context.Context, memdev, decoder, regionType string, size uint64, note RegionNote) (string, error) {
	req := kernel.CreateRegionRequest{Memdev: memdev, Decoder: decoder, Type: regionType, Size: size}
	if note != nil {
		req.Note = func(next string) error { return note(next, decoder, false) }
	}
	region, err := mc.kernel().CreateRegion(ctx, req)
	if err != nil {
		return "", err
	}
	if note != nil {
		if err := note(region, decoder, true); err != nil {
			mc.logf("%s: %s: %v", memdev, region, err)
		}
	}
	return region, nil
}

// CreateRegion creates a volatile region on the memdev under the decoder
// (the root decoder of its host bridge if ""), and binds its dax device for
// the mode: device_dax for ModeDax (memory never onlined), kmem for
// ModeNUMA (memory left offline, see Online). An existing region is reused.
func (mc *Manager) CreateRegion(ctx context.Context, memdev, mode, decoder string) (*RegionInfo, error) {
	return mc.CreateRegionSize(ctx, memdev, mode, decoder, 0)
}

// CreateRegionSize is CreateRegion with the size of a new region in bytes:
// the region maps only the first size bytes of the memdev's RAM capacity
// (cxl create-region -s), 0 maps all of it. The size must be a multiple of
// 256 MiB, the alignment of CXL regions.
func (mc *Manager) CreateRegionSize(ctx context.Context, memdev, mode, decoder string, size uint64) (*RegionInfo, error) {
	return mc.CreateRegionNoted(ctx, memdev, mode, decoder, size, nil)
}

// CreateRegionNoted is CreateRegionSize, telling note (nil: none) about a
// region that it creates (not about one that it reuses).
func (mc *Manager) CreateRegionNoted(ctx context.Context, memdev, mode, decoder string, size uint64, note RegionNote) (*RegionInfo, error) {
	if err := ValidMode(mode); err != nil {
		return nil, err
	}
	k := mc.kernel()
	if err := k.EnableMemdev(ctx, memdev); err != nil {
		return nil, err
	}
	region := ""
	if rs := mc.Regions(memdev); len(rs) > 0 {
		region = rs[0]
		mc.logf("%s: reusing %s", memdev, region)
	} else {
		if decoder == "" {
			d, err := k.RootDecoder(memdev, RegionRAM)
			if err != nil {
				return nil, err
			}
			decoder = d
		}
		var err error
		if region, err = mc.createRegion(ctx, memdev, decoder, RegionRAM, size, note); err != nil {
			return nil, err
		}
	}
	// the dax device appears asynchronously
	dax, err := k.WaitDaxRegion(ctx, region)
	if err != nil {
		return nil, err
	}
	// A dax device that the kernel bound to kmem by itself looks bound
	// while its memory is still being added: let the probe finish before
	// switching drivers (daxctl fails with ENOENT) or onlining.
	if mc.DaxDriver(dax) == DriverKmem {
		if err := k.WaitRegionBlocks(ctx, region); err != nil {
			return nil, err
		}
	}
	blocks, _ := mc.RegionBlocks(region)
	switch mode {
	case ModeDax:
		if mc.DaxDriver(dax) == DriverKmem {
			if err := k.OfflineBlocks(ctx, blocks, settleOffline, 30*time.Second); err != nil {
				return nil, err
			}
		}
		if err := mc.SetDaxDriver(ctx, dax, DriverDeviceDax); err != nil {
			return nil, err
		}
	case ModeNUMA:
		if err := mc.SetDaxDriver(ctx, dax, DriverKmem); err != nil {
			return nil, err
		}
		if err := k.WaitRegionBlocks(ctx, region); err != nil {
			return nil, err
		}
	}
	return mc.Info(memdev)
}

// Online onlines the memory blocks of the memdev's region (mode numa).
func (mc *Manager) Online(memdev string, movable bool) (*RegionInfo, error) {
	ri, err := mc.Info(memdev)
	if err != nil {
		return nil, err
	}
	if ri.Driver != DriverKmem {
		return nil, fmt.Errorf("%s: %s is bound to %q, not kmem: create the region in mode numa", memdev, ri.Dax, ri.Driver)
	}
	if len(ri.Blocks) == 0 {
		return nil, fmt.Errorf("%s: no memory blocks found for %s", memdev, ri.Region)
	}
	if err := mc.kernel().OnlineBlocks(ri.Blocks, movable); err != nil {
		return nil, err
	}
	return ri, nil
}

// Release makes the memdev removable: releases its regions (see
// ReleaseRegions) and disables the memdev. A missing memdev is not an
// error.
func (mc *Manager) Release(ctx context.Context, memdev string) error {
	if _, err := os.Stat(mc.cxlDev(memdev)); err != nil {
		return nil
	}
	if err := mc.ReleaseRegions(ctx, memdev); err != nil {
		return err
	}
	return mc.kernel().DisableMemdev(ctx, memdev)
}

// EnableRegion enables a region that is disabled (cxl enable-region): what
// a ReleaseRegion that did not finish leaves after its cxl disable-region,
// with the decoders still committed. The kernel then makes the dax or
// nvdimm region of the region again. An enabled region is left as it is.
func (mc *Manager) EnableRegion(ctx context.Context, region string) error {
	return mc.kernel().EnableRegion(ctx, region)
}

// ReleaseRegions releases the memdev's regions (see ReleaseRegion). The
// memdev stays enabled. A missing memdev is not an error.
func (mc *Manager) ReleaseRegions(ctx context.Context, memdev string) error {
	if _, err := os.Stat(mc.cxlDev(memdev)); err != nil {
		return nil
	}
	for _, r := range mc.Regions(memdev) {
		if err := mc.ReleaseRegion(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// ReleaseRegion offlines the memory of a region, and disables and destroys
// the region. Namespaces and labels of a region of persistent memory are
// not touched. A missing region is not an error.
//
// A region with memory blocks that are online after it is disabled is not
// destroyed: the kernel could not remove the memory (kmem keeps it "until
// the next reboot"), and destroying the region would leave online memory
// that no decoder maps, which reads garbage.
func (mc *Manager) ReleaseRegion(ctx context.Context, region string) error {
	return mc.kernel().ReleaseRegion(ctx, region)
}

// ReleaseRegionInOrder releases a region of the memdev as ReleaseRegion
// does, unless regions of other memdevs lie above the memdev's regions in
// the decoders of its ports (RegionsAbove): destroying it would leave a
// hole below them (DecoderHole). It returns those regions then, and the
// region stays: as it was if they were there before the release, disabled
// if they came during it. The last check and cxl destroy-region hold the
// lock of the region creations of the process (regionCreateMu): no region
// that this process creates comes above it in between. A missing region is
// not an error.
func (mc *Manager) ReleaseRegionInOrder(ctx context.Context, memdev, region string) ([]string, error) {
	return mc.kernel().ReleaseRegionInOrder(ctx, memdev, region)
}
