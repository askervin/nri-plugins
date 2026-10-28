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
// ndctl CLIs.
package memctl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containers/nri-plugins/pkg/cxl/api"
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
	DriverDeviceDax = "device_dax"
	DriverKmem      = "kmem"
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
		SysRoot: "/sys",
		DevRoot: "/dev",
		Exec: func(ctx context.Context, name string, args ...string) (string, error) {
			out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
			if err != nil {
				return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
			}
			return string(out), nil
		},
		LookPath:     exec.LookPath,
		PollInterval: 200 * time.Millisecond,
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

func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (mc *Manager) writeFile(path, val string) error {
	if mc.WriteFile != nil {
		return mc.WriteFile(path, val)
	}
	return os.WriteFile(path, []byte(val), 0o644)
}

// parseHex returns the hex number in s, with or without 0x.
func parseHex(s string) (uint64, error) {
	return strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"), 16, 64)
}

// readUint returns the number in a sysfs attribute, decimal or 0x hex.
func readUint(path string) (uint64, error) {
	s, err := readTrim(path)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("cannot parse %q in %s: %w", s, path, err)
	}
	return v, nil
}

func (mc *Manager) list(pattern string) []string {
	m, _ := filepath.Glob(mc.cxlDev(pattern))
	var out []string
	for _, p := range m {
		out = append(out, filepath.Base(p))
	}
	sort.Slice(out, func(i, j int) bool { return natLess(out[i], out[j]) })
	return out
}

var trailingNum = regexp.MustCompile(`^(.*?)(\d+)$`)

func natLess(a, b string) bool {
	ma, mb := trailingNum.FindStringSubmatch(a), trailingNum.FindStringSubmatch(b)
	if ma != nil && mb != nil && ma[1] == mb[1] {
		na, _ := strconv.Atoi(ma[2])
		nb, _ := strconv.Atoi(mb[2])
		return na < nb
	}
	return a < b
}

// Memdev is a CXL memory device of the machine.
type Memdev struct {
	Name   string
	Serial uint64
}

// Memdevs lists the CXL memory devices.
func (mc *Manager) Memdevs() []Memdev {
	var out []Memdev
	for _, name := range mc.list("mem*") {
		s, err := readTrim(mc.cxlDev(name, "serial"))
		if err != nil {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
		if err != nil {
			continue
		}
		out = append(out, Memdev{Name: name, Serial: v})
	}
	return out
}

// FindMemdev returns the memN name of the device with the serial.
func (mc *Manager) FindMemdev(serial uint64) (string, error) {
	for _, m := range mc.Memdevs() {
		if m.Serial == serial {
			return m.Name, nil
		}
	}
	return "", fmt.Errorf("%w 0x%x", ErrNotFound, serial)
}

// WaitMemdev waits until a device with the serial appears and its driver
// is bound.
func (mc *Manager) WaitMemdev(ctx context.Context, serial uint64) (string, error) {
	for {
		if name, err := mc.FindMemdev(serial); err == nil {
			if _, err := os.Stat(mc.cxlDev(name, "driver")); err == nil {
				return name, nil
			}
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("timeout waiting for CXL memory device with serial 0x%x: %w", serial, ctx.Err())
		case <-time.After(mc.PollInterval):
		}
	}
}

// endpoint returns the endpoint port (endpointN) of a memdev.
func (mc *Manager) endpoint(memdev string) (string, error) {
	for _, ep := range mc.list("endpoint*") {
		target, err := os.Readlink(mc.cxlDev(ep, "uport"))
		if err == nil && filepath.Base(target) == memdev {
			return ep, nil
		}
	}
	return "", fmt.Errorf("no endpoint port for %s (is it enabled?)", memdev)
}

// Regions returns the regions that have a target decoder of the memdev.
func (mc *Manager) Regions(memdev string) []string {
	ep, err := mc.endpoint(memdev)
	if err != nil {
		return nil
	}
	prefix := "decoder" + strings.TrimPrefix(ep, "endpoint") + "."
	var out []string
	for _, r := range mc.list("region*") {
		targets, _ := filepath.Glob(mc.cxlDev(r, "target*"))
		for _, t := range targets {
			if v, err := readTrim(t); err == nil && strings.HasPrefix(v, prefix) {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

var pciRootRe = regexp.MustCompile(`^(.*/pci([0-9a-f]{4}):([0-9a-f]{2}))/`)

// hostBridgeUID returns the uid of the host bridge of a memdev, as root
// decoders list it in target_list: N of the dportN of a CXL root port
// that links to the PCI root of the memdev, else the ACPI _UID of the PCI
// root (firmware_node/uid), else the bus number of the PCI root. The ACPI
// _UID equals the bus number with qemu pxb-cxl (bus_nr) but not on real
// hardware, where host bridge pci0000:63 can have the uid 35.
func (mc *Manager) hostBridgeUID(memdev string) (int, error) {
	real, err := filepath.EvalSymlinks(mc.cxlDev(memdev))
	if err != nil {
		return 0, err
	}
	m := pciRootRe.FindStringSubmatch(real + "/")
	if m == nil {
		return 0, fmt.Errorf("cannot find the PCI root of %s in %s", memdev, real)
	}
	pciRoot := m[1]
	dports, _ := filepath.Glob(mc.cxlDev("root*", "dport*"))
	for _, dport := range dports {
		target, err := filepath.EvalSymlinks(dport)
		if err != nil || target != pciRoot {
			continue
		}
		if v, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(dport), "dport")); err == nil {
			return v, nil
		}
	}
	if s, err := readTrim(filepath.Join(pciRoot, "firmware_node", "uid")); err == nil {
		if v, err := strconv.Atoi(s); err == nil {
			return v, nil
		}
	}
	v, _ := strconv.ParseInt(m[3], 16, 32)
	return int(v), nil
}

// RamSize returns the RAM capacity of a memdev in bytes.
func (mc *Manager) RamSize(memdev string) (uint64, error) {
	return readUint(mc.cxlDev(memdev, "ram", "size"))
}

// DaxDevices returns the dax devices of a region.
func (mc *Manager) DaxDevices(region string) []string {
	m, _ := filepath.Glob(mc.cxlDev(region, "dax_region*", "dax*.*"))
	var out []string
	for _, p := range m {
		out = append(out, filepath.Base(p))
	}
	sort.Strings(out)
	return out
}

func (mc *Manager) daxDev(dax string, p ...string) string {
	return filepath.Join(append([]string{mc.SysRoot, "bus", "dax", "devices", dax}, p...)...)
}

// DaxDriver returns the driver of a dax device ("" if none).
func (mc *Manager) DaxDriver(dax string) string {
	t, err := os.Readlink(mc.daxDev(dax, "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(t)
}

// TargetNode returns the NUMA node of the memory of a dax device.
func (mc *Manager) TargetNode(dax string) int {
	v, err := readTrim(mc.daxDev(dax, "target_node"))
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return -1
	}
	return n
}

// DaxDevNumbers returns the major and minor numbers of the character
// device of a dax device (/sys/bus/dax/devices/<dax>/dev, "major:minor").
func (mc *Manager) DaxDevNumbers(dax string) (major, minor int, err error) {
	v, err := readTrim(mc.daxDev(dax, "dev"))
	if err != nil {
		return 0, 0, err
	}
	ma, mi, ok := strings.Cut(v, ":")
	if ok {
		major, err = strconv.Atoi(ma)
		if err == nil {
			minor, err = strconv.Atoi(mi)
		}
	}
	if !ok || err != nil {
		return 0, 0, fmt.Errorf("%s: cannot parse device numbers %q", dax, v)
	}
	return major, minor, nil
}

// daxRegionDir returns the sysfs directory of the dax region attributes of
// a region (regionN/dax_regionN/dax_region).
func (mc *Manager) daxRegionDir(region string) string {
	if m, _ := filepath.Glob(mc.cxlDev(region, "dax_region*", "dax_region")); len(m) > 0 {
		return m[0]
	}
	return mc.cxlDev(region, "dax_"+region, "dax_region")
}

// DaxRegionInfo returns the free bytes and the allocation alignment of the
// dax region of a region, and the dax devices of the region.
func (mc *Manager) DaxRegionInfo(region string) (available, align uint64, devices []string, err error) {
	dir := mc.daxRegionDir(region)
	if available, err = readUint(filepath.Join(dir, "available_size")); err != nil {
		return 0, 0, nil, err
	}
	if align, err = readUint(filepath.Join(dir, "align")); err != nil {
		return 0, 0, nil, err
	}
	return available, align, mc.DaxDevices(region), nil
}

// DaxDeviceSize returns the size of a dax device in bytes.
func (mc *Manager) DaxDeviceSize(dax string) (uint64, error) {
	return readUint(mc.daxDev(dax, "size"))
}

// daxDeviceResource returns the start address of the memory of a dax
// device.
func (mc *Manager) daxDeviceResource(dax string) (uint64, error) {
	return readUint(mc.daxDev(dax, "resource"))
}

// UnbindDax unbinds a dax device from its driver. A device that kmem has
// with memory blocks that are not offline is not unbound: the kernel could
// not remove that memory, it would stay online until a reboot.
func (mc *Manager) UnbindDax(ctx context.Context, dax string) error {
	cur := mc.DaxDriver(dax)
	if cur == "" {
		return nil
	}
	if cur == DriverKmem {
		if err := mc.checkOffline(dax); err != nil {
			return err
		}
	}
	if err := mc.writeFile(filepath.Join(mc.SysRoot, "bus", "dax", "drivers", cur, "unbind"), dax); err != nil {
		return fmt.Errorf("unbind %s from %s: %w", dax, cur, err)
	}
	if got := mc.DaxDriver(dax); got != "" {
		return fmt.Errorf("%s is still bound to %q", dax, got)
	}
	mc.logf("%s: unbound from %s", dax, cur)
	return nil
}

// checkOffline returns an error that lists the memory blocks of a dax
// device that are not offline, nil if there are none.
func (mc *Manager) checkOffline(dax string) error {
	bs, err := mc.MemoryBlockSize()
	if err != nil {
		return fmt.Errorf("%s: %w", dax, err)
	}
	blocks, err := mc.DaxDeviceBlocks(dax, bs)
	if err != nil {
		return err
	}
	var online []int
	for _, b := range blocks {
		if st, err := readTrim(mc.block(b, "state")); err != nil || st != "offline" {
			online = append(online, b)
		}
	}
	if len(online) > 0 {
		return fmt.Errorf("%s: memory blocks %v are not offline, kmem keeps it", dax, online)
	}
	return nil
}

// ResizeDaxDevice unbinds a dax device from its driver and sets its size
// in bytes, a multiple of the align of its dax region. The device is left
// unbound.
func (mc *Manager) ResizeDaxDevice(ctx context.Context, dax string, size uint64) error {
	if err := mc.UnbindDax(ctx, dax); err != nil {
		return err
	}
	if err := mc.writeFile(mc.daxDev(dax, "size"), strconv.FormatUint(size, 10)); err != nil {
		return fmt.Errorf("%s: set size %d: %w", dax, size, err)
	}
	got, err := mc.DaxDeviceSize(dax)
	if err != nil {
		return err
	}
	if got != size {
		return fmt.Errorf("%s: size is %d after setting %d", dax, got, size)
	}
	mc.logf("%s: size %d", dax, size)
	return nil
}

// CreateDaxDevice creates a dax device of size bytes in the dax region of
// a region and returns its name. The device is not bound to a driver.
func (mc *Manager) CreateDaxDevice(ctx context.Context, region string, size uint64) (string, error) {
	dax, err := mc.newDaxDevice(region)
	if err != nil {
		return "", err
	}
	if err := mc.ResizeDaxDevice(ctx, dax, size); err != nil {
		if derr := mc.DeleteDaxDevice(ctx, region, dax); derr != nil {
			mc.logf("%s: %v", region, derr)
		}
		return "", err
	}
	return dax, nil
}

// CreateDaxDeviceRanges creates a dax device in the dax region of a region
// with the memory of the ranges, and returns its name. The device is not
// bound to a driver. When the dax region does not give the device exactly
// that memory, the device is deleted and an error returned.
func (mc *Manager) CreateDaxDeviceRanges(ctx context.Context, region string, ranges []Range) (string, error) {
	if len(ranges) == 0 {
		return "", fmt.Errorf("%s: a dax device without memory", region)
	}
	want := slices.Clone(ranges)
	sort.Slice(want, func(i, j int) bool { return want[i].Start < want[j].Start })
	dax, err := mc.newDaxDevice(region)
	if err != nil {
		return "", err
	}
	for _, r := range ranges {
		if err = mc.writeFile(mc.daxDev(dax, "mapping"), r.String()); err != nil {
			err = fmt.Errorf("%s: map %s: %w", dax, r, err)
			break
		}
	}
	if err == nil {
		// The kernel ignores a length that is not a multiple of the
		// device align without an error.
		var got []Range
		got, err = mc.DaxDeviceRanges(dax)
		if err == nil && !slices.Equal(got, want) {
			err = fmt.Errorf("%s: memory %v after mapping %v", dax, got, want)
		}
	}
	if err != nil {
		if derr := mc.DeleteDaxDevice(ctx, region, dax); derr != nil {
			mc.logf("%s: %v", region, derr)
		}
		return "", err
	}
	mc.logf("%s: mapped %v", dax, want)
	return dax, nil
}

// newDaxDevice creates a dax device of size 0 in the dax region of a
// region and returns its name.
func (mc *Manager) newDaxDevice(region string) (string, error) {
	dir := mc.daxRegionDir(region)
	if err := mc.writeFile(filepath.Join(dir, "create"), "1"); err != nil {
		return "", fmt.Errorf("%s: create a dax device: %w", region, err)
	}
	// reading create returns the youngest device of the dax region
	dax, err := readTrim(filepath.Join(dir, "create"))
	if err != nil {
		return "", err
	}
	if dax == "" {
		return "", fmt.Errorf("%s: no dax device was created", region)
	}
	mc.logf("%s: created %s", region, dax)
	return dax, nil
}

// DeleteDaxDevice unbinds a dax device, sets its size to 0 and deletes it
// from the dax region of a region. The first dax device of a region
// (daxN.0) is kept with size 0. A device that does not exist is not an
// error.
func (mc *Manager) DeleteDaxDevice(ctx context.Context, region, dax string) error {
	if _, err := os.Lstat(mc.daxDev(dax)); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := mc.ResizeDaxDevice(ctx, dax, 0); err != nil {
		return err
	}
	if strings.HasSuffix(dax, ".0") {
		return nil
	}
	if err := mc.writeFile(filepath.Join(mc.daxRegionDir(region), "delete"), dax); err != nil {
		return fmt.Errorf("%s: delete %s: %w", region, dax, err)
	}
	mc.logf("%s: deleted %s", region, dax)
	return nil
}

// Range is a range of physical addresses from Start to End, both
// included, as the kernel shows them.
type Range struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

// Size returns the number of bytes in the range.
func (r Range) Size() uint64 {
	return r.End - r.Start + 1
}

// Aligned tells whether the range starts and ends at multiples of align.
func (r Range) Aligned(align uint64) bool {
	return align > 0 && r.Start%align == 0 && r.Size()%align == 0
}

// String returns the range as "0x<start>-0x<end>".
func (r Range) String() string {
	return fmt.Sprintf("0x%x-0x%x", r.Start, r.End)
}

// blocks returns the numbers of the memory blocks of bs bytes that lie
// wholly in the range.
func (r Range) blocks(bs uint64) []int {
	var out []int
	for b := (r.Start + bs - 1) / bs; (b+1)*bs-1 <= r.End; b++ {
		out = append(out, int(b))
	}
	return out
}

// MemoryBlockSize returns the size of the memory blocks of the system in
// bytes (devices/system/memory/block_size_bytes, hex without 0x).
func (mc *Manager) MemoryBlockSize() (uint64, error) {
	path := filepath.Join(mc.SysRoot, "devices", "system", "memory", "block_size_bytes")
	s, err := readTrim(path)
	if err != nil {
		return 0, err
	}
	bs, err := parseHex(s)
	if err != nil || bs == 0 {
		return 0, fmt.Errorf("cannot parse the memory block size %q in %s", s, path)
	}
	return bs, nil
}

// RegionRange returns the physical address range of a region.
func (mc *Manager) RegionRange(region string) (Range, error) {
	res, err := readTrim(mc.cxlDev(region, "resource"))
	if err != nil {
		return Range{}, err
	}
	sz, err := readTrim(mc.cxlDev(region, "size"))
	if err != nil {
		return Range{}, err
	}
	start, err1 := parseHex(res)
	size, err2 := parseHex(sz)
	if err := errors.Join(err1, err2); err != nil || size == 0 {
		return Range{}, fmt.Errorf("cannot parse region %s resource %q size %q", region, res, sz)
	}
	return Range{Start: start, End: start + size - 1}, nil
}

// RegionBlocks returns the memory block numbers of a region.
func (mc *Manager) RegionBlocks(region string) ([]int, error) {
	blocks, _, err := mc.regionBlocks(region)
	return blocks, err
}

// regionBlocks returns the memory block numbers of a region that exist,
// and how many blocks lie wholly in the region (kmem adds only those).
func (mc *Manager) regionBlocks(region string) ([]int, int, error) {
	r, err := mc.RegionRange(region)
	if err != nil {
		return nil, 0, err
	}
	bs, err := mc.MemoryBlockSize()
	if err != nil {
		return nil, 0, err
	}
	whole := r.blocks(bs)
	var out []int
	for _, b := range whole {
		if mc.blockExists(b) {
			out = append(out, b)
		}
	}
	return out, len(whole), nil
}

// DaxDeviceRanges returns the physical address ranges of the memory of a
// dax device (its mappingN), in address order. Without mappings (kernels
// before 5.10) the device has one range from its resource and size. A
// device of size 0 has none.
func (mc *Manager) DaxDeviceRanges(dax string) ([]Range, error) {
	dirs, _ := filepath.Glob(mc.daxDev(dax, "mapping[0-9]*"))
	if len(dirs) == 0 {
		size, err := mc.DaxDeviceSize(dax)
		if err != nil || size == 0 {
			return nil, err
		}
		start, err := mc.daxDeviceResource(dax)
		if err != nil {
			return nil, err
		}
		return []Range{{Start: start, End: start + size - 1}}, nil
	}
	out := make([]Range, 0, len(dirs))
	for _, dir := range dirs {
		start, err := readUint(filepath.Join(dir, "start"))
		if err != nil {
			return nil, err
		}
		end, err := readUint(filepath.Join(dir, "end"))
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
func (mc *Manager) DaxDeviceBlocks(dax string, bs uint64) ([]int, error) {
	blocks, _, err := mc.daxBlocks(dax, bs)
	return blocks, err
}

// daxBlocks returns the numbers of the memory blocks of a dax device that
// exist, and how many blocks lie wholly in its memory.
func (mc *Manager) daxBlocks(dax string, bs uint64) ([]int, int, error) {
	if bs == 0 {
		return nil, 0, errors.New("memory block size 0")
	}
	ranges, err := mc.DaxDeviceRanges(dax)
	if err != nil {
		return nil, 0, err
	}
	var out []int
	want := 0
	for _, r := range ranges {
		for _, b := range r.blocks(bs) {
			want++
			if mc.blockExists(b) {
				out = append(out, b)
			}
		}
	}
	return out, want, nil
}

// WaitDaxBlocks waits until every memory block of a dax device that is
// bound to kmem exists.
func (mc *Manager) WaitDaxBlocks(ctx context.Context, dax string) error {
	bs, err := mc.MemoryBlockSize()
	if err != nil {
		return err
	}
	for {
		blocks, want, err := mc.daxBlocks(dax, bs)
		if err != nil {
			return err
		}
		if want == 0 {
			return fmt.Errorf("%s has no whole memory block of %d bytes", dax, bs)
		}
		if len(blocks) == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: %d of %d memory blocks appeared: %w", dax, len(blocks), want, ctx.Err())
		case <-time.After(mc.PollInterval):
		}
	}
}

// RegionFreeGaps returns the ranges of the memory of a region that none of
// its dax devices has, in address order.
func (mc *Manager) RegionFreeGaps(region string) ([]Range, error) {
	rr, err := mc.RegionRange(region)
	if err != nil {
		return nil, err
	}
	var used []Range
	for _, dax := range mc.DaxDevices(region) {
		ranges, err := mc.DaxDeviceRanges(dax)
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

func (mc *Manager) block(n int, p ...string) string {
	return filepath.Join(append([]string{mc.SysRoot, "devices", "system", "memory", "memory" + strconv.Itoa(n)}, p...)...)
}

// blockExists tells whether memory block n exists.
func (mc *Manager) blockExists(n int) bool {
	_, err := os.Stat(mc.block(n, "state"))
	return err == nil
}

// BlocksNode returns the NUMA node of online memory blocks
// (/sys/devices/system/memory/memoryN/nodeM), -1 if not found.
func (mc *Manager) BlocksNode(blocks []int) int {
	for _, b := range blocks {
		m, _ := filepath.Glob(mc.block(b, "node*"))
		for _, path := range m {
			if n, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(path), "node")); err == nil {
				return n
			}
		}
	}
	return -1
}

// SetBlocksState onlines ("online", "online_movable") or offlines
// ("offline") memory blocks, skipping blocks that are already there.
func (mc *Manager) SetBlocksState(blocks []int, state string) error {
	want := strings.TrimSuffix(strings.TrimSuffix(state, "_movable"), "_kernel")
	for _, b := range blocks {
		cur, err := readTrim(mc.block(b, "state"))
		if err != nil {
			return err
		}
		if cur == want {
			// online, but maybe in a zone that cannot be offlined reliably
			if state == "online_movable" {
				if z, err := readTrim(mc.block(b, "valid_zones")); err == nil && z != "" && !strings.HasPrefix(z, "Movable") {
					return fmt.Errorf("memory%d is already online in zone %s, not Movable (auto-onlined?): offline it first", b, z)
				}
			}
			continue
		}
		if err := mc.writeFile(mc.block(b, "state"), state); err != nil {
			return fmt.Errorf("memory%d: %s: %w", b, state, err)
		}
		mc.logf("memory%d: %s", b, state)
	}
	return nil
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
// away.
func (mc *Manager) SetDaxDriver(ctx context.Context, dax, driver string) error {
	cur := mc.DaxDriver(dax)
	if cur == driver {
		return nil
	}
	if !mc.has("daxctl") {
		return mc.SetDaxDriverSysfs(ctx, dax, driver)
	}
	// the daxctl modes of device_dax and kmem
	args := []string{"reconfigure-device", "--mode=devdax", "--force", dax}
	if driver == DriverKmem {
		args = []string{"reconfigure-device", "--mode=system-ram", "--no-online", dax}
	}
	if _, err := mc.Exec(ctx, "daxctl", args...); err != nil {
		return err
	}
	return mc.checkDaxDriver(dax, driver)
}

// SetDaxDriverSysfs binds a dax device to device_dax or kmem through the
// sysfs attributes of the dax bus. The memory blocks that kmem adds are
// offline unless auto_online_blocks onlines them.
func (mc *Manager) SetDaxDriverSysfs(ctx context.Context, dax, driver string) error {
	if mc.DaxDriver(dax) == driver {
		return nil
	}
	drivers := filepath.Join(mc.SysRoot, "bus", "dax", "drivers")
	if err := mc.UnbindDax(ctx, dax); err != nil {
		return err
	}
	// kmem matches the dax devices of CXL regions by their type, so bind
	// is enough; a new_id would make kmem probe every unbound dax device
	// of the regions. device_dax does not match them by type: new_id
	// makes it match and probe the device, bind is a fallback if the id
	// was already there. The id is removed again afterwards, so that a
	// later device with the same name binds to its default driver.
	if driver != DriverKmem {
		if err := mc.writeFile(filepath.Join(drivers, driver, "new_id"), dax); err != nil {
			mc.logf("%s: new_id: %v", driver, err)
		}
	}
	if mc.DaxDriver(dax) != driver {
		if err := mc.writeFile(filepath.Join(drivers, driver, "bind"), dax); err != nil {
			return fmt.Errorf("bind %s to %s: %w", dax, driver, err)
		}
	}
	if driver != DriverKmem {
		_ = mc.writeFile(filepath.Join(drivers, driver, "remove_id"), dax)
	}
	return mc.checkDaxDriver(dax, driver)
}

// checkDaxDriver returns an error if a dax device is not bound to driver,
// and logs the binding otherwise.
func (mc *Manager) checkDaxDriver(dax, driver string) error {
	if got := mc.DaxDriver(dax); got != driver {
		return fmt.Errorf("%s is bound to %q, not %q", dax, got, driver)
	}
	mc.logf("%s: bound to %s", dax, driver)
	return nil
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
// TODO: can we detect when kernel has finished moving all data from
// offlined blocks?
var settleOffline = 500 * time.Millisecond

var regionNameRe = regexp.MustCompile(`"region"\s*:\s*"(region\d+)"`)

// regionCreateMu serializes the region creations of the process (the pool
// driver and the local allocator, each with a Manager of its own) with
// DeleteHollowRegion, so that the name of the next region read before a
// creation is the one it gets (from this process), and a hollow region is
// never one that this process is setting up.
var regionCreateMu sync.Mutex

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
	args := []string{"create-region", "-t", regionType, "-d", decoder, "-m", memdev}
	if size > 0 {
		args = append(args, "-s", strconv.FormatUint(size, 10))
	}
	attr := "create_ram_region"
	if regionType == RegionPmem {
		attr = "create_pmem_region"
	}
	var noteErr error
	out, err := func() (string, error) {
		regionCreateMu.Lock()
		defer regionCreateMu.Unlock()
		if note != nil {
			next, _ := readTrim(mc.cxlDev(decoder, attr))
			if noteErr = note(next, decoder, false); noteErr != nil {
				return "", noteErr
			}
		}
		return mc.Exec(ctx, "cxl", args...)
	}()
	if noteErr != nil {
		return "", noteErr
	}
	if err != nil {
		return "", mc.explainCreateRegion(memdev, err)
	}
	region := ""
	if m := regionNameRe.FindStringSubmatch(out); m != nil {
		region = m[1]
	} else if rs := mc.Regions(memdev); len(rs) > 0 {
		region = rs[0]
	} else {
		return "", fmt.Errorf("cxl create-region did not report a region: %s", out)
	}
	if note != nil {
		if err := note(region, decoder, true); err != nil {
			mc.logf("%s: %s: %v", memdev, region, err)
		}
	}
	mc.logf("%s: created %s (%s) under %s", memdev, region, regionType, decoder)
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
	if _, err := os.Stat(mc.cxlDev(memdev, "driver")); err != nil {
		if _, err := mc.Exec(ctx, "cxl", "enable-memdev", memdev); err != nil {
			return nil, err
		}
	}
	region := ""
	if rs := mc.Regions(memdev); len(rs) > 0 {
		region = rs[0]
		mc.logf("%s: reusing %s", memdev, region)
	} else {
		if decoder == "" {
			d, err := mc.RootDecoder(memdev, RegionRAM)
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
	var dax string
	for {
		if ds := mc.DaxDevices(region); len(ds) > 0 && mc.DaxDriver(ds[0]) != "" {
			dax = ds[0]
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("no dax device bound to a driver appeared in %s: %w", region, ctx.Err())
		case <-time.After(mc.PollInterval):
		}
	}
	// A dax device that the kernel bound to kmem by itself looks bound
	// while its memory is still being added: let the probe finish before
	// switching drivers (daxctl fails with ENOENT) or onlining.
	if mc.DaxDriver(dax) == DriverKmem {
		if err := mc.waitRegionBlocks(ctx, region); err != nil {
			return nil, err
		}
	}
	blocks, _ := mc.RegionBlocks(region)
	switch mode {
	case ModeDax:
		if mc.DaxDriver(dax) == DriverKmem {
			if err := mc.offlineSettled(ctx, blocks, settleOffline, 30*time.Second); err != nil {
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
		if err := mc.waitRegionBlocks(ctx, region); err != nil {
			return nil, err
		}
	}
	return mc.Info(memdev)
}

// waitRegionBlocks waits until every memory block of a kmem region exists.
// The kernel creates the driver link of a dax device before it probes the
// driver, so a dax device that the kernel binds to kmem by itself (the
// default for a volatile region) looks bound while dev_dax_kmem_probe is
// still adding its memory.
func (mc *Manager) waitRegionBlocks(ctx context.Context, region string) error {
	for {
		blocks, want, err := mc.regionBlocks(region)
		if err != nil {
			return err
		}
		// a region without a whole block gets no memory blocks
		if len(blocks) == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: %d of %d memory blocks appeared: %w", region, len(blocks), want, ctx.Err())
		case <-time.After(mc.PollInterval):
		}
	}
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
	state := "online"
	if movable {
		state = "online_movable"
	}
	if len(ri.Blocks) == 0 {
		return nil, fmt.Errorf("%s: no memory blocks found for %s", memdev, ri.Region)
	}
	if err := mc.SetBlocksState(ri.Blocks, state); err != nil {
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
	if _, err := os.Stat(mc.cxlDev(memdev, "driver")); err == nil {
		if _, err := mc.Exec(ctx, "cxl", "disable-memdev", memdev); err != nil {
			return err
		}
		mc.logf("%s: disabled", memdev)
	}
	return nil
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
	if _, err := os.Stat(mc.cxlDev(region)); err != nil {
		return nil
	}
	// Offline every memory block of the region, whatever the driver of its
	// dax devices: a failed driver switch can leave blocks added and
	// online without kmem.
	if blocks, err := mc.RegionBlocks(region); err == nil && len(blocks) > 0 {
		if err := mc.SetBlocksState(blocks, "offline"); err != nil {
			return fmt.Errorf("%s: cannot offline memory (in use?): %w", region, err)
		}
	}
	if _, err := mc.Exec(ctx, "cxl", "disable-region", region); err != nil {
		return err
	}
	if blocks, err := mc.RegionBlocks(region); err == nil {
		var online []int
		for _, b := range blocks {
			if st, err := readTrim(mc.block(b, "state")); err == nil && st != "offline" {
				online = append(online, b)
			}
		}
		if len(online) > 0 {
			return fmt.Errorf("%s: memory blocks %v are online after disabling it (the kernel could not remove them, see dmesg): not destroying the region, the memory would read garbage", region, online)
		}
	}
	if _, err := mc.Exec(ctx, "cxl", "destroy-region", region); err != nil {
		return err
	}
	mc.logf("destroyed %s", region)
	return nil
}

// offlineSettled offlines memory blocks and waits until all of them have
// stayed offline for settle: a udev rule (for instance 40-redhat.rules of
// RHEL and its derivatives) may online hot-added blocks after they were
// offlined, whatever auto_online_blocks says. Blocks that come online are
// offlined again until timeout.
func (mc *Manager) offlineSettled(ctx context.Context, blocks []int, settle, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if err := mc.SetBlocksState(blocks, "offline"); err != nil {
			return err
		}
		stable := time.Now().Add(settle)
		onlined := false
		for !onlined && time.Now().Before(stable) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(mc.PollInterval):
			}
			for _, b := range blocks {
				if st, err := readTrim(mc.block(b, "state")); err == nil && st != "offline" {
					mc.logf("memory%d: %s again after offlining it (auto-onlined by udev?)", b, st)
					onlined = true
					break
				}
			}
		}
		if !onlined {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("memory blocks %v keep coming online after offlining them: is a udev rule onlining hot-added memory?", blocks)
		}
	}
}
