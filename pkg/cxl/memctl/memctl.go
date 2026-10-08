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
// them again: find a memdev by serial, create a region in devdax or
// system-ram mode, online or offline its memory, destroy the region and
// disable the memdev. It drives sysfs and the cxl and daxctl CLIs.
package memctl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Region modes.
const (
	ModeDevDax = "devdax"
	ModeRAM    = "ram"
)

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

func writeFile(path, val string) error {
	return os.WriteFile(path, []byte(val), 0o644)
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

// Endpoint returns the endpoint port (endpointN) of a memdev.
func (mc *Manager) Endpoint(memdev string) (string, error) {
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
	ep, err := mc.Endpoint(memdev)
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

var pciRootRe = regexp.MustCompile(`/pci([0-9a-f]{4}):([0-9a-f]{2})/`)

// HostBridgeUID returns the uid of the host bridge of a memdev: the bus
// number of its PCI root (qemu pxb-cxl bus_nr), as root decoders list it in
// target_list.
func (mc *Manager) HostBridgeUID(memdev string) (int, error) {
	real, err := filepath.EvalSymlinks(mc.cxlDev(memdev))
	if err != nil {
		return 0, err
	}
	m := pciRootRe.FindStringSubmatch(real + "/")
	if m == nil {
		return 0, fmt.Errorf("cannot find the PCI root of %s in %s", memdev, real)
	}
	v, _ := strconv.ParseInt(m[2], 16, 32)
	return int(v), nil
}

// RootDecoder returns the root decoder whose target list has the host
// bridge of the memdev and that can map volatile memory.
func (mc *Manager) RootDecoder(memdev string) (string, error) {
	uid, err := mc.HostBridgeUID(memdev)
	if err != nil {
		return "", err
	}
	for _, d := range mc.list("decoder*") {
		if t, _ := readTrim(mc.cxlDev(d, "devtype")); t != "cxl_decoder_root" {
			continue
		}
		if v, err := readTrim(mc.cxlDev(d, "cap_type3_volatile")); err == nil && v != "1" {
			continue
		}
		tl, _ := readTrim(mc.cxlDev(d, "target_list"))
		for _, t := range strings.Split(tl, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil && n == uid {
				return d, nil
			}
		}
	}
	return "", fmt.Errorf("no root decoder targets host bridge %d of %s", uid, memdev)
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

// RegionBlocks returns the memory block numbers of a region.
func (mc *Manager) RegionBlocks(region string) ([]int, error) {
	blocks, _, err := mc.regionBlocks(region)
	return blocks, err
}

// regionBlocks returns the memory block numbers of a region that exist,
// and how many blocks the region spans.
func (mc *Manager) regionBlocks(region string) ([]int, int, error) {
	res, err := readTrim(mc.cxlDev(region, "resource"))
	if err != nil {
		return nil, 0, err
	}
	sz, err := readTrim(mc.cxlDev(region, "size"))
	if err != nil {
		return nil, 0, err
	}
	bsz, err := readTrim(filepath.Join(mc.SysRoot, "devices", "system", "memory", "block_size_bytes"))
	if err != nil {
		return nil, 0, err
	}
	start, err1 := strconv.ParseUint(strings.TrimPrefix(res, "0x"), 16, 64)
	size, err2 := strconv.ParseUint(strings.TrimPrefix(sz, "0x"), 16, 64)
	bs, err3 := strconv.ParseUint(strings.TrimPrefix(bsz, "0x"), 16, 64)
	if err := errors.Join(err1, err2, err3); err != nil || bs == 0 {
		return nil, 0, fmt.Errorf("cannot parse region %s resource %q size %q block size %q", region, res, sz, bsz)
	}
	var out []int
	for b := start / bs; b < (start+size)/bs; b++ {
		if _, err := os.Stat(mc.block(int(b), "state")); err == nil {
			out = append(out, int(b))
		}
	}
	return out, int((start+size)/bs - start/bs), nil
}

func (mc *Manager) block(n int, p ...string) string {
	return filepath.Join(append([]string{mc.SysRoot, "devices", "system", "memory", "memory" + strconv.Itoa(n)}, p...)...)
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
		if err := writeFile(mc.block(b, "state"), state); err != nil {
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

// SetDaxDriver binds a dax device to device_dax (devdax) or kmem
// (system-ram). Memory of kmem must be offline before switching away.
func (mc *Manager) SetDaxDriver(ctx context.Context, dax, driver string) error {
	cur := mc.DaxDriver(dax)
	if cur == driver {
		return nil
	}
	if mc.has("daxctl") {
		mode := "devdax"
		if driver == DriverKmem {
			mode = "system-ram"
		}
		args := []string{"reconfigure-device", "--mode=" + mode, "--force", dax}
		if driver == DriverKmem {
			args = []string{"reconfigure-device", "--mode=" + mode, "--no-online", dax}
		}
		if _, err := mc.Exec(ctx, "daxctl", args...); err != nil {
			return err
		}
	} else {
		drivers := filepath.Join(mc.SysRoot, "bus", "dax", "drivers")
		if cur != "" {
			if err := writeFile(filepath.Join(drivers, cur, "unbind"), dax); err != nil {
				return fmt.Errorf("unbind %s from %s: %w", dax, cur, err)
			}
			mc.logf("%s: unbound from %s", dax, cur)
		}
		// new_id makes the driver match and probe the device; bind is a
		// fallback if the id was already there. The id is removed again
		// afterwards, so that a later device with the same name binds to
		// its default driver.
		if err := writeFile(filepath.Join(drivers, driver, "new_id"), dax); err != nil {
			mc.logf("%s: new_id: %v", driver, err)
		}
		if mc.DaxDriver(dax) != driver {
			if err := writeFile(filepath.Join(drivers, driver, "bind"), dax); err != nil {
				return fmt.Errorf("bind %s to %s: %w", dax, driver, err)
			}
		}
		_ = writeFile(filepath.Join(drivers, driver, "remove_id"), dax)
	}
	if got := mc.DaxDriver(dax); got != driver {
		return fmt.Errorf("%s is bound to %q, not %q", dax, got, driver)
	}
	mc.logf("%s: bound to %s", dax, driver)
	return nil
}

// RegionInfo describes a region of a memdev.
type RegionInfo struct {
	Memdev string `json:"memdev"`
	Region string `json:"region"`
	Dax    string `json:"dax"`
	Driver string `json:"driver"`
	Mode   string `json:"mode"`
	Node   int    `json:"node"`
	Device string `json:"device,omitempty"` // /dev/daxX.Y in devdax mode
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
		ri.Mode = ModeDevDax
		ri.Device = filepath.Join(mc.DevRoot, ri.Dax)
	case DriverKmem:
		ri.Mode = ModeRAM
	}
	ri.Blocks, _ = mc.RegionBlocks(ri.Region)
	return ri, nil
}

var regionNameRe = regexp.MustCompile(`"region"\s*:\s*"(region\d+)"`)

// CreateRegion creates a ram region on the memdev under the decoder (the
// root decoder of its host bridge if ""), and binds its dax device for the
// mode: device_dax for devdax (memory never onlined), kmem for ram (memory
// left offline, see Online). An existing region is reused.
func (mc *Manager) CreateRegion(ctx context.Context, memdev, mode, decoder string) (*RegionInfo, error) {
	if mode != ModeDevDax && mode != ModeRAM {
		return nil, fmt.Errorf("invalid mode %q (devdax or ram)", mode)
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
			d, err := mc.RootDecoder(memdev)
			if err != nil {
				return nil, err
			}
			decoder = d
		}
		out, err := mc.Exec(ctx, "cxl", "create-region", "-t", "ram", "-d", decoder, "-m", memdev)
		if err != nil {
			return nil, err
		}
		if m := regionNameRe.FindStringSubmatch(out); m != nil {
			region = m[1]
		} else if rs := mc.Regions(memdev); len(rs) > 0 {
			region = rs[0]
		} else {
			return nil, fmt.Errorf("cxl create-region did not report a region: %s", out)
		}
		mc.logf("%s: created %s under %s", memdev, region, decoder)
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
	case ModeDevDax:
		if mc.DaxDriver(dax) == DriverKmem {
			if err := mc.SetBlocksState(blocks, "offline"); err != nil {
				return nil, err
			}
		}
		if err := mc.SetDaxDriver(ctx, dax, DriverDeviceDax); err != nil {
			return nil, err
		}
	case ModeRAM:
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
// default for a ram region) looks bound while dev_dax_kmem_probe is still
// adding its memory.
func (mc *Manager) waitRegionBlocks(ctx context.Context, region string) error {
	for {
		blocks, want, err := mc.regionBlocks(region)
		if err != nil {
			return err
		}
		if want > 0 && len(blocks) == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: %d of %d memory blocks appeared: %w", region, len(blocks), want, ctx.Err())
		case <-time.After(mc.PollInterval):
		}
	}
}

// Online onlines the memory blocks of the memdev's region (mode ram).
func (mc *Manager) Online(memdev string, movable bool) (*RegionInfo, error) {
	ri, err := mc.Info(memdev)
	if err != nil {
		return nil, err
	}
	if ri.Driver != DriverKmem {
		return nil, fmt.Errorf("%s: %s is bound to %q, not kmem: create the region with --mode ram", memdev, ri.Dax, ri.Driver)
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

// Release makes the memdev removable: offlines its memory, disables and
// destroys its regions and disables the memdev. A missing memdev is not an
// error.
func (mc *Manager) Release(ctx context.Context, memdev string) error {
	if _, err := os.Stat(mc.cxlDev(memdev)); err != nil {
		return nil
	}
	for _, r := range mc.Regions(memdev) {
		for _, dax := range mc.DaxDevices(r) {
			if mc.DaxDriver(dax) == DriverKmem {
				if blocks, err := mc.RegionBlocks(r); err == nil {
					if err := mc.SetBlocksState(blocks, "offline"); err != nil {
						return fmt.Errorf("%s: cannot offline memory (in use?): %w", r, err)
					}
				}
			}
		}
		if _, err := mc.Exec(ctx, "cxl", "disable-region", r); err != nil {
			return err
		}
		if _, err := mc.Exec(ctx, "cxl", "destroy-region", r); err != nil {
			return err
		}
		mc.logf("%s: destroyed %s", memdev, r)
	}
	if _, err := os.Stat(mc.cxlDev(memdev, "driver")); err == nil {
		if _, err := mc.Exec(ctx, "cxl", "disable-memdev", memdev); err != nil {
			return err
		}
		mc.logf("%s: disabled", memdev)
	}
	return nil
}
