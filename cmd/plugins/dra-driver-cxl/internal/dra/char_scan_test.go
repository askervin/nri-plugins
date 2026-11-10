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

package dra

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

var update = flag.Bool("update", false, "write the golden files of the scans")

const (
	scanMiB = 1 << 20
	scanGiB = 1 << 30
	// scanBlockSize is the memory block size of the topologies.
	scanBlockSize = 128 * scanMiB
)

// scanTopology is a node of the characterization of the scans: a sysfs
// tree under root (with sys and proc) that pkg/cxl's reader and the kernel
// both read, the kernel on it and the serials of its memdevs.
type scanTopology struct {
	root    string
	k       *kernel.Kernel
	serials []uint64
}

// scanDevice is a device of a scan as the characterization pins it: the
// device of the ResourceSlice, and what a Prepare takes from the device of
// the table: the result of a region, the DRAM or the lease device, and the
// local memdev.
type scanDevice struct {
	Device resourcev1.Device `json:"device"`
	Result *state.Result     `json:"result,omitempty"`
	Memdev *device.Memdev    `json:"memdev,omitempty"`
}

// scanCase is a configuration of the publisher of a scan.
type scanCase struct {
	cfg        PublishConfig
	pool, held map[uint64]bool
	local      *LocalSnapshot
}

// scanCases returns the configurations of the publisher that the
// characterization applies to every topology with the serials.
func scanCases(serials []uint64) map[string]scanCase {
	managed := func() *LocalSnapshot {
		return &LocalSnapshot{Uses: map[uint64]LocalUse{}, Probed: map[uint64]uint64{}, BlockSize: scanBlockSize}
	}
	at := func(i int) uint64 { return serials[i%len(serials)] }
	shared := []string{}
	used := managed()
	for i, s := range serials {
		shared = append(shared, fmt.Sprintf("0x%x", s))
		used.Uses[s] = LocalUse{Shared: i == len(serials)-1, Claims: []string{"claim-a"}}
	}
	return map[string]scanCase{
		"unmanaged": {cfg: PublishConfig{PublishLeaseDevice: true}},
		"managed":   {cfg: PublishConfig{ManageMemdevs: true}, local: managed()},
		"ignored": {cfg: PublishConfig{ManageMemdevs: true, IgnoreRegions: []string{"region1"}, IgnoreNodes: []int{3},
			IgnoreDevices: []string{"mem0", "cxl/mem1", "251:2", strconv.FormatUint(at(3), 10), strconv.FormatUint(at(4), 16)}},
			local: managed()},
		"shared": {cfg: PublishConfig{ManageMemdevs: true, SharedDevices: shared}, local: managed()},
		"pool":   {cfg: PublishConfig{ManageMemdevs: true}, pool: map[uint64]bool{at(0): true}, held: map[uint64]bool{at(1): true}, local: managed()},
		"used":   {cfg: PublishConfig{ManageMemdevs: true, IgnoreDRAMNodes: true}, local: used},
	}
}

// scanTopologies returns the builders of the topologies by name.
func scanTopologies() map[string]func(t *testing.T) scanTopology {
	return map[string]func(t *testing.T) scanTopology{
		"fake-empty":                 scanFakeEmpty,
		"fake-memdevs":               scanFakeMemdevs,
		"fake-regions":               scanFakeRegions,
		"fake-hollow":                scanFakeHollow,
		"fake-pmem":                  scanFakePmem,
		"test14-node-four-claims":    scanDump("test14-node-four-claims"),
		"test14-node-numa-b-deleted": scanDump("test14-node-numa-b-deleted"),
	}
}

// scanDevices returns the devices of a scan of the topology with the
// configuration, as the characterization pins them.
func scanDevices(t *testing.T, top scanTopology, c scanCase) map[string]scanDevice {
	t.Helper()
	detected, err := nricxl.DevicesFromSysfs(top.root)
	if err != nil {
		t.Fatal(err)
	}
	devs := BuildDevices(c.cfg, detected, c.pool, c.held, c.local)
	out := map[string]scanDevice{}
	for _, d := range resources(devs) {
		sd := scanDevice{Device: d}
		switch dev := devs[d.Name].Dev.(type) {
		case *device.Memdev:
			sd.Memdev = dev
		default:
			sd.Result = &state.Result{Device: d.Name}
			r := &resourcev1.DeviceRequestAllocationResult{Device: d.Name}
			if err := otherResult(sd.Result, r, dev, config.Device{}); err != nil {
				t.Fatalf("%s: %v", d.Name, err)
			}
		}
		out[d.Name] = sd
	}
	return out
}

// TestCharScanTopologies pins the devices that the publisher builds of
// scans of node topologies (kernel/fake nodes, the sysfs dumps of
// pkg/cxl/testdata) with a set of configurations: the devices of the
// ResourceSlice and the facts of the table that a Prepare reads. The
// expected devices are in testdata/scan-<topology>.txt, a line per
// configuration and device (go test -update writes them).
func TestCharScanTopologies(t *testing.T) {
	for name, build := range scanTopologies() {
		t.Run(name, func(t *testing.T) {
			top := build(t)
			var data []byte
			cases := scanCases(top.serials)
			for _, c := range slices.Sorted(maps.Keys(cases)) {
				devs := scanDevices(t, top, cases[c])
				for _, name := range slices.Sorted(maps.Keys(devs)) {
					line, err := json.Marshal(devs[name])
					mustOK(t, err)
					data = fmt.Appendf(data, "%s %s %s\n", c, name, line)
				}
			}
			golden := filepath.Join("testdata", "scan-"+name+".txt")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, data, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, want) {
				t.Errorf("the devices differ from %s:\n%s", golden, data)
			}
		})
	}
}

// scanFake returns the topology of a fake with the memdevs plugged, after
// fn changed it, with the files of pkg/cxl's reader that the fake does not
// write (scanReaderFiles).
func scanFake(t *testing.T, specs []fake.MemdevSpec, fn func(f *fake.Fake, k *kernel.Kernel)) scanTopology {
	t.Helper()
	f := fake.New(t)
	top := scanTopology{root: filepath.Dir(f.SysRoot()), k: f.Kernel()}
	for _, s := range specs {
		f.Plug(s)
		top.serials = append(top.serials, s.Serial)
	}
	if fn != nil {
		fn(f, top.k)
	}
	scanReaderFiles(t, f)
	return top
}

// scanFakeEmpty is a node without memdevs: the DRAM of nodes 0 and 1 and
// the empty nodes of the windows.
func scanFakeEmpty(t *testing.T) scanTopology {
	top := scanFake(t, nil, nil)
	top.serials = []uint64{0xffff}
	return top
}

// scanFakeMemdevs is a node with memdevs without regions: of RAM under
// both host bridges, behind a switch, of persistent memory, of both, and a
// disabled one.
func scanFakeMemdevs(t *testing.T) scanTopology {
	return scanFake(t, []fake.MemdevSpec{
		{Serial: 0xa0, Ram: scanGiB},
		{Serial: 0xa1, Ram: 512 * scanMiB, HostBridge: 24},
		{Serial: 0xa2, Pmem: scanGiB},
		{Serial: 0xa3, Ram: scanGiB, Disabled: true},
		{Serial: 0xa4, Ram: scanGiB, Pmem: 512 * scanMiB, HostBridge: 24, Switch: true},
		{Serial: 0xa5, Ram: 192 * scanMiB},
	}, nil)
}

// scanRegion returns a region of the type created on the memdev.
func scanRegion(t *testing.T, k *kernel.Kernel, memdev, typ string, size uint64) string {
	t.Helper()
	d, err := k.RootDecoder(memdev, typ)
	mustOK(t, err)
	r, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: memdev, Decoder: d, Type: typ, Size: size})
	mustOK(t, err)
	return r
}

// scanOnline onlines the memory of the dax devices of a region.
func scanOnline(t *testing.T, k *kernel.Kernel, region string) {
	t.Helper()
	for _, dax := range k.DaxDevices(region) {
		blocks, err := k.DaxDeviceBlocks(dax, scanBlockSize)
		mustOK(t, err)
		mustOK(t, k.OnlineBlocks(blocks, true))
	}
}

// scanFakeRegions is a node with regions that the driver did not create:
// with online memory, with offline memory, with an empty dax device only,
// with two devdax devices beside the empty one, a disabled one with online
// memory left, and two regions on one memdev.
func scanFakeRegions(t *testing.T) scanTopology {
	ctx := context.Background()
	return scanFake(t, []fake.MemdevSpec{
		{Serial: 0xb0, Ram: scanGiB},
		{Serial: 0xb1, Ram: scanGiB, HostBridge: 24},
		{Serial: 0xb2, Ram: scanGiB},
		{Serial: 0xb3, Ram: scanGiB, HostBridge: 24},
		{Serial: 0xb4, Ram: scanGiB},
		{Serial: 0xb5, Ram: scanGiB, HostBridge: 24},
	}, func(f *fake.Fake, k *kernel.Kernel) {
		online := scanRegion(t, k, "mem0", kernel.RegionRAM, 512*scanMiB)
		scanOnline(t, k, online)
		scanRegion(t, k, "mem1", kernel.RegionRAM, 512*scanMiB)
		empty := scanRegion(t, k, "mem2", kernel.RegionRAM, 512*scanMiB)
		mustOK(t, k.ResizeDaxDevice(ctx, k.DaxDevices(empty)[0], 0))
		devdax := scanRegion(t, k, "mem3", kernel.RegionRAM, 512*scanMiB)
		mustOK(t, k.ResizeDaxDevice(ctx, k.DaxDevices(devdax)[0], 0))
		for range 2 {
			dax, err := k.CreateDaxDevice(ctx, devdax, 128*scanMiB)
			mustOK(t, err)
			mustOK(t, k.BindDax(ctx, dax, kernel.DriverDeviceDax))
		}
		disabled := scanRegion(t, k, "mem4", kernel.RegionRAM, 256*scanMiB)
		scanOnline(t, k, disabled)
		mustOK(t, k.DisableRegion(ctx, disabled))
		scanOnline(t, k, scanRegion(t, k, "mem5", kernel.RegionRAM, 256*scanMiB))
		scanRegion(t, k, "mem5", kernel.RegionRAM, 256*scanMiB)
	})
}

// scanFakeHollow is a node with hollow regions: one whose memdev was
// removed with its memory online, and one without memory; and a memdev
// with a region beside them.
func scanFakeHollow(t *testing.T) scanTopology {
	top := scanFake(t, []fake.MemdevSpec{{Serial: 0xc0, Ram: scanGiB}, {Serial: 0xc1, Ram: scanGiB, HostBridge: 24}},
		func(f *fake.Fake, k *kernel.Kernel) {
			scanOnline(t, k, scanRegion(t, k, "mem0", kernel.RegionRAM, 512*scanMiB))
			scanRegion(t, k, "mem1", kernel.RegionRAM, 512*scanMiB)
			f.Unplug(0xc0)
			f.HollowRegion("decoder0.1", 256*scanMiB)
		})
	top.serials = top.serials[1:]
	return top
}

// scanFakePmem is a node with memdevs of persistent memory: one with a
// pmem region, one without.
func scanFakePmem(t *testing.T) scanTopology {
	return scanFake(t, []fake.MemdevSpec{{Serial: 0xd0, Pmem: scanGiB}, {Serial: 0xd1, Pmem: scanGiB, HostBridge: 24}},
		func(f *fake.Fake, k *kernel.Kernel) {
			scanRegion(t, k, "mem0", kernel.RegionPmem, 512*scanMiB)
		})
}

// scanReaderFiles writes the files of the memdevs and of procfs that
// pkg/cxl's reader reads and the fake does not write: the uevent of every
// memdev, and /proc/zoneinfo of the online memory blocks (a zone per node
// and zone type, starting at its first online block) and of the DRAM of
// nodes 0 and 1.
func scanReaderFiles(t *testing.T, f *fake.Fake) {
	t.Helper()
	mems, _ := filepath.Glob(f.P("bus/cxl/devices/mem*"))
	for _, p := range mems {
		name := filepath.Base(p)
		rel := "bus/cxl/devices/" + name
		_, minor, _ := strings.Cut(f.Read(rel+"/dev"), ":")
		uevent := "MAJOR=251\nMINOR=" + minor + "\nDEVNAME=cxl/" + name + "\nDEVTYPE=cxl_memdev"
		if f.Exists(rel + "/driver") {
			uevent += "\nDRIVER=cxl_mem"
		}
		f.Write(rel+"/uevent", uevent)
	}
	type zone struct {
		node int
		name string
	}
	start, present := map[zone]int64{}, map[zone]int64{}
	blocks, _ := filepath.Glob(f.P("devices/system/memory/memory[0-9]*"))
	for _, p := range blocks {
		n, _ := strconv.Atoi(strings.TrimPrefix(filepath.Base(p), "memory"))
		rel := "devices/system/memory/" + filepath.Base(p)
		if f.Read(rel+"/state") != kernel.BlockStateOnline {
			continue
		}
		nodes, _ := filepath.Glob(filepath.Join(p, "node[0-9]*"))
		if len(nodes) == 0 {
			continue
		}
		node, _ := strconv.Atoi(strings.TrimPrefix(filepath.Base(nodes[0]), "node"))
		z := zone{node, f.Read(rel + "/valid_zones")}
		pfn := int64(n) * scanBlockSize >> 12
		if s, ok := start[z]; !ok || pfn < s {
			start[z] = pfn
		}
		present[z] += scanBlockSize >> 12
	}
	zones := []string{"Node 0, zone   Normal", "        present  2097152", "  start_pfn:           1",
		"Node 1, zone   Normal", "        present  2097152", "  start_pfn:           2097152"}
	keys := make([]zone, 0, len(start))
	for z := range start {
		keys = append(keys, z)
	}
	slices.SortFunc(keys, func(a, b zone) int { return int(start[a] - start[b]) })
	for _, z := range keys {
		zones = append(zones, fmt.Sprintf("Node %d, zone %8s", z.node, z.name),
			fmt.Sprintf("        present  %d", present[z]), fmt.Sprintf("  start_pfn:           %d", start[z]))
	}
	scanWrite(t, filepath.Join(f.ProcRoot(), "zoneinfo"), strings.Join(zones, "\n"))
}

// scanWrite writes a file and its directories.
func scanWrite(t *testing.T, path, data string) {
	t.Helper()
	mustOK(t, os.MkdirAll(filepath.Dir(path), 0o755))
	mustOK(t, os.WriteFile(path, []byte(data+"\n"), 0o644))
}

// scanDump returns the topology of a sysfs dump of pkg/cxl/testdata,
// captured by the e2e cxl-dump helper with grep -r: "path:line" for the
// files of /sys/bus/cxl/devices/* (cxl-sysfs.txt) and of the memory blocks
// and nodes (memory.txt), and the zones of /proc/zoneinfo. grep -r does not
// capture symlinks: the uport of endpoint4 links to mem0, the device of a
// uevent with DRIVER=<driver> links to <driver>, and the dax bus links to
// the dax devices of the regions; the online file of a memory block comes
// from its state.
func scanDump(name string) func(t *testing.T) scanTopology {
	return func(t *testing.T) scanTopology {
		root := t.TempDir()
		dir := filepath.Join("..", "..", "..", "..", "..", "pkg", "cxl", "testdata", name)
		files := map[string][]string{}
		for _, file := range []string{"cxl-sysfs.txt", "memory.txt"} {
			data, err := os.ReadFile(filepath.Join(dir, file))
			mustOK(t, err)
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				path, value, ok := strings.Cut(line, ":")
				if !ok {
					t.Fatalf("%s/%s: bad line %q", name, file, line)
				}
				files[path] = append(files[path], value)
				if strings.HasSuffix(path, "/state") {
					online := map[bool]string{true: "1", false: "0"}[strings.HasPrefix(value, "online")]
					files[filepath.Join(filepath.Dir(path), "online")] = []string{online}
				}
			}
		}
		zoneinfo, err := os.ReadFile(filepath.Join(dir, "zoneinfo.txt"))
		mustOK(t, err)
		files["/proc/zoneinfo"] = []string{strings.TrimSpace(string(zoneinfo))}
		for path, lines := range files {
			scanWrite(t, filepath.Join(root, path), strings.Join(lines, "\n"))
		}
		link := func(path, target string) {
			mustOK(t, os.MkdirAll(filepath.Dir(path), 0o755))
			mustOK(t, os.Symlink(target, path))
		}
		devices := filepath.Join(root, "sys/bus/cxl/devices")
		link(filepath.Join(devices, "endpoint4", "uport"), filepath.Join(devices, "mem0"))
		for path, lines := range files {
			for _, l := range lines {
				if driver, ok := strings.CutPrefix(l, "DRIVER="); ok && filepath.Base(path) == "uevent" {
					target := filepath.Join(root, "sys/bus/drivers", driver)
					mustOK(t, os.MkdirAll(target, 0o755))
					link(filepath.Join(root, filepath.Dir(path), "driver"), target)
				}
			}
		}
		daxes, _ := filepath.Glob(filepath.Join(devices, "region*", "dax_region*", "dax*.*"))
		for _, p := range daxes {
			link(filepath.Join(root, "sys/bus/dax/devices", filepath.Base(p)), p)
		}
		return scanTopology{root: root, k: &kernel.Kernel{SysRoot: filepath.Join(root, "sys"), ProcRoot: filepath.Join(root, "proc")},
			serials: []uint64{0xc100e2e1}}
	}
}
