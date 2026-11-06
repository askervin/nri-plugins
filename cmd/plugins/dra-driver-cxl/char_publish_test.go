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
	"bytes"
	"context"
	"flag"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"k8s.io/klog/v2"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// captureKlogV returns the klog output of the test at verbosity v.
func captureKlogV(t *testing.T, v string) func() string {
	t.Helper()
	fs := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(fs)
	noErr(t, fs.Set("logtostderr", "false"))
	noErr(t, fs.Set("alsologtostderr", "false"))
	noErr(t, fs.Set("v", v))
	var mu sync.Mutex
	var buf bytes.Buffer
	klog.SetOutput(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}))
	t.Cleanup(func() {
		klog.Flush()
		_ = fs.Set("logtostderr", "true")
		_ = fs.Set("v", "0")
	})
	return func() string {
		klog.Flush()
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

// wantLogLineText fails the test unless a line of the log ends with text.
func wantLogLineText(t *testing.T, log, text string) {
	t.Helper()
	for _, line := range strings.Split(log, "\n") {
		if strings.HasSuffix(line, text) {
			return
		}
	}
	t.Fatalf("no log line ends with %q:\n%s", text, log)
}

// charRegions returns the detected devices of two regions of memdevs that
// are not the driver's, region0 on node 2 and region1 on node 3, and the
// DRAM nodes 0, 2 and 3.
func charRegions() *nricxl.Devices {
	mem := func(name string, serial uint64) *nricxl.MemoryDevice {
		return &nricxl.MemoryDevice{Name: name, DevName: "cxl/" + name, RamSize: 1 << 30, Serial: serial, NodeAffinity: 0, Enabled: true}
	}
	m0, m1 := mem("mem0", 0xb0), mem("mem1", 0xb1)
	region := func(name string, node int, m *nricxl.MemoryDevice) *nricxl.RegionDevice {
		return &nricxl.RegionDevice{Name: name, Size: 1 << 30, Mode: "ram", Node: node, Enabled: true, Memories: []*nricxl.MemoryDevice{m}}
	}
	return &nricxl.Devices{
		MemoryDevices: []*nricxl.MemoryDevice{m0, m1},
		RegionDevices: []*nricxl.RegionDevice{region("region0", 2, m0), region("region1", 3, m1)},
		MemoryNodes:   []*nricxl.MemoryNode{{ID: 0, Size: 1 << 30}, {ID: 2, Size: 1 << 30}, {ID: 3, Size: 1 << 30}},
	}
}

// TestCharIgnoreRegions: a region of ignoreRegions is not published, with
// the reason at klog V(4); its node still counts as a CXL node, not as
// DRAM.
func TestCharIgnoreRegions(t *testing.T) {
	logs := captureKlogV(t, "4")
	cfg := &DriverConfig{IgnoreRegions: []string{"region0"}, ManageMemdevs: ptr(false)}
	devs, err := buildDevInfos(cfg, charRegions(), nil, nil)
	noErr(t, err)
	if got := slices.Sorted(maps.Keys(devs)); !slices.Equal(got, []string{"dram", "region1-node3"}) {
		t.Fatalf("published %v", got)
	}
	if dram := devs[device.DRAMDeviceName].Dev.(*device.DRAM); !slices.Equal(dram.Nodes, []int{0}) {
		t.Fatalf("DRAM nodes %v: the node of an ignored region is not DRAM", dram.Nodes)
	}
	wantLogLineText(t, logs(), `- ignoring region device "region0": region name "region0"`)
}

// TestCharIgnoreNodes: a region on a node of ignoreNodes is not published,
// with the reason at klog V(4); a region that both ignoreRegions and
// ignoreNodes refuse has the reason of ignoreRegions only.
func TestCharIgnoreNodes(t *testing.T) {
	logs := captureKlogV(t, "4")
	cfg := &DriverConfig{IgnoreNodes: []int{3}, ManageMemdevs: ptr(false)}
	devs, err := buildDevInfos(cfg, charRegions(), nil, nil)
	noErr(t, err)
	if got := slices.Sorted(maps.Keys(devs)); !slices.Equal(got, []string{"dram", "region0-node2"}) {
		t.Fatalf("published %v", got)
	}
	wantLogLineText(t, logs(), `- ignoring region device "region1": region is on node 3`)

	logs = captureKlogV(t, "4")
	cfg = &DriverConfig{IgnoreRegions: []string{"region0"}, IgnoreNodes: []int{2}, ManageMemdevs: ptr(false)}
	devs, err = buildDevInfos(cfg, charRegions(), nil, nil)
	noErr(t, err)
	if got := slices.Sorted(maps.Keys(devs)); !slices.Equal(got, []string{"dram", "region1-node3"}) {
		t.Fatalf("published %v", got)
	}
	out := logs()
	wantLogLineText(t, out, `- ignoring region device "region0": region name "region0"`)
	if strings.Contains(out, "region is on node 2") {
		t.Fatalf("region0 logged with a second reason:\n%s", out)
	}
}

// TestCharPublishOrder: the devices of the node's ResourceSlice are the
// devices of the scan, in no particular order (GetResources ranges over a
// map: two calls give the same set); a periodic rescan that finds the same
// devices does not log that it changed them.
func TestCharPublishOrder(t *testing.T) {
	names := []string{"memdev-a5", device.DRAMDeviceName, "memdev-a1", "region0-node2", device.LeaseDeviceName}
	devs := device.DevicesInfo{
		"memdev-a5":            {Name: "memdev-a5", Dev: &device.Memdev{Name: "mem5", Serial: 0xa5, Size: 1 << 30, NodeAffinity: -1, BlockSize: localBlockSize}},
		device.DRAMDeviceName:  {Name: device.DRAMDeviceName, Dev: &device.DRAM{Nodes: []int{0}, Size: 1 << 30}},
		"memdev-a1":            {Name: "memdev-a1", Dev: &device.Memdev{Name: "mem1", Serial: 0xa1, Size: 1 << 30, NodeAffinity: -1, BlockSize: localBlockSize}},
		"region0-node2":        {Name: "region0-node2", Dev: &nricxl.RegionDevice{Name: "region0", Size: 1 << 30, Node: 2, Enabled: true}},
		device.LeaseDeviceName: {Name: device.LeaseDeviceName, Dev: &device.LeaseToken{}},
	}
	s := &nodeState{baseState: &baseState{Allocatable: devs, NodeName: testNode}}
	set := func() []string {
		var out []string
		for _, d := range s.GetResources().Pools[testNode].Slices[0].Devices {
			out = append(out, d.Name)
		}
		slices.Sort(out)
		return out
	}
	first, second := set(), set()
	if want := slices.Sorted(slices.Values(names)); !slices.Equal(first, want) || !slices.Equal(second, want) {
		t.Fatalf("published %v and %v, expected the set %v", first, second, want)
	}

	root := t.TempDir()
	for _, dir := range []string{"sys/bus/cxl/devices", "sys/devices/system/node"} {
		noErr(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
	}
	d := &driver{
		sysfsRoot: root,
		config:    &DriverConfig{IgnoreDRAMNodes: true, PublishLeaseDevice: true},
		state:     nodeState{baseState: &baseState{NodeName: testNode}},
	}
	d.rescanAndPublish(context.Background())
	logs := captureKlogV(t, "4")
	d.rescan(context.Background(), true)
	if out := logs(); strings.Contains(out, "the periodic rescan changed the devices") {
		t.Fatalf("a periodic rescan of the same devices changed them:\n%s", out)
	}
}

// TestCharPersistentCapacityOfRAMMemdev: a memdev with RAM and persistent
// capacity is published by its RAM as a sliced local memdev, and the
// unused persistent capacity is logged at klog V(3).
func TestCharPersistentCapacityOfRAMMemdev(t *testing.T) {
	logs := captureKlogV(t, "3")
	m := localMemdev()
	m.PmemSize = 256 * mib
	devs, err := buildDevInfos(&DriverConfig{IgnoreDRAMNodes: true}, &nricxl.Devices{MemoryDevices: []*nricxl.MemoryDevice{m}}, nil,
		&localSnapshot{BlockSize: localBlockSize})
	noErr(t, err)
	dev, ok := devs[localDeviceName]
	if !ok {
		t.Fatalf("published %v", slices.Sorted(maps.Keys(devs)))
	}
	md, ok := dev.Dev.(*device.Memdev)
	if !ok || md.Persistent || md.Size != localRegionSize || md.BlockSize != localBlockSize {
		t.Fatalf("memdev %+v", dev.Dev)
	}
	attrs := localMemdevDevice(localDeviceName, md).Attributes
	if p := attrs[device.AttrPersistent].BoolValue; p == nil || *p {
		t.Fatalf("attributes %+v", attrs)
	}
	if bs := attrs[device.AttrMemoryBlockSize].IntValue; bs == nil || *bs != localBlockSize {
		t.Fatalf("attributes %+v", attrs)
	}
	wantLogLineText(t, logs(), `- memory device "mem0": persistent capacity of a memdev with RAM capacity is not used`)
}
