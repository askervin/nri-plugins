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
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/containers/nri-plugins/pkg/cxl/device"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

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
	cfg := PublishConfig{IgnoreRegions: []string{"region0"}}
	devs := BuildDevices(cfg, charRegions(), nil, nil, nil)
	if got := pubNames(devs); !slices.Equal(got, []string{"dram", "region1-node3"}) {
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
	cfg := PublishConfig{IgnoreNodes: []int{3}}
	devs := BuildDevices(cfg, charRegions(), nil, nil, nil)
	if got := pubNames(devs); !slices.Equal(got, []string{"dram", "region0-node2"}) {
		t.Fatalf("published %v", got)
	}
	wantLogLineText(t, logs(), `- ignoring region device "region1": region is on node 3`)

	logs = captureKlogV(t, "4")
	cfg = PublishConfig{IgnoreRegions: []string{"region0"}, IgnoreNodes: []int{2}}
	devs = BuildDevices(cfg, charRegions(), nil, nil, nil)
	if got := pubNames(devs); !slices.Equal(got, []string{"dram", "region1-node3"}) {
		t.Fatalf("published %v", got)
	}
	out := logs()
	wantLogLineText(t, out, `- ignoring region device "region0": region name "region0"`)
	if strings.Contains(out, "region is on node 2") {
		t.Fatalf("region0 logged with a second reason:\n%s", out)
	}
}

// TestCharPublishOrder: the devices of the node's ResourceSlice are the
// devices of the scan sorted by name, so two Resources calls are equal; a
// periodic rescan that finds the same devices does not log that it changed
// them.
func TestCharPublishOrder(t *testing.T) {
	names := []string{"memdev-a5", device.DRAMDeviceName, "memdev-a1", "region0-node2", device.LeaseDeviceName}
	devs := device.DevicesInfo{
		"memdev-a5":            {Name: "memdev-a5", Dev: &device.Memdev{Name: "mem5", Serial: 0xa5, Size: 1 << 30, NodeAffinity: -1, BlockSize: pubBlockSize}},
		device.DRAMDeviceName:  {Name: device.DRAMDeviceName, Dev: &device.DRAM{Nodes: []int{0}, Size: 1 << 30}},
		"memdev-a1":            {Name: "memdev-a1", Dev: &device.Memdev{Name: "mem1", Serial: 0xa1, Size: 1 << 30, NodeAffinity: -1, BlockSize: pubBlockSize}},
		"region0-node2":        {Name: "region0-node2", Dev: &nricxl.RegionDevice{Name: "region0", Size: 1 << 30, Node: 2, Enabled: true}},
		device.LeaseDeviceName: {Name: device.LeaseDeviceName, Dev: &device.LeaseToken{}},
	}
	p := pubPublisher(t, PublishOptions{NodeName: pubNode})
	p.SetDevices(devs)
	order := func() []string {
		var out []string
		for _, d := range p.Resources().Pools[pubNode].Slices[0].Devices {
			out = append(out, d.Name)
		}
		return out
	}
	want := slices.Sorted(slices.Values(names))
	if first, second := order(), order(); !slices.Equal(first, want) || !slices.Equal(second, want) {
		t.Fatalf("published %v and %v, expected %v in that order", first, second, want)
	}
	if !reflect.DeepEqual(p.Resources(), p.Resources()) {
		t.Fatal("two calls of Resources differ")
	}

	q := pubPublisher(t, PublishOptions{
		Config:   PublishConfig{IgnoreDRAMNodes: true, PublishLeaseDevice: true},
		NodeName: pubNode,
		Scan:     func() (*nricxl.Devices, error) { return nricxl.NewDevices(), nil },
	})
	q.Rescan(context.Background(), false)
	logs := captureKlogV(t, "4")
	q.Rescan(context.Background(), true)
	out := logs()
	if strings.Contains(out, "the periodic rescan changed the devices") {
		t.Fatalf("a periodic rescan of the same devices changed them:\n%s", out)
	}
	wantLogLineText(t, out, "rescanAndPublish: rescanning devices")
}

// TestCharPersistentCapacityOfRAMMemdev: a memdev with RAM and persistent
// capacity is published by its RAM as a sliced local memdev, and the
// unused persistent capacity is logged at klog V(3).
func TestCharPersistentCapacityOfRAMMemdev(t *testing.T) {
	logs := captureKlogV(t, "3")
	m := pubMemdev()
	m.PmemSize = 256 * pubMiB
	devs := BuildDevices(PublishConfig{IgnoreDRAMNodes: true, ManageMemdevs: true}, &nricxl.Devices{MemoryDevices: []*nricxl.MemoryDevice{m}}, nil, nil,
		&LocalSnapshot{BlockSize: pubBlockSize})
	dev, ok := devs[pubLocalDeviceName]
	if !ok {
		t.Fatalf("published %v", pubNames(devs))
	}
	md, ok := dev.Dev.(*device.Memdev)
	if !ok || md.Persistent || md.Size != pubRegionSize || md.BlockSize != pubBlockSize {
		t.Fatalf("memdev %+v", dev.Dev)
	}
	attrs := LocalMemdevDevice(pubLocalDeviceName, md).Attributes
	if p := attrs[device.AttrPersistent].BoolValue; p == nil || *p {
		t.Fatalf("attributes %+v", attrs)
	}
	if bs := attrs[device.AttrMemoryBlockSize].IntValue; bs == nil || *bs != pubBlockSize {
		t.Fatalf("attributes %+v", attrs)
	}
	wantLogLineText(t, logs(), `- memory device "mem0": persistent capacity of a memdev with RAM capacity is not used`)
}
