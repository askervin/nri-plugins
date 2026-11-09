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
	"flag"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/compat"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/device"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

// The helpers of the tests of the publisher have the prefix pub (or a name
// of their own) so that they do not clash with those of the other tests of
// the package.
const (
	pubNode = "node1"
	pubNS   = "demo"
	// pubLocalSerial is the local memdev of pubMemdev, published as
	// pubLocalDeviceName.
	pubLocalSerial     = 0xc100e2e1
	pubLocalDeviceName = "memdev-c100e2e1"
	pubMiB             = 1 << 20
	// pubRegionSize is the size of the local memdev and its region.
	pubRegionSize = 1 << 30
	// pubBlockSize is the memory block size of the tests.
	pubBlockSize = 128 * pubMiB
)

// pubMemdev returns the detected local memdev pubLocalSerial.
func pubMemdev() *nricxl.MemoryDevice {
	return &nricxl.MemoryDevice{
		Name: "mem0", DevName: "cxl/mem0", SysfsPath: "/sys/bus/cxl/devices/mem0", RamSize: pubRegionSize,
		Serial: pubLocalSerial, NodeAffinity: 0, Driver: "cxl_mem", Major: 251, Minor: 0, Enabled: true,
	}
}

func pubNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// pubStore returns a new store in a temporary directory, closed at the end
// of the test.
func pubStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), store.Options{Dir: t.TempDir(), BootID: "boot-1"})
	pubNoErr(t, err)
	t.Cleanup(func() { pubNoErr(t, st.Close()) })
	return st
}

// pubPublisher returns the publisher of opts, with a new store and a scan
// of no devices where opts has none.
func pubPublisher(t *testing.T, opts PublishOptions) *Publisher {
	t.Helper()
	if opts.Store == nil {
		opts.Store = pubStore(t)
	}
	if opts.Scan == nil {
		opts.Scan = func() (*nricxl.Devices, error) { return nricxl.NewDevices(), nil }
	}
	p, err := NewPublisher(opts)
	pubNoErr(t, err)
	return p
}

// pubNames returns the names of the devices, sorted.
func pubNames(devs device.DevicesInfo) []string {
	return slices.Sorted(maps.Keys(devs))
}

// captureKlogV makes klog write to a buffer at verbosity v for the test,
// each line once, and returns a function that returns the output so far.
func captureKlogV(t *testing.T, v string) func() string {
	t.Helper()
	fs := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(fs)
	pubNoErr(t, fs.Set("logtostderr", "false"))
	pubNoErr(t, fs.Set("alsologtostderr", "false"))
	pubNoErr(t, fs.Set("one_output", "true"))
	pubNoErr(t, fs.Set("v", v))
	var mu sync.Mutex
	var buf bytes.Buffer
	klog.SetOutput(pubLogWriter(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}))
	t.Cleanup(func() {
		klog.Flush()
		_ = fs.Set("logtostderr", "true")
		_ = fs.Set("one_output", "false")
		_ = fs.Set("v", "0")
	})
	return func() string {
		klog.Flush()
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

type pubLogWriter func(p []byte) (int, error)

func (f pubLogWriter) Write(p []byte) (int, error) { return f(p) }

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

// logMatches returns the number of lines of the log that match, by
// compat.Matches, the template with the replacements of the replacer.
func logMatches(log, template string, replace ...string) int {
	template = strings.NewReplacer(replace...).Replace(template)
	n := 0
	for _, line := range strings.Split(log, "\n") {
		if compat.Matches(template, line) {
			n++
		}
	}
	return n
}

// TestBuildDevInfosLocalMemdevs pins the local memdevs that a scan
// publishes: free and used ones of at least a memory block of a known
// size, not pooled, ignored, disabled or without RAM; the node of the
// plugin's region is not DRAM; without managed memdevs regions only.
func TestBuildDevInfosLocalMemdevs(t *testing.T) {
	memdev := func(name string, serial uint64) *nricxl.MemoryDevice {
		return &nricxl.MemoryDevice{Name: name, DevName: "cxl/" + name, RamSize: 1 << 30, Serial: serial, NodeAffinity: -1, Enabled: true}
	}
	free, foreign, pooled, ignored, used := memdev("mem1", 0xa1), memdev("mem2", 0xa2), memdev("mem3", 0xa3), memdev("mem4", 0xa4), memdev("mem5", 0xa5)
	free.NodeAffinity = 1
	disabled, noRAM := memdev("mem6", 0xa6), memdev("mem7", 0xa7)
	disabled.Enabled = false
	noRAM.RamSize = 0
	region := func(name string, node int, mem *nricxl.MemoryDevice) *nricxl.RegionDevice {
		return &nricxl.RegionDevice{Name: name, Size: 1 << 30, Mode: "ram", Node: node, Enabled: true, Memories: []*nricxl.MemoryDevice{mem}}
	}
	devices := &nricxl.Devices{
		MemoryDevices: []*nricxl.MemoryDevice{free, foreign, pooled, ignored, used, disabled, noRAM},
		RegionDevices: []*nricxl.RegionDevice{region("region0", 2, foreign), region("region1", 3, used)},
		MemoryNodes:   []*nricxl.MemoryNode{{ID: 0, Size: 1 << 30}, {ID: 2, Size: 1 << 30}, {ID: 3, Size: 1 << 30}},
	}
	cfg := PublishConfig{IgnoreDevices: []string{"0xa4"}, ManageMemdevs: true}
	local := &LocalSnapshot{Uses: map[uint64]LocalUse{0xa5: {}}, BlockSize: pubBlockSize}
	pool := map[uint64]bool{0xa3: true}
	devInfos := BuildDevices(cfg, devices, pool, nil, local)
	got := pubNames(devInfos)
	want := []string{"dram", "memdev-a1", "memdev-a5", "region0-node2"}
	if !slices.Equal(got, want) {
		t.Fatalf("published %v, expected %v", got, want)
	}
	for name, d := range devInfos {
		if d.Name != name {
			t.Fatalf("device %s named %s", name, d.Name)
		}
	}
	if m, ok := devInfos["memdev-a1"].Dev.(*device.Memdev); !ok || *m != (device.Memdev{Name: "mem1", Serial: 0xa1, Size: 1 << 30, NodeAffinity: 1, BlockSize: pubBlockSize}) {
		t.Fatalf("free memdev %+v", devInfos["memdev-a1"].Dev)
	}
	if _, ok := devInfos["memdev-a5"].Dev.(*device.Memdev); !ok {
		t.Fatalf("used memdev %+v", devInfos["memdev-a5"].Dev)
	}
	// memdevs smaller than a block, or an unknown block size: none
	free.RamSize = pubBlockSize - 2*pubMiB
	devInfos = BuildDevices(cfg, devices, pool, nil, local)
	if _, ok := devInfos["memdev-a1"]; ok {
		t.Fatal("a memdev smaller than a memory block published")
	}
	free.RamSize = pubBlockSize
	// a block of 512 MiB is not sure to fit 512 MiB
	devInfos = BuildDevices(cfg, devices, pool, nil, &LocalSnapshot{Uses: local.Uses, BlockSize: pubBlockSize * 4})
	if _, ok := devInfos["memdev-a1"]; ok {
		t.Fatal("a memdev of one large block published")
	}
	m, ok := devInfos["memdev-a5"].Dev.(*device.Memdev)
	if !ok {
		t.Fatalf("used memdev %+v", devInfos["memdev-a5"])
	}
	if c := LocalMemdevDevice("x", m).Capacity["memory"]; c.Value.Value() != 512*pubMiB {
		t.Fatalf("capacity %v of a 1 GiB memdev with 512 MiB blocks", c.Value)
	}
	devInfos = BuildDevices(cfg, devices, pool, nil, &LocalSnapshot{Uses: local.Uses})
	if got := pubNames(devInfos); !slices.Equal(got, []string{"dram", "region0-node2"}) {
		t.Fatalf("published %v without a block size", got)
	}
	// the node of the plugin's region is not DRAM
	if dram, ok := devInfos["dram"].Dev.(*device.DRAM); !ok || !slices.Equal(dram.Nodes, []int{0}) {
		t.Fatalf("DRAM %+v", devInfos["dram"].Dev)
	}

	// manageMemdevs: false publishes regions only
	cfg.ManageMemdevs = false
	devInfos = BuildDevices(cfg, devices, pool, nil, nil)
	if got := pubNames(devInfos); !slices.Equal(got, []string{"dram", "region0-node2", "region1-node3"}) {
		t.Fatalf("published %v without managed memdevs", got)
	}
}

// TestGetResourcesLocalMemdev pins the published device of a local memdev:
// its attributes, its capacity with the request policy of memory blocks,
// no nodeAffinity when unknown.
func TestGetResourcesLocalMemdev(t *testing.T) {
	devs := BuildDevices(PublishConfig{IgnoreDRAMNodes: true, ManageMemdevs: true}, &nricxl.Devices{MemoryDevices: []*nricxl.MemoryDevice{pubMemdev()}},
		nil, nil, &LocalSnapshot{BlockSize: pubBlockSize})
	p := pubPublisher(t, PublishOptions{NodeName: pubNode})
	p.SetDevices(devs)
	got := p.Resources().Pools[pubNode].Slices[0].Devices
	q := func(v int64) *resource.Quantity { return resource.NewQuantity(v, resource.BinarySI) }
	want := []resourcev1.Device{{
		Name: pubLocalDeviceName,
		Attributes: map[resourcev1.QualifiedName]resourcev1.DeviceAttribute{
			"type":            {StringValue: ptr("memdev")},
			"source":          {StringValue: ptr("local")},
			"serial":          {StringValue: ptr("0xc100e2e1")},
			"shared":          {BoolValue: ptr(false)},
			"persistent":      {BoolValue: ptr(false)},
			"size":            {IntValue: ptr(int64(pubRegionSize))},
			"nodeAffinity":    {IntValue: ptr(int64(0))},
			"memoryBlockSize": {IntValue: ptr(int64(134217728))},
		},
		Capacity: map[resourcev1.QualifiedName]resourcev1.DeviceCapacity{
			"memory": {
				Value: *q(pubRegionSize),
				RequestPolicy: &resourcev1.CapacityRequestPolicy{
					Default:    q(pubRegionSize),
					ValidRange: &resourcev1.CapacityRequestPolicyRange{Min: q(134217728), Step: q(134217728)},
				},
			},
		},
		NodeAllocatableResources: MemoryNodeAllocatableResources(),
		AllowMultipleAllocations: ptr(true),
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("published\n%+v\nexpected\n%+v", got, want)
	}
	if p := got[0].Capacity["memory"].RequestPolicy; p.Default.String() != "1Gi" || p.ValidRange.Min.String() != "128Mi" || p.ValidRange.Step.String() != "128Mi" {
		t.Fatalf("request policy %v %v %v", p.Default, p.ValidRange.Min, p.ValidRange.Step)
	}
	// no nodeAffinity when unknown
	d := LocalMemdevDevice("x", &device.Memdev{Size: pubRegionSize, NodeAffinity: -1, BlockSize: pubBlockSize})
	if _, ok := d.Attributes["nodeAffinity"]; ok {
		t.Fatalf("memdev %+v", d)
	}
}

// TestGetResourcesRegionDRAMLease pins the devices of regions, DRAM and the
// lease device: every memory device has type, source and size, a region
// the nodeAffinity of its memdevs when they agree.
func TestGetResourcesRegionDRAMLease(t *testing.T) {
	mem := func(affinity int) *nricxl.MemoryDevice {
		return &nricxl.MemoryDevice{Serial: 1, NodeAffinity: affinity, Enabled: true}
	}
	devices := &nricxl.Devices{
		RegionDevices: []*nricxl.RegionDevice{
			{Name: "region0", Size: 2 << 30, Mode: "ram", Node: 2, Enabled: true, Memories: []*nricxl.MemoryDevice{mem(0), mem(0)}},
			{Name: "region1", Size: 1 << 30, Mode: "ram", Node: 3, Enabled: true, Memories: []*nricxl.MemoryDevice{mem(0), mem(1)}},
		},
		MemoryNodes: []*nricxl.MemoryNode{{ID: 0, Size: 1 << 30}, {ID: 1, Size: 1 << 30}, {ID: 2, Size: 2 << 30}, {ID: 3, Size: 1 << 30}},
	}
	devs := BuildDevices(PublishConfig{PublishLeaseDevice: true}, devices, nil, nil, nil)
	p := pubPublisher(t, PublishOptions{NodeName: pubNode})
	p.SetDevices(devs)
	got := map[string]resourcev1.Device{}
	for _, d := range p.Resources().Pools[pubNode].Slices[0].Devices {
		got[d.Name] = d
	}
	if names := slices.Sorted(maps.Keys(got)); !slices.Equal(names, []string{"dram", "lease", "region0-node2", "region1-node3"}) {
		t.Fatalf("published %v", names)
	}
	wantAttrs := map[string]map[resourcev1.QualifiedName]resourcev1.DeviceAttribute{
		"region0-node2": {"type": {StringValue: ptr("region")}, "source": {StringValue: ptr("local")}, "node": {IntValue: ptr(int64(2))},
			"size": {IntValue: ptr(int64(2 << 30))}, "nodeAffinity": {IntValue: ptr(int64(0))}},
		// the memdevs of the region do not agree: no nodeAffinity
		"region1-node3": {"type": {StringValue: ptr("region")}, "source": {StringValue: ptr("local")}, "node": {IntValue: ptr(int64(3))},
			"size": {IntValue: ptr(int64(1 << 30))}},
		"dram": {"type": {StringValue: ptr("dram")}, "source": {StringValue: ptr("local")}, "nodes": {StringValue: ptr("0-1")},
			"size": {IntValue: ptr(int64(2 << 30))}},
		"lease": {"type": {StringValue: ptr("lease")}},
	}
	for name, want := range wantAttrs {
		if !reflect.DeepEqual(got[name].Attributes, want) {
			t.Errorf("%s: attributes %+v, expected %+v", name, got[name].Attributes, want)
		}
	}
	for _, name := range []string{"region0-node2", "region1-node3", "dram"} {
		d := got[name]
		c := d.Capacity["memory"]
		if c.Value.Value() != *d.Attributes["size"].IntValue || d.NodeAllocatableResources == nil || !*d.AllowMultipleAllocations {
			t.Errorf("%s: capacity %+v", name, d)
		}
	}
	if l := got["lease"]; l.Capacity != nil || !*l.AllowMultipleAllocations {
		t.Errorf("lease device %+v", l)
	}
	if _, ok := regionNodeAffinity(&nricxl.RegionDevice{Memories: []*nricxl.MemoryDevice{mem(-1)}}); ok {
		t.Error("an unknown affinity is published")
	}
}

// TestLocalRequestPolicy pins the request policy of a local memdev: steps
// of the memory block size, the whole device (its blocks) by default.
func TestLocalRequestPolicy(t *testing.T) {
	q := func(v int64) *resource.Quantity { return resource.NewQuantity(v, resource.BinarySI) }
	for _, tc := range []struct {
		size, bs uint64
		want     *resourcev1.CapacityRequestPolicy
	}{
		{pubRegionSize, pubBlockSize, &resourcev1.CapacityRequestPolicy{Default: q(pubRegionSize),
			ValidRange: &resourcev1.CapacityRequestPolicyRange{Min: q(pubBlockSize), Step: q(pubBlockSize)}}},
		// rounded down to whole blocks
		{pubRegionSize + 64*pubMiB, pubBlockSize, &resourcev1.CapacityRequestPolicy{Default: q(pubRegionSize),
			ValidRange: &resourcev1.CapacityRequestPolicyRange{Min: q(pubBlockSize), Step: q(pubBlockSize)}}},
		{2 * pubBlockSize, pubBlockSize, &resourcev1.CapacityRequestPolicy{Default: q(2 * pubBlockSize),
			ValidRange: &resourcev1.CapacityRequestPolicyRange{Min: q(pubBlockSize), Step: q(pubBlockSize)}}},
		// one block: a range needs room for min and one step
		{pubBlockSize + 64*pubMiB, pubBlockSize, &resourcev1.CapacityRequestPolicy{Default: q(pubBlockSize),
			ValidValues: []resource.Quantity{*q(pubBlockSize)}}},
		{pubRegionSize, 2 << 30, nil},
		{pubRegionSize, 0, nil},
		// blocks larger than the region alignment: the head that a
		// region can have (block size - 256 MiB) is not counted
		{2 << 30, 512 * pubMiB, &resourcev1.CapacityRequestPolicy{Default: q(1536 * pubMiB),
			ValidRange: &resourcev1.CapacityRequestPolicyRange{Min: q(512 * pubMiB), Step: q(512 * pubMiB)}}},
		{768 * pubMiB, 512 * pubMiB, &resourcev1.CapacityRequestPolicy{Default: q(512 * pubMiB),
			ValidValues: []resource.Quantity{*q(512 * pubMiB)}}},
		{512 * pubMiB, 512 * pubMiB, nil},
		{4 << 30, 2 << 30, &resourcev1.CapacityRequestPolicy{Default: q(2 << 30),
			ValidValues: []resource.Quantity{*q(2 << 30)}}},
	} {
		if got := LocalRequestPolicy(tc.size, tc.bs); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("size %d, block size %d: policy %+v, expected %+v", tc.size, tc.bs, got, tc.want)
		}
	}
}

// TestBuildDevInfosHollowRegion pins a hollow region of a scan: it is not
// published, the other devices are, and it is warned about once while it
// stays. The hollow region still has a node: memory of its address range
// that kmem could not remove is online, so the scan finds the node and the
// region enabled; that node is not DRAM either.
func TestBuildDevInfosHollowRegion(t *testing.T) {
	devices := nricxl.NewDevices()
	hollow := &nricxl.RegionDevice{Name: "region1", SysfsPath: "/sys/bus/cxl/devices/region1", Mode: "ram", Resource: 0x850000000, Size: 1 << 28,
		Node: 3, Enabled: true, OnlineSize: 1 << 28, Hollow: true}
	devices.RegionDevices = []*nricxl.RegionDevice{
		{Name: "region0", Size: 1 << 30, Mode: "ram", Node: 2, Enabled: true, Targets: []string{"decoder4.0"},
			Memories: []*nricxl.MemoryDevice{{Name: "mem0", Serial: 0xc100e2e0, Enabled: true}}},
		hollow,
	}
	devices.MemoryNodes = []*nricxl.MemoryNode{{ID: 0, Size: 1 << 30}, {ID: 2, Size: 1 << 30}, {ID: 3, Size: 1 << 28}}
	devInfos := BuildDevices(PublishConfig{ManageMemdevs: true}, devices, nil, nil, nil)
	if devInfos["region0-node2"] == nil || devInfos["region1-node3"] != nil || len(devInfos) != 2 {
		t.Fatalf("devices %v", pubNames(devInfos))
	}
	if dram, ok := devInfos["dram"].Dev.(*device.DRAM); !ok || !slices.Equal(dram.Nodes, []int{0}) {
		t.Fatalf("DRAM %+v", devInfos["dram"])
	}

	h := &hollowRegionLog{warned: map[string]bool{}}
	for i, want := range []int{1, 1, 0} {
		regions := devices.RegionDevices
		if want == 0 {
			regions = regions[:1]
		}
		if got := h.observe(regions); len(got) != want || (want == 1 && !got[hollow]) || len(h.warned) != want {
			t.Fatalf("scan %d: hollow %v, warned %v", i, got, h.warned)
		}
	}
}

// TestSharedLocalPrecedence pins the precedence per memdev: ignoreDevices
// over pool devices over sharedDevices over sliced; any spec form of
// ignoreDevices and sharedDevices matches; a memdev used one way by claims
// is not published the other way until it has none.
func TestSharedLocalPrecedence(t *testing.T) {
	memdev := func(name string, serial uint64) *nricxl.MemoryDevice {
		return &nricxl.MemoryDevice{Name: name, DevName: "cxl/" + name, RamSize: 1 << 30, Serial: serial, NodeAffinity: -1, Enabled: true, Major: 251, Minor: int(serial & 0xf)}
	}
	byName, byDevName, byNumbers, byDecimal, ignored, pooled, sliced, usedSliced, usedShared, foreign :=
		memdev("mem1", 0xa1), memdev("mem2", 0xa2), memdev("mem3", 0xa3), memdev("mem4", 0xa4), memdev("mem5", 0xa5),
		memdev("mem6", 0xa6), memdev("mem7", 0xa7), memdev("mem8", 0xa8), memdev("mem9", 0xa9), memdev("mem10", 0xaa)
	devices := &nricxl.Devices{
		MemoryDevices: []*nricxl.MemoryDevice{byName, byDevName, byNumbers, byDecimal, ignored, pooled, sliced, usedSliced, usedShared, foreign},
		RegionDevices: []*nricxl.RegionDevice{{Name: "region9", Size: 1 << 30, Mode: "ram", Node: 3, Enabled: true, Memories: []*nricxl.MemoryDevice{foreign}}},
	}
	cfg := PublishConfig{
		IgnoreDevices: []string{"0xa5"},
		SharedDevices: []string{"mem1", "cxl/mem2", "251:3", "164", "a5", "0xa6", "0xa8", "0xaa"},
		ManageMemdevs: true,
	}
	pool := map[uint64]bool{0xa6: true}
	local := &LocalSnapshot{BlockSize: pubBlockSize, Uses: map[uint64]LocalUse{
		0xa8: {Claims: []string{"s1"}},
		0xa9: {Shared: true, Claims: []string{"h1"}},
	}}
	devInfos := BuildDevices(cfg, devices, pool, nil, local)
	shared := map[string]bool{}
	for name, d := range devInfos {
		if m, ok := d.Dev.(*device.Memdev); ok {
			shared[name] = m.Shared
		}
	}
	want := map[string]bool{"memdev-a1": true, "memdev-a2": true, "memdev-a3": true, "memdev-a4": true, "memdev-a7": false}
	if !maps.Equal(shared, want) {
		t.Fatalf("published memdevs (name: shared) %v, expected %v", shared, want)
	}
	for _, tc := range []struct {
		mem  *nricxl.MemoryDevice
		want string
	}{
		{ignored, `ignored by memory device serial "0xa5"`},
		{pooled, "pool device"},
		{byName, ""},
		{sliced, ""},
	} {
		if _, got := sharedListing(cfg, tc.mem, pool, nil); got != tc.want {
			t.Errorf("%s: refusal %q, expected %q", tc.mem.Name, got, tc.want)
		}
	}
	if got := SharedSerials(cfg, devices.MemoryDevices, pool); !maps.Equal(got, map[uint64]bool{0xa1: true, 0xa2: true, 0xa3: true, 0xa4: true, 0xa8: true, 0xaa: true}) {
		t.Fatalf("shared serials %v", got)
	}

	// the hidden ones come back when the other use has no claims
	local.Uses[0xa8] = LocalUse{Claims: []string{}}
	local.Uses[0xa9] = LocalUse{Shared: true, Claims: []string{}}
	devInfos = BuildDevices(cfg, devices, pool, nil, local)
	for name, s := range map[string]bool{"memdev-a8": true, "memdev-a9": false} {
		if m, ok := devInfos[name].Dev.(*device.Memdev); !ok || m.Shared != s {
			t.Errorf("%s: %+v, expected shared %v", name, devInfos[name], s)
		}
	}
}

// TestSharedRefusalLogged pins the line of a memdev of sharedDevices that
// is not published as a shared local device, as the documentation quotes
// it, logged once per reason: held, and a pool device.
func TestSharedRefusalLogged(t *testing.T) {
	logs := captureKlogV(t, "0")
	// logged once per process: again for this test
	for _, reason := range []string{heldReason, "pool device"} {
		sharedRefusalsLogged.Delete("mem-refused\x00" + reason)
	}
	m := &nricxl.MemoryDevice{Name: "mem-refused", RamSize: 1 << 30, Serial: 0xa1f, NodeAffinity: -1, Enabled: true}
	cfg := PublishConfig{SharedDevices: []string{"mem-refused"}, ManageMemdevs: true, IgnoreDRAMNodes: true}
	detected := &nricxl.Devices{MemoryDevices: []*nricxl.MemoryDevice{m}}
	local := &LocalSnapshot{BlockSize: pubBlockSize}
	for range 2 {
		if devs := BuildDevices(cfg, detected, nil, map[uint64]bool{0xa1f: true}, local); len(devs) != 0 {
			t.Fatalf("published %v", pubNames(devs))
		}
	}
	if devs := BuildDevices(cfg, detected, map[uint64]bool{0xa1f: true}, nil, local); len(devs) != 0 {
		t.Fatalf("published %v", pubNames(devs))
	}
	out := logs()
	if n := logMatches(out, compat.DocNotPublishingMemoryDeviceMemNAsAShared, "<memN>", "mem-refused", "<reason>", heldReason); n != 1 {
		t.Fatalf("%d lines of the held refusal:\n%s", n, out)
	}
	if n := logMatches(out, compat.DocNotPublishingMemoryDeviceMemNAsAShared, "<memN>", "mem-refused", "<reason>", "pool device"); n != 1 {
		t.Fatalf("%d lines of the pool refusal:\n%s", n, out)
	}
}

// TestPersistentMemdevRefusals pins the line of a persistent memdev that is
// not published, as the documentation quotes it, at klog V(4): a pool
// device, a held memdev, a disabled one.
func TestPersistentMemdevRefusals(t *testing.T) {
	logs := captureKlogV(t, "4")
	m := &nricxl.MemoryDevice{Name: "mem3", PmemSize: 512 * pubMiB, Serial: 0xc100f5e1, NodeAffinity: -1, Enabled: true}
	detected := &nricxl.Devices{MemoryDevices: []*nricxl.MemoryDevice{m}}
	cfg := PublishConfig{ManageMemdevs: true, IgnoreDRAMNodes: true}
	local := &LocalSnapshot{BlockSize: pubBlockSize}
	if devs := BuildDevices(cfg, detected, nil, nil, local); !slices.Equal(pubNames(devs), []string{"memdev-c100f5e1"}) {
		t.Fatalf("published %v", pubNames(devs))
	}
	serial := map[uint64]bool{0xc100f5e1: true}
	for _, tc := range []struct {
		pool, held map[uint64]bool
		enabled    bool
		reason     string
	}{
		{serial, nil, true, "pool device"},
		{nil, serial, true, heldReason},
		{nil, nil, false, "memory device is disabled"},
	} {
		m.Enabled = tc.enabled
		if devs := BuildDevices(cfg, detected, tc.pool, tc.held, local); len(devs) != 0 {
			t.Fatalf("%s: published %v", tc.reason, pubNames(devs))
		}
		if n := logMatches(logs(), compat.DocNotPublishingMemoryDeviceMemNAsAPersistent, "<memN>", "mem3", "<reason>", tc.reason); n != 1 {
			t.Fatalf("%d lines with %q:\n%s", n, tc.reason, logs())
		}
	}
}

// TestMemdevSettings pins the usable size of a local memdev from the
// configured usable size (memdevSettings, UsableSize of the configuration)
// and the probed size: the smaller limit, rounded down to 256 MiB.
func TestMemdevSettings(t *testing.T) {
	cfg := PublishConfig{UsableSize: func(memdev string, serial uint64) uint64 {
		switch {
		case serial == 0x0badc0dedeadbeef:
			return 128 << 30
		case memdev == "mem1":
			return 1000 << 20
		}
		return 0
	}}
	m0 := &nricxl.MemoryDevice{Name: "mem0", Serial: 0x0badc0dedeadbeef, RamSize: 192 << 30}
	m1 := &nricxl.MemoryDevice{Name: "mem1", Serial: 0x1, RamSize: 2 << 30}
	m2 := &nricxl.MemoryDevice{Name: "mem2", Serial: 0x2, RamSize: 2 << 30}
	for _, tc := range []struct {
		m      *nricxl.MemoryDevice
		probed uint64
		want   uint64
	}{
		{m0, 0, 128 << 30},
		{m0, 64 << 30, 64 << 30},
		{m1, 0, 768 << 20},
		{m2, 0, 2 << 30},
		{m2, 1 << 30, 1 << 30},
	} {
		snap := &LocalSnapshot{Probed: map[uint64]uint64{tc.m.Serial: tc.probed}}
		if got := memdevUsableSize(cfg, tc.m, snap); got != tc.want {
			t.Errorf("%s probed %d: usable size %d, expected %d", tc.m.Name, tc.probed, got, tc.want)
		}
	}
	if got := memdevUsableSize(PublishConfig{}, m2, nil); got != 2<<30 {
		t.Errorf("usable size %d without settings", got)
	}
}

// TestRescanBeforeStart pins a Rescan before Start: it sets the devices and
// publishes nothing (no slice, no line of a publish); after Start a Rescan
// publishes them with its line.
func TestRescanBeforeStart(t *testing.T) {
	logs := captureKlogV(t, "0")
	client := sliceTestClient(pubNode, nil)
	p := pubPublisher(t, PublishOptions{
		Config:   PublishConfig{IgnoreDRAMNodes: true, PublishLeaseDevice: true},
		NodeName: pubNode,
		Client:   client,
		Scan:     func() (*nricxl.Devices, error) { return nricxl.NewDevices(), nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Rescan(ctx, false)
	if devs := p.Devices(); devs[device.LeaseDeviceName] == nil {
		t.Fatalf("devices after the rescan: %+v", devs)
	}
	list, err := client.ResourceV1().ResourceSlices().List(ctx, metav1.ListOptions{})
	pubNoErr(t, err)
	if len(list.Items) != 0 {
		t.Fatalf("published before the start: %+v", list.Items)
	}
	published := func() int {
		n := 0
		for _, line := range strings.Split(logs(), "\n") {
			if ok, err := compat.MatchesRegexp(compat.LogRescanAndPublishPublishedUpdatedResources, line); err != nil {
				t.Fatal(err)
			} else if ok {
				n++
			}
		}
		return n
	}
	if n := published(); n != 0 {
		t.Fatalf("%d lines of a publish before the start:\n%s", n, logs())
	}

	pubNoErr(t, p.Start(ctx))
	defer p.Stop()
	waitNodeSlice(t, client, pubNode, 5*time.Second, device.LeaseDeviceName)
	p.Rescan(ctx, false)
	if n := published(); n != 1 {
		t.Fatalf("%d lines of a publish after the start:\n%s", n, logs())
	}
	wantLogLineText(t, logs(), "rescanAndPublish: published updated resources (1 devices)")
}

// TestPublishedTable pins the table that a local Prepare looks its devices
// up in: that of the last publication, the last scan's before the
// first one; a scan that is not published leaves it.
func TestPublishedTable(t *testing.T) {
	client := sliceTestClient(pubNode, nil)
	p := pubPublisher(t, PublishOptions{
		Config:   PublishConfig{IgnoreDRAMNodes: true, PublishLeaseDevice: true},
		NodeName: pubNode,
		Client:   client,
		Scan:     func() (*nricxl.Devices, error) { return nricxl.NewDevices(), nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pubNoErr(t, p.Scan(ctx))
	if p.Published()[device.LeaseDeviceName] == nil {
		t.Fatalf("published table before the first publication: %+v", p.Published())
	}
	pubNoErr(t, p.Start(ctx))
	defer p.Stop()
	// a scan without the lease device, not published
	p.SetConfig(PublishConfig{IgnoreDRAMNodes: true})
	pubNoErr(t, p.Scan(ctx))
	if p.Devices()[device.LeaseDeviceName] != nil || p.Published()[device.LeaseDeviceName] == nil {
		t.Fatalf("scanned %v, published %v", p.Devices(), p.Published())
	}
	p.Rescan(ctx, false)
	if p.Published()[device.LeaseDeviceName] != nil {
		t.Fatalf("published %v after the rescan", p.Published())
	}
}
