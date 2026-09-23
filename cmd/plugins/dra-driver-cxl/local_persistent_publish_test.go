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
	"fmt"
	"maps"
	"reflect"
	"slices"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// pmemMemdev returns a memdev of persistent memory only.
func pmemMemdev(name string, serial uint64) kernel.MemdevInfo {
	m := observedMemdev(name, serial, 0, -1)
	m.PmemSize = 4 << 30
	return m
}

// The publication of persistent local memdevs and its refusals;
// persistent: false on every other local memdev.
func TestBuildDevInfosPersistentMemdevs(t *testing.T) {
	devices := &kernel.Snapshot{}
	for i := range 10 {
		devices.Memdevs = append(devices.Memdevs, pmemMemdev(fmt.Sprintf("mem%d", i+1), 0xb1+uint64(i)))
	}
	devices.Memdevs[0].NodeAffinity = 1
	devices.Memdevs[5].State = kernel.MemdevUnbound
	devices.Memdevs[7].RamSize = 1 << 30
	// a foreign pmem region with a node is not a region device (A5)
	observedRegion(devices, "region0", kernel.RegionPmem, 2, 4<<30, 0xb7)
	cfg := &DriverConfig{IgnoreDevices: []string{"mem3"}, SharedDevices: []string{"0xb2", "0xba"}, IgnoreDRAMNodes: true}
	local := &localSnapshot{Uses: map[uint64]localUse{
		0xb9: {Claims: []string{"u1"}},
		0xba: {Persistent: true, Claims: []string{"u2"}},
		0xb1: {Persistent: true},
	}, BlockSize: localBlockSize}
	devInfos := buildDevInfosHeldOK(t, cfg, devices, map[uint64]bool{0xb4: true}, map[uint64]bool{0xb5: true}, local)
	got := slices.Sorted(maps.Keys(devInfos))
	want := []string{"memdev-b1", "memdev-b2", "memdev-b8"}
	if !slices.Equal(got, want) {
		t.Fatalf("published %v, expected %v", got, want)
	}
	if m := devInfos["memdev-b1"].Dev.(*device.Memdev); *m != (device.Memdev{Name: "mem1", Serial: 0xb1, Size: 4 << 30, NodeAffinity: 1, Persistent: true}) {
		t.Fatalf("persistent memdev %+v", m)
	}
	if m := devInfos["memdev-b2"].Dev.(*device.Memdev); !m.Persistent || !m.Shared || m.Size != 4<<30 {
		t.Fatalf("shared persistent memdev %+v", m)
	}
	// RAM and pmem: the RAM, not persistent
	if m := devInfos["memdev-b8"].Dev.(*device.Memdev); m.Persistent || m.Shared || m.Size != 1<<30 {
		t.Fatalf("memdev with RAM and pmem %+v", m)
	}
	// idle again: the other sharing is published
	local.Uses[0xba] = localUse{Persistent: true}
	if devInfos = buildDevInfosHeldOK(t, cfg, devices, nil, nil, local); devInfos["memdev-ba"] == nil {
		t.Fatalf("idle persistent memdev not published: %v", slices.Sorted(maps.Keys(devInfos)))
	}
	// a sliced memdev that a persistent device's claims use is not
	ram := localMemdev()
	ram.Serial = 0xbb
	local.Uses[0xbb] = localUse{Persistent: true, Claims: []string{"u3"}}
	devices.Memdevs = append(devices.Memdevs, ram)
	if devInfos = buildDevInfosHeldOK(t, cfg, devices, nil, nil, local); devInfos["memdev-bb"] != nil {
		t.Fatal("a memdev used as a persistent device published as sliced")
	}
}

// buildDevInfosHeldOK is buildDevInfosHeld, failing the test on error.
func buildDevInfosHeldOK(t *testing.T, cfg *DriverConfig, devices *kernel.Snapshot, pool, held map[uint64]bool, local *localSnapshot) map[string]*device.DeviceInfo {
	t.Helper()
	devInfos, err := buildDevInfosHeld(cfg, devices, pool, held, local)
	noErr(t, err)
	return devInfos
}

// A persistent local memdev is published with its shares, shared or not.
func TestGetResourcesPersistentMemdev(t *testing.T) {
	for _, shared := range []bool{false, true} {
		got := localMemdevDevice("memdev-c100f5e1", &device.Memdev{Name: "mem2", Serial: 0xc100f5e1, Size: 4 << 30, NodeAffinity: 0, Shared: shared, Persistent: true})
		want := resourcev1.Device{
			Name: "memdev-c100f5e1",
			Attributes: map[resourcev1.QualifiedName]resourcev1.DeviceAttribute{
				"type":         {StringValue: ptr("memdev")},
				"source":       {StringValue: ptr("local")},
				"serial":       {StringValue: ptr("0xc100f5e1")},
				"shared":       {BoolValue: ptr(shared)},
				"persistent":   {BoolValue: ptr(true)},
				"size":         {IntValue: ptr(int64(4 << 30))},
				"nodeAffinity": {IntValue: ptr(int64(0))},
			},
			Capacity: map[resourcev1.QualifiedName]resourcev1.DeviceCapacity{
				"shares": {Value: *resource.NewQuantity(1000000, resource.DecimalSI)},
			},
			AllowMultipleAllocations: ptr(true),
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("shared %v: published\n%+v\nexpected\n%+v", shared, got, want)
		}
	}
}

// fsTypes defaults to erofs, is returned as a copy, and its invalid or
// misspelt settings are refused.
func TestDriverConfigFsTypes(t *testing.T) {
	cfg, err := newDriverConfigFromString("")
	noErr(t, err)
	if got := cfg.fsTypes(); !slices.Equal(got, []string{"erofs"}) {
		t.Fatalf("default fsTypes %v", got)
	}
	cfg.fsTypes()[0] = "x"
	if cfg.fsTypes()[0] != "erofs" || defaultFsTypes[0] != "erofs" {
		t.Fatal("fsTypes() is not a copy")
	}
	cfg, err = newDriverConfigFromString("fsTypes: [erofs, f2fs]")
	noErr(t, err)
	if got := cfg.fsTypes(); !slices.Equal(got, []string{"erofs", "f2fs"}) {
		t.Fatalf("fsTypes %v", got)
	}
	cfg, err = newDriverConfigFromString("fsTypes: []")
	noErr(t, err)
	if got := cfg.fsTypes(); got == nil || len(got) != 0 {
		t.Fatalf("empty fsTypes %#v", got)
	}
	_, err = newDriverConfigFromString("fsTypes: [ext4, Ext4]")
	wantErr(t, err, `fsTypes: invalid filesystem type "Ext4" (lower-case letters, digits, "_" and "-")`)
	_, err = newDriverConfigFromString("fsType: [ext4]")
	wantErr(t, err, `unknown field "fsType"`)
}

// coherent of memdevSettings matches a memdev by name or serial in every
// notation; without a configuration nothing is coherent.
func TestDriverConfigMemdevCoherent(t *testing.T) {
	cfg, err := newDriverConfigFromString(`
memdevSettings:
- device: "0x00c100f5e1"
  coherent: true
- device: mem3
  coherent: true
- device: "3238065634"
  usableSize: 1Gi
`)
	noErr(t, err)
	for _, tc := range []struct {
		name   string
		serial uint64
		want   bool
	}{
		{"mem0", 0xc100f5e1, true},
		{"mem3", 0x1, true},
		{"mem4", 0xc100f5e2, false}, // the setting without coherent
		{"mem5", 0x5, false},
	} {
		if got := cfg.memdevCoherent(tc.name, tc.serial); got != tc.want {
			t.Errorf("%s 0x%x: coherent %v, expected %v", tc.name, tc.serial, got, tc.want)
		}
	}
	if got := cfg.configuredUsableSize("mem4", 0xc100f5e2); got != 1<<30 {
		t.Fatalf("usable size %d of the decimal serial", got)
	}
	var none *DriverConfig
	if none.memdevCoherent("mem0", 1) {
		t.Fatal("coherent without a configuration")
	}
	for spec, want := range map[string]bool{"mem0": true, "0xc100f5e1": true, "0xC100F5E1": true, "c100f5e1": true, "3238065633": true, "0x1": false, "mem1": false, "0x": false} {
		if got := settingMatches(spec, "mem0", 0xc100f5e1); got != want {
			t.Errorf("settingMatches(%q) %v, expected %v", spec, got, want)
		}
	}
}
