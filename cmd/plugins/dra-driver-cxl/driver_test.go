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
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	resourceapi "k8s.io/api/resource/v1"

	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/containers"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/provenance"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

func TestNewDriverConfigFromString_WithTestability(t *testing.T) {
	configJSON := `{
		"testability": {
			"fakeRegionDevices": [
				{
					"Name": "fakeregion0",
					"Size": 1073741824,
					"Mode": "ram",
					"Node": 2,
					"Memories": [
						{
							"Name": "fakemem0",
							"RamSize": 1073741824,
							"Serial": 12345,
							"NodeAffinity": 0
						}
					]
				}
			]
		}
	}`

	cfg, err := newDriverConfigFromString(configJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Testability == nil {
		t.Fatal("expected non-nil Testability")
	}
	if len(cfg.Testability.FakeRegionDevices) != 1 {
		t.Fatalf("expected 1 fake region, got %d", len(cfg.Testability.FakeRegionDevices))
	}
	reg := cfg.Testability.FakeRegionDevices[0]
	if reg.Name != "fakeregion0" {
		t.Errorf("expected name fakeregion0, got %s", reg.Name)
	}
	if reg.Size != 1073741824 {
		t.Errorf("expected size 1073741824, got %d", reg.Size)
	}
	if reg.Node != 2 {
		t.Errorf("expected node 2, got %d", reg.Node)
	}
	if len(reg.Memories) != 1 {
		t.Fatalf("expected 1 memory device, got %d", len(reg.Memories))
	}
	if reg.Memories[0].Name != "fakemem0" {
		t.Errorf("expected memory name fakemem0, got %s", reg.Memories[0].Name)
	}
	if reg.Memories[0].Serial != 12345 {
		t.Errorf("expected serial 12345, got %d", reg.Memories[0].Serial)
	}
}

func TestNewDriverConfigFromString_WithoutTestability(t *testing.T) {
	configJSON := `{"ignoreDevices": ["mem0"]}`

	cfg, err := newDriverConfigFromString(configJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Testability != nil {
		t.Fatalf("expected nil Testability, got %+v", cfg.Testability)
	}
	if len(cfg.IgnoreDevices) != 1 || cfg.IgnoreDevices[0] != "mem0" {
		t.Errorf("expected IgnoreDevices [mem0], got %v", cfg.IgnoreDevices)
	}
}

func TestNewDriverConfigFromString_EmptyConfig(t *testing.T) {
	cfg, err := newDriverConfigFromString("{}")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Testability != nil {
		t.Fatalf("expected nil Testability for empty config")
	}
}

// fakeRegionConfig is the testability configuration of a fake region of 1
// GiB on node 2 with one memdev.
func fakeRegionConfig() *TestabilityConfig {
	return &TestabilityConfig{FakeRegionDevices: []nricxl.RegionDevice{{
		Name: "fakeregion0", Size: 1 << 30, Node: 2,
		Memories: []*nricxl.MemoryDevice{{Name: "fakemem0", RamSize: 1 << 30, Serial: 12345, NodeAffinity: 0}},
	}}}
}

// A fake region is added to the snapshot in mode ram, enabled on its node,
// which its dax device tells, its memdev enabled; the lookups find them.
func TestInjectFakeDevices_Defaults(t *testing.T) {
	snap := &kernel.Snapshot{}
	injectFakeDevices(fakeRegionConfig(), snap)
	want := kernel.RegionInfo{Name: "fakeregion0", State: kernel.RegionEnabled, Mode: kernel.RegionRAM, NumaNode: 2,
		Range: kernel.Range{End: 1<<30 - 1}, Memdevs: []string{"fakemem0"}, Serials: []uint64{12345}}
	if len(snap.Regions) != 1 || !reflect.DeepEqual(snap.Region("fakeregion0"), want) {
		t.Fatalf("regions %+v", snap.Regions)
	}
	if d := snap.DaxDevicesOf("fakeregion0"); len(d) != 1 || d[0].TargetNode != 2 {
		t.Fatalf("dax devices %+v", snap.DaxDevices)
	}
	m := snap.Memdev(12345)
	if len(snap.Memdevs) != 1 || !reflect.DeepEqual(m, kernel.MemdevInfo{Name: "fakemem0", Serial: 12345, State: kernel.MemdevReady, RamSize: 1 << 30}) {
		t.Fatalf("memdevs %+v", snap.Memdevs)
	}
}

// A fake region keeps its mode and its resource; the keys of pkg/cxl's
// types that the snapshot has no place for are accepted.
func TestInjectFakeDevices_PreservesExplicitValues(t *testing.T) {
	tc := &TestabilityConfig{FakeRegionDevices: []nricxl.RegionDevice{{
		Name: "fakeregion0", SysfsPath: "/custom/path/fakeregion0", Size: 1 << 30, Resource: 0x850000000, Mode: "pmem", Node: 3,
		Memories: []*nricxl.MemoryDevice{{Name: "fakemem0", Driver: "custom_driver", DevName: "custom/fakemem0", Major: 251, Minor: 7}},
	}}}
	snap := &kernel.Snapshot{}
	injectFakeDevices(tc, snap)
	r := snap.Region("fakeregion0")
	if r.Mode != kernel.RegionPmem || r.Range != (kernel.Range{Start: 0x850000000, End: 0x850000000 + 1<<30 - 1}) || r.NumaNode != 3 {
		t.Fatalf("region %+v", r)
	}
	if m := snap.Memdevs[0]; m.Name != "fakemem0" || m.Major != 251 || m.Minor != 7 || m.State != kernel.MemdevReady {
		t.Fatalf("memdev %+v", m)
	}
}

// A fake region without a node is disabled, without a dax device; a hollow
// one is hollow.
func TestInjectFakeDevices_DisabledRegion(t *testing.T) {
	tc := &TestabilityConfig{FakeRegionDevices: []nricxl.RegionDevice{
		{Name: "fakeregion0", Size: 1 << 30, Node: -1},
		{Name: "fakeregion1", Size: 1 << 30, Node: 2, Hollow: true},
	}}
	snap := &kernel.Snapshot{}
	injectFakeDevices(tc, snap)
	if r := snap.Region("fakeregion0"); r.State != kernel.RegionDisabled || len(snap.DaxDevicesOf("fakeregion0")) != 0 {
		t.Fatalf("region %+v, dax devices %+v", r, snap.DaxDevices)
	}
	if r := snap.Region("fakeregion1"); r.State != kernel.RegionHollow {
		t.Fatalf("region %+v", r)
	}
}

func TestInjectFakeDevices_EmptyConfig(t *testing.T) {
	snap := &kernel.Snapshot{}
	injectFakeDevices(&TestabilityConfig{}, snap)
	if len(snap.Regions) != 0 || len(snap.Memdevs) != 0 || len(snap.DaxDevices) != 0 {
		t.Errorf("snapshot %+v", snap)
	}
}

// The fake regions come after the observed ones, whose lookups still work.
func TestInjectFakeDevices_AppendsToExistingDevices(t *testing.T) {
	snap := &kernel.Snapshot{
		Regions: []kernel.RegionInfo{{Name: "region0", State: kernel.RegionEnabled, NumaNode: 0}},
		Memdevs: []kernel.MemdevInfo{{Name: "mem0", Serial: 1, State: kernel.MemdevReady}},
	}
	snap.Reindex()
	injectFakeDevices(fakeRegionConfig(), snap)
	if len(snap.Regions) != 2 || snap.Regions[0].Name != "region0" || snap.Regions[1].Name != "fakeregion0" {
		t.Fatalf("regions %+v", snap.Regions)
	}
	if snap.Region("region0").State != kernel.RegionEnabled || snap.Memdev(1).Name != "mem0" || snap.Memdev(12345).Name != "fakemem0" {
		t.Fatalf("lookups of %+v", snap)
	}
}

func TestInjectFakeDevices_MultipleRegions(t *testing.T) {
	tc := &TestabilityConfig{FakeRegionDevices: []nricxl.RegionDevice{
		{Name: "fakeregion0", Size: 1 << 30, Node: 2, Memories: []*nricxl.MemoryDevice{{Name: "fakemem0", RamSize: 1 << 30}}},
		{Name: "fakeregion1", Size: 2 << 30, Node: 3, Memories: []*nricxl.MemoryDevice{
			{Name: "fakemem1", RamSize: 1 << 30}, {Name: "fakemem2", RamSize: 1 << 30}}},
	}}
	snap := &kernel.Snapshot{}
	injectFakeDevices(tc, snap)
	if len(snap.Regions) != 2 || len(snap.Memdevs) != 3 || len(snap.DaxDevices) != 2 {
		t.Fatalf("snapshot %+v", snap)
	}
}

// A fake region is published as a region device on its node, with the
// affinity of its memdev.
func TestBuildDevInfos_WithFakeDevices(t *testing.T) {
	snap := &kernel.Snapshot{}
	injectFakeDevices(fakeRegionConfig(), snap)
	devInfos, err := buildDevInfos(&DriverConfig{IgnoreDRAMNodes: true}, snap, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := devInfos["fakeregion0-node2"]
	if len(devInfos) != 1 || !ok || info.Name != "fakeregion0-node2" {
		t.Fatalf("devices %v", devInfos)
	}
	if r, ok := info.Dev.(*device.Region); !ok || !reflect.DeepEqual(*r, device.Region{Name: "fakeregion0", NumaNode: 2, Size: 1 << 30, NodeAffinity: []int{0}}) {
		t.Fatalf("device %T %+v", info.Dev, info.Dev)
	}
}

// The scan of the publisher observes the kernel and adds the fake devices;
// on a node without the CXL bus it fails.
func TestScanFunc(t *testing.T) {
	f := fake.New(t)
	f.Plug(fake.MemdevSpec{Serial: 0xa0})
	cfg := &DriverConfig{Testability: fakeRegionConfig()}
	snap, err := cfg.scanFunc(f.Kernel())(context.Background())
	noErr(t, err)
	if len(snap.Memdevs) != 2 || snap.Memdev(0xa0).Name != "mem0" || snap.Region("fakeregion0").State != kernel.RegionEnabled {
		t.Fatalf("snapshot %+v", snap)
	}
	_, err = cfg.scanFunc(&kernel.Kernel{SysRoot: t.TempDir()})(context.Background())
	if err == nil || !strings.Contains(err.Error(), "bus/cxl/devices: no such file or directory") {
		t.Fatalf("error %v without the CXL bus", err)
	}
}

func TestTestabilityConfig_JSONRoundTrip(t *testing.T) {
	original := &DriverConfig{
		IgnoreDevices: []string{"mem0"},
		Testability: &TestabilityConfig{
			FakeRegionDevices: []nricxl.RegionDevice{
				{
					Name: "fakeregion0",
					Size: 1 << 30,
					Node: 2,
					Mode: "ram",
					Memories: []*nricxl.MemoryDevice{
						{
							Name:         "fakemem0",
							RamSize:      1 << 30,
							Serial:       42,
							NodeAffinity: 0,
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	restored, err := newDriverConfigFromString(string(data))
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if restored.Testability == nil {
		t.Fatal("expected non-nil Testability after round-trip")
	}
	if len(restored.Testability.FakeRegionDevices) != 1 {
		t.Fatalf("expected 1 fake region after round-trip, got %d", len(restored.Testability.FakeRegionDevices))
	}
	reg := restored.Testability.FakeRegionDevices[0]
	if reg.Name != "fakeregion0" || reg.Size != 1<<30 || reg.Node != 2 {
		t.Errorf("unexpected region values after round-trip: %+v", reg)
	}
	if len(reg.Memories) != 1 || reg.Memories[0].Serial != 42 {
		t.Errorf("unexpected memory values after round-trip: %+v", reg.Memories)
	}
}

func TestNewDriverConfigFromString_YAML(t *testing.T) {
	configYAML := `
ignoreDevices:
  - mem0
  - mem1
ignoreRegions:
  - region0
ignoreNodes:
  - 1
  - 3
ignoreNewMemoryDevices: true
ignoreNewRegions: true
ignoreNewNodes: true
ignoreDRAMNodes: true
`
	cfg, err := newDriverConfigFromString(configYAML)
	if err != nil {
		t.Fatalf("unexpected error parsing YAML: %v", err)
	}
	if len(cfg.IgnoreDevices) != 2 || cfg.IgnoreDevices[0] != "mem0" || cfg.IgnoreDevices[1] != "mem1" {
		t.Errorf("expected IgnoreDevices [mem0 mem1], got %v", cfg.IgnoreDevices)
	}
	if len(cfg.IgnoreRegions) != 1 || cfg.IgnoreRegions[0] != "region0" {
		t.Errorf("expected IgnoreRegions [region0], got %v", cfg.IgnoreRegions)
	}
	if len(cfg.IgnoreNodes) != 2 || cfg.IgnoreNodes[0] != 1 || cfg.IgnoreNodes[1] != 3 {
		t.Errorf("expected IgnoreNodes [1 3], got %v", cfg.IgnoreNodes)
	}
	if !cfg.IgnoreDRAMNodes || !cfg.IgnoreNewMemoryDevices || !cfg.IgnoreNewRegions || !cfg.IgnoreNewNodes {
		t.Errorf("expected ignoreDRAMNodes and ignoreNew*: %+v", cfg)
	}
}

// TestDriverConfigKeys checks that the keys of the configuration are the
// lower-camel json tags.
func TestDriverConfigKeys(t *testing.T) {
	cfg := &DriverConfig{IgnoreDevices: []string{"mem0"}, IgnoreRegions: []string{"region0"}, IgnoreNodes: []int{1},
		IgnoreNewMemoryDevices: true, IgnoreNewRegions: true, IgnoreNewNodes: true, IgnoreDRAMNodes: true,
		UdevStableDuration: "1s", ManageMemdevs: ptr(true), PublishLeaseDevice: true}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ignoreDevices":["mem0"],"ignoreRegions":["region0"],"ignoreNodes":[1],"ignoreNewMemoryDevices":true,"ignoreNewRegions":true,` +
		`"ignoreNewNodes":true,"ignoreDRAMNodes":true,"udevStableDuration":"1s","manageMemdevs":true}`
	if string(data) != want {
		t.Errorf("configuration %s, expected %s", data, want)
	}
	if _, err := newDriverConfigFromString("ignoreDevice: [mem0]"); err == nil {
		t.Error("an unknown key is accepted")
	}
}

func TestNewDriverConfigFromString_YAMLWithTestability(t *testing.T) {
	configYAML := `
testability:
  fakeRegionDevices:
    - Name: fakeregion0
      Size: 1073741824
      Mode: ram
      Node: 2
      Memories:
        - Name: fakemem0
          RamSize: 1073741824
          Serial: 12345
`
	cfg, err := newDriverConfigFromString(configYAML)
	if err != nil {
		t.Fatalf("unexpected error parsing YAML: %v", err)
	}
	if cfg.Testability == nil {
		t.Fatal("expected non-nil Testability")
	}
	if len(cfg.Testability.FakeRegionDevices) != 1 {
		t.Fatalf("expected 1 fake region, got %d", len(cfg.Testability.FakeRegionDevices))
	}
	reg := cfg.Testability.FakeRegionDevices[0]
	if reg.Name != "fakeregion0" {
		t.Errorf("expected name fakeregion0, got %s", reg.Name)
	}
	if reg.Size != 1073741824 {
		t.Errorf("expected size 1073741824, got %d", reg.Size)
	}
	if reg.Node != 2 {
		t.Errorf("expected node 2, got %d", reg.Node)
	}
	if len(reg.Memories) != 1 || reg.Memories[0].Serial != 12345 {
		t.Errorf("unexpected memory: %+v", reg.Memories)
	}
}

func TestResolveConfigStr_StringOnly(t *testing.T) {
	flags := &CXLFlags{ConfigStr: `{"ignoreDevices": ["mem0"]}`}
	result, err := resolveConfigStr(flags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != flags.ConfigStr {
		t.Errorf("expected config string to be returned as-is, got %q", result)
	}
}

func TestResolveConfigStr_FileOnly(t *testing.T) {
	content := `{"ignoreDevices": ["mem1"]}`
	tmpFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	flags := &CXLFlags{ConfigFile: tmpFile}
	result, err := resolveConfigStr(flags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != content {
		t.Errorf("expected %q, got %q", content, result)
	}
}

func TestResolveConfigStr_BothError(t *testing.T) {
	flags := &CXLFlags{
		ConfigStr:  `{"ignoreDevices": ["mem0"]}`,
		ConfigFile: "/some/file.json",
	}
	_, err := resolveConfigStr(flags)
	if err == nil {
		t.Fatal("expected error when both -c and -f are provided")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Errorf("expected error about mutual exclusivity, got: %v", err)
	}
}

func TestResolveConfigStr_NeitherReturnsEmpty(t *testing.T) {
	flags := &CXLFlags{}
	result, err := resolveConfigStr(flags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestResolveConfigStr_FileNotFound(t *testing.T) {
	flags := &CXLFlags{ConfigFile: "/nonexistent/path/config.yaml"}
	_, err := resolveConfigStr(flags)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestResolveConfigStr_YAMLFile(t *testing.T) {
	content := "ignoreDevices:\n  - mem0\nignoreDRAMNodes: true\n"
	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	flags := &CXLFlags{ConfigFile: tmpFile}
	result, err := resolveConfigStr(flags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg, err := newDriverConfigFromString(result)
	if err != nil {
		t.Fatalf("failed to parse config from file: %v", err)
	}
	if len(cfg.IgnoreDevices) != 1 || cfg.IgnoreDevices[0] != "mem0" {
		t.Errorf("expected IgnoreDevices [mem0], got %v", cfg.IgnoreDevices)
	}
	if !cfg.IgnoreDRAMNodes {
		t.Error("expected IgnoreDRAMNodes=true")
	}
}

func TestDriverConfigManageMemdevs(t *testing.T) {
	for _, tc := range []struct {
		config string
		want   bool
	}{
		{"{}", true},
		{"manageMemdevs: true", true},
		{"manageMemdevs: false", false},
		{`{"manageMemdevs": false, "ignoreDevices": ["mem0"]}`, false},
	} {
		cfg, err := newDriverConfigFromString(tc.config)
		if err != nil {
			t.Fatalf("%s: %v", tc.config, err)
		}
		if got := cfg.manageMemdevs(); got != tc.want {
			t.Errorf("%s: manageMemdevs %v, expected %v", tc.config, got, tc.want)
		}
	}
}

func TestDriverConfigDefaults(t *testing.T) {
	for _, tc := range []struct {
		config string
		want   string // fencing and steering policy, or the error
	}{
		{"{}", "allowed-mems none"},
		{"defaults: {}", "allowed-mems none"},
		{"defaults: {container: {}}", "allowed-mems none"},
		{"defaults: {container: {fencing: allowed-mems}}", "allowed-mems none"},
		{"defaults:\n  container:\n    fencing: none\n    steering: {policy: auto}", "none auto"},
		{`{"defaults": {"container": {"steering": {"policy": "first-dram", "maxStep": "1Gi"}}}}`, "allowed-mems first-dram"},
		{"defaults: {container: {fencing: mempolicy}}", "defaults.container.fencing: mempolicy is not implemented yet"},
		{"defaults: {container: {fencing: hard}}", `defaults.container.fencing: invalid value "hard" (allowed-mems, mempolicy or none)`},
		{"defaults: {container: {steering: {policy: bogus}}}", `defaults.container.steering.policy: invalid policy "bogus" (none, auto, first-dram, first-cxl, start-interleaved, end-interleaved or waypoints)`},
		{"defaults: {container: {steering: {maxStep: 1Gi}}}", "defaults.container.steering.maxStep needs a policy other than none"},
		{"defaults: {container: {Fencing: none}}", `defaults: json: unknown field "container.Fencing"`},
		{"defaults: {device: {mode: dax}}", `defaults: json: unknown field "device"`},
		{"containerMemory: {default: none}", "failed to parse driver config"},
	} {
		cfg, err := newDriverConfigFromString(tc.config)
		got := ""
		if err != nil {
			got = err.Error()
		} else {
			got = cfg.fencing() + " " + cfg.steeringPolicy()
		}
		if !strings.HasPrefix(got, tc.want) {
			t.Errorf("%s: %q, expected %q", tc.config, got, tc.want)
		}
	}
	cfg, err := newDriverConfigFromString("defaults: {container: {steering: {policy: auto, minStep: 64Mi}}}")
	noErr(t, err)
	if got := cfg.containerDefaults(); got.Steering == nil || got.Steering.Policy != config.PolicyAuto || got.Steering.MinStep != "64Mi" || got.Fencing != "" {
		t.Errorf("container defaults %+v", got)
	}
	if got := (&DriverConfig{}).containerDefaults(); got.Steering != nil || got.Fencing != "" {
		t.Errorf("container defaults of no defaults %+v", got)
	}
	data, err := json.Marshal(cfg)
	if err != nil || string(data) != `{"defaults":{"container":{"steering":{"minStep":"64Mi","policy":"auto"}}}}` {
		t.Errorf("configuration %s %v", data, err)
	}
}

// The local part of a start: nothing with manageMemdevs false, else the
// store and kernel of the node; an old file of a gone memdev is not used.
// The rules of the drivers are the one place of their per-source values:
// the store drops the preparations of another boot of cxl.nri.io and keeps
// those of the pool driver PREPARED_STALE, the engine mounts in the
// MountsDir of each.
func TestDriverRules(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	local := filepath.Join(dir, device.DriverName)
	noErr(t, os.MkdirAll(local, 0o750))
	flags := &CXLFlags{}
	config := &pluginConfig{Flags: flags, KubeletPluginDir: local}
	if r := newDriverRules(config, flags); r.pool != nil || len(r.all()) != 1 || r.local.MountsDir != filepath.Join(local, mountsDirName) {
		t.Fatalf("the rules without the pool driver: %+v", r)
	}
	flags.PoolDriverName = device.PoolDriverName
	rules := newDriverRules(config, flags)
	want := map[state.Source]string{
		state.SourceLocal: filepath.Join(local, mountsDirName),
		state.SourcePool:  filepath.Join(dir, device.PoolDriverName, mountsDirName),
	}
	if got := dra.MountsDirs(rules.all()...); !maps.Equal(got, want) {
		t.Fatalf("mounts directories %v, want %v", got, want)
	}
	uid := func(driver string) string { return "u-" + driver }
	for _, boot := range []string{"b0", "b1"} {
		st, closeStore, err := openDriverStore(ctx, config, flags, dir, boot, rules)
		noErr(t, err)
		if boot == "b0" {
			noErr(t, st.Commit(ctx, store.Durable, func(doc *store.Document) error {
				for _, driver := range []string{device.DriverName, device.PoolDriverName} {
					doc.Preparations = append(doc.Preparations, state.Preparation{UID: uid(driver), Driver: driver,
						ClaimName: "ns/c", BootID: boot, State: state.PreparationPrepared})
				}
				return nil
			}))
		} else {
			// both drivers keep their preparations of another boot
			r := st.Snapshot().Records
			for _, driver := range []string{device.DriverName, device.PoolDriverName} {
				if p := r.Preparation(driver, uid(driver)); p == nil || p.State != state.PreparationStale {
					t.Errorf("the preparation of %s of another boot: %+v", driver, p)
				}
			}
		}
		closeStore()
	}
}

func TestNewLocalHelper(t *testing.T) {
	ctx := context.Background()
	// start starts the local part of the driver on a node of its own with
	// the old state file old ("" for none); the store is closed by the
	// returned function
	start := func(cfg *DriverConfig, old string) (*frontEnds, *deviceEngine, string, func()) {
		t.Helper()
		dir := t.TempDir()
		for _, d := range []string{"sys/bus/cxl/devices", "sys/devices/system/node", "cdi"} {
			noErr(t, os.MkdirAll(filepath.Join(dir, d), 0o755))
		}
		if old != "" {
			noErr(t, os.WriteFile(filepath.Join(dir, localStateFileName), []byte(old), 0o600))
		}
		flags := &CXLFlags{CDIRoot: filepath.Join(dir, "cdi"), NodeName: testNode}
		config := &pluginConfig{Flags: flags, KubeletPluginDir: dir}
		rules := newDriverRules(config, flags)
		st, closeStore, err := openDriverStore(ctx, config, flags, dir, "", rules)
		noErr(t, err)
		devices, err := newDriverDevices(config, flags, cfg, dir, nil, st, rules)
		if err == nil {
			var fe *frontEnds
			if fe, err = newFrontEnds(config, flags, cfg, "", st, devices, nil, rules); err == nil {
				if err = fe.recover(ctx, flags.CDIRoot, cfg, devices); err == nil {
					return fe, devices, dir, closeStore
				}
			}
		}
		closeStore()
		t.Fatal(err)
		return nil, nil, "", nil
	}
	fe, _, _, stop := start(&DriverConfig{ManageMemdevs: ptr(false)}, "")
	stop()
	if fe.publisher.LocalSnapshot() != nil {
		t.Fatalf("unmanaged memdevs: %+v", fe.publisher.LocalSnapshot())
	}
	// the state of a memdev that is gone is not used at start
	old := `[{"serial":3238060769,"serialHex":"c100e2e1","memdev":"mem0","region":"region0","node":2,"claims":{"u1":[{"request":"mem","region":"region0","mode":"numa","size":2097152,"dax":"dax0.1"}]}}]`
	fe, devices, dir, stop := start(&DriverConfig{}, old)
	defer stop()
	if snap := fe.publisher.LocalSnapshot(); snap == nil || len(snap.Uses) != 0 {
		t.Fatalf("uses %+v of a gone memdev", snap)
	}
	if devices.k.SysRoot != dir+"/sys" {
		t.Fatalf("local devices on %s", devices.k.SysRoot)
	}
	for _, name := range []string{"state.json", localStateFileName + ".old"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{localStateFileName, preparedClaimsInfoFileName} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Fatalf("the driver wrote %s", name)
		}
	}
}

// A Prepare of either driver waits for the first NRI Synchronize (also of a
// prepared claim), failing before any device after nriPrepareWait.
func TestPrepareWaitsForNRI(t *testing.T) {
	old := nriPrepareWait
	t.Cleanup(func() { nriPrepareWait = old })
	ctx := context.Background()
	const why = "NRI not synchronized yet: context deadline exceeded: the containers of the claims would be created before the NRI plugin sees them; kubelet retries the Prepare"
	newNRI := func(t *testing.T) *containers.Plugin {
		t.Helper()
		st, err := store.Open(ctx, store.Options{Dir: t.TempDir()})
		noErr(t, err)
		t.Cleanup(func() { _ = st.Close() })
		p, err := containers.New(containers.Options{Store: st, SysRoot: t.TempDir()})
		noErr(t, err)
		return p
	}
	// waits runs prepare in the background and checks that it waits until
	// the NRI plugin synchronizes, then succeeds.
	waits := func(t *testing.T, nri *containers.Plugin, prepare func() kubeletplugin.PrepareResult) {
		t.Helper()
		nriPrepareWait = time.Minute
		done := make(chan kubeletplugin.PrepareResult, 1)
		go func() { done <- prepare() }()
		select {
		case res := <-done:
			t.Fatalf("did not wait for NRI: %+v", res)
		case <-time.After(50 * time.Millisecond):
		}
		if _, err := nri.Synchronize(ctx, nil, nil); err != nil {
			t.Fatal(err)
		}
		select {
		case res := <-done:
			noErr(t, res.Err)
		case <-time.After(5 * time.Second):
			t.Fatal("still waiting after Synchronize")
		}
	}

	t.Run(device.DriverName, func(t *testing.T) {
		e := newLocalTestEnv(t)
		e.start()
		nri := newNRI(t)
		setNRI(e.s, nri)
		claim := localClaim("u1", 16*mib)
		prepare := func() kubeletplugin.PrepareResult { return prepareResultOn(ctx, e.s, claim) }
		nriPrepareWait = 20 * time.Millisecond
		cmds := e.commands()
		wantErr(t, prepare().Err, why)
		_, prepared := e.prepared()[string(claim.UID)]
		if prepared || e.preparation("u1") != nil || e.commands() != cmds {
			t.Fatalf("prepared %v, preparation %+v, commands:\n%s", prepared, e.preparation("u1"), strings.TrimPrefix(e.commands(), cmds))
		}
		waits(t, nri, prepare)
		// prepared already: it waits too
		nri = newNRI(t)
		setNRI(e.s, nri)
		waits(t, nri, prepare)
		// no NRI plugin
		setNRI(e.s, nil)
		noErr(t, prepare().Err)
		e.mustUnprepare("u1")
		e.wantClean()
	})

	t.Run(device.PoolDriverName, func(t *testing.T) {
		e := newPoolTestEnv(t)
		e.plug(0xc1ee0001)
		p := e.driver(t)
		nri := newNRI(t)
		setNRI(p, nri)
		claim := poolClaim("u1", "c1", "pooled0", exclusiveData)
		nriPrepareWait = 20 * time.Millisecond
		ncmds := e.commands()
		wantErr(t, prepare(t, p, claim).Err, why)
		if prep := e.preparation("u1"); prep != nil || e.commands() != ncmds {
			t.Fatalf("preparation %+v, commands:\n%s", prep, strings.TrimPrefix(e.commands(), ncmds))
		}
		waits(t, nri, func() kubeletplugin.PrepareResult {
			res, err := p.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim})
			if err != nil {
				return kubeletplugin.PrepareResult{Err: err}
			}
			return res[claim.UID]
		})
		setNRI(p, nil)
		noErr(t, prepare(t, p, claim).Err)
		noErr(t, unprepare(t, p, "u1"))
		e.wantClean(t, p)
	})
}

// everyPeriod runs its pass at every period until it is stopped.
func TestEveryPeriod(t *testing.T) {
	stop := make(chan struct{})
	passes := make(chan struct{}, 10)
	done := make(chan struct{})
	go func() {
		everyPeriod(time.Millisecond, stop, func() { passes <- struct{}{} })
		close(done)
	}()
	for range 3 {
		select {
		case <-passes:
		case <-time.After(5 * time.Second):
			t.Fatal("no pass")
		}
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("not stopped")
	}
}

// The first list of the pool ResourceSlices runs after phase 1 of the
// recovery: when it runs, the engine has recovered its records and
// the local guard is set.
func TestFirstListAfterRecovery(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	for _, d := range []string{"sys/bus/cxl/devices", "sys/devices/system/node", "cdi"} {
		noErr(t, os.MkdirAll(filepath.Join(dir, d), 0o755))
	}
	flags := &CXLFlags{CDIRoot: filepath.Join(dir, "cdi"), NodeName: testNode}
	config := &pluginConfig{Flags: flags, KubeletPluginDir: dir}
	rules := newDriverRules(config, flags)
	st, closeStore, err := openDriverStore(ctx, config, flags, dir, "", rules)
	noErr(t, err)
	defer closeStore()
	devices, err := newDriverDevices(config, flags, &DriverConfig{}, dir, nil, st, rules)
	noErr(t, err)
	lists, guarded := 0, 0
	watcher := provenance.New(provenance.Options{Store: st, NodeName: testNode, Name: "poolSerials.json",
		List: func(context.Context) ([]resourceapi.ResourceSlice, error) {
			lists++
			devices.mu.Lock()
			if devices.guard != nil {
				guarded++
			}
			devices.mu.Unlock()
			return nil, nil
		}})
	fe, err := newFrontEnds(config, flags, &DriverConfig{}, "", st, devices, watcher, rules)
	noErr(t, err)
	noErr(t, fe.recover(ctx, flags.CDIRoot, &DriverConfig{}, devices))
	if lists == 0 || guarded != lists {
		t.Fatalf("%d lists, %d after the recovery", lists, guarded)
	}
}

// The dead keys ignoreNewMemoryDevices and ignoreNewRegions are accepted
// with a warning that they have no effect, the keys of the fake regions that
// have none with one warning naming them; unset, nothing is logged.
func TestDriverConfigDeadKeys(t *testing.T) {
	logs := captureKlog(t)
	cfg, err := newDriverConfigFromString("{ignoreNewMemoryDevices: true, ignoreNewRegions: true}")
	noErr(t, err)
	cfg.logDeadKeys()
	out := logs()
	for _, want := range []string{"ignoreNewMemoryDevices: the key has no effect and is ignored", "ignoreNewRegions: the key has no effect and is ignored"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	logs = captureKlog(t)
	(&DriverConfig{Testability: fakeRegionConfig()}).logDeadKeys()
	if out := logs(); strings.Contains(out, "no effect") {
		t.Errorf("a warning without the keys:\n%s", out)
	}
	// the keys of the fake regions that the observation has no place for
	cfg, err = newDriverConfigFromString(`{testability: {fakeRegionDevices: [{Name: r0, SysfsPath: /x, OnlineSize: 1, Targets: [d],
		Memories: [{Name: m0, Driver: d, DevName: n}]}, {Name: r1, Memories: [{Name: m1, SysfsPath: /y}]}]}}`)
	noErr(t, err)
	logs = captureKlog(t)
	cfg.logDeadKeys()
	want := "testability.fakeRegionDevices: the keys DevName, Driver, OnlineSize, SysfsPath, Targets have no effect and are ignored"
	if out := logs(); !strings.Contains(out, want) {
		t.Errorf("no %q in\n%s", want, out)
	}
}

// fakeEvents are kernel uevents for tests.
type fakeEvents struct {
	kernel.Changes
	started, stopped bool
	startErr         error
	fifo             string
	stable           chan struct{}
}

func (f *fakeEvents) Start(fifo string) error { f.started, f.fifo = true, fifo; return f.startErr }
func (f *fakeEvents) Stop()                   { f.stopped = true }
func (f *fakeEvents) Stable() <-chan struct{} { return f.stable }

// One watch of the uevents of the kernel objects, with the fake events of
// the FIFO, wakes the waits of the engine's kernel and gives the stable
// signal of the rescans after udevStableDuration; without uevents the waits
// only poll.
func TestWakeOnUevents(t *testing.T) {
	old := newKernelEvents
	t.Cleanup(func() { newKernelEvents = old })
	ev := &fakeEvents{}
	var stable time.Duration
	newKernelEvents = func(d time.Duration) (kernelEvents, error) { stable = d; return ev, nil }
	devices := &deviceEngine{k: &kernel.Kernel{}}
	cfg := &DriverConfig{UdevStableDuration: "1s", Testability: &TestabilityConfig{FakeUdevFifo: "/run/fifo"}}
	got, stop, err := wakeOnUevents(devices, cfg)
	noErr(t, err)
	if !ev.started || ev.fifo != "/run/fifo" || stable != time.Second || got != kernelEvents(ev) || devices.k.Events != kernel.Events(ev) {
		t.Fatalf("events %+v, stable %v, kernel events %v", ev, stable, devices.k.Events)
	}
	stop()
	if !ev.stopped {
		t.Fatal("not stopped")
	}
	if _, _, err := wakeOnUevents(devices, &DriverConfig{UdevStableDuration: "-1s"}); err == nil {
		t.Fatal("a negative udevStableDuration")
	}
	if _, _, err := wakeOnUevents(devices, &DriverConfig{UdevStableDuration: "-1s", IgnoreNewNodes: true}); err != nil {
		t.Fatalf("udevStableDuration with ignoreNewNodes: %v", err)
	}
	ev = &fakeEvents{startErr: errors.New("no netlink")}
	devices = &deviceEngine{k: &kernel.Kernel{}}
	logs := captureKlog(t)
	got, stop, err = wakeOnUevents(devices, &DriverConfig{})
	noErr(t, err)
	stop()
	if got != nil || devices.k.Events != nil {
		t.Fatalf("kernel events %v without uevents", devices.k.Events)
	}
	// an error, not a warning: nothing rescans the ResourceSlice
	if out := logs(); !strings.HasPrefix(out, "E") || !strings.Contains(out, "the ResourceSlice is not rescanned on uevents") {
		t.Fatalf("no error line in\n%s", out)
	}
}

// Every stable signal of the uevents rescans once, until the driver stops.
func TestRescanOnStable(t *testing.T) {
	stop, stable, rescans := make(chan struct{}), make(chan struct{}), make(chan struct{}, 4)
	done := make(chan struct{})
	logs := captureKlog(t)
	go func() {
		defer close(done)
		rescanLoop(stop, stable, func() { rescans <- struct{}{} })
	}()
	stable <- struct{}{}
	select {
	case <-rescans:
	case <-time.After(5 * time.Second):
		t.Fatal("no rescan after a stable signal")
	}
	close(stop)
	<-done
	if len(rescans) != 0 {
		t.Fatalf("%d rescans more", len(rescans))
	}
	if !strings.Contains(logs(), "kernel uevents: sysfs stabilized, signaling rescan") {
		t.Fatalf("no rescan line in\n%s", logs())
	}
	// without uevents, and with ignoreNewNodes, nothing rescans
	d := &driver{stop: make(chan struct{})}
	d.startRescans(context.Background(), &DriverConfig{})
	d.events = &fakeEvents{stable: stable}
	d.startRescans(context.Background(), &DriverConfig{IgnoreNewNodes: true})
}
