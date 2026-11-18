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
	"strings"
	"testing"
	"time"

	resourceapi "k8s.io/api/resource/v1"

	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/containers"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/klogtest"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/provenance"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

func TestNewDriverConfigFromString_WithoutTestability(t *testing.T) {
	configJSON := `{"ignoreDevices": ["mem0"]}`

	cfg, err := newDriverConfigFromString(configJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.IgnoreDevices) != 1 || cfg.IgnoreDevices[0] != "mem0" {
		t.Errorf("expected IgnoreDevices [mem0], got %v", cfg.IgnoreDevices)
	}
}

func TestNewDriverConfigFromString_EmptyConfig(t *testing.T) {
	if _, err := newDriverConfigFromString("{}"); err != nil {
		t.Fatalf("unexpected error: %v", err)
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
		st, closeStore, err := openDriverStore(ctx, config, flags, boot)
		noErr(t, err)
		if boot == "b0" {
			noErr(t, st.Commit(ctx, store.Durable, func(doc *store.Document) error {
				for _, driver := range []string{device.DriverName, device.PoolDriverName} {
					doc.Preparations = append(doc.Preparations, state.Preparation{UID: uid(driver), Driver: driver,
						ClaimName: "ns/c", State: state.PreparationPrepared})
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
	// start starts the local part of the driver on a node of its own; the
	// store is closed by the returned function
	start := func(cfg *DriverConfig) (*frontEnds, *deviceEngine, string, func()) {
		t.Helper()
		dir := t.TempDir()
		for _, d := range []string{"sys/bus/cxl/devices", "sys/devices/system/node", "cdi"} {
			noErr(t, os.MkdirAll(filepath.Join(dir, d), 0o755))
		}
		flags := &CXLFlags{CDIRoot: filepath.Join(dir, "cdi"), NodeName: testNode}
		config := &pluginConfig{Flags: flags, KubeletPluginDir: dir}
		rules := newDriverRules(config, flags)
		st, closeStore, err := openDriverStore(ctx, config, flags, "boot-1")
		noErr(t, err)
		devices, err := newDriverDevices(config, flags, cfg, kernelAt(dir), nil, st, rules)
		if err == nil {
			var fe *frontEnds
			if fe, err = newFrontEnds(config, flags, cfg, st, devices, nil, rules); err == nil {
				if err = fe.recover(ctx, flags.CDIRoot, cfg, devices); err == nil {
					return fe, devices, dir, closeStore
				}
			}
		}
		closeStore()
		t.Fatal(err)
		return nil, nil, "", nil
	}
	fe, _, _, stop := start(&DriverConfig{ManageMemdevs: ptr(false)})
	stop()
	if fe.publisher.LocalSnapshot() != nil {
		t.Fatalf("unmanaged memdevs: %+v", fe.publisher.LocalSnapshot())
	}
	fe, devices, dir, stop := start(&DriverConfig{})
	defer stop()
	if snap := fe.publisher.LocalSnapshot(); snap == nil || len(snap.Uses) != 0 {
		t.Fatalf("uses %+v without memdevs", snap)
	}
	if devices.k.SysRoot != dir+"/sys" {
		t.Fatalf("local devices on %s", devices.k.SysRoot)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err != nil {
		t.Fatal(err)
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
		st, err := store.Open(ctx, store.Options{Dir: t.TempDir(), BootID: "boot-1"})
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

// The first list of the pool ResourceSlices runs after the recovery: when
// it runs, the engine has recovered its records and
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
	st, closeStore, err := openDriverStore(ctx, config, flags, "boot-1")
	noErr(t, err)
	defer closeStore()
	devices, err := newDriverDevices(config, flags, &DriverConfig{}, kernelAt(dir), nil, st, rules)
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
	fe, err := newFrontEnds(config, flags, &DriverConfig{}, st, devices, watcher, rules)
	noErr(t, err)
	noErr(t, fe.recover(ctx, flags.CDIRoot, &DriverConfig{}, devices))
	if lists == 0 || guarded != lists {
		t.Fatalf("%d lists, %d after the recovery", lists, guarded)
	}
}

// The dead keys ignoreNewMemoryDevices and ignoreNewRegions are accepted
// with a warning that they have no effect.
func TestDriverConfigDeadKeys(t *testing.T) {
	logs := klogtest.Capture(t, 3)
	cfg, err := newDriverConfigFromString("{ignoreNewMemoryDevices: true, ignoreNewRegions: true}")
	noErr(t, err)
	cfg.logDeadKeys()
	out := logs()
	for _, want := range []string{"ignoreNewMemoryDevices: the key has no effect and is ignored", "ignoreNewRegions: the key has no effect and is ignored"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
}

// fakeEvents are kernel uevents for tests.
type fakeEvents struct {
	kernel.Changes
	started, stopped bool
	stable           chan struct{}
}

func (f *fakeEvents) Start()                  { f.started = true }
func (f *fakeEvents) Stop()                   { f.stopped = true }
func (f *fakeEvents) Stable() <-chan struct{} { return f.stable }

// One watch of the uevents of the kernel objects wakes the waits of the
// engine's kernel and gives the stable signal of the rescans after
// udevStableDuration; without uevents the waits only poll.
func TestWakeOnUevents(t *testing.T) {
	old := newKernelEvents
	t.Cleanup(func() { newKernelEvents = old })
	ev := &fakeEvents{}
	var stable time.Duration
	newKernelEvents = func(d time.Duration) (kernelEvents, error) { stable = d; return ev, nil }
	devices := &deviceEngine{k: &kernel.Kernel{}}
	cfg := &DriverConfig{UdevStableDuration: "1s"}
	got, stop, err := wakeOnUevents(devices, cfg)
	noErr(t, err)
	if !ev.started || stable != time.Second || got != kernelEvents(ev) || devices.k.Events != kernel.Events(ev) {
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
	newKernelEvents = func(time.Duration) (kernelEvents, error) { return nil, errors.New("no netlink") }
	devices = &deviceEngine{k: &kernel.Kernel{}}
	logs := klogtest.Capture(t, 3)
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
	logs := klogtest.Capture(t, 3)
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
