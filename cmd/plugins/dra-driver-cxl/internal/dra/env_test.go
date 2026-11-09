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
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/compat"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/engine"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/lend"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

const (
	// envNode and envNS are the node and the namespace of the claims.
	envNode = "node1"
	envNS   = "demo"
	// envPool is the DRA pool of the pool devices.
	envPool = "fake-cxl-pool"
	// the requester of the leases of companion claims
	envPod    = "borrower"
	envPodUID = "pod-uid-1"
	envCtr    = "app"

	mib = int64(1) << 20
	// envBlockSize is the memory block size of the fake kernel.
	envBlockSize = 128 * mib

	// serials of the local memdevs: sliced (1 GiB of RAM), shared (1 GiB
	// of RAM) and persistent (512 MiB of persistent memory).
	serialSliced = 0xc100e2e1
	serialShared = 0xc100e2e2
	serialPmem   = 0xc100f5e1
	// serials of the pool devices: one of volatile memory, one shared, one
	// of persistent memory.
	serialPoolX = 0xc1ee0001
	serialPoolS = 0xc1ae0001
	serialPoolP = 0xc1af0001

	// the status data of the pool devices
	poolExclusiveData = `{"serial":"0xc1ee0001","shared":false,"size":268435456,"host":"n1"}`
	poolSharedData    = `{"serial":"0xc1ae0001","shared":true,"size":268435456}`
	poolPmemData      = `{"serial":"0xc1af0001","shared":true,"size":536870912,"persistent":true}`
	poolWriterData    = `{"serial":"0xc1af0001","shared":true,"size":536870912,"persistent":true,"exclusive":true}`
)

// MemoryConfigs of the tests.
const (
	cfgDax     = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"dax"}}`
	cfgDaxRO   = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"dax","readOnly":true}}`
	cfgNUMA    = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"numa"}}`
	cfgBlock   = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"block"}}`
	cfgBlockRO = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"block","readOnly":true}}`
	cfgFsRO    = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs"}}`
	cfgFsRW    = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","readOnly":false}}`
)

// driverEnv is a node for the tests of the front-end: the fake kernel of
// pkg/cxl/kernel/fake, a store in a temporary directory with the views of
// the state files, the device engine of both sources, the two plugins
// over them (cxl.nri.io, local; the pool driver, pool), the publisher of
// the local devices and a CDI directory. The kernel and the files outlive
// a restart (restart), the fakes of the lease broker and of NRI too.
type driverEnv struct {
	t *testing.T
	k *fake.Fake
	// dir is the plugin data directory of cxl.nri.io and of the store,
	// poolDir that of the pool driver.
	dir, poolDir, cdiDir, filesystems string

	st    *store.Store
	eng   *engine.Engine
	local *Plugin
	pool  *Plugin
	pub   *Publisher
	cache *cdiapi.Cache
	// rec is what the recovery of the last start did.
	rec *engine.Recovered

	// memdevs are the local memdevs that the scans find, by serial;
	// regions the regions that they find besides.
	memdevs map[uint64]*nricxl.MemoryDevice
	regions []*nricxl.RegionDevice
	// fsTypes are the filesystem types that mode fs may mount.
	fsTypes []string
	// base are the commands of the fake before those of the drivers.
	base string

	// mu guards shared and events.
	mu sync.Mutex
	// shared are the local memdevs configured shared or used shared.
	shared map[uint64]bool
	// events are the calls of the fakes of the broker and of NRI, in order.
	events []string

	// nodes and hooks are the lender of both drivers (Lender.Set) after
	// lend, leases the lease claims of cxl.nri.io after setLeases.
	nodes  *fakeNodes
	hooks  lend.LeaseHooks
	lent   bool
	leases *fakeLeaseClaims
}

// newDriverEnv returns a started node with the memdevs of specs plugged,
// the local ones (localSpecs) found by the scans of cxl.nri.io.
func newDriverEnv(t *testing.T, localSpecs []fake.MemdevSpec, poolSpecs ...fake.MemdevSpec) *driverEnv {
	t.Helper()
	dir := t.TempDir()
	e := &driverEnv{
		t:           t,
		k:           fake.New(t),
		dir:         filepath.Join(dir, device.DriverName),
		poolDir:     filepath.Join(dir, device.PoolDriverName),
		cdiDir:      filepath.Join(dir, "cdi"),
		filesystems: filepath.Join(dir, "filesystems"),
		memdevs:     map[uint64]*nricxl.MemoryDevice{},
		shared:      map[uint64]bool{},
		fsTypes:     slices.Clone(config.KnownFsTypes),
	}
	for _, d := range []string{e.dir, e.poolDir, e.cdiDir} {
		mustOK(t, os.MkdirAll(d, 0o755))
	}
	mustOK(t, os.WriteFile(e.filesystems, []byte("nodev\tproc\nnodev\ttmpfs\n\text4\n\txfs\n\terofs\n\tbtrfs\n\tsquashfs\n\tgfs2\n"), 0o644))
	for _, s := range localSpecs {
		e.plugLocal(s)
	}
	for _, s := range poolSpecs {
		e.k.Plug(s)
	}
	e.base = e.k.Commands()
	t.Cleanup(func() {
		if e.st != nil {
			_ = e.st.Close()
		}
	})
	e.start()
	return e
}

// slicedSpec, sharedSpec and pmemSpec are the specs of the local memdevs.
func slicedSpec() fake.MemdevSpec { return fake.MemdevSpec{Serial: serialSliced, Ram: 1 << 30} }
func sharedSpec() fake.MemdevSpec { return fake.MemdevSpec{Serial: serialShared, Ram: 1 << 30} }
func pmemSpec() fake.MemdevSpec {
	return fake.MemdevSpec{Serial: serialPmem, Pmem: 512 << 20, HostBridge: 24}
}

// poolSpec returns the spec of a pool device of volatile memory, poolPmemSpec
// of persistent memory.
func poolSpec(serial uint64) fake.MemdevSpec { return fake.MemdevSpec{Serial: serial} }
func poolPmemSpec(serial uint64) fake.MemdevSpec {
	return fake.MemdevSpec{Serial: serial, Pmem: 512 << 20}
}

// plugLocal hot-adds a local memdev that the scans find and returns its
// name memN.
func (e *driverEnv) plugLocal(spec fake.MemdevSpec) string {
	name := e.k.Plug(spec)
	ram, pmem := spec.Ram, spec.Pmem
	if ram == 0 && pmem == 0 {
		ram = 256 << 20
	}
	e.memdevs[spec.Serial] = &nricxl.MemoryDevice{
		Name: name, DevName: "cxl/" + name, SysfsPath: filepath.Join(e.k.SysRoot(), "bus/cxl/devices", name), RamSize: ram,
		PmemSize: pmem, Serial: spec.Serial, NodeAffinity: 0, Driver: "cxl_mem", Enabled: true,
	}
	return name
}

// setShared configures the local memdev with the serial shared.
func (e *driverEnv) setShared(serial uint64) {
	e.mu.Lock()
	e.shared[serial] = true
	e.mu.Unlock()
	e.rescan()
}

// isShared tells whether the local memdev is configured or used shared.
func (e *driverEnv) isShared(serial uint64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.shared[serial]
}

// start starts the drivers on the env's kernel and files, as a start of
// the process does: the store opened, the engine of both sources and its
// recovery, both plugins with the lender and the lease claims of the env,
// their CDI specs written, a scan of the local devices.
func (e *driverEnv) start() {
	t := e.t
	t.Helper()
	ctx := context.Background()
	local := LocalRules(filepath.Join(e.dir, "mounts"))
	pool := PoolRules(device.PoolDriverName, filepath.Join(e.poolDir, "mounts"), e.preparingFile())
	st, err := store.Open(ctx, store.Options{Dir: e.dir, PoolDir: e.poolDir, PoolDriver: pool.Name, BootID: e.k.BootID(),
		CompatViews: true, SysRoot: e.k.SysRoot(), DevRoot: e.k.DevRoot()})
	mustOK(t, err)
	e.st = st
	e.eng, err = engine.New(engine.Options{
		Kernel:      e.k.Kernel(),
		Store:       st,
		Drivers:     map[state.Source]string{state.SourcePool: pool.Name, state.SourceLocal: local.Name},
		MountsDirs:  MountsDirs(local, pool),
		Records:     map[state.Source]string{state.SourcePool: e.preparingFile()},
		Sources:     []state.Source{state.SourcePool, state.SourceLocal},
		LeaseFsRoot: e.leaseFsRoot(),
		FsTypes:     e.fsTypes,
		Filesystems: e.filesystems,
		Shared:      func(serial state.Serial) bool { return e.isShared(uint64(serial)) },
		Revoke:      e.revoke,
		Timeouts: engine.Timeouts{Memdev: 300 * time.Millisecond, ProbeGrace: 20 * time.Millisecond, RegionRetry: 10 * time.Millisecond,
			Settle: 2 * time.Second, LocalSettle: 2 * time.Second, Restore: time.Second, Holder: 50 * time.Millisecond,
			OfflineSettle: 20 * time.Millisecond, Offline: time.Second},
	})
	mustOK(t, err)
	e.rec, err = e.eng.Recover(ctx)
	mustOK(t, err)
	e.cache, err = cdiapi.NewCache(cdiapi.WithSpecDirs(e.cdiDir), cdiapi.WithAutoRefresh(false))
	mustOK(t, err)
	e.pub, err = NewPublisher(PublishOptions{
		Config:    e.publishConfig(),
		NodeName:  envNode,
		Scan:      func() (*nricxl.Devices, error) { return e.detected(), nil },
		Store:     st,
		Probes:    e.eng.Probes,
		BlockSize: e.k.Kernel().BlockSize,
	})
	mustOK(t, err)
	e.local, err = New(Options{
		Rules:    local,
		Store:    st,
		Engine:   e.eng,
		NodeName: envNode,
		BootID:   e.k.BootID(),
		DevRoot:  e.k.DevRoot(),
		CDI:      e.cache,
		Local: LocalConfig{Managed: true, UsableSize: func(string, uint64) uint64 { return 0 },
			Coherent: func(string, uint64) bool { return false }},
		OnShared: func(serial uint64) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.shared[serial] = true
		},
		Publisher: e.pub,
	})
	mustOK(t, err)
	e.pool, err = New(Options{Rules: pool, Store: st, Engine: e.eng, NodeName: envNode, BootID: e.k.BootID(),
		DevRoot: e.k.DevRoot(), CDI: e.cache})
	mustOK(t, err)
	if e.lent {
		e.local.Lender().Set(e.nodeLender(), e.hooks)
		e.pool.Lender().Set(e.nodeLender(), e.hooks)
	}
	if e.leases != nil {
		e.local.SetLeases(e.leases)
	}
	e.pool.Recovered(e.rec, filepath.Join(e.poolDir, "preparedPoolClaims.json"))
	e.local.Recovered(e.rec, "")
	mustOK(t, e.local.WriteCDI())
	mustOK(t, e.pool.WriteCDI())
	e.rescan()
	e.check("started")
}

// restart stops the drivers (the store closed) and starts them again on
// the same kernel and files; it returns what the recovery did.
func (e *driverEnv) restart() *engine.Recovered {
	e.t.Helper()
	_ = e.st.Close()
	e.start()
	return e.rec
}

// reboot reboots the node (nothing of the kernel objects of the drivers is
// left, the memdevs stay) and starts the drivers again.
func (e *driverEnv) reboot() {
	e.t.Helper()
	e.k.Reboot()
	e.base = e.k.Commands()
	e.restart()
}

// preparingFile is the name of the records of the pool claims whose
// Prepare did not finish in the log lines.
func (e *driverEnv) preparingFile() string {
	return filepath.Join(e.poolDir, "preparingPoolClaims.json")
}

// leaseFsRoot is the directory of the lease-fs directories.
func (e *driverEnv) leaseFsRoot() string {
	return filepath.Join(e.dir, "lease-fs")
}

// publishConfig returns the configuration of the scans: local memdevs,
// the DRAM and the lease device published, the shared memdevs listed.
func (e *driverEnv) publishConfig() PublishConfig {
	e.mu.Lock()
	defer e.mu.Unlock()
	cfg := PublishConfig{ManageMemdevs: true, PublishLeaseDevice: true}
	for _, s := range slices.Sorted(maps.Keys(e.shared)) {
		cfg.SharedDevices = append(cfg.SharedDevices, fmt.Sprintf("0x%x", s))
	}
	return cfg
}

// detected returns the devices that a scan of the node finds: the local
// memdevs, the extra regions and two NUMA nodes of DRAM.
func (e *driverEnv) detected() *nricxl.Devices {
	d := &nricxl.Devices{RegionDevices: e.regions, MemoryNodes: []*nricxl.MemoryNode{
		{ID: 0, Name: "node0", Size: 8 << 30}, {ID: 1, Name: "node1", Size: 8 << 30},
	}}
	for _, s := range slices.Sorted(maps.Keys(e.memdevs)) {
		d.MemoryDevices = append(d.MemoryDevices, e.memdevs[s])
	}
	return d
}

// rescan sets the devices of the publisher as a scan of the node does.
func (e *driverEnv) rescan() {
	e.t.Helper()
	cfg := e.publishConfig()
	e.pub.SetConfig(cfg)
	mustOK(e.t, e.pub.ScanWith(context.Background(), cfg, e.pool.Serials()))
}

// addRegion adds a region that existed before the driver, on node, to the
// scans; its memdev is none of the env's.
func (e *driverEnv) addRegion(name string, node int, size uint64) string {
	e.regions = append(e.regions, &nricxl.RegionDevice{Name: name, Node: node, Size: size, Mode: "ram", Enabled: true,
		SysfsPath: filepath.Join(e.k.SysRoot(), "bus/cxl/devices", name), Targets: []string{"decoder9.0"},
		Memories: []*nricxl.MemoryDevice{{Name: "mem9", Serial: 0xeeee, NodeAffinity: 1}}})
	e.rescan()
	return fmt.Sprintf("%s-node%d", name, node)
}

// lend sets the lender of both drivers: the fake of NRI (nil: NRI is not
// connected) and the hooks of the broker (nil: lending disabled).
func (e *driverEnv) lend(nodes *fakeNodes, hooks lend.LeaseHooks) {
	e.nodes, e.hooks, e.lent = nodes, hooks, true
	e.local.Lender().Set(e.nodeLender(), hooks)
	e.pool.Lender().Set(e.nodeLender(), hooks)
}

// nodeLender returns the node lender of the env, nil for none.
func (e *driverEnv) nodeLender() NodeLender {
	if e.nodes == nil {
		return nil
	}
	return e.nodes
}

// lending sets fakes of NRI and of the broker as the lender of both
// drivers and returns them.
func (e *driverEnv) lending() (*fakeNodes, *fakeHooks) {
	nodes, hooks := &fakeNodes{e: e}, &fakeHooks{e: e}
	e.lend(nodes, hooks)
	return nodes, hooks
}

// setLeases sets a fake of the lease claims of the broker on cxl.nri.io
// and returns it.
func (e *driverEnv) setLeases() *fakeLeaseClaims {
	e.leases = &fakeLeaseClaims{e: e}
	e.local.SetLeases(e.leases)
	return e.leases
}

// revoke revokes the NUMA node that a grant of a companion claim lends,
// through the lender of the driver of the grant's source, as the engine's
// Revoke of the process does.
func (e *driverEnv) revoke(ctx context.Context, ref state.GrantRef, lend state.GrantLend) error {
	r := &e.st.Snapshot().Records
	p := e.pool
	if g := r.Grant(ref); g != nil && g.Asked.Source == state.SourceLocal {
		p = e.local
	}
	claimName := ref.Claim
	if prep := r.Preparation(p.Name(), ref.Claim); prep != nil && prep.ClaimName != "" {
		claimName = prep.ClaimName
	}
	return p.Lender().RevokeGrant(ctx, lend, claimName)
}

// check fails the test on a violation of the invariants of the records and
// the kernel now (Engine.Check, with state.Check, for both sources), and
// on a change of a kernel object that no row of its table has since the
// last check.
func (e *driverEnv) check(what string) {
	e.t.Helper()
	snap, err := e.eng.Observe(context.Background())
	mustOK(e.t, err)
	for _, v := range e.eng.Check(snap, []state.Source{state.SourcePool, state.SourceLocal}, nil) {
		e.t.Errorf("%s: %s", what, v)
	}
	for _, line := range e.eng.UnknownSeen() {
		e.t.Errorf("%s: %s%s", what, engine.UnknownTransition, line)
	}
}

// prepare prepares a claim on the plugin as kubelet does and checks the
// invariants after it; it returns the result.
func (e *driverEnv) prepare(p *Plugin, claim *resourcev1.ResourceClaim) kubeletplugin.PrepareResult {
	e.t.Helper()
	res, err := p.PrepareResourceClaims(context.Background(), []*resourcev1.ResourceClaim{claim})
	mustOK(e.t, err)
	e.check(p.Name() + ": prepared " + string(claim.UID))
	return res[claim.UID]
}

// mustPrepare prepares a claim, failing the test on an error.
func (e *driverEnv) mustPrepare(p *Plugin, claim *resourcev1.ResourceClaim) kubeletplugin.PrepareResult {
	e.t.Helper()
	res := e.prepare(p, claim)
	if res.Err != nil {
		e.t.Fatalf("%s: prepare %s: %v", p.Name(), claim.UID, res.Err)
	}
	return res
}

// unprepare unprepares the claim uid on the plugin as kubelet does and
// checks the invariants after it.
func (e *driverEnv) unprepare(p *Plugin, uid string) error {
	e.t.Helper()
	res, err := p.UnprepareResourceClaims(context.Background(), []kubeletplugin.NamespacedObject{{UID: types.UID(uid)}})
	mustOK(e.t, err)
	e.check(p.Name() + ": unprepared " + uid)
	return res[types.UID(uid)]
}

// mustUnprepare unprepares a claim, failing the test on an error.
func (e *driverEnv) mustUnprepare(p *Plugin, uid string) {
	e.t.Helper()
	if err := e.unprepare(p, uid); err != nil {
		e.t.Fatalf("%s: unprepare %s: %v", p.Name(), uid, err)
	}
}

// records returns the records of the store.
func (e *driverEnv) records() *state.Records {
	return &e.st.Snapshot().Records
}

// preparation returns the preparation of the claim uid of the plugin, nil
// for none.
func (e *driverEnv) preparation(p *Plugin, uid string) *state.Preparation {
	return e.records().Preparation(p.Name(), uid)
}

// stateOf returns the state of the preparation of the claim uid of the
// plugin, UNKNOWN for none.
func (e *driverEnv) stateOf(p *Plugin, uid string) state.PreparationState {
	if prep := e.preparation(p, uid); prep != nil {
		return prep.State
	}
	return state.PreparationUnknown
}

// wantState fails the test unless the preparation of the claim uid of the
// plugin is in the state.
func (e *driverEnv) wantState(p *Plugin, uid string, want state.PreparationState) {
	e.t.Helper()
	if got := e.stateOf(p, uid); got != want {
		e.t.Fatalf("%s: claim %s is %s, expected %s", p.Name(), uid, got, want)
	}
}

// commands returns the commands that the fake ran since the last mark
// (newDriverEnv, mark).
func (e *driverEnv) commands() string {
	return e.k.CommandsSince(e.base)
}

// mark makes the commands so far those before the test's.
func (e *driverEnv) mark() {
	e.base = e.k.Commands()
}

// wantNoCommands fails the test when the fake ran a command since the
// last mark.
func (e *driverEnv) wantNoCommands(what string) {
	e.t.Helper()
	if cmds := e.commands(); cmds != "" {
		e.t.Fatalf("%s: commands ran:\n%s", what, cmds)
	}
}

// wantClean fails the test unless nothing is prepared: no preparation,
// grant, memdev or region record, no region in the kernel, no CDI spec.
func (e *driverEnv) wantClean() {
	e.t.Helper()
	r := e.records()
	if len(r.Preparations)+len(r.Grants)+len(r.Memdevs)+len(r.Regions) > 0 {
		e.t.Fatalf("records left: preparations %+v grants %+v memdevs %+v regions %+v", r.Preparations, r.Grants, r.Memdevs, r.Regions)
	}
	snap, err := e.k.Kernel().Observe(context.Background())
	mustOK(e.t, err)
	for _, ri := range snap.Regions {
		e.t.Errorf("region %s (%s) left", ri.Name, ri.State)
	}
	for _, name := range []string{device.ClaimsCDISpecName, device.PoolCDISpecName} {
		if spec := e.cdiSpec(name); spec != nil {
			e.t.Errorf("CDI spec %s left: %+v", name, spec.Devices)
		}
	}
}

// cdiSpec returns the CDI spec of the name on disk, nil if there is none.
func (e *driverEnv) cdiSpec(name string) *cdiSpecs.Spec {
	e.t.Helper()
	m, _ := filepath.Glob(filepath.Join(e.cdiDir, name+".*"))
	if len(m) == 0 {
		return nil
	}
	data, err := os.ReadFile(m[0])
	mustOK(e.t, err)
	spec := &cdiSpecs.Spec{}
	mustOK(e.t, yaml.Unmarshal(data, spec))
	return spec
}

// cdiDevice returns the CDI device of the name in the spec of the plugin
// on disk, nil if there is none.
func (e *driverEnv) cdiDevice(p *Plugin, name string) *cdiSpecs.Device {
	e.t.Helper()
	spec := e.cdiSpec(p.Rules().CDISpecName)
	if spec == nil {
		return nil
	}
	for i := range spec.Devices {
		if spec.Devices[i].Name == name {
			return &spec.Devices[i]
		}
	}
	return nil
}

// cdiNames returns the names of the devices of the CDI spec of the plugin
// on disk, in order.
func (e *driverEnv) cdiNames(p *Plugin) []string {
	e.t.Helper()
	var out []string
	if spec := e.cdiSpec(p.Rules().CDISpecName); spec != nil {
		for _, d := range spec.Devices {
			out = append(out, d.Name)
		}
	}
	return out
}

// event records a call of a fake.
func (e *driverEnv) event(format string, args ...any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, fmt.Sprintf(format, args...))
}

// takeEvents returns the calls of the fakes so far and forgets them.
func (e *driverEnv) takeEvents() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.events
	e.events = nil
	return out
}

// wantEvents fails the test unless the calls of the fakes since the last
// takeEvents are want, in order.
func (e *driverEnv) wantEvents(what string, want ...string) {
	e.t.Helper()
	if got := e.takeEvents(); !slices.Equal(got, want) {
		e.t.Fatalf("%s: calls\n%s\nexpected\n%s", what, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// localClaim returns a claim of cxl.nri.io allocated the device dev of the
// node for request "mem", consuming bytes of it (0: no consumed capacity,
// < 0: that many shares), with the opaque configs of cxl.nri.io.
func localClaim(uid, dev string, consumed int64, configs ...string) *resourcev1.ResourceClaim {
	c := &resourcev1.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID(uid), Name: "claim-" + uid, Namespace: envNS},
		Status:     resourcev1.ResourceClaimStatus{Allocation: &resourcev1.AllocationResult{}},
	}
	addLocalResult(c, "mem", dev, consumed)
	for _, params := range configs {
		addConfig(c, device.DriverName, nil, params)
	}
	return c
}

// addLocalResult adds an allocation result of cxl.nri.io for the request
// on the device dev of the node to a claim (consumed as localClaim).
func addLocalResult(c *resourcev1.ResourceClaim, request, dev string, consumed int64) *resourcev1.ResourceClaim {
	r := resourcev1.DeviceRequestAllocationResult{Request: request, Driver: device.DriverName, Pool: envNode, Device: dev}
	switch {
	case consumed > 0:
		r.ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{device.CapacityMemory: *resource.NewQuantity(consumed, resource.BinarySI)}
	case consumed < 0:
		r.ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{device.CapacityShares: *resource.NewQuantity(-consumed, resource.DecimalSI)}
	}
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results, r)
	return c
}

// addConfig adds an opaque configuration of the driver for the requests
// (nil: all of them) to the allocation of a claim.
func addConfig(c *resourcev1.ResourceClaim, driver string, requests []string, params string) *resourcev1.ResourceClaim {
	c.Status.Allocation.Devices.Config = append(c.Status.Allocation.Devices.Config, resourcev1.DeviceAllocationConfiguration{
		Source:   resourcev1.AllocationConfigSourceClaim,
		Requests: requests,
		DeviceConfiguration: resourcev1.DeviceConfiguration{Opaque: &resourcev1.OpaqueDeviceConfiguration{
			Driver: driver, Parameters: runtime.RawExtension{Raw: json.RawMessage(params)},
		}},
	})
	return c
}

// poolConsumed returns the consumed capacity of an allocation result of a
// pool device with the status data: of a shared device all of its shares
// (exclusive) or one, nil otherwise.
func poolConsumed(data string) map[resourcev1.QualifiedName]resource.Quantity {
	var d struct{ Shared, Exclusive bool }
	if err := json.Unmarshal([]byte(data), &d); err != nil || !d.Shared {
		return nil
	}
	if d.Exclusive {
		return map[resourcev1.QualifiedName]resource.Quantity{device.CapacityShares: *resource.NewQuantity(device.SharesUnlimited, resource.DecimalSI)}
	}
	return map[resourcev1.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse("1")}
}

// poolClaim returns a claim allocated the pool device dev for request "mem"
// and the DRAM of cxl.nri.io for request "local", with the status data of
// the pool controller ("": none yet) and the opaque configs of the pool
// driver.
func poolClaim(uid, dev, data string, configs ...string) *resourcev1.ResourceClaim {
	c := &resourcev1.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID(uid), Name: "claim-" + uid, Namespace: envNS},
		Status: resourcev1.ResourceClaimStatus{Allocation: &resourcev1.AllocationResult{Devices: resourcev1.DeviceAllocationResult{
			Results: []resourcev1.DeviceRequestAllocationResult{
				{Request: "mem", Driver: device.PoolDriverName, Pool: envPool, Device: dev, ConsumedCapacity: poolConsumed(data)},
				{Request: "local", Driver: device.DriverName, Pool: envNode, Device: device.DRAMDeviceName},
			},
		}}},
	}
	if data != "" {
		setPoolData(c, dev, data)
	}
	for _, params := range configs {
		addConfig(c, device.PoolDriverName, nil, params)
	}
	return c
}

// setPoolData sets the status data of the pool device dev of a claim, as
// the pool controller writes it after its attach.
func setPoolData(c *resourcev1.ResourceClaim, dev, data string) *resourcev1.ResourceClaim {
	c.Status.Devices = append(c.Status.Devices, resourcev1.AllocatedDeviceStatus{
		Driver: device.PoolDriverName, Pool: envPool, Device: dev, Data: &runtime.RawExtension{Raw: []byte(data)},
	})
	for i := range c.Status.Allocation.Devices.Results {
		if r := &c.Status.Allocation.Devices.Results[i]; r.Driver == device.PoolDriverName && r.Device == dev {
			r.ConsumedCapacity = poolConsumed(data)
		}
	}
	return c
}

// addPoolResult adds an allocation result of the pool driver for the
// request on the pool device dev with its status data to a claim.
func addPoolResult(c *resourcev1.ResourceClaim, request, dev, data string) *resourcev1.ResourceClaim {
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
		resourcev1.DeviceRequestAllocationResult{Request: request, Driver: device.PoolDriverName, Pool: envPool, Device: dev})
	return setPoolData(c, dev, data)
}

// companion makes a claim the companion claim of the lease id, as the
// broker creates it: name, label and owner.
func companion(c *resourcev1.ResourceClaim, id string) *resourcev1.ResourceClaim {
	c.Name = "cxl-lease-" + id
	c.Labels = map[string]string{device.LeaseLabel: id}
	controller := true
	c.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: envPod, UID: envPodUID, Controller: &controller}}
	return c
}

// fakeNodes is NRI's lender of NUMA nodes: it records its calls in the
// events of the env.
type fakeNodes struct {
	e         *driverEnv
	mu        sync.Mutex
	lendErr   error
	revokeErr error
	// onLend and onRevoke are called at every lend and revoke, nil for
	// nothing; cut stops the process after the next lend.
	onLend, onRevoke func(node int)
	cut              bool
	lent             map[int][]string // node -> holders
}

// LendNode lends a node to the container on behalf of holder.
func (f *fakeNodes) LendNode(_ context.Context, podUID, name string, node int, holder string) error {
	f.e.event("lend %s/%s %d %s", podUID, name, node, holder)
	f.mu.Lock()
	on, cut := f.onLend, f.cut
	f.cut = false
	f.mu.Unlock()
	if on != nil {
		on(node)
	}
	if cut {
		panic(fake.ErrCut)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lendErr != nil {
		return f.lendErr
	}
	if f.lent == nil {
		f.lent = map[int][]string{}
	}
	if !slices.Contains(f.lent[node], holder) {
		f.lent[node] = append(f.lent[node], holder)
	}
	return nil
}

// RevokeNode drops holder of the node.
func (f *fakeNodes) RevokeNode(_ context.Context, podUID, name string, node int, holder string) error {
	f.e.event("revoke %s/%s %d %s", podUID, name, node, holder)
	f.mu.Lock()
	on, err := f.onRevoke, f.revokeErr
	f.mu.Unlock()
	if on != nil {
		on(node)
	}
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lent == nil {
		return nil
	}
	f.lent[node] = slices.DeleteFunc(f.lent[node], func(h string) bool { return h == holder })
	if len(f.lent[node]) == 0 {
		delete(f.lent, node)
	}
	return nil
}

// lentNodes returns the nodes that are lent, sorted.
func (f *fakeNodes) lentNodes() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(maps.Keys(f.lent))
}

// setErrors sets the errors of the next lends and revokes.
func (f *fakeNodes) setErrors(lend, revoke error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lendErr, f.revokeErr = lend, revoke
}

// fakeHooks is the lease broker of the companion claims: it records its
// calls in the events of the env.
type fakeHooks struct {
	e  *driverEnv
	mu sync.Mutex
	// lendingErr is the error of OnLending; fsDir and name are the FsDir
	// and the Name of the lends of OnLending.
	lendingErr  error
	fsDir, name string
	// block blocks OnLending of a claim of the name until its channel is
	// closed; entered gets the claim names of OnLending when it is set.
	block   map[string]chan struct{}
	entered chan string
	devs    []lend.LentDevice
}

// OnLending returns the lend of the lease's container.
func (h *fakeHooks) OnLending(id string, claim *resourcev1.ResourceClaim) (*lend.Lend, error) {
	h.e.event("lending %s %s", id, claim.Name)
	h.mu.Lock()
	err, block, entered := h.lendingErr, h.block[claim.Name], h.entered
	lend := &lend.Lend{Lease: id, Pod: state.PodRef{Namespace: envNS, Name: envPod, UID: envPodUID}, Container: envCtr, FsDir: h.fsDir, Name: h.name}
	h.mu.Unlock()
	if entered != nil {
		entered <- claim.Name
	}
	if block != nil {
		<-block
	}
	if err != nil {
		return nil, err
	}
	return lend, nil
}

// OnPrepared marks the lease Ready with the devices.
func (h *fakeHooks) OnPrepared(id string, devs []lend.LentDevice) {
	h.e.event("prepared %s", id)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.devs = devs
}

// OnLendFailed records a lend error.
func (h *fakeHooks) OnLendFailed(id string, err error) {
	h.e.event("failed %s: %v", id, err)
}

// OnReleasing is told the Unprepare of the companion claim.
func (h *fakeHooks) OnReleasing(id string) {
	h.e.event("releasing %s", id)
}

// lentDevices returns the devices of the last OnPrepared.
func (h *fakeHooks) lentDevices() []lend.LentDevice {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.devs)
}

// setLendingErr sets the error of the next OnLending calls.
func (h *fakeHooks) setLendingErr(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lendingErr = err
}

// fakeSpecHooks are fakeHooks that also tell the hash of the spec of the
// companion claims (SpecHasher).
type fakeSpecHooks struct {
	*fakeHooks
	hash  string
	first bool
}

// CompanionSpecHash returns the hash and whether the lease waits for its
// first Prepare.
func (h *fakeSpecHooks) CompanionSpecHash(lease string) (string, bool) {
	h.e.event("spec hash %s", lease)
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hash, h.first
}

// fakeLeaseClaims are the lease claims of the broker: it records its calls
// in the events of the env and the lease claims in the store as the broker
// keeps them.
type fakeLeaseClaims struct {
	e        *driverEnv
	mu       sync.Mutex
	openErr  error
	closeErr error
}

// OpenClaim records the claim OPEN.
func (f *fakeLeaseClaims) OpenClaim(claim *resourcev1.ResourceClaim) error {
	f.e.event("open %s", claim.UID)
	f.mu.Lock()
	err := f.openErr
	f.mu.Unlock()
	if err != nil {
		return err
	}
	return f.e.st.Commit(context.Background(), store.Durable, func(doc *store.Document) error {
		if doc.LeaseClaim(string(claim.UID)) == nil {
			doc.LeaseClaims = append(doc.LeaseClaims, state.LeaseClaim{UID: string(claim.UID), Namespace: claim.Namespace,
				Name: claim.Name, Pods: []state.PodRef{}, State: state.LeaseClaimOpen})
		}
		return nil
	})
}

// CloseClaim removes the record of the claim; unknown claims are not an
// error.
func (f *fakeLeaseClaims) CloseClaim(ctx context.Context, uid string) error {
	f.e.event("close %s (%s)", uid, f.e.stateOf(f.e.local, uid))
	f.mu.Lock()
	err := f.closeErr
	f.mu.Unlock()
	if err != nil {
		return err
	}
	return f.e.st.Commit(ctx, store.Durable, func(doc *store.Document) error {
		doc.LeaseClaims = slices.DeleteFunc(doc.LeaseClaims, func(c state.LeaseClaim) bool { return c.UID == uid })
		return nil
	})
}

// setErrors sets the errors of the next opens and closes.
func (f *fakeLeaseClaims) setErrors(open, close error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.openErr, f.closeErr = open, close
}

// formatPmem makes the fsdax namespace of the persistent memdev with the
// serial and a filesystem of the type on it ("": none), as a writer on
// another host leaves it (no region), and returns its block device.
func (e *driverEnv) formatPmem(serial uint64, typ string) string {
	e.t.Helper()
	k := e.k.Kernel()
	memdev := e.k.Memdev(serial)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d, err := k.RootDecoder(memdev, kernel.RegionPmem)
	mustOK(e.t, err)
	region, err := k.CreateRegion(ctx, kernel.CreateRegionRequest{Memdev: memdev, Decoder: d, Type: kernel.RegionPmem})
	mustOK(e.t, err)
	nd, err := k.WaitNdRegion(ctx, region)
	mustOK(e.t, err)
	ns, err := k.CreateFsdaxNamespace(ctx, nd, "")
	mustOK(e.t, err)
	if typ != "" {
		e.k.SetImage(ns.BlockDevice, fsImage(typ))
	}
	mustOK(e.t, k.ReleaseRegion(ctx, region))
	e.mark()
	return ns.BlockDevice
}

// fsImage returns the head of a block device with the signature of a
// filesystem type: erofs or ext4.
func fsImage(typ string) []byte {
	img := make([]byte, kernel.FsProbeBytes)
	switch typ {
	case "erofs":
		binary.LittleEndian.PutUint32(img[1024:], 0xE0F5E1E2)
	case "ext4":
		binary.LittleEndian.PutUint16(img[1080:], 0xEF53)
		binary.LittleEndian.PutUint32(img[1024+0x60:], 0x2)
	default:
		panic("fsImage: unknown type " + typ)
	}
	return img
}

// mustOK fails the test on an error.
func mustOK(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// wantErrText fails the test unless err has the text substr.
func wantErrText(t testing.TB, err error, substr string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), substr) {
		t.Fatalf("expected an error with %q, got %v", substr, err)
	}
}

// klogCapture makes klog write to a buffer at verbosity 3 for the test and
// returns a function that returns the output so far.
func klogCapture(t *testing.T) func() string {
	t.Helper()
	fs := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(fs)
	mustOK(t, fs.Set("logtostderr", "false"))
	mustOK(t, fs.Set("alsologtostderr", "false"))
	mustOK(t, fs.Set("v", "3"))
	var mu sync.Mutex
	var buf bytes.Buffer
	klog.SetOutput(logWriter(func(p []byte) (int, error) {
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

// logWriter is a writer of klog's output.
type logWriter func(p []byte) (int, error)

func (f logWriter) Write(p []byte) (int, error) { return f(p) }

// logLines returns the lines of a log that match the template of package
// compat (compat.Matches) with the placeholders <name> of a documented
// line replaced by the values of subst (name, value pairs).
func logLines(log, template string, subst ...string) []string {
	for i := 0; i+1 < len(subst); i += 2 {
		template = strings.ReplaceAll(template, "<"+subst[i]+">", subst[i+1])
	}
	var out []string
	for _, line := range strings.Split(log, "\n") {
		if compat.Matches(template, line) {
			out = append(out, line)
		}
	}
	return out
}

// wantLogLine fails the test unless the log has a line of the template
// (logLines).
func wantLogLine(t *testing.T, log, template string, subst ...string) {
	t.Helper()
	if len(logLines(log, template, subst...)) == 0 {
		t.Fatalf("no line %q (%q) in\n%s", template, subst, log)
	}
}

// wantLogText fails the test unless the log has the text in a line.
func wantLogText(t *testing.T, log, text string) {
	t.Helper()
	if !strings.Contains(log, text) {
		t.Fatalf("no %q in\n%s", text, log)
	}
}

// errSteered is an error of a fake.
var errSteered = errors.New("steered failure")
