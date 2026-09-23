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
	"encoding/binary"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
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

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/engine"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

const (
	// localSerial is the serial of the local memdev of the tests, mem0
	// under host bridge 12 of the fake kernel, published as
	// localDeviceName.
	localSerial     = 0xc100e2e1
	localDeviceName = "memdev-c100e2e1"
	mib             = 1 << 20
	// localRegionSize is the size of the local memdev and its region.
	localRegionSize = 1 << 30
	// localBlockSize is the memory block size of the fake kernel.
	localBlockSize = 128 * mib
	// fakePmemBytes is the size of the block device of a persistent memdev
	// of 512 MiB of the fake kernel: its fsdax namespace without the pfn
	// info block.
	fakePmemBytes = 534773760
)

// localTestEnv is a node for the tests of the local memdevs of cxl.nri.io:
// the fake kernel of pkg/cxl/kernel/fake (sysfs, commands, mounts), a state
// store, the plugin data directories and a CDI directory in a temporary
// directory, the device engine of both sources over them and the node
// state of cxl.nri.io (s, made by start). The kernel and the files outlive
// a restart (restart).
type localTestEnv struct {
	t *testing.T
	k *fake.Fake
	// st is the store of the node state s; devices its device engine.
	st      *store.Store
	devices *deviceEngine
	s       *dra.Plugin
	// publisher publishes the devices of the node; cdi is the CDI cache
	// of the claims.
	publisher *dra.Publisher
	cdi       *cdiapi.Cache
	// dir is the plugin data directory of cxl.nri.io and of the store,
	// poolDir that of the pool driver.
	dir, poolDir string
	cdiDir       string
	filesystems  string
	// config is the configuration of the driver; shared the serials of
	// the local memdevs it declares shared; poolSerials those of pool
	// devices, which the local guard refuses.
	config      *DriverConfig
	shared      map[uint64]bool
	poolSerials map[uint64]bool
	// fence fences the NUMA nodes of memory before it goes online, nil
	// for none.
	fence func(ctx context.Context, node int)
	// holderWait is the holder wait of a release.
	holderWait time.Duration
	// memdevs are the local memdevs that the publisher sees, by serial.
	memdevs map[uint64]kernel.MemdevInfo
	// base are the commands of the fake before those of the driver.
	base string
	// rec is what the recovery of the last start found.
	rec *engine.Recovered
}

// newLocalTestEnv returns a node with the local memdev localSerial (1 GiB
// of RAM under host bridge 12) and the memdevs of specs plugged; start
// starts the driver on it.
func newLocalTestEnv(t *testing.T, specs ...fake.MemdevSpec) *localTestEnv {
	t.Helper()
	dir := t.TempDir()
	e := &localTestEnv{
		t:           t,
		k:           fake.New(t),
		dir:         filepath.Join(dir, device.DriverName),
		poolDir:     filepath.Join(dir, device.PoolDriverName),
		cdiDir:      filepath.Join(dir, "cdi"),
		filesystems: filepath.Join(dir, "filesystems"),
		config:      &DriverConfig{IgnoreDRAMNodes: true},
		shared:      map[uint64]bool{},
		poolSerials: map[uint64]bool{},
		holderWait:  50 * time.Millisecond,
		memdevs:     map[uint64]kernel.MemdevInfo{},
	}
	for _, d := range []string{e.dir, e.poolDir, e.cdiDir} {
		noErr(t, os.MkdirAll(d, 0o755))
	}
	noErr(t, os.WriteFile(e.filesystems, []byte("nodev\tproc\nnodev\ttmpfs\n\text4\n\txfs\n\terofs\n\tbtrfs\n\tsquashfs\n\tgfs2\n"), 0o644))
	e.plug(fake.MemdevSpec{Serial: localSerial, Ram: localRegionSize})
	for _, s := range specs {
		e.plug(s)
	}
	e.base = e.k.Commands()
	t.Cleanup(func() {
		if e.st != nil {
			_ = e.st.Close()
		}
	})
	return e
}

// plug hot-adds a local memdev and adds it to those that the publisher
// sees; it returns its name memN.
func (e *localTestEnv) plug(spec fake.MemdevSpec) string {
	name := e.k.Plug(spec)
	ram, pmem := spec.Ram, spec.Pmem
	if ram == 0 && pmem == 0 {
		ram = 256 * mib
	}
	m := observedMemdev(name, spec.Serial, ram, 0)
	m.PmemSize = pmem
	if spec.Disabled {
		m.State = kernel.MemdevUnbound
	}
	e.memdevs[spec.Serial] = m
	return name
}

// start starts the driver on the env's kernel and files, as a start of the
// process does: the store opened (again), the device engine of both
// sources, its recovery, the node state of cxl.nri.io with the devices of a
// scan. A node state returned before must not be used after.
func (e *localTestEnv) start() *dra.Plugin {
	t := e.t
	t.Helper()
	if e.st != nil {
		_ = e.st.Close()
	}
	var err error
	e.st, err = store.Open(context.Background(), store.Options{Dir: e.dir, PoolDir: e.poolDir, PoolDriver: device.PoolDriverName,
		BootID: e.k.BootID(), SysRoot: e.k.SysRoot(), DevRoot: e.k.DevRoot()})
	noErr(t, err)
	e.devices, err = newDeviceEngine(deviceConfig{
		Kernel:          e.k.Kernel(),
		Store:           e.st,
		MountsDirs:      dra.MountsDirs(e.rules()...),
		PoolDriver:      device.PoolDriverName,
		PoolDataDir:     e.poolDir,
		LocalDir:        e.dir,
		LeaseFsRoot:     filepath.Join(e.dir, leaseFsDirName),
		StateFile:       filepath.Join(e.dir, store.FileName),
		FsTypes:         e.config.fsTypes(),
		Filesystems:     e.filesystems,
		Fence:           e.fence,
		ProbeAddressing: e.config.verifyAddressing(),
		PoolTimeout:     200 * time.Millisecond,
		HolderWait:      e.holderWait,
		ProbeGrace:      20 * time.Millisecond,
		RegionRetry:     10 * time.Millisecond,
		OfflineSettle:   20 * time.Millisecond,
	})
	noErr(t, err)
	e.devices.setShared(e.shared)
	var pools []uint64
	for s, ok := range e.poolSerials {
		if ok {
			pools = append(pools, s)
		}
	}
	noErr(t, e.devices.forgetPoolSerials(context.Background(), e.poolSerials))
	e.rec, err = e.devices.recover(context.Background())
	noErr(t, err)
	e.devices.setGuard(func(_ context.Context, serial uint64) error {
		if slices.Contains(pools, serial) || e.poolSerials[serial] {
			return errors.New("memory device serial is a pool device: it is not used as a local memory device")
		}
		return nil
	})
	if e.config.manageMemdevs() {
		if _, err := e.k.Kernel().BlockSize(); err != nil {
			klog.Warningf("local: memory block size: %v: local memory devices are not published until the memory block size is known", err)
		}
	}
	cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(e.cdiDir), cdiapi.WithAutoRefresh(false))
	noErr(t, err)
	e.cdi = cache
	e.publisher, err = dra.NewPublisher(dra.PublishOptions{
		Config:    e.config.publishConfig(),
		NodeName:  testNode,
		Scan:      func(context.Context) (*kernel.Snapshot, error) { return e.detected(), nil },
		Store:     e.st,
		Probes:    e.devices.Probes,
		BlockSize: e.k.Kernel().BlockSize,
	})
	noErr(t, err)
	e.s, err = dra.New(dra.Options{
		Rules:     e.rules()[0],
		Store:     e.st,
		Engine:    e.devices.Engine,
		NodeName:  testNode,
		BootID:    e.k.BootID(),
		DevRoot:   e.k.DevRoot(),
		CDI:       cache,
		Local:     e.config.localConfig(),
		OnShared:  e.devices.addShared,
		Publisher: e.publisher,
	})
	noErr(t, err)
	e.devices.setLender(state.SourceLocal, e.s.Lender())
	e.s.Recovered(e.rec, "")
	noErr(t, e.s.WriteCDI())
	e.rescan()
	e.check("started")
	return e.s
}

// restart stops the driver and starts it again on the same kernel and
// files.
func (e *localTestEnv) restart() *dra.Plugin {
	e.t.Helper()
	return e.start()
}

// reboot reboots the node: nothing of the kernel objects of the drivers is
// left, the memdevs stay; the driver is started again.
func (e *localTestEnv) reboot() *dra.Plugin {
	e.t.Helper()
	e.k.Reboot()
	return e.start()
}

// detected returns the observation of the node that a scan makes: the
// local memdevs that the publisher sees.
func (e *localTestEnv) detected() *kernel.Snapshot {
	detected := &kernel.Snapshot{}
	for _, serial := range slices.Sorted(maps.Keys(e.memdevs)) {
		detected.Memdevs = append(detected.Memdevs, e.memdevs[serial])
	}
	return detected
}

// rescan publishes the local memdevs as a scan of the publisher does.
func (e *localTestEnv) rescan() {
	e.t.Helper()
	cfg := e.config.publishConfig()
	e.publisher = e.publisherOf(cfg)
	noErr(e.t, e.publisher.ScanWith(context.Background(), cfg, e.poolSerials))
}

// publisherOf returns the publisher of the env with the configuration cfg
// (the configuration of the env may have changed since the start).
func (e *localTestEnv) publisherOf(cfg dra.PublishConfig) *dra.Publisher {
	e.publisher.SetConfig(cfg)
	return e.publisher
}

// prepare prepares a claim on the node state, as the kubelet plugin does,
// and checks the invariants after it.
func (e *localTestEnv) prepare(claim *resourcev1.ResourceClaim) error {
	e.t.Helper()
	res, err := e.s.PrepareResourceClaims(context.Background(), []*resourcev1.ResourceClaim{claim})
	noErr(e.t, err)
	e.check("prepared " + string(claim.UID))
	return res[claim.UID].Err
}

// unprepare unprepares the claim uid and checks the invariants after it.
func (e *localTestEnv) unprepare(uid string) error {
	e.t.Helper()
	res, err := e.s.UnprepareResourceClaims(context.Background(), []kubeletplugin.NamespacedObject{{UID: types.UID(uid)}})
	noErr(e.t, err)
	e.check("unprepared " + uid)
	return res[types.UID(uid)]
}

// mustPrepare prepares a claim, failing the test on an error.
func (e *localTestEnv) mustPrepare(claim *resourcev1.ResourceClaim) {
	e.t.Helper()
	if err := e.prepare(claim); err != nil {
		e.t.Fatalf("prepare %s: %v", claim.UID, err)
	}
}

// mustUnprepare unprepares a claim, failing the test on an error.
func (e *localTestEnv) mustUnprepare(uid string) {
	e.t.Helper()
	if err := e.unprepare(uid); err != nil {
		e.t.Fatalf("unprepare %s: %v", uid, err)
	}
}

// check fails the test on a violation of the invariants of the records and
// the kernel now, and on a change of a kernel object that no row of its
// table has since the last check.
func (e *localTestEnv) check(what string) {
	e.t.Helper()
	snap, err := e.devices.Observe(context.Background())
	noErr(e.t, err)
	for _, v := range e.devices.Check(snap, []state.Source{state.SourceLocal, state.SourcePool}, nil) {
		e.t.Errorf("%s: %s", what, v)
	}
	for _, line := range e.devices.UnknownSeen() {
		e.t.Errorf("%s: %s%s", what, engine.UnknownTransition, line)
	}
}

// cut runs fn, which the process does not finish: it stops (panics with
// fake.ErrCut) at a cut point of the fake; cut reports whether it did.
func (e *localTestEnv) cut(fn func()) (cut bool) {
	defer func() {
		if p := recover(); p != nil {
			if err, ok := p.(error); !ok || !errors.Is(err, fake.ErrCut) {
				panic(p)
			}
			cut = true
		}
	}()
	fn()
	return false
}

// records returns the records of the env's store.
func (e *localTestEnv) records() *state.Records {
	return &e.st.Snapshot().Records
}

// preparation returns the preparation of the claim uid of cxl.nri.io, nil
// if there is none.
func (e *localTestEnv) preparation(uid string) *state.Preparation {
	return e.records().Preparation(device.DriverName, uid)
}

// grant returns the grant of result n of the claim uid, nil if there is
// none.
func (e *localTestEnv) grant(uid string, n int) *state.Grant {
	return e.records().Grant(state.GrantRef{Claim: uid, Result: n})
}

// commands returns the commands that the fake ran for the driver.
func (e *localTestEnv) commands() string {
	return e.k.CommandsSince(e.base)
}

// localMemdev returns the record of the local memdev with the serial, nil
// if there is none.
func (e *localTestEnv) localMemdev(serial uint64) *state.Memdev {
	if m := e.records().Memdev(state.Serial(serial)); m != nil && m.Source == state.SourceLocal {
		return m
	}
	return nil
}

// localRegionRecord returns the record of the first region of ours on the
// local memdev with the serial, nil if it has none.
func (e *localTestEnv) localRegionRecord(serial uint64) *state.Region {
	r := e.records()
	if m := e.localMemdev(serial); m != nil {
		for _, ref := range m.Regions {
			if reg := r.Region(ref); reg != nil && reg.Ours() {
				return reg
			}
		}
	}
	return nil
}

// localRegion returns the first region of ours on the local memdev with
// the serial: its name once it is made (KEPT, or OWNED and no longer made
// for a first Prepare), else the name of the region being made as
// creating, and its first dax device once it is set up.
func (e *localTestEnv) localRegion(serial uint64) (region, creating, dax string) {
	reg := e.localRegionRecord(serial)
	switch {
	case reg == nil:
		return "", "", ""
	case reg.State == state.RegionOwned && e.records().RegionInMaking(e.localMemdev(serial), reg):
		return "", reg.Name, ""
	case reg.State == state.RegionOwned || reg.State == state.RegionKept:
		region = reg.Name
	case reg.State == state.RegionNoted || reg.State == state.RegionCreating:
		creating = reg.NotedName
	}
	if reg.SetUp {
		dax = reg.FirstDax()
	}
	return region, creating, dax
}

// localUses returns the claims of the local memdev with the serial with
// the number of their grants on it that got their use (REALISED,
// REALISED_UNRESTORED or RELEASING), 0 for a claim whose grant holds the
// region without a use yet (JOURNALED or REALISING). The dax devices of
// its regions that no grant uses are the uses of the claim "-".
func (e *localTestEnv) localUses(serial uint64) map[string]int {
	r := e.records()
	out := map[string]int{}
	m := e.localMemdev(serial)
	if m == nil {
		return out
	}
	for _, ref := range m.Grants {
		g := r.Grant(ref)
		if g == nil {
			continue
		}
		switch g.State {
		case state.GrantRealised, state.GrantUnrestored, state.GrantReleasing:
			out[ref.Claim]++
		case state.GrantJournaled, state.GrantRealising:
			if _, ok := out[ref.Claim]; !ok {
				out[ref.Claim] = 0
			}
		}
	}
	for _, ref := range m.Regions {
		reg := r.Region(ref)
		if reg == nil || !reg.Ours() {
			continue
		}
		for _, d := range reg.DaxDevices {
			if !d.Whole && d.State != state.DaxSeed && len(d.Users) == 0 {
				out["-"]++
			}
		}
	}
	return out
}

// inUse tells whether the engine has a record of the local memdev.
func (e *localTestEnv) inUse() bool {
	return e.localSnapshot().InUse(localSerial)
}

// rules returns the rules of cxl.nri.io and of the pool driver of the env.
func (e *localTestEnv) rules() []dra.SourceRules {
	return []dra.SourceRules{
		dra.LocalRules(filepath.Join(e.dir, mountsDirName)),
		dra.PoolRules(device.PoolDriverName, filepath.Join(e.poolDir, mountsDirName), filepath.Join(e.dir, store.FileName)),
	}
}

// allocatable returns the devices of the last scan of the node.
func (e *localTestEnv) allocatable() (device.DevicesInfo, error) {
	return e.publisher.Devices(), nil
}

// unmanaged makes cxl.nri.io a driver that does not manage local memdevs,
// on the same store, engine and publisher.
func (e *localTestEnv) unmanaged() {
	e.t.Helper()
	local := e.config.localConfig()
	local.Managed = false
	p, err := dra.New(dra.Options{
		Rules:     e.rules()[0],
		Store:     e.st,
		Engine:    e.devices.Engine,
		NodeName:  testNode,
		BootID:    e.k.BootID(),
		DevRoot:   e.k.DevRoot(),
		Local:     local,
		OnShared:  e.devices.addShared,
		Publisher: e.publisher,
	})
	noErr(e.t, err)
	p.SetCDI(e.cdi)
	e.s = p
	e.devices.setLender(state.SourceLocal, e.s.Lender())
}

// localSnapshot returns the uses of the local memdevs as the publisher sees
// them.
func (e *localTestEnv) localSnapshot() *dra.LocalSnapshot {
	return e.publisher.LocalSnapshot()
}

// prepared returns the PrepareResults that kubelet gets of the prepared
// claims of cxl.nri.io in the records, by UID.
func (e *localTestEnv) prepared() map[string]kubeletplugin.PrepareResult {
	r := e.records()
	out := map[string]kubeletplugin.PrepareResult{}
	for i := range r.Preparations {
		if p := &r.Preparations[i]; p.Driver == device.DriverName && p.Prepared() {
			out[p.UID] = store.PrepareResult(p, device.CDIKind)
		}
	}
	return out
}

// cdiSpec returns the CDI spec of the claims on disk, nil if there is
// none.
func (e *localTestEnv) cdiSpec() *cdiSpecs.Spec {
	e.t.Helper()
	m, _ := filepath.Glob(filepath.Join(e.cdiDir, device.ClaimsCDISpecName+".*"))
	if len(m) == 0 {
		return nil
	}
	data, err := os.ReadFile(m[0])
	noErr(e.t, err)
	spec := &cdiSpecs.Spec{}
	noErr(e.t, yaml.Unmarshal(data, spec))
	return spec
}

// wantCDIDevice checks the env and the device nodes of a CDI device of the
// claims spec.
func (e *localTestEnv) wantCDIDevice(name string, env []string, nodes []*cdiSpecs.DeviceNode) {
	e.t.Helper()
	d := cdiDeviceByName(e.cdiSpec(), name)
	if d == nil || !slices.Equal(d.ContainerEdits.Env, env) || !reflect.DeepEqual(d.ContainerEdits.DeviceNodes, nodes) {
		e.t.Fatalf("CDI device %s: %+v, expected env %v nodes %+v", name, d, env, nodes)
	}
}

// wantDeviceInfo checks the info of the first device of a prepared claim.
func (e *localTestEnv) wantDeviceInfo(uid string, want PreparedDeviceInfo) {
	e.t.Helper()
	info := e.s.ClaimInfo(uid)
	if info == nil || len(info.Devices) == 0 || !reflect.DeepEqual(info.Devices[0], want) {
		e.t.Fatalf("claim %s: device info\n%+v\nexpected\n%+v", uid, info, want)
	}
}

// wantClean fails the test unless nothing is prepared: no CDI device, no
// claim, no record of the engine, no region in the kernel.
func (e *localTestEnv) wantClean() {
	e.t.Helper()
	r := e.records()
	if len(r.Preparations)+len(r.Grants)+len(r.Memdevs)+len(r.Regions) > 0 {
		e.t.Fatalf("records left: preparations %+v grants %+v memdevs %+v regions %+v", r.Preparations, r.Grants, r.Memdevs, r.Regions)
	}
	snap, err := e.k.Kernel().Observe(context.Background())
	noErr(e.t, err)
	for _, ri := range snap.Regions {
		e.t.Errorf("region %s (%s) left", ri.Name, ri.State)
	}
	if spec := e.cdiSpec(); spec != nil && len(spec.Devices) > 0 {
		e.t.Errorf("CDI devices left: %+v", spec.Devices)
	}
}

// regions returns the regions of the memdev with the serial in the
// kernel.
func (e *localTestEnv) regions(serial uint64) []string {
	return e.k.Kernel().Regions(e.k.Memdev(serial))
}

// onlineBlocks returns the memory blocks of the kernel that are online.
func (e *localTestEnv) onlineBlocks() []int {
	snap, err := e.k.Kernel().Observe(context.Background())
	noErr(e.t, err)
	var out []int
	for _, b := range snap.Blocks {
		if b.State == kernel.BlockOnline {
			out = append(out, b.Index)
		}
	}
	return out
}

// formatPmem makes the fsdax namespace of the persistent memdev with the
// serial and a filesystem of the types on it, as a writer on another host
// would, leaving no region, and returns its block device.
func (e *localTestEnv) formatPmem(serial uint64, types ...string) string {
	e.t.Helper()
	k := e.k.Kernel()
	memdev := e.k.Memdev(serial)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d, err := k.RootDecoder(memdev, kernel.RegionPmem)
	noErr(e.t, err)
	region, err := k.CreateRegion(ctx, kernel.CreateRegionRequest{Memdev: memdev, Decoder: d, Type: kernel.RegionPmem})
	noErr(e.t, err)
	nd, err := k.WaitNdRegion(ctx, region)
	noErr(e.t, err)
	ns, err := k.CreateFsdaxNamespace(ctx, nd, "")
	noErr(e.t, err)
	if len(types) > 0 {
		e.k.SetImage(ns.BlockDevice, fsImage(types...))
	}
	noErr(e.t, k.ReleaseRegion(ctx, region))
	// the commands of the writer are not the driver's
	e.base = e.k.Commands()
	return ns.BlockDevice
}

// fsImage returns the head of a block device with the signatures of the
// filesystem types: ext4-dirty is an ext4 that needs recovery, gfs2-nolock
// a gfs2 without a cluster lock.
func fsImage(types ...string) []byte {
	img := make([]byte, kernel.FsProbeBytes)
	for _, t := range types {
		switch t {
		case "erofs":
			binary.LittleEndian.PutUint32(img[1024:], 0xE0F5E1E2)
		case "squashfs":
			copy(img, "hsqs")
		case "ext4", "ext4-dirty":
			binary.LittleEndian.PutUint16(img[1080:], 0xEF53)
			if t == "ext4-dirty" {
				binary.LittleEndian.PutUint32(img[1024+0x60:], 0x4|0x2)
			} else {
				binary.LittleEndian.PutUint32(img[1024+0x60:], 0x2)
			}
		case "xfs":
			copy(img, "XFSB")
		case "btrfs":
			copy(img[65600:], "_BHRfS_M")
		case "gfs2", "gfs2-nolock":
			binary.BigEndian.PutUint32(img[65536:], 0x01161970)
			binary.BigEndian.PutUint32(img[65540:], 1)
			proto := "lock_dlm"
			if t == "gfs2-nolock" {
				proto = "lock_nolock"
			}
			copy(img[65536+96:], proto+"\x00")
		default:
			panic("fsImage: unknown type " + t)
		}
	}
	return img
}

// makeOpaqueConfig returns an allocation config of the driver with config
// as its opaque parameters.
func makeOpaqueConfig(driver string, source resourcev1.AllocationConfigSource, config interface{}) resourcev1.DeviceAllocationConfiguration {
	raw, _ := json.Marshal(config)
	return resourcev1.DeviceAllocationConfiguration{
		Source: source,
		DeviceConfiguration: resourcev1.DeviceConfiguration{
			Opaque: &resourcev1.OpaqueDeviceConfiguration{
				Driver: driver,
				Parameters: runtime.RawExtension{
					Raw: raw,
				},
			},
		},
	}
}

// localMemdev returns the observed local memdev localSerial.
func localMemdev() kernel.MemdevInfo {
	m := observedMemdev("mem0", localSerial, localRegionSize, 0)
	m.Major = 251
	return m
}

// localClaim returns a claim allocated the local memdev for request "mem",
// consuming bytes of it (0: no consumed capacity), with opaque cxl.nri.io
// claim configs.
func localClaim(uid string, consumed int64, configs ...string) *resourcev1.ResourceClaim {
	return memdevClaim(uid, localDeviceName, consumed, configs...)
}

// memdevClaim returns a claim allocated the device dev of the node for
// request "mem", consuming bytes of it (0: no consumed capacity, < 0: one
// share), with opaque cxl.nri.io claim configs.
func memdevClaim(uid, dev string, consumed int64, configs ...string) *resourcev1.ResourceClaim {
	r := resourcev1.DeviceRequestAllocationResult{Request: "mem", Driver: device.DriverName, Pool: testNode, Device: dev}
	switch {
	case consumed > 0:
		r.ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{device.CapacityMemory: *resource.NewQuantity(consumed, resource.BinarySI)}
	case consumed < 0:
		r.ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{device.CapacityShares: *resource.NewQuantity(-consumed, resource.DecimalSI)}
	}
	c := &resourcev1.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID(uid), Name: "claim-" + uid, Namespace: testNS},
		Status: resourcev1.ResourceClaimStatus{
			Allocation: &resourcev1.AllocationResult{
				Devices: resourcev1.DeviceAllocationResult{Results: []resourcev1.DeviceRequestAllocationResult{r}},
			},
		},
	}
	for _, params := range configs {
		c.Status.Allocation.Devices.Config = append(c.Status.Allocation.Devices.Config,
			makeOpaqueConfig(device.DriverName, resourcev1.AllocationConfigSourceClaim, json.RawMessage(params)))
	}
	return c
}

// localCompanion returns localClaim as the companion claim of lease l1.
func localCompanion(uid string, consumed int64, configs ...string) *resourcev1.ResourceClaim {
	c := localClaim(uid, consumed, configs...)
	c.ObjectMeta = companionClaim("l1").ObjectMeta
	c.UID = types.UID(uid)
	return c
}

// memoryConfig returns a MemoryConfig of the device of mode, read-only or
// not, with the device settings extra (JSON members, "" for none).
func memoryConfig(mode string, readOnly bool, extra string) string {
	cfg := map[string]any{"mode": mode}
	if readOnly {
		cfg["readOnly"] = true
	}
	data, _ := json.Marshal(cfg)
	dev := string(data)
	if extra != "" {
		dev = strings.TrimSuffix(dev, "}") + "," + extra + "}"
	}
	return `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":` + dev + `}`
}

// fakeMemdevSpecPmem returns the spec of a local memdev of 512 MiB of
// persistent memory under host bridge 24.
func fakeMemdevSpecPmem(serial uint64) fake.MemdevSpec {
	return fake.MemdevSpec{Serial: serial, Pmem: 512 * mib, HostBridge: 24}
}
