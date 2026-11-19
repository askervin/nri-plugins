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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/engine"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// poolTestEnv is a node for the tests of the pool driver: the fake kernel
// of pkg/cxl/kernel/fake (sysfs, commands, mounts), a state store and a CDI
// directory in a temporary directory, and the pool driver over them. The
// kernel and the files outlive a restart of the driver (driver).
type poolTestEnv struct {
	t  *testing.T
	k  *fake.Fake
	st *store.Store
	// dir is the plugin data directory of the pool driver and of the
	// store.
	dir         string
	cdiDir      string
	leaseFsRoot string // of the pool driver, "" for none
	timeout     time.Duration
	holderWait  time.Duration
	// base are the commands of the fake before those of the driver.
	base string
	// pmem is the block device of the persistent device plugged last.
	pmem string
}

func newPoolTestEnv(t *testing.T) *poolTestEnv {
	dir := t.TempDir()
	e := &poolTestEnv{
		t:          t,
		k:          fake.New(t),
		dir:        filepath.Join(dir, device.PoolDriverName),
		cdiDir:     filepath.Join(dir, "cdi"),
		timeout:    200 * time.Millisecond,
		holderWait: 50 * time.Millisecond,
	}
	noErr(t, os.MkdirAll(e.dir, 0o755))
	t.Cleanup(func() {
		if e.st != nil {
			_ = e.st.Close()
		}
	})
	return e
}

// plug hot-adds the pool device with the serial (volatile memory) and
// returns its memdev.
func (e *poolTestEnv) plug(serial uint64) string {
	return e.k.Plug(fake.MemdevSpec{Serial: serial})
}

// plugPersistent hot-adds the pool device of persistent memory with the
// serial, whose fsdax namespace another host made with a filesystem of the
// types on it, and returns its memdev and its block device.
func (e *poolTestEnv) plugPersistent(serial uint64, types ...string) (string, string) {
	e.t.Helper()
	memdev := e.k.Plug(fake.MemdevSpec{Serial: serial, Pmem: 512 << 20})
	e.pmem = e.formatPmem(memdev, types...)
	return memdev, e.pmem
}

// formatPmem makes the fsdax namespace of the persistent memdev and a
// filesystem of the types on it, as a writer on another host would,
// leaving no region, and returns its block device.
func (e *poolTestEnv) formatPmem(memdev string, types ...string) string {
	e.t.Helper()
	k := e.k.Kernel()
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
		e.k.SetImage(ns.BlockDevice, fake.FsImage(types...))
	}
	noErr(e.t, k.ReleaseRegion(ctx, region))
	// the commands of the writer are not the driver's
	e.base = e.k.Commands()
	return ns.BlockDevice
}

// driver returns a new pool driver on the env's store, as after a restart
// (the store opened again, the engine's recovery), without a kubelet
// plugin. A driver returned before must not be used after.
func (e *poolTestEnv) driver(t *testing.T) *dra.Plugin {
	t.Helper()
	noErr(t, os.MkdirAll(e.cdiDir, 0o755))
	cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(e.cdiDir), cdiapi.WithAutoRefresh(false))
	noErr(t, err)
	if e.st != nil {
		_ = e.st.Close()
	}
	rules := dra.PoolRules(device.PoolDriverName, filepath.Join(e.dir, mountsDirName))
	e.st, err = store.Open(context.Background(), store.Options{Dir: e.dir, BootID: e.k.BootID()})
	noErr(t, err)
	devices, err := newDeviceEngine(deviceConfig{
		Engine: engine.Options{
			Kernel:      e.k.Kernel(),
			Store:       e.st,
			MountsDirs:  dra.MountsDirs(rules),
			LeaseFsRoot: e.leaseFsRoot,
			FsTypes:     api.KnownFsTypes,
			Timeouts: engine.Timeouts{Memdev: e.timeout, Settle: e.timeout, Holder: e.holderWait,
				ProbeGrace: 20 * time.Millisecond, RegionRetry: 10 * time.Millisecond, OfflineSettle: 20 * time.Millisecond},
		},
		PoolDriver: device.PoolDriverName,
	})
	noErr(t, err)
	p, err := dra.New(dra.Options{
		Rules:   rules,
		Store:   e.st,
		Engine:  devices.Engine,
		SysRoot: e.k.SysRoot(),
		DevRoot: e.k.DevRoot(),
		CDI:     cache,
	})
	noErr(t, err)
	devices.setLender(state.SourcePool, p.Lender())
	rec, err := devices.recover(context.Background())
	noErr(t, err)
	p.Recovered(rec)
	noErr(t, p.WriteCDI())
	checkPool(t, p, "started")
	return p
}

// records returns the records of the env's store.
func (e *poolTestEnv) records() *state.Records {
	return &e.st.Snapshot().Records
}

// preparation returns the preparation of the claim uid of the pool driver,
// nil if there is none.
func (e *poolTestEnv) preparation(uid string) *state.Preparation {
	return e.records().Preparation(device.PoolDriverName, uid)
}

// poolDevice is what the tests of the pool driver check of the device of
// a result of a claim in any state: the records of its grant (Size the
// size it got, else the one it asked), its memdev and region, and the
// settings of the result.
type poolDevice struct {
	Serial                state.Serial
	Mode                  string
	ReadOnly, Persistent  bool
	Size                  uint64
	Memdev, Region        string
	DaxDevice             string
	DaxMajor, DaxMinor    int
	NumaNode              int
	NdRegion, Namespace   string
	BlockDevice           string
	BlockMajor            int
	Access, Path, FsType  string
	NodeMount, LoopDevice string
	ResultSettings        config.ResultSettings
}

// device returns the device of the result n of the claim uid, failing the
// test without one.
func (e *poolTestEnv) device(p *dra.Plugin, uid string, n int) poolDevice {
	e.t.Helper()
	r := e.records()
	prep := r.Preparation(p.Name(), uid)
	if prep == nil || prep.Result(n) == nil || prep.Result(n).Grant == nil {
		e.t.Fatalf("claim %s has no grant of result %d", uid, n)
	}
	g := r.Grant(*prep.Result(n).Grant)
	if g == nil {
		e.t.Fatalf("claim %s: the grant of result %d has no record", uid, n)
	}
	d := poolDevice{Serial: g.Serial, Mode: string(g.Asked.Mode), ReadOnly: g.Asked.ReadOnly, Size: g.Got.Size,
		Region: string(g.Got.Region), NumaNode: state.NumaNodeOf(g.Got.NumaNode), Namespace: g.Got.Namespace,
		Access: string(g.Got.Mount), ResultSettings: prep.Result(n).Settings}
	if d.Size == 0 {
		d.Size = g.Asked.Size
	}
	if m := r.Memdev(g.Serial); m != nil {
		d.Memdev = m.Name
	}
	dev := r.DaxDevOf(g)
	d.DaxMajor, d.DaxMinor = dev.Major, dev.Minor
	if g.Asked.Mode == state.ModeDax && g.Got.Dax != "" {
		d.DaxDevice = filepath.Join(e.k.DevRoot(), g.Got.Dax)
	}
	if g.Asked.Mode == state.ModeBlock || g.Asked.Mode == state.ModeFs {
		d.Persistent = true
		if reg := r.Region(g.Got.Region); reg != nil && reg.Pmem != nil {
			d.NdRegion = reg.Pmem.NdRegion
		}
		if bd := g.Got.BlockDevice; bd != nil {
			d.BlockDevice, d.BlockMajor = bd.Name, bd.Dev.Major
		}
	}
	if g.Asked.Mode == state.ModeFs {
		d.Path = g.Asked.Path
		if m := r.MountOf(g); m != nil {
			d.NodeMount, d.LoopDevice, d.FsType = m.Path, m.Loop, m.FsType
		}
	}
	return d
}

// cdiSpec returns the pool CDI spec on disk, nil if there is none.
func (e *poolTestEnv) cdiSpec(t *testing.T) *cdiSpecs.Spec {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(e.cdiDir, device.PoolCDISpecName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	noErr(t, err)
	spec := &cdiSpecs.Spec{}
	noErr(t, json.Unmarshal(data, spec))
	return spec
}

func cdiDeviceByName(spec *cdiSpecs.Spec, name string) *cdiSpecs.Device {
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

// wantCDIDevice returns the CDI device with the name and the env.
func (e *poolTestEnv) wantCDIDevice(t *testing.T, name string, env []string) *cdiSpecs.Device {
	t.Helper()
	cd := cdiDeviceByName(e.cdiSpec(t), name)
	if cd == nil {
		t.Fatalf("no CDI device %s in %+v", name, e.cdiSpec(t))
	}
	if !slices.Equal(cd.ContainerEdits.Env, env) {
		t.Fatalf("CDI device %s env %v, expected %v", name, cd.ContainerEdits.Env, env)
	}
	return cd
}

// wantClean checks that nothing is prepared: no CDI spec, no serials, no
// record of the pool driver in the store, no region in the kernel.
func (e *poolTestEnv) wantClean(t *testing.T, p *dra.Plugin) {
	t.Helper()
	r := e.records()
	var left []string
	for i := range r.Preparations {
		if r.Preparations[i].Driver == device.PoolDriverName {
			left = append(left, "preparation "+r.Preparations[i].UID+" "+string(r.Preparations[i].State))
		}
	}
	for i := range r.Grants {
		left = append(left, "grant "+r.Grants[i].Ref.String()+" "+string(r.Grants[i].State))
	}
	for i := range r.Memdevs {
		left = append(left, "memdev "+r.Memdevs[i].Serial.String())
	}
	for i := range r.Regions {
		left = append(left, "region "+string(r.Regions[i].Ref()))
	}
	snap, err := e.k.Kernel().Observe(context.Background())
	noErr(t, err)
	for _, ri := range snap.Regions {
		left = append(left, "kernel "+ri.Name)
	}
	if e.cdiSpec(t) != nil || len(p.Serials()) != 0 || len(left) > 0 {
		t.Fatalf("not clean: CDI spec %+v, serials %v, records and regions %v", e.cdiSpec(t), p.Serials(), left)
	}
}

// commands returns the commands that the fake ran for the driver.
func (e *poolTestEnv) commands() string {
	return e.k.CommandsSince(e.base)
}

// grant returns the grant of result n of the claim uid, nil if there is
// none.
func (e *poolTestEnv) grant(uid string, n int) *state.Grant {
	return e.records().Grant(state.GrantRef{Claim: uid, Result: n})
}

// unfinished returns the preparation of the claim uid of the pool driver
// whose Prepare did not finish (PREPARING), that a rollback or the start
// kept (KEPT) or that is of another boot (PREPARED_STALE), nil if there is
// none.
func (e *poolTestEnv) unfinished(uid string) *state.Preparation {
	p := e.preparation(uid)
	if p == nil || (p.State != state.PreparationPreparing && p.State != state.PreparationKept && p.State != state.PreparationStale) {
		return nil
	}
	return p
}

// wantNoClaims checks that the pool driver has no claim: no CDI spec, no
// preparation and no grant.
func (e *poolTestEnv) wantNoClaims(t *testing.T, p *dra.Plugin) {
	t.Helper()
	r := e.records()
	if e.cdiSpec(t) != nil || len(r.Grants) > 0 || slices.ContainsFunc(r.Preparations, func(x state.Preparation) bool { return x.Driver == device.PoolDriverName }) {
		t.Fatalf("claims left: CDI spec %+v, preparations %+v, grants %+v", e.cdiSpec(t), r.Preparations, r.Grants)
	}
}

// wantCommand fails the test unless the fake ran a command that contains
// cmd.
func (e *poolTestEnv) wantCommand(t *testing.T, cmd string) {
	t.Helper()
	if cmds := e.commands(); !strings.Contains(cmds, cmd) {
		t.Fatalf("command %q not run:\n%s", cmd, cmds)
	}
}

// wantReleased fails the test unless the last commands released region0
// of mem0 and disabled the memdev.
func (e *poolTestEnv) wantReleased(t *testing.T, region, memdev string) {
	t.Helper()
	cmds := e.commands()
	want := "cxl disable-region " + region + "\ncxl destroy-region " + region + "\ncxl disable-memdev " + memdev
	if !strings.Contains(cmds, want) {
		t.Fatalf("device not released (%q):\n%s", want, cmds)
	}
}

// onlineBlocks returns the number of the memory blocks of a region that
// are online.
func (e *poolTestEnv) onlineBlocks(region string) int {
	k := e.k.Kernel()
	blocks, _ := k.RegionBlocks(region)
	n := 0
	for _, b := range blocks {
		if k.MemoryBlock(b).State == kernel.BlockOnline {
			n++
		}
	}
	return n
}

// poolConsumed returns the consumed capacity of an allocation result of
// a pool device with the status data: of a shared device all of its
// shares (exclusive) or one, nil otherwise.
func poolConsumed(data string) map[resourceapi.QualifiedName]resource.Quantity {
	d, err := device.ParsePoolStatusData([]byte(data))
	switch {
	case err != nil || !d.Shared:
		return nil
	case d.Exclusive:
		return map[resourceapi.QualifiedName]resource.Quantity{device.CapacityShares: *resource.NewQuantity(device.SharesUnlimited, resource.DecimalSI)}
	}
	return map[resourceapi.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse("1")}
}

// poolClaim returns a claim allocated a pool device, with the status
// entry written by the pool controller (data "" for none) and the shares
// that the scheduler counts for a shared device (poolConsumed).
func poolClaim(uid, name, dev, data string) *resourceapi.ResourceClaim {
	c := &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID(uid), Name: name, Namespace: "default"},
		Status: resourceapi.ResourceClaimStatus{
			Allocation: &resourceapi.AllocationResult{
				Devices: resourceapi.DeviceAllocationResult{
					Results: []resourceapi.DeviceRequestAllocationResult{
						{Request: "mem", Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: dev, ConsumedCapacity: poolConsumed(data)},
						{Request: "local", Driver: device.DriverName, Pool: "node1", Device: "dram"},
					},
				},
			},
		},
	}
	if data != "" {
		c.Status.Devices = []resourceapi.AllocatedDeviceStatus{
			{Driver: device.DriverName, Pool: "node1", Device: "dram"},
			{Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: dev, Data: &runtime.RawExtension{Raw: []byte(data)}},
		}
	}
	return c
}

func prepare(t *testing.T, p *dra.Plugin, claim *resourceapi.ResourceClaim) kubeletplugin.PrepareResult {
	t.Helper()
	res, err := p.PrepareResourceClaims(context.Background(), []*resourceapi.ResourceClaim{claim})
	if err != nil {
		t.Fatal(err)
	}
	checkPool(t, p, "prepared "+string(claim.UID))
	return res[claim.UID]
}

// kubeletClaim returns the claim uid as kubelet unprepares it: with the
// namespace and the name of a prepared claim.
func kubeletClaim(p *dra.Plugin, uid string) kubeletplugin.NamespacedObject {
	claim := kubeletplugin.NamespacedObject{UID: types.UID(uid)}
	if info := p.ClaimInfo(uid); info != nil {
		claim.Namespace, claim.Name, _ = strings.Cut(info.ClaimName, "/")
	}
	return claim
}

func unprepare(t *testing.T, p *dra.Plugin, uid string) error {
	t.Helper()
	res, err := p.UnprepareResourceClaims(context.Background(), []kubeletplugin.NamespacedObject{kubeletClaim(p, uid)})
	if err != nil {
		t.Fatal(err)
	}
	checkPool(t, p, "unprepared "+uid)
	return res[types.UID(uid)]
}

// checkPool fails the test on a violation of the invariants of the records
// of the pool driver and the kernel now: the document's (state.Check) and
// the engine's; and on a change of a kernel object that no row of its
// table has since the last check.
func checkPool(t *testing.T, p *dra.Plugin, what string) {
	t.Helper()
	snap, err := p.Engine().Observe(context.Background())
	noErr(t, err)
	for _, v := range p.Engine().Check(snap, []state.Source{state.SourcePool}, nil) {
		t.Errorf("%s: %s", what, v)
	}
	for _, line := range p.Engine().UnknownSeen() {
		t.Errorf("%s: %s%s", what, engine.UnknownTransition, line)
	}
}

func wantErr(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), substr) {
		t.Fatalf("expected an error with %q, got %v", substr, err)
	}
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// kernelAt returns the kernel of the node with its sysfs in root/sys.
func kernelAt(root string) *kernel.Kernel {
	k := kernel.New()
	k.SysRoot = filepath.Join(root, "sys")
	return k
}

// errCut is the panic of a process stop of the fake (fake.ErrCut).
var errCut = fake.ErrCut

// cutPrepare runs a Prepare of the claim that the process does not finish:
// it stops (panics with fake.ErrCut) at a cut point of the fake. The test
// then starts the driver again on the same store and kernel.
func cutPrepare(t *testing.T, p *dra.Plugin, claim *resourceapi.ResourceClaim) {
	t.Helper()
	defer func() {
		r := recover()
		if err, ok := r.(error); ok && errors.Is(err, errCut) {
			return
		}
		if r == nil {
			t.Fatal("the Prepare was not cut")
		}
		panic(r)
	}()
	_, _ = p.PrepareResourceClaims(context.Background(), []*resourceapi.ResourceClaim{claim})
}

// nodeMount returns the node mount of mode fs of the device with the
// serial and the access.
func (e *poolTestEnv) nodeMount(serial uint64, access string) string {
	return filepath.Join(e.dir, mountsDirName, fmt.Sprintf("%x-%s", serial, access))
}

// mounts returns the mounts of the node as the driver's mount table has
// them.
func (e *poolTestEnv) mounts() ([]mountInfo, error) {
	return e.k.Kernel().Mounts()
}

// mounted returns the mount at target, nil if there is none.
func (e *poolTestEnv) mounted(target string) *mountInfo {
	ms, _ := e.mounts()
	for i := len(ms) - 1; i >= 0; i-- {
		if ms[i].Target == target {
			return &ms[i]
		}
	}
	return nil
}

// wantNoMounts fails the test when a node mount or a lease bind of the
// pool driver is mounted.
func (e *poolTestEnv) wantNoMounts(t *testing.T, p *dra.Plugin) {
	t.Helper()
	ms, err := e.mounts()
	noErr(t, err)
	for _, m := range ms {
		if strings.HasPrefix(m.Target, e.dir+"/") || (e.leaseFsRoot != "" && strings.HasPrefix(m.Target, e.leaseFsRoot+"/")) {
			t.Fatalf("mounted: %+v", m)
		}
	}
	if v := e.k.Violations(); len(v) > 0 {
		t.Fatalf("mount rules violated: %v", v)
	}
}

// mountedErr returns the mount at target, nil if there is none, and no
// error, as a mount table does.
func (e *poolTestEnv) mountedErr(target string) (*mountInfo, error) {
	return e.mounted(target), nil
}
