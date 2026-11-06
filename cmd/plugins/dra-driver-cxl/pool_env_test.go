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
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"sigs.k8s.io/yaml"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

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
	// store, stateFile its view of the prepared claims.
	dir, stateFile string
	cdiDir         string
	leaseFsRoot    string // of the pool driver, "" for none
	filesystems    string
	timeout        time.Duration
	holderWait     time.Duration
	// fence fences the NUMA nodes, nil for none.
	fence *nodeFence
	// base are the commands of the fake before those of the driver.
	base string
	// pmem is the block device of the persistent device plugged last.
	pmem string
}

func newPoolTestEnv(t *testing.T) *poolTestEnv {
	dir := t.TempDir()
	e := &poolTestEnv{
		t:           t,
		k:           fake.New(t),
		dir:         filepath.Join(dir, device.PoolDriverName),
		cdiDir:      filepath.Join(dir, "cdi"),
		filesystems: filepath.Join(dir, "filesystems"),
		timeout:     200 * time.Millisecond,
		holderWait:  50 * time.Millisecond,
	}
	e.stateFile = filepath.Join(e.dir, poolStateFileName)
	noErr(t, os.MkdirAll(e.dir, 0o755))
	noErr(t, os.WriteFile(e.filesystems, []byte("nodev\tproc\nnodev\ttmpfs\n\text4\n\txfs\n\terofs\n\tbtrfs\n\tsquashfs\n\tgfs2\n"), 0o644))
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
		e.k.SetImage(ns.BlockDevice, fsImage(types...))
	}
	noErr(e.t, k.ReleaseRegion(ctx, region))
	// the commands of the writer are not the driver's
	e.base = e.k.Commands()
	return ns.BlockDevice
}

// driver returns a new pool driver on the env's store, as after a restart
// (the store opened again, the engine's recovery), without a kubelet
// plugin. A driver returned before must not be used after.
func (e *poolTestEnv) driver(t *testing.T) *poolDriver {
	t.Helper()
	noErr(t, os.MkdirAll(e.cdiDir, 0o755))
	cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(e.cdiDir), cdiapi.WithAutoRefresh(false))
	noErr(t, err)
	if e.st != nil {
		_ = e.st.Close()
	}
	e.st, err = store.Open(context.Background(), store.Options{Dir: e.dir, PoolDir: e.dir, PoolDriver: device.PoolDriverName,
		BootID: e.k.BootID(), CompatViews: true, DropOtherBoot: func(driver string) bool { return driver == device.DriverName }})
	noErr(t, err)
	devices, err := newDeviceEngine(deviceConfig{
		Kernel:        e.k.Kernel(),
		Store:         e.st,
		PoolDriver:    device.PoolDriverName,
		PoolDataDir:   e.dir,
		LeaseFsRoot:   e.leaseFsRoot,
		FsTypes:       config.KnownFsTypes,
		Filesystems:   e.filesystems,
		Fence:         e.fence,
		PoolTimeout:   e.timeout,
		HolderWait:    e.holderWait,
		ProbeGrace:    20 * time.Millisecond,
		RegionRetry:   10 * time.Millisecond,
		OfflineSettle: 20 * time.Millisecond,
	})
	noErr(t, err)
	p, err := newPoolDriver(poolConfig{
		Name:    device.PoolDriverName,
		Devices: devices,
		Store:   e.st,
		DataDir: e.dir,
		BootID:  e.k.BootID(),
		FsTypes: config.KnownFsTypes,
		Fence:   e.fence,
	})
	noErr(t, err)
	rec, err := devices.recover(context.Background())
	noErr(t, err)
	p.recovered(rec)
	p.cdi = cache
	noErr(t, p.writeCDISpec(""))
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

// device returns the device of the result n of the claim uid as the view
// gives it, failing the test without one.
func (e *poolTestEnv) device(p *poolDriver, uid string, n int) preparedPoolDevice {
	e.t.Helper()
	prep := e.preparation(uid)
	if prep == nil {
		e.t.Fatalf("claim %s has no record", uid)
	}
	for _, d := range p.devicesOf(prep) {
		if d.Result == n {
			return d
		}
	}
	e.t.Fatalf("claim %s has no device of result %d", uid, n)
	return preparedPoolDevice{}
}

// cdiSpec returns the pool CDI spec on disk, nil if there is none.
func (e *poolTestEnv) cdiSpec(t *testing.T) *cdiSpecs.Spec {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(e.cdiDir, device.PoolCDISpecName+".*"))
	if len(m) == 0 {
		return nil
	}
	data, err := os.ReadFile(m[0])
	noErr(t, err)
	spec := &cdiSpecs.Spec{}
	noErr(t, yaml.Unmarshal(data, spec))
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
func (e *poolTestEnv) wantClean(t *testing.T, p *poolDriver) {
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

// preparingFile returns the records of the claims whose Prepare did not
// finish, as preparingPoolClaims.json has them.
func (e *poolTestEnv) preparingFile(t *testing.T) map[string]*preparingPoolClaim {
	t.Helper()
	data, err := preparingContent(e.st.Snapshot(), e.st.ViewOptions())
	noErr(t, err)
	recs := map[string]*preparingPoolClaim{}
	noErr(t, json.Unmarshal(data, &recs))
	return recs
}

// wantNoClaims checks that the pool driver has no claim: no CDI spec, no
// preparation and no grant.
func (e *poolTestEnv) wantNoClaims(t *testing.T, p *poolDriver) {
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
	d, err := parsePoolDeviceData([]byte(data))
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

// addPoolDevice adds an allocation result of request req for the pool
// device dev with the status data to a claim.
func addPoolDevice(c *resourceapi.ResourceClaim, req, dev, data string) *resourceapi.ResourceClaim {
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
		resourceapi.DeviceRequestAllocationResult{Request: req, Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: dev, ConsumedCapacity: poolConsumed(data)})
	if data != "" {
		c.Status.Devices = append(c.Status.Devices,
			resourceapi.AllocatedDeviceStatus{Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: dev, Data: &runtime.RawExtension{Raw: []byte(data)}})
	}
	return c
}

func prepare(t *testing.T, p *poolDriver, claim *resourceapi.ResourceClaim) kubeletplugin.PrepareResult {
	t.Helper()
	res, err := p.PrepareResourceClaims(context.Background(), []*resourceapi.ResourceClaim{claim})
	if err != nil {
		t.Fatal(err)
	}
	checkPool(t, p, "prepared "+string(claim.UID))
	return res[claim.UID]
}

func unprepare(t *testing.T, p *poolDriver, uid string) error {
	t.Helper()
	res, err := p.UnprepareResourceClaims(context.Background(), []kubeletplugin.NamespacedObject{{UID: types.UID(uid)}})
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
func checkPool(t *testing.T, p *poolDriver, what string) {
	t.Helper()
	snap, err := p.engine.Observe(context.Background())
	noErr(t, err)
	for _, v := range p.engine.Check(snap, []state.Source{state.SourcePool}, nil) {
		t.Errorf("%s: %s", what, v)
	}
	for _, line := range p.engine.UnknownSeen() {
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

// errCut is the panic of a process stop of the fake (fake.ErrCut).
var errCut = fake.ErrCut

// cutPrepare runs a Prepare of the claim that the process does not finish:
// it stops (panics with fake.ErrCut) at a cut point of the fake. The test
// then starts the driver again on the same store and kernel.
func cutPrepare(t *testing.T, p *poolDriver, claim *resourceapi.ResourceClaim) {
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
func (e *poolTestEnv) wantNoMounts(t *testing.T, p *poolDriver) {
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

// wantDaxDriver fails the test unless the dax device is bound to driver.
func (e *poolTestEnv) wantDaxDriver(t *testing.T, dax, driver string) {
	t.Helper()
	if d := e.k.DaxDriver(dax); d != driver {
		t.Fatalf("%s is bound to %q, expected %s", dax, d, driver)
	}
}

// wantOffline fails the test when memory of the region is online.
func (e *poolTestEnv) wantOffline(t *testing.T, region string) {
	t.Helper()
	if n := e.onlineBlocks(region); n != 0 {
		t.Fatalf("%d memory blocks of %s online", n, region)
	}
}

// bindCall returns the mount call of a bind of a node mount at target.
func bindCall(nodeMount, target string) string {
	return fmt.Sprintf("mount %s %s  0x%x ", nodeMount, target, unix.MS_BIND)
}

// mountedErr returns the mount at target, nil if there is none, and no
// error, as a mount table does.
func (e *poolTestEnv) mountedErr(target string) (*mountInfo, error) {
	return e.mounted(target), nil
}

// parseHexSerial returns the serial of its 0x hex text.
func parseHexSerial(t *testing.T, text string) uint64 {
	t.Helper()
	serial, err := api.ParseSerial(text)
	noErr(t, err)
	return serial
}

// setImage writes a filesystem of the types on the fsdax namespace of the
// persistent memdev, which has no region of the driver.
func (e *poolTestEnv) setImage(memdev string, types ...string) {
	e.t.Helper()
	k := e.k.Kernel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// a release of the driver disabled it
	noErr(e.t, k.EnableMemdev(ctx, memdev))
	d, err := k.RootDecoder(memdev, kernel.RegionPmem)
	noErr(e.t, err)
	region, err := k.CreateRegion(ctx, kernel.CreateRegionRequest{Memdev: memdev, Decoder: d, Type: kernel.RegionPmem})
	noErr(e.t, err)
	nd, err := k.WaitNdRegion(ctx, region)
	noErr(e.t, err)
	nss, err := k.Namespaces(ctx, nd)
	noErr(e.t, err)
	ns := kernel.FsdaxNamespace(nss)
	if ns == nil {
		e.t.Fatalf("%s has no fsdax namespace", memdev)
	}
	e.k.SetImage(ns.BlockDevice, fsImage(types...))
	noErr(e.t, k.ReleaseRegion(ctx, region))
	e.base = e.k.Commands()
}

// plugPmem hot-adds the pool device of persistent memory with the serial
// without a namespace (none was ever made on it) and returns its memdev.
func (e *poolTestEnv) plugPmem(serial uint64) string {
	// the block device of the namespace that a writer makes
	e.pmem = filepath.Join(e.k.DevRoot(), "pmem0")
	return e.k.Plug(fake.MemdevSpec{Serial: serial, Pmem: 512 << 20})
}

// loop returns the path of the loop device n of the fake.
func (e *poolTestEnv) loop(n int) string {
	return filepath.Join(e.k.DevRoot(), "loop"+strconv.Itoa(n))
}

// loops returns the loop devices of the fake that are attached.
func (e *poolTestEnv) loops() []kernel.LoopDevice {
	return e.k.Kernel().LoopDevices()
}
