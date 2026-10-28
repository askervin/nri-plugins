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
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"sigs.k8s.io/yaml"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
	"github.com/containers/nri-plugins/pkg/cxl/memctl"
)

// fakePoolSys is a sysfs tree with one hotplugged CXL memdev (mem0) under
// host bridge 12, with the cxl and daxctl CLIs faked on top of it, like
// the tests of nri-plugins pkg/cxl/memctl.
type fakePoolSys struct {
	t      *testing.T
	root   string
	mu     sync.Mutex
	cmds   []string
	labels bool // the LSA of a persistent mem0 has an fsdax namespace
	// cutAfter is the beginning of a command after which the plugin is
	// killed (cutPrepare), "" for none.
	cutAfter string
}

const fakeMemPath = "devices/pci0000:0c/0000:0c:00.0/0000:0d:00.0/0000:0e:00.0/0000:0f:00.0/mem0"

func newFakePoolSys(t *testing.T) *fakePoolSys {
	f := &fakePoolSys{t: t, root: t.TempDir()}
	f.write("devices/system/memory/block_size_bytes", "8000000")
	for _, b := range []string{"74", "75"} {
		f.write("devices/system/memory/memory"+b+"/state", "offline")
	}
	f.write("bus/cxl/devices/decoder0.0/devtype", "cxl_decoder_root")
	f.write("bus/cxl/devices/decoder0.0/target_list", "12")
	// the name of the next region, which the fake cxl create-region
	// always creates
	f.write("bus/cxl/devices/decoder0.0/create_ram_region", "region0")
	f.write("bus/cxl/devices/decoder0.0/create_pmem_region", "region0")
	f.mkdir("bus/cxl/drivers/cxl_mem")
	f.mkdir("bus/dax/drivers/kmem")
	f.mkdir("bus/dax/drivers/device_dax")
	f.mkdir("bus/dax/devices")
	return f
}

func (f *fakePoolSys) p(rel string) string { return filepath.Join(f.root, rel) }

func (f *fakePoolSys) mkdir(rel string) {
	f.t.Helper()
	if err := os.MkdirAll(f.p(rel), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakePoolSys) write(rel, val string) {
	f.t.Helper()
	f.mkdir(filepath.Dir(rel))
	if err := os.WriteFile(f.p(rel), []byte(val+"\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakePoolSys) read(rel string) string {
	b, _ := os.ReadFile(f.p(rel))
	return strings.TrimSpace(string(b))
}

func (f *fakePoolSys) link(rel, target string) {
	f.t.Helper()
	f.mkdir(filepath.Dir(rel))
	_ = os.Remove(f.p(rel))
	if err := os.Symlink(target, f.p(rel)); err != nil {
		f.t.Fatal(err)
	}
}

// plug makes mem0 with the serial appear with its endpoint and driver.
func (f *fakePoolSys) plug(serial string) {
	f.write(fakeMemPath+"/serial", serial)
	f.link("bus/cxl/devices/mem0", "../../../"+fakeMemPath)
	f.link(fakeMemPath+"/driver", "../../../../../../../bus/cxl/drivers/cxl_mem")
	f.mkdir("bus/cxl/devices/endpoint4")
	f.link("bus/cxl/devices/endpoint4/uport", "../../../../"+fakeMemPath)
}

// unplug removes mem0 (hot-remove by the pool).
func (f *fakePoolSys) unplug() {
	_ = os.Remove(f.p("bus/cxl/devices/mem0"))
	_ = os.RemoveAll(f.p("bus/cxl/devices/endpoint4"))
	_ = os.RemoveAll(f.p("devices/pci0000:0c"))
}

const daxPath = "bus/cxl/devices/region0/dax_region0/dax0.0"

// exec runs a faked command, and kills the plugin after it if it is the
// command of cutAfter.
func (f *fakePoolSys) exec(ctx context.Context, name string, args ...string) (string, error) {
	out, err := f.run(ctx, name, args...)
	cmd := name + " " + strings.Join(args, " ")
	f.mu.Lock()
	cut := f.cutAfter != "" && strings.HasPrefix(cmd, f.cutAfter)
	if cut {
		f.cutAfter = ""
	}
	f.mu.Unlock()
	if cut {
		panic(errCut)
	}
	return out, err
}

func (f *fakePoolSys) run(ctx context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
	f.mu.Unlock()
	if out, ok := f.execPmem(name, args...); ok {
		return out, nil
	}
	switch name + " " + args[0] {
	case "cxl create-region":
		f.write("bus/cxl/devices/region0/target0", "decoder4.0")
		f.write("bus/cxl/devices/region0/resource", "0x250000000")
		f.write("bus/cxl/devices/region0/size", "0x10000000")
		f.mkdir(daxPath)
		f.link("bus/dax/devices/dax0.0", "../../../"+daxPath)
		f.write(daxPath+"/target_node", "2")
		f.write(daxPath+"/dev", "251:3")
		f.link(daxPath+"/driver", "../../../../../dax/drivers/kmem")
		return `[{"region":"region0","resource":"0x250000000","size":"256.00 MiB"}]`, nil
	case "cxl enable-memdev":
		f.link(fakeMemPath+"/driver", "../../../../../../../bus/cxl/drivers/cxl_mem")
		return "", nil
	case "cxl disable-region":
		return "", nil
	case "cxl destroy-region":
		_ = os.RemoveAll(f.p("bus/cxl/devices/region0"))
		_ = os.Remove(f.p("bus/dax/devices/dax0.0"))
		f.removeNdRegion()
		return "", nil
	case "cxl disable-memdev":
		_ = os.Remove(f.p(fakeMemPath + "/driver"))
		return "", nil
	case "daxctl reconfigure-device":
		drv := "kmem"
		if strings.Contains(strings.Join(args, " "), "--mode=devdax") {
			drv = "device_dax"
		}
		f.link(daxPath+"/driver", "../../../../../dax/drivers/"+drv)
		return "", nil
	}
	return "", errors.New("unexpected command " + name + " " + strings.Join(args, " "))
}

func (f *fakePoolSys) commands() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.cmds, "\n")
}

func (f *fakePoolSys) manager() *memctl.Manager {
	return &memctl.Manager{
		SysRoot:      f.root,
		DevRoot:      "/dev",
		Exec:         f.exec,
		LookPath:     func(string) (string, error) { return "/usr/bin/daxctl", nil },
		PollInterval: 2 * time.Millisecond,
		Logf:         f.t.Logf,
		WriteFile:    f.writeAttr,
	}
}

// writeAttr writes a sysfs attribute; delete_region of a root decoder
// deletes the region under it, as the kernel does.
func (f *fakePoolSys) writeAttr(path, val string) error {
	if filepath.Base(path) != "delete_region" {
		return os.WriteFile(path, []byte(val), 0o644)
	}
	f.mu.Lock()
	f.cmds = append(f.cmds, "delete_region "+filepath.Base(filepath.Dir(path))+" "+val)
	f.mu.Unlock()
	dir := filepath.Join(filepath.Dir(path), val)
	if _, err := os.Stat(dir); err != nil {
		return err
	}
	_ = os.RemoveAll(dir)
	_ = os.Remove(f.p("bus/cxl/devices/" + val))
	return nil
}

// hollowRegion makes the region under root decoder decoder0.0 hollow, as
// the kernel leaves a region whose memdev was removed before it was
// destroyed (plan-13 bug-12): commit 0, target0 empty, the address range
// kept. A plain region directory of the fake is replaced.
func (f *fakePoolSys) hollowRegion(region, mode string) {
	_ = os.RemoveAll(f.p("bus/cxl/devices/" + region))
	dir := "bus/cxl/devices/decoder0.0/" + region
	for file, value := range map[string]string{
		"commit": "0", "devtype": "cxl_region", "interleave_ways": "1", "mode": mode,
		"resource": "0x850000000", "size": "0x10000000", "target0": "", "uuid": "675e71d7-179f-4beb-ab43-55f82e02b39a",
	} {
		f.write(dir+"/"+file, value)
	}
	f.link("bus/cxl/devices/"+region, "decoder0.0/"+region)
}

// errCut is the panic of a plugin killed in a Prepare (cutPrepare).
var errCut = errors.New("killed")

// cutPrepare runs a Prepare of the claim that the plugin does not finish:
// it is killed (errCut) where the fakes say, and nothing after that runs.
// The test then starts the plugin again on the same files and sysfs.
func cutPrepare(t *testing.T, p *poolDriver, claim *resourceapi.ResourceClaim) {
	t.Helper()
	defer func() {
		switch r := recover(); r {
		case errCut:
		case nil:
			t.Fatal("the Prepare was not cut")
		default:
			panic(r)
		}
	}()
	_, _ = p.PrepareResourceClaims(context.Background(), []*resourceapi.ResourceClaim{claim})
}

type poolTestEnv struct {
	f           *fakePoolSys
	m           *fakeMounter // the mounts of the node outlive driver restarts
	cdiDir      string
	stateFile   string
	leaseFsRoot string // of the pool driver, "" for none
}

func newPoolTestEnv(t *testing.T) *poolTestEnv {
	dir := t.TempDir()
	return &poolTestEnv{
		f:         newFakePoolSys(t),
		m:         newFakeMounter(),
		cdiDir:    filepath.Join(dir, "cdi"),
		stateFile: filepath.Join(dir, poolStateFileName),
	}
}

// driver returns a new pool driver on the env's state file, as after a
// restart, without a kubelet plugin.
func (e *poolTestEnv) driver(t *testing.T) *poolDriver {
	t.Helper()
	if err := os.MkdirAll(e.cdiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(e.cdiDir), cdiapi.WithAutoRefresh(false))
	if err != nil {
		t.Fatal(err)
	}
	p, err := newPoolDriver(device.PoolDriverName, e.f.manager(), e.m, e.stateFile, 200*time.Millisecond, e.leaseFsRoot)
	if err != nil {
		t.Fatal(err)
	}
	p.probeGrace = 20 * time.Millisecond
	p.holderWait = 50 * time.Millisecond
	p.cdi = cache
	if err := p.writeCDISpec(); err != nil {
		t.Fatal(err)
	}
	return p
}

// cdiSpec returns the pool CDI spec on disk, nil if there is none.
func (e *poolTestEnv) cdiSpec(t *testing.T) *cdiSpecs.Spec {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(e.cdiDir, device.PoolCDISpecName+".*"))
	if len(m) == 0 {
		return nil
	}
	data, err := os.ReadFile(m[0])
	if err != nil {
		t.Fatal(err)
	}
	spec := &cdiSpecs.Spec{}
	if err := yaml.Unmarshal(data, spec); err != nil {
		t.Fatal(err)
	}
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

func prepare(t *testing.T, p *poolDriver, claim *resourceapi.ResourceClaim) kubeletplugin.PrepareResult {
	t.Helper()
	res, err := p.PrepareResourceClaims(context.Background(), []*resourceapi.ResourceClaim{claim})
	if err != nil {
		t.Fatal(err)
	}
	return res[claim.UID]
}

func unprepare(t *testing.T, p *poolDriver, uid string) error {
	t.Helper()
	res, err := p.UnprepareResourceClaims(context.Background(), []kubeletplugin.NamespacedObject{{UID: types.UID(uid)}})
	if err != nil {
		t.Fatal(err)
	}
	return res[types.UID(uid)]
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

func (f *fakePoolSys) wantCommand(t *testing.T, cmd string) {
	t.Helper()
	if !strings.Contains(f.commands(), cmd) {
		t.Fatalf("command %q not run:\n%s", cmd, f.commands())
	}
}

const releaseCommands = "cxl disable-region region0\ncxl destroy-region region0\ncxl disable-memdev mem0"

func (f *fakePoolSys) wantReleased(t *testing.T) {
	t.Helper()
	if !strings.HasSuffix(f.commands(), releaseCommands) {
		t.Fatalf("device not released:\n%s", f.commands())
	}
}

func (f *fakePoolSys) wantBlocks(t *testing.T, state string) {
	t.Helper()
	for _, b := range []string{"74", "75"} {
		if st := f.read("devices/system/memory/memory" + b + "/state"); st != state {
			t.Fatalf("memory%s is %q, expected %q", b, st, state)
		}
	}
}

// wantClean checks that nothing is prepared: no CDI spec, no serials, no
// claim whose Prepare did not finish (also not in the preparing file).
func (e *poolTestEnv) wantClean(t *testing.T, p *poolDriver) {
	t.Helper()
	if e.cdiSpec(t) != nil || len(p.Serials()) != 0 || len(p.prepared) != 0 || len(p.preparing) != 0 {
		t.Fatalf("not clean: CDI spec %+v, serials %v, prepared %v, preparing %v", e.cdiSpec(t), p.Serials(), p.prepared, p.preparing)
	}
	if recs := e.preparingFile(t); len(recs) != 0 {
		t.Fatalf("not clean: preparing file %v", recs)
	}
}

// preparingFile returns the claims of the preparing file, nil if there is
// none.
func (e *poolTestEnv) preparingFile(t *testing.T) map[string]*preparingPoolClaim {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(filepath.Dir(e.stateFile), poolPreparingFileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	recs := map[string]*preparingPoolClaim{}
	if err == nil {
		err = json.Unmarshal(data, &recs)
	}
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// failStateSave makes the saves of the state file fail (its temporary file
// is a directory) and returns the function that undoes it.
func (e *poolTestEnv) failStateSave(t *testing.T) func() {
	t.Helper()
	noErr(t, os.MkdirAll(e.stateFile+".tmp", 0o755))
	return func() { noErr(t, os.Remove(e.stateFile+".tmp")) }
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

const (
	exclusiveData = `{"serial":"0xc1ee0001","shared":false,"size":268435456,"host":"n1"}`
	sharedData    = `{"serial":"0xc1ae0001","shared":true,"size":268435456}`
)

func TestPoolDeviceData(t *testing.T) {
	for _, tc := range []struct {
		raw    string
		serial uint64
		shared bool
		err    string
	}{
		{raw: `{"serial":"0xc1ee0001","shared":false,"size":536870912}`, serial: 0xc1ee0001},
		{raw: `{"serial":"3253600257","shared":true,"size":1}`, serial: 3253600257, shared: true},
		{raw: `{"serial":"0xC1AE0001","shared":true,"size":1}`, serial: 0xc1ae0001, shared: true},
		{raw: `{"shared":true,"size":1}`, err: "required"},
		{raw: `{"serial":"0x1","size":1}`, err: "required"},
		{raw: `{"serial":"0x1","shared":true}`, err: "required"},
		{raw: `{"serial":"bogus","shared":true,"size":1}`, err: "invalid serial"},
		{raw: `{"serial":1,"shared":true,"size":1}`, err: "invalid device data"},
	} {
		d, err := parsePoolDeviceData([]byte(tc.raw))
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: expected error %q, got %v", tc.raw, tc.err, err)
			}
			continue
		}
		if err != nil || d.Serial != tc.serial || d.Shared != tc.shared {
			t.Errorf("%s: got %+v %v", tc.raw, d, err)
		}
	}

}

func TestPoolDataFor(t *testing.T) {
	claim := poolClaim("u1", "c1", "pooled0", exclusiveData)
	r := &claim.Status.Allocation.Devices.Results[0]
	if d, err := poolDataFor(claim, r); err != nil || d.Serial != 0xc1ee0001 || d.Shared || d.Size != 268435456 {
		t.Fatalf("poolDataFor: %+v %v", d, err)
	}
	// the entry of another device does not match
	claim.Status.Devices[1].Device = "pooled1"
	_, err := poolDataFor(claim, r)
	wantErr(t, err, "no entry")
	// missing entry, missing data
	_, err = poolDataFor(poolClaim("u1", "c1", "pooled0", ""), r)
	wantErr(t, err, "no entry")
	claim = poolClaim("u1", "c1", "pooled0", exclusiveData)
	claim.Status.Devices[1].Data = nil
	_, err = poolDataFor(claim, r)
	wantErr(t, err, "no data")
}

func TestPoolPrepareExclusive(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ee0001")
	p := e.driver(t)

	res := prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData))
	noErr(t, res.Err)
	want := []kubeletplugin.Device{{ // the cxl.nri.io result is not ours
		Requests:     []string{"mem"},
		PoolName:     "fake-cxl-pool",
		DeviceName:   "pooled0",
		CDIDeviceIDs: []string{"nri.io/cxl-pool=claim-u1-0"},
	}}
	if !reflect.DeepEqual(res.Devices, want) {
		t.Fatalf("unexpected devices %+v", res.Devices)
	}
	e.f.wantCommand(t, "cxl create-region -t ram -d decoder0.0 -m mem0")
	e.f.wantBlocks(t, "online_movable")
	if spec := e.cdiSpec(t); spec.Kind != "nri.io/cxl-pool" {
		t.Fatalf("CDI spec kind %q", spec.Kind)
	}
	cd := e.wantCDIDevice(t, "claim-u1-0", []string{"CXL_C1EE0001_MODE=numa", "CXL_C1EE0001_NODE=2", "CXL_C1EE0001_SERIAL=0xc1ee0001",
		"CXL_C1EE0001_SHARED=0", "CXL_C1EE0001_SIZE=268435456", "CXL_CLAIM_u1_0=1"})
	if len(cd.ContainerEdits.DeviceNodes) != 0 {
		t.Fatalf("unexpected device nodes %+v", cd.ContainerEdits.DeviceNodes)
	}
	if !p.Serials()[0xc1ee0001] {
		t.Fatalf("serial missing from %v", p.Serials())
	}
	st, err := os.Stat(e.stateFile)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", st, err)
	}
	data, _ := os.ReadFile(e.stateFile)
	for _, want := range []string{`"memdev": "mem0"`, `"region": "region0"`, `"node": 2`, `"claimName": "default/c1"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("state file lacks %s:\n%s", want, data)
		}
	}

	// unprepare releases: offline, destroy, disable
	noErr(t, unprepare(t, p, "u1"))
	e.f.wantReleased(t)
	e.f.wantBlocks(t, "offline")
	e.wantClean(t, p)
	// an unknown claim is fine
	noErr(t, unprepare(t, p, "u1"))

	// prepare again after a release (memdev disabled): enabled again
	noErr(t, prepare(t, p, poolClaim("u2", "c2", "pooled0", exclusiveData)).Err)
	e.f.wantCommand(t, "cxl enable-memdev mem0")
}

func TestPoolPrepareSharedTwoClaims(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ae0001")
	p := e.driver(t)

	res := prepare(t, p, poolClaim("u1", "c1", "shared0", sharedData))
	noErr(t, res.Err)
	if !slices.Equal(res.Devices[0].CDIDeviceIDs, []string{"nri.io/cxl-pool=claim-u1-0"}) {
		t.Fatalf("unexpected device %+v", res.Devices[0])
	}
	e.f.wantBlocks(t, "offline") // shared memory is never onlined
	e.f.wantCommand(t, "daxctl reconfigure-device --mode=devdax --force dax0.0")
	sharedEnv := func(uid string) []string {
		return []string{"CXL_C1AE0001_DAX=/dev/dax0.0", "CXL_C1AE0001_MODE=dax", "CXL_C1AE0001_READONLY=0",
			"CXL_C1AE0001_SERIAL=0xc1ae0001", "CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=268435456", "CXL_CLAIM_" + uid + "_0=1"}
	}
	cd := e.wantCDIDevice(t, "claim-u1-0", sharedEnv("u1"))
	wantNodes := []*cdiSpecs.DeviceNode{{Path: "/dev/dax0.0", Type: "c", Major: 251, Minor: 3}}
	if !reflect.DeepEqual(cd.ContainerEdits.DeviceNodes, wantNodes) {
		t.Fatalf("unexpected device nodes %+v", cd.ContainerEdits.DeviceNodes)
	}

	// a second claim on the same device reuses the region and has a CDI
	// device of its own
	noErr(t, prepare(t, p, poolClaim("u2", "c2", "shared0", sharedData)).Err)
	if n := strings.Count(e.f.commands(), "create-region"); n != 1 {
		t.Fatalf("region created %d times", n)
	}
	if spec := e.cdiSpec(t); len(spec.Devices) != 2 {
		t.Fatalf("expected one CDI device per claim, got %+v", spec.Devices)
	}
	e.wantCDIDevice(t, "claim-u2-0", sharedEnv("u2"))
	// an exclusive claim on the shared serial is refused
	res = prepare(t, p, poolClaim("u3", "c3", "shared0", `{"serial":"0xc1ae0001","shared":false,"size":268435456}`))
	wantErr(t, res.Err, "another claim prepared it with shared=true")

	// unprepare of one keeps the device
	noErr(t, unprepare(t, p, "u1"))
	if strings.Contains(e.f.commands(), "disable-region") || !p.Serials()[0xc1ae0001] {
		t.Fatalf("device released while still used:\n%s", e.f.commands())
	}
	if cdiDeviceByName(e.cdiSpec(t), "claim-u1-0") != nil {
		t.Fatal("CDI device of an unprepared claim left")
	}
	e.wantCDIDevice(t, "claim-u2-0", sharedEnv("u2"))
	// unprepare of both releases
	noErr(t, unprepare(t, p, "u2"))
	e.f.wantReleased(t)
	e.wantClean(t, p)
}

func TestPoolRestart(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ee0001")
	p := e.driver(t)
	res := prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData))
	noErr(t, res.Err)
	ncmds := len(e.f.cmds)
	// a restart rewrites the CDI spec (newNodeState removes the specs of
	// both drivers)
	_ = os.RemoveAll(e.cdiDir)

	p2 := e.driver(t)
	if !p2.Serials()[0xc1ee0001] {
		t.Fatalf("restored serials %v", p2.Serials())
	}
	if cdiDeviceByName(e.cdiSpec(t), "claim-u1-0") == nil {
		t.Fatal("CDI spec not rewritten after restart")
	}
	res2 := prepare(t, p2, poolClaim("u1", "c1", "pooled0", exclusiveData))
	if res2.Err != nil || len(res2.Devices) != 1 || !slices.Equal(res2.Devices[0].CDIDeviceIDs, res.Devices[0].CDIDeviceIDs) {
		t.Fatalf("stored result not returned: %+v", res2)
	}
	if len(e.f.cmds) != ncmds {
		t.Fatalf("repeated Prepare ran commands:\n%s", e.f.commands())
	}

	// the memdev disappears while the driver is down: kept until Unprepare
	e.f.unplug()
	p3 := e.driver(t)
	if !p3.Serials()[0xc1ee0001] {
		t.Fatal("device of a gone memdev dropped")
	}
	noErr(t, unprepare(t, p3, "u1"))
	e.wantClean(t, p3)
}

func TestPoolPrepareErrors(t *testing.T) {
	e := newPoolTestEnv(t)
	p := e.driver(t)
	// no status entry yet
	wantErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", "")).Err, "no entry")
	// memdev never appears
	wantErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err, "timeout")
	e.wantClean(t, p)

	// the second device of a claim fails: the first one is rolled back
	e.f.plug("0xc1ee0001")
	claim := poolClaim("u2", "c2", "pooled0", exclusiveData)
	claim.Status.Allocation.Devices.Results = append(claim.Status.Allocation.Devices.Results,
		resourceapi.DeviceRequestAllocationResult{Request: "mem2", Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: "pooled1"})
	wantErr(t, prepare(t, p, claim).Err, "pooled1")
	e.f.wantReleased(t)
	e.wantClean(t, p)
}

func TestBuildDevInfosSkipsPoolDevices(t *testing.T) {
	devices := nricxl.NewDevices()
	region := func(name string, node int, serial uint64) *nricxl.RegionDevice {
		return &nricxl.RegionDevice{
			Name: name, Size: 1 << 30, Mode: "ram", Node: node, Enabled: true,
			Memories: []*nricxl.MemoryDevice{{Name: "mem-" + name, Serial: serial, Enabled: true}},
		}
	}
	devices.RegionDevices = []*nricxl.RegionDevice{region("region0", 2, 0xc100e2e0), region("region1", 3, 0xc1ee0001)}
	devices.MemoryNodes = []*nricxl.MemoryNode{{ID: 0, Size: 1 << 30}, {ID: 2, Size: 1 << 30}, {ID: 3, Size: 1 << 30}}
	devInfos, err := buildDevInfos(&DriverConfig{}, devices, map[uint64]bool{0xc1ee0001: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := devInfos["region0-node2"]; !ok {
		t.Fatalf("local region missing: %v", devInfos)
	}
	if _, ok := devInfos["region1-node3"]; ok {
		t.Fatal("pool region published")
	}
	dram, ok := devInfos["dram"].Dev.(*device.DRAM)
	if !ok || !slices.Equal(dram.Nodes, []int{0}) {
		t.Fatalf("pool node counted as DRAM: %+v", devInfos["dram"])
	}
	if devInfos, _ := buildDevInfos(&DriverConfig{}, devices, nil, nil); devInfos["region1-node3"] == nil {
		t.Fatal("region1 skipped without the pool driver")
	}
}

const (
	daxConfig = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"dax"}}`
	roConfig  = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"readOnly":true}}`
)

// withConfig adds an opaque config of the pool driver to the allocation
// of a claim.
func withConfig(c *resourceapi.ResourceClaim, source resourceapi.AllocationConfigSource, requests []string, params string) *resourceapi.ResourceClaim {
	c.Status.Allocation.Devices.Config = append(c.Status.Allocation.Devices.Config, resourceapi.DeviceAllocationConfiguration{
		Source:   source,
		Requests: requests,
		DeviceConfiguration: resourceapi.DeviceConfiguration{Opaque: &resourceapi.OpaqueDeviceConfiguration{
			Driver: device.PoolDriverName, Parameters: runtime.RawExtension{Raw: []byte(params)},
		}},
	})
	return c
}

func TestPoolPrepareExclusiveDax(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ee0001")
	p := e.driver(t)

	claim := withConfig(poolClaim("u1", "c1", "pooled0", exclusiveData), resourceapi.AllocationConfigSourceClaim, nil, daxConfig)
	res := prepare(t, p, claim)
	noErr(t, res.Err)
	if !slices.Equal(res.Devices[0].CDIDeviceIDs, []string{"nri.io/cxl-pool=claim-u1-0"}) {
		t.Fatalf("unexpected device %+v", res.Devices[0])
	}
	e.f.wantCommand(t, "daxctl reconfigure-device --mode=devdax --force dax0.0")
	e.f.wantBlocks(t, "offline") // a dax device is never onlined
	cd := e.wantCDIDevice(t, "claim-u1-0", []string{"CXL_C1EE0001_DAX=/dev/dax0.0", "CXL_C1EE0001_MODE=dax", "CXL_C1EE0001_READONLY=0",
		"CXL_C1EE0001_SERIAL=0xc1ee0001", "CXL_C1EE0001_SHARED=0", "CXL_C1EE0001_SIZE=268435456", "CXL_CLAIM_u1_0=1"})
	wantNodes := []*cdiSpecs.DeviceNode{{Path: "/dev/dax0.0", Type: "c", Major: 251, Minor: 3}}
	if !reflect.DeepEqual(cd.ContainerEdits.DeviceNodes, wantNodes) {
		t.Fatalf("unexpected device nodes %+v", cd.ContainerEdits.DeviceNodes)
	}
	if d := p.prepared["u1"].Devices[0]; d.Mode != api.ModeDax || d.Node != -1 || d.DaxDevice != "/dev/dax0.0" {
		t.Fatalf("prepared device %+v", d)
	}

	// another claim on the serial in numa mode is refused
	res = prepare(t, p, poolClaim("u2", "c2", "pooled0", exclusiveData))
	wantErr(t, res.Err, "mode numa, but another claim prepared it in mode dax")

	noErr(t, unprepare(t, p, "u1"))
	e.f.wantReleased(t)
	e.wantClean(t, p)
}

func TestPoolReadOnlyCDIDevices(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ae0001")
	p := e.driver(t)

	res := prepare(t, p, withConfig(poolClaim("u1", "c1", "shared0", sharedData), resourceapi.AllocationConfigSourceClaim, nil, roConfig))
	noErr(t, res.Err)
	if !slices.Equal(res.Devices[0].CDIDeviceIDs, []string{"nri.io/cxl-pool=claim-u1-0"}) {
		t.Fatalf("unexpected device %+v", res.Devices[0])
	}
	ro := e.wantCDIDevice(t, "claim-u1-0", []string{"CXL_C1AE0001_DAX=/dev/dax0.0", "CXL_C1AE0001_MODE=dax", "CXL_C1AE0001_READONLY=1",
		"CXL_C1AE0001_SERIAL=0xc1ae0001", "CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=268435456", "CXL_CLAIM_u1_0=1"})
	wantNodes := []*cdiSpecs.DeviceNode{{Path: "/dev/dax0.0", Type: "c", Major: 251, Minor: 3, Permissions: "r"}}
	if !reflect.DeepEqual(ro.ContainerEdits.DeviceNodes, wantNodes) {
		t.Fatalf("unexpected read-only device nodes %+v", ro.ContainerEdits.DeviceNodes)
	}

	// a read-write claim of the same device: its own CDI device, the
	// region is reused
	res = prepare(t, p, poolClaim("u2", "c2", "shared0", sharedData))
	noErr(t, res.Err)
	if !slices.Equal(res.Devices[0].CDIDeviceIDs, []string{"nri.io/cxl-pool=claim-u2-0"}) {
		t.Fatalf("unexpected device %+v", res.Devices[0])
	}
	if n := strings.Count(e.f.commands(), "create-region"); n != 1 {
		t.Fatalf("region created %d times", n)
	}
	rw := e.wantCDIDevice(t, "claim-u2-0", []string{"CXL_C1AE0001_DAX=/dev/dax0.0", "CXL_C1AE0001_MODE=dax", "CXL_C1AE0001_READONLY=0",
		"CXL_C1AE0001_SERIAL=0xc1ae0001", "CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=268435456", "CXL_CLAIM_u2_0=1"})
	if rw.ContainerEdits.DeviceNodes[0].Permissions != "" {
		t.Fatalf("read-write device node %+v", rw.ContainerEdits.DeviceNodes[0])
	}

	// unprepare the read-only claim: its CDI device goes, the device stays
	noErr(t, unprepare(t, p, "u1"))
	if cdiDeviceByName(e.cdiSpec(t), "claim-u1-0") != nil || strings.Contains(e.f.commands(), "disable-region") {
		t.Fatalf("after the read-only unprepare: %+v\n%s", e.cdiSpec(t), e.f.commands())
	}
	noErr(t, unprepare(t, p, "u2"))
	e.f.wantReleased(t)
	e.wantClean(t, p)
}

func TestPoolConfigErrors(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ae0001")
	p := e.driver(t)
	for _, tc := range []struct {
		data, params, err string
	}{
		{sharedData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"numa"}}`, "MemoryConfig: device: a shared device is used as dax only"},
		{exclusiveData, roConfig, "MemoryConfig: device.readOnly needs mode dax, block or fs"},
		{exclusiveData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"ram"}}`, `MemoryConfig: device.mode: invalid mode "ram" (numa, dax, block or fs)`},
		{sharedData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"access":"cached"}}`, "MemoryConfig: device.access needs mode fs"},
		{sharedData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"fsType":"erofs"}}`, `unknown field "device.fsType"`},
		{sharedData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"block"}}`, "MemoryConfig: device.mode block needs a persistent device"},
		{exclusiveData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","readOnly":true}}`, "MemoryConfig: device.mode fs needs a persistent device"},
		{sharedData, `{"apiVersion":"v1","kind":"MemoryConfig"}`, `MemoryConfig: apiVersion "v1", expected "cxl.nri.io/v1alpha1"`},
		{sharedData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"DeviceConfig","mode":"dax"}`, `unknown kind "DeviceConfig" (MemoryConfig)`},
		// an old kind would give a read-write device of a reader
		{sharedData, `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"PoolDeviceConfig","readOnly":true}`,
			`cxl-pool.nri.io: preparing claim default/c1: unknown kind "PoolDeviceConfig" (MemoryConfig)`},
		{sharedData, `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"MemoryPolicyConfig","memoryUseOrder":"first-dram"}`,
			`unknown kind "MemoryPolicyConfig" (MemoryConfig)`},
	} {
		claim := withConfig(poolClaim("u1", "c1", "shared0", tc.data), resourceapi.AllocationConfigSourceClaim, nil, tc.params)
		wantErr(t, prepare(t, p, claim).Err, tc.err)
		e.wantClean(t, p)
	}
	if strings.Contains(e.f.commands(), "create-region") {
		t.Fatalf("a refused config touched the device:\n%s", e.f.commands())
	}
}

// TestPoolCDISpecKeys builds the CDI devices of a claim with two devices
// of one serial, the second one read-only, and a third device: one CDI
// device per allocation result with its own env (the second device of the
// serial has the key <HEX>_2) and device node; none of a companion claim.
func TestPoolCDISpecKeys(t *testing.T) {
	p := &poolDriver{prepared: map[string]*preparedPoolClaim{
		"u1": {Devices: []preparedPoolDevice{
			{Result: 0, Serial: 0xc1ae0001, Shared: true, Size: 1 << 28, Mode: api.ModeDax, DaxDevice: "/dev/dax0.0", DaxMajor: 251, DaxMinor: 3, Node: -1},
			{Result: 1, Serial: 0xc1ae0001, Shared: true, Size: 1 << 28, Mode: api.ModeDax, ReadOnly: true, DaxDevice: "/dev/dax0.0", DaxMajor: 251, DaxMinor: 3, Node: -1},
			{Result: 3, Serial: 0xc1ee0001, Size: 1 << 29, Mode: api.ModeNUMA, Node: 3},
		}},
		// a companion claim
		"u2": {Devices: []preparedPoolDevice{{Serial: 0xc1ee0002, Size: 1 << 29, Mode: api.ModeNUMA, Node: 4}}, Lend: &lendRecord{Lease: "l1"}},
	}}
	spec := p.buildCDISpec()
	want := []cdiSpecs.Device{
		{Name: "claim-u1-0", ContainerEdits: cdiSpecs.ContainerEdits{
			Env: []string{"CXL_C1AE0001_DAX=/dev/dax0.0", "CXL_C1AE0001_MODE=dax", "CXL_C1AE0001_READONLY=0", "CXL_C1AE0001_SERIAL=0xc1ae0001",
				"CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=268435456", "CXL_CLAIM_u1_0=1"},
			DeviceNodes: []*cdiSpecs.DeviceNode{{Path: "/dev/dax0.0", Type: "c", Major: 251, Minor: 3}},
		}},
		{Name: "claim-u1-1", ContainerEdits: cdiSpecs.ContainerEdits{
			Env: []string{"CXL_C1AE0001_2_DAX=/dev/dax0.0", "CXL_C1AE0001_2_MODE=dax", "CXL_C1AE0001_2_READONLY=1", "CXL_C1AE0001_2_SERIAL=0xc1ae0001",
				"CXL_C1AE0001_2_SHARED=1", "CXL_C1AE0001_2_SIZE=268435456", "CXL_CLAIM_u1_1=1"},
			DeviceNodes: []*cdiSpecs.DeviceNode{{Path: "/dev/dax0.0", Type: "c", Major: 251, Minor: 3, Permissions: "r"}},
		}},
		{Name: "claim-u1-3", ContainerEdits: cdiSpecs.ContainerEdits{
			Env: []string{"CXL_C1EE0001_MODE=numa", "CXL_C1EE0001_NODE=3", "CXL_C1EE0001_SERIAL=0xc1ee0001", "CXL_C1EE0001_SHARED=0",
				"CXL_C1EE0001_SIZE=536870912", "CXL_CLAIM_u1_3=1"},
		}},
	}
	if spec.Kind != device.PoolCDIKind || !reflect.DeepEqual(spec.Devices, want) {
		t.Fatalf("CDI spec %+v", spec)
	}
}

// A shared pool device needs at least one consumed share, checked before
// the device is touched: a claim of shares "0" fits next to an exclusive
// holder.
func TestPoolSharesGuard(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ae0001")
	p := e.driver(t)
	withShares := func(uid, shares string) *resourceapi.ResourceClaim {
		c := poolClaim(uid, "c-"+uid, "shared0", sharedData)
		c.Status.Allocation.Devices.Results[0].ConsumedCapacity = nil
		if shares != "" {
			c.Status.Allocation.Devices.Results[0].ConsumedCapacity = map[resourceapi.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse(shares)}
		}
		return c
	}
	for _, tc := range []struct{ shares, text string }{{"0", `"0"`}, {"", `""`}} {
		wantErr(t, prepare(t, p, withShares("u0", tc.shares)).Err,
			"cxl-pool.nri.io: preparing claim default/c-u0: device 0xc1ae0001: consumed shares "+tc.text+" is less than 1: request shares: 1 (a share) or no shares (exclusive)")
	}
	if strings.Contains(e.f.commands(), "create-region") {
		t.Fatalf("a refused claim touched the device:\n%s", e.f.commands())
	}
	noErr(t, prepare(t, p, withShares("u1", "1")).Err)
	noErr(t, unprepare(t, p, "u1"))
	noErr(t, prepare(t, p, withShares("u2", "1M")).Err)
	noErr(t, unprepare(t, p, "u2"))
	// a device that is not shared has no shares
	e.f.plug("0xc1ee0001")
	noErr(t, prepare(t, p, poolClaim("u3", "c3", "pooled0", exclusiveData)).Err)
	noErr(t, unprepare(t, p, "u3"))
}

// TestPoolPrepareMemoryConfig prepares a pool claim with MemoryConfig
// entries of the pool driver: a class preset with a container and a pool
// section (the controller's, not read here), changed by a claim entry; the
// container settings of the result are in the prepared state and in the
// snapshot that the NRI plugin reads. Invalid entries and values touch no
// device.
func TestPoolPrepareMemoryConfig(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ee0001")
	p := e.driver(t)
	const (
		class = resourceapi.AllocationConfigSourceClass
		claim = resourceapi.AllocationConfigSourceClaim
	)
	c := poolClaim("u1", "c1", "pooled0", exclusiveData)
	c.Spec.Devices.Requests = []resourceapi.DeviceRequest{{Name: "mem", Exactly: &resourceapi.ExactDeviceRequest{DeviceClassName: "cxl-pool"}}}
	withConfig(c, claim, []string{"mem"}, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"maxStep":"64Mi"}}}`)
	withConfig(c, class, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"numa"},"container":{"steering":{"policy":"auto"}},`+
		`"pool":{"opaque":{"fake-cxl-pool":{"numaNode":1},"other":{"x":1}}}}`)
	// an entry of cxl.nri.io is not read by the pool driver
	withDriverConfig(c, device.DriverName, claim, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"none"}}}`)
	res := prepare(t, p, c)
	noErr(t, res.Err)
	want := config.ResultSettings{
		Container: &config.Container{Steering: &config.Steering{Policy: config.PolicyAuto, MaxStep: "64Mi"}},
		Origins:   map[string]string{config.FieldPolicy: "class cxl-pool", config.FieldMaxStep: "claim default/c1 request mem"},
	}
	if d := p.prepared["u1"].Devices[0]; d.Mode != api.ModeNUMA || d.Node != 2 || !reflect.DeepEqual(d.ResultSettings, want) {
		t.Fatalf("prepared device %+v", d)
	}
	got := p.ClaimResults("u1")
	if len(got) != 1 || got[0].Index != 0 || got[0].Request != "mem" || got[0].Mode != api.ModeNUMA || got[0].Node != 2 ||
		got[0].Size != 256<<20 || !reflect.DeepEqual(got[0].Settings, want) {
		t.Fatalf("claim results %+v", got)
	}
	e.wantCDIDevice(t, "claim-u1-0", []string{"CXL_C1EE0001_MODE=numa", "CXL_C1EE0001_NODE=2", "CXL_C1EE0001_SERIAL=0xc1ee0001",
		"CXL_C1EE0001_SHARED=0", "CXL_C1EE0001_SIZE=268435456", "CXL_CLAIM_u1_0=1"})

	// the NRI plugin steers a container that uses the result
	n := &nriPlugin{poolResults: p.ClaimResults}
	m, err := n.manage("default/pod/ctr", n.containerResults("default/pod/ctr", []resultRef{{"u1", 0}}), true)
	noErr(t, err)
	if m.memory != memorySteered || m.policy != "first-cxl" || m.claimed.String() != "2" || m.plan == nil || m.mem.CXLQuota != 256<<20 {
		t.Fatalf("management %+v", m)
	}

	// the settings survive a restart of the driver
	p2 := e.driver(t)
	if got := p2.ClaimResults("u1"); len(got) != 1 || !reflect.DeepEqual(got[0].Settings, want) {
		t.Fatalf("claim results after a restart %+v", got)
	}
	noErr(t, unprepare(t, p, "u1"))
	e.wantClean(t, p)

	commands := e.f.commands()
	for _, tc := range []struct {
		source      resourceapi.AllocationConfigSource
		params, err string
	}{
		{claim, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"fencing":"none"}}`,
			"cxl-pool.nri.io: preparing claim default/c2: MemoryConfig: container.fencing: set by the driver configuration only (defaults.container.fencing)"},
		{class, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"waypoints","waypoints":[{"targetUsages":[{"memoryType":"HBM","usage":"1Gi"}]}]}}}`,
			`cxl-pool.nri.io: preparing claim default/c2: request mem: MemoryConfig: container.steering.waypoints[0].targetUsages[0].memoryType: invalid memory type "HBM" (DRAM or CXL)`},
		{claim, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","pool":{"opaque":{"fake-cxl-pool":1}}}`,
			"cxl-pool.nri.io: preparing claim default/c2: request mem: MemoryConfig: pool.opaque.fake-cxl-pool: not a JSON object"},
		{claim, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","pool":{"slot":"1"}}`,
			`cxl-pool.nri.io: preparing claim default/c2: MemoryConfig: FromClaim config 0: json: unknown field "pool.slot"`},
		{claim, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"none","minStep":"1Gi"}}}`,
			"cxl-pool.nri.io: preparing claim default/c2: request mem: MemoryConfig: container.steering.minStep needs a policy other than none"},
	} {
		wantErr(t, prepare(t, p, withConfig(poolClaim("u2", "c2", "pooled0", exclusiveData), tc.source, nil, tc.params)).Err, tc.err)
		e.wantClean(t, p)
	}
	if got := e.f.commands(); got != commands {
		t.Fatalf("a refused config touched the device:\n%s", strings.TrimPrefix(got, commands))
	}
}
