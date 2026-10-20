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
	"slices"
	"strings"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

// wantRegionCount checks how many times region0 was created and destroyed.
func (f *fakeLocalSys) wantRegionCount(t *testing.T, created, destroyed int) {
	t.Helper()
	cmds := f.commands()
	if c, d := strings.Count(cmds, "cxl create-region"), strings.Count(cmds, "cxl destroy-region"); c != created || d != destroyed {
		t.Fatalf("region created %d and destroyed %d times, expected %d and %d:\n%s", c, d, created, destroyed, cmds)
	}
}

// wantUse checks how the allocator uses the local memdev.
func wantUse(t *testing.T, a *localAllocator, want *localUse) {
	t.Helper()
	got, ok := a.Snapshot().use(localSerial)
	switch {
	case want == nil && ok:
		t.Fatalf("memdev used %+v, expected unused", got)
	case want != nil && (!ok || got.Shared != want.Shared || !slices.Equal(got.Claims, want.Claims)):
		t.Fatalf("memdev used %v %+v, expected %+v", ok, got, *want)
	}
}

// acquireShared gives the shared local memdev to a claim.
func acquireShared(t *testing.T, a *localAllocator, uid string, readOnly bool) *localSlice {
	t.Helper()
	s, err := a.AcquireShared(context.Background(), uid, "mem", localSerial, readOnly, "1 share")
	noErr(t, err)
	return s
}

// The claims of a shared memdev get the same whole dax device: zeroed once
// when its region is created, never resized or onlined; the region stays
// when the memdev is idle and configured shared, and is reused by the next
// claim without zeroing.
func TestLocalSharedClaims(t *testing.T) {
	f := newFakeLocalSys(t)
	dir := t.TempDir()
	a := f.allocator(t, dir)
	a.SetShared(map[uint64]bool{localSerial: true})
	ctx := context.Background()

	wantSlice(t, acquireShared(t, a, "u1", false),
		localSlice{Request: "mem", Region: "region0", Mode: api.ModeDax, Size: localRegionSize, Dax: "dax0.0", DaxDevice: "/dev/dax0.0", Major: 252})
	wantSlice(t, acquireShared(t, a, "u2", true),
		localSlice{Request: "mem", Region: "region0", Mode: api.ModeDax, Size: localRegionSize, Dax: "dax0.0", DaxDevice: "/dev/dax0.0", Major: 252, ReadOnly: true})
	f.wantDax(t, "dax0.0", localRegionSize, "device_dax")
	f.wantMemoryBlocks(t, "")
	f.wantRegionCount(t, 1, 0)
	if !slices.Equal(f.zeroed, []string{"252:0 1073741824 2097152"}) || strings.Contains(f.commands(), "size") {
		t.Fatalf("shared device zeroed %v or resized:\n%s", f.zeroed, f.commands())
	}
	wantUse(t, a, &localUse{Shared: true, Claims: []string{"u1", "u2"}})
	if !a.holds("u2", "dax0.0") {
		t.Fatal("dax0.0 not held for u2")
	}
	// the state file says shared
	data, err := os.ReadFile(filepath.Join(dir, localStateFileName))
	noErr(t, err)
	if !strings.Contains(string(data), `"shared": true`) {
		t.Fatalf("state file %s", data)
	}

	// releases keep the region and the dax device
	noErr(t, a.Release(ctx, "u1"))
	noErr(t, a.Release(ctx, "u2"))
	f.wantRegionCount(t, 1, 0)
	f.wantDax(t, "dax0.0", localRegionSize, "device_dax")
	wantUse(t, a, &localUse{Shared: true, Claims: []string{}})
	// the idle device is reused
	acquireShared(t, a, "u3", false)
	f.wantRegionCount(t, 1, 0)
	noErr(t, a.Release(ctx, "u3"))
	f.wantRegionCount(t, 1, 0)
	if len(f.zeroed) != 1 {
		t.Fatalf("zeroed again: %v", f.zeroed)
	}

	// not configured shared any more: the last release takes the region
	acquireShared(t, a, "u4", false)
	a.SetShared(nil)
	noErr(t, a.Release(ctx, "u4"))
	f.wantRegionReleased(t, "region0")
	wantUse(t, a, nil)
}

// A memdev is either sliced or shared while it has claims.
func TestLocalSharedMismatch(t *testing.T) {
	f := newFakeLocalSys(t)
	a := f.allocator(t, t.TempDir())
	ctx := context.Background()

	acquire(t, a, "u1", api.ModeDax, localBlockSize)
	_, err := a.AcquireShared(ctx, "u2", "mem", localSerial, false, "exclusive")
	wantErr(t, err, "memdev mem0 (serial 0xc100e2e1): used as slices by claims [u1]; a shared device cannot be sliced")
	f.wantDax(t, "dax0.0", localBlockSize, "device_dax")
	noErr(t, a.Release(ctx, "u1"))
	f.wantRegionReleased(t, "region0")

	acquireShared(t, a, "u2", false)
	_, _, err = a.Acquire(ctx, "u3", "mem", localSerial, api.ModeNUMA, localBlockSize, false)
	wantErr(t, err, "memdev mem0 (serial 0xc100e2e1): used shared by claims [u2]; a sliced device cannot be shared")
	f.wantDax(t, "dax0.0", localRegionSize, "device_dax")
	f.wantRegionCount(t, 2, 1)
	noErr(t, a.Release(ctx, "u2"))

	// a sliced memdev without claims is released for a shared claim, and
	// an idle shared one that is not configured shared for a slice
	a.SetShared(nil)
	acquire(t, a, "u4", api.ModeDax, localBlockSize)
	noErr(t, a.Release(ctx, "u4"))
	f.wantRegionCount(t, 3, 3)
}

// A restart keeps an idle shared device while it is configured shared,
// keeps one with prepared claims anyway, and releases one that is idle and
// not configured shared.
func TestLocalSharedReconcile(t *testing.T) {
	f := newFakeLocalSys(t)
	dir := t.TempDir()
	ctx := context.Background()
	a := f.allocator(t, dir)
	acquireShared(t, a, "u1", false)
	acquireShared(t, a, "u2", true)

	// configured shared: the claim that is not prepared is dropped
	b := f.allocator(t, dir)
	b.SetShared(map[uint64]bool{localSerial: true})
	b.Reconcile(ctx, map[string]bool{"u2": true})
	wantUse(t, b, &localUse{Shared: true, Claims: []string{"u2"}})
	f.wantDax(t, "dax0.0", localRegionSize, "device_dax")
	// configured shared, no claims: kept idle
	b = f.allocator(t, dir)
	b.SetShared(map[uint64]bool{localSerial: true})
	b.Reconcile(ctx, nil)
	wantUse(t, b, &localUse{Shared: true, Claims: []string{}})
	f.wantRegionCount(t, 1, 0)
	acquireShared(t, b, "u3", false)
	f.wantRegionCount(t, 1, 0)

	// not configured shared: kept for its prepared claim, released after
	c := f.allocator(t, dir)
	c.Reconcile(ctx, map[string]bool{"u3": true})
	wantUse(t, c, &localUse{Shared: true, Claims: []string{"u3"}})
	f.wantRegionCount(t, 1, 0)
	noErr(t, c.Release(ctx, "u3"))
	f.wantRegionReleased(t, "region0")
	wantUse(t, c, nil)

	// not configured shared and idle: released at start
	acquireShared(t, c, "u4", false)
	noErr(t, c.Release(ctx, "u4"))
	f.wantRegionCount(t, 2, 1)
	d := f.allocator(t, dir)
	d.Reconcile(ctx, nil)
	f.wantRegionReleased(t, "region0")
	wantUse(t, d, nil)
}

// A state file without "shared" is of a sliced memdev.
func TestLocalSharedOldStateFile(t *testing.T) {
	f := newFakeLocalSys(t)
	dir := t.TempDir()
	state := `{"bootID":"boot-1","devices":[{"serial":3238060769,"serialHex":"c100e2e1","memdev":"mem0","region":"region0","node":-1,"dax":"dax0.0","claims":{}}]}`
	noErr(t, os.WriteFile(filepath.Join(dir, localStateFileName), []byte(state), 0o600))
	a := f.allocator(t, dir)
	if d := a.devices[localSerial]; d == nil || d.Shared {
		t.Fatalf("device of an old state file %+v", d)
	}
	wantUse(t, a, &localUse{Claims: []string{}})
}

// sharedClaim returns a claim allocated the shared local memdev for
// request "mem", with consumed shares ("" for none) and opaque cxl.nri.io
// claim configs.
func sharedClaim(uid, shares string, configs ...string) *resourcev1.ResourceClaim {
	c := localClaim(uid, 0, configs...)
	if shares != "" {
		c.Status.Allocation.Devices.Results[0].ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse(shares)}
	}
	return c
}

// newSharedTestState returns a localTestState whose local memdev is
// configured shared.
func newSharedTestState(t *testing.T) *localTestState {
	e := newLocalTestState(t)
	e.config.SharedDevices = []string{"0xc100e2e1"}
	e.local.SetShared(map[uint64]bool{localSerial: true})
	e.rescan()
	return e
}

// published returns the local memdev as the node state publishes it, nil
// if it is not published.
func (e *localTestState) published() *resourcev1.Device {
	for _, d := range e.GetResources().Pools[testNode].Slices[0].Devices {
		if d.Name == localDeviceName {
			return &d
		}
	}
	return nil
}

func TestPublishSharedLocalMemdev(t *testing.T) {
	e := newSharedTestState(t)
	got := e.published()
	want := &resourcev1.Device{
		Name: localDeviceName,
		Attributes: map[resourcev1.QualifiedName]resourcev1.DeviceAttribute{
			"type":         {StringValue: ptr("memdev")},
			"source":       {StringValue: ptr("local")},
			"serial":       {StringValue: ptr("0xc100e2e1")},
			"shared":       {BoolValue: ptr(true)},
			"size":         {IntValue: ptr(int64(localRegionSize))},
			"nodeAffinity": {IntValue: ptr(int64(0))},
		},
		Capacity: map[resourcev1.QualifiedName]resourcev1.DeviceCapacity{
			"shares": {Value: *resource.NewQuantity(1000000, resource.DecimalSI)},
		},
		AllowMultipleAllocations: ptr(true),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("published\n%+v\nexpected\n%+v", got, want)
	}
	if v := got.Capacity["shares"].Value; v.String() != "1M" || got.Capacity["shares"].RequestPolicy != nil {
		t.Fatalf("shares %s", v.String())
	}
	data, err := json.Marshal(got.Capacity)
	noErr(t, err)
	if string(data) != `{"shares":{"value":"1M"}}` {
		t.Fatalf("capacity %s", data)
	}

	// any size, also with an unknown memory block size
	small := localMemdev()
	small.RamSize = 64 * mib
	devs, err := buildDevInfos(e.config, &nricxl.Devices{MemoryDevices: []*nricxl.MemoryDevice{small}}, nil, &localSnapshot{})
	noErr(t, err)
	if m, ok := devs[localDeviceName].Dev.(*device.Memdev); !ok || !m.Shared || m.Size != 64*mib {
		t.Fatalf("small shared memdev %+v", devs[localDeviceName])
	}
}

// Per memdev: ignoreDevices > pool devices > sharedDevices > sliced; any
// spec form of ignoreDevices matches.
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
	cfg := &DriverConfig{
		IgnoreDevices: []string{"0xa5"},
		SharedDevices: []string{"mem1", "cxl/mem2", "251:3", "164", "a5", "0xa6", "0xa8", "0xaa"},
	}
	pool := map[uint64]bool{0xa6: true}
	local := &localSnapshot{BlockSize: localBlockSize, Uses: map[uint64]localUse{
		0xa8: {Claims: []string{"s1"}},
		0xa9: {Shared: true, Claims: []string{"h1"}},
	}}
	devInfos, err := buildDevInfos(cfg, devices, pool, local)
	noErr(t, err)
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
		if _, got := sharedListing(cfg, tc.mem, pool); got != tc.want {
			t.Errorf("%s: refusal %q, expected %q", tc.mem.Name, got, tc.want)
		}
	}
	if got := sharedSerials(cfg, devices.MemoryDevices, pool); !maps.Equal(got, map[uint64]bool{0xa1: true, 0xa2: true, 0xa3: true, 0xa4: true, 0xa8: true, 0xaa: true}) {
		t.Fatalf("shared serials %v", got)
	}

	// the hidden ones come back when the other use has no claims
	local.Uses[0xa8] = localUse{Claims: []string{}}
	local.Uses[0xa9] = localUse{Shared: true, Claims: []string{}}
	devInfos, err = buildDevInfos(cfg, devices, pool, local)
	noErr(t, err)
	for name, s := range map[string]bool{"memdev-a8": true, "memdev-a9": false} {
		if m, ok := devInfos[name].Dev.(*device.Memdev); !ok || m.Shared != s {
			t.Errorf("%s: %+v, expected shared %v", name, devInfos[name], s)
		}
	}
}

func TestDriverConfigSharedDevices(t *testing.T) {
	cfg, err := newDriverConfigFromString(`sharedDevices: ["0xc100e2e1", "mem1"]`)
	noErr(t, err)
	if !slices.Equal(cfg.SharedDevices, []string{"0xc100e2e1", "mem1"}) {
		t.Fatalf("sharedDevices %v", cfg.SharedDevices)
	}
	for _, bad := range []string{`sharedDevices: "0xc100e2e1"`, `sharedDevice: ["0xc100e2e1"]`, `sharedDevices: [{serial: 1}]`} {
		if _, err := newDriverConfigFromString(bad); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}

// Claims of a shared local memdev: one dax device for all, exclusive or a
// share by the consumed shares, read-only per claim, content never zeroed
// and the region kept when idle.
func TestPrepareSharedLocal(t *testing.T) {
	e := newSharedTestState(t)
	ctx := context.Background()

	// the writer: no shares request, the scheduler counts all of them
	noErr(t, e.Prepare(ctx, sharedClaim("u1", "1M")))
	e.wantCDIDevices(t, "u1", "nri.io/cxl=claim-u1-0")
	e.wantDeviceInfo(t, "u1", PreparedDeviceInfo{
		RequestName: "mem", DeviceName: localDeviceName, DeviceType: device.DeviceTypeMemdev, Mode: api.ModeDax, Shared: true,
		SysfsPath: e.f.p("bus/cxl/devices/region0"), NodeAffinities: []int{0},
		TotalBytes: localRegionSize, ConsumedBytes: localRegionSize, Serial: "0xc100e2e1",
		DaxDevice: "/dev/dax0.0", DaxMajor: 252, DaxMinor: 0,
	})
	e.wantCDIDevice(t, "claim-u1-0",
		[]string{"CXL_C100E2E1_DAX=/dev/dax0.0", "CXL_C100E2E1_MODE=dax", "CXL_C100E2E1_READONLY=0", "CXL_C100E2E1_SERIAL=0xc100e2e1",
			"CXL_C100E2E1_SHARED=1", "CXL_C100E2E1_SIZE=1073741824", "CXL_CLAIM_u1=1"},
		[]*cdiSpecs.DeviceNode{{Path: "/dev/dax0.0", Type: "c", Major: 252, Minor: 0}})
	// readers: one share each, read-only device nodes of the same device
	noErr(t, e.Prepare(ctx, sharedClaim("u2", "1", localROConfig)))
	noErr(t, e.Prepare(ctx, sharedClaim("u3", "1", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"DeviceConfig","readOnly":true}`)))
	for _, uid := range []string{"u2", "u3"} {
		e.wantCDIDevice(t, "claim-"+uid+"-0",
			[]string{"CXL_C100E2E1_DAX=/dev/dax0.0", "CXL_C100E2E1_MODE=dax", "CXL_C100E2E1_READONLY=1", "CXL_C100E2E1_SERIAL=0xc100e2e1",
				"CXL_C100E2E1_SHARED=1", "CXL_C100E2E1_SIZE=1073741824", "CXL_CLAIM_" + uid + "=1"},
			[]*cdiSpecs.DeviceNode{{Path: "/dev/dax0.0", Type: "c", Major: 252, Minor: 0, Permissions: "r"}})
	}
	e.f.wantRegionCount(t, 1, 0)
	if len(e.f.zeroed) != 1 {
		t.Fatalf("shared device zeroed %v, expected once at creation", e.f.zeroed)
	}
	// still published while shared
	e.rescan()
	if d := e.published(); d == nil || *d.Attributes["shared"].BoolValue != true {
		t.Fatalf("published %+v", d)
	}

	// the shares guard, before the device is touched
	before := e.f.commands()
	for _, tc := range []struct{ shares, text string }{{"0", `"0"`}, {"", `""`}, {"500m", `"500m"`}} {
		wantErr(t, e.Prepare(ctx, sharedClaim("u9", tc.shares)),
			"claim demo/claim-u9: request mem: device 0xc100e2e1: consumed shares "+tc.text+" is less than 1: request shares: 1 (a share) or no shares (exclusive)")
	}
	// dax only
	wantErr(t, e.Prepare(ctx, sharedClaim("u9", "1", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"DeviceConfig","mode":"numa"}`)),
		"DeviceConfig: mode numa: a shared device is used as dax only")
	wantErr(t, e.Prepare(ctx, sharedClaim("u9", "1", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"DeviceConfig","mode":"numa","readOnly":true}`)),
		"DeviceConfig: readOnly needs mode dax")
	if e.f.commands() != before || e.Prepared["u9"].Devices != nil {
		t.Fatalf("a refused claim touched the device:\n%s", strings.TrimPrefix(e.f.commands(), before))
	}

	// all claims gone: the region and its dax device stay
	for _, uid := range []string{"u1", "u2", "u3"} {
		noErr(t, e.Unprepare(ctx, uid))
	}
	e.f.wantRegionCount(t, 1, 0)
	e.f.wantDax(t, "dax0.0", localRegionSize, "device_dax")
	if e.cdiSpec(t) != nil || !e.inUse() {
		t.Fatalf("after the last unprepare: in use %v", e.inUse())
	}
	e.rescan()
	if d := e.published(); d == nil {
		t.Fatal("idle shared device not published")
	}
	noErr(t, e.Prepare(ctx, sharedClaim("u4", "1M")))
	e.f.wantRegionCount(t, 1, 0)
	noErr(t, e.Unprepare(ctx, "u4"))
}

// A memdev is not published while claims of the other use have it.
func TestPrepareSharedLocalHiding(t *testing.T) {
	e := newSharedTestState(t)
	ctx := context.Background()
	noErr(t, e.Prepare(ctx, sharedClaim("u1", "1")))
	// the configuration says sliced after a restart: hidden while shared
	e.config.SharedDevices = nil
	e.local.SetShared(nil)
	e.rescan()
	if d := e.published(); d != nil {
		t.Fatalf("published while used shared: %+v", d)
	}
	noErr(t, e.Unprepare(ctx, "u1"))
	e.f.wantRegionReleased(t, "region0")
	e.rescan()
	if d := e.published(); d == nil || *d.Attributes["shared"].BoolValue {
		t.Fatalf("published %+v", d)
	}
	// sliced claims hide the memdev when it is configured shared
	noErr(t, e.Prepare(ctx, localClaim("u2", localBlockSize, localDaxConfig)))
	e.config.SharedDevices = []string{"mem0"}
	e.rescan()
	if d := e.published(); d != nil {
		t.Fatalf("published while used as slices: %+v", d)
	}
	noErr(t, e.Unprepare(ctx, "u2"))
	e.rescan()
	if d := e.published(); d == nil || !*d.Attributes["shared"].BoolValue {
		t.Fatalf("published %+v", d)
	}
}

// The companion claim of a lease of a shared local memdev: the broker
// gets the shared device.
func TestPrepareSharedLocalLend(t *testing.T) {
	e, lender, hooks := newLendTestState(t)
	e.config.SharedDevices = []string{"0xc100e2e1"}
	e.local.SetShared(map[uint64]bool{localSerial: true})
	e.rescan()
	ctx := context.Background()
	c := sharedClaim("u1", "1", localROConfig)
	c.ObjectMeta = companionClaim("l1").ObjectMeta
	c.UID = types.UID("u1")
	noErr(t, e.Prepare(ctx, c))
	if len(hooks.devs) != 1 || !hooks.devs[0].Shared || hooks.devs[0].DaxDevice != "/dev/dax0.0" || !hooks.devs[0].ReadOnly || hooks.devs[0].Size != localRegionSize {
		t.Fatalf("lent devices %+v", hooks.devs)
	}
	e.wantCDIDevices(t, "u1")
	noErr(t, e.Unprepare(ctx, "u1"))
	if len(lender.calls) != 0 {
		t.Fatalf("nodes lent for a shared device: %v", lender.calls)
	}
	e.f.wantRegionCount(t, 1, 0)
}

// A share of a shared local device through the broker: Ready with the
// environment of a shared device.
func TestBrokerLocalSharedLease(t *testing.T) {
	e, lender := newLocalLeaseEnv(t)
	ch := e.async(api.Request{Op: "request", Serial: "0xc100e2e1", Shared: true, ReadOnly: true, Source: "local", Wait: "5s"})
	claim := e.waitClaim("cxl-lease-000000a1")
	ex := claim.Spec.Devices.Requests[0].Exactly
	if ex == nil || ex.DeviceClassName != device.ClassLocalShared || ex.Capacity == nil {
		t.Fatalf("companion request %+v", claim.Spec.Devices.Requests[0])
	}
	if q := ex.Capacity.Requests[device.CapacityShares]; q.String() != "1" {
		t.Fatalf("companion capacity %+v", ex.Capacity)
	}
	c := allocatedLocal(claim, "lease", localDeviceName)
	rec, err := lender.check("000000a1", c)
	noErr(t, err)
	devs := []lentDevice{{Driver: device.DriverName, Source: api.SourceLocal, Request: "lease", Device: localDeviceName,
		Serial: localSerial, Shared: true, Size: localRegionSize, Mode: api.ModeDax, ReadOnly: true, Node: -1, DaxDevice: "/dev/dax1.1"}}
	noErr(t, lender.lend(context.Background(), rec, devs))
	lender.prepared("000000a1", devs)
	wantResponse(t, <-ch, api.Response{State: api.StateReady, Source: "local", Mode: "dax", Shared: true, ReadOnly: true,
		Size: localRegionSize, Serial: "0xc100e2e1", Dax: "/dev/dax1.1", Env: map[string]string{
			"CXL_C100E2E1_DAX": "/dev/dax1.1", "CXL_C100E2E1_MODE": "dax", "CXL_C100E2E1_READONLY": "1",
			"CXL_C100E2E1_SERIAL": "0xc100e2e1", "CXL_C100E2E1_SHARED": "1", "CXL_C100E2E1_SIZE": "1073741824"}})
	e.wantReleaseAll(1)
}

// A lease table of hosts capacities fails the strict decode: the plugin
// starts with an empty table.
func TestLeaseStoreWithHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), leasesFileName)
	old := `{"claims":{},"leases":{"000000a1":{"id":"000000a1","claim":"lc1","mode":"dax","shared":false,"hosts":"4","pod":{"namespace":"demo","name":"p","uid":"u"},"container":"c","state":"Ready","node":-1,"created":"2026-10-19T00:00:00Z"}}}`
	noErr(t, os.WriteFile(path, []byte(old), 0o600))
	s, err := loadLeaseStore(path)
	noErr(t, err)
	if len(s.Leases) != 0 || len(s.Claims) != 0 {
		t.Fatalf("lease store %+v", s)
	}
	// the new field round-trips
	s.Leases["000000a2"] = &lease{ID: "000000a2", SharedDevice: true, Node: -1}
	noErr(t, s.save())
	s, err = loadLeaseStore(path)
	noErr(t, err)
	if l := s.Leases["000000a2"]; l == nil || !l.SharedDevice || !l.deviceShared() {
		t.Fatalf("lease %+v", l)
	}
}

// The shares guard of shared devices and the use that it logs.
func TestConsumedShares(t *testing.T) {
	result := func(shares string) *resourcev1.DeviceRequestAllocationResult {
		r := &resourcev1.DeviceRequestAllocationResult{}
		if shares != "" {
			r.ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse(shares)}
		}
		return r
	}
	for _, tc := range []struct {
		shares string
		want   int64
		use    string
		err    string
	}{
		{shares: "1M", want: 1000000, use: "exclusive"},
		{shares: "1", want: 1, use: "1 share"},
		{shares: "3", want: 3, use: "3 shares"},
		{shares: "0", err: `device 0xc100e2e1: consumed shares "0" is less than 1: request shares: 1 (a share) or no shares (exclusive)`},
		{shares: "0.5", err: `device 0xc100e2e1: consumed shares "500m" is less than 1: request shares: 1 (a share) or no shares (exclusive)`},
		{shares: "", err: `device 0xc100e2e1: consumed shares "" is less than 1: request shares: 1 (a share) or no shares (exclusive)`},
		{shares: "-1", err: `device 0xc100e2e1: consumed shares "-1" is less than 1: request shares: 1 (a share) or no shares (exclusive)`},
	} {
		got, err := consumedShares(localSerial, result(tc.shares))
		switch {
		case tc.err != "" && (err == nil || err.Error() != tc.err):
			t.Errorf("%q: error %v, expected %q", tc.shares, err, tc.err)
		case tc.err == "" && (err != nil || got != tc.want || shareUse(got, device.SharesUnlimited) != tc.use):
			t.Errorf("%q: %d %v, expected %d %s", tc.shares, got, err, tc.want, tc.use)
		}
	}
}

// A failed creation of the region of a shared memdev, or of its zeroing,
// leaves no device, no claim and no region.
func TestLocalSharedCreateFailures(t *testing.T) {
	f := newFakeLocalSys(t)
	a := f.allocator(t, t.TempDir())
	a.SetShared(map[uint64]bool{localSerial: true})
	ctx := context.Background()

	f.failCreate = 2 // the retry fails too
	_, err := a.AcquireShared(ctx, "u1", "mem", localSerial, false, "exclusive")
	wantErr(t, err, "add_dev")
	wantUse(t, a, nil)

	f.zeroErr = errors.New("no mmap")
	_, err = a.AcquireShared(ctx, "u1", "mem", localSerial, false, "exclusive")
	wantErr(t, err, "memdev mem0 (serial 0xc100e2e1): zeroing new shared dax0.0: no mmap")
	f.wantRegionReleased(t, "region0")
	wantUse(t, a, nil)
	f.zeroErr = nil

	// the dax device of a kept region fails: no claim, the region stays
	acquireShared(t, a, "u2", false)
	noErr(t, a.Release(ctx, "u2"))
	f.write(daxPath+"/dev", "bogus")
	_, err = a.AcquireShared(ctx, "u3", "mem", localSerial, false, "1 share")
	wantErr(t, err, "memdev mem0 (serial 0xc100e2e1): dax0.0: ")
	wantUse(t, a, &localUse{Shared: true, Claims: []string{}})
	f.write(daxPath+"/dev", "252:0")
	acquireShared(t, a, "u3", false)
	wantUse(t, a, &localUse{Shared: true, Claims: []string{"u3"}})
}

// A kept region that disappeared is forgotten, and the next claim creates
// and zeroes a new one.
func TestLocalSharedRegionGone(t *testing.T) {
	f := newFakeLocalSys(t)
	a := f.allocator(t, t.TempDir())
	ctx := context.Background()
	acquireShared(t, a, "u1", false)
	noErr(t, a.Release(ctx, "u1"))
	noErr(t, a.mem.ReleaseRegion(ctx, "region0"))
	f.wantRegionCount(t, 1, 1)
	acquireShared(t, a, "u2", false)
	f.wantRegionCount(t, 2, 1)
	if len(f.zeroed) != 2 {
		t.Fatalf("new region not zeroed: %v", f.zeroed)
	}
	wantUse(t, a, &localUse{Shared: true, Claims: []string{"u2"}})
}

// The state of another boot is dropped without touching the region; a
// half-made shared entry is kept while configured shared and rebuilt by
// the next claim.
func TestLocalSharedReconcileOtherBootAndHalfMade(t *testing.T) {
	f := newFakeLocalSys(t)
	dir := t.TempDir()
	ctx := context.Background()
	a := f.allocator(t, dir)
	acquireShared(t, a, "u1", false)
	before := f.commands()
	b := f.allocatorOfBoot(t, dir, "boot-2")
	b.Reconcile(ctx, map[string]bool{"u1": true})
	wantUse(t, b, nil)
	if f.commands() != before {
		t.Fatalf("another boot's state touched the system:\n%s", strings.TrimPrefix(f.commands(), before))
	}

	// half-made: region known, dax device not
	a = f.allocator(t, t.TempDir())
	a.devices[localSerial] = &localDevice{Serial: localSerial, SerialHex: "c100e2e1", Memdev: "mem0", Region: "region0", Node: -1, Shared: true, Claims: map[string][]*localSlice{}}
	a.SetShared(map[uint64]bool{localSerial: true})
	a.Reconcile(ctx, nil)
	wantUse(t, a, &localUse{Shared: true, Claims: []string{}})
	acquireShared(t, a, "u2", false)
	f.wantRegionCount(t, 2, 1)
	if s := a.devices[localSerial].Claims["u2"]; len(s) != 1 || s[0].Dax != "dax0.0" {
		t.Fatalf("rebuilt device %+v", a.devices[localSerial])
	}
}

// Prepare failures after the shared acquire roll the claim back and keep
// the region: a failed save, and a claim whose second result fails.
func TestPrepareSharedLocalRollback(t *testing.T) {
	e := newSharedTestState(t)
	ctx := context.Background()
	noErr(t, e.Prepare(ctx, sharedClaim("u0", "1")))
	noErr(t, e.Unprepare(ctx, "u0"))
	tmp := e.local.stateFile + ".tmp"
	noErr(t, os.MkdirAll(filepath.Join(tmp, "x"), 0o755))
	wantErr(t, e.Prepare(ctx, sharedClaim("u1", "1")), localStateFileName)
	noErr(t, os.RemoveAll(tmp))
	wantUse(t, e.local, &localUse{Shared: true, Claims: []string{}})
	e.f.wantRegionCount(t, 1, 0)

	c := sharedClaim("u2", "1")
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
		resourcev1.DeviceRequestAllocationResult{Request: "other", Driver: device.DriverName, Pool: testNode, Device: "missing"})
	wantErr(t, e.Prepare(ctx, c), "could not find allocatable device missing")
	wantUse(t, e.local, &localUse{Shared: true, Claims: []string{}})
	e.f.wantRegionCount(t, 1, 0)
	if len(e.Prepared) != 0 {
		t.Fatalf("prepared %v", e.Prepared)
	}
}

// A stale allocation of the shared shape is refused on a sliced memdev.
func TestPrepareSlicedRefusesShares(t *testing.T) {
	e := newLocalTestState(t)
	wantErr(t, e.Prepare(context.Background(), sharedClaim("u1", "1M")),
		"claim demo/claim-u1: request mem: device 0xc100e2e1: allocated as a shared device, which it is not any more")
	if strings.Contains(e.f.commands(), "create-region") || e.inUse() {
		t.Fatalf("a refused claim touched the memdev:\n%s", e.f.commands())
	}
}

// The local device of this node wins over another node's device with the
// same serial, whatever the order of the ResourceSlices.
func TestBrokerSerialOfThisNode(t *testing.T) {
	e := newSlicesBrokerEnv(t)
	node0 := nodeResourceSlice("node0", localMemdevDevice("memdev-c100e2e2", &device.Memdev{Serial: 0xc100e2e2, Size: 256 * mib, NodeAffinity: -1, Shared: true}))
	_, err := e.client.ResourceV1().ResourceSlices().Create(context.Background(), node0, metav1.CreateOptions{})
	noErr(t, err)
	dev, err := e.b.deviceBySerial(0xc100e2e2)
	noErr(t, err)
	if dev == nil || dev.node != testNode || dev.driver != device.DriverName {
		t.Fatalf("device %+v", dev)
	}
	var l lease
	req := api.Request{Op: api.OpRequest, Serial: "0xc100e2e2", Shared: true, ReadOnly: true}
	noErr(t, e.b.requestOptions(&l, &req))
	if !l.SharedDevice || l.DeviceSource != api.SourceLocal {
		t.Fatalf("lease %+v", l)
	}
	// only another node has it
	l = lease{}
	req.Serial = "0xc100e2e3"
	wantErr(t, e.b.requestOptions(&l, &req), "device 0xc100e2e3: a local device of node node2, not of this node")
}
