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
	"testing"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/compat"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// newSharedEnv returns a started node whose local memdev is configured
// shared, with the memdevs of specs plugged.
func newSharedEnv(t *testing.T, specs ...fake.MemdevSpec) *localTestEnv {
	t.Helper()
	e := newLocalTestEnv(t, specs...)
	configureShared(e, true)
	e.start()
	return e
}

// configureShared configures the local memdev shared or not: in the
// configuration of the publisher and of the next start, and in the shared
// memdevs of the running device engine.
func configureShared(e *localTestEnv, shared bool) {
	e.config.SharedDevices = nil
	e.shared = map[uint64]bool{}
	if shared {
		e.config.SharedDevices = []string{"0xc100e2e1"}
		e.shared[localSerial] = true
	}
	if e.devices != nil {
		e.devices.setShared(e.shared)
	}
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

// wantSharedUse checks how the device engine uses the local memdev, nil
// for not at all.
func wantSharedUse(t *testing.T, e *localTestEnv, want *localUse) {
	t.Helper()
	got, ok := e.localSnapshot().Use(localSerial)
	switch {
	case want == nil && ok:
		t.Fatalf("memdev used %+v, expected unused", got)
	case want != nil && (!ok || got.Shared != want.Shared || !slices.Equal(got.Claims, want.Claims)):
		t.Fatalf("memdev used %v %+v, expected %+v", ok, got, *want)
	}
}

// sharedPublished returns the local memdev as the node state publishes
// it, nil if it is not published.
func sharedPublished(e *localTestEnv) *resourcev1.Device {
	for _, d := range e.publisher.Resources().Pools[testNode].Slices[0].Devices {
		if d.Name == localDeviceName {
			return &d
		}
	}
	return nil
}

// wantCDIDeviceIDs checks the CDI devices of the result of a prepared
// claim.
func wantCDIDeviceIDs(t *testing.T, e *localTestEnv, uid string, ids ...string) {
	t.Helper()
	res, ok := e.prepared()[uid]
	if !ok || len(res.Devices) != 1 || !slices.Equal(res.Devices[0].CDIDeviceIDs, ids) {
		t.Fatalf("claim %s: prepared %v %+v, expected CDI devices %v", uid, ok, res.Devices, ids)
	}
}

// wantDax checks the size and the driver of a dax device of the kernel.
func wantDax(t *testing.T, e *localTestEnv, dax string, size uint64, driver string) {
	t.Helper()
	if got, d := e.k.DaxSize(dax), e.k.DaxDriver(dax); got != size || d != driver {
		t.Fatalf("%s: size %d driver %q, expected %d %q", dax, got, d, size, driver)
	}
}

// logLines returns the lines of logs that match the constant template of
// compat (no regular expression).
func logLines(logs, template string) []string {
	var out []string
	for _, line := range strings.Split(logs, "\n") {
		if compat.Matches(template, line) {
			out = append(out, line)
		}
	}
	return out
}

// wantLogLine fails the test unless a line of logs matches the constant
// template of compat.
func wantLogLine(t *testing.T, logs, template string) {
	t.Helper()
	if len(logLines(logs, template)) == 0 {
		t.Fatalf("no line %q in\n%s", template, logs)
	}
}

// regexpLines returns the lines of logs that match the regular expression
// constant pattern of compat.
func regexpLines(t *testing.T, logs, pattern string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(logs, "\n") {
		ok, err := compat.MatchesRegexp(pattern, line)
		noErr(t, err)
		if ok {
			out = append(out, line)
		}
	}
	return out
}

// publishLocalAs makes the devices of the last scan have the local memdev
// shared or not, as a scan before a change of the configuration published
// it: a claim allocated from it then is a stale allocation.
func publishLocalAs(e *localTestEnv, shared bool) {
	e.t.Helper()
	cfg := *e.config
	cfg.SharedDevices = nil
	if shared {
		cfg.SharedDevices = []string{"0xc100e2e1"}
	}
	devs, err := buildDevInfos(&cfg, &kernel.Snapshot{Memdevs: []kernel.MemdevInfo{e.memdevs[localSerial]}}, nil,
		&localSnapshot{BlockSize: localBlockSize})
	noErr(e.t, err)
	if devs[localDeviceName] == nil {
		e.t.Fatalf("the local memdev is not published shared %v", shared)
	}
	e.publisher.SetDevices(devs)
}

// The claims of a shared memdev get the same whole dax device: zeroed once
// when its region is made, never resized or onlined; the region stays when
// the memdev is idle and configured shared, and the next claim gets it
// without zeroing. Without the configuration the last Unprepare releases
// the region. The lines of the zeroing and of the claims are the pinned
// ones.
func TestLocalSharedClaims(t *testing.T) {
	e := newSharedEnv(t)
	logs := captureKlog(t)
	resized := false
	e.k.Before("write bus/dax/devices/dax0.0/size", func() { resized = true })
	e.mustPrepare(localClaim("u1", -int64(device.SharesUnlimited)))
	e.mustPrepare(localClaim("u2", -1, localROConfig))
	for _, uid := range []string{"u1", "u2"} {
		g := e.grant(uid, 0)
		if g.Got.Region != "region0" || g.Got.Dax != "dax0.0" || g.Got.Size != localRegionSize || e.records().DaxDevOf(g).Major != 252 || g.Asked.ReadOnly != (uid == "u2") {
			t.Fatalf("grant %s: %+v %+v", uid, g.Asked, g.Got)
		}
	}
	wantDax(t, e, "dax0.0", localRegionSize, "device_dax")
	if got := e.onlineBlocks(); len(got) > 0 {
		t.Fatalf("online blocks %v", got)
	}
	wantLocalRegionCount(t, e, 1, 0)
	if z := e.k.Zeroed(); !slices.Equal(z, []string{"252:0 1073741824 2097152"}) || resized {
		t.Fatalf("shared device zeroed %v or resized (%v)", z, resized)
	}
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{"u1", "u2"}})
	if m := e.localMemdev(localSerial); m == nil || !m.Facts.Shared {
		t.Fatalf("memdev %+v", m)
	}
	lines := logs()
	wantLogLine(t, lines, compat.LogZeroedNewSharedSharedDaxSizeDRALocalSizeIn)
	wantLogLine(t, lines, compat.LogClaimWriterUidRequestMemSharedSharedDaxSizeDRALocalSize)
	wantLogLine(t, lines, compat.LogClaimClaimUidRequestMemSharedSharedDaxSizeDRALocalSize)
	if got := regexpLines(t, lines, compat.LogZeroedNewSharedReleasingItsRegionReleasedSharedRegion); len(got) != 1 {
		t.Fatalf("lines of the zeroing and the release %q", got)
	}

	// Unprepares keep the region and the dax device
	e.mustUnprepare("u1")
	e.mustUnprepare("u2")
	wantLocalRegionCount(t, e, 1, 0)
	wantDax(t, e, "dax0.0", localRegionSize, "device_dax")
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{}})
	// the idle device is reused
	e.mustPrepare(localClaim("u3", -1))
	e.mustUnprepare("u3")
	wantLocalRegionCount(t, e, 1, 0)
	if z := e.k.Zeroed(); len(z) != 1 {
		t.Fatalf("zeroed again: %v", z)
	}

	// not configured shared any more: the last Unprepare takes the region
	e.mustPrepare(localClaim("u4", -1))
	configureShared(e, false)
	e.mustUnprepare("u4")
	wantReleasedLast(t, e, "region0")
	wantSharedUse(t, e, nil)
}

// A memdev is either sliced or shared while it has claims: a stale
// allocation of the other use is refused before the memdev is touched. An
// idle shared device that is not configured shared is released for a
// slice.
func TestLocalSharedMismatch(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	e.mustPrepare(localClaim("u1", localBlockSize, localDaxConfig))
	publishLocalAs(e, true)
	before := e.k.Commands()
	wantErr(t, e.prepare(localClaim("u2", -int64(device.SharesUnlimited))),
		"memdev mem0 (serial 0xc100e2e1): used as slices by claims [u1]; a shared device cannot be sliced")
	if got := e.k.CommandsSince(before); got != "" {
		t.Fatalf("commands of a refused claim:\n%s", got)
	}
	wantDax(t, e, "dax0.0", localBlockSize, "device_dax")
	e.mustUnprepare("u1")
	wantReleasedLast(t, e, "region0")

	e.mustPrepare(localClaim("u2", -1))
	publishLocalAs(e, false)
	wantErr(t, e.prepare(localClaim("u3", localBlockSize)),
		"memdev mem0 (serial 0xc100e2e1): used shared by claims [u2]; a sliced device cannot be shared")
	wantDax(t, e, "dax0.0", localRegionSize, "device_dax")
	wantLocalRegionCount(t, e, 2, 1)
	e.mustUnprepare("u2")

	// the idle shared device, not configured shared, for a slice
	configureShared(e, false)
	e.mustPrepare(localClaim("u4", localBlockSize, localDaxConfig))
	e.mustUnprepare("u4")
	wantLocalRegionCount(t, e, 3, 3)
	e.wantClean()
}

// A restart keeps an idle shared device while it is configured shared,
// keeps one with prepared claims anyway, and releases one that is idle and
// not configured shared; the grant of a claim whose Prepare did not finish
// is dropped. The start logs what it keeps and releases in the pinned
// lines.
func TestLocalSharedReconcile(t *testing.T) {
	const other = 0x91
	e := newSharedEnv(t, fake.MemdevSpec{Serial: other, Ram: 512 * mib, HostBridge: 24})
	e.mustPrepare(localClaim("u2", -1, localROConfig))
	// u1 is cut after its shared device, in the region of its second
	// result
	c := localClaim("u1", -1)
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
		resourcev1.DeviceRequestAllocationResult{Request: "other", Driver: device.DriverName, Pool: testNode, Device: memdevDeviceName(other)})
	e.k.CutAfter("cxl create-region -t ram -d decoder0.1")
	cutLocalPrepare(t, e, c)
	logs := captureKlog(t)
	e.restart()
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{"u2"}})
	wantDax(t, e, "dax0.0", localRegionSize, "device_dax")
	if rs := e.regions(other); len(rs) > 0 {
		t.Fatalf("the region of the cut claim is left: %v", rs)
	}
	lines := logs()
	wantLogLine(t, lines, compat.LogSerialDRALocalSerialKeepingSharedSharedRegionAndSharedDaxClaims)
	if got := logLines(lines, compat.LogSerialDRALocalSerialKeepingSharedSharedRegionAndSharedDaxClaims); !strings.HasSuffix(got[0], "keeping shared region0 and dax0.0, claims [u2]") {
		t.Fatalf("line %q", got[0])
	}

	// configured shared, no claims: kept idle
	e.mustUnprepare("u2")
	n := len(logs())
	e.restart()
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{}})
	e.mustPrepare(localClaim("u3", -1))
	wantLocalRegionCount(t, e, 1, 0)
	if got := regexpLines(t, logs()[n:], compat.LogZeroedNewSharedReleasingItsRegionReleasedSharedRegion); len(got) > 0 {
		t.Fatalf("the kept device was zeroed or released: %q", got)
	}

	// not configured shared: kept for its prepared claim, released after
	configureShared(e, false)
	e.restart()
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{"u3"}})
	wantLocalRegionCount(t, e, 1, 0)
	if sharedPublished(e) != nil {
		t.Fatal("the memdev is published while a claim uses it shared")
	}
	e.mustUnprepare("u3")
	wantReleasedLast(t, e, "region0")
	wantSharedUse(t, e, nil)

	// not configured shared and idle: released at the start
	configureShared(e, true)
	e.restart()
	e.mustPrepare(localClaim("u4", -1))
	e.mustUnprepare("u4")
	wantLocalRegionCount(t, e, 2, 1)
	configureShared(e, false)
	n = len(logs())
	e.restart()
	wantReleasedLast(t, e, "region0")
	wantSharedUse(t, e, nil)
	lines = logs()[n:]
	wantLogLine(t, lines, compat.LogSerialDRALocalSerialNotConfiguredSharedAnyMoreReleasing)
	if got := regexpLines(t, lines, compat.LogZeroedNewSharedReleasingItsRegionReleasedSharedRegion); len(got) == 0 {
		t.Fatalf("no line of the release in\n%s", lines)
	}
}

// The publication of a shared local memdev: shares without a request
// policy, no memory capacity, of any size, also with an unknown memory
// block size.
func TestPublishSharedLocalMemdev(t *testing.T) {
	e := newSharedEnv(t)
	got := sharedPublished(e)
	want := &resourcev1.Device{
		Name: localDeviceName,
		Attributes: map[resourcev1.QualifiedName]resourcev1.DeviceAttribute{
			"type":         {StringValue: ptr("memdev")},
			"source":       {StringValue: ptr("local")},
			"serial":       {StringValue: ptr("0xc100e2e1")},
			"shared":       {BoolValue: ptr(true)},
			"persistent":   {BoolValue: ptr(false)},
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
	devs, err := buildDevInfos(e.config, &kernel.Snapshot{Memdevs: []kernel.MemdevInfo{small}}, nil, &localSnapshot{})
	noErr(t, err)
	if m, ok := devs[localDeviceName].Dev.(*device.Memdev); !ok || !m.Shared || m.Size != 64*mib {
		t.Fatalf("small shared memdev %+v", devs[localDeviceName])
	}
}

// The sharedDevices of the configuration: a list of strings.
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
// and the region kept when idle; the shares and the mode are checked
// before the device is touched.
func TestPrepareSharedLocal(t *testing.T) {
	e := newSharedEnv(t)
	daxDev := filepath.Join(e.k.DevRoot(), "dax0.0")

	// the writer: no shares request, the scheduler counts all of them
	e.mustPrepare(sharedClaim("u1", "1M"))
	wantCDIDeviceIDs(t, e, "u1", "nri.io/cxl=claim-u1-0")
	e.wantDeviceInfo("u1", PreparedDeviceInfo{
		RequestName: "mem", DeviceName: localDeviceName, DeviceType: device.DeviceTypeMemdev, Mode: api.ModeDax, Shared: true,
		SysfsPath: e.k.P("bus/cxl/devices/region0"), NodeAffinities: []int{0},
		TotalBytes: localRegionSize, ConsumedBytes: localRegionSize, Serial: "0xc100e2e1",
		DaxDevice: daxDev, DaxMajor: 252, DaxMinor: 0,
	})
	e.wantCDIDevice("claim-u1-0",
		[]string{"CXL_C100E2E1_DAX=" + daxDev, "CXL_C100E2E1_MODE=dax", "CXL_C100E2E1_READONLY=0", "CXL_C100E2E1_SERIAL=0xc100e2e1",
			"CXL_C100E2E1_SHARED=1", "CXL_C100E2E1_SIZE=1073741824", "CXL_CLAIM_u1_0=1"},
		[]*cdiSpecs.DeviceNode{{Path: daxDev, Type: "c", Major: 252, Minor: 0}})
	// readers: one share each, read-only device nodes of the same device
	e.mustPrepare(sharedClaim("u2", "1", localROConfig))
	e.mustPrepare(sharedClaim("u3", "1", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"readOnly":true}}`))
	for _, uid := range []string{"u2", "u3"} {
		e.wantCDIDevice("claim-"+uid+"-0",
			[]string{"CXL_C100E2E1_DAX=" + daxDev, "CXL_C100E2E1_MODE=dax", "CXL_C100E2E1_READONLY=1", "CXL_C100E2E1_SERIAL=0xc100e2e1",
				"CXL_C100E2E1_SHARED=1", "CXL_C100E2E1_SIZE=1073741824", "CXL_CLAIM_" + uid + "_0=1"},
			[]*cdiSpecs.DeviceNode{{Path: daxDev, Type: "c", Major: 252, Minor: 0, Permissions: "r"}})
	}
	wantLocalRegionCount(t, e, 1, 0)
	if z := e.k.Zeroed(); len(z) != 1 {
		t.Fatalf("shared device zeroed %v, expected once at creation", z)
	}
	// still published while shared
	e.rescan()
	if d := sharedPublished(e); d == nil || !*d.Attributes["shared"].BoolValue {
		t.Fatalf("published %+v", d)
	}

	// the shares guard, before the device is touched
	before := e.k.Commands()
	for _, tc := range []struct{ shares, text string }{{"0", `"0"`}, {"", `""`}, {"500m", `"500m"`}} {
		wantErr(t, e.prepare(sharedClaim("u9", tc.shares)),
			"claim demo/claim-u9: request mem: device 0xc100e2e1: consumed shares "+tc.text+" is less than 1: request shares: 1 (a share) or no shares (exclusive)")
	}
	// dax only
	wantErr(t, e.prepare(sharedClaim("u9", "1", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"numa"}}`)),
		"MemoryConfig: device: a shared device is used as dax only")
	wantErr(t, e.prepare(sharedClaim("u9", "1", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"numa","readOnly":true}}`)),
		"MemoryConfig: device.readOnly needs mode dax")
	if got := e.k.CommandsSince(before); got != "" || e.prepared()["u9"].Devices != nil || e.preparation("u9") != nil {
		t.Fatalf("a refused claim touched the device:\n%s", got)
	}

	// all claims gone: the region and its dax device stay
	for _, uid := range []string{"u1", "u2", "u3"} {
		e.mustUnprepare(uid)
	}
	wantLocalRegionCount(t, e, 1, 0)
	wantDax(t, e, "dax0.0", localRegionSize, "device_dax")
	if e.cdiSpec() != nil || !e.inUse() {
		t.Fatalf("after the last Unprepare: CDI spec %+v, in use %v", e.cdiSpec(), e.inUse())
	}
	e.rescan()
	if d := sharedPublished(e); d == nil {
		t.Fatal("idle shared device not published")
	}
	e.mustPrepare(sharedClaim("u4", "1M"))
	wantLocalRegionCount(t, e, 1, 0)
	e.mustUnprepare("u4")
}

// A memdev is not published while claims of the other use have it.
func TestPrepareSharedLocalHiding(t *testing.T) {
	e := newSharedEnv(t)
	e.mustPrepare(sharedClaim("u1", "1"))
	// the configuration says sliced: hidden while shared
	configureShared(e, false)
	e.rescan()
	if d := sharedPublished(e); d != nil {
		t.Fatalf("published while used shared: %+v", d)
	}
	e.mustUnprepare("u1")
	wantReleasedLast(t, e, "region0")
	e.rescan()
	if d := sharedPublished(e); d == nil || *d.Attributes["shared"].BoolValue {
		t.Fatalf("published %+v", d)
	}
	// sliced claims hide the memdev when it is configured shared
	e.mustPrepare(localClaim("u2", localBlockSize, localDaxConfig))
	e.config.SharedDevices = []string{"mem0"}
	e.rescan()
	if d := sharedPublished(e); d != nil {
		t.Fatalf("published while used as slices: %+v", d)
	}
	e.mustUnprepare("u2")
	e.rescan()
	if d := sharedPublished(e); d == nil || !*d.Attributes["shared"].BoolValue {
		t.Fatalf("published %+v", d)
	}
}

// The companion claim of a lease of a shared local memdev: the broker
// gets the shared device, no NUMA node is lent, the region stays.
func TestPrepareSharedLocalLend(t *testing.T) {
	e := newSharedEnv(t)
	lender, hooks := newFakeLender(), &fakeHooks{}
	e.s.Lender().Set(lender, hooks)
	c := sharedClaim("u1", "1", localROConfig)
	c.ObjectMeta = companionClaim("l1").ObjectMeta
	c.UID = "u1"
	e.mustPrepare(c)
	if len(hooks.devs) != 1 || !hooks.devs[0].Shared || hooks.devs[0].DaxDevice != filepath.Join(e.k.DevRoot(), "dax0.0") ||
		!hooks.devs[0].ReadOnly || hooks.devs[0].TotalBytes != localRegionSize {
		t.Fatalf("lent devices %+v", hooks.devs)
	}
	if res := e.prepared()["u1"]; len(res.Devices) != 1 || len(res.Devices[0].CDIDeviceIDs) != 0 {
		t.Fatalf("CDI devices of a companion claim: %+v", res.Devices)
	}
	e.mustUnprepare("u1")
	if len(lender.calls) != 0 {
		t.Fatalf("nodes lent for a shared device: %v", lender.calls)
	}
	wantLocalRegionCount(t, e, 1, 0)
}

// A failed creation of the region of a shared memdev, or of its zeroing,
// leaves no device, no claim and no region; a dax device of a kept region
// that fails leaves the region kept and no claim.
func TestLocalSharedCreateFailures(t *testing.T) {
	e := newSharedEnv(t)
	// the retry fails too
	e.k.FailCommand("cxl create-region", fake.ErrAddDev, fake.ErrAddDev)
	wantErr(t, e.prepare(sharedClaim("u1", "1M")), "add_dev")
	wantSharedUse(t, e, nil)

	e.k.ZeroErr = errors.New("no mmap")
	err := e.prepare(sharedClaim("u1", "1M"))
	wantErr(t, err, "memdev mem0 (serial 0xc100e2e1): zeroing new shared dax0.0: no mmap")
	wantReleasedLast(t, e, "region0")
	wantSharedUse(t, e, nil)
	e.k.ZeroErr = nil

	// the dax device of a kept region fails: no claim, the region stays
	e.mustPrepare(sharedClaim("u2", "1M"))
	e.mustUnprepare("u2")
	e.k.Write("bus/dax/devices/dax0.0/dev", "bogus")
	before := e.k.Commands()
	wantErr(t, e.prepare(sharedClaim("u3", "1")), `memdev mem0 (serial 0xc100e2e1): dax0.0: dax0.0: cannot parse device numbers "bogus"`)
	wantNoRegionRelease(t, e.k.CommandsSince(before))
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{}})
	e.k.Write("bus/dax/devices/dax0.0/dev", "252:0")
	e.mustPrepare(sharedClaim("u3", "1"))
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{"u3"}})
}

// A kept region that disappeared is forgotten, and the next claim creates
// and zeroes a new one.
func TestLocalSharedRegionGone(t *testing.T) {
	e := newSharedEnv(t)
	e.mustPrepare(sharedClaim("u1", "1"))
	e.mustUnprepare("u1")
	noErr(t, e.k.Kernel().ReleaseRegion(context.Background(), "region0"))
	wantLocalRegionCount(t, e, 1, 1)
	logs := captureKlog(t)
	noErr(t, prepareOn(context.Background(), e.s, sharedClaim("u2", "1")))
	e.check("prepared u2")
	// the other claims of the device: none
	if want := strings.NewReplacer("mem1", "mem0", "[<uids>]", "[]").Replace(compat.DocLocalMemdevMem1Serial0xc100e2e1Region0OfThe); !strings.Contains(logs(), want) {
		t.Fatalf("no %q in\n%s", want, logs())
	}
	wantLocalRegionCount(t, e, 2, 1)
	if z := e.k.Zeroed(); len(z) != 2 {
		t.Fatalf("new region not zeroed: %v", z)
	}
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{"u2"}})
}

// The preparations of another boot are kept PREPARED_STALE at the start
// without touching the memdev: no prepared claim, no use, no command; the
// Prepare again makes the claim anew.
func TestLocalSharedReconcileOtherBootAndHalfMade(t *testing.T) {
	e := newSharedEnv(t)
	e.mustPrepare(sharedClaim("u1", "1"))
	e.k.Reboot()
	before := e.k.Commands()
	e.start()
	if got := e.k.CommandsSince(before); got != "" {
		t.Fatalf("another boot's records touched the system:\n%s", got)
	}
	if p := e.preparation("u1"); p == nil || p.State != state.PreparationStale || e.s.ClaimInfo("u1") != nil {
		t.Fatalf("claim of another boot %+v", p)
	}
	wantSharedUse(t, e, nil)
	e.mustPrepare(sharedClaim("u1", "1"))
	if p := e.preparation("u1"); p == nil || p.State != state.PreparationPrepared {
		t.Fatalf("claim prepared again %+v", p)
	}
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{"u1"}})
}

// Prepare failures after the shared device was realised roll the claim
// back and keep the region: a failed write of the CDI spec. A claim whose
// second result has no device fails before the device is touched.
func TestPrepareSharedLocalRollback(t *testing.T) {
	e := newSharedEnv(t)
	e.mustPrepare(sharedClaim("u0", "1"))
	e.mustUnprepare("u0")
	spec := filepath.Join(e.cdiDir, device.ClaimsCDISpecName+".yaml")
	noErr(t, os.MkdirAll(filepath.Join(spec, "x"), 0o755))
	wantErr(t, e.prepare(sharedClaim("u1", "1")), "failed to write CDI spec")
	noErr(t, os.RemoveAll(spec))
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{}})
	wantLocalRegionCount(t, e, 1, 0)
	if e.preparation("u1") != nil || e.s.ClaimInfo("u1") != nil {
		t.Fatalf("rolled back claim %+v", e.preparation("u1"))
	}

	c := sharedClaim("u2", "1")
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
		resourcev1.DeviceRequestAllocationResult{Request: "other", Driver: device.DriverName, Pool: testNode, Device: "missing"})
	before := e.k.Commands()
	wantErr(t, e.prepare(c), "could not find allocatable device missing")
	if got := e.k.CommandsSince(before); got != "" {
		t.Fatalf("commands of a refused claim:\n%s", got)
	}
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{}})
	wantLocalRegionCount(t, e, 1, 0)
	if len(e.prepared()) != 0 {
		t.Fatalf("prepared %v", e.prepared())
	}
}

// A stale allocation of the shared shape is refused on a sliced memdev.
func TestPrepareSlicedRefusesShares(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	wantErr(t, e.prepare(sharedClaim("u1", "1M")),
		"claim demo/claim-u1: request mem: device 0xc100e2e1: allocated as a shared device, which it is not any more")
	if strings.Contains(e.commands(), "create-region") || e.inUse() {
		t.Fatalf("a refused claim touched the memdev:\n%s", e.commands())
	}
}
