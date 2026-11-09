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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	nricxl "github.com/containers/nri-plugins/pkg/cxl"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// localOtherSerial is a second local memdev of RAM, under host bridge 24.
const localOtherSerial = 0xc100e2e3

// localRegionNode returns the NUMA node of the region of the local memdev
// in the kernel.
func localRegionNode(e *localTestEnv) int {
	e.t.Helper()
	rs := e.regions(localSerial)
	if len(rs) != 1 {
		e.t.Fatalf("regions %v", rs)
	}
	ri, err := e.k.Kernel().Region(rs[0])
	noErr(e.t, err)
	if ri.NumaNode < 0 {
		e.t.Fatalf("region %+v without a node", ri)
	}
	return ri.NumaNode
}

// wantMovable checks that n memory blocks are online, all movable and in
// the region of the local memdev.
func wantMovable(e *localTestEnv, n int) {
	e.t.Helper()
	online := e.onlineBlocks()
	if len(online) != n {
		e.t.Fatalf("%d blocks online %v, expected %d", len(online), online, n)
	}
	if n == 0 {
		return
	}
	blocks, err := e.k.Kernel().RegionBlocks(e.regions(localSerial)[0])
	noErr(e.t, err)
	for _, b := range online {
		if mb := e.k.Kernel().MemoryBlock(b); mb.Zones != "Movable" || !slices.Contains(blocks, b) {
			e.t.Fatalf("block %+v online, region blocks %v", mb, blocks)
		}
	}
}

// localDax returns the path of the device node of a dax device and its
// numbers.
func localDax(e *localTestEnv, dax string) (string, int, int) {
	e.t.Helper()
	major, minor, err := e.k.Kernel().DaxDevNumbers(dax)
	noErr(e.t, err)
	return filepath.Join(e.k.DevRoot(), dax), major, minor
}

// wantLocalCDIDevices checks the CDI devices of the first device of a
// prepared claim.
func wantLocalCDIDevices(e *localTestEnv, uid string, ids ...string) {
	e.t.Helper()
	res := e.preparedMap()[uid]
	if len(res.Devices) == 0 || !slices.Equal(res.Devices[0].CDIDeviceIDs, ids) {
		e.t.Fatalf("claim %s: prepared %+v, expected CDI devices %v", uid, res.Devices, ids)
	}
}

// Dax slices of a local memdev: devdax devices of whole blocks, read-only
// device nodes, no device node of a slice gone at a start.
func TestPrepareLocalDax(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	e.mustPrepare(localClaim("u1", localBlockSize, localDaxConfig))
	// 32Mi is rounded up to a memory block
	e.mustPrepare(localClaim("u2", 32*mib, localROConfig))
	wantLocalCDIDevices(e, "u2", "nri.io/cxl=claim-u2-0")
	dax1, major, minor1 := localDax(e, "dax0.1")
	dax0, _, minor0 := localDax(e, "dax0.0")
	e.wantDeviceInfo("u2", PreparedDeviceInfo{
		RequestName: "mem", DeviceName: localDeviceName, DeviceType: device.DeviceTypeMemdev, Mode: api.ModeDax,
		SysfsPath: e.k.P("bus/cxl/devices/region0"), NodeAffinities: []int{0},
		TotalBytes: localBlockSize, ConsumedBytes: localBlockSize, Serial: "0xc100e2e1",
		DaxDevice: dax1, DaxMajor: major, DaxMinor: minor1, ReadOnly: true,
	})
	e.wantCDIDevice("claim-u2-0",
		[]string{"CXL_C100E2E1_DAX=" + dax1, "CXL_C100E2E1_MODE=dax", "CXL_C100E2E1_READONLY=1", "CXL_C100E2E1_SERIAL=0xc100e2e1",
			"CXL_C100E2E1_SHARED=0", "CXL_C100E2E1_SIZE=134217728", "CXL_CLAIM_u2_0=1"},
		[]*cdiSpecs.DeviceNode{{Path: dax1, Type: "c", Major: int64(major), Minor: int64(minor1), Permissions: "r"}})
	e.wantCDIDevice("claim-u1-0",
		[]string{"CXL_C100E2E1_DAX=" + dax0, "CXL_C100E2E1_MODE=dax", "CXL_C100E2E1_READONLY=0", "CXL_C100E2E1_SERIAL=0xc100e2e1",
			"CXL_C100E2E1_SHARED=0", "CXL_C100E2E1_SIZE=134217728", "CXL_CLAIM_u1_0=1"},
		[]*cdiSpecs.DeviceNode{{Path: dax0, Type: "c", Major: int64(major), Minor: int64(minor0)}})

	// the spec is rebuilt from the prepared claims at a start, without the
	// device node of a slice that is gone
	k := e.k.Kernel()
	noErr(t, k.UnbindDax(context.Background(), "dax0.1"))
	noErr(t, k.DeleteDaxDevice(context.Background(), "region0", "dax0.1"))
	noErr(t, os.RemoveAll(e.cdiDir))
	noErr(t, os.MkdirAll(e.cdiDir, 0o755))
	e.restart()
	if spec := e.cdiSpec(); spec == nil || len(spec.Devices) != 2 {
		t.Fatalf("rebuilt CDI spec %+v", spec)
	}
	e.wantCDIDevice("claim-u2-0", []string{"CXL_C100E2E1_MODE=dax", "CXL_C100E2E1_READONLY=1", "CXL_C100E2E1_SERIAL=0xc100e2e1",
		"CXL_C100E2E1_SHARED=0", "CXL_C100E2E1_SIZE=134217728", "CXL_CLAIM_u2_0=1"}, nil)
	// a numa claim on the same device gets the node
	e.mustPrepare(localClaim("u3", localBlockSize))
	if got := e.s.ClaimInfo("u3").Devices[0]; got.DeviceType != device.DeviceTypeMemdev || got.Mode != api.ModeNUMA || !slices.Equal(got.NUMANodes, []int{localRegionNode(e)}) {
		t.Fatalf("numa claim %+v", got)
	}
	e.mustUnprepare("u3")

	e.mustUnprepare("u1")
	if cdiDeviceByName(e.cdiSpec(), "claim-u1-0") != nil {
		t.Fatal("CDI device of u1 not removed")
	}
	if e.k.DaxSize("dax0.0") != 0 || e.k.DaxDriver("dax0.0") != "" {
		t.Fatalf("dax0.0 of size %d bound to %q after its slice", e.k.DaxSize("dax0.0"), e.k.DaxDriver("dax0.0"))
	}
	e.mustUnprepare("u2")
	if e.cdiSpec() != nil || e.inUse() {
		t.Fatalf("after the last unprepare: in use %v", e.inUse())
	}
	e.wantClean()
}

// Two results of a claim on one memdev: a CDI device each with only its
// slice, the second one's env keys with _2.
func TestPrepareLocalTwoSlices(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	claim := localClaim("u1", 8*mib, localDaxConfig)
	r := claim.Status.Allocation.Devices.Results[0]
	r.Request = "mem2"
	claim.Status.Allocation.Devices.Results = append(claim.Status.Allocation.Devices.Results, r)
	ro := makeOpaqueConfig(device.DriverName, resourcev1.AllocationConfigSourceClaim, json.RawMessage(localROConfig))
	ro.Requests = []string{"mem2"}
	claim.Status.Allocation.Devices.Config = append(claim.Status.Allocation.Devices.Config, ro)
	e.mustPrepare(claim)
	devs := e.preparedMap()["u1"].Devices
	if len(devs) != 2 || !slices.Equal(devs[0].CDIDeviceIDs, []string{"nri.io/cxl=claim-u1-0"}) ||
		!slices.Equal(devs[1].CDIDeviceIDs, []string{"nri.io/cxl=claim-u1-1"}) {
		t.Fatalf("prepared %+v", devs)
	}
	dax0, major, minor0 := localDax(e, "dax0.0")
	dax1, _, minor1 := localDax(e, "dax0.1")
	e.wantCDIDevice("claim-u1-0", []string{
		"CXL_C100E2E1_DAX=" + dax0, "CXL_C100E2E1_MODE=dax", "CXL_C100E2E1_READONLY=0", "CXL_C100E2E1_SERIAL=0xc100e2e1",
		"CXL_C100E2E1_SHARED=0", "CXL_C100E2E1_SIZE=134217728", "CXL_CLAIM_u1_0=1"},
		[]*cdiSpecs.DeviceNode{{Path: dax0, Type: "c", Major: int64(major), Minor: int64(minor0)}})
	// the second slice of the memdev in the claim: <HEX>_2
	e.wantCDIDevice("claim-u1-1", []string{
		"CXL_C100E2E1_2_DAX=" + dax1, "CXL_C100E2E1_2_MODE=dax", "CXL_C100E2E1_2_READONLY=1", "CXL_C100E2E1_2_SERIAL=0xc100e2e1",
		"CXL_C100E2E1_2_SHARED=0", "CXL_C100E2E1_2_SIZE=134217728", "CXL_CLAIM_u1_1=1"},
		[]*cdiSpecs.DeviceNode{{Path: dax1, Type: "c", Major: int64(major), Minor: int64(minor1), Permissions: "r"}})
	if spec := e.cdiSpec(); len(spec.Devices) != 2 {
		t.Fatalf("CDI devices %+v", spec.Devices)
	}
	e.mustUnprepare("u1")
	e.wantClean()
}

// Refused MemoryConfigs and a result of a missing device touch no device;
// unmanaged memdevs are refused.
func TestPrepareLocalErrors(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	for _, tc := range []struct{ params, err string }{
		{`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"readOnly":true}}`, "MemoryConfig: device.readOnly needs mode dax"},
		{`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"ram"}}`, `MemoryConfig: device.mode: invalid mode "ram" (numa or dax)`},
		{`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"size":1}}`, `unknown field "device.size"`},
		{`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"LocalDeviceConfig","mode":"dax"}`, `claim demo/claim-u1: unknown kind "LocalDeviceConfig" (MemoryConfig)`},
		{`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"LendConfig","lease":"l1"}`, `unknown kind "LendConfig" (MemoryConfig)`},
		{`{"apiVersion":"cxl.nri.io/v1alpha1","mode":"dax"}`, `unknown kind "" (MemoryConfig)`},
	} {
		wantErr(t, e.prepare(localClaim("u1", 2*mib, tc.params)), tc.err)
	}
	if strings.Contains(e.commands(), "create-region") || len(e.preparedMap()) != 0 {
		t.Fatalf("a refused config touched the memdev:\n%s", e.commands())
	}
	// a result on a device that is not there stops the claim before its
	// memdev is touched
	claim := localClaim("u1", 2*mib, localDaxConfig)
	claim.Status.Allocation.Devices.Results = append(claim.Status.Allocation.Devices.Results,
		resourcev1.DeviceRequestAllocationResult{Request: "other", Driver: device.DriverName, Pool: testNode, Device: "missing"})
	wantErr(t, e.prepare(claim), "could not find allocatable device missing")
	if strings.Contains(e.commands(), "create-region") || e.inUse() || len(e.preparedMap()) != 0 || e.preparation("u1") != nil {
		t.Fatalf("a refused claim touched the memdev:\n%s", e.commands())
	}
	// unmanaged memdevs
	e.unmanaged()
	wantErr(t, e.prepare(localClaim("u1", 2*mib)), "manageMemdevs: false")
	e.wantClean()
}

// newLocalLendEnv returns a started localTestEnv with the memdevs of specs
// too, whose companion claims are lent by the fake lender and told to the
// fake hooks.
func newLocalLendEnv(t *testing.T, specs ...fake.MemdevSpec) (*localTestEnv, *fakeLender, *fakeHooks) {
	t.Helper()
	e := newLocalTestEnv(t, specs...)
	e.start()
	lender, hooks := newFakeLender(), &fakeHooks{}
	e.s.Lender().Set(lender, hooks)
	return e, lender, hooks
}

// wantLog checks that a log of calls ends with want.
func wantLog(t *testing.T, log, want string) {
	t.Helper()
	if !strings.HasSuffix(log, want) {
		t.Fatalf("calls\n%s\nexpected to end with\n%s", log, want)
	}
}

// A companion claim of a numa slice: the node lent and told to the broker,
// no CDI device, told again by a Prepare again, revoked before the release.
func TestPrepareLocalLend(t *testing.T) {
	e, lender, hooks := newLocalLendEnv(t)
	// the lease gets the slice: 64Mi rounded up to a memory block
	e.mustPrepare(localCompanion("u1", 64*mib))
	node := localRegionNode(e)
	wantLog(t, lender.callLog(), "lend pod-uid-1/app "+strconv.Itoa(node))
	wantLog(t, hooks.log(), "lending l1 cxl-lease-l1\nprepared l1")
	wantDev := lentDevice{
		Driver: device.DriverName, Source: api.SourceLocal, Request: "mem", Device: localDeviceName, Pool: testNode,
		Serial: localSerial, Size: localBlockSize, Mode: api.ModeNUMA, Node: node,
	}
	if !reflect.DeepEqual(hooks.devs, []lentDevice{wantDev}) {
		t.Fatalf("lent devices %+v", hooks.devs)
	}
	if rec := e.s.ClaimInfo("u1").Lend; rec == nil || rec.Lease != "l1" || !slices.Equal(rec.Nodes, []int{node}) {
		t.Fatalf("lend record %+v", rec)
	}
	// the companion's own containers get no CDI device, and the spec has
	// none of the companion
	wantLocalCDIDevices(e, "u1")
	if cdiDeviceByName(e.cdiSpec(), "claim-u1-0") != nil {
		t.Fatal("CDI device of a companion claim")
	}
	// the lend is in the claims info
	data, err := os.ReadFile(filepath.Join(e.dir, preparedClaimsInfoFileName))
	if err != nil || !strings.Contains(string(data), `"lease": "l1"`) {
		t.Fatalf("claims info lacks the lend: %v\n%s", err, data)
	}
	// a repeated Prepare tells the broker again
	e.mustPrepare(localCompanion("u1", 64*mib))
	wantLog(t, hooks.log(), "prepared l1\nlending l1 cxl-lease-l1\nprepared l1")

	e.mustUnprepare("u1")
	wantLog(t, lender.callLog(), "lend pod-uid-1/app "+strconv.Itoa(node)+"\nrevoke pod-uid-1/app "+strconv.Itoa(node))
	wantLog(t, hooks.log(), "releasing l1")
	e.wantClean()
}

// A companion claim of a dax slice: the broker passes the dax device, no
// node is lent.
func TestPrepareLocalLendDax(t *testing.T) {
	e, lender, hooks := newLocalLendEnv(t)
	e.mustPrepare(localCompanion("u1", 16*mib, localDaxConfig))
	dax0, _, _ := localDax(e, "dax0.0")
	if len(hooks.devs) != 1 || hooks.devs[0].Mode != api.ModeDax || hooks.devs[0].DaxDevice != dax0 || hooks.devs[0].Node != -1 {
		t.Fatalf("lent dax devices %+v", hooks.devs)
	}
	// the borrower gets the fd from the broker, the companion nothing
	wantLocalCDIDevices(e, "u1")
	e.mustUnprepare("u1")
	if len(lender.calls) != 0 {
		t.Fatalf("nodes lent for a dax lease: %v", lender.calls)
	}
	e.wantClean()
}

// The refusals of a companion claim: lending disabled, a failed lend rolled
// back, other devices than local memdevs, a companion the broker refuses.
func TestPrepareLocalLendErrors(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	wantErr(t, e.prepare(localCompanion("u1", 64*mib)), "lease l1: lending to running containers is disabled (--leases=false)")
	e.wantClean()

	e, lender, hooks := newLocalLendEnv(t)
	// a failed lend rolls back
	lender.lendErr = errors.New("container is steered")
	wantErr(t, e.prepare(localCompanion("u2", 64*mib)), "container is steered")
	failed := hooks.log()
	wantLog(t, failed, "failed l1: lease l1: lending node 2 to demo/borrower/app: container is steered")
	if e.inUse() || len(e.preparedMap()) != 0 || len(e.regions(localSerial)) != 0 {
		t.Fatal("not rolled back")
	}

	// only local memdevs are lent
	devs, err := e.allocatable()
	noErr(t, err)
	devs["dram"] = &device.DeviceInfo{Name: "dram", Dev: &device.DRAM{Nodes: []int{0}, Size: 1 << 30}}
	claim := localCompanion("u4", 64*mib)
	claim.Status.Allocation.Devices.Results[0].Device = "dram"
	wantErr(t, e.prepare(claim), "the companion claim of lease l1 needs memdev devices only")

	// a refused companion claim: the device is not touched
	hooks.lendingErr = errors.New("claim demo/cxl-lease-l1: not the companion of lease l1")
	before := e.commands()
	wantErr(t, e.prepare(localCompanion("u5", 64*mib)), "not the companion of lease l1")
	if e.commands() != before {
		t.Fatalf("a refused companion touched the memdev:\n%s", strings.TrimPrefix(e.commands(), before))
	}
	e.wantClean()
	if !strings.Contains(failed, "\nfailed l1: lease l1: lending node ") {
		t.Fatalf("the broker hears %q, expected the lend error without the claim", failed[strings.LastIndex(failed, "failed l1: "):])
	}
}

// A prepared claim is returned as it is, also without an allocation; only a
// companion claim tells the broker again.
func TestPrepareAlreadyPrepared(t *testing.T) {
	e, lender, hooks := newLocalLendEnv(t)
	ctx := context.Background()
	res := prepareResultOn(ctx, e.s, localCompanion("u1", 64*mib))
	noErr(t, res.Err)
	noErr(t, prepareResultOn(ctx, e.s, localClaim("u2", 16*mib)).Err)
	before := e.commands()

	again := localCompanion("u1", 64*mib)
	again.Status.Allocation = nil
	res2 := prepareResultOn(ctx, e.s, again)
	if res2.Err != nil || !reflect.DeepEqual(res2, res) {
		t.Fatalf("repeated prepare %+v, expected %+v", res2, res)
	}
	wantLog(t, hooks.log(), "lending l1 cxl-lease-l1\nprepared l1")
	again = localClaim("u2", 16*mib)
	again.Status.Allocation = nil
	noErr(t, prepareResultOn(ctx, e.s, again).Err)
	if e.commands() != before || len(lender.calls) != 1 {
		t.Fatalf("repeated prepare touched devices:\n%s\nlender %v", strings.TrimPrefix(e.commands(), before), lender.calls)
	}
	if n := strings.Count(hooks.log(), "prepared l1"); n != 2 {
		t.Fatalf("hooks %s", hooks.log())
	}
	e.check("prepared again")
	e.mustUnprepare("u1")
	e.mustUnprepare("u2")
	e.wantClean()
}

// blockingLender is a fakeLender whose LendNode waits until release is
// closed.
type blockingLender struct {
	*fakeLender
	entered chan struct{}
	release chan struct{}
}

func (b *blockingLender) LendNode(ctx context.Context, podUID, name string, node int, holder string) error {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.release
	return b.fakeLender.LendNode(ctx, podUID, name, node, holder)
}

// lends returns the number of calls of the lender.
func (b *blockingLender) lends() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.calls)
}

// The NRI readers, the publisher and other claims never wait for a Prepare
// that lends, and two Prepares of one claim run one after the other.
func TestPrepareDoesNotBlockReaders(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	bl := &blockingLender{fakeLender: newFakeLender(), entered: make(chan struct{}, 1), release: make(chan struct{})}
	hooks := &fakeHooks{}
	e.s.Lender().Set(bl, hooks)
	ctx := context.Background()
	e.mustPrepare(localClaim("u0", 32*mib))

	done := make(chan error, 2)
	go func() { done <- prepareOn(ctx, e.s, localCompanion("u1", 64*mib)) }()
	select {
	case <-bl.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("Prepare did not lend")
	}
	readers := make(chan error, 1)
	go func() {
		if e.s.ClaimInfo("u0") == nil {
			readers <- errors.New("no claim info of u0")
			return
		}
		_, _, _ = e.s.PreparedResult("u0", 0)
		_ = e.publisher.Resources()
		err := prepareOn(ctx, e.s, localClaim("u2", 2*mib))
		if err == nil {
			err = unprepareOn(ctx, e.s, "u2")
		}
		readers <- err
	}()
	select {
	case err := <-readers:
		noErr(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("claim info, resources or another claim waited for a lend")
	}

	go func() { done <- prepareOn(ctx, e.s, localCompanion("u1", 64*mib)) }()
	select {
	case err := <-done:
		t.Fatalf("a Prepare of u1 finished during the lend of u1: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(bl.release)
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			noErr(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("Prepare of u1 did not finish")
		}
	}
	e.check("prepared")
	if n := bl.lends(); n != 1 {
		t.Fatalf("%d lends of u1", n)
	}
	n := 0
	for _, g := range e.records().Grants {
		if g.Ref.Claim == "u1" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d grants of u1", n)
	}
	wantLog(t, hooks.log(), "lending l1 cxl-lease-l1\nprepared l1\nlending l1 cxl-lease-l1\nprepared l1")
	e.mustUnprepare("u1")
	e.mustUnprepare("u0")
	e.wantClean()
}

// A failed revoke keeps the companion claim and its memory; a failed slice
// release keeps the claim and its CDI device for the retry.
func TestUnprepareLocalFailures(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	hooks := &fakeHooks{}
	e.s.Lender().Set(revokeFailer{fakeLender: newFakeLender()}, hooks)

	// a revoke that fails keeps the claim and its memory
	e.mustPrepare(localCompanion("u1", 64*mib))
	wantErr(t, e.unprepare("u1"), "node "+strconv.Itoa(localRegionNode(e))+" busy")
	if _, found := e.preparedMap()["u1"]; !found || strings.Contains(e.commands(), "destroy-region") {
		t.Fatalf("claim released after a failed revoke:\n%s", e.commands())
	}
	wantLog(t, hooks.log(), "releasing l1")
	e.s.Lender().Set(newFakeLender(), hooks)
	e.mustUnprepare("u1")
	if len(e.regions(localSerial)) != 0 {
		t.Fatalf("regions %v", e.regions(localSerial))
	}

	// a slice that fails to delete keeps the claim and its CDI device
	e.mustPrepare(localClaim("u2", 8*mib, localDaxConfig))
	e.k.FailWrite("bus/dax/devices/dax0.0/size", syscall.EBUSY)
	wantErr(t, e.unprepare("u2"), "releasing slice dax0.0")
	if _, found := e.preparedMap()["u2"]; !found || cdiDeviceByName(e.cdiSpec(), "claim-u2-0") == nil {
		t.Fatal("claim or CDI device gone after a failed release")
	}
	e.mustUnprepare("u2")
	if e.cdiSpec() != nil || e.inUse() {
		t.Fatalf("after the retry: in use %v", e.inUse())
	}
	e.wantClean()
}

// A companion claim whose CDI spec cannot be written rolls back: the lend
// revoked, the broker told, the memory released.
func TestPrepareLocalPersistFailure(t *testing.T) {
	e, lender, hooks := newLocalLendEnv(t, fake.MemdevSpec{Serial: localOtherSerial, Ram: localRegionSize, HostBridge: 24})
	e.rescan()
	// a claim with a CDI device on the other memdev, then a CDI directory
	// that cannot be written
	e.mustPrepare(memdevClaim("u0", memdevDeviceName(localOtherSerial), localBlockSize))
	noErr(t, os.RemoveAll(e.cdiDir))
	noErr(t, os.WriteFile(e.cdiDir, nil, 0o644))
	err := e.prepare(localCompanion("u1", 64*mib))
	wantErr(t, err, "CDI spec")
	if calls := lender.callLog(); calls != "lend pod-uid-1/app 2\nrevoke pod-uid-1/app 2" {
		t.Fatalf("lender calls %q", calls)
	}
	if log := hooks.log(); !strings.HasSuffix(log, "\nfailed l1: "+err.Error()) || strings.Contains(log, "releasing") {
		t.Fatalf("hooks %s", log)
	}
	if _, found := e.preparedMap()["u1"]; found || e.s.ClaimInfo("u1") != nil || e.preparation("u1") != nil || len(e.regions(localSerial)) != 0 {
		t.Fatalf("claim kept after the rollback, regions %v", e.regions(localSerial))
	}
	noErr(t, os.Remove(e.cdiDir))
	noErr(t, os.MkdirAll(e.cdiDir, 0o755))
	e.mustPrepare(localCompanion("u1", 64*mib))
	e.mustUnprepare("u1")
	e.mustUnprepare("u0")
	e.wantClean()
}

// A Prepare that fails after the lease was marked Lending (a region on the
// memdev that the driver did not make) leaves the lease to the retry.
func TestPrepareLocalFailsAfterCheck(t *testing.T) {
	e, _, hooks := newLocalLendEnv(t)
	k := e.k.Kernel()
	memdev := e.k.Memdev(localSerial)
	d, err := k.RootDecoder(memdev, kernel.RegionRAM)
	noErr(t, err)
	region, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: memdev, Decoder: d, Type: kernel.RegionRAM})
	noErr(t, err)
	wantErr(t, e.prepare(localCompanion("u1", 64*mib)), "that the plugin did not create")
	if log := hooks.log(); log != "lending l1 cxl-lease-l1" {
		t.Fatalf("hooks %s", log)
	}
	noErr(t, k.ReleaseRegion(context.Background(), region))
	e.mustPrepare(localCompanion("u1", 64*mib))
	if log := hooks.log(); log != "lending l1 cxl-lease-l1\nlending l1 cxl-lease-l1\nprepared l1" {
		t.Fatalf("hooks %s", log)
	}
	e.mustUnprepare("u1")
	e.wantClean()
}

// injectDevices adds devices of regions, DRAM or the lease device to the
// devices of the scan of the node state of the env.
func injectDevices(e *localTestEnv, infos ...*device.DeviceInfo) {
	e.t.Helper()
	devs, err := e.allocatable()
	noErr(e.t, err)
	for _, d := range infos {
		devs[d.Name] = d
	}
}

// A device section on a region or DRAM request fails unless it is numa.
func TestPrepareRegionDRAMNUMAOnly(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	injectDevices(e,
		&device.DeviceInfo{Name: "region0-node2", Dev: &nricxl.RegionDevice{Name: "region0", Node: 2, Size: 1 << 30, Enabled: true}},
		&device.DeviceInfo{Name: "dram", Dev: &device.DRAM{Nodes: []int{0}, Size: 1 << 30}})
	var unprefixed []string
	for _, tc := range []struct{ dev, params, err string }{
		{"region0-node2", localDaxConfig, "claim demo/claim-u1: request mem: MemoryConfig: device: a region is used as numa only"},
		{"region0-node2", localROConfig, "MemoryConfig: device: a region is used as numa only"},
		{"region0-node2", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"readOnly":true}}`, "MemoryConfig: device.readOnly needs mode dax"},
		{"dram", localDaxConfig, "claim demo/claim-u1: request mem: MemoryConfig: device: a dram is used as numa only"},
		{"dram", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"readOnly":true}}`, "MemoryConfig: device.readOnly needs mode dax"},
		{"dram", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"ram"}}`, `MemoryConfig: device.mode: invalid mode "ram" (numa or dax)`},
		{"region0-node2", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"numa"}}`, ""},
		{"dram", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"numa"}}`, ""},
	} {
		claim := localClaim("u1", 64*mib, tc.params)
		claim.Status.Allocation.Devices.Results[0].Device = tc.dev
		err := e.prepare(claim)
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%s %s: %v", tc.dev, tc.params, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), strings.TrimPrefix(tc.err, "claim demo/claim-u1: request mem: "))):
			t.Errorf("%s %s: expected error %q, got %v", tc.dev, tc.params, tc.err, err)
		case tc.err != "" && !strings.Contains(err.Error(), tc.err):
			unprefixed = append(unprefixed, err.Error())
		}
		if err == nil {
			e.mustUnprepare("u1")
		}
	}
	if len(e.preparedMap()) != 0 {
		t.Fatalf("prepared %v", e.preparedMap())
	}
	e.wantClean()
	wantPrefixed(t, unprefixed)
}

// wantPrefixed fails the test when errors of the device settings of a
// region, the DRAM or the lease device lacked the claim and the request.
func wantPrefixed(t *testing.T, unprefixed []string) {
	t.Helper()
	if len(unprefixed) > 0 {
		t.Errorf("the error of the device settings of a region, the DRAM or the lease device does not name the claim and the request: %q", unprefixed)
	}
}

// fakeLeaseClaims records the lease claims whose sockets are open, with
// their records in the store st as the lease broker keeps them.
type fakeLeaseClaims struct {
	st   *store.Store
	open map[string]bool
}

func (f *fakeLeaseClaims) OpenClaim(claim *resourcev1.ResourceClaim) error {
	if f.open == nil {
		f.open = map[string]bool{}
	}
	f.open[string(claim.UID)] = true
	return f.st.Commit(context.Background(), store.Durable, func(doc *store.Document) error {
		doc.LeaseClaims = append(doc.LeaseClaims, state.LeaseClaim{UID: string(claim.UID), Namespace: claim.Namespace, Name: claim.Name,
			State: state.LeaseClaimOpen})
		return nil
	})
}

func (f *fakeLeaseClaims) CloseClaim(ctx context.Context, uid string) error {
	delete(f.open, uid)
	return f.st.Commit(ctx, store.Durable, func(doc *store.Document) error {
		doc.LeaseClaims = slices.DeleteFunc(doc.LeaseClaims, func(c state.LeaseClaim) bool { return c.UID == uid })
		return nil
	})
}

// memoryConfigClaim returns a claim with the results numa (a slice of the
// local memdev), region, dram and lease, in this order, of the device
// classes cxl-local, cxl-region, cxl-dram and cxl-lease, with the configs.
func memoryConfigClaim(uid string, configs ...resourcev1.DeviceAllocationConfiguration) *resourcev1.ResourceClaim {
	c := localClaim(uid, localBlockSize)
	c.Status.Allocation.Devices.Results[0].Request = "numa"
	for _, r := range []struct{ request, dev string }{{"region", "region5-node4"}, {"dram", "dram"}, {"lease", device.LeaseDeviceName}} {
		c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
			resourcev1.DeviceRequestAllocationResult{Request: r.request, Driver: device.DriverName, Pool: testNode, Device: r.dev})
	}
	for _, i := range []int{1, 2} {
		c.Status.Allocation.Devices.Results[i].ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{
			device.CapacityMemory: *resource.NewQuantity(64*mib, resource.BinarySI)}
	}
	for _, r := range []struct{ request, class string }{{"numa", "cxl-local"}, {"region", "cxl-region"}, {"dram", "cxl-dram"}, {"lease", "cxl-lease"}} {
		c.Spec.Devices.Requests = append(c.Spec.Devices.Requests,
			resourcev1.DeviceRequest{Name: r.request, Exactly: &resourcev1.ExactDeviceRequest{DeviceClassName: r.class}})
	}
	c.Status.Allocation.Devices.Config = configs
	return c
}

// memoryConfigEntry returns an opaque config entry of cxl.nri.io.
func memoryConfigEntry(source resourcev1.AllocationConfigSource, requests []string, params string) resourcev1.DeviceAllocationConfiguration {
	e := makeOpaqueConfig(device.DriverName, source, json.RawMessage(params))
	e.Requests = requests
	return e
}

// The MemoryConfig entries of results of every device type: presets of
// classes, settings with origins, markers; refused entries touch no device.
func TestPrepareMemoryConfig(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	leases := &fakeLeaseClaims{st: e.st}
	e.s.SetLeases(leases)
	injectDevices(e,
		&device.DeviceInfo{Name: "region5-node4", Dev: &nricxl.RegionDevice{Name: "region5", Node: 4, Size: 1 << 30, Enabled: true}},
		&device.DeviceInfo{Name: "dram", Dev: &device.DRAM{Nodes: []int{0}, Size: 1 << 30}},
		&device.DeviceInfo{Name: device.LeaseDeviceName, Dev: &device.LeaseToken{}})
	const (
		class = resourcev1.AllocationConfigSourceClass
		claim = resourcev1.AllocationConfigSourceClaim
	)

	c := memoryConfigClaim("u1",
		// a claim entry before a class entry: classes come first
		memoryConfigEntry(claim, []string{"dram"}, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"first-dram","maxStep":"1Gi"}}}`),
		memoryConfigEntry(class, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"auto"}}}`),
		// null removes the preset of the class
		memoryConfigEntry(claim, []string{"numa"}, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":null}}}`),
	)
	e.mustPrepare(c)
	info := e.s.ClaimInfo("u1")
	auto := func(origin string) config.ResultSettings {
		return config.ResultSettings{Container: &config.Container{Steering: &config.Steering{Policy: config.PolicyAuto}}, Origins: map[string]string{config.FieldPolicy: origin}}
	}
	for i, want := range []config.ResultSettings{
		{},
		auto("class cxl-region"),
		{Container: &config.Container{Steering: &config.Steering{Policy: config.PolicyFirstDRAM, MaxStep: "1Gi"}},
			Origins: map[string]string{config.FieldPolicy: "claim demo/claim-u1 request dram", config.FieldMaxStep: "claim demo/claim-u1 request dram"}},
		auto("class cxl-lease"),
	} {
		if d := info.Devices[i]; d.Result != i || !sameSettings(d.ResultSettings, want) {
			t.Errorf("result %d (%s): %d %+v %v, expected %+v %v", i, d.RequestName, d.Result, d.Container, d.Origins, want.Container, want.Origins)
		}
	}
	node := localRegionNode(e)
	if d := info.Devices[0]; d.Mode != api.ModeNUMA || !slices.Equal(d.NUMANodes, []int{node}) {
		t.Fatalf("numa slice %+v", d)
	}
	// one CDI device per result, with the marker of the result
	for n, wantID := range []string{"claim-u1-0", "claim-u1-1", "claim-u1-2", "claim-u1-3"} {
		d := cdiDeviceByName(e.cdiSpec(), wantID)
		marker := resultEnvVarName("u1", n) + "=1"
		if d == nil || !slices.Contains(d.ContainerEdits.Env, marker) {
			t.Fatalf("CDI device %s: %+v, expected %s", wantID, d, marker)
		}
		for _, env := range d.ContainerEdits.Env {
			if strings.HasPrefix(env, "CXL_CLAIM_") && env != marker {
				t.Fatalf("CDI device %s has the marker %s", wantID, env)
			}
		}
	}
	if !leases.open["u1"] {
		t.Fatal("no lease socket")
	}

	// a container gets the management of the results it uses
	for _, tc := range []struct {
		results []int
		want    string
	}{
		{[]int{0}, "fenced " + strconv.Itoa(node) + " none (default)"},
		{[]int{1}, "steered 4 auto from class cxl-region"},
		{[]int{2}, "steered  first-dram from claim demo/claim-u1 request dram"},
		{[]int{0, 1}, "steered " + strconv.Itoa(node) + ",4 auto from class cxl-region"},
		{[]int{3}, "fenced  auto from class cxl-lease"},
	} {
		c, err := createdContainer(t, e.st, e.s, nil, "u1", tc.results...)
		noErr(t, err)
		if got := strings.ToLower(string(c.Management)) + " " + c.Claimed.String() + " " + c.Steering; got != tc.want {
			t.Errorf("results %v: %q, expected %q", tc.results, got, tc.want)
		}
	}
	_, err := createdContainer(t, e.st, e.s, nil, "u1", 1, 2)
	wantErr(t, err, "container demo/pod/ctr: container.steering.policy: class cxl-region says auto, claim demo/claim-u1 request dram says first-dram")
	noErr(t, leases.CloseClaim(context.Background(), "u1"))
	e.mustUnprepare("u1")

	// the device rules of every result are checked before any device is
	// touched
	commands := e.commands()
	var unprefixed []string
	for _, tc := range []struct{ request, params, err string }{
		{"lease", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"numa"}}`,
			"claim demo/claim-u9: request lease: MemoryConfig: device: the lease device has no device settings"},
		{"region", localDaxConfig, "claim demo/claim-u9: request region: MemoryConfig: device: a region is used as numa only"},
		{"dram", localROConfig, "claim demo/claim-u9: request dram: MemoryConfig: device: a dram is used as numa only"},
	} {
		err := e.prepare(memoryConfigClaim("u9", memoryConfigEntry(claim, []string{tc.request}, tc.params)))
		wantErr(t, err, strings.TrimPrefix(tc.err, "claim demo/claim-u9: request "+tc.request+": "))
		if !strings.Contains(err.Error(), tc.err) {
			unprefixed = append(unprefixed, err.Error())
		}
		if len(e.preparedMap()) != 0 || e.inUse() || leases.open["u9"] {
			t.Fatalf("%s: prepared %v, memdev in use %v", tc.err, e.preparedMap(), e.inUse())
		}
	}

	// the entries and the values of all results are checked before any
	// device is touched
	for _, tc := range []struct {
		configs []resourcev1.DeviceAllocationConfiguration
		err     string
	}{
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(class, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","pool":{"opaque":{"fake-cxl-pool":{"numaNode":1}}}}`)},
			"claim demo/claim-u9: MemoryConfig: pool: only for devices of cxl-pool.nri.io"},
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(class, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"fencing":"none"}}`)},
			"claim demo/claim-u9: MemoryConfig: container.fencing: set by the driver configuration only (defaults.container.fencing)"},
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(claim, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"off"}}}`)},
			`claim demo/claim-u9: request numa: MemoryConfig: container.steering.policy: invalid policy "off" (none, auto, first-dram, first-cxl, start-interleaved, end-interleaved or waypoints)`},
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(claim, []string{"dram"}, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"none","maxStep":"1Gi"}}}`)},
			"claim demo/claim-u9: request dram: MemoryConfig: container.steering.maxStep needs a policy other than none"},
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(claim, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"DeviceConfig","mode":"dax"}`)},
			`claim demo/claim-u9: unknown kind "DeviceConfig" (MemoryConfig)`},
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(claim, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryPolicyConfig","memoryUseOrder":"first-dram"}`)},
			`claim demo/claim-u9: unknown kind "MemoryPolicyConfig" (MemoryConfig)`},
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(claim, nil, `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"MemoryConfig"}`)},
			`claim demo/claim-u9: MemoryConfig: apiVersion "cxl-pool.nri.io/v1alpha1", expected "cxl.nri.io/v1alpha1"`},
		// every entry of the driver is checked, also of other requests
		{[]resourcev1.DeviceAllocationConfiguration{
			memoryConfigEntry(class, nil, localDaxConfig),
			memoryConfigEntry(claim, []string{"other"}, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"online":"all"}}`)},
			`claim demo/claim-u9: MemoryConfig: FromClaim config 0: json: unknown field "device.online"`},
	} {
		wantErr(t, e.prepare(memoryConfigClaim("u9", tc.configs...)), tc.err)
		if len(e.preparedMap()) != 0 || e.inUse() || leases.open["u9"] {
			t.Fatalf("%s: prepared %v, memdev in use %v", tc.err, e.preparedMap(), e.inUse())
		}
	}
	if got := e.commands(); got != commands {
		t.Fatalf("a refused config touched the memdev:\n%s", strings.TrimPrefix(got, commands))
	}
	e.wantClean()
	wantPrefixed(t, unprefixed)
}

// sameSettings tells whether two container settings are equal, an empty
// map of origins as none.
func sameSettings(a, b config.ResultSettings) bool {
	if len(a.Origins) == 0 && len(b.Origins) == 0 {
		a.Origins, b.Origins = nil, nil
	}
	return reflect.DeepEqual(a, b)
}

// A Prepare again of a claim that a failed Prepare left KEPT, refused by
// its validation, rolls nothing back: the region kept for the claim stays
// for the next Prepare or the Unprepare.
func TestPrepareKeptRefusedKeepsItsRegion(t *testing.T) {
	for _, tc := range []struct {
		name  string
		claim func() *resourcev1.ResourceClaim
		err   string
	}{
		{"a device that is not allocatable", func() *resourcev1.ResourceClaim {
			claim := localClaim("u1", localBlockSize)
			claim.Status.Allocation.Devices.Results[0].Device = "memdev-deadbeef"
			return claim
		}, "could not find allocatable device memdev-deadbeef"},
		{"an invalid MemoryConfig", func() *resourcev1.ResourceClaim {
			return localClaim("u1", localBlockSize, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"bogus"}}`)
		}, "MemoryConfig: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newLocalTestEnv(t)
			other := plugAbove(e)
			e.start()
			above := makeAboveAfterCreate(e, other)
			failDeviceDax(e)
			wantErr(t, e.prepare(localClaim("u1", localBlockSize)), errDeviceDax)
			releaseAbove(e, above())
			before := e.commands()
			wantErr(t, e.prepare(tc.claim()), tc.err)
			if got := strings.TrimPrefix(e.commands(), before); got != "" {
				t.Fatalf("the refused Prepare touched the memdev:\n%s", got)
			}
			if p := e.preparation("u1"); p == nil || p.State != state.PreparationKept {
				t.Fatalf("preparation %+v", p)
			}
			if d := e.localDevice(localSerial); d == nil || d.Region != "region0" {
				t.Fatalf("view %+v", d)
			} else if _, ok := d.Claims["u1"]; !ok {
				t.Fatalf("the region is not kept for u1: %+v", d)
			}
			e.mustPrepare(localClaim("u1", localBlockSize))
			wantLocalRegionCount(t, e, 1, 0)
			e.mustUnprepare("u1")
			e.wantClean()
		})
	}
}

// A companion claim of mode numa whose Prepare a process stop cut after its
// memory went online is kept at the start; its Prepare again refused by the
// lease broker revokes and releases nothing, and the next Prepare reuses its
// part.
func TestPrepareKeptCompanionRefused(t *testing.T) {
	e, _, _ := newLocalLendEnv(t)
	e.k.CutAfter("write devices/system/memory/memory74/state online_movable")
	cutLocalPrepare(t, e, localCompanion("u1", localBlockSize))
	e.restart()
	lender, hooks := newFakeLender(), &fakeHooks{}
	e.s.Lender().Set(lender, hooks)
	if p := e.preparation("u1"); p == nil || p.State != state.PreparationPreparing {
		t.Fatalf("preparation after the start %+v", p)
	}
	g := e.grant("u1", 0)
	if g == nil || g.Got.Dax == "" {
		t.Fatalf("grant after the start %+v", g)
	}
	kept := *g
	hooks.lendingErr = errors.New("claim demo/cxl-lease-l1: not the companion of lease l1")
	before := e.commands()
	wantErr(t, e.prepare(localCompanion("u1", localBlockSize)), "not the companion of lease l1")
	if got := strings.TrimPrefix(e.commands(), before); got != "" {
		t.Fatalf("the refused Prepare touched the memdev:\n%s", got)
	}
	if calls := lender.callLog(); calls != "" {
		t.Fatalf("the refused Prepare called the lender: %s", calls)
	}
	if p := e.preparation("u1"); p == nil || p.State != state.PreparationPreparing {
		t.Fatalf("preparation after the refusal %+v", p)
	}
	if g := e.grant("u1", 0); g == nil || g.State != kept.State || g.Got.Dax != kept.Got.Dax {
		t.Fatalf("grant after the refusal %+v, was %+v", g, kept)
	}
	hooks.lendingErr = nil
	before = e.commands()
	e.mustPrepare(localCompanion("u1", localBlockSize))
	if got := strings.TrimPrefix(e.commands(), before); strings.Contains(got, "create-region") || strings.Contains(got, "/size") {
		t.Fatalf("the Prepare again made its part anew:\n%s", got)
	}
	e.mustUnprepare("u1")
	e.wantClean()
}
