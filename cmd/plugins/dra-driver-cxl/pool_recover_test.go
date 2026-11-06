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
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
)

// A Prepare that a process stop cut after its region was made: the start
// releases what it made, the claim stays PREPARING with its results (its
// record lists the device), kubelet's Prepare again prepares it anew.
func TestPoolCutPrepareAtStart(t *testing.T) {
	e := newPoolTestEnv(t)
	memdev := e.plug(0xc1ee0001)
	p := e.driver(t)
	e.k.CutAfter("cxl create-region")
	cutPrepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData))
	logs := captureKlog(t)
	p = e.driver(t)
	out := logs()
	for _, want := range []string{
		"claim default/c1 (u1), whose Prepare did not finish: releasing devices 0xc1ee0001",
		"claim default/c1 (u1): released, its Prepare again prepares its devices anew",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if prep := e.preparation("u1"); prep == nil || prep.State != state.PreparationPreparing {
		t.Fatalf("preparation %+v", prep)
	}
	if rec := e.preparingFile(t)["u1"]; rec == nil || rec.ClaimName != "default/c1" || len(rec.Devices) != 1 || rec.Stale != "" {
		t.Fatalf("record of the claim %+v", rec)
	}
	if rs := e.k.Kernel().Regions(memdev); len(rs) != 0 {
		t.Fatalf("regions %v left at the start", rs)
	}
	noErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err)
	if prep := e.preparation("u1"); prep.State != state.PreparationPrepared || e.preparingFile(t)["u1"] != nil {
		t.Fatalf("preparation %+v", prep)
	}
	noErr(t, unprepare(t, p, "u1"))
	e.wantClean(t, p)
}

// A cut Prepare whose region lies below a newer region of another memdev
// is kept at the start: the claim is KEPT, its record stays in
// preparingPoolClaims.json, its Unprepare releases it.
func TestPoolKeptRecord(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ee0001)
	other := e.plug(0xc1ee0002)
	p := e.driver(t)
	e.k.CutAfter("cxl create-region")
	cutPrepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData))
	k := e.k.Kernel()
	d, err := k.RootDecoder(other, kernel.RegionRAM)
	noErr(t, err)
	above, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: other, Decoder: d, Type: kernel.RegionRAM})
	noErr(t, err)
	e.base = e.k.Commands()
	logs := captureKlog(t)
	p = e.driver(t)
	if want := "claim default/c1 (u1): not releasing its devices at start: " + above + " lie above their regions"; !strings.Contains(logs(), want) {
		t.Fatalf("no %q in\n%s", want, logs())
	}
	if prep := e.preparation("u1"); prep == nil || prep.State != state.PreparationKept {
		t.Fatalf("preparation %+v", prep)
	}
	rec := e.preparingFile(t)["u1"]
	if rec == nil || rec.ClaimName != "default/c1" || len(rec.Devices) != 1 || rec.Devices[0].Serial != 0xc1ee0001 || rec.Stale != "" ||
		len(rec.Regions) != 1 || rec.Regions[0].Region != "region0" {
		t.Fatalf("record of the kept claim %+v", rec)
	}
	if !p.Serials()[0xc1ee0001] {
		t.Fatalf("serials %v", p.Serials())
	}
	noErr(t, unprepare(t, p, "u1"))
	noErr(t, k.ReleaseRegion(context.Background(), above))
	e.wantClean(t, p)
}

// The companion claim of a numa lease cut in its Prepare (before its lend)
// is kept at the start for its Unprepare, which releases it
// (TestPoolCompanionRevoke has the revoke of a cut after the lend).
func TestPoolCutCompanionKept(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ee0001)
	p := e.driver(t)
	hooks := &fakeHooks{}
	lender := newFakeLender(testRef)
	p.Lender().Set(lender, hooks)
	claim := poolClaim("uid-cxl-lease-l1", "cxl-lease-l1", "pooled0", exclusiveData)
	claim.Namespace = testNS
	claim.Labels = map[string]string{device.LeaseLabel: "l1"}
	e.k.CutAfter("write devices/system/memory/memory")
	cutPrepare(t, p, claim)
	logs := captureKlog(t)
	p = e.driver(t)
	if want := "claim demo/cxl-lease-l1 (uid-cxl-lease-l1) is a companion claim: its Unprepare releases its devices, its Prepare again reuses them"; !strings.Contains(logs(), want) {
		t.Fatalf("no %q in\n%s", want, logs())
	}
	if prep := e.preparation("uid-cxl-lease-l1"); prep == nil || prep.State != state.PreparationPreparing {
		t.Fatalf("preparation %+v", prep)
	}
	p.Lender().Set(lender, hooks)
	p.Engine().RecoverCompanions()
	noErr(t, unprepare(t, p, "uid-cxl-lease-l1"))
	e.wantClean(t, p)
}

// A claim prepared in another boot is not prepared: no CDI device, no
// results; its record says why; its Prepare again prepares its device
// anew, its Unprepare releases the device by its serial.
func TestPoolOtherBoot(t *testing.T) {
	e := newPoolTestEnv(t)
	memdev := e.plug(0xc1ee0001)
	p := e.driver(t)
	noErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err)
	noErr(t, prepare(t, p, poolClaim("u2", "c2", "pooled0", exclusiveData)).Err)
	e.k.Reboot()
	p = e.driver(t)
	for _, uid := range []string{"u1", "u2"} {
		prep := e.preparation(uid)
		if prep == nil || prep.State != state.PreparationStale || p.ClaimResults(uid) != nil {
			t.Fatalf("claim %s: %+v", uid, prep)
		}
		if rec := e.preparingFile(t)[uid]; rec == nil || !strings.HasPrefix(rec.Stale, "prepared in another boot") {
			t.Fatalf("record of %s: %+v", uid, rec)
		}
	}
	if e.cdiSpec(t) != nil {
		t.Fatalf("CDI spec of the claims of another boot %+v", e.cdiSpec(t))
	}
	// the Prepare again of u1 prepares its device anew
	noErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err)
	if prep := e.preparation("u1"); prep.State != state.PreparationPrepared || cdiDeviceByName(e.cdiSpec(t), "claim-u1-0") == nil {
		t.Fatalf("preparation %+v", prep)
	}
	noErr(t, unprepare(t, p, "u1"))
	// the Unprepare of u2 disables its memdev, which no grant of this
	// boot uses
	logs := captureKlog(t)
	noErr(t, unprepare(t, p, "u2"))
	if want := "unpreparing claim default/c2 (u2), not prepared any more (prepared in another boot"; !strings.Contains(logs(), want) {
		t.Fatalf("no %q in\n%s", want, logs())
	}
	e.wantCommand(t, "cxl disable-memdev "+memdev)
	e.wantClean(t, p)
}

// The view preparedPoolClaims.json of the engine's records has the format
// and the values of the file that the pool driver wrote before the engine
// (the struct preparedPoolClaim, decoded strictly), computed from the
// kernel's objects and the claims: a numa, a shared dax device with a share
// id, a cached fs reader, a block reader, a block writer, the companions of
// a numa and of an fs lease.
func TestPoolViewOfEngineRecords(t *testing.T) {
	e := newPoolTestEnv(t)
	e.leaseFsRoot = filepath.Join(e.dir, "lease-fs")
	numaMem := e.plug(0xc1ee0001)
	daxMem := e.plug(0xc1ae0002)
	// under the other host bridge: the decoders of one have room for four
	compMem := e.k.Plug(fake.MemdevSpec{Serial: 0xc1ee0003, HostBridge: 24})
	pmemMem, pmem := e.plugPersistent(0xc1ae0001, "erofs")
	blockMem := e.k.Plug(fake.MemdevSpec{Serial: 0xc1af0001, Pmem: 512 << 20, HostBridge: 24})
	p := e.driver(t)
	hooks := &fakeHooks{fsDir: filepath.Join(e.leaseFsRoot, "lc1"), name: "models"}
	noErr(t, os.MkdirAll(hooks.fsDir, 0o755))
	p.Lender().Set(newFakeLender(testRef), hooks)
	shareID := types.UID("share-1")
	claims := map[string]*resourceapi.ResourceClaim{
		"n1": poolClaim("n1", "c-n1", "pooled0", exclusiveData),
		"s1": poolClaim("s1", "c-s1", "shared1", `{"serial":"0xc1ae0002","shared":true,"size":268435456}`),
		"f1": persistentClaim("f1", persistentData, fsConfig("cached", "/models")),
		"r1": persistentClaim("r1", persistentData, blockROConfig),
		"w1": withConfig(poolClaim("w1", "c-w1", "llm1", `{"serial":"0xc1af0001","shared":true,"size":536870912,"persistent":true,"exclusive":true}`),
			resourceapi.AllocationConfigSourceClaim, nil, blockConfig),
		"uid-cxl-lease-n2": numaCompanion("n2"),
		"uid-cxl-lease-l1": fsCompanion("l1", "direct"),
	}
	claims["s1"].Status.Allocation.Devices.Results[0].ShareID = &shareID
	claims["uid-cxl-lease-n2"].Status.Allocation.Devices.Results[0].Device = "pooled3"
	claims["uid-cxl-lease-n2"].Status.Devices[1] = poolClaim("x", "x", "pooled3", `{"serial":"0xc1ee0003","shared":false,"size":268435456}`).Status.Devices[1]
	order := []string{"n1", "s1", "f1", "r1", "w1", "uid-cxl-lease-n2", "uid-cxl-lease-l1"}
	for _, uid := range order {
		noErr(t, prepare(t, p, claims[uid]).Err)
	}

	data, err := os.ReadFile(e.stateFile)
	noErr(t, err)
	var marked map[string]map[string]any
	noErr(t, json.Unmarshal(data, &marked))
	for uid, v := range marked {
		if v["viewOf"] != store.FileName {
			t.Fatalf("%s: no marker", uid)
		}
		delete(v, "viewOf")
	}
	got := map[string]*preparedPoolClaim{}
	dec := json.NewDecoder(bytes.NewReader(mustJSON(t, marked)))
	dec.DisallowUnknownFields()
	noErr(t, dec.Decode(&got))

	k := e.k.Kernel()
	region := func(memdev string) string {
		rs := k.Regions(memdev)
		if len(rs) != 1 {
			t.Fatalf("%s has regions %v", memdev, rs)
		}
		return rs[0]
	}
	daxOf := func(memdev string) string { return "dax" + strings.TrimPrefix(region(memdev), "region") + ".0" }
	major, minor, err := k.DaxDevNumbers(daxOf(daxMem))
	noErr(t, err)
	blockOf := func(memdev string) (string, int, int, string) {
		nd, err := k.NdRegionOf(region(memdev))
		noErr(t, err)
		nss, err := k.Namespaces(context.Background(), nd)
		noErr(t, err)
		ns := kernel.FsdaxNamespace(nss)
		if ns == nil {
			t.Fatalf("%s has no fsdax namespace", memdev)
		}
		return ns.BlockDevice, ns.Major, ns.Minor, ns.Name
	}
	pmemDev, pmemMajor, pmemMinor, pmemNs := blockOf(pmemMem)
	if pmemDev != pmem {
		t.Fatalf("block device %s, plugged %s", pmemDev, pmem)
	}
	blockDev, blockMajor, blockMinor, blockNs := blockOf(blockMem)
	cached, direct := e.nodeMount(0xc1ae0001, "cached"), e.nodeMount(0xc1ae0001, "direct")
	loop := e.mounted(cached).Source
	boot := e.k.BootID()
	// the settings of the result 0 of a claim, resolved from its configs
	settings := func(uid string) config.ResultSettings {
		res, err := config.Resolve(claims[uid], device.PoolDriverName, claims[uid].Status.Allocation.Devices.Results[0].Request)
		noErr(t, err)
		return res.Settings()
	}
	result := func(uid, dev string, cdi bool, share *types.UID) kubeletplugin.PrepareResult {
		d := kubeletplugin.Device{Requests: []string{"mem"}, PoolName: "fake-cxl-pool", DeviceName: dev, ShareID: share}
		if cdi {
			d.CDIDeviceIDs = []string{poolCDIDeviceID(uid, 0)}
		}
		return kubeletplugin.PrepareResult{Devices: []kubeletplugin.Device{d}}
	}
	llm0 := func(uid, mode string, readOnly bool) preparedPoolDevice {
		return preparedPoolDevice{Request: "mem", Device: "llm0", Pool: "fake-cxl-pool", Serial: 0xc1ae0001, Shared: true, Size: fakePmemBytes,
			Mode: mode, ReadOnly: readOnly, Memdev: pmemMem, Region: region(pmemMem), Node: -1, Persistent: true, NdRegion: region(pmemMem),
			Namespace: pmemNs, BlockDevice: pmemDev, BlockMajor: pmemMajor, BlockMinor: pmemMinor, ResultSettings: settings(uid)}
	}
	fsDev := func(uid, access, path, mnt, loop string) preparedPoolDevice {
		d := llm0(uid, "fs", true)
		d.Access, d.FsType, d.Path, d.NodeMount, d.LoopDevice = access, "erofs", path, mnt, loop
		return d
	}
	pod := podRef{Namespace: testNS, Name: testPod, UID: testPodUID}
	compNode := k.TargetNode(daxOf(compMem))
	want := map[string]*preparedPoolClaim{
		"n1": {ClaimName: "default/c-n1", BootID: boot, Result: result("n1", "pooled0", true, nil), Devices: []preparedPoolDevice{{
			Request: "mem", Device: "pooled0", Pool: "fake-cxl-pool", Serial: 0xc1ee0001, Size: 268435456, Mode: "numa", Memdev: numaMem,
			Region: region(numaMem), Dax: daxOf(numaMem), Node: k.TargetNode(daxOf(numaMem)), ResultSettings: settings("n1")}}},
		"s1": {ClaimName: "default/c-s1", BootID: boot, Result: result("s1", "shared1", true, &shareID), Devices: []preparedPoolDevice{{
			Request: "mem", Device: "shared1", Pool: "fake-cxl-pool", Serial: 0xc1ae0002, Shared: true, Size: 268435456, Mode: "dax",
			Memdev: daxMem, Region: region(daxMem), Dax: daxOf(daxMem), DaxDevice: "/dev/" + daxOf(daxMem), DaxMajor: major, DaxMinor: minor,
			Node: -1, ResultSettings: settings("s1")}}},
		"f1": {ClaimName: "default/c-f1", BootID: boot, Result: result("f1", "llm0", true, nil),
			Devices: []preparedPoolDevice{fsDev("f1", "cached", "/models", cached, loop)}},
		"r1": {ClaimName: "default/c-r1", BootID: boot, Result: result("r1", "llm0", true, nil),
			Devices: []preparedPoolDevice{llm0("r1", "block", true)}},
		"w1": {ClaimName: "default/c-w1", BootID: boot, Result: result("w1", "llm1", true, nil), Devices: []preparedPoolDevice{{
			Request: "mem", Device: "llm1", Pool: "fake-cxl-pool", Serial: 0xc1af0001, Shared: true, Size: fakePmemBytes, Mode: "block",
			Memdev: blockMem, Region: region(blockMem), Node: -1, Persistent: true, NdRegion: region(blockMem), Namespace: blockNs,
			BlockDevice: blockDev, BlockMajor: blockMajor, BlockMinor: blockMinor, ResultSettings: settings("w1")}}},
		"uid-cxl-lease-n2": {ClaimName: "demo/cxl-lease-n2", BootID: boot, Result: result("uid-cxl-lease-n2", "pooled3", false, nil),
			Devices: []preparedPoolDevice{{Request: "mem", Device: "pooled3", Pool: "fake-cxl-pool", Serial: 0xc1ee0003, Size: 268435456,
				Mode: "numa", Memdev: compMem, Region: region(compMem), Dax: daxOf(compMem), Node: compNode, ResultSettings: settings("uid-cxl-lease-n2")}},
			// the lend as the broker gave it (OnLending), with the node lent
			Lend: &lendRecord{Lease: "n2", Pod: pod, Container: testCtr, Nodes: []int{compNode}, FsDir: hooks.fsDir, Name: "models"}},
		"uid-cxl-lease-l1": {ClaimName: "demo/cxl-lease-l1", BootID: boot, Result: result("uid-cxl-lease-l1", "llm0", false, nil),
			Devices: []preparedPoolDevice{fsDev("uid-cxl-lease-l1", "direct", "/run/cxl-fs/C1AE0001", direct, "")},
			Lend: &lendRecord{Lease: "l1", Pod: pod, Container: testCtr, FsDir: hooks.fsDir, Name: "models",
				Mounts: []string{filepath.Join(hooks.fsDir, "models")}}},
	}
	jsonEqual(t, "preparedPoolClaims.json", mustJSON(t, got), mustJSON(t, want))
	for _, uid := range order {
		noErr(t, unprepare(t, p, uid))
	}
	e.wantClean(t, p)
}

// The record of a KEPT claim in preparingPoolClaims.json has the shape of
// the old kept record: the devices as recorded before they were touched
// (the NUMA node of a device in mode numa: that of its region), the
// regions noted with their root decoder.
func TestPoolKeptRecordShape(t *testing.T) {
	e := newPoolTestEnv(t)
	p, above := keptClaim(t, e)
	reg := e.records().Region("region0")
	want := &preparingPoolClaim{ClaimName: "default/c1", BootID: e.k.BootID(),
		Devices: []preparedPoolDevice{{Request: "mem", Device: "pooled0", Pool: "fake-cxl-pool", Serial: 0xc1ee0001, Size: 268435456,
			Mode: "numa", Node: state.NumaNodeOf(reg.NumaNode)}},
		Regions: []preparingRegion{{Serial: 0xc1ee0001, Region: "region0", Decoder: "decoder0.0"}}}
	if state.NumaNodeOf(reg.NumaNode) < 0 {
		t.Fatalf("region %+v", reg)
	}
	jsonEqual(t, "kept record", mustJSON(t, e.preparingFile(t)["u1"]), mustJSON(t, want))
	noErr(t, unprepare(t, p, "u1"))
	noErr(t, e.k.Kernel().ReleaseRegion(context.Background(), above))
	e.wantClean(t, p)
}
