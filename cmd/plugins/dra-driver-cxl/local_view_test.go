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
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// jsonDiffs returns where the JSON values got and want differ, a line
// per value: its path, the value got and the one wanted.
func jsonDiffs(path string, got, want any) []string {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			break
		}
		var out []string
		keys := map[string]bool{}
		for k := range w {
			keys[k] = true
		}
		for k := range g {
			keys[k] = true
		}
		for _, k := range slices.Sorted(func(yield func(string) bool) {
			for k := range keys {
				if !yield(k) {
					return
				}
			}
		}) {
			out = append(out, jsonDiffs(path+"."+k, g[k], w[k])...)
		}
		return out
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			break
		}
		var out []string
		for i := range w {
			out = append(out, jsonDiffs(fmt.Sprintf("%s[%d]", path, i), g[i], w[i])...)
		}
		return out
	}
	gj, _ := json.Marshal(got)
	wj, _ := json.Marshal(want)
	if string(gj) == string(wj) {
		return nil
	}
	return []string{fmt.Sprintf("%s: %s, the old file had %s", path, gj, wj)}
}

// generic returns v as the generic value of its JSON.
func generic(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	noErr(t, err)
	var out any
	noErr(t, json.Unmarshal(data, &out))
	return out
}

// strictView returns the view name of the store of the env decoded
// strictly into v.
func strictView(e *localTestEnv, name string, v any) {
	e.t.Helper()
	data, err := e.view(name)
	noErr(e.t, err)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	noErr(e.t, dec.Decode(v))
}

// localViewOracle computes what the local allocator wrote of the memdevs
// and the claims of a node from the kernel (the fake) and the claims.
type localViewOracle struct {
	e *localTestEnv
	k *kernel.Kernel
}

// region returns the only region of the memdev with the serial.
func (o *localViewOracle) region(serial uint64) string {
	o.e.t.Helper()
	rs := o.e.regions(serial)
	if len(rs) != 1 {
		o.e.t.Fatalf("memdev 0x%x has regions %v", serial, rs)
	}
	return rs[0]
}

// node returns the NUMA node of the memory of a region.
func (o *localViewOracle) node(region string) int {
	o.e.t.Helper()
	ri, err := o.k.Region(region)
	noErr(o.e.t, err)
	return ri.NumaNode
}

// firstDax returns the first dax device of a region, daxN.0.
func firstDax(region string) string {
	return "dax" + strings.TrimPrefix(region, "region") + ".0"
}

// dax returns the dax device of a region bound to the driver with the
// size.
func (o *localViewOracle) dax(region, driver string, size uint64) kernel.DaxDeviceInfo {
	o.e.t.Helper()
	for _, name := range o.k.DaxDevices(region) {
		if d, err := o.k.DaxDevice(name); err == nil && d.Driver == driver && d.Size == size {
			return d
		}
	}
	o.e.t.Fatalf("%s has no dax device of %s of %d bytes: %v", region, driver, size, o.k.DaxDevices(region))
	return kernel.DaxDeviceInfo{}
}

// daxInfo returns the dax device of the name.
func (o *localViewOracle) daxInfo(name string) kernel.DaxDeviceInfo {
	o.e.t.Helper()
	d, err := o.k.DaxDevice(name)
	noErr(o.e.t, err)
	return d
}

// namespace returns the nd region and the fsdax namespace of a pmem
// region.
func (o *localViewOracle) namespace(region string) (string, *kernel.Namespace) {
	o.e.t.Helper()
	nd, err := o.k.NdRegionOf(region)
	noErr(o.e.t, err)
	nss, err := o.k.Namespaces(context.Background(), nd)
	noErr(o.e.t, err)
	ns := kernel.FsdaxNamespace(nss)
	if ns == nil {
		o.e.t.Fatalf("%s has no fsdax namespace", region)
	}
	return nd, ns
}

// device returns the record of a memdev as the allocator wrote it, of a
// region set up.
func (o *localViewOracle) device(serial uint64, region string) *localDevice {
	d := &localDevice{Serial: serial, SerialHex: fmt.Sprintf("%x", serial), Memdev: o.e.k.Memdev(serial), Region: region, Node: -1,
		Claims: map[string][]*localSlice{}}
	if region != "" && !o.k.IsPmemRegion(region) {
		d.Node, d.Dax = o.node(region), firstDax(region)
	}
	return d
}

// pmemDevice returns the record of a persistent memdev with its set-up
// region.
func (o *localViewOracle) pmemDevice(serial uint64) (*localDevice, *kernel.Namespace) {
	region := o.region(serial)
	d := o.device(serial, region)
	nd, ns := o.namespace(region)
	d.Persistent, d.NdRegion, d.Namespace, d.BlockDevice, d.BlockMajor, d.BlockMinor = true, nd, ns.Name, ns.BlockDevice, ns.Major, ns.Minor
	return d, ns
}

// slice returns the use of a slice of a region by a result.
func (o *localViewOracle) slice(request, region, mode string, readOnly bool, d kernel.DaxDeviceInfo) *localSlice {
	s := &localSlice{Request: request, Region: region, Mode: mode, Size: d.Size, Dax: d.Name, ReadOnly: readOnly}
	if mode == api.ModeDax {
		s.DaxDevice, s.Major, s.Minor = filepath.Join(o.e.k.DevRoot(), d.Name), d.Major, d.Minor
	}
	return s
}

// info returns the prepared device of an allocation result n of a claim
// on a local memdev as the Prepare of the allocator described it, of the
// use s of the memdev with the serial.
func (o *localViewOracle) info(claim *resourcev1.ResourceClaim, n int, serial uint64, s *localSlice) PreparedDeviceInfo {
	o.e.t.Helper()
	r := claim.Status.Allocation.Devices.Results[n]
	res, err := config.Resolve(claim, device.DriverName, r.Request)
	noErr(o.e.t, err)
	d := PreparedDeviceInfo{RequestName: r.Request, DeviceName: r.Device, Result: n, DeviceType: device.DeviceTypeMemdev, Mode: s.Mode,
		SysfsPath: o.e.k.P("bus/cxl/devices/" + s.Region), NodeAffinities: []int{0}, TotalBytes: s.Size, ConsumedBytes: int64(s.Size),
		Serial: api.FormatSerial(serial), ResultSettings: res.Settings()}
	switch s.Mode {
	case api.ModeNUMA:
		d.NUMANodes = []int{o.node(s.Region)}
	case api.ModeDax:
		d.DaxDevice, d.DaxMajor, d.DaxMinor, d.ReadOnly = s.DaxDevice, s.Major, s.Minor, s.ReadOnly
	}
	return d
}

// pmemInfo returns the prepared device of an allocation result n of a
// claim on the persistent memdev dev with the use s.
func (o *localViewOracle) pmemInfo(claim *resourcev1.ResourceClaim, n int, dev *localDevice, s *localSlice) PreparedDeviceInfo {
	d := o.info(claim, n, dev.Serial, s)
	d.Shared, d.Persistent, d.ReadOnly = dev.Shared, true, s.ReadOnly
	d.Namespace, d.BlockDevice, d.BlockMajor, d.BlockMinor = dev.Namespace, dev.BlockDevice, dev.BlockMajor, dev.BlockMinor
	d.Access, d.Path, d.NodeMount, d.LoopDevice, d.FsType = s.Access, s.Path, s.NodeMount, s.LoopDevice, s.FsType
	return d
}

// localDevices.json and preparedClaimsInfo.json of the engine's records
// have the shape and the values of the files of the local allocator.
func TestLocalViewOfEngineRecords(t *testing.T) {
	const (
		sharedSerial = 0xc100e2e5
		idleSerial   = 0xc100e2e6
		keptSerial   = 0xc100e2e7
		cutSerial    = 0xc100e2e9
		blockSerial  = 0xc1af0001
		fsSerial     = 0xc1af0002
		aboveSerial  = 0xc100e2e8
	)
	// four regions under each host bridge: of the sliced, the shared, the
	// kept memdev and the one above it under 12; of the persistent ones,
	// the idle shared one and the cut one under 24
	e := newLocalTestEnv(t,
		fake.MemdevSpec{Serial: sharedSerial},
		fake.MemdevSpec{Serial: idleSerial, HostBridge: 24},
		fake.MemdevSpec{Serial: keptSerial},
		fake.MemdevSpec{Serial: cutSerial, HostBridge: 24},
		fakeMemdevSpecPmem(blockSerial), fakeMemdevSpecPmem(fsSerial))
	above := e.k.Plug(fake.MemdevSpec{Serial: aboveSerial})
	e.formatPmem(fsSerial, "erofs")
	e.config.SharedDevices = []string{api.FormatSerial(sharedSerial), api.FormatSerial(idleSerial)}
	e.shared[sharedSerial], e.shared[idleSerial] = true, true
	e.config.FsTypes = slices.Clone(config.KnownFsTypes)
	e.start()
	e.s.Lender().Set(newFakeLender(), &fakeHooks{})
	steering := `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"first-dram","maxStep":"1Gi"}}}`
	two := localClaim("b1", 256*mib)
	pmemResult := memdevClaim("b1", memdevDeviceName(fsSerial), -1).Status.Allocation.Devices.Results[0]
	pmemResult.Request = "pmem"
	two.Status.Allocation.Devices.Results = append(two.Status.Allocation.Devices.Results, pmemResult)
	blockRO := makeOpaqueConfig(device.DriverName, resourcev1.AllocationConfigSourceClaim, json.RawMessage(memoryConfig(api.ModeBlock, true, "")))
	blockRO.Requests = []string{"pmem"}
	two.Status.Allocation.Devices.Config = append(two.Status.Allocation.Devices.Config, blockRO)
	claims := map[string]*resourcev1.ResourceClaim{
		"n1":   localClaim("n1", 128*mib, steering),
		"d1":   localClaim("d1", 128*mib, localROConfig),
		"comp": localCompanion("comp", 384*mib),
		"b1":   two,
		"s1":   memdevClaim("s1", memdevDeviceName(sharedSerial), -1, localDaxConfig),
		"s2":   memdevClaim("s2", memdevDeviceName(sharedSerial), -1, localROConfig),
		"w1":   memdevClaim("w1", memdevDeviceName(blockSerial), -int64(device.SharesUnlimited), memoryConfig(api.ModeBlock, false, "")),
		"f1":   memdevClaim("f1", memdevDeviceName(fsSerial), -1, memoryConfig(api.ModeFs, true, "")),
	}
	order := []string{"n1", "d1", "comp", "b1", "s1", "s2", "w1", "f1"}
	for _, uid := range order {
		e.mustPrepare(claims[uid])
	}
	// an idle shared device keeps its region
	e.mustPrepare(memdevClaim("i1", memdevDeviceName(idleSerial), -1, localDaxConfig))
	e.mustUnprepare("i1")
	// a rollback below a region of another memdev keeps its region for the
	// claim
	k := e.k.Kernel()
	e.k.After("cxl create-region", func() {
		e.k.After("cxl create-region", func() {})
		d, err := k.RootDecoder(above, kernel.RegionRAM)
		noErr(t, err)
		_, err = k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: above, Decoder: d, Type: kernel.RegionRAM})
		noErr(t, err)
		e.k.FailWrite("bus/dax/devices/"+firstDax(e.regions(keptSerial)[0])+"/size", syscall.EBUSY)
	})
	if err := e.prepare(memdevClaim("k1", memdevDeviceName(keptSerial), 256*mib, localDaxConfig)); err == nil {
		t.Fatal("the Prepare of k1 succeeded")
	}
	if p := e.preparation("k1"); p == nil || p.State != "KEPT" {
		t.Fatalf("preparation of k1 %+v", p)
	}
	// a creation of the region cut by a process stop
	e.k.CutAfter("cxl create-region")
	if !e.cut(func() {
		_ = prepareOn(context.Background(), e.s, memdevClaim("c1", memdevDeviceName(cutSerial), 128*mib))
	}) {
		t.Fatal("the Prepare of c1 was not cut")
	}

	o := &localViewOracle{e: e, k: k}
	// the sliced memdev
	sliced := o.device(localSerial, o.region(localSerial))
	r := sliced.Region
	numa := func(size uint64) *localSlice {
		return o.slice("mem", r, api.ModeNUMA, false, o.dax(r, "kmem", size))
	}
	sliced.Claims = map[string][]*localSlice{
		"n1":   {numa(128 * mib)},
		"d1":   {o.slice("mem", r, api.ModeDax, true, o.dax(r, "device_dax", 128*mib))},
		"comp": {numa(384 * mib)},
		"b1":   {numa(256 * mib)},
	}
	// the shared memdevs
	shared := o.device(sharedSerial, o.region(sharedSerial))
	shared.Shared = true
	whole := o.daxInfo(shared.Dax)
	shared.Claims = map[string][]*localSlice{
		"s1": {o.slice("mem", shared.Region, api.ModeDax, false, whole)},
		"s2": {o.slice("mem", shared.Region, api.ModeDax, true, whole)},
	}
	idle := o.device(idleSerial, o.region(idleSerial))
	idle.Shared = true
	// the kept region, which is not set up, and the region being created
	kept := o.device(keptSerial, o.region(keptSerial))
	kept.Dax = ""
	kept.Claims = map[string][]*localSlice{"k1": nil}
	cut := o.device(cutSerial, "")
	cut.Creating = o.region(cutSerial)
	cut.Claims = map[string][]*localSlice{"c1": nil}
	// the persistent memdevs
	block, blockNs := o.pmemDevice(blockSerial)
	block.Claims = map[string][]*localSlice{
		"w1": {{Request: "mem", Region: block.Region, Mode: api.ModeBlock, Size: blockNs.Size}},
	}
	fs, fsNs := o.pmemDevice(fsSerial)
	fsKey := strings.ToUpper(fs.SerialHex)
	fs.Claims = map[string][]*localSlice{
		"f1": {{Request: "mem", Region: fs.Region, Mode: api.ModeFs, Size: fsNs.Size, ReadOnly: true, Access: api.AccessDirect, FsType: "erofs",
			NodeMount: filepath.Join(e.dir, mountsDirName, fs.SerialHex+"-direct"), Path: "/run/cxl-fs/" + fsKey}},
		"b1": {{Request: "pmem", Result: 1, Region: fs.Region, Mode: api.ModeBlock, Size: fsNs.Size, ReadOnly: true}},
	}
	want := &localState{BootID: e.k.BootID(), Devices: []*localDevice{sliced, shared, idle, kept, cut, block, fs}}
	slices.SortFunc(want.Devices, func(a, b *localDevice) int { return cmp.Compare(a.Serial, b.Serial) })

	got := &localState{}
	strictView(e, localStateFileName, got)
	diffs := jsonDiffs("localDevices.json", generic(t, got), generic(t, want))

	// the prepared claims as the Prepare of the allocator described them
	node := o.node(r)
	wantInfo := PreparedClaimsInfo{}
	for _, uid := range order {
		wantInfo[uid] = &PreparedClaimInfo{ClaimName: "demo/claim-" + uid, BootID: e.k.BootID()}
	}
	wantInfo["comp"].ClaimName = "demo/cxl-lease-l1"
	wantInfo["comp"].Lend = &lendRecord{Lease: "l1", Pod: podRef{Namespace: testNS, Name: testPod, UID: testPodUID}, Container: testCtr, NumaNodes: []int{node}}
	for _, uid := range []string{"n1", "d1", "comp", "b1"} {
		wantInfo[uid].Devices = append(wantInfo[uid].Devices, o.info(claims[uid], 0, localSerial, sliced.Claims[uid][0]))
	}
	for _, uid := range []string{"s1", "s2"} {
		d := o.info(claims[uid], 0, sharedSerial, shared.Claims[uid][0])
		d.Shared = true
		wantInfo[uid].Devices = []PreparedDeviceInfo{d}
	}
	wantInfo["w1"].Devices = []PreparedDeviceInfo{o.pmemInfo(claims["w1"], 0, block, block.Claims["w1"][0])}
	wantInfo["f1"].Devices = []PreparedDeviceInfo{o.pmemInfo(claims["f1"], 0, fs, fs.Claims["f1"][0])}
	wantInfo["b1"].Devices = append(wantInfo["b1"].Devices, o.pmemInfo(claims["b1"], 1, fs, fs.Claims["b1"][0]))
	gotInfo := PreparedClaimsInfo{}
	strictView(e, preparedClaimsInfoFileName, &gotInfo)
	diffs = append(diffs, jsonDiffs("preparedClaimsInfo.json", generic(t, gotInfo), generic(t, wantInfo))...)
	// the first dax device of the sliced memdev, which its first slice
	// resized, is not in the view
	firstSlice := fmt.Sprintf("localDevices.json.devices[%d].dax: ", slices.Index(want.Devices, sliced))
	var known []string
	for _, d := range diffs {
		if strings.HasPrefix(d, firstSlice) {
			known = append(known, d)
			continue
		}
		t.Errorf("the view differs from the old file: %s", d)
	}
	if len(known) > 0 {
		t.Errorf("localDevices.json has no dax of a sliced memdev whose first dax device a slice uses: %q", known)
	}

	// the cut claim is released at the start, the others are unprepared
	e.restart()
	e.s.Lender().Set(newFakeLender(), &fakeHooks{})
	for _, uid := range append(order, "k1", "c1") {
		e.mustUnprepare(uid)
	}
	noErr(t, k.ReleaseRegion(context.Background(), e.k.Kernel().Regions(above)[0]))
	e.config.SharedDevices = nil
	e.shared = map[uint64]bool{}
	e.restart()
	e.wantClean()
}
