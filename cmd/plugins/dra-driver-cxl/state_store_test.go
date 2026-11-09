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
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/leases"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

const (
	mi = uint64(1) << 20
	gi = uint64(1) << 30
)

// testViewOptions are the view options of the fixtures.
var testViewOptions = store.ViewOptions{PoolDriver: device.PoolDriverName, SysRoot: "/sys", DevRoot: "/dev"}

// jsonEqual fails the test when the JSON a and b differ in content.
func jsonEqual(t *testing.T, what string, got, want []byte) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("%s: %v in %s", what, err, got)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatalf("%s: %v in %s", what, err, want)
	}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("%s differs:\n got  %s\n want %s", what, compact(got), compact(want))
	}
}

// compact returns JSON on one line.
func compact(data []byte) string {
	var v any
	if json.Unmarshal(data, &v) != nil {
		return string(data)
	}
	out, _ := json.Marshal(v)
	return string(out)
}

// mustJSON returns v in JSON as the driver's file writer writes it.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// claimResult returns the PrepareResult of the info of a claim as the
// Prepare of cxl.nri.io makes it.
func claimResult(uid string, info *PreparedClaimInfo) kubeletplugin.PrepareResult {
	res := kubeletplugin.PrepareResult{}
	for _, d := range info.Devices {
		dev := kubeletplugin.Device{Requests: []string{d.RequestName}, PoolName: "node-1", DeviceName: d.DeviceName}
		if info.Lend == nil {
			dev.CDIDeviceIDs = []string{claimCDIDeviceID(uid, d.Result)}
			if d.DeviceType == device.DeviceTypeLease {
				dev.CDIDeviceIDs = append(dev.CDIDeviceIDs, leaseCDIDeviceID(uid))
			}
		}
		res.Devices = append(res.Devices, dev)
	}
	return res
}

// localFixture returns the content of the state files of cxl.nri.io: claims
// of every kind on a sliced, a shared and a persistent memdev, a dram, a
// region and a lease result, companions, a claim whose Prepare runs, a
// holder, a memdev whose region is created, uses of no claim and a gone dax
// device.
func localFixture() (claimPreparations, PreparedClaimsInfo, localState) {
	steer := config.ResultSettings{Container: &config.Container{Steering: &config.Steering{Policy: "auto"}}, Origins: map[string]string{"container.steering.policy": "claim"}}
	pod := podRef{Namespace: "demo", Name: "requester", UID: "p-1"}
	sliced := func(n int, mode string) PreparedDeviceInfo {
		d := PreparedDeviceInfo{
			RequestName: "mem", DeviceName: "memdev-c100e2e1", Result: n, DeviceType: device.DeviceTypeMemdev, Mode: mode,
			SysfsPath: "/sys/bus/cxl/devices/region0", NodeAffinities: []int{0}, TotalBytes: 128 * mi, ConsumedBytes: int64(128 * mi),
			Serial: "0xc100e2e1",
		}
		if mode == "numa" {
			d.NUMANodes = []int{2}
		}
		return d
	}
	daxDev := func(d PreparedDeviceInfo, dax string, minor int, ro bool) PreparedDeviceInfo {
		d.DaxDevice, d.DaxMajor, d.DaxMinor, d.ReadOnly = "/dev/"+dax, 252, minor, ro
		return d
	}
	shared := func(ro bool) PreparedDeviceInfo {
		return PreparedDeviceInfo{
			RequestName: "mem", DeviceName: "memdev-c100e2e2", DeviceType: device.DeviceTypeMemdev, Mode: "dax",
			SysfsPath: "/sys/bus/cxl/devices/region1", TotalBytes: 512 * mi, ConsumedBytes: int64(512 * mi), Serial: "0xc100e2e2",
			DaxDevice: "/dev/dax1.0", DaxMajor: 252, DaxMinor: 10, ReadOnly: ro, Shared: true,
		}
	}
	persistent := func(n int, mode, access, mount, loop string) PreparedDeviceInfo {
		d := PreparedDeviceInfo{
			RequestName: "pmem", DeviceName: "memdev-c1ae2001", Result: n, DeviceType: device.DeviceTypeMemdev, Mode: mode,
			SysfsPath: "/sys/bus/cxl/devices/region2", TotalBytes: gi, ConsumedBytes: int64(gi), Serial: "0xc1ae2001",
			ReadOnly: true, Persistent: true, Namespace: "namespace7.0", BlockDevice: "/dev/pmem7", BlockMajor: 259,
		}
		if mode == "fs" {
			d.Access, d.Path, d.NodeMount, d.LoopDevice, d.FsType = access, "/run/cxl-fs/C1AE2001", mount, loop, "erofs"
		}
		return d
	}
	direct := "/var/lib/kubelet/plugins/cxl.nri.io/mounts/c1ae2001-direct"
	cached := "/var/lib/kubelet/plugins/cxl.nri.io/mounts/c1ae2001-cached"
	fsDir := "/var/lib/kubelet/plugins/cxl.nri.io/lease-fs/u-lease"
	numa := sliced(0, "numa")
	numa.ResultSettings = steer
	gone := sliced(0, "dax")
	gone.ReadOnly = true
	infos := PreparedClaimsInfo{
		"u-numa": {ClaimName: "demo/c-numa", Devices: []PreparedDeviceInfo{numa}, BootID: "boot-1"},
		"u-dax":  {ClaimName: "demo/c-dax", Devices: []PreparedDeviceInfo{daxDev(sliced(0, "dax"), "dax0.2", 2, true)}, BootID: "boot-1"},
		"u-two": {ClaimName: "demo/c-two", BootID: "boot-1", Devices: []PreparedDeviceInfo{
			sliced(0, "numa"),
			{RequestName: "dram", DeviceName: "dram", Result: 1, DeviceType: device.DeviceTypeDRAM, Mode: "numa", NUMANodes: []int{0, 1}, TotalBytes: 64 * gi},
			daxDev(sliced(2, "dax"), "dax0.4", 4, false),
		}},
		"u-comp": {ClaimName: "demo/cxl-lease-0a1b2c3d", Devices: []PreparedDeviceInfo{sliced(0, "numa")}, BootID: "boot-1",
			Lend: &lendRecord{Lease: "0a1b2c3d", Pod: pod, Container: "main", NumaNodes: []int{2}}},
		"u-sh1": {ClaimName: "demo/c-sh1", Devices: []PreparedDeviceInfo{shared(false)}, BootID: "boot-1"},
		"u-sh2": {ClaimName: "demo/c-sh2", Devices: []PreparedDeviceInfo{shared(true)}, BootID: "boot-1"},
		"u-fs":  {ClaimName: "demo/c-fs", Devices: []PreparedDeviceInfo{persistent(0, "fs", "direct", direct, "")}, BootID: "boot-1"},
		"u-blk": {ClaimName: "demo/c-blk", BootID: "boot-1", Devices: []PreparedDeviceInfo{
			{RequestName: "region", DeviceName: "region5-node5", Result: 0, DeviceType: device.DeviceTypeRegion, Mode: "numa",
				SysfsPath: "/sys/bus/cxl/devices/region5", Region: "region5", NUMANodes: []int{5}, NodeAffinities: []int{1},
				TotalBytes: 2 * gi, ConsumedBytes: int64(gi)},
			persistent(1, "block", "", "", ""),
		}},
		"u-lease": {ClaimName: "demo/c-lease", BootID: "boot-1", Devices: []PreparedDeviceInfo{
			{RequestName: "lease", DeviceName: "lease", Result: 0, DeviceType: device.DeviceTypeLease},
		}},
		"u-fsc": {ClaimName: "demo/cxl-lease-1b2c3d4e", BootID: "boot-1", Devices: []PreparedDeviceInfo{persistent(0, "fs", "cached", cached, "/dev/loop0")},
			Lend: &lendRecord{Lease: "1b2c3d4e", Pod: pod, Container: "main", FsDir: fsDir, Name: "mbt", Mounts: []string{fsDir + "/mbt"}}},
		"u-gone": {ClaimName: "demo/c-gone", Devices: []PreparedDeviceInfo{gone}, BootID: "boot-1"},
	}
	prepared := claimPreparations{}
	for uid, info := range infos {
		prepared[uid] = claimResult(uid, info)
	}
	use := func(mode, dax string, minor int, ro bool) *localSlice {
		s := &localSlice{Request: "mem", Region: "region0", Mode: mode, Size: 128 * mi, Dax: dax, ReadOnly: ro}
		if mode == "dax" {
			s.DaxDevice, s.Major, s.Minor = "/dev/"+dax, 252, minor
		}
		return s
	}
	sharedUse := func(ro bool) *localSlice {
		return &localSlice{Request: "mem", Region: "region1", Mode: "dax", Size: 512 * mi, Dax: "dax1.0", DaxDevice: "/dev/dax1.0", Major: 252, Minor: 10, ReadOnly: ro}
	}
	pmemUse := func(n int, mode, access, mount, loop string) *localSlice {
		s := &localSlice{Request: "pmem", Result: n, Region: "region2", Mode: mode, Size: gi, ReadOnly: true}
		if mode == "fs" {
			s.Access, s.FsType, s.NodeMount, s.LoopDevice, s.Path = access, "erofs", mount, loop, "/run/cxl-fs/C1AE2001"
		}
		return s
	}
	local := localState{BootID: "boot-1", Devices: []*localDevice{
		{Serial: 0xc100e2e1, SerialHex: "c100e2e1", Memdev: "mem0", Region: "region0", Node: 2, Dax: "dax0.0", Claims: map[string][]*localSlice{
			"u-numa": {use("numa", "dax0.1", 0, true)},
			"u-dax":  {use("dax", "dax0.2", 2, true)},
			"u-two":  {use("numa", "dax0.3", 0, false), use("dax", "dax0.4", 4, false)},
			"u-comp": {use("numa", "dax0.7", 0, false)},
			"u-mid":  {use("numa", "dax0.5", 0, false)},
			"u-hold": nil,
			// a dax device of no claim: the records keep its region, mode,
			// size and name
			"-": {{Region: "region0", Mode: "dax", Size: 128 * mi, Dax: "dax0.6"}},
		}},
		{Serial: 0xc100e2e2, SerialHex: "c100e2e2", Memdev: "mem1", Region: "region1", Node: 3, Dax: "dax1.0", Shared: true, Claims: map[string][]*localSlice{
			"u-sh1": {sharedUse(false)}, "u-sh2": {sharedUse(true)},
		}},
		{Serial: 0xc100e2e3, SerialHex: "c100e2e3", Memdev: "mem3", Creating: "region13", Node: -1, Claims: map[string][]*localSlice{"u-new": nil}},
		{Serial: 0xc100e2e4, SerialHex: "c100e2e4", Memdev: "mem4", Region: "region14", Node: 4, Dax: "dax14.0", Shared: true, Claims: map[string][]*localSlice{}},
		{Serial: 0xc1ae2001, SerialHex: "c1ae2001", Memdev: "mem2", Region: "region2", Node: -1, Persistent: true, NdRegion: "region7",
			Namespace: "namespace7.0", BlockDevice: "/dev/pmem7", BlockMajor: 259, Claims: map[string][]*localSlice{
				"u-fs":  {pmemUse(0, "fs", "direct", direct, "")},
				"u-blk": {pmemUse(1, "block", "", "", "")},
				"u-fsc": {pmemUse(0, "fs", "cached", cached, "/dev/loop0")},
			}},
	}}
	return prepared, infos, local
}

func TestLocalContentRoundTrip(t *testing.T) {
	prepared, infos, local := localFixture()
	doc := &store.Document{Schema: store.Schema, BootID: local.BootID}
	putLocal(doc, prepared, infos, &local)
	doc.Sort()
	for name, want := range map[string]any{
		store.ViewPreparedClaims:     prepared,
		store.ViewPreparedClaimsInfo: infos,
		store.ViewLocalDevices:       local,
	} {
		got, err := store.ViewContent(doc, name, testViewOptions)
		if err != nil {
			t.Fatal(err)
		}
		jsonEqual(t, name, got, mustJSON(t, want))
	}
}

// TestLocalContentOfOneFile replaces the content of one file at a time:
// the others keep theirs.
func TestLocalContentOfOneFile(t *testing.T) {
	prepared, infos, local := localFixture()
	doc := &store.Document{Schema: store.Schema, BootID: local.BootID}
	putLocal(doc, prepared, infos, &local)
	delete(local.Devices[0].Claims, "u-mid")
	if err := putLocalContent(doc, testViewOptions, localStateFileName, mustJSON(t, local), nil); err != nil {
		t.Fatal(err)
	}
	delete(infos, "u-dax")
	delete(prepared, "u-dax")
	if err := putLocalContent(doc, testViewOptions, preparedClaimsInfoFileName, mustJSON(t, infos), mustJSON(t, prepared)); err != nil {
		t.Fatal(err)
	}
	doc.Sort()
	for name, want := range map[string]any{
		store.ViewPreparedClaims:     prepared,
		store.ViewPreparedClaimsInfo: infos,
		store.ViewLocalDevices:       local,
	} {
		got, err := store.ViewContent(doc, name, testViewOptions)
		if err != nil {
			t.Fatal(err)
		}
		jsonEqual(t, name, got, mustJSON(t, want))
	}
}

// poolFixture returns the content of the state files of the pool driver: a
// numa, a dax and a cached fs claim, an fs companion, a Prepare that did not
// finish with its noted regions, and a stale claim.
func poolFixture() (map[string]*preparedPoolClaim, map[string]*preparingPoolClaim) {
	pod := podRef{Namespace: "demo", Name: "requester", UID: "p-1"}
	share := types.UID("share-1")
	fsDir := "/var/lib/kubelet/plugins/cxl.nri.io/lease-fs/u-lease"
	mount := "/var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/c1ae2002-cached"
	result := func(uid string, devs []preparedPoolDevice, companion bool, shareID *types.UID) kubeletplugin.PrepareResult {
		res := kubeletplugin.PrepareResult{Devices: []kubeletplugin.Device{}}
		for _, d := range devs {
			dev := kubeletplugin.Device{Requests: []string{d.Request}, PoolName: d.Pool, DeviceName: d.Device, ShareID: shareID}
			if !companion {
				dev.CDIDeviceIDs = []string{poolCDIDeviceID(uid, d.Result)}
			}
			res.Devices = append(res.Devices, dev)
		}
		return res
	}
	numa := []preparedPoolDevice{{Result: 0, Request: "mem", Device: "pooled3", Pool: "pool-a", Serial: 0xc1ae2003, Size: gi, Mode: "numa",
		Memdev: "mem4", Region: "region4", Dax: "dax4.0", NumaNode: 4}}
	dax := []preparedPoolDevice{{Result: 1, Request: "mem", Device: "pooled4", Pool: "pool-b", Serial: 0xc1ae2004, Shared: true, Size: gi, Mode: "dax",
		ReadOnly: true, Memdev: "mem5", Region: "region6", Dax: "dax6.0", DaxDevice: "/dev/dax6.0", DaxMajor: 252, DaxMinor: 6, NumaNode: -1}}
	fs := func(n int) []preparedPoolDevice {
		return []preparedPoolDevice{{Result: n, Request: "mem", Device: "pooled2", Pool: "pool-c", Serial: 0xc1ae2002, Shared: true, Size: gi,
			Mode: "fs", ReadOnly: true, Memdev: "mem3", Region: "region3", NumaNode: -1, Persistent: true, NdRegion: "region8",
			Namespace: "namespace8.0", BlockDevice: "/dev/pmem8", BlockMajor: 259, BlockMinor: 1, Access: "cached", FsType: "erofs",
			Path: "/run/cxl-fs/C1AE2002", NodeMount: mount, LoopDevice: "/dev/loop0"}}
	}
	lend := &lendRecord{Lease: "1b2c3d4e", Pod: pod, Container: "main", FsDir: fsDir, Name: "mbt", Mounts: []string{fsDir + "/mbt"}}
	prepared := map[string]*preparedPoolClaim{
		"p-numa": {ClaimName: "demo/c-pnuma", Devices: numa, Result: result("p-numa", numa, false, nil), BootID: "boot-1"},
		"p-dax":  {ClaimName: "demo/c-pdax", Devices: dax, Result: result("p-dax", dax, false, &share), BootID: "boot-1"},
		"p-fs":   {ClaimName: "demo/c-pfs", Devices: fs(0), Result: result("p-fs", fs(0), false, &share), BootID: "boot-1"},
		"p-comp": {ClaimName: "demo/cxl-lease-1b2c3d4e", Devices: fs(0), Result: result("p-comp", fs(0), true, &share), Lend: lend, BootID: "boot-1"},
	}
	untouched := preparedPoolDevice{Result: 0, Request: "mem", Device: "pooled5", Pool: "pool-a", Serial: 0xc1ae2005, Size: gi, Mode: "numa", NumaNode: 5}
	stale := untouchedDevice(fs(0)[0])
	staleLend := *lend
	preparing := map[string]*preparingPoolClaim{
		"p-cut": {ClaimName: "demo/c-cut", Devices: []preparedPoolDevice{untouched}, BootID: "boot-1",
			Regions: []preparingRegion{{Serial: 0xc1ae2005, Region: "region9"}}},
		"p-stale": {ClaimName: "demo/cxl-lease-2c3d4e5f", Devices: []preparedPoolDevice{stale}, Lend: &staleLend, BootID: "boot-1",
			Stale: "prepared in another boot (boot-0, this is boot-1)"},
	}
	return prepared, preparing
}

func TestPoolContentRoundTrip(t *testing.T) {
	prepared, preparing := poolFixture()
	doc := &store.Document{Schema: store.Schema, BootID: "boot-1"}
	putPool(doc, device.PoolDriverName, prepared, preparing, false)
	doc.Sort()
	got, err := store.ViewContent(doc, store.ViewPreparedPoolClaims, testViewOptions)
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, poolStateFileName, got, mustJSON(t, prepared))
	got, err = preparingContent(doc, testViewOptions)
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, poolPreparingFileName, got, mustJSON(t, preparing))
}

// leasesFixture returns a lease table of a lease claim with a lease of
// each mode.
func leasesFixture() *leaseStore {
	created := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	pod := podRef{Namespace: "demo", Name: "requester", UID: "p-1"}
	ls := &leaseStore{
		Claims: map[string]*leaseClaim{"u-lease": {UID: "u-lease", Namespace: "demo", Name: "c-lease", Pods: []podRef{pod}, FsDir: "/x/lease-fs/u-lease"}},
		Leases: map[string]*lease{
			"0a1b2c3d": {ID: "0a1b2c3d", Claim: "u-lease", RequestID: "r1", Source: "local", Mode: "numa", Size: "128Mi", Serial: "0xc100e2e1",
				Pod: pod, Container: "main", State: "Ready", Node: 2, Bytes: 128 * mi, Created: created},
			"1b2c3d4e": {ID: "1b2c3d4e", Claim: "u-lease", Source: "pool", Mode: "fs", SharedDevice: true, Access: "cached", FsType: "erofs",
				Name: "mbt", Path: "/run/cxl/fs/mbt", Serial: "0xc1ae2002", Pod: pod, Container: "main", State: "Releasing", Node: -1,
				Bytes: gi, Created: created},
			"2c3d4e5f": {ID: "2c3d4e5f", Claim: "u-lease", Mode: "dax", Shared: true, SharedDevice: true, DeviceSource: "pool", ReadOnly: true,
				Serial: "0xc1ae2004", Pod: pod, Container: "main", State: "Pending", Node: -1, Created: created},
			"3d4e5f6a": {ID: "3d4e5f6a", Claim: "u-lease", Mode: "block", ReadWrite: true, Pod: pod, Container: "main", State: "Failed",
				Error: "wrong mode", Node: -1, Block: "/dev/pmem8", Bytes: gi, Created: created},
		},
		BootID: "boot-1",
	}
	return ls
}

func TestLeasesContentRoundTrip(t *testing.T) {
	ls := leasesFixture()
	doc := &store.Document{Schema: store.Schema, BootID: "boot-1"}
	if err := putContent(doc, testViewOptions, leasesFileName, mustJSON(t, ls), nil); err != nil {
		t.Fatal(err)
	}
	got, err := store.ViewContent(doc, store.ViewLeases, testViewOptions)
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, leasesFileName, got, mustJSON(t, ls))
}

// serialsFixture returns the pool serials of a local memdev, a pool
// device of a remembered pool and one never listed.
func serialsFixture() *poolSerialsFile {
	seen := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	return &poolSerialsFile{
		Serials: []*serialRecord{
			{Serial: "0xc100e2e1", Local: true, Seen: seen},
			{Serial: "0xc1ae2002", Pool: "cxl-pool.nri.io/pool-c", Seen: seen},
			{Serial: "0xc1ae2003"},
		},
		Pools: map[string]time.Time{"cxl-pool.nri.io/pool-c": seen},
	}
}

func TestSerialsContentRoundTrip(t *testing.T) {
	f := serialsFixture()
	doc := &store.Document{Schema: store.Schema}
	noErr(t, putContent(doc, testViewOptions, poolSerialsFileName, mustJSON(t, f), nil))
	got, err := serialsContent(doc)
	noErr(t, err)
	jsonEqual(t, poolSerialsFileName, got, mustJSON(t, f))
}

// openTestStateStore opens a state store in a new directory pair.
func openTestStateStore(t *testing.T, local, pool, bootID string, flags store.Flags) (*stateStore, func()) {
	t.Helper()
	s, closeStore, err := openStateStore(context.Background(), stateStoreConfig{
		LocalDir: local, PoolDir: pool, PoolDriver: device.PoolDriverName, BootID: bootID, Flags: flags, SysRoot: "/sys", DevRoot: "/dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, closeStore
}

func TestStateStoreFiles(t *testing.T) {
	local, pool := t.TempDir(), t.TempDir()
	_, closeStore := openTestStateStore(t, local, pool, "boot-1", store.Flags{CompatViews: true})
	prepared, infos, ls := localFixture()
	noErr(t, writeStateFile(filepath.Join(local, localStateFileName), ls))
	noErr(t, writeStateFile(filepath.Join(local, device.PreparedClaimsFileName), prepared))
	noErr(t, writeStateFile(filepath.Join(local, preparedClaimsInfoFileName), infos))
	pp, pr := poolFixture()
	noErr(t, writeStateFile(filepath.Join(pool, poolStateFileName), pp))
	noErr(t, writeStateFile(filepath.Join(pool, poolPreparingFileName), pr))
	noErr(t, writeStateFile(filepath.Join(local, leasesFileName), leasesFixture()))
	noErr(t, writeStateFile(filepath.Join(local, poolSerialsFileName), serialsFixture()))
	contents := map[string]any{
		filepath.Join(local, device.PreparedClaimsFileName): prepared,
		filepath.Join(local, preparedClaimsInfoFileName):    infos,
		filepath.Join(local, localStateFileName):            ls,
		filepath.Join(local, leasesFileName):                leasesFixture(),
		filepath.Join(local, poolSerialsFileName):           serialsFixture(),
		filepath.Join(pool, poolStateFileName):              pp,
		filepath.Join(pool, poolPreparingFileName):          pr,
	}
	readAll := func(what string) {
		t.Helper()
		for path, want := range contents {
			got, err := readStateFile(path)
			noErr(t, err)
			jsonEqual(t, what+" "+path, got, mustJSON(t, want))
		}
	}
	readAll("written")
	data, err := os.ReadFile(filepath.Join(pool, poolStateFileName))
	noErr(t, err)
	if !strings.Contains(string(data), `"viewOf": "state.json"`) {
		t.Errorf("the view of %s has no marker", poolStateFileName)
	}
	if _, err := os.Stat(filepath.Join(pool, poolPreparingFileName)); err == nil {
		t.Errorf("%s is written as a file", poolPreparingFileName)
	}
	closeStore()
	if _, err := os.ReadFile(filepath.Join(local, store.FileName)); err != nil {
		t.Errorf("no document: %v", err)
	}

	// reopened from state.json, with the views off
	_, closeStore = openTestStateStore(t, local, pool, "boot-1", store.Flags{})
	defer closeStore()
	readAll("reopened")
	if _, err := os.Stat(filepath.Join(pool, poolStateFileName)); err == nil {
		t.Errorf("the views stay with --compat-views=false")
	}
}

// TestStateStoreReboot opens the document of the fixtures in another boot:
// the claims of cxl.nri.io and the memdevs are dropped, the pool claims are
// stale records as the pool driver demotes them.
func TestStateStoreReboot(t *testing.T) {
	local, pool := t.TempDir(), t.TempDir()
	_, closeStore := openTestStateStore(t, local, pool, "boot-1", store.Flags{})
	prepared, infos, ls := localFixture()
	noErr(t, writeStateFile(filepath.Join(local, localStateFileName), ls))
	noErr(t, writeStateFile(filepath.Join(local, device.PreparedClaimsFileName), prepared))
	noErr(t, writeStateFile(filepath.Join(local, preparedClaimsInfoFileName), infos))
	pp, _ := poolFixture()
	noErr(t, writeStateFile(filepath.Join(pool, poolStateFileName), pp))
	closeStore()

	_, closeStore = openTestStateStore(t, local, pool, "boot-2", store.Flags{})
	defer closeStore()
	for _, name := range []string{device.PreparedClaimsFileName, preparedClaimsInfoFileName} {
		got, err := readStateFile(filepath.Join(local, name))
		noErr(t, err)
		jsonEqual(t, name, got, []byte(`{}`))
	}
	got, err := readStateFile(filepath.Join(local, localStateFileName))
	noErr(t, err)
	jsonEqual(t, localStateFileName, got, []byte(`{"bootID": "boot-2", "devices": []}`))
	got, err = readStateFile(filepath.Join(pool, poolStateFileName))
	noErr(t, err)
	jsonEqual(t, poolStateFileName, got, []byte(`{}`))
	got, err = readStateFile(filepath.Join(pool, poolPreparingFileName))
	noErr(t, err)
	recs := map[string]*preparingPoolClaim{}
	noErr(t, json.Unmarshal(got, &recs))
	rec := recs["p-comp"]
	if rec == nil || rec.Stale != "prepared in another boot (boot-1, this is boot-2)" || rec.BootID != "boot-2" {
		t.Fatalf("stale companion %+v", rec)
	}
	if rec.Lend == nil || rec.Lend.Lease != "1b2c3d4e" || rec.Lend.Pod.Name != "requester" || len(rec.Lend.NumaNodes) != 0 || len(rec.Lend.Mounts) != 1 {
		t.Errorf("lend of the stale companion %+v", rec.Lend)
	}
	want := untouchedDevice(pp["p-comp"].Devices[0])
	jsonEqual(t, "stale device", mustJSON(t, rec.Devices[0]), mustJSON(t, want))
}

func TestStateStoreLost(t *testing.T) {
	local := t.TempDir()
	noErr(t, os.WriteFile(filepath.Join(local, store.FileName), []byte("{"), 0o600))
	_, closeStore := openTestStateStore(t, local, "", "boot-1", store.Flags{})
	defer closeStore()
	if err := writeStateFile(filepath.Join(local, localStateFileName), localState{}); err == nil || !strings.Contains(err.Error(), "--new-state") {
		t.Errorf("write in LOST mode: %v", err)
	}
	if _, err := readStateFile(filepath.Join(local, localStateFileName)); !os.IsNotExist(err) {
		t.Errorf("local devices in LOST mode: %v", err)
	}
}

// TestViewsOfDriverFiles commits the state files that the driver's file
// writer wrote on a node, in the directories cxl.nri.io and cxl-pool.nri.io
// of testdata/node-files (of the VM n4-cxl-shared-2 after a test90 run: a
// local dax lease companion and a lease claim) or of CXL_VIEW_DIFF_DIR, to
// a store, and compares each file with its view on disk without the marker
// and with its content read from the store.
func TestViewsOfDriverFiles(t *testing.T) {
	dir := os.Getenv("CXL_VIEW_DIFF_DIR")
	if dir == "" {
		dir = filepath.Join("testdata", "node-files")
	}
	files := map[string][]byte{}
	bootID := ""
	for _, d := range []string{device.DriverName, device.PoolDriverName} {
		for _, name := range importOrder {
			data, err := os.ReadFile(filepath.Join(dir, d, name))
			if err != nil {
				continue
			}
			files[filepath.Join(d, name)] = data
			var b struct {
				BootID string `json:"bootID"`
			}
			if name == localStateFileName && json.Unmarshal(data, &b) == nil {
				bootID = b.BootID
			}
		}
	}
	if len(files) == 0 {
		t.Fatalf("no state files in %s", dir)
	}
	root := t.TempDir()
	local, pool := filepath.Join(root, device.DriverName), filepath.Join(root, device.PoolDriverName)
	s, closeStore := openTestStateStore(t, local, pool, bootID, store.Flags{CompatViews: true})
	defer closeStore()
	for _, d := range []string{device.DriverName, device.PoolDriverName} {
		for _, name := range importOrder {
			if data, ok := files[filepath.Join(d, name)]; ok {
				noErr(t, s.writeState(filepath.Join(root, d, name), data))
			}
		}
	}
	for rel, want := range files {
		path := filepath.Join(root, rel)
		read, err := s.readState(path)
		noErr(t, err)
		jsonEqual(t, rel+" read", read, want)
		if !slices.Contains(store.ViewNames, filepath.Base(rel)) {
			continue
		}
		view, err := os.ReadFile(path)
		noErr(t, err)
		// the marker is in the file or in each of its entries
		var v map[string]any
		noErr(t, json.Unmarshal(view, &v))
		marked := v["viewOf"] == store.FileName
		delete(v, "viewOf")
		for _, c := range v {
			if m, ok := c.(map[string]any); ok && !marked {
				if m["viewOf"] != store.FileName {
					t.Errorf("%s: an entry without the marker: %v", rel, m)
				}
				delete(m, "viewOf")
			}
		}
		jsonEqual(t, rel+" view", mustJSON(t, v), want)
		t.Logf("%s: the view is the file", rel)
	}
}

// importOrder are the names of the state files in the order of their
// import: the prepared claims before their infos.
var importOrder = []string{
	device.PreparedClaimsFileName, preparedClaimsInfoFileName, localStateFileName, poolStateFileName, poolPreparingFileName,
	leasesFileName, poolSerialsFileName,
}

// untouchedDevice returns a device as a Prepare records it before it touches it:
// what the claim asks for, without what the Prepare made of it.
func untouchedDevice(d preparedPoolDevice) preparedPoolDevice {
	return preparedPoolDevice{Result: d.Result, Request: d.Request, Device: d.Device, Pool: d.Pool, Serial: d.Serial, Shared: d.Shared,
		Size: d.Size, Mode: d.Mode, ReadOnly: d.ReadOnly, Persistent: d.Persistent, Access: d.Access, FsType: d.FsType, Path: d.Path, NumaNode: -1}
}

// On a store in LOST mode the driver starts (no crash loop): the device
// engine recovers nothing, the pool driver, the node state and the lease
// broker start empty, the first Prepare fails with the text of the lost
// state, and nothing is written: neither the document nor a view.
func TestStartOnALostStore(t *testing.T) {
	root := t.TempDir()
	local, pool := filepath.Join(root, device.DriverName), filepath.Join(root, device.PoolDriverName)
	noErr(t, os.MkdirAll(local, 0o750))
	noErr(t, os.WriteFile(filepath.Join(local, store.FileName), []byte("{"), 0o600))
	for _, d := range []string{"sys/bus/cxl/devices", "sys/devices/system/node", "cdi"} {
		noErr(t, os.MkdirAll(filepath.Join(root, d), 0o755))
	}
	s, closeStore := openTestStateStore(t, local, pool, "boot-1", store.Flags{CompatViews: true})
	defer closeStore()
	if s.st.Lost() == nil {
		t.Fatal("the store is not lost")
	}
	ctx := context.Background()

	flags := &CXLFlags{PoolDriverName: device.PoolDriverName, PoolPrepareTimeout: time.Second, CDIRoot: filepath.Join(root, "cdi"), NodeName: "n1"}
	config := &pluginConfig{Flags: flags, KubeletPluginDir: local}
	rules := newDriverRules(config, flags)
	devices, err := newDriverDevices(config, flags, &DriverConfig{}, root, nil, s.st, rules)
	noErr(t, err)
	fe, err := newFrontEnds(config, flags, &DriverConfig{}, root, "boot-1", s.st, devices, nil, rules)
	noErr(t, err)
	noErr(t, fe.recover(ctx, filepath.Join(root, "cdi"), root, &DriverConfig{}, devices))
	p, ns := fe.pool, fe.local
	if r := p.Records(); len(r.Preparations) != 0 || len(p.Serials()) != 0 {
		t.Errorf("pool driver: preparations %v, serials %v", r.Preparations, p.Serials())
	}
	if uses := fe.publisher.LocalSnapshot().Uses; len(uses) != 0 {
		t.Errorf("local uses %v", uses)
	}
	cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(filepath.Join(root, "cdi")), cdiapi.WithAutoRefresh(false))
	noErr(t, err)
	b, err := leases.New(leases.Options{Store: s.st, Client: k8sfake.NewClientset(), NodeName: testNode, DataDir: local, CDI: cache,
		CLI: filepath.Join(root, "cxl-request"), WaitDefault: time.Second, PoolDriver: device.PoolDriverName})
	noErr(t, err)
	defer b.Stop()

	fe.publisher.SetDevices(device.DevicesInfo{"dram": {Name: "dram", Dev: &device.DRAM{Nodes: []int{0}, Size: 1 << 30}}})
	claim := &resourcev1.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{UID: "u1", Name: "c", Namespace: "ns"},
		Status: resourcev1.ResourceClaimStatus{Allocation: &resourcev1.AllocationResult{Devices: resourcev1.DeviceAllocationResult{
			Results: []resourcev1.DeviceRequestAllocationResult{{Request: "mem", Driver: device.DriverName, Pool: "n1", Device: "dram"}}}}},
	}
	if err := prepareOn(ctx, ns, claim); err == nil || !strings.Contains(err.Error(), "the driver state is lost") ||
		!strings.Contains(err.Error(), "--new-state") {
		t.Errorf("Prepare in LOST mode: %v", err)
	}
	if ns.ClaimInfo("u1") != nil {
		t.Error("the claim is prepared")
	}
	noErr(t, unprepareOn(ctx, ns, "u1"))
	if data, err := os.ReadFile(filepath.Join(local, store.FileName)); err != nil || string(data) != "{" {
		t.Errorf("the lost document was rewritten: %q %v", data, err)
	}
	for _, name := range store.ViewNames {
		for _, dir := range []string{local, pool} {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				t.Errorf("view %s written in LOST mode", filepath.Join(dir, name))
			}
		}
	}
}
