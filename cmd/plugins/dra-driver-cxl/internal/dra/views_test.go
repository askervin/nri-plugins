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

package dra

import (
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// NumaNodes has the nodes of the grants of mode numa of the prepared claims
// of the drivers asked for, sorted, without those of dax slices.
func TestNumaNodes(t *testing.T) {
	e := newDriverEnv(t, []fake.MemdevSpec{slicedSpec()}, fake.MemdevSpec{Serial: serialPoolX, HostBridge: 24})
	e.mustPrepare(e.pool, poolClaim("p1", "pooled0", poolExclusiveData))
	e.mustPrepare(e.local, localClaim("l1", localDev, envBlockSize))
	e.mustPrepare(e.local, localClaim("l2", localDev, envBlockSize))
	e.mustPrepare(e.local, localClaim("d1", localDev, envBlockSize, cfgDax))
	r := e.records()
	for _, tc := range []struct {
		drivers []string
		want    []int
	}{
		{[]string{device.DriverName, device.PoolDriverName}, []int{2, 3}},
		{[]string{device.DriverName}, []int{2}},
		{[]string{device.PoolDriverName}, []int{3}},
		{nil, nil},
	} {
		if got := NumaNodes(r, tc.drivers...); !slices.Equal(got, tc.want) {
			t.Errorf("%v: %v, expected %v", tc.drivers, got, tc.want)
		}
	}
	for _, uid := range []string{"l1", "l2", "d1"} {
		e.mustUnprepare(e.local, uid)
	}
	e.mustUnprepare(e.pool, "p1")
	if got := NumaNodes(e.records(), device.DriverName, device.PoolDriverName); len(got) != 0 {
		t.Fatalf("NUMA nodes %v", got)
	}
}

// Serials has the serials of the grants of the driver's source and of the
// Prepares in progress, until the Prepare ends.
func TestSerials(t *testing.T) {
	e := newDriverEnv(t, []fake.MemdevSpec{slicedSpec(), sharedSpec()}, poolSpec(serialPoolX))
	e.setShared(serialShared)
	e.mustPrepare(e.pool, poolClaim("p1", "pooled0", poolExclusiveData))
	e.mustPrepare(e.local, localClaim("l1", localDev, envBlockSize))
	if got := e.pool.Serials(); !reflect.DeepEqual(got, map[uint64]bool{serialPoolX: true}) {
		t.Fatalf("pool serials %v", got)
	}
	if got := e.local.Serials(); !reflect.DeepEqual(got, map[uint64]bool{serialSliced: true}) {
		t.Fatalf("local serials %v", got)
	}
	// a Prepare in progress before its grant is recorded: OnShared is told
	// between the intent and the grants
	var inflight []uint64
	e.local.onShared = func(serial uint64) {
		if e.records().Grant(state.GrantRef{Claim: "s1"}) == nil {
			inflight = slices.Sorted(maps.Keys(e.local.Serials()))
		}
	}
	// the shared memdev has a region of another driver: the Prepare fails
	k := e.k.Kernel()
	memdev := e.k.Memdev(serialShared)
	d, err := k.RootDecoder(memdev, kernel.RegionRAM)
	mustOK(t, err)
	region, err := k.CreateRegion(t.Context(), kernel.CreateRegionRequest{Memdev: memdev, Decoder: d, Type: kernel.RegionRAM})
	mustOK(t, err)
	wantErrText(t, e.prepare(e.local, localClaim("s1", MemdevDeviceName(serialShared), -1, cfgDax)).Err, "that the plugin did not create")
	if !slices.Equal(inflight, []uint64{serialSliced, serialShared}) {
		t.Fatalf("serials in the Prepare %v", inflight)
	}
	if got := e.local.Serials(); !reflect.DeepEqual(got, map[uint64]bool{serialSliced: true}) {
		t.Fatalf("serials after the Prepare %v", got)
	}
	mustOK(t, k.ReleaseRegion(t.Context(), region))
	e.mustUnprepare(e.local, "l1")
	e.mustUnprepare(e.pool, "p1")
	if len(e.local.Serials())+len(e.pool.Serials()) != 0 {
		t.Fatalf("serials %v %v", e.local.Serials(), e.pool.Serials())
	}
	var none *Plugin
	if none.Serials() != nil || none.Name() != "" || none.Lender() != nil || none.ClaimInfo("x") != nil || none.ClaimResults("x") != nil {
		t.Fatal("a nil plugin")
	}
}

// The readers of the prepared claims: ClaimResults of the pool driver for
// the NRI plugin, PreparedResult and ClaimInfo of prepared claims only,
// PoolDevices of a record in any state.
func TestClaimReaders(t *testing.T) {
	e := newDriverEnv(t, []fake.MemdevSpec{slicedSpec()}, poolSpec(serialPoolX))
	e.mustPrepare(e.pool, poolClaim("p1", "pooled0", poolExclusiveData))
	e.mustPrepare(e.local, localClaim("l1", localDev, envBlockSize))
	want := []PoolResult{{Index: 0, Request: "mem", Mode: api.ModeNUMA, Node: 2, Size: 256 << 20}}
	if got := e.pool.ClaimResults("p1"); !reflect.DeepEqual(got, want) {
		t.Fatalf("results %+v, expected %+v", got, want)
	}
	devs := e.pool.PoolDevices("p1")
	if len(devs) != 1 || devs[0].Result != 0 || devs[0].Request != "mem" || devs[0].Device != "pooled0" || devs[0].Pool != envPool ||
		devs[0].Serial != serialPoolX || devs[0].Memdev != "mem1" || devs[0].Region != "region0" || devs[0].Node != 2 || devs[0].Mode != api.ModeNUMA {
		t.Fatalf("pool devices %+v", devs)
	}
	name, d, ok := e.local.PreparedResult("l1", 0)
	if !ok || name != "demo/claim-l1" || d.DeviceName != localDev || d.Result != 0 {
		t.Fatalf("prepared result %q %+v %v", name, d, ok)
	}
	if _, _, ok := e.local.PreparedResult("l1", 1); ok {
		t.Fatal("a prepared result of no allocation result")
	}
	for _, uid := range []string{"x", "p1"} {
		if _, _, ok := e.local.PreparedResult(uid, 0); ok {
			t.Fatalf("a prepared result of %s of cxl.nri.io", uid)
		}
	}
	if e.pool.ClaimInfo("p1") == nil || e.local.ClaimInfo("p1") != nil || e.pool.ClaimResults("x") != nil || e.pool.PoolDevices("x") != nil {
		t.Fatal("the readers of a claim of another driver or of none")
	}
	e.mustUnprepare(e.pool, "p1")
	e.mustUnprepare(e.local, "l1")
	if e.pool.ClaimResults("p1") != nil || e.pool.PoolDevices("p1") != nil || e.local.ClaimInfo("l1") != nil {
		t.Fatal("the readers of an unprepared claim")
	}
}

// jsonTags returns the json tags of the fields of a struct type in order,
// "inline <type>" for an embedded struct without one.
func jsonTags(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		f := t.Field(i)
		tag, ok := f.Tag.Lookup("json")
		if f.Anonymous && !ok {
			out = append(out, "inline "+f.Type.String())
			continue
		}
		out = append(out, tag)
	}
	return out
}

// The JSON of DeviceInfo, ClaimInfo, PoolDevice and Lend is that of the
// structs of the state files before the store: PreparedDeviceInfo,
// PreparedClaimInfo, preparedPoolDevice and lendRecord.
func TestShapes(t *testing.T) {
	for _, tc := range []struct {
		v    any
		want []string
	}{
		{DeviceInfo{}, []string{"requestName", "deviceName", "result", "deviceType", "mode,omitempty", "sysfsPath,omitempty", "numaNodes",
			"nodeAffinities,omitempty", "totalBytes", "consumedBytes", "serial,omitempty", "region,omitempty", "daxDevice,omitempty",
			"daxMajor,omitempty", "daxMinor,omitempty", "readOnly,omitempty", "shared,omitempty", "persistent,omitempty",
			"namespace,omitempty", "blockDevice,omitempty", "blockMajor,omitempty", "blockMinor,omitempty", "access,omitempty",
			"path,omitempty", "nodeMount,omitempty", "loopDevice,omitempty", "fsType,omitempty", "inline config.ResultSettings"}},
		{ClaimInfo{}, []string{"claimName", "devices", "lend,omitempty", "bootID,omitempty"}},
		{PoolDevice{}, []string{"result", "request", "device", "pool", "serial", "shared", "size", "mode", "readOnly,omitempty", "memdev",
			"region", "dax", "daxDevice,omitempty", "daxMajor,omitempty", "daxMinor,omitempty", "node", "persistent,omitempty",
			"ndRegion,omitempty", "namespace,omitempty", "blockDevice,omitempty", "blockMajor,omitempty", "blockMinor,omitempty",
			"access,omitempty", "fsType,omitempty", "path,omitempty", "nodeMount,omitempty", "loopDevice,omitempty",
			"inline config.ResultSettings"}},
		{Lend{}, []string{"lease", "pod", "container", "nodes,omitempty", "fsDir,omitempty", "name,omitempty", "mounts,omitempty"}},
		{state.PodRef{}, []string{"namespace", "name", "uid"}},
	} {
		typ := reflect.TypeOf(tc.v)
		if got := jsonTags(typ); !slices.Equal(got, tc.want) {
			t.Errorf("%s: json tags\n%q\nexpected\n%q", typ, got, tc.want)
		}
	}
	if typ := reflect.TypeOf(ClaimInfo{}); typ.Field(1).Type.Elem() != reflect.TypeOf(DeviceInfo{}) ||
		typ.Field(2).Type.Elem() != reflect.TypeOf(Lend{}) || reflect.TypeOf(Lend{}).Field(1).Type != reflect.TypeOf(state.PodRef{}) {
		t.Fatal("the types of the fields of ClaimInfo or Lend")
	}
}
