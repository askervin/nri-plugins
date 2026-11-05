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

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state/statetest"
)

var update = flag.Bool("update", false, "write the golden files of the views")

// fixtureViews returns the views of the test records by file name.
func fixtureViews(t *testing.T, doc *Document) map[string][]byte {
	t.Helper()
	files, err := views(doc, ViewOptions{PoolDriver: statetest.PoolDriver, SysRoot: "/sys", DevRoot: "/dev"},
		statetest.LocalDir, statetest.PoolDir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for path, data := range files {
		out[filepath.Base(path)] = data
	}
	return out
}

// TestViewsGolden compares the views of the test records with the golden
// files in testdata (go test -update writes them).
func TestViewsGolden(t *testing.T) {
	files := fixtureViews(t, fixture(statetest.BootID))
	if len(files) != 5 {
		t.Errorf("%d views, want 5", len(files))
	}
	for name, data := range files {
		golden := filepath.Join("testdata", name+".golden")
		if *update {
			if err := os.WriteFile(golden, append(data, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(append(data, '\n'), want) {
			t.Errorf("%s differs from %s:\n%s", name, golden, data)
		}
	}
}

// unmarked returns data without the view marker: at the top of an object,
// and in every value of an object of objects (byValue).
func unmarked(t *testing.T, data []byte, byValue bool) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if !byValue {
		if string(m[viewKey]) != `"state.json"` {
			t.Errorf("no marker at the top")
		}
		delete(m, viewKey)
	} else {
		if _, ok := m[viewKey]; ok {
			t.Errorf("a marker among the claim UIDs")
		}
		for k, raw := range m {
			var v map[string]json.RawMessage
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			if string(v[viewKey]) != `"state.json"` {
				t.Errorf("value %s without the marker", k)
			}
			delete(v, viewKey)
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			m[k] = b
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// decodeStrictly decodes data into v, refusing unknown fields.
func decodeStrictly(t *testing.T, name string, data []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Errorf("%s does not decode into the old shape: %v", name, err)
	}
}

// TestViewsHaveTheOldShapes decodes every view, without its marker,
// strictly into the types of the old state files, and checks what the
// test90 observer reads of them.
func TestViewsHaveTheOldShapes(t *testing.T) {
	files := fixtureViews(t, fixture(statetest.BootID))

	var prepared map[string]oldPrepareResult
	decodeStrictly(t, ViewPreparedClaims, unmarked(t, files[ViewPreparedClaims], true), &prepared)
	var info map[string]oldPreparedClaimInfo
	decodeStrictly(t, ViewPreparedClaimsInfo, unmarked(t, files[ViewPreparedClaimsInfo], true), &info)
	var pool map[string]oldPreparedPoolClaim
	decodeStrictly(t, ViewPreparedPoolClaims, unmarked(t, files[ViewPreparedPoolClaims], true), &pool)
	var local oldLocalState
	decodeStrictly(t, ViewLocalDevices, unmarked(t, files[ViewLocalDevices], false), &local)
	var leases oldLeaseStore
	decodeStrictly(t, ViewLeases, unmarked(t, files[ViewLeases], false), &leases)

	wantLocal := []string{
		statetest.ClaimNUMA, statetest.ClaimDax, statetest.ClaimShared, statetest.ClaimMixed,
		statetest.ClaimFs, statetest.ClaimLease, statetest.ClaimCompanion,
	}
	slices.Sort(wantLocal)
	if got := sortedKeys(prepared); !slices.Equal(got, wantLocal) {
		t.Errorf("preparedClaims.json has %v, want %v", got, wantLocal)
	}
	if got := sortedKeys(info); !slices.Equal(got, wantLocal) {
		t.Errorf("preparedClaimsInfo.json has %v, want %v", got, wantLocal)
	}
	wantPool := []string{statetest.ClaimPoolNUMA, statetest.ClaimPoolFs, statetest.ClaimPoolDax, statetest.ClaimPoolLeaseC}
	slices.Sort(wantPool)
	if got := sortedKeys(pool); !slices.Equal(got, wantPool) {
		t.Errorf("preparedPoolClaims.json has %v, want %v", got, wantPool)
	}

	if ids := prepared[statetest.ClaimLease].Devices[0].CDIDeviceIDs; !slices.Equal(ids, []string{
		"nri.io/cxl=claim-" + statetest.ClaimLease + "-0", "nri.io/cxl=lease-" + statetest.ClaimLease,
	}) {
		t.Errorf("CDI devices of the lease claim %v", ids)
	}
	if ids := prepared[statetest.ClaimCompanion].Devices[0].CDIDeviceIDs; ids != nil {
		t.Errorf("CDI devices of a companion claim %v", ids)
	}
	if ids := pool[statetest.ClaimPoolNUMA].Result.Devices[0].CDIDeviceIDs; !slices.Equal(ids, []string{
		"nri.io/cxl-pool=claim-" + statetest.ClaimPoolNUMA + "-0",
	}) {
		t.Errorf("CDI devices of a pool claim %v", ids)
	}
	if id := pool[statetest.ClaimPoolDax].Result.Devices[0].ShareID; id == nil || *id == "" {
		t.Errorf("share id of a shared pool claim %v", id)
	}
	if l := info[statetest.ClaimCompanion].Lend; l == nil || l.Lease != statetest.LeaseNUMA || !slices.Equal(l.Nodes, []int{2}) {
		t.Errorf("lend of the numa companion %+v", l)
	}
	if l := pool[statetest.ClaimPoolLeaseC].Lend; l == nil || len(l.Mounts) != 1 || l.Name != "mbt" {
		t.Errorf("lend of the fs companion %+v", l)
	}
	if d := pool[statetest.ClaimPoolFs].Devices[0]; d.Serial != uint64(statetest.SerialPoolFs) || d.NodeMount == "" ||
		d.LoopDevice != "/dev/loop0" || d.Access != "cached" || !d.Persistent || d.BlockDevice != "/dev/pmem8" {
		t.Errorf("pool fs device %+v", d)
	}
	if d := pool[statetest.ClaimPoolNUMA].Devices[0]; d.Node != 4 || d.Dax != "dax4.0" || d.Region != "region4" {
		t.Errorf("pool numa device %+v", d)
	}

	if local.BootID != statetest.BootID || len(local.Devices) != 3 {
		t.Fatalf("localDevices.json boot %s with %d devices", local.BootID, len(local.Devices))
	}
	plain := local.Devices[0]
	if plain.SerialHex != "c100e2e1" || plain.Region != "region0" || plain.Dax != "dax0.0" || plain.Node != 2 {
		t.Errorf("plain memdev %+v", plain)
	}
	for _, uid := range []string{statetest.ClaimNUMA, statetest.ClaimDax, statetest.ClaimCompanion} {
		if n := len(plain.Claims[uid]); n != 1 {
			t.Errorf("claim %s has %d uses, want 1", uid, n)
		}
	}
	if uses, ok := plain.Claims[statetest.ClaimKept]; !ok || uses != nil {
		t.Errorf("the KEPT holder is %v, %v, want null", uses, ok)
	}
	if _, ok := plain.Claims["-"]; ok {
		t.Errorf("unused dax devices in a consistent document")
	}

	if got := sortedKeys(leases.Claims); !slices.Equal(got, []string{statetest.ClaimLease}) {
		t.Errorf("leases.json claims %v", got)
	}
	if l := leases.Leases[statetest.LeaseFs]; l == nil || l.State != "Releasing" || l.Node != -1 {
		t.Errorf("busy fs lease %+v", l)
	}
	if l := leases.Leases[statetest.LeaseNUMA]; l == nil || l.State != "Ready" || l.Node != 2 || l.Serial != "0xc100e2e1" {
		t.Errorf("numa lease %+v", l)
	}
}

// sortedKeys returns the keys of a map in order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func TestViewsLeaveOutClaimsThatAreNotPrepared(t *testing.T) {
	doc := fixture(statetest.BootID)
	for _, s := range []state.PreparationState{state.PreparationPreparing, state.PreparationKept, state.PreparationStale} {
		for i := range doc.Preparations {
			if doc.Preparations[i].UID == statetest.ClaimDax {
				doc.Preparations[i].State = s
			}
		}
		files := fixtureViews(t, doc)
		for _, name := range []string{ViewPreparedClaims, ViewPreparedClaimsInfo} {
			if bytes.Contains(files[name], []byte(`"`+statetest.ClaimDax+`"`)) {
				t.Errorf("%s has a claim %s", name, s)
			}
		}
	}
}

func TestUnusedDaxDeviceIsAnOrphan(t *testing.T) {
	doc := fixture(statetest.BootID)
	reg := doc.Region("region0")
	reg.DaxDevices = append(reg.DaxDevices, state.DaxDevice{
		Name: "dax0.7", Size: 1 << 27, Driver: state.DriverKmem, State: state.DaxKmemOffline,
	})
	var local oldLocalState
	decodeStrictly(t, ViewLocalDevices, unmarked(t, fixtureViews(t, doc)[ViewLocalDevices], false), &local)
	uses := local.Devices[0].Claims["-"]
	if len(uses) != 1 || uses[0].Dax != "dax0.7" || uses[0].Mode != "numa" {
		t.Errorf("orphan uses %+v", uses)
	}
}

// countingFiles count the writes of each file.
type countingFiles struct {
	osFiles
	mu     sync.Mutex
	writes map[string]int
}

func (c *countingFiles) WriteFile(name string, data []byte, sync bool) error {
	c.mu.Lock()
	c.writes[filepath.Base(strings.TrimSuffix(name, ".tmp"))]++
	c.mu.Unlock()
	return c.osFiles.WriteFile(name, data, sync)
}

func TestStoreWritesViews(t *testing.T) {
	local, pool := t.TempDir(), t.TempDir()
	files := &countingFiles{writes: map[string]int{}}
	s := open(t, local, files, func(o *Options) {
		o.CompatViews, o.PoolDir, o.PoolDriver = true, pool, statetest.PoolDriver
		o.BootID = statetest.BootID
	})
	defer closeStore(t, s)
	for _, path := range []string{
		filepath.Join(local, ViewPreparedClaims), filepath.Join(local, ViewPreparedClaimsInfo),
		filepath.Join(local, ViewLocalDevices), filepath.Join(local, ViewLeases), filepath.Join(pool, ViewPreparedPoolClaims),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("view not written at the start: %v", err)
		}
	}
	err := s.Commit(context.Background(), Durable, func(doc *Document) error {
		doc.Records = statetest.Records()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(pool, ViewPreparedPoolClaims))
	if err != nil || !bytes.Contains(data, []byte(statetest.ClaimPoolFs)) {
		t.Errorf("pool view after the commit: %v", err)
	}
	files.mu.Lock()
	before := files.writes[ViewPreparedPoolClaims]
	files.mu.Unlock()
	if err := s.Commit(context.Background(), Durable, addSteered("x")); err != nil {
		t.Fatal(err)
	}
	files.mu.Lock()
	after := files.writes[ViewPreparedPoolClaims]
	files.mu.Unlock()
	if after != before {
		t.Errorf("an unchanged view was written again")
	}
}

func TestViewsOff(t *testing.T) {
	local := t.TempDir()
	s := open(t, local, nil, nil)
	defer closeStore(t, s)
	if err := s.Commit(context.Background(), Durable, addSteered("x")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{ViewPreparedClaims, ViewPreparedClaimsInfo, ViewLocalDevices, ViewLeases} {
		if _, err := os.Stat(filepath.Join(local, name)); err == nil {
			t.Errorf("view %s written with the views off", name)
		}
	}
}

func TestFlags(t *testing.T) {
	var f Flags
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	f.Register(fs)
	if err := fs.Parse([]string{"--compat-views=false", "--discard-old-state", "--new-state"}); err != nil {
		t.Fatal(err)
	}
	if f.CompatViews || !f.DiscardOldState || !f.NewState {
		t.Errorf("flags %+v", f)
	}
	var d Flags
	d.Register(flag.NewFlagSet("d", flag.ContinueOnError))
	if !d.CompatViews || d.DiscardOldState || d.NewState {
		t.Errorf("defaults %+v", d)
	}
}

func TestLocalDeviceOfARegionBeingCreated(t *testing.T) {
	doc := fixture(statetest.BootID)
	reg := doc.Region("region0")
	reg.Name, reg.State, reg.SetUp = "", state.RegionCreating, false
	var local oldLocalState
	decodeStrictly(t, ViewLocalDevices, unmarked(t, fixtureViews(t, doc)[ViewLocalDevices], false), &local)
	if d := local.Devices[0]; d.Region != "" || d.Creating != "region0" || d.Dax != "" {
		t.Errorf("memdev of a region being created: region %q, creating %q, dax %q", d.Region, d.Creating, d.Dax)
	}
}

func TestLeaseOfADevice(t *testing.T) {
	l := &state.Lease{
		ID: "l", State: state.LeaseReady,
		Asked: state.LeaseAsked{Mode: state.ModeFs, Source: state.SourceLocal, SharedDevice: true, Access: state.AccessDirect},
		Got:   &state.LeaseGot{Source: state.SourcePool, SharedDevice: false, Access: state.AccessCached, Serial: 0xc1ae, Bytes: 7},
	}
	v := leaseView(l)
	if v.Source != "pool" || v.SharedDevice || v.Access != "cached" || v.Serial != "0xc1ae" || v.Bytes != 7 {
		t.Errorf("a lease with a device %+v", v)
	}
	l.Got = nil
	if v := leaseView(l); v.Source != "local" || !v.SharedDevice || v.Access != "direct" || v.Serial != "" {
		t.Errorf("a lease without a device %+v", v)
	}
}
