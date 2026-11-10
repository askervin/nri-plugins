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
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state/statetest"
)

// observerFixtures is the directory of the fixture pairs of test90's
// observer test: per directory a state.json and its five views.
var observerFixtures = filepath.Join("..", "..", "..", "..", "..", "test", "e2e", "memory.test-suite",
	"dra-driver-cxl", "n4-cxl-shared-2", "test90-gofmbt-reliability", "model", "testdata", "observe")

// observerDocuments returns the documents of the fixture pairs that the
// test records give, by name.
func observerDocuments(t *testing.T) map[string]*Document {
	t.Helper()
	noBoot := fixture(statetest.BootID)
	noBoot.BootID = ""
	rebooted := fixture(statetest.BootID)
	if _, err := applyBoot(rebooted, "boot-2"); err != nil {
		t.Fatal(err)
	}
	return map[string]*Document{
		"records":  fixture(statetest.BootID),
		"new":      {Schema: Schema, Generation: 1, BootID: statetest.BootID},
		"no-boot":  noBoot,
		"rebooted": rebooted,
		"making":   makingDocument(),
		"orphans":  orphansDocument(),
		"kept":     keptDocument(),
	}
}

// grantRef returns the reference of the grant of the result n of a claim.
func grantRef(claim string, n int) state.GrantRef {
	return state.GrantRef{Claim: claim, Result: n}
}

// makingDocument returns the test records with a local region being
// created, a ram region set up for the Prepares of its memdev that got no
// part of it yet, and a pmem region of an unfinished Prepare.
func makingDocument() *Document {
	doc := fixture(statetest.BootID)
	reg := doc.Region("region0")
	reg.Name, reg.State, reg.SetUp = "", state.RegionCreating, false
	unfinished := []state.GrantRef{grantRef(statetest.ClaimShared, 0), grantRef(statetest.ClaimMixed, 1), grantRef(statetest.ClaimFs, 0)}
	for _, r := range unfinished {
		g := doc.Grant(r)
		g.State, g.Got = state.GrantJournaled, state.Got{}
		doc.Preparation(statetest.LocalDriver, r.Claim).State = state.PreparationPreparing
	}
	return doc
}

// orphansDocument returns the test records with dax devices of a local
// region that no grant uses (and a seed and a whole device that are no
// orphans), a local memdev of a foreign region with a dax device, a grant
// reference without its grant, a pool result whose
// grant is gone, a block device that is not known, results of a negative
// index and of DRAM in a pool claim, and a second grant of a companion
// with another lend and the same lease bind.
func orphansDocument() *Document {
	doc := fixture(statetest.BootID)
	reg := doc.Region("region0")
	reg.DaxDevice("dax0.0").State = state.DaxDeviceDax
	reg.DaxDevices = append(reg.DaxDevices,
		state.DaxDevice{Name: "dax0.7", Size: 1 << 27, Driver: state.DriverKmem, State: state.DaxKmemOffline},
		state.DaxDevice{Name: "dax0.8", Size: 1 << 28, Driver: state.DriverDeviceDax, State: state.DaxDeviceDax},
		state.DaxDevice{Name: "dax0.9", State: state.DaxSeed})
	m := doc.Memdev(statetest.SerialLocal)
	m.Grants = append(m.Grants, grantRef(statetest.ClaimStale, 1))
	doc.Memdevs = append(doc.Memdevs, state.Memdev{
		Serial: statetest.SerialForeign, Name: "mem6", Source: state.SourceLocal, State: state.MemdevUnused,
		Facts: state.MemdevFacts{Ram: 2 << 30}, Regions: []state.RegionRef{"region5"},
	})
	doc.Region("region5").DaxDevices = []state.DaxDevice{
		{Name: "dax5.1", Size: 2 << 30, Driver: state.DriverKmem, State: state.DaxKmemOnline},
	}
	doc.Grants = slices.DeleteFunc(doc.Grants, func(g state.Grant) bool { return g.Ref == grantRef(statetest.ClaimPoolDax, 0) })
	doc.Grant(grantRef(statetest.ClaimPoolFs, 0)).Got.BlockDevice = nil
	p := doc.Preparation(statetest.PoolDriver, statetest.ClaimPoolNUMA)
	unnamed := grantRef(statetest.ClaimPoolNUMA, -1)
	p.Results = append(p.Results,
		state.Result{Index: -1, Kind: state.ResultGrant, Request: "mem", Pool: "pool-a", Device: "pooled3", Grant: &unnamed},
		state.Result{
			Index: 1, Kind: state.ResultDRAM, Request: "dram", Pool: statetest.Node, Device: "dram",
			DRAM: &state.DRAMResult{NumaNodes: []int{0}, Size: 1 << 30},
		})
	second := doc.Grant(grantRef(statetest.ClaimPoolLeaseC, 0)).Clone()
	secondRef := grantRef(statetest.ClaimPoolLeaseC, 1)
	second.Ref = secondRef
	second.Got.Lend = &state.GrantLend{Lease: statetest.LeaseFs, Container: "second", Name: "second"}
	second.Got.Bind = &state.Bind{Target: second.Got.Bind.Target, State: state.BindBound}
	doc.Grants = append(doc.Grants, second)
	p = doc.Preparation(statetest.PoolDriver, statetest.ClaimPoolLeaseC)
	p.Results = append(p.Results, state.Result{Index: 1, Kind: state.ResultGrant, Request: "memory", Pool: "pool-c", Device: "pooled2", Grant: &secondRef})
	doc.Sort()
	return doc
}

// keptDocument returns the test records with a KEPT region of an idle
// memdev, a ram region of unfinished Prepares one of which got a part of
// it, a pool claim of mode block, a companion grant with the lend of its
// intent only, a lease claim without leases and leases in every state.
func keptDocument() *Document {
	doc := fixture(statetest.BootID)
	doc.Region("region0").State = state.RegionKept
	doc.Memdev(statetest.SerialLocal).State = state.MemdevIdleKept
	doc.Preparation(statetest.LocalDriver, statetest.ClaimDax).State = state.PreparationKept
	doc.Preparation(statetest.PoolDriver, statetest.ClaimPoolNUMA).State = state.PreparationUnrestored
	g := doc.Grant(grantRef(statetest.ClaimShared, 0))
	g.State = state.GrantRealising
	g = doc.Grant(grantRef(statetest.ClaimMixed, 1))
	g.State, g.Got = state.GrantJournaled, state.Got{}
	for _, uid := range []string{statetest.ClaimShared, statetest.ClaimMixed} {
		doc.Preparation(statetest.LocalDriver, uid).State = state.PreparationPreparing
	}
	g = doc.Grant(grantRef(statetest.ClaimPoolFs, 0))
	g.Asked.Mode, g.Asked.Access, g.Asked.Path, g.Got.Mount = state.ModeBlock, "", "", ""
	requester := doc.Leases[0].Pod
	g = doc.Grant(grantRef(statetest.ClaimPoolLeaseC, 0))
	g.Got.Lend = nil
	g.Intent.Lend = &state.GrantLend{Lease: statetest.LeaseFs, Pod: requester, Container: "intent", Name: "intent"}
	for i, s := range []state.LeaseState{state.LeaseCreating, state.LeasePending, state.LeaseLending, state.LeaseFailed, state.LeaseNone} {
		l := state.Lease{
			ID: "f0f0f0f" + strconv.Itoa(i), Claim: statetest.ClaimLease, Pod: requester, Container: "main",
			Asked: state.LeaseAsked{Source: state.SourceLocal, Mode: state.ModeDax, Size: "64Mi"}, State: s,
			Created: doc.Leases[0].Created,
		}
		switch s {
		case state.LeaseFailed:
			l.Error = "no memory"
		case state.LeaseLending:
			l.Lend = &state.Lend{NumaNode: state.NumaNodePtr(3)}
		}
		doc.Leases = append(doc.Leases, l)
	}
	doc.LeaseClaims = append(doc.LeaseClaims, state.LeaseClaim{
		UID: "66666666-0000-0000-0000-000000000001", Namespace: "demo", Name: "c-idle", Pods: []state.PodRef{},
		State: state.LeaseClaimOpenNoListener,
	})
	doc.Sort()
	return doc
}

// observerFiles returns the content of every file of the fixture pairs by
// path: the state.json and the views of the documents of observerDocuments,
// and the views of the state.json of every other fixture directory.
func observerFiles(t *testing.T) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	addViews := func(dir string, doc *Document) {
		vs, err := views(doc, ViewOptions{PoolDriver: statetest.PoolDriver}, dir, dir)
		if err != nil {
			t.Fatal(err)
		}
		maps.Copy(files, vs)
	}
	docs := observerDocuments(t)
	for name, doc := range docs {
		dir := filepath.Join(observerFixtures, name)
		data, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		files[filepath.Join(dir, FileName)] = data
		addViews(dir, doc)
	}
	entries, err := os.ReadDir(observerFixtures)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for _, e := range entries {
		if _, ok := docs[e.Name()]; ok || !e.IsDir() {
			continue
		}
		dir := filepath.Join(observerFixtures, e.Name())
		doc, err := readDocument(filepath.Join(dir, FileName))
		if err != nil {
			t.Fatalf("fixture %s: %v", e.Name(), err)
		}
		addViews(dir, doc)
	}
	return files
}

// TestObserverFixtures compares the fixture pairs of test90's observer
// with the documents and the views that the store writes of them (go test
// -update writes them).
func TestObserverFixtures(t *testing.T) {
	files := observerFiles(t)
	for _, path := range slices.Sorted(maps.Keys(files)) {
		data := files[path]
		if *update {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Error(err)
			continue
		}
		if !bytes.Equal(data, want) {
			t.Errorf("%s is not what the store writes (go test -update writes it)", path)
		}
	}
}
