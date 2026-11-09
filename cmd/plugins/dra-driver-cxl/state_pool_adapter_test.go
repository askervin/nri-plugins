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
	"encoding/json"
	"maps"
	"slices"

	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
)

// preparingPoolClaim is a value of preparingPoolClaims.json: a claim whose
// Prepare did not finish, was kept by its rollback or is of another boot,
// with its devices as far as they are known before they are touched, and
// the lend of a companion claim.
type preparingPoolClaim struct {
	ClaimName string               `json:"claimName"` // namespace/name
	Devices   []preparedPoolDevice `json:"devices"`
	Lend      *lendRecord          `json:"lend,omitempty"`
	// Regions are the regions that the Prepares of the claim create or
	// created, noted before cxl create-region ran.
	Regions []preparingRegion `json:"regions,omitempty"`
	// BootID is the boot id of the kernel of the Prepare, that of Regions
	// and of the nodes of Lend.
	BootID string `json:"bootID,omitempty"`
	// Stale tells why a claim that was prepared is not prepared any more:
	// it was prepared, or its Prepare was cut, in another boot. "" for a
	// Prepare of this boot.
	Stale string `json:"stale,omitempty"`
}

// preparingRegion is a region that a Prepare creates on the memdev with
// the serial under the root decoder; the records do not keep the decoder.
type preparingRegion struct {
	Serial  uint64 `json:"serial"`
	Region  string `json:"region"`
	Decoder string `json:"decoder,omitempty"`
}

// putPool replaces the records of the pool driver in doc with those of
// the content of its state files: the prepared claims
// (preparedPoolClaims.json, PREPARED) and the claims whose Prepare did not
// finish (preparingPoolClaims.json, PREPARING, or PREPARED_STALE with the
// reason of a stale record). A claim that both have is prepared.
func putPool(doc *store.Document, driver string, prepared map[string]*preparedPoolClaim, preparing map[string]*preparingPoolClaim) {
	removeDriverRecords(doc, driver, state.SourcePool)
	b := newRecordBuilder()
	for _, uid := range slices.Sorted(maps.Keys(prepared)) {
		if pc := prepared[uid]; pc != nil {
			addPoolClaim(b, driver, uid, pc.ClaimName, pc.BootID, state.PreparationPrepared, pc.Devices, pc.Result.Devices, pc.Lend)
		}
	}
	for _, uid := range slices.Sorted(maps.Keys(preparing)) {
		rec := preparing[uid]
		if rec == nil || prepared[uid] != nil {
			continue
		}
		st := state.PreparationPreparing
		if rec.Stale != "" {
			st = state.PreparationStale
		}
		p := addPoolClaim(b, driver, uid, rec.ClaimName, rec.BootID, st, rec.Devices, nil, rec.Lend)
		p.Reason = rec.Stale
		addPreparingRegions(b, p, rec.Regions)
	}
	b.addTo(doc)
}

// addPoolClaim adds the preparation in state st of a claim of the pool
// driver with its grants, memdevs and regions; results are the devices of
// its PrepareResult.
func addPoolClaim(b *recordBuilder, driver, uid, claimName, bootID string, st state.PreparationState,
	devs []preparedPoolDevice, results []kubeletplugin.Device, lend *lendRecord) *state.Preparation {
	p := b.preparation(uid, state.Preparation{UID: uid, Driver: driver, ClaimName: claimName, BootID: bootID, State: st, Results: []state.Result{}})
	if lend != nil {
		p.Lease = lend.Lease
	}
	lends := &grantLends{lend: lend, prepared: st == state.PreparationPrepared}
	for j := range devs {
		d := &devs[j]
		ref := state.GrantRef{Claim: uid, Result: d.Result}
		r := state.Result{
			Index: d.Result, Kind: state.ResultGrant, Request: d.Request, Pool: d.Pool, Device: d.Device,
			Settings: d.ResultSettings, Grant: &ref,
		}
		if j < len(results) && results[j].ShareID != nil {
			r.ShareID = string(*results[j].ShareID)
		}
		p.Results = append(p.Results, r)
		g := addPoolGrant(b, ref, d, st)
		lends.assign(g, d.Mode, d.NumaNode)
	}
	return p
}

// addPoolGrant adds the grant ref of a device of the pool driver, its
// memdev and its region.
func addPoolGrant(b *recordBuilder, ref state.GrantRef, d *preparedPoolDevice, st state.PreparationState) *state.Grant {
	gs := state.GrantRealised
	if st != state.PreparationPrepared {
		gs = state.GrantJournaled
	}
	g := b.grant(ref, state.Grant{
		Serial: state.Serial(d.Serial),
		State:  gs,
		Asked: state.Asked{
			Source:   state.SourcePool,
			Kind:     grantKind(d.Shared, d.Persistent),
			Shared:   d.Shared,
			Mode:     state.Mode(d.Mode),
			ReadOnly: d.ReadOnly,
			Access:   state.Access(d.Access),
			FsType:   d.FsType,
			Path:     d.Path,
			Size:     d.Size,
		},
		Got: state.Got{
			Region:      state.RegionRef(d.Region),
			Dax:         d.Dax,
			NumaNode:    state.NumaNodePtr(d.NumaNode),
			Size:        d.Size,
			Namespace:   d.Namespace,
			BlockDevice: blockDevice(d.BlockDevice, d.BlockMajor, d.BlockMinor),
			Mount:       state.Access(d.Access),
		},
		Intent: state.Intent{Region: state.RegionRef(d.Region)},
	})
	m := b.memdev(state.Memdev{
		Serial: g.Serial,
		Name:   d.Memdev,
		Source: state.SourcePool,
		Facts:  state.MemdevFacts{Shared: d.Shared, Persistent: d.Persistent},
		State:  state.MemdevActive,
	})
	m.Grants = append(m.Grants, ref)
	if d.Region != "" {
		r := b.region(state.Region{
			Name: d.Region, Mode: state.RegionRam, Targets: []state.Serial{g.Serial}, Owner: state.OwnerOurs,
			State: state.RegionOwned, SetUp: true,
		}, m)
		if d.Persistent {
			r.Mode = state.RegionPmem
		}
		if d.NdRegion != "" && r.Pmem == nil {
			r.Pmem = &state.Pmem{NdRegion: d.NdRegion, Namespace: d.Namespace, BlockDevice: blockDevice(d.BlockDevice, d.BlockMajor, d.BlockMinor)}
		}
	}
	b.useDax(g, d.Dax, state.DevNumbers{Major: d.DaxMajor, Minor: d.DaxMinor})
	b.useMount(g, d.NodeMount, d.LoopDevice, d.FsType)
	return g
}

// addPreparingRegions adds the regions that a Prepare that did not finish
// created or was creating as the intent of its grant on their memdev.
func addPreparingRegions(b *recordBuilder, p *state.Preparation, regions []preparingRegion) {
	for _, pr := range regions {
		var g *state.Grant
		for _, res := range p.Results {
			if res.Grant != nil && b.byRef[*res.Grant] != nil && b.byRef[*res.Grant].Serial == state.Serial(pr.Serial) {
				g = b.byRef[*res.Grant]
				break
			}
		}
		m := b.memdev(state.Memdev{Serial: state.Serial(pr.Serial), Source: state.SourcePool, State: state.MemdevActive})
		b.region(state.Region{
			NotedName: pr.Region, Mode: state.RegionRam, Targets: []state.Serial{state.Serial(pr.Serial)},
			Owner: state.OwnerOurs, State: state.RegionNoted,
		}, m)
		if g != nil {
			if g.Intent.Region != "" && g.Intent.Region != state.RegionRef(pr.Region) && g.Intent.Region != g.Got.Region {
				g.Intent.Noted = append(g.Intent.Noted, g.Intent.Region)
			}
			g.Intent.Region = state.RegionRef(pr.Region)
		}
	}
}

// preparingContent returns the content of preparingPoolClaims.json of the
// records of the pool driver in doc, for operators and the greps of the
// e2e tests (test90's observer reads preparedPoolClaims.json only): its
// preparations PREPARING, KEPT (a rollback or the start kept what they
// made) and PREPARED_STALE.
func preparingContent(doc *store.Document, opts store.ViewOptions) ([]byte, error) {
	out := map[string]*preparingPoolClaim{}
	for i := range doc.Preparations {
		p := &doc.Preparations[i]
		if p.Driver != opts.PoolDriver || (p.State != state.PreparationPreparing && p.State != state.PreparationKept && p.State != state.PreparationStale) {
			continue
		}
		data, err := store.PoolDevicesContent(doc, p, opts)
		if err != nil {
			return nil, err
		}
		rec := &preparingPoolClaim{ClaimName: p.ClaimName, BootID: p.BootID, Lend: preparingLend(doc, p), Regions: preparingRegions(doc, p)}
		if err := json.Unmarshal(data, &rec.Devices); err != nil {
			return nil, err
		}
		for j := range rec.Devices {
			d := &rec.Devices[j]
			d.Memdev = ""
			if g := doc.Grant(state.GrantRef{Claim: p.UID, Result: d.Result}); g != nil {
				d.Access, d.FsType = string(g.Asked.Access), g.Asked.FsType
				if d.Mode == string(state.ModeNUMA) && d.NumaNode < 0 {
					d.NumaNode = regionNode(doc, g)
				}
			}
		}
		if p.State == state.PreparationStale {
			rec.Stale = p.Reason
			if rec.Stale == "" {
				rec.Stale = "not prepared"
			}
			if doc.BootID != "" {
				rec.BootID = doc.BootID
			}
		}
		out[p.UID] = rec
	}
	return json.MarshalIndent(out, "", "  ")
}

// regionNode returns the NUMA node of the region of a grant, -1 if it has
// none.
func regionNode(doc *store.Document, g *state.Grant) int {
	ref := g.Got.Region
	if ref == "" {
		ref = g.Intent.Region
	}
	if reg := doc.Region(ref); reg != nil {
		return state.NumaNodeOf(reg.NumaNode)
	}
	return -1
}

// preparingLend returns the lend of a companion claim whose Prepare did not
// finish: the intent of its grants.
func preparingLend(doc *store.Document, p *state.Preparation) *lendRecord {
	if p.Lease == "" {
		return nil
	}
	lend := &lendRecord{Lease: p.Lease}
	identity := false
	for _, r := range p.Results {
		if r.Grant == nil || r.Index < 0 {
			continue
		}
		g := doc.Grant(*r.Grant)
		if g == nil || g.Intent.Lend == nil {
			continue
		}
		l := g.Intent.Lend
		if !identity {
			lend.Pod, lend.Container, lend.FsDir, lend.Name = podRef(l.Pod), l.Container, l.FsDir, l.Name
			identity = true
		}
		if l.NumaNode != nil {
			lend.NumaNodes = append(lend.NumaNodes, *l.NumaNode)
		}
		if t := g.Intent.BindTarget; t != "" && !slices.Contains(lend.Mounts, t) {
			lend.Mounts = append(lend.Mounts, t)
		}
	}
	return lend
}

// preparingRegions returns the regions that a Prepare that did not finish
// noted: those of the intents of its grants.
func preparingRegions(doc *store.Document, p *state.Preparation) []preparingRegion {
	var out []preparingRegion
	for _, r := range p.Results {
		if r.Grant == nil || r.Index < 0 {
			continue
		}
		g := doc.Grant(*r.Grant)
		if g == nil {
			continue
		}
		for _, ref := range append(slices.Clone(g.Intent.Noted), g.Intent.Region) {
			if ref == "" || slices.ContainsFunc(out, func(pr preparingRegion) bool { return pr.Region == string(ref) }) {
				continue
			}
			out = append(out, preparingRegion{Serial: uint64(g.Serial), Region: string(ref)})
		}
	}
	return out
}
