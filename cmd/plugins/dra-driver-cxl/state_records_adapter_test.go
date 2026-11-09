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
	"path/filepath"
	"slices"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
)

// recordBuilder collects the records that the content of state files
// maps to, and adds them to a document.
type recordBuilder struct {
	preps   []*state.Preparation
	byUID   map[string]*state.Preparation
	grants  []*state.Grant
	byRef   map[state.GrantRef]*state.Grant
	memdevs []*state.Memdev
	regions []*state.Region
	// next is the next negative result index of a claim, for a use of a
	// memdev that no prepared result names.
	next map[string]int
	// daxUses and mountUses are what the grants got of the dax devices and
	// node mounts of their regions, added to the region records last.
	daxUses   []daxUse
	mountUses []mountUse
}

// daxUse is a dax device of a region that a grant got.
type daxUse struct {
	ref    state.GrantRef
	region state.RegionRef
	dax    string
	dev    state.DevNumbers
	mode   string
}

// mountUse is a node mount of a region that a grant uses.
type mountUse struct {
	ref                state.GrantRef
	region             state.RegionRef
	access             state.Access
	path, loop, fsType string
	writer             bool
}

// newRecordBuilder returns an empty builder.
func newRecordBuilder() *recordBuilder {
	return &recordBuilder{
		byUID: map[string]*state.Preparation{},
		byRef: map[state.GrantRef]*state.Grant{},
		next:  map[string]int{},
	}
}

// useDax notes the dax device dax of the region of the grant g, with its
// device numbers, for the region's record.
func (b *recordBuilder) useDax(g *state.Grant, dax string, dev state.DevNumbers) {
	if dax != "" && g.Got.Region != "" {
		b.daxUses = append(b.daxUses, daxUse{ref: g.Ref, region: g.Got.Region, dax: dax, dev: dev, mode: string(g.Asked.Mode)})
	}
}

// orphanDax adds the dax device of a use s of no claim to the record of its
// region, without users.
func (b *recordBuilder) orphanDax(region state.RegionRef, s *localSlice) {
	for _, r := range b.regions {
		if r.Ref() != region || r.DaxDevice(s.Dax) != nil {
			continue
		}
		st, driver := state.DaxDeviceDax, state.DriverDeviceDax
		if s.Mode == api.ModeNUMA {
			st, driver = state.DaxKmemOnline, state.DriverKmem
		}
		r.DaxDevices = append(r.DaxDevices, state.DaxDevice{Name: s.Dax, Size: s.Size, State: st, Driver: driver,
			Dev: state.DevNumbers{Major: s.Major, Minor: s.Minor}})
	}
}

// useMount notes the node mount of the grant g at path, with its loop
// device and filesystem type, for the record of the grant's region.
func (b *recordBuilder) useMount(g *state.Grant, path, loop, fsType string) {
	if path != "" && g.Got.Region != "" && g.Got.Mount != "" {
		b.mountUses = append(b.mountUses, mountUse{ref: g.Ref, region: g.Got.Region, access: g.Got.Mount,
			path: path, loop: loop, fsType: fsType, writer: !g.Asked.ReadOnly})
	}
}

// applyUses adds the noted dax devices and node mounts to the records of
// their regions.
func (b *recordBuilder) applyUses() {
	region := func(ref state.RegionRef) *state.Region {
		for _, r := range b.regions {
			if r.Ref() == ref {
				return r
			}
		}
		return nil
	}
	for _, u := range b.daxUses {
		reg := region(u.region)
		if reg == nil {
			continue
		}
		d := reg.DaxDevice(u.dax)
		if d == nil {
			st, driver := state.DaxDeviceDax, state.DriverDeviceDax
			if u.mode == api.ModeNUMA {
				st, driver = state.DaxKmemOnline, state.DriverKmem
			}
			reg.DaxDevices = append(reg.DaxDevices, state.DaxDevice{Name: u.dax, State: st, Driver: driver})
			d = &reg.DaxDevices[len(reg.DaxDevices)-1]
		}
		if d.Dev.IsZero() {
			d.Dev = u.dev
		}
		if !slices.Contains(d.Users, u.ref) {
			d.Users = append(d.Users, u.ref)
		}
	}
	for _, u := range b.mountUses {
		reg := region(u.region)
		if reg == nil {
			continue
		}
		m := reg.Mount(u.access)
		if m == nil {
			reg.Mounts = append(reg.Mounts, state.Mount{Access: u.access, Path: u.path, Loop: u.loop, FsType: u.fsType, State: state.MountedRO})
			m = &reg.Mounts[len(reg.Mounts)-1]
		}
		if u.writer {
			m.Writer, m.State = true, state.MountedRW
		}
		if !slices.Contains(m.Users, u.ref) {
			m.Users = append(m.Users, u.ref)
		}
	}
}

// addTo adds the collected records to doc.
func (b *recordBuilder) addTo(doc *store.Document) {
	b.applyUses()
	for _, p := range b.preps {
		doc.Preparations = append(doc.Preparations, *p)
	}
	for _, g := range b.grants {
		doc.Grants = append(doc.Grants, *g)
	}
	for _, m := range b.memdevs {
		doc.Memdevs = append(doc.Memdevs, *m)
	}
	for _, r := range b.regions {
		doc.Regions = append(doc.Regions, *r)
	}
}

// preparation returns the preparation of the claim uid, made with p when
// the builder has none.
func (b *recordBuilder) preparation(uid string, p state.Preparation) *state.Preparation {
	if have := b.byUID[uid]; have != nil {
		return have
	}
	b.preps = append(b.preps, &p)
	b.byUID[uid] = &p
	return &p
}

// grant returns the grant ref, made with g when the builder has none.
func (b *recordBuilder) grant(ref state.GrantRef, g state.Grant) *state.Grant {
	if have := b.byRef[ref]; have != nil {
		return have
	}
	g.Ref = ref
	b.grants = append(b.grants, &g)
	b.byRef[ref] = &g
	return &g
}

// request returns the request of the result of a grant, "" for none.
func (b *recordBuilder) request(ref state.GrantRef) string {
	if p := b.byUID[ref.Claim]; p != nil {
		for _, r := range p.Results {
			if r.Grant != nil && *r.Grant == ref {
				return r.Request
			}
		}
	}
	return ""
}

// newRef returns a reference to a grant of the claim uid with a negative
// result index, unique in the claim.
func (b *recordBuilder) newRef(uid string) state.GrantRef {
	n := b.next[uid] - 1
	b.next[uid] = n
	return state.GrantRef{Claim: uid, Result: n}
}

// memdev returns the memdev record of the serial, made with m when the
// builder has none, else with the name and facts of m added.
func (b *recordBuilder) memdev(m state.Memdev) *state.Memdev {
	for _, have := range b.memdevs {
		if have.Serial == m.Serial {
			if have.Name == "" {
				have.Name = m.Name
			}
			have.Facts.Shared = have.Facts.Shared || m.Facts.Shared
			have.Facts.Persistent = have.Facts.Persistent || m.Facts.Persistent
			if have.Facts.NumaAffinity == nil {
				have.Facts.NumaAffinity = m.Facts.NumaAffinity
			}
			return have
		}
	}
	b.memdevs = append(b.memdevs, &m)
	return &m
}

// region returns the region record of the reference of r, made with r when
// the builder has none, and lists it among the regions of the memdev m.
func (b *recordBuilder) region(r state.Region, m *state.Memdev) *state.Region {
	ref := r.Ref()
	if !slices.Contains(m.Regions, ref) {
		m.Regions = append(m.Regions, ref)
	}
	for _, have := range b.regions {
		if have.Ref() == ref {
			return have
		}
	}
	b.regions = append(b.regions, &r)
	return &r
}

// removeDriverRecords removes from doc the records of a driver's state
// files: its preparations and their grants, the memdevs of the source and
// their grants, and the regions on those memdevs.
func removeDriverRecords(doc *store.Document, driver string, source state.Source) {
	grants := map[state.GrantRef]bool{}
	doc.Preparations = slices.DeleteFunc(doc.Preparations, func(p state.Preparation) bool {
		if p.Driver != driver {
			return false
		}
		for _, r := range p.Results {
			if r.Grant != nil {
				grants[*r.Grant] = true
			}
		}
		return true
	})
	serials := map[state.Serial]bool{}
	doc.Memdevs = slices.DeleteFunc(doc.Memdevs, func(m state.Memdev) bool {
		if m.Source != source {
			return false
		}
		serials[m.Serial] = true
		for _, ref := range m.Grants {
			grants[ref] = true
		}
		return true
	})
	doc.Regions = slices.DeleteFunc(doc.Regions, func(r state.Region) bool {
		return r.Ours() && slices.ContainsFunc(r.Targets, func(s state.Serial) bool { return serials[s] })
	})
	doc.Grants = slices.DeleteFunc(doc.Grants, func(g state.Grant) bool { return grants[g.Ref] })
}

// grantKind returns the kind of a grant on a memdev that is shared or of
// persistent memory.
func grantKind(shared, persistent bool) state.GrantKind {
	switch {
	case persistent:
		return state.KindPersistent
	case shared:
		return state.KindShared
	}
	return state.KindExclusive
}

// parseSerial returns the serial of 0x hex or decimal text, 0 for an
// invalid one.
func parseSerial(text string) state.Serial {
	v, err := api.ParseSerial(text)
	if err != nil {
		return 0
	}
	return state.Serial(v)
}

// baseName returns the last element of a path, "" for "".
func baseName(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}

// blockDevice returns the block device of a name and numbers, nil if none
// is set.
func blockDevice(name string, major, minor int) *state.BlockDevice {
	if name == "" && major == 0 && minor == 0 {
		return nil
	}
	return &state.BlockDevice{Name: name, Dev: state.DevNumbers{Major: major, Minor: minor}}
}

// grantLends assigns the lend of a companion claim to its grants in result
// order: the lease and requester to each, the lent NUMA nodes to the numa
// grants with a node in turn, the lease binds to the fs grants in turn
// (the last one to the rest). prepared lends what Got records; a record of
// a Prepare that did not finish lends only its intent.
type grantLends struct {
	lend     *lendRecord
	prepared bool
	node     int
	mount    int
}

// assign gives the grant g of a device in mode with the NUMA node its part
// of the lend.
func (l *grantLends) assign(g *state.Grant, mode string, node int) {
	if l.lend == nil {
		return
	}
	gl := &state.GrantLend{
		Lease:     l.lend.Lease,
		Pod:       state.PodRef(l.lend.Pod),
		Container: l.lend.Container,
		FsDir:     l.lend.FsDir,
		Name:      l.lend.Name,
	}
	if mode == api.ModeNUMA && node >= 0 && l.node < len(l.lend.NumaNodes) {
		gl.NumaNode = state.NumaNodePtr(l.lend.NumaNodes[l.node])
		l.node++
	}
	intent := *gl
	g.Intent.Lend = &intent
	if l.prepared {
		g.Got.Lend = gl
	}
	if mode == api.ModeFs && len(l.lend.Mounts) > 0 {
		target := l.lend.Mounts[min(l.mount, len(l.lend.Mounts)-1)]
		l.mount++
		g.Intent.BindTarget = target
		if l.prepared {
			g.Got.Bind = &state.Bind{Target: target, State: state.BindBound}
		}
	}
}
