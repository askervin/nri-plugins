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

package state

import (
	"fmt"
	"slices"
	"strings"
)

// Violation is a record that breaks an invariant.
type Violation struct {
	Invariant string
	Record    string
	Text      string
}

// leaseClaimMissing is the text of the violation of a lease result of a
// prepared claim whose lease claim has no record.
const leaseClaimMissing = "lease claim %s has no record"

// LeaseClaimMissing tells whether a violation is that of a lease result of
// a prepared claim whose lease claim has no record: the claim's Unprepare
// closes its lease claim before its preparation turns UNPREPARING.
func LeaseClaimMissing(v Violation) bool {
	prefix, suffix, _ := strings.Cut(leaseClaimMissing, "%s")
	return v.Invariant == "records" && strings.HasPrefix(v.Record, "preparation ") &&
		strings.HasPrefix(v.Text, prefix) && strings.HasSuffix(v.Text, suffix)
}

// String returns the violation in words.
func (v Violation) String() string {
	return fmt.Sprintf("%s: %s: %s", v.Invariant, v.Record, v.Text)
}

// addFunc adds a violation by a record.
type addFunc func(record, format string, args ...any)

// Invariant is a predicate over the records alone.
type Invariant struct {
	Name  string
	Text  string
	check func(r *Records, add addFunc)
}

// DocumentInvariants are the invariants over the records alone; the engine
// checks the ones that also need the kernel's view.
var DocumentInvariants = []Invariant{
	{
		Name: "records",
		Text: "Every record has a state of its table that a stored record may have, and a unique identity. " +
			"Every region of ours is one Region record, referenced by every memdev in its Targets, and every " +
			"region a memdev references is a record of ours that targets it; a FOREIGN region is owned by no one. " +
			"Every grant belongs to one result of one preparation and is listed by the memdev of its serial " +
			"(except the grants of a PREPARED_STALE preparation); what Got names lists the grant among its users, " +
			"and every user of a dax device or a node mount names it back; a grant result names a grant record, " +
			"but of a PREPARING or UNPREPARING preparation (not journaled yet, or released before the front-end's " +
			"commit). A PREPARED preparation's grants are " +
			"REALISED, a PREPARED_UNRESTORED one's REALISED or REALISED_UNRESTORED, and the lease claim of their " +
			"lease results exists unless the claim's Unprepare runs (it closes the lease claim before the " +
			"preparation turns UNPREPARING; the engine leaves this rule to the lease broker). A node mount is MOUNTED_RW iff a writer uses it. A lease lends only while READY, " +
			"releasing or FAILED.",
		check: checkRecords,
	},
	{
		Name: "users",
		Text: "Between requests and after the recovery, every region of ours is OWNED, KEPT or HOLLOW_OWNED, and " +
			"every dax device of a region of ours that is OWNED or KEPT and is not the seed has a user grant that is " +
			"REALISED, REALISED_UNRESTORED or RELEASING, or is the Whole device of a KEPT region, of a memdev that " +
			"is IDLE_KEPT, or of a region that a grant of a Prepare that did not finish names, or has as its user a " +
			"grant of a Prepare that did not finish of a numa companion or of a KEPT preparation (kept for its " +
			"Unprepare); the recovery deletes the others, those of a HOLLOW_OWNED region go with it.",
		check: checkUsers,
	},
	{
		Name: "journaled",
		Text: "Every object that the driver created lies inside a journaled container: a region of ours targets " +
			"memdevs with a record; the region, bind target and lend of a grant's Got are named by its Intent; " +
			"a node mount's path is the Intent of a user grant or a Stale entry of its memdev.",
		check: checkJournaled,
	},
}

// Check returns the violations of the document invariants by the records.
func Check(r *Records) []Violation {
	var out []Violation
	for _, inv := range DocumentInvariants {
		inv.check(r, func(record, format string, args ...any) {
			out = append(out, Violation{Invariant: inv.Name, Record: record, Text: fmt.Sprintf(format, args...)})
		})
	}
	return out
}

// CheckStates returns an error that names the first record whose state is
// not one that a stored record may have, nil if there is none.
func CheckStates(r *Records) error {
	var err error
	checkStates(r, func(record, format string, args ...any) {
		if err == nil {
			err = fmt.Errorf("%s: %s", record, fmt.Sprintf(format, args...))
		}
	})
	return err
}

// The states that a record in the store may have, by table; the others
// are defined next to their tables.
var (
	memdevStored     = list(MemdevActive, MemdevIdleKept, MemdevGone)
	daxDeviceStored  = list(DaxCreating, DaxSized, DaxDeviceDax, DaxKmemOffline, DaxKmemOnline, DaxReleasing, DaxSeed)
	mountStored      = list(MountedRO, MountedRW, MountForeign, MountUnrestored, MountStale)
	bindStored       = list(BindAbsent, BindBound, BindStale, BindForeign, BindOtherClaim)
	leaseClaimStored = list(LeaseClaimOpen, LeaseClaimOpenNoListener, LeaseClaimClosing)
	provenanceStored = list(ProvenanceHeld, ProvenanceLocal, ProvenancePool)
	lendingLeases    = list(LeaseReady, LeaseReleasing, LeaseReleasingBusy, LeaseFailed)
)

// checkRecords adds the violations of record consistency.
func checkRecords(r *Records, add addFunc) {
	checkStates(r, add)
	checkUnique(r, add)
	checkRegionOwners(r, add)
	checkRegionUsers(r, add)
	checkMemdevRefs(r, add)
	for i := range r.Grants {
		checkGrant(r, &r.Grants[i], add)
	}
	for i := range r.Preparations {
		checkPreparation(r, &r.Preparations[i], add)
	}
	checkWritersAndLends(r, add)
}

// stored adds the records of a section whose state is not one of stored.
func stored[T any, S comparable](add addFunc, records []T, allowed []S, id func(*T) string, state func(*T) S) {
	for i := range records {
		if s := state(&records[i]); !slices.Contains(allowed, s) {
			add(id(&records[i]), "state %q is not one of a stored record", fmt.Sprint(s))
		}
	}
}

// checkStates adds the records whose state a stored record may not have.
func checkStates(r *Records, add addFunc) {
	stored(add, r.Preparations, preparationStored, preparationID, func(p *Preparation) PreparationState { return p.State })
	stored(add, r.Grants, grantStored, grantID, func(g *Grant) GrantState { return g.State })
	stored(add, r.Memdevs, memdevStored, memdevID, func(m *Memdev) MemdevState { return m.State })
	stored(add, r.Regions, regionStored, regionID, func(reg *Region) RegionState { return reg.State })
	stored(add, r.Leases, leaseStored, func(l *Lease) string { return "lease " + l.ID },
		func(l *Lease) LeaseState { return l.State })
	stored(add, r.LeaseClaims, leaseClaimStored, func(c *LeaseClaim) string { return "lease claim " + c.UID },
		func(c *LeaseClaim) LeaseClaimState { return c.State })
	stored(add, r.Provenance, provenanceStored, func(p *Provenance) string { return "provenance " + p.Serial.String() },
		func(p *Provenance) ProvenanceState { return p.State })
	for i := range r.Grants {
		if b := r.Grants[i].Got.Bind; b != nil && !slices.Contains(bindStored, b.State) {
			add(grantID(&r.Grants[i]), "bind state %q is not one of a stored record", b.State)
		}
	}
	for i := range r.Regions {
		reg := &r.Regions[i]
		stored(add, reg.DaxDevices, daxDeviceStored, func(d *DaxDevice) string { return regionID(reg) + " dax device " + d.Name },
			func(d *DaxDevice) DaxDeviceState { return d.State })
		stored(add, reg.Mounts, mountStored, func(m *Mount) string { return regionID(reg) + " mount " + m.Path },
			func(m *Mount) MountState { return m.State })
	}
}

// The names of records in violations.
func preparationID(p *Preparation) string { return "preparation " + p.Driver + "/" + p.UID }
func grantID(g *Grant) string             { return "grant " + g.Ref.String() }
func memdevID(m *Memdev) string           { return "memdev " + m.Serial.String() }
func regionID(r *Region) string           { return "region " + string(r.Ref()) }

// checkUnique adds the identities that more than one record of a section
// has.
func checkUnique(r *Records, add addFunc) {
	unique(add, r.Preparations, preparationID)
	unique(add, r.Grants, grantID)
	unique(add, r.Memdevs, memdevID)
	unique(add, r.Regions, regionID)
	unique(add, r.Leases, func(l *Lease) string { return "lease " + l.ID })
	unique(add, r.LeaseClaims, func(c *LeaseClaim) string { return "lease claim " + c.UID })
	unique(add, r.Provenance, func(p *Provenance) string { return "provenance " + p.Serial.String() })
	unique(add, r.Steered, func(s *Steered) string { return "steered " + s.Container })
}

// unique adds the identities that more than one record of the section has.
func unique[T any](add addFunc, records []T, id func(*T) string) {
	seen := map[string]bool{}
	for i := range records {
		k := id(&records[i])
		if seen[k] {
			add(k, "more than one record")
		}
		seen[k] = true
	}
}

// checkRegionOwners adds the regions whose owner and state disagree, that
// have no name, and the target memdevs that do not reference a region of
// ours.
func checkRegionOwners(r *Records, add addFunc) {
	for i := range r.Regions {
		reg := &r.Regions[i]
		if (reg.State == RegionForeign) != (reg.Owner == OwnerForeign) {
			add(regionID(reg), "state %s with owner %q", reg.State, reg.Owner)
		}
		if reg.Ref() == "" {
			add(regionID(reg), "no name and no noted name")
		}
		if !reg.Ours() {
			continue
		}
		for _, serial := range reg.Targets {
			if m := r.Memdev(serial); m != nil && !m.HasRegion(reg.Ref()) {
				add(regionID(reg), "target memdev %s does not reference it", serial)
			}
		}
	}
}

// checkRegionUsers adds the users of the dax devices and node mounts of
// regions of ours that do not use them.
func checkRegionUsers(r *Records, add addFunc) {
	for i := range r.Regions {
		reg := &r.Regions[i]
		if !reg.Ours() {
			continue
		}
		for _, d := range reg.DaxDevices {
			for _, u := range d.Users {
				if g := r.Grant(u); g == nil || g.Got.Region != reg.Ref() || g.Got.Dax != d.Name {
					add(regionID(reg), "dax device %s: user %s does not use it", d.Name, u)
				}
			}
		}
		for _, m := range reg.Mounts {
			for _, u := range m.Users {
				if g := r.Grant(u); g == nil || g.Got.Region != reg.Ref() || g.Got.Mount != m.Access {
					add(regionID(reg), "mount %s: user %s does not use it", m.Path, u)
				}
			}
		}
	}
}

// checkMemdevRefs adds the regions and grants that memdevs reference but
// that are not theirs.
func checkMemdevRefs(r *Records, add addFunc) {
	for i := range r.Memdevs {
		m := &r.Memdevs[i]
		for _, ref := range append(slices.Clone(m.Regions), m.Hollow...) {
			reg := r.Region(ref)
			switch {
			case reg == nil:
				add(memdevID(m), "region %s has no record", ref)
			case !reg.Ours() || !reg.TargetsSerial(m.Serial):
				add(memdevID(m), "region %s is not one of ours on it", ref)
			}
		}
		for _, ref := range m.Grants {
			if g := r.Grant(ref); g == nil || g.Serial != m.Serial {
				add(memdevID(m), "grant %s is not one of its grants", ref)
			}
		}
	}
}

// checkGrant adds the violations of the references of a grant: its
// preparation result, its memdev, and what its Got names.
func checkGrant(r *Records, g *Grant, add addFunc) {
	owners := 0
	var prep *Preparation
	for i := range r.Preparations {
		for _, res := range r.Preparations[i].Results {
			if res.Grant != nil && *res.Grant == g.Ref {
				owners++
				prep = &r.Preparations[i]
			}
		}
	}
	if owners != 1 {
		add(grantID(g), "belongs to %d preparation results", owners)
	}
	if prep == nil || prep.State != PreparationStale {
		if m := r.Memdev(g.Serial); m == nil || !m.HasGrant(g.Ref) {
			add(grantID(g), "memdev %s does not list it", g.Serial)
		}
	}
	checkGot(r, g, add)
}

// checkGot adds the objects that a grant's Got names and that do not list
// the grant.
func checkGot(r *Records, g *Grant, add addFunc) {
	if g.Got.Region == "" {
		if g.Got.Dax != "" || g.Got.Mount != "" {
			add(grantID(g), "uses a dax device or a mount without a region")
		}
		return
	}
	reg := r.Region(g.Got.Region)
	if reg == nil || !reg.Ours() || !reg.TargetsSerial(g.Serial) {
		add(grantID(g), "region %s is not one of ours on its memdev", g.Got.Region)
		return
	}
	if g.Got.Dax != "" {
		if d := reg.DaxDevice(g.Got.Dax); d == nil || !slices.Contains(d.Users, g.Ref) {
			add(grantID(g), "dax device %s does not list it", g.Got.Dax)
		}
	}
	if g.Got.Mount != "" {
		if m := reg.Mount(g.Got.Mount); m == nil || !slices.Contains(m.Users, g.Ref) {
			add(grantID(g), "mount %s does not list it", g.Got.Mount)
		}
	}
}

// checkPreparation adds the violations of the results of a preparation.
func checkPreparation(r *Records, p *Preparation, add addFunc) {
	seen := map[int]bool{}
	for i := range p.Results {
		res := &p.Results[i]
		if seen[res.Index] {
			add(preparationID(p), "result %d more than once", res.Index)
		}
		seen[res.Index] = true
		if n := resultParts(res); n != 1 || !resultKindSet(res) {
			add(preparationID(p), "result %d of kind %q has %d parts", res.Index, res.Kind, n)
			continue
		}
		switch res.Kind {
		case ResultGrant:
			checkGrantResult(r, p, res, add)
		case ResultLeaseClaim:
			if (p.State == PreparationPrepared || p.State == PreparationUnrestored) && r.LeaseClaim(res.LeaseClaim.UID) == nil {
				add(preparationID(p), leaseClaimMissing, res.LeaseClaim.UID)
			}
		}
	}
}

// checkGrantResult adds the violations of a result of kind grant: it names
// the grant of the claim with its index, and the grant's state fits the
// preparation's.
func checkGrantResult(r *Records, p *Preparation, res *Result, add addFunc) {
	if *res.Grant != (GrantRef{Claim: p.UID, Result: res.Index}) {
		add(preparationID(p), "result %d names grant %s", res.Index, res.Grant)
	}
	g := r.Grant(*res.Grant)
	switch {
	case g == nil && (p.State == PreparationPreparing || p.State == PreparationUnpreparing):
		// not journaled yet, or released by a rollback, the recovery or
		// the Unprepare before the front-end's commit
	case g == nil:
		add(preparationID(p), "grant %s has no record", res.Grant)
	case p.State == PreparationPrepared && g.State != GrantRealised:
		add(preparationID(p), "PREPARED with grant %s %s", g.Ref, g.State)
	case p.State == PreparationUnrestored && g.State != GrantRealised && g.State != GrantUnrestored:
		add(preparationID(p), "PREPARED_UNRESTORED with grant %s %s", g.Ref, g.State)
	}
}

// resultParts returns the number of the parts of a result that are set.
func resultParts(res *Result) int {
	n := 0
	for _, set := range []bool{res.Grant != nil, res.Region != nil, res.DRAM != nil, res.LeaseClaim != nil} {
		if set {
			n++
		}
	}
	return n
}

// resultKindSet tells whether the part of the result's kind is set.
func resultKindSet(res *Result) bool {
	switch res.Kind {
	case ResultGrant:
		return res.Grant != nil
	case ResultRegion:
		return res.Region != nil
	case ResultDRAM:
		return res.DRAM != nil
	case ResultLeaseClaim:
		return res.LeaseClaim != nil
	}
	return false
}

// checkWritersAndLends adds the node mounts whose state and writer
// disagree and the leases that lend in a state that does not.
func checkWritersAndLends(r *Records, add addFunc) {
	for i := range r.Regions {
		reg := &r.Regions[i]
		for _, m := range reg.Mounts {
			if (m.State == MountedRW) != m.Writer {
				add(regionID(reg), "mount %s is %s with writer %v", m.Path, m.State, m.Writer)
			}
		}
	}
	for _, l := range r.Leases {
		if l.Lend != nil && !slices.Contains(lendingLeases, l.State) {
			add("lease "+l.ID, "lends while %s", l.State)
		}
	}
}

// checkUsers adds the regions of ours that are not at rest and their dax
// devices without a realised or releasing user that are not kept.
func checkUsers(r *Records, add addFunc) {
	for i := range r.Regions {
		reg := &r.Regions[i]
		if !reg.Ours() {
			continue
		}
		if reg.State == RegionNoted || reg.State == RegionCreating {
			add(regionID(reg), "%s between requests", reg.State)
		}
		if reg.State == RegionHollowOwned {
			// its dax devices go with it when it is deleted
			continue
		}
		for _, d := range reg.DaxDevices {
			if d.State == DaxSeed || (d.Whole && (kept(r, reg) || unfinished(r, reg))) || used(r, &d) || r.UnfinishedUser(&d) {
				continue
			}
			add(regionID(reg), "dax device %s has no realised or releasing user", d.Name)
		}
	}
}

// used tells whether a user of the dax device is REALISED,
// REALISED_UNRESTORED or RELEASING.
func used(r *Records, d *DaxDevice) bool {
	for _, u := range d.Users {
		if g := r.Grant(u); g != nil && (g.State == GrantRealised || g.State == GrantUnrestored || g.State == GrantReleasing) {
			return true
		}
	}
	return false
}

// UnfinishedUser tells whether a user of the dax device is a grant of a
// Prepare that did not finish (JOURNALED, REALISING) that the start kept
// with its part for its Unprepare: one of a numa companion, or one of a
// KEPT preparation whose release at the start failed.
func (r *Records) UnfinishedUser(d *DaxDevice) bool {
	for _, u := range d.Users {
		g := r.Grant(u)
		if g == nil || (g.State != GrantJournaled && g.State != GrantRealising) {
			continue
		}
		if p := r.PreparationOf(g.Ref); (g.Intent.Lend != nil && g.Asked.Mode == ModeNUMA) || (p != nil && p.State == PreparationKept) {
			return true
		}
	}
	return false
}

// RegionInMaking tells whether the region reg of the local memdev m is
// still being made for a Prepare: NOTED or CREATING, or a ram region OWNED
// while every grant of the memdev is of a Prepare that did not finish
// (JOURNALED, REALISING) and got no part of it yet (it is set up, probed and
// zeroed before its first part).
func (r *Records) RegionInMaking(m *Memdev, reg *Region) bool {
	switch {
	case reg.State == RegionNoted || reg.State == RegionCreating:
		return true
	case reg.State != RegionOwned || reg.Mode != RegionRam || len(m.Grants) == 0:
		return false
	}
	for _, ref := range m.Grants {
		g := r.Grant(ref)
		if g == nil || (g.State != GrantJournaled && g.State != GrantRealising) || g.Got.Dax != "" {
			return false
		}
	}
	return true
}

// unfinished tells whether a grant of a Prepare that did not finish
// (JOURNALED, REALISING) names the region.
func unfinished(r *Records, reg *Region) bool {
	for i := range r.Grants {
		g := &r.Grants[i]
		if (g.State == GrantJournaled || g.State == GrantRealising) && (g.Got.Region == reg.Ref() || g.Intent.Region == reg.Ref()) {
			return true
		}
	}
	return false
}

// kept tells whether the region is KEPT or a memdev of it is IDLE_KEPT.
func kept(r *Records, reg *Region) bool {
	if reg.State == RegionKept {
		return true
	}
	for _, serial := range reg.Targets {
		if m := r.Memdev(serial); m != nil && m.State == MemdevIdleKept {
			return true
		}
	}
	return false
}

// checkJournaled adds the objects of ours that no intent or record names.
func checkJournaled(r *Records, add addFunc) {
	for i := range r.Regions {
		reg := &r.Regions[i]
		if !reg.Ours() {
			continue
		}
		for _, serial := range reg.Targets {
			if r.Memdev(serial) == nil {
				add(regionID(reg), "target memdev %s has no record", serial)
			}
		}
		for _, m := range reg.Mounts {
			if m.State != MountForeign && !journaledMount(r, reg, &m) {
				add(regionID(reg), "mount %s is named by no intent and no Stale entry", m.Path)
			}
		}
	}
	for i := range r.Grants {
		checkGrantIntent(&r.Grants[i], add)
	}
}

// checkGrantIntent adds the objects of a grant's Got that its Intent does
// not name.
func checkGrantIntent(g *Grant, add addFunc) {
	if g.Got.Region != "" && g.Got.Region != g.Intent.Region {
		add(grantID(g), "region %s, its intent names %q", g.Got.Region, g.Intent.Region)
	}
	if g.Got.Bind != nil && g.Got.Bind.Target != g.Intent.BindTarget {
		add(grantID(g), "bind %s, its intent names %q", g.Got.Bind.Target, g.Intent.BindTarget)
	}
	if l := g.Got.Lend; l != nil {
		il := g.Intent.Lend
		if il == nil || il.Lease != l.Lease || NumaNodeOf(il.NumaNode) != NumaNodeOf(l.NumaNode) {
			add(grantID(g), "lend of lease %s is not its intent", l.Lease)
		}
	}
}

// journaledMount tells whether a user grant's intent or a Stale entry of a
// target memdev names the path of the mount.
func journaledMount(r *Records, reg *Region, m *Mount) bool {
	for _, u := range m.Users {
		if g := r.Grant(u); g != nil && g.Intent.MountPath == m.Path {
			return true
		}
	}
	for _, serial := range reg.Targets {
		if md := r.Memdev(serial); md != nil && slices.Contains(md.Stale, StalePath{Path: m.Path, Kind: StaleMount}) {
			return true
		}
	}
	return false
}
