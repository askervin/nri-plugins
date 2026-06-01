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

package balloons

import (
	"errors"
	"sort"
	"testing"

	idset "github.com/intel/goresctrl/pkg/utils"

	"github.com/containers/nri-plugins/pkg/sysfs"
	"github.com/containers/nri-plugins/pkg/utils/cpuset"
)

var errFakeSstNoClos = errors.New("fakeSst: no CLOS for CPU")

// --- minimal sysfs.System / CPUPackage / CPU fakes ------------------

// fakePackage implements sysfs.CPUPackage via an embedded nil
// interface. Methods not overridden here panic if called, which is
// the desired guardrail in unit tests.
type fakePackage struct {
	sysfs.CPUPackage
	id   idset.ID
	cpus cpuset.CPUSet
}

func (p *fakePackage) ID() idset.ID         { return p.id }
func (p *fakePackage) CPUSet() cpuset.CPUSet { return p.cpus }

// fakeCPU implements sysfs.CPU likewise.
type fakeCPU struct {
	sysfs.CPU
	id  idset.ID
	pkg idset.ID
}

func (c *fakeCPU) ID() idset.ID        { return c.id }
func (c *fakeCPU) PackageID() idset.ID { return c.pkg }

// fakeSys is a minimal pctSys implementation built from package
// CPU maps.
type fakeSys struct {
	packageCpus map[idset.ID]cpuset.CPUSet // pkgID -> cpus
	cpuPkg      map[int]idset.ID           // cpu -> pkgID
}

func (s *fakeSys) PackageIDs() []idset.ID {
	ids := make([]idset.ID, 0, len(s.packageCpus))
	for id := range s.packageCpus {
		ids = append(ids, id)
	}
	return ids
}

func (s *fakeSys) Package(id idset.ID) sysfs.CPUPackage {
	cpus, ok := s.packageCpus[id]
	if !ok {
		return nil
	}
	return &fakePackage{id: id, cpus: cpus}
}

func (s *fakeSys) CPU(id idset.ID) sysfs.CPU {
	pkg, ok := s.cpuPkg[int(id)]
	if !ok {
		return nil
	}
	return &fakeCPU{id: id, pkg: pkg}
}

func (s *fakeSys) CPUIDs() []idset.ID { return nil }

// newTwoPackageFakeSys returns a fakeSys with two packages of 4 CPUs
// each: pkg0=0..3, pkg1=4..7.
func newTwoPackageFakeSys() *fakeSys {
	return &fakeSys{
		packageCpus: map[idset.ID]cpuset.CPUSet{
			0: cpuset.MustParse("0-3"),
			1: cpuset.MustParse("4-7"),
		},
		cpuPkg: map[int]idset.ID{
			0: 0, 1: 0, 2: 0, 3: 0,
			4: 1, 5: 1, 6: 1, 7: 1,
		},
	}
}

// --- minimal sst fake ------------------------------------------------

// fakeSst implements just the methods that pctAllocator.hints (and
// closCpus) actually call.
type fakeSst struct {
	supported bool
	cpuClos   map[int]int // cpu -> CLOS id
	maxHp     map[int]int // pkgID -> max HP CPUs (missing = "unknown")
	pkgCpus   map[int]cpuset.CPUSet
}

func (s *fakeSst) Supported() bool                                  { return s.supported }
func (s *fakeSst) ClosCount() int                                   { return 4 }
func (s *fakeSst) PackageIDs() []int                                { return nil }
func (s *fakeSst) CPUsOfPackage(int) []int                          { return nil }
func (s *fakeSst) PrepareManagedMode() error                        { return nil }
func (s *fakeSst) ConfigureClos(pctClosConfig) error                { return nil }
func (s *fakeSst) EnableCP() error                                  { return nil }
func (s *fakeSst) AssociateCPUs([]pctClosAssoc) error               { return nil }
func (s *fakeSst) GetCPUClosID(cpu int) (int, error) {
	if clos, ok := s.cpuClos[cpu]; ok {
		return clos, nil
	}
	// Return an error so closCpus skips this CPU rather than
	// treating it as "associated to CLOS 0 by default".
	return -1, errFakeSstNoClos
}

// Punits synthesizes one punit per package whose CPUs come from
// pkgCpus (or maxHp keys if pkgCpus is nil) with MaxHpCpus set
// from the maxHp map. PunitID is always 0 (single punit per pkg
// preserves the legacy per-package test semantics).
func (s *fakeSst) Punits() []pctPunit {
	pkgIDs := map[int]struct{}{}
	for id := range s.pkgCpus {
		pkgIDs[id] = struct{}{}
	}
	for id := range s.maxHp {
		pkgIDs[id] = struct{}{}
	}
	out := make([]pctPunit, 0, len(pkgIDs))
	for id := range pkgIDs {
		cpus, ok := s.pkgCpus[id]
		if !ok {
			// Derive a default cpu range matching newTwoPackageFakeSys layout.
			if id == 0 {
				cpus = cpuset.MustParse("0-3")
			} else if id == 1 {
				cpus = cpuset.MustParse("4-7")
			}
		}
		out = append(out, pctPunit{
			PkgID:     id,
			PunitID:   0,
			CPUs:      cpus,
			MaxHpCpus: s.maxHp[id],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PkgID != out[j].PkgID {
			return out[i].PkgID < out[j].PkgID
		}
		return out[i].PunitID < out[j].PunitID
	})
	return out
}

func (s *fakeSst) GetClosConfig(closID int) (pctClosCfg, bool, error) {
	return pctClosCfg{}, false, nil
}

func (s *fakeSst) Shutdown() error { return nil }

// --- helpers to construct a hand-wired pctAllocator -----------------

func newManagedPctForTest(t *testing.T, classes []*CPUClass, plans map[string]*pctClassPlan,
	allowed cpuset.CPUSet, sys *fakeSys, sst *fakeSst) *pctAllocator {
	t.Helper()
	a := &pctAllocator{
		sys:         sys,
		sst:         sst,
		mode:        pctModeManaged,
		classByName: map[string]*CPUClass{},
		classPlan:   plans,
		allowed:     allowed,
		hpUsed:      map[int]cpuset.CPUSet{},
		hpClasses:   map[string]bool{},
	}
	for _, cc := range classes {
		a.classByName[cc.Name] = cc
		if cc.PctPriority == "high" {
			a.hpClasses[cc.Name] = true
		}
	}
	pctTestWirePunits(a)
	return a
}

// pctTestWirePunits seeds a hand-built pctAllocator's punit caches
// from its sst's Punits(), intersected with allowed. It is the
// test-time equivalent of snapshotPunits() and lets struct-literal
// fixtures exercise the punit-keyed code paths.
func pctTestWirePunits(a *pctAllocator) {
	if a.punitByCpu == nil {
		a.punitByCpu = map[int]int{}
	}
	if a.hpClasses == nil {
		a.hpClasses = map[string]bool{}
	}
	for name, cc := range a.classByName {
		if cc.PctPriority == "high" {
			a.hpClasses[name] = true
		}
	}
	pus := a.sst.Punits()
	a.punits = a.punits[:0]
	for _, pu := range pus {
		cpus := pu.CPUs
		if a.allowed.Size() > 0 {
			cpus = cpus.Intersection(a.allowed)
		}
		if cpus.IsEmpty() {
			continue
		}
		idx := len(a.punits)
		a.punits = append(a.punits, pctPunit{
			PkgID: pu.PkgID, PunitID: pu.PunitID,
			CPUs: cpus, MaxHpCpus: pu.MaxHpCpus,
		})
		for _, c := range cpus.UnsortedList() {
			a.punitByCpu[c] = idx
		}
	}
}

// --- hints() test suite ---------------------------------------------

// TestPctHintsNoClassNoOp covers the "no plan and not managed-with-HP"
// branch where hints() must return an empty AllocationHints.
func TestPctHintsNoClassNoOp(t *testing.T) {
	sys := newTwoPackageFakeSys()
	sst := &fakeSst{supported: true}

	// disabled allocator: hints must short-circuit to empty.
	a := &pctAllocator{sys: sys, sst: sst, mode: pctModeDisabled}
	got := a.hints(AllocationIntent{ClassName: "anything"})
	if len(got.Prefer) != 0 || len(got.Avoid) != 0 {
		t.Errorf("disabled mode: hints=%+v, want empty", got)
	}

	// managed mode with no HP class defined and an unknown
	// className: no prefer, no avoid.
	classes := []*CPUClass{{Name: "lp", PctPriority: "low"}}
	// "lp" is configured but classIsHighPriority is false; still the
	// "anyHighPriorityClassDefined" gate must be false so no Avoid.
	a2 := newManagedPctForTest(t, classes,
		map[string]*pctClassPlan{"lp": {ClosID: 3}},
		cpuset.MustParse("0-7"), sys, sst)
	got = a2.hints(AllocationIntent{ClassName: "unknown-class"})
	if len(got.Avoid) != 0 {
		t.Errorf("no HP class: Avoid=%+v, want empty", got.Avoid)
	}
}

// TestPctHintsAssocOnlyPreferClosCpus covers the "explicit CLOS plan"
// branch in assoc-only mode: hints prefer CPUs already associated to
// the class's CLOS, enabling bin packing.
func TestPctHintsAssocOnlyPreferClosCpus(t *testing.T) {
	sys := newTwoPackageFakeSys()
	sst := &fakeSst{
		supported: true,
		// cpus 2 and 3 already on CLOS 1, others on default CLOS 0.
		cpuClos: map[int]int{2: 1, 3: 1},
	}
	a := &pctAllocator{
		sys:         sys,
		sst:         sst,
		mode:        pctModeAssocOnly,
		classByName: map[string]*CPUClass{"c1": {Name: "c1"}},
		classPlan:   map[string]*pctClassPlan{"c1": {ClosID: 1}},
		allowed:     cpuset.MustParse("0-7"),
		hpUsed:      map[int]cpuset.CPUSet{},
	}
	pctTestWirePunits(a)
	got := a.hints(AllocationIntent{ClassName: "c1"})
	if len(got.Prefer) != 1 {
		t.Fatalf("Prefer count = %d, want 1: got=%+v", len(got.Prefer), got)
	}
	if got.Prefer[0].Name != virtDevSstClosHint(1) {
		t.Errorf("Prefer[0].Name = %q, want %q", got.Prefer[0].Name, virtDevSstClosHint(1))
	}
	want := cpuset.MustParse("2-3")
	if !got.Prefer[0].Cpus.Equals(want) {
		t.Errorf("Prefer[0].Cpus = %s, want %s", got.Prefer[0].Cpus, want)
	}
	if len(got.Avoid) != 0 {
		t.Errorf("assoc-only mode must not emit Avoid hints: %+v", got.Avoid)
	}
}

// TestPctHintsHighPriorityReserveAndClosCpus covers the HP class
// branch: hints contain (a) CPUs already on the HP CLOS for bin
// packing and (b) the HP-reserve preference (largest-room package).
func TestPctHintsHighPriorityReserveAndClosCpus(t *testing.T) {
	sys := newTwoPackageFakeSys()
	sst := &fakeSst{
		supported: true,
		// cpu 0 already on CLOS 0 (HP).
		cpuClos: map[int]int{0: 0},
		// max_hp_cpus = 2 per package on both packages.
		maxHp: map[int]int{0: 2, 1: 2},
	}
	a := &pctAllocator{
		sys:  sys,
		sst:  sst,
		mode: pctModeManaged,
		classByName: map[string]*CPUClass{
			"hp": {Name: "hp", PctPriority: "high"},
		},
		classPlan: map[string]*pctClassPlan{"hp": {ClosID: 0}},
		allowed:   cpuset.MustParse("0-7"),
		// pkg0 has 1 HP cpu already used (cpu 0).
		hpUsed: map[int]cpuset.CPUSet{0: cpuset.MustParse("0")},
	}
	pctTestWirePunits(a)

	// Free pool excludes the already-used cpu 0.
	free := cpuset.MustParse("1-7")
	got := a.hints(AllocationIntent{
		ClassName:      "hp",
		CurrentCpus:    cpuset.New(),
		FreeCpus:       free,
		RequestedCount: 1,
	})

	// Expect two Prefer hints: CLOS 0 members (cpu 0) and HP reserve
	// (the package with more HP room — pkg1, since pkg0 has 2-1=1
	// room left and pkg1 has 2-0=2 room left).
	if len(got.Prefer) != 2 {
		t.Fatalf("Prefer count = %d, want 2: got=%+v", len(got.Prefer), got.Prefer)
	}
	if got.Prefer[0].Name != virtDevSstClosHint(0) {
		t.Errorf("Prefer[0].Name = %q, want %q", got.Prefer[0].Name, virtDevSstClosHint(0))
	}
	if got.Prefer[1].Name != virtDevSstHpReserveHint {
		t.Errorf("Prefer[1].Name = %q, want %q", got.Prefer[1].Name, virtDevSstHpReserveHint)
	}
	wantReserve := cpuset.MustParse("4-7")
	if !got.Prefer[1].Cpus.Equals(wantReserve) {
		t.Errorf("HP reserve = %s, want %s (largest-room package)", got.Prefer[1].Cpus, wantReserve)
	}
	// HP-class hints must NOT carry an Avoid (HP picks first).
	if len(got.Avoid) != 0 {
		t.Errorf("HP class: Avoid=%+v, want empty", got.Avoid)
	}
}

// TestPctHintsManagedNonHpAvoidsHpInUse covers the managed-mode
// non-HP-class branch: hints must Avoid CPUs on packages currently
// hosting HP balloons, so LP/idle classes do not steal HP turbo
// budget. THIS BRANCH IS NOT COVERED IN test19 e2e.
func TestPctHintsManagedNonHpAvoidsHpInUse(t *testing.T) {
	sys := newTwoPackageFakeSys()
	sst := &fakeSst{
		supported: true,
		cpuClos:   map[int]int{},
		maxHp:     map[int]int{0: 2, 1: 2},
	}
	a := &pctAllocator{
		sys:  sys,
		sst:  sst,
		mode: pctModeManaged,
		classByName: map[string]*CPUClass{
			"hp": {Name: "hp", PctPriority: "high"},
			"lp": {Name: "lp", PctPriority: "low"},
		},
		classPlan: map[string]*pctClassPlan{
			"hp": {ClosID: 0},
			"lp": {ClosID: 3},
		},
		allowed: cpuset.MustParse("0-7"),
		// pkg0 hosts HP cpu 1.
		hpUsed: map[int]cpuset.CPUSet{0: cpuset.MustParse("1")},
	}
	pctTestWirePunits(a)
	got := a.hints(AllocationIntent{
		ClassName: "lp",
		FreeCpus:  cpuset.MustParse("2-7"),
	})

	// LP has a CLOS plan, so Prefer must include CLOS 3 (empty in
	// our setup) — but only if any CPU is currently on CLOS 3. With
	// none, classClosID still matches but closCpus returns empty
	// and the Prefer entry is skipped. So len(Prefer) == 0.
	if len(got.Prefer) != 0 {
		t.Errorf("Prefer = %+v, want empty (no LP CPUs currently on CLOS 3)", got.Prefer)
	}
	// Avoid must list pkg0's full CPU set (where HP is in use).
	if len(got.Avoid) != 1 {
		t.Fatalf("Avoid count = %d, want 1: got=%+v", len(got.Avoid), got.Avoid)
	}
	if got.Avoid[0].Name != virtDevSstHpInUseHint {
		t.Errorf("Avoid[0].Name = %q, want %q", got.Avoid[0].Name, virtDevSstHpInUseHint)
	}
	wantAvoid := cpuset.MustParse("0-3") // entire pkg0
	if !got.Avoid[0].Cpus.Equals(wantAvoid) {
		t.Errorf("Avoid[0].Cpus = %s, want %s (pkg0 == HP-in-use package)", got.Avoid[0].Cpus, wantAvoid)
	}
}

// TestPctHintsAllowedBoundsResults ensures that even with sst /
// hpUsed pointing at CPUs outside the allowed set, hints honor
// Allowed (via the handler-level intersectHints + pct-internal
// allowed intersections).
func TestPctHintsAllowedBoundsResults(t *testing.T) {
	sys := newTwoPackageFakeSys()
	sst := &fakeSst{
		supported: true,
		cpuClos:   map[int]int{0: 0, 4: 0}, // HP cpus on both packages
		maxHp:     map[int]int{0: 2, 1: 2},
	}
	a := &pctAllocator{
		sys:  sys,
		sst:  sst,
		mode: pctModeManaged,
		classByName: map[string]*CPUClass{
			"hp": {Name: "hp", PctPriority: "high"},
		},
		classPlan: map[string]*pctClassPlan{"hp": {ClosID: 0}},
		// allowed restricts to pkg0 only.
		allowed: cpuset.MustParse("0-3"),
		hpUsed: map[int]cpuset.CPUSet{
			0: cpuset.MustParse("0"),
			1: cpuset.MustParse("4"), // outside allowed
		},
	}
	pctTestWirePunits(a)
	got := a.hints(AllocationIntent{
		ClassName:      "hp",
		FreeCpus:       cpuset.MustParse("1-3"),
		RequestedCount: 1,
	})
	// closCpus walks a.allowed, so cpu 4 is excluded automatically.
	// Prefer[0] (closCpus) must contain only cpu 0.
	if len(got.Prefer) == 0 {
		t.Fatalf("Prefer empty, want at least closCpus hint")
	}
	if !got.Prefer[0].Cpus.Equals(cpuset.MustParse("0")) {
		t.Errorf("Prefer[0].Cpus = %s, want {0} (cpu 4 outside allowed)", got.Prefer[0].Cpus)
	}
	// HP reserve must come from a package whose free CPUs are
	// inside allowed; only pkg0 qualifies.
	if len(got.Prefer) >= 2 {
		want := cpuset.MustParse("1-3")
		if !got.Prefer[1].Cpus.Equals(want) {
			t.Errorf("HP reserve = %s, want %s (pkg0 free cpus inside allowed)", got.Prefer[1].Cpus, want)
		}
	}
}
