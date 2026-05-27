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
	"fmt"
	"sort"

	idset "github.com/intel/goresctrl/pkg/utils"

	"github.com/containers/nri-plugins/pkg/sysfs"
	"github.com/containers/nri-plugins/pkg/utils/cpuset"
)

const (
	// pctDefaultHpClos / pctDefaultLpClos are the conventional
	// CLOS slots used in managed mode when the user does not pin
	// PctClosID explicitly. See the PCT Technical Article example.
	pctDefaultHpClos = 0
	pctDefaultLpClos = 3
)

// pctMode is the operating mode chosen at Configure time.
type pctMode int

const (
	pctModeDisabled pctMode = iota
	pctModeManaged          // nri-plugin owns SoC-wide SST + CLOS configs
	pctModeAssocOnly        // operator/BIOS owns CLOSes; we only associate CPUs
)

// pctClassPlan records the CLOS that should be used for one PCT
// cpuClass and the freq bounds to program in managed mode.
type pctClassPlan struct {
	ClosID  int
	MinFreq uint // kHz, 0 = leave alone
	MaxFreq uint // kHz, 0 = leave alone
}

// CPUClassPctAllocator manages Intel Priority Core Turbo CLOS
// associations for the balloons policy. It is the sibling of
// CPUClassTurboAllocator and is fed UseClass/ForgetClass calls
// from the same balloon lifecycle hooks.
type CPUClassPctAllocator struct {
	sys           sysfs.System
	bridge        sstBridge
	mode          pctMode
	classByName   map[string]*CPUClass
	classPlan     map[string]*pctClassPlan // class name -> CLOS plan (PCT classes only)
	idleClassName string
	idleClos      int // CLOS used for CPUs not held by any PCT class
	// hpUsed tracks CPUs currently held by HP balloons, grouped
	// by package ID. Updated from UseClass / ForgetClass /
	// ResetIdle so HpReserveCpus can reason about per-package
	// remaining PCT room (= MaxHpCpus(pkg) - len(hpUsed[pkg])).
	hpUsed map[int]cpuset.CPUSet
}

// NewCPUClassPctAllocator constructs a PCT allocator. The bridge
// (real goresctrl or OVERRIDE_SST mock) is selected by
// newSstBridge() based on environment. Configure() must be called
// afterwards with the user's cpuClasses.
func NewCPUClassPctAllocator(sys sysfs.System) (*CPUClassPctAllocator, error) {
	br, err := newSstBridge()
	if err != nil {
		return nil, err
	}
	return &CPUClassPctAllocator{
		sys:    sys,
		bridge: br,
		mode:   pctModeDisabled,
	}, nil
}

// Configure inspects the cpuClass definitions, picks a PCT
// operating mode (disabled / managed / assoc-only) and, in
// managed mode, programs the CLOSes. Subsequent UseClass /
// ForgetClass calls then associate CPUs to the right CLOS.
// idleCpuClassName is consulted only to decide which CLOS to use
// for the policy-wide ResetIdle path; an unset / unrecognised
// idle class falls back to the "default" class if defined.
func (a *CPUClassPctAllocator) Configure(classes []*CPUClass, idleCpuClassName string) error {
	a.classByName = make(map[string]*CPUClass, len(classes))
	for _, cc := range classes {
		a.classByName[cc.Name] = cc
	}
	a.idleClassName = idleCpuClassName
	a.idleClos = pctDefaultHpClos // CLOS 0 == default-after-reset
	a.hpUsed = map[int]cpuset.CPUSet{}

	mode, plans, err := a.planClasses(classes)
	if err != nil {
		return err
	}
	a.mode = mode
	a.classPlan = plans
	if mode == pctModeDisabled {
		log.Debugf("pct: no cpuClasses request PCT; PCT allocator disabled")
		return nil
	}
	if !a.bridge.Supported() {
		log.Warnf("pct: SST not supported on this host; ignoring PCT fields in cpuClasses")
		a.mode = pctModeDisabled
		a.classPlan = nil
		return nil
	}
	log.Infof("pct: mode=%s, %d PCT cpuClass(es)", a.modeString(), len(plans))

	if mode == pctModeManaged {
		if err := a.bridge.PrepareManagedMode(); err != nil {
			return fmt.Errorf("pct: failed to prepare managed mode: %w", err)
		}
		// Program every requested CLOS.
		closesProgrammed := map[int]bool{}
		closIDs := make([]int, 0, len(plans))
		for _, p := range plans {
			if closesProgrammed[p.ClosID] {
				continue
			}
			closIDs = append(closIDs, p.ClosID)
			closesProgrammed[p.ClosID] = true
		}
		sort.Ints(closIDs)
		for _, closID := range closIDs {
			// Find the first plan that targets this CLOS to get
			// the freq values (all plans for the same CLOS must
			// agree; the per-class plan distinction matters only
			// for assoc).
			var minF, maxF int
			for _, p := range plans {
				if p.ClosID == closID {
					minF = int(p.MinFreq)
					maxF = int(p.MaxFreq)
					break
				}
			}
			cfg := pctClosConfig{ClosID: closID, MinFreq: minF, MaxFreq: maxF}
			if err := a.bridge.ConfigureClos(cfg); err != nil {
				return fmt.Errorf("pct: failed to configure CLOS %d: %w", closID, err)
			}
			log.Debugf("pct: programmed CLOS %d min=%d max=%d", closID, minF, maxF)
		}
		if err := a.bridge.EnableCP(); err != nil {
			return fmt.Errorf("pct: failed to enable SST-CP: %w", err)
		}
	}
	return nil
}

// planClasses derives the per-class CLOS plan from cpuClasses and
// returns the operating mode. Validation guarantees the two modes
// don't mix here.
func (a *CPUClassPctAllocator) planClasses(classes []*CPUClass) (pctMode, map[string]*pctClassPlan, error) {
	plans := map[string]*pctClassPlan{}
	managed, assocOnly := false, false
	for _, cc := range classes {
		switch {
		case cc.PctPriority != "":
			managed = true
			plan := &pctClassPlan{}
			switch cc.PctPriority {
			case "high":
				plan.ClosID = pctDefaultHpClos
			case "low":
				plan.ClosID = pctDefaultLpClos
			default:
				return pctModeDisabled, nil, fmt.Errorf("cpuClass %q: invalid pctPriority %q", cc.Name, cc.PctPriority)
			}
			minSrc, maxSrc := cc.PctMinFreq, cc.PctMaxFreq
			if minSrc == 0 {
				minSrc = cc.MinFreq
			}
			if maxSrc == 0 {
				maxSrc = cc.MaxFreq
			}
			plan.MinFreq = a.resolveHWFreq(minSrc)
			plan.MaxFreq = a.resolveHWFreq(maxSrc)
			plans[cc.Name] = plan
		case cc.PctClosID != nil:
			assocOnly = true
			plans[cc.Name] = &pctClassPlan{ClosID: *cc.PctClosID}
		}
	}
	switch {
	case !managed && !assocOnly:
		return pctModeDisabled, nil, nil
	case managed && assocOnly:
		return pctModeDisabled, nil, fmt.Errorf("pct: cannot mix managed (pctPriority) and assoc-only (pctClosID) modes")
	case managed:
		return pctModeManaged, plans, nil
	default:
		return pctModeAssocOnly, plans, nil
	}
}

// resolveHWFreq resolves a symbolic Frequency using the platform
// hardware values, ignoring the soft turboPriority arbitration.
// "turbo" always resolves to the real hardware turbo ceiling.
func (a *CPUClassPctAllocator) resolveHWFreq(f Frequency) uint {
	if f == 0 {
		return 0
	}
	info, err := discoverTurboInfo(a.sys)
	if err != nil || info == nil {
		log.Warnf("pct: cannot discover platform turbo info: %v", err)
		return uint(f)
	}
	return f.Resolve(info.minFreqKHz, info.baseFreqKHz, info.maxTurboFreqKHz)
}

// Active reports whether PCT is in effect (mode != disabled).
func (a *CPUClassPctAllocator) Active() bool {
	return a != nil && a.mode != pctModeDisabled
}

// UseClass associates the given CPUs to the CLOS chosen for
// className. If className is not a PCT class, the CPUs are
// associated to the idle CLOS (CLOS 0 in managed mode; left
// unchanged in assoc-only mode).
func (a *CPUClassPctAllocator) UseClass(className string, cpus cpuset.CPUSet) error {
	if !a.Active() || cpus.IsEmpty() {
		return nil
	}
	a.trackHpUsage(className, cpus)
	plan, ok := a.classPlan[className]
	if !ok {
		// Non-PCT class: in managed mode, send CPUs to the idle
		// CLOS so any prior PCT association is cleared. In
		// assoc-only mode, leave them alone.
		if a.mode == pctModeAssocOnly {
			return nil
		}
		return a.associate(cpus, a.idleClos)
	}
	return a.associate(cpus, plan.ClosID)
}

// ForgetClass associates the given CPUs to the idle CLOS.
func (a *CPUClassPctAllocator) ForgetClass(cpus cpuset.CPUSet) error {
	if !a.Active() || cpus.IsEmpty() {
		return nil
	}
	a.clearHpUsage(cpus)
	if a.mode == pctModeAssocOnly {
		return nil
	}
	return a.associate(cpus, a.idleClos)
}

// ResetIdle associates the given CPUs to the idle CLOS. Used at
// policy startup to bring all available CPUs to a known baseline.
func (a *CPUClassPctAllocator) ResetIdle(cpus cpuset.CPUSet) error {
	if !a.Active() || cpus.IsEmpty() {
		return nil
	}
	a.clearHpUsage(cpus)
	if a.mode == pctModeAssocOnly {
		return nil
	}
	return a.associate(cpus, a.idleClos)
}

// trackHpUsage records that `cpus` are now held by a balloon of
// class `className`. CPUs are first removed from every package's
// HP set (in case they moved between balloons), then re-added to
// the appropriate package only if className is an HP class.
func (a *CPUClassPctAllocator) trackHpUsage(className string, cpus cpuset.CPUSet) {
	if !a.IsManaged() {
		return
	}
	a.clearHpUsage(cpus)
	if !a.ClassIsHighPriority(className) {
		return
	}
	perPkg := map[int][]int{}
	for _, cpu := range cpus.UnsortedList() {
		c := a.sys.CPU(idset.ID(cpu))
		if c == nil {
			continue
		}
		pkg := int(c.PackageID())
		perPkg[pkg] = append(perPkg[pkg], cpu)
	}
	for pkg, list := range perPkg {
		set := a.hpUsed[pkg]
		a.hpUsed[pkg] = set.Union(cpuset.New(list...))
	}
}

// clearHpUsage removes `cpus` from every package's HP set.
func (a *CPUClassPctAllocator) clearHpUsage(cpus cpuset.CPUSet) {
	if !a.IsManaged() {
		return
	}
	for pkg, set := range a.hpUsed {
		if remaining := set.Difference(cpus); remaining.Size() != set.Size() {
			a.hpUsed[pkg] = remaining
		}
	}
}

func (a *CPUClassPctAllocator) associate(cpus cpuset.CPUSet, clos int) error {
	list := cpus.UnsortedList()
	sort.Ints(list)
	assocs := make([]pctClosAssoc, 0, len(list))
	for _, c := range list {
		assocs = append(assocs, pctClosAssoc{CPU: c, ClosID: clos})
	}
	if err := a.bridge.AssociateCPUs(assocs); err != nil {
		return fmt.Errorf("pct: associate cpus %s to CLOS %d: %w", cpus, clos, err)
	}
	log.Debugf("pct: associated cpus %s to CLOS %d", cpus, clos)
	return nil
}

// Shutdown returns the platform to its default state. Safe to
// call multiple times.
func (a *CPUClassPctAllocator) Shutdown() error {
	if a == nil || !a.bridge.Supported() {
		return nil
	}
	if a.mode != pctModeManaged {
		return nil
	}
	return a.bridge.Shutdown()
}

func (a *CPUClassPctAllocator) modeString() string {
	switch a.mode {
	case pctModeManaged:
		return "managed"
	case pctModeAssocOnly:
		return "assoc-only"
	default:
		return "disabled"
	}
}

// IsManaged reports whether PCT runs in managed mode (i.e. some
// cpuClass uses pctPriority and we own the CLOS configuration).
func (a *CPUClassPctAllocator) IsManaged() bool {
	return a != nil && a.mode == pctModeManaged
}

// ReferencedClosIDs returns the sorted, deduplicated list of CLOS
// IDs that appear in any pctClassPlan. Used to register one static
// virtDevSstClos<N> per CLOS.
func (a *CPUClassPctAllocator) ReferencedClosIDs() []int {
	if !a.Active() {
		return nil
	}
	seen := map[int]bool{}
	ids := []int{}
	for _, p := range a.classPlan {
		if seen[p.ClosID] {
			continue
		}
		seen[p.ClosID] = true
		ids = append(ids, p.ClosID)
	}
	sort.Ints(ids)
	return ids
}

// ClassClosID returns the CLOS ID that the named cpuClass maps to,
// or (-1, false) if the class has no PCT plan.
func (a *CPUClassPctAllocator) ClassClosID(className string) (int, bool) {
	if !a.Active() {
		return -1, false
	}
	p, ok := a.classPlan[className]
	if !ok {
		return -1, false
	}
	return p.ClosID, true
}

// ClassIsHighPriority reports whether the cpuClass is the managed
// HP class (pctPriority: high). Used to drive the dynamic
// virtDevSstHpReserve close/far hint.
func (a *CPUClassPctAllocator) ClassIsHighPriority(className string) bool {
	if !a.IsManaged() {
		return false
	}
	cc, ok := a.classByName[className]
	return ok && cc.PctPriority == "high"
}

// ClosCpus returns the set of allowed CPUs currently associated to
// CLOS closID, as reported by the SST bridge. Used at policy setup
// to seed the static virtDevSstClos<N> virtual devices.
func (a *CPUClassPctAllocator) ClosCpus(closID int, allowed cpuset.CPUSet) cpuset.CPUSet {
	if !a.Active() {
		return cpuset.New()
	}
	out := []int{}
	for _, cpu := range allowed.UnsortedList() {
		id, err := a.bridge.GetCPUClosID(cpu)
		if err != nil {
			continue
		}
		if id == closID {
			out = append(out, cpu)
		}
	}
	return cpuset.New(out...)
}

// HpInUseCpus returns the union of all CPUs that belong to
// packages currently hosting at least one HP CPU. LP and non-PCT
// balloons use this as a far-from hint so that LP/normal work
// does not compete for shared package power budget with HP work.
func (a *CPUClassPctAllocator) HpInUseCpus() cpuset.CPUSet {
	if !a.IsManaged() {
		return cpuset.New()
	}
	out := cpuset.New()
	for pkgID, used := range a.hpUsed {
		if used.IsEmpty() {
			continue
		}
		pkg := a.sys.Package(idset.ID(pkgID))
		if pkg == nil {
			continue
		}
		out = out.Union(pkg.CPUSet())
	}
	return out
}

// HpReserveCpus returns the subset of `free` that lies on the
// package with the largest remaining PCT high-priority budget.
// The "HP room" of a package is
//
//	room = MaxHpCpus(pkg) − len(hpUsed[pkg] \ excludeBln)
//
// where excludeBln are CPUs of the balloon currently being
// resized (so it does not compete against itself). Packages
// where the bridge does not expose MaxHpCpus, or where every
// package returns "unknown", fall back to a free-CPU-count
// heuristic. Ties are broken by largest free-CPU count.
//
// The returned set is the intersection of the winning package's
// CPUs with `free`. If no package has any room or no free CPUs,
// returns the empty set so callers fall back to plain topology
// placement.
func (a *CPUClassPctAllocator) HpReserveCpus(free cpuset.CPUSet, excludeBln cpuset.CPUSet) cpuset.CPUSet {
	if !a.IsManaged() || free.IsEmpty() {
		return cpuset.New()
	}
	var bestPkg cpuset.CPUSet
	bestRoom := -1
	bestFree := -1
	anyKnown := false
	for _, pkgID := range a.sys.PackageIDs() {
		pkg := a.sys.Package(pkgID)
		if pkg == nil {
			continue
		}
		pkgFree := pkg.CPUSet().Intersection(free)
		if pkgFree.IsEmpty() {
			continue
		}
		room := pkgFree.Size() // fallback: "most free CPUs"
		if maxHp, ok := a.bridge.MaxHpCpus(int(pkgID)); ok {
			anyKnown = true
			used := a.hpUsed[int(pkgID)]
			if excludeBln.Size() > 0 {
				used = used.Difference(excludeBln)
			}
			room = maxHp - used.Size()
			if room < 0 {
				room = 0
			}
		}
		if room > bestRoom || (room == bestRoom && pkgFree.Size() > bestFree) {
			bestRoom = room
			bestFree = pkgFree.Size()
			bestPkg = pkgFree
		}
	}
	if bestRoom <= 0 && anyKnown {
		log.Debugf("pct: no HP room left on any package, falling back to topology placement")
		return cpuset.New()
	}
	if bestPkg.IsEmpty() {
		return cpuset.New()
	}
	return bestPkg
}
