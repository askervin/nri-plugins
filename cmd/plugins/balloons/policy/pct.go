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

// pctMode is the operating mode of the PCT allocator.
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

// pctSys is the subset of sysfs.System that pctAllocator depends
// on. Defined here so tests can substitute a fake without
// implementing the full sysfs.System surface.
type pctSys interface {
	PackageIDs() []idset.ID
	Package(id idset.ID) sysfs.CPUPackage
	CPU(id idset.ID) sysfs.CPU
	CPUIDs() []idset.ID
}

// pctAllocator manages Intel Priority Core Turbo CLOS associations
// driven by cpuClass definitions.
type pctAllocator struct {
	sys         pctSys
	sst         sst
	mode        pctMode
	classByName map[string]*CPUClass
	classPlan   map[string]*pctClassPlan // class name -> CLOS plan (PCT classes only)
	// fallbackClos is the hardware CLOS used for CPUs whose class
	// is not a PCT class. After SST reset CLOS 0 is the default,
	// so we use it here too. This is a hardware-level concept,
	// not a user-visible "idle".
	fallbackClos int
	allowed      cpuset.CPUSet
	// hpUsed groups CPUs currently held by HP balloons by their
	// package ID.
	hpUsed map[int]cpuset.CPUSet
}

// newPctAllocator returns a new PCT allocator in the disabled mode.
func newPctAllocator(sys pctSys) (*pctAllocator, error) {
	s, err := newSst()
	if err != nil {
		return nil, err
	}
	return &pctAllocator{
		sys:  sys,
		sst:  s,
		mode: pctModeDisabled,
	}, nil
}

// configure selects the PCT operating mode from the given cpuClass
// definitions and, in managed mode, programs the corresponding SST
// CLOSes. Honors `allowed` as the boundary of CPUs the allocator may
// touch.
//
//   - classes: cpuClass definitions to inspect for PCT fields.
//   - allowed: CPUs the allocator may configure.
func (a *pctAllocator) configure(classes []*CPUClass, allowed cpuset.CPUSet) error {
	a.classByName = make(map[string]*CPUClass, len(classes))
	for _, cc := range classes {
		a.classByName[cc.Name] = cc
	}
	a.fallbackClos = pctDefaultHpClos // CLOS 0 == default-after-reset
	a.allowed = allowed
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
	if !a.sst.Supported() {
		log.Warnf("pct: SST not supported on this host; ignoring PCT fields in cpuClasses")
		a.mode = pctModeDisabled
		a.classPlan = nil
		return nil
	}
	log.Infof("pct: mode=%s, %d PCT cpuClass(es)", a.modeString(), len(plans))

	if mode == pctModeManaged {
		if err := a.sst.PrepareManagedMode(); err != nil {
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
			if err := a.sst.ConfigureClos(cfg); err != nil {
				return fmt.Errorf("pct: failed to configure CLOS %d: %w", closID, err)
			}
			log.Debugf("pct: programmed CLOS %d min=%d max=%d", closID, minF, maxF)
		}
		if err := a.sst.EnableCP(); err != nil {
			return fmt.Errorf("pct: failed to enable SST-CP: %w", err)
		}
	}
	return nil
}

// planClasses returns the PCT operating mode and the per-class
// CLOS plan derived from cpuClasses.
func (a *pctAllocator) planClasses(classes []*CPUClass) (pctMode, map[string]*pctClassPlan, error) {
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

// resolveHWFreq returns the hardware frequency in kHz that the
// given symbolic Frequency refers to. "turbo" resolves to the
// platform's maximum turbo frequency.
func (a *pctAllocator) resolveHWFreq(f Frequency) uint {
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

// active reports whether PCT is in effect (mode != disabled).
func (a *pctAllocator) active() bool {
	return a != nil && a.mode != pctModeDisabled
}

// useClass associates the given CPUs to the CLOS chosen for className.
// In managed mode, CPUs whose className is not a PCT class are
// associated to the fallback CLOS. In assoc-only mode such CPUs are
// left unchanged. CPUs outside the configured Allowed set are silently
// dropped.
func (a *pctAllocator) useClass(className string, cpus cpuset.CPUSet) error {
	if !a.active() {
		return nil
	}
	if a.allowed.Size() > 0 {
		cpus = cpus.Intersection(a.allowed)
	}
	if cpus.IsEmpty() {
		return nil
	}
	a.trackHpUsage(className, cpus)
	plan, ok := a.classPlan[className]
	if !ok {
		if a.mode == pctModeAssocOnly {
			return nil
		}
		return a.associate(cpus, a.fallbackClos)
	}
	return a.associate(cpus, plan.ClosID)
}

// trackHpUsage updates per-package HP CPU bookkeeping so that
// cpus are recorded as held by an HP class if className is HP,
// and removed from HP bookkeeping otherwise.
func (a *pctAllocator) trackHpUsage(className string, cpus cpuset.CPUSet) {
	if !a.isManaged() {
		return
	}
	a.clearHpUsage(cpus)
	if !a.classIsHighPriority(className) {
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

// clearHpUsage removes cpus from per-package HP bookkeeping.
func (a *pctAllocator) clearHpUsage(cpus cpuset.CPUSet) {
	if !a.isManaged() {
		return
	}
	for pkg, set := range a.hpUsed {
		if remaining := set.Difference(cpus); remaining.Size() != set.Size() {
			a.hpUsed[pkg] = remaining
		}
	}
}

func (a *pctAllocator) associate(cpus cpuset.CPUSet, clos int) error {
	list := cpus.UnsortedList()
	sort.Ints(list)
	assocs := make([]pctClosAssoc, 0, len(list))
	for _, c := range list {
		assocs = append(assocs, pctClosAssoc{CPU: c, ClosID: clos})
	}
	if err := a.sst.AssociateCPUs(assocs); err != nil {
		return fmt.Errorf("pct: associate cpus %s to CLOS %d: %w", cpus, clos, err)
	}
	log.Debugf("pct: associated cpus %s to CLOS %d", cpus, clos)
	return nil
}

// Shutdown restores the platform to its default state. Safe to
// call multiple times.
func (a *pctAllocator) Shutdown() error {
	if a == nil || !a.sst.Supported() {
		return nil
	}
	if a.mode != pctModeManaged {
		return nil
	}
	return a.sst.Shutdown()
}

func (a *pctAllocator) modeString() string {
	switch a.mode {
	case pctModeManaged:
		return "managed"
	case pctModeAssocOnly:
		return "assoc-only"
	default:
		return "disabled"
	}
}

// isManaged reports whether PCT runs in managed mode (i.e. some
// cpuClass uses pctPriority and we own the CLOS configuration).
func (a *pctAllocator) isManaged() bool {
	return a != nil && a.mode == pctModeManaged
}

// classIsHighPriority reports whether className is the managed PCT
// high-priority class (pctPriority: high).
func (a *pctAllocator) classIsHighPriority(className string) bool {
	if !a.isManaged() {
		return false
	}
	cc, ok := a.classByName[className]
	return ok && cc.PctPriority == "high"
}

// closCpus returns the subset of Allowed CPUs that are currently
// associated to CLOS closID.
func (a *pctAllocator) closCpus(closID int) cpuset.CPUSet {
	if !a.active() {
		return cpuset.New()
	}
	out := []int{}
	for _, cpu := range a.allowed.UnsortedList() {
		id, err := a.sst.GetCPUClosID(cpu)
		if err != nil {
			continue
		}
		if id == closID {
			out = append(out, cpu)
		}
	}
	return cpuset.New(out...)
}

// hpInUseCpus returns the union of CPUs of all packages that
// currently host at least one HP CPU, constrained to Allowed.
func (a *pctAllocator) hpInUseCpus() cpuset.CPUSet {
	if !a.isManaged() {
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
	if a.allowed.Size() > 0 {
		out = out.Intersection(a.allowed)
	}
	return out
}

// hpReserveCpus returns the subset of free CPUs that lies on the
// package with the largest remaining PCT high-priority room. The
// HP room of a package is
//
//	room = MaxHpCpus(pkg) - len(hpUsed[pkg] \ excludeBln)
//
// Ties are broken by largest free-CPU count. Returns the empty set
// when no package has any room or no free CPUs, or when free is
// empty. The returned set is constrained to Allowed.
//
//   - free: free CPUs to consider for placement.
//   - excludeBln: CPUs to exclude from per-package HP room
//     accounting.
func (a *pctAllocator) hpReserveCpus(free cpuset.CPUSet, excludeBln cpuset.CPUSet) cpuset.CPUSet {
	if !a.isManaged() {
		return cpuset.New()
	}
	if a.allowed.Size() > 0 {
		free = free.Intersection(a.allowed)
	}
	if free.IsEmpty() {
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
		if maxHp, ok := a.sst.MaxHpCpus(int(pkgID)); ok {
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

// referencedClosIDs returns the sorted, deduplicated list of CLOS
// IDs referenced by any PCT cpuClass plan.
func (a *pctAllocator) referencedClosIDs() []int {
	if !a.active() {
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

// classClosID returns the CLOS ID that the named cpuClass maps to,
// or (-1, false) if the class has no PCT plan.
func (a *pctAllocator) classClosID(className string) (int, bool) {
	if !a.active() {
		return -1, false
	}
	p, ok := a.classPlan[className]
	if !ok {
		return -1, false
	}
	return p.ClosID, true
}

// virtDevSstHpReserveHint and virtDevSstHpInUseHint are the
// human-readable hint names returned in CpuPreference.Name for the
// dynamic PCT placement preferences.
const (
	virtDevSstHpReserveHint = "sst-hp-reserve"
	virtDevSstHpInUseHint   = "sst-hp-in-use"
)

// virtDevSstClosHint returns the human-readable hint name for the
// CLOS-membership preference of the given CLOS ID.
func virtDevSstClosHint(closID int) string {
	return fmt.Sprintf("sst-clos-%d", closID)
}

// hints returns prefer/avoid CPU sets that PCT would like an upcoming
// allocation under intent.ClassName to honor. Returned CpuPreference
// sets are not yet intersected with Allowed; the handler does that.
//
// Behavior, mirroring the previously-implicit balloons logic:
//   - Class has an explicit CLOS plan (assoc-only or managed): Prefer
//     CLOS-member CPUs.
//   - Class is the managed HP class: Prefer hpReserveCpus (a package
//     with HP headroom), and also CLOS-member CPUs.
//   - Class is not managed HP and at least one managed HP class
//     exists: Avoid hpInUseCpus (packages currently hosting HP work).
func (a *pctAllocator) hints(intent AllocationIntent) AllocationHints {
	if a == nil || !a.active() {
		return AllocationHints{}
	}
	out := AllocationHints{}

	if closID, ok := a.classClosID(intent.ClassName); ok {
		closCpus := a.closCpus(closID)
		if !closCpus.IsEmpty() {
			out.Prefer = append(out.Prefer, CpuPreference{
				Name: virtDevSstClosHint(closID),
				Cpus: closCpus,
			})
		}
	}

	if a.classIsHighPriority(intent.ClassName) {
		reserve := a.hpReserveCpus(intent.FreeCpus, intent.CurrentCpus)
		if !reserve.IsEmpty() {
			out.Prefer = append(out.Prefer, CpuPreference{
				Name: virtDevSstHpReserveHint,
				Cpus: reserve,
			})
		}
		return out
	}

	if a.isManaged() && a.anyHighPriorityClassDefined() {
		inUse := a.hpInUseCpus()
		if !inUse.IsEmpty() {
			out.Avoid = append(out.Avoid, CpuPreference{
				Name: virtDevSstHpInUseHint,
				Cpus: inUse,
			})
		}
	}
	return out
}

// anyHighPriorityClassDefined reports whether any configured cpuClass
// has pctPriority=high. This is independent of whether such a class
// currently has CPUs assigned.
func (a *pctAllocator) anyHighPriorityClassDefined() bool {
	for _, cc := range a.classByName {
		if cc.PctPriority == "high" {
			return true
		}
	}
	return false
}
