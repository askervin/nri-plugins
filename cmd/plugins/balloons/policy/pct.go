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

// CPUClassPctAllocator manages Intel Priority Core Turbo CLOS
// associations driven by cpuClass definitions.
type CPUClassPctAllocator struct {
	sys           sysfs.System
	sst           sst
	mode          pctMode
	classByName   map[string]*CPUClass
	classPlan     map[string]*pctClassPlan // class name -> CLOS plan (PCT classes only)
	idleClassName string
	idleClos      int // CLOS used for CPUs not held by any PCT class
	// hpUsed groups CPUs currently held by HP balloons by their
	// package ID.
	hpUsed map[int]cpuset.CPUSet
}

// NewCPUClassPctAllocator returns a new PCT allocator in the
// disabled mode.
func NewCPUClassPctAllocator(sys sysfs.System) (*CPUClassPctAllocator, error) {
	s, err := newSst()
	if err != nil {
		return nil, err
	}
	return &CPUClassPctAllocator{
		sys:  sys,
		sst:  s,
		mode: pctModeDisabled,
	}, nil
}

// Configure selects the PCT operating mode from the given
// cpuClass definitions and, in managed mode, programs the
// corresponding SST CLOSes.
//
//   - classes: cpuClass definitions to inspect for PCT fields.
//   - idleCpuClassName: name of the cpuClass to apply to idle
//     CPUs.
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

// resolveHWFreq returns the hardware frequency in kHz that the
// given symbolic Frequency refers to. "turbo" resolves to the
// platform's maximum turbo frequency.
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
// className. In managed mode, CPUs whose className is not a PCT
// class are associated to the idle CLOS. In assoc-only mode such
// CPUs are left unchanged.
func (a *CPUClassPctAllocator) UseClass(className string, cpus cpuset.CPUSet) error {
	if !a.Active() || cpus.IsEmpty() {
		return nil
	}
	a.trackHpUsage(className, cpus)
	plan, ok := a.classPlan[className]
	if !ok {
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

// ResetIdle associates the given CPUs to the idle CLOS.
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

// trackHpUsage updates per-package HP CPU bookkeeping so that
// cpus are recorded as held by an HP class if className is HP,
// and removed from HP bookkeeping otherwise.
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

// clearHpUsage removes cpus from per-package HP bookkeeping.
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
	if err := a.sst.AssociateCPUs(assocs); err != nil {
		return fmt.Errorf("pct: associate cpus %s to CLOS %d: %w", cpus, clos, err)
	}
	log.Debugf("pct: associated cpus %s to CLOS %d", cpus, clos)
	return nil
}

// Shutdown restores the platform to its default state. Safe to
// call multiple times.
func (a *CPUClassPctAllocator) Shutdown() error {
	if a == nil || !a.sst.Supported() {
		return nil
	}
	if a.mode != pctModeManaged {
		return nil
	}
	return a.sst.Shutdown()
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
// IDs referenced by any PCT cpuClass plan.
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

// ClassIsHighPriority reports whether className is the managed
// PCT high-priority class (pctPriority: high).
func (a *CPUClassPctAllocator) ClassIsHighPriority(className string) bool {
	if !a.IsManaged() {
		return false
	}
	cc, ok := a.classByName[className]
	return ok && cc.PctPriority == "high"
}

// ClosCpus returns the subset of allowed CPUs that are currently
// associated to CLOS closID.
func (a *CPUClassPctAllocator) ClosCpus(closID int, allowed cpuset.CPUSet) cpuset.CPUSet {
	if !a.Active() {
		return cpuset.New()
	}
	out := []int{}
	for _, cpu := range allowed.UnsortedList() {
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

// HpInUseCpus returns the union of CPUs of all packages that
// currently host at least one HP CPU.
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

// HpReserveCpus returns the subset of free CPUs that lies on the
// package with the largest remaining PCT high-priority room. The
// HP room of a package is
//
//	room = MaxHpCpus(pkg) - len(hpUsed[pkg] \ excludeBln)
//
// Ties are broken by largest free-CPU count. Returns the empty
// set when no package has any room or no free CPUs, or when free
// is empty.
//
//   - free: free CPUs to consider for placement.
//   - excludeBln: CPUs to exclude from per-package HP room
//     accounting.
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
