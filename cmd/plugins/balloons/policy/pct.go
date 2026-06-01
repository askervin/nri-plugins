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
	// hpClasses holds the names of cpuClasses currently
	// classified as high priority. In managed mode this is every
	// class with pctPriority=high. In assoc-only mode it is
	// populated from GetClosConfig at Configure(): the CLOS with
	// the largest programmed MaxFreq is HP; classes targeting
	// that CLOS are HP. Tie-break (equal MaxFreq) goes to the
	// smaller CLOS id, matching SST-CP ordered-priority
	// convention. Empty when no HP class can be determined.
	hpClasses map[string]bool
	// punits is the per-punit topology cached from sst.Punits()
	// at Configure() time, with each punit's CPUs already
	// intersected with allowed.
	punits []pctPunit
	// punitByCpu maps each allowed CPU to its index in punits.
	// CPUs outside any known punit are absent from the map; the
	// allocator treats them as "no HP knowledge".
	punitByCpu map[int]int
	// hpUsed[i] is the set of CPUs currently held by HP-class
	// workloads on punits[i].
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
	a.hpClasses = map[string]bool{}
	a.punits = nil
	a.punitByCpu = nil

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

	a.snapshotPunits()
	log.Infof("pct: mode=%s, %d PCT cpuClass(es), %d punit(s) across %d package(s)",
		a.modeString(), len(plans), len(a.punits), len(a.packageIDsFromPunits()))

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
			log.Infof("pct: programmed CLOS %d min=%d max=%d kHz", closID, minF, maxF)
		}
		if err := a.sst.EnableCP(); err != nil {
			return fmt.Errorf("pct: failed to enable SST-CP: %w", err)
		}
		// Managed mode: HP classes are exactly those with pctPriority=high.
		for _, cc := range classes {
			if cc.PctPriority == "high" {
				a.hpClasses[cc.Name] = true
				log.Infof("pct: cpuClass %q classified HP (managed: pctPriority=high, CLOS %d)",
					cc.Name, plans[cc.Name].ClosID)
			} else if cc.PctPriority == "low" {
				log.Infof("pct: cpuClass %q classified LP (managed: pctPriority=low, CLOS %d)",
					cc.Name, plans[cc.Name].ClosID)
			}
		}
	} else {
		// Assoc-only: classify HP/LP from CLOS configs programmed
		// by the operator/BIOS. The CLOS with the largest MaxFreq
		// among the CLOSes our cpuClasses target is HP.
		a.classifyAssocOnlyHP(classes)
	}
	return nil
}

// snapshotPunits caches the per-punit topology from the sst
// backend, intersecting each punit's CPUs with the allowed set.
// Punits whose intersection with allowed is empty are dropped --
// they cannot affect placement under this Configure(). The
// resulting punits and punitByCpu indices drive HP accounting and
// hpReserveCpus tier selection.
func (a *pctAllocator) snapshotPunits() {
	raw := a.sst.Punits()
	a.punits = make([]pctPunit, 0, len(raw))
	a.punitByCpu = map[int]int{}
	for _, pu := range raw {
		cpus := pu.CPUs
		if a.allowed.Size() > 0 {
			cpus = cpus.Intersection(a.allowed)
		}
		if cpus.IsEmpty() {
			continue
		}
		idx := len(a.punits)
		a.punits = append(a.punits, pctPunit{
			PkgID:     pu.PkgID,
			PunitID:   pu.PunitID,
			CPUs:      cpus,
			MaxHpCpus: pu.MaxHpCpus,
		})
		for _, c := range cpus.UnsortedList() {
			a.punitByCpu[c] = idx
		}
	}
}

// packageIDsFromPunits returns the set of package IDs present in
// the cached punits, in stable sorted order.
func (a *pctAllocator) packageIDsFromPunits() []int {
	seen := map[int]bool{}
	ids := []int{}
	for _, pu := range a.punits {
		if seen[pu.PkgID] {
			continue
		}
		seen[pu.PkgID] = true
		ids = append(ids, pu.PkgID)
	}
	sort.Ints(ids)
	return ids
}

// classifyAssocOnlyHP populates hpClasses by reading the
// programmed MaxFreq of each CLOS referenced by an assoc-only
// cpuClass. The CLOS with the largest MaxFreq is treated as HP;
// ties go to the smaller CLOS id (matching SST-CP ordered-priority
// convention where lower CLOS ids have higher priority). When no
// CLOS reports a programmed MaxFreq, no class is classified as HP
// (HP-specific hints stay quiet for that class set).
func (a *pctAllocator) classifyAssocOnlyHP(classes []*CPUClass) {
	maxFreqs := map[int]int{}
	closIDs := []int{}
	for _, p := range a.classPlan {
		if _, seen := maxFreqs[p.ClosID]; seen {
			continue
		}
		cfg, ok, err := a.sst.GetClosConfig(p.ClosID)
		if err != nil {
			log.Warnf("pct: assoc-only: GetClosConfig(%d) failed: %v", p.ClosID, err)
			continue
		}
		if !ok {
			log.Infof("pct: assoc-only: CLOS %d not programmed; cannot classify HP/LP", p.ClosID)
			continue
		}
		maxFreqs[p.ClosID] = cfg.MaxFreq
		closIDs = append(closIDs, p.ClosID)
		log.Infof("pct: assoc-only: CLOS %d programmed min=%d max=%d kHz", p.ClosID, cfg.MinFreq, cfg.MaxFreq)
	}
	if len(closIDs) == 0 {
		return
	}
	sort.Ints(closIDs)
	bestClos := -1
	bestMax := -1
	for _, id := range closIDs {
		if maxFreqs[id] > bestMax {
			bestMax = maxFreqs[id]
			bestClos = id
		}
	}
	if bestClos < 0 || bestMax <= 0 {
		log.Infof("pct: assoc-only: no CLOS has a programmed MaxFreq; HP classification skipped")
		return
	}
	for _, cc := range classes {
		p, ok := a.classPlan[cc.Name]
		if !ok || p.ClosID != bestClos {
			continue
		}
		a.hpClasses[cc.Name] = true
		log.Infof("pct: cpuClass %q classified HP (assoc-only: CLOS %d MaxFreq=%d kHz)", cc.Name, bestClos, bestMax)
	}
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

// trackHpUsage updates per-punit HP CPU bookkeeping so cpus are
// recorded as held by an HP class if className is HP, and removed
// from HP bookkeeping otherwise. CPUs not mapped to any punit
// (e.g. outside Allowed at Configure time) are ignored: they
// cannot affect HP placement and tracking them would only confuse
// hpInUseCpus.
func (a *pctAllocator) trackHpUsage(className string, cpus cpuset.CPUSet) {
	if !a.hpHintsActive() {
		return
	}
	a.clearHpUsage(cpus)
	if !a.classIsHighPriority(className) {
		return
	}
	perPunit := map[int][]int{}
	for _, cpu := range cpus.UnsortedList() {
		idx, ok := a.punitByCpu[cpu]
		if !ok {
			continue
		}
		perPunit[idx] = append(perPunit[idx], cpu)
	}
	for idx, list := range perPunit {
		set := a.hpUsed[idx]
		a.hpUsed[idx] = set.Union(cpuset.New(list...))
	}
}

// clearHpUsage removes cpus from per-punit HP bookkeeping.
func (a *pctAllocator) clearHpUsage(cpus cpuset.CPUSet) {
	if !a.hpHintsActive() {
		return
	}
	for idx, set := range a.hpUsed {
		if remaining := set.Difference(cpus); remaining.Size() != set.Size() {
			a.hpUsed[idx] = remaining
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

// classIsHighPriority reports whether className is currently
// classified as PCT high priority. In managed mode this comes from
// pctPriority=high; in assoc-only mode it comes from the largest
// programmed CLOS MaxFreq (see classifyAssocOnlyHP). The two
// regimes share one map so that hints() can treat HP/non-HP
// classes uniformly.
func (a *pctAllocator) classIsHighPriority(className string) bool {
	if !a.active() {
		return false
	}
	return a.hpClasses[className]
}

// hpHintsActive reports whether HP-room reasoning (hpReserveCpus,
// hpInUseCpus, trackHpUsage) is currently meaningful. It requires
// PCT to be active *and* at least one cpuClass to be classified as
// HP. In assoc-only mode without programmed CLOS frequencies this
// is false even though the allocator runs, because we cannot
// distinguish HP from LP CLOSes from the data we have.
func (a *pctAllocator) hpHintsActive() bool {
	return a.active() && len(a.hpClasses) > 0
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

// hpInUseCpus returns the union of CPUs of every punit currently
// hosting at least one HP CPU, constrained to Allowed. Expanding
// HP usage to whole-punit (rather than whole-package) granularity
// keeps the Avoid hint for non-HP classes from being unnecessarily
// broad on TPMI-class platforms with multiple punits per package.
func (a *pctAllocator) hpInUseCpus() cpuset.CPUSet {
	if !a.hpHintsActive() {
		return cpuset.New()
	}
	out := cpuset.New()
	for idx, used := range a.hpUsed {
		if used.IsEmpty() {
			continue
		}
		if idx < 0 || idx >= len(a.punits) {
			continue
		}
		out = out.Union(a.punits[idx].CPUs)
	}
	if a.allowed.Size() > 0 {
		out = out.Intersection(a.allowed)
	}
	return out
}

// hpReserveCpus returns the CPU set the upcoming HP allocation
// should prefer, computed with punit-granular HP-room accounting:
//
//	room(punit) = MaxHpCpus(punit) - len(hpUsed[punit] \ excludeBln)
//
// Selection follows a strict tier order:
//
//   - Tier A (single-punit win): the punit with the largest
//     non-zero room and at least requested free CPUs. Returns the
//     free CPUs of that punit.
//   - Tier B (same-package union): when no single punit can host
//     `requested` HP CPUs but some package's punits jointly can,
//     return the union of free CPUs across that package's punits.
//     The picked package is the one with the largest aggregate
//     room; ties broken by largest aggregate free-CPU count.
//   - Tier C (cross-package): never. Steering HP work across
//     sockets defeats the turbo gains it would obtain, because
//     cross-socket data traffic typically dominates per-core
//     frequency benefits.
//
// When `requested` is 0 the function falls back to Tier A only --
// pick the punit with the most HP room and at least one free CPU.
// Returns the empty set when no punit/package satisfies any tier
// or no free CPUs remain after Allowed-intersection; the caller
// then falls back to topology-only placement.
//
//   - free: free CPUs to consider for placement.
//   - excludeBln: CPUs to exclude from HP-room accounting (the
//     caller's current CPU set, e.g. when expanding an existing
//     allocation, so its current HP usage is not double-counted).
//   - requested: number of CPUs the upcoming allocation wants.
//     0 means "unknown" (initial priming before the count is
//     known); Tier A is used.
func (a *pctAllocator) hpReserveCpus(free cpuset.CPUSet, excludeBln cpuset.CPUSet, requested int) cpuset.CPUSet {
	if !a.hpHintsActive() {
		return cpuset.New()
	}
	if a.allowed.Size() > 0 {
		free = free.Intersection(a.allowed)
	}
	if free.IsEmpty() {
		return cpuset.New()
	}

	type punitState struct {
		free cpuset.CPUSet
		room int
	}
	states := make([]punitState, len(a.punits))
	anyKnown := false
	for i, pu := range a.punits {
		states[i].free = pu.CPUs.Intersection(free)
		if pu.MaxHpCpus <= 0 {
			// Unknown capacity for this punit: do not let it
			// influence HP steering. Leave room=0 so it never
			// wins Tier A; package-aggregate Tier B still
			// uses only known-capacity punits.
			continue
		}
		anyKnown = true
		used := a.hpUsed[i]
		if excludeBln.Size() > 0 {
			used = used.Difference(excludeBln)
		}
		room := pu.MaxHpCpus - used.Size()
		if room < 0 {
			room = 0
		}
		states[i].room = room
	}
	if !anyKnown {
		return cpuset.New()
	}

	// Tier A: best single punit that satisfies the request.
	need := requested
	if need < 1 {
		need = 1
	}
	bestIdx := -1
	bestRoom := 0
	bestFree := -1
	for i := range a.punits {
		s := states[i]
		if s.free.IsEmpty() || s.room <= 0 {
			continue
		}
		// Both the punit's free CPUs and its remaining HP
		// room must be able to host the entire request.
		if s.free.Size() < need || s.room < need {
			continue
		}
		if s.room > bestRoom || (s.room == bestRoom && s.free.Size() > bestFree) {
			bestIdx = i
			bestRoom = s.room
			bestFree = s.free.Size()
		}
	}
	if bestIdx >= 0 {
		log.Debugf("pct: hpReserveCpus tier=A punit=%d/%d room=%d free=%s",
			a.punits[bestIdx].PkgID, a.punits[bestIdx].PunitID, bestRoom, states[bestIdx].free)
		return states[bestIdx].free
	}

	// Tier B: aggregate per package; pick the package whose
	// punits together have the most room (and free CPUs).
	if requested > 0 {
		type pkgAgg struct {
			room  int
			free  cpuset.CPUSet
			freeN int
		}
		agg := map[int]*pkgAgg{}
		for i, pu := range a.punits {
			if states[i].room <= 0 || states[i].free.IsEmpty() {
				continue
			}
			e, ok := agg[pu.PkgID]
			if !ok {
				e = &pkgAgg{free: cpuset.New()}
				agg[pu.PkgID] = e
			}
			e.room += states[i].room
			e.free = e.free.Union(states[i].free)
		}
		pkgIDs := make([]int, 0, len(agg))
		for id, e := range agg {
			e.freeN = e.free.Size()
			pkgIDs = append(pkgIDs, id)
		}
		sort.Ints(pkgIDs) // deterministic tie-break order
		bestPkg := -1
		bestPkgRoom := 0
		bestPkgFree := -1
		for _, id := range pkgIDs {
			e := agg[id]
			if e.room < requested {
				continue
			}
			if e.freeN < requested {
				continue
			}
			if e.room > bestPkgRoom || (e.room == bestPkgRoom && e.freeN > bestPkgFree) {
				bestPkg = id
				bestPkgRoom = e.room
				bestPkgFree = e.freeN
			}
		}
		if bestPkg >= 0 {
			log.Debugf("pct: hpReserveCpus tier=B pkg=%d room=%d free=%s",
				bestPkg, bestPkgRoom, agg[bestPkg].free)
			return agg[bestPkg].free
		}
	}

	// Tier C is never taken: do not hint across packages.
	log.Debugf("pct: hpReserveCpus tier=none (no punit or package has %d HP room with %d free CPUs)",
		requested, free.Size())
	return cpuset.New()
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
// Behavior:
//   - Class has an explicit CLOS plan (assoc-only or managed): Prefer
//     CLOS-member CPUs.
//   - Class is currently classified HP: Prefer hpReserveCpus
//     (best-fit punit; same-package union as fallback), and also
//     CLOS-member CPUs. No cross-package hint is ever emitted.
//   - Class is not HP and at least one HP class exists: Avoid
//     hpInUseCpus (punits currently hosting HP work).
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
		reserve := a.hpReserveCpus(intent.FreeCpus, intent.CurrentCpus, intent.RequestedCount)
		if !reserve.IsEmpty() {
			out.Prefer = append(out.Prefer, CpuPreference{
				Name: virtDevSstHpReserveHint,
				Cpus: reserve,
			})
		}
		return out
	}

	if a.hpHintsActive() {
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
// is currently classified as HP. Retained for compatibility with
// older internal callers; new code should use hpHintsActive.
func (a *pctAllocator) anyHighPriorityClassDefined() bool {
	return len(a.hpClasses) > 0
}
