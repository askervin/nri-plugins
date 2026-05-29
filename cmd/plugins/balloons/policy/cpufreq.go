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

	cpucfg "github.com/containers/nri-plugins/pkg/apis/config/v1alpha1/resmgr/control/cpu"
	"github.com/containers/nri-plugins/pkg/resmgr/cache"
	cpucontrol "github.com/containers/nri-plugins/pkg/resmgr/control/cpu"
	"github.com/containers/nri-plugins/pkg/sysfs"
	"github.com/containers/nri-plugins/pkg/utils/cpuset"
)

// cpufreqAllocator owns cpufreq-side CPU-class lifecycle: resolution
// of symbolic frequencies (min/base/turbo), turbo-priority winner
// selection, and the cpucontrol.SetClass / cpucontrol.Assign calls
// that follow.
//
// A handler-internal user only needs to call useClass for the CPU
// sets it manages; the allocator takes care of pushing class
// definitions to the CPU controller and re-assigning CPUs of classes
// whose effective turbo frequency changes when the active winner
// changes.
//
// Turbo arbitration is scoped to "turbo domains". The default domain
// is the physical package (socket).
type cpufreqAllocator struct {
	sys         sysfs.System
	cch         cache.Cache
	classes     []*CPUClass
	classByName map[string]*CPUClass
	turboDomain string
	turboInfo   *platformTurboInfo
	allowed     cpuset.CPUSet

	// cpuDomain maps each known CPU id to its turbo domain id.
	// TurboDomain package: domainID=physical_package_id of each CPU.
	// TurboDomain system: domainID=0 for every CPU.
	cpuDomain map[int]domainID
	// domains lists every domain id appearing in cpuDomain, sorted,
	// for deterministic log output.
	domains []domainID

	// activeCpus[d][className] is the set of CPUs in turbo domain d
	// currently assigned to className by the latest useClass call.
	// recalculateTurbo() consults this map for each affected domain.
	activeCpus map[domainID]map[string]cpuset.CPUSet

	// winnerPrio[d] is the highest TurboPriority among CPU classes
	// that had any active CPUs in domain d the last time
	// recalculateTurbo(d) ran. -1 forces the first recalculation.
	winnerPrio map[domainID]int
}

// domainID identifies one turbo arbitration domain. For
// turboDomain="package" it equals the sysfs physical_package_id; for
// turboDomain="system" it is always 0.
type domainID int

// systemDomainID is the only domain id used in turboDomain="system"
// mode.
const systemDomainID domainID = 0

// turboDomainPackage and turboDomainSystem are the supported
// TurboDomain modes. An empty value resolves to turboDomainPackage.
const (
	turboDomainPackage = "package"
	turboDomainSystem  = "system"
)

// turboOption is a functional option for newCpufreqAllocator.
type turboOption func(*cpufreqAllocator) error

// withSystem provides the sysfs system topology for symbolic
// frequency resolution.
func withSystem(sys sysfs.System) turboOption {
	return func(a *cpufreqAllocator) error {
		a.sys = sys
		return nil
	}
}

// withCache provides the resource manager cache for cpucontrol.Assign.
func withCache(cch cache.Cache) turboOption {
	return func(a *cpufreqAllocator) error {
		a.cch = cch
		return nil
	}
}

// newCpufreqAllocator creates a cpufreq allocator and applies the
// given options. The constructor does not push any class definitions;
// caller is expected to follow up with a configure() call.
func newCpufreqAllocator(opts ...turboOption) (*cpufreqAllocator, error) {
	a := &cpufreqAllocator{
		activeCpus: map[domainID]map[string]cpuset.CPUSet{},
		winnerPrio: map[domainID]int{},
	}
	for _, opt := range opts {
		if err := opt(a); err != nil {
			return nil, err
		}
	}
	if a.sys == nil {
		return nil, fmt.Errorf("cpufreqAllocator: missing required option withSystem")
	}
	if a.cch == nil {
		return nil, fmt.Errorf("cpufreqAllocator: missing required option withCache")
	}
	a.discoverPlatformInfo()
	return a, nil
}

// configure replaces the CPU class set, turbo domain mode and the set
// of allowed CPUs. Resets per-domain turbo winners so the next
// useClass call recomputes the effective frequencies, and re-pushes
// class definitions to the CPU controller.
func (a *cpufreqAllocator) configure(classes []*CPUClass, turboDomain string, allowed cpuset.CPUSet) error {
	a.classes = classes
	a.classByName = make(map[string]*CPUClass, len(classes))
	for _, cc := range classes {
		a.classByName[cc.Name] = cc
	}
	switch turboDomain {
	case "", turboDomainPackage, turboDomainSystem:
		a.turboDomain = turboDomain
	default:
		return fmt.Errorf("cpufreqAllocator: unsupported turboDomain %q (expected %q or %q)",
			turboDomain, turboDomainPackage, turboDomainSystem)
	}
	a.allowed = allowed
	a.buildCpuDomains()
	a.activeCpus = map[domainID]map[string]cpuset.CPUSet{}
	a.winnerPrio = map[domainID]int{}
	a.pushInitialClassDefinitions()
	return nil
}

// isKnownClass reports whether the given class name is known to either
// the user-facing CPUClasses configuration of this allocator or to the
// CPU controller (via cpucontrol.GetClasses, which contains classes
// defined in the legacy control.cpu.classes section as well as every
// class pushed via cpucontrol.SetClass). The two sources can differ:
// classByName carries the turbo metadata needed by recalculateTurbo,
// while cpucontrol's class map is what actually drives sysfs writes,
// so a class defined only via control.cpu.classes is unknown to
// classByName but known to cpucontrol.
func (a *cpufreqAllocator) isKnownClass(name string) bool {
	if _, ok := a.classByName[name]; ok {
		return true
	}
	if _, ok := cpucontrol.GetClasses()[name]; ok {
		return true
	}
	return false
}

// resolveClassName resolves a (possibly empty or unknown) configured
// CPU class name to the class that should actually be applied. If the
// configured name matches a class known to either cpuClasses or
// control.cpu.classes it is returned unchanged. Otherwise, if a class
// named "default" is known to either source, "default" is returned.
// As a last resort the original name is returned, so the caller's
// existing log/warning paths still see what was requested.
func (a *cpufreqAllocator) resolveClassName(name string) string {
	if name == "" {
		// Empty is a valid "no class" assignment when the caller
		// does not request any class; fall back to "default" only
		// when one is configured, otherwise pass through silently.
		if a.isKnownClass(defaultClassName) {
			return defaultClassName
		}
		return ""
	}
	if a.isKnownClass(name) {
		return name
	}
	if a.isKnownClass(defaultClassName) {
		log.Errorf("unknown CPU class %q: falling back to using %q", name, defaultClassName)
		return defaultClassName
	}
	log.Errorf("unknown CPU class %q and fallback class %q missing from cpuClasses", name, defaultClassName)
	return name
}

// useClass marks the given CPUs as active under className, recalculates
// the turbo winner of every affected turbo domain, then assigns the
// CPUs to className (per domain) via the CPU controller. The
// recalculation runs first so that the controller's in-memory class
// definitions for each affected domain reflect the correct effective
// turbo frequency at the time of Assign. An empty or unknown
// className resolves to the "default" CPU class when one is
// configured. CPUs outside the configured Allowed set are silently
// dropped.
func (a *cpufreqAllocator) useClass(className string, cpus cpuset.CPUSet) error {
	if a.allowed.Size() > 0 {
		cpus = cpus.Intersection(a.allowed)
	}
	if cpus.IsEmpty() {
		return nil
	}
	className = a.resolveClassName(className)
	a.removeCpusFromAllClasses(cpus)
	byDomain := a.cpusByDomain(cpus)
	if className != "" {
		for d, dc := range byDomain {
			if a.activeCpus[d] == nil {
				a.activeCpus[d] = map[string]cpuset.CPUSet{}
			}
			a.activeCpus[d][className] = a.activeCpus[d][className].Union(dc)
		}
	}
	for d := range byDomain {
		a.recalculateTurbo(d)
	}
	for d, dc := range byDomain {
		syn := a.controlClassName(className, d)
		if err := cpucontrol.Assign(a.cch, syn, dc.UnsortedList()...); err != nil {
			return fmt.Errorf("failed to assign CPUs %s to class %q (turbo domain %d): %w",
				dc, className, d, err)
		}
	}
	return nil
}

// removeCpusFromAllClasses removes the given CPUs from every active
// class set, in every turbo domain. Empty class sets are deleted.
func (a *cpufreqAllocator) removeCpusFromAllClasses(cpus cpuset.CPUSet) {
	for d, perClass := range a.activeCpus {
		for name, set := range perClass {
			newSet := set.Difference(cpus)
			if newSet.IsEmpty() {
				delete(perClass, name)
			} else {
				perClass[name] = newSet
			}
		}
		if len(perClass) == 0 {
			delete(a.activeCpus, d)
		}
	}
}

// cpusByDomain groups the given CPU set by turbo domain id. CPUs that
// are not present in cpuDomain (e.g., offline at discovery time) are
// assigned to systemDomainID as a safe fallback.
func (a *cpufreqAllocator) cpusByDomain(cpus cpuset.CPUSet) map[domainID]cpuset.CPUSet {
	out := map[domainID]cpuset.CPUSet{}
	for _, cpu := range cpus.UnsortedList() {
		d, ok := a.cpuDomain[cpu]
		if !ok {
			d = systemDomainID
		}
		out[d] = out[d].Union(cpuset.New(cpu))
	}
	return out
}

// buildCpuDomains constructs the cpu->turboDomain map for the
// configured Allowed CPUs only. In "system" mode every allowed CPU
// maps to systemDomainID. In "package" mode (default) each maps to
// its physical_package_id. CPUs outside Allowed are intentionally not
// represented: cpuclass does not configure them.
func (a *cpufreqAllocator) buildCpuDomains() {
	a.cpuDomain = map[int]domainID{}
	seen := map[domainID]bool{}
	mode := a.turboDomain
	if mode == "" {
		mode = turboDomainPackage
	}
	for _, cpuID := range a.sys.CPUIDs() {
		if a.allowed.Size() > 0 && !a.allowed.Contains(int(cpuID)) {
			continue
		}
		c := a.sys.CPU(cpuID)
		if c == nil {
			continue
		}
		var d domainID
		switch mode {
		case turboDomainSystem:
			d = systemDomainID
		default:
			d = domainID(c.PackageID())
		}
		a.cpuDomain[int(cpuID)] = d
		seen[d] = true
	}
	a.domains = a.domains[:0]
	for d := range seen {
		a.domains = append(a.domains, d)
	}
	sort.Slice(a.domains, func(i, j int) bool { return a.domains[i] < a.domains[j] })
	// Force a recompute in every domain on the next UseClass call.
	for _, d := range a.domains {
		a.winnerPrio[d] = -1
	}
	log.Debugf("turbo domains (mode=%s): %v (cpu->domain: %v)", mode, a.domains, a.cpuDomain)
}

// controlClassName returns the CPU controller class name that should
// be used when assigning CPUs of turbo domain d to the user-visible
// class "name". User-facing cpuClasses (known to classByName) get a
// per-domain synthetic name "<name>@d<N>" so that recalculateTurbo
// can publish a different effective MaxFreq per domain. Other names
// -- empty, or legacy classes defined only in control.cpu.classes --
// pass through unchanged: legacy classes have no TurboPriority and
// therefore do not participate in per-domain arbitration; using
// their bare name lets the CPU controller find their definition in
// cfg.CPU.Classes (which is loaded after balloons.Start and thus
// after the very first Assign calls).
func (a *cpufreqAllocator) controlClassName(name string, d domainID) string {
	if name == "" {
		return ""
	}
	if _, ok := a.classByName[name]; !ok {
		return name
	}
	return syntheticClassName(name, d)
}

// syntheticClassName returns the controller-internal class name that
// carries the per-domain effective turbo for the given user-facing
// class name. Empty class names are passed through unchanged so the
// CPU controller's existing handling of "no class" stays untouched.
func syntheticClassName(name string, d domainID) string {
	if name == "" {
		return ""
	}
	return fmt.Sprintf("%s@d%d", name, d)
}

// discoverPlatformInfo reads platform turbo capabilities from sysfs.
// Failure is non-fatal; symbolic frequencies will resolve to 0 in
// that case (matching the behavior of the pre-allocator code path).
func (a *cpufreqAllocator) discoverPlatformInfo() {
	info, err := discoverTurboInfo(a.sys)
	if err != nil {
		log.Warnf("cpufreqAllocator: cannot discover platform turbo info: %v", err)
		return
	}
	a.turboInfo = info
}

// pushInitialClassDefinitions resolves symbolic frequencies in every
// CPUClass and pushes the resulting cpucfg.Class to the CPU controller
// via cpucontrol.SetClass, once per (class, turbo domain) pair using
// syntheticClassName. At this point no class has been declared a
// turbo winner in any domain, so symbolic "turbo" resolves to the
// platform max turbo frequency for every class. The first useClass
// call will trigger recalculateTurbo() for the affected domain to
// enforce the priority-based effective turbo.
func (a *cpufreqAllocator) pushInitialClassDefinitions() {
	if len(a.domains) == 0 {
		return
	}
	for _, cc := range a.classes {
		var controlClass cpucfg.Class
		if a.turboInfo != nil {
			controlClass = resolvedCpuClassToControlClass(cc, a.turboInfo, 0)
		} else {
			controlClass = cpuClassToControlClass(cc)
		}
		for _, d := range a.domains {
			cpucontrol.SetClass(syntheticClassName(cc.Name, d), controlClass)
		}
		log.Infof("cpuClass %q configured: minFreq=%s(%d) maxFreq=%s(%d) disabledCstates=%v",
			cc.Name, cc.MinFreq, controlClass.MinFreq, cc.MaxFreq, controlClass.MaxFreq, cc.DisabledCstates)
	}
}

// recalculateTurbo resolves exclusive turbo frequency access in the
// given turbo domain based on TurboPriority across all CPU classes
// that currently have active CPUs in that domain.
//
// Algorithm (steady-state no-op):
//  1. Find the highest TurboPriority among classes with non-empty
//     active CPU sets in domain d.
//  2. If the new highest priority equals the previously computed one
//     for d, return immediately. Effective frequencies in d cannot
//     have changed.
//  3. Otherwise: update CPU controller class definitions for ALL
//     CPUClasses in domain d via cpucontrol.SetClass (using
//     syntheticClassName). SetClass records the new definition in
//     memory and marks every CPU currently assigned to the synthetic
//     (class, domain) name as dirty. The CPU controller's Commit()
//     then issues the minimal set of sysfs writes needed to reach
//     the new desired state.
func (a *cpufreqAllocator) recalculateTurbo(d domainID) {
	if len(a.classes) == 0 {
		return
	}

	// Find the highest TurboPriority among classes with active CPUs
	// in domain d.
	newPrio := 0
	if perClass, ok := a.activeCpus[d]; ok {
		for _, cc := range a.classes {
			if cc.TurboPriority <= newPrio {
				continue
			}
			if set, ok := perClass[cc.Name]; ok && !set.IsEmpty() {
				newPrio = cc.TurboPriority
			}
		}
	}

	// Steady-state fast path.
	if prev, ok := a.winnerPrio[d]; ok && prev == newPrio {
		return
	}

	a.winnerPrio[d] = newPrio

	if a.turboInfo == nil {
		// No platform info -> we cannot compute effective turbo.
		// Still update winnerPrio to avoid repeated warnings.
		log.Warnf("turbo recalculation skipped (domain %d): no platform turbo info available", d)
		return
	}

	// Update CPU controller class definitions for every CPUClass in
	// this turbo domain with its new effective turbo. The actual
	// sysfs writes are deferred until the CPU controller's next
	// Commit() call.
	for _, cc := range a.classes {
		effectiveTurboKHz := a.turboInfo.baseFreqKHz
		if newPrio == 0 || cc.TurboPriority >= newPrio {
			effectiveTurboKHz = a.turboInfo.maxTurboFreqKHz
		}
		controlClass := resolvedCpuClassToControlClass(cc, a.turboInfo, effectiveTurboKHz)
		cpucontrol.SetClass(syntheticClassName(cc.Name, d), controlClass)
		log.Infof("turbo: domain=%d class %q (prio=%d, winner=%v): minFreq=%d maxFreq=%d",
			d, cc.Name, cc.TurboPriority,
			newPrio == 0 || cc.TurboPriority >= newPrio,
			controlClass.MinFreq, controlClass.MaxFreq)
	}
}

// cpuClassToControlClass converts a user-friendly CPUClass definition
// into the internal cpu.Class representation used by the CPU controller.
// Symbolic frequencies (min, base, turbo) are left as 0; use
// resolvedCpuClassToControlClass() when platform info is available.
func cpuClassToControlClass(cc *CPUClass) cpucfg.Class {
	resolveFreq := func(f Frequency) uint {
		if f.IsSymbolic() {
			return 0
		}
		return f.KHz()
	}
	return cpucfg.Class{
		MinFreq:                     resolveFreq(cc.MinFreq),
		MaxFreq:                     resolveFreq(cc.MaxFreq),
		EnergyPerformancePreference: cc.EnergyPerformancePreference,
		UncoreMinFreq:               resolveFreq(cc.UncoreMinFreq),
		UncoreMaxFreq:               resolveFreq(cc.UncoreMaxFreq),
		FreqGovernor:                cc.FreqGovernor,
		DisabledCstates:             cc.DisabledCstates,
	}
}

// resolvedCpuClassToControlClass converts a CPUClass to a control
// class with symbolic frequencies resolved using platform info.
// effectiveTurboKHz overrides the turbo frequency used when resolving
// the "turbo" symbolic name (0 means use the platform turbo frequency).
func resolvedCpuClassToControlClass(cc *CPUClass, info *platformTurboInfo, effectiveTurboKHz uint) cpucfg.Class {
	turboKHz := info.maxTurboFreqKHz
	if effectiveTurboKHz > 0 {
		turboKHz = effectiveTurboKHz
	}
	resolve := func(f Frequency) uint {
		if info != nil {
			return f.Resolve(info.minFreqKHz, info.baseFreqKHz, turboKHz)
		}
		if f.IsSymbolic() {
			return 0
		}
		return f.KHz()
	}
	return cpucfg.Class{
		MinFreq:                     resolve(cc.MinFreq),
		MaxFreq:                     resolve(cc.MaxFreq),
		EnergyPerformancePreference: cc.EnergyPerformancePreference,
		UncoreMinFreq:               resolve(cc.UncoreMinFreq),
		UncoreMaxFreq:               resolve(cc.UncoreMaxFreq),
		FreqGovernor:                cc.FreqGovernor,
		DisabledCstates:             cc.DisabledCstates,
	}
}

// platformTurboInfo holds platform-level turbo frequency capabilities
// discovered from sysfs.
type platformTurboInfo struct {
	// baseFreqKHz is the base frequency shared by all CPUs (kHz).
	baseFreqKHz uint
	// maxTurboFreqKHz is the maximum single-core turbo frequency (kHz).
	maxTurboFreqKHz uint
	// minFreqKHz is the platform minimum frequency (kHz).
	minFreqKHz uint
}

// discoverTurboInfo reads platform turbo capabilities from sysfs.
// It uses the first online CPU's frequency range as representative.
func discoverTurboInfo(sys interface {
	CPUIDs() []idset.ID
	CPU(id idset.ID) sysfs.CPU
}) (*platformTurboInfo, error) {
	cpuIDs := sys.CPUIDs()
	if len(cpuIDs) == 0 {
		return nil, fmt.Errorf("no CPUs found in system topology")
	}
	for _, id := range cpuIDs {
		cpu := sys.CPU(id)
		if cpu == nil || !cpu.Online() {
			continue
		}
		freq := cpu.FrequencyRange()
		baseFreq := cpu.BaseFrequency()
		if freq.Min == 0 && freq.Max == 0 {
			log.Warnf("cannot detect cpu%d frequency range, skipping platform turbo info discovery", id)
			continue
		}
		if baseFreq == 0 {
			log.Warnf("cannot detect cpu%d base frequency, default to max", id)
			baseFreq = freq.Max
		}
		return &platformTurboInfo{
			baseFreqKHz:     uint(baseFreq),
			maxTurboFreqKHz: uint(freq.Max),
			minFreqKHz:      uint(freq.Min),
		}, nil
	}
	return nil, fmt.Errorf("no online CPU with valid frequency information found")
}
