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

	cpucfg "github.com/containers/nri-plugins/pkg/apis/config/v1alpha1/resmgr/control/cpu"
	"github.com/containers/nri-plugins/pkg/resmgr/cache"
	cpucontrol "github.com/containers/nri-plugins/pkg/resmgr/control/cpu"
	"github.com/containers/nri-plugins/pkg/sysfs"
	"github.com/containers/nri-plugins/pkg/utils/cpuset"
)

// CPUClassTurboAllocator owns all CPU-class lifecycle concerns for the
// balloons policy: resolution of symbolic frequencies (min/base/turbo),
// turbo-priority winner selection, and the actual cpucontrol.SetClass /
// cpucontrol.Assign calls that follow from those decisions.
//
// The allocator keeps the policy code free of any direct CPU controller
// access. Balloons code only needs to call UseClass/ForgetClass for the
// CPU sets it manages; the allocator takes care of pushing class
// definitions to the CPU controller and re-assigning CPUs of classes
// whose effective turbo frequency changes when the active winner
// changes.
type CPUClassTurboAllocator struct {
	sys           sysfs.System
	cch           cache.Cache
	classes       []*CPUClass
	classByName   map[string]*CPUClass
	idleClassName string
	turboInfo     *platformTurboInfo

	// activeCpus tracks the set of CPUs currently assigned to each
	// CPU class (by the latest UseClass/ForgetClass calls). It is the
	// allocator's local model of "which classes are active". The
	// recalculation of the turbo winner consults this map without
	// reaching back into balloons or the CPU controller.
	activeCpus map[string]cpuset.CPUSet

	// winnerPrio is the highest TurboPriority among CPU classes that
	// had any active CPUs the last time recalculateTurbo() ran.
	// Initialized to -1 to force the first recalculation.
	winnerPrio int
}

// TurboOption is a functional option for NewCPUClassTurboAllocator.
type TurboOption func(*CPUClassTurboAllocator) error

// WithSystem provides the sysfs system topology for symbolic frequency
// resolution.
func WithSystem(sys sysfs.System) TurboOption {
	return func(a *CPUClassTurboAllocator) error {
		a.sys = sys
		return nil
	}
}

// WithCache provides the resource manager cache for cpucontrol.Assign.
func WithCache(cch cache.Cache) TurboOption {
	return func(a *CPUClassTurboAllocator) error {
		a.cch = cch
		return nil
	}
}

// WithCPUClasses provides the user-facing CPUClass definitions.
func WithCPUClasses(classes []*CPUClass) TurboOption {
	return func(a *CPUClassTurboAllocator) error {
		a.classes = classes
		a.classByName = make(map[string]*CPUClass, len(classes))
		for _, cc := range classes {
			a.classByName[cc.Name] = cc
		}
		return nil
	}
}

// WithIdleClass provides the name of the idle CPU class used by
// ForgetClass and ResetIdle.
func WithIdleClass(name string) TurboOption {
	return func(a *CPUClassTurboAllocator) error {
		a.idleClassName = name
		return nil
	}
}

// NewCPUClassTurboAllocator creates a turbo allocator and applies the
// given options. The constructor pushes initial CPU class definitions
// (with symbolic frequencies resolved against sysfs, when possible)
// into the CPU controller via cpucontrol.SetClass, so subsequent
// cpucontrol.Assign calls see the correct effective frequencies.
func NewCPUClassTurboAllocator(opts ...TurboOption) (*CPUClassTurboAllocator, error) {
	a := &CPUClassTurboAllocator{
		activeCpus: map[string]cpuset.CPUSet{},
		winnerPrio: -1,
	}
	for _, opt := range opts {
		if err := opt(a); err != nil {
			return nil, err
		}
	}
	if a.sys == nil {
		return nil, fmt.Errorf("CPUClassTurboAllocator: missing required option WithSystem")
	}
	if a.cch == nil {
		return nil, fmt.Errorf("CPUClassTurboAllocator: missing required option WithCache")
	}
	a.discoverPlatformInfo()
	a.pushInitialClassDefinitions()
	return a, nil
}

// Reconfigure replaces the CPU class set and idle class name. Resets
// the turbo winner so the next UseClass/ForgetClass call recomputes
// the effective frequencies, and re-pushes class definitions to the
// CPU controller.
func (a *CPUClassTurboAllocator) Reconfigure(classes []*CPUClass, idleClass string) error {
	a.classes = classes
	a.classByName = make(map[string]*CPUClass, len(classes))
	for _, cc := range classes {
		a.classByName[cc.Name] = cc
	}
	a.idleClassName = idleClass
	a.winnerPrio = -1
	a.pushInitialClassDefinitions()
	return nil
}

// Classes returns the current user-facing CPUClass set.
func (a *CPUClassTurboAllocator) Classes() []*CPUClass {
	return a.classes
}

// ClassByName looks up a CPUClass by name.
func (a *CPUClassTurboAllocator) ClassByName(name string) *CPUClass {
	return a.classByName[name]
}

// UseClass marks the given CPUs as active under className, recalculates
// the turbo winner, then assigns the CPUs to className via the CPU
// controller. The recalculation runs first so that the controller's
// in-memory class definition reflects the correct effective turbo
// frequency at the time of Assign.
func (a *CPUClassTurboAllocator) UseClass(className string, cpus cpuset.CPUSet) error {
	if cpus.IsEmpty() {
		return nil
	}
	a.removeCpusFromAllClasses(cpus)
	if className != "" {
		a.activeCpus[className] = a.activeCpus[className].Union(cpus)
	}
	a.recalculateTurbo()
	if err := cpucontrol.Assign(a.cch, className, cpus.UnsortedList()...); err != nil {
		return fmt.Errorf("failed to assign CPUs %s to class %q: %w", cpus, className, err)
	}
	return nil
}

// ForgetClass removes the given CPUs from any active class set,
// assigns them to the idle class via the CPU controller, then
// recalculates the turbo winner (the previously dominant class may
// have lost its last active balloon).
func (a *CPUClassTurboAllocator) ForgetClass(cpus cpuset.CPUSet) error {
	if cpus.IsEmpty() {
		return nil
	}
	a.removeCpusFromAllClasses(cpus)
	if err := cpucontrol.Assign(a.cch, a.idleClassName, cpus.UnsortedList()...); err != nil {
		return fmt.Errorf("failed to assign CPUs %s to idle class %q: %w", cpus, a.idleClassName, err)
	}
	a.recalculateTurbo()
	return nil
}

// ResetIdle assigns the given CPU set to the idle class via the CPU
// controller. Used at policy startup to bring all allowed CPUs to a
// known baseline before any container-driven UseClass call. Does not
// affect the active-class tracking.
func (a *CPUClassTurboAllocator) ResetIdle(cpus cpuset.CPUSet) error {
	if cpus.IsEmpty() {
		return nil
	}
	if err := cpucontrol.Assign(a.cch, a.idleClassName, cpus.UnsortedList()...); err != nil {
		return fmt.Errorf("failed to assign CPUs %s to idle class %q: %w", cpus, a.idleClassName, err)
	}
	return nil
}

// removeCpusFromAllClasses removes the given CPUs from every active
// class set. Empty class sets are deleted.
func (a *CPUClassTurboAllocator) removeCpusFromAllClasses(cpus cpuset.CPUSet) {
	for name, set := range a.activeCpus {
		newSet := set.Difference(cpus)
		if newSet.IsEmpty() {
			delete(a.activeCpus, name)
		} else {
			a.activeCpus[name] = newSet
		}
	}
}

// discoverPlatformInfo reads platform turbo capabilities from sysfs.
// Failure is non-fatal; symbolic frequencies will resolve to 0 in
// that case (matching the behavior of the pre-allocator code path).
func (a *CPUClassTurboAllocator) discoverPlatformInfo() {
	info, err := discoverTurboInfo(a.sys)
	if err != nil {
		log.Warnf("CPUClassTurboAllocator: cannot discover platform turbo info: %v", err)
		return
	}
	a.turboInfo = info
}

// pushInitialClassDefinitions resolves symbolic frequencies in every
// CPUClass and pushes the resulting cpucfg.Class to the CPU controller
// via cpucontrol.SetClass. At this point no class has been declared a
// turbo winner yet, so symbolic "turbo" resolves to the platform max
// turbo frequency for every class. The first UseClass call will
// trigger recalculateTurbo() to enforce the priority-based effective
// turbo.
func (a *CPUClassTurboAllocator) pushInitialClassDefinitions() {
	for _, cc := range a.classes {
		var controlClass cpucfg.Class
		if a.turboInfo != nil {
			controlClass = resolvedCpuClassToControlClass(cc, a.turboInfo, 0)
		} else {
			controlClass = cpuClassToControlClass(cc)
		}
		cpucontrol.SetClass(cc.Name, controlClass)
		log.Infof("cpuClass %q configured: minFreq=%s(%d) maxFreq=%s(%d) disabledCstates=%v",
			cc.Name, cc.MinFreq, controlClass.MinFreq, cc.MaxFreq, controlClass.MaxFreq, cc.DisabledCstates)
	}
}

// recalculateTurbo resolves exclusive turbo frequency access based on
// turboPriority across all CPU classes that currently have active CPUs.
//
// Algorithm (steady-state no-op):
//  1. Find the highest turboPriority among classes with non-empty
//     active CPU sets.
//  2. If the new highest priority equals the previously computed one,
//     return immediately. Effective frequencies cannot have changed.
//  3. Otherwise: update CPU controller class definitions for ALL
//     CPUClasses. Then re-Assign only the CPUs of classes whose
//     winner status flipped (won-before differs from wins-now). The
//     CPU controller's per-CPU last-written cache deduplicates any
//     redundant sysfs writes for CPUs whose actual values stay the
//     same.
func (a *CPUClassTurboAllocator) recalculateTurbo() {
	if len(a.classes) == 0 {
		return
	}

	// Find the highest turboPriority among classes with active CPUs.
	newPrio := 0
	for _, cc := range a.classes {
		if cc.TurboPriority <= newPrio {
			continue
		}
		if set, ok := a.activeCpus[cc.Name]; ok && !set.IsEmpty() {
			newPrio = cc.TurboPriority
		}
	}

	// Steady-state fast path.
	if newPrio == a.winnerPrio {
		return
	}

	prevPrio := a.winnerPrio
	a.winnerPrio = newPrio

	if a.turboInfo == nil {
		// No platform info -> we cannot compute effective turbo.
		// Still update winnerPrio to avoid repeated warnings.
		log.Warnf("turbo recalculation skipped: no platform turbo info available")
		return
	}

	// Update CPU controller class definitions for every CPUClass with
	// the new effective turbo. In-memory only; sysfs writes happen
	// via the per-class Assign loop below (deduplicated by the CPU
	// controller's lastFreq cache).
	for _, cc := range a.classes {
		effectiveTurboKHz := a.turboInfo.baseFreqKHz
		if newPrio == 0 || cc.TurboPriority >= newPrio {
			effectiveTurboKHz = a.turboInfo.maxTurboFreqKHz
		}
		controlClass := resolvedCpuClassToControlClass(cc, a.turboInfo, effectiveTurboKHz)
		cpucontrol.SetClass(cc.Name, controlClass)
		log.Infof("turbo: class %q (prio=%d, winner=%v): minFreq=%d maxFreq=%d",
			cc.Name, cc.TurboPriority,
			newPrio == 0 || cc.TurboPriority >= newPrio,
			controlClass.MinFreq, controlClass.MaxFreq)
	}

	// Re-Assign CPUs of classes whose winner status changed. On the
	// first-ever recalculation (prevPrio == -1) the caller's own
	// UseClass call assigns its CPUs after we return; other classes
	// (only relevant on policy reload) need re-Assign here.
	wonBefore := func(prio int) bool { return prevPrio == 0 || prio >= prevPrio }
	winsNow := func(prio int) bool { return newPrio == 0 || prio >= newPrio }
	if prevPrio < 0 {
		wonBefore = func(prio int) bool { return false }
	}
	for _, cc := range a.classes {
		if wonBefore(cc.TurboPriority) == winsNow(cc.TurboPriority) {
			continue
		}
		set, ok := a.activeCpus[cc.Name]
		if !ok || set.IsEmpty() {
			continue
		}
		if err := cpucontrol.Assign(a.cch, cc.Name, set.UnsortedList()...); err != nil {
			log.Warnf("turbo: failed to assign CPUs %s of class %q: %v", set, cc.Name, err)
		}
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
// It uses the first online CPU's frequency range as representative,
// since base/min/max turbo frequencies are typically identical across
// all P-cores on Intel platforms.
func discoverTurboInfo(sys sysfs.System) (*platformTurboInfo, error) {
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
		if baseFreq == 0 || freq.Max == 0 {
			continue
		}
		return &platformTurboInfo{
			baseFreqKHz:     uint(baseFreq),
			maxTurboFreqKHz: uint(freq.Max),
			minFreqKHz:      uint(freq.Min),
		}, nil
	}
	return nil, fmt.Errorf("no online CPU with valid frequency information found")
}
