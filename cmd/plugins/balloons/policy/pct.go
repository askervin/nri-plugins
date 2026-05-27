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
	if a.mode == pctModeAssocOnly {
		return nil
	}
	return a.associate(cpus, a.idleClos)
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
