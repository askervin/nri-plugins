// Copyright 2022 Intel Corporation. All Rights Reserved.
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

package cpu

import (
	"fmt"

	"github.com/containers/nri-plugins/pkg/utils/cpuset"

	cfgapi "github.com/containers/nri-plugins/pkg/apis/config/v1alpha1/resmgr/control"
	cfgcpu "github.com/containers/nri-plugins/pkg/apis/config/v1alpha1/resmgr/control/cpu"
	logger "github.com/containers/nri-plugins/pkg/log"
	"github.com/containers/nri-plugins/pkg/resmgr/cache"
	"github.com/containers/nri-plugins/pkg/resmgr/control"
	"github.com/containers/nri-plugins/pkg/sysfs"
	"github.com/intel/goresctrl/pkg/cstates"
	"github.com/intel/goresctrl/pkg/utils"
)

const (
	// ConfigModuleName is the configuration section for the CPU controller.
	ConfigModuleName = "cpu"

	// CPUController is the name of the CPU controller.
	CPUController = cache.CPU
)

// cpuctl encapsulates the runtime state of our CPU enforcement/controller.
type cpuctl struct {
	cache         cache.Cache      // resource manager cache
	system        sysfs.System     // system topology
	classes       map[string]Class // configured CPU classes
	cstates       *cstates.Cstates // C-states handler
	uncoreEnabled bool             // whether we need to care about uncore
	started       bool
	lastFreq      map[int]cpufreqState // cpu id -> last successfully written cpufreq values
	// dirtyCPUs accumulates CPUs whose desired class definition or
	// class assignment has changed since the last Commit(). Writes to
	// sysfs are deferred until Commit() so that intermediate bursts
	// of Assign()/SetClass() calls within a single policy decision
	// do not produce sequences of redundant or temporarily-wrong
	// sysfs writes.
	dirtyCPUs map[int]bool
}

// cpufreqState tracks the last successfully written cpufreq values
// for a single CPU. Used to skip redundant sysfs writes.
type cpufreqState struct {
	min      uint
	max      uint
	governor string
	hasMin   bool
	hasMax   bool
	hasGov   bool
}

type Class = cfgcpu.Class

var log logger.Logger = logger.NewLogger(CPUController)

// Ccontroller singleton instance.
var singleton *cpuctl

// getCPUController returns the (singleton) CPU controller instance.
func getCPUController() *cpuctl {
	if singleton == nil {
		singleton = &cpuctl{}
	}
	return singleton
}

// Check if our configuration is effectively empty.
func isEmptyConfig(cfg *cfgapi.Config) bool {
	return cfg == nil || len(cfg.CPU.Classes) == 0
}

// Start initializes the controller for enforcing decisions.
func (ctl *cpuctl) Start(cache cache.Cache, cfg *cfgapi.Config) (bool, error) {
	if isEmptyConfig(cfg) {
		log.Infof("empty configuration, disabling controller")
		return false, nil
	}

	sys, err := sysfs.DiscoverSystem()
	if err != nil {
		return false, fmt.Errorf("failed to discover system topology: %w", err)
	}

	ctl.system = sys
	ctl.cache = cache

	// DEBUG: dump the class assignments we have stored in the cache
	log.Debugf("retrieved cpu class assignments from cache:\n%s", utils.DumpJSON(getClassAssignments(ctl.cache)))

	if err := ctl.configure(cfg); err != nil {
		// Just print an error. A config update later on may be valid.
		log.Errorf("failed apply /cpuinitial configuration: %v", err)
	}

	ctl.started = true

	return true, nil
}

// Stop shuts down the controller.
func (ctl *cpuctl) Stop() {
}

// PreCreateHook handler for the CPU controller.
func (ctl *cpuctl) PreCreateHook(c cache.Container) error {
	return nil
}

// PreStartHook handler for the CPU controller.
func (ctl *cpuctl) PreStartHook(c cache.Container) error {
	return nil
}

// PostStartHook handler for the CPU controller.
func (ctl *cpuctl) PostStartHook(c cache.Container) error {
	return nil
}

// PostUpdateHook handler for the CPU controller.
func (ctl *cpuctl) PostUpdateHook(c cache.Container) error {
	return nil
}

// PostStopHook handler for the CPU controller.
func (ctl *cpuctl) PostStopHook(c cache.Container) error {
	return nil
}

// markCPUsDirty records the given CPUs as needing a sysfs re-check at
// the next Commit().
func (ctl *cpuctl) markCPUsDirty(cpus ...int) {
	if ctl.dirtyCPUs == nil {
		ctl.dirtyCPUs = make(map[int]bool, len(cpus))
	}
	for _, c := range cpus {
		ctl.dirtyCPUs[c] = true
	}
}

// markClassDirty records every CPU currently assigned to the given
// class as dirty. Used when SetClass changes a class definition that
// already has CPUs assigned to it.
func (ctl *cpuctl) markClassDirty(class string) {
	if ctl.cache == nil {
		return
	}
	assignments := *getClassAssignments(ctl.cache)
	cpus, ok := assignments[class]
	if !ok {
		return
	}
	ctl.markCPUsDirty(cpus.Members()...)
}

// Commit flushes deferred per-CPU sysfs updates accumulated since the
// previous Commit. It is the choke point that converts the desired
// state (class definitions in ctl.classes + cached class assignments)
// into the minimal set of sysfs writes needed to reach it. Per-CPU
// writes are still deduplicated against ctl.lastFreq, so even if a
// CPU is marked dirty by multiple intermediate Assign/SetClass calls
// the final value is written at most once.
func (ctl *cpuctl) Commit() error {
	if !ctl.started || len(ctl.dirtyCPUs) == 0 {
		return nil
	}

	assignments := *getClassAssignments(ctl.cache)

	// Group dirty CPUs by their currently assigned class. CPUs that
	// no longer appear in any class assignment are skipped: there is
	// no class definition to enforce on them.
	cpuClass := make(map[int]string, len(ctl.dirtyCPUs))
	for class, cpus := range assignments {
		for id := range cpus {
			if ctl.dirtyCPUs[int(id)] {
				cpuClass[int(id)] = class
			}
		}
	}

	byClass := make(map[string][]int, len(ctl.classes))
	for cpu, class := range cpuClass {
		byClass[class] = append(byClass[class], cpu)
	}

	var firstErr error
	for class, cpus := range byClass {
		if _, ok := ctl.classes[class]; !ok {
			log.Warnf("commit: class %q (cpus %v) missing from configuration", class, cpus)
			continue
		}
		if err := ctl.enforceCpufreq(class, cpus...); err != nil {
			log.Errorf("commit: cpufreq enforcement failed for class %q: %v", class, err)
			if firstErr == nil {
				firstErr = err
			}
		}
		if err := ctl.enforceCstates(class, cpus...); err != nil {
			log.Errorf("commit: cstate enforcement failed for class %q: %v", class, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	// Uncore is per-die; recompute over all dirty CPUs in one pass.
	affectedCPUs := make([]int, 0, len(ctl.dirtyCPUs))
	for cpu := range ctl.dirtyCPUs {
		affectedCPUs = append(affectedCPUs, cpu)
	}
	if err := ctl.enforceUncore(assignments, affectedCPUs...); err != nil {
		log.Errorf("commit: uncore enforcement failed: %v", err)
		if firstErr == nil {
			firstErr = err
		}
	}

	// Clear the dirty set unconditionally. enforceCpufreq has its own
	// per-property lastFreq update logic that avoids re-trying writes
	// that keep failing for unchanged desired values.
	ctl.dirtyCPUs = nil

	return firstErr
}

// enforceCpufreq enforces a class-specific cpufreq configuration to a cpuset.
// Per-CPU sysfs writes are skipped when the desired value matches the
// last successfully written value (tracked in ctl.lastFreq). A write
// failure on one CPU/property is logged but does not stop processing
// of remaining CPUs/properties. The first error encountered is
// returned to the caller.
func (ctl *cpuctl) enforceCpufreq(class string, cpus ...int) error {
	c, ok := ctl.classes[class]
	if !ok {
		return fmt.Errorf("non-existent cpu class %q", class)
	}
	if ctl.lastFreq == nil {
		ctl.lastFreq = make(map[int]cpufreqState)
	}

	min := uint(c.MinFreq)
	max := uint(c.MaxFreq)
	governor := c.FreqGovernor

	var firstErr error
	for _, cpu := range cpus {
		state := ctl.lastFreq[cpu]

		if min > 0 && (!state.hasMin || state.min != min) {
			log.Debugf("enforcing cpu frequency min %d from class %q on cpu %d", min, class, cpu)
			if err := utils.SetCPUScalingMinFreq(utils.ID(cpu), int(min)); err != nil {
				log.Errorf("cannot set min freq %d on cpu %d: %v", min, cpu, err)
				if firstErr == nil {
					firstErr = err
				}
			}
			// Update the cache even on failure: the desired value
			// is unchanged so retrying on every Assign would just
			// spam logs without ever succeeding. A subsequent
			// configure() resets lastFreq so a real configuration
			// change still triggers a fresh attempt.
			state.min = min
			state.hasMin = true
		}

		if max > 0 && (!state.hasMax || state.max != max) {
			log.Debugf("enforcing cpu frequency max %d from class %q on cpu %d", max, class, cpu)
			if err := utils.SetCPUScalingMaxFreq(utils.ID(cpu), int(max)); err != nil {
				log.Errorf("cannot set max freq %d on cpu %d: %v", max, cpu, err)
				if firstErr == nil {
					firstErr = err
				}
			}
			state.max = max
			state.hasMax = true
		}

		if governor != "" && (!state.hasGov || state.governor != governor) {
			log.Debugf("enforcing cpu frequency governor %q from class %q on cpu %d", governor, class, cpu)
			if err := utils.SetCPUScalingGovernor(utils.ID(cpu), governor); err != nil {
				log.Errorf("cannot set cpufreq governor %q on cpu %d: %v", governor, cpu, err)
				if firstErr == nil {
					firstErr = err
				}
			}
			state.governor = governor
			state.hasGov = true
		}

		ctl.lastFreq[cpu] = state
	}

	return firstErr
}

// enforceCstates enforces a class-specific C-state configuration to a cpuset
func (ctl *cpuctl) enforceCstates(class string, cpus ...int) error {
	c, ok := ctl.classes[class]
	if !ok {
		return fmt.Errorf("non-existent cpu class %q", class)
	}
	if ctl.cstates == nil || len(cpus) == 0 {
		return nil
	}
	enabledCstates := []string{}
	for _, name := range ctl.cstates.Names() {
		enabled := true
		for _, dname := range c.DisabledCstates {
			if name == dname {
				enabled = false
				break
			}
		}
		if enabled {
			enabledCstates = append(enabledCstates, name)
		}
	}
	cpuCstates := ctl.cstates.Copy(cstates.NewBasicFilter().SetCPUs(cpus...))
	enCpuCstates := cpuCstates.Copy(cstates.NewBasicFilter().SetCstateNames(enabledCstates...))
	disCpuCstates := cpuCstates.Copy(cstates.NewBasicFilter().SetCstateNames(c.DisabledCstates...))
	enCpuCstates.SetAttrs(cstates.AttrDisable, "0")
	disCpuCstates.SetAttrs(cstates.AttrDisable, "1")
	log.Debugf("enforcing cstates: enable: %v disable: %v from class %q on cpus %v", enabledCstates, c.DisabledCstates, class, cpus)
	if err := enCpuCstates.Apply(); err != nil {
		return fmt.Errorf("cannot enable cstates %v on cpus %v: %w", enabledCstates, cpus, err)
	}
	if err := disCpuCstates.Apply(); err != nil {
		return fmt.Errorf("cannot disable cstates %v on cpus %v: %w", c.DisabledCstates, cpus, err)
	}
	return nil
}

// enforceUncore enforces uncore frequency limits
func (ctl *cpuctl) enforceUncore(assignments cpuClassAssignments, affectedCPUs ...int) error {
	if !ctl.uncoreEnabled {
		return nil
	}

	cpus := cpuset.New(affectedCPUs...)

	for _, cpuPkgID := range ctl.system.PackageIDs() {
		cpuPkg := ctl.system.Package(cpuPkgID)
		for _, cpuDieID := range cpuPkg.DieIDs() {
			dieCPUs := cpuPkg.DieCPUSet(cpuDieID)

			// Check if this die is affected by the specified cpuset
			if cpus.Size() == 0 || dieCPUs.Intersection(cpus).Size() > 0 {
				min, max, minCls, maxCls := effectiveUncoreFreqs(utils.NewIDSet(dieCPUs.List()...), ctl.classes, assignments)

				if min == 0 && max == 0 {
					log.Debugf("no uncore frequency limits for cpu package/die %d/%d", cpuPkgID, cpuDieID)
					continue
				}

				log.Debugf("enforcing uncore min freq to %d (class %q), max freq to %d (class %q) on cpu package/die %d/%d", min, minCls, max, maxCls, cpuPkgID, cpuDieID)
				if min > 0 {
					if max > 0 && min > max {
						log.Warnf("uncore frequency limit min > max (%d > %d) on cpu package/die %d/%d", min, max, cpuPkgID, cpuDieID)
					}

					if err := utils.SetUncoreMinFreq(cpuPkgID, cpuDieID, int(min)); err != nil {
						return err
					}
				}
				if max > 0 {
					if err := utils.SetUncoreMaxFreq(cpuPkgID, cpuDieID, int(max)); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// effectiveUncoreClasses resolves the effective classes for setting the uncore
// frequency limits for a cpu package/die. It has "performance preference" so
// that the highest value (for both min and max) of the cpu classes effective
// on the die is selected.
func effectiveUncoreFreqs(cpus utils.IDSet, classes map[string]Class, assignments cpuClassAssignments) (minFreq, maxFreq uint, minCls, maxCls string) {
	for className, assignedCPUs := range assignments {
		// Check if this class is "effective" on the specified cpuset
		if idSetIntersects(cpus, assignedCPUs) {
			class := classes[className]
			if class.UncoreMinFreq > minFreq {
				minCls = className
				minFreq = class.UncoreMinFreq
			}
			if class.UncoreMaxFreq > maxFreq {
				maxCls = className
				maxFreq = class.UncoreMaxFreq
			}
		}
	}
	return minFreq, maxFreq, minCls, maxCls
}

func idSetIntersects(a, b utils.IDSet) bool {
	// Try to optimize the search for unbalanced idsets
	if len(a) < len(b) {
		for id := range a {
			if _, ok := b[id]; ok {
				return true
			}
		}
	} else {
		for id := range b {
			if _, ok := a[id]; ok {
				return true
			}
		}
	}
	return false
}

func (ctl *cpuctl) configure(cfg *cfgapi.Config) error {
	// Preserve any class definitions that were pushed via SetClass
	// before the controller started. The balloons policy uses
	// SetClass to publish CPU class definitions with proper kHz
	// values resolved from symbolic frequencies (min/base/turbo).
	// CommonConfig() also injects placeholder entries (kHz=0) into
	// cfg.CPU.Classes so that controller startup sanity checks see
	// the class names. Merge them: cfg-provided classes seed the
	// map, then any SetClass-pushed values take precedence.
	preserved := ctl.classes
	ctl.classes = nil
	ctl.uncoreEnabled = false
	// Reset per-CPU last-written cache: a config change may
	// alter min/max for the same class, so the next enforce
	// pass must actually write to sysfs.
	ctl.lastFreq = nil
	// Reset the dirty set; we'll re-populate it below with every
	// CPU currently assigned to a known class so that the Commit()
	// at the end of configure() re-enforces the full desired state.
	ctl.dirtyCPUs = nil

	if cfg != nil && len(cfg.CPU.Classes) != 0 {
		ctl.classes = make(map[string]Class, len(cfg.CPU.Classes))
		for name, c := range cfg.CPU.Classes {
			ctl.classes[name] = c
		}
	}
	for name, c := range preserved {
		if ctl.classes == nil {
			ctl.classes = make(map[string]Class)
		}
		ctl.classes[name] = c
	}

	// Re-configure CPUs that are assigned to some known class
	assignments := *getClassAssignments(ctl.cache)

	// DEBUG: dump the class assignments we have stored in the cache
	log.Debugf("applying cpu controller configuration:\n%s", utils.DumpJSON(ctl.classes))

	// Sanity check
	cstatesNeeded := map[string]bool{}
	uncoreAvailable := utils.UncoreFreqAvailable()
	for name, conf := range ctl.classes {
		if conf.UncoreMinFreq != 0 || conf.UncoreMaxFreq != 0 {
			if !uncoreAvailable {
				return fmt.Errorf("uncore limits set in cpu class %q but uncore driver not available in the system, make sure that the intel_uncore_frequency driver is loaded", name)
			}
			ctl.uncoreEnabled = true
			break
		}
		for _, cstate := range conf.DisabledCstates {
			cstatesNeeded[cstate] = true
		}
	}
	if len(cstatesNeeded) != 0 {
		var err error
		filter := cstates.NewBasicFilter().SetAttributes(cstates.AttrDisable)
		if cstatesEnvOverridesJson != "" {
			// Only for e2e tests: do not access C-states
			// in sysfs. Instead, load C-states
			// configuration from the JSON, simulate sysfs
			// and log all accesses to it.
			ctl.cstates, err = NewCstatesFromOverride(filter)
		} else {
			ctl.cstates, err = cstates.NewCstatesFromSysfs(filter)
		}
		if err != nil {
			return fmt.Errorf("failed to read C-states: %w", err)
		}
	}

	// Mark every CPU assigned to a known class as dirty so the
	// Commit() below re-enforces all per-CPU values in one batch.
	// Classes that have disappeared from the configuration are
	// preserved in the cache, but their CPUs are not re-enforced
	// (see the warning below).
	for class, cpus := range assignments {
		if _, ok := ctl.classes[class]; ok {
			for id := range cpus {
				ctl.markCPUsDirty(int(id))
			}
		} else {
			// TODO: what should we really do with classes that do not exist in
			// the configuration anymore? Now we remember the CPUs assigned to
			// them. A further config update might re-introduce the class in
			// which case the CPUs will be reconfigured.
			log.Warnf("class %q with cpus %v missing from the configuration", class, cpus)
		}
	}

	log.Debugf("cpu controller configured")

	return nil
}

func (ctl *cpuctl) getClasses() map[string]Class {
	ret := make(map[string]Class, len(ctl.classes))
	for k, v := range ctl.classes {
		ret[k] = v
	}
	return ret
}

// Register us as a controller.
func init() {
	err := control.Register(CPUController, "CPU controller", getCPUController())
	if err != nil {
		log.Warnf("failed to register CPU controller: %v", err)
	}
}
