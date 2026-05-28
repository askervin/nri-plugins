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

	"github.com/containers/nri-plugins/pkg/resmgr/cache"
	"github.com/containers/nri-plugins/pkg/sysfs"
	"github.com/containers/nri-plugins/pkg/utils/cpuset"
)

// ConfigSpec carries cpuclass configuration applied via
// cpuClassHandler.Configure. Idleness is intentionally absent — the
// caller decides which class name (if any) means "idle" and applies
// it via UseClass.
type ConfigSpec struct {
	// Classes is the user-facing list of CPU classes.
	Classes []*CPUClass
	// TurboDomain selects the per-domain turbo arbitration scope.
	// Empty resolves to "package".
	TurboDomain string
	// Allowed bounds every cpuclass operation. CPUs outside this
	// set are silently dropped by Configure / UseClass / Hints.
	Allowed cpuset.CPUSet
}

// AllocationIntent describes an upcoming CPU allocation for which the
// caller wants placement preferences.
type AllocationIntent struct {
	// ClassName is the cpuClass the upcoming allocation will use.
	ClassName string
	// CurrentCpus are CPUs the balloon already owns; expansion
	// uses these to exclude self from HP-room accounting.
	CurrentCpus cpuset.CPUSet
	// FreeCpus is the set of CPUs the caller is willing to choose
	// from (typically the policy's free-CPU pool).
	FreeCpus cpuset.CPUSet
}

// CpuPreference is a named CPU set carrying a single placement
// preference (either "prefer" or "avoid" depending on which slice of
// AllocationHints it appears in).
type CpuPreference struct {
	// Name is a short human-readable identifier (e.g. "sst-hp-reserve").
	Name string
	// Cpus is the CPU set this preference applies to.
	Cpus cpuset.CPUSet
}

// AllocationHints carries technology-agnostic placement preferences
// returned by cpuClassHandler.Hints. Prefer lists CPU sets to favor;
// Avoid lists CPU sets to avoid. Both are ordered by descending
// priority.
type AllocationHints struct {
	Prefer []CpuPreference
	Avoid  []CpuPreference
}

// cpuClassHandler is the sole cpuclass entry point for policy code.
// It owns construction and configuration of the underlying
// per-technology allocators (cpufreq and pct), exposes a uniform
// UseClass for cpuset-to-class assignment, and answers Hints queries
// in technology-agnostic terms.
type cpuClassHandler struct {
	sys     sysfs.System
	cch     cache.Cache
	allowed cpuset.CPUSet

	cpufreq *cpufreqAllocator
	pct     *pctAllocator
}

// defaultClassName is the name of the CPU class used as a fallback
// when a balloon type does not specify cpuClass or when idleCpuClass
// is left empty.
const defaultClassName = "default"

// newCpuClassHandler constructs a cpuClassHandler with both internal
// allocators (cpufreq and pct) ready in a "no configuration applied"
// state. Configure must be called before the handler is usable.
func newCpuClassHandler(sys sysfs.System, cch cache.Cache) (*cpuClassHandler, error) {
	cpufreq, err := newCpufreqAllocator(withSystem(sys), withCache(cch))
	if err != nil {
		return nil, fmt.Errorf("cpuclass: failed to create cpufreq allocator: %w", err)
	}
	pct, err := newPctAllocator(sys)
	if err != nil {
		return nil, fmt.Errorf("cpuclass: failed to create pct allocator: %w", err)
	}
	return &cpuClassHandler{
		sys:     sys,
		cch:     cch,
		cpufreq: cpufreq,
		pct:     pct,
	}, nil
}

// Configure (re)applies a configuration spec. Idempotent: may be
// called repeatedly with changed classes, turbo-domain mode, or
// allowed set.
func (h *cpuClassHandler) Configure(spec ConfigSpec) error {
	h.allowed = spec.Allowed
	if err := h.cpufreq.configure(spec.Classes, spec.TurboDomain, spec.Allowed); err != nil {
		return fmt.Errorf("cpuclass: cpufreq configure: %w", err)
	}
	if err := h.pct.configure(spec.Classes, spec.Allowed); err != nil {
		return fmt.Errorf("cpuclass: pct configure: %w", err)
	}
	return nil
}

// UseClass applies className to the given CPUs across every internal
// allocator. An empty className means "no class" (resolves to
// "default" if such a class exists). CPUs outside the configured
// Allowed set are silently dropped.
func (h *cpuClassHandler) UseClass(className string, cpus cpuset.CPUSet) error {
	if err := h.cpufreq.useClass(className, cpus); err != nil {
		log.Warnf("cpuclass: cpufreq failed to apply class %q on CPUs %s: %v", className, cpus, err)
	}
	if err := h.pct.useClass(className, cpus); err != nil {
		log.Warnf("cpuclass: pct failed to apply class %q on CPUs %s: %v", className, cpus, err)
	}
	return nil
}

// Hints returns technology-agnostic placement preferences for an
// upcoming CPU allocation. The returned CpuPreference sets are always
// subsets of the configured Allowed set.
func (h *cpuClassHandler) Hints(intent AllocationIntent) AllocationHints {
	hints := h.pct.hints(intent)
	if h.allowed.Size() > 0 {
		hints = intersectHints(hints, h.allowed)
	}
	return hints
}

// Shutdown releases any platform-level resources owned by the
// handler. Safe to call multiple times.
func (h *cpuClassHandler) Shutdown() error {
	if h == nil || h.pct == nil {
		return nil
	}
	return h.pct.Shutdown()
}

// intersectHints returns a copy of hints with every CpuPreference
// constrained to the given bound. Preferences that become empty are
// dropped.
func intersectHints(hints AllocationHints, bound cpuset.CPUSet) AllocationHints {
	out := AllocationHints{}
	for _, p := range hints.Prefer {
		s := p.Cpus.Intersection(bound)
		if s.IsEmpty() {
			continue
		}
		out.Prefer = append(out.Prefer, CpuPreference{Name: p.Name, Cpus: s})
	}
	for _, p := range hints.Avoid {
		s := p.Cpus.Intersection(bound)
		if s.IsEmpty() {
			continue
		}
		out.Avoid = append(out.Avoid, CpuPreference{Name: p.Name, Cpus: s})
	}
	return out
}
