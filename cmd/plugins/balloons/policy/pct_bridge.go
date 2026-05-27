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
	"os"

	"github.com/containers/nri-plugins/pkg/utils/cpuset"
)

// pctClosConfig describes one CLOS configuration that the
// pctAllocator wants the SST bridge to program.
type pctClosConfig struct {
	ClosID  int
	MinFreq int // kHz
	MaxFreq int // kHz
}

// pctClosAssoc records the desired CLOS association for a CPU.
type pctClosAssoc struct {
	CPU    int
	ClosID int
}

// sstBridge is the small subset of Intel SST functionality the
// balloons policy needs. Implemented by sstBridgeGoresctrl (real
// hardware via goresctrl/pkg/sst) and sstBridgeMock (in-memory
// fake seeded from OVERRIDE_SST for development and e2e testing).
type sstBridge interface {
	// Supported returns true if SST is available on this host
	// (or the mock has been seeded as supported).
	Supported() bool

	// ClosCount returns the number of CLOSes supported (typically 4).
	ClosCount() int

	// PackageIDs returns the IDs of all packages present.
	PackageIDs() []int

	// CPUsOfPackage returns the CPUs belonging to the given package.
	CPUsOfPackage(pkgID int) []int

	// PrepareManagedMode performs the full SoC-wide initialization
	// sequence required before per-CLOS configuration: CPReset,
	// TFEnable, CPSetPriorityType(Ordered) for every package.
	PrepareManagedMode() error

	// ConfigureClos programs CLOS bounds on every package.
	ConfigureClos(cfg pctClosConfig) error

	// EnableCP enables SST-CP on every package, completing the
	// managed-mode setup. Called once after all ConfigureClos calls.
	EnableCP() error

	// AssociateCPUs binds each CPU to the indicated CLOS. No-op if
	// the CPU is already associated to that CLOS.
	AssociateCPUs(assocs []pctClosAssoc) error

	// GetCPUClosID returns the current CLOS association of a CPU.
	GetCPUClosID(cpu int) (int, error)

	// MaxHpCpus returns the maximum number of CPUs that can be
	// simultaneously held in the high-priority CLOS on the given
	// package. The second return value is false if the platform
	// does not expose this capability; callers should then fall
	// back to a free-CPU-count heuristic.
	MaxHpCpus(pkgID int) (int, bool)

	// Shutdown restores managed-mode platform state to a sensible
	// default (associate all CPUs to CLOS 0, optionally disable
	// SST-TF/CP). For the mock this also flushes the state file.
	Shutdown() error
}

// newSstBridge selects the SST bridge implementation. If
// OVERRIDE_SST is set the in-memory mock is used; otherwise the
// real goresctrl-backed bridge.
func newSstBridge() (sstBridge, error) {
	if v := os.Getenv(sstOverrideEnvVar); v != "" {
		return newSstBridgeMock(v)
	}
	return newSstBridgeGoresctrl()
}

// sstFreqValuesEqual reports whether two CLOS frequency values
// (kHz) should be considered equal. Zero means "not specified",
// which the bridge interprets as "leave whatever is there".
func sstFreqValuesEqual(a, b int) bool { return a == b }

// cpusetToInts is a small helper used by the bridge implementations.
func cpusetToInts(s cpuset.CPUSet) []int { return s.UnsortedList() }
