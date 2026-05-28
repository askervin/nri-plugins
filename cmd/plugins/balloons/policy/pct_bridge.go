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

// sstBridge is the subset of Intel SST functionality used by the
// balloons policy. Implementations: sstBridgeGoresctrl for real
// hardware via goresctrl/pkg/sst, and sstBridgeMock for an
// in-memory fake seeded from OVERRIDE_SST.
type sstBridge interface {
	// Supported reports whether SST is available.
	Supported() bool

	// ClosCount returns the number of CLOSes supported.
	ClosCount() int

	// PackageIDs returns the IDs of all packages.
	PackageIDs() []int

	// CPUsOfPackage returns the CPUs of the given package.
	CPUsOfPackage(pkgID int) []int

	// PrepareManagedMode resets and enables SST-TF on every
	// package and selects ordered priority arbitration.
	PrepareManagedMode() error

	// ConfigureClos programs CLOS frequency bounds on every
	// package.
	ConfigureClos(cfg pctClosConfig) error

	// EnableCP enables SST-CP on every package.
	EnableCP() error

	// AssociateCPUs binds each CPU to the indicated CLOS.
	AssociateCPUs(assocs []pctClosAssoc) error

	// GetCPUClosID returns the current CLOS association of a CPU.
	GetCPUClosID(cpu int) (int, error)

	// MaxHpCpus returns the maximum number of CPUs that can be
	// held in the high-priority CLOS on the given package. The
	// second return value is false if the platform does not
	// expose this capability.
	MaxHpCpus(pkgID int) (int, bool)

	// Shutdown restores managed-mode platform state to defaults.
	Shutdown() error
}

// newSstBridge returns an SST bridge: the in-memory mock when
// OVERRIDE_SST is set, otherwise the goresctrl-backed bridge.
func newSstBridge() (sstBridge, error) {
	if v := os.Getenv(sstOverrideEnvVar); v != "" {
		return newSstBridgeMock(v)
	}
	return newSstBridgeGoresctrl()
}

// sstFreqValuesEqual reports whether two CLOS frequency values in
// kHz are equal. Zero stands for "not specified".
func sstFreqValuesEqual(a, b int) bool { return a == b }

// cpusetToInts returns the CPUs in s as an int slice.
func cpusetToInts(s cpuset.CPUSet) []int { return s.UnsortedList() }
