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

package policy

// CPUClass specifies CPU frequency, C-state, and turbo attributes
// for a CPU class.
// +k8s:deepcopy-gen=true
type CPUClass struct {
	// Name of the CPU class.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// MinFreq is the minimum CPU frequency for this class.
	// Accepts values with units: "3.2GHz", "2900MHz", "2900000kHz",
	// or a plain number in kHz. Also accepts symbolic names: "min"
	// (platform minimum), "base" (CPU base frequency), "turbo"
	// (maximum turbo frequency), resolved at runtime from sysfs.
	// When turboPriority is set, "turbo" resolves to actual turbo
	// only for the highest-priority active class; others get base.
	MinFreq Frequency `json:"minFreq,omitempty"`
	// MaxFreq is the maximum CPU frequency for this class.
	// Same format and symbolic names as MinFreq.
	MaxFreq Frequency `json:"maxFreq,omitempty"`
	// EnergyPerformancePreference for CPUs in this class.
	// +kubebuilder:validation:Minimum=0
	EnergyPerformancePreference uint `json:"energyPerformancePreference,omitempty"`
	// UncoreMinFreq is the minimum uncore frequency for this class.
	// Accepts values with units like MinFreq.
	UncoreMinFreq Frequency `json:"uncoreMinFreq,omitempty"`
	// UncoreMaxFreq is the maximum uncore frequency for this class.
	// Accepts values with units like MinFreq.
	UncoreMaxFreq Frequency `json:"uncoreMaxFreq,omitempty"`
	// FreqGovernor is the CPUFreq governor for this class
	// (e.g., "performance", "powersave", "schedutil").
	FreqGovernor string `json:"freqGovernor,omitempty"`
	// DisabledCstates lists C-states disabled for CPUs in this class.
	// Example: ["C4", "C6", "C8", "C10"]
	DisabledCstates []string `json:"disabledCstates,omitempty"`
	// TurboPriority controls exclusive turbo frequency access.
	// Among CPU classes with active balloons, only the class with
	// the highest turboPriority gets the symbolic frequency "turbo"
	// resolved to the actual turbo frequency. All other classes get
	// "turbo" resolved to the base frequency instead.
	// If all classes have turboPriority 0 (default), every class
	// gets actual turbo frequencies -- no competition occurs.
	// +kubebuilder:validation:Minimum=0
	TurboPriority int `json:"turboPriority,omitempty"`
}
