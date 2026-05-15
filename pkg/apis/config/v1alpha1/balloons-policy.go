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

package v1alpha1

import (
	cpucfg "github.com/containers/nri-plugins/pkg/apis/config/v1alpha1/resmgr/control/cpu"
	policyapi "github.com/containers/nri-plugins/pkg/apis/config/v1alpha1/resmgr/policy"
)

var (
	_ ResmgrConfig = &BalloonsPolicy{}
)

func (c *BalloonsPolicy) AgentConfig() *AgentConfig {
	if c == nil {
		return nil
	}

	a := c.Spec.Agent

	return &a
}

func (c *BalloonsPolicy) CommonConfig() *CommonConfig {
	if c == nil {
		return nil
	}
	ctrl := c.Spec.Control
	// Inject user-friendly cpuClasses into control.cpu.classes so
	// the CPU controller sees them at startup. CPUClasses entries
	// take precedence over identically-named control.cpu.classes.
	// Symbolic frequencies (min, base, turbo) are passed as 0 here;
	// the balloons policy resolves them at runtime using sysfs data.
	if len(c.Spec.CPUClasses) > 0 {
		if ctrl.CPU.Classes == nil {
			ctrl.CPU.Classes = make(map[string]cpucfg.Class)
		}
		for _, cc := range c.Spec.CPUClasses {
			ctrl.CPU.Classes[cc.Name] = cpucfg.Class{
				MinFreq:                     freqKHzOrZero(cc.MinFreq),
				MaxFreq:                     freqKHzOrZero(cc.MaxFreq),
				EnergyPerformancePreference: cc.EnergyPerformancePreference,
				UncoreMinFreq:               freqKHzOrZero(cc.UncoreMinFreq),
				UncoreMaxFreq:               freqKHzOrZero(cc.UncoreMaxFreq),
				FreqGovernor:                cc.FreqGovernor,
				DisabledCstates:             cc.DisabledCstates,
			}
		}
	}
	return &CommonConfig{
		Control:         ctrl,
		Log:             c.Spec.Log,
		Instrumentation: c.Spec.Instrumentation,
	}
}

// freqKHzOrZero returns the kHz value of a frequency, or 0 if it is
// symbolic (min/base/turbo). Symbolic frequencies are resolved later
// by the policy using actual platform sysfs data.
func freqKHzOrZero(f policyapi.Frequency) uint {
	if f.IsSymbolic() {
		return 0
	}
	return f.KHz()
}

func (c *BalloonsPolicy) PolicyConfig() interface{} {
	if c == nil {
		return nil
	}
	return &c.Spec.Config
}

func (c *BalloonsPolicy) Validate() error {
	if c == nil {
		return nil
	}

	if err := c.CommonConfig().Validate(); err != nil {
		return err
	}

	if err := c.Spec.Validate(); err != nil {
		return err
	}

	return nil
}
