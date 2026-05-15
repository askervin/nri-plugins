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
	"github.com/containers/nri-plugins/pkg/resmgr/cache"
	"github.com/intel/goresctrl/pkg/utils"
)

// GetClasses returns all available CPU classes.
func GetClasses() map[string]Class {
	return getCPUController().getClasses()
}

// SetClass adds or updates a CPU class definition. This allows
// policies to dynamically define CPU classes (e.g., from
// user-friendly CPUClasses configuration) without requiring them
// to be present in the static control.cpu.classes config.
//
// The change is purely in-memory: any CPUs currently assigned to the
// updated class are marked dirty so the next Commit() will re-enforce
// the new definition on them in a single batch.
func SetClass(name string, class Class) {
	ctl := getCPUController()
	if ctl.classes == nil {
		ctl.classes = make(map[string]Class)
	}
	ctl.classes[name] = class
	ctl.markClassDirty(name)
}

// Assign assigns a set of cpus to a class.
//
// The assignment is recorded in the cache (so it survives across
// restarts) and the affected CPUs are marked dirty. No sysfs writes
// happen here; the CPU controller's Commit() (invoked once per NRI
// request after all per-container hooks have run) coalesces all
// pending changes into the minimal set of writes needed to reach the
// final desired state.
func Assign(c cache.Cache, class string, cpus ...int) error {
	// NOTE: no locking implemented anywhere around -> we don't expect multiple parallel callers

	// Store the class assignment. Assign cpus to a class and remove them from
	// other classes
	assignments := *getClassAssignments(c)

	if this, ok := assignments[class]; !ok {
		assignments[class] = utils.NewIDSetFromIntSlice(cpus...)
	} else {
		this.Add(cpus...)
	}

	for k, v := range assignments {
		if k != class {
			v.Del(cpus...)

			// Don't store empty classes, serves as a garbage collector, too
			if v.Size() == 0 {
				delete(assignments, k)
			}
		}
	}

	setClassAssignments(c, &assignments)

	getCPUController().markCPUsDirty(cpus...)

	return nil
}
