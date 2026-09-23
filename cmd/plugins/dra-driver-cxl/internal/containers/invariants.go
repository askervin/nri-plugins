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

package containers

import (
	"fmt"
)

// Check returns the violations of the invariant of the fenced containers
// (I11): the cgroup cpuset.mems of every fenced, started container with a
// readable cgroup is its wantMems, once fencing is ready and nodes are
// fenced. A container whose last update failed violates it until the next
// pass.
func (p *Plugin) Check() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.readiness != ReadinessReady || p.fenced.IsEmpty() {
		return nil
	}
	var out []string
	mem := p.memNodes()
	for _, c := range p.sorted() {
		if c.Management != ManagementFenced || c.Lifecycle != LifecycleStarted || c.CgroupDir == "" {
			continue
		}
		want, err := passMems(c, p.fenced, mem)
		if err != nil {
			continue
		}
		if cur := curMems(c); !sameMems(want, cur) {
			out = append(out, fmt.Sprintf("I11: ctr=%s id=%s: cpuset.mems %q, not %s (fenced nodes %s)", c.name(), c.ID, cur, want, p.fenced))
		}
	}
	return out
}
