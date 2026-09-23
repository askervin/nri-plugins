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

package memctl

import "github.com/containers/nri-plugins/pkg/cxl/kernel"

// ErrProbeUnsupported is returned by ProbeAliasing on architectures where
// cache lines cannot be flushed.
var ErrProbeUnsupported = kernel.ErrProbeUnsupported

// Aliasing is the result of an address line probe of memory (see
// kernel.Aliasing).
type Aliasing = kernel.Aliasing

// ProbeAliasing runs an address line test (memtest86 "walking ones") on
// the memory of a dax device (see kernel.Kernel.ProbeAliasing). The probe
// overwrites 16 bytes at a few hundred offsets: run it before the memory
// is in use.
func (mc *Manager) ProbeAliasing(dax string) (*Aliasing, error) {
	return mc.kernel().ProbeAliasing(dax)
}
