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

package main

import (
	"fmt"

	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// Settings of local memdevs: the usable size of a memdev whose memory
// aliases (offsets X and X+P reach the same memory, as on a device or
// platform that ignores an address bit) comes from memdevSettings and from
// the address line probe that the device engine runs on every new region
// (verifyAddressing), whose results it keeps in localProbes.json; the
// engine makes the regions of the memdev with only the usable size and the
// publisher publishes only that.

// MemdevSetting is a setting of the local memdevs that Device matches.
type MemdevSetting struct {
	// Device matches a memdev by name (mem0, cxl/mem0) or serial (decimal
	// or 0x hex).
	Device string `json:"device"`
	// spec is Device parsed by validate.
	spec dra.MemdevSpec
	// UsableSize is a quantity ("128Gi"): only the first UsableSize bytes
	// of the RAM capacity of the memdev are used. Use it for a memdev
	// whose memory is broken or aliased above it. Rounded down to a
	// multiple of 256 MiB.
	UsableSize string `json:"usableSize,omitempty"`
	// Coherent tells that the memory of the memdev is coherent between
	// the hosts that share it (sharedDevices): other hosts' writes are
	// visible without cache maintenance.
	Coherent bool `json:"coherent,omitempty"`
}

// validateMemdevSettings returns an error if a memdev setting is invalid.
func (c *DriverConfig) validateMemdevSettings() error {
	for i := range c.MemdevSettings {
		s := &c.MemdevSettings[i]
		if s.Device == "" {
			return fmt.Errorf("memdevSettings[%d]: no device", i)
		}
		spec, err := dra.ParseMemdevID(s.Device)
		if err != nil {
			return fmt.Errorf("memdevSettings[%d]: %w", i, err)
		}
		s.spec = spec
		if s.UsableSize != "" {
			q, err := resource.ParseQuantity(s.UsableSize)
			if err != nil {
				return fmt.Errorf("memdevSettings[%d]: usableSize %q: %w", i, s.UsableSize, err)
			}
			if q.Value() < kernel.RegionAlign {
				return fmt.Errorf("memdevSettings[%d]: usableSize %q is less than %s", i, s.UsableSize,
					resource.NewQuantity(kernel.RegionAlign, resource.BinarySI))
			}
		}
	}
	return nil
}

// memdevSetting returns the first memdev setting that matches the memdev
// name or serial, nil if none.
func (c *DriverConfig) memdevSetting(memdev string, serial uint64) *MemdevSetting {
	if c == nil {
		return nil
	}
	for i := range c.MemdevSettings {
		if s := &c.MemdevSettings[i]; s.spec.MatchID(memdev, serial) {
			return s
		}
	}
	return nil
}

// configuredUsableSize returns the usableSize of the first memdev setting
// that matches the memdev name or serial, 0 if none.
func (c *DriverConfig) configuredUsableSize(memdev string, serial uint64) uint64 {
	s := c.memdevSetting(memdev, serial)
	if s == nil || s.UsableSize == "" {
		return 0
	}
	q, err := resource.ParseQuantity(s.UsableSize)
	if err != nil || q.Value() <= 0 {
		return 0
	}
	return uint64(q.Value())
}

// memdevCoherent returns coherent of the first memdev setting that matches
// the memdev name or serial, false if none.
func (c *DriverConfig) memdevCoherent(memdev string, serial uint64) bool {
	s := c.memdevSetting(memdev, serial)
	return s != nil && s.Coherent
}

// verifyAddressing tells whether the allocator probes new regions for
// aliasing (VerifyAddressing, default true).
func (c *DriverConfig) verifyAddressing() bool {
	return c == nil || c.VerifyAddressing == nil || *c.VerifyAddressing
}
