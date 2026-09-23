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
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
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
	// Device matches a memdev by name (mem0) or serial (decimal, 0x<hex>
	// or <hex>).
	Device string `json:"device"`
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
	for i, s := range c.MemdevSettings {
		if s.Device == "" {
			return fmt.Errorf("memdevSettings[%d]: no device", i)
		}
		if s.UsableSize != "" {
			q, err := resource.ParseQuantity(s.UsableSize)
			if err != nil {
				return fmt.Errorf("memdevSettings[%d]: usableSize %q: %w", i, s.UsableSize, err)
			}
			if q.Value() < dra.CXLRegionAlign {
				return fmt.Errorf("memdevSettings[%d]: usableSize %q is less than 256Mi", i, s.UsableSize)
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
		if s := &c.MemdevSettings[i]; settingMatches(s.Device, memdev, serial) {
			return s
		}
	}
	return nil
}

// settingMatches tells whether the device of a memdev setting matches the
// memdev name or serial: the name, or the serial in decimal, 0x<hex> or
// <hex>, compared as a number.
func settingMatches(spec, memdev string, serial uint64) bool {
	if spec == memdev {
		return true
	}
	if hex, ok := strings.CutPrefix(spec, "0x"); ok {
		v, err := strconv.ParseUint(hex, 16, 64)
		return err == nil && v == serial
	}
	if v, err := strconv.ParseUint(spec, 10, 64); err == nil && v == serial {
		return true
	}
	v, err := strconv.ParseUint(spec, 16, 64)
	return err == nil && v == serial
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
