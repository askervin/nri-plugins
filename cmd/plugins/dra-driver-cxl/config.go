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
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// DriverConfig is the configuration file of the driver.
type DriverConfig struct {
	// IgnoreDevices is a list of CXL memory devices: a device is
	// its name, uevent DEVNAME, <major>:<minor>, or serial number in
	// decimal or 0x hex (dra.MemdevSpec). Example: ["mem0",
	// "cxl/mem0", "251:0", "3238060771", "0xc100e2e0"]
	IgnoreDevices []string `json:"ignoreDevices,omitempty"`
	// SharedDevices is a list of local CXL memory devices that are
	// published as shared devices (class cxl-local-shared): one devdax
	// device for all claims, never sliced, onlined or zeroed. Matched
	// like IgnoreDevices; IgnoreDevices and pool devices take
	// precedence. Example: ["0xc100e2e1"]
	SharedDevices []string `json:"sharedDevices,omitempty"`
	// ignoreDevices and sharedDevices are IgnoreDevices and
	// SharedDevices parsed by validate.
	ignoreDevices, sharedDevices []dra.MemdevSpec
	// IgnoreRegions is a list of CXL memory regions ["region0"]
	// to be ignored by the driver.
	IgnoreRegions []string `json:"ignoreRegions,omitempty"`
	// IgnoreNodes is a list of NUMA nodes to be ignored by the
	// driver.
	IgnoreNodes []int `json:"ignoreNodes,omitempty"`

	// If IgnoreDRAMNodes is true, NUMA nodes with DRAM memory
	// will be ignored by the driver. By default, DRAM nodes are
	// exposed in DRAM ResourceSlices.
	IgnoreDRAMNodes bool `json:"ignoreDRAMNodes,omitempty"`

	// ManageMemdevs publishes the local CXL memory devices that have
	// no regions as memdev devices, and creates and destroys their
	// regions for claims. Default: true.
	ManageMemdevs *bool `json:"manageMemdevs,omitempty"`

	// MemdevSettings are settings of individual local memdevs, such as
	// the usable part of a memdev whose memory aliases.
	MemdevSettings []MemdevSetting `json:"memdevSettings,omitempty"`

	// FsTypes are the filesystem types that mode fs mounts on the node,
	// for the local and the pool driver; nil is defaultFsTypes (erofs
	// only), an empty list mounts none. The node kernel parses what the
	// writer of a device wrote: a type other than erofs trusts every party
	// that can write the devices raw. A type that the plugin does not know
	// is single-host. Example: ["erofs", "ext4"]
	FsTypes []string `json:"fsTypes,omitempty"`

	// VerifyAddressing runs an address line test on every new region of
	// a local memdev before it is used: a memdev whose memory aliases
	// (offsets X and X+P reach the same memory) is used only up to P,
	// and remembered so. Default: true.
	VerifyAddressing *bool `json:"verifyAddressing,omitempty"`

	// Defaults are the container settings of every container of the
	// node (config.Defaults: container.steering, container.fencing),
	// overlaid by the settings of the claims that a container uses.
	// Decoded strictly by config.ParseDefaults into defaults.
	Defaults json.RawMessage `json:"defaults,omitempty"`
	defaults *config.Defaults
}

// containerDefaults returns the container settings of the defaults.
func (c *DriverConfig) containerDefaults() config.Container {
	return c.defaults.ContainerSettings()
}

// fencing returns defaults.container.fencing, config.FencingAllowedMems
// when it is not set.
func (c *DriverConfig) fencing() string {
	if f := c.containerDefaults().Fencing; f != "" {
		return f
	}
	return config.FencingAllowedMems
}

// steeringPolicy returns defaults.container.steering.policy,
// config.PolicyNone when it is not set.
func (c *DriverConfig) steeringPolicy() string {
	if s := c.containerDefaults().Steering; s != nil && s.Policy != "" {
		return s.Policy
	}
	return config.PolicyNone
}

// logDefaults logs the container defaults.
func (c *DriverConfig) logDefaults() {
	if fencing := c.fencing(); fencing == config.FencingAllowedMems {
		klog.Infof("defaults.container.fencing: %s: containers get the CXL nodes of the driver only by claims and leases", fencing)
	} else {
		klog.Infof("defaults.container.fencing: %s: containers are not kept off the CXL nodes of the driver", fencing)
	}
	if policy := c.steeringPolicy(); policy == config.PolicyNone {
		klog.Infof("defaults.container.steering.policy: %s: containers are steered only when their claims opt in", policy)
	} else {
		klog.Infof("defaults.container.steering.policy: %s: containers with numa claims are steered unless their claims say none", policy)
	}
}

// validate returns an error if a value of the configuration is invalid,
// and decodes the defaults.
func (c *DriverConfig) validate() error {
	var err error
	if c.ignoreDevices, err = dra.ParseMemdevSpecs(c.IgnoreDevices); err != nil {
		return fmt.Errorf("ignoreDevices: %w", err)
	}
	if c.sharedDevices, err = dra.ParseMemdevSpecs(c.SharedDevices); err != nil {
		return fmt.Errorf("sharedDevices: %w", err)
	}
	if err = c.validateMemdevSettings(); err != nil {
		return err
	}
	for _, t := range c.FsTypes {
		if !api.ValidFSType(t) {
			return fmt.Errorf(`fsTypes: invalid filesystem type %q (lower-case letters, digits, "_" and "-")`, t)
		}
	}
	c.defaults = nil
	if len(c.Defaults) > 0 {
		d, err := config.ParseDefaults(c.Defaults)
		if err != nil {
			return err
		}
		c.defaults = d
	}
	return nil
}

// defaultFsTypes are the filesystem types that mode fs mounts when the
// configuration has no fsTypes: erofs only, the type that is designed for
// images from untrusted writers.
var defaultFsTypes = []string{api.FSTypeErofs}

// fsTypes returns the filesystem types that mode fs mounts on the node:
// FsTypes, defaultFsTypes when it is not set.
func (c *DriverConfig) fsTypes() []string {
	if c == nil || c.FsTypes == nil {
		return slices.Clone(defaultFsTypes)
	}
	return slices.Clone(c.FsTypes)
}

// logFsTypes logs the filesystem types that mode fs mounts on the node.
func (c *DriverConfig) logFsTypes() {
	types := c.fsTypes()
	if len(types) == 0 {
		klog.Infof("fsTypes: none: mode fs mounts no filesystem on this node")
		return
	}
	klog.Infof("fsTypes: %s: the filesystem types that mode fs mounts on this node", strings.Join(types, ", "))
}

// manageMemdevs tells whether local memdevs are published and get regions
// for claims (ManageMemdevs, default true).
func (c *DriverConfig) manageMemdevs() bool {
	return c.ManageMemdevs == nil || *c.ManageMemdevs
}

func newDriverConfigFromString(configStr string) (*DriverConfig, error) {
	driverConfig := &DriverConfig{}
	if err := yaml.UnmarshalStrict([]byte(configStr), driverConfig); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := driverConfig.validate(); err != nil {
		return nil, err
	}
	return driverConfig, nil
}

// readConfig returns the content of the configuration file, "" when
// there is none.
func readConfig(file string) (string, error) {
	if file == "" {
		return "", nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("configuration: %w", err)
	}
	return string(data), nil
}

// publishConfig returns the settings of the publisher of the
// configuration, with the lease device if leases is set.
func (c *DriverConfig) publishConfig(leases bool) dra.PublishConfig {
	return dra.PublishConfig{
		IgnoreDevices:      c.ignoreDevices,
		SharedDevices:      c.sharedDevices,
		IgnoreRegions:      c.IgnoreRegions,
		IgnoreNodes:        c.IgnoreNodes,
		IgnoreDRAMNodes:    c.IgnoreDRAMNodes,
		ManageMemdevs:      c.manageMemdevs(),
		PublishLeaseDevice: leases,
		UsableSize:         c.configuredUsableSize,
	}
}

// localConfig returns the settings of the local memdevs of the
// configuration.
func (c *DriverConfig) localConfig() dra.LocalConfig {
	return dra.LocalConfig{Managed: c.manageMemdevs(), UsableSize: c.configuredUsableSize, Coherent: c.memdevCoherent}
}

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
