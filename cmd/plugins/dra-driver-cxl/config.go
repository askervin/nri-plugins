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
	"time"

	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	nricxl "github.com/containers/nri-plugins/pkg/cxl"
	"github.com/containers/nri-plugins/pkg/cxl/config"
)

// TestabilityConfig holds configuration for injecting fake CXL
// devices for testing without real hardware. Fake devices are
// appended to the real detected devices before buildDevInfos()
// processes them.
type TestabilityConfig struct {
	// FakeRegionDevices lists CXL region devices to inject.
	// Each entry is appended to nricxl.Devices.RegionDevices
	// right after DevicesFromSysfs() returns. Memory devices
	// referenced in Memories are also appended to
	// nricxl.Devices.MemoryDevices.
	FakeRegionDevices []nricxl.RegionDevice `json:"fakeRegionDevices,omitempty"`
	// FakeUdevFifo is a path to a named pipe (FIFO) from which
	// the driver reads fake udev events. Each line is a JSON
	// object whose keys and values are udev event properties.
	// The driver creates the FIFO if it does not exist. Example:
	//   {"ACTION":"add","SUBSYSTEM":"node","DEVPATH":"/devices/system/node/node2"}
	FakeUdevFifo string `json:"fakeUdevFifo,omitempty"`
}

type DriverConfig struct {
	// IgnoreDevices is a list of CXL memory devices. Matches
	// uevent DEVNAME, <major>:<minor>, or serial number in
	// decimal format, or 0x<hex>. Example: ["mem0", "cxl/mem0",
	// "251:0", "3238060771", "0xc100e2e0"]
	IgnoreDevices []string `json:"ignoreDevices,omitempty"`
	// SharedDevices is a list of local CXL memory devices that are
	// published as shared devices (class cxl-local-shared): one devdax
	// device for all claims, never sliced, onlined or zeroed. Matched
	// like IgnoreDevices; IgnoreDevices and pool devices take
	// precedence. Example: ["0xc100e2e1"]
	SharedDevices []string `json:"sharedDevices,omitempty"`
	// IgnoreRegions is a list of CXL memory regions ["region0"]
	// to be ignored by the driver.
	IgnoreRegions []string `json:"ignoreRegions,omitempty"`
	// IgnoreNodes is a list of NUMA nodes to be ignored by the
	// driver.
	IgnoreNodes []int `json:"ignoreNodes,omitempty"`

	// If IgnoreNewNodes is true, enabled nodes are ignored by the driver.
	// IgnoreNewMemoryDevices and IgnoreNewRegions are accepted with a
	// warning and have no effect.
	IgnoreNewMemoryDevices bool `json:"ignoreNewMemoryDevices,omitempty"`
	IgnoreNewRegions       bool `json:"ignoreNewRegions,omitempty"`
	IgnoreNewNodes         bool `json:"ignoreNewNodes,omitempty"`

	// If IgnoreDRAMNodes is true, NUMA nodes with DRAM memory
	// will be ignored by the driver. By default, DRAM nodes are
	// exposed in DRAM ResourceSlices.
	IgnoreDRAMNodes bool `json:"ignoreDRAMNodes,omitempty"`

	// UdevStableDuration is the quiet period after the last udev
	// event before a rescan is triggered. Parsed as a Go
	// duration string (e.g. "200ms", "1s"). Default: "200ms".
	UdevStableDuration string `json:"udevStableDuration,omitempty"`

	// Testability enables injection of fake CXL devices for
	// testing without real hardware.
	Testability *TestabilityConfig `json:"testability,omitempty"`

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

	// PublishLeaseDevice publishes the lease device (set from --leases,
	// not part of the configuration file).
	PublishLeaseDevice bool `json:"-"`
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
	if err := c.validateMemdevSettings(); err != nil {
		return err
	}
	for _, t := range c.FsTypes {
		if !config.ValidFsType(t) {
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
var defaultFsTypes = []string{config.FsTypeErofs}

// fsTypes returns the filesystem types that mode fs mounts on the node:
// FsTypes, defaultFsTypes when it is not set.
func (c *DriverConfig) fsTypes() []string {
	if c == nil || c.FsTypes == nil {
		return slices.Clone(defaultFsTypes)
	}
	return slices.Clone(c.FsTypes)
}

// logDeadKeys warns of the configuration keys that are accepted but have no
// effect: ignoreNewMemoryDevices and ignoreNewRegions.
func (c *DriverConfig) logDeadKeys() {
	for _, k := range []struct {
		name string
		set  bool
	}{{"ignoreNewMemoryDevices", c.IgnoreNewMemoryDevices}, {"ignoreNewRegions", c.IgnoreNewRegions}} {
		if k.set {
			klog.Warningf("%s: the key has no effect and is ignored", k.name)
		}
	}
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

const defaultUdevStableDuration = 200 * time.Millisecond

// parseUdevStableDuration parses the UdevStableDuration config string.
// Returns the default (200ms) when the string is empty.
func parseUdevStableDuration(s string) (time.Duration, error) {
	if s == "" {
		return defaultUdevStableDuration, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid udevStableDuration %q: %w", s, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("udevStableDuration must not be negative, got %v", d)
	}
	return d, nil
}

func newDriverConfigFromString(configStr string) (*DriverConfig, error) {
	driverConfig := &DriverConfig{}
	if err := yaml.UnmarshalStrict([]byte(configStr), driverConfig); err != nil {
		return nil, fmt.Errorf("failed to parse driver config: %v", err)
	}
	if err := driverConfig.validate(); err != nil {
		return nil, err
	}
	return driverConfig, nil
}

// resolveConfigStr returns the configuration string from either the
// -c flag or the -f flag. It returns an error if both are provided.
func resolveConfigStr(flags *CXLFlags) (string, error) {
	hasStr := flags.ConfigStr != ""
	hasFile := flags.ConfigFile != ""

	if hasStr && hasFile {
		return "", fmt.Errorf("provide configuration as a file (-f) or as a string (-c), but not both")
	}

	if hasFile {
		data, err := os.ReadFile(flags.ConfigFile)
		if err != nil {
			return "", fmt.Errorf("failed to read configuration file %q: %v", flags.ConfigFile, err)
		}
		return string(data), nil
	}

	return flags.ConfigStr, nil
}

// injectFakeDevices appends fake CXL region devices from the
// testability configuration into the detected devices structure.
// Sensible defaults are applied for fields left unset.
func injectFakeDevices(tc *TestabilityConfig, devices *nricxl.Devices) {
	if len(tc.FakeRegionDevices) == 0 {
		return
	}
	klog.Warning("Testability: injecting fake CXL devices - do not use in production")
	for i := range tc.FakeRegionDevices {
		reg := &tc.FakeRegionDevices[i]
		if reg.SysfsPath == "" {
			reg.SysfsPath = fmt.Sprintf("/fake/sys/bus/cxl/devices/%s", reg.Name)
		}
		if reg.Mode == "" {
			reg.Mode = "ram"
		}
		if reg.Node >= 0 {
			reg.Enabled = true
		}
		if reg.OnlineSize == 0 && reg.Enabled {
			reg.OnlineSize = reg.Size
		}
		for j := range reg.Memories {
			mem := reg.Memories[j]
			if mem.SysfsPath == "" {
				mem.SysfsPath = fmt.Sprintf("/fake/sys/bus/cxl/devices/%s", mem.Name)
			}
			if mem.Driver == "" {
				mem.Driver = "cxl_mem"
			}
			if mem.DevName == "" {
				mem.DevName = fmt.Sprintf("cxl/%s", mem.Name)
			}
			mem.Enabled = true
			devices.MemoryDevices = append(devices.MemoryDevices, mem)
		}
		klog.Infof("Testability: injecting fake region %q (node %d, size %d, memories %d)",
			reg.Name, reg.Node, reg.Size, len(reg.Memories))
		devices.RegionDevices = append(devices.RegionDevices, reg)
	}
}

// detectDevices detects the devices under the sysfs root (a variable for
// tests).
var detectDevices = nricxl.DevicesFromSysfs

// scanFunc returns the scan of the devices of the node under sysfsRoot:
// the devices of sysfs, with the fake devices of the testability
// configuration.
func (c *DriverConfig) scanFunc(sysfsRoot string) func() (*nricxl.Devices, error) {
	return func() (*nricxl.Devices, error) {
		detected, err := detectDevices(sysfsRoot)
		if err != nil {
			return nil, err
		}
		if c.Testability != nil {
			injectFakeDevices(c.Testability, detected)
		}
		return detected, nil
	}
}

// publishConfig returns the settings of the publisher of the
// configuration.
func (c *DriverConfig) publishConfig() dra.PublishConfig {
	return dra.PublishConfig{
		IgnoreDevices:      c.IgnoreDevices,
		SharedDevices:      c.SharedDevices,
		IgnoreRegions:      c.IgnoreRegions,
		IgnoreNodes:        c.IgnoreNodes,
		IgnoreDRAMNodes:    c.IgnoreDRAMNodes,
		ManageMemdevs:      c.manageMemdevs(),
		PublishLeaseDevice: c.PublishLeaseDevice,
		UsableSize:         c.configuredUsableSize,
	}
}

// localConfig returns the settings of the local memdevs of the
// configuration.
func (c *DriverConfig) localConfig() dra.LocalConfig {
	return dra.LocalConfig{Managed: c.manageMemdevs(), UsableSize: c.configuredUsableSize, Coherent: c.memdevCoherent}
}
