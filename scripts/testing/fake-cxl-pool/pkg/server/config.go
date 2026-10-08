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

// Package server implements the fake-cxl-pool REST API server: pools of
// memory devices (backing files), qemu hosts (VMs) and hotplug attachments.
package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/api"
)

// Defaults.
const (
	// Serial scheme: 0xc1 = CXL, 0x00 in the next byte = present at boot
	// (e2e topology local devices are 0xc100e2e0+i), 0xae = shared pool
	// devices, 0xee = exclusive pool devices.
	DefaultSharedSerialBase    = 0xc1ae0000
	DefaultExclusiveSerialBase = 0xc1ee0000
	DefaultPoolName            = "default"
	DefaultPoolDir             = "/tmp/fake-cxl-pool"
	DefaultPoolCapacity        = 8 << 30
	DefaultDiscoveryPeriod     = 10 * time.Second
	DefaultDetachTimeout       = 15 * time.Second
	DefaultAttachTimeout       = 30 * time.Second
	// CapacityMultiplier: CXL device capacity is reported in 256 MiB units.
	CapacityMultiplier = 256 << 20
)

// Config is the server configuration (YAML).
type Config struct {
	Listen string `json:"listen,omitempty"`
	// SharedSerialBase and ExclusiveSerialBase: devices without a serial
	// get the next free serial above the base of their kind.
	SharedSerialBase    *api.Serial     `json:"sharedSerialBase,omitempty"`
	ExclusiveSerialBase *api.Serial     `json:"exclusiveSerialBase,omitempty"`
	StateFile           string          `json:"stateFile,omitempty"`
	Pools               []PoolConfig    `json:"pools,omitempty"`
	Devices             []DeviceConfig  `json:"devices,omitempty"`
	Hosts               []HostConfig    `json:"hosts,omitempty"`
	Discovery           DiscoveryConfig `json:"discovery"`
	DetachTimeout       api.Duration    `json:"detachTimeout,omitempty"`
}

// PoolConfig configures a pool.
type PoolConfig struct {
	Name     string   `json:"name"`
	Dir      string   `json:"dir"`
	Capacity api.Size `json:"capacity,omitempty"`
	Sharable *bool    `json:"sharable,omitempty"`
}

// DeviceConfig configures a static pool device.
type DeviceConfig struct {
	Name   string            `json:"name"`
	Size   api.Size          `json:"size"`
	Shared bool              `json:"shared,omitempty"`
	Pool   string            `json:"pool,omitempty"`
	File   string            `json:"file,omitempty"`
	Serial *api.Serial       `json:"serial,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// HostConfig configures a static host.
type HostConfig struct {
	Name string `json:"name"`
	UUID string `json:"uuid,omitempty"`
	QMP  string `json:"qmp,omitempty"`
	HMP  string `json:"hmp,omitempty"`
	// Control forces the monitor protocol: "qmp" or "hmp" (default: qmp
	// if a QMP socket is known, else hmp).
	Control string `json:"control,omitempty"`
}

// DiscoveryConfig configures qemu process discovery.
type DiscoveryConfig struct {
	Qemu *bool `json:"qemu,omitempty"`
	// Names, if set, limits discovery to VMs whose name matches one of
	// these path.Match patterns.
	Names        []string     `json:"names,omitempty"`
	Interval     api.Duration `json:"interval,omitempty"`
	LocalDevices *bool        `json:"localDevices,omitempty"`
}

// QemuEnabled returns true if /proc scanning is enabled (default true).
func (d *DiscoveryConfig) QemuEnabled() bool { return d.Qemu == nil || *d.Qemu }

// LocalDevicesEnabled returns true if pre-declared backends become local
// devices (default true).
func (d *DiscoveryConfig) LocalDevicesEnabled() bool { return d.LocalDevices == nil || *d.LocalDevices }

// LoadConfig reads a YAML config file. Unknown keys are errors.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(b)
}

// ParseConfig parses YAML config data and applies defaults.
func ParseConfig(data []byte) (*Config, error) {
	cfg := &Config{}
	if err := yaml.UnmarshalStrict(data, cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if err := cfg.Complete(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// DefaultConfig returns the configuration used without a config file.
func DefaultConfig() *Config {
	cfg := &Config{}
	_ = cfg.Complete()
	return cfg
}

// Complete applies defaults and validates the configuration.
func (c *Config) Complete() error {
	if c.Listen == "" {
		c.Listen = api.DefaultListen
	}
	if c.SharedSerialBase == nil {
		sb := api.Serial(DefaultSharedSerialBase)
		c.SharedSerialBase = &sb
	}
	if c.ExclusiveSerialBase == nil {
		sb := api.Serial(DefaultExclusiveSerialBase)
		c.ExclusiveSerialBase = &sb
	}
	if len(c.Pools) == 0 {
		c.Pools = []PoolConfig{{Name: DefaultPoolName, Dir: DefaultPoolDir}}
	}
	seen := map[string]bool{}
	for i := range c.Pools {
		p := &c.Pools[i]
		if p.Name == "" {
			return fmt.Errorf("pool %d: missing name", i)
		}
		if seen[p.Name] {
			return fmt.Errorf("duplicate pool %q", p.Name)
		}
		seen[p.Name] = true
		if p.Dir == "" {
			p.Dir = filepath.Join(DefaultPoolDir, p.Name)
			if p.Name == DefaultPoolName {
				p.Dir = DefaultPoolDir
			}
		}
		if p.Capacity == 0 {
			p.Capacity = DefaultPoolCapacity
		}
		if p.Sharable == nil {
			t := true
			p.Sharable = &t
		}
	}
	seen = map[string]bool{}
	for i := range c.Devices {
		d := &c.Devices[i]
		if d.Name == "" {
			return fmt.Errorf("device %d: missing name", i)
		}
		if seen[d.Name] {
			return fmt.Errorf("duplicate device %q", d.Name)
		}
		seen[d.Name] = true
		if d.Size <= 0 {
			return fmt.Errorf("device %q: missing size", d.Name)
		}
		if d.Pool == "" {
			d.Pool = c.Pools[0].Name
		}
	}
	seen = map[string]bool{}
	for i := range c.Hosts {
		h := &c.Hosts[i]
		if h.Name == "" {
			return fmt.Errorf("host %d: missing name", i)
		}
		if seen[h.Name] {
			return fmt.Errorf("duplicate host %q", h.Name)
		}
		seen[h.Name] = true
		h.UUID = strings.ToLower(h.UUID)
		if h.Control != "" && h.Control != "qmp" && h.Control != "hmp" {
			return fmt.Errorf("host %q: control must be qmp or hmp", h.Name)
		}
	}
	if c.Discovery.Interval == 0 {
		c.Discovery.Interval = api.Duration(DefaultDiscoveryPeriod)
	}
	if c.Discovery.Interval < 0 {
		return fmt.Errorf("discovery.interval must be positive")
	}
	if c.DetachTimeout == 0 {
		c.DetachTimeout = api.Duration(DefaultDetachTimeout)
	}
	if c.DetachTimeout < 0 {
		return fmt.Errorf("detachTimeout must be positive")
	}
	if c.StateFile == "" {
		c.StateFile = filepath.Clean(c.Pools[0].Dir) + ".state.json"
	}
	return nil
}
