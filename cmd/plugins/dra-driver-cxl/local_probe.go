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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/pkg/cxl/memctl"
)

// Usable size of local memdevs: a memdev whose memory aliases (offsets X
// and X+P reach the same memory, as on a device or platform that ignores
// an address bit) has only P distinct bytes. The allocator creates its
// regions with only the usable size and the publisher publishes only that.
// The usable size comes from memdevSettings of the configuration, and from
// the address line probe that the allocator runs on every new region
// (verifyAddressing), whose results are kept in localProbesFileName.

const (
	// localProbesFileName keeps the usable sizes that the address line
	// probe found, by serial, across restarts and reboots.
	localProbesFileName = "localProbes.json"
)

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
			if q.Value() < cxlRegionAlign {
				return fmt.Errorf("memdevSettings[%d]: usableSize %q is less than 256Mi", i, s.UsableSize)
			}
		}
	}
	return nil
}

// configuredUsableSize returns the usableSize of the first memdev setting
// that matches the memdev name or serial, 0 if none.
func (c *DriverConfig) configuredUsableSize(memdev string, serial uint64) uint64 {
	if c == nil {
		return 0
	}
	for _, s := range c.MemdevSettings {
		if s.Device != memdev && !serialMatches(s.Device, serial) {
			continue
		}
		if s.UsableSize == "" {
			return 0
		}
		q, err := resource.ParseQuantity(s.UsableSize)
		if err != nil || q.Value() <= 0 {
			return 0
		}
		return uint64(q.Value())
	}
	return 0
}

// serialMatches tells whether spec is the serial in decimal, 0x<hex> or
// <hex>, leading zeros allowed.
func serialMatches(spec string, serial uint64) bool {
	if v, err := strconv.ParseUint(spec, 0, 64); err == nil && v == serial {
		return true
	}
	v, err := strconv.ParseUint(spec, 16, 64)
	return err == nil && v == serial
}

// verifyAddressing tells whether the allocator probes new regions for
// aliasing (VerifyAddressing, default true).
func (c *DriverConfig) verifyAddressing() bool {
	return c == nil || c.VerifyAddressing == nil || *c.VerifyAddressing
}

// localProbe is the result of the address line probe of a memdev.
type localProbe struct {
	// UsableSize is the number of distinct bytes the probe found.
	UsableSize uint64 `json:"usableSize"`
	// Result describes the aliasing.
	Result string `json:"result"`
	// Region is the region that was probed, and Size its size.
	Region string `json:"region"`
	Size   uint64 `json:"size"`
	// Time is when the probe ran.
	Time time.Time `json:"time"`
}

// SetUsableSizes sets the function that returns the configured usable
// size of a memdev (0: all of it), and whether new regions are probed.
func (a *localAllocator) SetUsableSizes(configured func(memdev string, serial uint64) uint64, verify bool) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.configured = configured
	a.verify = verify
}

// usableSize returns the bytes of the memdev that the allocator uses: the
// smaller of the configured usable size and the probed one, rounded down
// to the alignment of CXL regions; 0 for all of it. Called with a.mu held
// or before the allocator is shared.
func (a *localAllocator) usableSize(memdev string, serial uint64) uint64 {
	var size uint64
	if a.configured != nil {
		size = a.configured(memdev, serial)
	}
	a.snapMu.Lock()
	p, ok := a.probes[serial]
	a.snapMu.Unlock()
	if ok && p.UsableSize > 0 && (size == 0 || p.UsableSize < size) {
		size = p.UsableSize
	}
	return size / cxlRegionAlign * cxlRegionAlign
}

// usableSizes returns the probed usable sizes by serial, for the snapshot.
func (a *localAllocator) probedSizes() map[uint64]uint64 {
	a.snapMu.Lock()
	defer a.snapMu.Unlock()
	m := make(map[uint64]uint64, len(a.probes))
	for serial, p := range a.probes {
		m[serial] = p.UsableSize
	}
	return m
}

// loadProbes reads the probe results, if there are any.
func (a *localAllocator) loadProbes() error {
	a.probes = map[uint64]localProbe{}
	if a.probesFile == "" {
		return nil
	}
	data, err := os.ReadFile(a.probesFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", a.probesFile, err)
	}
	byHex := map[string]localProbe{}
	if err := json.Unmarshal(data, &byHex); err != nil {
		return fmt.Errorf("parsing %s: %w", a.probesFile, err)
	}
	for hex, p := range byHex {
		serial, err := strconv.ParseUint(hex, 16, 64)
		if err != nil {
			return fmt.Errorf("parsing %s: serial %q: %w", a.probesFile, hex, err)
		}
		a.probes[serial] = p
		klog.Warningf("local: memdev serial 0x%x: using only its first %d bytes, found by the address line probe of %s at %s: %s (remove %s to probe all of it again)",
			serial, p.UsableSize, p.Region, p.Time.Format(time.RFC3339), p.Result, a.probesFile)
	}
	return nil
}

// saveProbe records a probe result and saves the results.
func (a *localAllocator) saveProbe(serial uint64, p localProbe) error {
	a.snapMu.Lock()
	a.probes[serial] = p
	byHex := make(map[string]localProbe, len(a.probes))
	for s, v := range a.probes {
		byHex[strconv.FormatUint(s, 16)] = v
	}
	a.snapMu.Unlock()
	if a.probesFile == "" {
		return nil
	}
	return writeJSONFile(a.probesFile, byHex)
}

// probeRegion runs the address line probe on the new region of a device,
// whose first dax device spans the whole region and is bound to
// device_dax. It returns the usable size if the memory aliases (0 if it
// does not), and an error if the probe found memory that does not hold
// what was written.
func (a *localAllocator) probeRegion(d *localDevice) (uint64, error) {
	if !a.verify {
		return 0, nil
	}
	start := time.Now()
	size, err := a.mem.DaxDeviceSize(d.Dax)
	if err != nil {
		return 0, err
	}
	res, err := a.probe(d.Dax)
	if errors.Is(err, memctl.ErrProbeUnsupported) {
		klog.V(4).Infof("local: memdev %s (serial 0x%x): %v", d.Memdev, d.Serial, err)
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("memdev %s (serial 0x%x): probing %s for address aliasing: %w", d.Memdev, d.Serial, d.Region, err)
	}
	klog.Infof("local: memdev %s (serial 0x%x): address line probe of %s (%d bytes): %s in %s", d.Memdev, d.Serial, d.Region, size, res, since(start))
	if res.Offset == 0 {
		if res.Garbage >= 0 {
			return 0, fmt.Errorf("memdev %s (serial 0x%x): %s: %s", d.Memdev, d.Serial, d.Region, res)
		}
		return 0, nil
	}
	usable := res.Offset / cxlRegionAlign * cxlRegionAlign
	if usable == 0 {
		return 0, fmt.Errorf("memdev %s (serial 0x%x): %s: %s: less than 256 MiB is usable", d.Memdev, d.Serial, d.Region, res)
	}
	klog.Warningf("local: memdev %s (serial 0x%x): %s: %s; using only the first %d bytes of the memdev from now on",
		d.Memdev, d.Serial, d.Region, res, usable)
	if err := a.saveProbe(d.Serial, localProbe{UsableSize: usable, Result: res.String(), Region: d.Region, Size: size, Time: time.Now()}); err != nil {
		klog.Errorf("local: saving the probe result: %v", err)
	}
	return usable, nil
}

// createProbedRegion creates the devdax region of a device with the usable
// size of the memdev, probes it and, while its memory aliases, creates it
// again with the usable bytes only. A smaller region can reveal aliasing
// that a larger one hid (two aliases of the same memory: the probe sees
// the one written last).
func (a *localAllocator) createProbedRegion(ctx context.Context, d *localDevice, bs uint64) error {
	const maxTries = 4
	last := uint64(0)
	for try := 1; ; try++ {
		if err := a.createRegion(ctx, d, bs); err != nil {
			return err
		}
		usable, err := a.probeRegion(d)
		if err != nil || usable == 0 {
			return err
		}
		if try == maxTries || (last != 0 && usable >= last) {
			return fmt.Errorf("memdev %s (serial 0x%x): %s still aliases after %d tries (usable size %d)", d.Memdev, d.Serial, d.Region, try, usable)
		}
		last = usable
		if err := a.mem.ReleaseRegion(ctx, d.Region); err != nil {
			return fmt.Errorf("memdev %s (serial 0x%x): releasing aliased %s: %w", d.Memdev, d.Serial, d.Region, err)
		}
		klog.Infof("local: memdev %s (serial 0x%x): released aliased %s, creating a region of %d bytes", d.Memdev, d.Serial, d.Region, a.usableSize(d.Memdev, d.Serial))
		d.Region, d.Dax, d.Node = "", "", -1
	}
}
