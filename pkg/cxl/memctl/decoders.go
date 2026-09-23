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

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// DecoderHole is a port between the CXL root and a memdev whose HDM
// decoders were released out of order: a region that used decoder K of
// the port was destroyed while a region on a higher decoder of the same
// port lives on.
//
// Linux commits the decoders of a port in order and allocates only the
// decoder after the last committed one (drivers/cxl/core/region.c
// match_free_decoder, check_commit_order). A decoder released below the
// last committed one stays counted in the port's decoders_committed, and
// the port refuses every new region, of any memdev under it, with EBUSY
// ("cxl region: create_region: regionN: failed to set target0 to memM",
// kernel "failed to attach decoderX.0 to regionN: -16"), until every
// region above it is destroyed. Then the kernel reaps the released
// decoders and the port works again.
type DecoderHole struct {
	// Port is the port (portN: a host bridge or a switch).
	Port string
	// Committed is the port's decoders_committed.
	Committed int
	// Free are the decoders below Committed without a region.
	Free []string
	// Blocking are the regions on decoders above the lowest free one: the
	// port takes new regions again once all of them are destroyed.
	Blocking []string
}

func (h DecoderHole) String() string {
	s := fmt.Sprintf("%s has %d committed decoders, %s without a region", h.Port, h.Committed, strings.Join(h.Free, ","))
	if len(h.Blocking) > 0 {
		s += " below " + strings.Join(h.Blocking, ",")
	}
	return s
}

var portDirRe = regexp.MustCompile(`^port\d+$`)

// DecoderHoles returns the ports between the CXL root and the memdev's
// endpoint whose decoders were released out of order (see DecoderHole),
// nearest to the root first. A memdev without an endpoint has none.
func (mc *Manager) DecoderHoles(memdev string) []DecoderHole {
	var holes []DecoderHole
	for _, dir := range mc.ports(memdev) {
		if h, ok := portHole(dir); ok {
			holes = append(holes, h)
		}
	}
	return holes
}

// RegionsAbove returns the regions of other memdevs on the decoders above
// those of the memdev's regions in the ports between the CXL root and the
// memdev's endpoint, nearest to the root first: while they live,
// destroying the memdev's regions leaves a hole in those ports (see
// DecoderHole). A memdev without an endpoint or regions has none.
func (mc *Manager) RegionsAbove(memdev string) []string {
	own := mc.Regions(memdev)
	if len(own) == 0 {
		return nil
	}
	var above []string
	for _, dir := range mc.ports(memdev) {
		ours := false
		for _, region := range portRegions(dir) {
			switch {
			case slices.Contains(own, region):
				ours = true
			case ours && region != "" && !slices.Contains(above, region):
				above = append(above, region)
			}
		}
	}
	return above
}

// ports returns the sysfs directories of the ports between the CXL root
// and the memdev's endpoint, nearest to the root first, nil for a memdev
// without an endpoint.
func (mc *Manager) ports(memdev string) []string {
	ep, err := mc.endpoint(memdev)
	if err != nil {
		return nil
	}
	real, err := filepath.EvalSymlinks(mc.cxlDev(ep))
	if err != nil {
		return nil
	}
	// The ports are the ancestors of the endpoint in the device tree:
	// .../root0/port2/port3/endpoint6.
	var ports []string
	for dir := filepath.Dir(real); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if portDirRe.MatchString(filepath.Base(dir)) {
			ports = append(ports, dir)
		}
	}
	slices.Reverse(ports)
	return ports
}

// portRegions returns the regions of the committed decoders of the port in
// sysfs directory dir in decoder order, "" for a decoder without a region.
func portRegions(dir string) []string {
	n, err := readUint(filepath.Join(dir, "decoders_committed"))
	if err != nil {
		return nil
	}
	prefix := "decoder" + strings.TrimPrefix(filepath.Base(dir), "port") + "."
	var regions []string
	for id := 0; id < int(n); id++ {
		region, err := readTrim(filepath.Join(dir, prefix+strconv.Itoa(id), "region"))
		if err != nil {
			continue
		}
		regions = append(regions, region)
	}
	return regions
}

// portHole returns the hole in the decoders of the port in sysfs
// directory dir, if any.
func portHole(dir string) (DecoderHole, bool) {
	port := filepath.Base(dir)
	h := DecoderHole{Port: port}
	n, err := readUint(filepath.Join(dir, "decoders_committed"))
	if err != nil || n == 0 {
		return h, false
	}
	h.Committed = int(n)
	prefix := "decoder" + strings.TrimPrefix(port, "port") + "."
	m, _ := filepath.Glob(filepath.Join(dir, prefix+"*"))
	byID := map[int]string{}
	for _, p := range m {
		id, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(p), prefix))
		if err != nil {
			continue
		}
		byID[id] = p
	}
	lowest := -1
	for id := 0; id < h.Committed; id++ {
		p, ok := byID[id]
		if !ok {
			continue
		}
		if region, err := readTrim(filepath.Join(p, "region")); err == nil && region == "" {
			h.Free = append(h.Free, filepath.Base(p))
			if lowest < 0 {
				lowest = id
			}
		}
	}
	if lowest < 0 {
		return h, false
	}
	for id := lowest + 1; id < h.Committed; id++ {
		if p, ok := byID[id]; ok {
			if region, err := readTrim(filepath.Join(p, "region")); err == nil && region != "" {
				h.Blocking = append(h.Blocking, region)
			}
		}
	}
	return h, true
}

// explainCreateRegion adds the decoder holes of the memdev's ports to the
// error of a failed cxl create-region: the kernel's EBUSY does not tell
// which port refused the region, or until when.
func (mc *Manager) explainCreateRegion(memdev string, err error) error {
	holes := mc.DecoderHoles(memdev)
	if len(holes) == 0 {
		return err
	}
	var s []string
	var blocking []string
	for _, h := range holes {
		s = append(s, h.String())
		for _, r := range h.Blocking {
			if !slices.Contains(blocking, r) {
				blocking = append(blocking, r)
			}
		}
	}
	until := "the decoders above them are released"
	switch len(blocking) {
	case 0:
	case 1:
		until = blocking[0] + " is destroyed"
	default:
		until = strings.Join(blocking, ", ") + " are destroyed"
	}
	return fmt.Errorf("%w (CXL decoders released out of order: %s; the kernel creates no region through these ports until %s)",
		err, strings.Join(s, "; "), until)
}

// HollowRegion tells whether a region is hollow: it is not committed and
// has no target decoder set. That is what is left of a region whose memory
// devices were removed before it was destroyed: the kernel detaches their
// endpoint decoders and resets the decode, but keeps the region with its
// address range in the root decoder (the window); no decoder maps that
// range any more. It is also, for a moment, the state of a region that cxl
// create-region is setting up, and for good that of one whose setup was
// cut (the tool killed). cxl destroy-region refuses a hollow region
// ("cxl_region_get_target_decoder: regionN: error locating decoder for
// target0"): see DeleteHollowRegion.
func (mc *Manager) HollowRegion(region string) bool {
	dir := mc.cxlDev(region)
	if _, err := os.Stat(dir); err != nil {
		return false
	}
	if c, err := readTrim(filepath.Join(dir, "commit")); err == nil && c != "0" {
		return false
	}
	targets, _ := filepath.Glob(filepath.Join(dir, "target[0-9]*"))
	for _, t := range targets {
		if v, err := readTrim(t); err != nil || v != "" {
			return false
		}
	}
	return true
}

// RegionRootDecoder returns the root decoder of a region: the parent of its
// sysfs directory (.../root0/decoder0.1/region1).
func (mc *Manager) RegionRootDecoder(region string) (string, error) {
	real, err := filepath.EvalSymlinks(mc.cxlDev(region))
	if err != nil {
		return "", err
	}
	parent := filepath.Base(filepath.Dir(real))
	if t, _ := readTrim(mc.cxlDev(parent, "devtype")); t != "cxl_decoder_root" {
		return "", fmt.Errorf("%s: its parent device %s is not a root decoder", region, parent)
	}
	return parent, nil
}

// DeleteHollowRegion deletes a hollow region (see HollowRegion) by writing
// its name to the delete_region attribute of its root decoder, which is
// what cxl destroy-region does last, after the target decoders that a
// hollow region does not have. It holds the lock of the region creations
// of the process (regionCreateMu): the region is then not one that a cxl
// create-region of this process is setting up. The caller must know the
// region as its own (see RegionNote): another process may be setting a
// hollow region up. A region with memory blocks that are not offline is
// not deleted: kmem keeps that memory until a reboot, and the region stays
// with it, as ReleaseRegion keeps such a region. A missing region is not
// an error.
func (mc *Manager) DeleteHollowRegion(region string) error {
	regionCreateMu.Lock()
	defer regionCreateMu.Unlock()
	dir := mc.cxlDev(region)
	if _, err := os.Stat(dir); err != nil {
		return nil
	}
	if !mc.HollowRegion(region) {
		return fmt.Errorf("%s is not hollow: it is committed or has a target decoder", region)
	}
	if blocks, err := mc.RegionBlocks(region); err == nil {
		var online []int
		for _, b := range blocks {
			if st, err := readTrim(mc.block(b, "state")); err != nil || st != "offline" {
				online = append(online, b)
			}
		}
		if len(online) > 0 {
			return fmt.Errorf("%s: memory blocks %v of its address range are not offline (kmem keeps them until a reboot): not deleting it", region, online)
		}
	}
	decoder, err := mc.RegionRootDecoder(region)
	if err != nil {
		return err
	}
	res, _ := readTrim(filepath.Join(dir, "resource"))
	attr := mc.cxlDev(decoder, "delete_region")
	if err := mc.writeFile(attr, region); err != nil {
		return fmt.Errorf("%s: deleting hollow %s: %w", attr, region, err)
	}
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("%s: %s still exists after its deletion", attr, region)
	}
	mc.logf("deleted hollow %s (resource %s) through %s", region, res, attr)
	return nil
}
