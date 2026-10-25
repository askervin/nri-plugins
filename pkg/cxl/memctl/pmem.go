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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Region types of cxl create-region -t.
const (
	// RegionRAM is a region of volatile memory.
	RegionRAM = "ram"
	// RegionPmem is a region of persistent memory with an nvdimm region.
	RegionPmem = "pmem"
)

// Namespace modes and fsdax maps, as ndctl names them.
const (
	NamespaceFsdax  = "fsdax"
	NamespaceRaw    = "raw"
	NamespaceDevdax = "devdax"
	NamespaceSector = "sector"
	// MapMem keeps the struct pages of an fsdax namespace in system RAM.
	MapMem = "mem"
	// MapDev keeps them in the namespace itself.
	MapDev = "dev"
)

// Namespace is a namespace of an nvdimm region:
//   - Name: namespaceN.M
//   - Mode: NamespaceFsdax, NamespaceRaw, NamespaceDevdax or NamespaceSector
//   - Map: MapMem or MapDev of fsdax namespaces
//   - Size: bytes of its block device, of the namespace without one
//   - BlockDevice: /dev/pmemK of fsdax, raw and sector namespaces
//   - Major, Minor: device numbers of the block device
type Namespace struct {
	Name        string `json:"name"`
	Mode        string `json:"mode"`
	Map         string `json:"map,omitempty"`
	Size        uint64 `json:"size"`
	BlockDevice string `json:"blockDevice,omitempty"`
	Major       int    `json:"major,omitempty"`
	Minor       int    `json:"minor,omitempty"`
}

// PmemRegion is a region of persistent memory of a memdev: the CXL region,
// its nvdimm region and the namespaces of the nvdimm region.
type PmemRegion struct {
	Memdev     string      `json:"memdev"`
	Region     string      `json:"region"`
	NdRegion   string      `json:"ndRegion"`
	Namespaces []Namespace `json:"namespaces"`
}

// FsdaxNamespace returns the first fsdax namespace with map mem, nil if
// there is none.
func FsdaxNamespace(namespaces []Namespace) *Namespace {
	for i := range namespaces {
		if ns := &namespaces[i]; ns.Mode == NamespaceFsdax && ns.Map == MapMem && ns.BlockDevice != "" {
			return ns
		}
	}
	return nil
}

func (mc *Manager) ndDev(p ...string) string {
	return filepath.Join(append([]string{mc.SysRoot, "bus", "nd", "devices"}, p...)...)
}

// Persistent tells whether a memdev has persistent memory capacity.
func (mc *Manager) Persistent(memdev string) (bool, error) {
	size, err := readUint(mc.cxlDev(memdev, "pmem", "size"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return size > 0, nil
}

// RootDecoder returns the root decoder whose target list has the host
// bridge of the memdev and that can map regions of the region type
// (RegionRAM or RegionPmem).
func (mc *Manager) RootDecoder(memdev, regionType string) (string, error) {
	capAttr := ""
	switch regionType {
	case RegionRAM:
		capAttr = "cap_ram"
	case RegionPmem:
		capAttr = "cap_pmem"
	default:
		return "", fmt.Errorf("invalid region type %q (%s or %s)", regionType, RegionRAM, RegionPmem)
	}
	uid, err := mc.hostBridgeUID(memdev)
	if err != nil {
		return "", err
	}
	for _, d := range mc.list("decoder*") {
		if t, _ := readTrim(mc.cxlDev(d, "devtype")); t != "cxl_decoder_root" {
			continue
		}
		// a decoder without the attribute can map both types
		if v, err := readTrim(mc.cxlDev(d, capAttr)); err == nil && v != "1" {
			continue
		}
		tl, _ := readTrim(mc.cxlDev(d, "target_list"))
		for _, t := range strings.Split(tl, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil && n == uid {
				return d, nil
			}
		}
	}
	return "", fmt.Errorf("no root decoder for %s regions targets host bridge %d of %s", regionType, uid, memdev)
}

// isPmemRegion tells whether a CXL region is a region of persistent
// memory (it has a pmem_regionN).
func (mc *Manager) isPmemRegion(region string) bool {
	m, _ := filepath.Glob(mc.cxlDev(region, "pmem_region*"))
	return len(m) > 0
}

// NdRegion returns the nvdimm region of a CXL region of persistent memory:
// the nvdimm region with the id of the CXL region.
func (mc *Manager) NdRegion(region string) (string, error) {
	id, ok := strings.CutPrefix(region, "region")
	if _, err := strconv.Atoi(id); !ok || err != nil {
		return "", fmt.Errorf("invalid region name %q", region)
	}
	nd := "region" + id
	if _, err := os.Stat(mc.ndDev(nd)); err != nil {
		return "", fmt.Errorf("%s has no nvdimm region: %w", region, err)
	}
	return nd, nil
}

// hasDriver tells whether a device directory has a bound driver.
func hasDriver(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "driver"))
	return err == nil
}

// blockDevice returns the name of the block device (pmemK) of a device
// directory, "" if it has none.
func blockDevice(dir string) string {
	m, _ := filepath.Glob(filepath.Join(dir, "block", "*"))
	sort.Strings(m)
	if len(m) == 0 {
		return ""
	}
	return filepath.Base(m[0])
}

// namespace returns a namespace of an nvdimm region and whether its
// probing has finished: it has no memory (a seed), a block device of its
// own (raw), or a holder (pfn, btt or dax device) with a driver and, for
// pfn and btt, a block device.
func (mc *Manager) namespace(name string) (Namespace, bool, error) {
	dir := mc.ndDev(name)
	ns := Namespace{Name: name}
	size, err := readUint(filepath.Join(dir, "size"))
	if errors.Is(err, os.ErrNotExist) {
		return ns, false, nil // being added
	}
	if err != nil {
		return ns, false, err
	}
	ns.Size = size
	if size == 0 {
		return ns, true, nil // the seed of new namespaces
	}
	holder, _ := readTrim(filepath.Join(dir, "holder"))
	blockDir := dir
	switch {
	case holder == "":
		ns.Mode = NamespaceRaw
	case strings.HasPrefix(holder, "pfn"):
		ns.Mode = NamespaceFsdax
		blockDir = mc.ndDev(holder)
		switch m, _ := readTrim(filepath.Join(blockDir, "mode")); m {
		case "ram":
			ns.Map = MapMem
		case "pmem":
			ns.Map = MapDev
		}
	case strings.HasPrefix(holder, "btt"):
		ns.Mode = NamespaceSector
		blockDir = mc.ndDev(holder)
	case strings.HasPrefix(holder, "dax"):
		ns.Mode = NamespaceDevdax
		return ns, hasDriver(mc.ndDev(holder)), nil
	default:
		return ns, false, fmt.Errorf("%s: unknown holder %q", name, holder)
	}
	blk := blockDevice(blockDir)
	if blk == "" {
		return ns, false, nil
	}
	if holder != "" && !hasDriver(blockDir) {
		return ns, false, nil
	}
	major, minor, bytes, err := mc.BlockDeviceInfo(blk)
	if err != nil {
		return ns, false, err
	}
	ns.BlockDevice = filepath.Join(mc.DevRoot, blk)
	ns.Major, ns.Minor, ns.Size = major, minor, bytes
	return ns, true, nil
}

// BlockDeviceInfo returns the device numbers and the size in bytes of a
// block device (/sys/class/block/<name>).
func (mc *Manager) BlockDeviceInfo(name string) (major, minor int, size uint64, err error) {
	dir := filepath.Join(mc.SysRoot, "class", "block", name)
	v, err := readTrim(filepath.Join(dir, "dev"))
	if err != nil {
		return 0, 0, 0, err
	}
	ma, mi, ok := strings.Cut(v, ":")
	if ok {
		major, err = strconv.Atoi(ma)
		if err == nil {
			minor, err = strconv.Atoi(mi)
		}
	}
	if !ok || err != nil {
		return 0, 0, 0, fmt.Errorf("%s: cannot parse device numbers %q", name, v)
	}
	sectors, err := readUint(filepath.Join(dir, "size"))
	if err != nil {
		return 0, 0, 0, err
	}
	return major, minor, sectors * 512, nil
}

// namespaces returns the namespaces of an nvdimm region with memory, and
// whether all of them and the region have finished probing.
func (mc *Manager) namespaces(ndregion string) ([]Namespace, bool, error) {
	dir := mc.ndDev(ndregion)
	if !hasDriver(dir) {
		return nil, false, nil
	}
	// The kernel registers the namespaces that it found at the probe of
	// the region asynchronously; init_namespaces counts them.
	active := 0
	if v, err := readTrim(filepath.Join(dir, "init_namespaces")); err == nil {
		a, _, _ := strings.Cut(v, "/")
		active, _ = strconv.Atoi(a)
	}
	id := strings.TrimPrefix(ndregion, "region")
	m, _ := filepath.Glob(filepath.Join(dir, "namespace"+id+".*"))
	names := make([]string, 0, len(m))
	for _, p := range m {
		names = append(names, filepath.Base(p))
	}
	sort.Slice(names, func(i, j int) bool { return natLess(names[i], names[j]) })
	settled := len(names) >= active
	var out []Namespace
	for _, name := range names {
		ns, ok, err := mc.namespace(name)
		if err != nil {
			return nil, false, err
		}
		settled = settled && ok
		if ns.Size > 0 {
			out = append(out, ns)
		}
	}
	return out, settled, nil
}

// Namespaces returns the namespaces with memory of an nvdimm region, after
// waiting until the region and its namespaces have finished probing.
func (mc *Manager) Namespaces(ctx context.Context, ndregion string) ([]Namespace, error) {
	for {
		out, settled, err := mc.namespaces(ndregion)
		if err != nil {
			return nil, err
		}
		if settled {
			return out, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%s: namespaces still probing: %w", ndregion, ctx.Err())
		case <-time.After(mc.PollInterval):
		}
	}
}

// CreatePmemRegion creates a region of persistent memory on the memdev
// under the decoder (the root decoder of its host bridge for pmem if ""),
// and returns it with its nvdimm region and namespaces. The memdev is
// enabled if needed; an existing region of the memdev is reused. The
// namespaces are those of the labels of the memdev.
func (mc *Manager) CreatePmemRegion(ctx context.Context, memdev, decoder string) (*PmemRegion, error) {
	if _, err := os.Stat(mc.cxlDev(memdev, "driver")); err != nil {
		if _, err := mc.Exec(ctx, "cxl", "enable-memdev", memdev); err != nil {
			return nil, err
		}
	}
	region := ""
	if rs := mc.Regions(memdev); len(rs) > 0 {
		region = rs[0]
		if !mc.isPmemRegion(region) {
			return nil, fmt.Errorf("%s: %s is not a region of persistent memory", memdev, region)
		}
		mc.logf("%s: reusing %s", memdev, region)
	} else {
		if decoder == "" {
			d, err := mc.RootDecoder(memdev, RegionPmem)
			if err != nil {
				return nil, err
			}
			decoder = d
		}
		out, err := mc.Exec(ctx, "cxl", "create-region", "-t", RegionPmem, "-d", decoder, "-m", memdev)
		if err != nil {
			return nil, mc.explainCreateRegion(memdev, err)
		}
		if m := regionNameRe.FindStringSubmatch(out); m != nil {
			region = m[1]
		} else if rs := mc.Regions(memdev); len(rs) > 0 {
			region = rs[0]
		} else {
			return nil, fmt.Errorf("cxl create-region did not report a region: %s", out)
		}
		mc.logf("%s: created %s (pmem) under %s", memdev, region, decoder)
	}
	// the nvdimm region appears asynchronously
	var nd string
	for {
		var err error
		if nd, err = mc.NdRegion(region); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%s: no nvdimm region appeared: %w", region, ctx.Err())
		case <-time.After(mc.PollInterval):
		}
	}
	ns, err := mc.Namespaces(ctx, nd)
	if err != nil {
		return nil, err
	}
	return &PmemRegion{Memdev: memdev, Region: region, NdRegion: nd, Namespaces: ns}, nil
}

var namespaceNameRe = regexp.MustCompile(`"dev"\s*:\s*"(namespace\d+\.\d+)"`)

// CreateFsdaxNamespace creates an fsdax namespace with map mem in an
// nvdimm region, or reconfigures the namespace existing ("" for a new
// one) as such, with ndctl create-namespace, and returns it when its
// block device is there. This writes the labels of the region.
func (mc *Manager) CreateFsdaxNamespace(ctx context.Context, ndregion, existing string) (*Namespace, error) {
	args := []string{"create-namespace", "-f", "-r", ndregion, "-m", NamespaceFsdax, "-M", MapMem}
	if existing != "" {
		args = append(args, "-e", existing)
	}
	out, err := mc.Exec(ctx, "ndctl", args...)
	if err != nil {
		return nil, err
	}
	m := namespaceNameRe.FindStringSubmatch(out)
	if m == nil {
		return nil, fmt.Errorf("ndctl create-namespace did not report a namespace: %s", out)
	}
	for {
		nss, err := mc.Namespaces(ctx, ndregion)
		if err != nil {
			return nil, err
		}
		for i := range nss {
			if ns := &nss[i]; ns.Name == m[1] && ns.Mode == NamespaceFsdax && ns.BlockDevice != "" {
				mc.logf("%s: created %s (fsdax, map %s, %s, %d bytes)", ndregion, ns.Name, ns.Map, ns.BlockDevice, ns.Size)
				return ns, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%s: %s has no fsdax block device: %w", ndregion, m[1], ctx.Err())
		case <-time.After(mc.PollInterval):
		}
	}
}
