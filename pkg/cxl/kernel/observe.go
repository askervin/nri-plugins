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

package kernel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
)

// Snapshot is one observation of the CXL kernel objects of the node. The
// objects are listed in natural order of their names; an object that could
// not be read is left out and named in Errors. Its lookups only read it: a
// Snapshot of Observe has indexes, others are scanned.
type Snapshot struct {
	// BootID is the boot id of the running kernel, "" if it cannot be
	// read.
	BootID string `json:"bootID"`
	// BlockSize is the memory block size in bytes, 0 if it cannot be read.
	BlockSize uint64 `json:"blockSize"`
	// Memdevs are the memdevs that are present.
	Memdevs []MemdevInfo `json:"memdevs,omitempty"`
	// Ports are the ports of the decoder paths of the memdevs, each once,
	// in the order of the paths.
	Ports []Port `json:"ports,omitempty"`
	// Regions are all regions, hollow ones too.
	Regions []RegionInfo `json:"regions,omitempty"`
	// DaxRegions are the dax regions of the regions, DaxDevices their dax
	// devices.
	DaxRegions []DaxRegion     `json:"daxRegions,omitempty"`
	DaxDevices []DaxDeviceInfo `json:"daxDevices,omitempty"`
	Blocks     []MemoryBlock   `json:"blocks,omitempty"`
	NumaNodes  []NumaNode      `json:"numaNodes,omitempty"`
	Pmem       []NdRegion      `json:"pmem,omitempty"`
	Devices    []BlockDevice   `json:"blockDevices,omitempty"`
	Mounts     []MountInfo     `json:"mounts,omitempty"`
	Supers     []Superblock    `json:"superblocks,omitempty"`
	Loops      []LoopDevice    `json:"loops,omitempty"`
	Errors     []string        `json:"errors,omitempty"`
	byRegion   map[string]int  // index of Regions by name
	byDax      map[string]int  // index of DaxDevices by name
	byPort     map[string]int  // index of Ports by name
	byBlock    map[int]int     // index of Blocks by index
	bySerial   map[uint64]int  // index of Memdevs by serial
	byDevice   map[string]int  // index of Devices by /dev path
}

// BlockDevice is the observation of a block device of a namespace, or of a
// loop device over one.
type BlockDevice struct {
	// Path is /dev/pmemK or /dev/loopN.
	Path  string `json:"path"`
	Major int    `json:"major"`
	Minor int    `json:"minor"`
	// Size is its size in bytes.
	Size uint64 `json:"size"`
	// ReadOnly is its read-only flag (BLKROGET).
	ReadOnly bool `json:"readOnly"`
	// Namespace is the namespace of a pmem block device, "" for a loop
	// device.
	Namespace string `json:"namespace,omitempty"`
	// Backing is the backing block device of a loop device.
	Backing string `json:"backing,omitempty"`
}

// BootID returns the boot id of the running kernel
// (/proc/sys/kernel/random/boot_id).
func (k *Kernel) BootID() (string, error) {
	return ReadTrim(filepath.Join(k.procRoot(), "sys", "kernel", "random", "boot_id"))
}

// Observe returns a snapshot of the CXL kernel objects of the node. Its
// error is the error of the context when it ends during the observation.
func (k *Kernel) Observe(ctx context.Context) (*Snapshot, error) {
	s := &Snapshot{}
	problem := func(format string, args ...any) {
		s.Errors = append(s.Errors, fmt.Sprintf(format, args...))
	}
	var err error
	if s.BootID, err = k.BootID(); err != nil {
		problem("boot id: %v", err)
	}
	if err := k.observeSysfs(ctx, s, problem, true); err != nil {
		return nil, err
	}
	k.observeBlockDevices(s, problem)
	if mounts, err := k.Mounts(); err == nil {
		s.Mounts = mounts
	} else {
		problem("mounts: %v", err)
	}
	if len(s.Devices) > 0 {
		devs := map[string]string{}
		for _, d := range s.Devices {
			devs[strconv.Itoa(d.Major)+":"+strconv.Itoa(d.Minor)] = d.Path
		}
		if sbs, err := k.superblocksOf(devs); err == nil {
			s.Supers = sbs
		} else {
			problem("superblocks: %v", err)
		}
	}
	s.index()
	return s, ctx.Err()
}

// ObserveTopology returns a snapshot of the memory block size, the memdevs,
// the regions with their dax devices and memory blocks, and the NUMA nodes
// of the node, read from sysfs only: it opens no device and reads no
// mounts or mappings of dax devices, and the snapshot has no ports, dax
// regions, pmem, block devices, mounts, boot id, or memory ranges and
// memory blocks of dax devices. Its error is that of reading the CXL bus,
// of a memdev, a region or a NUMA node of which a fact cannot be read, of
// a serial that is not 0x<hex>, of a memory block size that cannot be read
// on a node with regions, or the error of the context when it ends.
func (k *Kernel) ObserveTopology(ctx context.Context) (*Snapshot, error) {
	if _, err := os.ReadDir(k.cxlDev()); err != nil {
		return nil, err
	}
	var errs []error
	strict := *k
	strict.fact = func(err error) { errs = append(errs, err) }
	s := &Snapshot{}
	problem := func(format string, args ...any) {
		s.Errors = append(s.Errors, fmt.Sprintf(format, args...))
	}
	if err := strict.observeSysfs(ctx, s, problem, false); err != nil {
		return nil, err
	}
	if s.BlockSize == 0 && len(s.Regions) > 0 {
		errs = append(errs, errors.New("the memory block size cannot be read"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	s.index()
	return s, nil
}

// observeSysfs adds the memory block size, the memdevs, the regions with
// their dax devices and memory blocks, and the NUMA nodes to the snapshot
// s, and with full the ports of the memdevs, the dax regions, the nd
// regions and the memory of the dax devices. Its error is the error of the
// context when it ends.
func (k *Kernel) observeSysfs(ctx context.Context, s *Snapshot, problem func(string, ...any), full bool) error {
	var err error
	if s.BlockSize, err = k.BlockSize(); err != nil {
		problem("memory block size: %v", err)
	}
	t := k.topology()
	endpoints := map[string]string{}
	for ep, memdev := range t.memdevOfEndpoint {
		endpoints[memdev] = ep
	}
	seenPort := map[string]bool{}
	for _, name := range k.memdevNames() {
		m, err := k.memdev(name, endpoints)
		if err != nil {
			problem("%v", err)
			k.factErr(err)
			continue
		}
		s.Memdevs = append(s.Memdevs, m)
		if full {
			k.observePorts(s, m.Endpoint, seenPort, problem)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, name := range k.listCXL("region*") {
		r, err := k.region(name, t)
		if err != nil {
			problem("%v", err)
			k.factErr(err)
			continue
		}
		s.Regions = append(s.Regions, r)
		k.observeRegion(s, r, problem, full)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.NumaNodes = k.NumaNodes()
	return nil
}

// observePorts adds the ports of the decoder path of the endpoint ep ("" for
// none) that are not seen yet to the snapshot s.
func (k *Kernel) observePorts(s *Snapshot, ep string, seen map[string]bool, problem func(string, ...any)) {
	if ep == "" {
		return
	}
	for _, dir := range k.endpointPorts(ep) {
		name := filepath.Base(dir)
		if seen[name] {
			continue
		}
		seen[name] = true
		p, err := readPort(dir)
		if err != nil {
			problem("%s: %v", name, err)
			continue
		}
		s.Ports = append(s.Ports, p)
	}
}

// observeRegion adds the dax devices and the memory blocks of the region r
// to the snapshot s, and with full its dax region, its nd region and the
// memory of its dax devices.
func (k *Kernel) observeRegion(s *Snapshot, r RegionInfo, problem func(string, ...any), full bool) {
	if r.DaxRegion != "" && full {
		if d, err := k.DaxRegion(r.Name); err == nil {
			s.DaxRegions = append(s.DaxRegions, d)
		} else {
			problem("%s: dax region: %v", r.Name, err)
		}
	}
	if r.DaxRegion != "" {
		for _, dax := range k.DaxDevices(r.Name) {
			if d, err := k.daxDevice(dax, full); err == nil {
				s.DaxDevices = append(s.DaxDevices, d)
			} else {
				problem("%v", err)
			}
		}
	}
	if r.Mode == RegionRAM && r.Range != (Range{}) && s.BlockSize > 0 {
		for _, b := range r.Range.blocks(s.BlockSize) {
			s.Blocks = append(s.Blocks, k.MemoryBlock(b))
		}
	}
	if !full || r.NdRegion == "" {
		return
	}
	nd, err := k.NdRegion(r.NdRegion)
	if err != nil {
		problem("%s: %v", r.NdRegion, err)
		return
	}
	nd.Region = r.Name
	s.Pmem = append(s.Pmem, nd)
}

// observeBlockDevices adds the block devices of the namespaces of the
// snapshot and the loop devices over them.
func (k *Kernel) observeBlockDevices(s *Snapshot, problem func(string, ...any)) {
	sys := k.sys()
	for _, nd := range s.Pmem {
		for _, ns := range nd.Namespaces {
			if ns.BlockDevice == "" {
				continue
			}
			d := BlockDevice{Path: ns.BlockDevice, Major: ns.Major, Minor: ns.Minor, Size: ns.Size, Namespace: ns.Name}
			var err error
			if d.ReadOnly, err = sys.ReadOnly(d.Path); err != nil {
				problem("%s: read-only flag: %v", d.Path, err)
			}
			s.Devices = append(s.Devices, d)
		}
	}
	for _, l := range k.LoopDevices() {
		backing := ""
		for _, d := range s.Devices {
			if d.Namespace != "" && SameDevice(l.Backing, d.Path) {
				backing = d.Path
			}
		}
		if backing == "" {
			continue
		}
		s.Loops = append(s.Loops, l)
		d := BlockDevice{Path: filepath.Join(k.devRoot(), l.Name), Backing: backing}
		if ma, mi, err := parseDevNumbers(l.Name, l.DevNum); err == nil {
			d.Major, d.Minor = ma, mi
		}
		if sectors, err := ReadUint(filepath.Join(k.sysRoot(), "block", l.Name, "size")); err == nil {
			d.Size = sectors * 512
		}
		var err error
		if d.ReadOnly, err = sys.ReadOnly(d.Path); err != nil {
			problem("%s: read-only flag: %v", d.Path, err)
		}
		s.Devices = append(s.Devices, d)
	}
}

// Reindex builds the indexes of the lookups of the snapshot again, for the
// objects added to its lists.
func (s *Snapshot) Reindex() { s.index() }

// index builds the indexes of the lookups of the snapshot.
func (s *Snapshot) index() {
	s.byRegion = map[string]int{}
	for i, r := range s.Regions {
		s.byRegion[r.Name] = i
	}
	s.byDax = map[string]int{}
	for i, d := range s.DaxDevices {
		s.byDax[d.Name] = i
	}
	s.byPort = map[string]int{}
	for i, p := range s.Ports {
		s.byPort[p.Name] = i
	}
	s.byBlock = map[int]int{}
	for i, b := range s.Blocks {
		s.byBlock[b.Index] = i
	}
	s.bySerial = map[uint64]int{}
	for i, m := range s.Memdevs {
		s.bySerial[m.Serial] = i
	}
	s.byDevice = map[string]int{}
	for i, d := range s.Devices {
		s.byDevice[d.Path] = i
	}
}

// find returns the index of the entry of a lookup: from the index that
// Observe built, else by a scan (a Snapshot that Observe did not make, such
// as a decoded one, is read without being written).
func find[K comparable](idx map[K]int, n int, key K, keyOf func(int) K) (int, bool) {
	if idx != nil {
		i, ok := idx[key]
		return i, ok
	}
	for i := 0; i < n; i++ {
		if keyOf(i) == key {
			return i, true
		}
	}
	return 0, false
}

// Memdev returns the memdev with the serial, in state MemdevAbsent if the
// snapshot has none.
func (s *Snapshot) Memdev(serial uint64) MemdevInfo {
	if i, ok := find(s.bySerial, len(s.Memdevs), serial, func(i int) uint64 { return s.Memdevs[i].Serial }); ok {
		return s.Memdevs[i]
	}
	return MemdevInfo{Serial: serial, State: MemdevAbsent, NodeAffinity: -1}
}

// Region returns the region with the name, in state RegionAbsent if the
// snapshot has none.
func (s *Snapshot) Region(name string) RegionInfo {
	if i, ok := find(s.byRegion, len(s.Regions), name, func(i int) string { return s.Regions[i].Name }); ok {
		return s.Regions[i]
	}
	return RegionInfo{Name: name, State: RegionAbsent, NumaNode: -1}
}

// RegionsOf returns the regions with a target decoder of the memdev with
// the serial.
func (s *Snapshot) RegionsOf(serial uint64) []RegionInfo {
	var out []RegionInfo
	for _, r := range s.Regions {
		if slices.Contains(r.Serials, serial) {
			out = append(out, r)
		}
	}
	return out
}

// DaxDevice returns the dax device with the name, in state DaxAbsent if
// the snapshot has none.
func (s *Snapshot) DaxDevice(name string) DaxDeviceInfo {
	if i, ok := find(s.byDax, len(s.DaxDevices), name, func(i int) string { return s.DaxDevices[i].Name }); ok {
		return s.DaxDevices[i]
	}
	return DaxDeviceInfo{Name: name, State: DaxAbsent, TargetNode: -1}
}

// DaxDevicesOf returns the dax devices of a region.
func (s *Snapshot) DaxDevicesOf(region string) []DaxDeviceInfo {
	var out []DaxDeviceInfo
	for _, d := range s.DaxDevices {
		if d.Region == region {
			out = append(out, d)
		}
	}
	return out
}

// Block returns the memory block with the index, in state BlockAbsent if
// the snapshot has none.
func (s *Snapshot) Block(index int) MemoryBlock {
	if i, ok := find(s.byBlock, len(s.Blocks), index, func(i int) int { return s.Blocks[i].Index }); ok {
		return s.Blocks[i]
	}
	return MemoryBlock{Index: index, State: BlockAbsent, NumaNode: -1}
}

// OnlineBlocks returns the memory blocks of blocks that are online.
func (s *Snapshot) OnlineBlocks(blocks []int) []int {
	var out []int
	for _, b := range blocks {
		if s.Block(b).State == BlockOnline {
			out = append(out, b)
		}
	}
	return out
}

// Port returns the port with the name, false if the snapshot has none.
func (s *Snapshot) Port(name string) (Port, bool) {
	if i, ok := find(s.byPort, len(s.Ports), name, func(i int) string { return s.Ports[i].Name }); ok {
		return s.Ports[i], true
	}
	return Port{Name: name}, false
}

// pathPort returns a port of the decoder path of a memdev, an error if
// the snapshot could not read it.
func (s *Snapshot) pathPort(name string) (Port, error) {
	p, ok := s.Port(name)
	if !ok {
		return p, fmt.Errorf("the decoders of %s could not be read", name)
	}
	return p, nil
}

// DecoderHoles returns the holes in the ports of the decoder path of the
// memdev with the serial (see Kernel.DecoderHoles); a port that the
// snapshot could not read is an error.
func (s *Snapshot) DecoderHoles(serial uint64) ([]DecoderHole, error) {
	var holes []DecoderHole
	for _, name := range s.Memdev(serial).Ports {
		p, err := s.pathPort(name)
		if err != nil {
			return nil, err
		}
		if h, ok := p.Hole(); ok {
			holes = append(holes, h)
		}
	}
	return holes, nil
}

// RegionsAbove returns the regions of other memdevs above those of the
// memdev with the serial in the ports of its decoder path (see
// Kernel.RegionsAbove); a port that the snapshot could not read is an
// error, never "nothing above".
func (s *Snapshot) RegionsAbove(serial uint64) ([]string, error) {
	m := s.Memdev(serial)
	if len(m.Regions) == 0 {
		return nil, nil
	}
	var above []string
	for _, name := range m.Ports {
		if !portDirRe.MatchString(name) {
			continue
		}
		p, err := s.pathPort(name)
		if err != nil {
			return nil, err
		}
		for _, r := range p.Above(m.Regions) {
			if !slices.Contains(above, r) {
				above = append(above, r)
			}
		}
	}
	return above, nil
}

// NumaNode returns the NUMA node with the id, false if the snapshot has
// none.
func (s *Snapshot) NumaNode(id int) (NumaNode, bool) {
	for _, n := range s.NumaNodes {
		if n.ID == id {
			return n, true
		}
	}
	return NumaNode{ID: id}, false
}

// NdRegionOf returns the nd region of a CXL region, in state NdAbsent if
// the snapshot has none.
func (s *Snapshot) NdRegionOf(region string) NdRegion {
	for _, nd := range s.Pmem {
		if nd.Region == region {
			return nd
		}
	}
	return NdRegion{Region: region, State: NdAbsent}
}

// BlockDevice returns the block device with the /dev path, false if the
// snapshot has none.
func (s *Snapshot) BlockDevice(path string) (BlockDevice, bool) {
	if i, ok := find(s.byDevice, len(s.Devices), path, func(i int) string { return s.Devices[i].Path }); ok {
		return s.Devices[i], true
	}
	return BlockDevice{Path: path}, false
}

// SuperblocksOf returns the superblocks on the block device dev and on the
// loop devices over it.
func (s *Snapshot) SuperblocksOf(dev string) []Superblock {
	var out []Superblock
	for _, sb := range s.Supers {
		if sb.Device == dev {
			out = append(out, sb)
			continue
		}
		if d, ok := s.BlockDevice(sb.Device); ok && d.Backing == dev {
			out = append(out, sb)
		}
	}
	return out
}
