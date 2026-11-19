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

package dra

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	v1 "k8s.io/api/core/v1"
	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/klog/v2"
	"k8s.io/utils/cpuset"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// DeviceInfo is a device of the table of the publisher: its name in the
// ResourceSlice and the device behind it.
type DeviceInfo struct {
	Name string
	// Dev is a *DRAM, *Region, *Memdev or *LeaseToken.
	Dev any
}

// DevicesInfo are the devices of the table of the publisher by name.
type DevicesInfo map[string]*DeviceInfo

// DRAM is the Dev of the DRAM device.
type DRAM struct {
	Nodes []int
	Size  uint64
}

// Region is the Dev of a region device (DeviceTypeRegion).
type Region struct {
	Name     string // regionN
	NumaNode int    // NUMA node of its memory
	Size     uint64 // bytes
	// NodeAffinity are the CPU NUMA nodes of its memdevs, -1 for one not
	// known.
	NodeAffinity []int
}

// Memdev is the Dev of a local memdev device (DeviceTypeMemdev).
type Memdev struct {
	Name         string // memN
	Serial       uint64
	Size         uint64 // RAM capacity, bytes (persistent capacity of a persistent memdev)
	NodeAffinity int    // CPU NUMA node of the memdev, -1 if unknown
	BlockSize    uint64 // memory block size, bytes: slices are multiples of it
	Shared       bool   // published shared: one devdax device for all claims
	// Persistent is true for a memdev of persistent memory: modes block
	// and fs, one pmem region for all claims.
	Persistent bool
}

// LeaseToken is the Dev of the lease device: it has no hardware, no
// capacity and can be allocated any number of times.
type LeaseToken struct{}

// LocalUse is how the device engine uses a local memdev.
type LocalUse struct {
	// Shared is true when the memdev is used as a shared device, false
	// when it is sliced; of a persistent device, whether it is shared.
	Shared bool
	// Persistent is true when the memdev is used as a persistent device.
	Persistent bool
	// Claims are the UIDs of the claims that use the memdev.
	Claims []string
}

// LocalSnapshot is what the publisher of local memdevs needs from the
// records of the device engine.
type LocalSnapshot struct {
	// Uses are the uses of the local memdevs that the engine has records
	// of, by serial.
	Uses map[uint64]LocalUse
	// BlockSize is the memory block size in bytes, 0 if unknown.
	BlockSize uint64
	// Probed are the usable sizes that the address line probe found, by
	// serial.
	Probed map[uint64]uint64
}

// ProbedSize returns the usable size that the address line probe found for
// the memdev with the serial, 0 if none.
func (l *LocalSnapshot) ProbedSize(serial uint64) uint64 {
	if l == nil {
		return 0
	}
	return l.Probed[serial]
}

// InUse tells whether the engine uses the local memdev with the serial.
func (l *LocalSnapshot) InUse(serial uint64) bool {
	if l == nil {
		return false
	}
	_, ok := l.Uses[serial]
	return ok
}

// Use returns how the engine uses the local memdev with the serial, and
// whether it uses it.
func (l *LocalSnapshot) Use(serial uint64) (LocalUse, bool) {
	if l == nil {
		return LocalUse{}, false
	}
	u, ok := l.Uses[serial]
	return u, ok
}

// claims returns the claims of the local memdevs that the engine uses, by
// serial.
func (l *LocalSnapshot) claims() map[uint64][]string {
	if l == nil {
		return nil
	}
	out := map[uint64][]string{}
	for s, u := range l.Uses {
		out[s] = u.Claims
	}
	return out
}

// LocalUsableSize returns the bytes of whole memory blocks of bs bytes that
// a region on a memdev of size bytes is sure to hold, wherever in its
// window it starts.
func LocalUsableSize(size, bs uint64) uint64 {
	if bs == 0 {
		return 0
	}
	if bs > kernel.RegionAlign {
		head := bs - kernel.RegionAlign
		if size <= head {
			return 0
		}
		size -= head
	}
	return size / bs * bs
}

// hollowRegions are the hollow regions of the last scan, warned about.
var hollowRegions = &hollowRegionLog{warned: map[string]bool{}}

// hollowRegionLog warns once about each hollow region of the scans that is
// not one of the device engine (the engine warns about its own).
//
// Identity: one per process (hollowRegions), shared by the scans.
//
// States: none but the set warned, the hollow regions of the last scan.
//
// Transitions: each scan replaces warned with its hollow regions; a region
// is warned about when it enters the set.
//
// Persistence: none: a restart warns again.
//
// Locks and waits: mu guards warned, held for one observe.
type hollowRegionLog struct {
	// mu guards warned: a leaf lock.
	mu     sync.Mutex
	warned map[string]bool // name and resource of a hollow region
}

// observe logs a warning for each hollow region among regions that is not
// ours and that the last scan did not have: no decoder maps its address
// range any more (memory of it that kmem could not remove stays online
// until a reboot, which is why such a region may still have a node), it
// holds that range in its root decoder, and cxl destroy-region cannot
// remove it; with the command that removes it.
func (h *hollowRegionLog) observe(regions []kernel.RegionInfo, ours func(name string) bool) {
	seen := map[string]bool{}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range regions {
		if r.State != kernel.RegionHollow || ours(r.Name) {
			continue
		}
		key := fmt.Sprintf("%s@%#x", r.Name, r.Range.Start)
		seen[key] = true
		if h.warned[key] {
			continue
		}
		decoder := r.RootDecoder
		if decoder == "" {
			decoder = "<its root decoder>"
		}
		klog.Warningf("CXL region %s (mode %s, resource %#x, size %#x) has no target decoder: it is not published. It is left behind when its memory device was removed before the region was destroyed (or is being created right now). No decoder maps its address range, which it holds; cxl destroy-region cannot remove it. If it stays and none of its memory blocks is online: echo %s > /sys/bus/cxl/devices/%s/delete_region",
			r.Name, r.Mode, r.Range.Start, regionSize(r), r.Name, decoder)
	}
	h.warned = seen
}

// regionSize returns the size of a region in bytes, 0 while it has no
// address range.
func regionSize(r kernel.RegionInfo) uint64 {
	if r.Range == (kernel.Range{}) {
		return 0
	}
	return r.Range.Size()
}

// regionNodes returns the NUMA node of the memory of each region of the
// snapshot, by name: the node of a zone of online memory that starts in the
// region (the first online memory block of its node and zone), else the
// target node of a dax device of the region, -1 if neither tells.
func regionNodes(snap *kernel.Snapshot) map[string]int {
	type zone struct {
		node  int
		zones string
	}
	// a zone of /proc/zoneinfo starts at its first online memory block
	first := map[zone]int{}
	for _, b := range snap.Blocks {
		z := zone{b.NumaNode, b.Zones}
		if f, ok := first[z]; b.State == kernel.BlockOnline && b.NumaNode >= 0 && (!ok || b.Index < f) {
			first[z] = b.Index
		}
	}
	out := map[string]int{}
	for _, r := range snap.Regions {
		node := -1
		for z, b := range first {
			if addr := uint64(b) * snap.BlockSize; r.Range != (kernel.Range{}) && addr >= r.Range.Start && addr <= r.Range.End {
				node = z.node
			}
		}
		for _, d := range snap.DaxDevicesOf(r.Name) {
			if node < 0 && d.TargetNode >= 0 {
				node = d.TargetNode
			}
		}
		out[r.Name] = node
	}
	return out
}

// numaNodesByName returns the NUMA nodes of the snapshot in the order of
// their names (node10 before node2).
func numaNodesByName(snap *kernel.Snapshot) []kernel.NumaNode {
	nodes := slices.Clone(snap.NumaNodes)
	slices.SortStableFunc(nodes, func(a, b kernel.NumaNode) int { return strings.Compare(strconv.Itoa(a.ID), strconv.Itoa(b.ID)) })
	return nodes
}

// regionMemdevs returns the memdevs of the targets of a region, in the
// order of the names of their endpoints.
func regionMemdevs(snap *kernel.Snapshot, r *kernel.RegionInfo) []kernel.MemdevInfo {
	out := make([]kernel.MemdevInfo, 0, len(r.Serials))
	for _, s := range r.Serials {
		out = append(out, snap.Memdev(s))
	}
	slices.SortStableFunc(out, func(a, b kernel.MemdevInfo) int { return strings.Compare(a.Endpoint, b.Endpoint) })
	return out
}

// BuildDevices returns the devices to publish of a snapshot, by device
// name. poolSerials are the serials of pool devices (prepared by the
// pool driver, published by a pool controller, or remembered as such): their
// regions are skipped, and they are never local memdevs; held are the
// serials of new memdevs that are held as possible pool devices: like pool
// devices, neither they nor their regions are published. Regions on memdevs
// that the device engine uses (local) are skipped too: the engine created
// them, and the memdevs are published as memdev devices.
func BuildDevices(cfg PublishConfig, snap *kernel.Snapshot, poolSerials, held map[uint64]bool, local *LocalSnapshot) DevicesInfo {
	cxlNodes := make(map[int]bool)
	devInfos := make(map[string]*DeviceInfo)
	nodes := regionNodes(snap)
	for i := range snap.Regions {
		r := &snap.Regions[i]
		node := nodes[r.Name]
		klog.V(3).Infof("discovered CXL region device: %+v", *r)
		// the memory of a hollow region that kmem could not remove is not
		// DRAM either
		cxlNodes[node] = true
		if r.State == kernel.RegionHollow {
			klog.V(4).Infof("- ignoring region device %q: it has no target decoder", r.Name)
			continue
		}
		mems := regionMemdevs(snap, r)
		if reason := regionIgnoreReason(cfg, r, node, mems, poolSerials, held, local); reason != "" {
			klog.V(4).Infof("- ignoring region device %q: %s", r.Name, reason)
			continue
		}
		dev := &Region{Name: r.Name, NumaNode: node, Size: regionSize(*r)}
		for _, m := range mems {
			dev.NodeAffinity = append(dev.NodeAffinity, m.NodeAffinity)
		}
		name := fmt.Sprintf("%s-node%d", r.Name, node)
		devInfos[name] = &DeviceInfo{Name: name, Dev: dev}
	}
	if cfg.ManageMemdevs {
		addLocalMemdevs(devInfos, cfg, snap, poolSerials, held, local)
	}
	if !cfg.IgnoreDRAMNodes {
		addDRAM(devInfos, cfg, snap, cxlNodes)
	}
	if cfg.PublishLeaseDevice {
		devInfos[device.LeaseDeviceName] = &DeviceInfo{
			Name: device.LeaseDeviceName,
			Dev:  &LeaseToken{},
		}
	}
	return devInfos
}

// regionIgnoreReason returns why a region on node with the memdevs mems
// that is not hollow is not published, "" if it is: on a pool or held
// memdev, on a memdev of the engine, without a node (disabled), of
// persistent memory, in ignoreRegions, on a node of ignoreNodes, with a
// memdev of ignoreDevices; the first reason only.
func regionIgnoreReason(cfg PublishConfig, r *kernel.RegionInfo, node int, mems []kernel.MemdevInfo, poolSerials, held map[uint64]bool, local *LocalSnapshot) string {
	reason := poolIgnoreReason(mems, poolSerials, held)
	if reason == "" {
		reason = localIgnoreReason(mems, local)
	}
	if node < 0 {
		reason = "region is disabled"
	}
	if reason == "" && r.Mode == kernel.RegionPmem {
		reason = "region of persistent memory"
	}
	if reason != "" {
		return reason
	}
	if slices.Contains(cfg.IgnoreRegions, r.Name) {
		return fmt.Sprintf("region name %q", r.Name)
	}
	if slices.Contains(cfg.IgnoreNodes, node) {
		return fmt.Sprintf("region is on node %d", node)
	}
	for i := range mems {
		if m := memdevMatches(cfg.IgnoreDevices, &mems[i]); m != "" {
			return "region has a " + m
		}
	}
	return ""
}

// addDRAM adds the DRAM device of the memory nodes that are not CXL nodes
// to devInfos.
func addDRAM(devInfos DevicesInfo, cfg PublishConfig, snap *kernel.Snapshot, cxlNodes map[int]bool) {
	dramDev := &DRAM{}
	for _, node := range numaNodesByName(snap) {
		if cxlNodes[node.ID] {
			continue
		}
		ignoreReason := ""
		switch {
		case node.MemTotal == 0:
			ignoreReason = "node has 0 size"
		case slices.Contains(cfg.IgnoreNodes, node.ID):
			ignoreReason = fmt.Sprintf("node ID %d is in ignoreNodes", node.ID)
		}
		if ignoreReason != "" {
			klog.V(4).Infof("- ignoring DRAM on node %d: %s", node.ID, ignoreReason)
			continue
		}
		dramDev.Nodes = append(dramDev.Nodes, node.ID)
		dramDev.Size += node.MemTotal
		klog.V(4).Infof("discovered DRAM memory on node %d: size %d bytes", node.ID, node.MemTotal)
	}
	if dramDev.Size > 0 {
		devInfos[device.DRAMDeviceName] = &DeviceInfo{
			Name: device.DRAMDeviceName,
			Dev:  any(dramDev),
		}
		klog.V(3).Infof("discovered system DRAM device: %+v", dramDev)
	}
}

// poolIgnoreReason returns why a region on the memdevs mems, a pool device
// or a memdev that is held among them, is not published, "" if it is on
// neither.
func poolIgnoreReason(mems []kernel.MemdevInfo, poolSerials, held map[uint64]bool) string {
	for _, memDev := range mems {
		if poolSerials[memDev.Serial] {
			return fmt.Sprintf("pool device (%s), memory device serial 0x%x", device.PoolDriverName, memDev.Serial)
		}
		if held[memDev.Serial] {
			return fmt.Sprintf("memory device serial 0x%x is held back: it may be a pool device", memDev.Serial)
		}
	}
	return ""
}

// heldReason is why a memdev that is held is not published.
const heldReason = "held back: it may be a pool device"

// localIgnoreReason returns why a region on the memdevs mems, a local
// memdev that the engine uses among them, is not published, "" if it is not
// on one.
func localIgnoreReason(mems []kernel.MemdevInfo, local *LocalSnapshot) string {
	for _, memDev := range mems {
		if local.InUse(memDev.Serial) {
			return fmt.Sprintf("created by the plugin on local memory device %s", MemdevDeviceName(memDev.Serial))
		}
	}
	return ""
}

// memdevMatches returns which spec of specs matches a memdev, described,
// "" if none does. A spec matches the memdev name (mem0), the uevent device
// name (cxl/mem0), <major>:<minor> or the serial in decimal, 0x<hex> or
// <hex>.
func memdevMatches(specs []string, memDev *kernel.MemdevInfo) string {
	for _, spec := range specs {
		switch spec {
		case memDev.Name:
			return fmt.Sprintf("memory device name %q", spec)
		case "cxl/" + memDev.Name:
			return fmt.Sprintf("memory uevent device name %q", spec)
		case fmt.Sprintf("%d:%d", memDev.Major, memDev.Minor):
			return fmt.Sprintf("memory device with major:minor %q", spec)
		case fmt.Sprintf("%d", memDev.Serial), fmt.Sprintf("0x%x", memDev.Serial), fmt.Sprintf("%x", memDev.Serial):
			return fmt.Sprintf("memory device serial %q", spec)
		}
	}
	return ""
}

// sharedListing tells whether SharedDevices of the configuration lists a
// memdev, and why a listed memdev is not a shared local device: it is
// ignored, a pool device or held ("" if it is one).
func sharedListing(cfg PublishConfig, memDev *kernel.MemdevInfo, poolSerials, held map[uint64]bool) (bool, string) {
	if memdevMatches(cfg.SharedDevices, memDev) == "" {
		return false, ""
	}
	if reason := memdevMatches(cfg.IgnoreDevices, memDev); reason != "" {
		return true, "ignored by " + reason
	}
	if poolSerials[memDev.Serial] {
		return true, "pool device"
	}
	if held[memDev.Serial] {
		return true, heldReason
	}
	return true, ""
}

// SharedSerials returns the serials of the memdevs that are shared local
// devices of the configuration: SharedDevices lists them, and they are
// neither ignored nor pool devices.
func SharedSerials(cfg PublishConfig, memDevs []kernel.MemdevInfo, poolSerials map[uint64]bool) map[uint64]bool {
	out := map[uint64]bool{}
	for i := range memDevs {
		memDev := &memDevs[i]
		if listed, refusal := sharedListing(cfg, memDev, poolSerials, nil); listed && refusal == "" {
			out[memDev.Serial] = true
		}
	}
	return out
}

// sharedRefusalsLogged has the refusals of shared local devices that are
// logged already, so that each is logged once.
var sharedRefusalsLogged sync.Map

// logSharedRefusal logs once why a memdev of SharedDevices is not published
// as a shared local device.
func logSharedRefusal(memDev *kernel.MemdevInfo, reason string) {
	if _, logged := sharedRefusalsLogged.LoadOrStore(memDev.Name+"\x00"+reason, true); !logged {
		klog.Infof("- not publishing memory device %q as a shared local device: %s", memDev.Name, reason)
	}
}

// addLocalMemdevs adds the local memdevs that the engine can use to
// devInfos. Per memdev, ignoreDevices takes precedence over pool devices,
// pool devices over sharedDevices, and sharedDevices over sliced memdevs. A
// memdev of persistent memory only (no RAM capacity) is a persistent
// memdev, shared when sharedDevices lists it (addPersistentMemdev). A shared
// memdev is published when it is enabled, has RAM capacity, no regions but
// the engine's and no claims of slices. A sliced memdev is published when it
// is enabled, its RAM capacity is sure to hold a whole memory block, it has
// no regions but the engine's and no claims that use it shared or
// persistent.
func addLocalMemdevs(devInfos DevicesInfo, cfg PublishConfig, snap *kernel.Snapshot, poolSerials, held map[uint64]bool, local *LocalSnapshot) {
	bs := uint64(0)
	if local != nil {
		bs = local.BlockSize
	}
	regions := map[uint64][]string{}
	for _, r := range snap.Regions {
		for _, s := range r.Serials {
			regions[s] = append(regions[s], r.Name)
		}
	}
	for i := range snap.Memdevs {
		memDev := &snap.Memdevs[i]
		listed, refusal := sharedListing(cfg, memDev, poolSerials, held)
		if refusal != "" {
			logSharedRefusal(memDev, refusal)
		}
		if memDev.PmemSize > 0 && memDev.RamSize == 0 {
			addPersistentMemdev(devInfos, cfg, memDev, listed && refusal == "", poolSerials, held, regions[memDev.Serial], local)
			continue
		}
		if memDev.PmemSize > 0 {
			klog.V(3).Infof("- memory device %q: persistent capacity of a memdev with RAM capacity is not used", memDev.Name)
		}
		if listed && refusal == "" {
			addSharedMemdev(devInfos, memDev, memdevUsableSize(cfg, memDev, local), regions[memDev.Serial], local, bs)
			continue
		}
		size := memdevUsableSize(cfg, memDev, local)
		if reason := partsRefusal(cfg, memDev, size, bs, poolSerials, held, regions[memDev.Serial], local); reason != "" {
			klog.V(4).Infof("- not publishing memory device %q as a local memory device: %s", memDev.Name, reason)
			continue
		}
		name := MemdevDeviceName(memDev.Serial)
		devInfos[name] = &DeviceInfo{
			Name: name,
			Dev: &Memdev{
				Name:         memDev.Name,
				Serial:       memDev.Serial,
				Size:         size,
				NodeAffinity: memDev.NodeAffinity,
				BlockSize:    bs,
			},
		}
		klog.V(3).Infof("discovered local memory device %s: %s serial 0x%x size %d (RAM capacity %d) memory block size %d", name, memDev.Name, memDev.Serial, size, memDev.RamSize, bs)
	}
}

// partsRefusal returns why a memdev of usable size bytes with memory
// blocks of bs bytes is not published as a sliced local memdev, "" if it
// is: no RAM, an unknown block size, too small, disabled, a pool or held
// memdev, regions that the engine did not create, claims that use it
// persistent or shared, ignoreDevices.
func partsRefusal(cfg PublishConfig, memDev *kernel.MemdevInfo, size, bs uint64, poolSerials, held map[uint64]bool, regions []string, local *LocalSnapshot) string {
	use, used := local.Use(memDev.Serial)
	switch {
	case memDev.RamSize == 0:
		return "no RAM capacity"
	case bs == 0:
		return "the memory block size is unknown"
	case LocalUsableSize(size, bs) == 0:
		return fmt.Sprintf("usable RAM capacity %d is not sure to hold a whole memory block of %d bytes", size, bs)
	case memDev.State == kernel.MemdevUnbound:
		return "memory device is disabled"
	case poolSerials[memDev.Serial]:
		return "pool device"
	case held[memDev.Serial]:
		return heldReason
	case len(regions) > 0 && !used:
		return fmt.Sprintf("it has regions %v that the plugin did not create", regions)
	case use.Persistent && len(use.Claims) > 0:
		return fmt.Sprintf("used as a persistent device by claims %v", use.Claims)
	case use.Shared && len(use.Claims) > 0:
		return fmt.Sprintf("used shared by claims %v", use.Claims)
	}
	return memdevMatches(cfg.IgnoreDevices, memDev)
}

// memdevUsableSize returns the bytes of a local memdev that the engine
// uses: its RAM capacity, or less when memdevSettings or the address line
// probe limit it, rounded down to the alignment of CXL regions.
func memdevUsableSize(cfg PublishConfig, memDev *kernel.MemdevInfo, local *LocalSnapshot) uint64 {
	size := memDev.RamSize
	for _, limit := range []uint64{cfg.usableSize(memDev.Name, memDev.Serial), local.ProbedSize(memDev.Serial)} {
		if limit > 0 && limit < size {
			size = limit / kernel.RegionAlign * kernel.RegionAlign
		}
	}
	return size
}

// addSharedMemdev adds a memdev of sharedDevices to devInfos as a shared
// local device, unless it is disabled, has no RAM capacity, has regions that
// the engine did not create or claims that use it as slices.
//   - regions: the regions on the memdev
//   - bs: the memory block size, 0 if unknown
func addSharedMemdev(devInfos DevicesInfo, memDev *kernel.MemdevInfo, size uint64, regions []string, local *LocalSnapshot, bs uint64) {
	use, used := local.Use(memDev.Serial)
	reason := ""
	switch {
	case memDev.RamSize == 0:
		reason = "no RAM capacity"
	case memDev.State == kernel.MemdevUnbound:
		reason = "memory device is disabled"
	case len(regions) > 0 && !used:
		reason = fmt.Sprintf("it has regions %v that the plugin did not create", regions)
	case use.Persistent && len(use.Claims) > 0:
		reason = fmt.Sprintf("used as a persistent device by claims %v", use.Claims)
	case !use.Shared && len(use.Claims) > 0:
		reason = fmt.Sprintf("used as slices by claims %v", use.Claims)
	}
	if reason != "" {
		klog.V(4).Infof("- not publishing memory device %q as a shared local device: %s", memDev.Name, reason)
		return
	}
	name := MemdevDeviceName(memDev.Serial)
	devInfos[name] = &DeviceInfo{
		Name: name,
		Dev: &Memdev{
			Name:         memDev.Name,
			Serial:       memDev.Serial,
			Size:         size,
			NodeAffinity: memDev.NodeAffinity,
			BlockSize:    bs,
			Shared:       true,
		},
	}
	klog.V(3).Infof("discovered shared local memory device %s: %s serial 0x%x size %d", name, memDev.Name, memDev.Serial, memDev.RamSize)
}

// addPersistentMemdev adds a memdev of persistent memory to devInfos as a
// persistent local device, shared when sharedDevices lists it, unless it is
// ignored, a pool device or held, disabled, has regions that the engine did
// not create, or claims that use it as slices, as a volatile shared device,
// or as a persistent device of the other sharing.
//   - shared: sharedDevices lists the memdev, which is neither ignored nor
//     a pool device
//   - regions: the regions on the memdev
func addPersistentMemdev(devInfos DevicesInfo, cfg PublishConfig, memDev *kernel.MemdevInfo, shared bool, poolSerials, held map[uint64]bool, regions []string, local *LocalSnapshot) {
	use, used := local.Use(memDev.Serial)
	reason := memdevMatches(cfg.IgnoreDevices, memDev)
	switch {
	case reason != "":
	case poolSerials[memDev.Serial]:
		reason = "pool device"
	case held[memDev.Serial]:
		reason = heldReason
	case memDev.State == kernel.MemdevUnbound:
		reason = "memory device is disabled"
	case len(regions) > 0 && !used:
		reason = fmt.Sprintf("it has regions %v that the plugin did not create", regions)
	case len(use.Claims) == 0:
	case !use.Persistent && use.Shared:
		reason = fmt.Sprintf("used shared by claims %v", use.Claims)
	case !use.Persistent:
		reason = fmt.Sprintf("used as slices by claims %v", use.Claims)
	case use.Shared != shared:
		reason = fmt.Sprintf("used as a %s persistent device by claims %v", sharedWord(use.Shared), use.Claims)
	}
	if reason != "" {
		klog.V(4).Infof("- not publishing memory device %q as a persistent local memory device: %s", memDev.Name, reason)
		return
	}
	name := MemdevDeviceName(memDev.Serial)
	devInfos[name] = &DeviceInfo{
		Name: name,
		Dev: &Memdev{
			Name:         memDev.Name,
			Serial:       memDev.Serial,
			Size:         memDev.PmemSize,
			NodeAffinity: memDev.NodeAffinity,
			Shared:       shared,
			Persistent:   true,
		},
	}
	klog.V(3).Infof("discovered persistent local memory device %s: %s serial 0x%x size %d shared %v", name, memDev.Name, memDev.Serial, memDev.PmemSize, shared)
}

// sharedWord returns "shared" or "not shared".
func sharedWord(shared bool) string {
	if shared {
		return "shared"
	}
	return "not shared"
}

// MemdevDeviceName returns the device name of a local memdev: "memdev-" +
// lower-case hex serial.
func MemdevDeviceName(serial uint64) string {
	return device.MemdevDevicePrefix + strconv.FormatUint(serial, 16)
}

// resources returns the devices of the node's ResourceSlices of the table,
// sorted by name.
func resources(devs DevicesInfo) []resourcev1.Device {
	out := []resourcev1.Device{}
	for _, name := range slices.Sorted(maps.Keys(devs)) {
		allocatable := devs[name]
		if allocatable.Dev == nil {
			continue
		}
		switch dev := allocatable.Dev.(type) {
		case *Region:
			out = append(out, regionDevice(name, dev))
		case *DRAM:
			out = append(out, dramDevice(name, dev))
		case *Memdev:
			out = append(out, LocalMemdevDevice(name, dev))
		case *LeaseToken:
			out = append(out, leaseDevice(name))
		default:
			klog.Warningf("unexpected device type in state.Allocatable: %T", dev)
		}
	}
	return out
}

// leaseDevice returns the ResourceSlice device of the lease device: no
// capacity, no node allocatable resources, any number of claims can
// allocate it.
func leaseDevice(name string) resourcev1.Device {
	return resourcev1.Device{
		Name: name,
		Attributes: map[resourcev1.QualifiedName]resourcev1.DeviceAttribute{
			device.AttrType: {StringValue: ptr(device.DeviceTypeLease)},
		},
		AllowMultipleAllocations: ptr(true),
	}
}

// memoryCapacity returns the memory capacity of a device of size bytes.
func memoryCapacity(size uint64) map[resourcev1.QualifiedName]resourcev1.DeviceCapacity {
	return map[resourcev1.QualifiedName]resourcev1.DeviceCapacity{
		device.CapacityMemory: {Value: *resource.NewQuantity(int64(size), resource.BinarySI)},
	}
}

// regionDevice returns the ResourceSlice device of a region.
func regionDevice(name string, dev *Region) resourcev1.Device {
	attrs := map[resourcev1.QualifiedName]resourcev1.DeviceAttribute{
		device.AttrType:   {StringValue: ptr(device.DeviceTypeRegion)},
		device.AttrSource: {StringValue: ptr(api.SourceLocal)},
		device.AttrNode:   {IntValue: ptr(int64(dev.NumaNode))},
		device.AttrSize:   {IntValue: ptr(int64(dev.Size))},
	}
	if a, ok := regionNodeAffinity(dev); ok {
		attrs[device.AttrNodeAffinity] = resourcev1.DeviceAttribute{IntValue: ptr(int64(a))}
	}
	return resourcev1.Device{
		Name:                     name,
		Attributes:               attrs,
		Capacity:                 memoryCapacity(dev.Size),
		NodeAllocatableResources: MemoryNodeAllocatableResources(),
		AllowMultipleAllocations: ptr(true),
	}
}

// regionNodeAffinity returns the CPU NUMA node of the memdevs of a region,
// and whether they all have the same known one.
func regionNodeAffinity(dev *Region) (int, bool) {
	affinity := -1
	for _, a := range dev.NodeAffinity {
		switch {
		case a < 0:
			return -1, false
		case affinity < 0:
			affinity = a
		case a != affinity:
			return -1, false
		}
	}
	return affinity, affinity >= 0
}

// dramDevice returns the ResourceSlice device of the DRAM of the node.
func dramDevice(name string, dev *DRAM) resourcev1.Device {
	return resourcev1.Device{
		Name: name,
		Attributes: map[resourcev1.QualifiedName]resourcev1.DeviceAttribute{
			device.AttrType:   {StringValue: ptr(device.DeviceTypeDRAM)},
			device.AttrSource: {StringValue: ptr(api.SourceLocal)},
			device.AttrNodes:  {StringValue: ptr(cpuset.New(dev.Nodes...).String())},
			device.AttrSize:   {IntValue: ptr(int64(dev.Size))},
		},
		Capacity:                 memoryCapacity(dev.Size),
		NodeAllocatableResources: MemoryNodeAllocatableResources(),
		AllowMultipleAllocations: ptr(true),
	}
}

// LocalMemdevDevice returns the ResourceSlice device of a local memdev.
func LocalMemdevDevice(name string, dev *Memdev) resourcev1.Device {
	if dev.Persistent || dev.Shared {
		return sharedMemdevDevice(name, dev)
	}
	attrs := map[resourcev1.QualifiedName]resourcev1.DeviceAttribute{
		device.AttrType:       {StringValue: ptr(device.DeviceTypeMemdev)},
		device.AttrSource:     {StringValue: ptr(api.SourceLocal)},
		device.AttrSerial:     {StringValue: ptr(api.FormatSerial(dev.Serial))},
		device.AttrShared:     {BoolValue: ptr(false)},
		device.AttrPersistent: {BoolValue: ptr(false)},
		device.AttrSize:       {IntValue: ptr(int64(dev.Size))},
		// every slice is a multiple of the memory block size
		device.AttrMemoryBlockSize: {IntValue: ptr(int64(dev.BlockSize))},
	}
	if dev.NodeAffinity >= 0 {
		attrs[device.AttrNodeAffinity] = resourcev1.DeviceAttribute{IntValue: ptr(int64(dev.NodeAffinity))}
	}
	return resourcev1.Device{
		Name:       name,
		Attributes: attrs,
		Capacity: map[resourcev1.QualifiedName]resourcev1.DeviceCapacity{
			device.CapacityMemory: {
				// the whole memory blocks that the region is sure to hold
				Value:         *resource.NewQuantity(int64(LocalUsableSize(dev.Size, dev.BlockSize)), resource.BinarySI),
				RequestPolicy: LocalRequestPolicy(dev.Size, dev.BlockSize),
			},
		},
		NodeAllocatableResources: MemoryNodeAllocatableResources(),
		AllowMultipleAllocations: ptr(true),
	}
}

// sharedMemdevDevice returns the ResourceSlice device of a shared or a
// persistent local memdev: a shares capacity without a request policy, so
// that a claim that requests no shares has the device exclusively; no
// memory capacity and nothing node allocatable, as its memory is never
// onlined.
func sharedMemdevDevice(name string, dev *Memdev) resourcev1.Device {
	attrs := map[resourcev1.QualifiedName]resourcev1.DeviceAttribute{
		device.AttrType:       {StringValue: ptr(device.DeviceTypeMemdev)},
		device.AttrSource:     {StringValue: ptr(api.SourceLocal)},
		device.AttrSerial:     {StringValue: ptr(api.FormatSerial(dev.Serial))},
		device.AttrShared:     {BoolValue: ptr(dev.Shared)},
		device.AttrPersistent: {BoolValue: ptr(dev.Persistent)},
		device.AttrSize:       {IntValue: ptr(int64(dev.Size))},
	}
	if dev.NodeAffinity >= 0 {
		attrs[device.AttrNodeAffinity] = resourcev1.DeviceAttribute{IntValue: ptr(int64(dev.NodeAffinity))}
	}
	return resourcev1.Device{
		Name:       name,
		Attributes: attrs,
		Capacity: map[resourcev1.QualifiedName]resourcev1.DeviceCapacity{
			device.CapacityShares: {Value: *resource.NewQuantity(device.SharesUnlimited, resource.DecimalSI)},
		},
		AllowMultipleAllocations: ptr(true),
	}
}

// LocalRequestPolicy returns the memory capacity request policy of a local
// memdev of size bytes with memory blocks of bs bytes: a request is rounded
// up to a multiple of bs, and a request without an amount gets the whole
// blocks that the region is sure to hold (LocalUsableSize). A memdev of one
// such block has it as the only valid amount. Nil for a memdev without one.
func LocalRequestPolicy(size, bs uint64) *resourcev1.CapacityRequestPolicy {
	usable := LocalUsableSize(size, bs)
	if usable == 0 {
		return nil
	}
	whole := resource.NewQuantity(int64(usable), resource.BinarySI)
	if usable < 2*bs {
		// a range needs room for its min and one step
		return &resourcev1.CapacityRequestPolicy{Default: whole, ValidValues: []resource.Quantity{*whole}}
	}
	return &resourcev1.CapacityRequestPolicy{
		Default: whole,
		ValidRange: &resourcev1.CapacityRequestPolicyRange{
			Min:  resource.NewQuantity(int64(bs), resource.BinarySI),
			Step: resource.NewQuantity(int64(bs), resource.BinarySI),
		},
	}
}

// MemoryNodeAllocatableResources maps the memory capacity that a claim
// consumes from a device to the node allocatable "memory" resource, so that
// kubelet accounts claimed memory in the pod and container cgroups. Memory
// capacity (device and node) is in bytes, hence capacityMultiplier is 1.
//
// Requires DRANodeAllocatableResources feature gate. Without it the
// apiserver drops the field from published ResourceSlices, and the
// publisher logs a warning once and publishes the devices without it.
func MemoryNodeAllocatableResources() map[v1.ResourceName]resourcev1.NodeAllocatableResource {
	return map[v1.ResourceName]resourcev1.NodeAllocatableResource{
		v1.ResourceMemory: {
			Mapping: &resourcev1.NodeAllocatableMapping{
				CapacityKey:        ptr(device.CapacityMemory),
				CapacityMultiplier: ptr(resource.MustParse("1")),
			},
		},
	}
}
