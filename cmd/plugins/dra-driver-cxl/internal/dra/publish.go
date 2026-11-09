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
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	v1 "k8s.io/api/core/v1"
	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	coreclientset "k8s.io/client-go/kubernetes"
	"k8s.io/dynamic-resource-allocation/resourceslice"
	"k8s.io/klog/v2"
	"k8s.io/utils/cpuset"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/provenance"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

// Publisher publishes the ResourceSlice of the node of cxl.nri.io: one pool
// named after the node, one slice, owner the Node.
//
// Identity: one per process, of the node.
//
// States: the table, the devices of the last scan with a generation that
// counts its changes; not started (the scans set the table, nothing is
// published) and started (every scan is published).
//
// Transitions: a scan (at the start, then on udev events and the watch's
// ticks, one at a time from the list of the pool slices to the publish)
// sets the table; the generation grows when its devices change.
//
// Invariants: a pool device and a HELD memdev are never published as local
// ones; the devices are sorted by name, so their order is not a change; no
// local memdev is published before a list of the pool slices succeeded.
//
// Persistence: none; the table is derived from the kernel, the provenance
// records and the records of the local memdevs.
//
// Locks and waits: scanMu serializes the scans (it is held across the lists
// of the API server, bounded); mu guards the table, never held across a
// scan or a publish.
type Publisher struct {
	opts PublishOptions

	scanMu  sync.Mutex
	scanned atomic.Int64

	mu      sync.Mutex
	devices device.DevicesInfo
	// published is the table of the last publication, nil before the
	// first.
	published  device.DevicesInfo
	generation uint64
	names      []string
	slices     *nodeResourceSlices // nil before Start

	triggerMu     sync.Mutex
	pending       bool // a scan is asked for
	pendingUrgent bool // a scan that is not periodic is asked for
	trigger       chan struct{}
	stopped       bool
}

// PublishOptions are the settings of a Publisher.
type PublishOptions struct {
	// Config are the settings of the configuration of the driver.
	Config PublishConfig
	// NodeName is the node of the slice; Client publishes it, OnError gets
	// the errors of publishing (marked recoverable).
	NodeName string
	Client   coreclientset.Interface
	OnError  func(ctx context.Context, err error, msg string)
	// Scan returns the devices of the node.
	Scan func() (*nricxl.Devices, error)
	// Watcher knows the provenance of the memdevs, nil for no pool.
	Watcher *provenance.Watcher
	// PoolSerials returns the serials of the pool driver's devices, nil
	// without a pool driver.
	PoolSerials func() map[uint64]bool
	// Store has the records of the local memdevs; Probes returns the
	// results of the address line probes, BlockSize the memory block size.
	Store     *store.Store
	Probes    func() map[state.Serial]state.Probe
	BlockSize func() (uint64, error)
}

// PublishConfig are the settings of the configuration of the driver that
// the publisher applies.
type PublishConfig struct {
	// IgnoreDevices are memdevs that are never published (name, uevent
	// device name, <major>:<minor>, serial); SharedDevices the local memdevs
	// published as shared devices.
	IgnoreDevices, SharedDevices []string
	// IgnoreRegions and IgnoreNodes are regions and NUMA nodes that are not
	// published.
	IgnoreRegions []string
	IgnoreNodes   []int
	// IgnoreDRAMNodes: the DRAM of the node is not published.
	IgnoreDRAMNodes bool
	// ManageMemdevs: the local memdevs are published.
	ManageMemdevs bool
	// PublishLeaseDevice: the lease device is published.
	PublishLeaseDevice bool
	// UsableSize returns the configured usable size of a memdev, 0 for all
	// of it.
	UsableSize func(memdev string, serial uint64) uint64
}

// usableSize returns the configured usable size of a memdev.
func (c *PublishConfig) usableSize(memdev string, serial uint64) uint64 {
	if c.UsableSize == nil {
		return 0
	}
	return c.UsableSize(memdev, serial)
}

// NewPublisher returns the publisher of the node's ResourceSlice of the
// scans of opts.Scan and the records of opts.Store; it publishes after
// Start.
func NewPublisher(opts PublishOptions) (*Publisher, error) {
	if opts.Store == nil || opts.Scan == nil {
		return nil, errors.New("the publisher needs the state store and the scan of the devices")
	}
	return &Publisher{opts: opts, devices: device.DevicesInfo{}, trigger: make(chan struct{}, 1)}, nil
}

// SetConfig sets the configuration of the next scans.
func (p *Publisher) SetConfig(cfg PublishConfig) {
	p.scanMu.Lock()
	defer p.scanMu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.opts.Config = cfg
}

// config returns the configuration of the scans.
func (p *Publisher) config() PublishConfig {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.opts.Config
}

// SetOnError sets the handler of the errors of publishing (marked
// recoverable); it takes effect at Start.
func (p *Publisher) SetOnError(onError func(ctx context.Context, err error, msg string)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.opts.OnError = onError
}

// Published returns the devices of the last publication, by name, those of
// the last scan before the first publication.
func (p *Publisher) Published() device.DevicesInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.published == nil {
		return p.devices
	}
	return p.published
}

// Devices returns the devices of the last scan, by name.
func (p *Publisher) Devices() device.DevicesInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.devices
}

// SetDevices sets the devices of the table, as a scan does.
func (p *Publisher) SetDevices(devs device.DevicesInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.setLocked(devs)
}

// setLocked sets the devices of the table and counts a change of them.
// Called with p.mu held.
func (p *Publisher) setLocked(devs device.DevicesInfo) {
	names := slices.Sorted(maps.Keys(devs))
	if !slices.Equal(names, p.names) || !sameDevices(p.devices, devs) {
		p.generation++
	}
	p.devices, p.names = devs, names
}

// sameDevices tells whether two tables publish the same devices.
func sameDevices(a, b device.DevicesInfo) bool {
	if len(a) != len(b) {
		return false
	}
	ra, rb := resources(a), resources(b)
	return equalDevices(ra, rb)
}

// Generation returns the generation of the table: it grows with every
// change of its devices.
func (p *Publisher) Generation() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.generation
}

// LastScan returns the time of the last scan, or of the start.
func (p *Publisher) LastScan() time.Time {
	return time.Unix(0, p.scanned.Load())
}

// Resources returns the resources of the node's ResourceSlice: the devices
// of the table, sorted by name.
func (p *Publisher) Resources() resourceslice.DriverResources {
	p.mu.Lock()
	devs := p.devices
	p.mu.Unlock()
	return p.resourcesOf(devs)
}

// resourcesOf returns the resources of the node's ResourceSlice of the
// devices of a table, sorted by name.
func (p *Publisher) resourcesOf(devs device.DevicesInfo) resourceslice.DriverResources {
	return resourceslice.DriverResources{
		Pools: map[string]resourceslice.Pool{
			p.opts.NodeName: {Slices: []resourceslice.Slice{{Devices: resources(devs)}}},
		},
	}
}

// Scan scans the node and sets the table, without publishing it.
func (p *Publisher) Scan(ctx context.Context) error {
	p.scanMu.Lock()
	defer p.scanMu.Unlock()
	defer p.scanned.Store(time.Now().UnixNano())
	devs, err := p.scan(ctx)
	if err != nil {
		return err
	}
	p.SetDevices(devs)
	return nil
}

// Start starts publishing: the first publish of the table, then the
// publisher goroutine, which scans and publishes when Trigger asks for it,
// until ctx ends or Stop.
func (p *Publisher) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.slices == nil {
		p.slices = newNodeResourceSlices(p.opts.Client, p.opts.NodeName, p.opts.OnError)
	}
	p.mu.Unlock()
	if err := p.publish(ctx); err != nil {
		return fmt.Errorf("startup error: %v", err)
	}
	p.scanned.Store(time.Now().UnixNano())
	go p.run(ctx)
	return nil
}

// Stop stops the publisher goroutine and the ResourceSlice controller. The
// published slice stays. Nothing for a nil publisher.
func (p *Publisher) Stop() {
	if p == nil {
		return
	}
	p.triggerMu.Lock()
	if !p.stopped {
		p.stopped = true
		close(p.trigger)
	}
	p.triggerMu.Unlock()
	p.mu.Lock()
	s := p.slices
	p.mu.Unlock()
	s.stop()
}

// Trigger asks the publisher goroutine for a scan and a publish; a periodic
// one logs at klog V(4) unless it changed the devices. A scan that is asked
// for already covers it.
func (p *Publisher) Trigger(_ context.Context, periodic bool) {
	p.triggerMu.Lock()
	defer p.triggerMu.Unlock()
	if p.stopped {
		return
	}
	p.pending = true
	p.pendingUrgent = p.pendingUrgent || !periodic
	select {
	case p.trigger <- struct{}{}:
	default:
	}
}

// run scans and publishes at every trigger until ctx ends or Stop.
func (p *Publisher) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-p.trigger:
			if !ok {
				return
			}
			p.triggerMu.Lock()
			pending, urgent := p.pending, p.pendingUrgent
			p.pending, p.pendingUrgent = false, false
			p.triggerMu.Unlock()
			if pending {
				p.Rescan(ctx, !urgent)
			}
		}
	}
}

// Rescan scans the node, sets the table and publishes it when the
// publisher runs; a periodic one logs at klog V(4) unless it changed the
// devices. A failed scan keeps the table.
func (p *Publisher) Rescan(ctx context.Context, periodic bool) {
	p.scanMu.Lock()
	defer p.scanMu.Unlock()
	defer p.scanned.Store(time.Now().UnixNano())
	logf := klog.Infof
	if periodic {
		logf = klog.V(4).Infof
	}
	logf("rescanAndPublish: rescanning devices")
	devs, err := p.scan(ctx)
	if err != nil {
		klog.Errorf("rescanAndPublish: %v", err)
		return
	}
	p.mu.Lock()
	old := p.names
	p.setLocked(devs)
	changed := !slices.Equal(old, p.names)
	started := p.slices != nil
	p.mu.Unlock()
	if periodic && changed {
		logf = klog.Infof
		logf("rescanAndPublish: the periodic rescan changed the devices")
	}
	if !started {
		return
	}
	if err := p.publish(ctx); err != nil {
		klog.Errorf("rescanAndPublish: failed to publish resources: %v", err)
		return
	}
	logf("rescanAndPublish: published updated resources (%d devices)", len(devs))
}

// publish publishes the table.
func (p *Publisher) publish(ctx context.Context) error {
	p.mu.Lock()
	table := p.devices
	p.mu.Unlock()
	res := p.resourcesOf(table)
	devs := res.Pools[p.opts.NodeName].Slices[0].Devices
	for i := range devs {
		klog.V(5).Infof("Processing allocatable device %v: %+v", devs[i].Name, devs[i])
	}
	klog.FromContext(ctx).Info("Publishing resources", "len", len(devs))
	klog.V(5).Infof("devices: %+v", devs)
	p.mu.Lock()
	s := p.slices
	p.mu.Unlock()
	if err := s.publish(ctx, res); err != nil {
		return fmt.Errorf("error publishing resources: %v", err)
	}
	p.mu.Lock()
	p.published = table
	p.mu.Unlock()
	return nil
}

// scan returns the devices to publish of a scan of the node: the serials of
// the pool driver's devices and of the pool slices noted, the memdevs held
// or remembered as pool devices left out.
func (p *Publisher) scan(ctx context.Context) (device.DevicesInfo, error) {
	cfg, poolSerials := p.ScanInput(ctx)
	return p.scanWith(ctx, cfg, poolSerials)
}

// ScanWith scans the node with the configuration and the pool serials of
// ScanInput and sets the table, without publishing it.
func (p *Publisher) ScanWith(ctx context.Context, cfg PublishConfig, poolSerials map[uint64]bool) error {
	p.scanMu.Lock()
	defer p.scanMu.Unlock()
	defer p.scanned.Store(time.Now().UnixNano())
	devs, err := p.scanWith(ctx, cfg, poolSerials)
	if err != nil {
		return err
	}
	p.SetDevices(devs)
	return nil
}

// scanWith returns the devices to publish of a scan of the node with the
// configuration and the pool serials of ScanInput.
func (p *Publisher) scanWith(ctx context.Context, cfg PublishConfig, poolSerials map[uint64]bool) (device.DevicesInfo, error) {
	detected, err := p.opts.Scan()
	if err != nil {
		return nil, fmt.Errorf("failed to detect devices: %v", err)
	}
	local := p.LocalSnapshot()
	poolSerials, held := p.opts.Watcher.Gate(ctx, detected, poolSerials, local.claims())
	if len(detected.RegionDevices) == 0 {
		klog.Info("No region devices detected")
	}
	return BuildDevices(cfg, detected, poolSerials, held, local), nil
}

// ScanInput returns the configuration and the pool serials of a scan: the
// serials of the memdevs that the pool driver prepares, of the devices that
// pool controllers publish, and the remembered pool serials. While the
// devices of the pool controllers are not known, the configuration
// publishes no local memdevs.
func (p *Publisher) ScanInput(ctx context.Context) (PublishConfig, map[uint64]bool) {
	serials := map[uint64]bool{}
	if p.opts.PoolSerials != nil {
		maps.Copy(serials, p.opts.PoolSerials())
	}
	w := p.opts.Watcher
	w.NotePrepared(serials)
	remote, known := w.Serials(ctx)
	for s := range remote {
		serials[s] = true
	}
	cfg := p.config()
	if known || !cfg.ManageMemdevs {
		return cfg, serials
	}
	klog.Warning("not publishing local memory devices: the devices of the pool controllers are not known")
	cfg.ManageMemdevs = false
	return cfg, serials
}

// LocalSnapshot returns the uses of the local memdevs that the records
// have, the memory block size and the probed usable sizes; nil when the
// local memdevs are not managed.
func (p *Publisher) LocalSnapshot() *LocalSnapshot {
	if !p.config().ManageMemdevs {
		return nil
	}
	snap := &LocalSnapshot{Uses: map[uint64]LocalUse{}, Probed: map[uint64]uint64{}}
	r := &p.opts.Store.Snapshot().Records
	for i := range r.Memdevs {
		m := &r.Memdevs[i]
		if m.Source != state.SourceLocal {
			continue
		}
		u := LocalUse{Shared: m.Facts.Shared, Persistent: m.Facts.Persistent, Claims: []string{}}
		for _, ref := range m.Grants {
			if !slices.Contains(u.Claims, ref.Claim) {
				u.Claims = append(u.Claims, ref.Claim)
			}
		}
		slices.Sort(u.Claims)
		snap.Uses[uint64(m.Serial)] = u
	}
	if p.opts.Probes != nil {
		for serial, pr := range p.opts.Probes() {
			snap.Probed[uint64(serial)] = pr.UsableSize
		}
	}
	if p.opts.BlockSize != nil {
		snap.BlockSize, _ = p.opts.BlockSize()
	}
	return snap
}

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

// CXLRegionAlign is the alignment of the physical address of a CXL region
// in its window: a region starts at most block size - CXLRegionAlign after
// a memory block boundary.
const CXLRegionAlign = 256 << 20

// LocalUsableSize returns the bytes of whole memory blocks of bs bytes that
// a region on a memdev of size bytes is sure to hold, wherever in its
// window it starts.
func LocalUsableSize(size, bs uint64) uint64 {
	if bs == 0 {
		return 0
	}
	if bs > CXLRegionAlign {
		head := bs - CXLRegionAlign
		if size <= head {
			return 0
		}
		size -= head
	}
	return size / bs * bs
}

// hollowRegions are the hollow regions of the last scan, warned about.
var hollowRegions = &hollowRegionLog{warned: map[string]bool{}}

// hollowRegionLog warns once about each hollow region of the scans.
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
	mu     sync.Mutex
	warned map[string]bool // sysfs path and resource of a hollow region
}

// observe returns the hollow regions among regions (pkg/cxl
// RegionDevice.Hollow, kernel.RegionHollow), and logs a warning for each one
// that the last scan did not have: no decoder maps its address range any
// more (memory of it that kmem could not remove stays online until a
// reboot, which is why such a region may still have a node), it holds that
// range in its root decoder, and cxl destroy-region cannot remove it. The
// device engine deletes such a region that it knows as its own; others are
// only reported, with the command that removes them.
func (h *hollowRegionLog) observe(regions []*nricxl.RegionDevice) map[*nricxl.RegionDevice]bool {
	out := map[*nricxl.RegionDevice]bool{}
	seen := map[string]bool{}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range regions {
		if !r.Hollow {
			continue
		}
		out[r] = true
		key := fmt.Sprintf("%s@%#x", r.SysfsPath, r.Resource)
		seen[key] = true
		if h.warned[key] {
			continue
		}
		decoder := "<its root decoder>"
		if real, err := filepath.EvalSymlinks(r.SysfsPath); err == nil {
			decoder = filepath.Base(filepath.Dir(real))
		}
		klog.Warningf("CXL region %s (mode %s, resource %#x, size %#x) has no target decoder: it is not published. It is left behind when its memory device was removed before the region was destroyed (or is being created right now). No decoder maps its address range, which it holds; cxl destroy-region cannot remove it. If it stays and none of its memory blocks is online: echo %s > /sys/bus/cxl/devices/%s/delete_region",
			r.Name, r.Mode, r.Resource, r.Size, r.Name, decoder)
	}
	h.warned = seen
	return out
}

// BuildDevices returns the devices to publish of the detected devices, by
// device name. poolSerials are the serials of pool devices (prepared by the
// pool driver, published by a pool controller, or remembered as such): their
// regions are skipped, and they are never local memdevs; held are the
// serials of new memdevs that are held as possible pool devices: like pool
// devices, neither they nor their regions are published. Regions on memdevs
// that the device engine uses (local) are skipped too: the engine created
// them, and the memdevs are published as memdev devices.
func BuildDevices(cfg PublishConfig, detected *nricxl.Devices, poolSerials, held map[uint64]bool, local *LocalSnapshot) device.DevicesInfo {
	cxlNodes := make(map[int]bool)
	devInfos := make(map[string]*device.DeviceInfo)
	hollow := hollowRegions.observe(detected.RegionDevices)
	for _, regDev := range detected.RegionDevices {
		klog.V(3).Infof("discovered CXL region device: %+v", regDev)
		if hollow[regDev] {
			// its memory that kmem could not remove is not DRAM
			cxlNodes[regDev.Node] = true
			klog.V(4).Infof("- ignoring region device %q: it has no target decoder", regDev.Name)
			continue
		}
		cxlNodes[regDev.Node] = true
		if reason := regionIgnoreReason(cfg, regDev, poolSerials, held, local); reason != "" {
			klog.V(4).Infof("- ignoring region device %q: %s", regDev.Name, reason)
			continue
		}
		name := regionDeviceName(regDev)
		devInfos[name] = &device.DeviceInfo{
			Name:      name,
			Dev:       any(regDev),
			SysfsPath: regDev.SysfsPath,
		}
	}
	if cfg.ManageMemdevs {
		addLocalMemdevs(devInfos, cfg, detected, poolSerials, held, local)
	}
	if !cfg.IgnoreDRAMNodes {
		addDRAM(devInfos, cfg, detected, cxlNodes)
	}
	if cfg.PublishLeaseDevice {
		devInfos[device.LeaseDeviceName] = &device.DeviceInfo{
			Name: device.LeaseDeviceName,
			Dev:  &device.LeaseToken{},
		}
	}
	return devInfos
}

// regionIgnoreReason returns why a region that is not hollow is not
// published, "" if it is: on a pool or held memdev, on a memdev of the
// engine, disabled, of persistent memory, in ignoreRegions, on a node of
// ignoreNodes, with a memdev of ignoreDevices; the first reason only.
func regionIgnoreReason(cfg PublishConfig, regDev *nricxl.RegionDevice, poolSerials, held map[uint64]bool, local *LocalSnapshot) string {
	reason := poolIgnoreReason(regDev, poolSerials, held)
	if reason == "" {
		reason = localIgnoreReason(regDev, local)
	}
	if !regDev.Enabled {
		reason = "region is disabled"
	}
	if reason == "" && regDev.Mode == kernel.RegionPmem {
		reason = "region of persistent memory"
	}
	if reason != "" {
		return reason
	}
	if slices.Contains(cfg.IgnoreRegions, regDev.Name) {
		return fmt.Sprintf("region name %q", regDev.Name)
	}
	if slices.Contains(cfg.IgnoreNodes, regDev.Node) {
		return fmt.Sprintf("region is on node %d", regDev.Node)
	}
	for _, memDev := range regDev.Memories {
		if r := memdevMatches(cfg.IgnoreDevices, memDev); r != "" {
			return "region has a " + r
		}
	}
	return ""
}

// addDRAM adds the DRAM device of the memory nodes that are not CXL nodes
// to devInfos.
func addDRAM(devInfos device.DevicesInfo, cfg PublishConfig, detected *nricxl.Devices, cxlNodes map[int]bool) {
	dramDev := &device.DRAM{}
	for _, node := range detected.MemoryNodes {
		if cxlNodes[node.ID] {
			continue
		}
		ignoreReason := ""
		switch {
		case node.Size == 0:
			ignoreReason = "node has 0 size"
		case slices.Contains(cfg.IgnoreNodes, node.ID):
			ignoreReason = fmt.Sprintf("node ID %d is in ignoreNodes", node.ID)
		}
		if ignoreReason != "" {
			klog.V(4).Infof("- ignoring DRAM on node %d: %s", node.ID, ignoreReason)
			continue
		}
		dramDev.Nodes = append(dramDev.Nodes, node.ID)
		dramDev.Size += node.Size
		klog.V(4).Infof("discovered DRAM memory on node %d: size %d bytes", node.ID, node.Size)
	}
	if dramDev.Size > 0 {
		devInfos[device.DRAMDeviceName] = &device.DeviceInfo{
			Name: device.DRAMDeviceName,
			Dev:  any(dramDev),
		}
		klog.V(3).Infof("discovered system DRAM device: %+v", dramDev)
	}
}

// regionDeviceName returns the device name of a region: <region>-node<N>.
func regionDeviceName(regDev *nricxl.RegionDevice) string {
	return fmt.Sprintf("%s-node%d", regDev.Name, regDev.Node)
}

// poolIgnoreReason returns why a region on a pool device or on a memdev
// that is held is not published, "" if it is on neither.
func poolIgnoreReason(regDev *nricxl.RegionDevice, poolSerials, held map[uint64]bool) string {
	for _, memDev := range regDev.Memories {
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

// localIgnoreReason returns why a region on a local memdev that the engine
// uses is not published, "" if it is not on one.
func localIgnoreReason(regDev *nricxl.RegionDevice, local *LocalSnapshot) string {
	for _, memDev := range regDev.Memories {
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
func memdevMatches(specs []string, memDev *nricxl.MemoryDevice) string {
	for _, spec := range specs {
		switch spec {
		case memDev.Name:
			return fmt.Sprintf("memory device name %q", spec)
		case memDev.DevName:
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
func sharedListing(cfg PublishConfig, memDev *nricxl.MemoryDevice, poolSerials, held map[uint64]bool) (bool, string) {
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
func SharedSerials(cfg PublishConfig, memDevs []*nricxl.MemoryDevice, poolSerials map[uint64]bool) map[uint64]bool {
	out := map[uint64]bool{}
	for _, memDev := range memDevs {
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
func logSharedRefusal(memDev *nricxl.MemoryDevice, reason string) {
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
func addLocalMemdevs(devInfos device.DevicesInfo, cfg PublishConfig, detected *nricxl.Devices, poolSerials, held map[uint64]bool, local *LocalSnapshot) {
	bs := uint64(0)
	if local != nil {
		bs = local.BlockSize
	}
	regions := map[uint64][]string{}
	for _, regDev := range detected.RegionDevices {
		for _, memDev := range regDev.Memories {
			regions[memDev.Serial] = append(regions[memDev.Serial], regDev.Name)
		}
	}
	for _, memDev := range detected.MemoryDevices {
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
		devInfos[name] = &device.DeviceInfo{
			Name: name,
			Dev: &device.Memdev{
				Name:         memDev.Name,
				Serial:       memDev.Serial,
				Size:         size,
				NodeAffinity: memDev.NodeAffinity,
				BlockSize:    bs,
			},
			SysfsPath: memDev.SysfsPath,
		}
		klog.V(3).Infof("discovered local memory device %s: %s serial 0x%x size %d (RAM capacity %d) memory block size %d", name, memDev.Name, memDev.Serial, size, memDev.RamSize, bs)
	}
}

// partsRefusal returns why a memdev of usable size bytes with memory
// blocks of bs bytes is not published as a sliced local memdev, "" if it
// is: no RAM, an unknown block size, too small, disabled, a pool or held
// memdev, regions that the engine did not create, claims that use it
// persistent or shared, ignoreDevices.
func partsRefusal(cfg PublishConfig, memDev *nricxl.MemoryDevice, size, bs uint64, poolSerials, held map[uint64]bool, regions []string, local *LocalSnapshot) string {
	use, used := local.Use(memDev.Serial)
	switch {
	case memDev.RamSize == 0:
		return "no RAM capacity"
	case bs == 0:
		return "the memory block size is unknown"
	case LocalUsableSize(size, bs) == 0:
		return fmt.Sprintf("usable RAM capacity %d is not sure to hold a whole memory block of %d bytes", size, bs)
	case !memDev.Enabled:
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
func memdevUsableSize(cfg PublishConfig, memDev *nricxl.MemoryDevice, local *LocalSnapshot) uint64 {
	size := memDev.RamSize
	for _, limit := range []uint64{cfg.usableSize(memDev.Name, memDev.Serial), local.ProbedSize(memDev.Serial)} {
		if limit > 0 && limit < size {
			size = limit / CXLRegionAlign * CXLRegionAlign
		}
	}
	return size
}

// addSharedMemdev adds a memdev of sharedDevices to devInfos as a shared
// local device, unless it is disabled, has no RAM capacity, has regions that
// the engine did not create or claims that use it as slices.
//   - regions: the regions on the memdev
//   - bs: the memory block size, 0 if unknown
func addSharedMemdev(devInfos device.DevicesInfo, memDev *nricxl.MemoryDevice, size uint64, regions []string, local *LocalSnapshot, bs uint64) {
	use, used := local.Use(memDev.Serial)
	reason := ""
	switch {
	case memDev.RamSize == 0:
		reason = "no RAM capacity"
	case !memDev.Enabled:
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
	devInfos[name] = &device.DeviceInfo{
		Name: name,
		Dev: &device.Memdev{
			Name:         memDev.Name,
			Serial:       memDev.Serial,
			Size:         size,
			NodeAffinity: memDev.NodeAffinity,
			BlockSize:    bs,
			Shared:       true,
		},
		SysfsPath: memDev.SysfsPath,
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
func addPersistentMemdev(devInfos device.DevicesInfo, cfg PublishConfig, memDev *nricxl.MemoryDevice, shared bool, poolSerials, held map[uint64]bool, regions []string, local *LocalSnapshot) {
	use, used := local.Use(memDev.Serial)
	reason := memdevMatches(cfg.IgnoreDevices, memDev)
	switch {
	case reason != "":
	case poolSerials[memDev.Serial]:
		reason = "pool device"
	case held[memDev.Serial]:
		reason = heldReason
	case !memDev.Enabled:
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
	devInfos[name] = &device.DeviceInfo{
		Name: name,
		Dev: &device.Memdev{
			Name:         memDev.Name,
			Serial:       memDev.Serial,
			Size:         memDev.PmemSize,
			NodeAffinity: memDev.NodeAffinity,
			Shared:       shared,
			Persistent:   true,
		},
		SysfsPath: memDev.SysfsPath,
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

// resources returns the devices of the node's ResourceSlice of the table,
// sorted by name.
func resources(devs device.DevicesInfo) []resourcev1.Device {
	out := []resourcev1.Device{}
	for _, name := range slices.Sorted(maps.Keys(devs)) {
		allocatable := devs[name]
		if allocatable.Dev == nil {
			continue
		}
		switch dev := allocatable.Dev.(type) {
		case *nricxl.RegionDevice:
			out = append(out, regionDevice(name, dev))
		case *device.DRAM:
			out = append(out, dramDevice(name, dev))
		case *device.Memdev:
			out = append(out, LocalMemdevDevice(name, dev))
		case *device.LeaseToken:
			out = append(out, leaseDevice(name))
		default:
			klog.Warningf("unexpected device type in state.Allocatable: %T", dev)
		}
	}
	return out
}

// equalDevices tells whether two lists of devices are the same.
func equalDevices(a, b []resourcev1.Device) bool {
	return resourceslice.DevicesDeepEqual(a, b)
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
func regionDevice(name string, dev *nricxl.RegionDevice) resourcev1.Device {
	attrs := map[resourcev1.QualifiedName]resourcev1.DeviceAttribute{
		device.AttrType:   {StringValue: ptr(device.DeviceTypeRegion)},
		device.AttrSource: {StringValue: ptr(api.SourceLocal)},
		device.AttrNode:   {IntValue: ptr(int64(dev.Node))},
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
func regionNodeAffinity(dev *nricxl.RegionDevice) (int, bool) {
	affinity := -1
	for _, mem := range dev.Memories {
		switch {
		case mem.NodeAffinity < 0:
			return -1, false
		case affinity < 0:
			affinity = mem.NodeAffinity
		case mem.NodeAffinity != affinity:
			return -1, false
		}
	}
	return affinity, affinity >= 0
}

// dramDevice returns the ResourceSlice device of the DRAM of the node.
func dramDevice(name string, dev *device.DRAM) resourcev1.Device {
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
func LocalMemdevDevice(name string, dev *device.Memdev) resourcev1.Device {
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
func sharedMemdevDevice(name string, dev *device.Memdev) resourcev1.Device {
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
// apiserver drops the field from published ResourceSlices and the driver
// logs "some fields were dropped by the apiserver".
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
