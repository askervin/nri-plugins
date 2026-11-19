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
	"slices"
	"sync"
	"sync/atomic"
	"time"

	coreclientset "k8s.io/client-go/kubernetes"
	"k8s.io/dynamic-resource-allocation/resourceslice"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/provenance"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
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
// Transitions: a scan (at the start, then on udev events, the watch's
// ticks and after the Prepares and Unprepares that changed the records,
// one at a time from the list of the pool slices to the publish) sets the
// table; the generation grows when its devices change. A publish of an
// unchanged table writes nothing to the API server.
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

	// mu guards the fields below up to triggerMu: a leaf lock.
	mu      sync.Mutex
	devices DevicesInfo
	// published is the table of the last publication, nil before the
	// first.
	published  DevicesInfo
	generation uint64
	names      []string
	slices     *nodeResourceSlices // nil before Start

	// triggerMu guards the fields below: a leaf lock.
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
	// Scan returns an observation of the kernel objects of the node.
	Scan func(ctx context.Context) (*kernel.Snapshot, error)
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
	return &Publisher{opts: opts, devices: DevicesInfo{}, trigger: make(chan struct{}, 1)}, nil
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
func (p *Publisher) Published() DevicesInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.published == nil {
		return p.devices
	}
	return p.published
}

// Devices returns the devices of the last scan, by name.
func (p *Publisher) Devices() DevicesInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.devices
}

// SetDevices sets the devices of the table, as a scan does.
func (p *Publisher) SetDevices(devs DevicesInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.setLocked(devs)
}

// setLocked sets the devices of the table and counts a change of them.
// Called with p.mu held.
func (p *Publisher) setLocked(devs DevicesInfo) {
	names := slices.Sorted(maps.Keys(devs))
	if !slices.Equal(names, p.names) || !sameDevices(p.devices, devs) {
		p.generation++
	}
	p.devices, p.names = devs, names
}

// sameDevices tells whether two tables publish the same devices.
func sameDevices(a, b DevicesInfo) bool {
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
func (p *Publisher) resourcesOf(devs DevicesInfo) resourceslice.DriverResources {
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
func (p *Publisher) scan(ctx context.Context) (DevicesInfo, error) {
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
func (p *Publisher) scanWith(ctx context.Context, cfg PublishConfig, poolSerials map[uint64]bool) (DevicesInfo, error) {
	snap, err := p.opts.Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to detect devices: %v", err)
	}
	local := p.LocalSnapshot()
	poolSerials, held := p.opts.Watcher.Gate(ctx, snap, poolSerials, local.claims())
	if len(snap.Regions) == 0 {
		klog.Info("No region devices detected")
	}
	hollowRegions.observe(snap.Regions, p.ours())
	return BuildDevices(cfg, snap, poolSerials, held, local), nil
}

// ours returns whether the records have the region with the name as one
// of the device engine.
func (p *Publisher) ours() func(name string) bool {
	r := &p.opts.Store.Snapshot().Records
	return func(name string) bool {
		reg := r.Region(state.RegionRef(name))
		return reg != nil && reg.Ours()
	}
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
