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
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/containers/nri-plugins/pkg/cgmpolmgr"

	cxlapi "github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"

	"k8s.io/klog/v2"
	"k8s.io/utils/cpuset"
)

// NRIOpts holds NRI plugin configuration from CLI flags.
type NRIOpts struct {
	Name   string
	Idx    string
	Socket string
}

// cgroupV2MountPoint is the default mount point for cgroup v2.
// TODO: make this configurable or auto-detect from /proc/mounts.
const cgroupV2MountPoint = "/sys/fs/cgroup"

// hasMemoryFile lists the NUMA nodes with memory, under the sysfs root.
const hasMemoryFile = "sys/devices/system/node/has_memory"

// pendingSteering is the memory steering of a container that has
// been created but not started yet.
type pendingSteering struct {
	name string
	plan *cgmpolmgr.Plan
	// unsteered is the management of the container if its steering does
	// not start (unsteeredMemory).
	unsteered string
}

// steeredFileName is the file of the steering record (steeredRecord) in
// the plugin data directory.
const steeredFileName = "steeredContainers.json"

// steeredRecord is the record of the containers whose cgroup a steering
// manager of the plugin writes: container ID -> the cgroup directory of
// the manager. An entry is added, and the file written, before the
// manager writes the cgroup, and removed when the manager has stopped. So
// the file of a process that was killed, or that exited on the loss of
// NRI, names the containers whose memory.high its managers left, and the
// restarted plugin releases exactly those (Synchronize, syncManagement),
// whatever their settings say now (the configuration may have changed
// across the restart), and leaves the memory.high of the others alone.
// Guarded by p.mu of the plugin.
type steeredRecord struct {
	// path is the file, "" for none (kept in memory only).
	path string
	// legacy: there was no record at start (the first start of a plugin
	// that keeps one, or a lost or unreadable file): Synchronize releases
	// the containers that their settings steer instead.
	legacy bool
	ids    map[string]string
}

// loadSteeredRecord returns the steering record of the file path.
func loadSteeredRecord(path string) steeredRecord {
	r := steeredRecord{path: path, ids: map[string]string{}}
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &r.ids)
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		klog.V(3).Infof("NRI: no steering record %s: releasing the containers that their settings steer", path)
		r.legacy = true
	case err != nil:
		klog.Warningf("NRI: steering record %s: %v: releasing the containers that their settings steer", path, err)
		r.legacy = true
		r.ids = map[string]string{}
	}
	return r
}

// add records that a manager steers the container id in the cgroup dir.
func (r *steeredRecord) add(id, dir string) {
	if r.ids == nil {
		r.ids = map[string]string{}
	}
	r.ids[id] = dir
	r.save()
}

// remove drops the containers ids from the record.
func (r *steeredRecord) remove(ids ...string) {
	changed := false
	for _, id := range ids {
		if _, ok := r.ids[id]; ok {
			delete(r.ids, id)
			changed = true
		}
	}
	if changed {
		r.save()
	}
}

// left returns the cgroup directory of the container id that a manager
// of a previous process steered, and whether there is one.
func (r *steeredRecord) left(id string) (string, bool) {
	dir, ok := r.ids[id]
	return dir, ok
}

// synced drops the containers that keep returns false for (that no
// manager of this process steers: Synchronize has released them, or they
// are gone) and writes the file, which is the record from now on.
func (r *steeredRecord) synced(keep func(id string) bool) {
	for id := range r.ids {
		if !keep(id) {
			delete(r.ids, id)
		}
	}
	r.legacy = false
	r.save()
}

// save writes the file of the record, if any.
func (r *steeredRecord) save() {
	if r.path == "" {
		return
	}
	ids := r.ids
	if ids == nil {
		ids = map[string]string{}
	}
	if err := writeJSONFile(r.path, ids); err != nil {
		klog.Warningf("NRI: steering record: %v", err)
	}
}

// The management of the memory of a container.
const (
	// memorySteered: cgmpolmgr steers the memory of the container.
	memorySteered = "steered"
	// memoryFenced: the container has cpuset.mems without the fenced
	// nodes that its results have no numa memory on and that are not lent
	// to it (wantMems, lend.go).
	memoryFenced = "fenced"
	// memoryNone: the memory nodes of the container are left as they are.
	memoryNone = "none"
)

// resultRef is an allocation result of a claim: the claim UID and the
// index of the result in the allocation of the claim.
type resultRef struct {
	uid string
	n   int
}

// containerResult is a prepared allocation result of either driver that a
// container uses.
type containerResult struct {
	// pool: a device of the pool driver.
	pool bool
	// deviceType is the device type of a result of cxl.nri.io.
	deviceType string
	mode       string
	nodes      []int
	// bytes is the memory of the result.
	bytes    int64
	settings config.ResultSettings
}

// numaCXL tells whether the result has CXL memory in mode numa: a numa
// slice of a local memdev, a region or a pool device in mode numa.
func (r *containerResult) numaCXL() bool {
	return r.mode == cxlapi.ModeNUMA && (r.pool || r.deviceType == device.DeviceTypeMemdev || r.deviceType == device.DeviceTypeRegion)
}

// management is how the NRI plugin manages the memory of a container.
type management struct {
	// memory is memorySteered, memoryFenced or memoryNone.
	memory string
	// eff are the effective container settings.
	eff *config.Effective
	// claimed are the NUMA nodes of the CXL numa memory of the results.
	claimed cpuset.CPUSet
	// plan is the steering plan of a steered container, if built.
	plan *cgmpolmgr.Plan
	// policy is the memory use order of the plan.
	policy string
	// mem is the memory to steer.
	mem cgmpolmgr.MemoryTypes
	// capacityOnly: the results have DRAM or region memory that is not
	// steered.
	capacityOnly bool
}

// nriPlugin implements the NRI container lifecycle hooks that start
// and stop memory steering of containers whose CXL claims opt in, keeps
// the fenced containers off the fenced nodes (fence.go), and keeps the
// table of containers that the lend primitives (lend.go) use.
type nriPlugin struct {
	stub  nriStub
	state *nodeState
	fence *nodeFence // nil: fencing none
	// defaults are the container settings of the driver configuration
	// (defaults.container).
	defaults config.Container
	// poolResults returns the prepared allocation results of a pool
	// claim, nil for none.
	poolResults func(uid string) []poolResult
	// leases are the nodes of the leases of containers, nil for none
	// (no lease broker).
	leases leaseNodes
	// hasMemory is the sysfs file of the NUMA nodes with memory.
	hasMemory string
	pending   map[string]pendingSteering    // key: containerID
	managers  map[string]*cgmpolmgr.Manager // key: containerID
	steered   steeredRecord                 // the containers that managers steer
	mu        sync.Mutex                    // protects all fields below too

	ctrs       map[string]*trackedContainer // key: containerID
	seq        uint64                       // creation counter of ctrs
	syncedC    chan struct{}                // closed at first Synchronize
	goneFns    []func(ref containerRef)
	startedFns []func(ref containerRef)
	// lendsRestored is set when the lends of a restarted plugin are
	// applied again, fenceReady when fencing of running containers runs
	// (synchronized and lends restored).
	lendsRestored bool
	fenceReady    bool

	lendMu  sync.Mutex     // serializes LendNode, RevokeNode and fence passes
	fenceWG sync.WaitGroup // fence passes running in the background

	// connMu protects the state of the connection to the runtime:
	// started when Start of the stub has succeeded, stopping when Stop
	// is closing it, closed when the stub has reported it closed.
	connMu                    sync.Mutex
	started, stopping, closed bool
}

// exitOnNRILost ends the process when the runtime has closed the NRI
// connection (a variable for tests).
var exitOnNRILost = os.Exit

// klogLogger writes cgmpolmgr log messages with klog.
type klogLogger struct{}

func (klogLogger) Debugf(format string, args ...any) { klog.V(4).Infof(format, args...) }
func (klogLogger) Infof(format string, args ...any)  { klog.Infof(format, args...) }
func (klogLogger) Warnf(format string, args ...any)  { klog.Warningf(format, args...) }
func (klogLogger) Errorf(format string, args ...any) { klog.Errorf(format, args...) }

// startNRIPlugin creates and starts the NRI plugin. It connects to
// the container runtime's NRI socket and begins listening for
// container lifecycle events. The plugin manages containers with the
// container settings defaults and those of their results, keeps containers
// off the nodes of fence, gets the results of pool claims from pool, the
// nodes of the leases of containers from leases (nil: none) and the nodes
// with memory from the sysfs under sysfsRoot, and keeps its steering
// record (steeredRecord) in the directory dataDir.
func startNRIPlugin(ctx context.Context, state *nodeState, opts NRIOpts, defaults config.Container, fence *nodeFence, pool *poolDriver, leases leaseNodes, sysfsRoot, dataDir string) (*nriPlugin, error) {
	p := &nriPlugin{
		state:       state,
		fence:       fence,
		defaults:    defaults,
		poolResults: pool.ClaimResults,
		leases:      leases,
		hasMemory:   filepath.Join(sysfsRoot, "/", hasMemoryFile),
		pending:     make(map[string]pendingSteering),
		managers:    make(map[string]*cgmpolmgr.Manager),
		steered:     loadSteeredRecord(filepath.Join(dataDir, steeredFileName)),
	}
	p.initLendState()

	stubOpts := []stub.Option{
		stub.WithOnClose(func() { p.onClose(ctx) }),
	}
	if opts.Name != "" {
		stubOpts = append(stubOpts, stub.WithPluginName(opts.Name))
	}
	if opts.Idx != "" {
		stubOpts = append(stubOpts, stub.WithPluginIdx(opts.Idx))
	}
	if opts.Socket != "" {
		stubOpts = append(stubOpts, stub.WithSocketPath(opts.Socket))
	}

	s, err := stub.New(p, stubOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create NRI plugin stub: %w", err)
	}
	p.stub = s

	if err := p.stub.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start NRI plugin: %w", err)
	}
	p.connStarted(ctx)
	fence.setApplier(p)

	klog.V(3).Info("NRI plugin started")
	return p, nil
}

// Stop shuts down the NRI plugin and all active cgroup managers. The
// close of the connection that it causes is not a loss (onClose).
func (p *nriPlugin) Stop() {
	p.markStopping()

	p.mu.Lock()
	stopped := make([]string, 0, len(p.managers))
	for key, mgr := range p.managers {
		mgr.Stop()
		delete(p.managers, key)
		stopped = append(stopped, key)
	}
	p.steered.remove(stopped...)
	for key := range p.pending {
		delete(p.pending, key)
	}
	p.mu.Unlock()

	if p.stub != nil {
		p.stub.Stop()
		klog.V(3).Info("NRI plugin stopped")
	}
}

// markStopping makes a close of the connection from now on not a loss
// (onClose): the driver is stopping. Shutdown calls it before it stops
// anything, as the runtime may close the connection while the driver
// stops (a node shutdown stops both), and Stop calls it before it closes
// the connection itself.
func (p *nriPlugin) markStopping() {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	p.stopping = true
}

// onClose is called by the stub when the connection to the runtime has
// closed, also when Stop closes it (asynchronously, after Stop has
// returned). The stub never connects again: a connection that the
// runtime closes (it restarts, or drops the plugin) is lost for good, and
// the process exits so that it is restarted (by the DaemonSet, or by
// Restart= of a systemd unit) and connects again, like the other NRI
// plugins do. The restarted driver gets its state back from its state
// files and Synchronize, as after a SIGKILL. A close while stopping or
// after ctx is done is not a loss, nor is one before Start has succeeded
// (Start fails and the driver runs on without NRI, or connStarted exits).
func (p *nriPlugin) onClose(ctx context.Context) {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	p.closed = true
	p.exitIfLostLocked(ctx)
}

// connStarted records that Start of the stub has succeeded, and exits if
// the runtime has closed the connection already.
func (p *nriPlugin) connStarted(ctx context.Context) {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	p.started = true
	p.exitIfLostLocked(ctx)
}

// exitIfLostLocked ends the process with exit status 1 (restarted by
// systemd's Restart=on-failure too) if the connection that the stub has
// started is closed, not by Stop, while ctx is not done. Called with
// p.connMu held: Stop cannot come between the decision and the exit.
func (p *nriPlugin) exitIfLostLocked(ctx context.Context) {
	switch {
	case !p.started || !p.closed:
		return
	case p.stopping || ctx.Err() != nil:
		klog.V(3).Info("NRI connection to the runtime closed (stopping)")
		return
	}
	klog.Error("NRI connection to the runtime lost, exiting to be restarted and connect again")
	klog.Flush()
	exitOnNRILost(1)
}

// CreateContainer is called by the container runtime (via NRI) when a
// new container is about to be created. It decides the management of the
// memory of the container from the container settings of the allocation
// results that it uses and the defaults: a steered container gets one
// memory steering plan of the memory of its results, stored until
// StartContainer; a fenced container gets cpuset.mems without the fenced
// nodes that its results have no numa memory on, if that changes its
// cpuset.mems. A container that is not steered is lent the nodes of the
// leases that the broker kept for it when it stopped to restart: a fenced
// one gets them in the adjustment, as an update at its start would reach
// only its spec (lend.go). Returns an error if the container settings of
// the results conflict or are invalid, or no plan can be built, blocking
// container creation.
func (p *nriPlugin) CreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	ctrName := pod.GetNamespace() + "/" + pod.GetName() + "/" + ctr.GetName()
	ctrID := ctr.GetId()

	klog.V(3).Infof("NRI CreateContainer: ctr=%s id=%s", ctrName, ctrID)

	// The results are read before p.mu is taken.
	results := p.containerResults(ctrName, extractResults(ctr.GetEnv()))
	m, err := p.manage(ctrName, results, true)
	if err != nil {
		klog.Errorf("NRI CreateContainer: %v", err)
		p.mu.Lock()
		p.trackCreated(pod, ctr)
		p.mu.Unlock()
		return nil, nil, err
	}
	logManagement(ctrName, m, len(results) > 0)

	p.mu.Lock()
	tc := p.trackCreated(pod, ctr)
	tc.memory = m.memory
	tc.claimed = m.claimed
	tc.recordOwnClaimed()
	if m.plan != nil {
		p.pending[ctrID] = pendingSteering{name: ctrName, plan: m.plan, unsteered: unsteeredMemory(m.eff)}
	}
	if lent := p.seedLends(tc, p.keptLends(pod.GetUid(), ctr.GetName())); !lent.IsEmpty() {
		klog.V(3).Infof("NRI CreateContainer: ctr=%s: nodes %s lent by its leases (kept for its restart)", ctrName, lent)
	}
	mems, fenced := p.fenceCreated(tc)
	p.mu.Unlock()

	if mems == "" {
		return nil, nil, nil
	}
	klog.V(3).Infof("NRI CreateContainer: ctr=%s: cpuset.mems=%s (fenced nodes %s)", ctrName, mems, fenced)
	adjust := &api.ContainerAdjustment{}
	adjust.SetLinuxCPUSetMems(mems)
	return adjust, nil, nil
}

// manage returns the management of the memory of a container that uses
// the results, with the steering plan of a steered container if plan is
// set. A container is steered when its effective steering policy is not
// none and its results have DRAM or CXL numa memory; otherwise it is
// fenced when its effective fencing is allowed-mems, else none. Returns an
// error if the container settings of the results conflict or are invalid,
// or the steering plan cannot be built.
func (p *nriPlugin) manage(ctrName string, results []containerResult, plan bool) (*management, error) {
	settings := make([]config.ResultSettings, 0, len(results))
	for _, r := range results {
		settings = append(settings, r.settings)
	}
	eff, err := config.Combine(settings, p.defaults)
	if err != nil {
		return nil, fmt.Errorf("container %s: %w", ctrName, err)
	}
	m := &management{memory: memoryNone, eff: eff, claimed: claimedNodes(results), mem: steeredMemory(results)}
	if pol, ok := eff.Container.Steering.CgmPolicy(m.mem); ok {
		m.memory, m.policy = memorySteered, pol.MemoryUseOrder
		if plan {
			if m.plan, err = pol.Plan(m.mem); err != nil {
				return nil, fmt.Errorf("NRI CreateContainer: ctr=%s: failed to build memory steering plan: %w", ctrName, err)
			}
		}
		return m, nil
	}
	m.memory = unsteeredMemory(eff)
	for _, r := range results {
		if r.deviceType == device.DeviceTypeDRAM || (r.deviceType == device.DeviceTypeRegion && r.mode == cxlapi.ModeNUMA) {
			m.capacityOnly = true
		}
	}
	return m, nil
}

// logManagement logs the management of the memory of a new container.
//   - hasResults: the container uses allocation results
func logManagement(ctrName string, m *management, hasResults bool) {
	klog.V(3).Infof("NRI CreateContainer: ctr=%s: memory %s (steering %s, fencing %s)",
		ctrName, m.memory, m.eff.PolicyText(), fencingText(m.eff))
	switch {
	case m.memory == memorySteered && m.plan != nil:
		klog.V(5).Infof("NRI CreateContainer: ctr=%s: prepared memory steering (order=%s, dramNodes=%v, cxlNodes=%v, %s)",
			ctrName, m.policy, m.mem.DRAMNodes, m.mem.CXLNodes, m.plan)
	case m.memory == memorySteered:
	case m.eff.Steers() && hasResults:
		klog.V(3).Infof("NRI CreateContainer: ctr=%s: steering policy %s: no numa memory to steer", ctrName, m.eff.Container.Steering.Policy)
	}
	if m.capacityOnly {
		klog.V(3).Infof("NRI CreateContainer: ctr=%s: dram and region memory is not steered: the claims reserve capacity only", ctrName)
	}
}

// fencingText returns the effective fencing and its origin, such as
// "allowed-mems (default)" or "none (node default)".
func fencingText(eff *config.Effective) string {
	switch origin := eff.Origins[config.FieldFencing]; origin {
	case config.OriginDefault, "":
		return eff.Container.Fencing + " (" + config.OriginDefault + ")"
	case config.OriginNodeDefault:
		return eff.Container.Fencing + " (" + config.OriginNodeDefault + ")"
	default:
		return eff.Container.Fencing + " from " + origin
	}
}

// unsteeredMemory returns the management of the memory of a container
// that is not steered: fenced when its effective fencing is allowed-mems,
// else none.
func unsteeredMemory(eff *config.Effective) string {
	if eff.Container.Fencing == config.FencingAllowedMems {
		return memoryFenced
	}
	return memoryNone
}

// defaultMemory returns the management of the memory of a container that
// uses no allocation results.
func (p *nriPlugin) defaultMemory() string {
	eff, err := config.Combine(nil, p.defaults)
	if err != nil {
		return memoryNone
	}
	return unsteeredMemory(eff)
}

// containerResults returns the prepared allocation results of both drivers
// that refs refer to. Results that are not prepared are left out.
func (p *nriPlugin) containerResults(ctrName string, refs []resultRef) []containerResult {
	var out []containerResult
	for _, ref := range refs {
		if claim, d, ok := p.state.preparedResult(ref.uid, ref.n); ok {
			klog.V(5).Infof("NRI CreateContainer: ctr=%s claim=%s (%s) result %d: name=%s type=%s mode=%s sysfs=%s numa=%v affinities=%v total=%s consumed=%s request=%s",
				ctrName, ref.uid, claim, ref.n,
				d.DeviceName, d.DeviceType, d.Mode, d.SysfsPath, d.NUMANodes, d.NodeAffinities,
				formatBytes(d.TotalBytes), formatBytes(uint64(d.ConsumedBytes)), d.RequestName)
			out = append(out, containerResult{
				deviceType: d.DeviceType,
				mode:       d.Mode,
				nodes:      nonNegative(d.NUMANodes),
				bytes:      d.ConsumedBytes,
				settings:   d.ResultSettings,
			})
			continue
		}
		if r, ok := p.poolResult(ref); ok {
			klog.V(5).Infof("NRI CreateContainer: ctr=%s claim=%s result %d: pool device mode=%s node=%d size=%s request=%s",
				ctrName, ref.uid, ref.n, r.Mode, r.Node, formatBytes(r.Size), r.Request)
			cr := containerResult{pool: true, mode: r.Mode, bytes: int64(r.Size), settings: r.Settings}
			if r.Node >= 0 {
				cr.nodes = []int{r.Node}
			}
			out = append(out, cr)
			continue
		}
		klog.V(5).Infof("NRI CreateContainer: ctr=%s claim=%s result %d: not prepared (driver may have restarted)", ctrName, ref.uid, ref.n)
	}
	return out
}

// poolResult returns the prepared pool allocation result of ref, and false
// if there is none.
func (p *nriPlugin) poolResult(ref resultRef) (poolResult, bool) {
	if p.poolResults == nil {
		return poolResult{}, false
	}
	for _, r := range p.poolResults(ref.uid) {
		if r.Index == ref.n {
			return r, true
		}
	}
	return poolResult{}, false
}

// claimedNodes returns the NUMA nodes of the CXL numa memory of the
// results.
func claimedNodes(results []containerResult) cpuset.CPUSet {
	nodes := cpuset.New()
	for i := range results {
		if results[i].numaCXL() {
			nodes = nodes.Union(cpuset.New(results[i].nodes...))
		}
	}
	return nodes
}

// steeredMemory returns the memory types and quotas of the results: DRAM
// of dram devices, CXL of numa slices of local memdevs, regions and pool
// devices in mode numa.
func steeredMemory(results []containerResult) cgmpolmgr.MemoryTypes {
	dramNodeSet := make(map[int]bool)
	cxlNodeSet := make(map[int]bool)
	var mem cgmpolmgr.MemoryTypes
	for i := range results {
		r := &results[i]
		switch {
		case r.deviceType == device.DeviceTypeDRAM:
			for _, n := range r.nodes {
				dramNodeSet[n] = true
			}
			mem.DRAMQuota += r.bytes
		case r.numaCXL():
			for _, n := range r.nodes {
				cxlNodeSet[n] = true
			}
			mem.CXLQuota += r.bytes
		}
	}
	mem.DRAMNodes = sortedNodes(dramNodeSet)
	mem.CXLNodes = sortedNodes(cxlNodeSet)
	return mem
}

// RemoveContainer is called by the container runtime (via NRI) when a
// container is being removed. It stops memory steering of the
// container.
func (p *nriPlugin) RemoveContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	ctrName := pod.GetNamespace() + "/" + pod.GetName() + "/" + ctr.GetName()
	ctrID := ctr.GetId()

	p.containerGone(ctrID)

	refs := extractResults(ctr.GetEnv())
	if len(refs) == 0 {
		klog.V(5).Infof("NRI RemoveContainer: ctr=%s: no CXL claims", ctrName)
		return nil
	}

	klog.V(5).Infof("NRI RemoveContainer: ctr=%s releasing results: %v", ctrName, refs)

	p.stopContainerManagers(ctrID, ctrName)

	return nil
}

// StartContainer is called by the container runtime (via NRI) when the
// task of a container has been created, before it starts. It resolves the
// cgroup directory of the container and starts steering its memory along
// the plan stored in CreateContainer, recorded in the steering record
// before the manager writes the cgroup. A container whose steering does
// not start is managed like a container that is not steered (notSteered).
// The OnContainerStarted callbacks and the fence pass of the container
// wait for PostStartContainer: an update sent now would reach only the
// spec (lend.go).
func (p *nriPlugin) StartContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	ctrName := pod.GetNamespace() + "/" + pod.GetName() + "/" + ctr.GetName()
	ctrID := ctr.GetId()
	ctrPid := ctr.GetPid()

	p.mu.Lock()
	pending, hasPending := p.pending[ctrID]
	if hasPending {
		delete(p.pending, ctrID)
	}
	tc := p.trackStarted(pod, ctr)
	if hasPending {
		tc.memory = memorySteered
	}
	klog.V(4).Infof("NRI StartContainer: ctr=%s id=%s pid=%d cgroup=%s baseMems=%s",
		ctrName, ctrID, tc.ref.Pid, tc.ref.CgroupPath, tc.base)
	p.mu.Unlock()

	if !hasPending {
		klog.V(3).Infof("NRI StartContainer: ctr=%s id=%s: no memory claims to be managed", ctrName, ctrID)
		return nil
	}

	cgroupDir, err := resolveContainerCgroupDir(ctr)
	if err != nil {
		klog.Errorf("NRI StartContainer: ctr=%s id=%s: failed to resolve cgroup directory: %v",
			ctrName, ctrID, err)
		p.notSteered(tc, pending)
		return nil
	}

	klog.V(3).Infof("NRI StartContainer: ctr=%s id=%s pid=%d cgroupsPath=%s", ctrName, ctrID, ctrPid, cgroupDir)

	mgr, err := cgmpolmgr.New(cgroupDir, pending.plan,
		cgmpolmgr.WithName(pending.name),
		cgmpolmgr.WithLogger(klogLogger{}))
	if err != nil {
		klog.Warningf("NRI StartContainer: ctr=%s: failed to create memory steering manager: %v",
			ctrName, err)
		p.notSteered(tc, pending)
		return nil
	}

	p.mu.Lock()
	p.steered.add(ctrID, cgroupDir)
	p.mu.Unlock()
	if err := mgr.Start(); err != nil {
		klog.Warningf("NRI StartContainer: ctr=%s: failed to start memory steering: %v",
			ctrName, err)
		p.notSteered(tc, pending)
		return nil
	}

	p.mu.Lock()
	p.managers[ctrID] = mgr
	p.mu.Unlock()

	klog.V(3).Infof("NRI StartContainer: ctr=%s: started memory steering (cgroup=%s)", ctrName, cgroupDir)

	return nil
}

// notSteered manages a started container whose steering did not start
// like a container that is not steered (fenced with allowed-mems): no
// manager of this process steers it (syncManagement), so it is fenced and
// may be lent to. Its fence pass runs at its PostStartContainer. A failed
// Start of a manager has removed memory.high again, so the container
// leaves the steering record.
func (p *nriPlugin) notSteered(tc *trackedContainer, pending pendingSteering) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.steered.remove(tc.ref.ID)
	if p.ctrs[tc.ref.ID] != tc || p.managers[tc.ref.ID] != nil {
		return
	}
	tc.memory = pending.unsteered
	klog.Warningf("NRI StartContainer: ctr=%s id=%s: not steered, memory %s", tc.name(), tc.ref.ID, tc.memory)
}

var _ stub.PostStartContainerInterface = (*nriPlugin)(nil)

// PostStartContainer is called by the container runtime (via NRI) after it
// has started a container and marked it started: from now on containerd
// applies updates of the container to its cgroup (lend.go). It runs the
// OnContainerStarted callbacks (the broker lends the nodes of the leases
// of a restarted requester again, or finds them lent at its creation) and,
// for a fenced container, a fence pass of the container in the background,
// which updates its cgroup if an update before its start reached only its
// spec.
func (p *nriPlugin) PostStartContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLendState()
	tc := p.ctrs[ctr.GetId()]
	if tc == nil {
		// stopped already
		return nil
	}
	if !tc.started {
		tc = p.trackStarted(pod, ctr)
	}
	klog.V(4).Infof("NRI PostStartContainer: ctr=%s id=%s", tc.name(), tc.ref.ID)
	p.fireStarted(tc)
	if p.fenceAtStart(tc) {
		// in the background: the pass waits for p.mu
		p.fenceStarted(tc.ref.ID)
	}
	return nil
}

// StopContainer is called by the container runtime (via NRI) when a
// container is being stopped. Stops memory steering as a safety net
// in case RemoveContainer is not called.
func (p *nriPlugin) StopContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) ([]*api.ContainerUpdate, error) {
	ctrName := pod.GetNamespace() + "/" + pod.GetName() + "/" + ctr.GetName()
	ctrID := ctr.GetId()
	klog.V(3).Infof("NRI StopContainer: ctr=%s", ctrName)

	p.containerGone(ctrID)
	p.stopContainerManagers(ctrID, ctrName)

	return nil, nil
}

// stopContainerManagers stops and removes the memory steering manager
// and the pending plan of the container.
func (p *nriPlugin) stopContainerManagers(ctrID string, ctrName string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.pending, ctrID)

	if mgr, ok := p.managers[ctrID]; ok {
		mgr.Stop()
		delete(p.managers, ctrID)
		p.steered.remove(ctrID)
		klog.V(3).Infof("NRI: stopped memory steering for ctr=%s", ctrName)
	}
}

// sortedNodes returns the nodes of the set in ascending order.
func sortedNodes(nodes map[int]bool) []int {
	sorted := make([]int, 0, len(nodes))
	for n := range nodes {
		sorted = append(sorted, n)
	}
	sort.Ints(sorted)
	return sorted
}

// resolveContainerCgroupDir determines the cgroup v2 filesystem
// directory for a container. It reads /proc/<pid>/cgroup to find the
// actual cgroup path the kernel assigned to the container's init
// process, which is more reliable than the NRI-provided CgroupsPath
// (which may use systemd slice notation), and takes the container's own
// cgroup from it (containerCgroupDir).
func resolveContainerCgroupDir(ctr *api.Container) (string, error) {
	pid := ctr.GetPid()
	if pid == 0 {
		return "", fmt.Errorf("container PID is 0, cannot resolve cgroup")
	}

	// Read /proc/<pid>/cgroup. For cgroup v2, there's a single
	// line of the form "0::<path>".
	procCgroupPath := filepath.Join(procDir, fmt.Sprint(pid), "cgroup")
	data, err := os.ReadFile(procCgroupPath)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", procCgroupPath, err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		// cgroup v2 line: "0::<path>"
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			cgroupRelPath := parts[2]
			absPath := containerCgroupDir(filepath.Join(cgroupRoot, cgroupRelPath), ctr.GetId())
			klog.V(5).Infof("resolveContainerCgroupDir: pid=%d /proc cgroup line=%q -> absPath=%s",
				pid, line, absPath)
			return absPath, nil
		}
	}

	return "", fmt.Errorf("no cgroup v2 entry found in %s (content: %q)", procCgroupPath, string(data))
}

// containerCgroupDir returns the cgroup directory of the container id
// from the cgroup directory dir of its init process: the nearest of dir
// and its ancestors under the cgroup root whose name has the id, as the
// runtimes name the cgroup of a container (cri-containerd-<id>.scope,
// crio-<id>.scope, <id> with the cgroupfs driver); dir if none does. The
// init process is in the container's cgroup at StartContainer (runc
// init), but the workload may have moved into a child cgroup by the time
// of a Synchronize: systemd in the container moves itself to init.scope,
// nested runtimes delegate. The runtime updates the container's cgroup, the
// cpuset.mems of the child stays "".
func containerCgroupDir(dir, id string) string {
	if id == "" {
		return dir
	}
	root := filepath.Clean(cgroupRoot)
	for d := filepath.Clean(dir); strings.HasPrefix(d, root+"/"); d = filepath.Dir(d) {
		if strings.Contains(filepath.Base(d), id) {
			return d
		}
	}
	return dir
}

// extractResults scans an environment variable list for the CDI-injected
// result markers CXL_CLAIM_<uid>_<n> and returns the unique allocation
// results. Duplicates are possible because kubelet doesn't deduplicate CDI
// device IDs.
func extractResults(envVars []string) []resultRef {
	seen := make(map[resultRef]bool)
	var refs []resultRef
	for _, env := range envVars {
		if ref, ok := resultFromEnvVar(env); ok && !seen[ref] {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}
	return refs
}

// formatBytes formats a byte count as a human-readable string using
// binary units (KiB, MiB, GiB).
func formatBytes(bytes uint64) string {
	const (
		kib = 1024
		mib = 1024 * kib
		gib = 1024 * mib
	)
	switch {
	case bytes >= gib:
		return fmt.Sprintf("%.1fGiB", float64(bytes)/float64(gib))
	case bytes >= mib:
		return fmt.Sprintf("%.1fMiB", float64(bytes)/float64(mib))
	case bytes >= kib:
		return fmt.Sprintf("%.1fKiB", float64(bytes)/float64(kib))
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}
