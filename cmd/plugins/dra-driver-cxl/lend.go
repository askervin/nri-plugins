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

// Lend primitives: lending NUMA nodes of CXL memory to running
// containers by growing and shrinking their cpuset.mems through NRI
// UpdateContainers. A node is lent on behalf of holders (leases): devices
// under one CXL host bridge share a NUMA node, so two leases of a
// container can hold the same node, and the node stays lent until its
// last holder revokes it.
//
// Locking: p.mu (nri.go) protects the container table and is taken by
// the NRI event handlers. It is never held across UpdateContainers:
// containerd serializes NRI events and unsolicited updates with one
// lock, so an update issued while an event handler waits for p.mu
// would deadlock until the request timeout. p.lendMu serializes
// LendNode and RevokeNode so that two concurrent lends to the same
// container cannot compute cpuset.mems from the same stale lent set.
// For the same reason LendNode and RevokeNode must not be called
// synchronously from an NRI event handler, and the OnContainerGone and
// OnContainerStarted callbacks run in their own goroutines.
//
// Fencing (fence.go): a fenced container (memoryFenced: not steered,
// fencing allowed-mems) has cpuset.mems = wantMems: its own nodes without
// the fenced nodes, the CXL numa nodes of its allocation results and the
// nodes lent to it. A fence pass (fenceContainers) applies it to the
// tracked containers under lendMu, like a lend, so lends and passes never
// compute from stale sets. A pass runs when a node is fenced, when fencing
// of running containers becomes ready (NRI synchronized and lends
// restored) and at every Synchronize after that; passes started from
// Synchronize and LendsRestored run in their own goroutines.
// CreateContainer gives a new container wantMems as an adjustment, with
// the nodes of the leases kept for it when it restarts (keptLends).
// Steered containers (memorySteered, a pending plan or a manager) are
// never updated and never lent to. A container that Synchronize finds is
// not steered by this process, whatever its settings say
// (syncManagement). Lock order: the Fence lock of the fence, lendMu, p.mu,
// then the fenced set and the claim tables (the lock of the node state,
// the pool snapshot lock serialsMu), then the lease table of the broker;
// p.mu is never held across UpdateContainers.
//
// Updates before the start: containerd (2.x, container_start.go) applies
// an NRI update to the cgroup only of a container that it has marked
// started, which it does after task start, right before
// PostStartContainer. Of a container that it has created but not marked
// started it changes only the spec, which reaches the cgroup only if the
// task is created after it, and the task is created before the
// StartContainer event; one that is not in its store yet (during
// CreateContainer) it skips. Both are reported as applied. So the
// OnContainerStarted callbacks and a fence pass of the started container
// run from PostStartContainer, and lends and passes compare with the
// cpuset.mems of the cgroup of a started container (curMems), not with
// the one recorded, and update it again when it differs. Not covered: a
// revoke of a container that is not fenced between its StartContainer and
// its PostStartContainer reaches its spec only, and its cgroup keeps the
// node (with fencing none the plugin keeps no container off a node, and
// offlining migrates the pages of the node whatever cpuset.mems says).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"github.com/containers/nri-plugins/pkg/cgmpolmgr"
	"k8s.io/klog/v2"
	"k8s.io/utils/cpuset"
)

// containerRef is a running container known to the NRI stub.
type containerRef struct {
	PodUID, PodNamespace, PodName, Name, ID string
	Pid                                     uint32 // init pid at StartContainer (0 if unknown)
	CgroupPath                              string // absolute cgroup v2 dir, as resolveContainerCgroupDir
	BaseMems                                string // cpuset.mems.effective at start, e.g. "0-1"
}

// nodeLender lends NUMA nodes to running containers through NRI.
type nodeLender interface {
	// ContainerByPid finds the container whose cgroup contains pid
	// (/proc/<pid>/cgroup prefix match against CgroupPath).
	ContainerByPid(pid int) (*containerRef, bool)
	// Container by pod UID and container name.
	Container(podUID, name string) (*containerRef, bool)
	// LendNode lends NUMA node to the container on behalf of holder: the
	// node is in the container's cpuset.mems, set through NRI
	// UpdateContainers (mems = BaseMems + all nodes that have a
	// holder). Idempotent per node and holder.
	LendNode(ctx context.Context, podUID, name string, node int, holder string) error
	// RevokeNode drops holder of the node; the node leaves cpuset.mems
	// (pages migrate back) when it has no holder left. Idempotent per
	// node and holder; a container that is gone is not an error.
	RevokeNode(ctx context.Context, podUID, name string, node int, holder string) error
	// LentNodes returns the nodes currently lent to the container.
	LentNodes(podUID, name string) []int
	// OnContainerGone registers a callback for StopContainer/RemoveContainer
	// of a container that has lends or a lease socket.
	OnContainerGone(func(ref containerRef))
	// OnContainerStarted registers a callback for PostStartContainer: the
	// container has started, and the runtime applies updates to its
	// cgroup.
	OnContainerStarted(func(ref containerRef))
}

var _ nodeLender = (*nriPlugin)(nil)

// leaseNodes tells the NRI plugin the NUMA nodes that the leases of a
// container hold (the lease broker), so that a requester container that
// restarts is created with them.
type leaseNodes interface {
	// LeaseNodes returns the nodes of the Ready numa leases of the
	// container name of the pod, with the leases that hold each node.
	LeaseNodes(podUID, name string) map[int][]string
}

// errSteered is returned by LendNode for containers whose memory is
// steered by cgmpolmgr.
var errSteered = errors.New("container is memory-steered (container.steering.policy of its claims or the node defaults); lending is not supported together with steering yet")

// procDir is the proc filesystem root (a variable for tests).
var procDir = "/proc"

// cgroupRoot is the cgroup v2 mount point (a variable for tests).
var cgroupRoot = cgroupV2MountPoint

// nriStub is the part of stub.Stub that nriPlugin uses.
type nriStub interface {
	Start(context.Context) error
	Stop()
	UpdateContainers([]*api.ContainerUpdate) ([]*api.ContainerUpdate, error)
}

// trackedContainer is an entry of the container table.
type trackedContainer struct {
	ref     containerRef
	seq     uint64        // creation order, the newest wins in Container()
	started bool          // StartContainer seen (or running at Synchronize)
	synced  bool          // learned from Synchronize, not from Create/Start
	memory  string        // management: memorySteered, memoryFenced or memoryNone
	base    cpuset.CPUSet // BaseMems parsed
	lent    lentNodes     // nodes lent to this container id
	mems    string        // cpuset.mems of the spec as the plugin knows it
	claimed cpuset.CPUSet // NUMA nodes of the CXL numa memory of its results
}

// lentNodes maps the nodes lent to a container to their holders.
type lentNodes map[int]map[string]bool

// nodes returns the lent nodes that have a holder.
func (l lentNodes) nodes() cpuset.CPUSet {
	nodes := make([]int, 0, len(l))
	for n, holders := range l {
		if len(holders) > 0 {
			nodes = append(nodes, n)
		}
	}
	return cpuset.New(nodes...)
}

// with returns the holders of node after holder lends (lend) or revokes
// (!lend) it.
func (l lentNodes) with(node int, holder string, lend bool) map[string]bool {
	holders := make(map[string]bool, len(l[node])+1)
	for h := range l[node] {
		holders[h] = true
	}
	if lend {
		holders[holder] = true
	} else {
		delete(holders, holder)
	}
	return holders
}

// after returns the lent nodes that have a holder when node has holders.
func (l lentNodes) after(node int, holders map[string]bool) cpuset.CPUSet {
	if len(holders) > 0 {
		return l.nodes().Union(cpuset.New(node))
	}
	return l.nodes().Difference(cpuset.New(node))
}

// set records the holders of node.
func (l lentNodes) set(node int, holders map[string]bool) lentNodes {
	if l == nil {
		l = lentNodes{}
	}
	if len(holders) == 0 {
		delete(l, node)
	} else {
		l[node] = holders
	}
	return l
}

// initLendState initializes the container table of the plugin.
func (p *nriPlugin) initLendState() {
	if p.ctrs == nil {
		p.ctrs = make(map[string]*trackedContainer)
	}
	if p.syncedC == nil {
		p.syncedC = make(chan struct{})
	}
}

// WaitSynchronized waits until the first NRI Synchronize has filled
// the container table, or ctx is done. Not part of nodeLender: lease code
// that runs at plugin start may call it before reconciling.
func (p *nriPlugin) WaitSynchronized(ctx context.Context) error {
	p.mu.Lock()
	p.initLendState()
	c := p.syncedC
	p.mu.Unlock()
	select {
	case <-c:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("NRI not synchronized yet: %w", ctx.Err())
	}
}

// trackCreated adds a created container to the table, managed as a
// container without allocation results. Caller holds p.mu.
func (p *nriPlugin) trackCreated(pod *api.PodSandbox, ctr *api.Container) *trackedContainer {
	p.initLendState()
	id := ctr.GetId()
	if tc, ok := p.ctrs[id]; ok {
		return tc
	}
	p.seq++
	tc := &trackedContainer{
		ref: containerRef{
			PodUID:       pod.GetUid(),
			PodNamespace: pod.GetNamespace(),
			PodName:      pod.GetName(),
			Name:         ctr.GetName(),
			ID:           id,
		},
		seq:    p.seq,
		memory: p.defaultMemory(),
		mems:   ctr.GetLinux().GetResources().GetCpu().GetMems(),
	}
	p.ctrs[id] = tc
	return tc
}

// trackStarted records pid, cgroup and base memory nodes of a started
// container. Caller holds p.mu. Returns the entry.
func (p *nriPlugin) trackStarted(pod *api.PodSandbox, ctr *api.Container) *trackedContainer {
	tc := p.trackCreated(pod, ctr)
	tc.started = true
	tc.ref.Pid = ctr.GetPid()
	if tc.ref.CgroupPath == "" {
		if dir, err := resolveContainerCgroupDir(ctr); err == nil {
			tc.ref.CgroupPath = dir
		} else {
			klog.V(3).Infof("NRI lend: ctr=%s id=%s: no cgroup directory: %v", tc.name(), tc.ref.ID, err)
		}
	}
	tc.base = p.baseMems(tc, ctr)
	tc.ref.BaseMems = tc.base.String()
	return tc
}

// baseMems returns the memory nodes a container has of its own: its
// cpuset.mems.effective (or, if unreadable, the cpuset.mems of its
// spec), minus the nodes currently lent to any container by this
// plugin. An unconstrained container started while a lent CXL node is
// online would otherwise count that node as its own. Caller holds p.mu.
func (p *nriPlugin) baseMems(tc *trackedContainer, ctr *api.Container) cpuset.CPUSet {
	var mems string
	if tc.ref.CgroupPath != "" {
		if data, err := os.ReadFile(filepath.Join(tc.ref.CgroupPath, "cpuset.mems.effective")); err == nil {
			mems = strings.TrimSpace(string(data))
		} else {
			klog.V(3).Infof("NRI lend: ctr=%s: %v", tc.name(), err)
		}
	}
	if mems == "" {
		mems = ctr.GetLinux().GetResources().GetCpu().GetMems()
	}
	set, err := cpuset.Parse(mems)
	if err != nil {
		klog.Warningf("NRI lend: ctr=%s: invalid memory nodes %q: %v", tc.name(), mems, err)
		return cpuset.New()
	}
	return set.Difference(p.allLentNodes())
}

// allLentNodes returns the union of the nodes lent to any container.
// Caller holds p.mu.
func (p *nriPlugin) allLentNodes() cpuset.CPUSet {
	all := cpuset.New()
	for _, tc := range p.ctrs {
		all = all.Union(tc.lent.nodes())
	}
	return all
}

// keptLends returns the lends of the leases of the container name of the
// pod, kept by the broker when the container stopped to restart, nil for
// none. Caller holds p.mu: the broker marks a lease Releasing before it
// revokes it, so the revoke finds the container that a lease seeds
// (seedLends) under the same p.mu.
func (p *nriPlugin) keptLends(podUID, name string) lentNodes {
	if p.leases == nil || podUID == "" {
		return nil
	}
	var kept lentNodes
	for node, ids := range p.leases.LeaseNodes(podUID, name) {
		for _, id := range ids {
			if node >= 0 {
				kept = kept.set(node, kept.with(node, id, true))
			}
		}
	}
	return kept
}

// seedLends gives a container that has no lends the kept lends of its
// leases, unless it is steered (lending to it is refused), and returns the
// lent nodes. Caller holds p.mu.
func (p *nriPlugin) seedLends(tc *trackedContainer, kept lentNodes) cpuset.CPUSet {
	if len(kept) == 0 || len(tc.lent) != 0 || p.steeredLocked(tc) {
		return cpuset.New()
	}
	tc.lent = kept
	return kept.nodes()
}

// curMems returns the cpuset.mems of a container: that of its cgroup once
// it has started (an update before the start may have reached its spec
// only, see the header), else that of its spec as the plugin knows it.
// Caller holds p.mu.
func (tc *trackedContainer) curMems() string {
	if tc.started && tc.ref.CgroupPath != "" {
		if data, err := os.ReadFile(filepath.Join(tc.ref.CgroupPath, "cpuset.mems")); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return tc.mems
}

// untrack removes a container from the table and returns its entry,
// or nil if it was not tracked. Caller holds p.mu.
func (p *nriPlugin) untrack(id string) *trackedContainer {
	tc, ok := p.ctrs[id]
	if !ok {
		return nil
	}
	delete(p.ctrs, id)
	return tc
}

func (tc *trackedContainer) name() string {
	return tc.ref.PodNamespace + "/" + tc.ref.PodName + "/" + tc.ref.Name
}

// snapshot returns a copy of the reference of the container.
func (tc *trackedContainer) snapshot() containerRef {
	ref := tc.ref
	ref.BaseMems = tc.base.String()
	return ref
}

// fireGone runs the OnContainerGone callbacks in the background.
// Caller holds p.mu.
func (p *nriPlugin) fireGone(tc *trackedContainer) {
	if tc == nil {
		return
	}
	if lent := tc.lent.nodes(); !lent.IsEmpty() {
		klog.V(3).Infof("NRI lend: ctr=%s id=%s gone with lent nodes %s", tc.name(), tc.ref.ID, lent)
	}
	ref := tc.snapshot()
	for _, fn := range p.goneFns {
		go fn(ref)
	}
}

// fireStarted runs the OnContainerStarted callbacks in the background.
// Caller holds p.mu.
func (p *nriPlugin) fireStarted(tc *trackedContainer) {
	ref := tc.snapshot()
	for _, fn := range p.startedFns {
		go fn(ref)
	}
}

// containerGone removes a stopped or removed container from the table
// and fires OnContainerGone once.
func (p *nriPlugin) containerGone(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLendState()
	p.fireGone(p.untrack(id))
}

// Synchronize implements stub.SynchronizeInterface. It rebuilds the
// container table from the runtime's pods and containers when the
// plugin (re)connects, and starts a fence pass in the background when
// fencing of running containers is ready. Containers that are no longer
// present are reported gone. Lent sets of containers that remain (a
// reconnect of a running plugin) are kept. After a plugin restart the
// lent sets are empty and BaseMems is cpuset.mems.effective, which still
// includes the nodes lent before the restart; they are dropped from
// BaseMems when the lease code re-applies (LendNode) or revokes
// (RevokeNode) them. A container that is new to the table gets the kept
// lends of its leases (keptLends), as at CreateContainer: a requester
// that restarted while the plugin was down, or whose CreateContainer
// adjustment of the previous plugin has the nodes of its leases, keeps
// them through the first fence pass. The steering of containers is not
// restarted: those that were steered lose their memory.high and are
// managed like containers that are not steered (syncManagement); the
// steering record keeps only the containers of the managers of this
// process from now on.
func (p *nriPlugin) Synchronize(_ context.Context, pods []*api.PodSandbox, ctrs []*api.Container) ([]*api.ContainerUpdate, error) {
	podByID := make(map[string]*api.PodSandbox, len(pods))
	for _, pod := range pods {
		podByID[pod.GetId()] = pod
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLendState()

	seen := make(map[string]bool, len(ctrs))
	for _, ctr := range ctrs {
		state := ctr.GetState()
		if state != api.ContainerState_CONTAINER_CREATED &&
			state != api.ContainerState_CONTAINER_RUNNING &&
			state != api.ContainerState_CONTAINER_PAUSED {
			continue
		}
		pod, ok := podByID[ctr.GetPodSandboxId()]
		if !ok {
			pod = &api.PodSandbox{Id: ctr.GetPodSandboxId()}
		}
		seen[ctr.GetId()] = true
		_, known := p.ctrs[ctr.GetId()]
		var tc *trackedContainer
		if state == api.ContainerState_CONTAINER_CREATED {
			tc = p.trackCreated(pod, ctr)
		} else {
			tc = p.trackStarted(pod, ctr)
		}
		if !known {
			tc.synced = true
			p.syncManagement(tc, ctr)
			if lent := p.seedLends(tc, p.keptLends(pod.GetUid(), tc.ref.Name)); !lent.IsEmpty() {
				// not its own nodes, as in baseMems
				tc.base = tc.base.Difference(lent)
				tc.ref.BaseMems = tc.base.String()
				klog.V(3).Infof("NRI Synchronize: ctr=%s id=%s: nodes %s lent by its leases", tc.name(), tc.ref.ID, lent)
			}
		}
		tc.mems = ctr.GetLinux().GetResources().GetCpu().GetMems()
		klog.V(4).Infof("NRI Synchronize: ctr=%s id=%s pid=%d cgroup=%s baseMems=%s memory=%s",
			tc.name(), tc.ref.ID, tc.ref.Pid, tc.ref.CgroupPath, tc.base, tc.memory)
	}
	for id := range p.ctrs {
		if !seen[id] {
			p.fireGone(p.untrack(id))
		}
	}
	p.steered.synced(func(id string) bool { return p.managers[id] != nil })

	select {
	case <-p.syncedC:
	default:
		close(p.syncedC)
	}
	klog.V(3).Infof("NRI Synchronize: %d pods, %d containers tracked", len(pods), len(p.ctrs))
	p.startFencing()
	return nil, nil
}

// syncManagement sets the management and the claimed nodes of a container
// that the plugin learns from Synchronize, as CreateContainer would have
// decided them, except that it is never steered: steering is planned at
// CreateContainer and runs in the process that started the container, so
// no manager of this process steers it (the plugin restarted, gracefully
// or killed, or the container was created while the plugin was down). A
// container that its settings steer is managed as its fencing says, like a
// container that is not steered. A container whose settings are not valid
// any more (the configuration or the claims changed) is taken as steered:
// neither fenced nor lent to. Then the container is released as the Stop
// of a manager would (releaseSteering) if a manager of a previous process
// steered it. Caller holds p.mu.
func (p *nriPlugin) syncManagement(tc *trackedContainer, ctr *api.Container) {
	results := p.containerResults(tc.name(), extractResults(ctr.GetEnv()))
	m, err := p.manage(tc.name(), results, false)
	id := tc.ref.ID
	ours := p.managers[id] != nil || p.pending[id].plan != nil
	steers := false
	switch {
	case err != nil:
		klog.Warningf("NRI Synchronize: ctr=%s: %v; taken as steered", tc.name(), err)
		tc.memory = memorySteered
	case m.memory == memorySteered && !ours:
		tc.memory, tc.claimed = unsteeredMemory(m.eff), m.claimed
		steers = true
	default:
		tc.memory, tc.claimed = m.memory, m.claimed
	}
	if !ours {
		p.releaseSteering(tc, steers)
	}
}

// releaseSteering sets memory.high of a container to max, as the Stop of
// a manager does, if the steering record (steeredRecord) says that a
// manager of a previous process steered it, whatever its settings say now
// (steers: they steer it): the manager of a killed plugin left the
// memory.high of its last step, which nothing raises any more. The
// memory.high of a container that no manager steered (created while the
// plugin was down, or one that is not steered) is left alone: it may be
// someone else's (MemoryQoS). Without a record (legacy) the containers
// that their settings steer are released, as a started one may have had
// a manager. Its cpuset.mems and memory policies are left as they are.
// Caller holds p.mu.
func (p *nriPlugin) releaseSteering(tc *trackedContainer, steers bool) {
	dir, recorded := p.steered.left(tc.ref.ID)
	switch {
	case p.steered.legacy && steers && !tc.started:
		klog.V(3).Infof("NRI Synchronize: ctr=%s id=%s: steering not restarted, memory %s", tc.name(), tc.ref.ID, tc.memory)
		return
	case p.steered.legacy && steers:
		dir = tc.ref.CgroupPath
	case !recorded:
		if steers {
			klog.V(3).Infof("NRI Synchronize: ctr=%s id=%s: steering not restarted, memory %s; memory.high left alone: no manager steered it",
				tc.name(), tc.ref.ID, tc.memory)
		}
		return
	case dir == "":
		dir = tc.ref.CgroupPath
	}
	if dir == "" {
		klog.Warningf("NRI Synchronize: ctr=%s id=%s: steering not restarted, memory %s; memory.high not checked: no cgroup directory",
			tc.name(), tc.ref.ID, tc.memory)
		return
	}
	was, err := cgmpolmgr.Release(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		klog.V(3).Infof("NRI Synchronize: ctr=%s id=%s: steering not restarted, memory %s; no memory.high: %v",
			tc.name(), tc.ref.ID, tc.memory, err)
	case err != nil:
		klog.Warningf("NRI Synchronize: ctr=%s id=%s: steering not restarted, memory %s; removing memory.high failed: %v",
			tc.name(), tc.ref.ID, tc.memory, err)
	case was != "":
		klog.Infof("NRI Synchronize: ctr=%s id=%s: steering not restarted, memory %s; memory.high %s removed (max)",
			tc.name(), tc.ref.ID, tc.memory, was)
	default:
		klog.V(3).Infof("NRI Synchronize: ctr=%s id=%s: steering not restarted, memory %s; memory.high max",
			tc.name(), tc.ref.ID, tc.memory)
	}
}

// ContainerByPid implements nodeLender.
func (p *nriPlugin) ContainerByPid(pid int) (*containerRef, bool) {
	cgPath, err := pidCgroupDir(pid)
	if err != nil {
		klog.V(4).Infof("NRI lend: pid %d: %v", pid, err)
		return nil, false
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	var best *trackedContainer
	for _, tc := range p.ctrs {
		dir := tc.ref.CgroupPath
		match := dir != "" && (cgPath == dir || strings.HasPrefix(cgPath, dir+"/"))
		if !match && dir == "" && tc.ref.ID != "" {
			// cgroup not resolved: runtimes name the scope after the id
			// (cri-containerd-<id>.scope, crio-<id>.scope).
			match = strings.Contains(cgPath, tc.ref.ID)
		}
		if match && (best == nil || len(dir) > len(best.ref.CgroupPath)) {
			best = tc
		}
	}
	if best == nil {
		return nil, false
	}
	ref := best.snapshot()
	return &ref, true
}

// pidCgroupDir returns the absolute cgroup v2 directory of a process.
func pidCgroupDir(pid int) (string, error) {
	path := filepath.Join(procDir, fmt.Sprint(pid), "cgroup")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if rel, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join(cgroupRoot, rel), nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 entry in %s", path)
}

// lookup returns the newest container of the pod with the name.
// Caller holds p.mu.
func (p *nriPlugin) lookup(podUID, name string) *trackedContainer {
	var best *trackedContainer
	for _, tc := range p.ctrs {
		if tc.ref.PodUID == podUID && tc.ref.Name == name && (best == nil || tc.seq > best.seq) {
			best = tc
		}
	}
	return best
}

// Container implements nodeLender.
func (p *nriPlugin) Container(podUID, name string) (*containerRef, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	tc := p.lookup(podUID, name)
	if tc == nil {
		return nil, false
	}
	ref := tc.snapshot()
	return &ref, true
}

// LentNodes implements nodeLender.
func (p *nriPlugin) LentNodes(podUID, name string) []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	tc := p.lookup(podUID, name)
	if tc == nil {
		return nil
	}
	return tc.lent.nodes().List()
}

// OnContainerGone implements nodeLender.
func (p *nriPlugin) OnContainerGone(fn func(ref containerRef)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.goneFns = append(p.goneFns, fn)
}

// OnContainerStarted implements nodeLender.
func (p *nriPlugin) OnContainerStarted(fn func(ref containerRef)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.startedFns = append(p.startedFns, fn)
}

// LendNode implements nodeLender.
func (p *nriPlugin) LendNode(ctx context.Context, podUID, name string, node int, holder string) error {
	if node < 0 {
		return fmt.Errorf("invalid NUMA node %d", node)
	}
	return p.changeLend(ctx, podUID, name, node, holder, true)
}

// RevokeNode implements nodeLender.
func (p *nriPlugin) RevokeNode(ctx context.Context, podUID, name string, node int, holder string) error {
	if node < 0 {
		return fmt.Errorf("invalid NUMA node %d", node)
	}
	return p.changeLend(ctx, podUID, name, node, holder, false)
}

// changeLend adds (lend) or removes (!lend) holder of node in the lent
// nodes of a container and applies cpuset.mems = base + the nodes that
// have a holder through NRI. The node is a CXL node, so it is also
// dropped from the base set (it is there after a plugin restart, see
// Synchronize). The base of a fenced container is its own nodes without
// the fenced nodes, and its cpuset.mems has the CXL numa nodes of its
// results too (wantMems). The cpuset.mems of a steered container is not
// changed. A lend that the bookkeeping has is applied again when the
// cgroup of the container lacks it (an update before its start reached
// its spec only, see the header). A container that has not started has
// only the lends of its creation (seedLends): a lend of one of them is
// done, a revoke drops it, from the spec of a fenced container too.
func (p *nriPlugin) changeLend(ctx context.Context, podUID, name string, node int, holder string, lend bool) error {
	op := "revoke"
	if lend {
		op = "lend"
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p.lendMu.Lock()
	defer p.lendMu.Unlock()

	p.mu.Lock()
	if p.stub == nil {
		p.mu.Unlock()
		return fmt.Errorf("%s node %d: lending unavailable: NRI not connected", op, node)
	}
	p.initLendState()
	tc := p.lookup(podUID, name)
	if tc == nil {
		p.mu.Unlock()
		if !lend {
			klog.V(3).Infof("NRI lend: revoke node %d from pod %s container %s: container gone", node, podUID, name)
			return nil
		}
		return fmt.Errorf("lend node %d: container %q of pod %s not found", node, name, podUID)
	}
	ctrName, id := tc.name(), tc.ref.ID
	if lend && p.steeredLocked(tc) {
		p.mu.Unlock()
		return fmt.Errorf("lend node %d to %s: %w", node, ctrName, errSteered)
	}
	if !tc.started {
		seeded := tc.lent[node][holder]
		switch {
		case lend && seeded:
			p.mu.Unlock()
			klog.V(4).Infof("NRI lend: lend node %d for %s: ctr=%s: lent at its creation, not started yet", node, holder, ctrName)
			return nil
		case lend:
			p.mu.Unlock()
			return fmt.Errorf("lend node %d to %s: container not started yet", node, ctrName)
		case !seeded:
			p.mu.Unlock()
			return nil
		case tc.memory != memoryFenced:
			// its spec has the nodes of the runtime: lent by updates only
			tc.lent = tc.lent.set(node, tc.lent.with(node, holder, false))
			p.mu.Unlock()
			klog.V(3).Infof("NRI lend: revoke node %d for %s: ctr=%s: not started yet", node, holder, ctrName)
			return nil
		}
		// a fenced container created with the node: off its spec
	}

	nodeSet := cpuset.New(node)
	holders := tc.lent.with(node, holder, lend)
	lent := tc.lent.after(node, holders)
	var base cpuset.CPUSet
	var mems string
	var needed bool
	if tc.memory == memoryFenced || p.steeredLocked(tc) {
		var err error
		if base, mems, needed, err = p.fencedLend(tc, nodeSet, lent); err != nil {
			p.mu.Unlock()
			return fmt.Errorf("%s node %d: ctr=%s: %w", op, node, ctrName, err)
		}
	} else {
		base = tc.base.Difference(nodeSet)
		mems = base.Union(lent).String()
		needed = !sameSet(lent, tc.lent.nodes()) || !sameSet(base, tc.base)
		switch {
		case !lend && !needed && len(holders) == 0:
			// Not lent as far as we know, but a lend from before a plugin
			// restart that is not re-applied still shows in cpuset.mems.
			needed = cgroupMemsContain(tc.ref.CgroupPath, node)
		case lend && !needed:
			if missing := cgroupLacks(tc.ref.CgroupPath, lent); !missing.IsEmpty() {
				// lost only if an update had them (not a seeded lend:
				// lent at its creation without an update)
				if memsContain(tc.mems, missing) {
					klog.Infof("NRI lend: ctr=%s id=%s: the cpuset.mems of its cgroup lacks the lent nodes %s, updating again", ctrName, id, missing)
				}
				needed = true
			}
		}
	}
	if !needed {
		tc.lent = tc.lent.set(node, holders)
		p.mu.Unlock()
		klog.V(4).Infof("NRI lend: %s node %d for %s: ctr=%s: cpuset.mems unchanged (base=%s lent=%s, node holders %d)",
			op, node, holder, ctrName, base, lent, len(holders))
		return nil
	}
	if base.IsEmpty() {
		p.mu.Unlock()
		return fmt.Errorf("%s node %d: ctr=%s: base memory nodes unknown, refusing to set cpuset.mems without them",
			op, node, ctrName)
	}
	s := p.stub
	p.mu.Unlock()

	klog.V(3).Infof("NRI lend: %s node %d for %s: ctr=%s id=%s cpuset.mems=%s (base=%s lent=%s)", op, node, holder, ctrName, id, mems, base, lent)
	if err := updateMems(s, id, mems); err != nil {
		return fmt.Errorf("%s node %d: ctr=%s: %w", op, node, ctrName, err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if cur, ok := p.ctrs[id]; ok && cur == tc {
		tc.base = base
		tc.ref.BaseMems = base.String()
		tc.lent = tc.lent.set(node, holders)
		tc.mems = mems
	}
	return nil
}

// fencedLend returns, for a lend change of node (nodeSet) of a fenced
// container, its own nodes without the fenced nodes and node (base), its
// cpuset.mems with the nodes lent, and whether its cpuset.mems (curMems)
// changes. The cpuset.mems of a steered container never changes. Caller
// holds p.mu.
func (p *nriPlugin) fencedLend(tc *trackedContainer, nodeSet, lent cpuset.CPUSet) (cpuset.CPUSet, string, bool, error) {
	if p.steeredLocked(tc) {
		return tc.base, tc.mems, false, nil
	}
	own, err := ownMems(tc, p.memNodes())
	if err != nil {
		return cpuset.New(), "", false, fmt.Errorf("base memory nodes unknown: %w", err)
	}
	base := own.Difference(p.fence.Nodes()).Difference(nodeSet)
	want := base.Union(tc.claimed, lent)
	_, differ := p.memsDiffer(tc, want, "NRI lend")
	return base, want.String(), differ, nil
}

// memsDiffer returns the cpuset.mems of a container (curMems) and whether
// it is not want, and logs it when its cgroup has not got an update that
// the plugin has recorded. Caller holds p.mu.
func (p *nriPlugin) memsDiffer(tc *trackedContainer, want cpuset.CPUSet, prefix string) (string, bool) {
	cur := tc.curMems()
	if sameMems(want, cur) {
		return cur, false
	}
	if sameMems(want, tc.mems) {
		klog.Infof("%s: ctr=%s id=%s: the cpuset.mems of its cgroup is %q, not %s as updated, updating again",
			prefix, tc.name(), tc.ref.ID, cur, tc.mems)
	}
	return cur, true
}

// cgroupLacks returns the nodes that the cpuset.mems of the cgroup dir
// lacks, of its cpuset.mems.effective when its cpuset.mems is empty (it
// has the nodes of its parent); none when the cgroup cannot be read.
func cgroupLacks(dir string, nodes cpuset.CPUSet) cpuset.CPUSet {
	if dir == "" || nodes.IsEmpty() {
		return cpuset.New()
	}
	for _, file := range []string{"cpuset.mems", "cpuset.mems.effective"} {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return cpuset.New()
		}
		if s := strings.TrimSpace(string(data)); s != "" {
			set, err := cpuset.Parse(s)
			if err != nil {
				return cpuset.New()
			}
			return nodes.Difference(set)
		}
	}
	return cpuset.New()
}

// updateMems sets cpuset.mems of a container through NRI.
func updateMems(s nriStub, id, mems string) error {
	failed, err := s.UpdateContainers([]*api.ContainerUpdate{{
		ContainerId: id,
		Linux: &api.LinuxContainerUpdate{
			Resources: &api.LinuxResources{
				Cpu: &api.LinuxCPU{Mems: mems},
			},
		},
	}})
	if err != nil {
		return fmt.Errorf("NRI UpdateContainers(cpuset.mems=%s): %w", mems, err)
	}
	for _, f := range failed {
		if f.GetContainerId() == id {
			return fmt.Errorf("NRI UpdateContainers(cpuset.mems=%s): update failed in the runtime", mems)
		}
	}
	return nil
}

// memsContain tells whether the cpuset.mems mems has the nodes.
func memsContain(mems string, nodes cpuset.CPUSet) bool {
	set, err := cpuset.Parse(mems)
	return err == nil && nodes.IsSubsetOf(set)
}

// cgroupMemsContain tells whether cpuset.mems of a cgroup contains node.
func cgroupMemsContain(dir string, node int) bool {
	if dir == "" {
		return false
	}
	data, err := os.ReadFile(filepath.Join(dir, "cpuset.mems"))
	if err != nil {
		return false
	}
	set, err := cpuset.Parse(strings.TrimSpace(string(data)))
	return err == nil && set.Contains(node)
}

// sameSet compares sets by content (CPUSet.Equals tells a zero set
// from an empty one).
func sameSet(a, b cpuset.CPUSet) bool {
	return a.IsSubsetOf(b) && b.IsSubsetOf(a)
}

// steeredLocked tells whether cgmpolmgr steers the memory of a container
// or will at its start. Caller holds p.mu.
func (p *nriPlugin) steeredLocked(tc *trackedContainer) bool {
	id := tc.ref.ID
	return tc.memory == memorySteered || p.managers[id] != nil || p.pending[id].plan != nil
}

// memNodes returns the reader of the NUMA nodes with memory.
func (p *nriPlugin) memNodes() *memNodes {
	return &memNodes{path: p.hasMemory}
}

// memNodes reads the NUMA nodes with memory from a sysfs file, once.
type memNodes struct {
	path  string
	read  bool
	nodes cpuset.CPUSet
	err   error
}

// get returns the NUMA nodes with memory.
func (m *memNodes) get() (cpuset.CPUSet, error) {
	if !m.read {
		m.read = true
		data, err := os.ReadFile(m.path)
		if err == nil {
			m.nodes, err = cpuset.Parse(strings.TrimSpace(string(data)))
		}
		if err == nil && m.nodes.IsEmpty() {
			err = fmt.Errorf("no NUMA nodes with memory in %s", m.path)
		}
		if err != nil {
			m.err = fmt.Errorf("nodes with memory: %w", err)
		}
	}
	return m.nodes, m.err
}

// ownMems returns the memory nodes a container has of its own: the
// cpuset.mems of its spec, or the nodes with memory (mem) when the spec
// has none.
func ownMems(tc *trackedContainer, mem *memNodes) (cpuset.CPUSet, error) {
	if tc.mems == "" {
		return mem.get()
	}
	own, err := cpuset.Parse(tc.mems)
	if err != nil {
		return cpuset.New(), fmt.Errorf("invalid cpuset.mems %q: %w", tc.mems, err)
	}
	return own, nil
}

// wantMems returns the memory nodes of a fenced container: its own nodes
// without the fenced nodes, the nodes of its claims and the lent nodes.
// Returns an error if its own nodes are unknown or nothing is left.
//   - mem: the nodes with memory, its own nodes when its spec has none
func wantMems(tc *trackedContainer, fenced, lent cpuset.CPUSet, mem *memNodes) (cpuset.CPUSet, error) {
	own, err := ownMems(tc, mem)
	if err != nil {
		return cpuset.New(), err
	}
	want := own.Difference(fenced).Union(tc.claimed, lent)
	if want.IsEmpty() {
		return want, fmt.Errorf("no memory nodes left of %s without the fenced nodes %s", own, fenced)
	}
	return want, nil
}

// sameMems tells whether cpuset.mems has the nodes of want.
func sameMems(want cpuset.CPUSet, mems string) bool {
	set, err := cpuset.Parse(mems)
	return err == nil && sameSet(want, set)
}

// fenceCreated returns the cpuset.mems that a new container gets ("" for
// no change, the spec's is kept) and the fenced nodes, and records the
// cpuset.mems. Caller holds p.mu.
func (p *nriPlugin) fenceCreated(tc *trackedContainer) (string, cpuset.CPUSet) {
	fenced := p.fence.Nodes()
	if tc.memory != memoryFenced || fenced.IsEmpty() || p.steeredLocked(tc) {
		return "", fenced
	}
	want, err := wantMems(tc, fenced, tc.lent.nodes(), p.memNodes())
	if err != nil {
		klog.Warningf("NRI CreateContainer: ctr=%s: cpuset.mems left as it is: %v", tc.name(), err)
		return "", fenced
	}
	if sameMems(want, tc.mems) {
		return "", fenced
	}
	tc.mems = want.String()
	return tc.mems, fenced
}

// fenceAtStart tells whether a started container gets a fence pass of its
// own (fenceStarted): it is fenced and not steered, there are fenced nodes
// and fencing of running containers is ready. Updates of the container
// before its start may have reached its spec only, also that of a pass
// while the plugin synchronized as the runtime was creating its task.
// Caller holds p.mu.
func (p *nriPlugin) fenceAtStart(tc *trackedContainer) bool {
	return p.fenceReady && tc.memory == memoryFenced && !p.fence.Nodes().IsEmpty() && !p.steeredLocked(tc)
}

// fenceStarted starts a fence pass of one started container in the
// background: its cgroup gets its wantMems if it has not got it. Caller
// holds p.mu.
func (p *nriPlugin) fenceStarted(id string) {
	p.fenceWG.Add(1)
	go func() {
		defer p.fenceWG.Done()
		p.fencePass(context.Background(), id)
	}()
}

// LendsRestored tells that the lends of a restarted plugin are applied
// again. Fencing of running containers starts when NRI has synchronized
// too. Not part of nodeLender, like WaitSynchronized.
func (p *nriPlugin) LendsRestored() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLendState()
	if p.lendsRestored {
		return
	}
	p.lendsRestored = true
	p.startFencing()
}

// startFencing makes fencing of running containers ready when NRI has
// synchronized and the lends are restored, and then starts a fence pass
// in the background. Caller holds p.mu.
func (p *nriPlugin) startFencing() {
	if p.fence == nil || !p.lendsRestored {
		return
	}
	select {
	case <-p.syncedC:
	default:
		return
	}
	if !p.fenceReady {
		p.fenceReady = true
		klog.V(3).Info("NRI fence: lends restored, fencing running containers")
	}
	p.fenceWG.Add(1)
	go func() {
		defer p.fenceWG.Done()
		p.fenceContainers(context.Background())
	}()
}

// fenceUpdate is a cpuset.mems update of a container by a fence pass.
type fenceUpdate struct {
	tc        *trackedContainer
	was, mems string
}

// fenceContainers implements fenceApplier: when fencing of running
// containers is ready, it sets cpuset.mems of the tracked containers that
// are fenced and not steered to wantMems where that changes it (curMems:
// the cgroup of a started container), with one NRI UpdateContainers.
// Created containers are included. Failed updates are logged and tried
// again by the next pass.
func (p *nriPlugin) fenceContainers(ctx context.Context) {
	p.fencePass(ctx, "")
}

// fencePass is fenceContainers of the container with the id only, of all
// containers if id is "".
func (p *nriPlugin) fencePass(ctx context.Context, only string) {
	if ctx.Err() != nil {
		return
	}
	// Not waiting for a lend when not ready: readiness never ends.
	p.mu.Lock()
	ready := p.fenceReady
	p.mu.Unlock()
	if !ready {
		return
	}
	p.lendMu.Lock()
	defer p.lendMu.Unlock()

	p.mu.Lock()
	fenced := p.fence.Nodes()
	if !p.fenceReady || p.stub == nil || fenced.IsEmpty() {
		p.mu.Unlock()
		return
	}
	var changes []fenceUpdate
	var updates []*api.ContainerUpdate
	mem := p.memNodes()
	for _, tc := range p.sortedContainers() {
		if (only != "" && tc.ref.ID != only) || tc.memory != memoryFenced || p.steeredLocked(tc) {
			continue
		}
		want, err := wantMems(tc, fenced, tc.lent.nodes(), mem)
		if err != nil {
			klog.Warningf("NRI fence: ctr=%s id=%s: %v", tc.name(), tc.ref.ID, err)
			continue
		}
		was, differ := p.memsDiffer(tc, want, "NRI fence")
		if !differ {
			continue
		}
		u := &api.ContainerUpdate{ContainerId: tc.ref.ID}
		u.SetLinuxCPUSetMems(want.String())
		updates = append(updates, u)
		changes = append(changes, fenceUpdate{tc: tc, was: was, mems: want.String()})
	}
	s := p.stub
	p.mu.Unlock()
	if len(updates) == 0 {
		return
	}

	notUpdated, err := s.UpdateContainers(updates)
	failed := make(map[string]bool, len(notUpdated))
	for _, u := range notUpdated {
		failed[u.GetContainerId()] = true
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	nFailed := 0
	for _, c := range changes {
		id := c.tc.ref.ID
		switch {
		case err != nil:
			klog.Warningf("NRI fence: ctr=%s id=%s: %v", c.tc.name(), id,
				fmt.Errorf("NRI UpdateContainers(cpuset.mems=%s): %w", c.mems, err))
		case failed[id]:
			klog.Warningf("NRI fence: ctr=%s id=%s: %v", c.tc.name(), id,
				fmt.Errorf("NRI UpdateContainers(cpuset.mems=%s): update failed in the runtime", c.mems))
		default:
			if cur, ok := p.ctrs[id]; ok && cur == c.tc {
				c.tc.mems = c.mems
			}
			klog.V(3).Infof("NRI fence: ctr=%s id=%s cpuset.mems=%s (was %q, fenced nodes %s)",
				c.tc.name(), id, c.mems, c.was, fenced)
			continue
		}
		nFailed++
	}
	klog.Infof("NRI fence: %d containers updated, %d failed (fenced nodes %s)", len(changes)-nFailed, nFailed, fenced)
}

// sortedContainers returns the tracked containers in creation order.
// Caller holds p.mu.
func (p *nriPlugin) sortedContainers() []*trackedContainer {
	ctrs := make([]*trackedContainer, 0, len(p.ctrs))
	for _, tc := range p.ctrs {
		ctrs = append(ctrs, tc)
	}
	sort.Slice(ctrs, func(i, j int) bool { return ctrs[i].seq < ctrs[j].seq })
	return ctrs
}
