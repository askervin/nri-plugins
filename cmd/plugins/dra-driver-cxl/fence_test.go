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
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/utils/cpuset"

	cxlapi "github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// fenceRecorder is a fenceApplier that records the fenced nodes of every
// pass, and what at calls.
type fenceRecorder struct {
	mu    sync.Mutex
	fence *nodeFence
	at    func() string
	calls []string
}

func (r *fenceRecorder) fenceContainers(context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	call := r.fence.Nodes().String()
	if r.at != nil {
		call += " " + r.at()
	}
	r.calls = append(r.calls, call)
}

func (r *fenceRecorder) taken() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.calls
	r.calls = nil
	return out
}

// newRecordedFence returns an allowed-mems fence whose passes are recorded.
func newRecordedFence(at func() string) (*nodeFence, *fenceRecorder) {
	f := newNodeFence(containerMemoryAllowedMems)
	r := &fenceRecorder{fence: f, at: at}
	f.setApplier(r)
	return f, r
}

// newFenceEnv returns an ltEnv in mode allowed-mems with the nodes with
// memory hasMemory and the fenced nodes fenced (without a pass).
func newFenceEnv(t *testing.T, hasMemory string, fenced ...int) *ltEnv {
	t.Helper()
	e := newLtEnv(t)
	e.p.fence = newNodeFence(containerMemoryAllowedMems)
	e.p.fence.seed(cpuset.New(fenced...))
	e.p.fence.setApplier(e.p)
	e.p.hasMemory = filepath.Join(e.root, "has_memory")
	e.hasMemory(hasMemory)
	return e
}

// hasMemory sets the nodes with memory, "" for none (unreadable).
func (e *ltEnv) hasMemory(nodes string) {
	e.t.Helper()
	if nodes == "" {
		_ = os.Remove(e.p.hasMemory)
		return
	}
	if err := os.WriteFile(e.p.hasMemory, []byte(nodes+"\n"), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

// passes waits for the fence passes running in the background.
func (e *ltEnv) passes() {
	e.p.fenceWG.Wait()
}

// specMems sets cpuset.mems of the spec of a container.
func specMems(ctr *api.Container, mems string) *api.Container {
	ctr.Linux = &api.LinuxContainer{Resources: &api.LinuxResources{Cpu: &api.LinuxCPU{Mems: mems}}}
	return ctr
}

// withClaims adds the claim markers of the claims to the env of a container.
func withClaims(ctr *api.Container, uids ...string) *api.Container {
	for _, uid := range uids {
		ctr.Env = append(ctr.Env, claimEnvVarName(uid)+"=1")
	}
	return ctr
}

// createMems runs CreateContainer and returns the cpuset.mems of the
// adjustment, "-" for no adjustment.
func (e *ltEnv) createMems(pod *api.PodSandbox, ctr *api.Container) string {
	e.t.Helper()
	adj, upd, err := e.p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		e.t.Fatal(err)
	}
	if len(upd) != 0 {
		e.t.Fatalf("CreateContainer returned updates %v", upd)
	}
	if adj == nil {
		return "-"
	}
	return adj.GetLinux().GetResources().GetCpu().GetMems()
}

// trackedMems returns the recorded cpuset.mems of a container.
func (e *ltEnv) trackedMems(id string) string {
	e.p.mu.Lock()
	defer e.p.mu.Unlock()
	return e.p.ctrs[id].mems
}

// fenceClaims is a node state with prepared claims: steered DRAM, a dax
// slice and a numa slice of a local memdev.
func fenceClaims() *nodeState {
	return &nodeState{baseState: &baseState{}, preparedClaims: PreparedClaimsInfo{
		"dram": {ClaimName: "ns/dram", Devices: []PreparedDeviceInfo{
			{DeviceType: device.DeviceTypeDRAM, Mode: cxlapi.ModeNUMA, NUMANodes: []int{0}, ConsumedBytes: 1 << 30},
		}},
		"dax": {ClaimName: "ns/dax", Devices: []PreparedDeviceInfo{
			{DeviceType: device.DeviceTypeMemdev, Mode: cxlapi.ModeDax, NUMANodes: []int{2}, ConsumedBytes: 1 << 30},
		}},
		"numa": {ClaimName: "ns/numa", Devices: []PreparedDeviceInfo{
			{DeviceType: device.DeviceTypeMemdev, Mode: cxlapi.ModeNUMA, NUMANodes: []int{2}, ConsumedBytes: 1 << 30},
		}},
		"region": {ClaimName: "ns/region", Devices: []PreparedDeviceInfo{
			{DeviceType: device.DeviceTypeRegion, Mode: cxlapi.ModeNUMA, NUMANodes: []int{4}, ConsumedBytes: 1 << 30},
		}},
	}}
}

func TestFenceNodes(t *testing.T) {
	ctx := context.Background()
	// nil: containerMemory none
	var none *nodeFence
	none.Fence(ctx, 2)
	none.seed(cpuset.New(2))
	none.setApplier(nil)
	none.setNoNRI()
	if !none.Nodes().IsEmpty() || none.mode() != containerMemoryNone || newNodeFence(containerMemoryNone) != nil {
		t.Fatalf("none fences %s", none.Nodes())
	}

	f, r := newRecordedFence(nil)
	if f.mode() != containerMemoryAllowedMems {
		t.Fatalf("mode %s", f.mode())
	}
	f.seed(cpuset.New(3))
	f.Fence(ctx, -1)
	f.Fence(ctx, 2)
	f.Fence(ctx, 2) // fenced already
	f.Fence(ctx, 3) // seeded
	if got := r.taken(); !reflect.DeepEqual(got, []string{"2-3"}) {
		t.Fatalf("passes %v", got)
	}
	// without NRI the node is recorded only
	f.setNoNRI()
	f.Fence(ctx, 5)
	if got := r.taken(); len(got) != 0 || f.Nodes().String() != "2-3,5" {
		t.Fatalf("passes %v, nodes %s", got, f.Nodes())
	}
}

func TestFencePreparedNodes(t *testing.T) {
	pool := &poolDriver{claimNodes: map[string][]int{"p1": {3}, "p2": {3, 6}}}
	if got := preparedNodes(fenceClaims(), pool).String(); got != "2-3,6" {
		t.Fatalf("prepared nodes %s, expected 2-3,6", got)
	}
	if got := preparedNodes(nil, nil); !got.IsEmpty() {
		t.Fatalf("prepared nodes %s of nothing", got)
	}
}

func TestFenceWantMems(t *testing.T) {
	mem := func(path string) *memNodes { return &memNodes{path: path} }
	dir := t.TempDir()
	hasMem := filepath.Join(dir, "has_memory")
	noErr(t, os.WriteFile(hasMem, []byte("0-2\n"), 0o644))
	for _, tc := range []struct {
		mems    string // of the spec
		claimed cpuset.CPUSet
		lent    cpuset.CPUSet
		path    string
		want    string // "" for an error
	}{
		{"", cpuset.New(), cpuset.New(), hasMem, "0-1"},
		{"0", cpuset.New(), cpuset.New(), hasMem, "0"},
		{"0-2", cpuset.New(), cpuset.New(), hasMem, "0-1"},
		{"", cpuset.New(), cpuset.New(2), hasMem, "0-2"},
		{"0-1,2", cpuset.New(), cpuset.New(2), hasMem, "0-2"},
		{"", cpuset.New(3), cpuset.New(), hasMem, "0-1,3"},
		{"1", cpuset.New(3), cpuset.New(2), hasMem, "1-3"},
		{"0", cpuset.New(), cpuset.New(), filepath.Join(dir, "none"), "0"},
		{"", cpuset.New(), cpuset.New(), filepath.Join(dir, "none"), ""},
		{"2", cpuset.New(), cpuset.New(), hasMem, ""},
		{"x", cpuset.New(), cpuset.New(), hasMem, ""},
	} {
		c := &trackedContainer{mems: tc.mems, claimed: tc.claimed}
		got, err := wantMems(c, cpuset.New(2, 3), tc.lent, mem(tc.path))
		if (err != nil) != (tc.want == "") || got.String() != tc.want {
			t.Errorf("spec %q claimed %s lent %s: %s %v, expected %q", tc.mems, tc.claimed, tc.lent, got, err, tc.want)
		}
	}
}

func TestFenceCreateContainer(t *testing.T) {
	e := newFenceEnv(t, "0-2")
	e.p.state = fenceClaims()
	e.p.poolNodes = func(uid string) []int { return map[string][]int{"pool": {3}}[uid] }
	pod := ltPod("u1")

	// nothing fenced: no adjustment
	if got := e.createMems(pod, ltCtr(pod, "c0", "a", 0)); got != "-" || e.trackedMems("c0") != "" {
		t.Fatalf("adjustment %s, mems %q without fenced nodes", got, e.trackedMems("c0"))
	}

	e.p.fence.seed(cpuset.New(2, 3))
	for _, tc := range []struct {
		ctr  *api.Container
		want string // adjustment, "-" for none
		mems string // recorded
	}{
		{ltCtr(pod, "c1", "a", 0), "0-1", "0-1"},
		{specMems(ltCtr(pod, "c2", "a", 0), "0-1"), "-", "0-1"},
		{specMems(ltCtr(pod, "c3", "a", 0), "0-2"), "0-1", "0-1"},
		{specMems(ltCtr(pod, "c4", "a", 0), "1"), "-", "1"},
		// steered: left to cgmpolmgr
		{withClaims(ltCtr(pod, "c5", "a", 0), "dram"), "-", ""},
		{withClaims(ltCtr(pod, "c6", "a", 0), "numa", "dax"), "-", ""},
		// dax claims are no memory nodes
		{withClaims(ltCtr(pod, "c7", "a", 0), "dax"), "0-1", "0-1"},
		// pool numa claims get their node
		{withClaims(ltCtr(pod, "c8", "a", 0), "pool"), "0-1,3", "0-1,3"},
		{withClaims(specMems(ltCtr(pod, "c9", "a", 0), "0-1,3"), "pool"), "-", "0-1,3"},
		// an unknown claim
		{withClaims(ltCtr(pod, "c10", "a", 0), "gone"), "0-1", "0-1"},
	} {
		id := tc.ctr.GetId()
		if got := e.createMems(pod, tc.ctr); got != tc.want {
			t.Errorf("%s: adjustment %s, expected %s", id, got, tc.want)
		}
		if got := e.trackedMems(id); got != tc.mems {
			t.Errorf("%s: recorded mems %q, expected %q", id, got, tc.mems)
		}
	}

	// own nodes unknown: no adjustment
	e.hasMemory("")
	if got := e.createMems(pod, ltCtr(pod, "c11", "a", 0)); got != "-" {
		t.Fatalf("adjustment %s without nodes with memory", got)
	}
	e.passes()
	e.expectUpdates()

	// containerMemory none
	n := newLtEnv(t)
	if got := n.createMems(pod, specMems(ltCtr(pod, "c1", "a", 0), "0-2")); got != "-" {
		t.Fatalf("adjustment %s in mode none", got)
	}
}

func TestFencePass(t *testing.T) {
	e := newFenceEnv(t, "0-2", 2)
	e.p.state = fenceClaims()
	ctx := context.Background()
	p1, p2 := ltPod("u1"), ltPod("u2")
	e.proc(101, "kubepods/u1/c1", "0-2", "")
	e.proc(102, "kubepods/u1/c3", "0-2", "")
	c1 := ltCtr(p1, "c1", "app", 101)
	c1.State = api.ContainerState_CONTAINER_RUNNING
	c2 := ltCtr(p1, "c2", "init", 0)
	c2.State = api.ContainerState_CONTAINER_CREATED
	c3 := withClaims(ltCtr(p1, "c3", "steered", 102), "dram")
	c3.State = api.ContainerState_CONTAINER_RUNNING
	c4 := specMems(ltCtr(p2, "c4", "pinned", 0), "0")
	c4.State = api.ContainerState_CONTAINER_CREATED
	c5 := ltCtr(p2, "c5", "flaky", 0)
	c5.State = api.ContainerState_CONTAINER_CREATED
	ctrs := []*api.Container{c1, c2, c3, c4, c5}
	resync := func() {
		t.Helper()
		if _, err := e.p.Synchronize(ctx, []*api.PodSandbox{p1, p2}, ctrs); err != nil {
			t.Fatal(err)
		}
		e.passes()
	}

	// not ready before the lends are restored: Fence only records
	resync()
	e.p.fence.Fence(ctx, 3)
	e.expectUpdates()
	if got := e.p.fence.Nodes().String(); got != "2-3" {
		t.Fatalf("fenced %s", got)
	}

	// running and created containers, not the steered one, not the one
	// whose nodes do not change; a failed update is tried again
	e.stub.failIDs = map[string]bool{"c5": true}
	e.p.LendsRestored()
	e.passes()
	e.expectUpdates("c1 mems=0-1", "c2 mems=0-1")
	if got := e.trackedMems("c5"); got != "" {
		t.Fatalf("failed update recorded: %q", got)
	}
	e.stub.failIDs = nil
	e.p.LendsRestored() // once only
	e.passes()
	e.expectUpdates()
	e.p.fence.Fence(ctx, 4)
	e.expectUpdates("c5 mems=0-1")

	// the runtime has the updates: nothing to do at a reconnect
	for _, c := range []*api.Container{c1, c2, c5} {
		specMems(c, "0-1")
	}
	resync()
	e.expectUpdates()
	// a reconnect after an update was lost does it again
	specMems(c2, "")
	resync()
	e.expectUpdates("c2 mems=0-1")

	// an error of UpdateContainers fails all, the next pass repeats
	specMems(c1, "0-2")
	specMems(c2, "0-2")
	e.stub.err = errors.New("ttrpc closed")
	resync()
	e.expectUpdates()
	e.stub.err = nil
	e.p.fence.Fence(ctx, 5)
	e.expectUpdates("c1 mems=0-1", "c2 mems=0-1")

	// a new container is fenced at creation, the pass leaves it be
	if got := e.createMems(p2, ltCtr(p2, "c6", "new", 0)); got != "0-1" {
		t.Fatalf("adjustment %s", got)
	}
	e.p.fence.Fence(ctx, 6)
	e.expectUpdates()
}

func TestFenceLend(t *testing.T) {
	e := newFenceEnv(t, "0-2", 2)
	ctx := context.Background()
	if _, err := e.p.Synchronize(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	e.p.LendsRestored()
	e.passes()
	// fenced at creation
	e.run(ltPod("u1"), "c1", "app", 101, "0-2")
	if got := e.trackedMems("c1"); got != "0-1" {
		t.Fatalf("mems %q after creation", got)
	}
	e.expectUpdates()

	// the DRAM nodes and the lent node, back to the DRAM nodes
	noErr(t, e.p.LendNode(ctx, "u1", "app", 2, "l1"))
	e.expectUpdates("c1 mems=0-2")
	noErr(t, e.p.LendNode(ctx, "u1", "app", 2, "l2"))
	e.expectUpdates()
	if ref, _ := e.p.Container("u1", "app"); ref.BaseMems != "0-1" || e.trackedMems("c1") != "0-2" {
		t.Fatalf("BaseMems %q, mems %q", ref.BaseMems, e.trackedMems("c1"))
	}
	// a pass keeps the lent node
	e.p.fence.Fence(ctx, 3)
	e.expectUpdates()
	noErr(t, e.p.RevokeNode(ctx, "u1", "app", 2, "l1"))
	e.expectUpdates()
	noErr(t, e.p.RevokeNode(ctx, "u1", "app", 2, "l2"))
	e.expectUpdates("c1 mems=0-1")
	noErr(t, e.p.RevokeNode(ctx, "u1", "app", 2, "l2"))
	e.expectUpdates()

	// own nodes unknown
	e.hasMemory("")
	e.run(ltPod("u2"), "c2", "app", 201, "0-2")
	if err := e.p.LendNode(ctx, "u2", "app", 2, "l1"); err == nil || !strings.Contains(err.Error(), "base memory nodes unknown") {
		t.Fatalf("lend without own nodes: %v", err)
	}
	e.expectUpdates()

	// steered: never updated
	e.hasMemory("0-2")
	e.p.mu.Lock()
	e.p.ctrs["c2"].steered = true
	e.p.mu.Unlock()
	noErr(t, e.p.RevokeNode(ctx, "u2", "app", 2, "l1"))
	e.p.fence.Fence(ctx, 4)
	e.expectUpdates()
}

// TestFenceRestart checks that a restarted plugin keeps the lent node of a
// borrower: the lend is re-applied before the first pass.
func TestFenceRestart(t *testing.T) {
	e := newFenceEnv(t, "0-2", 2)
	ctx := context.Background()
	p1, p2 := ltPod("u1"), ltPod("u2")
	e.proc(101, "kubepods/u1/c1", "0-2", "0-2")
	e.proc(201, "kubepods/u2/c2", "0-2", "")
	c1 := specMems(ltCtr(p1, "c1", "app", 101), "0-2")
	c1.State = api.ContainerState_CONTAINER_RUNNING
	c2 := ltCtr(p2, "c2", "app", 201)
	c2.State = api.ContainerState_CONTAINER_RUNNING
	if _, err := e.p.Synchronize(ctx, []*api.PodSandbox{p1, p2}, []*api.Container{c1, c2}); err != nil {
		t.Fatal(err)
	}
	e.passes()
	e.expectUpdates()
	noErr(t, e.p.LendNode(ctx, "u1", "app", 2, "l1"))
	e.expectUpdates()
	e.p.LendsRestored()
	e.passes()
	e.expectUpdates("c2 mems=0-1")
}

func TestFenceLocalBeforeOnline(t *testing.T) {
	f := newFakeLocalSys(t)
	a := f.allocator(t, t.TempDir())
	// the state of the memory blocks at each pass
	online := func() string {
		m, _ := filepath.Glob(f.p("devices/system/memory/memory*/state"))
		n := 0
		for _, path := range m {
			if b, _ := os.ReadFile(path); strings.HasPrefix(string(b), "online") {
				n++
			}
		}
		return "online=" + strings.Repeat("x", n)
	}
	fence, r := newRecordedFence(online)
	a.fence = fence
	acquire(t, a, "u1", cxlapi.ModeDax, localBlockSize)
	if got := r.taken(); len(got) != 0 {
		t.Fatalf("dax slice fenced: %v", got)
	}
	acquire(t, a, "u2", cxlapi.ModeNUMA, localBlockSize)
	if got := r.taken(); !reflect.DeepEqual(got, []string{"2 online="}) {
		t.Fatalf("passes %v, expected one before onlining", got)
	}
	f.wantMemoryBlocks(t, "online_movable", 75)
	acquire(t, a, "u3", cxlapi.ModeNUMA, localBlockSize)
	if got := r.taken(); len(got) != 0 {
		t.Fatalf("fenced node fenced again: %v", got)
	}
}

func TestFencePoolBeforeOnline(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ee0001")
	p := e.driver(t)
	fence, r := newRecordedFence(func() string { return e.f.read("devices/system/memory/memory74/state") })
	p.fence = fence

	noErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err)
	if got := r.taken(); !reflect.DeepEqual(got, []string{"2 offline"}) {
		t.Fatalf("passes %v, expected one before onlining", got)
	}
	e.f.wantBlocks(t, "online_movable")
	if got := p.ClaimNodes("u1"); !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("claim nodes %v", got)
	}
	if got := p.numaNodes(); !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("numa nodes %v", got)
	}
	if got := preparedNodes(nil, e.driver(t)).String(); got != "2" {
		t.Fatalf("prepared nodes after a restart %s", got)
	}
	noErr(t, unprepare(t, p, "u1"))
	if got := p.ClaimNodes("u1"); got != nil {
		t.Fatalf("claim nodes %v after unprepare", got)
	}
	var none *poolDriver
	if none.ClaimNodes("u1") != nil || none.numaNodes() != nil {
		t.Fatal("nodes of a disabled pool driver")
	}

	// dax devices are not fenced
	e2 := newPoolTestEnv(t)
	e2.f.plug("0xc1ee0001")
	p2 := e2.driver(t)
	fence2, r2 := newRecordedFence(nil)
	p2.fence = fence2
	claim := withConfig(poolClaim("u2", "c2", "pooled0", exclusiveData), resourceapi.AllocationConfigSourceClaim, nil, daxConfig)
	noErr(t, prepare(t, p2, claim).Err)
	if got := r2.taken(); len(got) != 0 || p2.ClaimNodes("u2") != nil {
		t.Fatalf("dax device fenced: %v, claim nodes %v", got, p2.ClaimNodes("u2"))
	}
}

// TestFenceConcurrent checks that a Fence of a node that another Fence is
// fencing returns only after the containers have been updated.
func TestFenceConcurrent(t *testing.T) {
	e := newFenceEnv(t, "0-2")
	ctx := context.Background()
	p := ltPod("u1")
	c1 := ltCtr(p, "c1", "app", 0)
	c1.State = api.ContainerState_CONTAINER_CREATED
	if _, err := e.p.Synchronize(ctx, []*api.PodSandbox{p}, []*api.Container{c1}); err != nil {
		t.Fatal(err)
	}
	e.p.LendsRestored()
	e.passes()
	e.expectUpdates()

	e.stub.entered, e.stub.gate = make(chan struct{}, 4), make(chan struct{})
	first, second := make(chan struct{}), make(chan struct{})
	go func() { e.p.fence.Fence(ctx, 2); close(first) }()
	<-e.stub.entered
	go func() { e.p.fence.Fence(ctx, 2); close(second) }()
	select {
	case <-second:
		t.Fatal("the second Fence returned before the update of the first")
	case <-time.After(50 * time.Millisecond):
	}
	close(e.stub.gate)
	<-first
	<-second
	e.expectUpdates("c1 mems=0-1")
}

// TestFenceMissedAtStart checks that a container whose update failed
// before the runtime knew it gets the update at its start.
func TestFenceMissedAtStart(t *testing.T) {
	e := newFenceEnv(t, "0-2")
	ctx := context.Background()
	if _, err := e.p.Synchronize(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	e.p.LendsRestored()
	e.passes()
	pod := ltPod("u1")
	e.proc(101, "kubepods/u1/c1", "0-2", "")
	c1 := ltCtr(pod, "c1", "app", 101)
	if got := e.createMems(pod, c1); got != "-" {
		t.Fatalf("adjustment %s without fenced nodes", got)
	}
	// created, not in the runtime's store yet
	e.stub.failIDs = map[string]bool{"c1": true}
	e.p.fence.Fence(ctx, 2)
	e.expectUpdates()
	e.stub.failIDs = nil
	noErr(t, e.p.StartContainer(ctx, pod, c1))
	e.wait(e.start, "c1")
	e.passes()
	e.expectUpdates("c1 mems=0-1")

	// fenced at creation: nothing at the start
	e.proc(102, "kubepods/u1/c2", "0-1", "0-1")
	c2 := ltCtr(pod, "c2", "app2", 102)
	if got := e.createMems(pod, c2); got != "0-1" {
		t.Fatalf("adjustment %s", got)
	}
	noErr(t, e.p.StartContainer(ctx, pod, c2))
	e.wait(e.start, "c2")
	e.passes()
	e.expectUpdates()
}
