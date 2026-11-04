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
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/cpuset"

	cxlapi "github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
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
	f := newNodeFence(config.FencingAllowedMems)
	r := &fenceRecorder{fence: f, at: at}
	f.setApplier(r)
	return f, r
}

// newFenceEnv returns an ltEnv in mode allowed-mems with the nodes with
// memory hasMemory and the fenced nodes fenced (without a pass).
func newFenceEnv(t *testing.T, hasMemory string, fenced ...int) *ltEnv {
	t.Helper()
	e := newLtEnv(t)
	e.p.defaults = config.Container{}
	e.p.fence = newNodeFence(config.FencingAllowedMems)
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

// withClaims adds the markers of the results 0 of the claims to the env of
// a container.
func withClaims(ctr *api.Container, uids ...string) *api.Container {
	for _, uid := range uids {
		ctr.Env = append(ctr.Env, resultEnvVarName(uid, 0)+"=1")
	}
	return ctr
}

// optIn returns the container settings of a result with the steering
// policy from a claim.
func optIn(policy string) config.ResultSettings {
	return config.ResultSettings{
		Container: &config.Container{Steering: &config.Steering{Policy: policy}},
		Origins:   map[string]string{config.FieldPolicy: "claim ns/x request mem"},
	}
}

// createMems runs CreateContainer and returns the cpuset.mems of the
// adjustment, "-" for no adjustment. The updates of the container reach
// only its spec until it has started (startCtr), as in containerd.
func (e *ltEnv) createMems(pod *api.PodSandbox, ctr *api.Container) string {
	e.t.Helper()
	adj, upd, err := e.p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		e.t.Fatal(err)
	}
	e.stub.setSpecOnly(ctr.GetId(), true)
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

// fenceClaims is a node state with prepared claims: DRAM, a dax slice, a
// numa slice of a local memdev and a region, and DRAM and a numa slice
// that opt in to steering.
func fenceClaims() *nodeState {
	return &nodeState{baseState: &baseState{}, preparedClaims: PreparedClaimsInfo{
		"dram-auto": {ClaimName: "ns/dram-auto", Devices: []PreparedDeviceInfo{
			{DeviceType: device.DeviceTypeDRAM, Mode: cxlapi.ModeNUMA, NUMANodes: []int{0}, ConsumedBytes: 1 << 30, ResultSettings: optIn(config.PolicyAuto)},
		}},
		"numa-auto": {ClaimName: "ns/numa-auto", Devices: []PreparedDeviceInfo{
			{DeviceType: device.DeviceTypeMemdev, Mode: cxlapi.ModeNUMA, NUMANodes: []int{2}, ConsumedBytes: 1 << 30, ResultSettings: optIn(config.PolicyAuto)},
		}},
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
	// nil: fencing none
	var none *nodeFence
	none.Fence(ctx, 2)
	none.seed(cpuset.New(2))
	none.setApplier(nil)
	none.setNoNRI()
	if !none.Nodes().IsEmpty() || none.mode() != config.FencingNone || newNodeFence(config.FencingNone) != nil {
		t.Fatalf("none fences %s", none.Nodes())
	}

	f, r := newRecordedFence(nil)
	if f.mode() != config.FencingAllowedMems {
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
	pool := &poolDriver{results: map[string][]poolResult{
		"p1": {{Mode: cxlapi.ModeNUMA, Node: 3}},
		"p2": {{Mode: cxlapi.ModeNUMA, Node: 3}, {Index: 1, Mode: cxlapi.ModeNUMA, Node: 6}, {Index: 2, Mode: cxlapi.ModeDax, Node: -1}},
	}}
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
	e.p.poolResults = func(uid string) []poolResult {
		return map[string][]poolResult{"pool": {{Mode: cxlapi.ModeNUMA, Node: 3, Size: 1 << 30}}}[uid]
	}
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
		{withClaims(ltCtr(pod, "c5", "a", 0), "dram-auto"), "-", ""},
		{withClaims(ltCtr(pod, "c6", "a", 0), "numa-auto", "dax"), "-", ""},
		// not steered: DRAM is capacity only, numa slices and regions
		// give their nodes
		{withClaims(ltCtr(pod, "c5n", "a", 0), "dram"), "0-1", "0-1"},
		{withClaims(ltCtr(pod, "c6n", "a", 0), "numa", "dax"), "0-2", "0-2"},
		{withClaims(ltCtr(pod, "c6r", "a", 0), "region"), "0-1,4", "0-1,4"},
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

	// fencing none
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
	c3 := withClaims(ltCtr(p1, "c3", "steered", 102), "dram-auto")
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

	// running and created containers, also c3 that its settings steer (no
	// manager of this process steers it), not the one whose nodes do not
	// change; a failed update is tried again
	e.stub.failIDs = map[string]bool{"c5": true}
	e.p.LendsRestored()
	e.passes()
	e.expectUpdates("c1 mems=0-1", "c2 mems=0-1", "c3 mems=0-1")
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
	for _, c := range []*api.Container{c1, c2, c3, c5} {
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
	e.setCgroupMems("kubepods/u1/c1", "0-2")
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
	e.p.ctrs["c2"].memory = memorySteered
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
	if got := p.ClaimResults("u1"); len(got) != 1 || got[0].Node != 2 || got[0].Mode != cxlapi.ModeNUMA || got[0].Index != 0 || got[0].Size != 256<<20 {
		t.Fatalf("claim results %+v", got)
	}
	if got := p.numaNodes(); !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("numa nodes %v", got)
	}
	if got := preparedNodes(nil, e.driver(t)).String(); got != "2" {
		t.Fatalf("prepared nodes after a restart %s", got)
	}
	noErr(t, unprepare(t, p, "u1"))
	if got := p.ClaimResults("u1"); got != nil {
		t.Fatalf("claim results %v after unprepare", got)
	}
	var none *poolDriver
	if none.ClaimResults("u1") != nil || none.numaNodes() != nil {
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
	if got := r2.taken(); len(got) != 0 || p2.numaNodes() != nil {
		t.Fatalf("dax device fenced: %v, numa nodes %v", got, p2.numaNodes())
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
	e.startCtr(pod, c1)
	e.passes()
	e.expectUpdates("c1 mems=0-1")

	// fenced at creation: nothing at the start
	e.proc(102, "kubepods/u1/c2", "0-1", "0-1")
	c2 := ltCtr(pod, "c2", "app2", 102)
	if got := e.createMems(pod, c2); got != "0-1" {
		t.Fatalf("adjustment %s", got)
	}
	e.startCtr(pod, c2)
	e.passes()
	e.expectUpdates()
}

// fakeLeases is the lease table of a broker for the NRI plugin.
type fakeLeases struct {
	mu    sync.Mutex
	nodes map[string]map[int][]string // key: pod UID/container name
}

func (f *fakeLeases) LeaseNodes(podUID, name string) map[int][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nodes[podUID+"/"+name]
}

// set makes the leases ids Ready numa leases of node of a container, none
// without ids.
func (f *fakeLeases) set(podUID, name string, node int, ids ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nodes == nil {
		f.nodes = map[string]map[int][]string{}
	}
	if len(ids) == 0 {
		delete(f.nodes, podUID+"/"+name)
		return
	}
	f.nodes[podUID+"/"+name] = map[int][]string{node: ids}
}

// readyFence makes fencing of running containers ready.
func (e *ltEnv) readyFence() {
	e.t.Helper()
	if _, err := e.p.Synchronize(context.Background(), nil, nil); err != nil {
		e.t.Fatal(err)
	}
	e.p.LendsRestored()
	e.passes()
	e.expectUpdates()
}

// TestLendRestartedRequester (bug-05) checks that a requester container
// that restarts while the broker keeps its numa lease is created with the
// node of the lease: an update at its start would reach its spec only.
func TestLendRestartedRequester(t *testing.T) {
	e := newFenceEnv(t, "0-2", 2)
	leases := &fakeLeases{}
	e.p.leases = leases
	ctx := context.Background()
	e.readyFence()
	pod := ltPod("u1")
	c1 := e.run(pod, "c1", "main", 101, "0-1")
	noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1"))
	e.expectUpdates("c1 mems=0-2")
	leases.set("u1", "main", 2, "l1")

	// the workload crashes, the broker keeps the lease for the restart
	_, err := e.p.StopContainer(ctx, pod, c1)
	noErr(t, err)
	e.wait(e.gone, "c1")
	c2 := ltCtr(pod, "c2", "main", 102)
	if got := e.createMems(pod, c2); got != "0-2" {
		t.Fatalf("adjustment %s of the restarted requester, expected the lent node", got)
	}
	if got := e.p.LentNodes("u1", "main"); !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("lent %v at the creation", got)
	}
	// the reconcile of the broker before its start: done
	noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1"))
	// its task is created from the spec; then the broker lends again
	e.proc(102, "kubepods/u1/c2", "0-2", "0-2")
	e.startCtr(pod, c2)
	e.passes()
	noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1"))
	e.expectUpdates()
	if ref, _ := e.p.Container("u1", "main"); ref.BaseMems != "0-1" {
		t.Fatalf("BaseMems %q has the lent node", ref.BaseMems)
	}
	// a pass keeps the node; other containers, as the companion pod's,
	// are not lent to
	e.p.fence.Fence(ctx, 3)
	e.expectUpdates()
	cp := ltPod("u9")
	if got := e.createMems(cp, ltCtr(cp, "c9", "pause", 0)); got != "0-1" {
		t.Fatalf("adjustment %s of the companion", got)
	}
	// the lease is released
	leases.set("u1", "main", 2)
	noErr(t, e.p.RevokeNode(ctx, "u1", "main", 2, "l1"))
	e.expectUpdates("c2 mems=0-1")
	if got := e.cgroupMems("kubepods/u1/c2"); got != "0-1" {
		t.Fatalf("cgroup mems %s after the release", got)
	}

	// released while the restarted requester is created: off its spec
	leases.set("u1", "main", 2, "l2")
	c3 := ltCtr(pod, "c3", "main", 0)
	if got := e.createMems(pod, c3); got != "0-2" {
		t.Fatalf("adjustment %s", got)
	}
	leases.set("u1", "main", 2)
	noErr(t, e.p.RevokeNode(ctx, "u1", "main", 2, "l2"))
	e.expectUpdates("c3 mems=0-1")
	if got := e.p.LentNodes("u1", "main"); len(got) != 0 || e.trackedMems("c3") != "0-1" {
		t.Fatalf("lent %v, mems %q after the revoke", got, e.trackedMems("c3"))
	}
	noErr(t, e.p.RevokeNode(ctx, "u1", "main", 2, "l2"))
	if err := e.p.LendNode(ctx, "u1", "main", 2, "l2"); err == nil || !strings.Contains(err.Error(), "not started") {
		t.Fatalf("lend before the start: %v", err)
	}
	e.expectUpdates()

	// steered: not lent to at its creation
	e.p.state = fenceClaims()
	sp := ltPod("u2")
	leases.set("u2", "main", 2, "l3")
	if got := e.createMems(sp, withClaims(ltCtr(sp, "c4", "main", 0), "numa-auto")); got != "-" {
		t.Fatalf("adjustment %s of a steered container", got)
	}
	if got := e.p.LentNodes("u2", "main"); len(got) != 0 {
		t.Fatalf("lent %v to a steered container", got)
	}

	// not fenced: lent by updates after its start only
	n := newLtEnv(t)
	n.p.leases = leases
	np := ltPod("u3")
	leases.set("u3", "main", 2, "l4")
	if got := n.createMems(np, ltCtr(np, "c5", "main", 0)); got != "-" {
		t.Fatalf("adjustment %s in mode none", got)
	}
	noErr(t, n.p.RevokeNode(ctx, "u3", "main", 2, "l4"))
	if got := n.p.LentNodes("u3", "main"); len(got) != 0 {
		t.Fatalf("lent %v after the revoke", got)
	}
	n.expectUpdates()
}

// TestLendUpdateBeforeStart checks that a lend whose update reached only
// the spec, as an update before containerd has marked the container
// started, is applied again: by the pass at the start of a fenced
// container, by the next lend (the reconcile of the broker) of one that is
// not fenced.
func TestLendUpdateBeforeStart(t *testing.T) {
	e := newFenceEnv(t, "0-2", 2)
	ctx := context.Background()
	e.readyFence()
	pod := ltPod("u1")
	c1 := ltCtr(pod, "c1", "main", 101)
	if got := e.createMems(pod, c1); got != "0-1" {
		t.Fatalf("adjustment %s", got)
	}
	e.proc(101, "kubepods/u1/c1", "0-1", "0-1")
	noErr(t, e.p.StartContainer(ctx, pod, c1))
	e.noCallback(e.start)
	e.stub.setSpecOnly("c1", true)
	noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1"))
	e.expectUpdates("c1 mems=0-2")
	if got := e.cgroupMems("kubepods/u1/c1"); got != "0-1" {
		t.Fatalf("cgroup mems %s", got)
	}
	e.startCtr(pod, c1)
	e.passes()
	e.expectUpdates("c1 mems=0-2")
	if got := e.cgroupMems("kubepods/u1/c1"); got != "0-2" {
		t.Fatalf("cgroup mems %s after the start", got)
	}
	noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1"))
	e.expectUpdates()
	// lost after the start (no such runtime): the next lend repeats it
	e.setCgroupMems("kubepods/u1/c1", "0-1")
	noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1"))
	e.expectUpdates("c1 mems=0-2")

	n := newLtEnv(t)
	np := ltPod("u2")
	c2 := specMems(ltCtr(np, "c2", "main", 201), "0-1")
	if got := n.createMems(np, c2); got != "-" {
		t.Fatalf("adjustment %s in mode none", got)
	}
	n.proc(201, "kubepods/u2/c2", "0-1", "0-1")
	noErr(t, n.p.StartContainer(ctx, np, c2))
	n.stub.setSpecOnly("c2", true)
	noErr(t, n.p.LendNode(ctx, "u2", "main", 2, "l1"))
	n.expectUpdates("c2 mems=0-2")
	n.startCtr(np, c2)
	n.expectUpdates()
	noErr(t, n.p.LendNode(ctx, "u2", "main", 2, "l1"))
	n.expectUpdates("c2 mems=0-2")
	if got := n.cgroupMems("kubepods/u2/c2"); got != "0-2" {
		t.Fatalf("cgroup mems %s", got)
	}
	noErr(t, n.p.LendNode(ctx, "u2", "main", 2, "l1"))
	n.expectUpdates()
}

// TestFenceSynchronizeWhileCreating (bug-05, v14) checks that the first
// pass of a plugin that synchronized while the runtime was creating the
// task of a container is applied at the start of the container: the
// update reached its spec only, after the task had read it.
func TestFenceSynchronizeWhileCreating(t *testing.T) {
	e := newFenceEnv(t, "0-2", 2)
	ctx := context.Background()
	pod := ltPod("u1")
	c1 := ltCtr(pod, "c1", "main", 0)
	c1.State = api.ContainerState_CONTAINER_CREATED
	e.stub.setSpecOnly("c1", true)
	if _, err := e.p.Synchronize(ctx, []*api.PodSandbox{pod}, []*api.Container{c1}); err != nil {
		t.Fatal(err)
	}
	e.p.LendsRestored()
	e.passes()
	e.expectUpdates("c1 mems=0-1")
	// the task has every node
	e.proc(101, "kubepods/u1/c1", "0-2", "")
	c1.Pid = 101
	noErr(t, e.p.StartContainer(ctx, pod, c1))
	e.passes()
	e.expectUpdates()
	e.stub.setSpecOnly("c1", false)
	noErr(t, e.p.PostStartContainer(ctx, pod, c1))
	e.wait(e.start, "c1")
	e.passes()
	e.expectUpdates("c1 mems=0-1")
	if got := e.cgroupMems("kubepods/u1/c1"); got != "0-1" {
		t.Fatalf("cgroup mems %s", got)
	}
	e.p.fence.Fence(ctx, 3)
	e.expectUpdates()
	// a PostStartContainer of a container that is gone
	_, err := e.p.StopContainer(ctx, pod, c1)
	noErr(t, err)
	e.wait(e.gone, "c1")
	noErr(t, e.p.PostStartContainer(ctx, pod, c1))
	e.noCallback(e.start)
}

// TestLendSynchronizeKept checks that a restarted plugin gives a container
// that is new to it the lends of its kept leases: a requester created with
// the node of its lease by the previous plugin keeps it through the first
// pass, before its start.
func TestLendSynchronizeKept(t *testing.T) {
	e := newFenceEnv(t, "0-2", 2)
	leases := &fakeLeases{}
	leases.set("u1", "main", 2, "l1")
	e.p.leases = leases
	ctx := context.Background()
	pod := ltPod("u1")
	c2 := specMems(ltCtr(pod, "c2", "main", 0), "0-2")
	c2.State = api.ContainerState_CONTAINER_CREATED
	// a running requester whose cgroup lacks the node
	other := ltPod("u2")
	leases.set("u2", "main", 2, "l2")
	e.proc(201, "kubepods/u2/c3", "0-1", "0-1")
	c3 := specMems(ltCtr(other, "c3", "main", 201), "0-2")
	c3.State = api.ContainerState_CONTAINER_RUNNING
	if _, err := e.p.Synchronize(ctx, []*api.PodSandbox{pod, other}, []*api.Container{c2, c3}); err != nil {
		t.Fatal(err)
	}
	// the reconcile of the broker, then the first pass
	noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1"))
	noErr(t, e.p.LendNode(ctx, "u2", "main", 2, "l2"))
	e.expectUpdates("c3 mems=0-2")
	e.p.LendsRestored()
	e.passes()
	e.expectUpdates()
	if got := e.p.LentNodes("u1", "main"); !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("lent %v", got)
	}
	if ref, _ := e.p.Container("u2", "main"); ref.BaseMems != "0-1" {
		t.Fatalf("BaseMems %q", ref.BaseMems)
	}
	e.proc(102, "kubepods/u1/c2", "0-2", "0-2")
	c2.Pid = 102
	e.startCtr(pod, c2)
	e.passes()
	e.expectUpdates()
}

// captureKlog makes klog write to a buffer at verbosity 3 for the test and
// returns a function that returns the output so far.
func captureKlog(t *testing.T) func() string {
	t.Helper()
	fs := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(fs)
	noErr(t, fs.Set("logtostderr", "false"))
	noErr(t, fs.Set("alsologtostderr", "false"))
	noErr(t, fs.Set("v", "3"))
	var mu sync.Mutex
	var buf bytes.Buffer
	klog.SetOutput(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}))
	t.Cleanup(func() {
		klog.Flush()
		_ = fs.Set("logtostderr", "true")
		_ = fs.Set("v", "0")
	})
	return func() string {
		klog.Flush()
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// The init process of a running container is in a child cgroup of the
// container's (systemd in the container moves itself to init.scope) when
// a restarted plugin synchronizes. The plugin takes the container's own
// cgroup, which the runtime updates, so an update is sent once, not again
// at every pass and every lend for the lifetime of the container with an
// "updating again" line each time (05-review D1). A lease requester in
// another child cgroup of the container is found in it.
func TestReviewSubCgroupUpdatesForever(t *testing.T) {
	e := newFenceEnv(t, "0-2", 2)
	logs := captureKlog(t)
	ctx := context.Background()
	pod := ltPod("u1")
	parent := filepath.Join(cgroupRoot, "kubepods/u1/c1")
	child := e.proc(101, "kubepods/u1/c1/init.scope", "0-2", "")
	noErr(t, os.WriteFile(filepath.Join(parent, "cpuset.mems"), []byte("\n"), 0o644))
	noErr(t, os.WriteFile(filepath.Join(parent, "cpuset.mems.effective"), []byte("0-2\n"), 0o644))
	// runc writes the container's cgroup; the kernel recomputes the
	// child's effective set, its cpuset.mems stays ""
	e.stub.applied = func(id, mems string) {
		_ = os.WriteFile(filepath.Join(parent, "cpuset.mems"), []byte(mems+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(parent, "cpuset.mems.effective"), []byte(mems+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(child, "cpuset.mems.effective"), []byte(mems+"\n"), 0o644)
	}
	c1 := ltCtr(pod, "c1", "main", 101)
	c1.State = api.ContainerState_CONTAINER_RUNNING
	if _, err := e.p.Synchronize(ctx, []*api.PodSandbox{pod}, []*api.Container{c1}); err != nil {
		t.Fatal(err)
	}
	e.p.mu.Lock()
	dir := e.p.ctrs["c1"].ref.CgroupPath
	e.p.mu.Unlock()
	if dir != parent {
		t.Fatalf("cgroup %s, expected the container's %s", dir, parent)
	}
	e.p.LendsRestored()
	e.passes()
	e.expectUpdates("c1 mems=0-1")
	// a later pass (any Fence of a new node) finds it fenced
	e.p.fenceContainers(ctx)
	e.expectUpdates()
	noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1"))
	e.expectUpdates("c1 mems=0-2")
	for i := 0; i < 3; i++ { // three reconciles
		noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1"))
		e.expectUpdates()
	}
	if n := strings.Count(logs(), "updating again"); n != 0 {
		t.Errorf("%d \"updating again\" lines; parent cpuset.mems %q", n, e.cgroupMems("kubepods/u1/c1"))
	}
	e.proc(201, "kubepods/u1/c1/app.scope", "0-2", "")
	if ref, ok := e.p.ContainerByPid(201); !ok || ref.ID != "c1" {
		t.Errorf("a process in another child cgroup: %+v %v", ref, ok)
	}
}

func TestContainerCgroupDir(t *testing.T) {
	old := cgroupRoot
	cgroupRoot = "/sys/fs/cgroup"
	t.Cleanup(func() { cgroupRoot = old })
	const id = "4bb166f8e2"
	scope := "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podu1.slice/cri-containerd-" + id + ".scope"
	for _, tc := range []struct{ dir, id, want string }{
		{scope, id, scope},
		{scope + "/init.scope", id, scope},
		{"/sys/fs/cgroup/kubepods/burstable/podu1/" + id + "/a/b", id, "/sys/fs/cgroup/kubepods/burstable/podu1/" + id},
		{"/sys/fs/cgroup/system.slice/crio-" + id + ".scope/container", id, "/sys/fs/cgroup/system.slice/crio-" + id + ".scope"},
		{"/sys/fs/cgroup/kubepods/podu1/other/init.scope", id, "/sys/fs/cgroup/kubepods/podu1/other/init.scope"},
		{scope + "/init.scope", "", scope + "/init.scope"},
		{"/elsewhere/" + id + "/init.scope", id, "/elsewhere/" + id + "/init.scope"},
	} {
		if got := containerCgroupDir(tc.dir, tc.id); got != tc.want {
			t.Errorf("containerCgroupDir(%s, %q) = %s, expected %s", tc.dir, tc.id, got, tc.want)
		}
	}
}

// fencing none, a requester restarts with its kept lease and a spec pinned
// to its DRAM nodes (kubelet memory manager): the first lend after its
// start is not logged as a lost update ("updating again"): nothing was sent
// before (05-review D6).
func TestReviewSeededNoneLogsUpdatingAgain(t *testing.T) {
	e := newLtEnv(t)
	logs := captureKlog(t)
	leases := &fakeLeases{}
	e.p.leases = leases
	ctx := context.Background()
	pod := ltPod("u1")
	leases.set("u1", "main", 2, "l1")
	c2 := specMems(ltCtr(pod, "c2", "main", 102), "0-1")
	if got := e.createMems(pod, c2); got != "-" {
		t.Fatalf("adjustment %s", got)
	}
	e.proc(102, "kubepods/u1/c2", "0-1", "0-1")
	e.startCtr(pod, c2)
	noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1")) // the broker at PostStart
	e.expectUpdates("c2 mems=0-2")
	// a lost update is: the cgroup loses the node again
	e.setCgroupMems("kubepods/u1/c2", "0-1")
	noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1"))
	e.expectUpdates("c2 mems=0-2")
	if n := strings.Count(logs(), "updating again"); n != 1 {
		t.Errorf("%d \"updating again\" lines, expected 1 (the lost update):\n%s", n, logs())
	}
}
