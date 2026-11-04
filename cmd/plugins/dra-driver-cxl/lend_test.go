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
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containers/nri-plugins/pkg/cgmpolmgr"
	"github.com/containers/nri-plugins/pkg/cxl/config"
)

// ltStub is a fake NRI stub that records UpdateContainers.
type ltStub struct {
	mu      sync.Mutex
	updates []string // "<id> mems=<mems>"
	fail    bool     // report the update as failed
	err     error    // return this error
	// failIDs are the containers whose updates are reported failed.
	failIDs map[string]bool
	// specOnly are the containers whose updates reach only their spec,
	// as in containerd before it has marked a container started.
	specOnly map[string]bool
	// applied is called for an update that reaches the cgroup.
	applied func(id, mems string)
	// entered gets a value when UpdateContainers is called, and gate
	// blocks it until closed (nil: neither).
	entered chan struct{}
	gate    chan struct{}
}

func (s *ltStub) Start(context.Context) error { return nil }
func (s *ltStub) Stop()                       {}
func (s *ltStub) UpdateContainers(u []*api.ContainerUpdate) ([]*api.ContainerUpdate, error) {
	if s.entered != nil {
		s.entered <- struct{}{}
	}
	if s.gate != nil {
		<-s.gate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	if s.fail {
		return u, nil
	}
	var failed, applied []*api.ContainerUpdate
	for _, cu := range u {
		if s.failIDs[cu.GetContainerId()] {
			failed = append(failed, cu)
			continue
		}
		s.updates = append(s.updates, cu.GetContainerId()+" mems="+cu.GetLinux().GetResources().GetCpu().GetMems())
		if !s.specOnly[cu.GetContainerId()] {
			applied = append(applied, cu)
		}
	}
	if s.applied != nil {
		s.mu.Unlock()
		for _, cu := range applied {
			s.applied(cu.GetContainerId(), cu.GetLinux().GetResources().GetCpu().GetMems())
		}
		s.mu.Lock()
	}
	return failed, nil
}

// setSpecOnly makes the updates of the container reach only its spec
// (on) or its cgroup too.
func (s *ltStub) setSpecOnly(id string, on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.specOnly == nil {
		s.specOnly = map[string]bool{}
	}
	s.specOnly[id] = on
}

func (s *ltStub) taken() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.updates
	s.updates = nil
	return out
}

// ltEnv is a plugin with a fake stub and fake /proc and cgroupfs.
type ltEnv struct {
	t     *testing.T
	p     *nriPlugin
	stub  *ltStub
	root  string
	gone  chan containerRef
	start chan containerRef
}

func newLtEnv(t *testing.T) *ltEnv {
	t.Helper()
	root := t.TempDir()
	oldProc, oldCg := procDir, cgroupRoot
	procDir, cgroupRoot = filepath.Join(root, "proc"), filepath.Join(root, "cg")
	t.Cleanup(func() { procDir, cgroupRoot = oldProc, oldCg })

	e := &ltEnv{
		t:     t,
		stub:  &ltStub{},
		root:  root,
		gone:  make(chan containerRef, 16),
		start: make(chan containerRef, 16),
	}
	e.p = &nriPlugin{
		stub:     e.stub,
		defaults: config.Container{Fencing: config.FencingNone},
		pending:  make(map[string]pendingSteering),
		managers: make(map[string]*cgmpolmgr.Manager),
	}
	e.p.initLendState()
	e.p.OnContainerGone(func(ref containerRef) { e.gone <- ref })
	e.p.OnContainerStarted(func(ref containerRef) { e.start <- ref })
	e.stub.applied = e.toCgroup
	return e
}

// toCgroup writes the cpuset.mems of an update to the cgroup of a started
// container, as runc does.
func (e *ltEnv) toCgroup(id, mems string) {
	e.p.mu.Lock()
	dir := ""
	if tc := e.p.ctrs[id]; tc != nil && tc.started {
		dir = tc.ref.CgroupPath
	}
	e.p.mu.Unlock()
	if dir == "" {
		return
	}
	if _, err := os.Stat(dir); err != nil {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "cpuset.mems"), []byte(mems+"\n"), 0o644); err != nil {
		e.t.Error(err)
	}
}

// setCgroupMems sets the cpuset.mems of the cgroup of a container.
func (e *ltEnv) setCgroupMems(rel, mems string) {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(cgroupRoot, rel, "cpuset.mems"), []byte(mems+"\n"), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

// cgroupMems returns the cpuset.mems of the cgroup of a container.
func (e *ltEnv) cgroupMems(rel string) string {
	e.t.Helper()
	data, err := os.ReadFile(filepath.Join(cgroupRoot, rel, "cpuset.mems"))
	if err != nil {
		e.t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

// proc makes /proc/<pid>/cgroup point to cgroup rel and returns the
// absolute cgroup directory, with cpuset.mems.effective = effMems and
// cpuset.mems = mems.
func (e *ltEnv) proc(pid uint32, rel, effMems, mems string) string {
	e.t.Helper()
	pdir := filepath.Join(procDir, fmt.Sprint(pid))
	cg := filepath.Join(cgroupRoot, rel)
	for _, d := range []string{pdir, cg} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			e.t.Fatal(err)
		}
	}
	write := func(path, data string) {
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			e.t.Fatal(err)
		}
	}
	write(filepath.Join(pdir, "cgroup"), "0::/"+rel+"\n")
	write(filepath.Join(cg, "cpuset.mems.effective"), effMems+"\n")
	write(filepath.Join(cg, "cpuset.mems"), mems+"\n")
	return cg
}

func ltPod(uid string) *api.PodSandbox {
	return &api.PodSandbox{Id: "sb-" + uid, Uid: uid, Namespace: "ns", Name: "pod-" + uid}
}

func ltCtr(pod *api.PodSandbox, id, name string, pid uint32) *api.Container {
	return &api.Container{Id: id, PodSandboxId: pod.GetId(), Name: name, Pid: pid}
}

// run creates and starts a container whose cgroup has effMems, and the
// cpuset.mems of its adjustment, as runc creates it. Its updates reach
// only its spec until it has started, as in containerd.
func (e *ltEnv) run(pod *api.PodSandbox, id, name string, pid uint32, effMems string) *api.Container {
	e.t.Helper()
	ctr := ltCtr(pod, id, name, pid)
	ctx := context.Background()
	adj, _, err := e.p.CreateContainer(ctx, pod, ctr)
	if err != nil {
		e.t.Fatal(err)
	}
	e.stub.setSpecOnly(ctr.GetId(), true)
	e.proc(pid, "kubepods/"+pod.GetUid()+"/"+id, effMems, adj.GetLinux().GetResources().GetCpu().GetMems())
	e.startCtr(pod, ctr)
	return ctr
}

// runPinned is run of a container whose spec has the cpuset.mems mems, as
// kubelet's memory manager pins it: its cgroup has it as cpuset.mems and
// cpuset.mems.effective. With fencing none the lends of a container change
// its cpuset.mems only if it has one of its own (lend.go).
func (e *ltEnv) runPinned(pod *api.PodSandbox, id, name string, pid uint32, mems string) *api.Container {
	e.t.Helper()
	ctr := specMems(ltCtr(pod, id, name, pid), mems)
	if _, _, err := e.p.CreateContainer(context.Background(), pod, ctr); err != nil {
		e.t.Fatal(err)
	}
	e.stub.setSpecOnly(ctr.GetId(), true)
	e.proc(pid, "kubepods/"+pod.GetUid()+"/"+id, mems, mems)
	e.startCtr(pod, ctr)
	return ctr
}

// startCtr starts a created container: StartContainer, then the runtime
// marks it started (its updates reach the cgroup) and PostStartContainer.
// Waits for the OnContainerStarted callback and the fence passes.
func (e *ltEnv) startCtr(pod *api.PodSandbox, ctr *api.Container) {
	e.t.Helper()
	ctx := context.Background()
	if err := e.p.StartContainer(ctx, pod, ctr); err != nil {
		e.t.Fatal(err)
	}
	e.stub.setSpecOnly(ctr.GetId(), false)
	if err := e.p.PostStartContainer(ctx, pod, ctr); err != nil {
		e.t.Fatal(err)
	}
	e.wait(e.start, ctr.GetId())
	e.passes()
}

func (e *ltEnv) wait(c chan containerRef, id string) containerRef {
	e.t.Helper()
	select {
	case ref := <-c:
		if ref.ID != id {
			e.t.Fatalf("callback for %q, expected %q", ref.ID, id)
		}
		return ref
	case <-time.After(5 * time.Second):
		e.t.Fatalf("no callback for %q", id)
	}
	return containerRef{}
}

func (e *ltEnv) noCallback(c chan containerRef) {
	e.t.Helper()
	select {
	case ref := <-c:
		e.t.Fatalf("unexpected callback for %q", ref.ID)
	case <-time.After(50 * time.Millisecond):
	}
}

func (e *ltEnv) expectUpdates(want ...string) {
	e.t.Helper()
	got := e.stub.taken()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		e.t.Fatalf("updates %q, expected %q", got, want)
	}
}

func TestLendContainerTable(t *testing.T) {
	e := newLtEnv(t)
	ctx := context.Background()
	pod := ltPod("u1")
	ctr := ltCtr(pod, "c1", "app", 101)
	cg := e.proc(101, "kubepods/u1/c1", "0-1", "")

	if _, _, err := e.p.CreateContainer(ctx, pod, ctr); err != nil {
		t.Fatal(err)
	}
	ref, ok := e.p.Container("u1", "app")
	if !ok || ref.ID != "c1" || ref.PodNamespace != "ns" || ref.PodName != "pod-u1" || ref.Pid != 0 {
		t.Fatalf("created: %+v %v", ref, ok)
	}
	if err := e.p.LendNode(ctx, "u1", "app", 2, "l1"); err == nil || !strings.Contains(err.Error(), "not started") {
		t.Fatalf("lend before start: %v", err)
	}

	if err := e.p.StartContainer(ctx, pod, ctr); err != nil {
		t.Fatal(err)
	}
	// started when the runtime applies updates to its cgroup
	e.noCallback(e.start)
	if err := e.p.PostStartContainer(ctx, pod, ctr); err != nil {
		t.Fatal(err)
	}
	started := e.wait(e.start, "c1")
	want := containerRef{PodUID: "u1", PodNamespace: "ns", PodName: "pod-u1", Name: "app", ID: "c1",
		Pid: 101, CgroupPath: cg, BaseMems: "0-1"}
	if started != want {
		t.Fatalf("started %+v, expected %+v", started, want)
	}
	if ref, _ := e.p.Container("u1", "app"); *ref != want {
		t.Fatalf("Container %+v, expected %+v", *ref, want)
	}

	// The init pid, and a pid in a sub-cgroup of the container.
	if ref, ok := e.p.ContainerByPid(101); !ok || ref.ID != "c1" {
		t.Fatalf("ContainerByPid(101): %+v %v", ref, ok)
	}
	e.proc(102, "kubepods/u1/c1/sub", "0-1", "")
	if ref, ok := e.p.ContainerByPid(102); !ok || ref.ID != "c1" {
		t.Fatalf("ContainerByPid(102): %+v %v", ref, ok)
	}
	// Prefix match is by path element, not by string.
	e.proc(103, "kubepods/u1/c10", "0-1", "")
	if ref, ok := e.p.ContainerByPid(103); ok {
		t.Fatalf("ContainerByPid(103) matched %+v", ref)
	}
	if _, ok := e.p.ContainerByPid(999); ok {
		t.Fatal("ContainerByPid(999) matched")
	}

	// Stop fires gone once; Remove after Stop does not fire again.
	if _, err := e.p.StopContainer(ctx, pod, ctr); err != nil {
		t.Fatal(err)
	}
	if gone := e.wait(e.gone, "c1"); gone.BaseMems != "0-1" || gone.Pid != 101 {
		t.Fatalf("gone %+v", gone)
	}
	if err := e.p.RemoveContainer(ctx, pod, ctr); err != nil {
		t.Fatal(err)
	}
	e.noCallback(e.gone)
	if _, ok := e.p.Container("u1", "app"); ok {
		t.Fatal("container still known after stop")
	}

	// Remove without Stop fires gone too.
	e.run(pod, "c2", "app", 201, "0")
	if err := e.p.RemoveContainer(ctx, pod, ltCtr(pod, "c2", "app", 201)); err != nil {
		t.Fatal(err)
	}
	e.wait(e.gone, "c2")
	e.expectUpdates()
}

func TestLendMemsArithmetic(t *testing.T) {
	e := newLtEnv(t)
	ctx := context.Background()
	e.runPinned(ltPod("u1"), "c1", "app", 101, "0-1")

	steps := []struct {
		lend bool
		node int
		want string // update, "" for none
		lent []int
	}{
		{true, 2, "c1 mems=0-2", []int{2}},
		{true, 2, "", []int{2}}, // idempotent
		{true, 4, "c1 mems=0-2,4", []int{2, 4}},
		{false, 2, "c1 mems=0-1,4", []int{4}},
		{false, 2, "", []int{4}}, // idempotent
		{false, 4, "c1 mems=0-1", []int{}},
		{false, 4, "", []int{}},
	}
	for i, s := range steps {
		var err error
		if s.lend {
			err = e.p.LendNode(ctx, "u1", "app", s.node, "l1")
		} else {
			err = e.p.RevokeNode(ctx, "u1", "app", s.node, "l1")
		}
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if s.want == "" {
			e.expectUpdates()
		} else {
			e.expectUpdates(s.want)
		}
		if got := e.p.LentNodes("u1", "app"); !reflect.DeepEqual(got, s.lent) {
			t.Fatalf("step %d: lent %v, expected %v", i, got, s.lent)
		}
	}
	if ref, _ := e.p.Container("u1", "app"); ref.BaseMems != "0-1" {
		t.Fatalf("BaseMems changed: %q", ref.BaseMems)
	}
	if err := e.p.LendNode(ctx, "u1", "app", -1, "l1"); err == nil {
		t.Fatal("negative node accepted")
	}
}

// TestLendTwoHolders lends one node for two leases: the node stays in
// cpuset.mems until both have revoked it.
func TestLendTwoHolders(t *testing.T) {
	e := newLtEnv(t)
	ctx := context.Background()
	e.runPinned(ltPod("u1"), "c1", "app", 101, "0-1")
	cg := filepath.Join(cgroupRoot, "kubepods/u1/c1")
	setMems := func(mems string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(cg, "cpuset.mems"), []byte(mems+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	steps := []struct {
		lend   bool
		holder string
		want   string // update, "" for none
		lent   []int
		mems   string // cpuset.mems of the cgroup after the step, "" unchanged
	}{
		{true, "a", "c1 mems=0-2", []int{2}, "0-2"},
		{true, "b", "", []int{2}, ""},
		{true, "a", "", []int{2}, ""}, // idempotent
		// b holds the node: no shrink, although cpuset.mems has it
		{false, "a", "", []int{2}, ""},
		{false, "a", "", []int{2}, ""}, // idempotent
		{false, "x", "", []int{2}, ""}, // not a holder
		{false, "b", "c1 mems=0-1", []int{}, "0-1"},
		{false, "b", "", []int{}, ""}, // idempotent
	}
	for i, s := range steps {
		var err error
		if s.lend {
			err = e.p.LendNode(ctx, "u1", "app", 2, s.holder)
		} else {
			err = e.p.RevokeNode(ctx, "u1", "app", 2, s.holder)
		}
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if s.want == "" {
			e.expectUpdates()
		} else {
			e.expectUpdates(s.want)
		}
		if got := e.p.LentNodes("u1", "app"); !reflect.DeepEqual(got, s.lent) {
			t.Fatalf("step %d: lent %v, expected %v", i, got, s.lent)
		}
		if s.mems != "" {
			setMems(s.mems)
		}
	}

	// two nodes, each with its own holders
	for _, l := range []struct {
		node   int
		holder string
		want   string
	}{{2, "a", "c1 mems=0-2"}, {3, "a", "c1 mems=0-3"}, {3, "b", ""}} {
		if err := e.p.LendNode(ctx, "u1", "app", l.node, l.holder); err != nil {
			t.Fatal(err)
		}
		if l.want == "" {
			e.expectUpdates()
		} else {
			e.expectUpdates(l.want)
		}
	}
	if err := e.p.RevokeNode(ctx, "u1", "app", 3, "a"); err != nil {
		t.Fatal(err)
	}
	e.expectUpdates()
	if err := e.p.RevokeNode(ctx, "u1", "app", 2, "a"); err != nil {
		t.Fatal(err)
	}
	e.expectUpdates("c1 mems=0-1,3")
	if got := e.p.LentNodes("u1", "app"); !reflect.DeepEqual(got, []int{3}) {
		t.Fatalf("lent %v", got)
	}
}

func TestLendGoneContainer(t *testing.T) {
	e := newLtEnv(t)
	ctx := context.Background()
	pod := ltPod("u1")
	ctr := e.runPinned(pod, "c1", "app", 101, "0")
	if err := e.p.LendNode(ctx, "u1", "app", 3, "l1"); err != nil {
		t.Fatal(err)
	}
	e.expectUpdates("c1 mems=0,3")

	if _, err := e.p.StopContainer(ctx, pod, ctr); err != nil {
		t.Fatal(err)
	}
	e.wait(e.gone, "c1")
	if err := e.p.RevokeNode(ctx, "u1", "app", 3, "l1"); err != nil {
		t.Fatalf("revoke of a gone container: %v", err)
	}
	e.expectUpdates()
	if err := e.p.LendNode(ctx, "u1", "app", 3, "l1"); err == nil {
		t.Fatal("lend to a gone container succeeded")
	}
	if got := e.p.LentNodes("u1", "app"); len(got) != 0 {
		t.Fatalf("lent nodes of a gone container: %v", got)
	}

	// The restarted container (new id) starts without lends.
	e.runPinned(pod, "c1b", "app", 111, "0")
	if got := e.p.LentNodes("u1", "app"); len(got) != 0 {
		t.Fatalf("restarted container has lends: %v", got)
	}
	if err := e.p.LendNode(ctx, "u1", "app", 3, "l1"); err != nil {
		t.Fatal(err)
	}
	e.expectUpdates("c1b mems=0,3")
}

func TestLendRefusedWhenSteered(t *testing.T) {
	e := newLtEnv(t)
	ctx := context.Background()
	e.run(ltPod("u1"), "c1", "app", 101, "0-1")
	e.run(ltPod("u2"), "c2", "app", 201, "0-1")

	e.p.mu.Lock()
	e.p.managers["c1"] = &cgmpolmgr.Manager{}
	e.p.ctrs["c2"].memory = memorySteered
	e.p.mu.Unlock()
	t.Cleanup(func() { delete(e.p.managers, "c1") })

	for _, uid := range []string{"u1", "u2"} {
		err := e.p.LendNode(ctx, uid, "app", 2, "l1")
		if !errors.Is(err, errSteered) {
			t.Fatalf("pod %s: expected steering refusal, got %v", uid, err)
		}
		if !strings.Contains(err.Error(), "lending is not supported together with steering yet") {
			t.Fatalf("unclear error: %v", err)
		}
		if err := e.p.RevokeNode(ctx, uid, "app", 2, "l1"); err != nil {
			t.Fatalf("revoke on a steered container: %v", err)
		}
	}
	e.expectUpdates()
}

func TestLendUpdateFailures(t *testing.T) {
	e := newLtEnv(t)
	ctx := context.Background()
	e.runPinned(ltPod("u1"), "c1", "app", 101, "0")

	e.stub.fail = true
	if err := e.p.LendNode(ctx, "u1", "app", 2, "l1"); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("failed update not reported: %v", err)
	}
	e.stub.fail, e.stub.err = false, errors.New("ttrpc closed")
	if err := e.p.LendNode(ctx, "u1", "app", 2, "l1"); err == nil || !strings.Contains(err.Error(), "ttrpc closed") {
		t.Fatalf("update error not reported: %v", err)
	}
	if got := e.p.LentNodes("u1", "app"); len(got) != 0 {
		t.Fatalf("failed lends recorded: %v", got)
	}
	e.stub.err = nil
	if err := e.p.LendNode(ctx, "u1", "app", 2, "l1"); err != nil {
		t.Fatal(err)
	}
	e.expectUpdates("c1 mems=0,2")

	// No stub: NRI not connected.
	e.p.mu.Lock()
	e.p.stub = nil
	e.p.mu.Unlock()
	if err := e.p.LendNode(ctx, "u1", "app", 3, "l1"); err == nil || !strings.Contains(err.Error(), "NRI not connected") {
		t.Fatalf("expected NRI not connected, got %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := e.p.LendNode(cctx, "u1", "app", 3, "l1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

func TestLendNeverWithoutBaseMems(t *testing.T) {
	e := newLtEnv(t)
	ctx := context.Background()
	pod := ltPod("u1")
	// No cgroup and no spec mems: base unknown, but with fencing none it
	// inherits every node, nothing is set (bug-18).
	ctr := ltCtr(pod, "c1", "app", 0)
	if _, _, err := e.p.CreateContainer(ctx, pod, ctr); err != nil {
		t.Fatal(err)
	}
	e.startCtr(pod, ctr)
	noErr(t, e.p.LendNode(ctx, "u1", "app", 2, "l1"))
	if got := e.p.LentNodes("u1", "app"); !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("lent %v", got)
	}
	// The only own node is the node being lent.
	e.runPinned(ltPod("u2"), "c2", "app", 201, "2")
	if err := e.p.LendNode(ctx, "u2", "app", 2, "l1"); err == nil || !strings.Contains(err.Error(), "base memory nodes unknown") {
		t.Fatalf("lend of the only node: %v", err)
	}
	e.expectUpdates()

	// Spec mems is the fallback when cgroupfs is unreadable.
	pod3 := ltPod("u3")
	ctr3 := ltCtr(pod3, "c3", "app", 0)
	ctr3.Linux = &api.LinuxContainer{Resources: &api.LinuxResources{Cpu: &api.LinuxCPU{Mems: "1"}}}
	if _, _, err := e.p.CreateContainer(ctx, pod3, ctr3); err != nil {
		t.Fatal(err)
	}
	e.startCtr(pod3, ctr3)
	if err := e.p.LendNode(ctx, "u3", "app", 2, "l1"); err != nil {
		t.Fatal(err)
	}
	e.expectUpdates("c3 mems=1-2")
}

func TestLendBaseExcludesNodesLentToOthers(t *testing.T) {
	e := newLtEnv(t)
	ctx := context.Background()
	e.runPinned(ltPod("u1"), "c1", "app", 101, "0-1")
	if err := e.p.LendNode(ctx, "u1", "app", 2, "l1"); err != nil {
		t.Fatal(err)
	}
	e.expectUpdates("c1 mems=0-2")
	// An unconstrained container started now sees node 2 as effective.
	e.run(ltPod("u2"), "c2", "app", 201, "0-2")
	if ref, _ := e.p.Container("u2", "app"); ref.BaseMems != "0-1" {
		t.Fatalf("BaseMems %q includes a node lent to another container", ref.BaseMems)
	}
}

func TestLendSynchronize(t *testing.T) {
	e := newLtEnv(t)
	ctx := context.Background()
	p1, p2 := ltPod("u1"), ltPod("u2")
	// Before a restart node 2 was lent to c1, node 3 to c2 (and the
	// lease of c2 is not re-applied), c3 is only created.
	cg1 := e.proc(101, "kubepods/u1/c1", "0-2", "0-2")
	e.proc(201, "kubepods/u2/c2", "0,3", "0,3")
	c1 := ltCtr(p1, "c1", "app", 101)
	c1.State = api.ContainerState_CONTAINER_RUNNING
	c2 := ltCtr(p2, "c2", "app", 201)
	c2.State = api.ContainerState_CONTAINER_RUNNING
	c3 := ltCtr(p2, "c3", "init", 0)
	c3.State = api.ContainerState_CONTAINER_CREATED
	c4 := ltCtr(p2, "c4", "old", 0)
	c4.State = api.ContainerState_CONTAINER_STOPPED

	syncCtx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	if err := e.p.WaitSynchronized(syncCtx); err == nil {
		t.Fatal("synchronized before Synchronize")
	}
	cancel()
	if _, err := e.p.Synchronize(ctx, []*api.PodSandbox{p1, p2}, []*api.Container{c1, c2, c3, c4}); err != nil {
		t.Fatal(err)
	}
	if err := e.p.WaitSynchronized(ctx); err != nil {
		t.Fatal(err)
	}
	e.noCallback(e.start)

	ref, ok := e.p.Container("u1", "app")
	want := containerRef{PodUID: "u1", PodNamespace: "ns", PodName: "pod-u1", Name: "app", ID: "c1",
		Pid: 101, CgroupPath: cg1, BaseMems: "0-2"}
	if !ok || *ref != want {
		t.Fatalf("synced %+v, expected %+v", ref, want)
	}
	if _, ok := e.p.Container("u2", "old"); ok {
		t.Fatal("stopped container tracked")
	}
	if ref, ok := e.p.ContainerByPid(201); !ok || ref.ID != "c2" {
		t.Fatalf("ContainerByPid after sync: %+v %v", ref, ok)
	}

	// Re-applying the lend drops node 2 from BaseMems.
	if err := e.p.LendNode(ctx, "u1", "app", 2, "l1"); err != nil {
		t.Fatal(err)
	}
	e.expectUpdates("c1 mems=0-2")
	if ref, _ := e.p.Container("u1", "app"); ref.BaseMems != "0-1" {
		t.Fatalf("BaseMems after re-lend %q", ref.BaseMems)
	}
	if err := e.p.RevokeNode(ctx, "u1", "app", 2, "l1"); err != nil {
		t.Fatal(err)
	}
	e.expectUpdates("c1 mems=0-1")

	// A revoke without a re-lend still shrinks cpuset.mems.
	if err := e.p.RevokeNode(ctx, "u2", "app", 3, "l1"); err != nil {
		t.Fatal(err)
	}
	e.expectUpdates("c2 mems=0")

	// A later Synchronize (reconnect) keeps lends and reports
	// containers that vanished.
	if err := e.p.LendNode(ctx, "u1", "app", 5, "l1"); err != nil {
		t.Fatal(err)
	}
	e.expectUpdates("c1 mems=0-1,5")
	if _, err := e.p.Synchronize(ctx, []*api.PodSandbox{p1}, []*api.Container{c1}); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for range 2 {
		select {
		case ref := <-e.gone:
			got[ref.ID] = true
		case <-time.After(5 * time.Second):
			t.Fatal("missing gone callback")
		}
	}
	if !got["c2"] || !got["c3"] {
		t.Fatalf("gone after resync: %v", got)
	}
	if lent := e.p.LentNodes("u1", "app"); !reflect.DeepEqual(lent, []int{5}) {
		t.Fatalf("lent after resync: %v", lent)
	}
}

func TestLendConcurrent(t *testing.T) {
	e := newLtEnv(t)
	ctx := context.Background()
	e.runPinned(ltPod("u1"), "c1", "app", 101, "0")
	var wg sync.WaitGroup
	for n := 1; n <= 8; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if err := e.p.LendNode(ctx, "u1", "app", n, "l1"); err != nil {
				t.Error(err)
			}
			_ = e.p.LentNodes("u1", "app")
			_, _ = e.p.ContainerByPid(101)
		}(n)
	}
	wg.Wait()
	if lent := e.p.LentNodes("u1", "app"); !reflect.DeepEqual(lent, []int{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("lent %v", lent)
	}
	ups := e.stub.taken()
	if len(ups) != 8 || ups[7] != "c1 mems=0-8" {
		t.Fatalf("updates %q", ups)
	}
}

// TestLendNoneInherits (bug-18) checks that with fencing none a lend and a
// revoke leave the empty cpuset.mems of a container alone: it has every
// node with memory, also one whose memory goes online later, and a revoke
// must not take a node that has memory of others off it. Also after a
// plugin restart, with the lease kept or released while it was down.
func TestLendNoneInherits(t *testing.T) {
	e := newLtEnv(t)
	logs := captureKlog(t)
	ctx := context.Background()
	pod := ltPod("u1")
	// node 2 has memory, a numa slice of another pod
	e.run(pod, "c1", "main", 101, "0-2")
	for i, s := range []struct {
		lend   bool
		node   int
		holder string
		lent   []int
	}{
		{true, 2, "l1", []int{2}},
		{true, 2, "l1", []int{2}}, // the reconcile of the broker
		{true, 2, "l2", []int{2}},
		{false, 2, "l1", []int{2}},
		{true, 3, "l3", []int{2, 3}}, // no memory yet
		{false, 2, "l2", []int{3}},
		{false, 2, "l2", []int{3}},
		{false, 3, "l3", []int{}},
	} {
		if s.lend {
			noErr(t, e.p.LendNode(ctx, "u1", "main", s.node, s.holder))
		} else {
			noErr(t, e.p.RevokeNode(ctx, "u1", "main", s.node, s.holder))
		}
		e.expectUpdates()
		if got := e.p.LentNodes("u1", "main"); !reflect.DeepEqual(got, s.lent) {
			t.Fatalf("step %d: lent %v, expected %v", i, got, s.lent)
		}
	}
	if got := e.cgroupMems("kubepods/u1/c1"); got != "" {
		t.Fatalf("cgroup mems %q, expected empty", got)
	}
	out := logs()
	if n := strings.Count(out, "cpuset.mems left empty, it has the nodes of its parent (fencing none"); n != 6 {
		t.Errorf("%d \"left empty\" lines, expected 6 (one per change of the holders):\n%s", n, out)
	}
	if strings.Contains(out, "cpuset.mems=") {
		t.Errorf("cpuset.mems set:\n%s", out)
	}
	// node 3 has no memory yet: not in its cpuset.mems.effective
	if !strings.Contains(out, "lend node 3 for l3: ctr=ns/pod-u1/main id=c1: its cpuset.mems.effective lacks the lent nodes 3 (") {
		t.Errorf("no warning of node 3:\n%s", out)
	}
	if n := strings.Count(out, "cpuset.mems.effective lacks"); n != strings.Count(out, "lacks the lent nodes 3 (") {
		t.Errorf("warning of another node:\n%s", out)
	}

	// a restarted plugin: the broker keeps the lease l1 of node 2, the
	// lease l3 of node 3 was released while the plugin was down
	n := newLtEnv(t)
	leases := &fakeLeases{}
	leases.set("u1", "main", 2, "l1")
	n.p.leases = leases
	n.proc(101, "kubepods/u1/c1", "0-3", "")
	c1 := ltCtr(pod, "c1", "main", 101)
	c1.State = api.ContainerState_CONTAINER_RUNNING
	if _, err := n.p.Synchronize(ctx, []*api.PodSandbox{pod}, []*api.Container{c1}); err != nil {
		t.Fatal(err)
	}
	noErr(t, n.p.LendNode(ctx, "u1", "main", 2, "l1"))
	n.p.LendsRestored()
	noErr(t, n.p.RevokeNode(ctx, "u1", "main", 3, "l3"))
	leases.set("u1", "main", 2)
	noErr(t, n.p.RevokeNode(ctx, "u1", "main", 2, "l1"))
	n.expectUpdates()
	if got := n.p.LentNodes("u1", "main"); len(got) != 0 {
		t.Fatalf("lent %v after the revokes", got)
	}
	if got := n.cgroupMems("kubepods/u1/c1"); got != "" {
		t.Fatalf("cgroup mems %q after the restart, expected empty", got)
	}
	// the lent nodes are not its own, as with a cpuset.mems of its own
	if ref, _ := n.p.Container("u1", "main"); ref.BaseMems != "0-1" {
		t.Fatalf("BaseMems %q", ref.BaseMems)
	}
}

// TestLendNoneFencedBefore (bug-18) checks lends with fencing none to the
// containers that a plugin with fencing allowed-mems fenced before the
// switch to none: they keep their cpuset.mems, a lend adds the node and a
// revoke removes it again, but not a node of their claims.
func TestLendNoneFencedBefore(t *testing.T) {
	e := newLtEnv(t)
	e.p.state = fenceClaims()
	leases := &fakeLeases{}
	e.p.leases = leases
	ctx := context.Background()
	p1, p2 := ltPod("u1"), ltPod("u2")
	// a requester with node 2 of its lease l1, and a container with a numa
	// slice of node 2 and node 3 of its lease l2, both kept by the broker
	leases.set("u1", "main", 2, "l1")
	leases.set("u2", "main", 3, "l2")
	e.proc(101, "kubepods/u1/c1", "0-2", "0-2")
	c1 := specMems(ltCtr(p1, "c1", "main", 101), "0-2")
	c1.State = api.ContainerState_CONTAINER_RUNNING
	e.proc(201, "kubepods/u2/c2", "0-3", "0-3")
	c2 := withClaims(specMems(ltCtr(p2, "c2", "main", 201), "0-3"), "numa")
	c2.State = api.ContainerState_CONTAINER_RUNNING
	if _, err := e.p.Synchronize(ctx, []*api.PodSandbox{p1, p2}, []*api.Container{c1, c2}); err != nil {
		t.Fatal(err)
	}
	// the reconcile of the broker: lent already
	noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1"))
	noErr(t, e.p.LendNode(ctx, "u2", "main", 3, "l2"))
	e.p.LendsRestored()
	e.passes()
	e.expectUpdates()

	// the leases are released
	leases.set("u1", "main", 2)
	leases.set("u2", "main", 3)
	noErr(t, e.p.RevokeNode(ctx, "u1", "main", 2, "l1"))
	e.expectUpdates("c1 mems=0-1")
	noErr(t, e.p.RevokeNode(ctx, "u2", "main", 3, "l2"))
	e.expectUpdates("c2 mems=0-2")

	// a lease of the node of its claim: the node stays at the revoke, and
	// as its cgroup and spec have it, nothing is sent
	noErr(t, e.p.LendNode(ctx, "u2", "main", 2, "l3"))
	e.expectUpdates()
	if got := e.p.LentNodes("u2", "main"); !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("lent %v, expected [2]", got)
	}
	noErr(t, e.p.RevokeNode(ctx, "u2", "main", 2, "l3"))
	e.expectUpdates()
	noErr(t, e.p.RevokeNode(ctx, "u2", "main", 2, "l3"))
	e.expectUpdates()
	if got := e.p.LentNodes("u2", "main"); len(got) != 0 {
		t.Fatalf("lent %v after the revoke", got)
	}
	// a new lease of the requester
	noErr(t, e.p.LendNode(ctx, "u1", "main", 3, "l4"))
	e.expectUpdates("c1 mems=0-1,3")
	noErr(t, e.p.RevokeNode(ctx, "u1", "main", 3, "l4"))
	e.expectUpdates("c1 mems=0-1")
	for _, c := range []struct{ rel, mems string }{{"kubepods/u1/c1", "0-1"}, {"kubepods/u2/c2", "0-2"}} {
		if got := e.cgroupMems(c.rel); got != c.mems {
			t.Errorf("%s: cgroup mems %q, expected %q", c.rel, got, c.mems)
		}
	}
}

// TestLendNonePinnedClaimed (bug-18 review) checks that with fencing none
// a revoke keeps only the claimed nodes that a pinned container had before
// any lend: a claimed node that only a lend added leaves at the revoke.
// After a plugin restart a claimed node in its cpuset.mems is its own.
func TestLendNonePinnedClaimed(t *testing.T) {
	e := newLtEnv(t)
	e.p.state = fenceClaims()
	ctx := context.Background()
	runClaimed := func(pod *api.PodSandbox, id string, pid uint32, mems string) {
		t.Helper()
		ctr := withClaims(specMems(ltCtr(pod, id, "main", pid), mems), "numa")
		if _, _, err := e.p.CreateContainer(ctx, pod, ctr); err != nil {
			t.Fatal(err)
		}
		e.stub.setSpecOnly(ctr.GetId(), true)
		e.proc(pid, "kubepods/"+pod.GetUid()+"/"+id, mems, mems)
		e.startCtr(pod, ctr)
	}
	// pinned to 0-1, its numa claim of node 2 not in it (fencing none
	// adds nothing)
	runClaimed(ltPod("u1"), "c1", 101, "0-1")
	noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1"))
	e.expectUpdates("c1 mems=0-2")
	noErr(t, e.p.RevokeNode(ctx, "u1", "main", 2, "l1"))
	e.expectUpdates("c1 mems=0-1")
	if got := e.cgroupMems("kubepods/u1/c1"); got != "0-1" {
		t.Fatalf("c1: cgroup mems %q, expected 0-1", got)
	}

	// pinned to 0-2 with its claimed node 2: a lease of node 2 sends
	// nothing, and the node stays at the revoke; a lease of node 3 comes
	// and goes
	runClaimed(ltPod("u2"), "c2", 201, "0-2")
	noErr(t, e.p.LendNode(ctx, "u2", "main", 2, "l2"))
	e.expectUpdates()
	noErr(t, e.p.RevokeNode(ctx, "u2", "main", 2, "l2"))
	e.expectUpdates()
	noErr(t, e.p.LendNode(ctx, "u2", "main", 3, "l3"))
	e.expectUpdates("c2 mems=0-3")
	noErr(t, e.p.RevokeNode(ctx, "u2", "main", 3, "l3"))
	e.expectUpdates("c2 mems=0-2")
	if ref, _ := e.p.Container("u2", "main"); ref.BaseMems != "0-2" {
		t.Fatalf("c2: BaseMems %q, expected 0-2", ref.BaseMems)
	}

	// A restarted plugin: c1 has node 2 of the kept lease l1. It cannot
	// tell a lent node from an own one: the claimed node is kept.
	n := newLtEnv(t)
	n.p.state = fenceClaims()
	leases := &fakeLeases{}
	leases.set("u1", "main", 2, "l1")
	n.p.leases = leases
	pod := ltPod("u1")
	n.proc(101, "kubepods/u1/c1", "0-2", "0-2")
	c1 := withClaims(specMems(ltCtr(pod, "c1", "main", 101), "0-2"), "numa")
	c1.State = api.ContainerState_CONTAINER_RUNNING
	if _, err := n.p.Synchronize(ctx, []*api.PodSandbox{pod}, []*api.Container{c1}); err != nil {
		t.Fatal(err)
	}
	noErr(t, n.p.LendNode(ctx, "u1", "main", 2, "l1"))
	leases.set("u1", "main", 2)
	noErr(t, n.p.RevokeNode(ctx, "u1", "main", 2, "l1"))
	n.expectUpdates()
	if got := n.cgroupMems("kubepods/u1/c1"); got != "0-2" {
		t.Fatalf("c1 after the restart: cgroup mems %q, expected 0-2", got)
	}
}

// TestLendNoneSkipNeedsSpec (bug-18 review) checks that an update that the
// cgroup of a pinned container has already is skipped only when its spec
// has it too: a later update of its resources would write the spec's
// cpuset.mems to the cgroup.
func TestLendNoneSkipNeedsSpec(t *testing.T) {
	e := newLtEnv(t)
	ctx := context.Background()
	pod := ltPod("u1")
	// a lend of the previous plugin reached the cgroup, the spec as the
	// plugin learns it has the nodes of the runtime
	e.proc(101, "kubepods/u1/c1", "0-2", "0-2")
	c1 := specMems(ltCtr(pod, "c1", "main", 101), "0-1")
	c1.State = api.ContainerState_CONTAINER_RUNNING
	if _, err := e.p.Synchronize(ctx, []*api.PodSandbox{pod}, []*api.Container{c1}); err != nil {
		t.Fatal(err)
	}
	noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1"))
	e.expectUpdates("c1 mems=0-2")
	noErr(t, e.p.RevokeNode(ctx, "u1", "main", 2, "l1"))
	e.expectUpdates("c1 mems=0-1")
}

// TestLendNoneParentRestricts (bug-18 review) checks that a lend to an
// inheriting container whose cpuset.mems.effective lacks the node (a
// parent cgroup restricts it) is recorded, without an update, and warned
// about once per new holder.
func TestLendNoneParentRestricts(t *testing.T) {
	e := newLtEnv(t)
	logs := captureKlog(t)
	ctx := context.Background()
	const warning = "NRI lend: lend node 2 for l1: ctr=ns/pod-u1/main id=c1: its cpuset.mems.effective lacks the lent nodes 2 (a parent cgroup restricts it, or they have no memory): it cannot use them"
	// node 2 has memory, but a parent cgroup gives it 0-1 only
	e.run(ltPod("u1"), "c1", "main", 101, "0-1")
	noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1"))
	e.expectUpdates()
	if got := e.p.LentNodes("u1", "main"); !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("lent %v, expected [2]", got)
	}
	out := logs()
	n := strings.Count(out, warning)
	if n == 0 {
		t.Fatalf("no warning %q:\n%s", warning, out)
	}
	// the reconcile of the broker: no warning again
	noErr(t, e.p.LendNode(ctx, "u1", "main", 2, "l1"))
	e.expectUpdates()
	if out := logs(); strings.Count(out, warning) != n {
		t.Fatalf("warned again at a re-lend:\n%s", out)
	}
	if got := e.cgroupMems("kubepods/u1/c1"); got != "" {
		t.Fatalf("cgroup mems %q, expected empty", got)
	}
}

// TestLendsRestoredLogged (bug-18) checks that the plugin logs once when
// NRI has synchronized and the lends are restored, in either order, with
// fencing none too, where no fence pass runs.
func TestLendsRestoredLogged(t *testing.T) {
	const (
		none   = "NRI fence: lends restored (fencing none)"
		fenced = "NRI fence: lends restored, fencing running containers"
	)
	for _, tc := range []struct {
		fencing, line, other string
		restoredFirst        bool
	}{
		{config.FencingNone, none, fenced, false},
		{config.FencingNone, none, fenced, true},
		{config.FencingAllowedMems, fenced, none, false},
		{config.FencingAllowedMems, fenced, none, true},
	} {
		t.Run(fmt.Sprintf("%s/restoredFirst=%v", tc.fencing, tc.restoredFirst), func(t *testing.T) {
			var e *ltEnv
			if tc.fencing == config.FencingAllowedMems {
				e = newFenceEnv(t, "0-2", 2)
			} else {
				e = newLtEnv(t)
			}
			logs := captureKlog(t)
			ctx := context.Background()
			if tc.restoredFirst {
				e.p.LendsRestored()
			} else {
				_, err := e.p.Synchronize(ctx, nil, nil)
				noErr(t, err)
			}
			if out := logs(); strings.Contains(out, "lends restored") {
				t.Fatalf("logged before both:\n%s", out)
			}
			if tc.restoredFirst {
				_, err := e.p.Synchronize(ctx, nil, nil)
				noErr(t, err)
			} else {
				e.p.LendsRestored()
			}
			_, err := e.p.Synchronize(ctx, nil, nil)
			noErr(t, err)
			e.p.LendsRestored()
			e.passes()
			out := logs()
			if n := strings.Count(out, tc.line); n != 1 {
				t.Errorf("%d lines %q, expected 1:\n%s", n, tc.line, out)
			}
			if strings.Contains(out, tc.other) {
				t.Errorf("line %q logged:\n%s", tc.other, out)
			}
		})
	}
}
