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

package containers

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cgmpolmgr"
	"github.com/containers/nri-plugins/pkg/cxl/config"
)

// managements returns the management and the claimed nodes of the
// records of the table.
func (e *env) managements() map[string]string {
	e.p.mu.Lock()
	defer e.p.mu.Unlock()
	got := map[string]string{}
	for id, c := range e.p.ctrs {
		got[id] = c.Management.text() + " " + c.Claimed.String()
	}
	return got
}

// managers returns the ids of the containers that a manager steers.
func (e *env) managers() []string {
	e.p.mu.Lock()
	defer e.p.mu.Unlock()
	var ids []string
	for id, c := range e.p.ctrs {
		if c.manager != nil || c.Plan != nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// TestLendToUnsteeredNUMAClaim lends a node to a container whose static
// numa claim is not steered, and refuses a lend to one that is.
func TestLendToUnsteeredNUMAClaim(t *testing.T) {
	e := newFenceEnv(t, "0-1", 2)
	e.local.set(nriClaims())
	ctx := context.Background()
	e.readyFence()
	pod := testPod("u1")
	e.proc(101, "kubepods/u1/c1", "0-2", "0-2") // as runc creates it
	c1 := withClaims(testCtr(pod, "c1", "app", 101), "split")
	if got := e.createMems(pod, c1); got != "0-2" {
		t.Fatalf("adjustment %s", got)
	}
	e.startCtr(pod, c1)
	e.passes()
	e.expectUpdates()
	noErr(t, e.p.LendNode(ctx, "u1", "app", 3, "l1"))
	e.expectUpdates("c1 mems=0-3")
	noErr(t, e.p.RevokeNode(ctx, "u1", "app", 3, "l1"))
	e.expectUpdates("c1 mems=0-2")

	e.proc(102, "kubepods/u1/c2", "0-2", "")
	c2 := withClaims(testCtr(pod, "c2", "steered", 102), "auto")
	if got := e.createMems(pod, c2); got != "-" {
		t.Fatalf("adjustment %s of a steered container", got)
	}
	err := e.p.LendNode(ctx, "u1", "steered", 3, "l1")
	if !errors.Is(err, ErrSteered) || !strings.Contains(err.Error(), "lend node 3 to ns/pod-u1/steered: container is memory-steered") {
		t.Fatalf("lend to a steered container: %v", err)
	}
	e.expectUpdates()
}

// TestSynchronizeManagement checks the management of the containers that
// a restarted plugin learns from Synchronize.
func TestSynchronizeManagement(t *testing.T) {
	e := newFenceEnv(t, "0-1", 2)
	e.local.set(nriClaims())
	e.setPool(nriPoolResults())
	ctx := context.Background()
	p1 := testPod("u1")
	var ctrs []*api.Container
	for _, c := range []struct {
		id    string
		pid   uint32
		claim string
	}{{"c1", 101, "auto"}, {"c2", 102, "split"}, {"c3", 103, "pool"}, {"c4", 104, ""}} {
		e.proc(c.pid, "kubepods/u1/"+c.id, "0-2", "")
		ctr := testCtr(p1, c.id, c.id, c.pid)
		if c.claim != "" {
			withClaims(ctr, c.claim)
		}
		ctr.State = api.ContainerState_CONTAINER_RUNNING
		ctrs = append(ctrs, ctr)
	}
	// settings that conflict (the claims changed): taken as steered
	conflict := withClaims(testCtr(p1, "c5", "c5", 0), "auto", "none")
	conflict.State = api.ContainerState_CONTAINER_RUNNING
	ctrs = append(ctrs, conflict)
	_, err := e.p.Synchronize(ctx, []*api.PodSandbox{p1}, ctrs)
	noErr(t, err)
	// c1, that its settings steer, is managed like a container that is not
	// steered
	want := map[string]string{"c1": "fenced 2", "c2": "fenced 2", "c3": "fenced 3", "c4": "fenced ", "c5": "steered "}
	if got := e.managements(); !reflect.DeepEqual(got, want) {
		t.Fatalf("management %v, expected %v", got, want)
	}
	// managers are not restarted
	if ids := e.managers(); len(ids) != 0 {
		t.Fatalf("managers %v", ids)
	}
	e.p.LendsRestored()
	e.passes()
	e.expectUpdates("c1 mems=0-2", "c2 mems=0-2", "c3 mems=0-1,3", "c4 mems=0-1")
	noErr(t, e.p.LendNode(ctx, "u1", "c1", 3, "l1"))
	e.expectUpdates("c1 mems=0-3")
	if err := e.p.LendNode(ctx, "u1", "c5", 3, "l1"); !errors.Is(err, ErrSteered) {
		t.Fatalf("lend to a container with conflicting settings: %v", err)
	}
	noErr(t, e.p.LendNode(ctx, "u1", "c2", 3, "l1"))
	e.expectUpdates("c2 mems=0-3")
}

// TestSynchronizeReleasesSteering checks the running containers of a
// restarted plugin: a container that its settings steer is not
// steered by the new process, and it is fenced like a container that is
// not steered, also one created while the plugin was down that has every
// node (X2). A container that a Steered record of the killed plugin names
// loses the memory.high that its manager left, also one taken as steered;
// the memory.high of the others is left alone (MemoryQoS). The records
// keep only the managers of the new process. A restart of the container is
// steered by a new manager, recorded until it stops.
func TestSynchronizeReleasesSteering(t *testing.T) {
	e := newEnvWith(t, envOptions{steered: map[string]string{"c1": "", "c8": "", "gone": ""}})
	// the records name the cgroups of the env
	noErr(t, e.st.Commit(context.Background(), store.Durable, func(doc *store.Document) error {
		for i := range doc.Steered {
			doc.Steered[i].CgroupDir = filepath.Join(cgroupRoot, "kubepods/u1", doc.Steered[i].Container)
		}
		return nil
	}))
	e.p.Seed([]int{2, 3})
	e.hasMemory("0-3")
	e.local.set(nriClaims())
	e.setPool(nriPoolResults())
	t.Cleanup(e.p.Stop)
	ctx := context.Background()
	p1 := testPod("u1")

	// c1 was steered when the plugin was killed: the cpuset.mems of its
	// manager and the memory.high of its last step
	cg1 := e.proc(101, "kubepods/u1/c1", "0,2", "0,2")
	steerable(t, cg1, "140668928")
	// c2 was created while the plugin was down: every node, memory.high max
	cg2 := e.proc(102, "kubepods/u1/c2", "0-3", "")
	steerable(t, cg2, "max")
	// c3 is not steered, someone else (MemoryQoS) set its memory.high
	cg3 := e.proc(103, "kubepods/u1/c3", "0-3", "")
	steerable(t, cg3, "1073741824")
	// c5's settings conflict: never created by the plugin
	cg5 := e.proc(105, "kubepods/u1/c5", "0-3", "")
	steerable(t, cg5, "268435456")
	// c7 was created while the plugin was down, its settings steer it,
	// MemoryQoS set its memory.high
	cg7 := e.proc(107, "kubepods/u1/c7", "0-3", "")
	steerable(t, cg7, "536870912")
	// c8 was steered by the killed plugin under settings that combined
	// then, they conflict now
	cg8 := e.proc(108, "kubepods/u1/c8", "0,2", "0,2")
	steerable(t, cg8, "201326592")
	c1 := withClaims(testCtr(p1, "c1", "app", 101), "auto")
	c2 := withClaims(testCtr(p1, "c2", "down", 102), "poolauto")
	c3 := withClaims(testCtr(p1, "c3", "plain", 103), "split")
	c5 := withClaims(testCtr(p1, "c5", "conflict", 105), "auto", "none")
	c7 := withClaims(testCtr(p1, "c7", "qos", 107), "auto")
	c8 := withClaims(testCtr(p1, "c8", "changed", 108), "auto", "none")
	for _, c := range []*api.Container{c1, c2, c3, c5, c7, c8} {
		c.State = api.ContainerState_CONTAINER_RUNNING
	}
	// c4 was created by the killed plugin (with a plan), not started
	c4 := withClaims(testCtr(p1, "c4", "late", 0), "auto")
	c4.State = api.ContainerState_CONTAINER_CREATED
	_, err := e.p.Synchronize(ctx, []*api.PodSandbox{p1}, []*api.Container{c1, c2, c3, c4, c5, c7, c8})
	noErr(t, err)

	want := map[string]string{"c1": "fenced 2", "c2": "fenced 3", "c3": "fenced 2", "c4": "fenced 2", "c5": "steered ",
		"c7": "fenced 2", "c8": "steered "}
	if got := e.managements(); !reflect.DeepEqual(got, want) {
		t.Fatalf("management %v, expected %v", got, want)
	}
	if ids := e.managers(); len(ids) != 0 {
		t.Fatalf("managers %v", ids)
	}
	for _, c := range []struct{ dir, high string }{{cg1, "max"}, {cg2, "max"}, {cg3, "1073741824"}, {cg5, "268435456"},
		{cg7, "536870912"}, {cg8, "max"}} {
		if got := memoryHigh(t, c.dir); got != c.high {
			t.Errorf("%s: memory.high %s, expected %s", c.dir, got, c.high)
		}
	}
	if ids := e.steered(); len(ids) != 0 {
		t.Errorf("steering records %v after Synchronize, expected none", ids)
	}

	// the first pass fences them: c2 loses node 2 of another claim
	e.expectUpdates()
	e.p.LendsRestored()
	e.passes()
	e.expectUpdates("c1 mems=0-2", "c2 mems=0-1,3", "c3 mems=0-2", "c4 mems=0-2", "c7 mems=0-2")
	e.check()
	// lent to, as containers that are not steered
	noErr(t, e.p.LendNode(ctx, "u1", "app", 3, "l1"))
	e.expectUpdates("c1 mems=0-3")
	noErr(t, e.p.RevokeNode(ctx, "u1", "app", 3, "l1"))
	e.expectUpdates("c1 mems=0-2")
	if err := e.p.LendNode(ctx, "u1", "conflict", 3, "l1"); !errors.Is(err, ErrSteered) {
		t.Fatalf("lend to a container taken as steered: %v", err)
	}

	// c4 starts without a plan in this process: not steered, fenced (its
	// task is created after the update of its spec)
	e.proc(104, "kubepods/u1/c4", "0-3", "0-2")
	c4.Pid = 104
	e.startCtr(p1, c4)
	e.passes()
	e.expectUpdates()
	if ids := e.managers(); len(ids) != 0 {
		t.Fatalf("managers %v", ids)
	}

	// c1 restarts: the new container gets a plan and a manager
	_, err = e.p.StopContainer(ctx, p1, c1)
	noErr(t, err)
	e.wait(e.gone, "u1", "app")
	cg6 := e.proc(106, "kubepods/u1/c6", "0-3", "")
	steerable(t, cg6, "max")
	c6 := withClaims(testCtr(p1, "c6", "app", 106), "auto")
	if got := e.createMems(p1, c6); got != "-" || e.record("c6").Plan == nil {
		t.Fatalf("adjustment %s of the restarted steered container", got)
	}
	e.startCtr(p1, c6)
	if ids := e.managers(); !reflect.DeepEqual(ids, []string{"c6"}) {
		t.Fatalf("managers %v", ids)
	}
	if got := memoryHigh(t, cg6); got == "max" {
		t.Fatal("restarted container not throttled by its manager")
	}
	if ids := e.steered(); !reflect.DeepEqual(ids, map[string]string{"c6": cg6}) {
		t.Fatalf("steering records %v, expected c6", ids)
	}
	if err := e.p.LendNode(ctx, "u1", "app", 3, "l1"); !errors.Is(err, ErrSteered) {
		t.Fatalf("lend to the restarted steered container: %v", err)
	}
	e.p.pass(ctx, "")
	e.expectUpdates()
	// its stop releases it
	_, err = e.p.StopContainer(ctx, p1, c6)
	noErr(t, err)
	e.wait(e.gone, "u1", "app")
	if got := memoryHigh(t, cg6); got != "max" {
		t.Fatalf("memory.high %s after the stop of the manager", got)
	}
	if ids := e.steered(); len(ids) != 0 {
		t.Fatalf("steering records %v after the stop of the manager", ids)
	}
}

// TestSynchronizeReleasesSteeringLegacy: without Steered records in the
// store (a new store, --new-state, a lost store) a restarted plugin
// releases the started containers that their settings steer, once, and
// keeps the records from then on; with a store that it loaded (also from
// state.json.prev), the containers without a record are left alone.
func TestSynchronizeReleasesSteeringLegacy(t *testing.T) {
	for _, tc := range []struct {
		origin store.Origin
		legacy bool
	}{{store.New, true}, {store.NewState, true}, {store.Lost, true}, {store.Loaded, false}, {store.FromPrev, false}} {
		t.Run(fmtOrigin(tc.origin), func(t *testing.T) {
			e := newEnvWith(t, envOptions{origin: tc.origin})
			e.p.Seed([]int{2})
			e.hasMemory("0-3")
			e.local.set(nriClaims())
			if e.p.legacy != tc.legacy {
				t.Fatalf("legacy %v", e.p.legacy)
			}
			ctx := context.Background()
			p1 := testPod("u1")
			cg1 := e.proc(101, "kubepods/u1/c1", "0,2", "0,2")
			steerable(t, cg1, "140668928")
			cg3 := e.proc(103, "kubepods/u1/c3", "0-3", "")
			steerable(t, cg3, "1073741824")
			c1 := withClaims(testCtr(p1, "c1", "app", 101), "auto")
			c3 := withClaims(testCtr(p1, "c3", "plain", 103), "split")
			c1.State, c3.State = api.ContainerState_CONTAINER_RUNNING, api.ContainerState_CONTAINER_RUNNING
			// created, not started: no manager can have written it
			c4 := withClaims(testCtr(p1, "c4", "late", 0), "auto")
			c4.State = api.ContainerState_CONTAINER_CREATED
			_, err := e.p.Synchronize(ctx, []*api.PodSandbox{p1}, []*api.Container{c1, c3, c4})
			noErr(t, err)
			want := "140668928"
			if tc.legacy {
				want = "max"
			}
			if got := memoryHigh(t, cg1); got != want {
				t.Errorf("memory.high %s of a container that its settings steer, expected %s", got, want)
			}
			if got := memoryHigh(t, cg3); got != "1073741824" {
				t.Errorf("memory.high %s of a container that is not steered", got)
			}
			if ids := e.steered(); len(ids) != 0 || e.p.legacy {
				t.Errorf("steering records %v (legacy %v) after Synchronize", ids, e.p.legacy)
			}
		})
	}
}

// fmtOrigin returns the name of a store origin.
func fmtOrigin(o store.Origin) string {
	return map[store.Origin]string{store.Loaded: "Loaded", store.FromPrev: "FromPrev", store.New: "New",
		store.NewState: "NewState", store.Lost: "Lost"}[o]
}

// A container steered by a killed plugin under the old defaults (steering
// policy auto) is released by the plugin restarted with new defaults (no
// steering) that do not steer it: the Steered record names it.
func TestReviewReleaseAfterDefaultsChange(t *testing.T) {
	old := newDecider(t, config.Container{Steering: &config.Steering{Policy: config.PolicyAuto}})
	d, err := old.decide("x", old.results(testPod("p"), "x", []resultRef{{uid: "split", n: 0}, {uid: "split", n: 2}}), false)
	noErr(t, err)
	if d.management != ManagementSteered {
		t.Fatalf("precondition: old defaults do not steer: %s", d.management)
	}
	e := newEnvWith(t, envOptions{steered: map[string]string{"c1": ""}})
	e.p.Seed([]int{2})
	e.hasMemory("0-3")
	e.local.set(nriClaims())
	pod := testPod("u1")
	cg := e.proc(101, "kubepods/u1/c1", "0,2", "0,2")
	steerable(t, cg, "140668928")
	c1 := testCtr(pod, "c1", "app", 101)
	c1.Env = append(c1.Env, state.ResultEnvVarName("split", 0)+"=1", state.ResultEnvVarName("split", 2)+"=1")
	c1.State = api.ContainerState_CONTAINER_RUNNING
	_, err = e.p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{c1})
	noErr(t, err)
	if got := memoryHigh(t, cg); got != "max" {
		t.Errorf("memory.high %s of the dead manager kept after a defaults change", got)
	}
	if m := e.record("c1").Management; m != ManagementFenced {
		t.Errorf("management %s, expected fenced", m)
	}
}

// A steered container whose manager does not start is managed like a
// container that is not steered: fenced by the repair pass
// of its PostStartContainer, lent to, and not in the Steered records.
func TestSteeringStartFails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(e *env) // the cgroup of c1 (pid 101)
	}{
		{"no cgroup", func(e *env) {}},
		{"manager start fails", func(e *env) {
			// no memory.numa_stat: the manager cannot read the usage
			e.proc(101, "kubepods/u1/c1", "0-3", "")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newFenceEnv(t, "0-3", 2, 3)
			e.local.set(nriClaims())
			ctx := context.Background()
			e.readyFence()
			pod := testPod("u1")
			c1 := withClaims(testCtr(pod, "c1", "app", 101), "auto")
			if got := e.createMems(pod, c1); got != "-" || e.record("c1").Plan == nil {
				t.Fatalf("adjustment %s of a steered container", got)
			}
			tc.setup(e)
			e.startCtr(pod, c1)
			if c := e.record("c1"); c.Management != ManagementFenced || len(e.managers()) != 0 {
				t.Fatalf("management %s managers %v, expected fenced without a manager", c.Management, e.managers())
			}
			if ids := e.steered(); len(ids) != 0 {
				t.Fatalf("steering records %v", ids)
			}
			e.expectUpdates("c1 mems=0-2")
			if tc.name == "no cgroup" {
				// its cgroup is unknown: the pass updates its spec
				return
			}
			if got := e.cgroupMems("kubepods/u1/c1"); got != "0-2" {
				t.Fatalf("cgroup cpuset.mems %s", got)
			}
			noErr(t, e.p.LendNode(ctx, "u1", "app", 3, "l1"))
			e.expectUpdates("c1 mems=0-3")
		})
	}
	// fencing none: not steered, its cpuset.mems left alone
	e := newEnv(t)
	e.local.set(nriClaims())
	pod := testPod("u1")
	c1 := withClaims(testCtr(pod, "c1", "app", 101), "auto")
	if got := e.createMems(pod, c1); got != "-" || e.record("c1").Management != ManagementSteered {
		t.Fatalf("adjustment %s of a steered container", got)
	}
	e.proc(101, "kubepods/u1/c1", "0-3", "")
	e.startCtr(pod, c1)
	if c := e.record("c1"); c.Management != ManagementNone || len(e.managers()) != 0 || len(e.steered()) != 0 {
		t.Fatalf("record %+v, managers %v", c, e.managers())
	}
	noErr(t, e.p.LendNode(context.Background(), "u1", "app", 3, "l1"))
	e.expectUpdates()
}

// TestCharSynchronizeSteeringLog pins the lines of the containers whose
// steering a restarted plugin does not restart: one that a Steered record
// of the killed plugin names (memory.high released) and one that its
// settings steer without a record (memory.high left alone).
func TestCharSynchronizeSteeringLog(t *testing.T) {
	e := newEnvWith(t, envOptions{steered: map[string]string{"c1": ""}})
	e.p.Seed([]int{2})
	e.hasMemory("0-3")
	e.local.set(nriClaims())
	logs := captureKlog(t)
	ctx := context.Background()
	p1 := testPod("u1")
	cg1 := e.proc(101, "kubepods/u1/c1", "0,2", "0,2")
	steerable(t, cg1, "140668928")
	cg7 := e.proc(107, "kubepods/u1/c7", "0-3", "")
	steerable(t, cg7, "536870912")
	c1 := withClaims(testCtr(p1, "c1", "app", 101), "auto")
	c7 := withClaims(testCtr(p1, "c7", "qos", 107), "auto")
	c1.State, c7.State = api.ContainerState_CONTAINER_RUNNING, api.ContainerState_CONTAINER_RUNNING
	_, err := e.p.Synchronize(ctx, []*api.PodSandbox{p1}, []*api.Container{c1, c7})
	noErr(t, err)
	for _, line := range []string{
		"NRI Synchronize: ctr=ns/pod-u1/app id=c1: steering not restarted, memory fenced; memory.high 140668928 removed (max)",
		"NRI Synchronize: ctr=ns/pod-u1/qos id=c7: steering not restarted, memory fenced; memory.high left alone: no manager steered it",
	} {
		if !strings.Contains(logs(), line) {
			t.Errorf("no line %q:\n%s", line, logs())
		}
	}
	if got := memoryHigh(t, cg1); got != "max" {
		t.Errorf("memory.high %s of the recorded container", got)
	}
	if got := memoryHigh(t, cg7); got != "536870912" {
		t.Errorf("memory.high %s of the container without a record", got)
	}
}

// TestSteeredRecordBeforeStart checks that the Steered record of a
// container is in the store when its manager starts to write its cgroup,
// and that a Start that fails leaves no record.
func TestSteeredRecordBeforeStart(t *testing.T) {
	e := newFenceEnv(t, "0-3", 2)
	e.local.set(nriClaims())
	e.readyFence()
	t.Cleanup(e.p.Stop)
	pod := testPod("u1")
	var at map[string]string
	old := startManager
	t.Cleanup(func() { startManager = old })
	startManager = func(m *cgmpolmgr.Manager) error {
		at = e.steered()
		return old(m)
	}
	cg1 := e.proc(101, "kubepods/u1/c1", "0-3", "")
	steerable(t, cg1, "max")
	c1 := withClaims(testCtr(pod, "c1", "app", 101), "auto")
	if got := e.createMems(pod, c1); got != "-" {
		t.Fatalf("adjustment %s", got)
	}
	e.startCtr(pod, c1)
	if !reflect.DeepEqual(at, map[string]string{"c1": cg1}) {
		t.Fatalf("steering records %v at the start of the manager, expected c1", at)
	}
	if got := memoryHigh(t, cg1); got == "max" {
		t.Fatal("not steered")
	}

	startManager = func(*cgmpolmgr.Manager) error {
		at = e.steered()
		return errors.New("no cgroup any more")
	}
	cg2 := e.proc(102, "kubepods/u1/c2", "0-3", "")
	steerable(t, cg2, "max")
	c2 := withClaims(testCtr(pod, "c2", "app2", 102), "auto")
	e.createMems(pod, c2)
	e.startCtr(pod, c2)
	if at["c2"] != cg2 {
		t.Fatalf("steering records %v at the start of the manager, expected c2", at)
	}
	if got := e.steered(); !reflect.DeepEqual(got, map[string]string{"c1": cg1}) {
		t.Fatalf("steering records %v after a failed start, expected c1", got)
	}
	if c := e.record("c2"); c.Management != ManagementFenced {
		t.Fatalf("management %s after a failed start", c.Management)
	}
}
