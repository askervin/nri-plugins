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
	"k8s.io/utils/cpuset"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cgmpolmgr"
	"github.com/containers/nri-plugins/pkg/cxl/fsm"
)

// Container is the plugin's record of a container of a pod on the node:
// how the plugin manages its memory, the cpuset.mems of its spec as the
// plugin knows it, the NUMA nodes of its allocation results and the nodes
// lent to it.
//
// Identity: ID, the container ID. A restart of the container of a pod is a
// new ID of the same (PodUID, Name), which a lease is bound to; the newest
// record of the pair is its container.
//
// States: Lifecycle (LifecycleTable): UNSEEN, created while the plugin was
// not connected and found by Synchronize, its CreateContainer adjustment was
// never applied; CREATED, its CreateContainer seen, the spec holds
// cpuset.mems, the cgroup may not exist; TASK_CREATED, StartContainer seen,
// the runtime made the cgroup from the spec and an update reaches the spec
// only; STARTED, the runtime marked it started (PostStartContainer, or
// running at Synchronize): updates reach the cgroup; GONE, stopped or
// removed, the record leaves the table. Management (ManagementTable),
// decided once when the record is made: STEERED, a cgmpolmgr manager of this
// process writes its cpuset.mems and memory.high (or will, with its Plan; or
// its settings do not combine any more), never fenced and never lent to;
// FENCED, the plugin owns its cpuset.mems through NRI: wantMems; NONE
// (fencing none): its cpuset.mems is left as the runtime made it, a lend
// changes only one that has a cpuset.mems of its own.
//
// Transitions: LifecycleTable and ManagementTable below; a transition not in
// them is refused. A lend or a revoke changes no state; its rules: a lend to
// a STEERED container is refused (ErrSteered); a lend to a container that
// has not started (UNSEEN, CREATED) is done when the container was lent the
// node at its creation (the READY numa leases of its pod and name, seeded),
// an error otherwise; a revoke of a seeded node drops its holder, and of a
// FENCED container takes the node off its spec; a lend or a revoke of a
// started container (TASK_CREATED, STARTED) recomputes wantMems and sends
// one UpdateContainers outside the table mutex when its cpuset.mems
// changes.
//
// Invariants: a FENCED container's cpuset.mems is wantMems or an update is
// pending (I11); Claimed are the NUMA nodes of the CXL numa memory of the
// results that it uses; a lent node has a holder; Plan only while STEERED
// and not started; manager only while STEERED.
//
// Persistence: none, the table is in memory; Synchronize builds it again
// after a restart, the leases of the store seed the lends, and a Steered
// record of the store names a container whose manager was of a previous
// process.
//
// Locks and waits: the plugin's table mutex guards the record; the update
// token is held from the computation of wantMems to the record of the
// update's result.
type Container struct {
	ID, PodUID, PodNamespace, PodName, Name string
	Lifecycle                               Lifecycle
	Management                              Management
	// Pid is the init pid at its start, 0 before.
	Pid uint32
	// CgroupDir is the container's own cgroup v2 directory, "" until its
	// start resolves it.
	CgroupDir string
	// SpecMems is the cpuset.mems of its spec as the plugin knows it.
	SpecMems string
	// Base are its own memory nodes without the nodes lent to any
	// container.
	Base cpuset.CPUSet
	// Claimed are the NUMA nodes of the CXL numa memory of its results;
	// OwnClaimed those of them that its cpuset.mems had before any lend.
	Claimed, OwnClaimed cpuset.CPUSet
	// Lends are the nodes lent to it with their holders.
	Lends Lends
	// Plan is the steering plan of a steered container until its start.
	Plan *cgmpolmgr.Plan
	// Steering is its effective steering policy with its origin, as the
	// log lines give it: "auto from claim ns/a request r".
	Steering string

	// unsteered is its management when its steering does not start.
	unsteered Management
	// manager steers its memory from its start until it stops.
	manager *cgmpolmgr.Manager
	// seq orders the records by their creation.
	seq uint64
}

// Lifecycle is the phase of a container in the runtime.
type Lifecycle string

// The lifecycle of a container.
const (
	// LifecycleNone is a container that the plugin has no record of.
	LifecycleNone        Lifecycle = "NONE"
	LifecycleUnseen      Lifecycle = "UNSEEN"
	LifecycleCreated     Lifecycle = "CREATED"
	LifecycleTaskCreated Lifecycle = "TASK_CREATED"
	LifecycleStarted     Lifecycle = "STARTED"
	LifecycleGone        Lifecycle = "GONE"
)

// Management is how the plugin manages the memory of a container.
type Management string

// The management of the memory of a container.
const (
	// ManagementUndecided is a record that is being made.
	ManagementUndecided Management = "UNDECIDED"
	ManagementSteered   Management = "STEERED"
	ManagementFenced    Management = "FENCED"
	ManagementNone      Management = "NONE"
)

// Trigger names the NRI event that causes a transition.
type Trigger = fsm.Trigger

const (
	// TriggerCreate is the NRI CreateContainer of a container.
	TriggerCreate Trigger = "NRI CreateContainer"
	// TriggerStart is the NRI StartContainer of a container: its task is
	// created.
	TriggerStart Trigger = "NRI StartContainer"
	// TriggerPostStart is the NRI PostStartContainer of a container: the
	// runtime marked it started.
	TriggerPostStart Trigger = "NRI PostStartContainer"
	// TriggerStop is the NRI StopContainer or RemoveContainer of a
	// container.
	TriggerStop Trigger = "NRI StopContainer"
	// TriggerSynchronize is the NRI Synchronize of the plugin: the
	// containers that the runtime has.
	TriggerSynchronize Trigger = "NRI Synchronize"
)

// Triggers are the triggers of the tables, in the order of the
// documentation.
var Triggers = []Trigger{TriggerCreate, TriggerStart, TriggerPostStart, TriggerStop, TriggerSynchronize,
	TriggerLendsRestored, TriggerNRIStart, TriggerNRIClose, TriggerStopping}

// LifecycleTable is the transition table of Container.Lifecycle.
var LifecycleTable = fsm.Table[Lifecycle]{
	Object: "Container",
	Field:  "Lifecycle",
	States: list(LifecycleNone, LifecycleUnseen, LifecycleCreated, LifecycleTaskCreated, LifecycleStarted,
		LifecycleGone),
	Rows: []fsm.Transition[Lifecycle]{
		{
			From: list(LifecycleNone), To: LifecycleCreated, Triggers: list(TriggerCreate),
			When: "the runtime creates the container",
			Effects: "the management decided; fenced: an adjustment of cpuset.mems iff wantMems differs from " +
				"the spec; the nodes of its READY numa leases recorded as lent (seeded); also when the " +
				"settings of its results do not combine (the creation fails, the record stays with the " +
				"management of the defaults until the container stops)",
		},
		{
			From: list(LifecycleNone), To: LifecycleUnseen, Triggers: list(TriggerSynchronize),
			When:  "Synchronize lists a created, running or paused container that the plugin has no record of",
			Guard: "the first Synchronize of the process",
			Effects: "the management decided from its results; not steered by this process; a manager of a " +
				"previous process (its Steered record, or its settings without any record) released " +
				"(memory.high max); seeded; no adjustment possible",
		},
		{
			From: list(LifecycleUnseen), To: LifecycleStarted, Triggers: list(TriggerSynchronize),
			When:    "Synchronize lists the container running or paused",
			Effects: "its pid, cgroup and own nodes read; its claimed nodes in its cpuset.mems are its own",
		},
		{
			From: list(LifecycleNone, LifecycleUnseen, LifecycleCreated), To: LifecycleTaskCreated,
			Triggers: list(TriggerStart),
			When:     "the runtime has created the task of the container (a record is made for a container that the plugin has none of, with the management of the defaults)",
			Effects: "its pid, cgroup and own nodes read; steered: the Steered record committed (d, bounded) " +
				"before the manager starts; a manager that does not start makes it fenced or none; updates " +
				"from here reach its spec only",
		},
		{
			From: list(LifecycleUnseen, LifecycleCreated, LifecycleTaskCreated), To: LifecycleStarted,
			Triggers: list(TriggerPostStart),
			When:     "the runtime has marked the container started",
			Effects: "its pid, cgroup and own nodes read if StartContainer was not seen; the OnContainerStarted " +
				"callbacks (the broker lends the nodes of its READY numa leases again); fenced: the repair " +
				"pass of the one container (wantMems against its cgroup) once fencing is ready",
		},
		{
			From: list(LifecycleStarted), Stays: true, Triggers: list(TriggerPostStart),
			When: "Synchronize found the container running before its PostStartContainer",
			Effects: "the OnContainerStarted callbacks; fenced: the repair pass of the one container once " +
				"fencing is ready",
		},
		{
			From: list(LifecycleUnseen, LifecycleCreated, LifecycleTaskCreated, LifecycleStarted), To: LifecycleGone,
			Triggers: list(TriggerStop),
			When:     "the runtime stops or removes the container",
			Effects: "the record leaves the table; the OnContainerGone callbacks (the broker keeps its leases " +
				"while the pod lives or a newer instance exists); its manager stopped (memory.high max), then " +
				"its Steered record removed (d, bounded)",
		},
	},
	Refused: []fsm.Refusal[Lifecycle]{
		{From: list(LifecycleGone), Why: "a gone container is out of the table; its restart is a new record"},
		{From: list(LifecycleStarted), To: list(LifecycleNone, LifecycleUnseen, LifecycleCreated, LifecycleTaskCreated),
			Why: "a started container never goes back"},
	},
}

// ManagementTable is the transition table of Container.Management.
var ManagementTable = fsm.Table[Management]{
	Object: "Container",
	Field:  "Management",
	States: list(ManagementUndecided, ManagementSteered, ManagementFenced, ManagementNone),
	Rows: []fsm.Transition[Management]{
		{
			From: list(ManagementUndecided), To: ManagementSteered, Triggers: list(TriggerCreate),
			When:  "the effective settings of its results steer and there is DRAM or CXL numa memory to steer",
			Guard: "the settings of the results combine and a plan is built (else the creation fails)",
			Effects: "the plan kept until its start; no adjustment: it has every node until its manager " +
				"writes its cgroup",
		},
		{
			From: list(ManagementUndecided), To: ManagementSteered, Triggers: list(TriggerSynchronize),
			When:    "the settings of the results of a container that Synchronize finds do not combine",
			Effects: "taken as steered: neither fenced nor lent to",
		},
		{
			From: list(ManagementUndecided), To: ManagementFenced,
			Triggers: list(TriggerCreate, TriggerSynchronize, TriggerStart),
			When: "not steered (by this process) and fencing allowed-mems; the defaults for a container " +
				"whose creation failed or that the plugin has no record of",
			Effects: "wantMems: its own nodes without the fenced nodes, its claimed and its lent nodes",
		},
		{
			From: list(ManagementUndecided), To: ManagementNone,
			Triggers: list(TriggerCreate, TriggerSynchronize, TriggerStart),
			When:     "not steered (by this process) and fencing none",
			Effects:  "its cpuset.mems is left as the runtime made it",
		},
		{
			From: list(ManagementSteered), To: ManagementFenced, Triggers: list(TriggerStart),
			When:    "its manager does not start (no cgroup, cgmpolmgr.New or Start fails) and fencing allowed-mems",
			Effects: "its Steered record removed; fenced by the repair pass at its PostStartContainer",
		},
		{
			From: list(ManagementSteered), To: ManagementNone, Triggers: list(TriggerStart),
			When:    "its manager does not start and fencing none",
			Effects: "its Steered record removed",
		},
	},
	Refused: []fsm.Refusal[Management]{
		{From: list(ManagementFenced, ManagementNone), To: list(ManagementSteered),
			Why: "a container is steered only by a plan of its creation; a re-created container is a new record"},
	},
}

// Catalogue returns the records of the package with their tables, for the
// documentation.
func Catalogue() []state.Object {
	return []state.Object{
		{Name: "Container", Tables: []fsm.TableText{LifecycleTable.Text(), ManagementTable.Text()}},
		{Name: "Plugin", Tables: []fsm.TableText{ReadinessTable.Text(), ConnTable.Text()}},
	}
}

// Lends maps the nodes lent to a container to their holders (the lease
// ids): devices under one CXL host bridge share a NUMA node, so two leases
// of a container may hold one node, which stays lent until its last holder
// revokes it.
type Lends map[int]map[string]bool

// nodes returns the lent nodes that have a holder.
func (l Lends) nodes() cpuset.CPUSet {
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
func (l Lends) with(node int, holder string, lend bool) map[string]bool {
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
func (l Lends) after(node int, holders map[string]bool) cpuset.CPUSet {
	if len(holders) > 0 {
		return l.nodes().Union(cpuset.New(node))
	}
	return l.nodes().Difference(cpuset.New(node))
}

// set returns the lends with the holders of node.
func (l Lends) set(node int, holders map[string]bool) Lends {
	if l == nil {
		l = Lends{}
	}
	if len(holders) == 0 {
		delete(l, node)
	} else {
		l[node] = holders
	}
	return l
}

// name returns the container as namespace/pod/container.
func (c *Container) name() string {
	return c.PodNamespace + "/" + c.PodName + "/" + c.Name
}

// pod returns the pod of the container.
func (c *Container) pod() state.PodRef {
	return state.PodRef{Namespace: c.PodNamespace, Name: c.PodName, UID: c.PodUID}
}

// started tells whether the task of the container is created: its cgroup
// exists, and its own nodes are read from it.
func (c *Container) started() bool {
	return c.Lifecycle == LifecycleTaskCreated || c.Lifecycle == LifecycleStarted
}

// steered tells whether a manager of cgmpolmgr steers the memory of the
// container or will at its start.
func (c *Container) steered() bool {
	return c.Management == ManagementSteered
}

// list returns its arguments as a slice.
func list[S any](values ...S) []S {
	return values
}
