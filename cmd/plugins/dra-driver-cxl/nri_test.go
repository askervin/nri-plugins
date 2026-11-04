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
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/net/multiplex"
	"github.com/containerd/ttrpc"

	"github.com/containers/nri-plugins/pkg/cgmpolmgr"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// claimSettings returns the container settings of a result whose claim
// ns/<claim> request <request> sets the steering.
func claimSettings(claim, request string, s config.Steering) config.ResultSettings {
	origin := "claim ns/" + claim + " request " + request
	rs := config.ResultSettings{Container: &config.Container{Steering: &s}, Origins: map[string]string{}}
	if s.Policy != "" {
		rs.Origins[config.FieldPolicy] = origin
	}
	if s.MinStep != "" {
		rs.Origins[config.FieldMinStep] = origin
	}
	if s.MaxStep != "" {
		rs.Origins[config.FieldMaxStep] = origin
	}
	return rs
}

// nriClaims is a node state with prepared claims of cxl.nri.io:
//   - split: result 0 a numa slice on node 2, result 1 a dax slice, result
//     2 DRAM on nodes 0-1, result 3 a region on node 4
//   - auto: a numa slice on node 2 that opts in with policy auto
//   - none: a numa slice on node 2 that says policy none
//   - dram: DRAM on node 0 with policy first-dram and maxStep 64Mi
//   - lease: the lease device
func nriClaims() *nodeState {
	auto := claimSettings("auto", "mem", config.Steering{Policy: config.PolicyAuto})
	return &nodeState{baseState: &baseState{}, preparedClaims: PreparedClaimsInfo{
		"split": {ClaimName: "ns/split", Devices: []PreparedDeviceInfo{
			{Result: 0, RequestName: "numa", DeviceType: device.DeviceTypeMemdev, Mode: api.ModeNUMA, NUMANodes: []int{2}, ConsumedBytes: 1 << 30},
			{Result: 1, RequestName: "dax", DeviceType: device.DeviceTypeMemdev, Mode: api.ModeDax, ConsumedBytes: 1 << 30},
			{Result: 2, RequestName: "dram", DeviceType: device.DeviceTypeDRAM, Mode: api.ModeNUMA, NUMANodes: []int{1, 0}, ConsumedBytes: 2 << 30},
			{Result: 3, RequestName: "region", DeviceType: device.DeviceTypeRegion, Mode: api.ModeNUMA, NUMANodes: []int{4}, ConsumedBytes: 1 << 30},
		}},
		"auto": {ClaimName: "ns/auto", Devices: []PreparedDeviceInfo{
			{RequestName: "mem", DeviceType: device.DeviceTypeMemdev, Mode: api.ModeNUMA, NUMANodes: []int{2}, ConsumedBytes: 1 << 30, ResultSettings: auto},
		}},
		"none": {ClaimName: "ns/none", Devices: []PreparedDeviceInfo{
			{RequestName: "mem", DeviceType: device.DeviceTypeMemdev, Mode: api.ModeNUMA, NUMANodes: []int{2}, ConsumedBytes: 1 << 30,
				ResultSettings: claimSettings("none", "mem", config.Steering{Policy: config.PolicyNone})},
		}},
		"dram": {ClaimName: "ns/dram", Devices: []PreparedDeviceInfo{
			{RequestName: "mem", DeviceType: device.DeviceTypeDRAM, Mode: api.ModeNUMA, NUMANodes: []int{0}, ConsumedBytes: 1 << 30,
				ResultSettings: claimSettings("dram", "mem", config.Steering{Policy: config.PolicyFirstDRAM, MaxStep: "64Mi"})},
		}},
		"lease": {ClaimName: "ns/lease", Devices: []PreparedDeviceInfo{{RequestName: "lease", DeviceType: device.DeviceTypeLease}}},
	}}
}

// nriPoolResults returns the prepared results of pool claims: pool result 0
// a numa device on node 3, result 1 a dax device; poolauto a numa device on
// node 3 that opts in with policy auto.
func nriPoolResults(uid string) []poolResult {
	return map[string][]poolResult{
		"pool": {
			{Index: 0, Request: "numa", Mode: api.ModeNUMA, Node: 3, Size: 256 << 20},
			{Index: 1, Request: "dax", Mode: api.ModeDax, Node: -1, Size: 256 << 20},
		},
		"poolauto": {
			{Index: 0, Request: "mem", Mode: api.ModeNUMA, Node: 3, Size: 256 << 20,
				Settings: claimSettings("poolauto", "mem", config.Steering{Policy: config.PolicyAuto})},
		},
	}[uid]
}

func TestResultMarkers(t *testing.T) {
	uid := "0a1b2c3d-0000-1111-2222-333344445555"
	if got := resultEnvVarName(uid, 3); got != "CXL_CLAIM_0a1b2c3d_0000_1111_2222_333344445555_3" {
		t.Fatalf("marker %s", got)
	}
	ref, ok := resultFromEnvVar(resultEnvVarName(uid, 12) + "=1")
	if !ok || ref != (resultRef{uid: uid, n: 12}) {
		t.Fatalf("parsed %+v %v", ref, ok)
	}
	for _, env := range []string{"PATH=/bin", "CXL_CLAIM_u1=1", "CXL_CLAIM_u1_x=1",
		"CXL_CLAIM__1=1", "CXL_CLAIM_u1_+1=1", "CXL_CLAIM_u1_01=1", "CXL_CLAIM_u1_-1=1", "CXL_C1EE0001_SIZE=1"} {
		if ref, ok := resultFromEnvVar(env); ok {
			t.Errorf("%s: parsed %+v", env, ref)
		}
	}

	uid2 := "6a1b2c3d-0000-1111-2222-333344445555"
	env := []string{"PATH=/bin", resultEnvVarName(uid, 0) + "=1", "CXL_C1EE0001_SIZE=1", resultEnvVarName(uid2, 1) + "=1",
		resultEnvVarName(uid, 0) + "=1", resultEnvVarName(uid, 2) + "=1"}
	if got := extractResults(env); !reflect.DeepEqual(got, []resultRef{{uid, 0}, {uid2, 1}, {uid, 2}}) {
		t.Fatalf("results %v", got)
	}
	if got := extractResults([]string{"PATH=/bin"}); got != nil {
		t.Fatalf("results %v of no markers", got)
	}
}

// TestContainerResults checks that a container gets the memory and the
// claimed nodes of the results that it uses only (a claim with requests
// used by different containers), of both drivers.
func TestContainerResults(t *testing.T) {
	p := &nriPlugin{state: nriClaims(), poolResults: nriPoolResults}
	for _, tc := range []struct {
		refs    []resultRef
		mem     cgmpolmgr.MemoryTypes
		claimed string
	}{
		{[]resultRef{{"split", 0}}, cgmpolmgr.MemoryTypes{CXLNodes: []int{2}, CXLQuota: 1 << 30}, "2"},
		{[]resultRef{{"split", 1}}, cgmpolmgr.MemoryTypes{}, ""},
		{[]resultRef{{"split", 2}}, cgmpolmgr.MemoryTypes{DRAMNodes: []int{0, 1}, DRAMQuota: 2 << 30}, ""},
		{[]resultRef{{"split", 3}}, cgmpolmgr.MemoryTypes{CXLNodes: []int{4}, CXLQuota: 1 << 30}, "4"},
		{[]resultRef{{"split", 0}, {"split", 2}, {"pool", 0}},
			cgmpolmgr.MemoryTypes{DRAMNodes: []int{0, 1}, CXLNodes: []int{2, 3}, DRAMQuota: 2 << 30, CXLQuota: 1<<30 + 256<<20}, "2-3"},
		{[]resultRef{{"pool", 1}, {"lease", 0}}, cgmpolmgr.MemoryTypes{}, ""},
		// unknown claims and results
		{[]resultRef{{"split", 7}, {"gone", 0}, {"pool", 2}}, cgmpolmgr.MemoryTypes{}, ""},
	} {
		results := p.containerResults("ns/pod/ctr", tc.refs)
		if mem := steeredMemory(results); fmt.Sprint(mem) != fmt.Sprint(tc.mem) {
			t.Errorf("%v: memory %+v, expected %+v", tc.refs, mem, tc.mem)
		}
		if got := claimedNodes(results).String(); got != tc.claimed {
			t.Errorf("%v: claimed nodes %q, expected %q", tc.refs, got, tc.claimed)
		}
	}
	// without state and pool driver
	if got := (&nriPlugin{}).containerResults("ns/pod/ctr", []resultRef{{"split", 0}}); got != nil {
		t.Fatalf("results %+v", got)
	}
}

func TestManage(t *testing.T) {
	auto := config.Container{Steering: &config.Steering{Policy: config.PolicyAuto}}
	fencingNone := config.Container{Fencing: config.FencingNone}
	for _, tc := range []struct {
		name     string
		defaults config.Container
		refs     []resultRef
		memory   string // or the error
		claimed  string
		policy   string // memory use order of the plan
		text     string // steering of the log
		fencing  string // fencing of the log
	}{
		{name: "no results", memory: memoryFenced, text: "none (default)", fencing: "allowed-mems (default)"},
		{name: "numa claim, default none", refs: []resultRef{{"split", 0}}, memory: memoryFenced, claimed: "2", text: "none (default)"},
		{name: "numa claim, fencing none", defaults: fencingNone, refs: []resultRef{{"split", 0}}, memory: memoryNone, claimed: "2",
			fencing: "none (node default)"},
		{name: "numa claim, auto", refs: []resultRef{{"auto", 0}}, memory: memorySteered, claimed: "2", policy: "first-cxl",
			text: "auto from claim ns/auto request mem"},
		{name: "numa and dram, auto", refs: []resultRef{{"auto", 0}, {"split", 2}}, memory: memorySteered, claimed: "2", policy: "start-interleaved"},
		{name: "dram, first-dram", refs: []resultRef{{"dram", 0}}, memory: memorySteered, policy: "first-dram"},
		{name: "dram, default none", refs: []resultRef{{"split", 2}}, memory: memoryFenced},
		{name: "node default auto", defaults: auto, refs: []resultRef{{"split", 0}, {"split", 3}}, memory: memorySteered, claimed: "2,4",
			policy: "first-cxl", text: "auto (node default)"},
		{name: "node default auto, claim none", defaults: auto, refs: []resultRef{{"none", 0}}, memory: memoryFenced, claimed: "2",
			text: "none from claim ns/none request mem"},
		{name: "node default auto, no numa memory", defaults: auto, refs: []resultRef{{"split", 1}, {"lease", 0}}, memory: memoryFenced},
		{name: "pool numa, default none", refs: []resultRef{{"pool", 0}}, memory: memoryFenced, claimed: "3"},
		{name: "pool numa, auto", refs: []resultRef{{"poolauto", 0}}, memory: memorySteered, claimed: "3", policy: "first-cxl"},
		{name: "pool numa, node default auto", defaults: auto, refs: []resultRef{{"pool", 0}}, memory: memorySteered, claimed: "3", policy: "first-cxl"},
		{name: "local and pool numa, auto", refs: []resultRef{{"auto", 0}, {"poolauto", 0}}, memory: memorySteered, claimed: "2-3", policy: "first-cxl"},
		{name: "conflict", refs: []resultRef{{"auto", 0}, {"none", 0}},
			memory: "container ns/pod/ctr: container.steering.policy: claim ns/auto request mem says auto, claim ns/none request mem says none"},
		{name: "conflict with node default", defaults: auto, refs: []resultRef{{"dram", 0}, {"none", 0}},
			memory: "container ns/pod/ctr: container.steering.policy: claim ns/dram request mem says first-dram, claim ns/none request mem says none"},
	} {
		p := &nriPlugin{state: nriClaims(), poolResults: nriPoolResults, defaults: tc.defaults}
		m, err := p.manage("ns/pod/ctr", p.containerResults("ns/pod/ctr", tc.refs), true)
		if err != nil {
			if err.Error() != tc.memory {
				t.Errorf("%s: %v, expected %s", tc.name, err, tc.memory)
			}
			continue
		}
		if m.memory != tc.memory || m.claimed.String() != tc.claimed {
			t.Errorf("%s: memory %s claimed %q, expected %s %q", tc.name, m.memory, m.claimed, tc.memory, tc.claimed)
		}
		if (m.plan != nil) != (tc.policy != "") || m.policy != tc.policy {
			t.Errorf("%s: plan %v order %q, expected %q", tc.name, m.plan, m.policy, tc.policy)
		}
		if tc.text != "" && m.eff.PolicyText() != tc.text {
			t.Errorf("%s: steering %q, expected %q", tc.name, m.eff.PolicyText(), tc.text)
		}
		if tc.fencing != "" && fencingText(m.eff) != tc.fencing {
			t.Errorf("%s: fencing %q, expected %q", tc.name, fencingText(m.eff), tc.fencing)
		}
	}

	// an invalid effective steering names the origins
	p := &nriPlugin{state: nriClaims()}
	results := []containerResult{{settings: claimSettings("a", "r", config.Steering{MaxStep: "1Gi"})}}
	_, err := p.manage("ns/pod/ctr", results, true)
	wantErr(t, err, "container ns/pod/ctr: MemoryConfig: container.steering.maxStep needs a policy other than none (policy none (default), maxStep 1Gi from claim ns/a request r)")
	// no plan of a quota that cgmpolmgr refuses
	results = []containerResult{{deviceType: device.DeviceTypeDRAM, mode: api.ModeNUMA, nodes: []int{0},
		settings: claimSettings("a", "r", config.Steering{Policy: config.PolicyFirstDRAM, MinStep: "1Gi"})}}
	_, err = p.manage("ns/pod/ctr", results, true)
	wantErr(t, err, "NRI CreateContainer: ctr=ns/pod/ctr: failed to build memory steering plan")
	if m, err := p.manage("ns/pod/ctr", results, false); err != nil || m.memory != memorySteered || m.plan != nil {
		t.Fatalf("without a plan: %+v %v", m, err)
	}
}

// TestCreateContainerManagement creates containers that use results of
// claims through NRI: the management, the plan and the refusal of
// conflicting settings.
func TestCreateContainerManagement(t *testing.T) {
	e := newFenceEnv(t, "0-1", 2)
	e.p.state = nriClaims()
	e.p.poolResults = nriPoolResults
	pod := ltPod("u1")
	memory := func(id string) string {
		e.p.mu.Lock()
		defer e.p.mu.Unlock()
		return e.p.ctrs[id].memory
	}

	// a numa claim is not steered by default: fenced with its node, no plan
	ctr := &nriapi.Container{Id: "c1", PodSandboxId: pod.GetId(), Name: "a", Env: []string{resultEnvVarName("split", 0) + "=1"}}
	if got := e.createMems(pod, ctr); got != "0-2" || memory("c1") != memoryFenced || e.p.pending["c1"].plan != nil {
		t.Fatalf("adjustment %s, memory %s", got, memory("c1"))
	}
	// no results, and the dax result of the same claim: no node
	if got := e.createMems(pod, withClaims(ltCtr(pod, "c2", "b", 0))); got != "0-1" {
		t.Fatalf("adjustment %s of a container without results", got)
	}
	ctr = &nriapi.Container{Id: "c3", PodSandboxId: pod.GetId(), Name: "c", Env: []string{resultEnvVarName("split", 1) + "=1"}}
	if got := e.createMems(pod, ctr); got != "0-1" || memory("c3") != memoryFenced {
		t.Fatalf("adjustment %s of the dax result", got)
	}
	// opted in: steered, a plan, no adjustment
	if got := e.createMems(pod, withClaims(ltCtr(pod, "c4", "d", 0), "auto")); got != "-" || memory("c4") != memorySteered || e.p.pending["c4"].plan == nil {
		t.Fatalf("adjustment %s, memory %s of an opted-in container", got, memory("c4"))
	}
	// pool numa memory is steered on opt-in
	if got := e.createMems(pod, withClaims(ltCtr(pod, "c5", "e", 0), "poolauto")); got != "-" || memory("c5") != memorySteered {
		t.Fatalf("adjustment %s, memory %s of an opted-in pool container", got, memory("c5"))
	}
	// conflicting policies: not created
	_, _, err := e.p.CreateContainer(context.Background(), pod, withClaims(ltCtr(pod, "c6", "f", 0), "auto", "none"))
	wantErr(t, err, "container ns/pod-u1/f: container.steering.policy: claim ns/auto request mem says auto, claim ns/none request mem says none")
	if e.p.pending["c6"].plan != nil {
		t.Fatal("plan of a refused container")
	}
	e.expectUpdates()
}

// TestLendToUnsteeredNUMAClaim lends a node to a container whose static
// numa claim is not steered, and refuses a lend to one that is.
func TestLendToUnsteeredNUMAClaim(t *testing.T) {
	e := newFenceEnv(t, "0-1", 2)
	e.p.state = nriClaims()
	ctx := context.Background()
	if _, err := e.p.Synchronize(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	e.p.LendsRestored()
	e.passes()
	pod := ltPod("u1")
	e.proc(101, "kubepods/u1/c1", "0-2", "0-2") // as runc creates it
	c1 := withClaims(ltCtr(pod, "c1", "app", 101), "split")
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
	c2 := withClaims(ltCtr(pod, "c2", "steered", 102), "auto")
	if got := e.createMems(pod, c2); got != "-" {
		t.Fatalf("adjustment %s of a steered container", got)
	}
	err := e.p.LendNode(ctx, "u1", "steered", 3, "l1")
	if !errors.Is(err, errSteered) || !strings.Contains(err.Error(), "lend node 3 to ns/pod-u1/steered: container is memory-steered") {
		t.Fatalf("lend to a steered container: %v", err)
	}
	e.expectUpdates()
}

// TestSynchronizeManagement checks the management of the containers that
// a restarted plugin learns from Synchronize.
func TestSynchronizeManagement(t *testing.T) {
	e := newFenceEnv(t, "0-1", 2)
	e.p.state = nriClaims()
	e.p.poolResults = nriPoolResults
	ctx := context.Background()
	p1 := ltPod("u1")
	var ctrs []*nriapi.Container
	for _, c := range []struct {
		id    string
		pid   uint32
		claim string
	}{{"c1", 101, "auto"}, {"c2", 102, "split"}, {"c3", 103, "pool"}, {"c4", 104, ""}} {
		e.proc(c.pid, "kubepods/u1/"+c.id, "0-2", "")
		ctr := ltCtr(p1, c.id, c.id, c.pid)
		if c.claim != "" {
			withClaims(ctr, c.claim)
		}
		ctr.State = nriapi.ContainerState_CONTAINER_RUNNING
		ctrs = append(ctrs, ctr)
	}
	// settings that conflict (the claims changed): taken as steered
	conflict := withClaims(ltCtr(p1, "c5", "c5", 0), "auto", "none")
	conflict.State = nriapi.ContainerState_CONTAINER_RUNNING
	ctrs = append(ctrs, conflict)
	if _, err := e.p.Synchronize(ctx, []*nriapi.PodSandbox{p1}, ctrs); err != nil {
		t.Fatal(err)
	}
	e.p.mu.Lock()
	got := map[string]string{}
	for id, tc := range e.p.ctrs {
		got[id] = tc.memory + " " + tc.claimed.String()
	}
	e.p.mu.Unlock()
	// c1, that its settings steer, is managed like a container that is not
	// steered
	want := map[string]string{"c1": "fenced 2", "c2": "fenced 2", "c3": "fenced 3", "c4": "fenced ", "c5": "steered "}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("management %v, expected %v", got, want)
	}
	// managers are not restarted
	if len(e.p.managers) != 0 || len(e.p.pending) != 0 {
		t.Fatalf("managers %v pending %v", e.p.managers, e.p.pending)
	}
	e.p.LendsRestored()
	e.passes()
	e.expectUpdates("c1 mems=0-2", "c2 mems=0-2", "c3 mems=0-1,3", "c4 mems=0-1")
	noErr(t, e.p.LendNode(ctx, "u1", "c1", 3, "l1"))
	e.expectUpdates("c1 mems=0-3")
	if err := e.p.LendNode(ctx, "u1", "c5", 3, "l1"); !errors.Is(err, errSteered) {
		t.Fatalf("lend to a container with conflicting settings: %v", err)
	}
	noErr(t, e.p.LendNode(ctx, "u1", "c2", 3, "l1"))
	e.expectUpdates("c2 mems=0-3")
}

// steerableCgroup gives the cgroup dir the files that a steering manager
// reads and writes, with memory.high high.
func steerableCgroup(t *testing.T, dir, high string) {
	t.Helper()
	for name, data := range map[string]string{
		"memory.high":      high,
		"memory.current":   "4096",
		"memory.events":    "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0",
		"memory.numa_stat": "anon N0=4096 N1=0 N2=0 N3=0\nshmem N0=0 N1=0 N2=0 N3=0",
		"cgroup.procs":     "",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// memoryHigh returns memory.high of the cgroup dir.
func memoryHigh(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "memory.high"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

// steeredFile writes the steering record of a killed plugin (container ID
// -> cgroup directory) to a file and returns the path.
func steeredFile(t *testing.T, ids map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), steeredFileName)
	noErr(t, writeJSONFile(path, ids))
	return path
}

// readSteeredFile returns the containers of the steering record file.
func readSteeredFile(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	noErr(t, err)
	ids := map[string]string{}
	noErr(t, json.Unmarshal(data, &ids))
	return ids
}

// TestSynchronizeReleasesSteering checks the running containers of a
// restarted plugin (bug-04): a container that its settings steer is not
// steered by the new process, and it is fenced like a container that is
// not steered, also one created while the plugin was down that has every
// node (X2). A container that the steering record of the killed plugin
// names loses the memory.high that its manager left, also one taken as
// steered; the memory.high of the others is left alone (MemoryQoS). The
// record keeps only the managers of the new process. A restart of the
// container is steered by a new manager, recorded until it stops.
func TestSynchronizeReleasesSteering(t *testing.T) {
	e := newFenceEnv(t, "0-3", 2, 3)
	e.p.state = nriClaims()
	e.p.poolResults = nriPoolResults
	t.Cleanup(e.p.Stop)
	ctx := context.Background()
	p1 := ltPod("u1")

	// c1 was steered when the plugin was killed: the cpuset.mems of its
	// manager and the memory.high of its last step
	cg1 := e.proc(101, "kubepods/u1/c1", "0,2", "0,2")
	steerableCgroup(t, cg1, "140668928")
	// c2 was created while the plugin was down: every node, memory.high max
	cg2 := e.proc(102, "kubepods/u1/c2", "0-3", "")
	steerableCgroup(t, cg2, "max")
	// c3 is not steered, someone else (MemoryQoS) set its memory.high
	cg3 := e.proc(103, "kubepods/u1/c3", "0-3", "")
	steerableCgroup(t, cg3, "1073741824")
	// c5's settings conflict: never created by the plugin
	cg5 := e.proc(105, "kubepods/u1/c5", "0-3", "")
	steerableCgroup(t, cg5, "268435456")
	// c7 was created while the plugin was down, its settings steer it,
	// MemoryQoS set its memory.high
	cg7 := e.proc(107, "kubepods/u1/c7", "0-3", "")
	steerableCgroup(t, cg7, "536870912")
	// c8 was steered by the killed plugin under settings that combined
	// then, they conflict now
	cg8 := e.proc(108, "kubepods/u1/c8", "0,2", "0,2")
	steerableCgroup(t, cg8, "201326592")
	c1 := withClaims(ltCtr(p1, "c1", "app", 101), "auto")
	c2 := withClaims(ltCtr(p1, "c2", "down", 102), "poolauto")
	c3 := withClaims(ltCtr(p1, "c3", "plain", 103), "split")
	c5 := withClaims(ltCtr(p1, "c5", "conflict", 105), "auto", "none")
	c7 := withClaims(ltCtr(p1, "c7", "qos", 107), "auto")
	c8 := withClaims(ltCtr(p1, "c8", "changed", 108), "auto", "none")
	for _, c := range []*nriapi.Container{c1, c2, c3, c5, c7, c8} {
		c.State = nriapi.ContainerState_CONTAINER_RUNNING
	}
	// c4 was created by the killed plugin (with a plan), not started
	c4 := withClaims(ltCtr(p1, "c4", "late", 0), "auto")
	c4.State = nriapi.ContainerState_CONTAINER_CREATED
	record := steeredFile(t, map[string]string{"c1": cg1, "c8": cg8, "gone": filepath.Join(cgroupRoot, "kubepods/u1/gone")})
	e.p.steered = loadSteeredRecord(record)
	if _, err := e.p.Synchronize(ctx, []*nriapi.PodSandbox{p1}, []*nriapi.Container{c1, c2, c3, c4, c5, c7, c8}); err != nil {
		t.Fatal(err)
	}

	e.p.mu.Lock()
	got := map[string]string{}
	for id, tc := range e.p.ctrs {
		got[id] = tc.memory + " " + tc.claimed.String()
	}
	e.p.mu.Unlock()
	want := map[string]string{"c1": "fenced 2", "c2": "fenced 3", "c3": "fenced 2", "c4": "fenced 2", "c5": "steered ",
		"c7": "fenced 2", "c8": "steered "}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("management %v, expected %v", got, want)
	}
	if len(e.p.managers) != 0 || len(e.p.pending) != 0 {
		t.Fatalf("managers %v pending %v", e.p.managers, e.p.pending)
	}
	for _, c := range []struct{ dir, high string }{{cg1, "max"}, {cg2, "max"}, {cg3, "1073741824"}, {cg5, "268435456"},
		{cg7, "536870912"}, {cg8, "max"}} {
		if got := memoryHigh(t, c.dir); got != c.high {
			t.Errorf("%s: memory.high %s, expected %s", c.dir, got, c.high)
		}
	}
	if ids := readSteeredFile(t, record); len(ids) != 0 {
		t.Errorf("steering record %v after Synchronize, expected none", ids)
	}

	// the first pass fences them: c2 loses node 2 of another claim
	e.expectUpdates()
	e.p.LendsRestored()
	e.passes()
	e.expectUpdates("c1 mems=0-2", "c2 mems=0-1,3", "c3 mems=0-2", "c4 mems=0-2", "c7 mems=0-2")
	// lent to, as containers that are not steered
	noErr(t, e.p.LendNode(ctx, "u1", "app", 3, "l1"))
	e.expectUpdates("c1 mems=0-3")
	noErr(t, e.p.RevokeNode(ctx, "u1", "app", 3, "l1"))
	e.expectUpdates("c1 mems=0-2")
	if err := e.p.LendNode(ctx, "u1", "conflict", 3, "l1"); !errors.Is(err, errSteered) {
		t.Fatalf("lend to a container taken as steered: %v", err)
	}

	// c4 starts without a plan in this process: not steered, fenced (its
	// task is created after the update of its spec)
	e.proc(104, "kubepods/u1/c4", "0-3", "0-2")
	c4.Pid = 104
	e.startCtr(p1, c4)
	e.passes()
	e.expectUpdates()
	if len(e.p.managers) != 0 {
		t.Fatalf("managers %v", e.p.managers)
	}

	// c1 restarts: the new container gets a plan and a manager
	_, err := e.p.StopContainer(ctx, p1, c1)
	noErr(t, err)
	e.wait(e.gone, "c1")
	cg6 := e.proc(106, "kubepods/u1/c6", "0-3", "")
	steerableCgroup(t, cg6, "max")
	c6 := withClaims(ltCtr(p1, "c6", "app", 106), "auto")
	if got := e.createMems(p1, c6); got != "-" || e.p.pending["c6"].plan == nil {
		t.Fatalf("adjustment %s of the restarted steered container", got)
	}
	e.startCtr(p1, c6)
	e.p.mu.Lock()
	mgr := e.p.managers["c6"]
	e.p.mu.Unlock()
	if mgr == nil {
		t.Fatal("no manager of the restarted container")
	}
	if got := memoryHigh(t, cg6); got == "max" {
		t.Fatal("restarted container not throttled by its manager")
	}
	if ids := readSteeredFile(t, record); !reflect.DeepEqual(ids, map[string]string{"c6": cg6}) {
		t.Fatalf("steering record %v, expected c6", ids)
	}
	if err := e.p.LendNode(ctx, "u1", "app", 3, "l1"); !errors.Is(err, errSteered) {
		t.Fatalf("lend to the restarted steered container: %v", err)
	}
	e.p.fenceContainers(ctx)
	e.expectUpdates()
	// its stop releases it
	_, err = e.p.StopContainer(ctx, p1, c6)
	noErr(t, err)
	e.wait(e.gone, "c6")
	if got := memoryHigh(t, cg6); got != "max" {
		t.Fatalf("memory.high %s after the stop of the manager", got)
	}
	if ids := readSteeredFile(t, record); len(ids) != 0 {
		t.Fatalf("steering record %v after the stop of the manager", ids)
	}
}

// TestSynchronizeReleasesSteeringLegacy: without a steering record (the
// first start of a plugin that keeps one) a restarted plugin releases the
// started containers that their settings steer, and keeps a record from
// then on.
func TestSynchronizeReleasesSteeringLegacy(t *testing.T) {
	e := newFenceEnv(t, "0-3", 2)
	e.p.state = nriClaims()
	ctx := context.Background()
	p1 := ltPod("u1")
	cg1 := e.proc(101, "kubepods/u1/c1", "0,2", "0,2")
	steerableCgroup(t, cg1, "140668928")
	cg3 := e.proc(103, "kubepods/u1/c3", "0-3", "")
	steerableCgroup(t, cg3, "1073741824")
	c1 := withClaims(ltCtr(p1, "c1", "app", 101), "auto")
	c3 := withClaims(ltCtr(p1, "c3", "plain", 103), "split")
	c1.State, c3.State = nriapi.ContainerState_CONTAINER_RUNNING, nriapi.ContainerState_CONTAINER_RUNNING
	record := filepath.Join(t.TempDir(), steeredFileName)
	e.p.steered = loadSteeredRecord(record)
	if !e.p.steered.legacy {
		t.Fatal("no file: expected the legacy rule")
	}
	if _, err := e.p.Synchronize(ctx, []*nriapi.PodSandbox{p1}, []*nriapi.Container{c1, c3}); err != nil {
		t.Fatal(err)
	}
	if got := memoryHigh(t, cg1); got != "max" {
		t.Errorf("memory.high %s of a container that its settings steer", got)
	}
	if got := memoryHigh(t, cg3); got != "1073741824" {
		t.Errorf("memory.high %s of a container that is not steered", got)
	}
	if ids := readSteeredFile(t, record); len(ids) != 0 || e.p.steered.legacy {
		t.Errorf("steering record %v (legacy %v) after Synchronize", ids, e.p.steered.legacy)
	}
	// an unreadable record is taken as none
	noErr(t, os.WriteFile(record, []byte(`{"c1": `), 0o600))
	if r := loadSteeredRecord(record); !r.legacy || len(r.ids) != 0 {
		t.Errorf("record of an invalid file %+v", r)
	}
}

// A container steered by a killed plugin under the old defaults (steering
// policy auto) is released by the plugin restarted with new defaults (no
// steering) that do not steer it: the steering record names it (05-review
// D2).
func TestReviewReleaseAfterDefaultsChange(t *testing.T) {
	e := newFenceEnv(t, "0-3", 2)
	e.p.state = nriClaims()
	ctx := context.Background()
	old := config.Container{Steering: &config.Steering{Policy: config.PolicyAuto}}
	e.p.defaults = old
	results := e.p.containerResults("x", []resultRef{{uid: "split", n: 0}, {uid: "split", n: 2}})
	m, err := e.p.manage("x", results, false)
	noErr(t, err)
	if m.memory != memorySteered {
		t.Fatalf("precondition: old defaults do not steer: %s", m.memory)
	}
	e.p.defaults = config.Container{} // the new configuration
	pod := ltPod("u1")
	cg := e.proc(101, "kubepods/u1/c1", "0,2", "0,2")
	steerableCgroup(t, cg, "140668928")
	e.p.steered = loadSteeredRecord(steeredFile(t, map[string]string{"c1": cg}))
	c1 := ltCtr(pod, "c1", "app", 101)
	c1.Env = append(c1.Env, resultEnvVarName("split", 0)+"=1", resultEnvVarName("split", 2)+"=1")
	c1.State = nriapi.ContainerState_CONTAINER_RUNNING
	if _, err := e.p.Synchronize(ctx, []*nriapi.PodSandbox{pod}, []*nriapi.Container{c1}); err != nil {
		t.Fatal(err)
	}
	if got := memoryHigh(t, cg); got != "max" {
		t.Errorf("memory.high %s of the dead manager kept after a defaults change", got)
	}
	e.p.mu.Lock()
	memory := e.p.ctrs["c1"].memory
	e.p.mu.Unlock()
	if memory != memoryFenced {
		t.Errorf("memory %s, expected fenced", memory)
	}
}

// A steered container whose manager does not start is managed like a
// container that is not steered (05-review D5): fenced by the pass of its
// PostStartContainer, lent to, and not in the steering record.
func TestSteeringStartFails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(e *ltEnv) // the cgroup of c1 (pid 101)
	}{
		{"no cgroup", func(e *ltEnv) {}},
		{"manager start fails", func(e *ltEnv) {
			// no memory.numa_stat: the manager cannot read the usage
			e.proc(101, "kubepods/u1/c1", "0-3", "")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newFenceEnv(t, "0-3", 2, 3)
			e.p.state = nriClaims()
			ctx := context.Background()
			record := steeredFile(t, map[string]string{})
			e.p.steered = loadSteeredRecord(record)
			if _, err := e.p.Synchronize(ctx, nil, nil); err != nil {
				t.Fatal(err)
			}
			e.p.LendsRestored()
			e.passes()
			pod := ltPod("u1")
			c1 := withClaims(ltCtr(pod, "c1", "app", 101), "auto")
			if got := e.createMems(pod, c1); got != "-" || e.p.pending["c1"].plan == nil {
				t.Fatalf("adjustment %s of a steered container", got)
			}
			tc.setup(e)
			e.startCtr(pod, c1)
			e.p.mu.Lock()
			memory, mgr := e.p.ctrs["c1"].memory, e.p.managers["c1"]
			e.p.mu.Unlock()
			if memory != memoryFenced || mgr != nil {
				t.Fatalf("memory %s manager %v, expected fenced without a manager", memory, mgr)
			}
			if ids := readSteeredFile(t, record); len(ids) != 0 {
				t.Fatalf("steering record %v", ids)
			}
			if tc.name == "no cgroup" {
				// its cgroup is unknown: the pass updates its spec
				e.expectUpdates("c1 mems=0-2")
				return
			}
			e.expectUpdates("c1 mems=0-2")
			if got := e.cgroupMems("kubepods/u1/c1"); got != "0-2" {
				t.Fatalf("cgroup cpuset.mems %s", got)
			}
			noErr(t, e.p.LendNode(ctx, "u1", "app", 3, "l1"))
			e.expectUpdates("c1 mems=0-3")
		})
	}
}

func TestSortedNodes(t *testing.T) {
	if got := sortedNodes(map[int]bool{5: true, 0: true, 2: true}); !reflect.DeepEqual(got, []int{0, 2, 5}) {
		t.Errorf("sorted nodes %v", got)
	}
	if got := sortedNodes(nil); len(got) != 0 {
		t.Errorf("sorted nodes of nil %v", got)
	}
}

func TestFormatBytes(t *testing.T) {
	for in, want := range map[uint64]string{
		0:               "0B",
		1023:            "1023B",
		1536:            "1.5KiB",
		128 << 20:       "128.0MiB",
		(5 << 30) / 2:   "2.5GiB",
		uint64(1) << 40: "1024.0GiB",
	} {
		if got := formatBytes(in); got != want {
			t.Errorf("formatBytes(%d) = %q, expected %q", in, got, want)
		}
	}
}

// recordExits makes exitOnNRILost send the exit statuses to the returned
// channel for the test.
func recordExits(t *testing.T) chan int {
	t.Helper()
	exits := make(chan int, 4)
	old := exitOnNRILost
	exitOnNRILost = func(code int) { exits <- code }
	t.Cleanup(func() { exitOnNRILost = old })
	return exits
}

// expectExits checks that the exit statuses sent to exits are want.
func expectExits(t *testing.T, exits chan int, want ...int) {
	t.Helper()
	close(exits)
	got := []int{}
	for code := range exits {
		got = append(got, code)
	}
	if !reflect.DeepEqual(got, append([]int{}, want...)) {
		t.Errorf("exit statuses %v, expected %v", got, want)
	}
}

// TestNRIConnectionLost: the plugin exits with status 1 when the runtime
// closes the connection after Start, before Start has returned too, and
// not when Stop or a done ctx closes it or Start fails.
func TestNRIConnectionLost(t *testing.T) {
	done, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		run  func(ctx context.Context, p *nriPlugin)
		want []int
	}{
		{"runtime closes", context.Background(), func(ctx context.Context, p *nriPlugin) {
			p.connStarted(ctx)
			p.onClose(ctx)
		}, []int{1}},
		{"closed before Start returned", context.Background(), func(ctx context.Context, p *nriPlugin) {
			p.onClose(ctx)
			p.connStarted(ctx)
		}, []int{1}},
		{"Start failed", context.Background(), func(ctx context.Context, p *nriPlugin) {
			p.onClose(ctx)
		}, nil},
		{"Stop", context.Background(), func(ctx context.Context, p *nriPlugin) {
			p.connStarted(ctx)
			p.Stop()
			p.onClose(ctx)
		}, nil},
		{"ctx done", done, func(ctx context.Context, p *nriPlugin) {
			p.connStarted(ctx)
			p.onClose(ctx)
		}, nil},
		// the runtime closes the connection while Shutdown stops the
		// broker, before the NRI plugin (05-review D4)
		{"Shutdown", context.Background(), func(ctx context.Context, p *nriPlugin) {
			p.connStarted(ctx)
			d := &driver{nriPlugin: p, broker: &broker{cancel: func() { p.onClose(ctx) }}}
			_ = d.Shutdown(ctx) // always nil
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exits := recordExits(t)
			tc.run(tc.ctx, newLtEnv(t).p)
			expectExits(t, exits, tc.want...)
		})
	}
}

// fakeRuntime is the runtime end of an NRI connection: it accepts a
// plugin on a socket, registers and configures it.
type fakeRuntime struct {
	sock       string
	registered chan struct{} // gets a value at RegisterPlugin
	conns      chan net.Conn // the connection of the configured plugin
}

func (rt *fakeRuntime) RegisterPlugin(context.Context, *nriapi.RegisterPluginRequest) (*nriapi.Empty, error) {
	rt.registered <- struct{}{}
	return &nriapi.Empty{}, nil
}

func (*fakeRuntime) UpdateContainers(context.Context, *nriapi.UpdateContainersRequest) (*nriapi.UpdateContainersResponse, error) {
	return &nriapi.UpdateContainersResponse{}, nil
}

// newFakeRuntime starts a fake runtime that serves one plugin.
func newFakeRuntime(t *testing.T) *fakeRuntime {
	t.Helper()
	// a short path: the limit of a unix socket path is 108 bytes
	dir, err := os.MkdirTemp("", "nri")
	noErr(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	rt := &fakeRuntime{
		sock:       filepath.Join(dir, "nri.sock"),
		registered: make(chan struct{}, 1),
		conns:      make(chan net.Conn, 1),
	}
	l, err := net.Listen("unix", rt.sock)
	noErr(t, err)
	srv, err := ttrpc.NewServer()
	noErr(t, err)
	nriapi.RegisterRuntimeService(srv, rt)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		accepted net.Conn
	)
	// cleanups run in reverse order: close everything, then wait
	t.Cleanup(wg.Wait)
	t.Cleanup(func() {
		_ = l.Close()
		_ = srv.Close()
		mu.Lock()
		defer mu.Unlock()
		if accepted != nil {
			_ = accepted.Close()
		}
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := l.Accept()
		if err != nil {
			t.Errorf("fake runtime: accept: %v", err)
			return
		}
		mu.Lock()
		accepted = conn
		mu.Unlock()
		mux := multiplex.Multiplex(conn)
		rl, err := mux.Listen(multiplex.RuntimeServiceConn)
		if err != nil {
			t.Errorf("fake runtime: listen: %v", err)
			return
		}
		go func() { _ = srv.Serve(context.Background(), rl) }()
		pc, err := mux.Open(multiplex.PluginServiceConn)
		if err != nil {
			t.Errorf("fake runtime: open plugin connection: %v", err)
			return
		}
		plugin := nriapi.NewPluginClient(ttrpc.NewClient(pc))
		// as the runtime does: configure after the registration
		select {
		case <-rt.registered:
		case <-time.After(10 * time.Second):
			t.Errorf("fake runtime: the plugin did not register")
			return
		}
		if _, err := plugin.Configure(context.Background(), &nriapi.ConfigureRequest{
			RuntimeName:         "fake",
			RuntimeVersion:      "v2.2.0",
			NRIVersion:          "v0.12.2",
			RegistrationTimeout: 5000,
			RequestTimeout:      2000,
		}); err != nil {
			t.Errorf("fake runtime: configure: %v", err)
			return
		}
		rt.conns <- conn
	}()
	return rt
}

// conn returns the connection of the configured plugin.
func (rt *fakeRuntime) conn(t *testing.T) net.Conn {
	t.Helper()
	select {
	case conn := <-rt.conns:
		return conn
	case <-time.After(10 * time.Second):
		t.Fatal("fake runtime: the plugin was not configured")
		return nil
	}
}

// waitClosed waits until the stub has reported the connection closed.
func waitClosed(t *testing.T, p *nriPlugin) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		p.connMu.Lock()
		closed := p.closed
		p.connMu.Unlock()
		if closed {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the stub did not report the connection closed")
		}
	}
}

// TestNRIConnectionLostStub: with the NRI stub connected to a runtime,
// the plugin exits when the runtime closes the connection, and not when
// Stop closes it (which the stub reports to onClose too).
func TestNRIConnectionLostStub(t *testing.T) {
	start := func(t *testing.T, rt *fakeRuntime) *nriPlugin {
		t.Helper()
		p, err := startNRIPlugin(context.Background(), &nodeState{baseState: &baseState{}},
			NRIOpts{Name: "test", Idx: "50", Socket: rt.sock}, config.Container{Fencing: config.FencingNone},
			nil, nil, nil, t.TempDir(), t.TempDir())
		noErr(t, err)
		return p
	}
	t.Run("runtime closes", func(t *testing.T) {
		exits := recordExits(t)
		rt := newFakeRuntime(t)
		p := start(t, rt)
		t.Cleanup(p.Stop)
		noErr(t, rt.conn(t).Close())
		select {
		case code := <-exits:
			if code != 1 {
				t.Errorf("exit status %d, expected 1", code)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("no exit after the runtime closed the connection")
		}
		waitClosed(t, p)
		expectExits(t, exits)
	})
	t.Run("Stop", func(t *testing.T) {
		exits := recordExits(t)
		rt := newFakeRuntime(t)
		p := start(t, rt)
		rt.conn(t)
		p.Stop()
		waitClosed(t, p)
		expectExits(t, exits)
	})
}
