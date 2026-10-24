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
	"reflect"
	"strings"
	"testing"

	nriapi "github.com/containerd/nri/pkg/api"

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
	e.proc(101, "kubepods/u1/c1", "0-2", "")
	c1 := withClaims(ltCtr(pod, "c1", "app", 101), "split")
	if got := e.createMems(pod, c1); got != "0-2" {
		t.Fatalf("adjustment %s", got)
	}
	noErr(t, e.p.StartContainer(ctx, pod, c1))
	e.wait(e.start, "c1")
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
	want := map[string]string{"c1": "steered 2", "c2": "fenced 2", "c3": "fenced 3", "c4": "fenced ", "c5": "steered "}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("management %v, expected %v", got, want)
	}
	// managers are not restarted
	if len(e.p.managers) != 0 || len(e.p.pending) != 0 {
		t.Fatalf("managers %v pending %v", e.p.managers, e.p.pending)
	}
	e.p.LendsRestored()
	e.passes()
	e.expectUpdates("c2 mems=0-2", "c3 mems=0-1,3", "c4 mems=0-1")
	if err := e.p.LendNode(ctx, "u1", "c1", 3, "l1"); !errors.Is(err, errSteered) {
		t.Fatalf("lend to a steered container after a restart: %v", err)
	}
	if err := e.p.LendNode(ctx, "u1", "c5", 3, "l1"); !errors.Is(err, errSteered) {
		t.Fatalf("lend to a container with conflicting settings: %v", err)
	}
	noErr(t, e.p.LendNode(ctx, "u1", "c2", 3, "l1"))
	e.expectUpdates("c2 mems=0-3")
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
