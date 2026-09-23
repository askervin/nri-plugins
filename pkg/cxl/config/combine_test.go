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

package config

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/containers/nri-plugins/pkg/cgmpolmgr"
)

const (
	originA = "claim ns/a request r"
	originB = "claim ns/b request s"
)

// result returns the settings of a result with the steering, all fields
// from the origin.
func result(s Steering, origin string) ResultSettings {
	r := ResultSettings{Container: &Container{Steering: &s}, Origins: map[string]string{}}
	for path, set := range map[string]bool{
		FieldPolicy:    s.Policy != "",
		FieldWaypoints: len(s.Waypoints) > 0,
		FieldMinStep:   s.MinStep != "",
		FieldMaxStep:   s.MaxStep != "",
	} {
		if set {
			r.Origins[path] = origin
		}
	}
	return r
}

// wps returns waypoints with one target usage each.
func wps(usages ...TargetUsage) []Waypoint {
	var out []Waypoint
	for _, u := range usages {
		out = append(out, Waypoint{TargetUsages: []TargetUsage{u}})
	}
	return out
}

func TestCombine(t *testing.T) {
	dram4 := wps(TargetUsage{MemoryTypeDRAM, "4Gi"})
	for _, tc := range []struct {
		name     string
		results  []ResultSettings
		defaults Container
		want     string
		origins  map[string]string
		policy   string
		err      string
	}{
		{
			name:    "no results, no defaults",
			want:    `{"steering":{"policy":"none"},"fencing":"allowed-mems"}`,
			origins: map[string]string{FieldPolicy: OriginDefault, FieldFencing: OriginDefault},
			policy:  "none (default)",
		},
		{
			name:     "no results, node defaults",
			defaults: Container{Steering: &Steering{Policy: PolicyFirstDRAM, MaxStep: "1Gi"}, Fencing: FencingNone},
			want:     `{"steering":{"policy":"first-dram","maxStep":"1Gi"},"fencing":"none"}`,
			origins:  map[string]string{FieldPolicy: OriginNodeDefault, FieldMaxStep: OriginNodeDefault, FieldFencing: OriginNodeDefault},
			policy:   "first-dram (node default)",
		},
		{
			name:    "results without container settings",
			results: []ResultSettings{{}, {Container: &Container{}}},
			want:    `{"steering":{"policy":"none"},"fencing":"allowed-mems"}`,
			origins: map[string]string{FieldPolicy: OriginDefault, FieldFencing: OriginDefault},
			policy:  "none (default)",
		},
		{
			name:    "one result opts in",
			results: []ResultSettings{{}, result(Steering{Policy: PolicyAuto}, originA)},
			want:    `{"steering":{"policy":"auto"},"fencing":"allowed-mems"}`,
			origins: map[string]string{FieldPolicy: originA, FieldFencing: OriginDefault},
			policy:  "auto from claim ns/a request r",
		},
		{
			name:    "agreement, the first origin",
			results: []ResultSettings{result(Steering{Policy: PolicyAuto}, originA), result(Steering{Policy: PolicyAuto}, originB)},
			want:    `{"steering":{"policy":"auto"},"fencing":"allowed-mems"}`,
			origins: map[string]string{FieldPolicy: originA, FieldFencing: OriginDefault},
			policy:  "auto from claim ns/a request r",
		},
		{
			name:    "fields from different results",
			results: []ResultSettings{result(Steering{Policy: PolicyFirstDRAM}, originA), result(Steering{MaxStep: "1Gi"}, originB)},
			want:    `{"steering":{"policy":"first-dram","maxStep":"1Gi"},"fencing":"allowed-mems"}`,
			origins: map[string]string{FieldPolicy: originA, FieldMaxStep: originB, FieldFencing: OriginDefault},
			policy:  "first-dram from claim ns/a request r",
		},
		{
			name:    "quantities agree by value",
			results: []ResultSettings{result(Steering{Policy: PolicyAuto, MaxStep: "1Gi"}, originA), result(Steering{MaxStep: "1073741824"}, originB)},
			want:    `{"steering":{"policy":"auto","maxStep":"1Gi"},"fencing":"allowed-mems"}`,
			origins: map[string]string{FieldPolicy: originA, FieldMaxStep: originA, FieldFencing: OriginDefault},
			policy:  "auto from claim ns/a request r",
		},
		{
			name:    "conflict of policies",
			results: []ResultSettings{result(Steering{Policy: PolicyFirstCXL}, originA), {}, result(Steering{Policy: PolicyNone}, originB)},
			err:     "container.steering.policy: claim ns/a request r says first-cxl, claim ns/b request s says none",
		},
		{
			name:    "conflict of quantities",
			results: []ResultSettings{result(Steering{Policy: PolicyAuto, MinStep: "1Gi"}, originA), result(Steering{MinStep: "1G"}, originB)},
			err:     "container.steering.minStep: claim ns/a request r says 1Gi, claim ns/b request s says 1G",
		},
		{
			name: "conflict of waypoints",
			results: []ResultSettings{
				result(Steering{Policy: PolicyWaypoints, Waypoints: dram4}, originA),
				result(Steering{Waypoints: wps(TargetUsage{MemoryTypeCXL, "4Gi"})}, originB),
			},
			err: `container.steering.waypoints: claim ns/a request r says [{"targetUsages":[{"memoryType":"DRAM","usage":"4Gi"}]}], ` +
				`claim ns/b request s says [{"targetUsages":[{"memoryType":"CXL","usage":"4Gi"}]}]`,
		},
		{
			name:    "conflict without origins",
			results: []ResultSettings{{Container: &Container{Steering: &Steering{Policy: PolicyAuto}}}, {Container: &Container{Steering: &Steering{Policy: PolicyNone}}}},
			err:     "container.steering.policy: result 0 says auto, result 1 says none",
		},
		{
			name:     "defaults overlaid",
			results:  []ResultSettings{result(Steering{MaxStep: "512Mi"}, originA)},
			defaults: Container{Steering: &Steering{Policy: PolicyAuto, MinStep: "64Mi"}},
			want:     `{"steering":{"policy":"auto","minStep":"64Mi","maxStep":"512Mi"},"fencing":"allowed-mems"}`,
			origins:  map[string]string{FieldPolicy: OriginNodeDefault, FieldMinStep: OriginNodeDefault, FieldMaxStep: originA, FieldFencing: OriginDefault},
			policy:   "auto (node default)",
		},
		{
			name:     "a result overrides the default policy",
			results:  []ResultSettings{result(Steering{Policy: PolicyNone}, originA)},
			defaults: Container{Steering: &Steering{Policy: PolicyAuto}, Fencing: FencingNone},
			want:     `{"steering":{"policy":"none"},"fencing":"none"}`,
			origins:  map[string]string{FieldPolicy: originA, FieldFencing: OriginNodeDefault},
			policy:   "none from claim ns/a request r",
		},
		{
			name:     "the parameters of the defaults go with their policy",
			results:  []ResultSettings{result(Steering{Policy: PolicyNone}, originA)},
			defaults: Container{Steering: &Steering{Policy: PolicyWaypoints, Waypoints: dram4, MinStep: "64Mi", MaxStep: "1Gi"}},
			want:     `{"steering":{"policy":"none"},"fencing":"allowed-mems"}`,
			origins:  map[string]string{FieldPolicy: originA, FieldFencing: OriginDefault},
			policy:   "none from claim ns/a request r",
		},
		{
			name:     "the same policy keeps the parameters of the defaults",
			results:  []ResultSettings{result(Steering{Policy: PolicyWaypoints, MaxStep: "2Gi"}, originA)},
			defaults: Container{Steering: &Steering{Policy: PolicyWaypoints, Waypoints: dram4, MaxStep: "1Gi"}},
			want:     `{"steering":{"policy":"waypoints","waypoints":[{"targetUsages":[{"memoryType":"DRAM","usage":"4Gi"}]}],"maxStep":"2Gi"},"fencing":"allowed-mems"}`,
			origins:  map[string]string{FieldPolicy: originA, FieldWaypoints: OriginNodeDefault, FieldMaxStep: originA, FieldFencing: OriginDefault},
			policy:   "waypoints from claim ns/a request r",
		},
		{
			name:    "missing policy",
			results: []ResultSettings{result(Steering{MaxStep: "1Gi"}, originA)},
			err:     "MemoryConfig: container.steering.maxStep needs a policy other than none (policy none (default), maxStep 1Gi from claim ns/a request r)",
		},
		{
			name:     "parameters of a result with the default policy none",
			results:  []ResultSettings{result(Steering{Waypoints: dram4}, originA)},
			defaults: Container{Steering: &Steering{Policy: PolicyNone}},
			err:      "MemoryConfig: container.steering.waypoints needs a policy other than none (policy none (node default), waypoints from claim ns/a request r)",
		},
		{
			name:    "policy none of one result, a step of another",
			results: []ResultSettings{result(Steering{Policy: PolicyNone}, originB), result(Steering{MinStep: "1Gi"}, originA)},
			err:     "MemoryConfig: container.steering.minStep needs a policy other than none (policy none from claim ns/b request s, minStep 1Gi from claim ns/a request r)",
		},
		{
			name:    "waypoints of one result, another policy of another",
			results: []ResultSettings{result(Steering{Policy: PolicyFirstCXL}, originB), result(Steering{Waypoints: dram4}, originA)},
			err:     "MemoryConfig: container.steering.waypoints needs policy waypoints (policy first-cxl from claim ns/b request s, waypoints from claim ns/a request r)",
		},
		{
			name:    "policy waypoints without waypoints",
			results: []ResultSettings{result(Steering{Policy: PolicyWaypoints}, originA)},
			err:     "MemoryConfig: container.steering.policy waypoints needs waypoints (policy waypoints from claim ns/a request r)",
		},
		{
			name:     "policy waypoints with the waypoints of another result",
			results:  []ResultSettings{result(Steering{Policy: PolicyWaypoints}, originA), result(Steering{Waypoints: dram4}, originB)},
			defaults: Container{Fencing: FencingAllowedMems},
			want:     `{"steering":{"policy":"waypoints","waypoints":[{"targetUsages":[{"memoryType":"DRAM","usage":"4Gi"}]}]},"fencing":"allowed-mems"}`,
			origins:  map[string]string{FieldPolicy: originA, FieldWaypoints: originB, FieldFencing: OriginNodeDefault},
			policy:   "waypoints from claim ns/a request r",
		},
		{
			name:     "minStep of a result exceeds maxStep of the defaults",
			results:  []ResultSettings{result(Steering{MinStep: "2Gi"}, originA)},
			defaults: Container{Steering: &Steering{Policy: PolicyAuto, MaxStep: "1Gi"}},
			err:      "MemoryConfig: container.steering.minStep 2Gi exceeds maxStep 1Gi (minStep 2Gi from claim ns/a request r, maxStep 1Gi (node default))",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, err := Combine(tc.results, tc.defaults)
			if !checkErr(err, tc.err) {
				t.Fatalf("got  %v\nwant %s", err, tc.err)
			}
			if tc.err != "" {
				return
			}
			data, _ := json.Marshal(eff.Container)
			if string(data) != tc.want {
				t.Errorf("got\n%s\nexpected\n%s", data, tc.want)
			}
			if !reflect.DeepEqual(eff.Origins, tc.origins) {
				t.Errorf("origins %v, expected %v", eff.Origins, tc.origins)
			}
			if got := eff.PolicyText(); got != tc.policy {
				t.Errorf("policy text %q, expected %q", got, tc.policy)
			}
			if got, want := eff.Steers(), eff.Container.Steering.Policy != PolicyNone; got != want {
				t.Errorf("steers %v", got)
			}
		})
	}
}

func TestCombineDoesNotChangeInputs(t *testing.T) {
	defaults := Container{Steering: &Steering{Policy: PolicyAuto, MaxStep: "1Gi"}}
	r := result(Steering{Policy: PolicyFirstDRAM}, originA)
	if _, err := Combine([]ResultSettings{r}, defaults); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*defaults.Steering, Steering{Policy: PolicyAuto, MaxStep: "1Gi"}) {
		t.Errorf("defaults changed: %+v", *defaults.Steering)
	}
	if !reflect.DeepEqual(*r.Container.Steering, Steering{Policy: PolicyFirstDRAM}) {
		t.Errorf("result changed: %+v", *r.Container.Steering)
	}
}

func TestCombineResolved(t *testing.T) {
	a := testClaim(class(`"container": {"steering": {"policy": "auto"}}`, "r"), claimed(`"container": {"steering": {"maxStep": "1Gi"}}`))
	ra, err := Resolve(a, local, "r")
	if err != nil {
		t.Fatal(err)
	}
	b := testClaim(claimed(`"container": {"steering": {"policy": "none"}}`))
	b.Name = "b"
	rb, err := Resolve(b, local, "d")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Combine([]ResultSettings{ra.Settings(), rb.Settings()}, Container{})
	if want := "container.steering.policy: class cxl-local says auto, claim ns/b request d says none"; !checkErr(err, want) {
		t.Errorf("got  %v\nwant %s", err, want)
	}
	eff, err := Combine([]ResultSettings{ra.Settings()}, Container{Fencing: FencingNone})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := eff.PolicyText(), "auto from class cxl-local"; got != want {
		t.Errorf("policy text %q", got)
	}
	if got := eff.Origins[FieldMaxStep]; got != originClaimR {
		t.Errorf("maxStep origin %q", got)
	}
}

func TestResultSettingsJSON(t *testing.T) {
	r := result(Steering{Policy: PolicyAuto, MaxStep: "1Gi"}, originA)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"container":{"steering":{"policy":"auto","maxStep":"1Gi"}},"origins":{"container.steering.maxStep":"claim ns/a request r","container.steering.policy":"claim ns/a request r"}}`
	if string(data) != want {
		t.Errorf("got\n%s\nexpected\n%s", data, want)
	}
	var back ResultSettings
	if err := json.Unmarshal(data, &back); err != nil || !reflect.DeepEqual(back, r) {
		t.Errorf("round trip %+v %v", back, err)
	}
	if data, _ := json.Marshal(ResultSettings{}); string(data) != `{}` {
		t.Errorf("empty settings %s", data)
	}
}

func TestCgmPolicy(t *testing.T) {
	dram := cgmpolmgr.MemoryTypes{DRAMNodes: []int{0}, DRAMQuota: 1 << 30}
	cxl := cgmpolmgr.MemoryTypes{CXLNodes: []int{2}, CXLQuota: 1 << 30}
	both := cgmpolmgr.MemoryTypes{DRAMNodes: []int{0}, CXLNodes: []int{2}, DRAMQuota: 1 << 30, CXLQuota: 1 << 30}
	for _, tc := range []struct {
		name  string
		s     *Steering
		mem   cgmpolmgr.MemoryTypes
		want  cgmpolmgr.Policy
		steer bool
	}{
		{name: "nil", s: nil, mem: both},
		{name: "no policy", s: &Steering{}, mem: both},
		{name: "none", s: &Steering{Policy: PolicyNone}, mem: both},
		{name: "no memory", s: &Steering{Policy: PolicyAuto}},
		{name: "auto CXL only", s: &Steering{Policy: PolicyAuto}, mem: cxl, want: cgmpolmgr.Policy{MemoryUseOrder: "first-cxl"}, steer: true},
		{name: "auto DRAM only", s: &Steering{Policy: PolicyAuto}, mem: dram, want: cgmpolmgr.Policy{MemoryUseOrder: "first-dram"}, steer: true},
		{name: "auto both", s: &Steering{Policy: PolicyAuto, MaxStep: "1Gi"}, mem: both,
			want: cgmpolmgr.Policy{MemoryUseOrder: "start-interleaved", MaxStep: "1Gi"}, steer: true},
		{name: "first-dram", s: &Steering{Policy: PolicyFirstDRAM, MinStep: "64Mi"}, mem: cxl,
			want: cgmpolmgr.Policy{MemoryUseOrder: "first-dram", MinStep: "64Mi"}, steer: true},
		{name: "first-cxl", s: &Steering{Policy: PolicyFirstCXL}, mem: both, want: cgmpolmgr.Policy{MemoryUseOrder: "first-cxl"}, steer: true},
		{name: "start-interleaved", s: &Steering{Policy: PolicyStartInterleaved}, mem: both, want: cgmpolmgr.Policy{MemoryUseOrder: "start-interleaved"}, steer: true},
		{name: "end-interleaved", s: &Steering{Policy: PolicyEndInterleaved}, mem: both, want: cgmpolmgr.Policy{MemoryUseOrder: "end-interleaved"}, steer: true},
		{
			name: "waypoints",
			s: &Steering{Policy: PolicyWaypoints, MinStep: "64Mi", MaxStep: "1Gi", Waypoints: []Waypoint{
				{TargetUsages: []TargetUsage{{MemoryTypeDRAM, "512Mi"}}},
				{TargetUsages: []TargetUsage{{MemoryTypeDRAM, "1Gi"}, {MemoryTypeCXL, "1Gi"}}},
			}},
			mem: both,
			want: cgmpolmgr.Policy{MemoryUseOrder: "waypoints", MinStep: "64Mi", MaxStep: "1Gi", MemoryUseWaypoints: []cgmpolmgr.MemoryUseWaypoint{
				{TargetUsages: []cgmpolmgr.MemoryUseWaypointEntry{{MemoryType: "DRAM", Usage: "512Mi"}}},
				{TargetUsages: []cgmpolmgr.MemoryUseWaypointEntry{{MemoryType: "DRAM", Usage: "1Gi"}, {MemoryType: "CXL", Usage: "1Gi"}}},
			}},
			steer: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, steer := tc.s.CgmPolicy(tc.mem)
			if steer != tc.steer || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v %v, expected %+v %v", got, steer, tc.want, tc.steer)
			}
			if !steer {
				return
			}
			if err := got.Validate(); err != nil {
				t.Errorf("cgmpolmgr refuses %+v: %v", got, err)
			}
			if _, err := got.Plan(tc.mem); err != nil {
				t.Errorf("no plan for %+v: %v", got, err)
			}
		})
	}
}

func TestPolicyNames(t *testing.T) {
	// every policy but none and auto is a memory use order of cgmpolmgr
	for _, p := range policies {
		_, err := cgmpolmgr.ParseMemoryUseOrder(p)
		if want := p != PolicyNone && p != PolicyAuto; (err == nil) != want {
			t.Errorf("%s: %v", p, err)
		}
	}
}
