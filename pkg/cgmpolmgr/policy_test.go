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

package cgmpolmgr

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseMemorySize(t *testing.T) {
	for s, expected := range map[string]int64{
		"16Mi":    16 * MiB,
		"1Gi":     GiB,
		"1.5Gi":   GiB + GiB/2,
		"1G":      1000000000,
		"1048576": 1048576,
		" 2Ki ":   2048,
		"0":       0,
	} {
		bytes, err := ParseMemorySize(s)
		require.NoError(t, err, s)
		require.Equal(t, expected, bytes, s)
	}
	for _, s := range []string{"", "abc", "-1", "1X"} {
		_, err := ParseMemorySize(s)
		require.Error(t, err, s)
	}
}

func TestParseMemoryUseOrder(t *testing.T) {
	for _, order := range []MemoryUseOrder{
		MemoryUseFirstDRAM, MemoryUseFirstCXL, MemoryUseStartInterleaved, MemoryUseEndInterleaved, MemoryUseWaypoints,
	} {
		parsed, err := ParseMemoryUseOrder(order.String())
		require.NoError(t, err)
		require.Equal(t, order, parsed)
	}
	parsed, err := ParseMemoryUseOrder(" First-DRAM ")
	require.NoError(t, err)
	require.Equal(t, MemoryUseFirstDRAM, parsed)

	_, err = ParseMemoryUseOrder("dram-first")
	require.Error(t, err)
	require.Equal(t, "MemoryUseOrder(42)", MemoryUseOrder(42).String())
}

func TestPolicyValidate(t *testing.T) {
	valid := []Policy{
		{MemoryUseOrder: "first-dram"},
		{MemoryUseOrder: "first-cxl", MinStep: "16Mi"},
		{MemoryUseOrder: "start-interleaved", MaxStep: "1Gi"},
		{MemoryUseOrder: "end-interleaved", MinStep: "16Mi", MaxStep: "16Mi"},
		{
			MemoryUseOrder: "waypoints",
			MemoryUseWaypoints: []MemoryUseWaypoint{
				{TargetUsages: []MemoryUseWaypointEntry{{MemoryType: "DRAM", Usage: "1Gi"}}},
				{TargetUsages: []MemoryUseWaypointEntry{{MemoryType: "cxl", Usage: "1Gi"}}},
			},
		},
	}
	for i, pol := range valid {
		require.NoError(t, pol.Validate(), "policy %d", i)
	}

	invalid := []struct {
		name string
		pol  Policy
		err  string
	}{
		{"empty order", Policy{}, "memoryUseOrder"},
		{"unknown order", Policy{MemoryUseOrder: "random"}, "memoryUseOrder"},
		{"waypoints without waypoints", Policy{MemoryUseOrder: "waypoints"}, "memoryUseWaypoints must be specified"},
		{
			"waypoints with other order",
			Policy{
				MemoryUseOrder:     "first-dram",
				MemoryUseWaypoints: []MemoryUseWaypoint{{TargetUsages: []MemoryUseWaypointEntry{{MemoryType: "DRAM", Usage: "1Gi"}}}},
			},
			"must not be specified",
		},
		{"bad minStep", Policy{MemoryUseOrder: "first-dram", MinStep: "lots"}, "minStep"},
		{"zero maxStep", Policy{MemoryUseOrder: "first-dram", MaxStep: "0"}, "maxStep"},
		{"minStep above maxStep", Policy{MemoryUseOrder: "first-dram", MinStep: "2Gi", MaxStep: "1Gi"}, "must not exceed"},
		{
			"empty target usages",
			Policy{MemoryUseOrder: "waypoints", MemoryUseWaypoints: []MemoryUseWaypoint{{}}},
			"no target usages",
		},
		{
			"unknown memory type",
			Policy{
				MemoryUseOrder:     "waypoints",
				MemoryUseWaypoints: []MemoryUseWaypoint{{TargetUsages: []MemoryUseWaypointEntry{{MemoryType: "HBM", Usage: "1Gi"}}}},
			},
			"unknown memory type",
		},
		{
			"decreasing usage",
			Policy{
				MemoryUseOrder: "waypoints",
				MemoryUseWaypoints: []MemoryUseWaypoint{
					{TargetUsages: []MemoryUseWaypointEntry{{MemoryType: "DRAM", Usage: "2Gi"}}},
					{TargetUsages: []MemoryUseWaypointEntry{{MemoryType: "DRAM", Usage: "1Gi"}}},
				},
			},
			"less than",
		},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorContains(t, tc.pol.Validate(), tc.err)
		})
	}
}

func TestPolicyPlanOrders(t *testing.T) {
	mem := MemoryTypes{
		DRAMNodes: []int{0},
		CXLNodes:  []int{1},
		DRAMQuota: 20 * GiB,
		CXLQuota:  100 * GiB,
	}
	tcases := []struct {
		order     string
		waypoints []Waypoint
	}{
		{"first-dram", []Waypoint{{Usage: nm(20*GiB, 0)}, {Usage: nm(20*GiB, 100*GiB)}}},
		{"first-cxl", []Waypoint{{Usage: nm(0, 100*GiB)}, {Usage: nm(20*GiB, 100*GiB)}}},
		{"start-interleaved", []Waypoint{{Usage: nm(20*GiB, 20*GiB)}, {Usage: nm(20*GiB, 100*GiB)}}},
		{"end-interleaved", []Waypoint{{Usage: nm(0, 80*GiB)}, {Usage: nm(20*GiB, 100*GiB)}}},
	}
	for _, tc := range tcases {
		t.Run(tc.order, func(t *testing.T) {
			plan, err := Policy{MemoryUseOrder: tc.order}.Plan(mem)
			require.NoError(t, err)
			require.Equal(t, tc.waypoints, plan.Waypoints)
			// Steps default to the total quota.
			require.Equal(t, 120*GiB, plan.MinStep)
			require.Equal(t, 120*GiB, plan.MaxStep)
		})
	}

	t.Run("larger DRAM quota with end-interleaved", func(t *testing.T) {
		plan, err := Policy{MemoryUseOrder: "end-interleaved"}.Plan(MemoryTypes{
			DRAMNodes: []int{0}, CXLNodes: []int{1}, DRAMQuota: 100 * GiB, CXLQuota: 20 * GiB,
		})
		require.NoError(t, err)
		require.Equal(t, []Waypoint{{Usage: nm(80*GiB, 0)}, {Usage: nm(100*GiB, 20*GiB)}}, plan.Waypoints)
	})

	t.Run("single type spreads over nodes", func(t *testing.T) {
		for _, order := range []string{"first-dram", "first-cxl", "start-interleaved", "end-interleaved"} {
			plan, err := Policy{MemoryUseOrder: order}.Plan(MemoryTypes{
				DRAMNodes: []int{0, 2}, CXLNodes: []int{1}, DRAMQuota: 20 * GiB,
			})
			require.NoError(t, err, order)
			require.Equal(t, []Waypoint{{Usage: NodeMem{0: 10 * GiB, 2: 10 * GiB}}}, plan.Waypoints, order)
			require.Equal(t, 20*GiB, plan.MaxStep, order)
		}
	})
}

func TestPolicyPlanSteps(t *testing.T) {
	mem := MemoryTypes{DRAMNodes: []int{0}, CXLNodes: []int{1}, DRAMQuota: 2 * GiB, CXLQuota: 2 * GiB}

	plan, err := Policy{MemoryUseOrder: "first-dram", MinStep: "1Gi"}.Plan(mem)
	require.NoError(t, err)
	require.Equal(t, 1*GiB, plan.MinStep)
	require.Equal(t, 4*GiB, plan.MaxStep, "maxStep defaults to the total quota")

	plan, err = Policy{MemoryUseOrder: "first-dram", MaxStep: "512Mi"}.Plan(mem)
	require.NoError(t, err)
	require.Equal(t, 512*MiB, plan.MinStep, "minStep defaults to maxStep")
	require.Equal(t, 512*MiB, plan.MaxStep)

	plan, err = Policy{MemoryUseOrder: "first-dram", MinStep: "8Gi"}.Plan(mem)
	require.NoError(t, err)
	require.Equal(t, 8*GiB, plan.MinStep)
	require.Equal(t, 8*GiB, plan.MaxStep, "maxStep is raised to minStep")

	plan, err = Policy{MemoryUseOrder: "first-dram", MinStep: "16Mi", MaxStep: "64Mi"}.Plan(mem)
	require.NoError(t, err)
	require.Equal(t, 16*MiB, plan.MinStep)
	require.Equal(t, 64*MiB, plan.MaxStep)
}

func TestPolicyPlanUserWaypoints(t *testing.T) {
	pol := Policy{
		MemoryUseOrder: "waypoints",
		MemoryUseWaypoints: []MemoryUseWaypoint{
			{TargetUsages: []MemoryUseWaypointEntry{{MemoryType: "DRAM", Usage: "100Mi"}, {MemoryType: "CXL", Usage: "50Mi"}}},
			{TargetUsages: []MemoryUseWaypointEntry{{MemoryType: "CXL", Usage: "200Mi"}}},
			{TargetUsages: []MemoryUseWaypointEntry{{MemoryType: "DRAM", Usage: "300Mi"}, {MemoryType: "CXL", Usage: "250Mi"}}},
		},
		MinStep: "20Mi",
		MaxStep: "60Mi",
	}
	mem := MemoryTypes{DRAMNodes: []int{2}, CXLNodes: []int{3, 4}, DRAMQuota: 300 * MiB, CXLQuota: 300 * MiB}
	plan, err := pol.Plan(mem)
	require.NoError(t, err)
	require.Equal(t, []Waypoint{
		{Usage: NodeMem{2: 100 * MiB, 3: 25 * MiB, 4: 25 * MiB}},
		{Usage: NodeMem{2: 100 * MiB, 3: 100 * MiB, 4: 100 * MiB}},
		{Usage: NodeMem{2: 300 * MiB, 3: 125 * MiB, 4: 125 * MiB}},
	}, plan.Waypoints)
	require.Equal(t, 20*MiB, plan.MinStep)
	require.Equal(t, 60*MiB, plan.MaxStep)

	_, err = pol.Plan(MemoryTypes{DRAMNodes: []int{2}, DRAMQuota: 300 * MiB})
	require.ErrorContains(t, err, "no CXL memory")
}

func TestPolicyPlanErrors(t *testing.T) {
	pol := Policy{MemoryUseOrder: "first-dram"}
	_, err := pol.Plan(MemoryTypes{})
	require.ErrorContains(t, err, "no memory type")
	_, err = pol.Plan(MemoryTypes{DRAMNodes: []int{0}, DRAMQuota: -1})
	require.ErrorContains(t, err, "negative")
	_, err = pol.Plan(MemoryTypes{DRAMNodes: []int{0}, CXLNodes: []int{0}, DRAMQuota: 1, CXLQuota: 1})
	require.ErrorContains(t, err, "more than once")
	_, err = pol.Plan(MemoryTypes{DRAMNodes: []int{-1}, DRAMQuota: 1})
	require.ErrorContains(t, err, "invalid node")
	_, err = Policy{MemoryUseOrder: "nope"}.Plan(MemoryTypes{DRAMNodes: []int{0}, DRAMQuota: 1})
	require.ErrorContains(t, err, "memoryUseOrder")
}

func TestPolicyJSON(t *testing.T) {
	data := `{"memoryUseOrder":"waypoints","memoryUseWaypoints":[{"targetUsages":[{"memoryType":"DRAM","usage":"1Gi"}]}],"minStep":"16Mi"}`
	var pol Policy
	require.NoError(t, json.Unmarshal([]byte(data), &pol))
	require.NoError(t, pol.Validate())
	out, err := json.Marshal(pol)
	require.NoError(t, err)
	require.JSONEq(t, data, string(out))
}
