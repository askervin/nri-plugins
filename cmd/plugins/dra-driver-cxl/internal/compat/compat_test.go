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

package compat

import "testing"

func TestMatches(t *testing.T) {
	for _, tc := range []struct {
		template, line string
		want           bool
	}{
		{LogNRIFenceFencingCXLNodesNumaNodeOfPrepared, "I1105 12:00:00 fence.go:125] NRI fence: fencing CXL nodes 2,3 of prepared claims", true},
		{LogNRIFenceFencingCXLNodesNumaNodeOfPrepared, "NRI fence: fencing CXL nodes 2 of claims", false},
		{LogSerialDRALocalSerialKeepingSharedSharedRegionAndSharedDaxClaims,
			"local: memdev mem1 (serial 0xc100e2e1): keeping shared region0 and dax0.0, claims [a b]", true},
		{LogSerialDRALocalSerialKeepingSharedSharedRegionAndSharedDaxClaims,
			"local: memdev mem1 (serial 0xc100e2e1): keeping shared region0 and dax0.0, claims a b", false},
		{ExecutorLendsRestored, "NRI fence: lends restored (fencing none)", true},
		{ExecutorLendsRestored, "NRI fence: lends", false},
	} {
		if got := Matches(tc.template, tc.line); got != tc.want {
			t.Errorf("Matches(%q, %q) = %v, want %v", tc.template, tc.line, got, tc.want)
		}
	}
}

func TestMatchesRegexp(t *testing.T) {
	for _, tc := range []struct {
		pattern, line string
		want          bool
	}{
		{ObserverFencingLog, "defaults.container.fencing: allowed-mems: containers get the CXL nodes", true},
		{ObserverFencingLog, "defaults.container.fencing allowed-mems", false},
		{LogNRICreateContainerCtrDRANsPlainMainCpusetMemsH9df004,
			"NRI CreateContainer: ctr=ns/plain/main: cpuset.mems=0-1 (fenced)", true},
		{LogNRICreateContainerCtrDRANsPlainMainCpusetMemsH9df004,
			"NRI CreateContainer: ctr=ns/plain/main: cpuset.mems=", false},
		{LogUnpreparReleas, "Unprepared claim ns/a", true},
		{LogDRAPoolDriverClaimPreparedPooled0, "cxl-pool.nri.io: claim ns/a: prepared pooled0 serial 0xc1ae0000", true},
		{ObserverPanic, "goroutine 1 [running]: panic: oops", true},
	} {
		got, err := MatchesRegexp(tc.pattern, tc.line)
		if err != nil {
			t.Fatalf("MatchesRegexp(%q): %v", tc.pattern, err)
		}
		if got != tc.want {
			t.Errorf("MatchesRegexp(%q, %q) = %v, want %v", tc.pattern, tc.line, got, tc.want)
		}
	}
	if _, err := MatchesRegexp(ExecutorLendsRestored, "x"); err == nil {
		t.Errorf("MatchesRegexp of a template: no error")
	}
}

// TestRegexpsCompile checks that every regular expression constant compiles
// in its dialect.
func TestRegexpsCompile(t *testing.T) {
	for _, r := range regexps {
		if _, err := MatchesRegexp(r.pattern, ""); err != nil {
			t.Errorf("%q: %v", r.pattern, err)
		}
	}
}
