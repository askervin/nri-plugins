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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseNodeList(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []int
		err  string
	}{
		{in: "5", want: []int{5}},
		{in: "5,6", want: []int{5, 6}},
		{in: "5-6", want: []int{5, 6}},
		{in: " 1-2,5-6\n", want: []int{1, 2, 5, 6}},
		{in: "6,5,5-6", want: []int{5, 6}},
		{in: "0-3,7", want: []int{0, 1, 2, 3, 7}},
		{in: "", err: "empty node list"},
		{in: "a", err: `"a" is not a node number`},
		{in: "-1", err: `"" is not a node number`},
		{in: "6-5", err: "range 6-5 ends before it starts"},
		{in: "1,,2", err: `"" is not a node number`},
		{in: "65536", err: `"65536" is not a node number`},
	} {
		got, err := parseNodeList(tc.in)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("parseNodeList(%q): error %v, want one with %q", tc.in, err, tc.err)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseNodeList(%q) = %v, %v, want %v", tc.in, got, err, tc.want)
		}
	}
}

func TestFormatNodeList(t *testing.T) {
	for _, tc := range []struct {
		in   []int
		want string
	}{
		{nil, ""},
		{[]int{5}, "5"},
		{[]int{5, 6}, "5-6"},
		{[]int{1, 2, 5, 6}, "1-2,5-6"},
		{[]int{0, 2, 3, 4, 7}, "0,2-4,7"},
	} {
		if got := formatNodeList(tc.in); got != tc.want {
			t.Errorf("formatNodeList(%v) = %q, want %q", tc.in, got, tc.want)
		}
		if tc.want == "" {
			continue
		}
		if back, err := parseNodeList(tc.want); err != nil || !reflect.DeepEqual(back, tc.in) {
			t.Errorf("parseNodeList(%q) = %v, %v, want %v", tc.want, back, err, tc.in)
		}
	}
}

func TestMemoryNodesAndCheckNodes(t *testing.T) {
	sysfs := t.TempDir()
	dir := filepath.Join(sysfs, "devices/system/node")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := memoryNodes(sysfs); err == nil {
		t.Errorf("memoryNodes without has_memory: no error")
	}
	if err := os.WriteFile(filepath.Join(dir, "has_memory"), []byte("1-2,5-6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	have, err := memoryNodes(sysfs)
	if err != nil || !reflect.DeepEqual(have, []int{1, 2, 5, 6}) {
		t.Fatalf("memoryNodes = %v, %v, want [1 2 5 6]", have, err)
	}
	if err := checkNodes([]int{5, 6}, have); err != nil {
		t.Errorf("checkNodes([5 6]): %v", err)
	}
	err = checkNodes([]int{5, 4}, have)
	if err == nil || err.Error() != "node 4 has no memory (the nodes with memory: 1-2,5-6)" {
		t.Errorf("checkNodes([5 4]): %v", err)
	}
}

func TestHasCapSysNice(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		status string
		want   bool
		err    string
	}{
		{status: "Name:\tx\nCapEff:\t000001ffffffffff\n", want: true},
		{status: "CapEff:\t0000000000000000\n", want: false},
		{status: "CapEff:\t0000000000800000\n", want: true}, // only CAP_SYS_NICE (23)
		{status: "CapEff:\t00000000007fffff\n", want: false},
		{status: "CapEff:\tzz\n", err: "CapEff"},
		{status: "Name:\tx\n", err: "has no CapEff"},
	} {
		path := filepath.Join(dir, "status")
		if err := os.WriteFile(path, []byte(tc.status), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := hasCapSysNice(path)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("hasCapSysNice(%q): error %v, want one with %q", tc.status, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("hasCapSysNice(%q) = %v, %v, want %v", tc.status, got, err, tc.want)
		}
	}
}
