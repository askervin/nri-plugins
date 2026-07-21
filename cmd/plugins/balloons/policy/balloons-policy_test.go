// Copyright 2022 Intel Corporation. All Rights Reserved.
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

package balloons

import (
	"testing"
)

func TestChangesBalloons(t *testing.T) {
	tcases := []struct {
		name          string
		opts1         *BalloonsOptions
		opts2         *BalloonsOptions
		expectedValue bool
	}{
		{
			name:          "both options are nil",
			expectedValue: false,
		},
		{
			name:          "one option is nil",
			opts2:         &BalloonsOptions{},
			expectedValue: true,
		},
		{
			name: "reserved pool namespaces differ by len",
			opts1: &BalloonsOptions{
				IdleCpuClass:           "icc0",
				ReservedPoolNamespaces: []string{"ns0"},
			},
			opts2: &BalloonsOptions{
				IdleCpuClass:           "icc0",
				ReservedPoolNamespaces: []string{},
			},
			expectedValue: true,
		},
		{
			name: "reserved pool namespaces differ by content",
			opts1: &BalloonsOptions{
				IdleCpuClass:           "icc0",
				ReservedPoolNamespaces: []string{"ns0"},
			},
			opts2: &BalloonsOptions{
				IdleCpuClass:           "icc0",
				ReservedPoolNamespaces: []string{"ns1"},
			},
			expectedValue: true,
		},
		{
			name: "idle cpu classes differ",
			opts1: &BalloonsOptions{
				IdleCpuClass:           "icc0",
				ReservedPoolNamespaces: []string{"ns0"},
			},
			opts2: &BalloonsOptions{
				IdleCpuClass:           "icc1",
				ReservedPoolNamespaces: []string{"ns0"},
			},
			expectedValue: false,
		},
		{
			name: "balloon defs differ",
			opts1: &BalloonsOptions{
				IdleCpuClass:           "icc0",
				ReservedPoolNamespaces: []string{"ns0"},
				BalloonDefs:            []*BalloonDef{},
			},
			opts2: &BalloonsOptions{
				IdleCpuClass:           "icc1",
				ReservedPoolNamespaces: []string{"ns0"},
				BalloonDefs:            []*BalloonDef{},
			},
			expectedValue: false,
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			value := changesBalloons(tc.opts1, tc.opts2)
			if value != tc.expectedValue {
				t.Errorf("Expected return value %v but got %v", tc.expectedValue, value)
			}
		})
	}
}

func TestWildcardMatch(t *testing.T) {
	tcases := []struct {
		pattern  string
		name     string
		expected bool
	}{
		{"tech.com/tpu", "tech.com/tpu", true},
		{"tech.com/tpu", "tech.com/gpu", false},
		{"tech.com/*", "tech.com/tpu", true},
		{"tech.com/*", "tech.com/", true},
		{"tech.com/*", "telco.com/nic", false},
		{"*/gpu", "nvidia.com/gpu", true},
		{"*/gpu", "nvidia.com/tpu", false},
		{"*", "anything/at-all", true},
		{"tech.com/?pu", "tech.com/tpu", true},
		{"tech.com/?pu", "tech.com/gpu", true},
		{"tech.com/?pu", "tech.com/pu", false},
		{"tech.com/?pu", "tech.com/ttpu", false},
		{"a*c*e", "abcde", true},
		{"a*c*e", "ace", true},
		{"a*c*e", "abce", true},
		{"a*c*e", "abcd", false},
		{"", "", true},
		{"", "x", false},
	}
	for _, tc := range tcases {
		t.Run(tc.pattern+" vs "+tc.name, func(t *testing.T) {
			if got := wildcardMatch(tc.pattern, tc.name); got != tc.expected {
				t.Errorf("wildcardMatch(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.expected)
			}
		})
	}
}
