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
	"fmt"
	"testing"
)

// The usable size and the coherence of a local memdev from its
// memdevSettings, which match a memdev by name or serial in every notation;
// without a configuration nothing is coherent; invalid settings are refused.
func TestMemdevSettings(t *testing.T) {
	cfg, err := newDriverConfigFromString(`
memdevSettings:
- device: "0x0badc0dedeadbeef"
  usableSize: 128Gi
- device: mem1
  usableSize: 1000Mi
  coherent: true
- device: "3238065634"
  usableSize: 1Gi
- device: "0x00c100f5e1"
  coherent: true
`)
	noErr(t, err)
	// the publisher rounds the usable sizes down (internal/dra
	// TestMemdevUsableSize)
	for _, tc := range []struct {
		name     string
		serial   uint64
		usable   uint64
		coherent bool
	}{
		{"mem0", 0x0badc0dedeadbeef, 128 << 30, false},
		{"mem1", 0x1, 1000 << 20, true},
		{"mem2", 0x2, 0, false},
		{"mem4", 0xc100f5e2, 1 << 30, false},
		{"mem5", 0xc100f5e1, 0, true},
	} {
		if got := cfg.configuredUsableSize(tc.name, tc.serial); got != tc.usable {
			t.Errorf("%s: configured usable size %d, expected %d", tc.name, got, tc.usable)
		}
		if got := cfg.memdevCoherent(tc.name, tc.serial); got != tc.coherent {
			t.Errorf("%s: coherent %v, expected %v", tc.name, got, tc.coherent)
		}
	}
	var none *DriverConfig
	if none.memdevCoherent("mem0", 1) {
		t.Fatal("coherent without a configuration")
	}
	for spec, want := range map[string]bool{"mem0": true, "cxl/mem0": true, "0xc100f5e1": true, "0XC100F5E1": true, "3238065633": true, "0x1": false, "mem1": false} {
		cfg, err := newDriverConfigFromString(fmt.Sprintf("memdevSettings: [{device: %q, coherent: true}]", spec))
		noErr(t, err)
		if got := cfg.memdevCoherent("mem0", 0xc100f5e1); got != want {
			t.Errorf("device %q: coherent %v, expected %v", spec, got, want)
		}
	}
	for _, bad := range []string{
		"memdevSettings: [{usableSize: 1Gi}]",
		"memdevSettings: [{device: mem0, usableSize: 1x}]",
		"memdevSettings: [{device: mem0, usableSize: 100Mi}]",
		`memdevSettings: [{device: "c100f5e1"}]`,
		`memdevSettings: [{device: "251:0"}]`,
		`memdevSettings: [{device: "0x"}]`,
	} {
		if _, err := newDriverConfigFromString(bad); err == nil {
			t.Errorf("no error for %q", bad)
		}
	}
}
