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
	"slices"
	"testing"
)

// fsTypes defaults to erofs, is returned as a copy, and its invalid or
// misspelt settings are refused.
func TestDriverConfigFsTypes(t *testing.T) {
	cfg, err := newDriverConfigFromString("")
	noErr(t, err)
	if got := cfg.fsTypes(); !slices.Equal(got, []string{"erofs"}) {
		t.Fatalf("default fsTypes %v", got)
	}
	cfg.fsTypes()[0] = "x"
	if cfg.fsTypes()[0] != "erofs" || defaultFsTypes[0] != "erofs" {
		t.Fatal("fsTypes() is not a copy")
	}
	cfg, err = newDriverConfigFromString("fsTypes: [erofs, f2fs]")
	noErr(t, err)
	if got := cfg.fsTypes(); !slices.Equal(got, []string{"erofs", "f2fs"}) {
		t.Fatalf("fsTypes %v", got)
	}
	cfg, err = newDriverConfigFromString("fsTypes: []")
	noErr(t, err)
	if got := cfg.fsTypes(); got == nil || len(got) != 0 {
		t.Fatalf("empty fsTypes %#v", got)
	}
	_, err = newDriverConfigFromString("fsTypes: [ext4, Ext4]")
	wantErr(t, err, `fsTypes: invalid filesystem type "Ext4" (lower-case letters, digits, "_" and "-")`)
	_, err = newDriverConfigFromString("fsType: [ext4]")
	wantErr(t, err, `unknown field "fsType"`)
}

// coherent of memdevSettings matches a memdev by name or serial in every
// notation; without a configuration nothing is coherent.
func TestDriverConfigMemdevCoherent(t *testing.T) {
	cfg, err := newDriverConfigFromString(`
memdevSettings:
- device: "0x00c100f5e1"
  coherent: true
- device: mem3
  coherent: true
- device: "3238065634"
  usableSize: 1Gi
`)
	noErr(t, err)
	for _, tc := range []struct {
		name   string
		serial uint64
		want   bool
	}{
		{"mem0", 0xc100f5e1, true},
		{"mem3", 0x1, true},
		{"mem4", 0xc100f5e2, false}, // the setting without coherent
		{"mem5", 0x5, false},
	} {
		if got := cfg.memdevCoherent(tc.name, tc.serial); got != tc.want {
			t.Errorf("%s 0x%x: coherent %v, expected %v", tc.name, tc.serial, got, tc.want)
		}
	}
	if got := cfg.configuredUsableSize("mem4", 0xc100f5e2); got != 1<<30 {
		t.Fatalf("usable size %d of the decimal serial", got)
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
	for _, spec := range []string{"c100f5e1", "251:0", "0x"} {
		if _, err := newDriverConfigFromString(fmt.Sprintf("memdevSettings: [{device: %q}]", spec)); err == nil {
			t.Errorf("device %q accepted", spec)
		}
	}
}
