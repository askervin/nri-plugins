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
	"testing"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

// The usable size of a local memdev from its memdevSettings; invalid
// settings are refused.
func TestMemdevSettings(t *testing.T) {
	cfg, err := newDriverConfigFromString(`
memdevSettings:
- device: "0x0badc0dedeadbeef"
  usableSize: 128Gi
- device: mem1
  usableSize: 1000Mi
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	// the publisher rounds them down (internal/dra TestMemdevUsableSize)
	for _, tc := range []struct {
		m    *nricxl.MemoryDevice
		want uint64
	}{
		{&nricxl.MemoryDevice{Name: "mem0", Serial: 0x0badc0dedeadbeef, RamSize: 192 << 30}, 128 << 30},
		{&nricxl.MemoryDevice{Name: "mem1", Serial: 0x1, RamSize: 2 << 30}, 1000 << 20},
		{&nricxl.MemoryDevice{Name: "mem2", Serial: 0x2, RamSize: 2 << 30}, 0},
	} {
		if got := cfg.configuredUsableSize(tc.m.Name, tc.m.Serial); got != tc.want {
			t.Errorf("%s: configured usable size %d, expected %d", tc.m.Name, got, tc.want)
		}
	}
	for _, bad := range []string{
		"memdevSettings: [{usableSize: 1Gi}]",
		"memdevSettings: [{device: mem0, usableSize: 1x}]",
		"memdevSettings: [{device: mem0, usableSize: 100Mi}]",
	} {
		cfg, err := newDriverConfigFromString(bad)
		if err == nil {
			err = cfg.validate()
		}
		if err == nil {
			t.Errorf("no error for %q", bad)
		}
	}
}
