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
	m0 := &nricxl.MemoryDevice{Name: "mem0", Serial: 0x0badc0dedeadbeef, RamSize: 192 << 30}
	m1 := &nricxl.MemoryDevice{Name: "mem1", Serial: 0x1, RamSize: 2 << 30}
	m2 := &nricxl.MemoryDevice{Name: "mem2", Serial: 0x2, RamSize: 2 << 30}
	for _, tc := range []struct {
		m      *nricxl.MemoryDevice
		probed uint64
		want   uint64
	}{
		{m0, 0, 128 << 30},
		{m0, 64 << 30, 64 << 30},
		{m1, 0, 768 << 20},
		{m2, 0, 2 << 30},
		{m2, 1 << 30, 1 << 30},
	} {
		snap := &localSnapshot{Probed: map[uint64]uint64{tc.m.Serial: tc.probed}}
		if got := memdevUsableSize(cfg, tc.m, snap); got != tc.want {
			t.Errorf("%s probed %d: usable size %d, expected %d", tc.m.Name, tc.probed, got, tc.want)
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
