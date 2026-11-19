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
	"slices"
	"testing"
)

// The sharedDevices of the configuration: a list of strings, each a memdev
// spec; an invalid spec of sharedDevices or ignoreDevices fails the load.
func TestDriverConfigSharedDevices(t *testing.T) {
	cfg, err := newDriverConfigFromString(`sharedDevices: ["0xc100e2e1", "mem1"]`)
	noErr(t, err)
	if !slices.Equal(cfg.SharedDevices, []string{"0xc100e2e1", "mem1"}) {
		t.Fatalf("sharedDevices %v", cfg.SharedDevices)
	}
	for _, bad := range []string{`sharedDevices: "0xc100e2e1"`, `sharedDevice: ["0xc100e2e1"]`, `sharedDevices: [{serial: 1}]`,
		`sharedDevices: ["c100e2e1"]`, `ignoreDevices: ["mem0", "cxl/c100e2e1"]`} {
		if _, err := newDriverConfigFromString(bad); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}
