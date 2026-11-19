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
	"strings"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// sharedClaim returns a claim allocated the shared local memdev for
// request "mem", with consumed shares ("" for none) and opaque cxl.nri.io
// claim configs.
func sharedClaim(uid, shares string, configs ...string) *resourcev1.ResourceClaim {
	c := localClaim(uid, 0, configs...)
	if shares != "" {
		c.Status.Allocation.Devices.Results[0].ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse(shares)}
	}
	return c
}

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

// A stale allocation of the shared shape is refused on a sliced memdev.
func TestPrepareSlicedRefusesShares(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	wantErr(t, e.prepare(sharedClaim("u1", "1M")),
		"claim demo/claim-u1: request mem: device 0xc100e2e1: allocated as a shared device, which it is not any more")
	if strings.Contains(e.commands(), "create-region") || e.inUse() {
		t.Fatalf("a refused claim touched the memdev:\n%s", e.commands())
	}
}
