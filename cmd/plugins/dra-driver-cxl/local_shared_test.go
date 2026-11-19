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
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/klogtest"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// newSharedEnv returns a started node whose local memdev is configured
// shared, with the memdevs of specs plugged.
func newSharedEnv(t *testing.T, specs ...fake.MemdevSpec) *localTestEnv {
	t.Helper()
	e := newLocalTestEnv(t, specs...)
	configureShared(e, true)
	e.start()
	return e
}

// configureShared configures the local memdev shared or not: in the
// configuration of the publisher and of the next start, and in the shared
// memdevs of the running device engine.
func configureShared(e *localTestEnv, shared bool) {
	e.config.SharedDevices = nil
	e.shared = map[uint64]bool{}
	if shared {
		e.config.SharedDevices = []string{"0xc100e2e1"}
		e.shared[localSerial] = true
	}
	if e.devices != nil {
		e.devices.setShared(e.shared)
	}
}

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

// wantSharedUse checks how the device engine uses the local memdev, nil
// for not at all.
func wantSharedUse(t *testing.T, e *localTestEnv, want *localUse) {
	t.Helper()
	got, ok := e.localSnapshot().Use(localSerial)
	switch {
	case want == nil && ok:
		t.Fatalf("memdev used %+v, expected unused", got)
	case want != nil && (!ok || got.Shared != want.Shared || !slices.Equal(got.Claims, want.Claims)):
		t.Fatalf("memdev used %v %+v, expected %+v", ok, got, *want)
	}
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

// A failed creation of the region of a shared memdev, or of its zeroing,
// leaves no device, no claim and no region; a dax device of a kept region
// that fails leaves the region kept and no claim.
func TestLocalSharedCreateFailures(t *testing.T) {
	e := newSharedEnv(t)
	// the retry fails too
	e.k.FailCommand("cxl create-region", fake.ErrAddDev, fake.ErrAddDev)
	wantErr(t, e.prepare(sharedClaim("u1", "1M")), "add_dev")
	wantSharedUse(t, e, nil)

	e.k.ZeroErr = errors.New("no mmap")
	err := e.prepare(sharedClaim("u1", "1M"))
	wantErr(t, err, "memdev mem0 (serial 0xc100e2e1): zeroing new shared dax0.0: no mmap")
	wantReleasedLast(t, e, "region0")
	wantSharedUse(t, e, nil)
	e.k.ZeroErr = nil

	// the dax device of a kept region fails: no claim, the region stays
	e.mustPrepare(sharedClaim("u2", "1M"))
	e.mustUnprepare("u2")
	e.k.Write("bus/dax/devices/dax0.0/dev", "bogus")
	before := e.k.Commands()
	wantErr(t, e.prepare(sharedClaim("u3", "1")), `memdev mem0 (serial 0xc100e2e1): dax0.0: dax0.0: cannot parse device numbers "bogus"`)
	wantNoRegionRelease(t, e.k.CommandsSince(before))
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{}})
	e.k.Write("bus/dax/devices/dax0.0/dev", "252:0")
	e.mustPrepare(sharedClaim("u3", "1"))
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{"u3"}})
}

// A kept region that disappeared is forgotten, and the next claim creates
// and zeroes a new one.
func TestLocalSharedRegionGone(t *testing.T) {
	e := newSharedEnv(t)
	e.mustPrepare(sharedClaim("u1", "1"))
	e.mustUnprepare("u1")
	noErr(t, e.k.Kernel().ReleaseRegion(context.Background(), "region0"))
	wantLocalRegionCount(t, e, 1, 1)
	logs := klogtest.Capture(t, 3)
	noErr(t, prepareOn(context.Background(), e.s, sharedClaim("u2", "1")))
	e.check("prepared u2")
	// the other claims of the device: none
	if want := "engine: local memdev 0xc100e2e1 (mem0): region0 of the shared device is gone, forgetting it and its claims []"; !strings.Contains(logs(), want) {
		t.Fatalf("no %q in\n%s", want, logs())
	}
	wantLocalRegionCount(t, e, 2, 1)
	if z := e.k.Zeroed(); len(z) != 2 {
		t.Fatalf("new region not zeroed: %v", z)
	}
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{"u2"}})
}

// Prepare failures after the shared device was realised roll the claim
// back and keep the region: a failed write of the CDI spec. A claim whose
// second result has no device fails before the device is touched.
func TestPrepareSharedLocalRollback(t *testing.T) {
	e := newSharedEnv(t)
	e.mustPrepare(sharedClaim("u0", "1"))
	e.mustUnprepare("u0")
	spec := filepath.Join(e.cdiDir, device.ClaimsCDISpecName)
	noErr(t, os.MkdirAll(filepath.Join(spec, "x"), 0o755))
	wantErr(t, e.prepare(sharedClaim("u1", "1")), "write CDI spec")
	noErr(t, os.RemoveAll(spec))
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{}})
	wantLocalRegionCount(t, e, 1, 0)
	if e.preparation("u1") != nil || e.s.ClaimInfo("u1") != nil {
		t.Fatalf("rolled back claim %+v", e.preparation("u1"))
	}

	c := sharedClaim("u2", "1")
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
		resourcev1.DeviceRequestAllocationResult{Request: "other", Driver: device.DriverName, Pool: testNode, Device: "missing"})
	before := e.k.Commands()
	wantErr(t, e.prepare(c), "could not find allocatable device missing")
	if got := e.k.CommandsSince(before); got != "" {
		t.Fatalf("commands of a refused claim:\n%s", got)
	}
	wantSharedUse(t, e, &localUse{Shared: true, Claims: []string{}})
	wantLocalRegionCount(t, e, 1, 0)
	if len(e.prepared()) != 0 {
		t.Fatalf("prepared %v", e.prepared())
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
