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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	resourceapi "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

const (
	// a shared persistent device with one share, and exclusive
	persistentData = `{"serial":"0xc1ae0001","shared":true,"size":536870912,"persistent":true}`
	writerData     = `{"serial":"0xc1ae0001","shared":true,"size":536870912,"persistent":true,"exclusive":true}`
	blockConfig    = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"block"}}`
	blockROConfig  = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"block","readOnly":true}}`
)

// fsConfig returns a MemoryConfig of mode fs with the access and path.
func fsConfig(access, path string) string {
	return fmt.Sprintf(`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","readOnly":true,"access":%q,"path":%q}}`, access, path)
}

func persistentClaim(uid, data, config string) *resourceapi.ResourceClaim {
	return withConfig(poolClaim(uid, "c-"+uid, "llm0", data), resourceapi.AllocationConfigSourceClaim, nil, config)
}

// newPoolLeaseEnv returns a pool test env with the persistent device of
// persistentData written by a writer, a pool driver with a lease-fs root,
// and fake hooks that give the lend records of companion claims the
// lease-fs directory of the lease claim lc1 and the name models.
func newPoolLeaseEnv(t *testing.T) (*poolTestEnv, *dra.Plugin, *fakeHooks) {
	t.Helper()
	e := newPoolTestEnv(t)
	e.leaseFsRoot = filepath.Join(e.dir, "lease-fs")
	e.plugPersistent(0xc1ae0001, "erofs")
	hooks := &fakeHooks{fsDir: filepath.Join(e.leaseFsRoot, "lc1"), name: "models"}
	noErr(t, os.MkdirAll(hooks.fsDir, 0o755))
	return e, e.leaseDriver(t, hooks), hooks
}

// leaseDriver returns a new pool driver, as after a restart, that lends
// companion claims with the hooks.
func (e *poolTestEnv) leaseDriver(t *testing.T, hooks *fakeHooks) *dra.Plugin {
	t.Helper()
	p := e.driver(t)
	p.Lender().Set(newFakeLender(), hooks)
	return p
}

// fsCompanion returns the companion claim of lease id of mode fs with the
// access on the persistent device, as the broker writes its MemoryConfig.
func fsCompanion(id, access string) *resourceapi.ResourceClaim {
	cfg := fmt.Sprintf(`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","readOnly":true,"access":%q}}`, access)
	c := persistentClaim("uid-"+companionName(id), persistentData, cfg)
	c.ObjectMeta = companionClaim(id).ObjectMeta
	return c
}

// TestPoolLeaseBindErrors refuses the Prepare of companion claims of fs
// leases whose bind cannot be made before any device is touched, and tells
// the broker (TestPoolLeaseBindChecks has the binds that fail).
func TestPoolLeaseBindErrors(t *testing.T) {
	e, p, hooks := newPoolLeaseEnv(t)
	target := filepath.Join(hooks.fsDir, "models")
	checkClean := func(what string) {
		t.Helper()
		e.wantClean(t, p)
		e.wantNoMounts(t, p)
		// refused before any device is touched
		if strings.Contains(e.commands(), "create-region") {
			t.Fatalf("%s: a device was touched:\n%s", what, e.commands())
		}
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: bind directory left: %v", what, err)
		}
	}

	// E1: a lease claim of an older driver
	hooks.fsDir = ""
	wantErr(t, prepare(t, p, fsCompanion("l1", "direct")).Err,
		"cxl-pool.nri.io: claim demo/cxl-lease-l1: lease l1: its lease claim has no filesystem directory")
	if !strings.Contains(hooks.log(), "failed l1: lease l1: its lease claim has no filesystem directory") {
		t.Fatalf("lend failure not told:\n%s", hooks.log())
	}
	checkClean("E1")
	hooks.fsDir = filepath.Join(e.leaseFsRoot, "lc1")

	// E2: two fs devices
	c := fsCompanion("l2", "direct")
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
		resourceapi.DeviceRequestAllocationResult{Request: "mem2", Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: "llm0", ConsumedCapacity: poolConsumed(persistentData)})
	wantErr(t, prepare(t, p, c).Err, "lease l2: more than one filesystem device")
	checkClean("E2")
}
