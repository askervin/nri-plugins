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

package dra

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// The Unprepare of a companion claim of cxl.nri.io: the lease claim closed
// before anything, the broker told, UNPREPARING committed before the
// revoke, the memory released after it, the record removed.
func TestUnprepareOrder(t *testing.T) {
	e := lendEnv(t)
	nodes, _ := e.lending()
	e.setLeases()
	e.mustPrepare(e.local, e.companionOf(e.local))
	var atRevoke []string
	nodes.onRevoke = func(int) {
		atRevoke = append(atRevoke, string(e.stateOf(e.local, "c1")))
		if e.records().Grant(state.GrantRef{Claim: "c1"}) == nil || e.onlineBlocks() == 0 {
			atRevoke = append(atRevoke, "released")
		}
	}
	e.takeEvents()
	e.mustUnprepare(e.local, "c1")
	e.wantEvents("unprepared", "close c1 (PREPARED)", "releasing l1", "revoke pod-uid-1/app 2 l1")
	if len(atRevoke) != 1 || atRevoke[0] != string(state.PreparationUnpreparing) {
		t.Fatalf("at the revoke: %v", atRevoke)
	}
	e.wantClean()
}

// A revoke that fails, or comes before the lender is set up, fails the
// Unprepare of a companion claim of either driver: the claim stays
// UNPREPARING with its memory, kubelet's retry finishes it.
func TestUnprepareRevokeFails(t *testing.T) {
	for _, local := range []bool{true, false} {
		e := lendEnv(t)
		p := e.pluginOf(local)
		t.Run(p.Name(), func(t *testing.T) {
			e.t = t
			nodes, _ := e.lending()
			e.mustPrepare(p, e.companionOf(p))
			nodes.setErrors(nil, errSteered)
			err := e.unprepare(p, "c1")
			revokeErr := "lease l1: revoking node 2 from demo/borrower/app: " + errSteered.Error()
			want := "cxl-pool.nri.io: unpreparing claim demo/cxl-lease-l1: " + revokeErr
			if local {
				want = "error freeing devices: claim demo/cxl-lease-l1: " + revokeErr
			}
			wantErrText(t, err, want)
			e.wantState(p, "c1", state.PreparationUnpreparing)
			if e.onlineBlocks() == 0 {
				t.Fatal("the memory went offline after a failed revoke")
			}
			// a start: the lender is not set up yet
			e.lent = false
			e.restart()
			p = e.pluginOf(local)
			wantErrText(t, e.unprepare(p, "c1"), "lending is not set up yet (the plugin is starting)")
			e.wantState(p, "c1", state.PreparationUnpreparing)
			nodes.setErrors(nil, nil)
			e.lend(nodes, e.hooks)
			e.mustUnprepare(p, "c1")
			e.wantClean()
		})
	}
}

// A release that fails leaves the claim UNPREPARING; cxl.nri.io keeps its
// CDI devices (CDIUnpreparing), the pool driver does not; the retry
// releases it.
func TestUnprepareReleaseFails(t *testing.T) {
	t.Run("cxl.nri.io", func(t *testing.T) {
		e := newDriverEnv(t, []fake.MemdevSpec{slicedSpec()})
		e.mustPrepare(e.local, localClaim("u1", localDev, envBlockSize, cfgDax))
		dax := e.records().Grant(state.GrantRef{Claim: "u1"}).Got.Dax
		e.k.FailWrite("bus/dax/devices/"+dax+"/size", syscall.EBUSY)
		wantErrText(t, e.unprepare(e.local, "u1"), "error freeing devices: claim demo/claim-u1: ")
		e.wantState(e.local, "u1", state.PreparationUnpreparing)
		if e.cdiDevice(e.local, "claim-u1-0") == nil {
			t.Fatal("no CDI device of an UNPREPARING claim")
		}
		if info := e.local.ClaimInfo("u1"); info == nil {
			t.Fatal("no claim info of an UNPREPARING claim")
		}
		// a Prepare again of the UNPREPARING claim returns its result
		res := e.mustPrepare(e.local, localClaim("u1", localDev, envBlockSize, cfgDax))
		wantResult(t, res, resultDevice("mem", envNode, localDev, "nri.io/cxl=claim-u1-0"))
		e.wantState(e.local, "u1", state.PreparationUnpreparing)
		e.restart()
		e.wantState(e.local, "u1", state.PreparationUnpreparing)
		if e.cdiDevice(e.local, "claim-u1-0") == nil {
			t.Fatal("no CDI device of an UNPREPARING claim after a start")
		}
		e.mustUnprepare(e.local, "u1")
		e.wantClean()
	})
	t.Run("cxl-pool.nri.io", func(t *testing.T) {
		e := newDriverEnv(t, nil, poolPmemSpec(serialPoolP))
		e.formatPmem(serialPoolP, "erofs")
		e.mustPrepare(e.pool, poolClaim("u1", "llm0", poolPmemData, cfgFsRO))
		mnt := filepath.Join(e.poolDir, "mounts", "c1af0001-direct")
		e.k.SetBusy(mnt, true)
		err := e.unprepare(e.pool, "u1")
		wantErrText(t, err, "cxl-pool.nri.io: unpreparing claim demo/claim-u1: ")
		wantErrText(t, err, "device 0xc1af0001: unmounting "+mnt+": device or resource busy")
		e.wantState(e.pool, "u1", state.PreparationUnpreparing)
		if e.cdiDevice(e.pool, "claim-u1-0") != nil {
			t.Fatal("a CDI device of an UNPREPARING pool claim")
		}
		// a Prepare again of the UNPREPARING claim returns its result
		res := e.mustPrepare(e.pool, poolClaim("u1", "llm0", poolPmemData, cfgFsRO))
		if len(res.Devices) != 1 || len(res.Devices[0].CDIDeviceIDs) != 1 || res.Devices[0].CDIDeviceIDs[0] != "nri.io/cxl-pool=claim-u1-0" {
			t.Fatalf("the result of an UNPREPARING claim %+v", res)
		}
		e.wantState(e.pool, "u1", state.PreparationUnpreparing)
		// the retry of an UNPREPARING claim
		wantErrText(t, e.unprepare(e.pool, "u1"), "busy")
		e.k.SetBusy(mnt, false)
		e.mustUnprepare(e.pool, "u1")
		e.wantClean()
	})
}

// A CDI spec that does not write after the release of a prepared claim
// fails the Unprepare of cxl.nri.io (FailUnprepareOnCDI); the pool driver
// logs it. Either way the claim is gone, and
// kubelet's retry finds nothing to release.
func TestUnprepareCDIFails(t *testing.T) {
	for _, local := range []bool{true, false} {
		e := newDriverEnv(t, []fake.MemdevSpec{slicedSpec()}, poolSpec(serialPoolX), fake.MemdevSpec{Serial: serialPoolS, HostBridge: 24})
		p := e.pluginOf(local)
		t.Run(p.Name(), func(t *testing.T) {
			e.t = t
			claims := []*resourcev1.ResourceClaim{localClaim("u1", localDev, envBlockSize), localClaim("u2", device.DRAMDeviceName, 64*mib)}
			if !local {
				claims = []*resourcev1.ResourceClaim{poolClaim("u1", "pooled0", poolExclusiveData), poolClaim("u2", "shared0", poolSharedData)}
			}
			for _, c := range claims {
				e.mustPrepare(p, c)
			}
			if names := e.cdiNames(p); len(names) != 2 {
				t.Fatalf("CDI devices %v", names)
			}
			// the spec file a directory with an entry: the rename of the
			// written spec fails (a spec of no devices is not written)
			spec := filepath.Join(e.cdiDir, p.Rules().CDISpecName+".yaml")
			mustOK(t, os.Remove(spec))
			mustOK(t, os.MkdirAll(filepath.Join(spec, "entry"), 0o755))
			logs := klogCapture(t)
			err := e.unprepare(p, "u1")
			want := "failed to write CDI spec " + p.Rules().CDISpecName + ": "
			if local {
				wantErrText(t, err, "error freeing devices: "+want)
				if strings.Contains(logs(), "Freed devices for claim 'u1'") {
					t.Fatal("a failed Unprepare logged as freed")
				}
			} else {
				mustOK(t, err)
				wantLogText(t, logs(), p.Name()+": "+want)
				wantLogText(t, logs(), p.Name()+": unprepared claim demo/claim-u1 (u1)")
			}
			if e.preparation(p, "u1") != nil {
				t.Fatal("the record of u1 is left")
			}
			mustOK(t, os.RemoveAll(spec))
			e.mustUnprepare(p, "u1")
			e.mustUnprepare(p, "u2")
			e.wantClean()
		})
	}
}
