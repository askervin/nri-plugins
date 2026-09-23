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
	"strings"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// A Prepare that a process stop cut after its region was made: the start
// releases what it made, the claim stays PREPARING with its results (its
// record lists the device), kubelet's Prepare again prepares it anew.
func TestPoolCutPrepareAtStart(t *testing.T) {
	e := newPoolTestEnv(t)
	memdev := e.plug(0xc1ee0001)
	p := e.driver(t)
	e.k.CutAfter("cxl create-region")
	cutPrepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData))
	logs := captureKlog(t)
	p = e.driver(t)
	out := logs()
	for _, want := range []string{
		"claim default/c1 (u1), whose Prepare did not finish: releasing devices 0xc1ee0001",
		"claim default/c1 (u1): released, its Prepare again prepares its devices anew",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if prep := e.preparation("u1"); prep == nil || prep.State != state.PreparationPreparing {
		t.Fatalf("preparation %+v", prep)
	}
	if prep := e.unfinished("u1"); prep == nil || prep.ClaimName != "default/c1" || len(prep.Results) != 1 || prep.Reason != "" {
		t.Fatalf("record of the claim %+v", prep)
	}
	if rs := e.k.Kernel().Regions(memdev); len(rs) != 0 {
		t.Fatalf("regions %v left at the start", rs)
	}
	noErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err)
	if prep := e.preparation("u1"); prep.State != state.PreparationPrepared {
		t.Fatalf("preparation %+v", prep)
	}
	noErr(t, unprepare(t, p, "u1"))
	e.wantClean(t, p)
}

// A cut Prepare whose region lies below a newer region of another memdev
// is kept at the start: the claim is KEPT, its records stay with the
// region of its grant, its Unprepare releases it.
func TestPoolKeptRecord(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ee0001)
	other := e.plug(0xc1ee0002)
	p := e.driver(t)
	e.k.CutAfter("cxl create-region")
	cutPrepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData))
	k := e.k.Kernel()
	d, err := k.RootDecoder(other, kernel.RegionRAM)
	noErr(t, err)
	above, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: other, Decoder: d, Type: kernel.RegionRAM})
	noErr(t, err)
	e.base = e.k.Commands()
	logs := captureKlog(t)
	p = e.driver(t)
	if want := "claim default/c1 (u1): not releasing its devices at start: " + above + " lie above their regions"; !strings.Contains(logs(), want) {
		t.Fatalf("no %q in\n%s", want, logs())
	}
	if prep := e.preparation("u1"); prep == nil || prep.State != state.PreparationKept {
		t.Fatalf("preparation %+v", prep)
	}
	prep := e.unfinished("u1")
	g := e.grant("u1", 0)
	if prep == nil || prep.ClaimName != "default/c1" || len(prep.Results) != 1 || prep.Reason != "" || g == nil || g.Serial != 0xc1ee0001 ||
		g.Intent.Region != "region0" {
		t.Fatalf("record of the kept claim %+v, grant %+v", prep, g)
	}
	// its device as the claim asks it, before the Prepare made it
	if d := e.device(p, "u1", 0); d.Serial != 0xc1ee0001 || d.Mode != api.ModeNUMA || d.Size != 268435456 || d.Region != "" {
		t.Fatalf("device of the kept claim %+v", d)
	}
	if !p.Serials()[0xc1ee0001] {
		t.Fatalf("serials %v", p.Serials())
	}
	noErr(t, unprepare(t, p, "u1"))
	noErr(t, k.ReleaseRegion(context.Background(), above))
	e.wantClean(t, p)
}

// The companion claim of a numa lease cut in its Prepare (before its lend)
// is kept at the start for its Unprepare, which releases it
// (TestPoolCompanionRevoke has the revoke of a cut after the lend).
func TestPoolCutCompanionKept(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ee0001)
	p := e.driver(t)
	hooks := &fakeHooks{}
	lender := newFakeLender()
	p.Lender().Set(lender, hooks)
	claim := poolClaim("uid-cxl-lease-l1", "cxl-lease-l1", "pooled0", exclusiveData)
	claim.Namespace = testNS
	claim.Labels = map[string]string{device.LeaseLabel: "l1"}
	e.k.CutAfter("write devices/system/memory/memory")
	cutPrepare(t, p, claim)
	logs := captureKlog(t)
	p = e.driver(t)
	if want := "claim demo/cxl-lease-l1 (uid-cxl-lease-l1) is a companion claim: its Unprepare releases its devices, its Prepare again reuses them"; !strings.Contains(logs(), want) {
		t.Fatalf("no %q in\n%s", want, logs())
	}
	if prep := e.preparation("uid-cxl-lease-l1"); prep == nil || prep.State != state.PreparationPreparing {
		t.Fatalf("preparation %+v", prep)
	}
	p.Lender().Set(lender, hooks)
	p.Engine().RecoverCompanions()
	noErr(t, unprepare(t, p, "uid-cxl-lease-l1"))
	e.wantClean(t, p)
}

// A claim prepared in another boot is not prepared: no CDI device, no
// results; its record says why; its Prepare again prepares its device
// anew, its Unprepare releases the device by its serial.
func TestPoolOtherBoot(t *testing.T) {
	e := newPoolTestEnv(t)
	memdev := e.plug(0xc1ee0001)
	p := e.driver(t)
	noErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err)
	noErr(t, prepare(t, p, poolClaim("u2", "c2", "pooled0", exclusiveData)).Err)
	e.k.Reboot()
	p = e.driver(t)
	for _, uid := range []string{"u1", "u2"} {
		prep := e.preparation(uid)
		if prep == nil || prep.State != state.PreparationStale || p.ClaimResults(uid) != nil {
			t.Fatalf("claim %s: %+v", uid, prep)
		}
		if !strings.HasPrefix(prep.Reason, "prepared in another boot") {
			t.Fatalf("record of %s: %+v", uid, prep)
		}
	}
	if e.cdiSpec(t) != nil {
		t.Fatalf("CDI spec of the claims of another boot %+v", e.cdiSpec(t))
	}
	// the Prepare again of u1 prepares its device anew
	noErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err)
	if prep := e.preparation("u1"); prep.State != state.PreparationPrepared || cdiDeviceByName(e.cdiSpec(t), "claim-u1-0") == nil {
		t.Fatalf("preparation %+v", prep)
	}
	noErr(t, unprepare(t, p, "u1"))
	// the Unprepare of u2 disables its memdev, which no grant of this
	// boot uses
	logs := captureKlog(t)
	noErr(t, unprepare(t, p, "u2"))
	if want := "unpreparing claim default/c2 (u2), not prepared any more (prepared in another boot"; !strings.Contains(logs(), want) {
		t.Fatalf("no %q in\n%s", want, logs())
	}
	e.wantCommand(t, "cxl disable-memdev "+memdev)
	e.wantClean(t, p)
}
