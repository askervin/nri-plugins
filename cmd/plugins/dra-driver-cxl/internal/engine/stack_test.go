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

package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/compat"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// The decoder stacks of the host bridge 12 in the scenarios of the e2e
// model: the local memdev l and the pool devices b and c under it.
var stackSpecs = []fake.MemdevSpec{{Serial: serialL, Ram: gib}, {Serial: serialB}, {Serial: serialC}}

// wantStack fails the test unless the decoder stack of the host bridge of
// the memdev with the serial is the regions of the memdevs of serials, 0 for
// a hole.
func wantStack(t *testing.T, v *env, serials ...uint64) {
	t.Helper()
	k := v.f.Kernel()
	port := k.Memdev(serialL).Ports[0]
	var want []string
	for _, s := range serials {
		if s == 0 {
			want = append(want, "")
			continue
		}
		rs := k.Regions(k.Memdev(s).Name)
		if len(rs) != 1 {
			t.Fatalf("memdev 0x%x has regions %v", s, rs)
		}
		want = append(want, rs[0])
	}
	if got := v.f.Stack(port); !slices.Equal(got, want) {
		t.Fatalf("stack of %s %q, want %q", port, got, want)
	}
}

// The sequence of the model's TestBlockedUntilHoleClears: a pool
// device released below a newer region leaves a hole; a Prepare that needs
// a new region through the stack fails with the hole text until the region
// above is gone, then succeeds.
func TestStackBlockedUntilHoleClears(t *testing.T) {
	v := newEnv(t, stackSpecs...)
	v.mustPrepare(localDriver, "ldax", localReq("ldax", 0, serialL, state.ModeDax, state.KindExclusive, 256*mib))
	v.mustPrepare(poolDriver, "xdax-b", poolReq("xdax-b", 0, serialB, state.ModeDax, state.KindExclusive))
	v.mustPrepare(poolDriver, "sdax-b", poolReq("sdax-b", 0, serialC, state.ModeDax, state.KindShared))
	wantStack(t, v, serialL, serialB, serialC)
	v.mustUnprepare(poolDriver, "xdax-b")
	wantStack(t, v, serialL, 0, serialC)

	err := v.prepare(poolDriver, "xnuma-b", poolReq("xnuma-b", 0, serialB, state.ModeNUMA, state.KindExclusive))
	var hole *kernel.ErrDecoderHole
	if !errors.As(err, &hole) || !strings.Contains(err.Error(), compat.OracleBlockedText) {
		t.Fatalf("error %v", err)
	}
	v.check("blocked")
	wantStack(t, v, serialL, 0, serialC)

	v.mustUnprepare(poolDriver, "sdax-b")
	wantStack(t, v, serialL)
	v.mustPrepare(poolDriver, "xnuma-b", poolReq("xnuma-b", 0, serialB, state.ModeNUMA, state.KindExclusive))
	wantStack(t, v, serialL, serialB)
	v.mustUnprepare(poolDriver, "xnuma-b")
	v.mustUnprepare(localDriver, "ldax")
	v.clean("unprepared")
}

// The model's TestStackUsersOfOneRegion: a shared pool device is the region
// of its claims until the last one goes; then it leaves a hole below the
// local region, which the release of the local region reaps.
func TestStackUsersOfOneRegion(t *testing.T) {
	v := newEnv(t, stackSpecs...)
	v.mustPrepare(poolDriver, "sdax-c0", poolReq("sdax-c0", 0, serialC, state.ModeDax, state.KindShared))
	v.mustPrepare(localDriver, "lnuma", localReq("lnuma", 0, serialL, state.ModeNUMA, state.KindExclusive, 128*mib))
	v.mustPrepare(poolDriver, "sdax-c1", poolReq("sdax-c1", 0, serialC, state.ModeDax, state.KindShared))
	wantStack(t, v, serialC, serialL)
	v.mustUnprepare(poolDriver, "sdax-c0")
	wantStack(t, v, serialC, serialL)
	v.mustUnprepare(poolDriver, "sdax-c1")
	wantStack(t, v, 0, serialL)
	v.mustUnprepare(localDriver, "lnuma")
	wantStack(t, v)
	v.clean("unprepared")
}

// Prepares that a process stop cut on two memdevs of one stack are released
// at the start top-most first: no hole is left.
func TestStackRecoveryTopMostFirst(t *testing.T) {
	v := newEnv(t, stackSpecs...)
	for _, c := range []struct {
		uid    string
		serial uint64
	}{{"b", serialB}, {"c", serialC}} {
		if err := v.st.Commit(context.Background(), 0, func(doc *storeDocument) error {
			doc.Preparations = append(doc.Preparations, state.Preparation{UID: c.uid, Driver: poolDriver, BootID: v.f.BootID(),
				State: state.PreparationPreparing, Results: []state.Result{grantResult(c.uid, 0)}})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := v.e.PrepareGrants(context.Background(), []GrantRequest{poolReq(c.uid, 0, c.serial, state.ModeDax, state.KindExclusive)}); err != nil {
			t.Fatal(err)
		}
	}
	wantStack(t, v, serialB, serialC)
	out := v.restart()
	if !slices.Equal(out.Released, []state.GrantRef{{Claim: "c"}, {Claim: "b"}}) || len(out.Kept) > 0 {
		t.Fatalf("recovered %+v", out)
	}
	wantStack(t, v)
	v.check("recovered")
	finish(t, v, "recovered")
}

// A local sliced memdev and a pool memdev under one host bridge port: the
// Unprepare of the local claim below the pool region destroys its region
// and leaves a hole; the next creation through the port fails (the hole
// text) until the pool region goes, which reaps the hole.
func TestStackLocalSlicedHole(t *testing.T) {
	v := newEnv(t, stackSpecs...)
	v.mustPrepare(localDriver, "l", sliceReq("l", 0, state.ModeDax, 256*mib))
	v.mustPrepare(poolDriver, "b", poolReq("b", 0, serialB, state.ModeDax, state.KindExclusive))
	wantStack(t, v, serialL, serialB)
	v.mustUnprepare(localDriver, "l")
	wantStack(t, v, 0, serialB)
	for _, c := range []struct {
		driver string
		req    GrantRequest
	}{
		{localDriver, sliceReq("l2", 0, state.ModeNUMA, 256*mib)},
		{poolDriver, poolReq("c", 0, serialC, state.ModeDax, state.KindExclusive)},
	} {
		err := v.prepare(c.driver, c.req.Ref.Claim, c.req)
		var hole *kernel.ErrDecoderHole
		if !errors.As(err, &hole) || !strings.Contains(err.Error(), compat.OracleBlockedText) {
			t.Fatalf("%s: error %v", c.req.Ref.Claim, err)
		}
		v.check("blocked " + c.req.Ref.Claim)
		wantStack(t, v, 0, serialB)
	}
	v.mustUnprepare(poolDriver, "b")
	wantStack(t, v)
	v.mustPrepare(localDriver, "l2", sliceReq("l2", 0, state.ModeNUMA, 256*mib))
	wantStack(t, v, serialL)
	v.mustUnprepare(localDriver, "l2")
	v.clean("unprepared")
}

// A local rollback below a pool region keeps the local region for the
// claim (KEPT): the pool claim is prepared between the two parts of a
// local claim (its guard of the second memdev), whose second part fails;
// the Prepare again reuses the kept region once the pool region is gone.
func TestStackLocalRollbackBelowPool(t *testing.T) {
	const serialM = 0x22
	v := newEnv(t, fake.MemdevSpec{Serial: serialL, Ram: gib}, fake.MemdevSpec{Serial: serialB},
		fake.MemdevSpec{Serial: serialM, Ram: gib, HostBridge: 24})
	pooled := false
	v.configure(func(o *Options) {
		o.LocalGuard = func(_ context.Context, serial state.Serial) error {
			if serial == serialM && !pooled {
				pooled = true
				v.mustPrepare(poolDriver, "b", poolReq("b", 0, serialB, state.ModeDax, state.KindExclusive))
				v.f.FailCommand("cxl create-region", errors.New("cxl region: cmd_create_region: failed"))
			}
			return nil
		}
	})
	reqs := []GrantRequest{sliceReq("k", 0, state.ModeDax, 256*mib), localReq("k", 1, serialM, state.ModeDax, state.KindExclusive, 256*mib)}
	logs := captureKlog(t)
	if err := v.prepare(localDriver, "k", reqs...); err == nil {
		t.Fatal("the Prepare succeeded")
	}
	v.check("rolled back")
	wantLog(t, logs(), "local: memdev mem0 (serial 0x11): keeping region0 for claims [k], whose Prepare did not finish: region1 lie above it")
	wantRegion(t, v, "region0", state.RegionKept)
	wantStack(t, v, serialL, serialB)
	if g := v.grant("k", 0); g.State != state.GrantJournaled || g.Intent.Region != "region0" {
		t.Fatalf("grant %+v", g)
	}
	if g := v.records().Grant(state.GrantRef{Claim: "k", Result: 1}); g != nil {
		t.Fatalf("grant of the second part %+v", g)
	}
	wantPreparation(t, v, localDriver, "k", state.PreparationKept)
	v.mustUnprepare(poolDriver, "b")
	wantStack(t, v, serialL)
	v.mustPrepare(localDriver, "k", reqs...)
	if g := v.grant("k", 0); g.Got.Region != "region0" {
		t.Fatalf("grant %+v", g.Got)
	}
	v.mustUnprepare(localDriver, "k")
	wantStack(t, v)
	v.clean("unprepared")
}

// Cut Prepares of a local sliced memdev and a pool memdev of one stack are
// released at the start top-most first, whichever is above: no hole is
// left.
func TestStackLocalRecoveryTopMostFirst(t *testing.T) {
	for _, c := range []struct {
		name  string
		order []string
		want  []state.GrantRef
	}{
		{"local below", []string{"l", "b"}, []state.GrantRef{{Claim: "b"}, {Claim: "l"}}},
		{"local above", []string{"b", "l"}, []state.GrantRef{{Claim: "l"}, {Claim: "b"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := newEnv(t, stackSpecs...)
			reqs := map[string]GrantRequest{
				"l": sliceReq("l", 0, state.ModeNUMA, 256*mib),
				"b": poolReq("b", 0, serialB, state.ModeDax, state.KindExclusive),
			}
			drivers := map[string]string{"l": localDriver, "b": poolDriver}
			for _, uid := range c.order {
				if err := v.st.Commit(context.Background(), 0, func(doc *storeDocument) error {
					doc.Preparations = append(doc.Preparations, state.Preparation{UID: uid, Driver: drivers[uid], BootID: v.f.BootID(),
						State: state.PreparationPreparing, Results: []state.Result{grantResult(uid, 0)}})
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if _, err := v.e.PrepareGrants(context.Background(), []GrantRequest{reqs[uid]}); err != nil {
					t.Fatal(err)
				}
			}
			out := v.restart()
			if !slices.Equal(out.Released, c.want) || len(out.Kept) > 0 {
				t.Fatalf("recovered %+v", out)
			}
			wantStack(t, v)
			cmds := v.f.Commands()
			if top, below := strings.Index(cmds, "cxl destroy-region region1"), strings.Index(cmds, "cxl destroy-region region0"); top < 0 || below < top {
				t.Fatalf("not released top-most first:\n%s", cmds)
			}
			finish(t, v, "recovered")
		})
	}
}
