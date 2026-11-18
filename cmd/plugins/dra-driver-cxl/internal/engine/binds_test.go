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
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// The lease bind of a companion grant of mode fs: bound at its target after
// the node mount, unbound at its release.
func TestPersistentBind(t *testing.T) {
	v := pmemEnv(t, "ext4")
	req := fsGrant("c", true, "")
	req.BindTarget = filepath.Join(v.dir, localDriver, "lease-fs", "lc1", "data")
	req.Lend = &state.GrantLend{Lease: "0123abcd", Name: "data"}
	v.mustPrepare(poolDriver, "c", req)
	g := v.grant("c", 0)
	if g.Got.Bind == nil || g.Got.Bind.State != state.BindBound || g.Got.Lend == nil {
		t.Fatalf("grant %+v", g.Got)
	}
	if !slices.ContainsFunc(v.f.MountTable(), func(m mountInfo) bool { return m.Target == req.BindTarget }) {
		t.Fatalf("not bound: %+v", v.f.MountTable())
	}
	v.mustUnprepare(poolDriver, "c")
	v.clean("unprepared")
}

// A lease bind that is busy at its release (a file of it mapped): the bind
// is STALE, the release fails; a later release unbinds it.
func TestPersistentBindBusy(t *testing.T) {
	v := pmemEnv(t, "ext4")
	req := fsGrant("c", true, "")
	req.BindTarget = filepath.Join(v.dir, localDriver, "lease-fs", "lc1", "data")
	req.Lend = &state.GrantLend{Lease: "0123abcd", Name: "data"}
	v.mustPrepare(poolDriver, "c", req)
	v.f.SetBusy(req.BindTarget, true)
	err := v.unprepare(poolDriver, "c")
	if err == nil || !strings.Contains(err.Error(), "lease 0123abcd: unmounting") {
		t.Fatalf("error %v", err)
	}
	if b := v.grant("c", 0).Got.Bind; b.State != state.BindStale {
		t.Fatalf("bind %+v", b)
	}
	if m := v.records().Memdev(serialP); len(m.Stale) != 1 {
		t.Fatalf("stale %+v", m.Stale)
	}
	v.f.SetBusy(req.BindTarget, false)
	v.mustUnprepare(poolDriver, "c")
	v.clean("unprepared")
}

// The retry of the stale lease binds of a memdev whose queue another
// request holds is left to a later release: the release of a grant of
// another memdev does not wait for it.
func TestReleaseStaleRetrySkipsBusyQueue(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.f.Plug(fake.MemdevSpec{Serial: serialA})
	target := busyCompanion(t, v)
	v.mustPrepare(poolDriver, "a", poolReq("a", 0, serialA, state.ModeDax, state.KindExclusive))
	leave, err := v.e.acquire(context.Background(), serialP)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = v.e.ReleaseGrants(ctx, []state.GrantRef{{Claim: "a"}}, ReleaseUnprepare)
	leave()
	if err != nil || ctx.Err() != nil {
		t.Fatalf("release of a: %v (%v)", err, ctx.Err())
	}
	if mi, _ := v.f.Kernel().Mounted(target); mi == nil {
		t.Fatal("the stale bind of the held memdev was unmounted")
	}
	v.mustUnprepare(poolDriver, "a")
	v.mustUnprepare(poolDriver, "c")
	v.clean("unprepared")
}

// A stale lease bind is unmounted again by the release of a grant of
// another memdev; then the grant that it left RELEASING is released, and
// with it the memdev.
func TestReleaseRetriesStaleBindsOfEveryMemdev(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.f.Plug(fake.MemdevSpec{Serial: serialA})
	target := busyCompanion(t, v)
	logs := captureKlog(t)
	v.mustPrepare(poolDriver, "a", poolReq("a", 0, serialA, state.ModeDax, state.KindExclusive))
	v.mustUnprepare(poolDriver, "a")
	out := logs()
	for _, want := range []string{"unbound stale lease bind " + target, "released mem0 (serial 0x91)"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if g := v.records().Grant(state.GrantRef{Claim: "c"}); g != nil {
		t.Fatalf("grant %+v", g)
	}
	v.mustUnprepare(poolDriver, "c")
	v.clean("released after the stale bind")
}

// The periodic pass unmounts a stale lease bind once its holder is gone,
// without a release, and releases the grant it left RELEASING and the
// memdev; a bind still busy stays for the next pass.
func TestRetryStalePeriodic(t *testing.T) {
	v := pmemEnv(t, "ext4")
	target := busyCompanion(t, v)
	v.f.SetBusy(target, true)
	v.e.RetryStale(context.Background(), state.TriggerUnprepare)
	v.mustBeMounted("a busy stale bind after the pass", target)
	if m := v.records().Memdev(serialP); m == nil || len(m.Stale) != 1 {
		t.Fatalf("memdev %+v", m)
	}
	v.f.SetBusy(target, false)
	logs := captureKlog(t)
	v.e.RetryStale(context.Background(), state.TriggerUnprepare)
	v.mustNotBeMounted("after the pass", target)
	if out := logs(); !strings.Contains(out, "released mem0 (serial 0x91)") {
		t.Errorf("the memdev is not released:\n%s", out)
	}
	if m := v.records().Memdev(serialP); m != nil {
		t.Fatalf("memdev record %+v", m)
	}
	v.mustUnprepare(poolDriver, "c")
	v.clean("released by the periodic pass")
}

// The lease bind of a grant that another prepared grant lists too is not
// unmounted by its release.
func TestReleaseBindOfAnotherClaim(t *testing.T) {
	v := pmemEnv(t, "ext4")
	target := filepath.Join(v.dir, localDriver, "lease-fs", "lc1", "data")
	v.mustPrepare(poolDriver, "c", bindReq("c", target))
	if err := v.e.commit(context.Background(), func(r *state.Records) error {
		g := r.Grant(state.GrantRef{Claim: "c"}).Clone()
		g.Ref = state.GrantRef{Claim: "d"}
		r.Grants = append(r.Grants, g)
		r.Memdev(serialP).Grants = append(r.Memdev(serialP).Grants, g.Ref)
		reg := r.Region(g.Got.Region)
		m := reg.Mount(g.Got.Mount)
		m.Users = append(m.Users, g.Ref)
		r.Preparations = append(r.Preparations, state.Preparation{UID: "d", Driver: poolDriver,
			State: state.PreparationPrepared, Results: []state.Result{grantResult("d", 0)}})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	logs := captureKlog(t)
	v.mustUnprepare(poolDriver, "c")
	if out := logs(); !strings.Contains(out, "is the bind of another prepared claim, not unmounting it") {
		t.Fatalf("no skip line in\n%s", out)
	}
	if mi, _ := v.f.Kernel().Mounted(target); mi == nil {
		t.Fatal("the bind of the other claim is gone")
	}
}
