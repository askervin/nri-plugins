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
	"strings"
	"testing"
	"time"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// serialQ is a second memdev of persistent memory.
const serialQ = 0x92

// twoPmemEnv returns a node with the memdevs of persistent memory serialP
// (mem0) and serialQ (mem1), each with an ext4 filesystem.
func twoPmemEnv(t *testing.T) *env {
	t.Helper()
	v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib}, fake.MemdevSpec{Serial: serialQ, Pmem: gib})
	v.formatPmem("mem0", "ext4")
	v.formatPmem("mem1", "ext4")
	return v
}

// qGrant returns the request of a reader of mode fs on serialQ.
func qGrant(uid string, n int) GrantRequest {
	return fsReq(poolReq(uid, n, serialQ, state.ModeFs, state.KindPersistent), true, "")
}

// busyCompanion prepares the companion claim c with a lease bind on serialP
// whose Unprepare fails on the busy bind, which is free again afterwards.
func busyCompanion(t *testing.T, v *env) string {
	t.Helper()
	target := filepath.Join(v.dir, localDriver, "lease-fs", "lc1", "data")
	v.mustPrepare(poolDriver, "c", bindReq("c", target))
	v.f.SetBusy(target, true)
	if err := v.unprepare(poolDriver, "c"); err == nil {
		t.Fatal("a busy unbind succeeded")
	}
	v.f.SetBusy(target, false)
	return target
}

// The holder waits of one release call end at one deadline: two held
// memdevs fail together within about one holder wait.
func TestReleaseOneHolderDeadline(t *testing.T) {
	v := twoPmemEnv(t)
	v.mustPrepare(poolDriver, "c", fsGrant("c", true, ""), qGrant("c", 1))
	devs := []string{v.grant("c", 0).Got.BlockDevice.Name, v.grant("c", 1).Got.BlockDevice.Name}
	for _, dev := range devs {
		v.f.SetHolder(dev, "someone")
	}
	holder := v.e.opts.Timeouts.Holder
	start := time.Now()
	err := v.unprepare(poolDriver, "c")
	took := time.Since(start)
	if err == nil || strings.Count(err.Error(), "is still in use") != 2 {
		t.Fatalf("error %v", err)
	}
	if took > holder*3/2 {
		t.Fatalf("the release took %v, the holder wait is %v", took, holder)
	}
	for _, dev := range devs {
		v.f.SetHolder(dev, "")
	}
	v.mustUnprepare(poolDriver, "c")
	v.clean("unprepared")
}

// The holder deadline of a release starts after the stale lease binds were
// retried: a release after them that waited for a holder of another memdev
// leaves the call its own holder wait.
func TestReleaseStaleRetryKeepsTheDeadline(t *testing.T) {
	v := twoPmemEnv(t)
	busyCompanion(t, v)
	devP := v.grant("c", 0).Got.BlockDevice.Name
	v.f.SetHolder(devP, "someone")
	v.mustPrepare(poolDriver, "r", qGrant("r", 0))
	devQ := v.grant("r", 0).Got.BlockDevice.Name
	v.f.SetHolder(devQ, "briefly")
	holder := v.e.opts.Timeouts.Holder
	time.AfterFunc(holder*3/2, func() { v.f.SetHolder(devQ, "") })
	if err := v.unprepare(poolDriver, "r"); err != nil {
		t.Fatalf("unprepare r: %v", err)
	}
	v.f.SetHolder(devP, "")
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

// bindReq returns the request of a reader of mode fs on serialP of a
// companion claim whose lease bind is at target.
func bindReq(uid, target string) GrantRequest {
	req := fsGrant(uid, true, "")
	req.BindTarget = target
	req.Lend = &state.GrantLend{Lease: "0123abcd", Name: "data"}
	return req
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

// A busy lease bind at the start is recorded as stale with the memdev of
// the node mount it binds, unmounted at the next release.
func TestRecoverBusyBindIsStale(t *testing.T) {
	v := pmemEnv(t, "ext4")
	target := filepath.Join(v.dir, localDriver, "lease-fs", "lc1", "data")
	v.mustPrepare(poolDriver, "c", bindReq("c", target))
	v.mustPrepare(poolDriver, "r", fsGrant("r", true, ""))
	// the companion's records are gone (its Unprepare cut after its
	// bind's record): the bind is not listed
	if err := v.e.commit(context.Background(), func(r *state.Records) error {
		r.Grant(state.GrantRef{Claim: "c"}).Got.Bind = nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	v.f.SetBusy(target, true)
	v.restart()
	if m := v.records().Memdev(serialP); len(m.Stale) != 1 || m.Stale[0].Path != target {
		t.Fatalf("memdev %+v", m)
	}
	v.f.SetBusy(target, false)
	v.mustUnprepare(poolDriver, "r")
	if mi, _ := v.f.Kernel().Mounted(target); mi != nil {
		t.Fatalf("the stale bind is mounted: %+v", mi)
	}
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
		r.Preparations = append(r.Preparations, state.Preparation{UID: "d", Driver: poolDriver, BootID: v.f.BootID(),
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

// The writer and the reader of one claim on one memdev are released
// together: the node mount is unmounted without a remount read-only first.
// The release of a claim next to another one's says so.
func TestReleaseOneCallTogether(t *testing.T) {
	v := pmemEnv(t, "ext4")
	w := fsGrant("c", false, "")
	r := fsGrant("c", true, "")
	r.Ref.Result = 1
	v.mustPrepare(poolDriver, "c", w, r)
	logs := captureKlog(t)
	v.mustUnprepare(poolDriver, "c")
	if out := logs(); strings.Contains(out, "remounted") || strings.Contains(out, "read-only flag") {
		t.Fatalf("the claim's own reader kept the node mount:\n%s", out)
	}
	v.clean("unprepared")
	v.mustPrepare(poolDriver, "r1", fsGrant("r1", true, ""))
	v.mustPrepare(poolDriver, "r2", fsGrant("r2", true, ""))
	logs = captureKlog(t)
	v.mustUnprepare(poolDriver, "r1")
	if out := logs(); !strings.Contains(out, "serial 0x91 is still used by another claim") {
		t.Fatalf("no line of the other claim in\n%s", out)
	}
	v.mustUnprepare(poolDriver, "r2")
	v.clean("unprepared")
}

// busyCompanionNextToReader prepares the fs claim r and the fs lease
// companion c on the node mount of serialP, then fails the Unprepare of c
// on its busy lease bind. It returns the node mount and the bind.
func busyCompanionNextToReader(t *testing.T, v *env) (string, string) {
	t.Helper()
	target := companionTarget(v)
	v.mustPrepare(poolDriver, "r", fsGrant("r", true, ""))
	v.mustPrepare(poolDriver, "c", bindReq("c", target))
	mnt := mountPathOf(v.records(), v.grant("c", 0))
	if mnt == "" || mnt != mountPathOf(v.records(), v.grant("r", 0)) {
		t.Fatalf("node mounts %q and %q, want one", mnt, mountPathOf(v.records(), v.grant("r", 0)))
	}
	v.f.SetBusy(target, true)
	if err := v.unprepare(poolDriver, "c"); err == nil {
		t.Fatal("a busy unbind succeeded")
	}
	return mnt, target
}

// mustBeMounted fails the test when nothing is mounted at each path.
func (v *env) mustBeMounted(what string, paths ...string) {
	v.t.Helper()
	for _, p := range paths {
		if mi, err := v.f.Kernel().Mounted(p); err != nil || mi == nil {
			v.t.Fatalf("%s: %s is not mounted (%v)", what, p, err)
		}
	}
}

// mustNotBeMounted fails the test when something is mounted at a path.
func (v *env) mustNotBeMounted(what string, paths ...string) {
	v.t.Helper()
	for _, p := range paths {
		if mi, err := v.f.Kernel().Mounted(p); err != nil || mi != nil {
			v.t.Fatalf("%s: %s is mounted: %+v (%v)", what, p, mi, err)
		}
	}
}

// A companion whose Unprepare failed on its busy lease bind still uses its
// node mount: the Unprepare of another fs claim of the node mount keeps it;
// when the holder of the bind ended, the Unprepare again of the companion
// unbinds, unmounts and releases the memdev.
func TestReleaseKeepsNodeMountOfBusyCompanion(t *testing.T) {
	v := pmemEnv(t, "erofs")
	mnt, target := busyCompanionNextToReader(t, v)
	v.mustUnprepare(poolDriver, "r")
	v.mustBeMounted("after the Unprepare of r", mnt, target)
	v.f.SetBusy(target, false)
	v.mustUnprepare(poolDriver, "c")
	v.mustNotBeMounted("after the Unprepare again of c", mnt, target)
	v.clean("unprepared")
}
