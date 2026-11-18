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
	"errors"
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

// bindReq returns the request of a reader of mode fs on serialP of a
// companion claim whose lease bind is at target.
func bindReq(uid, target string) GrantRequest {
	req := fsGrant(uid, true, "")
	req.BindTarget = target
	req.Lend = &state.GrantLend{Lease: "0123abcd", Name: "data"}
	return req
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

// The release of a persistent grant whose region a failed release left
// disabled waits for no holder of its recorded block device when that name
// is another memdev's block device now: the mount of the other memdev does
// not fail it.
func TestReleaseRecordedBlockDeviceOfAnother(t *testing.T) {
	v := twoPmemEnv(t)
	v.mustPrepare(poolDriver, "q", qGrant("q", 0))
	recorded := *v.grant("q", 0).Got.BlockDevice
	v.f.FailCommand("cxl destroy-region", errors.New("cxl region: cmd_destroy_region: failed"))
	if err := v.unprepare(poolDriver, "q"); err == nil {
		t.Fatal("the release succeeded")
	}
	v.check("release failed")
	v.mustPrepare(localDriver, "p", localPmemReq("p", 0, state.ModeFs, false, ""))
	if bd := v.grant("p", 0).Got.BlockDevice; bd.Name != recorded.Name || bd.Dev == recorded.Dev {
		t.Fatalf("block device of p %+v, of q %+v: not the same name with other numbers", bd, recorded)
	}
	v.mustUnprepare(poolDriver, "q")
	v.mustUnprepare(localDriver, "p")
	v.clean("unprepared")
}
