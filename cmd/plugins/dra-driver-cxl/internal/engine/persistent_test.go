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
	"bytes"
	"errors"
	"flag"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/compat"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// pmemEnv returns a node with the persistent pool memdev serialP whose
// fsdax namespace has a filesystem of the type.
func pmemEnv(t *testing.T, typ string) *env {
	t.Helper()
	v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
	v.formatPmem("mem0", typ)
	return v
}

// fsGrant returns the request of a pool grant of mode fs on serialP.
func fsGrant(uid string, readOnly bool, access state.Access) GrantRequest {
	return fsReq(poolReq(uid, 0, serialP, state.ModeFs, state.KindPersistent), readOnly, access)
}

// A writable block grant creates the fsdax namespace of the device, the
// block device read-write; its release destroys the region and disables
// the memdev, leaving the namespace in the labels.
func TestPersistentBlockWriter(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
	v.mustPrepare(poolDriver, "b1", poolReq("b1", 0, serialP, state.ModeBlock, state.KindPersistent))
	g := v.grant("b1", 0)
	if g.Got.BlockDevice == nil || g.Got.Namespace == "" || g.Intent.NdRegion == "" || v.f.IsReadOnly(g.Got.BlockDevice.Name) {
		t.Fatalf("grant %+v", g)
	}
	// a reader next to the block writer is refused
	err := v.prepare(poolDriver, "b2", fsGrant("b2", true, ""))
	if err == nil || !strings.Contains(err.Error(), "mode block read-write needs the device alone on this node") {
		t.Fatalf("error %v", err)
	}
	v.mustUnprepare(poolDriver, "b1")
	v.clean("unprepared")
	if !v.f.Labels(serialP) {
		t.Fatal("the labels went with the region")
	}
}

// A reader of a device that no writer formatted is refused: no fsdax
// namespace.
func TestPersistentReaderNeedsNamespace(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
	err := v.prepare(poolDriver, "r1", fsGrant("r1", true, ""))
	if err == nil || !strings.Contains(err.Error(), compat.OracleRefusedNoNS) {
		t.Fatalf("error %v", err)
	}
	v.check("refused")
	v.clean("refused")
}

// ext4 read-write: the writer mounts it rw with DAX, a reader joins the
// mount, the writer's release makes it read-only, the reader's unmounts it.
func TestPersistentFsReadWrite(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.mustPrepare(poolDriver, "w", fsGrant("w", false, ""))
	g := v.grant("w", 0)
	direct := filepath.Join(v.dir, poolDriver, "mounts", "91-direct")
	m := v.records().Region(g.Got.Region).Mount(state.AccessDirect)
	if m == nil || m.Path != direct || g.Got.Mount != state.AccessDirect || m.FsType != "ext4" || g.Intent.MountPath != direct {
		t.Fatalf("grant %+v, mount %+v", g.Got, m)
	}
	if m == nil || m.State != state.MountedRW || !m.Writer {
		t.Fatalf("mount %+v", m)
	}
	v.mustPrepare(poolDriver, "r", fsGrant("r", true, ""))
	if m := v.records().Region(g.Got.Region).Mount(state.AccessDirect); len(m.Users) != 2 || m.State != state.MountedRW {
		t.Fatalf("mount %+v", m)
	}
	v.mustUnprepare(poolDriver, "w")
	if m := v.records().Region(g.Got.Region).Mount(state.AccessDirect); m.State != state.MountedRO || m.Writer {
		t.Fatalf("mount after the writer %+v", m)
	}
	if !v.f.IsReadOnly(g.Got.BlockDevice.Name) {
		t.Fatal("block device writable without a writer")
	}
	v.mustUnprepare(poolDriver, "r")
	v.clean("unprepared")
	if len(v.f.Violations()) > 0 {
		t.Fatalf("violations %v", v.f.Violations())
	}
}

// erofs read-only with access cached: a read-only loop device over the
// block device, dax=never.
func TestPersistentFsReadOnly(t *testing.T) {
	v := pmemEnv(t, "erofs")
	v.mustPrepare(poolDriver, "r", fsGrant("r", true, state.AccessCached))
	g, m := v.grant("r", 0), v.mount("r", 0)
	if g.Got.Mount != state.AccessCached || m.Loop == "" || m.FsType != "erofs" {
		t.Fatalf("grant %+v, mount %+v", g.Got, m)
	}
	err := v.prepare(poolDriver, "w", fsGrant("w", false, state.AccessCached))
	want := "erofs is a read-only filesystem: set readOnly: true"
	if err == nil || !strings.HasSuffix(err.Error(), want) {
		t.Fatalf("error %v", err)
	}
	v.mustUnprepare(poolDriver, "r")
	v.clean("unprepared")
}

// A read-write claim with access cached of a device that a reader mounts
// with access direct only is refused with the text of the e2e tests, and
// the refusal mounts and changes nothing.
func TestPersistentP9D(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.mustPrepare(poolDriver, "r", fsGrant("r", true, state.AccessDirect))
	n := mountCalls(v)
	err := v.prepare(poolDriver, "w", fsGrant("w", false, state.AccessCached))
	want := strings.ReplaceAll(compat.EventDeviceFSSerialItIsMountedWithAccessDirect, "$FS_SERIAL", api.FormatSerial(serialP))
	if err == nil || err.Error() != want {
		t.Fatalf("error %v, want %q", err, want)
	}
	// the refusal mounts and changes nothing: the reader's read-only node
	// mount stays the only one, on the read-only block device
	wantMountCalls(t, v, n)
	direct := v.mount("r", 0).Path
	if mounts := v.f.MountTable(); len(mounts) != 1 || mounts[0].Target != direct || !mounts[0].SuperReadOnly() {
		t.Fatalf("mounts %+v", mounts)
	}
	if !v.f.IsReadOnly(filepath.Join(v.f.DevRoot(), "pmem0")) {
		t.Fatal("block device writable after the refusal")
	}
	v.mustUnprepare(poolDriver, "r")
}

// sources are the sources of the grants of the engine.
var sources = []state.Source{state.SourcePool, state.SourceLocal}

// driverOf returns the driver of the claims of a source.
func driverOf(source state.Source) string {
	if source == state.SourceLocal {
		return localDriver
	}
	return poolDriver
}

// fsUse returns the request of a grant of mode fs of the claim uid on the
// persistent memdev serialP of the source.
func fsUse(source state.Source, uid string, readOnly bool, access state.Access) GrantRequest {
	if source == state.SourceLocal {
		return localPmemReq(uid, 0, state.ModeFs, readOnly, access)
	}
	return fsGrant(uid, readOnly, access)
}

// mountCalls returns the number of system calls of the mount table of the
// node so far.
func mountCalls(v *env) int {
	return len(v.f.MountCalls(""))
}

// mountCallsSince returns the system calls of the mount table of the node
// after the first n.
func mountCallsSince(v *env, n int) []string {
	return slices.Clone(v.f.MountCalls("")[n:])
}

// wantMountCalls fails the test unless the system calls of the mount table
// of the node after the first n are want.
func wantMountCalls(t *testing.T, v *env, n int, want ...string) {
	t.Helper()
	if got := mountCallsSince(v, n); !slices.Equal(got, want) {
		t.Fatalf("calls\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// A cached ext4 is on a writable loop device: the reader makes the block
// device read-only, attaches the loop device read-write and makes it
// read-only before its mount; a writer makes the block device, then the
// loop device writable before the superblock; the release of the writer
// writes the data out before the superblock turns read-only, then the loop
// device, then the block device. A read-only type is on a read-only loop
// device.
func TestPersistentCachedOrder(t *testing.T) {
	for _, source := range sources {
		t.Run(string(source), func(t *testing.T) {
			driver := driverOf(source)
			v := pmemEnv(t, "ext4")
			cached := filepath.Join(v.dir, driver, "mounts", "91-cached")
			pmem, loop := filepath.Join(v.f.DevRoot(), "pmem0"), filepath.Join(v.f.DevRoot(), "loop0")
			n := mountCalls(v)
			v.mustPrepare(driver, "r", fsUse(source, "r", true, state.AccessCached))
			if m := v.mount("r", 0); m.Loop != loop || m.Path != cached {
				t.Fatalf("mount %+v", m)
			}
			wantMountCalls(t, v, n, "blkroset "+pmem+" 1", "loop "+loop+" "+pmem+" rw", "blkroset "+loop+" 1",
				"fsmount "+loop+" "+cached+" ext4 ro dax=never", "loop-release "+loop+" detach=false")
			n = mountCalls(v)
			v.mustPrepare(driver, "w", fsUse(source, "w", false, state.AccessCached))
			wantMountCalls(t, v, n, "blkroset "+pmem+" 0", "blkroset "+loop+" 0", "reconfigure "+cached+" rw")
			n = mountCalls(v)
			v.mustUnprepare(driver, "w")
			wantMountCalls(t, v, n, "syncfs "+cached, "reconfigure "+cached+" ro", "blkroset "+loop+" 1", "blkroset "+pmem+" 1")
			v.mustUnprepare(driver, "r")
			if mounts, loops := v.f.MountTable(), v.f.Kernel().LoopDevices(); len(mounts) != 0 || len(loops) != 0 {
				t.Fatalf("left: mounts %+v loops %+v", mounts, loops)
			}
			v.clean("unprepared")
			if len(v.f.Violations()) > 0 {
				t.Fatalf("violations %v", v.f.Violations())
			}
		})
	}
	t.Run("read-only type", func(t *testing.T) {
		v := pmemEnv(t, "erofs")
		pmem, loop := filepath.Join(v.f.DevRoot(), "pmem0"), filepath.Join(v.f.DevRoot(), "loop0")
		n := mountCalls(v)
		v.mustPrepare(poolDriver, "r", fsGrant("r", true, state.AccessCached))
		if got := v.f.MountCalls("loop "); !slices.Equal(got, []string{"loop " + loop + " " + pmem}) {
			t.Fatalf("loop devices %q of the calls %q", got, mountCallsSince(v, n))
		}
		v.mustUnprepare(poolDriver, "r")
		v.clean("unprepared")
	})
}

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

// The log lines of the node mounts and of the read-only flags of the block
// devices, each once and in order, with the driver's name first.
func TestPersistentLogLines(t *testing.T) {
	serial := strings.TrimPrefix(api.FormatSerial(serialP), "0x")
	prefix := poolDriver + ": device " + api.FormatSerial(serialP) + ": "
	doc := func(line string, placeholders ...string) string {
		return strings.NewReplacer(append([]string{"<serial>", serial}, placeholders...)...).Replace(line)
	}
	wantLines := func(t *testing.T, logs string, want ...string) {
		t.Helper()
		if got := linesWithPrefix(logs, prefix); !slices.Equal(got, want) {
			t.Fatalf("log lines\n  %s\nexpected\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
		}
	}
	t.Run("writer alone", func(t *testing.T) {
		v := pmemEnv(t, "ext4")
		logs := captureKlog(t)
		direct := filepath.Join(v.dir, poolDriver, "mounts", "91-direct")
		v.mustPrepare(poolDriver, "w", fsGrant("w", false, ""))
		v.mustUnprepare(poolDriver, "w")
		pmem := v.f.DevRoot() + "/pmem0"
		mounted := doc(compat.DocCXLPoolNRIIoDevice0xSerialMounted,
			"<source>", pmem, "<mnt>", direct, "<type>", "ext4", "ro|rw", "rw", "<data>", "dax=always")
		e2e := strings.NewReplacer("$PMEM", pmem, "$MNT_DIRECT", direct).Replace(compat.LogMountedPmemAtMntDirectExt4RwDaxAlways)
		if !strings.HasSuffix(mounted, ": "+e2e) {
			t.Fatalf("line %q does not end with %q", mounted, e2e)
		}
		wantLines(t, logs(), mounted, doc(compat.DocCXLPoolNRIIoDevice0xSerialUnmounted, "<mnt>", direct))
	})
	t.Run("cached reader and writer", func(t *testing.T) {
		v := pmemEnv(t, "ext4")
		logs := captureKlog(t)
		cached := filepath.Join(v.dir, poolDriver, "mounts", "91-cached")
		pmem, loop := v.f.DevRoot()+"/pmem0", v.f.DevRoot()+"/loop0"
		pmemRO := doc(compat.DocCXLPoolNRIIoDevice0xSerialDevH3d032c, "/dev/pmemK", pmem)
		loopRW := doc(compat.DocCXLPoolNRIIoDevice0xSerialDevH11871f, "/dev/loopN", loop)
		v.mustPrepare(poolDriver, "r", fsGrant("r", true, state.AccessCached))
		v.mustPrepare(poolDriver, "w", fsGrant("w", false, state.AccessCached))
		v.mustUnprepare(poolDriver, "w")
		v.mustUnprepare(poolDriver, "r")
		wantLines(t, logs(),
			pmemRO,
			prefix+loop+" read-only",
			doc(compat.DocCXLPoolNRIIoDevice0xSerialMounted,
				"<source>", loop, "<mnt>", cached, "<type>", "ext4", "ro|rw", "ro", "<data>", "dax=never"),
			prefix+pmem+" read-write",
			loopRW,
			doc(compat.DocCXLPoolNRIIoDevice0xSerialRemountedH6128ac, "<mnt>", cached),
			doc(compat.DocCXLPoolNRIIoDevice0xSerialRemountedH548a27, "<mnt>", cached),
			prefix+loop+" read-only",
			pmemRO,
			doc(compat.DocCXLPoolNRIIoDevice0xSerialUnmounted, "<mnt>", cached))
	})
}

// linesWithPrefix returns the messages of the klog output that begin with
// prefix, in order, without the klog header.
func linesWithPrefix(logs, prefix string) []string {
	var lines []string
	for _, l := range strings.Split(logs, "\n") {
		if _, msg, ok := strings.Cut(l, "] "); ok && strings.HasPrefix(msg, prefix) {
			lines = append(lines, msg)
		}
	}
	return lines
}

// writerFunc is an io.Writer of a function.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// captureKlog returns the klog output from now on, at verbosity 3.
func captureKlog(t *testing.T) func() string {
	t.Helper()
	fs := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(fs)
	_ = fs.Set("logtostderr", "false")
	_ = fs.Set("alsologtostderr", "false")
	_ = fs.Set("v", "3")
	var mu sync.Mutex
	var buf bytes.Buffer
	klog.SetOutput(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}))
	t.Cleanup(func() {
		klog.Flush()
		_ = fs.Set("logtostderr", "true")
		_ = fs.Set("v", "0")
	})
	return func() string {
		klog.Flush()
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
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

// A use of a local persistent memdev whose release failed stays a use of
// the device until its release is done: the node mount of a reader whose
// unmount is busy, the read-write superblock of a writer whose downgrade is
// busy. The rules of one node refuse the Prepares of other claims next to
// it, which mount and change nothing; a reader of its node mount reuses it
// as it is.
func TestPersistentReleasingUses(t *testing.T) {
	refused := func(t *testing.T, v *env, req GrantRequest, want string) {
		t.Helper()
		n := mountCalls(v)
		if err := v.prepare(localDriver, req.Ref.Claim, req); err == nil || err.Error() != want {
			t.Errorf("claim %s: error %v, want %q", req.Ref.Claim, err, want)
		}
		if calls := mountCallsSince(v, n); len(calls) > 0 {
			t.Errorf("claim %s: calls %q of a refused Prepare", req.Ref.Claim, calls)
		}
	}
	t.Run("node mount of a reader", func(t *testing.T) {
		v := pmemEnv(t, "ext4")
		v.mustPrepare(localDriver, "r", localPmemReq("r", 0, state.ModeFs, true, state.AccessCached))
		cached := v.mount("r", 0).Path
		v.f.SetBusy(cached, true)
		if err := v.unprepare(localDriver, "r"); err == nil || !strings.Contains(err.Error(), "unmounting "+cached+": device or resource busy") {
			t.Fatalf("error %v", err)
		}
		refused(t, v, localPmemReq("w", 0, state.ModeFs, false, state.AccessDirect),
			"device 0x91: it is mounted with access cached only on this node: a read-write claim with access direct would mount it a second time")
		v.f.SetBusy(cached, false)
		finish(t, v, "finished")
		if viol := v.f.Violations(); len(viol) > 0 {
			t.Fatalf("violations %v", viol)
		}
	})
	t.Run("superblock of a writer", func(t *testing.T) {
		v := pmemEnv(t, "ext4")
		v.mustPrepare(localDriver, "w", localPmemReq("w", 0, state.ModeFs, false, ""))
		v.mustPrepare(localDriver, "r", localPmemReq("r", 0, state.ModeFs, true, ""))
		direct := v.mount("w", 0).Path
		v.f.SetWriting(direct, true)
		if err := v.unprepare(localDriver, "w"); err == nil || !strings.Contains(err.Error(), "remounting "+direct+" read-only: device or resource busy") {
			t.Fatalf("error %v", err)
		}
		other := strings.ReplaceAll(compat.EventDeviceFSSerialItIsMountedReadWriteWith, "$FS_SERIAL", api.FormatSerial(serialP))
		refused(t, v, localPmemReq("c", 0, state.ModeFs, true, state.AccessCached), other)
		refused(t, v, localPmemReq("w2", 0, state.ModeFs, false, state.AccessCached), other)
		// a reader of the node mount: as it is, read-write
		n := mountCalls(v)
		v.mustPrepare(localDriver, "r2", localPmemReq("r2", 0, state.ModeFs, true, state.AccessDirect))
		if calls := mountCallsSince(v, n); len(calls) > 0 {
			t.Errorf("calls %q of the reader", calls)
		}
		if mi, _ := v.f.Kernel().Mounted(direct); mi == nil || mi.SuperReadOnly() {
			t.Errorf("node mount %+v", mi)
		}
		v.f.SetWriting(direct, false)
		finish(t, v, "finished")
		if viol := v.f.Violations(); len(viol) > 0 {
			t.Fatalf("violations %v", viol)
		}
	})
}

// A claim of mode fs of another boot (PREPARED_STALE) has nothing mounted:
// the one-node rules do not count it, a new reader next to a stale writer
// and a new writer next to a stale reader are prepared.
func TestPersistentStaleClaimIsNoUse(t *testing.T) {
	for _, c := range []struct {
		name         string
		stale, newer bool
		want         state.MountState
	}{
		{"stale writer, new reader", false, true, state.MountedRO},
		{"stale reader, new writer", true, false, state.MountedRW},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
			v.formatPmem("mem0", "ext4")
			v.mustPrepare(localDriver, "old", localPmemReq("old", 0, state.ModeFs, c.stale, ""))
			v.f.Reboot()
			v.restart()
			wantPreparation(t, v, localDriver, "old", state.PreparationStale)
			v.mustPrepare(localDriver, "new", localPmemReq("new", 0, state.ModeFs, c.newer, ""))
			if m := v.mount("new", 0); m.State != c.want {
				t.Fatalf("node mount %+v, want %s", m, c.want)
			}
			v.mustUnprepare(localDriver, "old")
			v.mustUnprepare(localDriver, "new")
			v.clean("unprepared")
		})
	}
}

// A writer whose Unprepare failed after its node mount was unmounted has
// nothing mounted: the one-node rules do not count it, a reader is
// prepared next to it; the retry of the Unprepare leaves the reader's
// mount.
func TestPersistentFailedReleaseWithoutMountIsNoUse(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
	v.formatPmem("mem0", "ext4")
	v.mustPrepare(localDriver, "w", localPmemReq("w", 0, state.ModeFs, false, ""))
	v.f.FailCommand("cxl disable-region", errors.New("cxl region: cmd_disable_region: failed"))
	if err := v.unprepare(localDriver, "w"); err == nil {
		t.Fatal("the release succeeded")
	}
	v.check("release failed")
	v.mustPrepare(localDriver, "r", localPmemReq("r", 0, state.ModeFs, true, ""))
	if m := v.mount("r", 0); m.State != state.MountedRO {
		t.Fatalf("node mount %+v", m)
	}
	v.mustUnprepare(localDriver, "w")
	if m := v.mount("r", 0); m.State != state.MountedRO {
		t.Fatalf("node mount after the retry %+v", m)
	}
	v.mustUnprepare(localDriver, "r")
	v.clean("unprepared")
}

// A claim of mode fs whose Unprepare a process stop cut after its region
// was destroyed keeps the block device of that region in its record; the
// writer of a new region next to a reader goes, and the block device, which
// may have the same name now, is read-only again: the records of the uses
// say what it is, not that claim's.
func TestPersistentReleaseIgnoresGoneBlockDevice(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
	v.formatPmem("mem0", "ext4")
	v.mustPrepare(localDriver, "a", localPmemReq("a", 0, state.ModeFs, true, ""))
	v.f.CutAfter("cxl destroy-region")
	if !v.cut(func() { _ = v.unprepare(localDriver, "a") }) {
		t.Fatal("not cut")
	}
	v.restart()
	v.mustPrepare(localDriver, "r", localPmemReq("r", 0, state.ModeFs, true, ""))
	v.mustPrepare(localDriver, "w", localPmemReq("w", 0, state.ModeFs, false, ""))
	v.mustUnprepare(localDriver, "w")
	if g := v.grant("r", 0); !v.f.IsReadOnly(g.Got.BlockDevice.Name) {
		t.Fatalf("%s is read-write without a writer", g.Got.BlockDevice.Name)
	}
	v.mustUnprepare(localDriver, "r")
	v.mustUnprepare(localDriver, "a")
	v.clean("unprepared")
}
