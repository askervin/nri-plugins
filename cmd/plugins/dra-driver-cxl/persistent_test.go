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

	"golang.org/x/sys/unix"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
)

const pmemSerial = 0xc1ae0001

// pnEnv is a persistentNode on a fake mounter with the uses that it
// prepared, as a driver keeps them.
type pnEnv struct {
	t    *testing.T
	m    *fakeMounter
	n    *persistentNode
	dir  string
	uses []persistentUse
}

func newPnEnv(t *testing.T, image ...string) *pnEnv {
	dir := t.TempDir()
	m := newFakeMounter()
	m.images["/dev/pmem0"] = fsImage(image...)
	fs := filepath.Join(dir, "filesystems")
	noErr(t, os.WriteFile(fs, []byte("nodev\tsysfs\nnodev\ttmpfs\n\text4\n\txfs\n"), 0o644))
	n := newPersistentNode(persistentConfig{Driver: "test", Mounter: m, MountsDir: filepath.Join(dir, "mounts"),
		LeaseFsRoot: filepath.Join(dir, "lease-fs"), Filesystems: fs, FsTypes: slices.Clone(config.KnownFsTypes)})
	return &pnEnv{t: t, m: m, n: n, dir: dir}
}

var singleHost = config.DeviceFacts{Persistent: true, Shared: true, SingleHost: true}

// prepare prepares a use of mode fs (or block for access "block") of the
// device and keeps it.
func (e *pnEnv) prepare(uid string, readOnly bool, access, fsType string, facts config.DeviceFacts) (persistentUse, error) {
	e.t.Helper()
	w := persistentWant{UID: uid, Mode: api.ModeFs, ReadOnly: readOnly, Access: access, FsType: fsType}
	if access == "block" {
		w.Mode, w.Access = api.ModeBlock, ""
	}
	u, err := e.n.Prepare(context.Background(), persistentTarget{Serial: pmemSerial, BlockDevice: "/dev/pmem0", Facts: facts}, w, e.uses)
	if err == nil {
		e.uses = append(e.uses, u)
	}
	e.m.wantNoViolations(e.t)
	return u, err
}

// release releases the uses of the claim uid.
func (e *pnEnv) release(uid string) error {
	e.t.Helper()
	var gone, remaining []persistentUse
	for _, u := range e.uses {
		if u.UID == uid {
			gone = append(gone, u)
		} else {
			remaining = append(remaining, u)
		}
	}
	err := e.n.Release(context.Background(), pmemSerial, gone, remaining)
	if err == nil {
		e.uses = remaining
	}
	e.m.wantNoViolations(e.t)
	return err
}

// callsSince returns the calls of the fake mounter after the first n but
// the reads of the superblocks.
func (e *pnEnv) callsSince(n int) []string {
	e.m.mu.Lock()
	defer e.m.mu.Unlock()
	return slices.DeleteFunc(slices.Clone(e.m.calls[n:]), func(c string) bool { return strings.HasPrefix(c, "superblocks ") })
}

func (e *pnEnv) ncalls() int {
	e.m.mu.Lock()
	defer e.m.mu.Unlock()
	return len(e.m.calls)
}

func (e *pnEnv) wantCalls(since int, want ...string) {
	e.t.Helper()
	if got := e.callsSince(since); !slices.Equal(got, want) {
		e.t.Fatalf("calls\n  %s\nexpected\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func (e *pnEnv) wantSuper(mnt, ro string) {
	e.t.Helper()
	mi, _ := e.m.Mounted(mnt)
	if mi == nil || len(mi.SuperOpts) == 0 || mi.SuperOpts[0] != ro {
		e.t.Fatalf("superblock of %s: %+v, expected %s", mnt, mi, ro)
	}
}

// TestPersistentWritersAndReaders: two writers and a reader of one ext4
// share one read-write superblock; the last writer downgrades it, a new
// writer upgrades it, the last use unmounts it.
func TestPersistentWritersAndReaders(t *testing.T) {
	e := newPnEnv(t, "ext4")
	direct := e.n.NodeMountPath(pmemSerial, api.AccessDirect)
	n := e.ncalls()
	a, err := e.prepare("a", false, "", "", singleHost)
	noErr(t, err)
	if a.Access != api.AccessDirect || a.FsType != "ext4" || a.NodeMount != direct || a.LoopDevice != "" || a.ReadOnly {
		t.Fatalf("use %+v", a)
	}
	e.wantCalls(n, "fsmount /dev/pmem0 "+direct+" ext4 rw dax=always")
	_, err = e.prepare("b", false, api.AccessDirect, "ext4", singleHost)
	noErr(t, err)
	_, err = e.prepare("c", true, "", "", singleHost)
	noErr(t, err)
	e.wantCalls(n, "fsmount /dev/pmem0 "+direct+" ext4 rw dax=always")
	e.wantSuper(direct, "rw")
	if e.m.isRO("/dev/pmem0") {
		t.Fatal("block device read-only under a writer")
	}

	n = e.ncalls()
	noErr(t, e.release("a"))
	e.wantCalls(n)
	noErr(t, e.release("b"))
	e.wantCalls(n, "syncfs "+direct, "reconfigure "+direct+" ro", "blkroset /dev/pmem0 1")
	e.wantSuper(direct, "ro")

	// a writer again upgrades in place
	n = e.ncalls()
	_, err = e.prepare("d", false, "", "", singleHost)
	noErr(t, err)
	e.wantCalls(n, "blkroset /dev/pmem0 0", "reconfigure "+direct+" rw")
	e.wantSuper(direct, "rw")
	noErr(t, e.release("c"))

	// a file open for writing fails the downgrade, the use stays
	_, err = e.prepare("r", true, "", "", singleHost)
	noErr(t, err)
	e.m.writing[direct] = true
	wantErr(t, e.release("d"), "device 0xc1ae0001: remounting "+direct+" read-only: device or resource busy")
	e.wantSuper(direct, "rw")
	if e.m.isRO("/dev/pmem0") {
		t.Fatal("block device read-only after a failed downgrade")
	}
	e.m.writing[direct] = false
	noErr(t, e.release("d"))
	n = e.ncalls()
	noErr(t, e.release("r"))
	e.wantCalls(n, "umount "+direct)
	if _, err := os.Stat(direct); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("node mount directory left: %v", err)
	}
}

// TestPersistentCachedOrder: a cached ext4 is on a writable loop device;
// the reader makes both block devices read-only before its mount, an
// upgrade makes the block device, then the loop device writable before the
// superblock (A8), a downgrade the reverse.
func TestPersistentCachedOrder(t *testing.T) {
	e := newPnEnv(t, "ext4")
	cached := e.n.NodeMountPath(pmemSerial, api.AccessCached)
	n := e.ncalls()
	r, err := e.prepare("r", true, api.AccessCached, "", singleHost)
	noErr(t, err)
	if r.LoopDevice != "/dev/loop0" {
		t.Fatalf("use %+v", r)
	}
	e.wantCalls(n, "blkroset /dev/pmem0 1", "loop /dev/loop0 /dev/pmem0 rw", "blkroset /dev/loop0 1",
		"fsmount /dev/loop0 "+cached+" ext4 ro dax=never", "loop-release /dev/loop0 detach=false")
	n = e.ncalls()
	_, err = e.prepare("w", false, api.AccessCached, "", singleHost)
	noErr(t, err)
	e.wantCalls(n, "blkroset /dev/pmem0 0", "blkroset /dev/loop0 0", "reconfigure "+cached+" rw")
	n = e.ncalls()
	noErr(t, e.release("w"))
	e.wantCalls(n, "syncfs "+cached, "reconfigure "+cached+" ro", "blkroset /dev/loop0 1", "blkroset /dev/pmem0 1")
	noErr(t, e.release("r"))
	if len(e.m.loops) != 0 || len(e.m.mounts) != 0 {
		t.Fatalf("loops %v mounts %v left", e.m.loops, e.m.mounts)
	}
}

// TestPersistentUpgradeFails: an upgrade that the filesystem refuses
// leaves both block devices read-only again.
func TestPersistentUpgradeFails(t *testing.T) {
	e := newPnEnv(t, "xfs")
	cached := e.n.NodeMountPath(pmemSerial, api.AccessCached)
	_, err := e.prepare("r", true, api.AccessCached, "", singleHost)
	noErr(t, err)
	if c := e.m.callsOf("fsmount"); !slices.Equal(c, []string{"fsmount /dev/loop0 " + cached + " xfs ro dax=never,nouuid"}) {
		t.Fatalf("mounts %q", c)
	}
	e.m.reconfErr[cached] = unix.EINVAL
	_, err = e.prepare("w", false, api.AccessCached, "", singleHost)
	wantErr(t, err, "device 0xc1ae0001: remounting "+cached+" read-write: invalid argument")
	if !e.m.isRO("/dev/pmem0") || !e.m.isRO("/dev/loop0") {
		t.Fatal("block devices writable after a failed upgrade")
	}
	e.wantSuper(cached, "ro")
	noErr(t, e.release("r"))
}

// TestPersistentRules: the texts of the checks before anything is mounted
// (contract 3 and 4) and of the mounts.
func TestPersistentRules(t *testing.T) {
	notSingle := config.DeviceFacts{Persistent: true, Shared: true}
	coherent := config.DeviceFacts{Persistent: true, Shared: true, Coherent: true}
	for _, tc := range []struct {
		name   string
		image  []string
		setup  func(e *pnEnv)
		ro     bool
		access string
		fsType string
		facts  config.DeviceFacts
		err    string
	}{
		{name: "P4", image: []string{"ext4"}, ro: true, facts: singleHost,
			setup: func(e *pnEnv) { e.n.cfg.FsTypes = []string{"erofs", "squashfs"} },
			err:   "device 0xc1ae0001: filesystem type ext4 is not allowed on this node (fsTypes: erofs, squashfs)"},
		{name: "P4 none", image: []string{"erofs"}, ro: true, facts: singleHost,
			setup: func(e *pnEnv) { e.n.cfg.FsTypes = []string{} },
			err:   "device 0xc1ae0001: filesystem type erofs is not allowed on this node (fsTypes: none)"},
		{name: "P4 default erofs only", image: []string{"ext4"}, ro: true, facts: singleHost,
			setup: func(e *pnEnv) {
				e.n = newPersistentNode(persistentConfig{Driver: "test", Mounter: e.m, MountsDir: e.n.cfg.MountsDir})
			},
			err: "device 0xc1ae0001: filesystem type ext4 is not allowed on this node (fsTypes: erofs)"},
		{name: "P5", ro: true, fsType: "tmpfs", facts: singleHost,
			setup: func(e *pnEnv) { e.n.cfg.FsTypes = append(e.n.cfg.FsTypes, "tmpfs") },
			err:   "device 0xc1ae0001: filesystem type tmpfs does not mount a block device"},
		{name: "P6", image: []string{"erofs"}, facts: singleHost,
			err: "device 0xc1ae0001: erofs is a read-only filesystem: set readOnly: true"},
		{name: "P7", image: []string{"btrfs"}, ro: true, access: api.AccessDirect, facts: singleHost,
			err: "device 0xc1ae0001: btrfs has no DAX: use access cached"},
		{name: "P8 single-host", image: []string{"ext4"}, facts: notSingle,
			err: "device 0xc1ae0001: read-write on several hosts needs a cluster filesystem on coherent memory: ext4 is a single-host filesystem"},
		{name: "P8 lock_nolock", image: []string{"gfs2-nolock"}, fsType: "gfs2", facts: coherent,
			err: "device 0xc1ae0001: read-write on several hosts needs a cluster filesystem on coherent memory: gfs2 with lock_nolock is a single-host filesystem"},
		{name: "P8 coherence", image: []string{"gfs2"}, fsType: "gfs2", facts: notSingle,
			err: "device 0xc1ae0001: read-write on several hosts needs a cluster filesystem on coherent memory: the device is not coherent between hosts"},
		{name: "P8 cluster", image: []string{"gfs2"}, fsType: "gfs2", facts: coherent},
		{name: "P9a", image: []string{"ext4"}, ro: true, access: api.AccessCached, facts: singleHost,
			setup: func(e *pnEnv) { _, err := e.prepare("w", false, api.AccessDirect, "", singleHost); noErr(e.t, err) },
			err:   "device 0xc1ae0001: it is mounted read-write with access direct on this node: access cached would mount it a second time"},
		{name: "P9b", image: []string{"ext4"}, access: api.AccessDirect, facts: singleHost,
			setup: func(e *pnEnv) {
				_, err := e.prepare("r1", true, api.AccessDirect, "", singleHost)
				noErr(e.t, err)
				_, err = e.prepare("r2", true, api.AccessCached, "", singleHost)
				noErr(e.t, err)
			},
			err: "device 0xc1ae0001: it is mounted with access direct and cached on this node: a read-write claim needs one access only"},
		{name: "P9d", image: []string{"ext4"}, access: api.AccessDirect, facts: singleHost,
			setup: func(e *pnEnv) { _, err := e.prepare("r", true, api.AccessCached, "", singleHost); noErr(e.t, err) },
			err:   "device 0xc1ae0001: it is mounted with access cached only on this node: a read-write claim with access direct would mount it a second time"},
		{name: "P9c block writer first", image: []string{"ext4"}, ro: true, facts: singleHost,
			setup: func(e *pnEnv) { _, err := e.prepare("b", false, "block", "", singleHost); noErr(e.t, err) },
			err:   "device 0xc1ae0001: mode block read-write needs the device alone on this node"},
		{name: "P9c block writer second", image: []string{"ext4"}, ro: false, access: "block", facts: singleHost,
			setup: func(e *pnEnv) { _, err := e.prepare("r", true, "", "", singleHost); noErr(e.t, err) },
			err:   "device 0xc1ae0001: mode block read-write needs the device alone on this node"},
		{name: "P9e", image: []string{"btrfs"}, facts: singleHost,
			setup: func(e *pnEnv) { _, err := e.prepare("r", true, "", "", singleHost); noErr(e.t, err) },
			err:   "device 0xc1ae0001: btrfs is mounted read-only on this node and cannot be remounted read-write: a read-write claim waits until the read-only claims of the node are gone"},
		{name: "P10 ext4", image: []string{"ext4-dirty"}, ro: true, facts: singleHost,
			err: "device 0xc1ae0001: ext4 on /dev/pmem0 needs recovery (it was not unmounted cleanly): a read-only mount cannot recover it, a read-write claim on one node does"},
		{name: "P10 EROFS", image: []string{"xfs"}, ro: true, facts: singleHost,
			setup: func(e *pnEnv) { e.m.dirty["/dev/pmem0"] = true },
			err:   "device 0xc1ae0001: xfs on /dev/pmem0 needs recovery (it was not unmounted cleanly)"},
		{name: "P10 a writer recovers", image: []string{"ext4-dirty"}, facts: singleHost},
		{name: "P11", image: []string{"ext4"}, ro: true, facts: singleHost,
			setup: func(e *pnEnv) {
				e.m.mountErr["/dev/pmem0"] = unix.EINVAL
				e.m.ctxMsgs["/dev/pmem0"] = "e ext4: unsupported blocksize for DAX"
			},
			err: "device 0xc1ae0001: /dev/pmem0 has no ext4 filesystem: invalid argument: e ext4: unsupported blocksize for DAX"},
		{name: "P12", image: []string{"ext4"}, ro: true, facts: singleHost,
			setup: func(e *pnEnv) { e.m.superOpts["/dev/pmem0"] = []string{"ro", "dax=never"} },
			err:   "device 0xc1ae0001: ext4 on /dev/pmem0 was mounted without DAX"},
		{name: "P1", ro: true, facts: singleHost,
			err: "device 0xc1ae0001: /dev/pmem0 has no filesystem of a type that the plugin knows (erofs, squashfs, ext4, xfs, btrfs or gfs2): set device.fsType"},
		{name: "P3 of a node mount", image: []string{"ext4"}, ro: true, fsType: "xfs", facts: singleHost,
			setup: func(e *pnEnv) { _, err := e.prepare("r", true, "", "", singleHost); noErr(e.t, err) },
			err:   "device 0xc1ae0001: /dev/pmem0 has a filesystem of type ext4, not xfs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPnEnv(t, tc.image...)
			if tc.setup != nil {
				tc.setup(e)
			}
			before := len(e.m.mounts)
			_, err := e.prepare("x", tc.ro, tc.access, tc.fsType, tc.facts)
			if tc.err == "" {
				noErr(t, err)
				return
			}
			wantErr(t, err, tc.err)
			if len(e.m.mounts) != before {
				t.Fatalf("mounts after a refusal: %+v", e.m.mounts)
			}
			for _, u := range slices.Clone(e.uses) {
				noErr(t, e.release(u.UID))
			}
			entries, _ := os.ReadDir(e.n.MountsDir())
			if len(e.m.mounts) != 0 || len(e.m.loops) != 0 || len(entries) != 0 {
				t.Fatalf("left: mounts %+v loops %v dirs %v", e.m.mounts, e.m.loops, entries)
			}
		})
	}
}

// TestPersistentDefaults: the default access by type, the mount data and
// the block uses.
func TestPersistentDefaults(t *testing.T) {
	for image, access := range map[string]string{"erofs": api.AccessDirect, "ext4": api.AccessDirect, "xfs": api.AccessDirect,
		"btrfs": api.AccessCached, "squashfs": api.AccessCached} {
		e := newPnEnv(t, image)
		u, err := e.prepare("r", true, "", "", singleHost)
		noErr(t, err)
		if u.Access != access || u.FsType != image {
			t.Errorf("%s: %+v", image, u)
		}
		// read-only types keep mount(2) with ro,nosuid,nodev
		if config.FsTypeReadOnly(image) && len(e.m.callsOf("mount ")) != 1 || !config.FsTypeReadOnly(image) && len(e.m.callsOf("fsmount ")) != 1 {
			t.Errorf("%s: calls %q", image, e.m.calls)
		}
		noErr(t, e.release("r"))
	}
	// both accesses of a read-only xfs: two superblocks with nouuid
	e := newPnEnv(t, "xfs")
	_, err := e.prepare("d", true, api.AccessDirect, "", singleHost)
	noErr(t, err)
	_, err = e.prepare("c", true, api.AccessCached, "", singleHost)
	noErr(t, err)
	if c := e.m.callsOf("fsmount"); len(c) != 2 || !strings.HasSuffix(c[0], "ro dax=always,nouuid") || !strings.HasSuffix(c[1], "ro dax=never,nouuid") {
		t.Fatalf("mounts %q", c)
	}
	noErr(t, e.release("d"))
	noErr(t, e.release("c"))

	// block uses: a reader makes the device read-only, a writer writable
	e = newPnEnv(t)
	_, err = e.prepare("r", true, "block", "", singleHost)
	noErr(t, err)
	if !e.m.isRO("/dev/pmem0") {
		t.Fatal("block reader on a writable device")
	}
	noErr(t, e.release("r"))
	_, err = e.prepare("w", false, "block", "", singleHost)
	noErr(t, err)
	if e.m.isRO("/dev/pmem0") {
		t.Fatal("block writer on a read-only device")
	}
}

// TestPersistentRestore: the start mounts what the uses derive and
// changes existing superblocks and block devices to it.
func TestPersistentRestore(t *testing.T) {
	ok := func(uint64, string) error { return nil }
	e := newPnEnv(t, "ext4")
	direct := e.n.NodeMountPath(pmemSerial, api.AccessDirect)
	w, err := e.prepare("w", false, "", "", singleHost)
	noErr(t, err)
	r, err := e.prepare("r", true, "", "", singleHost)
	noErr(t, err)

	// a missing mount of a writer is mounted read-write again
	e.m.mounts = nil
	e.m.ro["/dev/pmem0"] = true
	got := e.n.Restore([]persistentUse{w, r}, ok)
	if l, found := got[direct]; !found || l != "" {
		t.Fatalf("restored %v", got)
	}
	e.wantSuper(direct, "rw")
	e.m.wantNoViolations(t)

	// the writer is gone (its Prepare was cut): downgraded
	e.n.Restore([]persistentUse{r}, ok)
	e.wantSuper(direct, "ro")
	if !e.m.isRO("/dev/pmem0") {
		t.Fatal("block device writable without a writer")
	}
	// a writer again: upgraded
	e.n.Restore([]persistentUse{w, r}, ok)
	e.wantSuper(direct, "rw")
	if e.m.isRO("/dev/pmem0") {
		t.Fatal("block device read-only under a writer")
	}
	e.m.wantNoViolations(t)

	// a device that is not the one prepared is not mounted: unrestored
	e.m.mounts = nil
	stale := filepath.Join(e.n.MountsDir(), "c1ee0002-direct")
	noErr(t, os.MkdirAll(stale, 0o755))
	noErr(t, e.m.FsMount("/dev/pmem7", stale, "ext4", true, nil))
	bad := func(uint64, string) error { return errors.New("not the namespace") }
	got = e.n.Restore([]persistentUse{w, r}, bad)
	if len(got) != 0 {
		t.Fatalf("restored %v", got)
	}
	if why, found := e.n.Unrestored(direct); !found || !strings.Contains(why.Error(), "not mounting "+direct+" again: not the namespace") {
		t.Fatalf("unrestored %v %v", why, found)
	}
	if mi, _ := e.m.Mounted(stale); mi != nil {
		t.Fatal("the mount of no use was not swept")
	}
	if _, err := e.n.Remount(direct, []persistentUse{w, r}, bad); err == nil {
		t.Fatal("remounted a changed device")
	}
	loop, err := e.n.Remount(direct, []persistentUse{w, r}, ok)
	noErr(t, err)
	if _, found := e.n.Unrestored(direct); found || loop != "" {
		t.Fatalf("still unrestored, loop %q", loop)
	}
	e.wantSuper(direct, "rw")
	e.m.wantNoViolations(t)

	// a foreign mount at a node mount is neither used nor unmounted
	e2 := newPnEnv(t, "ext4")
	mnt := e2.n.NodeMountPath(pmemSerial, api.AccessDirect)
	noErr(t, os.MkdirAll(mnt, 0o755))
	noErr(t, e2.m.Mount("tmpfs", mnt, "tmpfs", 0, ""))
	u := persistentUse{UID: "r", Serial: pmemSerial, Mode: api.ModeFs, ReadOnly: true, Access: api.AccessDirect, FsType: "ext4", BlockDevice: "/dev/pmem0", NodeMount: mnt}
	res := e2.n.RestoreMounts([]persistentUse{u}, ok)
	wantErr(t, res[mnt].Err, "is a tmpfs mount of tmpfs, not of /dev/pmem0")
	if mi, _ := e2.m.Mounted(mnt); mi == nil || mi.FsType != "tmpfs" {
		t.Fatalf("foreign mount touched: %+v", mi)
	}
	if _, found := e2.n.Unrestored(mnt); found {
		t.Fatal("a mounted node mount is unrestored")
	}
}

// TestPersistentLeaseBinds: read-only binds of writable types are clones
// with the read-only attribute, read-write ones plain binds; both are
// checked, unbound, swept by their own driver and by the common sweep.
func TestPersistentLeaseBinds(t *testing.T) {
	e := newPnEnv(t, "ext4")
	w, err := e.prepare("w", false, "", "", singleHost)
	noErr(t, err)
	r := w
	r.UID, r.ReadOnly = "r", true
	fsDir := filepath.Join(e.n.cfg.LeaseFsRoot, "lc1")
	noErr(t, os.MkdirAll(fsDir, 0o755))

	ro := &lendRecord{Lease: "l1", FsDir: fsDir, Name: "ro"}
	n := e.ncalls()
	noErr(t, e.n.BindLease(ro, []persistentUse{r}, nil))
	e.wantCalls(n, "robind "+w.NodeMount+" "+filepath.Join(fsDir, "ro"))
	rw := &lendRecord{Lease: "l2", FsDir: fsDir, Name: "rw"}
	noErr(t, e.n.BindLease(rw, []persistentUse{w}, nil))
	if mi, _ := e.m.Mounted(filepath.Join(fsDir, "rw")); mi == nil || !slices.Equal(mi.MountFlags, []string{"rw", "nosuid", "nodev"}) {
		t.Fatalf("read-write bind %+v", mi)
	}
	if mi, _ := e.m.Mounted(filepath.Join(fsDir, "ro")); mi == nil || !slices.Equal(mi.MountFlags, []string{"ro", "nosuid", "nodev"}) {
		t.Fatalf("read-only bind %+v", mi)
	}
	// a bind without the flags is unmounted again
	e.m.bindFlags = []string{"ro", "relatime"}
	bad := &lendRecord{Lease: "l3", FsDir: fsDir, Name: "bad"}
	wantErr(t, e.n.BindLease(bad, []persistentUse{w}, nil),
		"device 0xc1ae0001: the bind of "+w.NodeMount+" at "+filepath.Join(fsDir, "bad")+" is not a read-write nosuid nodev ext4 mount")
	e.m.bindFlags = nil

	// the start of this driver keeps the wanted binds and sweeps a bind
	// of its node mount that no claim lists
	stale := filepath.Join(fsDir, "stale")
	noErr(t, os.MkdirAll(stale, 0o755))
	noErr(t, e.m.Mount(w.NodeMount, stale, "", unix.MS_BIND, ""))
	// a bind of another driver's node mount is left to that driver
	other := newPersistentNode(persistentConfig{Driver: "other", Mounter: e.m, MountsDir: filepath.Join(e.dir, "other-mounts"), LeaseFsRoot: e.n.cfg.LeaseFsRoot})
	omnt := other.NodeMountPath(0xc100f5e1, api.AccessDirect)
	noErr(t, os.MkdirAll(omnt, 0o755))
	noErr(t, e.m.FsMount("/dev/pmem5", omnt, "ext4", true, nil))
	obind := filepath.Join(e.n.cfg.LeaseFsRoot, "lc2", "local")
	noErr(t, os.MkdirAll(obind, 0o755))
	noErr(t, e.m.Mount(omnt, obind, "", unix.MS_BIND, ""))
	// an orphan: a bind whose node mount is gone
	orphanSrc := filepath.Join(e.dir, "gone")
	noErr(t, os.MkdirAll(orphanSrc, 0o755))
	noErr(t, e.m.FsMount("/dev/pmem6", orphanSrc, "ext4", true, nil))
	orphan := filepath.Join(e.n.cfg.LeaseFsRoot, "lc3", "x")
	noErr(t, os.MkdirAll(orphan, 0o755))
	noErr(t, e.m.Mount(orphanSrc, orphan, "", unix.MS_BIND, ""))
	noErr(t, e.m.Unmount(orphanSrc))

	want := e.n.RestoreLeaseBinds([]leaseBindClaim{{UID: "c1", Lend: ro, Uses: []persistentUse{r}}, {UID: "c2", Lend: rw, Fs: &w}})
	for target, mounted := range map[string]bool{stale: false, obind: true, orphan: true, filepath.Join(fsDir, "ro"): true, filepath.Join(fsDir, "rw"): true} {
		if mi, _ := e.m.Mounted(target); (mi != nil) != mounted {
			t.Errorf("%s mounted %v, expected %v", target, mi != nil, mounted)
		}
	}
	want[obind] = true // the other driver's
	sweepLeaseBinds(want, e.n, nil, other)
	if mi, _ := e.m.Mounted(orphan); mi != nil {
		t.Fatal("orphan bind not swept")
	}
	if mi, _ := e.m.Mounted(obind); mi == nil {
		t.Fatal("a wanted bind of another driver was swept")
	}

	// unbinding: a tmpfs over a bind is no lease bind
	noErr(t, e.m.Mount("tmpfs", filepath.Join(fsDir, "rw"), "tmpfs", 0, ""))
	wantErr(t, e.n.UnbindLease(rw, nil), "lease l2: "+filepath.Join(fsDir, "rw")+" is a tmpfs mount of tmpfs, not a lease bind")
	noErr(t, e.m.Unmount(filepath.Join(fsDir, "rw")))
	noErr(t, e.n.UnbindLease(rw, nil))
	// a busy bind becomes a stale bind, released when it goes
	e.m.setBusy(filepath.Join(fsDir, "ro"), true)
	if err := e.n.UnbindLease(ro, nil); err == nil {
		t.Fatal("busy bind unbound")
	}
	e.n.KeepStale(ro, &r)
	if rel := e.n.UnbindStale(nil); len(rel) != 0 || len(e.n.StaleBinds()) != 1 {
		t.Fatalf("released %v, stale %v", rel, e.n.StaleBinds())
	}
	e.m.setBusy(filepath.Join(fsDir, "ro"), false)
	if rel := e.n.UnbindStale(nil); !slices.Equal(rel, []staleBind{{Target: filepath.Join(fsDir, "ro"), Serial: pmemSerial, BlockDevice: "/dev/pmem0"}}) || len(e.n.StaleBinds()) != 0 {
		t.Fatalf("released %v, stale %v", rel, e.n.StaleBinds())
	}
	e.m.wantNoViolations(t)
}

func TestPersistentCDI(t *testing.T) {
	if m := fsCDIMount("/n", "/c", true); !slices.Equal(m.Options, []string{"bind", "ro", "nosuid", "nodev"}) || m.HostPath != "/n" || m.ContainerPath != "/c" || m.Type != "bind" {
		t.Errorf("read-only %+v", m)
	}
	if m := fsCDIMount("/n", "/c", false); !slices.Equal(m.Options, []string{"bind", "nosuid", "nodev"}) {
		t.Errorf("read-write %+v", m)
	}
	if d := blockDeviceNode("/dev/pmem0", 259, 1, true); *d != (cdiSpecs.DeviceNode{Path: "/dev/pmem0", Type: "b", Major: 259, Minor: 1, Permissions: "r"}) {
		t.Errorf("block %+v", d)
	}
}

// TestPersistentUnexplainedSuperblocks: a superblock of the device that no
// use explains (a node mount left without its use, a mount in another
// mount namespace) refuses a writer, an upgrade, a fresh mount of a
// writable type and a block writer; a read-write one also the read-only
// flag (review B1, S1).
func TestPersistentUnexplainedSuperblocks(t *testing.T) {
	unexplained := func(src, ro, where string) string {
		return "device 0xc1ae0001: /dev/pmem0 has a superblock that no claim of this node explains (" + src + " mounted " + ro + " in " + where +
			"): it is not used until that mount is gone"
	}
	// (a) a cached ext4 mount stays, its use is gone: a direct writer
	e := newPnEnv(t, "ext4")
	cached := e.n.NodeMountPath(pmemSerial, api.AccessCached)
	_, err := e.prepare("r", true, api.AccessCached, "", singleHost)
	noErr(t, err)
	e.uses = nil
	_, err = e.prepare("w", false, api.AccessDirect, "", singleHost)
	wantErr(t, err, unexplained("/dev/loop0", "ro", "pid 1 at "+cached))
	if len(e.m.callsOf("fsmount")) != 1 || e.m.isRO("/dev/pmem0") != true {
		t.Fatalf("calls %q", e.m.calls)
	}
	// a fresh read-only mount of the other access too
	_, err = e.prepare("r2", true, api.AccessDirect, "", singleHost)
	wantErr(t, err, unexplained("/dev/loop0", "ro", "pid 1 at "+cached))

	// (b) an xfs mount stays, its use is gone: a block writer
	e = newPnEnv(t, "xfs")
	direct := e.n.NodeMountPath(pmemSerial, api.AccessDirect)
	_, err = e.prepare("r", true, api.AccessDirect, "", singleHost)
	noErr(t, err)
	e.uses = nil
	_, err = e.prepare("b", false, "block", "", singleHost)
	wantErr(t, err, unexplained("/dev/pmem0", "ro", "pid 1 at "+direct))
	if !e.m.isRO("/dev/pmem0") {
		t.Fatal("block device writable under a foreign superblock")
	}

	// (c) a read-write superblock in another mount namespace (a bind that
	// outlived its lease): a new reader is refused, and nothing makes the
	// device read-only under it
	e = newPnEnv(t, "ext4")
	e.m.addForeign(4242, "/dev/pmem0", "/run/cxl/fs/rw", "ext4", false)
	_, err = e.prepare("r", true, "", "", singleHost)
	wantErr(t, err, unexplained("/dev/pmem0", "rw", "pid 4242 at /run/cxl/fs/rw"))
	if len(e.m.callsOf("blkroset")) != 0 {
		t.Fatalf("calls %q", e.m.calls)
	}
	wantErr(t, e.n.setReadOnly(pmemSerial, "/dev/pmem0", true),
		"device 0xc1ae0001: not making /dev/pmem0 read-only: /dev/pmem0 is mounted read-write in pid 4242 at /run/cxl/fs/rw")

	// an upgrade next to a foreign superblock of a loop device over the
	// device
	e = newPnEnv(t, "ext4")
	_, err = e.prepare("r", true, api.AccessDirect, "", singleHost)
	noErr(t, err)
	e.m.loops["/dev/loop9"] = "/dev/pmem0"
	e.m.addForeign(77, "/dev/loop9", "/mnt/old", "ext4", true)
	_, err = e.prepare("w", false, api.AccessDirect, "", singleHost)
	wantErr(t, err, unexplained("/dev/loop9", "ro", "pid 77 at /mnt/old"))
	e.wantSuper(e.n.NodeMountPath(pmemSerial, api.AccessDirect), "ro")
	// a bind of the node mount in another namespace is its superblock
	e.m.foreign = map[int][]mountInfo{}
	e.m.addForeign(78, "/dev/pmem0", "/run/cxl/fs/ro", "ext4", true)
	_, err = e.prepare("w", false, api.AccessDirect, "", singleHost)
	noErr(t, err)

	// S1: fail closed when the superblocks cannot be read
	e = newPnEnv(t, "ext4")
	e.m.superErr = errors.New("no proc")
	_, err = e.prepare("r", true, "", "", singleHost)
	wantErr(t, err, "device 0xc1ae0001: the superblocks of /dev/pmem0: no proc")
	e.m.superErr = nil
	_, err = e.prepare("r", true, "", "", singleHost)
	noErr(t, err)
	_, err = e.prepare("w", false, "", "", singleHost)
	noErr(t, err)
	e.m.superErr = errors.New("no proc")
	wantErr(t, e.release("w"), "device 0xc1ae0001: not making /dev/pmem0 read-only: its superblocks: no proc")
}

// TestPersistentReleaseVerifiedDevice: a release changes the read-only
// flag of the recorded block device of the remaining uses only when the
// driver's check says it is the device's now (review R1).
func TestPersistentReleaseVerifiedDevice(t *testing.T) {
	e := newPnEnv(t, "ext4")
	e.n.SetCheck(func(_ uint64, dev string) error {
		if dev != "/dev/pmem0" {
			return errors.New("renumbered")
		}
		return nil
	})
	gone := persistentUse{UID: "a", Serial: pmemSerial, Mode: api.ModeBlock, ReadOnly: false, BlockDevice: "/dev/pmem0"}
	stale := persistentUse{UID: "b", Serial: pmemSerial, Mode: api.ModeBlock, ReadOnly: true, BlockDevice: "/dev/pmem7"}
	noErr(t, e.n.Release(context.Background(), pmemSerial, []persistentUse{gone}, []persistentUse{stale}))
	if c := e.m.callsOf("blkroset"); len(c) != 0 {
		t.Fatalf("calls %q", c)
	}
	stale.BlockDevice = "/dev/pmem0"
	noErr(t, e.n.Release(context.Background(), pmemSerial, []persistentUse{gone}, []persistentUse{stale}))
	if c := e.m.callsOf("blkroset"); !slices.Equal(c, []string{"blkroset /dev/pmem0 1"}) {
		t.Fatalf("calls %q", c)
	}
}
