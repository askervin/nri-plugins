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

package kernel_test

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

const mountInfoSample = `22 1 0:21 / / rw,relatime shared:1 - btrfs /dev/vda3 rw,seclabel,compress=zstd:1,space_cache=v2,subvolid=257,subvol=/root
75 22 0:5 / /dev rw,nosuid shared:2 - devtmpfs devtmpfs rw,seclabel,size=4096k,nr_inodes=1048576,mode=755
301 22 259:0 / /var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/c1ae0001-direct ro,nosuid,nodev,relatime shared:150 - erofs /dev/pmem0 ro,user_xattr,acl,dax=always
302 22 7:0 / /var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/c1ae0001-cached ro,nosuid,nodev,relatime shared:151 - erofs /dev/loop0 ro,user_xattr,acl,dax=never
310 22 0:40 / /mnt/with\040space rw,relatime - tmpfs tmpfs rw
313 22 259:0 /sub\040dir /mnt/sub ro,nosuid,nodev,relatime shared:150 - erofs /dev/pmem0 ro,user_xattr,acl,dax=always
311 22 0:41 / /mnt/stacked rw,relatime - tmpfs first rw
312 311 0:42 / /mnt/stacked rw,relatime master:3 - tmpfs second rw,size=1k
`

// The mounts of a mountinfo: escaped fields, binds of subdirectories,
// stacked mounts (the driver's TestParseMountInfo).
func TestParseMountInfo(t *testing.T) {
	mounts, err := kernel.ParseMountInfo(strings.NewReader(mountInfoSample))
	noErr(t, err)
	if len(mounts) != 8 {
		t.Fatalf("%d mounts", len(mounts))
	}
	want := kernel.MountInfo{
		DevNum:     "259:0",
		Root:       "/",
		Target:     "/var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/c1ae0001-direct",
		FsType:     "erofs",
		Source:     "/dev/pmem0",
		SuperOpts:  []string{"ro", "user_xattr", "acl", "dax=always"},
		MountFlags: []string{"ro", "nosuid", "nodev", "relatime"},
	}
	mi := kernel.FindMount(mounts, want.Target+"/")
	if mi == nil || !reflect.DeepEqual(*mi, want) || !mi.HasSuperOpt("dax=always") || mi.HasSuperOpt("dax=never") || !mi.SuperReadOnly() {
		t.Fatalf("direct mount %+v", mi)
	}
	if mi := kernel.FindMount(mounts, "/var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/c1ae0001-cached"); mi == nil || mi.Source != "/dev/loop0" || !mi.HasSuperOpt("dax=never") {
		t.Fatalf("cached mount %+v", mi)
	}
	if mi := kernel.FindMount(mounts, "/mnt/sub"); mi == nil || mi.Root != "/sub dir" || mi.Source != "/dev/pmem0" {
		t.Fatalf("bind of a subdirectory: %+v", mi)
	}
	if mi := kernel.FindMount(mounts, "/mnt/with space"); mi == nil || mi.FsType != "tmpfs" || mi.SuperReadOnly() {
		t.Fatalf("escaped mount point: %+v", mi)
	}
	if mi := kernel.FindMount(mounts, "/mnt/stacked"); mi == nil || mi.Source != "second" {
		t.Fatalf("stacked mount: %+v", mi)
	}
	if kernel.FindMount(mounts, "/var/lib/kubelet/plugins/cxl-pool.nri.io/mounts") != nil {
		t.Fatal("a parent directory is not a mount")
	}
	for _, bad := range []string{"1 2 3\n", "22 1 0:21 / / rw,relatime shared:1 btrfs /dev/vda3 rw\n", "22 1 0:21 / / rw - btrfs\n"} {
		if _, err := kernel.ParseMountInfo(strings.NewReader(bad)); err == nil {
			t.Errorf("invalid line accepted: %q", bad)
		}
	}
}

// fsdaxNode returns a fake with a persistent memdev whose region0 has an
// fsdax namespace with the block device /dev/pmem0 of the fake, and that
// device.
func fsdaxNode(t *testing.T) (*fake.Fake, *kernel.Kernel, string) {
	t.Helper()
	f, k := pmemNode(t)
	createRegion(t, k, "mem0", kernel.RegionPmem, 0)
	ns, err := k.CreateFsdaxNamespace(ctxTimeout(t, 5*time.Second), "region0", "")
	noErr(t, err)
	return f, k, ns.BlockDevice
}

// mountPoint returns a new directory to mount at.
func mountPoint(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	noErr(t, os.MkdirAll(dir, 0o755))
	return dir
}

// The superblocks of a block device and of the loop devices over it, in
// every mount namespace, one per device (the driver's
// TestSysMounterSuperblocks).
func TestSuperblocks(t *testing.T) {
	f, k, dev := fsdaxNode(t)
	direct := mountPoint(t, "direct")
	noErr(t, k.SetBlockDeviceReadOnly(dev, false))
	noErr(t, k.FsMount(dev, direct, "ext4", true, []string{"dax=always"}))
	loop, err := k.AttachLoop(dev, false)
	noErr(t, err)
	cached := mountPoint(t, "cached")
	noErr(t, k.Mount(loop.Path(), cached, "erofs", syscall.MS_RDONLY, "dax=never"))
	noErr(t, loop.Release(false))
	f.AddForeign(300, dev, "/run/cxl/fs/y", "ext4", false)
	sbs, err := k.Superblocks(dev)
	noErr(t, err)
	want := []kernel.Superblock{
		{Device: dev, DevNum: "259:0", Source: dev, FsType: "ext4", Where: "pid 1 at " + direct},
		{Device: loop.Path(), DevNum: "7:0", Source: loop.Path(), FsType: "erofs", ReadOnly: true, Where: "pid 1 at " + cached},
	}
	if !reflect.DeepEqual(sbs, want) {
		t.Fatalf("superblocks %+v\nwant %+v", sbs, want)
	}
	if _, err := k.Superblocks(f.DevRoot() + "/pmem9"); err == nil {
		t.Fatal("no error for a device without a number")
	}
	// the mounts of the process
	if mi, err := k.Mounted(direct); err != nil || mi == nil || mi.Source != dev || mi.SuperReadOnly() {
		t.Fatalf("mounted %+v %v", mi, err)
	}
	if ms, err := k.MountsUnder(filepath.Dir(cached)); err != nil || len(ms) != 1 || ms[0].Source != loop.Path() {
		t.Fatalf("mounts under %s: %+v %v", filepath.Dir(cached), ms, err)
	}
	// the cached mount goes, and its autoclear loop device with it
	noErr(t, k.Unmount(cached))
	if l := k.LoopDevices(); len(l) != 0 {
		t.Fatalf("loop devices %+v", l)
	}
	f.SetBusy(direct, true)
	if err := k.Unmount(direct); !errors.Is(err, kernel.ErrEBUSY) {
		t.Fatalf("busy unmount: %v", err)
	}
}

// A block device is never made read-only under a read-write superblock in
// any mount namespace, nor when its superblocks cannot be read; a device
// that is gone is not an error.
func TestSetBlockDeviceReadOnly(t *testing.T) {
	f, k, dev := fsdaxNode(t)
	noErr(t, k.SetBlockDeviceReadOnly(dev, true))
	if ro, err := k.ReadOnly(dev); err != nil || !ro {
		t.Fatalf("read-only %v %v", ro, err)
	}
	if got := f.MountCalls("blkroset"); len(got) != 1 {
		t.Fatalf("calls %v", got)
	}
	// unchanged: no call
	noErr(t, k.SetBlockDeviceReadOnly(dev, true))
	noErr(t, k.SetBlockDeviceReadOnly(dev, false))
	f.AddForeign(300, dev, "/run/cxl/fs/x", "ext4", false)
	err := k.SetBlockDeviceReadOnly(dev, true)
	wantErr(t, err, kernel.ErrEBUSY, "not making "+dev+" read-only: "+dev+" is mounted read-write in pid 300 at /run/cxl/fs/x")
	if f.IsReadOnly(dev) {
		t.Fatal("made read-only under a read-write superblock")
	}
	f.RemoveForeign(300)
	f.HideProc(true)
	wantErr(t, k.SetBlockDeviceReadOnly(dev, true), nil, "its superblocks")
	f.HideProc(false)
	// gone
	noErr(t, k.SetBlockDeviceReadOnly(f.DevRoot()+"/pmem9", true))
	noErr(t, k.SetBlockDeviceReadOnly("", true))
	f.SetReadOnlyError(dev, syscall.EPERM)
	wantErr(t, k.SetBlockDeviceReadOnly(dev, true), nil, "making "+dev+" read-only")
	if v := f.Violations(); len(v) != 0 {
		t.Fatalf("violations %v", v)
	}
}

// What holds a block device: a loop device over it (also one that a
// restarted container set up, whose backing sysfs shows as "/pmem0"), an
// exclusive open that fails; not a device that is gone (the driver's
// TestSysMounterHolder, TestSysMounterLoopBackingAfterRestart).
func TestHolder(t *testing.T) {
	f, k, dev := fsdaxNode(t)
	if h, err := k.Holder(dev); err != nil || h != "" {
		t.Fatalf("holder %q %v", h, err)
	}
	loop, err := k.AttachLoop(dev, false)
	noErr(t, err)
	if h, err := k.Holder(dev); err != nil || h != filepath.Base(loop.Path()) {
		t.Fatalf("holder %q %v", h, err)
	}
	if b, err := k.LoopBackingFile(loop.Path()); err != nil || b != dev {
		t.Fatalf("backing %q %v", b, err)
	}
	// after a restart of the driver container sysfs shows the path
	// relative to the root of its /dev: the device number tells
	f.Write("block/loop0/loop/backing_file", "/pmem0")
	if b, err := k.LoopBackingFile(loop.Path()); err != nil || b != dev {
		t.Fatalf("backing after a restart %q %v", b, err)
	}
	if l := k.LoopDevices(); len(l) != 1 || l[0].Backing != dev || l[0].DevNum != "7:0" {
		t.Fatalf("loop devices %+v", l)
	}
	if b, err := k.LoopBackingFile("/dev/loop9"); err != nil || b != "" {
		t.Fatalf("backing of a missing loop device %q %v", b, err)
	}
	noErr(t, k.ClearLoop(loop))
	if h, err := k.Holder(dev); err != nil || h != "" {
		t.Fatalf("holder after the clear %q %v", h, err)
	}
	f.SetHolder(dev, "a container's bind")
	if h, err := k.Holder(dev); err != nil || h != "in use" {
		t.Fatalf("holder %q %v", h, err)
	}
	if h, err := k.Holder(f.DevRoot() + "/pmem9"); err != nil || h != "" {
		t.Fatalf("holder of a missing device %q %v", h, err)
	}
	f.SetSyscallErrors(syscall.EACCES, nil, nil)
	wantErr(t, func() error { _, err := k.Holder(dev); return err }(), nil, "permission denied")
	for backing, want := range map[string]bool{"/dev/pmem0": true, "/dev/x/pmem0": false, "/tmp/pmem0": false, "pmem0": false, "/pmem0": true, "/pmem1": false, "/": false} {
		if got := kernel.SameDevice(backing, "/dev/pmem0"); got != want {
			t.Errorf("SameDevice(%q) = %v", backing, got)
		}
	}
	if p := kernel.DevPath("/pmem1"); p != "/dev/pmem1" {
		t.Errorf("DevPath %q", p)
	}
}

// Reconfigure changes the superblock of every mount of it; a reconfigure
// to read-only with a file open for writing is EBUSY; a read-only bind of a
// node mount reaches its target read-only.
func TestReconfigureAndBind(t *testing.T) {
	f, k, dev := fsdaxNode(t)
	node := mountPoint(t, "node")
	noErr(t, k.SetBlockDeviceReadOnly(dev, false))
	noErr(t, k.FsMount(dev, node, "ext4", true, nil))
	bind := mountPoint(t, "bind")
	noErr(t, k.BindReadOnly(node, bind))
	if mi, _ := k.Mounted(bind); mi == nil || !slices.Contains(mi.MountFlags, "ro") || mi.SuperReadOnly() {
		t.Fatalf("bind %+v", mi)
	}
	f.SetWriting(node, true)
	if err := k.Reconfigure(node, false); !errors.Is(err, kernel.ErrEBUSY) {
		t.Fatalf("reconfigure while writing: %v", err)
	}
	f.SetWriting(node, false)
	noErr(t, k.Syncfs(node))
	noErr(t, k.Reconfigure(node, false))
	if mi, _ := k.Mounted(bind); mi == nil || !mi.SuperReadOnly() {
		t.Fatalf("bind after the reconfigure %+v", mi)
	}
	noErr(t, k.SetBlockDeviceReadOnly(dev, true))
	if err := k.Reconfigure(node, true); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("read-write on a read-only device: %v", err)
	}
	if v := f.Violations(); len(v) != 0 {
		t.Fatalf("violations %v", v)
	}
}

// fsImage returns the head of a block device with the signatures of the
// filesystem types: erofs, squashfs, ext4 (ext4-dirty: needs recovery),
// xfs, btrfs, gfs2 (lock_dlm), gfs2-nolock (lock_nolock).
func fsImage(types ...string) []byte {
	img := make([]byte, kernel.FsProbeBytes)
	for _, t := range types {
		switch t {
		case "erofs":
			binary.LittleEndian.PutUint32(img[1024:], 0xE0F5E1E2)
		case "squashfs":
			copy(img, "hsqs")
		case "ext4", "ext4-dirty":
			binary.LittleEndian.PutUint16(img[1080:], 0xEF53)
			if t == "ext4-dirty" {
				binary.LittleEndian.PutUint32(img[1024+0x60:], 0x4|0x2)
			} else {
				binary.LittleEndian.PutUint32(img[1024+0x60:], 0x2)
			}
		case "xfs":
			copy(img, "XFSB")
		case "btrfs":
			copy(img[65600:], "_BHRfS_M")
		case "gfs2", "gfs2-nolock":
			binary.BigEndian.PutUint32(img[65536:], 0x01161970)
			binary.BigEndian.PutUint32(img[65540:], 1)
			proto := "lock_dlm"
			if t == "gfs2-nolock" {
				proto = "lock_nolock"
			}
			copy(img[65536+96:], proto+"\x00")
		default:
			panic("fsImage: unknown type " + t)
		}
	}
	return img
}

// The signatures of the known filesystem types in the head of a block
// device (the driver's TestParseFsSignature).
func TestParseFsSignature(t *testing.T) {
	for _, tc := range []struct {
		image    []string
		types    []string
		proto    string
		recovery bool
	}{
		{nil, nil, "", false},
		{[]string{"erofs"}, []string{"erofs"}, "", false},
		{[]string{"squashfs"}, []string{"squashfs"}, "", false},
		{[]string{"ext4"}, []string{"ext4"}, "", false},
		{[]string{"ext4-dirty"}, []string{"ext4"}, "", true},
		{[]string{"xfs"}, []string{"xfs"}, "", false},
		{[]string{"btrfs"}, []string{"btrfs"}, "", false},
		{[]string{"gfs2"}, []string{"gfs2"}, "lock_dlm", false},
		{[]string{"gfs2-nolock"}, []string{"gfs2"}, "lock_nolock", false},
		{[]string{"xfs", "ext4"}, []string{"ext4", "xfs"}, "", false},
	} {
		s := kernel.ParseFsSignature(fsImage(tc.image...))
		if !slices.Equal(s.Types, tc.types) || s.Gfs2LockProto != tc.proto || s.Ext4NeedsRecovery != tc.recovery {
			t.Errorf("%v: %+v", tc.image, s)
		}
	}
	// a gfs2 magic without the superblock meta type is not gfs2
	img := fsImage("gfs2")
	img[65543] = 2
	if s := kernel.ParseFsSignature(img); len(s.Types) != 0 {
		t.Errorf("gfs2 of meta type 2: %+v", s)
	}
	// a short head matches what it covers
	if s := kernel.ParseFsSignature(fsImage("ext4", "btrfs")[:4096]); !slices.Equal(s.Types, []string{"ext4"}) {
		t.Errorf("short head: %+v", s)
	}
	if s := kernel.ParseFsSignature([]byte("XF")); len(s.Types) != 0 {
		t.Errorf("tiny head: %+v", s)
	}
}

// The head of a block device is read for its signatures; the data of a
// persistent memdev outlives its block device.
func TestReadFsSignature(t *testing.T) {
	f, k, dev := fsdaxNode(t)
	f.SetImage(dev, fsImage("erofs"))
	s, err := k.ReadFsSignature(dev)
	if err != nil || !slices.Equal(s.Types, []string{kernel.FsErofs}) {
		t.Fatalf("signature %+v %v", s, err)
	}
	if head, err := k.ReadHead(dev, 10); err != nil || len(head) != 10 {
		t.Fatalf("head %d bytes %v", len(head), err)
	}
	if _, err := k.ReadFsSignature(f.DevRoot() + "/pmem9"); err == nil {
		t.Fatal("signature of a missing device")
	}
	// a reboot: the data stay, the block device comes back
	f.Reboot()
	createRegion(t, k, "mem0", kernel.RegionPmem, 0)
	nss, err := k.Namespaces(ctxTimeout(t, 5*time.Second), "region0")
	noErr(t, err)
	ns := kernel.FsdaxNamespace(nss)
	if ns == nil {
		t.Fatalf("namespaces after a reboot %+v", nss)
	}
	if s, err := k.ReadFsSignature(ns.BlockDevice); err != nil || !slices.Equal(s.Types, []string{kernel.FsErofs}) || ns.Minor == 0 {
		t.Fatalf("after a reboot: %s %d:%d signature %+v %v", ns.BlockDevice, ns.Major, ns.Minor, s, err)
	}
	// a new probe gives the block device another name and numbers
	renamed := f.RenamePmem("region0", "pmem3", "259:9")
	nss, err = k.Namespaces(ctxTimeout(t, 5*time.Second), "region0")
	noErr(t, err)
	if ns := kernel.FsdaxNamespace(nss); ns == nil || ns.BlockDevice != renamed || ns.Minor != 9 {
		t.Fatalf("renamed: %+v", nss)
	}
	if s, err := k.ReadFsSignature(renamed); err != nil || !slices.Equal(s.Types, []string{kernel.FsErofs}) {
		t.Fatalf("renamed signature %+v %v", s, err)
	}
}
