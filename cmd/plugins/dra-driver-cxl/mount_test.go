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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// mountInfoSample has the mounts of mode fs as the kernel of the e2e VMs
// shows them, a mount point with a space, and a mount stacked on another
// one.
const mountInfoSample = `22 1 0:21 / / rw,relatime shared:1 - btrfs /dev/vda3 rw,seclabel,compress=zstd:1,space_cache=v2,subvolid=257,subvol=/root
75 22 0:5 / /dev rw,nosuid shared:2 - devtmpfs devtmpfs rw,seclabel,size=4096k,nr_inodes=1048576,mode=755
301 22 259:0 / /var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/c1ae0001-direct ro,nosuid,nodev,relatime shared:150 - erofs /dev/pmem0 ro,user_xattr,acl,dax=always
302 22 7:0 / /var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/c1ae0001-cached ro,nosuid,nodev,relatime shared:151 - erofs /dev/loop0 ro,user_xattr,acl,dax=never
310 22 0:40 / /mnt/with\040space rw,relatime - tmpfs tmpfs rw
313 22 259:0 /sub\040dir /mnt/sub ro,nosuid,nodev,relatime shared:150 - erofs /dev/pmem0 ro,user_xattr,acl,dax=always
311 22 0:41 / /mnt/stacked rw,relatime - tmpfs first rw
312 311 0:42 / /mnt/stacked rw,relatime master:3 - tmpfs second rw,size=1k
`

func TestParseMountInfo(t *testing.T) {
	mounts, err := parseMountInfo(strings.NewReader(mountInfoSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 8 {
		t.Fatalf("%d mounts", len(mounts))
	}
	want := mountInfo{
		Root:       "/",
		Target:     "/var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/c1ae0001-direct",
		FsType:     "erofs",
		Source:     "/dev/pmem0",
		SuperOpts:  []string{"ro", "user_xattr", "acl", "dax=always"},
		MountFlags: []string{"ro", "nosuid", "nodev", "relatime"},
	}
	mi := findMount(mounts, want.Target+"/")
	if mi == nil || !reflect.DeepEqual(*mi, want) || !mi.hasSuperOpt("dax=always") || mi.hasSuperOpt("dax=never") {
		t.Fatalf("direct mount %+v", mi)
	}
	if mi := findMount(mounts, "/var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/c1ae0001-cached"); mi == nil || mi.Source != "/dev/loop0" || !mi.hasSuperOpt("dax=never") {
		t.Fatalf("cached mount %+v", mi)
	}
	if mi := findMount(mounts, "/mnt/sub"); mi == nil || mi.Root != "/sub dir" || mi.Source != "/dev/pmem0" {
		t.Fatalf("bind of a subdirectory: %+v", mi)
	}
	if mi := findMount(mounts, "/mnt/with space"); mi == nil || mi.FsType != "tmpfs" {
		t.Fatalf("escaped mount point: %+v", mi)
	}
	if mi := findMount(mounts, "/mnt/stacked"); mi == nil || mi.Source != "second" {
		t.Fatalf("stacked mount: %+v", mi)
	}
	if findMount(mounts, "/var/lib/kubelet/plugins/cxl-pool.nri.io/mounts") != nil {
		t.Fatal("a parent directory is not a mount")
	}
	for _, bad := range []string{"1 2 3\n", "22 1 0:21 / / rw,relatime shared:1 btrfs /dev/vda3 rw\n", "22 1 0:21 / / rw - btrfs\n"} {
		if _, err := parseMountInfo(strings.NewReader(bad)); err == nil {
			t.Errorf("invalid line accepted: %q", bad)
		}
	}
	for in, out := range map[string]string{`a\040b`: "a b", `\134x`: `\x`, `tail\04`: `tail\04`, `x\999`: `x\999`, "plain": "plain"} {
		if got := unescapeMountInfo(in); got != out {
			t.Errorf("unescape %q: %q, expected %q", in, got, out)
		}
	}
}

func TestSysMounterHolder(t *testing.T) {
	root := t.TempDir()
	m := &sysMounter{sysRoot: root, devRoot: filepath.Join(root, "dev"), loopStatus: func(string) (*unix.LoopInfo64, error) { return nil, unix.ENXIO }}
	loop := func(name, backing string) {
		t.Helper()
		dir := filepath.Join(root, "block", name, "loop")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "backing_file"), []byte(backing+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	loop("loop2", "/var/tmp/pmem0")    // a file named like the device
	loop("loop3", "/dev/disk/x/pmem0") // not in /dev
	if h, err := m.Holder("/dev/pmem0"); err != nil || h != "" {
		t.Fatalf("holder %q %v of a missing device", h, err)
	}
	loop("loop4", "/dev/pmem0")
	if h, err := m.Holder("/dev/pmem0"); err != nil || h != "loop4" {
		t.Fatalf("holder %q %v", h, err)
	}
	if b, err := m.LoopBackingFile("/dev/loop4"); err != nil || b != "/dev/pmem0" {
		t.Fatalf("backing file %q %v", b, err)
	}
	if b, err := m.LoopBackingFile("/dev/loop9"); err != nil || b != "" {
		t.Fatalf("backing file of a missing loop device %q %v", b, err)
	}
	// a device that can be opened exclusively has no holder
	f := filepath.Join(root, "pmem1")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if h, err := m.Holder(f); err != nil || h != "" {
		t.Fatalf("holder %q %v", h, err)
	}
	for backing, want := range map[string]bool{"/dev/pmem0": true, "/dev/x/pmem0": false, "/tmp/pmem0": false, "pmem0": false} {
		if got := sameDevice(backing, "/dev/pmem0"); got != want {
			t.Errorf("sameDevice(%q) = %v", backing, got)
		}
	}
}

// TestSysMounterLoopBackingAfterRestart: the loop device of a cached node
// mount was set up by an earlier driver container through its /dev, and
// sysfs shows its backing file relative to the root of that devtmpfs
// mount ("/pmem1", plan-13 bug-13). LoopBackingFile finds the block device
// by its device number, and without it the path is taken as a path under
// /dev: the loop device is the holder of /dev/pmem1 either way.
func TestSysMounterLoopBackingAfterRestart(t *testing.T) {
	root := t.TempDir()
	devRoot := filepath.Join(root, "dev")
	write := func(rel, val string) {
		t.Helper()
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(val+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("block/loop0/loop/backing_file", "/pmem1")
	write("dev/block/259:1/uevent", "MAJOR=259\nMINOR=1\nDEVNAME=pmem1\nDEVTYPE=disk")
	write("block/loop1/loop/backing_file", "/var/lib/images/a.img") // a file
	status := map[string]*unix.LoopInfo64{
		filepath.Join(devRoot, "loop0"): {Rdevice: unix.Mkdev(259, 1)},
		filepath.Join(devRoot, "loop1"): {Device: unix.Mkdev(253, 0), Inode: 12},
	}
	m := &sysMounter{sysRoot: root, devRoot: devRoot, loopStatus: func(path string) (*unix.LoopInfo64, error) {
		if st := status[path]; st != nil {
			return st, nil
		}
		return nil, unix.ENXIO
	}}
	pmem1 := filepath.Join(devRoot, "pmem1")
	if b, err := m.LoopBackingFile("/dev/loop0"); err != nil || b != pmem1 {
		t.Fatalf("backing of loop0 %q %v, expected %s", b, err, pmem1)
	}
	if b, err := m.LoopBackingFile("/dev/loop1"); err != nil || b != "/var/lib/images/a.img" {
		t.Fatalf("backing of loop1 %q %v", b, err)
	}
	if h, err := m.Holder(pmem1); err != nil || h != "loop0" {
		t.Fatalf("holder of %s %q %v", pmem1, h, err)
	}
	// the device number of a loop device without its device node: the
	// path in sysfs, under /dev
	delete(status, filepath.Join(devRoot, "loop0"))
	if b, err := m.LoopBackingFile("/dev/loop0"); err != nil || b != "/pmem1" || !sameDevice(b, "/dev/pmem1") || devPath(b) != "/dev/pmem1" {
		t.Fatalf("backing of loop0 %q %v", b, err)
	}
	m.devRoot = "/dev"
	if h, err := m.Holder("/dev/pmem1"); err != nil || h != "loop0" {
		t.Fatalf("holder of /dev/pmem1 %q %v", h, err)
	}
	// a sysfs entry without DEVNAME
	m.devRoot = devRoot
	status[filepath.Join(devRoot, "loop0")] = &unix.LoopInfo64{Rdevice: unix.Mkdev(259, 1)}
	write("dev/block/259:1/uevent", "MAJOR=259\nMINOR=1")
	if b, err := m.LoopBackingFile("/dev/loop0"); err != nil || b != "/pmem1" {
		t.Fatalf("backing of loop0 %q %v", b, err)
	}
	for backing, want := range map[string]bool{"/pmem0": true, "/pmem1": false, "/": false} {
		if got := sameDevice(backing, "/dev/pmem0"); got != want {
			t.Errorf("sameDevice(%q) = %v", backing, got)
		}
	}
}
