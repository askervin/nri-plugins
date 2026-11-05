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

package kernel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// aliasedMapping maps the same size bytes of a memfd n times in a row: the
// mapping has n*size bytes, and offsets X and X+size reach the same memory,
// as on a device that ignores the address bit log2(size).
func aliasedMapping(t *testing.T, size, n int) []byte {
	fd, err := unix.MemfdCreate("probe-test", 0)
	if err != nil {
		t.Skipf("memfd_create: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Ftruncate(fd, int64(size)); err != nil {
		t.Fatal(err)
	}
	all, err := unix.Mmap(-1, 0, size*n, unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Munmap(all) })
	base := uintptr(unsafe.Pointer(&all[0]))
	for i := 0; i < n; i++ {
		_, _, errno := unix.Syscall6(unix.SYS_MMAP, base+uintptr(i*size), uintptr(size),
			unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_FIXED, uintptr(fd), 0)
		if errno != 0 {
			t.Fatalf("mmap: %v", errno)
		}
	}
	return all
}

// The address line probe on plain memory and on memory that aliases
// (memctl TestProbeAliasing).
func TestProbeMemory(t *testing.T) {
	if !cacheFlushSupported {
		t.Skip(ErrProbeUnsupported)
	}
	plain, err := unix.Mmap(-1, 0, 64<<20, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Munmap(plain) }()
	if a := ProbeMemory(plain); a.Offset != 0 || a.Garbage >= 0 {
		t.Fatalf("aliasing in plain memory: %s", a)
	}
	// 3 x 8 MiB: like a 192 GiB device with 128 GiB distinct, offsets
	// 16 MiB.. alias 0.., and 8 MiB.. alias 0.. too
	a := ProbeMemory(aliasedMapping(t, 8<<20, 3))
	if a.Offset != 8<<20 || a.Base != 0 {
		t.Fatalf("expected aliasing at +8 MiB from 0, got %s", a)
	}
	if s := a.String(); s != "offsets 0x0 and 0x800000 reach the same memory (address bit 23 is ignored): only the first 8388608 bytes are distinct" {
		t.Fatalf("String() = %q", s)
	}
	if s := (&Aliasing{Garbage: 4096}).String(); s != "no aliasing, but offset 0x1000 did not read back what was written" {
		t.Fatalf("String() = %q", s)
	}
	if s := (*Aliasing)(nil).String(); s != "not probed" {
		t.Fatalf("String() = %q", s)
	}
}

// The character device of a dax device is opened again while it is not
// there yet (ENXIO), other errors are returned at once (memctl
// TestOpenDaxNode).
func TestOpenDaxNode(t *testing.T) {
	node := filepath.Join(t.TempDir(), "dax0.0")
	if err := os.WriteFile(node, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	oldOpen, oldTimeout, oldInterval := openFile, daxOpenTimeout, daxOpenInterval
	t.Cleanup(func() { openFile, daxOpenTimeout, daxOpenInterval = oldOpen, oldTimeout, oldInterval })
	daxOpenTimeout, daxOpenInterval = time.Second, time.Millisecond
	fails := 0
	openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if fails < 3 {
			fails++
			return nil, &os.PathError{Op: "open", Path: name, Err: unix.ENXIO}
		}
		return os.OpenFile(name, flag, perm)
	}
	f, err := openDaxNode(context.Background(), node)
	if err != nil || fails != 3 {
		t.Fatalf("open after ENXIO: %v, %d fails", err, fails)
	}
	_ = f.Close()
	calls := 0
	openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		calls++
		return nil, &os.PathError{Op: "open", Path: name, Err: unix.EACCES}
	}
	if _, err := openDaxNode(context.Background(), node); !errors.Is(err, unix.EACCES) || calls != 1 {
		t.Fatalf("expected EACCES at once, got %v after %d calls", err, calls)
	}
	daxOpenTimeout = 20 * time.Millisecond
	openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		return nil, &os.PathError{Op: "open", Path: name, Err: unix.ENXIO}
	}
	if _, err := openDaxNode(context.Background(), node); !errors.Is(err, unix.ENXIO) {
		t.Fatalf("expected ENXIO after the timeout, got %v", err)
	}
	// the context ends the retries
	daxOpenTimeout = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := openDaxNode(ctx, node); !errors.Is(err, unix.ENXIO) {
		t.Fatalf("expected ENXIO at the end of the context, got %v", err)
	}
}

// Zeroing writes zeros through windows that are multiples of the align
// (the driver's TestZeroFile).
func TestZeroFile(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "dax"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	size := uint64(3*zeroChunk + 4096)
	data := make([]byte, size)
	for i := range data {
		data[i] = 0xa5
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := ZeroFile(f, size-512, 3<<20); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range got[:size-512] {
		if b != 0 {
			t.Fatalf("byte %d is %#x", i, b)
		}
	}
	if got[size-512] != 0xa5 {
		t.Fatal("zeroed past the size")
	}
	// a device that cannot be opened
	oldTimeout := daxOpenTimeout
	t.Cleanup(func() { daxOpenTimeout = oldTimeout })
	daxOpenTimeout = 20 * time.Millisecond
	s := &SysCalls{DevRoot: t.TempDir()}
	if err := s.ZeroDax(context.Background(), 0, 0, 1<<20, 2<<20); err == nil {
		t.Fatal("zeroing a device that does not exist")
	}
}

func TestUnescapeMountInfo(t *testing.T) {
	for in, out := range map[string]string{`a\040b`: "a b", `\134x`: `\x`, `tail\04`: `tail\04`, `x\999`: `x\999`, "plain": "plain"} {
		if got := unescapeMountInfo(in); got != out {
			t.Errorf("unescape %q: %q, expected %q", in, got, out)
		}
	}
}

func TestDevNumbers(t *testing.T) {
	for _, n := range [][2]uint32{{259, 1}, {7, 300}, {4095, 1 << 19}, {5000, 3}} {
		dev := unix.Mkdev(n[0], n[1])
		if devMajor(dev) != n[0] || devMinor(dev) != n[1] {
			t.Errorf("%d:%d: %d:%d", n[0], n[1], devMajor(dev), devMinor(dev))
		}
	}
	if _, _, err := parseDevNumbers("x", "259"); err == nil {
		t.Error("numbers without a colon accepted")
	}
	if got := parseList("0-2,5, 7-8,x"); !reflect.DeepEqual(got, []int{0, 1, 2, 5, 7, 8}) {
		t.Errorf("parseList %v", got)
	}
}

// loopSys is a Sys whose loop devices have backings of the device numbers
// of rdev.
type loopSys struct {
	SysCalls
	rdev map[string]uint64
}

func (s *loopSys) LoopRdevice(loop string) (uint64, error) {
	if d, ok := s.rdev[loop]; ok {
		return d, nil
	}
	return 0, unix.ENXIO
}

// The backing of a loop device set up in another mount namespace: by its
// device number, else the path that sysfs shows, which is taken as a path
// under /dev (the driver's TestSysMounterLoopBackingAfterRestart).
func TestLoopBackingFile(t *testing.T) {
	root := t.TempDir()
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
	write("block/loop1/loop/backing_file", "/var/lib/images/a.img")
	devRoot := filepath.Join(root, "dev")
	sys := &loopSys{rdev: map[string]uint64{filepath.Join(devRoot, "loop0"): unix.Mkdev(259, 1), filepath.Join(devRoot, "loop1"): 0}}
	k := &Kernel{SysRoot: root, DevRoot: devRoot, Sys: sys}
	pmem1 := filepath.Join(devRoot, "pmem1")
	if b, err := k.LoopBackingFile("/dev/loop0"); err != nil || b != pmem1 {
		t.Fatalf("backing of loop0 %q %v, expected %s", b, err, pmem1)
	}
	if h, err := k.Holder(pmem1); err != nil || h != "loop0" {
		t.Fatalf("holder of %s %q %v", pmem1, h, err)
	}
	if b, err := k.LoopBackingFile("/dev/loop1"); err != nil || b != "/var/lib/images/a.img" {
		t.Fatalf("backing of loop1 %q %v", b, err)
	}
	// no device number: the path in sysfs, under /dev
	delete(sys.rdev, filepath.Join(devRoot, "loop0"))
	if b, err := k.LoopBackingFile("/dev/loop0"); err != nil || b != "/pmem1" || !SameDevice(b, "/dev/pmem1") || DevPath(b) != "/dev/pmem1" {
		t.Fatalf("backing of loop0 %q %v", b, err)
	}
	if h, err := k.Holder(pmem1); err != nil || h != "loop0" {
		t.Fatalf("holder of %s through the path in sysfs %q %v", pmem1, h, err)
	}
	// a sysfs entry without DEVNAME
	sys.rdev[filepath.Join(devRoot, "loop0")] = unix.Mkdev(259, 1)
	write("dev/block/259:1/uevent", "MAJOR=259\nMINOR=1")
	if b, err := k.LoopBackingFile("/dev/loop0"); err != nil || b != "/pmem1" {
		t.Fatalf("backing of loop0 %q %v", b, err)
	}
}

// The holders of a block device: a loop device over it, not those over files
// named like it; the exclusive open of the system says nothing holds a
// device that is gone or a plain file; the backing of a loop device whose
// ioctl fails is the path in sysfs (the driver's TestSysMounterHolder).
func TestHolderLoops(t *testing.T) {
	root := t.TempDir()
	devRoot := filepath.Join(root, "dev")
	k := &Kernel{SysRoot: root, DevRoot: devRoot, Sys: &loopSys{}}
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
	pmem0 := filepath.Join(devRoot, "pmem0")
	loop("loop2", "/var/tmp/pmem0")    // a file named like the device
	loop("loop3", "/dev/disk/x/pmem0") // not in /dev
	if h, err := k.Holder(pmem0); err != nil || h != "" {
		t.Fatalf("holder %q %v of a missing device", h, err)
	}
	loop("loop4", "/dev/pmem0")
	if h, err := k.Holder(pmem0); err != nil || h != "loop4" {
		t.Fatalf("holder %q %v", h, err)
	}
	if b, err := k.LoopBackingFile("/dev/loop4"); err != nil || b != "/dev/pmem0" {
		t.Fatalf("backing file %q %v", b, err)
	}
	if b, err := k.LoopBackingFile("/dev/loop9"); err != nil || b != "" {
		t.Fatalf("backing file of a missing loop device %q %v", b, err)
	}
	// a file that can be opened exclusively has no holder
	file := filepath.Join(root, "pmem1")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if h, err := k.Holder(file); err != nil || h != "" {
		t.Fatalf("holder %q %v", h, err)
	}
	for backing, want := range map[string]bool{"/dev/pmem0": true, "/dev/x/pmem0": false, "/tmp/pmem0": false, "pmem0": false} {
		if got := SameDevice(backing, "/dev/pmem0"); got != want {
			t.Errorf("SameDevice(%q) = %v", backing, got)
		}
	}
}

// The superblocks of a block device and of the loop devices over it are
// read from the mountinfo of one process per mount namespace: a loop over
// another file is not one, a second process of a namespace already read is
// not read, a superblock only in another namespace is one (the driver's
// TestSysMounterSuperblocks).
func TestSuperblocksNamespaces(t *testing.T) {
	root := t.TempDir()
	sys, proc := filepath.Join(root, "sys"), filepath.Join(root, "proc")
	k := &Kernel{SysRoot: sys, ProcRoot: proc, DevRoot: "/dev", Sys: &loopSys{}}
	write := func(path, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	process := func(pid, ns, mountinfo string) {
		t.Helper()
		write(filepath.Join(proc, pid, "mountinfo"), mountinfo)
		if err := os.MkdirAll(filepath.Join(proc, pid, "ns"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("mnt:["+ns+"]", filepath.Join(proc, pid, "ns", "mnt")); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(sys, "class/block/pmem0/dev"), "259:0\n")
	write(filepath.Join(sys, "block/loop3/loop/backing_file"), "/dev/pmem0\n")
	write(filepath.Join(sys, "block/loop3/dev"), "7:3\n")
	write(filepath.Join(sys, "block/loop4/loop/backing_file"), "/var/tmp/img\n")
	write(filepath.Join(sys, "block/loop4/dev"), "7:4\n")
	process("100", "1", "301 22 259:0 / /var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/c1ae0001-direct rw,nosuid,nodev shared:150 - ext4 /dev/pmem0 rw,dax=always\n"+
		"302 22 7:4 / /mnt/img rw - ext4 /dev/loop4 rw\n")
	process("200", "1", "301 22 259:0 / /other ro - ext4 /dev/pmem0 ro\n") // the same namespace: not read
	process("300", "2", "401 1 7:3 / /run/cxl/fs/x ro,nosuid,nodev - ext4 /dev/loop3 ro,dax=never\n"+
		"402 1 259:0 / /run/cxl/fs/y ro,nosuid,nodev - ext4 /dev/pmem0 rw,dax=always\n")
	write(filepath.Join(proc, "self", "mountinfo"), "")
	sbs, err := k.Superblocks("/dev/pmem0")
	if err != nil {
		t.Fatal(err)
	}
	want := []Superblock{
		{Device: "/dev/pmem0", DevNum: "259:0", Source: "/dev/pmem0", FsType: "ext4", Where: "pid 100 at /var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/c1ae0001-direct"},
		{Device: "/dev/loop3", DevNum: "7:3", Source: "/dev/loop3", FsType: "ext4", ReadOnly: true, Where: "pid 300 at /run/cxl/fs/x"},
	}
	if !reflect.DeepEqual(sbs, want) {
		t.Fatalf("superblocks %+v", sbs)
	}
	if _, err := k.Superblocks("/dev/pmem9"); err == nil {
		t.Fatal("no error for a device without a number")
	}
}

func TestParseFifoEvent(t *testing.T) {
	evt, err := parseFifoEvent(`{"ACTION":"add","SUBSYSTEM":"dax","DEVPATH":"/devices/x","SEQNUM":"7"}`)
	if err != nil || evt.Action != "add" || evt.Subsystem != "dax" || evt.Devpath != "/devices/x" || evt.Seqnum != "7" {
		t.Fatalf("event %+v %v", evt, err)
	}
	if _, err := parseFifoEvent("bogus"); err == nil {
		t.Fatal("a malformed event accepted")
	}
	path := filepath.Join(t.TempDir(), "fifo")
	if err := ensureFifo(path); err != nil {
		t.Fatal(err)
	}
	if err := ensureFifo(path); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(file, nil, 0o644)
	if err := ensureFifo(file); !errors.Is(err, os.ErrExist) {
		t.Fatalf("a file as a fifo: %v", err)
	}
}

// An error of an operation has its kind and its cause, and the message of
// the operation.
func TestKernelError(t *testing.T) {
	err := errorf(ErrNoRoom, "dax0.1: set size %d: %w", 4096, syscall.ENOSPC)
	if !errors.Is(err, ErrNoRoom) || !errors.Is(err, syscall.ENOSPC) || errors.Is(err, ErrBusyOnline) ||
		err.Error() != "dax0.1: set size 4096: no space left on device" {
		t.Fatalf("error %q", err)
	}
	if !isGone(fmt.Errorf("x: %w", os.ErrNotExist)) || !isGone(syscall.ENXIO) || isGone(syscall.EBUSY) {
		t.Fatal("isGone")
	}
	if newErrDecoderHole(nil, err) != nil {
		t.Fatal("a hole without holes")
	}
}
