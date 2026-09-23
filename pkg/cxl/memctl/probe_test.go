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

package memctl

import (
	"errors"
	"os"
	"path/filepath"
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
	t.Cleanup(func() { unix.Close(fd) })
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

func TestProbeAliasing(t *testing.T) {
	if !cacheFlushSupported {
		t.Skip(ErrProbeUnsupported)
	}
	plain, err := unix.Mmap(-1, 0, 64<<20, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Munmap(plain) }()
	if a := probeAliasing(plain); a.Offset != 0 || a.Garbage >= 0 {
		t.Fatalf("aliasing in plain memory: %s", a)
	}

	// 3 x 8 MiB: like a 192 GiB device with 128 GiB distinct, offsets
	// 16 MiB.. alias 0.., and 8 MiB.. alias 0.. too
	a := probeAliasing(aliasedMapping(t, 8<<20, 3))
	if a.Offset != 8<<20 || a.Base != 0 {
		t.Fatalf("expected aliasing at +8 MiB from 0, got %s", a)
	}
	t.Log(a)
}

func TestOpenDaxNode(t *testing.T) {
	node := filepath.Join(t.TempDir(), "dax0.0")
	if err := os.WriteFile(node, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	oldOpen, oldTimeout, oldInterval := openFile, daxOpenTimeout, daxOpenInterval
	t.Cleanup(func() { openFile, daxOpenTimeout, daxOpenInterval = oldOpen, oldTimeout, oldInterval })
	daxOpenTimeout, daxOpenInterval = time.Second, time.Millisecond
	// the character device appears after failing opens
	fails := 0
	openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if fails < 3 {
			fails++
			return nil, &os.PathError{Op: "open", Path: name, Err: unix.ENXIO}
		}
		return os.OpenFile(name, flag, perm)
	}
	f, err := openDaxNode(node)
	if err != nil {
		t.Fatalf("open after ENXIO: %v", err)
	}
	_ = f.Close()
	if fails != 3 {
		t.Fatalf("expected 3 failed opens, got %d", fails)
	}
	// other errors are returned at once
	calls := 0
	openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		calls++
		return nil, &os.PathError{Op: "open", Path: name, Err: unix.EACCES}
	}
	if _, err := openDaxNode(node); !errors.Is(err, unix.EACCES) || calls != 1 {
		t.Fatalf("expected EACCES at once, got %v after %d calls", err, calls)
	}
	// ENXIO until the timeout is returned
	daxOpenTimeout = 20 * time.Millisecond
	openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		return nil, &os.PathError{Op: "open", Path: name, Err: unix.ENXIO}
	}
	if _, err := openDaxNode(node); !errors.Is(err, unix.ENXIO) {
		t.Fatalf("expected ENXIO after the timeout, got %v", err)
	}
}
