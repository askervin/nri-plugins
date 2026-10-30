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
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// aliasedMapping maps the same size bytes of a memfd n times in a row: the
// mapping has n*size bytes, and offsets X and X+size reach the same memory,
// as on a device that ignores the address bit log2(size).
func aliasedMapping(t *testing.T, size, n int) []byte {
	chunks := make([]int, n)
	return chunkMapping(t, size, size, chunks)
}

// chunkMapping maps chunks of chunk bytes of a memfd of size bytes in a
// row: chunk i of the mapping is the memfd at offset chunks[i]*chunk.
func chunkMapping(t *testing.T, size, chunk int, chunks []int) []byte {
	fd, err := unix.MemfdCreate("probe-test", 0)
	if err != nil {
		t.Skipf("memfd_create: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Ftruncate(fd, int64(size)); err != nil {
		t.Fatal(err)
	}
	all, err := unix.Mmap(-1, 0, chunk*len(chunks), unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Munmap(all) })
	base := uintptr(unsafe.Pointer(&all[0]))
	for i, c := range chunks {
		_, _, errno := unix.Syscall6(unix.SYS_MMAP, base+uintptr(i*chunk), uintptr(chunk),
			unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_FIXED, uintptr(fd), uintptr(c*chunk))
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
	if a.Offset != 8<<20 || a.Base != 0 || a.Bit != 23 {
		t.Fatalf("expected aliasing at +8 MiB from 0, got %s", a)
	}
	t.Log(a)

	// 4 chunks of 256 MiB, the last one is the first one again: not a
	// power of two apart, like the 256 MiB at 126 GiB of a 128 GiB
	// region on real hardware
	a = probeAliasing(chunkMapping(t, 3*probeGrid, probeGrid, []int{0, 1, 2, 0}))
	if a.Offset != 3*probeGrid || a.Base != probeGridDelta || a.Alias != 3*probeGrid+probeGridDelta || a.Bit != -1 {
		t.Fatalf("expected chunk 3 to alias chunk 0, got %s", a)
	}
	t.Log(a)
}
