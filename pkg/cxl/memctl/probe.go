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
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ErrProbeUnsupported is returned by ProbeAliasing on architectures where
// cache lines cannot be flushed.
var ErrProbeUnsupported = errors.New("address aliasing probe is not supported on this architecture")

// Aliasing is the result of an aliasing probe of memory.
type Aliasing struct {
	// Offset is where the usable memory ends, 0 if no aliasing was
	// found: offsets Base and Alias reach the same memory, Alias is the
	// higher one, and only [0, Offset) can be used without using both.
	// Offset is Alias rounded down to probeGrid (256 MiB, the alignment
	// of CXL regions), or the power of two of an ignored address bit.
	Offset uint64
	// Base and Alias are the first pair of offsets that reach the same
	// memory.
	Base, Alias uint64
	// Bit is the ignored address bit when the aliasing is a power of two
	// apart, -1 otherwise.
	Bit int
	// Garbage is the offset of a marker that read back neither as written
	// nor as the marker of an alias, -1 if none.
	Garbage int64
}

const (
	probeMarker = 0x5a17c0ffee000000
	probePage   = 4096
	// probeGrid is the stride of the own-address pass: CXL regions and
	// their remapping are 256 MiB granular.
	probeGrid = 256 << 20
	// probeGridDelta is where in every probeGrid chunk the own-address
	// pass writes, away from the probeBases.
	probeGridDelta = 3<<20 + 3*64
	// probeGridMarker marks the records of the own-address pass.
	probeGridMarker = 0x6a17c0ffee000000
)

// probeBases are the offsets below every power of two that the address
// line test writes markers at: the start, an odd page, and a few far from
// the start.
var probeBases = []uint64{0, 3 * probePage, 5 << 20, 7<<30 + 5*probePage, 33<<30 + 11*probePage}

// ProbeAliasing finds aliasing in the memory of a dax device, offsets
// that reach the same memory, with two passes:
//
//   - Address line test (memtest86 "walking ones"): for every power of
//     two P from 4 KiB up to the size and a few base offsets X below it,
//     write a marker at X, another one at X+P, and read X back. If X
//     holds the marker of X+P, the address bit log2(P) is ignored.
//   - Own-address test on a 256 MiB grid: write its own offset at the
//     same place of every 256 MiB chunk, then read them all back. A chunk
//     that holds the offset of another chunk is the same memory as that
//     chunk. This finds remapped chunks that are not a power of two
//     apart.
//
// Every store and load bypasses the CPU caches (cache lines are flushed),
// so that a dirty line of an aliased address cannot hide the aliasing.
// The probe overwrites 8 bytes at a few hundred offsets: run it before the
// memory is in use. Takes milliseconds.
func (mc *Manager) ProbeAliasing(dax string) (*Aliasing, error) {
	if !cacheFlushSupported {
		return nil, ErrProbeUnsupported
	}
	size, err := mc.DaxDeviceSize(dax)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return &Aliasing{Bit: -1, Garbage: -1}, nil
	}
	major, minor, err := mc.DaxDevNumbers(dax)
	if err != nil {
		return nil, err
	}
	// a device node of our own: the container may have no /dev/daxX.Y
	dir, err := os.MkdirTemp(mc.DevRoot, ".cxl-probe-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	node := filepath.Join(dir, dax)
	if err := unix.Mknod(node, unix.S_IFCHR|0o600, int(unix.Mkdev(uint32(major), uint32(minor)))); err != nil {
		return nil, fmt.Errorf("mknod %s: %w", node, err)
	}
	f, err := os.OpenFile(node, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	mem, err := unix.Mmap(int(f.Fd()), 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap %s: %w", dax, err)
	}
	defer func() { _ = unix.Munmap(mem) }()
	return probeAliasing(mem), nil
}

// probeAliasing runs both passes on mapped memory.
func probeAliasing(mem []byte) *Aliasing {
	size := uint64(len(mem))
	res := &Aliasing{Bit: -1, Garbage: -1}
	word := func(off uint64) *uint64 { return (*uint64)(unsafe.Pointer(&mem[off])) }
	store := func(off, v uint64) {
		atomic.StoreUint64(word(off), v)
		flushLine(uintptr(unsafe.Pointer(&mem[off])))
		memoryFence()
	}
	load := func(off uint64) uint64 {
		flushLine(uintptr(unsafe.Pointer(&mem[off])))
		memoryFence()
		return atomic.LoadUint64(word(off))
	}
	found := func(base, alias, usable uint64, bit int) {
		if res.Offset == 0 || usable < res.Offset {
			res.Offset, res.Base, res.Alias, res.Bit = usable, base, alias, bit
		}
	}
	garbage := func(off uint64) {
		if res.Garbage < 0 {
			res.Garbage = int64(off)
		}
	}

	// address line test
	for p := uint64(probePage); p < size; p <<= 1 {
		hit := false
		for _, b := range probeBases {
			if b+p+8 > size || b >= p {
				continue
			}
			store(b, probeMarker|1)
			store(b+p, probeMarker|2)
			switch v := load(b); v {
			case probeMarker | 1:
			case probeMarker | 2:
				if !hit {
					found(b, b+p, p, bitIndex(p))
					hit = true
				}
			default:
				garbage(b)
			}
		}
		if hit {
			break
		}
	}

	// own-address test on a grid
	var offs []uint64
	for off := uint64(probeGridDelta); off+8 <= size; off += probeGrid {
		offs = append(offs, off)
		store(off, probeGridMarker^off)
	}
	for _, off := range offs {
		v := load(off)
		if v == probeGridMarker^off {
			continue
		}
		other := v ^ probeGridMarker
		if other < size && other%probeGrid == probeGridDelta && other != off {
			lo, hi := min(off, other), max(off, other)
			found(lo, hi, hi/probeGrid*probeGrid, -1)
			continue
		}
		garbage(off)
	}
	return res
}

func (a *Aliasing) String() string {
	switch {
	case a == nil:
		return "not probed"
	case a.Offset != 0 && a.Bit >= 0:
		return fmt.Sprintf("offsets %#x and %#x reach the same memory (address bit %d is ignored): only the first %d bytes are distinct",
			a.Base, a.Alias, a.Bit, a.Offset)
	case a.Offset != 0:
		return fmt.Sprintf("offsets %#x and %#x reach the same memory: only the first %d bytes are usable",
			a.Base, a.Alias, a.Offset)
	case a.Garbage >= 0:
		return fmt.Sprintf("no aliasing, but offset %#x did not read back what was written", a.Garbage)
	}
	return "no aliasing"
}

func bitIndex(p uint64) int {
	n := 0
	for p > 1 {
		p >>= 1
		n++
	}
	return n
}
