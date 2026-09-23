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
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ErrProbeUnsupported is returned by ProbeAliasing on architectures where
// cache lines cannot be flushed.
var ErrProbeUnsupported = errors.New("address aliasing probe is not supported on this architecture")

// Aliasing is the result of an address line probe of memory.
type Aliasing struct {
	// Offset is the smallest power of two P for which offsets X and X+P
	// reach the same memory, 0 if no aliasing was found. The memory
	// holds Offset distinct bytes at most: only [0, Offset) can be used.
	Offset uint64
	// Base is the first offset X where it was seen.
	Base uint64
	// Garbage is the offset of a marker that read back neither as written
	// nor as the marker of an alias, -1 if none.
	Garbage int64
}

const (
	probeMarker = 0x5a17c0ffee000000
	probePage   = 4096
)

// probeBases are the offsets below every power of two that the probe
// writes markers at: the start, an odd page, and a few far from the start.
var probeBases = []uint64{0, 3 * probePage, 5 << 20, 7<<30 + 5*probePage, 33<<30 + 11*probePage}

// A dax device that the kernel binds to device_dax by itself has its
// driver link before device_dax has added its character device: until
// then an open fails with ENXIO. The probe tries again every
// daxOpenInterval for daxOpenTimeout.
var (
	daxOpenTimeout  = 5 * time.Second
	daxOpenInterval = 10 * time.Millisecond
	// openFile opens a file (a variable for tests).
	openFile = os.OpenFile
)

// ProbeAliasing runs an address line test (memtest86 "walking ones") on
// the memory of a dax device: for every power of two P from 4 KiB up to
// the size of the device and a few base offsets X below it, it writes a
// marker at X, another one at X+P, and reads X back. If X holds the marker
// of X+P, both reach the same memory: the device or the platform ignores
// the address bit log2(P). Every store and load bypasses the CPU caches
// (cache lines are flushed), so that a dirty line of an aliased address
// cannot hide the aliasing. The probe overwrites 16 bytes at a few hundred
// offsets: run it before the memory is in use. Takes milliseconds.
func (mc *Manager) ProbeAliasing(dax string) (*Aliasing, error) {
	if !cacheFlushSupported {
		return nil, ErrProbeUnsupported
	}
	size, err := mc.DaxDeviceSize(dax)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return &Aliasing{Garbage: -1}, nil
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
	f, err := openDaxNode(node)
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

// openDaxNode opens the device node of a dax device for reading and
// writing, trying again while the character device is not there yet.
func openDaxNode(node string) (*os.File, error) {
	deadline := time.Now().Add(daxOpenTimeout)
	for {
		f, err := openFile(node, os.O_RDWR, 0)
		notYet := errors.Is(err, unix.ENXIO) || errors.Is(err, unix.ENODEV)
		if !notYet || !time.Now().Before(deadline) {
			return f, err
		}
		time.Sleep(daxOpenInterval)
	}
}

// probeAliasing runs the address line test on mapped memory.
func probeAliasing(mem []byte) *Aliasing {
	size := uint64(len(mem))
	res := &Aliasing{Garbage: -1}
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
	for p := uint64(probePage); p < size; p <<= 1 {
		for _, b := range probeBases {
			if b+p+8 > size || b >= p {
				continue
			}
			store(b, probeMarker|1)
			store(b+p, probeMarker|2)
			switch v := load(b); v {
			case probeMarker | 1:
			case probeMarker | 2:
				if res.Offset == 0 {
					res.Offset, res.Base = p, b
				}
			default:
				if res.Garbage < 0 {
					res.Garbage = int64(b)
				}
			}
		}
		if res.Offset != 0 {
			break
		}
	}
	return res
}

func (a *Aliasing) String() string {
	switch {
	case a == nil:
		return "not probed"
	case a.Offset != 0:
		return fmt.Sprintf("offsets %#x and %#x reach the same memory (address bit %d is ignored): only the first %d bytes are distinct",
			a.Base, a.Base+a.Offset, bitIndex(a.Offset), a.Offset)
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
