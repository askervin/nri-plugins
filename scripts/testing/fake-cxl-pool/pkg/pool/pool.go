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

// Package pool manages fake-cxl-pool memory pools: directories of device
// backing files with capacity accounting, and device serial numbers.
package pool

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
)

// Pool is a directory of backing files with a capacity limit.
type Pool struct {
	Name     string
	Dir      string
	Capacity int64
	Sharable bool

	mu   sync.Mutex
	used map[string]int64 // device name -> size
}

// New returns a pool.
func New(name, dir string, capacity int64, sharable bool) *Pool {
	return &Pool{Name: name, Dir: dir, Capacity: capacity, Sharable: sharable, used: map[string]int64{}}
}

// Used returns the sum of the sizes of the devices in the pool.
func (p *Pool) Used() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	var total int64
	for _, s := range p.used {
		total += s
	}
	return total
}

// Free returns the remaining capacity.
func (p *Pool) Free() int64 {
	return p.Capacity - p.Used()
}

// Reserve accounts a device of the size in the pool. Reserving an already
// reserved name updates its size.
func (p *Pool) Reserve(device string, size int64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var total int64
	for n, s := range p.used {
		if n != device {
			total += s
		}
	}
	if p.Capacity > 0 && total+size > p.Capacity {
		return fmt.Errorf("pool %q: not enough capacity for %d bytes (capacity %d, used %d)", p.Name, size, p.Capacity, total)
	}
	p.used[device] = size
	return nil
}

// Unreserve removes a device from the pool accounting.
func (p *Pool) Unreserve(device string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, device)
}

// Devices returns the names of the reserved devices.
func (p *Pool) Devices() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for n := range p.used {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// FilePath returns the default backing file path of a device.
func (p *Pool) FilePath(device string) string {
	return filepath.Join(p.Dir, device+".raw")
}

// EnsureDir creates the pool directory.
func (p *Pool) EnsureDir() error {
	return os.MkdirAll(p.Dir, 0o755)
}

// EnsureBackingFile creates the backing file (and its directory) if it is
// missing, and extends it (sparse) if it is smaller than size. An existing
// larger file is left as is: qemu maps only size bytes of it.
func EnsureBackingFile(path string, size int64) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("backing file %s is not a regular file", path)
	}
	if st.Size() < size {
		if err := f.Truncate(size); err != nil {
			return err
		}
	}
	return nil
}

// RemoveBackingFile removes a backing file. A missing file is not an error.
func RemoveBackingFile(path string) error {
	err := os.Remove(path)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`)

// ValidName returns an error unless name is a DNS-label-like device name
// (lowercase letters, digits, '-' and '.').
func ValidName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid name %q: use lowercase letters, digits, '-' and '.', at most 63 characters", name)
	}
	return nil
}

// Serials allocates serial numbers from a base.
type Serials struct {
	mu   sync.Mutex
	base uint64
	used map[uint64]string // serial -> device
}

// NewSerials returns a serial allocator.
func NewSerials(base uint64) *Serials {
	return &Serials{base: base, used: map[uint64]string{}}
}

// Use marks a serial used by a device. It fails if another device has it.
func (s *Serials) Use(serial uint64, device string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.used[serial]; ok && d != device {
		return fmt.Errorf("serial 0x%x is already used by device %q", serial, d)
	}
	s.used[serial] = device
	return nil
}

// Release frees a serial.
func (s *Serials) Release(serial uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.used, serial)
}

// Next allocates the lowest free serial above the base for a device.
func (s *Serials) Next(device string) uint64 {
	return s.NextExcept(device, nil)
}

// NextExcept is Next that also skips the serials for which skip is true.
func (s *Serials) NextExcept(device string, skip func(uint64) bool) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sn := s.base + 1; ; sn++ {
		if _, ok := s.used[sn]; !ok && (skip == nil || !skip(sn)) {
			s.used[sn] = device
			return sn
		}
	}
}

// Owner returns the device that uses the serial.
func (s *Serials) Owner(serial uint64) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.used[serial]
	return d, ok
}
