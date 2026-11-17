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

package dra

// DeviceInfo is a device of the table of the publisher: its name in the
// ResourceSlice and the device behind it.
type DeviceInfo struct {
	Name string
	// Dev is a *DRAM, *Region, *Memdev or *LeaseToken.
	Dev any
}

// DevicesInfo are the devices of the table of the publisher by name.
type DevicesInfo map[string]*DeviceInfo

// DRAM is the Dev of the DRAM device.
type DRAM struct {
	Nodes []int
	Size  uint64
}

// Region is the Dev of a region device (DeviceTypeRegion).
type Region struct {
	Name     string // regionN
	NumaNode int    // NUMA node of its memory
	Size     uint64 // bytes
	// NodeAffinity are the CPU NUMA nodes of its memdevs, -1 for one not
	// known.
	NodeAffinity []int
}

// Memdev is the Dev of a local memdev device (DeviceTypeMemdev).
type Memdev struct {
	Name         string // memN
	Serial       uint64
	Size         uint64 // RAM capacity, bytes (persistent capacity of a persistent memdev)
	NodeAffinity int    // CPU NUMA node of the memdev, -1 if unknown
	BlockSize    uint64 // memory block size, bytes: slices are multiples of it
	Shared       bool   // published shared: one devdax device for all claims
	// Persistent is true for a memdev of persistent memory: modes block
	// and fs, one pmem region for all claims.
	Persistent bool
}

// LeaseToken is the Dev of the lease device: it has no hardware, no
// capacity and can be allocated any number of times.
type LeaseToken struct{}
