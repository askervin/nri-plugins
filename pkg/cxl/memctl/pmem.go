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
	"context"
	"fmt"

	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// Region types of cxl create-region -t.
const (
	// RegionRAM is a region of volatile memory.
	RegionRAM = kernel.RegionRAM
	// RegionPmem is a region of persistent memory with an nvdimm region.
	RegionPmem = kernel.RegionPmem
)

// Namespace modes and fsdax maps, as ndctl names them.
const (
	NamespaceFsdax  = kernel.NamespaceFsdax
	NamespaceRaw    = kernel.NamespaceRaw
	NamespaceDevdax = kernel.NamespaceDevdax
	NamespaceSector = kernel.NamespaceSector
	// MapMem keeps the struct pages of an fsdax namespace in system RAM.
	MapMem = kernel.MapMem
	// MapDev keeps them in the namespace itself.
	MapDev = kernel.MapDev
)

// Namespace is a namespace of an nvdimm region:
//   - Name: namespaceN.M
//   - Mode: NamespaceFsdax, NamespaceRaw, NamespaceDevdax or NamespaceSector
//   - Map: MapMem or MapDev of fsdax namespaces
//   - Size: bytes of its block device, of the namespace without one
//   - BlockDevice: /dev/pmemK of fsdax, raw and sector namespaces
//   - Major, Minor: device numbers of the block device
type Namespace struct {
	Name        string `json:"name"`
	Mode        string `json:"mode"`
	Map         string `json:"map,omitempty"`
	Size        uint64 `json:"size"`
	BlockDevice string `json:"blockDevice,omitempty"`
	Major       int    `json:"major,omitempty"`
	Minor       int    `json:"minor,omitempty"`
}

// namespaceOf returns the Namespace of a namespace of package kernel.
func namespaceOf(ns kernel.Namespace) Namespace {
	return Namespace{Name: ns.Name, Mode: ns.Mode, Map: ns.Map, Size: ns.Size, BlockDevice: ns.BlockDevice, Major: ns.Major, Minor: ns.Minor}
}

// namespacesOf returns the Namespaces of namespaces of package kernel.
func namespacesOf(nss []kernel.Namespace) []Namespace {
	var out []Namespace
	for _, ns := range nss {
		out = append(out, namespaceOf(ns))
	}
	return out
}

// PmemRegion is a region of persistent memory of a memdev: the CXL region,
// its nvdimm region and the namespaces of the nvdimm region.
type PmemRegion struct {
	Memdev     string      `json:"memdev"`
	Region     string      `json:"region"`
	NdRegion   string      `json:"ndRegion"`
	Namespaces []Namespace `json:"namespaces"`
}

// FsdaxNamespace returns the first fsdax namespace with map mem, nil if
// there is none.
func FsdaxNamespace(namespaces []Namespace) *Namespace {
	for i := range namespaces {
		if ns := &namespaces[i]; ns.Mode == NamespaceFsdax && ns.Map == MapMem && ns.BlockDevice != "" {
			return ns
		}
	}
	return nil
}

// Persistent tells whether a memdev has persistent memory capacity.
func (mc *Manager) Persistent(memdev string) (bool, error) {
	return mc.kernel().Persistent(memdev)
}

// RootDecoder returns the root decoder whose target list has the host
// bridge of the memdev and that can map regions of the region type
// (RegionRAM or RegionPmem).
func (mc *Manager) RootDecoder(memdev, regionType string) (string, error) {
	return mc.kernel().RootDecoder(memdev, regionType)
}

// NdRegion returns the nvdimm region of a CXL region of persistent memory:
// the nvdimm region with the id of the CXL region.
func (mc *Manager) NdRegion(region string) (string, error) {
	return mc.kernel().NdRegionOf(region)
}

// BlockDeviceInfo returns the device numbers and the size in bytes of a
// block device (/sys/class/block/<name>).
func (mc *Manager) BlockDeviceInfo(name string) (major, minor int, size uint64, err error) {
	return mc.kernel().BlockDeviceInfo(name)
}

// Namespaces returns the namespaces with memory of an nvdimm region, after
// waiting until the region and its namespaces have finished probing.
func (mc *Manager) Namespaces(ctx context.Context, ndregion string) ([]Namespace, error) {
	nss, err := mc.kernel().Namespaces(ctx, ndregion)
	if err != nil {
		return nil, err
	}
	return namespacesOf(nss), nil
}

// CreatePmemRegion creates a region of persistent memory on the memdev
// under the decoder (the root decoder of its host bridge for pmem if ""),
// and returns it with its nvdimm region and namespaces. The memdev is
// enabled if needed; an existing region of the memdev is reused. The
// namespaces are those of the labels of the memdev.
func (mc *Manager) CreatePmemRegion(ctx context.Context, memdev, decoder string) (*PmemRegion, error) {
	return mc.CreatePmemRegionNoted(ctx, memdev, decoder, nil)
}

// CreatePmemRegionNoted is CreatePmemRegion, telling note (nil: none)
// about a region that it creates (not about one that it reuses).
func (mc *Manager) CreatePmemRegionNoted(ctx context.Context, memdev, decoder string, note RegionNote) (*PmemRegion, error) {
	k := mc.kernel()
	if err := k.EnableMemdev(ctx, memdev); err != nil {
		return nil, err
	}
	region := ""
	if rs := mc.Regions(memdev); len(rs) > 0 {
		region = rs[0]
		if !k.IsPmemRegion(region) {
			return nil, fmt.Errorf("%s: %s is not a region of persistent memory", memdev, region)
		}
		mc.logf("%s: reusing %s", memdev, region)
	} else {
		if decoder == "" {
			d, err := k.RootDecoder(memdev, RegionPmem)
			if err != nil {
				return nil, err
			}
			decoder = d
		}
		var err error
		if region, err = mc.createRegion(ctx, memdev, decoder, RegionPmem, 0, note); err != nil {
			return nil, err
		}
	}
	// the nvdimm region appears asynchronously
	nd, err := k.WaitNdRegion(ctx, region)
	if err != nil {
		return nil, err
	}
	ns, err := mc.Namespaces(ctx, nd)
	if err != nil {
		return nil, err
	}
	return &PmemRegion{Memdev: memdev, Region: region, NdRegion: nd, Namespaces: ns}, nil
}

// CreateFsdaxNamespace creates an fsdax namespace with map mem in an
// nvdimm region, or reconfigures the namespace existing ("" for a new
// one) as such, with ndctl create-namespace, and returns it when its
// block device is there. This writes the labels of the region, and
// destroys what the reconfigured namespace had: it is refused unless the
// region has finished probing and has no fsdax namespace, which a writer
// may have formatted.
func (mc *Manager) CreateFsdaxNamespace(ctx context.Context, ndregion, existing string) (*Namespace, error) {
	ns, err := mc.kernel().CreateFsdaxNamespace(ctx, ndregion, existing)
	if err != nil {
		return nil, err
	}
	out := namespaceOf(*ns)
	return &out, nil
}
