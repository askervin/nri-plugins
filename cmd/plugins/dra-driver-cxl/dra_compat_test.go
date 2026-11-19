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
	"context"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/containers"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// The names of the front-end (internal/dra) as the tests of the driver
// package use them.

type (
	localSnapshot = dra.LocalSnapshot
	localUse      = dra.LocalUse
)

var (
	memdevDeviceName  = dra.MemdevDeviceName
	localMemdevDevice = dra.LocalMemdevDevice
	resultEnvVarName  = state.ResultEnvVarName
	daxDeviceNode     = dra.DaxDeviceNode
	blockDeviceNode   = dra.BlockDeviceNode
	fsCDIMount        = dra.FsCDIMount
)

var (
	poolDataFor         = device.PoolStatus
	parsePoolDeviceData = device.ParsePoolStatusData
)

// lendOf returns the lend of the prepared companion claim uid of the
// driver p, nil for another claim.
func lendOf(p *dra.Plugin, uid string) *lendRecord {
	if info := p.ClaimInfo(uid); info != nil {
		return info.Lend
	}
	return nil
}

// buildDevInfos returns the devices that the publisher publishes of the
// observation of the node with the configuration, the pool serials and the
// uses of the local memdevs.
func buildDevInfos(cfg *DriverConfig, detected *kernel.Snapshot, poolSerials map[uint64]bool, local *localSnapshot) (dra.DevicesInfo, error) {
	return dra.BuildDevices(cfg.publishConfig(), detected, poolSerials, nil, local), nil
}

// buildDevInfosHeld is buildDevInfos with the serials of the new memdevs
// that are held.
func buildDevInfosHeld(cfg *DriverConfig, detected *kernel.Snapshot, poolSerials, held map[uint64]bool, local *localSnapshot) (dra.DevicesInfo, error) {
	return dra.BuildDevices(cfg.publishConfig(), detected, poolSerials, held, local), nil
}

// observedMemdev returns an observed memdev with a driver, of RAM capacity
// ram and with the CPU NUMA node affinity.
func observedMemdev(name string, serial, ram uint64, affinity int) kernel.MemdevInfo {
	return kernel.MemdevInfo{Name: name, Serial: serial, State: kernel.MemdevReady, RamSize: ram, NodeAffinity: affinity}
}

// observedRegion adds a region of the mode and of size bytes on the memdevs
// with the serials to the snapshot s, after the ranges of its regions:
// enabled on node, a RAM region with its memory blocks online on node;
// disabled without memory for node -1. The block size of s is
// localBlockSize unless it has one.
func observedRegion(s *kernel.Snapshot, name, mode string, node int, size uint64, serials ...uint64) {
	if s.BlockSize == 0 {
		s.BlockSize = localBlockSize
	}
	start := uint64(0)
	for _, r := range s.Regions {
		start = max(start, (r.Range.End+s.BlockSize)/s.BlockSize*s.BlockSize)
	}
	r := kernel.RegionInfo{Name: name, State: kernel.RegionEnabled, Mode: mode, NumaNode: node,
		Range: kernel.Range{Start: start, End: start + size - 1}, Serials: serials}
	if node < 0 {
		r.State = kernel.RegionDisabled
	} else {
		s.DaxDevices = append(s.DaxDevices, kernel.DaxDeviceInfo{Name: "dax-" + name, Region: name, Size: size, TargetNode: node})
	}
	if node >= 0 && mode == kernel.RegionRAM {
		for _, b := range r.Range.Blocks(s.BlockSize) {
			s.Blocks = append(s.Blocks, kernel.MemoryBlock{Index: b, State: kernel.BlockOnline, NumaNode: node})
		}
	}
	s.Regions = append(s.Regions, r)
}

// poolNumaNodes returns the NUMA nodes of the memory of the claims of the
// pool driver p that the engine onlined.
func poolNumaNodes(p *dra.Plugin) []int {
	if p == nil {
		return nil
	}
	return dra.NumaNodes(p.Records(), p.Name())
}

// prepareOn prepares a claim on the plugin p as kubelet does and returns
// its error.
func prepareOn(ctx context.Context, p *dra.Plugin, claim *resourceapi.ResourceClaim) error {
	return prepareResultOn(ctx, p, claim).Err
}

// prepareResultOn prepares a claim on the plugin p as kubelet does and
// returns its result.
func prepareResultOn(ctx context.Context, p *dra.Plugin, claim *resourceapi.ResourceClaim) kubeletplugin.PrepareResult {
	res, err := p.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim})
	if err != nil {
		return kubeletplugin.PrepareResult{Err: err}
	}
	return res[claim.UID]
}

// unprepareOn unprepares the claim uid on the plugin p as kubelet does and
// returns its error.
func unprepareOn(ctx context.Context, p *dra.Plugin, uid string) error {
	res, err := p.UnprepareResourceClaims(ctx, []kubeletplugin.NamespacedObject{{UID: types.UID(uid)}})
	if err != nil {
		return err
	}
	return res[types.UID(uid)]
}

// setNRI makes the Prepares of the plugin p wait for the first Synchronize
// of the NRI plugin nri, nil for none.
func setNRI(p *dra.Plugin, nri *containers.Plugin) {
	if nri == nil {
		p.SetWaitNRI(nil)
		return
	}
	p.SetWaitNRI(func(ctx context.Context) error { return waitNRI(ctx, nri) })
}

// leaseOf returns the lease id of a companion claim, "" for other claims.
func leaseOf(claim *resourceapi.ResourceClaim) string {
	return dra.LeaseOf(claim)
}
