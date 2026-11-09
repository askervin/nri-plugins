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
	"encoding/json"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/containers"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/provenance"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/device"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
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
	poolDataFor         = provenance.StatusData
	parsePoolDeviceData = provenance.ParseDeviceData
)

// lendOf returns the lend of a companion claim as preparedPoolClaims.json
// has it, nil for another claim.
func lendOf(doc *store.Document, prep *state.Preparation) *lendRecord {
	var rec *lendRecord
	data, err := store.PoolLendContent(doc, prep)
	if err == nil {
		err = json.Unmarshal(data, &rec)
	}
	if err != nil {
		panic(err)
	}
	return rec
}

// buildDevInfos returns the devices that the publisher publishes of the
// detected devices with the configuration, the pool serials and the uses of
// the local memdevs.
func buildDevInfos(cfg *DriverConfig, detected *nricxl.Devices, poolSerials map[uint64]bool, local *localSnapshot) (device.DevicesInfo, error) {
	return dra.BuildDevices(cfg.publishConfig(), detected, poolSerials, nil, local), nil
}

// buildDevInfosHeld is buildDevInfos with the serials of the new memdevs
// that are held.
func buildDevInfosHeld(cfg *DriverConfig, detected *nricxl.Devices, poolSerials, held map[uint64]bool, local *localSnapshot) (device.DevicesInfo, error) {
	return dra.BuildDevices(cfg.publishConfig(), detected, poolSerials, held, local), nil
}

// claimCDIDeviceID returns the qualified CDI device name of the allocation
// result n of a claim of cxl.nri.io.
func claimCDIDeviceID(claimUID string, n int) string {
	return device.CDIKind + "=" + dra.ClaimCDIDeviceName(claimUID, n)
}

// poolCDIDeviceID returns the qualified CDI device name of the allocation
// result n of a claim of the pool driver.
func poolCDIDeviceID(claimUID string, n int) string {
	return device.PoolCDIKind + "=" + dra.ClaimCDIDeviceName(claimUID, n)
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
