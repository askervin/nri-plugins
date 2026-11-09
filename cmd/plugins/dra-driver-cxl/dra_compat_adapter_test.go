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
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
)

// The names of the front-end (internal/dra) as the adapters of the state
// files of the tests use them, and the shapes of those state files.

const (
	// preparedClaimsInfoFileName is the view of the prepared claims of
	// cxl.nri.io with their devices in its plugin data directory.
	preparedClaimsInfoFileName = "preparedClaimsInfo.json"
)

type (
	// PreparedDeviceInfo is a device of a prepared claim of cxl.nri.io.
	PreparedDeviceInfo = dra.DeviceInfo
	// PreparedClaimInfo is a prepared claim of cxl.nri.io with its devices.
	PreparedClaimInfo = dra.ClaimInfo
	// PreparedClaimsInfo is preparedClaimsInfo.json: the prepared claims of
	// cxl.nri.io by UID.
	PreparedClaimsInfo map[string]*PreparedClaimInfo
	// claimPreparations is preparedClaims.json: the PrepareResults of the
	// prepared claims of cxl.nri.io by UID.
	claimPreparations map[string]kubeletplugin.PrepareResult
	// preparedPoolDevice is a device of a prepared pool claim.
	preparedPoolDevice = dra.PoolDevice
	// lendRecord is the lend of a companion claim.
	lendRecord = dra.Lend
	// lentDevice is a device of a companion claim as the lease broker
	// needs it.
	lentDevice = dra.LentDevice
	// leaseHooks is what the drivers tell the lease broker.
	leaseHooks = dra.LeaseHooks
	// companionLender lends the companion claims of a driver.
	companionLender = dra.Lender
	// podRef identifies a pod.
	podRef = state.PodRef
)

// preparedPoolClaim is a value of preparedPoolClaims.json.
type preparedPoolClaim struct {
	ClaimName string                      `json:"claimName"` // namespace/name
	Devices   []preparedPoolDevice        `json:"devices"`
	Result    kubeletplugin.PrepareResult `json:"result"` // what Prepare returned
	Lend      *lendRecord                 `json:"lend,omitempty"`
	// BootID is the boot id of the kernel that the claim was prepared in.
	BootID string `json:"bootID,omitempty"`
}

// ptr returns a pointer to v.
func ptr[T any](v T) *T {
	return &v
}
