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
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/lend"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
)

// The names of the front-end (internal/dra) as the tests use them, and the
// state files of earlier versions that the tests of the start write.

const (
	// localStateFileName is the state file of the local memdevs of an
	// earlier version in the plugin data directory of cxl.nri.io.
	localStateFileName = "localDevices.json"
	// preparedClaimsInfoFileName is the view of the prepared claims of
	// cxl.nri.io with their devices of an earlier version in its plugin
	// data directory.
	preparedClaimsInfoFileName = "preparedClaimsInfo.json"
)

type (
	// PreparedDeviceInfo is a device of a prepared claim of cxl.nri.io.
	PreparedDeviceInfo = state.DeviceInfo
	// preparedPoolDevice is a device of a prepared pool claim.
	preparedPoolDevice = store.PoolDevice
	// lendRecord is the lend of a companion claim.
	lendRecord = lend.Lend
	// lentDevice is a memdev of a companion claim as the lease broker gets
	// it.
	lentDevice = state.DeviceInfo
	// leaseHooks is what the drivers tell the lease broker.
	leaseHooks = lend.LeaseHooks
	// companionLender lends the companion claims of a driver.
	companionLender = dra.Lender
	// podRef identifies a pod.
	podRef = state.PodRef
)

// ptr returns a pointer to v.
func ptr[T any](v T) *T {
	return &v
}
