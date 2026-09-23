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

package provenance

import (
	"encoding/json"
	"fmt"

	resourcev1 "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/pkg/cxl/api"
)

// The status data of a pool device: claim.status.devices[].data that the
// pool controller writes with the Attached condition (the contract of
// docs/memory/cxl/pool.md). It is the evidence of a pool claim of the node
// and what the pool driver prepares.

// statusData is the JSON of the status data. Serial, shared and size are
// required; exclusive (a shared device whose claim consumed all of its
// shares), persistent, singleHost (no other host has the device while the
// claim is allocated) and coherent (other hosts' writes are visible without
// cache maintenance) are false when missing.
type statusData struct {
	Serial     string  `json:"serial"`
	Shared     *bool   `json:"shared"`
	Size       *uint64 `json:"size"`
	Exclusive  bool    `json:"exclusive"`
	Persistent bool    `json:"persistent"`
	SingleHost bool    `json:"singleHost"`
	Coherent   bool    `json:"coherent"`
}

// DeviceData is the parsed status data of a pool device.
type DeviceData struct {
	Serial     uint64
	Shared     bool
	Size       uint64
	Exclusive  bool
	Persistent bool
	SingleHost bool
	Coherent   bool
}

// StatusData returns the status data of an allocation result of a claim,
// from its entry in claim.status.devices (matched by driver, pool and
// device), and an error if it has none or it does not parse.
func StatusData(claim *resourcev1.ResourceClaim, r *resourcev1.DeviceRequestAllocationResult) (*DeviceData, error) {
	for _, st := range claim.Status.Devices {
		if st.Driver != r.Driver || st.Pool != r.Pool || st.Device != r.Device {
			continue
		}
		if st.Data == nil || len(st.Data.Raw) == 0 {
			return nil, fmt.Errorf("status of device %s/%s has no data (written by the pool controller with the Attached condition)", r.Pool, r.Device)
		}
		return ParseDeviceData(st.Data.Raw)
	}
	return nil, fmt.Errorf("claim status has no entry for device %s/%s (not attached by the pool controller yet?)", r.Pool, r.Device)
}

// ParseDeviceData returns the status data of a pool device of its JSON.
func ParseDeviceData(raw []byte) (*DeviceData, error) {
	var d statusData
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("invalid device data %s: %w", string(raw), err)
	}
	if d.Serial == "" || d.Shared == nil || d.Size == nil {
		return nil, fmt.Errorf("device data %s: serial, shared and size are required", string(raw))
	}
	serial, err := api.ParseSerial(d.Serial)
	if err != nil {
		return nil, fmt.Errorf("device data: %w", err)
	}
	return &DeviceData{Serial: serial, Shared: *d.Shared, Size: *d.Size, Exclusive: d.Exclusive, Persistent: d.Persistent,
		SingleHost: d.SingleHost, Coherent: d.Coherent}, nil
}
