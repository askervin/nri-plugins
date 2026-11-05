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

package store

import (
	"time"

	"github.com/containers/nri-plugins/pkg/cxl/config"
)

// The types below have the JSON shapes of the five files that test90's
// observer reads, in their established format, field by field: a view must
// decode into them strictly.

type oldPodRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

type oldLendRecord struct {
	Lease     string    `json:"lease"`
	Pod       oldPodRef `json:"pod"`
	Container string    `json:"container"`
	Nodes     []int     `json:"nodes,omitempty"`
	FsDir     string    `json:"fsDir,omitempty"`
	Name      string    `json:"name,omitempty"`
	Mounts    []string  `json:"mounts,omitempty"`
}

type oldPreparedDeviceInfo struct {
	RequestName    string `json:"requestName"`
	DeviceName     string `json:"deviceName"`
	Result         int    `json:"result"`
	DeviceType     string `json:"deviceType"`
	Mode           string `json:"mode,omitempty"`
	SysfsPath      string `json:"sysfsPath,omitempty"`
	NUMANodes      []int  `json:"numaNodes"`
	NodeAffinities []int  `json:"nodeAffinities,omitempty"`
	TotalBytes     uint64 `json:"totalBytes"`
	ConsumedBytes  int64  `json:"consumedBytes"`
	Serial         string `json:"serial,omitempty"`
	Region         string `json:"region,omitempty"`
	DaxDevice      string `json:"daxDevice,omitempty"`
	DaxMajor       int    `json:"daxMajor,omitempty"`
	DaxMinor       int    `json:"daxMinor,omitempty"`
	ReadOnly       bool   `json:"readOnly,omitempty"`
	Shared         bool   `json:"shared,omitempty"`
	Persistent     bool   `json:"persistent,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	BlockDevice    string `json:"blockDevice,omitempty"`
	BlockMajor     int    `json:"blockMajor,omitempty"`
	BlockMinor     int    `json:"blockMinor,omitempty"`
	Access         string `json:"access,omitempty"`
	Path           string `json:"path,omitempty"`
	NodeMount      string `json:"nodeMount,omitempty"`
	LoopDevice     string `json:"loopDevice,omitempty"`
	FsType         string `json:"fsType,omitempty"`
	config.ResultSettings
}

type oldPreparedClaimInfo struct {
	ClaimName string                  `json:"claimName"`
	Devices   []oldPreparedDeviceInfo `json:"devices"`
	Lend      *oldLendRecord          `json:"lend,omitempty"`
	BootID    string                  `json:"bootID,omitempty"`
}

type oldPreparedPoolDevice struct {
	Result      int    `json:"result"`
	Request     string `json:"request"`
	Device      string `json:"device"`
	Pool        string `json:"pool"`
	Serial      uint64 `json:"serial"`
	Shared      bool   `json:"shared"`
	Size        uint64 `json:"size"`
	Mode        string `json:"mode"`
	ReadOnly    bool   `json:"readOnly,omitempty"`
	Memdev      string `json:"memdev"`
	Region      string `json:"region"`
	Dax         string `json:"dax"`
	DaxDevice   string `json:"daxDevice,omitempty"`
	DaxMajor    int    `json:"daxMajor,omitempty"`
	DaxMinor    int    `json:"daxMinor,omitempty"`
	Node        int    `json:"node"`
	Persistent  bool   `json:"persistent,omitempty"`
	NdRegion    string `json:"ndRegion,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	BlockDevice string `json:"blockDevice,omitempty"`
	BlockMajor  int    `json:"blockMajor,omitempty"`
	BlockMinor  int    `json:"blockMinor,omitempty"`
	Access      string `json:"access,omitempty"`
	FsType      string `json:"fsType,omitempty"`
	Path        string `json:"path,omitempty"`
	NodeMount   string `json:"nodeMount,omitempty"`
	LoopDevice  string `json:"loopDevice,omitempty"`
	config.ResultSettings
}

type oldDevice struct {
	Requests     []string
	PoolName     string
	DeviceName   string
	CDIDeviceIDs []string
	ShareID      *string
	Metadata     *struct{}
}

type oldPrepareResult struct {
	Err     *struct{}
	Devices []oldDevice
}

type oldPreparedPoolClaim struct {
	ClaimName string                  `json:"claimName"`
	Devices   []oldPreparedPoolDevice `json:"devices"`
	Result    oldPrepareResult        `json:"result"`
	Lend      *oldLendRecord          `json:"lend,omitempty"`
	BootID    string                  `json:"bootID,omitempty"`
}

// oldLocalUse is a value of the claims of a memdev in localDevices.json.
type oldLocalUse struct {
	Request    string `json:"request"`
	Result     int    `json:"result,omitempty"`
	Region     string `json:"region"`
	Mode       string `json:"mode"`
	Size       uint64 `json:"size"`
	Dax        string `json:"dax,omitempty"`
	DaxDevice  string `json:"daxDevice,omitempty"`
	Major      int    `json:"major,omitempty"`
	Minor      int    `json:"minor,omitempty"`
	ReadOnly   bool   `json:"readOnly,omitempty"`
	Access     string `json:"access,omitempty"`
	FsType     string `json:"fsType,omitempty"`
	NodeMount  string `json:"nodeMount,omitempty"`
	LoopDevice string `json:"loopDevice,omitempty"`
	Path       string `json:"path,omitempty"`
}

type oldLocalDevice struct {
	Serial      uint64                    `json:"serial"`
	SerialHex   string                    `json:"serialHex"`
	Memdev      string                    `json:"memdev"`
	Region      string                    `json:"region,omitempty"`
	Creating    string                    `json:"creating,omitempty"`
	Node        int                       `json:"node"`
	Dax         string                    `json:"dax,omitempty"`
	Shared      bool                      `json:"shared,omitempty"`
	Persistent  bool                      `json:"persistent,omitempty"`
	NdRegion    string                    `json:"ndRegion,omitempty"`
	Namespace   string                    `json:"namespace,omitempty"`
	BlockDevice string                    `json:"blockDevice,omitempty"`
	BlockMajor  int                       `json:"blockMajor,omitempty"`
	BlockMinor  int                       `json:"blockMinor,omitempty"`
	Claims      map[string][]*oldLocalUse `json:"claims"`
}

type oldLocalState struct {
	BootID  string            `json:"bootID"`
	Devices []*oldLocalDevice `json:"devices"`
}

type oldLeaseClaim struct {
	UID       string      `json:"uid"`
	Namespace string      `json:"namespace"`
	Name      string      `json:"name"`
	Pods      []oldPodRef `json:"pods"`
	FsDir     string      `json:"fsDir,omitempty"`
}

type oldLease struct {
	ID           string    `json:"id"`
	Claim        string    `json:"claim"`
	RequestID    string    `json:"requestId,omitempty"`
	Source       string    `json:"source,omitempty"`
	Mode         string    `json:"mode"`
	Shared       bool      `json:"shared"`
	SharedDevice bool      `json:"sharedDevice,omitempty"`
	DeviceSource string    `json:"deviceSource,omitempty"`
	ReadOnly     bool      `json:"readOnly,omitempty"`
	ReadWrite    bool      `json:"readWrite,omitempty"`
	Access       string    `json:"access,omitempty"`
	FsType       string    `json:"fsType,omitempty"`
	Name         string    `json:"name,omitempty"`
	Path         string    `json:"path,omitempty"`
	Size         string    `json:"size,omitempty"`
	Serial       string    `json:"serial,omitempty"`
	Pod          oldPodRef `json:"pod"`
	Container    string    `json:"container"`
	State        string    `json:"state"`
	Error        string    `json:"error,omitempty"`
	Node         int       `json:"node"`
	Bytes        uint64    `json:"bytes,omitempty"`
	Dax          string    `json:"dax,omitempty"`
	Block        string    `json:"block,omitempty"`
	Created      time.Time `json:"created"`
}

type oldLeaseStore struct {
	Claims map[string]*oldLeaseClaim `json:"claims"`
	Leases map[string]*oldLease      `json:"leases"`
	BootID string                    `json:"bootID,omitempty"`
}
