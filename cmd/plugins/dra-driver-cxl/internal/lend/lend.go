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

// Package lend has the types that the DRA drivers and the lease broker
// exchange about the companion claims of leases and the claims on the
// lease device.
package lend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	resourcev1 "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
)

// Lend is the lend of a companion claim: the lease and its requester, the
// NUMA nodes lent and the lease binds, as the views of the claim give it.
type Lend struct {
	Lease     string       `json:"lease"`
	Pod       state.PodRef `json:"pod"`
	Container string       `json:"container"`
	NumaNodes []int        `json:"nodes,omitempty"` // lent NUMA nodes
	// FsDir is the host directory of the mounts of the fs leases of the
	// lease claim, "" for other leases and for a lease claim without it.
	FsDir string `json:"fsDir,omitempty"`
	// Name is the mount point of an fs lease in FsDir.
	Name string `json:"name,omitempty"`
	// Mounts are the host paths of the binds of the node mounts of the fs
	// devices in FsDir.
	Mounts []string `json:"mounts,omitempty"`
}

// LeaseHooks is what a driver tells the lease broker about companion
// claims. The hooks are called with the driver's claim locked and must not
// call back into the driver.
type LeaseHooks interface {
	// OnLending checks that the claim is the companion of the lease,
	// marks the lease Lending and returns the lend of the lease's
	// container (without nodes). An error fails the Prepare.
	OnLending(id string, claim *resourcev1.ResourceClaim) (*Lend, error)
	// OnPrepared marks the lease Ready with the prepared memdevs of the
	// companion claim, of the source.
	OnPrepared(id string, source state.Source, devs []state.DeviceInfo)
	// OnLendFailed records a lend error (kubelet retries the Prepare).
	OnLendFailed(id string, err error)
	// OnReleasing is called when the companion claim is unprepared.
	OnReleasing(id string)
}

// SpecHasher is the part of the hooks that tells the hash of the spec of
// the companion claim of a lease that the hooks recorded when they made the
// claim ("" for none, then no comparison), and whether the lease waits for
// its first Prepare (CREATING or PENDING).
type SpecHasher interface {
	CompanionSpecHash(lease string) (hash string, first bool)
}

// LeaseClaims is what cxl.nri.io needs from the lease broker for claims on
// the lease device.
type LeaseClaims interface {
	// OpenClaim records the claim and starts its socket. Idempotent.
	OpenClaim(claim *resourcev1.ResourceClaim) error
	// CloseClaim releases every lease of the claim, waits (bounded) until
	// their nodes are revoked and the deletion of their companions is
	// requested, then stops the socket and removes the directories.
	// Unknown claims are not an error.
	CloseClaim(ctx context.Context, uid string) error
}

// ErrLendingUnavailable is the error of a lend without NRI.
var ErrLendingUnavailable = errors.New("lending unavailable: NRI not connected")

// SpecHashVersion is the version of SpecHash; a recorded hash of another
// version is not compared.
const SpecHashVersion = "v1:"

// SpecHash returns the hash of the spec of a claim, of version
// SpecHashVersion: the SHA-256 of its JSON.
func SpecHash(spec *resourcev1.ResourceClaimSpec) string {
	data, err := json.Marshal(spec)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return SpecHashVersion + hex.EncodeToString(sum[:])
}
