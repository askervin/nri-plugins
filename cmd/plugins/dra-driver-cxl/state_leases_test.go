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
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
)

// The content of leases.json as the driver before the state store wrote
// it, and its records: the lease broker keeps its records in the store
// (internal/leases), and the store writes leases.json as their view; the
// tests compare that view with the old content.

// putLeasesContent replaces the lease claims and the leases in doc
// with those of the content of leases.json.
func putLeasesContent(doc *store.Document, data []byte) error {
	var ls leaseStore
	if err := json.Unmarshal(data, &ls); err != nil {
		return err
	}
	return putLeases(doc, &ls)
}

// leaseClaim is a prepared claim on the lease device: it owns the socket
// <data dir>/leases/<uid>/cxl.sock and, when FsDir is set, the directory
// of the mounts of its fs leases, <data dir>/lease-fs/<uid>, which its
// containers have at api.FsDir. A claim prepared without FsDir has
// containers without that mount.
type leaseClaim struct {
	UID       string   `json:"uid"`
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Pods      []podRef `json:"pods"` // reservedFor at Prepare (refreshed on demand)
	FsDir     string   `json:"fsDir,omitempty"`
}

// lease is one request of a container. A lease is stored in state
// Creating before any API object exists, so that a restart can clean up
// after a crash. The states are api.State*; Released is never stored.
type lease struct {
	ID string `json:"id"`
	// Claim is the uid of the lease claim whose socket received it.
	Claim     string `json:"claim"`
	RequestID string `json:"requestId,omitempty"`
	// Source is the requested source ("": local, then pool), and the
	// source of the device once Ready.
	Source string `json:"source,omitempty"`
	Mode   string `json:"mode"`   // effective: api.ModeNUMA, api.ModeDax, api.ModeBlock or api.ModeFs
	Shared bool   `json:"shared"` // one share of a shared device
	// SharedDevice is true when the device of the lease is a shared
	// device: one share of it when Shared, the whole device otherwise.
	SharedDevice bool `json:"sharedDevice,omitempty"`
	// DeviceSource is the source of the device that Serial names when
	// a ResourceSlice has it and no source was requested, "" otherwise.
	DeviceSource string `json:"deviceSource,omitempty"`
	ReadOnly     bool   `json:"readOnly,omitempty"` // dax, block: the fd is opened read-only; fs: !ReadWrite
	// ReadWrite is the opt-in of an fs lease to mount the filesystem
	// read-write.
	ReadWrite bool   `json:"readWrite,omitempty"`
	Access    string `json:"access,omitempty"` // fs: api.AccessDirect or api.AccessCached, "" by type until Ready
	// FsType is the filesystem type of an fs lease: the requested one ("":
	// detect), the one mounted once Ready.
	FsType string `json:"fsType,omitempty"`
	// Name is the mount point of an fs lease in api.FsDir, unique among
	// the leases of the lease claim.
	Name string `json:"name,omitempty"`
	// Path is the directory of the filesystem of a Ready fs lease in the
	// container, api.FsDir/<Name>.
	Path string `json:"path,omitempty"`
	Size string `json:"size,omitempty"` // requested quantity
	// Serial is 0x<lower-case hex>: the requested device, or the device
	// of a Ready lease.
	Serial    string `json:"serial,omitempty"`
	Pod       podRef `json:"pod"`
	Container string `json:"container"`
	State     string `json:"state"`
	Error     string `json:"error,omitempty"`
	Node      int    `json:"node"` // lent NUMA node, -1 if none
	Bytes     uint64 `json:"bytes,omitempty"`
	Dax       string `json:"dax,omitempty"` // /dev/daxX.Y (dax mode)
	// Block is the host path of the block device of a Ready block lease,
	// /dev/pmemK.
	Block   string    `json:"block,omitempty"`
	Created time.Time `json:"created"`
}

// leaseStore is the persisted lease table. Not safe for concurrent use:
// the broker serializes access with its mutex.
type leaseStore struct {
	Claims map[string]*leaseClaim `json:"claims"` // lease claim uid -> ...
	Leases map[string]*lease      `json:"leases"` // lease id -> ...
	// BootID is the boot id of the kernel of the leases: a lease does not
	// survive a reboot (forgetOtherBoot), its lease claim does.
	BootID string `json:"bootID,omitempty"`
	// Recovered is true when the stored table could not be decoded and
	// the store started empty: the lease claims of the node are unknown.
	Recovered bool `json:"-"`
}

// leaseStates are the lease states by the protocol's names.
var leaseStates = map[string]state.LeaseState{
	api.StateCreating:  state.LeaseCreating,
	api.StatePending:   state.LeasePending,
	api.StateLending:   state.LeaseLending,
	api.StateReady:     state.LeaseReady,
	api.StateReleasing: state.LeaseReleasing,
	api.StateFailed:    state.LeaseFailed,
}

// putLeases replaces the lease claims and the leases in doc with those of
// the content of leases.json.
func putLeases(doc *store.Document, s *leaseStore) error {
	doc.LeaseClaims, doc.Leases = nil, nil
	if s.BootID != "" {
		doc.BootID = s.BootID
	}
	for _, uid := range slices.Sorted(maps.Keys(s.Claims)) {
		c := s.Claims[uid]
		if c == nil {
			continue
		}
		lc := state.LeaseClaim{UID: c.UID, Namespace: c.Namespace, Name: c.Name, FsDir: c.FsDir, State: state.LeaseClaimOpen}
		for _, p := range c.Pods {
			lc.Pods = append(lc.Pods, state.PodRef(p))
		}
		doc.LeaseClaims = append(doc.LeaseClaims, lc)
	}
	for _, id := range slices.Sorted(maps.Keys(s.Leases)) {
		l := s.Leases[id]
		if l == nil {
			continue
		}
		rec, err := leaseRecord(l)
		if err != nil {
			return err
		}
		doc.Leases = append(doc.Leases, rec)
	}
	return nil
}

// leaseRecord returns the lease record of a lease of leases.json: what a
// lease that got its device has of it (bytes, a device path, a directory)
// are its Got as well.
func leaseRecord(l *lease) (state.Lease, error) {
	st, ok := leaseStates[l.State]
	if !ok {
		return state.Lease{}, fmt.Errorf("lease %s: state %q", l.ID, l.State)
	}
	rec := state.Lease{
		ID:        l.ID,
		Claim:     l.Claim,
		RequestID: l.RequestID,
		Pod:       state.PodRef(l.Pod),
		Container: l.Container,
		State:     st,
		Error:     l.Error,
		Created:   l.Created,
		Asked: state.LeaseAsked{
			Source:       state.Source(l.Source),
			DeviceSource: state.Source(l.DeviceSource),
			Mode:         state.Mode(l.Mode),
			Shared:       l.Shared,
			SharedDevice: l.SharedDevice,
			ReadOnly:     l.ReadOnly,
			ReadWrite:    l.ReadWrite,
			Access:       state.Access(l.Access),
			FsType:       l.FsType,
			Name:         l.Name,
			Size:         l.Size,
			Serial:       parseSerial(l.Serial),
		},
	}
	if l.Bytes != 0 || l.Dax != "" || l.Block != "" || l.Path != "" {
		rec.Got = &state.LeaseGot{
			Source:       state.Source(l.Source),
			Serial:       parseSerial(l.Serial),
			SharedDevice: l.SharedDevice,
			Bytes:        l.Bytes,
			Dax:          l.Dax,
			Block:        l.Block,
			Access:       state.Access(l.Access),
			FsType:       l.FsType,
			Path:         l.Path,
		}
	}
	if l.Node >= 0 {
		rec.Lend = &state.Lend{NumaNode: state.NumaNodePtr(l.Node)}
	}
	return rec, nil
}
