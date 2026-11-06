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

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
)

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

// putSteered replaces the steering records in doc with those of the content
// of steeredContainers.json.
func putSteered(doc *store.Document, ids map[string]string) {
	doc.Steered = nil
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		doc.Steered = append(doc.Steered, state.Steered{Container: id, CgroupDir: ids[id]})
	}
}

// steeredContent returns the content of steeredContainers.json of the
// records in doc.
func steeredContent(doc *store.Document) ([]byte, error) {
	ids := map[string]string{}
	for _, s := range doc.Steered {
		ids[s.Container] = s.CgroupDir
	}
	return json.MarshalIndent(ids, "", "  ")
}
