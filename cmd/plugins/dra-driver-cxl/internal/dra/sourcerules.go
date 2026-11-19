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

package dra

import (
	resourcev1 "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// SourceRules are what the two DRA drivers of the process do differently:
// the source of their devices, how an allocation result maps to a memdev and
// a grant, whether the driver publishes the node's ResourceSlice, its CDI
// kind, and the rules that the two drivers apply differently.
type SourceRules struct {
	// Name is the DRA driver name.
	Name string
	// Source is the source of the devices of the driver's grants.
	Source state.Source
	// Publishes: the driver publishes the node's ResourceSlice.
	Publishes bool
	// CDIKind is the kind of the CDI devices of the driver, CDISpecName
	// the name of its spec file.
	CDIKind, CDISpecName string
	// MountsDir is the directory of the node mounts of mode fs of the
	// driver's devices.
	MountsDir string

	// validate returns the Prepare of a claim, every result checked.
	validate func(p *Plugin, claim *resourcev1.ResourceClaim) (*prepare, error)
}

// LocalRules returns the rules of cxl.nri.io: the local memdevs of the node,
// found in the last scan; publishes the node's ResourceSlice; CDI kind
// device.CDIKind; node mounts in mountsDir.
func LocalRules(mountsDir string) SourceRules {
	return SourceRules{
		Name:        device.DriverName,
		Source:      state.SourceLocal,
		Publishes:   true,
		CDIKind:     device.CDIKind,
		CDISpecName: device.ClaimsCDISpecName,
		MountsDir:   mountsDir,
		validate:    (*Plugin).validateLocal,
	}
}

// PoolRules returns the rules of the pool driver name: the devices that a
// pool controller attached to the node for a claim, found by the serial of
// the claim's status data; publishes nothing; CDI kind device.PoolCDIKind;
// node mounts in mountsDir.
func PoolRules(name, mountsDir string) SourceRules {
	return SourceRules{
		Name:        name,
		Source:      state.SourcePool,
		CDIKind:     device.PoolCDIKind,
		CDISpecName: device.PoolCDISpecName,
		MountsDir:   mountsDir,
		validate:    (*Plugin).validatePool,
	}
}

// MountsDirs returns the directories of the node mounts of mode fs of the
// sources of rules, by source (engine.Options.MountsDirs).
func MountsDirs(rules ...SourceRules) map[state.Source]string {
	dirs := map[state.Source]string{}
	for _, r := range rules {
		dirs[r.Source] = r.MountsDir
	}
	return dirs
}

// serialsOf returns the serials of the grants of a preparation, for the log
// lines.
func serialsOf(r *state.Records, prep *state.Preparation) []string {
	var serials []string
	for _, res := range prep.Results {
		if g := grantOf(r, &res); g != nil {
			serials = append(serials, api.FormatSerial(uint64(g.Serial)))
		}
	}
	return serials
}
