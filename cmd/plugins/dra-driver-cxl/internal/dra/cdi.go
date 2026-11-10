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
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strconv"

	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// The CDI spec of a driver: one device claim-<uid>-<n> per allocation
// result n of every claim that the driver has prepared, but companion
// claims and claims whose devices did not verify at a start: the result
// marker CXL_CLAIM_<uid>_<n>, the environment of the result's memory
// (api.Env), the device node of a dax or block device and the bind mount of
// the node mount of an fs device. It is built from the records (not from
// the existing file), so it is right also after a restart, and the same
// for both drivers but its kind and file name.

// ClaimCDIDeviceName returns the CDI device name of the allocation result n
// of a claim: "claim-<uid>-<n>".
func ClaimCDIDeviceName(claimUID string, n int) string {
	return "claim-" + claimUID + "-" + strconv.Itoa(n)
}

// envKeys counts the memories of each base env key in one claim.
type envKeys map[string]int

// next returns the env key of the next memory with the base key: the base
// key for the first one, then "<base>_<n>" (api.Nth).
func (k envKeys) next(base string) string {
	k[base]++
	return api.Nth(base, k[base])
}

// DaxDeviceNode returns the CDI device node of a devdax device. A read-only
// node has permissions "r": the runtime turns that into a device cgroup
// rule that refuses opens for writing, whatever the container's
// capabilities.
func DaxDeviceNode(path string, major, minor int, readOnly bool) *cdiSpecs.DeviceNode {
	node := &cdiSpecs.DeviceNode{
		Path:  path,
		Type:  "c",
		Major: int64(major),
		Minor: int64(minor),
	}
	if readOnly {
		node.Permissions = "r"
	}
	return node
}

// BlockDeviceNode returns the CDI device node of a block device, with
// permissions "r" when read-only.
func BlockDeviceNode(dev string, major, minor int, readOnly bool) *cdiSpecs.DeviceNode {
	node := &cdiSpecs.DeviceNode{Path: dev, Type: "b", Major: int64(major), Minor: int64(minor)}
	if readOnly {
		node.Permissions = "r"
	}
	return node
}

// FsCDIMount returns the CDI mount of a node mount at path in a container:
// options bind, ro, nosuid, nodev, without ro for a use that writes.
func FsCDIMount(nodeMount, path string, readOnly bool) *cdiSpecs.Mount {
	options := []string{"bind", "ro", "nosuid", "nodev"}
	if !readOnly {
		options = []string{"bind", "nosuid", "nodev"}
	}
	return &cdiSpecs.Mount{HostPath: nodeMount, ContainerPath: path, Type: "bind", Options: options}
}

// cdiClaims tells whether the CDI spec of a driver has the devices of a
// preparation: a claim that is not a companion, PREPARED, or the claim
// pending whose Prepare is finishing, or UNPREPARING when the driver keeps
// those (unpreparing).
func cdiClaims(prep *state.Preparation, pending string, unpreparing bool) bool {
	switch {
	case prep.Lease != "":
		return false
	case prep.UID == pending, prep.State == state.PreparationPrepared:
		return true
	}
	return unpreparing && prep.State == state.PreparationUnpreparing
}

// buildCDISpec returns the CDI spec of the kind of the claims of the driver
// in doc that cdiClaims takes.
func buildCDISpec(doc *store.Document, driver, kind string, opts store.ResultOptions, pending string, unpreparing bool) (*cdiSpecs.Spec, error) {
	spec := &cdiSpecs.Spec{Kind: kind}
	byUID := map[string]*state.Preparation{}
	for i := range doc.Preparations {
		prep := &doc.Preparations[i]
		if prep.Driver == driver && cdiClaims(prep, pending, unpreparing) {
			byUID[prep.UID] = prep
		}
	}
	var errs []error
	for _, uid := range slices.Sorted(maps.Keys(byUID)) {
		info, err := claimInfoOf(doc, byUID[uid], opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("claim %s: %w", byUID[uid].ClaimName, err))
			continue
		}
		keys := envKeys{}
		for i := range info.Devices {
			spec.Devices = append(spec.Devices, cdiDevice(uid, &info.Devices[i], keys))
		}
	}
	return spec, errors.Join(errs...)
}

// cdiDevice returns the CDI device of a prepared device of the claim uid,
// with the env key of its memory from keys.
func cdiDevice(uid string, d *state.DeviceInfo, keys envKeys) cdiSpecs.Device {
	env := map[string]string{state.ResultEnvVarName(uid, d.Result): "1"}
	edits := cdiSpecs.ContainerEdits{}
	if m, ok := deviceMemory(d, keys); ok {
		maps.Copy(env, api.Env(m))
	}
	switch {
	case d.Mode == api.ModeDax && d.DaxDevice != "":
		edits.DeviceNodes = []*cdiSpecs.DeviceNode{DaxDeviceNode(d.DaxDevice, d.DaxMajor, d.DaxMinor, d.ReadOnly)}
	case d.Persistent && d.Mode == api.ModeBlock:
		edits.DeviceNodes = []*cdiSpecs.DeviceNode{BlockDeviceNode(d.BlockDevice, d.BlockMajor, d.BlockMinor, d.ReadOnly)}
	case d.Persistent && d.Mode == api.ModeFs:
		edits.Mounts = []*cdiSpecs.Mount{FsCDIMount(d.NodeMount, d.Path, d.ReadOnly)}
	}
	edits.Env = api.EnvList(env)
	return cdiSpecs.Device{Name: ClaimCDIDeviceName(uid, d.Result), ContainerEdits: edits}
}

// writeCDISpec writes a CDI spec file of the cache, or removes it when the
// spec has no devices, in the words of the driver's voice v.
func writeCDISpec(cache *cdiapi.Cache, spec *cdiSpecs.Spec, name string, v voice) error {
	if len(spec.Devices) == 0 {
		v.cdiRemoved(name, cache.RemoveSpec(name))
		return nil
	}
	version, err := cdiapi.MinimumRequiredVersion(spec)
	if err != nil {
		return v.cdiVersionError(err)
	}
	spec.Version = version
	if err := cache.WriteSpec(spec, name); err != nil {
		return v.cdiWriteError(name, err)
	}
	v.cdiWrote(name, len(spec.Devices))
	return nil
}

// RemoveCXLSpecs removes the CDI specs of kinds device.CDIKind and
// device.PoolCDIKind from the spec directory that the CDI cache writes to.
func RemoveCXLSpecs(cache *cdiapi.Cache) error {
	var errs []error
	for _, spec := range cache.GetVendorSpecs(device.CDIVendor) {
		if spec.Kind != device.CDIKind && spec.Kind != device.PoolCDIKind {
			continue
		}
		if err := cache.RemoveSpec(filepath.Base(spec.GetPath())); err != nil {
			errs = append(errs, fmt.Errorf("failed to remove old CDI spec %s: %w", spec.GetPath(), err))
		}
	}
	return errors.Join(errs...)
}
