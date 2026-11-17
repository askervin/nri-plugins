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

package config

import (
	"github.com/containers/nri-plugins/pkg/cxl/api"
)

// The classes of filesystem types.
const (
	// fsClassReadOnly is never mounted read-write; any number of hosts
	// may mount it read-only.
	fsClassReadOnly = "read-only"
	// fsClassSingleHost is read-write on one host only, and read-only on
	// several hosts only while no host has it read-write.
	fsClassSingleHost = "single-host"
	// fsClassCluster may be read-write on several hosts at a time, on
	// memory that is coherent between them.
	fsClassCluster = "cluster"
)

// fsType is what the drivers know of a filesystem type.
type fsType struct {
	class string
	dax   bool
}

// fsTypes are the known filesystem types (api.KnownFsTypes) by name.
var fsTypes = map[string]fsType{
	api.FsTypeErofs:    {class: fsClassReadOnly, dax: true},
	api.FsTypeSquashfs: {class: fsClassReadOnly},
	api.FsTypeExt4:     {class: fsClassSingleHost, dax: true},
	api.FsTypeXfs:      {class: fsClassSingleHost, dax: true},
	api.FsTypeBtrfs:    {class: fsClassSingleHost},
	api.FsTypeGfs2:     {class: fsClassCluster},
}

// fsTypeClass returns the class of a filesystem type: fsClassReadOnly,
// fsClassSingleHost or fsClassCluster; fsClassSingleHost for a type that
// the drivers do not know.
func fsTypeClass(name string) string {
	if t, ok := fsTypes[name]; ok {
		return t.class
	}
	return fsClassSingleHost
}

// FsTypeReadOnly returns true if a filesystem of the type is never
// mounted read-write (erofs, squashfs).
func FsTypeReadOnly(name string) bool {
	return fsTypeClass(name) == fsClassReadOnly
}

// FsTypeCluster returns true if the type is a cluster filesystem (gfs2).
func FsTypeCluster(name string) bool {
	return fsTypeClass(name) == fsClassCluster
}

// FsTypeDAX returns true if a filesystem of the type can be mounted with
// access direct (erofs, ext4, xfs).
func FsTypeDAX(name string) bool {
	return fsTypes[name].dax
}

// FsTypeUpgradable returns true if a read-only superblock of the type that
// was mounted on a read-only block device can be made read-write in place
// once the block device is writable (ext4, xfs; btrfs keeps its device
// open read-only, gfs2 mounts read-only claims as spectator).
func FsTypeUpgradable(name string) bool {
	return name == api.FsTypeExt4 || name == api.FsTypeXfs
}

// FsMountData returns the mount options that the plugin passes when it
// mounts a filesystem of the type, as "key" or "key=value" items in
// order: dax=always (access direct) or dax=never (access cached) for the
// DAX types, nouuid for read-only xfs, spectator for read-only gfs2;
// none for other types.
func FsMountData(name, access string, readOnly bool) []string {
	var data []string
	if FsTypeDAX(name) {
		if access == api.AccessDirect {
			data = append(data, "dax=always")
		} else {
			data = append(data, "dax=never")
		}
	}
	switch {
	case !readOnly:
	case name == api.FsTypeXfs:
		data = append(data, "nouuid")
	case name == api.FsTypeGfs2:
		data = append(data, "spectator")
	}
	return data
}
