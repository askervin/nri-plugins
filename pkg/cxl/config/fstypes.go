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
	"slices"

	"github.com/containers/nri-plugins/pkg/cxl/api"
)

// The filesystem types that the plugin knows.
const (
	FsTypeErofs    = "erofs"
	FsTypeSquashfs = "squashfs"
	FsTypeExt4     = "ext4"
	FsTypeXfs      = "xfs"
	FsTypeBtrfs    = "btrfs"
	FsTypeGfs2     = "gfs2"
)

// The classes of filesystem types.
const (
	// FsClassReadOnly is never mounted read-write; any number of hosts
	// may mount it read-only.
	FsClassReadOnly = "read-only"
	// FsClassSingleHost is read-write on one host only, and read-only on
	// several hosts only while no host has it read-write.
	FsClassSingleHost = "single-host"
	// FsClassCluster may be read-write on several hosts at a time, on
	// memory that is coherent between them.
	FsClassCluster = "cluster"
)

// KnownFsTypes are the filesystem types that the plugin knows, the
// default of the driver configuration fsTypes.
var KnownFsTypes = []string{FsTypeErofs, FsTypeSquashfs, FsTypeExt4, FsTypeXfs, FsTypeBtrfs, FsTypeGfs2}

// fsType is what the plugin knows of a filesystem type.
type fsType struct {
	class string
	dax   bool
}

// fsTypes are the known filesystem types by name.
var fsTypes = map[string]fsType{
	FsTypeErofs:    {class: FsClassReadOnly, dax: true},
	FsTypeSquashfs: {class: FsClassReadOnly},
	FsTypeExt4:     {class: FsClassSingleHost, dax: true},
	FsTypeXfs:      {class: FsClassSingleHost, dax: true},
	FsTypeBtrfs:    {class: FsClassSingleHost},
	FsTypeGfs2:     {class: FsClassCluster},
}

// ValidFsType returns true if name is a valid filesystem type name
// (^[a-z0-9][a-z0-9_-]{0,31}$).
func ValidFsType(name string) bool {
	return api.ValidFsType(name)
}

// KnownFsType returns true if the plugin knows the filesystem type.
func KnownFsType(name string) bool {
	return slices.Contains(KnownFsTypes, name)
}

// FsTypeClass returns the class of a filesystem type: FsClassReadOnly,
// FsClassSingleHost or FsClassCluster; FsClassSingleHost for a type that
// the plugin does not know. A gfs2 filesystem whose superblock has lock
// protocol lock_nolock is single-host although its type is cluster.
func FsTypeClass(name string) string {
	if t, ok := fsTypes[name]; ok {
		return t.class
	}
	return FsClassSingleHost
}

// FsTypeReadOnly returns true if a filesystem of the type is never
// mounted read-write (erofs, squashfs).
func FsTypeReadOnly(name string) bool {
	return FsTypeClass(name) == FsClassReadOnly
}

// FsTypeCluster returns true if the type is a cluster filesystem (gfs2).
func FsTypeCluster(name string) bool {
	return FsTypeClass(name) == FsClassCluster
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
	return name == FsTypeExt4 || name == FsTypeXfs
}

// FsMountData returns the mount options that the plugin passes when it
// mounts a filesystem of the type, as "key" or "key=value" items in
// order: dax=always (access direct) or dax=never (access cached) for the
// DAX types, nouuid for read-only xfs, spectator for read-only gfs2;
// none for other types.
func FsMountData(name, access string, readOnly bool) []string {
	var data []string
	if FsTypeDAX(name) {
		if access == AccessDirect {
			data = append(data, "dax=always")
		} else {
			data = append(data, "dax=never")
		}
	}
	switch {
	case !readOnly:
	case name == FsTypeXfs:
		data = append(data, "nouuid")
	case name == FsTypeGfs2:
		data = append(data, "spectator")
	}
	return data
}
