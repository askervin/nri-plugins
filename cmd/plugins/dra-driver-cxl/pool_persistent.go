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
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/pkg/cxl/api"
)

// Pool devices of persistent memory: the pool driver gives a container the
// block device of the fsdax namespace of the device (mode block), or a
// filesystem on it (mode fs) through a node mount per device and access
// that the claims of the node share (docs/memory/cxl/usage.md), made by the
// device engine. An fs lease gets a bind of the node mount in the lease-fs
// directory of its lease claim, which propagates into the running
// containers of the claim (docs/memory/cxl/leases.md).

// defaultFsPathDir is the directory of the default path of mode fs in
// containers, /run/cxl-fs/<KEY>.
const defaultFsPathDir = "/run/cxl-fs"

// persistentMode tells whether a mode is a mode of persistent devices.
func persistentMode(mode string) bool {
	return mode == api.ModeBlock || mode == api.ModeFs
}

// defaultFsPath returns the path of mode fs of the memory with the env key
// in a container when its device settings have none.
func defaultFsPath(key string) string {
	return defaultFsPathDir + "/" + key
}

// fsMount returns the CDI mount of the node mount of a device in mode fs.
func fsMount(d *preparedPoolDevice) *cdiSpecs.Mount {
	return fsCDIMount(d.NodeMount, d.Path, d.ReadOnly)
}
