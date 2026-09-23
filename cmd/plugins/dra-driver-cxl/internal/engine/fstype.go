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

package engine

import (
	"fmt"
	"slices"
	"strings"

	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// fsType returns the type of the filesystem of the block device dev of the
// device with the serial with the signatures s and the declared type ("":
// none). A type that the plugin does not know is taken as declared when
// the device has no signature of a known type.
func fsType(s kernel.FsSignature, serial, dev, declared string) (string, error) {
	prefix := "device " + serial + ": "
	switch {
	case len(s.Types) == 1 && (declared == "" || declared == s.Types[0]):
		return s.Types[0], nil
	case len(s.Types) == 1:
		return "", fmt.Errorf("%s%s has a filesystem of type %s, not %s", prefix, dev, s.Types[0], declared)
	case len(s.Types) > 1 && slices.Contains(s.Types, declared):
		return declared, nil
	case len(s.Types) > 1:
		return "", fmt.Errorf("%s%s has signatures of several filesystems (%s): set device.fsType", prefix, dev, strings.Join(s.Types, ", "))
	case declared == "":
		return "", fmt.Errorf("%s%s has no filesystem of a type that the plugin knows (%s): set device.fsType", prefix, dev, listOr(config.KnownFsTypes))
	case config.KnownFsType(declared):
		return "", fmt.Errorf("%s%s has no filesystem of type %s (no signature of a type that the plugin knows)", prefix, dev, declared)
	}
	return declared, nil
}

// cluster returns true if a filesystem of the type with the signatures s
// is a cluster filesystem (gfs2 with lock_dlm), else why it is
// single-host.
func cluster(s kernel.FsSignature, fsType string) (bool, string) {
	switch {
	case !config.FsTypeCluster(fsType):
		return false, fsType + " is a single-host filesystem"
	case s.Gfs2LockProto == kernel.Gfs2LockProtoDLM:
		return true, ""
	case s.Gfs2LockProto == "":
		return false, fsType + " without a lock protocol is a single-host filesystem"
	}
	return false, fsType + " with " + s.Gfs2LockProto + " is a single-host filesystem"
}

// listOr returns the values as "a, b or c".
func listOr(values []string) string {
	if len(values) < 2 {
		return strings.Join(values, "")
	}
	return strings.Join(values[:len(values)-1], ", ") + " or " + values[len(values)-1]
}
