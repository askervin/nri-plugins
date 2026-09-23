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
	"strings"
	"testing"

	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// The type of the filesystem of a block device from its signatures and
// the declared type, with the texts of the refusals (P1, P2, P3).
func TestFsSignatureType(t *testing.T) {
	const dev = "/dev/pmem0"
	for _, tc := range []struct {
		types    []string
		declared string
		fsType   string
		err      string
	}{
		{[]string{"ext4"}, "", "ext4", ""},
		{[]string{"ext4"}, "ext4", "ext4", ""},
		{[]string{"ext4"}, "xfs", "", "device 0xc1ae0001: /dev/pmem0 has a filesystem of type ext4, not xfs"},                                   // P3
		{[]string{"btrfs"}, "f2fs", "", "device 0xc1ae0001: /dev/pmem0 has a filesystem of type btrfs, not f2fs"},                               // P3 unknown
		{[]string{"ext4", "xfs"}, "xfs", "xfs", ""},                                                                                             // several, declared
		{[]string{"ext4", "xfs"}, "", "", "device 0xc1ae0001: /dev/pmem0 has signatures of several filesystems (ext4, xfs): set device.fsType"}, // P2
		{[]string{"ext4", "xfs"}, "btrfs", "", "has signatures of several filesystems (ext4, xfs)"},
		{nil, "", "", "device 0xc1ae0001: /dev/pmem0 has no filesystem of a type that the plugin knows (erofs, squashfs, ext4, xfs, btrfs or gfs2): set device.fsType"}, // P1
		{nil, "f2fs", "f2fs", ""}, // mounted as declared
		{nil, "xfs", "", "device 0xc1ae0001: /dev/pmem0 has no filesystem of type xfs (no signature of a type that the plugin knows)"}, // P3b
	} {
		got, err := fsType(kernel.FsSignature{Types: tc.types}, "0xc1ae0001", dev, tc.declared)
		switch {
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%v %q: error %v, expected %q", tc.types, tc.declared, err, tc.err)
		case tc.err == "" && err != nil:
			t.Errorf("%v %q: %v", tc.types, tc.declared, err)
		case tc.err == "" && got != tc.fsType:
			t.Errorf("%v %q: %s, expected %s", tc.types, tc.declared, got, tc.fsType)
		}
	}
}

// A cluster filesystem is gfs2 with lock_dlm; the others are single-host,
// and the reason says why.
func TestFsSignatureCluster(t *testing.T) {
	for _, tc := range []struct {
		sig    kernel.FsSignature
		fsType string
		ok     bool
		why    string
	}{
		{kernel.FsSignature{Types: []string{"gfs2"}, Gfs2LockProto: kernel.Gfs2LockProtoDLM}, "gfs2", true, ""},
		{kernel.FsSignature{Types: []string{"gfs2"}, Gfs2LockProto: "lock_nolock"}, "gfs2", false, "gfs2 with lock_nolock is a single-host filesystem"},
		{kernel.FsSignature{Types: []string{"gfs2"}}, "gfs2", false, "gfs2 without a lock protocol is a single-host filesystem"},
		{kernel.FsSignature{Types: []string{"ext4"}}, "ext4", false, "ext4 is a single-host filesystem"},
		{kernel.FsSignature{Types: []string{"erofs"}}, "f2fs", false, "f2fs is a single-host filesystem"},
	} {
		if ok, why := cluster(tc.sig, tc.fsType); ok != tc.ok || why != tc.why {
			t.Errorf("%+v %s: %v %q", tc.sig, tc.fsType, ok, why)
		}
	}
}
