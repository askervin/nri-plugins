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
	"slices"
	"testing"
)

func TestParseFsSignature(t *testing.T) {
	for _, tc := range []struct {
		image    []string
		types    []string
		proto    string
		recovery bool
	}{
		{nil, nil, "", false},
		{[]string{"erofs"}, []string{"erofs"}, "", false},
		{[]string{"squashfs"}, []string{"squashfs"}, "", false},
		{[]string{"ext4"}, []string{"ext4"}, "", false},
		{[]string{"ext4-dirty"}, []string{"ext4"}, "", true},
		{[]string{"xfs"}, []string{"xfs"}, "", false},
		{[]string{"btrfs"}, []string{"btrfs"}, "", false},
		{[]string{"gfs2"}, []string{"gfs2"}, "lock_dlm", false},
		{[]string{"gfs2-nolock"}, []string{"gfs2"}, "lock_nolock", false},
		{[]string{"xfs", "ext4"}, []string{"ext4", "xfs"}, "", false},
	} {
		s := parseFsSignature(fsImage(tc.image...))
		if !slices.Equal(s.Types, tc.types) || s.Gfs2LockProto != tc.proto || s.Ext4NeedsRecovery != tc.recovery {
			t.Errorf("%v: %+v", tc.image, s)
		}
	}
	// a gfs2 magic without the superblock meta type is not gfs2
	img := fsImage("gfs2")
	img[65543] = 2
	if s := parseFsSignature(img); len(s.Types) != 0 {
		t.Errorf("gfs2 of meta type 2: %+v", s)
	}
	// a short head matches what it covers
	if s := parseFsSignature(fsImage("ext4", "btrfs")[:4096]); !slices.Equal(s.Types, []string{"ext4"}) {
		t.Errorf("short head: %+v", s)
	}
	if s := parseFsSignature([]byte("XF")); len(s.Types) != 0 {
		t.Errorf("tiny head: %+v", s)
	}
}

func TestFsSignatureType(t *testing.T) {
	const dev = "/dev/pmem0"
	for _, tc := range []struct {
		image    []string
		declared string
		fsType   string
		err      string
	}{
		{[]string{"ext4"}, "", "ext4", ""},
		{[]string{"ext4"}, "ext4", "ext4", ""},
		{[]string{"ext4"}, "xfs", "", "device 0xc1ae0001: /dev/pmem0 has a filesystem of type ext4, not xfs"},                                   // P3
		{[]string{"btrfs"}, "f2fs", "", "device 0xc1ae0001: /dev/pmem0 has a filesystem of type btrfs, not f2fs"},                               // P3 unknown
		{[]string{"xfs", "ext4"}, "xfs", "xfs", ""},                                                                                             // several, declared
		{[]string{"xfs", "ext4"}, "", "", "device 0xc1ae0001: /dev/pmem0 has signatures of several filesystems (ext4, xfs): set device.fsType"}, // P2
		{[]string{"xfs", "ext4"}, "btrfs", "", "has signatures of several filesystems (ext4, xfs)"},
		{nil, "", "", "device 0xc1ae0001: /dev/pmem0 has no filesystem of a type that the plugin knows (erofs, squashfs, ext4, xfs, btrfs or gfs2): set device.fsType"}, // P1
		{nil, "f2fs", "f2fs", ""}, // mounted as declared
		{nil, "xfs", "", "device 0xc1ae0001: /dev/pmem0 has no filesystem of type xfs (no signature of a type that the plugin knows)"}, // P3b
	} {
		got, err := parseFsSignature(fsImage(tc.image...)).fsType(0xc1ae0001, dev, tc.declared)
		if tc.err != "" {
			wantErr(t, err, tc.err)
			continue
		}
		noErr(t, err)
		if got != tc.fsType {
			t.Errorf("%v %q: %s, expected %s", tc.image, tc.declared, got, tc.fsType)
		}
	}
}

func TestFsSignatureCluster(t *testing.T) {
	for _, tc := range []struct {
		image  string
		fsType string
		ok     bool
		why    string
	}{
		{"gfs2", "gfs2", true, ""},
		{"gfs2-nolock", "gfs2", false, "gfs2 with lock_nolock is a single-host filesystem"},
		{"ext4", "ext4", false, "ext4 is a single-host filesystem"},
		{"erofs", "f2fs", false, "f2fs is a single-host filesystem"},
	} {
		ok, why := parseFsSignature(fsImage(tc.image)).cluster(tc.fsType)
		if ok != tc.ok || why != tc.why {
			t.Errorf("%s: %v %q", tc.image, ok, why)
		}
	}
}
