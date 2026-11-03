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
	"reflect"
	"strings"
	"testing"
)

func TestKnownFsTypes(t *testing.T) {
	want := []string{"erofs", "squashfs", "ext4", "xfs", "btrfs", "gfs2"}
	if !reflect.DeepEqual(KnownFsTypes, want) {
		t.Fatalf("KnownFsTypes %v, expected %v", KnownFsTypes, want)
	}
	if len(fsTypes) != len(KnownFsTypes) {
		t.Fatalf("%d types in the table, %d known", len(fsTypes), len(KnownFsTypes))
	}
	for _, name := range KnownFsTypes {
		if !KnownFsType(name) || !ValidFsType(name) {
			t.Errorf("%s: known %v, valid %v", name, KnownFsType(name), ValidFsType(name))
		}
	}
	for _, name := range []string{"", "ext2", "f2fs", "tmpfs", "EXT4"} {
		if KnownFsType(name) {
			t.Errorf("%q is known", name)
		}
	}
}

func TestFsTypeTable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		class    string
		readOnly bool
		dax      bool
		cluster  bool
	}{
		{"erofs", FsClassReadOnly, true, true, false},
		{"squashfs", FsClassReadOnly, true, false, false},
		{"ext4", FsClassSingleHost, false, true, false},
		{"xfs", FsClassSingleHost, false, true, false},
		{"btrfs", FsClassSingleHost, false, false, false},
		{"gfs2", FsClassCluster, false, false, true},
		{"f2fs", FsClassSingleHost, false, false, false},
		{"ocfs2", FsClassSingleHost, false, false, false},
		{"", FsClassSingleHost, false, false, false},
	} {
		class, readOnly, dax, cluster := FsTypeClass(tc.name), FsTypeReadOnly(tc.name), FsTypeDAX(tc.name), FsTypeCluster(tc.name)
		if class != tc.class || readOnly != tc.readOnly || dax != tc.dax || cluster != tc.cluster {
			t.Errorf("%q: class %s read-only %v DAX %v cluster %v, expected %s %v %v %v",
				tc.name, class, readOnly, dax, cluster, tc.class, tc.readOnly, tc.dax, tc.cluster)
		}
	}
}

func TestFsMountData(t *testing.T) {
	for _, tc := range []struct {
		name     string
		access   string
		readOnly bool
		want     string
	}{
		{"erofs", AccessDirect, true, "dax=always"},
		{"erofs", AccessCached, true, "dax=never"},
		{"squashfs", AccessCached, true, ""},
		{"ext4", AccessDirect, true, "dax=always"},
		{"ext4", AccessCached, true, "dax=never"},
		{"ext4", AccessDirect, false, "dax=always"},
		{"ext4", AccessCached, false, "dax=never"},
		{"xfs", AccessDirect, true, "dax=always,nouuid"},
		{"xfs", AccessCached, true, "dax=never,nouuid"},
		{"xfs", AccessDirect, false, "dax=always"},
		{"xfs", AccessCached, false, "dax=never"},
		{"btrfs", AccessCached, true, ""},
		{"btrfs", AccessCached, false, ""},
		{"gfs2", AccessCached, true, "spectator"},
		{"gfs2", AccessCached, false, ""},
		{"f2fs", AccessCached, true, ""},
		{"f2fs", AccessCached, false, ""},
	} {
		if got := strings.Join(FsMountData(tc.name, tc.access, tc.readOnly), ","); got != tc.want {
			t.Errorf("%s %s read-only %v: data %q, expected %q", tc.name, tc.access, tc.readOnly, got, tc.want)
		}
	}
}

func TestValidFsType(t *testing.T) {
	for name, want := range map[string]bool{
		"ext4": true, "9p": true, "my_fs-2": true, "a": true, strings.Repeat("z", 32): true,
		"": false, "Ext4": false, "_a": false, "-a": false, "fuse.x": false, "a b": false, strings.Repeat("z", 33): false,
	} {
		if got := ValidFsType(name); got != want {
			t.Errorf("ValidFsType(%q) = %v", name, got)
		}
	}
}

func TestFsTypeUpgradable(t *testing.T) {
	for name, want := range map[string]bool{"ext4": true, "xfs": true, "btrfs": false, "gfs2": false, "erofs": false, "squashfs": false, "f2fs": false} {
		if got := FsTypeUpgradable(name); got != want {
			t.Errorf("FsTypeUpgradable(%q) = %v", name, got)
		}
	}
}
