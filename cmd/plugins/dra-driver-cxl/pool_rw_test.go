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
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"
)

const (
	// a share of a shared persistent device whose attachment is exclusive
	// to the node (ReadWriteOnce)
	singleHostData = `{"serial":"0xc1ae0001","shared":true,"size":536870912,"persistent":true,"singleHost":true}`
	// a share of a shared persistent device on coherent memory
	coherentData = `{"serial":"0xc1ae0001","shared":true,"size":536870912,"persistent":true,"coherent":true}`
)

// fsRWConfig returns a MemoryConfig of mode fs read-write with the access,
// path and fsType.
func fsRWConfig(access, path, fsType string) string {
	return fmt.Sprintf(`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","readOnly":false,"access":%q,"path":%q,"fsType":%q}}`, access, path, fsType)
}

// fsROConfig returns a MemoryConfig of mode fs without readOnly (read-only).
func fsROConfig(access string) string {
	return fmt.Sprintf(`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","access":%q}}`, access)
}

// TestPoolPersistentReadWrite: two writers and a reader of one ext4 on one
// node (test20 phase C): one read-write node mount, CDI binds by claim, the
// environment, the state file; a restart keeps it; the Unprepare of the
// writers makes it read-only, that of the reader releases the device.
func TestPoolPersistentReadWrite(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plugPersistent(0xc1ae0001, "ext4")
	p := e.driver(t)
	direct := e.nodeMount(0xc1ae0001, "direct")

	// read-write needs the device on this node only
	wantErr(t, prepare(t, p, persistentClaim("x", persistentData, fsRWConfig("", "", ""))).Err,
		"MemoryConfig: device.readOnly: false: other hosts may use the device: read-write needs it on this node only (claim status singleHost), or a cluster filesystem (device.fsType gfs2) on coherent memory")
	e.wantClean(t, p)

	noErr(t, prepare(t, p, persistentClaim("a", singleHostData, fsRWConfig("", "", ""))).Err)
	noErr(t, prepare(t, p, persistentClaim("b", singleHostData, fsRWConfig("", "/data", "ext4"))).Err)
	noErr(t, prepare(t, p, persistentClaim("c", singleHostData, fsROConfig(""))).Err)
	if got := e.k.MountCalls("fsmount"); !slices.Equal(got, []string{"fsmount " + e.pmem + " " + direct + " ext4 rw dax=always"}) {
		t.Fatalf("mounts %q", got)
	}
	env := func(uid, path, ro string) []string {
		return []string{"CXL_C1AE0001_ACCESS=direct", "CXL_C1AE0001_FSTYPE=ext4", "CXL_C1AE0001_MODE=fs", "CXL_C1AE0001_PATH=" + path,
			"CXL_C1AE0001_READONLY=" + ro, "CXL_C1AE0001_SERIAL=0xc1ae0001", "CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=534773760", "CXL_CLAIM_" + uid + "_0=1"}
	}
	for _, c := range []struct {
		uid, path, ro string
		options       []string
	}{
		{"a", "/run/cxl-fs/C1AE0001", "0", []string{"bind", "nosuid", "nodev"}},
		{"b", "/data", "0", []string{"bind", "nosuid", "nodev"}},
		{"c", "/run/cxl-fs/C1AE0001", "1", []string{"bind", "ro", "nosuid", "nodev"}},
	} {
		cd := e.wantCDIDevice(t, "claim-"+c.uid+"-0", env(c.uid, c.path, c.ro))
		want := []*cdiSpecs.Mount{{HostPath: direct, ContainerPath: c.path, Type: "bind", Options: c.options}}
		if !reflect.DeepEqual(cd.ContainerEdits.Mounts, want) {
			t.Fatalf("%s: CDI mounts %+v", c.uid, cd.ContainerEdits.Mounts)
		}
	}
	data, _ := os.ReadFile(e.stateFile)
	if !strings.Contains(string(data), `"fsType": "ext4"`) || e.device(p, "a", 0).ReadOnly || !e.device(p, "c", 0).ReadOnly {
		t.Fatalf("state:\n%s", data)
	}

	// a reader with the other access next to the writers: P9a
	wantErr(t, prepare(t, p, persistentClaim("d", singleHostData, fsROConfig("cached"))).Err,
		"device 0xc1ae0001: it is mounted read-write with access direct on this node: access cached would mount it a second time")

	// a restart keeps the read-write node mount as it is
	n := len(e.k.MountCalls(""))
	p = e.driver(t)
	for _, c := range e.k.MountCalls("")[n:] {
		if strings.HasPrefix(c, "fsmount") || strings.HasPrefix(c, "reconfigure") || strings.HasPrefix(c, "umount") {
			t.Fatalf("restart touched the mounts: %q", e.k.MountCalls("")[n:])
		}
	}
	// the writers go: read-only for the reader
	noErr(t, unprepare(t, p, "a"))
	n = len(e.k.MountCalls(""))
	noErr(t, unprepare(t, p, "b"))
	got := slices.DeleteFunc(slices.Clone(e.k.MountCalls("")[n:]), func(c string) bool { return strings.HasPrefix(c, "superblocks ") })
	if !slices.Equal(got, []string{"syncfs " + direct, "reconfigure " + direct + " ro", "blkroset " + e.pmem + " 1"}) {
		t.Fatalf("downgrade calls %q", got)
	}
	// a writer again upgrades in place
	noErr(t, prepare(t, p, persistentClaim("w", singleHostData, fsRWConfig("direct", "", ""))).Err)
	if mi, _ := e.mountedErr(direct); mi == nil || mi.SuperOpts[0] != "rw" || e.k.IsReadOnly(e.pmem) {
		t.Fatalf("not upgraded: %+v", mi)
	}
	for _, uid := range []string{"w", "c"} {
		noErr(t, unprepare(t, p, uid))
	}
	e.wantReleased(t, "region0", "mem0")
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
}

// TestPoolPersistentCluster: gfs2 read-write without singleHost needs a
// gfs2 with lock_dlm on coherent memory.
func TestPoolPersistentCluster(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plugPersistent(0xc1ae0001, "gfs2-nolock")
	p := e.driver(t)
	wantErr(t, prepare(t, p, persistentClaim("x", coherentData, fsRWConfig("", "", "gfs2"))).Err,
		"device 0xc1ae0001: read-write on several hosts needs a cluster filesystem on coherent memory: gfs2 with lock_nolock is a single-host filesystem")
	e.wantReleased(t, "region0", "mem0")
	e.setImage("mem0", "gfs2")
	noErr(t, prepare(t, p, persistentClaim("x", coherentData, fsRWConfig("", "", "gfs2"))).Err)
	e.wantCDIDevice(t, "claim-x-0", []string{"CXL_C1AE0001_ACCESS=cached", "CXL_C1AE0001_FSTYPE=gfs2", "CXL_C1AE0001_MODE=fs",
		"CXL_C1AE0001_PATH=/run/cxl-fs/C1AE0001", "CXL_C1AE0001_READONLY=0", "CXL_C1AE0001_SERIAL=0xc1ae0001", "CXL_C1AE0001_SHARED=1",
		"CXL_C1AE0001_SIZE=534773760", "CXL_CLAIM_x_0=1"})
	noErr(t, unprepare(t, p, "x"))
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
}
