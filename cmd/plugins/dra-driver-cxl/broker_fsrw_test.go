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
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/containers/nri-plugins/pkg/cxl/api"
)

// fsRWLeaseData is the status data of a share of llm0 whose attachment is
// exclusive to the node.
const fsRWLeaseData = `{"serial":"0xc1af0001","shared":true,"size":536870912,"persistent":true,"singleHost":true}`

// TestBrokerFsLeaseReadWrite runs a read-write and a read-only fs lease of
// one ext4 through the broker and the pool driver: the companion configs
// (readOnly explicitly), the binds (a plain bind read-write, a read-only
// clone), the responses with the type and the environment.
func TestBrokerFsLeaseReadWrite(t *testing.T) {
	e := newLeaseFsEnv(t)
	e.pe.m.images["/dev/pmem0"] = fsImage("ext4")
	fsDir := filepath.Join(e.dir, "lease-fs", testLeaseClaimUID)
	direct := e.p.nodeMountPath(0xc1af0001, "direct")

	prepare := func(id string, req api.Request, data string) api.Response {
		t.Helper()
		ch := make(chan api.Response, 1)
		go func() {
			r, _ := e.call(req)
			ch <- r
		}()
		claim := e.waitClaim(companionName(id))
		r := prepare(t, e.p, allocated(claim, "llm0", data))
		noErr(t, r.Err)
		return <-ch
	}
	rw := prepare("000000a1", api.Request{Op: "request", Serial: "0xc1af0001", Shared: true, ReadWrite: true, Mode: "fs", Name: "rw", Wait: "5s"}, fsRWLeaseData)
	env := func(path, ro string) map[string]string {
		return map[string]string{"CXL_C1AF0001_ACCESS": "direct", "CXL_C1AF0001_FSTYPE": "ext4", "CXL_C1AF0001_MODE": "fs", "CXL_C1AF0001_PATH": path,
			"CXL_C1AF0001_READONLY": ro, "CXL_C1AF0001_SERIAL": "0xc1af0001", "CXL_C1AF0001_SHARED": "1", "CXL_C1AF0001_SIZE": "534773760"}
	}
	wantResponse(t, rw, api.Response{State: api.StateReady, Source: "pool", Mode: "fs", FsType: "ext4", Shared: true, Access: "direct",
		Path: "/run/cxl/fs/rw", Size: fakePmemBytes, Serial: "0xc1af0001", Env: env("/run/cxl/fs/rw", "0")})
	if mi, _ := e.pe.m.Mounted(filepath.Join(fsDir, "rw")); mi == nil || !slices.Equal(mi.MountFlags, []string{"rw", "nosuid", "nodev"}) || mi.FsType != "ext4" {
		t.Fatalf("read-write bind %+v", mi)
	}
	if mi, _ := e.pe.m.Mounted(direct); mi == nil || mi.SuperOpts[0] != "rw" {
		t.Fatalf("node mount %+v", mi)
	}
	ro := prepare("000000a2", api.Request{Op: "request", Serial: "0xc1af0001", Shared: true, Mode: "fs", Name: "ro", Wait: "5s"}, fsLeaseData)
	wantResponse(t, ro, api.Response{State: api.StateReady, Source: "pool", Mode: "fs", FsType: "ext4", Shared: true, ReadOnly: true, Access: "direct",
		Path: "/run/cxl/fs/ro", Size: fakePmemBytes, Serial: "0xc1af0001", Env: env("/run/cxl/fs/ro", "1")})
	if c := e.pe.m.callsOf("robind"); !slices.Equal(c, []string{"robind " + direct + " " + filepath.Join(fsDir, "ro")}) {
		t.Fatalf("read-only bind calls %q", c)
	}
	// the companion configs say readOnly explicitly
	for id, want := range map[string]string{
		"000000a1": `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","readOnly":false}}`,
		"000000a2": `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","readOnly":true}}`,
	} {
		claim := e.waitClaim(companionName(id))
		if got := string(claim.Spec.Devices.Config[0].Opaque.Parameters.Raw); got != want {
			t.Errorf("%s: config %s", id, got)
		}
	}
	// the lease table has the opt-in and the type
	e.b.mu.Lock()
	data, _ := json.Marshal(e.b.store.Leases["000000a1"])
	e.b.mu.Unlock()
	var l lease
	noErr(t, json.Unmarshal(data, &l))
	if !l.ReadWrite || l.ReadOnly || l.FsType != "ext4" || l.readOnly() {
		t.Fatalf("lease %s", data)
	}
	e.pe.m.wantNoViolations(t)
}

// TestBrokerLeaseSocketNoFollow: what a container of before the read-only
// mount of its socket directory put there is never followed: a symlink at
// the socket path does not get the mode of the socket, a symlink at the
// mount point of api.FsDir is replaced by a directory, and the entries
// that the container wrote are removed with the claim, not their targets.
func TestBrokerLeaseSocketNoFollow(t *testing.T) {
	e := newBrokerEnv(t)
	dir := filepath.Dir(e.sock())
	victim := filepath.Join(t.TempDir(), "victim")
	noErr(t, os.WriteFile(victim, []byte("x"), 0o600))
	victimDir := t.TempDir()
	noErr(t, os.Chmod(victimDir, 0o700))
	noErr(t, os.MkdirAll(dir, 0o755))
	noErr(t, os.Symlink(victim, e.sock()))
	noErr(t, os.Symlink(victimDir, filepath.Join(dir, leaseFsMountPoint)))
	noErr(t, os.MkdirAll(filepath.Join(dir, "junk", "deep"), 0o755))
	noErr(t, os.WriteFile(filepath.Join(dir, "junk", "deep", "f"), []byte("x"), 0o644))
	noErr(t, os.Symlink(victimDir, filepath.Join(dir, "link")))

	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	if st, err := os.Lstat(e.sock()); err != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0o666 {
		t.Fatalf("socket %v %v", st, err)
	}
	if st, _ := os.Stat(victim); st.Mode().Perm() != 0o600 {
		t.Fatalf("the target of a symlink got mode %v", st.Mode())
	}
	if st, err := os.Lstat(filepath.Join(dir, leaseFsMountPoint)); err != nil || !st.IsDir() || st.Mode().Perm() != 0o755 {
		t.Fatalf("mount point %v %v", st, err)
	}
	if st, _ := os.Stat(victimDir); st.Mode().Perm() != 0o700 {
		t.Fatalf("the target of a symlink got mode %v", st.Mode())
	}
	noErr(t, e.b.CloseClaim(context.Background(), testLeaseClaimUID))
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket directory left: %v", err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("the target of a symlink was removed: %v", err)
	}
	if _, err := os.Stat(victimDir); err != nil {
		t.Fatalf("the target of a symlink was removed: %v", err)
	}
}
