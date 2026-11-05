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
	"bytes"
	"flag"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/compat"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// pmemEnv returns a node with the persistent pool memdev serialP whose
// fsdax namespace has a filesystem of the type.
func pmemEnv(t *testing.T, typ string) *env {
	t.Helper()
	v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
	v.formatPmem("mem0", typ)
	return v
}

// fsGrant returns the request of a pool grant of mode fs on serialP.
func fsGrant(uid string, readOnly bool, access state.Access) GrantRequest {
	return fsReq(poolReq(uid, 0, serialP, state.ModeFs, state.KindPersistent), readOnly, access)
}

// A writable block grant creates the fsdax namespace of the device, the
// block device read-write; its release destroys the region and disables
// the memdev, leaving the namespace in the labels.
func TestPersistentBlockWriter(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
	v.mustPrepare(poolDriver, "b1", poolReq("b1", 0, serialP, state.ModeBlock, state.KindPersistent))
	g := v.grant("b1", 0)
	if g.Got.BlockDevice == nil || g.Got.Namespace == "" || g.Intent.NdRegion == "" || v.f.IsReadOnly(g.Got.BlockDevice.Name) {
		t.Fatalf("grant %+v", g)
	}
	// a reader next to the block writer is refused
	err := v.prepare(poolDriver, "b2", fsGrant("b2", true, ""))
	if err == nil || !strings.Contains(err.Error(), "mode block read-write needs the device alone on this node") {
		t.Fatalf("error %v", err)
	}
	v.mustUnprepare(poolDriver, "b1")
	v.clean("unprepared")
	if !v.f.Labels(serialP) {
		t.Fatal("the labels went with the region")
	}
}

// A reader of a device that no writer formatted is refused: no fsdax
// namespace.
func TestPersistentReaderNeedsNamespace(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
	err := v.prepare(poolDriver, "r1", fsGrant("r1", true, ""))
	if err == nil || !strings.Contains(err.Error(), compat.OracleRefusedNoNS) {
		t.Fatalf("error %v", err)
	}
	v.check("refused")
	v.clean("refused")
}

// ext4 read-write: the writer mounts it rw with DAX, a reader joins the
// mount, the writer's release makes it read-only, the reader's unmounts it.
func TestPersistentFsReadWrite(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.mustPrepare(poolDriver, "w", fsGrant("w", false, ""))
	g := v.grant("w", 0)
	direct := filepath.Join(v.dir, poolDriver, "mounts", "91-direct")
	if g.Got.MountPath != direct || g.Got.Mount != state.AccessDirect || g.Got.FsType != "ext4" || g.Intent.MountPath != direct {
		t.Fatalf("grant %+v", g.Got)
	}
	m := v.records().Region(g.Got.Region).Mount(state.AccessDirect)
	if m == nil || m.State != state.MountedRW || !m.Writer {
		t.Fatalf("mount %+v", m)
	}
	v.mustPrepare(poolDriver, "r", fsGrant("r", true, ""))
	if m := v.records().Region(g.Got.Region).Mount(state.AccessDirect); len(m.Users) != 2 || m.State != state.MountedRW {
		t.Fatalf("mount %+v", m)
	}
	v.mustUnprepare(poolDriver, "w")
	if m := v.records().Region(g.Got.Region).Mount(state.AccessDirect); m.State != state.MountedRO || m.Writer {
		t.Fatalf("mount after the writer %+v", m)
	}
	if !v.f.IsReadOnly(g.Got.BlockDevice.Name) {
		t.Fatal("block device writable without a writer")
	}
	v.mustUnprepare(poolDriver, "r")
	v.clean("unprepared")
	if len(v.f.Violations()) > 0 {
		t.Fatalf("violations %v", v.f.Violations())
	}
}

// erofs read-only with access cached: a read-only loop device over the
// block device, dax=never.
func TestPersistentFsReadOnly(t *testing.T) {
	v := pmemEnv(t, "erofs")
	v.mustPrepare(poolDriver, "r", fsGrant("r", true, state.AccessCached))
	g := v.grant("r", 0)
	if g.Got.Mount != state.AccessCached || g.Got.Loop == "" || g.Got.FsType != "erofs" {
		t.Fatalf("grant %+v", g.Got)
	}
	err := v.prepare(poolDriver, "w", fsGrant("w", false, state.AccessCached))
	want := "erofs is a read-only filesystem: set readOnly: true"
	if err == nil || !strings.HasSuffix(err.Error(), want) {
		t.Fatalf("error %v", err)
	}
	v.mustUnprepare(poolDriver, "r")
	v.clean("unprepared")
}

// A read-write claim with access cached of a device that a reader mounts
// with access direct only is refused with the text of the e2e tests, and
// nothing is mounted.
func TestPersistentP9D(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.mustPrepare(poolDriver, "r", fsGrant("r", true, state.AccessDirect))
	err := v.prepare(poolDriver, "w", fsGrant("w", false, state.AccessCached))
	want := strings.ReplaceAll(compat.EventDeviceFSSerialItIsMountedWithAccessDirect, "$FS_SERIAL", api.FormatSerial(serialP))
	if err == nil || err.Error() != want {
		t.Fatalf("error %v, want %q", err, want)
	}
	if mounts := v.f.MountTable(); len(mounts) != 1 {
		t.Fatalf("mounts %+v", mounts)
	}
	v.mustUnprepare(poolDriver, "r")
}

// The lease bind of a companion grant of mode fs: bound at its target after
// the node mount, unbound at its release.
func TestPersistentBind(t *testing.T) {
	v := pmemEnv(t, "ext4")
	req := fsGrant("c", true, "")
	req.BindTarget = filepath.Join(v.dir, localDriver, "lease-fs", "lc1", "data")
	req.Lend = &state.GrantLend{Lease: "0123abcd", Name: "data"}
	v.mustPrepare(poolDriver, "c", req)
	g := v.grant("c", 0)
	if g.Got.Bind == nil || g.Got.Bind.State != state.BindBound || g.Got.Lend == nil {
		t.Fatalf("grant %+v", g.Got)
	}
	if !slices.ContainsFunc(v.f.MountTable(), func(m mountInfo) bool { return m.Target == req.BindTarget }) {
		t.Fatalf("not bound: %+v", v.f.MountTable())
	}
	v.mustUnprepare(poolDriver, "c")
	v.clean("unprepared")
}

// The log lines of the node mounts and of the read-only flags of the block
// devices, each once and in order, with the driver's name first.
func TestPersistentLogLines(t *testing.T) {
	serial := strings.TrimPrefix(api.FormatSerial(serialP), "0x")
	prefix := poolDriver + ": device " + api.FormatSerial(serialP) + ": "
	doc := func(line string, placeholders ...string) string {
		return strings.NewReplacer(append([]string{"<serial>", serial}, placeholders...)...).Replace(line)
	}
	wantLines := func(t *testing.T, logs string, want ...string) {
		t.Helper()
		if got := linesWithPrefix(logs, prefix); !slices.Equal(got, want) {
			t.Fatalf("log lines\n  %s\nexpected\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
		}
	}
	t.Run("writer alone", func(t *testing.T) {
		v := pmemEnv(t, "ext4")
		logs := captureKlog(t)
		direct := filepath.Join(v.dir, poolDriver, "mounts", "91-direct")
		v.mustPrepare(poolDriver, "w", fsGrant("w", false, ""))
		v.mustUnprepare(poolDriver, "w")
		pmem := v.f.DevRoot() + "/pmem0"
		mounted := doc(compat.DocCXLPoolNRIIoDevice0xSerialMounted,
			"<source>", pmem, "<mnt>", direct, "<type>", "ext4", "ro|rw", "rw", "<data>", "dax=always")
		e2e := strings.NewReplacer("$PMEM", pmem, "$MNT_DIRECT", direct).Replace(compat.LogMountedPmemAtMntDirectExt4RwDaxAlways)
		if !strings.HasSuffix(mounted, ": "+e2e) {
			t.Fatalf("line %q does not end with %q", mounted, e2e)
		}
		wantLines(t, logs(), mounted, doc(compat.DocCXLPoolNRIIoDevice0xSerialUnmounted, "<mnt>", direct))
	})
	t.Run("cached reader and writer", func(t *testing.T) {
		v := pmemEnv(t, "ext4")
		logs := captureKlog(t)
		cached := filepath.Join(v.dir, poolDriver, "mounts", "91-cached")
		pmem, loop := v.f.DevRoot()+"/pmem0", v.f.DevRoot()+"/loop0"
		pmemRO := doc(compat.DocCXLPoolNRIIoDevice0xSerialDevH3d032c, "/dev/pmemK", pmem)
		loopRW := doc(compat.DocCXLPoolNRIIoDevice0xSerialDevH11871f, "/dev/loopN", loop)
		v.mustPrepare(poolDriver, "r", fsGrant("r", true, state.AccessCached))
		v.mustPrepare(poolDriver, "w", fsGrant("w", false, state.AccessCached))
		v.mustUnprepare(poolDriver, "w")
		v.mustUnprepare(poolDriver, "r")
		wantLines(t, logs(),
			pmemRO,
			prefix+loop+" read-only",
			doc(compat.DocCXLPoolNRIIoDevice0xSerialMounted,
				"<source>", loop, "<mnt>", cached, "<type>", "ext4", "ro|rw", "ro", "<data>", "dax=never"),
			prefix+pmem+" read-write",
			loopRW,
			doc(compat.DocCXLPoolNRIIoDevice0xSerialRemountedH6128ac, "<mnt>", cached),
			doc(compat.DocCXLPoolNRIIoDevice0xSerialRemountedH548a27, "<mnt>", cached),
			prefix+loop+" read-only",
			pmemRO,
			doc(compat.DocCXLPoolNRIIoDevice0xSerialUnmounted, "<mnt>", cached))
	})
}

// linesWithPrefix returns the messages of the klog output that begin with
// prefix, in order, without the klog header.
func linesWithPrefix(logs, prefix string) []string {
	var lines []string
	for _, l := range strings.Split(logs, "\n") {
		if _, msg, ok := strings.Cut(l, "] "); ok && strings.HasPrefix(msg, prefix) {
			lines = append(lines, msg)
		}
	}
	return lines
}

// writerFunc is an io.Writer of a function.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// captureKlog returns the klog output from now on, at verbosity 3.
func captureKlog(t *testing.T) func() string {
	t.Helper()
	fs := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(fs)
	_ = fs.Set("logtostderr", "false")
	_ = fs.Set("alsologtostderr", "false")
	_ = fs.Set("v", "3")
	var mu sync.Mutex
	var buf bytes.Buffer
	klog.SetOutput(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}))
	t.Cleanup(func() {
		klog.Flush()
		_ = fs.Set("logtostderr", "true")
		_ = fs.Set("v", "0")
	})
	return func() string {
		klog.Flush()
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

// A lease bind that is busy at its release (a file of it mapped): the bind
// is STALE, the release fails; a later release unbinds it.
func TestPersistentBindBusy(t *testing.T) {
	v := pmemEnv(t, "ext4")
	req := fsGrant("c", true, "")
	req.BindTarget = filepath.Join(v.dir, localDriver, "lease-fs", "lc1", "data")
	req.Lend = &state.GrantLend{Lease: "0123abcd", Name: "data"}
	v.mustPrepare(poolDriver, "c", req)
	v.f.SetBusy(req.BindTarget, true)
	err := v.unprepare(poolDriver, "c")
	if err == nil || !strings.Contains(err.Error(), "lease 0123abcd: unmounting") {
		t.Fatalf("error %v", err)
	}
	if b := v.grant("c", 0).Got.Bind; b.State != state.BindStale {
		t.Fatalf("bind %+v", b)
	}
	if m := v.records().Memdev(serialP); len(m.Stale) != 1 {
		t.Fatalf("stale %+v", m.Stale)
	}
	v.f.SetBusy(req.BindTarget, false)
	v.mustUnprepare(poolDriver, "c")
	v.clean("unprepared")
}
