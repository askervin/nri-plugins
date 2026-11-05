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
	"strings"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/compat"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// TestCharPersistentP9D: a read-write claim with access cached of an ext4
// device that a reader mounts with access direct only on the node is
// refused with the text that the e2e tests find in the Events of its pod,
// and the refusal mounts and changes nothing: the reader's read-only node
// mount stays the only one.
func TestCharPersistentP9D(t *testing.T) {
	e := newPnEnv(t, "ext4")
	direct := e.n.NodeMountPath(pmemSerial, api.AccessDirect)
	_, err := e.prepare("r", true, api.AccessDirect, "", singleHost)
	noErr(t, err)

	n := e.ncalls()
	_, err = e.prepare("w", false, api.AccessCached, "", singleHost)
	want := strings.ReplaceAll(compat.EventDeviceFSSerialItIsMountedWithAccessDirect, "$FS_SERIAL", api.FormatSerial(pmemSerial))
	if err == nil || err.Error() != want {
		t.Fatalf("error %v, expected %q", err, want)
	}
	e.wantCalls(n)
	if len(e.m.mounts) != 1 || e.m.mounts[0].Target != direct || len(e.uses) != 1 {
		t.Fatalf("mounts %+v, uses %+v after the refusal, expected the reader's node mount only", e.m.mounts, e.uses)
	}
	e.wantSuper(direct, "ro")
	if !e.m.isRO("/dev/pmem0") {
		t.Fatal("block device writable after the refusal")
	}
	noErr(t, e.release("r"))
}

// TestCharPersistentLogLines: the log lines of the node mounts and the
// read-only flags of the block devices of a persistent device, each once
// and in order, as the documentation and the e2e tests quote them with the
// name of the pool driver first. A writer alone mounts read-write with DAX
// and unmounts at its release, without a line of a read-only flag: the
// flag of the block device does not change. A cached reader with a writer
// next to it logs every change of the flags of the block device and of the
// loop device, and the remounts.
func TestCharPersistentLogLines(t *testing.T) {
	serial := strings.TrimPrefix(api.FormatSerial(pmemSerial), "0x")
	prefix := device.PoolDriverName + ": device " + api.FormatSerial(pmemSerial) + ": "
	// doc fills the placeholders of a documented line
	doc := func(line string, placeholders ...string) string {
		return strings.NewReplacer(append([]string{"<serial>", serial}, placeholders...)...).Replace(line)
	}
	newEnv := func(t *testing.T) (*pnEnv, func() string) {
		e := newPnEnv(t, "ext4")
		e.n.cfg.Driver = device.PoolDriverName
		return e, captureKlog(t)
	}
	wantLines := func(t *testing.T, logs string, want ...string) {
		t.Helper()
		if got := logLinesWithPrefix(logs, prefix); !slices.Equal(got, want) {
			t.Fatalf("log lines\n  %s\nexpected\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
		}
	}

	t.Run("writer alone", func(t *testing.T) {
		e, logs := newEnv(t)
		direct := e.n.NodeMountPath(pmemSerial, api.AccessDirect)
		_, err := e.prepare("w", false, "", "", singleHost)
		noErr(t, err)
		noErr(t, e.release("w"))
		mounted := doc(compat.DocCXLPoolNRIIoDevice0xSerialMounted,
			"<source>", "/dev/pmem0", "<mnt>", direct, "<type>", "ext4", "ro|rw", "rw", "<data>", "dax=always")
		// the line of the mount ends with the text that the e2e tests wait for
		e2e := strings.NewReplacer("$PMEM", "/dev/pmem0", "$MNT_DIRECT", direct).Replace(compat.LogMountedPmemAtMntDirectExt4RwDaxAlways)
		if !strings.HasSuffix(mounted, ": "+e2e) {
			t.Fatalf("line %q does not end with %q", mounted, e2e)
		}
		wantLines(t, logs(),
			mounted,
			doc(compat.DocCXLPoolNRIIoDevice0xSerialUnmounted, "<mnt>", direct))
	})

	t.Run("cached reader and writer", func(t *testing.T) {
		e, logs := newEnv(t)
		cached := e.n.NodeMountPath(pmemSerial, api.AccessCached)
		pmemRO := doc(compat.DocCXLPoolNRIIoDevice0xSerialDevH3d032c, "/dev/pmemK", "/dev/pmem0")
		loopRW := doc(compat.DocCXLPoolNRIIoDevice0xSerialDevH11871f, "/dev/loopN", "/dev/loop0")
		_, err := e.prepare("r", true, api.AccessCached, "", singleHost)
		noErr(t, err)
		_, err = e.prepare("w", false, api.AccessCached, "", singleHost)
		noErr(t, err)
		noErr(t, e.release("w"))
		noErr(t, e.release("r"))
		wantLines(t, logs(),
			// the reader
			pmemRO,
			prefix+"/dev/loop0 read-only",
			doc(compat.DocCXLPoolNRIIoDevice0xSerialMounted,
				"<source>", "/dev/loop0", "<mnt>", cached, "<type>", "ext4", "ro|rw", "ro", "<data>", "dax=never"),
			// the writer upgrades the block device, the loop device, then the superblock
			prefix+"/dev/pmem0 read-write",
			loopRW,
			doc(compat.DocCXLPoolNRIIoDevice0xSerialRemountedH6128ac, "<mnt>", cached),
			// its release downgrades in the reverse order
			doc(compat.DocCXLPoolNRIIoDevice0xSerialRemountedH548a27, "<mnt>", cached),
			prefix+"/dev/loop0 read-only",
			pmemRO,
			// the last release
			doc(compat.DocCXLPoolNRIIoDevice0xSerialUnmounted, "<mnt>", cached))
	})
}

// logLinesWithPrefix returns the messages of the klog output that begin
// with prefix, in order, without the klog header.
func logLinesWithPrefix(logs, prefix string) []string {
	var lines []string
	for _, l := range strings.Split(logs, "\n") {
		if _, msg, ok := strings.Cut(l, "] "); ok && strings.HasPrefix(msg, prefix) {
			lines = append(lines, msg)
		}
	}
	return lines
}
