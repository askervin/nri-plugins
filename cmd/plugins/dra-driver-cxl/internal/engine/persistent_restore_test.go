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
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/compat"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
)

// The start makes the superblock of a node mount and the read-only flag of
// its block device what the prepared uses derive: a node mount that is gone
// is mounted again read-write for a writer, the block device that was left
// read-only made writable first; a read-write superblock without a writer
// (the Prepare of the writer cut after its upgrade) is made read-only, then
// the block device; a read-only one under a writer is made read-write, the
// block device first. A node mount that is gone and whose block device is
// another one now is not mounted again, with the line that the observer
// counts.
func TestRestoreFlags(t *testing.T) {
	for _, source := range sources {
		t.Run(string(source), func(t *testing.T) {
			driver := driverOf(source)
			v := pmemEnv(t, "ext4")
			k := v.f.Kernel()
			pmem := filepath.Join(v.f.DevRoot(), "pmem0")
			wantFlags := func(what, mnt string, readOnly bool) {
				t.Helper()
				mi, err := k.Mounted(mnt)
				if err != nil || mi == nil || mi.SuperReadOnly() != readOnly || v.f.IsReadOnly(pmem) != readOnly {
					t.Fatalf("%s: node mount %+v (%v), block device read-only %v, want read-only %v", what, mi, err, v.f.IsReadOnly(pmem), readOnly)
				}
			}
			v.mustPrepare(driver, "w", fsUse(source, "w", false, ""))
			v.mustPrepare(driver, "r", fsUse(source, "r", true, ""))
			direct := v.mount("w", 0).Path

			// gone, its block device read-only: mounted again read-write
			if err := k.Unmount(direct); err != nil {
				t.Fatal(err)
			}
			if _, err := k.SetBlockDeviceReadOnly(pmem, true); err != nil {
				t.Fatal(err)
			}
			n := mountCalls(v)
			v.restart()
			wantMountCalls(t, v, n, "blkroset "+pmem+" 0", "fsmount "+pmem+" "+direct+" ext4 rw dax=always")
			wantFlags("mounted again", direct, false)

			// the writer is gone, its Prepare again cut after the upgrade:
			// made read-only
			v.mustUnprepare(driver, "w")
			v.f.CutMount(direct)
			if !v.cut(func() { _ = v.prepare(driver, "w", fsUse(source, "w", false, "")) }) {
				t.Fatal("not cut")
			}
			wantFlags("cut", direct, false)
			n = mountCalls(v)
			if out := v.restart(); !slices.Equal(out.Released, []state.GrantRef{{Claim: "w"}}) {
				t.Fatalf("recovered %+v", out)
			}
			wantMountCalls(t, v, n, "syncfs "+direct, "reconfigure "+direct+" ro", "blkroset "+pmem+" 1")
			wantFlags("downgraded", direct, true)

			// a writer again, the superblock and the block device made
			// read-only behind it: made read-write
			v.mustPrepare(driver, "w", fsUse(source, "w", false, ""))
			if err := k.Reconfigure(direct, false); err != nil {
				t.Fatal(err)
			}
			if _, err := k.SetBlockDeviceReadOnly(pmem, true); err != nil {
				t.Fatal(err)
			}
			n = mountCalls(v)
			v.restart()
			wantMountCalls(t, v, n, "blkroset "+pmem+" 0", "reconfigure "+direct+" rw")
			wantFlags("upgraded", direct, false)
			if viol := v.f.Violations(); len(viol) > 0 {
				t.Fatalf("violations %v", viol)
			}

			// gone, and the block device is another one: not mounted again
			if err := k.Unmount(direct); err != nil {
				t.Fatal(err)
			}
			v.f.RenamePmem("region0", "pmem3", "259:9")
			logs := captureKlog(t)
			n = mountCalls(v)
			out := v.restart()
			wantMountCalls(t, v, n)
			if !slices.Equal(out.Unrestored, []state.GrantRef{{Claim: "r"}, {Claim: "w"}}) {
				t.Fatalf("recovered %+v", out)
			}
			changed := "device 0x91: its fsdax namespace is namespace0.0 with " + filepath.Join(v.f.DevRoot(), "pmem3") +
				" (259:9), not namespace0.0 with " + pmem + " (259:1) as prepared"
			// a pool claim is unrestored for its node mount, with the line
			// that the observer counts; a local claim for its block device,
			// with the line of its memdev only
			want := "not mounting " + direct + " again: " + changed
			line, notRemounted := driver+": claim ns/r: "+want, true
			if source == state.SourceLocal {
				want, line, notRemounted = changed, "local: memdev mem0 (serial 0x91): "+changed, false
			}
			for _, ref := range out.Unrestored {
				if why := out.Why[ref]; why == nil || why.Error() != want {
					t.Errorf("%s unrestored for %v, want %q", ref, why, want)
				}
			}
			lines := logs()
			wantLog(t, lines, line)
			counted := ""
			for _, l := range strings.Split(lines, "\n") {
				if ok, err := compat.MatchesRegexp(compat.ObserverLogCountNotRemounted, l); err != nil {
					t.Fatal(err)
				} else if ok && counted == "" {
					counted = l
				}
			}
			switch {
			case notRemounted && counted == "":
				t.Errorf("no line that the observer counts in\n%s", lines)
			case !notRemounted && counted != "":
				t.Errorf("the start logged %q, which the observer counts", counted)
			}
			if mi, _ := k.Mounted(direct); mi != nil {
				t.Fatalf("mounted again: %+v", mi)
			}
			v.mustUnprepare(driver, "w")
			v.mustUnprepare(driver, "r")
			v.clean("unprepared")
		})
	}
}
