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
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	resourceapi "k8s.io/api/resource/v1"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"golang.org/x/sys/unix"
)

// Prepares that the plugin does not finish (plan-13 bug-11): the plugin is
// killed in a Prepare after it touched a device and before it saved the
// claim, and kubelet unprepares the claim (its pod was deleted) or
// prepares it again after the restart. The restarted plugin releases what
// such a Prepare touched at start (bug-14), but of the claims that it
// keeps for their Unprepare or Prepare again.

// wantPreparing checks that the claim uid is in the preparing file and in
// the preparing claims of p with one device of the serial and mode, and
// nowhere in the state file.
func (e *poolTestEnv) wantPreparing(t *testing.T, p *poolDriver, uid string, serial uint64, mode string) {
	t.Helper()
	recs := e.preparingFile(t)
	for what, rec := range map[string]*preparingPoolClaim{"preparing file": recs[uid], "plugin": p.preparing[uid]} {
		if rec == nil || len(rec.Devices) != 1 || rec.Devices[0].Serial != serial || rec.Devices[0].Mode != mode {
			t.Fatalf("%s: claim %s %+v", what, uid, rec)
		}
	}
	if data, _ := os.ReadFile(e.stateFile); strings.Contains(string(data), uid) {
		t.Fatalf("claim %s in the state file:\n%s", uid, data)
	}
}

// TestPoolCutPersistentPrepare kills the plugin in the Prepare of a static
// claim of mode fs of a persistent device (the executor's run 6:
// driver-kill-at region, the pod deleted before kubelet's retry): after
// the region (with the namespace of the labels), and after the node
// mount. The restarted plugin unmounts the node mount of no prepared
// claim, releases the device and forgets the claim, and the Unprepare of
// the claim finds nothing: before bug-11 the plugin did not know the
// claim and left the region. With the node mount busy at start it keeps
// the claim and does not publish its device, and the Unprepare of the
// claim releases the device once the mount is free.
func TestPoolCutPersistentPrepare(t *testing.T) {
	for _, tc := range []struct {
		name, cutAfter string
		mount, busy    bool
	}{
		{name: "region", cutAfter: "cxl create-region"},
		{name: "mount", mount: true},
		{name: "busy mount", mount: true, busy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPoolTestEnv(t)
			e.f.plugPersistent(persistentSerial)
			e.f.labels = true
			p := e.driver(t)
			direct := p.nodeMountPath(0xc1ae0001, "direct")
			e.f.cutAfter = tc.cutAfter
			if tc.mount {
				e.m.cutAt = direct
			}
			cutPrepare(t, p, persistentClaim("d1", persistentData, fsConfig("direct", "")))
			e.wantPreparing(t, p, "d1", 0xc1ae0001, api.ModeFs)
			e.wantRegion(t, true)

			// a node mount that is busy at start stays mounted
			e.m.setBusy(direct, tc.busy)
			p2 := e.driver(t)
			if mi, _ := e.m.Mounted(direct); (mi != nil) != tc.busy {
				t.Fatalf("node mount of no prepared claim at start: %+v", mi)
			}
			if tc.busy {
				// kept, not published; the Unprepare fails while the
				// node mount is busy, and leaves the region and the claim
				e.wantPreparing(t, p2, "d1", 0xc1ae0001, api.ModeFs)
				if !p2.Serials()[0xc1ae0001] || len(p2.prepared) != 0 || e.cdiSpec(t) != nil {
					t.Fatalf("serials %v, prepared %v, CDI spec %+v", p2.Serials(), p2.prepared, e.cdiSpec(t))
				}
				e.wantRegion(t, true)
				wantErr(t, unprepare(t, p2, "d1"), "cxl-pool.nri.io: unpreparing claim default/c-d1: releasing llm0 (serial 0xc1ae0001): device 0xc1ae0001: unmounting "+direct)
				e.wantRegion(t, true)
				e.wantPreparing(t, p2, "d1", 0xc1ae0001, api.ModeFs)
				e.m.setBusy(direct, false)
				noErr(t, unprepare(t, p2, "d1"))
			}
			e.f.wantReleased(t)
			e.wantRegion(t, false)
			e.wantClean(t, p2)
			e.wantNoMounts(t, p2)
			// kubelet's Unprepare (again): nothing to do
			ncmds := e.f.commands()
			noErr(t, unprepare(t, p2, "d1"))
			if e.f.commands() != ncmds {
				t.Fatalf("a second Unprepare ran commands:\n%s", strings.TrimPrefix(e.f.commands(), ncmds))
			}
			// and after another restart
			e.wantClean(t, e.driver(t))
		})
	}
}

// TestPoolCutPrepareRetry: kubelet prepares the claim of a cut Prepare
// again after the restart (its pod was not deleted): the start released
// the device, the Prepare again makes the region anew, the claim is
// prepared and no longer preparing; its Unprepare releases the device as
// usual.
func TestPoolCutPrepareRetry(t *testing.T) {
	for _, tc := range []struct {
		name, data, config, cutAfter, mode string
		persistent                         bool
	}{
		{"fs", persistentData, fsConfig("direct", ""), "cxl create-region", api.ModeFs, true},
		{"numa", exclusiveData, "", "cxl create-region", api.ModeNUMA, false},
		{"dax", exclusiveData, daxConfig, "daxctl reconfigure-device", api.ModeDax, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPoolTestEnv(t)
			serial := uint64(0xc1ee0001)
			claim := poolClaim("u1", "c1", "pooled0", tc.data)
			if tc.persistent {
				e.f.plugPersistent(persistentSerial)
				e.f.labels = true
				serial = 0xc1ae0001
			} else {
				e.f.plug("0xc1ee0001")
			}
			if tc.config != "" {
				claim = withConfig(claim, resourceapi.AllocationConfigSourceClaim, nil, tc.config)
			}
			p := e.driver(t)
			e.f.cutAfter = tc.cutAfter
			cutPrepare(t, p, claim)
			e.wantRegion(t, true)

			p2 := e.driver(t)
			e.f.wantReleased(t)
			e.wantClean(t, p2)
			res := prepare(t, p2, claim)
			noErr(t, res.Err)
			if n := strings.Count(e.f.commands(), "create-region"); n != 2 {
				t.Fatalf("region created %d times:\n%s", n, e.f.commands())
			}
			if p2.prepared["u1"] == nil || len(p2.preparing) != 0 || len(e.preparingFile(t)) != 0 {
				t.Fatalf("prepared %v, preparing %v, preparing file %v", p2.prepared, p2.preparing, e.preparingFile(t))
			}
			if d := p2.prepared["u1"].Devices; len(d) != 1 || d[0].Serial != serial || d[0].Mode != tc.mode {
				t.Fatalf("prepared devices %+v", d)
			}
			if cdiDeviceByName(e.cdiSpec(t), "claim-u1-0") == nil {
				t.Fatalf("no CDI device of the prepared claim: %+v", e.cdiSpec(t))
			}
			// prepared after a restart too, not preparing
			p3 := e.driver(t)
			if p3.prepared["u1"] == nil || len(p3.preparing) != 0 {
				t.Fatalf("after a restart: prepared %v, preparing %v", p3.prepared, p3.preparing)
			}
			noErr(t, unprepare(t, p3, "u1"))
			e.f.wantReleased(t)
			e.wantClean(t, p3)
		})
	}
}

// TestPoolCutPrepareFailedRetry: the start could not release what a cut
// Prepare touched (a command failed) and kept the claim, and the Prepare
// again of the claim fails before it reaches the device (no status entry):
// its rollback releases what the cut Prepare touched, and forgets the
// claim.
func TestPoolCutPrepareFailedRetry(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ee0001")
	p := e.driver(t)
	e.f.cutAfter = "cxl create-region"
	cutPrepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData))
	e.f.failCmd = "cxl disable-region"
	p2 := e.driver(t)
	e.f.failCmd = ""
	e.wantPreparing(t, p2, "u1", 0xc1ee0001, api.ModeNUMA)
	e.wantRegion(t, true)
	wantErr(t, prepare(t, p2, poolClaim("u1", "c1", "pooled0", "")).Err, "no entry")
	e.f.wantReleased(t)
	e.wantClean(t, p2)
}

// TestPoolCutRefusedPrepare (plan-13 bug-14, run FP3) kills the plugin in
// the Prepare of a claim whose device refuses it (an fs reader of a device
// without erofs: its rollback destroys the region) after cxl
// create-region. The start releases the region while it is the newest one
// in the decoders of its ports, and the Prepare again of the claim makes
// it anew and rolls it back. Before the fix the region was kept for the
// Prepare again: the regions that other claims got until kubelet's retry
// lay above it, and the rollback of the retry left a hole that blocked
// every new region through the ports of the host bridge. When a region of
// another memdev lies above it at start already, the start keeps it: its
// release would leave that hole now; a region below it does not matter.
func TestPoolCutRefusedPrepare(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ports []string // the regions of the decoders of the ports of mem0, nil: no ports
		kept  bool
	}{
		{name: "no ports"},
		{name: "top", ports: []string{"region5", "region0"}},
		{name: "below another", ports: []string{"region0", "region5"}, kept: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPoolTestEnv(t)
			e.f.plugPersistent(persistentSerial)
			e.f.labels = true
			e.m.mountErr["/dev/pmem0"] = unix.EINVAL // no erofs
			claim := persistentClaim("r1", persistentData, fsConfig("direct", ""))
			p := e.driver(t)
			e.f.cutAfter = "cxl create-region"
			cutPrepare(t, p, claim)
			e.wantRegion(t, true)
			if tc.ports != nil {
				e.f.stackPorts(tc.ports...)
			}

			ncmds := e.f.commands()
			p2 := e.driver(t)
			if tc.kept {
				if e.f.commands() != ncmds {
					t.Fatalf("commands at start:\n%s", strings.TrimPrefix(e.f.commands(), ncmds))
				}
				e.wantRegion(t, true)
				e.wantPreparing(t, p2, "r1", 0xc1ae0001, api.ModeFs)
			} else {
				e.f.wantReleased(t)
				e.wantClean(t, p2)
			}
			// the Prepare again: made anew, or the kept region reused, and
			// rolled back
			wantErr(t, prepare(t, p2, claim).Err, "/dev/pmem0 has no erofs filesystem")
			want := 2
			if tc.kept {
				want = 1
			}
			if n := strings.Count(e.f.commands(), "create-region"); n != want {
				t.Fatalf("region created %d times, expected %d:\n%s", n, want, e.f.commands())
			}
			e.f.wantReleased(t)
			e.wantClean(t, p2)
		})
	}
}

// TestPoolCutVolatilePrepare kills the plugin in the Prepare of volatile
// devices: in mode numa after the region was created and while its memory
// goes online, in mode dax after the dax device was bound to device_dax.
// The restarted plugin offlines the memory and releases the device at
// start, so nothing is fenced for it. When it keeps the claim (a command
// failed), it fences the NUMA node of the numa device, and the Unprepare
// releases the device.
func TestPoolCutVolatilePrepare(t *testing.T) {
	for _, tc := range []struct {
		name, config, mode string
		kept               bool
	}{
		{"numa", "", api.ModeNUMA, false},
		{"dax", daxConfig, api.ModeDax, false},
		{"numa kept", "", api.ModeNUMA, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPoolTestEnv(t)
			e.f.plug("0xc1ee0001")
			claim := poolClaim("u1", "c1", "pooled0", exclusiveData)
			if tc.config != "" {
				claim = withConfig(claim, resourceapi.AllocationConfigSourceClaim, nil, tc.config)
			}
			p := e.driver(t)
			if tc.mode == api.ModeNUMA {
				// killed after the first memory block went online
				p.mem.WriteFile = func(path, val string) error {
					err := e.f.writeAttr(path, val)
					if val == "online_movable" {
						panic(errCut)
					}
					return err
				}
			} else {
				e.f.cutAfter = "daxctl reconfigure-device --mode=devdax"
			}
			cutPrepare(t, p, claim)
			if tc.mode == api.ModeNUMA && e.f.read("devices/system/memory/memory74/state") != "online_movable" {
				t.Fatal("the memory was not onlined before the kill")
			}

			if tc.kept {
				e.f.failCmd = "cxl disable-region"
			}
			p2 := e.driver(t)
			e.f.failCmd = ""
			if !tc.kept {
				e.f.wantReleased(t)
				e.f.wantBlocks(t, "offline")
				e.wantClean(t, p2)
				if got := p2.numaNodes(); len(got) != 0 {
					t.Fatalf("fenced nodes %v", got)
				}
				return
			}
			e.wantPreparing(t, p2, "u1", 0xc1ee0001, tc.mode)
			if got := p2.numaNodes(); !slices.Equal(got, []int{2}) {
				t.Fatalf("fenced nodes %v, expected [2]", got)
			}
			if p2.ClaimResults("u1") != nil {
				t.Fatalf("results of a claim that is not prepared: %+v", p2.ClaimResults("u1"))
			}
			noErr(t, unprepare(t, p2, "u1"))
			e.f.wantReleased(t)
			e.f.wantBlocks(t, "offline")
			e.wantClean(t, p2)
		})
	}
}

// cutLender kills the plugin after it lent a node.
type cutLender struct {
	*fakeLender
	revoked func(node int) // called at a revoke
}

func (c *cutLender) LendNode(ctx context.Context, podUID, name string, node int, holder string) error {
	if err := c.fakeLender.LendNode(ctx, podUID, name, node, holder); err != nil {
		return err
	}
	panic(errCut)
}

func (c *cutLender) RevokeNode(ctx context.Context, podUID, name string, node int, holder string) error {
	if c.revoked != nil {
		c.revoked(node)
	}
	return c.fakeLender.RevokeNode(ctx, podUID, name, node, holder)
}

// TestPoolCutCompanionPrepare kills the plugin in the Prepare of the
// companion claim of a numa lease after it lent the node to the borrower,
// and in the Prepare of the companion claim of an fs lease after the bind
// (the executor's run 3: driver-kill-at bind, then lease-put). The start
// keeps companion claims. The Unprepare of the companion revokes the node
// before the memory goes offline, and releases the device; before the
// lender is set up it fails (kubelet retries). The bind was unmounted at
// start.
func TestPoolCutCompanionPrepare(t *testing.T) {
	t.Run("numa", func(t *testing.T) {
		e := newPoolTestEnv(t)
		e.f.plug("0xc1ee0001")
		hooks := &fakeHooks{}
		lender := &cutLender{fakeLender: newFakeLender(testRef)}
		p := e.driver(t)
		p.lender.set(lender, hooks)
		claim := poolClaim("uid-cxl-lease-l1", "cxl-lease-l1", "pooled0", exclusiveData)
		claim.ObjectMeta = companionClaim("l1").ObjectMeta
		cutPrepare(t, p, claim)
		if got := lender.LentNodes(testPodUID, testCtr); !slices.Equal(got, []int{2}) {
			t.Fatalf("lent nodes %v", got)
		}

		// kept at start, with its node fenced
		p2 := e.driver(t)
		e.wantPreparing(t, p2, "uid-cxl-lease-l1", 0xc1ee0001, api.ModeNUMA)
		if got := p2.numaNodes(); !slices.Equal(got, []int{2}) {
			t.Fatalf("fenced nodes %v, expected [2]", got)
		}
		// kubelet's retry before NRI is connected and the lender set up:
		// nothing is released yet
		wantErr(t, unprepare(t, p2, "uid-cxl-lease-l1"), "lease l1: lending is not set up yet (the plugin is starting): nodes [2] of demo/")
		e.f.wantBlocks(t, "online_movable")
		e.wantPreparing(t, p2, "uid-cxl-lease-l1", 0xc1ee0001, api.ModeNUMA)
		online := ""
		lender.revoked = func(node int) { online = e.f.read("devices/system/memory/memory74/state") }
		p2.lender.set(lender, hooks)
		e.wantPreparing(t, p2, "uid-cxl-lease-l1", 0xc1ee0001, api.ModeNUMA)
		if rec := p2.preparing["uid-cxl-lease-l1"]; rec.Lend == nil || rec.Lend.Lease != "l1" || rec.Lend.Container != testCtr {
			t.Fatalf("lend of the preparing claim %+v", rec.Lend)
		}
		noErr(t, unprepare(t, p2, "uid-cxl-lease-l1"))
		if online != "online_movable" || len(lender.LentNodes(testPodUID, testCtr)) != 0 {
			t.Fatalf("revoke with the memory %q, lent nodes %v", online, lender.LentNodes(testPodUID, testCtr))
		}
		if log := hooks.log(); !strings.HasSuffix(log, "releasing l1") {
			t.Fatalf("hooks:\n%s", log)
		}
		e.f.wantReleased(t)
		e.f.wantBlocks(t, "offline")
		e.wantClean(t, p2)
	})

	t.Run("fs bind", func(t *testing.T) {
		e, p, hooks := newPoolLeaseEnv(t)
		target := filepath.Join(hooks.fsDir, "models")
		e.m.cutAt = target
		cutPrepare(t, p, fsCompanion("l1", "direct"))
		if mi, _ := e.m.Mounted(target); mi == nil {
			t.Fatal("no bind before the kill")
		}

		p2 := e.leaseDriver(t, hooks)
		e.wantPreparing(t, p2, "uid-cxl-lease-l1", 0xc1ae0001, api.ModeFs)
		if mi, _ := e.m.Mounted(target); mi != nil {
			t.Fatalf("bind of no prepared claim left at start: %+v", mi)
		}
		noErr(t, unprepare(t, p2, "uid-cxl-lease-l1"))
		e.f.wantReleased(t)
		e.wantClean(t, p2)
		e.wantNoMounts(t, p2)
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("bind directory left: %v", err)
		}
	})
}

// cutInCreateRegion makes the next cxl create-region of p leave a hollow
// region named region and kill the plugin (a kill inside the tool, after
// the region got its size and before its target): the root decoder names
// region as the next one, as the kernel does.
func (e *poolTestEnv) cutInCreateRegion(p *poolDriver, region string) {
	e.f.write("bus/cxl/devices/decoder0.0/create_ram_region", region)
	exec := p.mem.Exec
	p.mem.Exec = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "cxl" && args[0] == "create-region" {
			e.f.hollowRegion(region, "ram")
			panic(errCut)
		}
		return exec(ctx, name, args...)
	}
}

// TestPoolCutCreateRegion kills the plugin inside cxl create-region, which
// leaves a hollow region (no target, not committed) that the memdev does
// not list; its name was recorded before the tool ran. The start disables
// the memdev and deletes that region through delete_region (plan-13
// bug-12: cxl destroy-region refuses it). When the start keeps the claim
// (the memdev could not be disabled), its Unprepare does, and so does its
// Prepare again after it prepared the device. A hollow region that no
// record names is never deleted.
func TestPoolCutCreateRegion(t *testing.T) {
	for _, next := range []string{"start", "unprepare", "prepare again"} {
		t.Run(next, func(t *testing.T) {
			e := newPoolTestEnv(t)
			e.f.plug("0xc1ee0001")
			e.f.hollowRegion("region7", "ram") // of someone else
			p := e.driver(t)
			e.cutInCreateRegion(p, "region1")
			cutPrepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData))
			if recs := e.preparingFile(t); recs["u1"] == nil ||
				!slices.Equal(recs["u1"].Regions, []preparingRegion{{Serial: 0xc1ee0001, Region: "region1", Decoder: "decoder0.0"}}) {
				t.Fatalf("record %+v", recs["u1"])
			}
			// the kernel names the lowest free id next
			e.f.write("bus/cxl/devices/decoder0.0/create_ram_region", "region0")

			if next != "start" {
				e.f.failCmd = "cxl disable-memdev"
			}
			p2 := e.driver(t)
			e.f.failCmd = ""
			if next != "start" {
				e.wantPreparing(t, p2, "u1", 0xc1ee0001, api.ModeNUMA)
				if p2.preparing["u1"].Devices[0].Node != -1 {
					t.Fatalf("node of a device without a region %+v", p2.preparing["u1"].Devices[0])
				}
				if !p2.mem.HollowRegion("region1") {
					t.Fatalf("region1 deleted at start:\n%s", e.f.commands())
				}
			}
			switch next {
			case "start":
				ncmds := e.f.commands()
				if !strings.HasSuffix(ncmds, "cxl disable-memdev mem0\ndelete_region decoder0.0 region1") {
					t.Fatalf("commands:\n%s", ncmds)
				}
				noErr(t, unprepare(t, p2, "u1"))
				if e.f.commands() != ncmds {
					t.Fatalf("the Unprepare ran commands:\n%s", strings.TrimPrefix(e.f.commands(), ncmds))
				}
			case "unprepare":
				noErr(t, unprepare(t, p2, "u1"))
				if !strings.HasSuffix(e.f.commands(), "cxl disable-memdev mem0\ndelete_region decoder0.0 region1") {
					t.Fatalf("commands:\n%s", e.f.commands())
				}
			case "prepare again":
				noErr(t, prepare(t, p2, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err)
				if !strings.HasSuffix(e.f.commands(), "delete_region decoder0.0 region1") || p2.prepared["u1"].Devices[0].Region != "region0" {
					t.Fatalf("commands:\n%s", e.f.commands())
				}
				e.wantRegion(t, true)
				noErr(t, unprepare(t, p2, "u1"))
				e.f.wantReleased(t)
			}
			if _, err := os.Lstat(e.f.p("bus/cxl/devices/region1")); !os.IsNotExist(err) {
				t.Fatalf("hollow region left: %v", err)
			}
			if !p2.mem.HollowRegion("region7") {
				t.Fatalf("the hollow region of someone else was deleted:\n%s", e.f.commands())
			}
			e.wantClean(t, p2)
		})
	}
}

// TestPoolRollbackKeepsForeignHollowRegion: the rollback of a Prepare
// whose cxl create-region failed deletes no hollow region that its record
// does not name (another owner's, under the same root decoder, as the
// local memdev of the e2e VMs).
func TestPoolRollbackKeepsForeignHollowRegion(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ee0001")
	e.f.hollowRegion("region7", "ram")
	e.f.write("bus/cxl/devices/decoder0.0/create_ram_region", "region8")
	p := e.driver(t)
	p.retryDelay = 0
	exec := p.mem.Exec
	p.mem.Exec = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "cxl" && args[0] == "create-region" {
			return "", errors.New("cxl create-region: failed to set target0 to mem0")
		}
		return exec(ctx, name, args...)
	}
	wantErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err, "failed to set target0")
	if strings.Contains(e.f.commands(), "delete_region") || !p.mem.HollowRegion("region7") {
		t.Fatalf("commands:\n%s", e.f.commands())
	}
	e.wantClean(t, p)
}

// TestPoolRegionNoteReplaced: when cxl create-region creates another region
// than the root decoder named before (another process created one in
// between), the record names the region that it created.
func TestPoolRegionNoteReplaced(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ee0001")
	e.f.write("bus/cxl/devices/decoder0.0/create_ram_region", "region5")
	p := e.driver(t)
	// killed while the memory goes online, after the region was created
	p.mem.WriteFile = func(path, val string) error {
		err := e.f.writeAttr(path, val)
		if val == "online_movable" {
			panic(errCut)
		}
		return err
	}
	cutPrepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData))
	if rec := e.preparingFile(t)["u1"]; rec == nil || !slices.Equal(rec.Regions, []preparingRegion{{Serial: 0xc1ee0001, Region: "region0", Decoder: "decoder0.0"}}) {
		t.Fatalf("record %+v", rec)
	}
}

// TestPoolUnprepareHollowRegion unprepares a prepared claim whose memdev
// was removed while its region existed: the kernel left the region hollow,
// the Unprepare deletes it. A region of a removed memdev that is not
// hollow, or whose memory is still online, is left alone.
func TestPoolUnprepareHollowRegion(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ee0001")
	p := e.driver(t)
	noErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err)
	e.f.unplug()
	e.f.hollowRegion("region0", "ram")
	noErr(t, unprepare(t, p, "u1"))
	if !strings.HasSuffix(e.f.commands(), "delete_region decoder0.0 region0") {
		t.Fatalf("commands:\n%s", e.f.commands())
	}
	e.wantRegion(t, false)
	e.wantClean(t, p)

	for _, tc := range []struct{ name, file, value string }{
		{"committed", "bus/cxl/devices/decoder0.0/region0/commit", "1"},
		{"online memory", "devices/system/memory/memory75/state", "online_movable"},
	} {
		e.f.plug("0xc1ee0001")
		noErr(t, prepare(t, p, poolClaim("u2", "c2", "pooled0", exclusiveData)).Err)
		e.f.unplug()
		e.f.hollowRegion("region0", "ram")
		// over the memory blocks 74 and 75
		e.f.write("bus/cxl/devices/decoder0.0/region0/resource", "0x250000000")
		e.f.write("devices/system/memory/memory74/state", "offline")
		e.f.write("devices/system/memory/memory75/state", "offline")
		e.f.write(tc.file, tc.value)
		ncmds := e.f.commands()
		noErr(t, unprepare(t, p, "u2"))
		if e.f.commands() != ncmds {
			t.Fatalf("%s: commands:\n%s", tc.name, strings.TrimPrefix(e.f.commands(), ncmds))
		}
		e.wantRegion(t, true)
		e.wantClean(t, p)
		e.f.write("devices/system/memory/memory75/state", "offline")
	}
}

// TestPoolForgetSaveFails: a record is forgotten only when the preparing
// file without it is saved: the start releases the device of a cut
// Prepare and keeps its record, the Unprepare of the unfinished claim
// fails, and kubelet's retry finds the record and forgets it; a Prepare
// that cannot forget its record leaves it to the claim's Unprepare.
func TestPoolForgetSaveFails(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ee0001")
	p := e.driver(t)
	e.f.cutAfter = "cxl create-region"
	cutPrepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData))
	tmp := filepath.Join(filepath.Dir(e.stateFile), poolPreparingFileName) + ".tmp"
	noErr(t, os.MkdirAll(tmp, 0o755))
	p2 := e.driver(t)
	e.f.wantReleased(t)
	if p2.preparing["u1"] == nil || e.preparingFile(t)["u1"] == nil {
		t.Fatalf("record forgotten at start without its save: %v", p2.preparing)
	}
	wantErr(t, unprepare(t, p2, "u1"), poolPreparingFileName)
	if p2.preparing["u1"] == nil || e.preparingFile(t)["u1"] == nil {
		t.Fatalf("record forgotten without its save: %v", p2.preparing)
	}
	noErr(t, os.Remove(tmp))
	noErr(t, unprepare(t, p2, "u1"))
	e.f.wantReleased(t)
	e.wantClean(t, p2)
	if p := e.driver(t); len(p.preparing) != 0 {
		t.Fatalf("record back after a restart: %v", p.preparing)
	}

	// a Prepare that cannot forget the record: prepared, the record
	// stays until the Unprepare
	exec := p2.mem.Exec
	p2.mem.Exec = func(ctx context.Context, name string, args ...string) (string, error) {
		out, err := exec(ctx, name, args...)
		if name == "daxctl" || (name == "cxl" && args[0] == "create-region") {
			_ = os.MkdirAll(tmp, 0o755)
		}
		return out, err
	}
	noErr(t, prepare(t, p2, poolClaim("u2", "c2", "pooled0", exclusiveData)).Err)
	if p2.prepared["u2"] == nil || p2.preparing["u2"] == nil {
		t.Fatalf("prepared %v, preparing %v", p2.prepared, p2.preparing)
	}
	noErr(t, os.Remove(tmp))
	noErr(t, unprepare(t, p2, "u2"))
	e.f.wantReleased(t)
	e.wantClean(t, p2)
}

// TestPoolPreparingSaveFails: a Prepare whose record cannot be saved fails
// before it touches the device.
func TestPoolPreparingSaveFails(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ee0001")
	p := e.driver(t)
	tmp := filepath.Join(filepath.Dir(e.stateFile), poolPreparingFileName) + ".tmp"
	noErr(t, os.MkdirAll(tmp, 0o755))
	wantErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err, poolPreparingFileName)
	if cmds := e.f.commands(); cmds != "" {
		t.Fatalf("the device was touched:\n%s", cmds)
	}
	e.wantClean(t, p)
	noErr(t, os.Remove(tmp))
	noErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err)
	noErr(t, unprepare(t, p, "u1"))
	e.wantClean(t, p)
}

// TestPoolPreparingLoad loads a preparing file whose claim is prepared (the
// plugin stopped after the state was saved), which is forgotten, one whose
// claim has no memdev on the node, likewise, and a preparing file that
// cannot be parsed, which is taken as empty.
func TestPoolPreparingLoad(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plug("0xc1ee0001")
	p := e.driver(t)
	claim := poolClaim("u1", "c1", "pooled0", exclusiveData)
	noErr(t, prepare(t, p, claim).Err)
	file := filepath.Join(filepath.Dir(e.stateFile), poolPreparingFileName)
	p.preparing["u1"] = &preparingPoolClaim{ClaimName: "default/c1", Devices: []preparedPoolDevice{{Serial: 0xc1ee0001, Mode: api.ModeNUMA, Node: -1}}}
	noErr(t, p.savePreparing())

	p2 := e.driver(t)
	if p2.prepared["u1"] == nil || len(p2.preparing) != 0 || len(e.preparingFile(t)) != 0 {
		t.Fatalf("prepared %v, preparing %v, file %v", p2.prepared, p2.preparing, e.preparingFile(t))
	}
	// a claim whose memdev is not on the node is forgotten
	p2.preparing["u2"] = &preparingPoolClaim{ClaimName: "default/c2", Devices: []preparedPoolDevice{{Serial: 0xc1ee0009, Mode: api.ModeNUMA, Node: -1}}}
	noErr(t, p2.savePreparing())
	if p := e.driver(t); len(p.preparing) != 0 || len(e.preparingFile(t)) != 0 || p.Serials()[0xc1ee0009] {
		t.Fatalf("preparing %v, file %v, serials %v", p.preparing, e.preparingFile(t), p.Serials())
	}
	noErr(t, os.WriteFile(file, []byte("{"), 0o600))
	p3 := e.driver(t)
	if p3.prepared["u1"] == nil || len(p3.preparing) != 0 {
		t.Fatalf("prepared %v, preparing %v", p3.prepared, p3.preparing)
	}
	noErr(t, unprepare(t, p3, "u1"))
	e.f.wantReleased(t)
	if data, _ := os.ReadFile(file); string(data) != "{" {
		t.Fatalf("preparing file %q", data)
	}
}

// TestBuildDevInfosHollowRegion: a hollow region of a scan is not
// published, the other devices are, and it is warned about once while it
// stays. The hollow region still has a node: memory of its address range
// that kmem could not remove is online, so the scan finds the node and
// the region enabled; that node is not DRAM either.
func TestBuildDevInfosHollowRegion(t *testing.T) {
	devices := nricxl.NewDevices()
	hollow := &nricxl.RegionDevice{Name: "region1", SysfsPath: "/sys/bus/cxl/devices/region1", Mode: "ram", Resource: 0x850000000, Size: 1 << 28,
		Node: 3, Enabled: true, OnlineSize: 1 << 28, Hollow: true}
	devices.RegionDevices = []*nricxl.RegionDevice{
		{Name: "region0", Size: 1 << 30, Mode: "ram", Node: 2, Enabled: true, Targets: []string{"decoder4.0"},
			Memories: []*nricxl.MemoryDevice{{Name: "mem0", Serial: 0xc100e2e0, Enabled: true}}},
		hollow,
	}
	devices.MemoryNodes = []*nricxl.MemoryNode{{ID: 0, Size: 1 << 30}, {ID: 2, Size: 1 << 30}, {ID: 3, Size: 1 << 28}}
	devInfos, err := buildDevInfos(&DriverConfig{}, devices, nil, nil)
	noErr(t, err)
	if devInfos["region0-node2"] == nil || devInfos["region1-node3"] != nil || len(devInfos) != 2 {
		t.Fatalf("devices %v", slices.Sorted(maps.Keys(devInfos)))
	}
	if dram, ok := devInfos["dram"].Dev.(*device.DRAM); !ok || !slices.Equal(dram.Nodes, []int{0}) {
		t.Fatalf("DRAM %+v", devInfos["dram"])
	}

	h := &hollowRegionLog{warned: map[string]bool{}}
	for i, want := range []int{1, 1, 0} {
		regions := devices.RegionDevices
		if want == 0 {
			regions = regions[:1]
		}
		if got := h.observe(regions); len(got) != want || (want == 1 && !got[hollow]) || len(h.warned) != want {
			t.Fatalf("scan %d: hollow %v, warned %v", i, got, h.warned)
		}
	}
}
