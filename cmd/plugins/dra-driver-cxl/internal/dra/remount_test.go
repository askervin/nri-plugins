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

package dra

import (
	"path/filepath"
	"syscall"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// unrestore unmounts the node mount mnt of a prepared claim of mode fs and
// makes the mounts of the block device dev fail, then restarts the drivers:
// the claim is PREPARED_UNRESTORED. It returns why its grant (result 0) is
// unrestored, as the recovery says.
func (e *driverEnv) unrestore(p *Plugin, uid, mnt, dev string) error {
	e.t.Helper()
	mustOK(e.t, e.k.Kernel().Unmount(mnt))
	e.k.SetMountError(dev, syscall.EIO, "")
	rec := e.restart()
	p = e.pluginOf(p.Name() == device.DriverName)
	e.wantState(p, uid, state.PreparationUnrestored)
	why := rec.Why[state.GrantRef{Claim: uid}]
	if why == nil {
		e.t.Fatalf("no reason of the unrestored grant of %s: %+v", uid, rec)
	}
	if e.cdiDevice(p, "claim-"+uid+"-0") != nil {
		e.t.Fatal("a CDI device of an unrestored claim")
	}
	if got := p.Unrestored()[uid]; got == nil || got.Error() != why.Error() {
		e.t.Fatalf("unrestored %v, expected %v", got, why)
	}
	return why
}

// A claim of cxl.nri.io whose node mount the start could not mount again:
// no CDI device, logged at the start; a Prepare again that fails keeps it
// unrestored, one that mounts the node mount again gives it its CDI device
// again.
func TestRemountLocal(t *testing.T) {
	e := newDriverEnv(t, []fake.MemdevSpec{pmemSpec()})
	dev := e.formatPmem(serialPmem, "ext4")
	claim := localClaim("r1", pmemDev, -1, cfgFsRO)
	e.mustPrepare(e.local, claim)
	mnt := filepath.Join(e.dir, "mounts", "c100f5e1-direct")
	logs := klogCapture(t)
	why := e.unrestore(e.local, "r1", mnt, dev)
	wantLogText(t, logs(), "claim demo/claim-r1 (r1) has no CDI device: "+why.Error()+"; a new container of it fails on its CDI device, "+
		"its Prepare again tries to mount it again, its Unprepare releases the device")
	res := e.prepare(e.local, claim)
	wantErrText(t, res.Err, "claim demo/claim-r1: ")
	wantErrText(t, res.Err, "; unprepare the claim (delete its pods) to prepare it anew")
	e.wantState(e.local, "r1", state.PreparationUnrestored)
	e.k.SetMountError(dev, nil, "")
	e.mustPrepare(e.local, claim)
	e.wantState(e.local, "r1", state.PreparationPrepared)
	log := logs()
	wantLogText(t, log, "local: claim r1: "+mnt+" is mounted again (it was not: "+why.Error()+")")
	wantLogText(t, log, "claim demo/claim-r1 (r1): its devices are restored: it has its CDI devices again")
	if e.cdiDevice(e.local, "claim-r1-0") == nil || e.local.Unrestored()["r1"] != nil {
		t.Fatalf("not restored: %v", e.local.Unrestored())
	}
	e.mustUnprepare(e.local, "r1")
	e.wantClean()
}

// A claim of the pool driver whose node mount the start could not mount
// again, in the pool driver's words; its Unprepare while unrestored
// releases it.
func TestRemountPool(t *testing.T) {
	e := newDriverEnv(t, nil, poolPmemSpec(serialPoolP))
	dev := e.formatPmem(serialPoolP, "erofs")
	claim := poolClaim("r1", "llm0", poolPmemData, cfgFsRO)
	e.mustPrepare(e.pool, claim)
	mnt := filepath.Join(e.poolDir, "mounts", "c1af0001-direct")
	logs := klogCapture(t)
	why := e.unrestore(e.pool, "r1", mnt, dev)
	log := logs()
	wantLogText(t, log, "cxl-pool.nri.io: claim demo/claim-r1 (r1) has no CDI device: its node mount "+mnt+" is not mounted ("+why.Error()+
		"); a new container of it fails on its CDI device, its Prepare again tries to mount it again, its Unprepare releases the device")
	wantLogText(t, log, "cxl-pool.nri.io: loaded 1 prepared claims from "+filepath.Join(e.poolDir, "preparedPoolClaims.json"))
	wantErrText(t, e.prepare(e.pool, claim).Err, "cxl-pool.nri.io: preparing claim demo/claim-r1: ")
	e.wantState(e.pool, "r1", state.PreparationUnrestored)
	e.k.SetMountError(dev, nil, "")
	e.mustPrepare(e.pool, claim)
	e.wantState(e.pool, "r1", state.PreparationPrepared)
	wantLogText(t, logs(), "cxl-pool.nri.io: claim demo/claim-r1: "+mnt+" is mounted again: the claims of it have their CDI devices again")
	if e.cdiDevice(e.pool, "claim-r1-0") == nil {
		t.Fatal("no CDI device after the remount")
	}
	// unrestored again: the Unprepare releases it
	_ = e.unrestore(e.pool, "r1", mnt, dev)
	e.mustUnprepare(e.pool, "r1")
	e.k.SetMountError(dev, nil, "")
	e.wantClean()
}

// Two claims of one node mount that the start could not mount again: the
// Prepare again of one mounts it again for both, and both have their CDI
// devices again.
func TestRemountTwoClaims(t *testing.T) {
	for _, local := range []bool{true, false} {
		e := newDriverEnv(t, []fake.MemdevSpec{pmemSpec()}, poolPmemSpec(serialPoolP))
		p := e.pluginOf(local)
		t.Run(p.Name(), func(t *testing.T) {
			e.t = t
			serial, typ, mnt := uint64(serialPoolP), "erofs", filepath.Join(e.poolDir, "mounts", "c1af0001-direct")
			claim := func(uid string) *resourcev1.ResourceClaim { return poolClaim(uid, "llm0", poolPmemData, cfgFsRO) }
			if local {
				serial, typ, mnt = serialPmem, "ext4", filepath.Join(e.dir, "mounts", "c100f5e1-direct")
				claim = func(uid string) *resourcev1.ResourceClaim { return localClaim(uid, pmemDev, -1, cfgFsRO) }
			}
			dev := e.formatPmem(serial, typ)
			e.mustPrepare(p, claim("r1"))
			e.mustPrepare(p, claim("r2"))
			_ = e.unrestore(p, "r1", mnt, dev)
			p = e.pluginOf(local)
			e.wantState(p, "r2", state.PreparationUnrestored)
			e.k.SetMountError(dev, nil, "")
			e.mustPrepare(p, claim("r1"))
			e.wantState(p, "r1", state.PreparationPrepared)
			// the start mounts the node mount of both again
			e.wantState(p, "r2", state.PreparationPrepared)
			if e.cdiDevice(p, "claim-r2-0") == nil || p.Unrestored()["r2"] != nil {
				t.Fatalf("r2 is not restored: %v", p.Unrestored())
			}
			e.mustPrepare(p, claim("r2"))
			e.wantState(p, "r2", state.PreparationPrepared)
			if e.cdiDevice(p, "claim-r2-0") == nil || p.Unrestored()["r2"] != nil {
				t.Fatalf("r2 is not restored: %v", p.Unrestored())
			}
			e.mustUnprepare(p, "r1")
			e.mustUnprepare(p, "r2")
			e.wantClean()
		})
	}
}
