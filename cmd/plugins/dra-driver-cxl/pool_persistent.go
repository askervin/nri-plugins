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
	"fmt"
	"maps"
	"slices"
	"time"

	"k8s.io/klog/v2"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/memctl"
)

// Pool devices of persistent memory: the pool driver gives a container the
// block device of the fsdax namespace of the device (mode block), or a
// filesystem on it (mode fs) through a node mount per device and access
// that the claims of the node share (docs/memory/cxl/usage.md), with the
// shared code of persistent.go. An fs lease gets a bind of the node mount
// in the lease-fs directory of its lease claim, which propagates into the
// running containers of the claim (docs/memory/cxl/leases.md).

// defaultFsPathDir is the directory of the default path of mode fs in
// containers, /run/cxl-fs/<KEY>.
const defaultFsPathDir = "/run/cxl-fs"

// persistentMode tells whether a mode is a mode of persistent devices.
func persistentMode(mode string) bool {
	return mode == api.ModeBlock || mode == api.ModeFs
}

// defaultFsPath returns the path of mode fs of the memory with the env key
// in a container when its device settings have none.
func defaultFsPath(key string) string {
	return defaultFsPathDir + "/" + key
}

// nodeMountPath returns the node mount of mode fs of the device with the
// serial and the access: <data dir>/mounts/<serial hex>-<access>.
func (p *poolDriver) nodeMountPath(serial uint64, access string) string {
	return p.pn.NodeMountPath(serial, access)
}

// mountsDir returns the directory of the node mounts of mode fs.
func (p *poolDriver) mountsDir() string {
	return p.pn.MountsDir()
}

// persistentUse returns the device of the claim uid as a use of a
// persistent device.
func (d *preparedPoolDevice) persistentUse(uid string) persistentUse {
	return persistentUse{UID: uid, Result: d.Result, Serial: d.Serial, Mode: d.Mode, ReadOnly: d.ReadOnly, Access: d.Access,
		FsType: d.FsType, BlockDevice: d.BlockDevice, NodeMount: d.NodeMount, LoopDevice: d.LoopDevice}
}

// persistentUsesOf returns the persistent devices of a claim uid as uses.
func persistentUsesOf(uid string, devs []preparedPoolDevice) []persistentUse {
	var out []persistentUse
	for i := range devs {
		if devs[i].Persistent {
			out = append(out, devs[i].persistentUse(uid))
		}
	}
	return out
}

// persistentUses returns the uses of the device with the serial by the
// prepared claims other than exceptUID ("": every claim).
func (p *poolDriver) persistentUses(serial uint64, exceptUID string) []persistentUse {
	var out []persistentUse
	for _, uid := range slices.Sorted(maps.Keys(p.prepared)) {
		if uid == exceptUID {
			continue
		}
		out = append(out, usesOf(serial, persistentUsesOf(uid, p.prepared[uid].Devices))...)
	}
	return out
}

// otherBind returns whether a prepared claim other than exceptUID lists a
// lease bind.
func (p *poolDriver) otherBind(exceptUID string) func(target string) bool {
	return func(target string) bool { return p.leaseBindUsed(target, exceptUID) }
}

// preparePersistent prepares a device of persistent memory on the memdev
// in mode block or fs into dev for the claim uid next to the uses others
// of the device on the node: a pmem region with an fsdax namespace, which
// only a writable block claim creates, then the use (persistentNode.
// Prepare). On error dev has the block device if it was found. note is
// told about a new region.
func (p *poolDriver) preparePersistent(ctx context.Context, uid string, memdev string, data *poolDevice, dev *preparedPoolDevice, note memctl.RegionNote, others []persistentUse) error {
	serial := api.FormatSerial(data.Serial)
	ok, err := p.mem.Persistent(memdev)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("device %s: %s has no persistent memory", serial, memdev)
	}
	wctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	pr, err := p.mem.CreatePmemRegionNoted(wctx, memdev, "", note)
	if err != nil {
		return err
	}
	dev.Region, dev.NdRegion = pr.Region, pr.NdRegion
	ns, err := pmemNamespace(wctx, p.mem, data.Serial, pr, data.Mode, data.ReadOnly)
	if err != nil {
		return err
	}
	dev.Namespace, dev.BlockDevice, dev.BlockMajor, dev.BlockMinor = ns.Name, ns.BlockDevice, ns.Major, ns.Minor
	dev.Size = ns.Size
	if data.Mode == api.ModeFs {
		dev.Path = data.Path
	}
	use, err := p.pn.Prepare(ctx, persistentTarget{Serial: data.Serial, BlockDevice: dev.BlockDevice, Facts: data.facts()},
		persistentWant{UID: uid, Result: dev.Result, Mode: data.Mode, ReadOnly: data.ReadOnly, Access: data.Access, FsType: data.FsType}, others)
	if err != nil {
		return err
	}
	dev.Access, dev.FsType, dev.NodeMount, dev.LoopDevice = use.Access, use.FsType, use.NodeMount, use.LoopDevice
	return nil
}

// checkNodeMount returns the loop device of an existing cached node mount,
// or an error if the mount at the node mount is not the filesystem of the
// block device for the access.
func (p *poolDriver) checkNodeMount(serial uint64, blockDev, access string, mi *mountInfo) (string, error) {
	return p.pn.checkNodeMount(serial, blockDev, access, "", mi)
}

// waitNoHolder waits until the deadline until nothing holds the block
// device of a persistent device (persistentNode.WaitNoHolder).
func (p *poolDriver) waitNoHolder(ctx context.Context, serial uint64, blockDev string, deadline time.Time) error {
	return p.pn.WaitNoHolder(ctx, serial, blockDev, deadline)
}

// releaseDevices releases the devices that a claim (uid) prepared or
// failed to prepare, devs, and the serials that it touched without such a
// device. The uses of persistent devices go first (persistentNode.Release:
// the node mounts that no other claim uses are unmounted, superblocks and
// block devices read-only when no writer stays), then each serial that no
// other claim uses is released when nothing holds its block device any
// more, waiting at most the holder wait for all of them together. A serial
// whose uses cannot be released is not released. The regions of devs of a
// memdev that is gone are deleted when the kernel left them hollow
// (memctl.HollowRegion).
func (p *poolDriver) releaseDevices(ctx context.Context, uid string, devs []preparedPoolDevice, serials []uint64) []error {
	p.unbindStale(ctx)
	var errs []error
	blockDevs := map[uint64]string{}
	regions := map[uint64][]string{}
	names := map[uint64]string{}
	gone := map[uint64][]persistentUse{}
	for i := range devs {
		d := &devs[i]
		if !slices.Contains(serials, d.Serial) {
			serials = append(serials, d.Serial)
		}
		if names[d.Serial] == "" {
			names[d.Serial] = d.Device
		}
		if d.BlockDevice != "" {
			blockDevs[d.Serial] = d.BlockDevice
		}
		if d.Region != "" && !slices.Contains(regions[d.Serial], d.Region) {
			regions[d.Serial] = append(regions[d.Serial], d.Region)
		}
		if d.Persistent {
			gone[d.Serial] = append(gone[d.Serial], d.persistentUse(uid))
		}
	}
	failed := map[uint64]bool{}
	for _, serial := range serials {
		if len(gone[serial]) == 0 {
			continue
		}
		if err := p.pn.Release(ctx, serial, gone[serial], p.persistentUses(serial, uid)); err != nil {
			errs = append(errs, fmt.Errorf("releasing %s (serial 0x%x): %w", names[serial], serial, err))
			failed[serial] = true
		}
	}
	deadline := time.Now().Add(p.pn.HolderWait())
	for _, serial := range serials {
		if failed[serial] {
			continue
		}
		if p.preparedDevice(serial, uid) != nil {
			klog.Infof("%s: serial 0x%x is still used by another claim", p.name, serial)
			continue
		}
		if dev := blockDevs[serial]; dev != "" {
			if err := p.waitNoHolder(ctx, serial, dev, deadline); err != nil {
				errs = append(errs, fmt.Errorf("releasing serial 0x%x: %w", serial, err))
				continue
			}
		}
		gone, err := p.release(ctx, serial)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("releasing serial 0x%x: %w", serial, err))
		case gone:
			p.deleteHollowRegions(uid, serial, regions[serial], "its memdev was removed before the region was destroyed")
		}
	}
	return errs
}

// currentBlockDevice returns the block device of the fsdax namespace of
// the region of the memdev with the serial, else of another namespace of
// it with a block device, "" if there is none.
func (p *poolDriver) currentBlockDevice(serial uint64) string {
	return currentPmemBlockDevice(p.mem, p.timeout, serial)
}

// releasedDevices returns the devices of a prepared claim as releaseDevices
// releases them. The block device of a persistent device is the recorded
// one, unless the start could not mount its node mount again (unrestored)
// or it is not the one of its region now (checkBlockDevice: the region is
// gone, or its namespace has other numbers). Then the recorded one may be
// another device's now, and the release would wait for its holder in vain
// (plan-13 bug-15 review): it is that of its region now
// (currentBlockDevice), as for a claim whose Prepare did not finish, none
// when the memdev has no region. The recorded one stays when the
// namespaces of the region cannot be read now: none would release the
// device without the holder check.
func (p *poolDriver) releasedDevices(pc *preparedPoolClaim) []preparedPoolDevice {
	devs := slices.Clone(pc.Devices)
	for i := range devs {
		d := &devs[i]
		if !d.Persistent || d.BlockDevice == "" {
			continue
		}
		err, unrestored := p.pn.Unrestored(d.NodeMount)
		if d.NodeMount == "" || !unrestored {
			err = p.checkBlockDevice(d)
		}
		if err == nil {
			continue
		}
		s := api.FormatSerial(d.Serial)
		cur := p.currentBlockDevice(d.Serial)
		switch {
		case cur == "" && p.hasRegion(d.Serial):
			klog.Warningf("%s: claim %s: %v; the block device of the region of device %s is not known now: its release waits for the holders of %s as prepared",
				p.name, pc.ClaimName, err, s, d.BlockDevice)
			continue
		case cur == "":
			klog.Infof("%s: claim %s: %v; device %s has no region now: its release waits for no holder of %s",
				p.name, pc.ClaimName, err, s, d.BlockDevice)
		default:
			klog.Infof("%s: claim %s: %v; the release of device %s waits for the holders of %s, the block device of its region now, not of %s",
				p.name, pc.ClaimName, err, s, cur, d.BlockDevice)
		}
		d.BlockDevice = cur
	}
	return devs
}

// hasRegion tells whether the memdev with the serial has a region.
func (p *poolDriver) hasRegion(serial uint64) bool {
	memdev, err := p.mem.FindMemdev(serial)
	return err == nil && len(p.mem.Regions(memdev)) > 0
}

// deleteHollowRegions deletes the regions that the pool driver knows as
// its own, regions, if they are hollow (memctl.HollowRegion): the regions
// of a device with the serial, why tells how they became hollow. A region
// that a prepared claim other than exceptUID records is kept. It returns
// the errors, which are also logged: a hollow region does not keep the
// pool from removing the device, it only holds its address range in the
// root decoder.
func (p *poolDriver) deleteHollowRegions(exceptUID string, serial uint64, regions []string, why string) []error {
	var errs []error
	for _, r := range regions {
		if !p.mem.HollowRegion(r) || p.regionUsed(r, exceptUID) {
			continue
		}
		klog.Warningf("%s: serial 0x%x: %s has no target decoder (%s): deleting it", p.name, serial, r, why)
		if err := p.mem.DeleteHollowRegion(r); err != nil {
			errs = append(errs, err)
			decoder, derr := p.mem.RegionRootDecoder(r)
			if derr != nil {
				decoder = "<its root decoder>"
			}
			klog.Errorf("%s: serial 0x%x: %v; it holds its address range until it is deleted, when none of its memory blocks is online: echo %s > /sys/bus/cxl/devices/%s/delete_region",
				p.name, serial, err, r, decoder)
			continue
		}
		klog.Infof("%s: serial 0x%x: deleted hollow %s", p.name, serial, r)
	}
	return errs
}

// regionUsed tells whether a device of a prepared claim other than
// exceptUID records the region.
func (p *poolDriver) regionUsed(region, exceptUID string) bool {
	for uid, pc := range p.prepared {
		if uid == exceptUID {
			continue
		}
		for i := range pc.Devices {
			if pc.Devices[i].Region == region {
				return true
			}
		}
	}
	return false
}

// bindLeaseMounts binds the node mount of the device of mode fs of a
// companion claim (uid) in the lease-fs directory of its lend
// (persistentNode.BindLease).
func (p *poolDriver) bindLeaseMounts(uid string, rec *lendRecord, devs []preparedPoolDevice) error {
	return p.pn.BindLease(rec, persistentUsesOf(uid, devs), p.otherBind(uid))
}

// unbindLeaseMounts unmounts the lease binds of a lend of the claim
// exceptUID that no other prepared claim lists (persistentNode.
// UnbindLease).
func (p *poolDriver) unbindLeaseMounts(rec *lendRecord, exceptUID string) error {
	return p.pn.UnbindLease(rec, p.otherBind(exceptUID))
}

// addStaleBind records a stale bind, once per target.
func (p *poolDriver) addStaleBind(sb staleBind) {
	p.pn.addStaleBind(sb)
}

// unbindStale unmounts the stale binds that are in no prepared claim
// (persistentNode.UnbindStale); then the serial of a stale bind that is
// gone is released when no prepared or inflight claim has it and nothing
// holds its block device within the holder wait. Errors are logged.
func (p *poolDriver) unbindStale(ctx context.Context) {
	for _, sb := range p.pn.UnbindStale(p.otherBind("")) {
		p.releaseUnused(ctx, sb.Serial, sb.BlockDevice)
	}
}

// releaseUnused releases the serial when no prepared or inflight claim
// has it and nothing holds its block device within the holder wait.
// Errors are logged.
func (p *poolDriver) releaseUnused(ctx context.Context, serial uint64, blockDev string) {
	if p.preparedDevice(serial, "") != nil || p.inflight[serial] > 0 {
		return
	}
	if err := p.waitNoHolder(ctx, serial, blockDev, time.Now().Add(p.pn.HolderWait())); err != nil {
		klog.Errorf("%s: not releasing serial 0x%x after its stale lease bind: %v", p.name, serial, err)
		return
	}
	if _, err := p.release(ctx, serial); err != nil {
		klog.Errorf("%s: releasing serial 0x%x after its stale lease bind: %v", p.name, serial, err)
	}
}

// leaseBindUsed tells whether a prepared claim other than exceptUID has
// the lease bind.
func (p *poolDriver) leaseBindUsed(target, exceptUID string) bool {
	for uid, pc := range p.prepared {
		if uid != exceptUID && pc.Lend != nil && slices.Contains(pc.Lend.Mounts, target) {
			return true
		}
	}
	return false
}

// bindOrigin returns the serial and the block device of the filesystem of
// a lease bind whose source is source (persistentNode.bindOrigin).
func (p *poolDriver) bindOrigin(mounts []mountInfo, source string) (uint64, string) {
	return p.pn.bindOrigin(mounts, source)
}

// fsDevice returns the first device of mode fs, nil if there is none.
func fsDevice(devs []preparedPoolDevice) *preparedPoolDevice {
	for i := range devs {
		if devs[i].Mode == api.ModeFs {
			return &devs[i]
		}
	}
	return nil
}

// leaseBinds returns the lease binds that the prepared claims list.
func (p *poolDriver) leaseBinds() map[string]bool {
	if p == nil {
		return nil
	}
	out := map[string]bool{}
	for _, pc := range p.prepared {
		if pc.Lend != nil {
			for _, t := range pc.Lend.Mounts {
				out[t] = true
			}
		}
	}
	return out
}

// persistent returns the persistent devices of the pool driver, nil for a
// nil (disabled) pool driver.
func (p *poolDriver) persistent() *persistentNode {
	if p == nil {
		return nil
	}
	return p.pn
}

// restoreMounts mounts again the node mounts of the prepared claims that
// are missing, with the superblock state and the read-only flags that
// their uses derive (persistentNode.RestoreMounts), binds again the lease
// binds of prepared companion claims that are missing, unmounts the lease
// binds of the node mounts of the driver that no prepared claim lists
// (persistentNode.RestoreLeaseBinds), then the node mounts that no
// prepared claim uses. A node mount that is not mounted after that is
// unrestored: the CDI device of a claim of it would bind a directory that
// is missing, and every start of its container would fail on the bind
// (plan-13 bug-15 R2: the region of the device is gone, by a reboot that
// the boot ids do not tell, or a device removed and added again). Its
// claims, but companion claims, stay prepared without a CDI device: a new
// container of them fails at its creation on an unresolvable CDI device,
// their Unprepare releases the device, their Prepare again and the next
// start try to mount it again.
func (p *poolDriver) restoreMounts() {
	var uses []persistentUse
	claimOf := map[string]string{}
	var claims []leaseBindClaim
	for _, uid := range slices.Sorted(maps.Keys(p.prepared)) {
		pc := p.prepared[uid]
		us := persistentUsesOf(uid, pc.Devices)
		uses = append(uses, us...)
		for _, u := range us {
			if u.NodeMount != "" && claimOf[u.NodeMount] == "" {
				claimOf[u.NodeMount] = pc.ClaimName
			}
		}
		if pc.Lend != nil {
			claims = append(claims, leaseBindClaim{UID: uid, ClaimName: pc.ClaimName, Lend: pc.Lend, Uses: us})
		}
	}
	restored := p.pn.RestoreMounts(uses, p.checkUseBlockDevice)
	for _, mnt := range slices.Sorted(maps.Keys(restored)) {
		if err := restored[mnt].Err; err != nil {
			klog.Errorf("%s: claim %s: %v", p.name, claimOf[mnt], err)
		}
	}
	for _, uid := range slices.Sorted(maps.Keys(p.prepared)) {
		if pc := p.prepared[uid]; pc.Lend == nil {
			if mnt := p.unrestoredMount(pc); mnt != "" {
				why, _ := p.pn.Unrestored(mnt)
				klog.Errorf("%s: claim %s (%s) has no CDI device: its node mount %s is not mounted (%v); a new container of it fails on its CDI device, its Prepare again tries to mount it again, its Unprepare releases the device",
					p.name, pc.ClaimName, uid, mnt, why)
			}
		}
	}
	changed := false
	for _, pc := range p.prepared {
		for i := range pc.Devices {
			d := &pc.Devices[i]
			if r, ok := restored[d.NodeMount]; ok && d.NodeMount != "" && r.Err == nil && r.Loop != d.LoopDevice {
				d.LoopDevice, changed = r.Loop, true
			}
		}
	}
	// the binds go before the node mounts: their sources tell which binds
	// are of the node mounts of this driver
	p.pn.RestoreLeaseBinds(claims)
	p.pn.SweepNodeMounts(uses)
	if changed {
		if err := p.save(); err != nil {
			klog.Errorf("%s: %v", p.name, err)
		}
	}
}

// checkUseBlockDevice returns an error if the block device blockDev of a
// prepared device with the serial is not the one of the fsdax namespace of
// its region now (checkBlockDevice).
func (p *poolDriver) checkUseBlockDevice(serial uint64, blockDev string) error {
	for _, uid := range slices.Sorted(maps.Keys(p.prepared)) {
		for i := range p.prepared[uid].Devices {
			if d := &p.prepared[uid].Devices[i]; d.Serial == serial && d.BlockDevice == blockDev {
				return p.checkBlockDevice(d)
			}
		}
	}
	return fmt.Errorf("device %s: no prepared device has %s", api.FormatSerial(serial), blockDev)
}

// unrestoredMount returns the first node mount of a prepared claim that the
// start could not mount again (unrestored), "" if it has none.
func (p *poolDriver) unrestoredMount(pc *preparedPoolClaim) string {
	for i := range pc.Devices {
		if mnt := pc.Devices[i].NodeMount; mnt != "" {
			if _, ok := p.pn.Unrestored(mnt); ok {
				return mnt
			}
		}
	}
	return ""
}

// remount mounts again the node mounts of a prepared claim that the start
// could not mount (unrestoredMount), for kubelet's Prepare again of the
// claim, and rewrites the CDI spec and the state file when it mounted one:
// the claims of the node mount have their CDI device again. An error
// names the node mount that stays unmounted; the claim must be unprepared
// to be prepared anew. Called with p.mu held.
func (p *poolDriver) remount(pc *preparedPoolClaim) error {
	changed := false
	for mnt := p.unrestoredMount(pc); mnt != ""; mnt = p.unrestoredMount(pc) {
		i := slices.IndexFunc(pc.Devices, func(d preparedPoolDevice) bool { return d.NodeMount == mnt })
		d := &pc.Devices[i]
		loop, err := p.pn.Remount(mnt, p.persistentUses(d.Serial, ""), p.checkUseBlockDevice)
		if err != nil {
			if changed {
				_ = p.sync()
			}
			return fmt.Errorf("device %s: its node mount %s is not mounted and cannot be mounted again: %w; unprepare the claim (delete its pods) to prepare it anew",
				api.FormatSerial(d.Serial), mnt, err)
		}
		for _, other := range p.prepared {
			for j := range other.Devices {
				if other.Devices[j].NodeMount == mnt {
					other.Devices[j].LoopDevice = loop
				}
			}
		}
		klog.Infof("%s: claim %s: %s is mounted again: the claims of it have their CDI devices again", p.name, pc.ClaimName, mnt)
		changed = true
	}
	if changed {
		return p.sync()
	}
	return nil
}

// checkBlockDevice returns an error if the block device of a prepared
// device is not the one of the fsdax namespace of the region of the memdev
// with its serial now: its name, numbers and namespace must be those that
// Prepare recorded.
func (p *poolDriver) checkBlockDevice(d *preparedPoolDevice) error {
	return checkPmemBlockDevice(p.mem, p.timeout, d.Serial, d.Namespace, d.BlockDevice, d.BlockMajor, d.BlockMinor)
}

// fsMount returns the CDI mount of the node mount of a device in mode fs.
func fsMount(d *preparedPoolDevice) *cdiSpecs.Mount {
	return fsCDIMount(d.NodeMount, d.Path, d.ReadOnly)
}
