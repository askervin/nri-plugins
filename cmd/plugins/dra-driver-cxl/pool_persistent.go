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
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/memctl"
)

// Pool devices of persistent memory: the pool driver gives a container the
// block device of the fsdax namespace of the device (mode block), or a
// read-only erofs filesystem on it (mode fs) through a node mount per
// device and access that the claims of the node share
// (docs/memory/cxl/usage.md). An fs lease gets a bind of the node mount
// in the lease-fs directory of its lease claim, which propagates into the
// running containers of the claim (docs/memory/cxl/leases.md).

const (
	// mountsDirName is the directory of the node mounts of mode fs in the
	// data directory of the pool driver.
	mountsDirName = "mounts"
	// defaultFsPathDir is the directory of the default path of mode fs in
	// containers, /run/cxl-fs/<KEY>.
	defaultFsPathDir = "/run/cxl-fs"
	// defaultHolderWait is how long one Unprepare or rollback waits for
	// the block devices of its persistent devices to have no holder
	// before releasing them.
	defaultHolderWait = 10 * time.Second
	// restoreProbeTimeout is how long the start waits for the namespaces
	// of a device whose node mount it mounts again.
	restoreProbeTimeout = 5 * time.Second
	// holderPoll is the interval of the checks of that wait.
	holderPoll = 100 * time.Millisecond
	// fsType is the filesystem type of mode fs.
	fsType = "erofs"
	// fsMountFlags are the flags of the node mounts of mode fs.
	fsMountFlags = unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV
	// daxAlways and daxNever are the erofs options of access direct and
	// cached.
	daxAlways = "dax=always"
	daxNever  = "dax=never"
	// maxUnbinds bounds the unmounts of one lease bind (stacked mounts).
	maxUnbinds = 8
)

// fsMountOptions are the options of the CDI bind mount of mode fs.
var fsMountOptions = []string{"bind", "ro", "nosuid", "nodev"}

// leaseBindFlags are the per-mount flags that a lease bind inherits from
// the node mount (fsMountFlags) and must have.
var leaseBindFlags = []string{"ro", "nosuid", "nodev"}

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
	return filepath.Join(p.mountsDir(), fmt.Sprintf("%x-%s", serial, access))
}

// mountsDir returns the directory of the node mounts of mode fs.
func (p *poolDriver) mountsDir() string {
	return filepath.Join(filepath.Dir(p.stateFile), mountsDirName)
}

// preparePersistent prepares a device of persistent memory on the memdev
// in mode block or fs into dev: a pmem region with an fsdax namespace,
// which only a writable block claim creates, and in mode fs the node
// mount of the device and the access. On error dev has the block device
// if it was found, and the node mount only if it is mounted.
func (p *poolDriver) preparePersistent(ctx context.Context, memdev string, data *poolDevice, dev *preparedPoolDevice) error {
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
	pr, err := p.mem.CreatePmemRegion(wctx, memdev, "")
	if err != nil {
		return err
	}
	dev.Region, dev.NdRegion = pr.Region, pr.NdRegion
	ns := memctl.FsdaxNamespace(pr.Namespaces)
	if ns == nil {
		if data.Mode == api.ModeFs || data.ReadOnly {
			return fmt.Errorf("device %s: no fsdax namespace in %s: has a writer written the device?", serial, pr.NdRegion)
		}
		existing := ""
		if len(pr.Namespaces) > 0 {
			existing = pr.Namespaces[0].Name
		}
		if ns, err = p.mem.CreateFsdaxNamespace(wctx, pr.NdRegion, existing); err != nil {
			return err
		}
	}
	dev.Namespace, dev.BlockDevice, dev.BlockMajor, dev.BlockMinor = ns.Name, ns.BlockDevice, ns.Major, ns.Minor
	dev.Size = ns.Size
	if data.Mode != api.ModeFs {
		return nil
	}
	dev.Access, dev.Path = data.Access, data.Path
	mnt := p.nodeMountPath(data.Serial, data.Access)
	if dev.LoopDevice, err = p.ensureNodeMount(data.Serial, dev.BlockDevice, dev.Access, mnt); err != nil {
		return err
	}
	dev.NodeMount = mnt
	return nil
}

// ensureNodeMount returns the loop device of a cached mount after it
// mounted the erofs of the block device at the node mount mnt for the
// access, or found it mounted there: direct on the block device with
// dax=always, cached on a read-only direct-I/O loop device over it with
// dax=never. Another mount at mnt is never used and never unmounted.
func (p *poolDriver) ensureNodeMount(serial uint64, blockDev, access, mnt string) (string, error) {
	s := api.FormatSerial(serial)
	mi, err := p.mounter.Mounted(mnt)
	if err != nil {
		return "", err
	}
	if mi != nil {
		return p.checkNodeMount(serial, blockDev, access, mi)
	}
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		return "", err
	}
	if access == api.AccessDirect {
		if err := p.mounter.Mount(blockDev, mnt, fsType, fsMountFlags, daxAlways); err != nil {
			p.removeMountDir(mnt)
			return "", fmt.Errorf("device %s: %s has no erofs filesystem: %w", s, blockDev, err)
		}
		// Another mount of the block device on the node has the
		// superblock, and its options win.
		mi, err := p.mounter.Mounted(mnt)
		if err == nil && (mi == nil || !mi.hasSuperOpt(daxAlways)) {
			err = fmt.Errorf("device %s: erofs on %s was mounted without DAX", s, blockDev)
		}
		if err != nil {
			if uerr := p.mounter.Unmount(mnt); uerr != nil {
				klog.Errorf("%s: device %s: unmounting %s: %v", p.name, s, mnt, uerr)
			} else {
				p.removeMountDir(mnt)
			}
			return "", err
		}
		klog.Infof("%s: device %s: mounted %s at %s (%s)", p.name, s, blockDev, mnt, daxAlways)
		return "", nil
	}
	loop, err := p.mounter.AttachLoop(blockDev)
	if err != nil {
		p.removeMountDir(mnt)
		return "", fmt.Errorf("device %s: a loop device over %s: %w", s, blockDev, err)
	}
	if err := p.mounter.Mount(loop.Path(), mnt, fsType, fsMountFlags, daxNever); err != nil {
		if lerr := loop.Release(true); lerr != nil {
			klog.Errorf("%s: device %s: detaching %s: %v", p.name, s, loop.Path(), lerr)
		}
		p.removeMountDir(mnt)
		return "", fmt.Errorf("device %s: %s has no erofs filesystem: %w", s, blockDev, err)
	}
	// the mount keeps the autoclear loop device
	if err := loop.Release(false); err != nil {
		klog.Warningf("%s: device %s: closing %s: %v", p.name, s, loop.Path(), err)
	}
	klog.Infof("%s: device %s: mounted %s over %s at %s (%s)", p.name, s, loop.Path(), blockDev, mnt, daxNever)
	return loop.Path(), nil
}

// checkNodeMount returns the loop device of an existing cached node mount,
// or an error if the mount at the node mount is not the erofs of the block
// device for the access: on the block device with dax=always (direct), on
// a loop device over it (cached).
func (p *poolDriver) checkNodeMount(serial uint64, blockDev, access string, mi *mountInfo) (string, error) {
	s := api.FormatSerial(serial)
	want := blockDev
	ok := mi.FsType == fsType
	if access == api.AccessCached {
		want = "a loop device over " + blockDev
		backing := ""
		if ok && strings.HasPrefix(mi.Source, "/dev/loop") {
			var err error
			if backing, err = p.mounter.LoopBackingFile(mi.Source); err != nil {
				return "", err
			}
		}
		ok = ok && sameDevice(backing, blockDev)
	} else {
		ok = ok && mi.Source == blockDev
	}
	if !ok {
		return "", fmt.Errorf("device %s: %s is a %s mount of %s, not of %s", s, mi.Target, mi.FsType, mi.Source, want)
	}
	if access == api.AccessCached {
		return mi.Source, nil
	}
	if !mi.hasSuperOpt(daxAlways) {
		return "", fmt.Errorf("device %s: erofs on %s was mounted without DAX", s, blockDev)
	}
	return "", nil
}

// removeMountDir removes the directory of a node mount that is not
// mounted.
func (p *poolDriver) removeMountDir(mnt string) {
	if err := os.Remove(mnt); err != nil && !errors.Is(err, os.ErrNotExist) {
		klog.Warningf("%s: removing %s: %v", p.name, mnt, err)
	}
}

// mountUsed tells whether a prepared claim other than exceptUID uses the
// node mount.
func (p *poolDriver) mountUsed(mnt, exceptUID string) bool {
	for uid, pc := range p.prepared {
		if uid == exceptUID {
			continue
		}
		for i := range pc.Devices {
			if pc.Devices[i].NodeMount == mnt {
				return true
			}
		}
	}
	return false
}

// unmountNode unmounts a node mount if it is mounted, never detaching it,
// and removes its directory. A busy mount is an error.
func (p *poolDriver) unmountNode(serial uint64, mnt string) error {
	mi, err := p.mounter.Mounted(mnt)
	if err != nil {
		return err
	}
	if mi != nil {
		if err := p.mounter.Unmount(mnt); err != nil {
			return fmt.Errorf("device %s: unmounting %s: %w", api.FormatSerial(serial), mnt, err)
		}
		klog.Infof("%s: device %s: unmounted %s", p.name, api.FormatSerial(serial), mnt)
	}
	p.removeMountDir(mnt)
	return nil
}

// waitNoHolder waits until the deadline until nothing holds the block
// device of a persistent device: no mount, no loop device, no exclusive
// open.
//
// This check is what keeps a region with a live superblock from being
// released, and it must stay: an umount succeeds while a bind of the same
// superblock exists elsewhere, and an rmdir of a directory that is a mount
// point in another mount namespace (the lease-fs and /run/cxl/fs mount
// points of a container namespace that outlives its lease claim) succeeds
// and detaches those mounts lazily (Linux 3.18 and later), so a lease bind
// can be gone from the plugin's view and still hold the device.
func (p *poolDriver) waitNoHolder(ctx context.Context, serial uint64, blockDev string, deadline time.Time) error {
	for {
		holder, err := p.mounter.Holder(blockDev)
		if err != nil {
			return err
		}
		if holder == "" {
			return nil
		}
		if !time.Now().Before(deadline) {
			klog.Warningf("%s: device %s: %s is held: %s", p.name, api.FormatSerial(serial), blockDev, holder)
			return fmt.Errorf("device %s: %s is still in use", api.FormatSerial(serial), blockDev)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("device %s: %s is still in use: %w", api.FormatSerial(serial), blockDev, ctx.Err())
		case <-time.After(holderPoll):
		}
	}
}

// releaseDevices releases the devices that a claim (uid) prepared or
// failed to prepare, devs, and the serials that it touched without such a
// device. Node mounts that no other claim uses are unmounted first, then
// each serial that no other claim uses is released when nothing holds its
// block device any more, waiting at most the holder wait for all of them
// together. A serial whose node mount cannot be unmounted is not
// released.
func (p *poolDriver) releaseDevices(ctx context.Context, uid string, devs []preparedPoolDevice, serials []uint64) []error {
	p.unbindStale(ctx)
	var errs []error
	blockDevs := map[uint64]string{}
	failed := map[uint64]bool{}
	var unmounted []string
	for i := range devs {
		d := &devs[i]
		if !slices.Contains(serials, d.Serial) {
			serials = append(serials, d.Serial)
		}
		if d.BlockDevice != "" {
			blockDevs[d.Serial] = d.BlockDevice
		}
		if d.NodeMount == "" || slices.Contains(unmounted, d.NodeMount) || p.mountUsed(d.NodeMount, uid) {
			continue
		}
		if err := p.unmountNode(d.Serial, d.NodeMount); err != nil {
			errs = append(errs, fmt.Errorf("releasing %s (serial 0x%x): %w", d.Device, d.Serial, err))
			failed[d.Serial] = true
			continue
		}
		unmounted = append(unmounted, d.NodeMount)
	}
	deadline := time.Now().Add(p.holderWait)
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
		if err := p.release(ctx, serial); err != nil {
			errs = append(errs, fmt.Errorf("releasing serial 0x%x: %w", serial, err))
		}
	}
	return errs
}

// staleBind is a lease bind that belongs to no prepared claim and could
// not be unmounted, with the serial and the block device of the device
// whose erofs it mounts (0 and "" when they are unknown).
type staleBind struct {
	Target      string
	Serial      uint64
	BlockDevice string
}

// bindLeaseMounts binds the node mount of the device of mode fs of a
// companion claim (uid) at <rec.FsDir>/<rec.Name>, or finds it bound
// there, and records the bind in rec.Mounts. The bind must be an erofs
// mount of the root of the node mount with the flags ro, nosuid and nodev;
// a new bind without them is unmounted again, another mount at the target,
// or the bind of another prepared claim, is neither used nor unmounted. A
// lease has at most one fs device.
func (p *poolDriver) bindLeaseMounts(uid string, rec *lendRecord, devs []preparedPoolDevice) error {
	bound := false
	for i := range devs {
		d := &devs[i]
		if d.Mode != api.ModeFs {
			continue
		}
		switch {
		case rec.Name == "":
			return fmt.Errorf("lease %s: the device is of mode %s, the lease is not", rec.Lease, api.ModeFs)
		case rec.FsDir == "":
			return fmt.Errorf("lease %s: its lease claim has no filesystem directory", rec.Lease)
		case bound:
			return fmt.Errorf("lease %s: more than one filesystem device", rec.Lease)
		case !api.ValidName(rec.Name):
			return fmt.Errorf("lease %s: invalid name %q", rec.Lease, rec.Name)
		}
		bound = true
		target := filepath.Join(rec.FsDir, rec.Name)
		found, err := p.bindLeaseMount(uid, d, target)
		if err != nil {
			return err
		}
		if !slices.Contains(rec.Mounts, target) {
			rec.Mounts = append(rec.Mounts, target)
		}
		if found {
			klog.Infof("%s: lease %s: %s is bound at %s already", p.name, rec.Lease, d.NodeMount, target)
		} else {
			klog.Infof("%s: lease %s: bound %s at %s", p.name, rec.Lease, d.NodeMount, target)
		}
	}
	return nil
}

// bindLeaseMount binds the node mount of an fs device at target for the
// claim uid with MS_BIND only, so that the bind and its propagated copies
// inherit the flags of the node mount, and reports whether the bind was
// there already. The bind is checked as bindLeaseMounts says; a new bind
// that fails the check and cannot be unmounted becomes a stale bind.
func (p *poolDriver) bindLeaseMount(uid string, d *preparedPoolDevice, target string) (bool, error) {
	s := api.FormatSerial(d.Serial)
	node, err := p.mounter.Mounted(d.NodeMount)
	switch {
	case err != nil:
		return false, err
	case node == nil:
		return false, fmt.Errorf("device %s: %s is not mounted", s, d.NodeMount)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return false, err
	}
	mi, err := p.mounter.Mounted(target)
	if err != nil {
		return false, err
	}
	if mi != nil {
		switch {
		case !isLeaseBind(mi, node):
			return false, fmt.Errorf("device %s: %s is a %s mount of %s, not of %s", s, target, mi.FsType, mi.Source, d.NodeMount)
		case p.leaseBindUsed(target, uid):
			return false, fmt.Errorf("device %s: %s is the bind of another lease", s, target)
		}
		return true, nil
	}
	if err := p.mounter.Mount(d.NodeMount, target, "", unix.MS_BIND, ""); err != nil {
		p.removeMountDir(target)
		return false, fmt.Errorf("device %s: binding %s at %s: %w", s, d.NodeMount, target, err)
	}
	mi, err = p.mounter.Mounted(target)
	if err == nil && (mi == nil || !isLeaseBind(mi, node)) {
		err = fmt.Errorf("device %s: the bind of %s at %s is not a read-only nosuid nodev erofs mount", s, d.NodeMount, target)
	}
	if err != nil {
		if uerr := p.mounter.Unmount(target); uerr != nil {
			klog.Errorf("%s: device %s: unmounting %s: %v; trying again at the next release", p.name, s, target, uerr)
			p.addStaleBind(staleBind{Target: target, Serial: d.Serial, BlockDevice: d.BlockDevice})
		} else {
			p.removeMountDir(target)
		}
		return false, err
	}
	return false, nil
}

// isLeaseBind tells whether a mount is a bind of the node mount node with
// the flags of a lease bind.
func isLeaseBind(mi, node *mountInfo) bool {
	if mi.FsType != fsType || mi.Source != node.Source || mi.Root != node.Root {
		return false
	}
	for _, f := range leaseBindFlags {
		if !slices.Contains(mi.MountFlags, f) {
			return false
		}
	}
	return true
}

// unbindLeaseMounts unmounts the lease binds of a lend of the claim
// exceptUID, never detaching them, and removes their directories. A bind
// that another prepared claim lists is left alone. A bind that cannot be
// unmounted (busy while the borrower has files of it open or mapped), or
// that has another mount than an erofs on it, is an error, and the binds
// after it are left; rec is not changed.
func (p *poolDriver) unbindLeaseMounts(rec *lendRecord, exceptUID string) error {
	if rec == nil {
		return nil
	}
	for _, target := range rec.Mounts {
		if p.leaseBindUsed(target, exceptUID) {
			klog.Warningf("%s: lease %s: %s is the bind of another prepared claim, not unmounting it", p.name, rec.Lease, target)
			continue
		}
		for n := 0; ; n++ {
			mi, err := p.mounter.Mounted(target)
			if err == nil && mi == nil {
				break
			}
			if err == nil && mi.FsType != fsType {
				return fmt.Errorf("lease %s: %s is a %s mount of %s, not a lease bind", rec.Lease, target, mi.FsType, mi.Source)
			}
			if err == nil && n >= maxUnbinds {
				err = errors.New("still mounted")
			}
			if err == nil {
				err = p.mounter.Unmount(target)
			}
			if err != nil {
				return fmt.Errorf("lease %s: unmounting %s: %w", rec.Lease, target, err)
			}
			klog.Infof("%s: lease %s: unbound %s", p.name, rec.Lease, target)
		}
		p.removeMountDir(target)
	}
	return nil
}

// addStaleBind records a stale bind, once per target.
func (p *poolDriver) addStaleBind(sb staleBind) {
	for _, old := range p.staleBinds {
		if old.Target == sb.Target {
			return
		}
	}
	p.staleBinds = append(p.staleBinds, sb)
}

// unbindStale unmounts the stale binds that are in no prepared claim,
// never detaching them, and forgets those that are gone; a stale bind that
// a prepared claim lists now (a Prepare again adopted it) is forgotten too.
// Then the serial of a stale bind that is gone is released when no
// prepared or inflight claim has it, no stale bind is left of it and
// nothing holds its block device within the holder wait. Errors are
// logged.
func (p *poolDriver) unbindStale(ctx context.Context) {
	var left, gone []staleBind
	for _, sb := range p.staleBinds {
		if p.leaseBindUsed(sb.Target, "") {
			continue
		}
		mi, err := p.mounter.Mounted(sb.Target)
		switch {
		case err != nil, mi == nil:
		case mi.FsType != fsType:
			err = fmt.Errorf("a %s mount of %s is on it", mi.FsType, mi.Source)
		default:
			if err = p.mounter.Unmount(sb.Target); err == nil {
				klog.Infof("%s: unbound stale lease bind %s", p.name, sb.Target)
			}
		}
		if err != nil {
			klog.Errorf("%s: unmounting stale lease bind %s: %v", p.name, sb.Target, err)
			left = append(left, sb)
			continue
		}
		p.removeMountDir(sb.Target)
		gone = append(gone, sb)
	}
	p.staleBinds = left
	released := map[uint64]bool{}
	for _, sb := range gone {
		if sb.Serial == 0 || sb.BlockDevice == "" || released[sb.Serial] ||
			slices.ContainsFunc(left, func(l staleBind) bool { return l.Serial == sb.Serial }) {
			continue
		}
		released[sb.Serial] = true
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
	if err := p.waitNoHolder(ctx, serial, blockDev, time.Now().Add(p.holderWait)); err != nil {
		klog.Errorf("%s: not releasing serial 0x%x after its stale lease bind: %v", p.name, serial, err)
		return
	}
	if err := p.release(ctx, serial); err != nil {
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

// bindOrigin returns the serial and the block device of the erofs of a
// lease bind whose source is source, from the node mount with that
// source: 0 and "" if there is none.
func (p *poolDriver) bindOrigin(mounts []mountInfo, source string) (uint64, string) {
	for i := range mounts {
		m := &mounts[i]
		if m.Source != source || filepath.Dir(m.Target) != p.mountsDir() {
			continue
		}
		hex, _, _ := strings.Cut(filepath.Base(m.Target), "-")
		serial, err := strconv.ParseUint(hex, 16, 64)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(source, "/dev/loop") {
			return serial, source
		}
		if backing, err := p.mounter.LoopBackingFile(source); err == nil && backing != "" {
			return serial, backing
		}
		return serial, ""
	}
	return 0, ""
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

// restoreLeaseMounts binds again the missing lease binds of the prepared
// companion claims whose node mount is mounted, and unmounts the mounts
// under the lease-fs root that belong to no prepared claim; one that
// cannot be unmounted becomes a stale bind.
func (p *poolDriver) restoreLeaseMounts() {
	want := map[string]bool{}
	for _, uid := range slices.Sorted(maps.Keys(p.prepared)) {
		pc := p.prepared[uid]
		if pc.Lend == nil {
			continue
		}
		for _, target := range pc.Lend.Mounts {
			want[target] = true
			mi, err := p.mounter.Mounted(target)
			if err != nil {
				klog.Errorf("%s: claim %s: lease %s: %v", p.name, pc.ClaimName, pc.Lend.Lease, err)
				continue
			}
			if mi != nil {
				continue
			}
			d := fsDevice(pc.Devices)
			if d == nil {
				klog.Errorf("%s: claim %s: lease %s: not binding %s again: no device of mode %s", p.name, pc.ClaimName, pc.Lend.Lease, target, api.ModeFs)
				continue
			}
			if node, err := p.mounter.Mounted(d.NodeMount); err != nil || node == nil {
				klog.Errorf("%s: claim %s: lease %s: not binding %s again: %s is not mounted (%v)", p.name, pc.ClaimName, pc.Lend.Lease, target, d.NodeMount, err)
				continue
			}
			if _, err := p.bindLeaseMount(uid, d, target); err != nil {
				klog.Errorf("%s: claim %s: lease %s: not binding %s again: %v", p.name, pc.ClaimName, pc.Lend.Lease, target, err)
				continue
			}
			klog.Infof("%s: claim %s: lease %s: bound %s at %s again", p.name, pc.ClaimName, pc.Lend.Lease, d.NodeMount, target)
		}
	}
	if p.leaseFsRoot == "" {
		return
	}
	mounts, err := p.mounter.Mounts()
	if err != nil {
		klog.Errorf("%s: %v", p.name, err)
		return
	}
	// the topmost first: stacked mounts come out one by one
	for i := len(mounts) - 1; i >= 0; i-- {
		t := mounts[i].Target
		if !strings.HasPrefix(t, p.leaseFsRoot+"/") || want[t] {
			continue
		}
		klog.Infof("%s: %s belongs to no prepared claim, unmounting it", p.name, t)
		if err := p.mounter.Unmount(t); err != nil {
			klog.Errorf("%s: unmounting %s: %v; trying again at the next release", p.name, t, err)
			serial, blockDev := p.bindOrigin(mounts, mounts[i].Source)
			p.addStaleBind(staleBind{Target: t, Serial: serial, BlockDevice: blockDev})
			continue
		}
		p.removeMountDir(t)
	}
}

// restoreMounts mounts again the node mounts of the prepared claims that
// are missing and the lease binds of prepared companion claims that are
// missing, and unmounts the lease binds and the node mounts that no
// prepared claim uses.
func (p *poolDriver) restoreMounts() {
	want := map[string]bool{}
	loops := map[string]string{} // node mount -> its loop device, mounted ones only
	changed := false
	for _, uid := range slices.Sorted(maps.Keys(p.prepared)) {
		pc := p.prepared[uid]
		for i := range pc.Devices {
			d := &pc.Devices[i]
			if d.NodeMount == "" || want[d.NodeMount] {
				continue
			}
			want[d.NodeMount] = true
			mi, err := p.mounter.Mounted(d.NodeMount)
			if err != nil {
				klog.Errorf("%s: claim %s: %v", p.name, pc.ClaimName, err)
				continue
			}
			if mi == nil {
				klog.Infof("%s: claim %s: device 0x%x: %s is not mounted, mounting it again", p.name, pc.ClaimName, d.Serial, d.NodeMount)
				if err := p.checkBlockDevice(d); err != nil {
					klog.Errorf("%s: claim %s: not mounting %s again: %v", p.name, pc.ClaimName, d.NodeMount, err)
					p.removeMountDir(d.NodeMount)
					continue
				}
			}
			loop, err := p.ensureNodeMount(d.Serial, d.BlockDevice, d.Access, d.NodeMount)
			if err != nil {
				klog.Errorf("%s: claim %s: %v", p.name, pc.ClaimName, err)
				continue
			}
			loops[d.NodeMount] = loop
		}
	}
	for _, pc := range p.prepared {
		for i := range pc.Devices {
			d := &pc.Devices[i]
			if loop, ok := loops[d.NodeMount]; ok && d.NodeMount != "" && loop != d.LoopDevice {
				d.LoopDevice, changed = loop, true
			}
		}
	}
	p.restoreLeaseMounts()
	entries, err := os.ReadDir(p.mountsDir())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		klog.Errorf("%s: %v", p.name, err)
	}
	for _, e := range entries {
		mnt := filepath.Join(p.mountsDir(), e.Name())
		if want[mnt] {
			continue
		}
		klog.Infof("%s: %s belongs to no prepared claim, unmounting it", p.name, mnt)
		if mi, err := p.mounter.Mounted(mnt); err != nil || mi != nil {
			if err == nil {
				err = p.mounter.Unmount(mnt)
			}
			if err != nil {
				klog.Errorf("%s: unmounting %s: %v", p.name, mnt, err)
				continue
			}
		}
		p.removeMountDir(mnt)
	}
	if changed {
		if err := p.save(); err != nil {
			klog.Errorf("%s: %v", p.name, err)
		}
	}
}

// checkBlockDevice returns an error if the block device of a prepared
// device is not the one of the fsdax namespace of the region of the memdev
// with its serial now: its name, numbers and namespace must be those that
// Prepare recorded.
func (p *poolDriver) checkBlockDevice(d *preparedPoolDevice) error {
	s := api.FormatSerial(d.Serial)
	memdev, err := p.mem.FindMemdev(d.Serial)
	if err != nil {
		return err
	}
	regions := p.mem.Regions(memdev)
	if len(regions) == 0 {
		return fmt.Errorf("device %s: %s has no region", s, memdev)
	}
	nd, err := p.mem.NdRegion(regions[0])
	if err != nil {
		return fmt.Errorf("device %s: %w", s, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), min(p.timeout, restoreProbeTimeout))
	defer cancel()
	nss, err := p.mem.Namespaces(ctx, nd)
	if err != nil {
		return fmt.Errorf("device %s: %w", s, err)
	}
	ns := memctl.FsdaxNamespace(nss)
	switch {
	case ns == nil:
		return fmt.Errorf("device %s: no fsdax namespace in %s", s, nd)
	case ns.BlockDevice != d.BlockDevice || ns.Name != d.Namespace || ns.Major != d.BlockMajor || ns.Minor != d.BlockMinor:
		return fmt.Errorf("device %s: its fsdax namespace is %s with %s (%d:%d), not %s with %s (%d:%d) as prepared",
			s, ns.Name, ns.BlockDevice, ns.Major, ns.Minor, d.Namespace, d.BlockDevice, d.BlockMajor, d.BlockMinor)
	}
	return nil
}

// blockDeviceNode returns the CDI device node of the block device of a
// device in mode block, read-only ("r") when the claim is.
func blockDeviceNode(d *preparedPoolDevice) *cdiSpecs.DeviceNode {
	node := &cdiSpecs.DeviceNode{
		Path:  d.BlockDevice,
		Type:  "b",
		Major: int64(d.BlockMajor),
		Minor: int64(d.BlockMinor),
	}
	if d.ReadOnly {
		node.Permissions = "r"
	}
	return node
}

// fsMount returns the CDI mount of the node mount of a device in mode fs.
func fsMount(d *preparedPoolDevice) *cdiSpecs.Mount {
	return &cdiSpecs.Mount{
		HostPath:      d.NodeMount,
		ContainerPath: d.Path,
		Type:          "bind",
		Options:       slices.Clone(fsMountOptions),
	}
}
