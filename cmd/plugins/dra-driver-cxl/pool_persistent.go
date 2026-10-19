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
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/memctl"
)

// Pool devices of persistent memory: the pool driver gives a container the
// block device of the fsdax namespace of the device (mode block), or a
// read-only erofs filesystem on it (mode fs) through a node mount per
// device and access that the claims of the node share
// (docs/memory/cxl/usage.md).

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
)

// fsMountOptions are the options of the CDI bind mount of mode fs.
var fsMountOptions = []string{"bind", "ro", "nosuid", "nodev"}

// forbiddenPathDirs are the directories that the path of mode fs must not
// be in.
var forbiddenPathDirs = []string{"/dev", "/proc", "/sys", "/run/cxl", "/var/run/cxl"}

// persistentMode tells whether a mode is a mode of persistent devices.
func persistentMode(mode string) bool {
	return mode == api.ModeBlock || mode == api.ModeFs
}

// validFsPath tells whether p may be the path of mode fs in a container:
// absolute, clean, not / and not in one of forbiddenPathDirs.
func validFsPath(p string) bool {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		return false
	}
	for _, dir := range forbiddenPathDirs {
		if p == dir || strings.HasPrefix(p, dir+"/") {
			return false
		}
	}
	return true
}

// defaultFsPath returns the path of mode fs of the memory with the env key
// in a container when the DeviceConfig has none.
func defaultFsPath(key string) string {
	return defaultFsPathDir + "/" + key
}

// poolModeFor returns the mode of a pool device with the config. The
// checks of the config alone come first, then those that need the claim
// status data of the device (persistent, shared, exclusive).
func (cfg *deviceConfig) poolModeFor(d *poolDevice) (string, error) {
	k := device.DeviceConfigKind
	mode := cfg.Mode
	switch mode {
	case "", api.ModeNUMA, api.ModeDax, api.ModeBlock, api.ModeFs:
	default:
		return "", fmt.Errorf("%s: invalid mode %q (%s, %s, %s or %s)", k, mode, api.ModeNUMA, api.ModeDax, api.ModeBlock, api.ModeFs)
	}
	switch {
	case cfg.Access != "" && mode != api.ModeFs:
		return "", fmt.Errorf("%s: access needs mode %s", k, api.ModeFs)
	case cfg.Path != "" && mode != api.ModeFs:
		return "", fmt.Errorf("%s: path needs mode %s", k, api.ModeFs)
	case cfg.Access != "" && cfg.Access != api.AccessDirect && cfg.Access != api.AccessCached:
		return "", fmt.Errorf("%s: invalid access %q (%s or %s)", k, cfg.Access, api.AccessDirect, api.AccessCached)
	case cfg.Path != "" && !validFsPath(cfg.Path):
		return "", fmt.Errorf("%s: invalid path %q (an absolute path outside %s and %s)", k, cfg.Path,
			strings.Join(forbiddenPathDirs[:len(forbiddenPathDirs)-1], ", "), forbiddenPathDirs[len(forbiddenPathDirs)-1])
	case mode == api.ModeFs && !cfg.ReadOnly:
		return "", fmt.Errorf("%s: mode %s is read-only: set readOnly: true (write the device with mode %s)", k, api.ModeFs, api.ModeBlock)
	case cfg.ReadOnly && mode == api.ModeNUMA:
		return "", errReadOnlyMode()
	}
	switch {
	case !d.Persistent && persistentMode(mode):
		return "", fmt.Errorf("%s: mode %s needs a persistent device", k, mode)
	case d.Persistent && !persistentMode(mode):
		return "", fmt.Errorf("%s: a persistent device needs mode %s or %s", k, api.ModeBlock, api.ModeFs)
	case mode == api.ModeBlock && d.Shared && !d.Exclusive && !cfg.ReadOnly:
		return "", fmt.Errorf("%s: mode %s: a shared device is writable only with all of its hosts", k, api.ModeBlock)
	case d.Persistent:
		return mode, nil
	}
	// volatile memory
	switch {
	case mode == "" && d.Shared:
		mode = api.ModeDax
	case mode == "":
		mode = api.ModeNUMA
	}
	switch {
	case d.Shared && mode != api.ModeDax:
		return "", fmt.Errorf("%s: mode %s: a shared device is used as %s only", k, mode, api.ModeDax)
	case cfg.ReadOnly && mode != api.ModeDax:
		return "", errReadOnlyMode()
	}
	return mode, nil
}

// errReadOnlyMode returns the error of readOnly in a mode without it.
func errReadOnlyMode() error {
	return fmt.Errorf("%s: readOnly needs mode %s, %s or %s", device.DeviceConfigKind, api.ModeDax, api.ModeBlock, api.ModeFs)
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

// restoreMounts mounts again the node mounts of the prepared claims that
// are missing, and unmounts the node mounts that no prepared claim uses.
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
