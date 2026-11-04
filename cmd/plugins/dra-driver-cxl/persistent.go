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
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/memctl"
)

// Devices of persistent memory of both drivers on the node: the block
// device of the fsdax namespace of the region of the device (mode block),
// or a filesystem on it (mode fs) through one node mount per device and
// access that the claims of the node share, and the lease binds of fs
// leases (docs/memory/cxl/usage.md "Persistent memory", leases.md). The
// state of a superblock (read-write while a use of the device writes) and
// the read-only flags of the block devices are derived from the uses of
// the device that the driver passes, never stored. The driver serializes
// the calls of one device.

const (
	// mountsDirName is the directory of the node mounts of mode fs in the
	// data directory of a driver.
	mountsDirName = "mounts"
	// defaultHolderWait is how long one Unprepare or rollback waits for
	// the block devices of its persistent devices to have no holder
	// before releasing them.
	defaultHolderWait = 10 * time.Second
	// restoreProbeTimeout is how long the start waits for the namespaces
	// of a device whose node mount it mounts again.
	restoreProbeTimeout = 5 * time.Second
	// holderPoll is the interval of the checks of that wait.
	holderPoll = 100 * time.Millisecond
	// fsMountFlags are the flags of the node mounts of read-only
	// filesystem types (mount(2)).
	fsMountFlags = unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV
	// daxAlways is the super option of a DAX mount.
	daxAlways = "dax=always"
	// maxUnbinds bounds the unmounts of one lease bind (stacked mounts).
	maxUnbinds = 8
	// procFilesystems lists the filesystem types of the kernel.
	procFilesystems = "/proc/filesystems"
)

// persistentUse is a prepared use of a persistent device on the node: one
// allocation result of mode block or fs of a static or companion claim.
type persistentUse struct {
	UID    string
	Result int
	Serial uint64
	// Mode is api.ModeBlock or api.ModeFs.
	Mode string
	// ReadOnly is the effective read-only setting: a use with ReadOnly
	// false writes the device.
	ReadOnly bool
	// Access is the effective access of mode fs.
	Access string
	// FsType is the filesystem type of the node mount of mode fs.
	FsType string
	// BlockDevice is the block device of the device as prepared.
	BlockDevice string
	// NodeMount and LoopDevice are the node mount of mode fs and the loop
	// device of a cached one.
	NodeMount  string
	LoopDevice string
}

// writer tells whether the use writes the device.
func (u *persistentUse) writer() bool {
	return !u.ReadOnly
}

// persistentTarget is a persistent device as its driver prepared it for a
// use: the block device of the fsdax namespace of its region and its facts.
type persistentTarget struct {
	Serial      uint64
	BlockDevice string
	Facts       config.DeviceFacts
}

// persistentWant is what an allocation result asks of a persistent device.
type persistentWant struct {
	UID    string
	Result int
	Mode   string // api.ModeBlock or api.ModeFs
	// ReadOnly is the effective read-only setting (config.Device.IsReadOnly).
	ReadOnly bool
	// Access is the access of mode fs, "" for the default of the type.
	Access string
	// FsType is the declared filesystem type, "" to detect it.
	FsType string
}

// persistentConfig configures the persistent devices of a driver.
type persistentConfig struct {
	// Driver is the name of the driver in logs.
	Driver string
	// Mounter mounts filesystems and sets up loop and block devices.
	Mounter nodeMounter
	// MountsDir is the directory of the node mounts.
	MountsDir string
	// LeaseFsRoot is the directory of the lease-fs directories of the
	// lease claims, "" for no sweep of lease binds.
	LeaseFsRoot string
	// FsTypes are the filesystem types that mode fs may mount, nil for
	// erofs only (the type built for images that nobody vouches for).
	FsTypes []string
	// Filesystems is the list of filesystem types of the kernel, ""
	// for /proc/filesystems.
	Filesystems string
	// HolderWait is how long a release waits for no holder of a block
	// device, 0 for defaultHolderWait.
	HolderWait time.Duration
	// Check returns an error if blockDev is not the block device of the
	// fsdax namespace of the region of the device with the serial now, as
	// prepared; nil for no check. A release changes the read-only flag of
	// a block device only when it passes.
	Check func(serial uint64, blockDev string) error
}

// persistentNode is the persistent devices of a driver on the node.
type persistentNode struct {
	cfg persistentConfig
	// mu guards unrestored and staleBinds.
	mu sync.Mutex
	// unrestored are the node mounts (-> why) that the start or a Remount
	// could not mount again.
	unrestored map[string]error
	// staleBinds are lease binds of no prepared claim that could not be
	// unmounted; UnbindStale tries again.
	staleBinds []staleBind
}

// staleBind is a lease bind that belongs to no prepared claim and could
// not be unmounted, with the serial and the block device of the device
// whose filesystem it mounts (0 and "" when they are unknown).
type staleBind struct {
	Target      string
	Serial      uint64
	BlockDevice string
}

// leaseBindClaim is a prepared companion claim with its lend and the use
// of its device of mode fs: Fs, else the first use of mode fs of Uses.
type leaseBindClaim struct {
	UID       string
	ClaimName string
	Lend      *lendRecord
	Fs        *persistentUse
	Uses      []persistentUse
}

// fsUse returns the first use of mode fs, nil if there is none.
func fsUse(uses []persistentUse) *persistentUse {
	for i := range uses {
		if uses[i].Mode == api.ModeFs {
			return &uses[i]
		}
	}
	return nil
}

// restoredMount is the result of restoring a node mount: its loop device
// ("" direct), or why it is not usable.
type restoredMount struct {
	Loop string
	Err  error
}

// newPersistentNode returns the persistent devices of a driver.
func newPersistentNode(cfg persistentConfig) *persistentNode {
	if cfg.HolderWait <= 0 {
		cfg.HolderWait = defaultHolderWait
	}
	if cfg.FsTypes == nil {
		cfg.FsTypes = []string{config.FsTypeErofs}
	}
	cfg.FsTypes = slices.Clone(cfg.FsTypes)
	if cfg.Filesystems == "" {
		cfg.Filesystems = procFilesystems
	}
	return &persistentNode{cfg: cfg, unrestored: map[string]error{}}
}

// NodeMountPath returns the node mount of the device with the serial and
// the access: <mounts dir>/<serial hex>-<access>.
func (n *persistentNode) NodeMountPath(serial uint64, access string) string {
	return filepath.Join(n.cfg.MountsDir, fmt.Sprintf("%x-%s", serial, access))
}

// MountsDir returns the directory of the node mounts.
func (n *persistentNode) MountsDir() string {
	return n.cfg.MountsDir
}

// usesOf returns the uses of the device with the serial.
func usesOf(serial uint64, uses []persistentUse) []persistentUse {
	var out []persistentUse
	for _, u := range uses {
		if u.Serial == serial {
			out = append(out, u)
		}
	}
	return out
}

// firstWriter returns the first use that writes, nil if none does.
func firstWriter(uses []persistentUse) *persistentUse {
	for i := range uses {
		if uses[i].writer() {
			return &uses[i]
		}
	}
	return nil
}

// fsAccesses returns the accesses of the uses of mode fs, sorted.
func fsAccesses(uses []persistentUse) []string {
	var out []string
	for _, u := range uses {
		if u.Mode == api.ModeFs && !slices.Contains(out, u.Access) {
			out = append(out, u.Access)
		}
	}
	slices.Sort(out)
	return out
}

// nodeMounts returns the node mounts of the uses, sorted.
func nodeMounts(uses []persistentUse) []string {
	var out []string
	for _, u := range uses {
		if u.NodeMount != "" && !slices.Contains(out, u.NodeMount) {
			out = append(out, u.NodeMount)
		}
	}
	slices.Sort(out)
	return out
}

// blockDeviceOf returns the first block device of the uses, "" if none.
func blockDeviceOf(uses []persistentUse) string {
	for _, u := range uses {
		if u.BlockDevice != "" {
			return u.BlockDevice
		}
	}
	return ""
}

// roWord returns "read-only" or "read-write".
func roWord(readOnly bool) string {
	if readOnly {
		return "read-only"
	}
	return "read-write"
}

// loopOf returns the loop device that a mount is of, "" if none.
func loopOf(mi *mountInfo) string {
	if strings.HasPrefix(mi.Source, "/dev/loop") {
		return mi.Source
	}
	return ""
}

// Prepare returns the use w of the device t prepared next to others, the
// other uses of the device on the node (the uses of the other claims and
// those that the Prepare of w's claim prepared already): mode block gets
// the read-only flag of the block device, mode fs the node mount of its
// type and access, mounted, reused or made read-write. The use has its
// effective access, type, node mount and loop device. On error nothing of
// the device changed but what cannot be undone, which is logged.
func (n *persistentNode) Prepare(ctx context.Context, t persistentTarget, w persistentWant, others []persistentUse) (persistentUse, error) {
	others = usesOf(t.Serial, others)
	u := persistentUse{UID: w.UID, Result: w.Result, Serial: t.Serial, Mode: w.Mode, ReadOnly: w.ReadOnly, BlockDevice: t.BlockDevice}
	s := api.FormatSerial(t.Serial)
	blockWriter := slices.ContainsFunc(others, func(o persistentUse) bool { return o.Mode == api.ModeBlock && o.writer() })
	if blockWriter || (w.Mode == api.ModeBlock && !w.ReadOnly && len(others) > 0) {
		return u, fmt.Errorf("device %s: mode block read-write needs the device alone on this node", s)
	}
	if w.Mode != api.ModeFs {
		if u.writer() {
			// others is empty: every superblock of the device is foreign
			if err := n.checkUnexplained(t.Serial, t.BlockDevice, nil); err != nil {
				return u, err
			}
		}
		writer := u.writer() || firstWriter(others) != nil
		return u, n.setReadOnly(t.Serial, t.BlockDevice, !writer)
	}
	return n.prepareFs(t, w, u, others)
}

// prepareFs prepares the use u of mode fs (Prepare).
func (n *persistentNode) prepareFs(t persistentTarget, w persistentWant, u persistentUse, others []persistentUse) (persistentUse, error) {
	m := n.cfg.Mounter
	s := api.FormatSerial(t.Serial)
	dev := t.BlockDevice
	fail := func(format string, args ...any) (persistentUse, error) {
		return u, fmt.Errorf("device "+s+": "+format, args...)
	}

	// the type: that of a node mount of the device, else of its signature
	var mounted *mountInfo
	for _, a := range []string{api.AccessDirect, api.AccessCached} {
		mi, err := m.Mounted(n.NodeMountPath(t.Serial, a))
		if err != nil {
			return u, err
		}
		if mi == nil || mounted != nil {
			continue
		}
		if ok, err := n.isDeviceMount(mi, dev, a); err != nil {
			return u, err
		} else if ok {
			mounted = mi
		}
	}
	var sig *fsSignature
	probe := func() (*fsSignature, error) {
		if sig == nil {
			s, err := readFsSignature(m, dev)
			if err != nil {
				return nil, fmt.Errorf("device %s: reading %s: %w", api.FormatSerial(t.Serial), dev, err)
			}
			sig = &s
		}
		return sig, nil
	}
	var fsType string
	if mounted != nil {
		fsType = mounted.FsType
		if w.FsType != "" && w.FsType != fsType {
			return fail("%s has a filesystem of type %s, not %s", dev, fsType, w.FsType)
		}
	} else {
		sg, err := probe()
		if err != nil {
			return u, err
		}
		if fsType, err = sg.fsType(t.Serial, dev, w.FsType); err != nil {
			return u, err
		}
	}

	allowed := strings.Join(n.cfg.FsTypes, ", ")
	if allowed == "" {
		allowed = "none"
	}
	switch {
	case !slices.Contains(n.cfg.FsTypes, fsType):
		return fail("filesystem type %s is not allowed on this node (fsTypes: %s)", fsType, allowed)
	case n.nodevType(fsType):
		return fail("filesystem type %s does not mount a block device", fsType)
	case !w.ReadOnly && config.FsTypeReadOnly(fsType):
		return fail("%s is a read-only filesystem: set readOnly: true", fsType)
	case w.Access == api.AccessDirect && !config.FsTypeDAX(fsType):
		return fail("%s has no DAX: use access cached", fsType)
	}
	access := w.Access
	if access == "" {
		access = api.AccessCached
		if config.FsTypeDAX(fsType) {
			access = api.AccessDirect
		}
	}
	if !w.ReadOnly && !t.Facts.SingleHost {
		sg, err := probe()
		if err != nil {
			return u, err
		}
		ok, why := sg.cluster(fsType)
		if ok && !t.Facts.Coherent {
			ok, why = false, "the device is not coherent between hosts"
		}
		if !ok {
			return fail("read-write on several hosts needs a cluster filesystem on coherent memory: %s", why)
		}
	}

	// the rules of one node
	other := firstWriter(others)
	accesses := fsAccesses(others)
	switch {
	case other != nil && other.Access != access:
		return fail("it is mounted read-write with access %s on this node: access %s would mount it a second time", other.Access, access)
	case !w.ReadOnly && len(accesses) == 2:
		return fail("it is mounted with access %s and %s on this node: a read-write claim needs one access only", api.AccessDirect, api.AccessCached)
	case !w.ReadOnly && len(accesses) == 1 && accesses[0] != access:
		return fail("it is mounted with access %s only on this node: a read-write claim with access %s would mount it a second time", accesses[0], access)
	}

	writer := u.writer() || other != nil
	mnt := n.NodeMountPath(t.Serial, access)
	mi, err := m.Mounted(mnt)
	if err != nil {
		return u, err
	}
	loop := ""
	if mi != nil {
		if loop, err = n.checkNodeMount(t.Serial, dev, access, fsType, mi); err != nil {
			return u, err
		}
		switch {
		case u.writer() && mi.superReadOnly() && !config.FsTypeUpgradable(fsType):
			return fail("%s is mounted read-only on this node and cannot be remounted read-write: a read-write claim waits until the read-only claims of the node are gone", fsType)
		case u.writer() && mi.superReadOnly():
			if err := n.upgrade(t.Serial, dev, loop, mnt, append(nodeMounts(others), mnt)); err != nil {
				return u, err
			}
		case !writer && !mi.superReadOnly():
			// a rw superblock without a writer (a release that failed)
			if err := n.downgrade(t.Serial, dev, loop, mnt); err != nil {
				klog.Errorf("%s: %v", n.cfg.Driver, err)
			}
		}
	} else {
		if !writer && fsType == config.FsTypeExt4 {
			sg, err := probe()
			if err != nil {
				return u, err
			}
			if sg.Ext4NeedsRecovery {
				return u, errNeedsRecovery(t.Serial, fsType, dev)
			}
		}
		if loop, err = n.mountNode(t.Serial, dev, access, fsType, mnt, writer, nodeMounts(others)); err != nil {
			return u, err
		}
	}
	u.Access, u.FsType, u.NodeMount, u.LoopDevice = access, fsType, mnt, loop
	n.forgetUnrestored(mnt)
	return u, nil
}

// errNeedsRecovery returns the error of a filesystem that a read-only
// mount cannot recover.
func errNeedsRecovery(serial uint64, fsType, dev string) error {
	return fmt.Errorf("device %s: %s on %s needs recovery (it was not unmounted cleanly): a read-only mount cannot recover it, a read-write claim on one node does",
		api.FormatSerial(serial), fsType, dev)
}

// nodevType tells whether the kernel lists the filesystem type as one
// without a block device.
func (n *persistentNode) nodevType(fsType string) bool {
	data, err := os.ReadFile(n.cfg.Filesystems)
	if err != nil {
		klog.V(3).Infof("%s: %v", n.cfg.Driver, err)
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "nodev" && f[1] == fsType {
			return true
		}
	}
	return false
}

// mountNode returns the loop device of a cached node mount after it
// mounted the filesystem of the type on the block device dev at the node
// mount mnt for the access: read-write for a writer, else read-only on a
// read-only block device; access direct on the block device, cached on a
// direct-I/O loop device over it. Read-only types are mounted with
// mount(2) on a read-only loop device. A writable type is not mounted
// while the device has a superblock that the node mounts explained do not
// have.
func (n *persistentNode) mountNode(serial uint64, dev, access, fsType, mnt string, writer bool, explained []string) (string, error) {
	m := n.cfg.Mounter
	s := api.FormatSerial(serial)
	readOnlyType := config.FsTypeReadOnly(fsType)
	if !readOnlyType {
		if err := n.checkUnexplained(serial, dev, explained); err != nil {
			return "", err
		}
	}
	ro := !writer || readOnlyType
	data := config.FsMountData(fsType, access, ro)
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		return "", err
	}
	if err := n.setReadOnly(serial, dev, ro); err != nil {
		n.removeMountDir(mnt)
		return "", err
	}
	source := dev
	var loop loopDevice
	if access == api.AccessCached {
		l, err := m.AttachLoop(dev, !readOnlyType)
		if err != nil {
			n.removeMountDir(mnt)
			return "", fmt.Errorf("device %s: a loop device over %s: %w", s, dev, err)
		}
		loop, source = l, l.Path()
		if !readOnlyType {
			if err := n.setReadOnly(serial, source, ro); err != nil {
				n.detachLoop(serial, loop)
				n.removeMountDir(mnt)
				return "", err
			}
		}
	}
	var err error
	if readOnlyType {
		err = m.Mount(source, mnt, fsType, fsMountFlags, strings.Join(data, ","))
	} else {
		err = m.FsMount(source, mnt, fsType, !ro, data)
	}
	if err != nil {
		if loop != nil {
			n.detachLoop(serial, loop)
		}
		n.removeMountDir(mnt)
		if ro && errors.Is(err, unix.EROFS) {
			return "", errNeedsRecovery(serial, fsType, dev)
		}
		return "", fmt.Errorf("device %s: %s has no %s filesystem: %w", s, dev, fsType, err)
	}
	if loop != nil {
		// the mount keeps the autoclear loop device
		if err := loop.Release(false); err != nil {
			klog.Warningf("%s: device %s: closing %s: %v", n.cfg.Driver, s, loop.Path(), err)
		}
	}
	if access == api.AccessDirect && config.FsTypeDAX(fsType) {
		// another mount of the block device on the node has the
		// superblock, and its options win
		mi, err := m.Mounted(mnt)
		if err == nil && (mi == nil || !mi.hasSuperOpt(daxAlways)) {
			err = fmt.Errorf("device %s: %s on %s was mounted without DAX", s, fsType, dev)
		}
		if err != nil {
			if uerr := m.Unmount(mnt); uerr != nil {
				klog.Errorf("%s: device %s: unmounting %s: %v", n.cfg.Driver, s, mnt, uerr)
			} else {
				n.removeMountDir(mnt)
			}
			return "", err
		}
	}
	what := fsType + ", " + map[bool]string{true: "ro", false: "rw"}[ro]
	if len(data) > 0 {
		what += ", " + strings.Join(data, ",")
	}
	klog.Infof("%s: device %s: mounted %s at %s (%s)", n.cfg.Driver, s, source, mnt, what)
	if loop != nil {
		return loop.Path(), nil
	}
	return "", nil
}

// detachLoop detaches a loop device that no mount uses.
func (n *persistentNode) detachLoop(serial uint64, loop loopDevice) {
	if err := loop.Release(true); err != nil {
		klog.Errorf("%s: device %s: detaching %s: %v", n.cfg.Driver, api.FormatSerial(serial), loop.Path(), err)
	}
}

// upgrade makes the read-only superblock of the node mount mnt read-write:
// the block device, then the loop device of a cached mount, then the
// superblock. On error both are read-only again. It refuses while the
// device has a superblock that the node mounts explained do not have.
func (n *persistentNode) upgrade(serial uint64, dev, loop, mnt string, explained []string) error {
	s := api.FormatSerial(serial)
	if err := n.checkUnexplained(serial, dev, explained); err != nil {
		return err
	}
	fail := func(err error) error {
		if loop != "" {
			if rerr := n.setReadOnly(serial, loop, true); rerr != nil {
				klog.Errorf("%s: %v", n.cfg.Driver, rerr)
			}
		}
		if rerr := n.setReadOnly(serial, dev, true); rerr != nil {
			klog.Errorf("%s: %v", n.cfg.Driver, rerr)
		}
		return fmt.Errorf("device %s: remounting %s read-write: %w", s, mnt, err)
	}
	if err := n.setReadOnly(serial, dev, false); err != nil {
		return fail(err)
	}
	if loop != "" {
		if err := n.setReadOnly(serial, loop, false); err != nil {
			return fail(err)
		}
	}
	if err := n.cfg.Mounter.Reconfigure(mnt, true); err != nil {
		return fail(err)
	}
	klog.Infof("%s: device %s: remounted %s read-write", n.cfg.Driver, s, mnt)
	return nil
}

// downgrade makes the read-write superblock of the node mount mnt
// read-only: its data written, the superblock, then the loop device of a
// cached mount, then the block device.
func (n *persistentNode) downgrade(serial uint64, dev, loop, mnt string) error {
	s := api.FormatSerial(serial)
	m := n.cfg.Mounter
	if err := m.Syncfs(mnt); err != nil {
		return fmt.Errorf("device %s: remounting %s read-only: %w", s, mnt, err)
	}
	if err := m.Reconfigure(mnt, false); err != nil {
		return fmt.Errorf("device %s: remounting %s read-only: %w", s, mnt, err)
	}
	klog.Infof("%s: device %s: remounted %s read-only", n.cfg.Driver, s, mnt)
	if loop != "" {
		if err := n.setReadOnly(serial, loop, true); err != nil {
			return err
		}
	}
	return n.setReadOnly(serial, dev, true)
}

// setReadOnly sets the read-only flag of the block device dev of the
// device with the serial, when it differs. A block device is never made
// read-only while a read-write superblock is on it, or on a loop device
// over it. A block device that is gone is not an error.
func (n *persistentNode) setReadOnly(serial uint64, dev string, readOnly bool) error {
	if dev == "" {
		return nil
	}
	s := api.FormatSerial(serial)
	m := n.cfg.Mounter
	cur, err := m.ReadOnly(dev)
	switch {
	case isGone(err):
		return nil
	case err == nil && cur == readOnly:
		return nil
	}
	if readOnly {
		// never under a read-write superblock anywhere on the node; and
		// not when that cannot be known
		sbs, err := m.Superblocks(dev)
		if err != nil {
			return fmt.Errorf("device %s: not making %s read-only: its superblocks: %w", s, dev, err)
		}
		for _, sb := range sbs {
			if !sb.ReadOnly {
				return fmt.Errorf("device %s: not making %s read-only: %s is mounted read-write in %s", s, dev, sb.Source, sb.Where)
			}
		}
	}
	if err := m.SetReadOnly(dev, readOnly); err != nil {
		if isGone(err) {
			return nil
		}
		return fmt.Errorf("device %s: making %s %s: %w", s, dev, roWord(readOnly), err)
	}
	klog.Infof("%s: device %s: %s %s", n.cfg.Driver, s, dev, roWord(readOnly))
	return nil
}

// isGone tells whether err says that a device does not exist.
func isGone(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENXIO) || errors.Is(err, unix.ENODEV)
}

// checkUnexplained returns an error if the block device dev of the device
// with the serial, or a loop device over it, has a superblock anywhere on
// the node that is not that of one of the node mounts explained (the node
// mounts of the uses of the device), or if its superblocks cannot be read.
func (n *persistentNode) checkUnexplained(serial uint64, dev string, explained []string) error {
	s := api.FormatSerial(serial)
	sbs, err := n.cfg.Mounter.Superblocks(dev)
	if err != nil {
		return fmt.Errorf("device %s: the superblocks of %s: %w", s, dev, err)
	}
	known := map[string]bool{}
	for _, mnt := range explained {
		mi, err := n.cfg.Mounter.Mounted(mnt)
		if err != nil {
			return err
		}
		if mi != nil {
			known[mi.Source] = true
		}
	}
	for _, sb := range sbs {
		if !known[sb.Device] {
			return fmt.Errorf("device %s: %s has a superblock that no claim of this node explains (%s mounted %s in %s): it is not used until that mount is gone",
				s, dev, sb.Source, map[bool]string{true: "ro", false: "rw"}[sb.ReadOnly], sb.Where)
		}
	}
	return nil
}

// verified returns dev when the driver's check says that it is the block
// device of the device with the serial now, else "" (logged).
func (n *persistentNode) verified(serial uint64, dev string) string {
	if dev == "" || n.cfg.Check == nil {
		return dev
	}
	if err := n.cfg.Check(serial, dev); err != nil {
		klog.Warningf("%s: device %s: not changing the read-only flag of %s: %v", n.cfg.Driver, api.FormatSerial(serial), dev, err)
		return ""
	}
	return dev
}

// SetCheck sets the check of the block devices of the release (Check).
func (n *persistentNode) SetCheck(check func(serial uint64, blockDev string) error) {
	n.cfg.Check = check
}

// isDeviceMount tells whether a mount is one of the block device dev for
// the access: of dev itself (direct), of a loop device over it (cached).
func (n *persistentNode) isDeviceMount(mi *mountInfo, dev, access string) (bool, error) {
	if access != api.AccessCached {
		return mi.Source == dev, nil
	}
	if loopOf(mi) == "" {
		return false, nil
	}
	backing, err := n.cfg.Mounter.LoopBackingFile(mi.Source)
	if err != nil {
		return false, err
	}
	return sameDevice(backing, dev), nil
}

// checkNodeMount returns the loop device of an existing cached node mount,
// or an error if the mount at the node mount is not the filesystem of the
// type ("": any) of the block device for the access: on the block device
// (direct, with dax=always for the DAX types), on a loop device over it
// (cached).
func (n *persistentNode) checkNodeMount(serial uint64, dev, access, fsType string, mi *mountInfo) (string, error) {
	s := api.FormatSerial(serial)
	ok, err := n.isDeviceMount(mi, dev, access)
	if err != nil {
		return "", err
	}
	if !ok {
		want := dev
		if access == api.AccessCached {
			want = "a loop device over " + dev
		}
		return "", fmt.Errorf("device %s: %s is a %s mount of %s, not of %s", s, mi.Target, mi.FsType, mi.Source, want)
	}
	if fsType != "" && mi.FsType != fsType {
		return "", fmt.Errorf("device %s: %s is a %s mount of %s, not %s", s, mi.Target, mi.FsType, mi.Source, fsType)
	}
	if access == api.AccessCached {
		return mi.Source, nil
	}
	if config.FsTypeDAX(mi.FsType) && !mi.hasSuperOpt(daxAlways) {
		return "", fmt.Errorf("device %s: %s on %s was mounted without DAX", s, mi.FsType, dev)
	}
	return "", nil
}

// DeviceMount returns the node mount of the device with the serial and the
// access ("": either) when a mount there is one of the block device dev,
// "" otherwise.
func (n *persistentNode) DeviceMount(serial uint64, dev, access string) string {
	accesses := []string{access}
	if access == "" {
		accesses = []string{api.AccessDirect, api.AccessCached}
	}
	for _, a := range accesses {
		mnt := n.NodeMountPath(serial, a)
		mi, err := n.cfg.Mounter.Mounted(mnt)
		if err != nil || mi == nil {
			continue
		}
		if ok, err := n.isDeviceMount(mi, dev, a); err == nil && ok {
			return mnt
		}
	}
	return ""
}

// removeMountDir removes the directory of a mount that is not mounted.
func (n *persistentNode) removeMountDir(mnt string) {
	if err := os.Remove(mnt); err != nil && !errors.Is(err, os.ErrNotExist) {
		klog.Warningf("%s: removing %s: %v", n.cfg.Driver, mnt, err)
	}
}

// unmountNode unmounts a node mount if it is mounted, never detaching it,
// and removes its directory. A busy mount is an error.
func (n *persistentNode) unmountNode(serial uint64, mnt string) error {
	mi, err := n.cfg.Mounter.Mounted(mnt)
	if err != nil {
		return err
	}
	if mi != nil {
		if err := n.cfg.Mounter.Unmount(mnt); err != nil {
			return fmt.Errorf("device %s: unmounting %s: %w", api.FormatSerial(serial), mnt, err)
		}
		klog.Infof("%s: device %s: unmounted %s", n.cfg.Driver, api.FormatSerial(serial), mnt)
	}
	n.removeMountDir(mnt)
	return nil
}

// Release releases the uses gone of the device with the serial while the
// uses remaining stay: the node mounts that no remaining use has are
// unmounted, the superblock of a node mount whose remaining uses have no
// writer is made read-only, and so are the block devices when no writer
// remains (the block device of the remaining uses only when Check passes
// for it). An error (a busy unmount or downgrade) stops it.
func (n *persistentNode) Release(ctx context.Context, serial uint64, gone, remaining []persistentUse) error {
	remaining = usesOf(serial, remaining)
	used := nodeMounts(remaining)
	for _, mnt := range nodeMounts(usesOf(serial, gone)) {
		if slices.Contains(used, mnt) {
			continue
		}
		if err := n.unmountNode(serial, mnt); err != nil {
			return err
		}
	}
	if len(remaining) == 0 {
		return nil
	}
	if firstWriter(remaining) != nil {
		return nil
	}
	// the recorded block device may be another device's now
	dev := n.verified(serial, blockDeviceOf(remaining))
	var loops []string
	for _, mnt := range used {
		mi, err := n.cfg.Mounter.Mounted(mnt)
		if err != nil || mi == nil {
			continue
		}
		loop := loopOf(mi)
		if loop != "" {
			loops = append(loops, loop)
		}
		if !mi.superReadOnly() {
			if err := n.downgrade(serial, dev, loop, mnt); err != nil {
				return err
			}
		}
	}
	for _, loop := range loops {
		if err := n.setReadOnly(serial, loop, true); err != nil {
			return err
		}
	}
	return n.setReadOnly(serial, dev, true)
}

// WaitNoHolder waits until the deadline until nothing holds the block
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
func (n *persistentNode) WaitNoHolder(ctx context.Context, serial uint64, blockDev string, deadline time.Time) error {
	for {
		holder, err := n.cfg.Mounter.Holder(blockDev)
		if err != nil {
			return err
		}
		if holder == "" {
			return nil
		}
		if !time.Now().Before(deadline) {
			klog.Warningf("%s: device %s: %s is held: %s", n.cfg.Driver, api.FormatSerial(serial), blockDev, holder)
			return fmt.Errorf("device %s: %s is still in use", api.FormatSerial(serial), blockDev)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("device %s: %s is still in use: %w", api.FormatSerial(serial), blockDev, ctx.Err())
		case <-time.After(holderPoll):
		}
	}
}

// HolderWait returns how long a release waits for no holder.
func (n *persistentNode) HolderWait() time.Duration {
	return n.cfg.HolderWait
}

// RestoreMounts makes, at start, the node mounts of the prepared uses of
// the driver what the uses derive: a missing node mount is mounted again
// when check passes for its device (its block device is the one
// prepared), an existing one is checked and made read-write or read-only
// as its uses say, and the block devices get the read-only flag that the
// uses derive. It returns the result of each node mount; one that is not
// mounted afterwards is unrestored (Unrestored). Failures to change the
// state of a superblock or a block device are logged: the next Prepare or
// Release of the device tries again.
func (n *persistentNode) RestoreMounts(uses []persistentUse, check func(serial uint64, blockDev string) error) map[string]restoredMount {
	out := map[string]restoredMount{}
	serials := map[uint64]bool{}
	for _, u := range uses {
		serials[u.Serial] = true
	}
	for _, serial := range slices.Sorted(maps.Keys(serials)) {
		us := usesOf(serial, uses)
		writer := firstWriter(us) != nil
		for _, mnt := range nodeMounts(us) {
			i := slices.IndexFunc(us, func(u persistentUse) bool { return u.NodeMount == mnt })
			loop, err := n.restoreNodeMount(&us[i], writer, nodeMounts(us), check)
			out[mnt] = restoredMount{Loop: loop, Err: err}
			if err != nil {
				if mi, merr := n.cfg.Mounter.Mounted(mnt); merr == nil && mi == nil {
					n.setUnrestored(mnt, err)
				}
			}
		}
		dev := blockDeviceOf(us)
		if dev == "" {
			continue
		}
		if err := check(serial, dev); err != nil {
			klog.V(3).Infof("%s: device %s: not setting the read-only flag of %s: %v", n.cfg.Driver, api.FormatSerial(serial), dev, err)
			continue
		}
		var loops []string
		for _, mnt := range nodeMounts(us) {
			if mi, err := n.cfg.Mounter.Mounted(mnt); err == nil && mi != nil && loopOf(mi) != "" && !config.FsTypeReadOnly(mi.FsType) {
				loops = append(loops, loopOf(mi))
			}
		}
		var errs []error
		if writer {
			errs = append(errs, n.setReadOnly(serial, dev, false))
			for _, l := range loops {
				errs = append(errs, n.setReadOnly(serial, l, false))
			}
		} else {
			for _, l := range loops {
				errs = append(errs, n.setReadOnly(serial, l, true))
			}
			errs = append(errs, n.setReadOnly(serial, dev, true))
		}
		if err := errors.Join(errs...); err != nil {
			klog.Errorf("%s: %v", n.cfg.Driver, err)
		}
	}
	return out
}

// Restore is RestoreMounts, with its errors logged, followed by
// SweepNodeMounts: it returns the loop devices of the node mounts that are
// mounted ("" direct).
func (n *persistentNode) Restore(uses []persistentUse, check func(serial uint64, blockDev string) error) map[string]string {
	loops := map[string]string{}
	restored := n.RestoreMounts(uses, check)
	for _, mnt := range slices.Sorted(maps.Keys(restored)) {
		if r := restored[mnt]; r.Err != nil {
			klog.Errorf("%s: %s: %v", n.cfg.Driver, mnt, r.Err)
		} else {
			loops[mnt] = r.Loop
		}
	}
	n.SweepNodeMounts(uses)
	return loops
}

// restoreNodeMount returns the loop device of the node mount of a use
// after it mounted it again when it is missing and check passes for its
// device, or checked the mount there; an existing superblock is made
// read-write for a writer of the device or read-only without one, a
// failure of that is logged. explained are the node mounts of the uses of
// the device.
func (n *persistentNode) restoreNodeMount(u *persistentUse, writer bool, explained []string, check func(uint64, string) error) (string, error) {
	mi, err := n.cfg.Mounter.Mounted(u.NodeMount)
	if err != nil {
		return "", err
	}
	if mi == nil {
		klog.Infof("%s: device %s: %s is not mounted, mounting it again", n.cfg.Driver, api.FormatSerial(u.Serial), u.NodeMount)
		if err := check(u.Serial, u.BlockDevice); err != nil {
			n.removeMountDir(u.NodeMount)
			return "", fmt.Errorf("not mounting %s again: %w", u.NodeMount, err)
		}
		return n.mountNode(u.Serial, u.BlockDevice, u.Access, u.FsType, u.NodeMount, writer, explained)
	}
	loop, err := n.checkNodeMount(u.Serial, u.BlockDevice, u.Access, u.FsType, mi)
	if err != nil {
		return "", err
	}
	switch {
	case writer && mi.superReadOnly() && config.FsTypeUpgradable(mi.FsType):
		err = n.upgrade(u.Serial, u.BlockDevice, loop, u.NodeMount, explained)
	case writer && mi.superReadOnly():
		err = fmt.Errorf("device %s: %s is mounted read-only and cannot be remounted read-write (%s)", api.FormatSerial(u.Serial), u.NodeMount, mi.FsType)
	case !writer && !mi.superReadOnly():
		err = n.downgrade(u.Serial, u.BlockDevice, loop, u.NodeMount)
	}
	if err != nil {
		klog.Errorf("%s: %v", n.cfg.Driver, err)
	}
	return loop, nil
}

// SweepNodeMounts unmounts the mounts in the mounts directory that no use
// has, and removes their directories. Errors are logged.
func (n *persistentNode) SweepNodeMounts(uses []persistentUse) {
	want := nodeMounts(uses)
	entries, err := os.ReadDir(n.cfg.MountsDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		klog.Errorf("%s: %v", n.cfg.Driver, err)
	}
	for _, e := range entries {
		mnt := filepath.Join(n.cfg.MountsDir, e.Name())
		if slices.Contains(want, mnt) {
			continue
		}
		klog.Infof("%s: %s belongs to no prepared claim, unmounting it", n.cfg.Driver, mnt)
		if mi, err := n.cfg.Mounter.Mounted(mnt); err != nil || mi != nil {
			if err == nil {
				err = n.cfg.Mounter.Unmount(mnt)
			}
			if err != nil {
				klog.Errorf("%s: unmounting %s: %v", n.cfg.Driver, mnt, err)
				continue
			}
		}
		n.removeMountDir(mnt)
	}
}

// Remount mounts the node mount mnt that the start could not mount again
// for the uses of its device (every prepared use of it), and returns its
// loop device; an error names why it stays unmounted.
func (n *persistentNode) Remount(mnt string, uses []persistentUse, check func(uint64, string) error) (string, error) {
	i := slices.IndexFunc(uses, func(u persistentUse) bool { return u.NodeMount == mnt })
	if i < 0 {
		return "", fmt.Errorf("no use of %s", mnt)
	}
	u := uses[i]
	us := usesOf(u.Serial, uses)
	loop, err := n.restoreNodeMount(&u, firstWriter(us) != nil, nodeMounts(us), check)
	if err != nil {
		n.setUnrestored(mnt, err)
		return "", err
	}
	n.forgetUnrestored(mnt)
	return loop, nil
}

// Unrestored returns why the node mount is not mounted after the start, and
// whether it is unrestored.
func (n *persistentNode) Unrestored(mnt string) (error, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	err, ok := n.unrestored[mnt]
	return err, ok
}

func (n *persistentNode) setUnrestored(mnt string, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.unrestored[mnt] = err
}

func (n *persistentNode) forgetUnrestored(mnt string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.unrestored, mnt)
}

// BindLease binds the node mount of the use of mode fs of a companion claim
// at <rec.FsDir>/<rec.Name>, or finds it bound there, and records the bind
// in rec.Mounts. The bind must be a mount of the root of the node mount of
// its type with the flags ro (rw for a use that writes), nosuid and nodev;
// a new bind without them is unmounted again; another mount at the target,
// or one that otherBind says is the bind of another prepared claim, is
// neither used nor unmounted. A lease has at most one fs use.
func (n *persistentNode) BindLease(rec *lendRecord, uses []persistentUse, otherBind func(target string) bool) error {
	bound := false
	for i := range uses {
		u := &uses[i]
		if u.Mode != api.ModeFs {
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
		found, err := n.bindLease(u, target, otherBind)
		if err != nil {
			return err
		}
		if !slices.Contains(rec.Mounts, target) {
			rec.Mounts = append(rec.Mounts, target)
		}
		if found {
			klog.Infof("%s: lease %s: %s is bound at %s already", n.cfg.Driver, rec.Lease, u.NodeMount, target)
		} else {
			klog.Infof("%s: lease %s: bound %s at %s", n.cfg.Driver, rec.Lease, u.NodeMount, target)
		}
	}
	return nil
}

// bindLease binds the node mount of an fs use at target and reports
// whether the bind was there already: read-only binds of writable types by
// a clone with the read-only attribute, others by MS_BIND, so that the
// bind and its propagated copies have the flags of the node mount. The
// bind is checked as BindLease says; a new bind that fails the check and
// cannot be unmounted becomes a stale bind.
func (n *persistentNode) bindLease(u *persistentUse, target string, otherBind func(string) bool) (bool, error) {
	m := n.cfg.Mounter
	s := api.FormatSerial(u.Serial)
	node, err := m.Mounted(u.NodeMount)
	switch {
	case err != nil:
		return false, err
	case node == nil:
		return false, fmt.Errorf("device %s: %s is not mounted", s, u.NodeMount)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return false, err
	}
	mi, err := m.Mounted(target)
	if err != nil {
		return false, err
	}
	if mi != nil {
		switch {
		case !isLeaseBind(mi, node, u.ReadOnly):
			return false, fmt.Errorf("device %s: %s is a %s mount of %s, not of %s", s, target, mi.FsType, mi.Source, u.NodeMount)
		case otherBind != nil && otherBind(target):
			return false, fmt.Errorf("device %s: %s is the bind of another lease", s, target)
		}
		return true, nil
	}
	if u.ReadOnly && !config.FsTypeReadOnly(node.FsType) {
		err = m.BindReadOnly(u.NodeMount, target)
	} else {
		err = m.Mount(u.NodeMount, target, "", unix.MS_BIND, "")
	}
	if err != nil {
		n.removeMountDir(target)
		return false, fmt.Errorf("device %s: binding %s at %s: %w", s, u.NodeMount, target, err)
	}
	mi, err = m.Mounted(target)
	if err == nil && (mi == nil || !isLeaseBind(mi, node, u.ReadOnly)) {
		err = fmt.Errorf("device %s: the bind of %s at %s is not a %s nosuid nodev %s mount", s, u.NodeMount, target, roWord(u.ReadOnly), node.FsType)
	}
	if err != nil {
		if uerr := m.Unmount(target); uerr != nil {
			klog.Errorf("%s: device %s: unmounting %s: %v; trying again at the next release", n.cfg.Driver, s, target, uerr)
			n.addStaleBind(staleBind{Target: target, Serial: u.Serial, BlockDevice: u.BlockDevice})
		} else {
			n.removeMountDir(target)
		}
		return false, err
	}
	return false, nil
}

// isLeaseBind tells whether a mount is a bind of the node mount node with
// the flags of a lease bind, ro or rw by readOnly.
func isLeaseBind(mi, node *mountInfo, readOnly bool) bool {
	if mi.FsType != node.FsType || mi.Source != node.Source || mi.Root != node.Root {
		return false
	}
	for _, f := range []string{map[bool]string{true: "ro", false: "rw"}[readOnly], "nosuid", "nodev"} {
		if !slices.Contains(mi.MountFlags, f) {
			return false
		}
	}
	return true
}

// leaseBindType tells whether a mount may be a lease bind: of a block
// device, of a filesystem type that mode fs mounts.
func (n *persistentNode) leaseBindType(mi *mountInfo) bool {
	return strings.HasPrefix(mi.Source, "/dev/") && (config.KnownFsType(mi.FsType) || slices.Contains(n.cfg.FsTypes, mi.FsType))
}

// UnbindLease unmounts the lease binds of a lend, never detaching them, and
// removes their directories. A bind that otherBind says another prepared
// claim lists is left alone. A bind that cannot be unmounted (busy while
// the borrower has files of it open or mapped), or that has another mount
// on it than a lease bind, is an error, and the binds after it are left;
// rec is not changed.
func (n *persistentNode) UnbindLease(rec *lendRecord, otherBind func(target string) bool) error {
	if rec == nil {
		return nil
	}
	m := n.cfg.Mounter
	for _, target := range rec.Mounts {
		if otherBind != nil && otherBind(target) {
			klog.Warningf("%s: lease %s: %s is the bind of another prepared claim, not unmounting it", n.cfg.Driver, rec.Lease, target)
			continue
		}
		for i := 0; ; i++ {
			mi, err := m.Mounted(target)
			if err == nil && mi == nil {
				break
			}
			if err == nil && !n.leaseBindType(mi) {
				return fmt.Errorf("lease %s: %s is a %s mount of %s, not a lease bind", rec.Lease, target, mi.FsType, mi.Source)
			}
			if err == nil && i >= maxUnbinds {
				err = errors.New("still mounted")
			}
			if err == nil {
				err = m.Unmount(target)
			}
			if err != nil {
				return fmt.Errorf("lease %s: unmounting %s: %w", rec.Lease, target, err)
			}
			klog.Infof("%s: lease %s: unbound %s", n.cfg.Driver, rec.Lease, target)
		}
		n.removeMountDir(target)
	}
	return nil
}

// KeepStale records the lease binds of a lend that could not be unmounted
// as stale binds of the device of the use u (nil: unknown).
func (n *persistentNode) KeepStale(rec *lendRecord, u *persistentUse) {
	if rec == nil {
		return
	}
	sb := staleBind{}
	if u != nil {
		sb.Serial, sb.BlockDevice = u.Serial, u.BlockDevice
	}
	for _, t := range rec.Mounts {
		sb.Target = t
		n.addStaleBind(sb)
	}
}

// addStaleBind records a stale bind, once per target.
func (n *persistentNode) addStaleBind(sb staleBind) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, old := range n.staleBinds {
		if old.Target == sb.Target {
			return
		}
	}
	n.staleBinds = append(n.staleBinds, sb)
}

// StaleBinds returns the stale binds.
func (n *persistentNode) StaleBinds() []staleBind {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.staleBinds)
}

// UnbindStale unmounts the stale binds that otherBind says no prepared
// claim lists, never detaching them, and forgets those that are gone; a
// stale bind that a prepared claim lists now (a Prepare again adopted it)
// is forgotten too. It returns a gone bind per device whose serial and
// block device are known and of which no stale bind is left: the driver
// releases those devices when no claim has them. Errors are logged.
func (n *persistentNode) UnbindStale(otherBind func(target string) bool) []staleBind {
	n.mu.Lock()
	binds := n.staleBinds
	n.staleBinds = nil
	n.mu.Unlock()
	var left, gone []staleBind
	for _, sb := range binds {
		if otherBind != nil && otherBind(sb.Target) {
			continue
		}
		mi, err := n.cfg.Mounter.Mounted(sb.Target)
		switch {
		case err != nil, mi == nil:
		case !n.leaseBindType(mi):
			err = fmt.Errorf("a %s mount of %s is on it", mi.FsType, mi.Source)
		default:
			if err = n.cfg.Mounter.Unmount(sb.Target); err == nil {
				klog.Infof("%s: unbound stale lease bind %s", n.cfg.Driver, sb.Target)
			}
		}
		if err != nil {
			klog.Errorf("%s: unmounting stale lease bind %s: %v", n.cfg.Driver, sb.Target, err)
			left = append(left, sb)
			continue
		}
		n.removeMountDir(sb.Target)
		gone = append(gone, sb)
	}
	n.mu.Lock()
	n.staleBinds = append(left, n.staleBinds...)
	n.mu.Unlock()
	var release []staleBind
	for _, sb := range gone {
		if sb.Serial == 0 || sb.BlockDevice == "" ||
			slices.ContainsFunc(release, func(r staleBind) bool { return r.Serial == sb.Serial }) ||
			slices.ContainsFunc(left, func(l staleBind) bool { return l.Serial == sb.Serial }) {
			continue
		}
		release = append(release, sb)
	}
	return release
}

// bindOrigin returns the serial and the block device of the filesystem of
// a lease bind whose source is source, from the node mount in the mounts
// directory with that source: 0 and "" if there is none.
func (n *persistentNode) bindOrigin(mounts []mountInfo, source string) (uint64, string) {
	for i := range mounts {
		m := &mounts[i]
		if m.Source != source || filepath.Dir(m.Target) != n.cfg.MountsDir {
			continue
		}
		hex, _, _ := strings.Cut(filepath.Base(m.Target), "-")
		serial, err := strconv.ParseUint(hex, 16, 64)
		if err != nil {
			continue
		}
		if loopOf(m) == "" {
			return serial, source
		}
		if backing, err := n.cfg.Mounter.LoopBackingFile(source); err == nil && backing != "" {
			return serial, devPath(backing)
		}
		return serial, ""
	}
	return 0, ""
}

// RestoreLeaseBinds binds again the missing lease binds of the prepared
// companion claims whose node mount is mounted, and unmounts the mounts
// under the lease-fs root that no claim lists and that bind a node mount
// of the driver (their source is that of a mount in the mounts directory);
// one that cannot be unmounted becomes a stale bind. It returns the binds
// that the claims list.
func (n *persistentNode) RestoreLeaseBinds(claims []leaseBindClaim) map[string]bool {
	want := map[string]bool{}
	for _, c := range claims {
		if c.Lend != nil {
			for _, t := range c.Lend.Mounts {
				want[t] = true
			}
		}
	}
	m := n.cfg.Mounter
	for _, c := range claims {
		if c.Lend == nil {
			continue
		}
		otherBind := func(target string) bool {
			return slices.ContainsFunc(claims, func(o leaseBindClaim) bool {
				return o.UID != c.UID && o.Lend != nil && slices.Contains(o.Lend.Mounts, target)
			})
		}
		for _, target := range c.Lend.Mounts {
			mi, err := m.Mounted(target)
			if err != nil {
				klog.Errorf("%s: claim %s: lease %s: %v", n.cfg.Driver, c.ClaimName, c.Lend.Lease, err)
				continue
			}
			if mi != nil {
				continue
			}
			fs := c.Fs
			if fs == nil {
				fs = fsUse(c.Uses)
			}
			if fs == nil {
				klog.Errorf("%s: claim %s: lease %s: not binding %s again: no device of mode %s", n.cfg.Driver, c.ClaimName, c.Lend.Lease, target, api.ModeFs)
				continue
			}
			if node, err := m.Mounted(fs.NodeMount); err != nil || node == nil {
				klog.Errorf("%s: claim %s: lease %s: not binding %s again: %s is not mounted (%v)", n.cfg.Driver, c.ClaimName, c.Lend.Lease, target, fs.NodeMount, err)
				continue
			}
			if _, err := n.bindLease(fs, target, otherBind); err != nil {
				klog.Errorf("%s: claim %s: lease %s: not binding %s again: %v", n.cfg.Driver, c.ClaimName, c.Lend.Lease, target, err)
				continue
			}
			klog.Infof("%s: claim %s: lease %s: bound %s at %s again", n.cfg.Driver, c.ClaimName, c.Lend.Lease, fs.NodeMount, target)
		}
	}
	if n.cfg.LeaseFsRoot == "" {
		return want
	}
	mounts, err := m.Mounts()
	if err != nil {
		klog.Errorf("%s: %v", n.cfg.Driver, err)
		return want
	}
	own := map[string]bool{}
	for _, mi := range mounts {
		if filepath.Dir(mi.Target) == n.cfg.MountsDir {
			own[mi.Source] = true
		}
	}
	n.sweepBinds(mounts, func(mi *mountInfo) bool { return !want[mi.Target] && own[mi.Source] }, n)
	return want
}

// sweepBinds unmounts, topmost first, the mounts under the lease-fs root
// of n that stale says are stale binds, and removes their directories; one
// that cannot be unmounted becomes a stale bind of the node of owners whose
// node mount it binds, else of n.
func (n *persistentNode) sweepBinds(mounts []mountInfo, stale func(*mountInfo) bool, owners ...*persistentNode) {
	m := n.cfg.Mounter
	for i := len(mounts) - 1; i >= 0; i-- {
		mi := &mounts[i]
		if !strings.HasPrefix(mi.Target, n.cfg.LeaseFsRoot+"/") || !stale(mi) {
			continue
		}
		klog.Infof("%s: %s belongs to no prepared claim, unmounting it", n.cfg.Driver, mi.Target)
		if err := m.Unmount(mi.Target); err != nil {
			klog.Errorf("%s: unmounting %s: %v; trying again at the next release", n.cfg.Driver, mi.Target, err)
			owner := n
			serial, blockDev := uint64(0), ""
			for _, o := range owners {
				if o == nil {
					continue
				}
				if s, d := o.bindOrigin(mounts, mi.Source); s != 0 {
					owner, serial, blockDev = o, s, d
					break
				}
			}
			owner.addStaleBind(staleBind{Target: mi.Target, Serial: serial, BlockDevice: blockDev})
			continue
		}
		n.removeMountDir(mi.Target)
	}
}

// sweepLeaseBinds unmounts the mounts under the lease-fs root that are not
// wanted, the binds that the prepared claims of the drivers of nodes list:
// the binds whose node mount is gone, which no driver sweeps at its start.
// One that cannot be unmounted becomes a stale bind of the node whose node
// mount it binds, else of the first node. Nil nodes are skipped.
func sweepLeaseBinds(wanted map[string]bool, nodes ...*persistentNode) {
	var first *persistentNode
	for _, n := range nodes {
		if n != nil && n.cfg.LeaseFsRoot != "" {
			first = n
			break
		}
	}
	if first == nil {
		return
	}
	mounts, err := first.cfg.Mounter.Mounts()
	if err != nil {
		klog.Errorf("%s: %v", first.cfg.Driver, err)
		return
	}
	first.sweepBinds(mounts, func(mi *mountInfo) bool { return !wanted[mi.Target] }, nodes...)
}

// pmemNamespace returns the fsdax namespace (map mem) of the pmem region
// pr of the device with the serial for a use of the mode: the existing one,
// else a new one for a writable block use; every other use needs one that
// a writer made.
func pmemNamespace(ctx context.Context, mem *memctl.Manager, serial uint64, pr *memctl.PmemRegion, mode string, readOnly bool) (*memctl.Namespace, error) {
	if ns := memctl.FsdaxNamespace(pr.Namespaces); ns != nil {
		return ns, nil
	}
	if mode == api.ModeFs || readOnly {
		return nil, fmt.Errorf("device %s: no fsdax namespace in %s: has a writer written the device?", api.FormatSerial(serial), pr.NdRegion)
	}
	existing := ""
	if len(pr.Namespaces) > 0 {
		existing = pr.Namespaces[0].Name
	}
	return mem.CreateFsdaxNamespace(ctx, pr.NdRegion, existing)
}

// checkPmemBlockDevice returns an error if the block device of the fsdax
// namespace of the region of the memdev with the serial is not the one
// prepared: its namespace ns, name blockDev and numbers.
//   - timeout: how long to wait for the namespaces of the region
func checkPmemBlockDevice(mem *memctl.Manager, timeout time.Duration, serial uint64, ns, blockDev string, major, minor int) error {
	s := api.FormatSerial(serial)
	memdev, err := mem.FindMemdev(serial)
	if err != nil {
		return err
	}
	regions := mem.Regions(memdev)
	if len(regions) == 0 {
		return fmt.Errorf("device %s: %s has no region", s, memdev)
	}
	nd, err := mem.NdRegion(regions[0])
	if err != nil {
		return fmt.Errorf("device %s: %w", s, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), min(timeout, restoreProbeTimeout))
	defer cancel()
	nss, err := mem.Namespaces(ctx, nd)
	if err != nil {
		return fmt.Errorf("device %s: %w", s, err)
	}
	cur := memctl.FsdaxNamespace(nss)
	switch {
	case cur == nil:
		return fmt.Errorf("device %s: no fsdax namespace in %s", s, nd)
	case cur.BlockDevice != blockDev || cur.Name != ns || cur.Major != major || cur.Minor != minor:
		return fmt.Errorf("device %s: its fsdax namespace is %s with %s (%d:%d), not %s with %s (%d:%d) as prepared",
			s, cur.Name, cur.BlockDevice, cur.Major, cur.Minor, ns, blockDev, major, minor)
	}
	return nil
}

// currentPmemBlockDevice returns the block device of the fsdax namespace
// of the region of the memdev with the serial, else of another namespace
// of it with a block device, "" if there is none (or its namespaces do not
// finish probing within the timeout, at most restoreProbeTimeout).
func currentPmemBlockDevice(mem *memctl.Manager, timeout time.Duration, serial uint64) string {
	memdev, err := mem.FindMemdev(serial)
	if err != nil {
		return ""
	}
	regions := mem.Regions(memdev)
	if len(regions) == 0 {
		return ""
	}
	nd, err := mem.NdRegion(regions[0])
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), min(timeout, restoreProbeTimeout))
	defer cancel()
	nss, err := mem.Namespaces(ctx, nd)
	if err != nil {
		klog.Warningf("serial 0x%x: %v", serial, err)
		return ""
	}
	if ns := memctl.FsdaxNamespace(nss); ns != nil {
		return ns.BlockDevice
	}
	for _, ns := range nss {
		if ns.BlockDevice != "" {
			return ns.BlockDevice
		}
	}
	return ""
}

// fsCDIMount returns the CDI mount of a node mount at path in a container:
// options bind, ro, nosuid, nodev, without ro for a use that writes.
func fsCDIMount(nodeMount, path string, readOnly bool) *cdiSpecs.Mount {
	options := []string{"bind", "ro", "nosuid", "nodev"}
	if !readOnly {
		options = []string{"bind", "nosuid", "nodev"}
	}
	return &cdiSpecs.Mount{HostPath: nodeMount, ContainerPath: path, Type: "bind", Options: options}
}

// blockDeviceNode returns the CDI device node of a block device, with
// permissions "r" when read-only.
func blockDeviceNode(dev string, major, minor int, readOnly bool) *cdiSpecs.DeviceNode {
	node := &cdiSpecs.DeviceNode{Path: dev, Type: "b", Major: int64(major), Minor: int64(minor)}
	if readOnly {
		node.Permissions = "r"
	}
	return node
}
