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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

// mountInfo is a mount of /proc/self/mountinfo.
type mountInfo struct {
	DevNum     string // major:minor of the device of the superblock
	Root       string // the directory of the filesystem that is mounted, / for its root
	Target     string // mount point
	FsType     string
	Source     string
	SuperOpts  []string // super options, like dax=always
	MountFlags []string // per-mount options, like ro
}

// superReadOnly tells whether the superblock of a mount is read-only.
func (m *mountInfo) superReadOnly() bool {
	return m.hasSuperOpt("ro")
}

// hasSuperOpt tells whether the super options of a mount have opt.
func (m *mountInfo) hasSuperOpt(opt string) bool {
	for _, o := range m.SuperOpts {
		if o == opt {
			return true
		}
	}
	return false
}

// superblock is a superblock on a block device, as one of its mounts shows
// it.
type superblock struct {
	// Device is the block device of the superblock, /dev/pmemK or
	// /dev/loopN.
	Device   string
	Source   string // the source of the mount
	ReadOnly bool   // the superblock is read-only
	Where    string // the mount: "pid P at <mount point>"
}

// loopDevice is a loop device set up by nodeMounter.AttachLoop, held open
// until Release.
type loopDevice interface {
	// Path returns the device node of the loop device (/dev/loopN).
	Path() string
	// Release closes the loop device; with detach it first clears its
	// backing file. Without detach an autoclear loop device goes away
	// when its last user (a mount) does.
	Release(detach bool) error
}

// nodeMounter mounts filesystems and sets up loop devices on the node.
type nodeMounter interface {
	// Mount mounts the filesystem of source at target (mount(2)).
	Mount(source, target, fstype string, flags uintptr, data string) error
	// FsMount mounts the filesystem of source at target with the new mount
	// API: fsopen(fstype), the source, the flag "ro" unless readWrite, the
	// options ("key=value" as strings, others as flags), FSCONFIG_CMD_CREATE,
	// fsmount with MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV, move_mount. Its error
	// wraps the errno and has the messages that the filesystem context
	// logged.
	FsMount(source, target, fstype string, readWrite bool, options []string) error
	// Reconfigure makes the superblock of the mount at target read-write or
	// read-only (fspick, the flag "rw" or "ro", FSCONFIG_CMD_RECONFIGURE).
	Reconfigure(target string, readWrite bool) error
	// Syncfs writes the dirty data of the filesystem of the mount at target
	// to its device (syncfs(2)).
	Syncfs(target string) error
	// BindReadOnly binds the mount at source at target as a read-only,
	// nosuid, nodev mount (open_tree with OPEN_TREE_CLONE, mount_setattr,
	// move_mount).
	BindReadOnly(source, target string) error
	// SetReadOnly sets or clears the read-only flag of a block device
	// (BLKROSET).
	SetReadOnly(dev string, readOnly bool) error
	// ReadOnly returns the read-only flag of a block device (BLKROGET).
	ReadOnly(dev string) (bool, error)
	// ReadHead returns the first n bytes of a device, fewer when it is
	// shorter.
	ReadHead(dev string, n int) ([]byte, error)
	// Superblocks returns the superblocks of the node on the block device
	// dev and on the loop devices over it, in every mount namespace, one
	// per device with a mount.
	Superblocks(dev string) ([]superblock, error)
	// Unmount unmounts target without detaching it (umount2(target, 0)).
	Unmount(target string) error
	// Mounted returns the topmost mount at target, nil if there is none.
	Mounted(target string) (*mountInfo, error)
	// Mounts returns the mounts of the mount namespace of the process.
	Mounts() ([]mountInfo, error)
	// LoopBackingFile returns the backing file of a loop device
	// (/dev/loopN), "" if it has none: a block device as /dev/<its name>,
	// whatever mount namespace set the loop device up.
	LoopBackingFile(loop string) (string, error)
	// AttachLoop returns a new direct-I/O, autoclear loop device over the
	// file or block device backing: read-only, or with writable a loop
	// device whose backing is opened read-write.
	AttachLoop(backing string, writable bool) (loopDevice, error)
	// Holder returns what holds a block device, "" if nothing does: a loop
	// device over it, or "in use" when it cannot be opened exclusively.
	Holder(dev string) (string, error)
}

// sysMounter is the nodeMounter of the system, with sysfs at sysRoot.
type sysMounter struct {
	sysRoot string
	devRoot string
	// procRoot is the procfs of the processes of the node (the driver runs
	// in the host's pid namespace).
	procRoot string
	// loopStatus returns the status of a loop device (LOOP_GET_STATUS64 of
	// the device node), nil for that ioctl (a variable for tests).
	loopStatus func(path string) (*unix.LoopInfo64, error)
}

// newSysMounter returns the nodeMounter of the system.
func newSysMounter(sysRoot string) *sysMounter {
	return &sysMounter{sysRoot: sysRoot, devRoot: "/dev", procRoot: "/proc"}
}

func (m *sysMounter) Mount(source, target, fstype string, flags uintptr, data string) error {
	return unix.Mount(source, target, fstype, flags, data)
}

func (m *sysMounter) Unmount(target string) error {
	return unix.Unmount(target, 0)
}

// Mounts returns the mounts of the mount namespace of the process.
func (m *sysMounter) Mounts() ([]mountInfo, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	return parseMountInfo(bytes.NewReader(data))
}

func (m *sysMounter) Mounted(target string) (*mountInfo, error) {
	mounts, err := m.Mounts()
	if err != nil {
		return nil, err
	}
	return findMount(mounts, target), nil
}

// findMount returns the topmost mount at target, nil if there is none.
func findMount(mounts []mountInfo, target string) *mountInfo {
	target = filepath.Clean(target)
	for i := len(mounts) - 1; i >= 0; i-- {
		if mounts[i].Target == target {
			return &mounts[i]
		}
	}
	return nil
}

// parseMountInfo returns the mounts of a /proc/<pid>/mountinfo.
func parseMountInfo(r io.Reader) ([]mountInfo, error) {
	var out []mountInfo
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		// id parent major:minor root target options [optional...] - fstype source superopts
		f := strings.Fields(s.Text())
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if len(f) < 6 || sep < 0 || len(f) < sep+3 {
			return nil, fmt.Errorf("invalid mountinfo line %q", s.Text())
		}
		mi := mountInfo{
			DevNum:     f[2],
			Root:       unescapeMountInfo(f[3]),
			Target:     unescapeMountInfo(f[4]),
			MountFlags: strings.Split(f[5], ","),
			FsType:     f[sep+1],
			Source:     unescapeMountInfo(f[sep+2]),
		}
		if len(f) > sep+3 {
			mi.SuperOpts = strings.Split(f[sep+3], ",")
		}
		out = append(out, mi)
	}
	return out, s.Err()
}

// unescapeMountInfo returns a mountinfo field with its octal escapes
// (\040 for a space) replaced.
func unescapeMountInfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// sysLoop is a loop device of sysMounter.
type sysLoop struct {
	path string
	f    *os.File
}

func (l *sysLoop) Path() string { return l.path }

func (l *sysLoop) Release(detach bool) error {
	var err error
	if detach {
		err = unix.IoctlSetInt(int(l.f.Fd()), unix.LOOP_CLR_FD, 0)
	}
	return errors.Join(err, l.f.Close())
}

// loopAttachTries is how many free loop devices AttachLoop tries when
// another process configures the one it got first.
const loopAttachTries = 5

func (m *sysMounter) AttachLoop(backing string, writable bool) (loopDevice, error) {
	// the kernel makes a loop device read-only when either its backing or
	// the loop device itself is not opened for writing
	mode := os.O_RDONLY
	if writable {
		mode = os.O_RDWR
	}
	bf, err := os.OpenFile(backing, mode, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = bf.Close() }()
	ctl, err := os.OpenFile(filepath.Join(m.devRoot, "loop-control"), os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ctl.Close() }()
	for try := 1; ; try++ {
		n, err := unix.IoctlRetInt(int(ctl.Fd()), unix.LOOP_CTL_GET_FREE)
		if err != nil {
			return nil, fmt.Errorf("%s: LOOP_CTL_GET_FREE: %w", ctl.Name(), err)
		}
		path := filepath.Join(m.devRoot, "loop"+strconv.Itoa(n))
		lf, err := os.OpenFile(path, mode, 0)
		if err != nil {
			return nil, err
		}
		cfg := &unix.LoopConfig{Fd: uint32(bf.Fd())}
		cfg.Info.Flags = unix.LO_FLAGS_DIRECT_IO | unix.LO_FLAGS_AUTOCLEAR
		if !writable {
			cfg.Info.Flags |= unix.LO_FLAGS_READ_ONLY
		}
		copy(cfg.Info.File_name[:len(cfg.Info.File_name)-1], backing)
		err = unix.IoctlLoopConfigure(int(lf.Fd()), cfg)
		if errors.Is(err, unix.EBUSY) && try < loopAttachTries {
			_ = lf.Close()
			continue
		}
		if err != nil {
			_ = lf.Close()
			return nil, fmt.Errorf("%s: LOOP_CONFIGURE with %s: %w", path, backing, err)
		}
		// the kernel falls back to buffered I/O when the backing file
		// does not allow direct I/O
		if st, err := unix.IoctlLoopGetStatus64(int(lf.Fd())); err == nil && st.Flags&unix.LO_FLAGS_DIRECT_IO == 0 {
			klog.Warningf("%s over %s does not use direct I/O: the page cache may hold the data twice", path, backing)
		}
		return &sysLoop{path: path, f: lf}, nil
	}
}

// LoopBackingFile returns the backing file of a loop device. A block device
// is found by its device number (loopBackingDevice): the path in sysfs
// (loop/backing_file) is the path of the backing file as the reader sees
// it, and when the mount through which the file was opened is not in the
// reader's mount namespace, it is relative to the root of that mount. The
// loop devices of the cached node mounts are set up in the driver
// container through its /dev, a mount of devtmpfs: after a restart of the
// container the next one reads "/pmem1" for "/dev/pmem1" (plan-13
// bug-13). The path in sysfs is returned when the device number cannot be
// found, and for a backing file that is not a block device.
func (m *sysMounter) LoopBackingFile(loop string) (string, error) {
	b, err := os.ReadFile(filepath.Join(m.sysRoot, "block", filepath.Base(loop), "loop", "backing_file"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	path := strings.TrimSpace(string(b))
	dev, err := m.loopBackingDevice(loop)
	switch {
	case err != nil:
		klog.V(3).Infof("%s: the block device of its backing file %s: %v", loop, path, err)
	case dev != "":
		return dev, nil
	}
	return path, nil
}

// loopBackingDevice returns /dev/<name> of the block device that backs a
// loop device: the device number of the backing file (lo_rdevice of
// LOOP_GET_STATUS64) and its name in sysfs (/sys/dev/block/<major>:<minor>
// /uevent DEVNAME); "" when the backing file is not a block device.
func (m *sysMounter) loopBackingDevice(loop string) (string, error) {
	status := m.loopStatus
	if status == nil {
		status = loopStatus
	}
	info, err := status(filepath.Join(m.devRoot, filepath.Base(loop)))
	if err != nil {
		return "", err
	}
	if info.Rdevice == 0 {
		return "", nil
	}
	major, minor := unix.Major(info.Rdevice), unix.Minor(info.Rdevice)
	uevent := filepath.Join(m.sysRoot, "dev", "block", fmt.Sprintf("%d:%d", major, minor), "uevent")
	data, err := os.ReadFile(uevent)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if name, ok := strings.CutPrefix(line, "DEVNAME="); ok && name != "" {
			return filepath.Join(m.devRoot, name), nil
		}
	}
	return "", fmt.Errorf("no DEVNAME in %s", uevent)
}

// loopStatus returns the status of the loop device with the device node
// path. Opening a loop device does not change it: an autoclear loop device
// is cleared only when its last opener (the mount of a cached node mount)
// closes it.
func loopStatus(path string) (*unix.LoopInfo64, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := unix.IoctlLoopGetStatus64(int(f.Fd()))
	if err != nil {
		return nil, fmt.Errorf("%s: LOOP_GET_STATUS64: %w", path, err)
	}
	return info, nil
}

// devPath returns the path of the backing file of a loop device as a path
// under /dev when it is relative to the root of a devtmpfs mount that the
// reader does not see (a single component: "/pmem1"), else the path.
func devPath(backing string) string {
	if filepath.Dir(backing) == "/" && backing != "/" {
		return "/dev" + backing
	}
	return backing
}

// sameDevice tells whether the backing file of a loop device, as the
// process that set it up saw its path, is the device node dev.
func sameDevice(backing, dev string) bool {
	backing = devPath(backing)
	return backing == dev || (filepath.Dir(backing) == "/dev" && filepath.Base(backing) == filepath.Base(dev))
}

func (m *sysMounter) Holder(dev string) (string, error) {
	loops, _ := filepath.Glob(filepath.Join(m.sysRoot, "block", "loop*", "loop", "backing_file"))
	for _, p := range loops {
		loop := filepath.Base(filepath.Dir(filepath.Dir(p)))
		if v, err := m.LoopBackingFile(loop); err == nil && sameDevice(v, dev) {
			return loop, nil
		}
	}
	fd, err := unix.Open(dev, unix.O_RDONLY|unix.O_EXCL|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.EBUSY):
		return "in use", nil
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENXIO), errors.Is(err, unix.ENODEV):
		return "", nil // the device is gone
	case err != nil:
		return "", fmt.Errorf("open %s: %w", dev, err)
	}
	return "", unix.Close(fd)
}

func (m *sysMounter) FsMount(source, target, fstype string, readWrite bool, options []string) error {
	fd, err := unix.Fsopen(fstype, unix.FSOPEN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("fsopen %s: %w", fstype, err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.FsconfigSetString(fd, "source", source); err != nil {
		return fsContextError(fd, err)
	}
	if !readWrite {
		if err := unix.FsconfigSetFlag(fd, "ro"); err != nil {
			return fsContextError(fd, err)
		}
	}
	for _, o := range options {
		k, v, isString := strings.Cut(o, "=")
		if isString {
			err = unix.FsconfigSetString(fd, k, v)
		} else {
			err = unix.FsconfigSetFlag(fd, k)
		}
		if err != nil {
			return fsContextError(fd, fmt.Errorf("%s: %w", o, err))
		}
	}
	if err := unix.FsconfigCreate(fd); err != nil {
		return fsContextError(fd, err)
	}
	mfd, err := unix.Fsmount(fd, unix.FSMOUNT_CLOEXEC, unix.MOUNT_ATTR_NOSUID|unix.MOUNT_ATTR_NODEV)
	if err != nil {
		return fsContextError(fd, fmt.Errorf("fsmount: %w", err))
	}
	defer func() { _ = unix.Close(mfd) }()
	if err := unix.MoveMount(mfd, "", unix.AT_FDCWD, target, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("move_mount to %s: %w", target, err)
	}
	return nil
}

func (m *sysMounter) Reconfigure(target string, readWrite bool) error {
	fd, err := unix.Fspick(unix.AT_FDCWD, target, unix.FSPICK_CLOEXEC)
	if err != nil {
		return fmt.Errorf("fspick %s: %w", target, err)
	}
	defer func() { _ = unix.Close(fd) }()
	flag := "ro"
	if readWrite {
		flag = "rw"
	}
	if err := unix.FsconfigSetFlag(fd, flag); err != nil {
		return fsContextError(fd, err)
	}
	if err := unix.FsconfigReconfigure(fd); err != nil {
		return fsContextError(fd, err)
	}
	return nil
}

// fsContextError returns err with the messages that the filesystem
// context of fd logged, if any.
func fsContextError(fd int, err error) error {
	var msgs []string
	buf := make([]byte, 4096)
	for range 64 {
		n, rerr := unix.Read(fd, buf)
		if rerr != nil || n <= 0 {
			break
		}
		msgs = append(msgs, strings.TrimSpace(string(buf[:n])))
	}
	if len(msgs) == 0 {
		return err
	}
	return fmt.Errorf("%w: %s", err, strings.Join(msgs, "; "))
}

func (m *sysMounter) Syncfs(target string) error {
	fd, err := unix.Open(target, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", target, err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Syncfs(fd); err != nil {
		return fmt.Errorf("syncfs %s: %w", target, err)
	}
	return nil
}

func (m *sysMounter) BindReadOnly(source, target string) error {
	fd, err := unix.OpenTree(unix.AT_FDCWD, source, unix.OPEN_TREE_CLONE|unix.O_CLOEXEC)
	if err != nil {
		return fmt.Errorf("open_tree %s: %w", source, err)
	}
	defer func() { _ = unix.Close(fd) }()
	attr := &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV}
	if err := unix.MountSetattr(fd, "", unix.AT_EMPTY_PATH, attr); err != nil {
		return fmt.Errorf("mount_setattr of the clone of %s: %w", source, err)
	}
	if err := unix.MoveMount(fd, "", unix.AT_FDCWD, target, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("move_mount of the clone of %s to %s: %w", source, target, err)
	}
	return nil
}

func (m *sysMounter) SetReadOnly(dev string, readOnly bool) error {
	f, err := os.OpenFile(dev, os.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	v := 0
	if readOnly {
		v = 1
	}
	if err := unix.IoctlSetPointerInt(int(f.Fd()), unix.BLKROSET, v); err != nil {
		return fmt.Errorf("%s: BLKROSET %d: %w", dev, v, err)
	}
	return nil
}

func (m *sysMounter) ReadOnly(dev string) (bool, error) {
	f, err := os.OpenFile(dev, os.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	v, err := unix.IoctlGetInt(int(f.Fd()), unix.BLKROGET)
	if err != nil {
		return false, fmt.Errorf("%s: BLKROGET: %w", dev, err)
	}
	return v != 0, nil
}

func (m *sysMounter) ReadHead(dev string, n int) ([]byte, error) {
	f, err := os.OpenFile(dev, os.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, n)
	got, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading %s: %w", dev, err)
	}
	return buf[:got], nil
}

// Superblocks scans the mountinfo of a process of each mount namespace of
// the node for the mounts whose device number is that of dev or of a loop
// device over it (by sysfs: the dev file of the block device, the backing
// of the loop devices).
func (m *sysMounter) Superblocks(dev string) ([]superblock, error) {
	devs := map[string]string{} // major:minor -> device node
	num, err := os.ReadFile(filepath.Join(m.sysRoot, "class", "block", filepath.Base(dev), "dev"))
	if err != nil {
		return nil, fmt.Errorf("the device number of %s: %w", dev, err)
	}
	devs[strings.TrimSpace(string(num))] = dev
	loops, _ := filepath.Glob(filepath.Join(m.sysRoot, "block", "loop*", "loop", "backing_file"))
	for _, p := range loops {
		loop := filepath.Base(filepath.Dir(filepath.Dir(p)))
		backing, err := m.LoopBackingFile(loop)
		if err != nil || !sameDevice(backing, dev) {
			continue
		}
		n, err := os.ReadFile(filepath.Join(m.sysRoot, "block", loop, "dev"))
		if err != nil {
			return nil, fmt.Errorf("the device number of %s: %w", loop, err)
		}
		devs[strings.TrimSpace(string(n))] = filepath.Join(m.devRoot, loop)
	}
	entries, err := os.ReadDir(m.procRoot)
	if err != nil {
		return nil, err
	}
	seenNS := map[string]bool{}
	seen := map[string]bool{}
	var out []superblock
	for _, e := range entries {
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		ns, err := os.Readlink(filepath.Join(m.procRoot, pid, "ns", "mnt"))
		if err != nil || seenNS[ns] {
			continue // gone, or a namespace that is read
		}
		data, err := os.ReadFile(filepath.Join(m.procRoot, pid, "mountinfo"))
		if err != nil {
			continue
		}
		mounts, err := parseMountInfo(bytes.NewReader(data))
		if err != nil {
			continue
		}
		seenNS[ns] = true
		for _, mi := range mounts {
			d, ok := devs[mi.DevNum]
			if !ok || seen[mi.DevNum] {
				continue
			}
			seen[mi.DevNum] = true
			out = append(out, superblock{Device: d, Source: mi.Source, ReadOnly: mi.superReadOnly(), Where: "pid " + pid + " at " + mi.Target})
		}
	}
	return out, nil
}
