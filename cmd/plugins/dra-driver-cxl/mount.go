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
	Target     string // mount point
	FsType     string
	Source     string
	SuperOpts  []string // super options, like dax=always
	MountFlags []string // per-mount options, like ro
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
	// Unmount unmounts target without detaching it (umount2(target, 0)).
	Unmount(target string) error
	// Mounted returns the topmost mount at target, nil if there is none.
	Mounted(target string) (*mountInfo, error)
	// LoopBackingFile returns the backing file of a loop device
	// (/dev/loopN), "" if it has none.
	LoopBackingFile(loop string) (string, error)
	// AttachLoop returns a new read-only, direct-I/O, autoclear loop
	// device over the file or block device backing.
	AttachLoop(backing string) (loopDevice, error)
	// Holder returns what holds a block device, "" if nothing does: a loop
	// device over it, or "in use" when it cannot be opened exclusively.
	Holder(dev string) (string, error)
}

// sysMounter is the nodeMounter of the system, with sysfs at sysRoot.
type sysMounter struct {
	sysRoot string
	devRoot string
}

// newSysMounter returns the nodeMounter of the system.
func newSysMounter(sysRoot string) *sysMounter {
	return &sysMounter{sysRoot: sysRoot, devRoot: "/dev"}
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

func (m *sysMounter) AttachLoop(backing string) (loopDevice, error) {
	bf, err := os.OpenFile(backing, os.O_RDONLY, 0)
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
		lf, err := os.OpenFile(path, os.O_RDONLY, 0)
		if err != nil {
			return nil, err
		}
		cfg := &unix.LoopConfig{Fd: uint32(bf.Fd())}
		cfg.Info.Flags = unix.LO_FLAGS_READ_ONLY | unix.LO_FLAGS_DIRECT_IO | unix.LO_FLAGS_AUTOCLEAR
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

func (m *sysMounter) LoopBackingFile(loop string) (string, error) {
	b, err := os.ReadFile(filepath.Join(m.sysRoot, "block", filepath.Base(loop), "loop", "backing_file"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// sameDevice tells whether the backing file of a loop device, as the
// process that set it up saw its path, is the device node dev.
func sameDevice(backing, dev string) bool {
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
