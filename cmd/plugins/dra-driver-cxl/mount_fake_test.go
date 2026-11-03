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
	"encoding/binary"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeMounter is the mount table, the loop devices and the block devices
// of a node. Like the kernel it gives a second mount of a source the
// superblock (and the super options) of the first one, changes the
// superblock of every mount of a source at a reconfigure, removes an
// autoclear loop device with its last mount, refuses a read-write
// superblock on a read-only block device, and makes a read-only mount of
// a dirty filesystem on a read-only device fail with EROFS. It records
// the violations of the rules of the shared persistent code (violations):
// a block device made read-only under a read-write superblock, a
// read-only mount of a writable filesystem type on a writable block
// device, two superblocks of one image of which one is read-write.
type fakeMounter struct {
	mu sync.Mutex
	// cutAt kills the plugin after a Mount at that target (cutPrepare),
	// "" for none
	cutAt     string
	mounts    []mountInfo
	calls     []string
	loops     map[string]string // loop device -> backing
	nextLoop  int
	mountErr  map[string]error    // source -> error of Mount and FsMount
	ctxMsgs   map[string]string   // source -> messages of the filesystem context of a failed FsMount
	superOpts map[string][]string // source -> super options of a new superblock
	busy      map[string]bool     // targets whose Unmount fails with EBUSY
	bindRoot  string              // the root of a new bind, "": that of its source
	holders   map[string]string   // block device -> holder, like a container's bind mount
	holderErr error               // error of Holder
	detachErr error               // error of Release(true) of a loop device
	bindFlags []string            // the per-mount flags of a new bind, nil: those of its source
	// block devices
	ro        map[string]bool   // read-only flags (BLKROSET)
	roErr     map[string]error  // device -> error of SetReadOnly
	images    map[string][]byte // device -> its head (ReadHead); a loop device reads its backing's
	dirty     map[string]bool   // device -> its filesystem needs recovery
	loopRW    map[string]bool   // loop devices whose backing is opened read-write
	writing   map[string]bool   // targets with a file open for writing: a reconfigure to ro is EBUSY
	syncErr   error             // error of Syncfs
	reconfErr map[string]error  // target -> error of Reconfigure
	// foreign are mounts in other mount namespaces (a container's), which
	// Mounts does not show, by the pid of a process in them
	foreign    map[int][]mountInfo
	superErr   error // error of Superblocks
	violations []string
}

func newFakeMounter() *fakeMounter {
	return &fakeMounter{
		loops:     map[string]string{},
		mountErr:  map[string]error{},
		ctxMsgs:   map[string]string{},
		superOpts: map[string][]string{},
		busy:      map[string]bool{},
		holders:   map[string]string{},
		ro:        map[string]bool{},
		roErr:     map[string]error{},
		images:    map[string][]byte{},
		dirty:     map[string]bool{},
		loopRW:    map[string]bool{},
		writing:   map[string]bool{},
		reconfErr: map[string]error{},
		foreign:   map[int][]mountInfo{},
	}
}

func (m *fakeMounter) call(format string, args ...any) {
	m.calls = append(m.calls, fmt.Sprintf(format, args...))
}

// violate records a violation of the rules. Called with m.mu held.
func (m *fakeMounter) violate(format string, args ...any) {
	m.violations = append(m.violations, fmt.Sprintf(format, args...))
}

// wantNoViolations checks that no rule was violated.
func (m *fakeMounter) wantNoViolations(t *testing.T) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.violations) != 0 {
		t.Fatalf("violations of the rules of persistent devices:\n%s", strings.Join(m.violations, "\n"))
	}
}

// image returns the block device under a source: the backing of a loop
// device, else the source. Called with m.mu held.
func (m *fakeMounter) image(source string) string {
	if b, ok := m.loops[source]; ok {
		return devPath(b)
	}
	return source
}

// rwSuper returns a mount with a read-write superblock on the source.
// Called with m.mu held.
func (m *fakeMounter) rwSuper(match func(source string) bool) *mountInfo {
	for _, mi := range m.allMounts() {
		if match(mi.Source) && !mi.superReadOnly() {
			return &mi
		}
	}
	return nil
}

// allMounts returns the mounts of every mount namespace. Called with m.mu
// held.
func (m *fakeMounter) allMounts() []mountInfo {
	all := slices.Clone(m.mounts)
	for _, pid := range slices.Sorted(maps.Keys(m.foreign)) {
		all = append(all, m.foreign[pid]...)
	}
	return all
}

// addForeign adds a mount of source in the mount namespace of the process
// pid, with a read-only or read-write superblock.
func (m *fakeMounter) addForeign(pid int, source, target, fstype string, readOnly bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.foreign[pid] = append(m.foreign[pid], mountInfo{Root: "/", Target: target, FsType: fstype, Source: source,
		SuperOpts: []string{map[bool]string{true: "ro", false: "rw"}[readOnly]}, MountFlags: []string{"ro", "nosuid", "nodev"}})
}

func (m *fakeMounter) Superblocks(dev string) ([]superblock, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.call("superblocks %s", dev)
	if m.superErr != nil {
		return nil, m.superErr
	}
	var out []superblock
	seen := map[string]bool{}
	add := func(pid int, mounts []mountInfo) {
		for _, mi := range mounts {
			if seen[mi.Source] || (mi.Source != dev && m.image(mi.Source) != dev) {
				continue
			}
			seen[mi.Source] = true
			out = append(out, superblock{Device: mi.Source, Source: mi.Source, ReadOnly: mi.superReadOnly(), Where: fmt.Sprintf("pid %d at %s", pid, mi.Target)})
		}
	}
	add(1, m.mounts)
	for _, pid := range slices.Sorted(maps.Keys(m.foreign)) {
		add(pid, m.foreign[pid])
	}
	return out, nil
}

func (m *fakeMounter) Mount(source, target, fstype string, flags uintptr, data string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.call("mount %s %s %s 0x%x %s", source, target, fstype, flags, data)
	if err := m.mountErr[source]; err != nil {
		return err
	}
	if _, err := os.Stat(target); err != nil {
		return err
	}
	if flags&unix.MS_BIND != 0 {
		// a bind has the superblock and the per-mount flags of its source
		src := findMount(m.mounts, source)
		if src == nil {
			return unix.EINVAL
		}
		bind := *src
		bind.Target = filepath.Clean(target)
		bind.MountFlags = slices.Clone(src.MountFlags)
		if m.bindFlags != nil {
			bind.MountFlags = slices.Clone(m.bindFlags)
		}
		if m.bindRoot != "" {
			bind.Root = m.bindRoot
		}
		m.mounts = append(m.mounts, bind)
		m.cut(target)
		return nil
	}
	opts := []string{"ro", data}
	if o, ok := m.superOpts[source]; ok {
		opts = o
	}
	for _, mi := range m.mounts {
		if mi.Source == source {
			opts = mi.SuperOpts
		}
	}
	m.mounts = append(m.mounts, mountInfo{Root: "/", Target: target, FsType: fstype, Source: source, SuperOpts: slices.Clone(opts), MountFlags: []string{"ro", "nosuid", "nodev"}})
	m.cut(target)
	return nil
}

func (m *fakeMounter) FsMount(source, target, fstype string, readWrite bool, options []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.call("fsmount %s %s %s %s %s", source, target, fstype, map[bool]string{true: "rw", false: "ro"}[readWrite], strings.Join(options, ","))
	if err := m.mountErr[source]; err != nil {
		if msg := m.ctxMsgs[source]; msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	if _, err := os.Stat(target); err != nil {
		return err
	}
	img := m.image(source)
	devRO := m.ro[source]
	_, isLoop := m.loops[source]
	switch {
	case readWrite && devRO:
		return unix.EACCES
	case readWrite && isLoop && m.ro[img]:
		return unix.EIO // the loop device writes to a read-only backing
	case !readWrite && devRO && m.dirty[img]:
		return unix.EROFS
	case !readWrite && !devRO:
		m.violate("fsmount of %s at %s read-only on a writable block device", source, target)
	}
	var opts []string
	for _, mi := range m.mounts {
		if mi.Source == source {
			opts = mi.SuperOpts
		}
	}
	if opts == nil {
		// a new superblock: another one of the same image is another cache
		for _, mi := range m.mounts {
			if mi.Source != source && m.image(mi.Source) == img {
				if fstype == "xfs" && !slices.Contains(options, "nouuid") {
					return fmt.Errorf("%w: Filesystem has duplicate UUID", unix.EINVAL)
				}
				if readWrite || !mi.superReadOnly() {
					m.violate("a second superblock of %s (%s and %s), one read-write", img, mi.Source, source)
				}
			}
		}
		opts = append([]string{map[bool]string{true: "rw", false: "ro"}[readWrite]}, options...)
		if o, ok := m.superOpts[source]; ok {
			opts = o
		}
	}
	m.mounts = append(m.mounts, mountInfo{Root: "/", Target: filepath.Clean(target), FsType: fstype, Source: source, SuperOpts: slices.Clone(opts), MountFlags: []string{"rw", "nosuid", "nodev"}})
	m.cut(target)
	return nil
}

func (m *fakeMounter) Reconfigure(target string, readWrite bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.call("reconfigure %s %s", target, map[bool]string{true: "rw", false: "ro"}[readWrite])
	if err := m.reconfErr[target]; err != nil {
		return err
	}
	mi := findMount(m.mounts, target)
	if mi == nil {
		return unix.EINVAL
	}
	source := mi.Source
	img := m.image(source)
	_, isLoop := m.loops[source]
	switch {
	case readWrite && m.ro[source]:
		return unix.EACCES
	case readWrite && isLoop && m.ro[img]:
		return unix.EIO
	case !readWrite && m.writing[target]:
		return unix.EBUSY
	}
	if readWrite {
		for _, o := range m.mounts {
			if o.Source != source && m.image(o.Source) == img {
				m.violate("%s made read-write next to the superblock of %s", source, o.Source)
			}
		}
	}
	for i := range m.mounts {
		if m.mounts[i].Source == source && len(m.mounts[i].SuperOpts) > 0 {
			opts := slices.Clone(m.mounts[i].SuperOpts)
			opts[0] = map[bool]string{true: "rw", false: "ro"}[readWrite]
			m.mounts[i].SuperOpts = opts
		}
	}
	m.cut(target)
	return nil
}

func (m *fakeMounter) Syncfs(target string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.call("syncfs %s", target)
	return m.syncErr
}

func (m *fakeMounter) BindReadOnly(source, target string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.call("robind %s %s", source, target)
	if _, err := os.Stat(target); err != nil {
		return err
	}
	src := findMount(m.mounts, source)
	if src == nil {
		return unix.EINVAL
	}
	bind := *src
	bind.Target = filepath.Clean(target)
	bind.MountFlags = []string{"ro", "nosuid", "nodev"}
	if m.bindFlags != nil {
		bind.MountFlags = slices.Clone(m.bindFlags)
	}
	if m.bindRoot != "" {
		bind.Root = m.bindRoot
	}
	m.mounts = append(m.mounts, bind)
	m.cut(target)
	return nil
}

func (m *fakeMounter) SetReadOnly(dev string, readOnly bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.call("blkroset %s %d", dev, map[bool]int{true: 1, false: 0}[readOnly])
	if err := m.roErr[dev]; err != nil {
		return err
	}
	if readOnly {
		if mi := m.rwSuper(func(s string) bool { return s == dev || m.image(s) == dev }); mi != nil {
			m.violate("%s made read-only under the read-write superblock of %s at %s", dev, mi.Source, mi.Target)
		}
	}
	m.ro[dev] = readOnly
	m.cut(dev)
	return nil
}

func (m *fakeMounter) ReadOnly(dev string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ro[dev], nil
}

func (m *fakeMounter) ReadHead(dev string, n int) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	img := m.images[m.image(dev)]
	return slices.Clone(img[:min(n, len(img))]), nil
}

// cut kills the plugin after a mount at the target of cutAt. Called with
// m.mu held, which the deferred unlock of the caller releases.
func (m *fakeMounter) cut(target string) {
	if m.cutAt == "" || filepath.Clean(target) != m.cutAt {
		return
	}
	m.cutAt = ""
	panic(errCut)
}

func (m *fakeMounter) Unmount(target string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.call("umount %s", target)
	if m.busy[target] {
		return unix.EBUSY
	}
	mi := findMount(m.mounts, target)
	if mi == nil {
		return unix.EINVAL
	}
	source := mi.Source
	m.mounts = slices.DeleteFunc(m.mounts, func(x mountInfo) bool { return x.Target == target })
	m.autoclear(source)
	return nil
}

// autoclear removes an autoclear loop device without mounts.
func (m *fakeMounter) autoclear(loop string) {
	if _, ok := m.loops[loop]; !ok {
		return
	}
	for _, mi := range m.mounts {
		if mi.Source == loop {
			return
		}
	}
	delete(m.loops, loop)
	delete(m.loopRW, loop)
	delete(m.ro, loop)
}

func (m *fakeMounter) Mounts() ([]mountInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.mounts), nil
}

func (m *fakeMounter) Mounted(target string) (*mountInfo, error) {
	mounts, _ := m.Mounts()
	return findMount(mounts, target), nil
}

type fakeLoop struct {
	m    *fakeMounter
	path string
}

func (l *fakeLoop) Path() string { return l.path }

func (l *fakeLoop) Release(detach bool) error {
	l.m.mu.Lock()
	defer l.m.mu.Unlock()
	l.m.call("loop-release %s detach=%v", l.path, detach)
	if detach && l.m.detachErr != nil {
		return l.m.detachErr
	}
	if detach {
		delete(l.m.loops, l.path)
		delete(l.m.loopRW, l.path)
		delete(l.m.ro, l.path)
	} else {
		l.m.autoclear(l.path)
	}
	return nil
}

func (m *fakeMounter) AttachLoop(backing string, writable bool) (loopDevice, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	path := fmt.Sprintf("/dev/loop%d", m.nextLoop)
	m.nextLoop++
	if writable {
		m.call("loop %s %s rw", path, backing)
	} else {
		m.call("loop %s %s", path, backing)
	}
	m.loops[path] = backing
	m.loopRW[path] = writable
	// a read-only loop device is read-only; a writable one is not, also
	// over a read-only backing (01-findings K15)
	m.ro[path] = !writable
	return &fakeLoop{m: m, path: path}, nil
}

func (m *fakeMounter) LoopBackingFile(loop string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loops[loop], nil
}

func (m *fakeMounter) Holder(dev string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.holderErr != nil {
		return "", m.holderErr
	}
	if h := m.holders[dev]; h != "" {
		return h, nil
	}
	for loop, backing := range m.loops {
		if sameDevice(backing, dev) { // as sysMounter compares them
			return filepath.Base(loop), nil
		}
	}
	for _, mi := range m.allMounts() {
		if mi.Source == dev {
			return "in use", nil
		}
	}
	return "", nil
}

// setBusy makes the Unmount of target fail with EBUSY, or not.
func (m *fakeMounter) setBusy(target string, busy bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.busy[target] = busy
}

func (m *fakeMounter) callsOf(prefix string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, c := range m.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// isRO returns the read-only flag of a block device.
func (m *fakeMounter) isRO(dev string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ro[dev]
}

// fsImage returns the head of a block device with the signatures of the
// filesystem types: erofs, squashfs, ext4 (ext4-dirty: needs recovery),
// xfs, btrfs, gfs2 (lock_dlm), gfs2-nolock (lock_nolock).
func fsImage(types ...string) []byte {
	img := make([]byte, fsProbeBytes)
	for _, t := range types {
		switch t {
		case "erofs":
			binary.LittleEndian.PutUint32(img[1024:], 0xE0F5E1E2)
		case "squashfs":
			copy(img, "hsqs")
		case "ext4", "ext4-dirty":
			binary.LittleEndian.PutUint16(img[1080:], 0xEF53)
			if t == "ext4-dirty" {
				binary.LittleEndian.PutUint32(img[1024+0x60:], 0x4|0x2)
			} else {
				binary.LittleEndian.PutUint32(img[1024+0x60:], 0x2)
			}
		case "xfs":
			copy(img, "XFSB")
		case "btrfs":
			copy(img[65600:], "_BHRfS_M")
		case "gfs2", "gfs2-nolock":
			binary.BigEndian.PutUint32(img[65536:], 0x01161970)
			binary.BigEndian.PutUint32(img[65540:], 1)
			proto := "lock_dlm"
			if t == "gfs2-nolock" {
				proto = "lock_nolock"
			}
			copy(img[65536+96:], proto+"\x00")
		default:
			panic("fsImage: unknown type " + t)
		}
	}
	return img
}
