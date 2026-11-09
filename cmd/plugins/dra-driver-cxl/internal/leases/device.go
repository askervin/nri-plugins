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

package leases

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// The devices of dax and block leases are passed to the requester as an
// open fd; the device nodes are made by udev after the driver of the
// device bound it, so the opens wait for them.

// openWait bounds the wait of an open for its device node.
const openWait = 5 * time.Second

// openDevice opens the device of a dax or block lease for passing it to a
// container, read-only or read-write: a devdax device /dev/daxX.Y as
// openDaxDevice does, another device (the block device /dev/pmemK) as
// openBlockDevice does.
func openDevice(path string, readOnly bool) (*os.File, error) {
	if strings.HasPrefix(path, "/dev/dax") {
		return openDaxDevice(path, readOnly)
	}
	return openBlockDevice(path, readOnly)
}

// openFlag returns the flag of an open read-only or read-write.
func openFlag(readOnly bool) int {
	if readOnly {
		return os.O_RDONLY
	}
	return os.O_RDWR
}

// notYet tells whether an open failed because the device node is not
// there yet: ENOENT or ENXIO.
func notYet(err error) bool {
	var errno syscall.Errno
	return (errors.As(err, &errno) && (errno == syscall.ENXIO || errno == syscall.ENOENT)) || os.IsNotExist(err)
}

// openBlockDevice opens a block device for passing it to a container,
// read-only or read-write. The device node is made by udev after the fsdax
// namespace got its block device, so the open is retried every 100 ms for
// up to 5 s while it fails with ENOENT or ENXIO.
func openBlockDevice(path string, readOnly bool) (*os.File, error) {
	deadline := time.Now().Add(openWait)
	for {
		f, err := os.OpenFile(path, openFlag(readOnly), 0)
		if err == nil {
			return f, nil
		}
		if !notYet(err) || time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// openDaxDevice opens /dev/daxX.Y for passing it to a container, read-only
// (the container can map it for reading only) or read-write. The device
// node is made by udev after the device_dax driver bound the dax device,
// and a node of an earlier dax device with the same name may still carry
// the old minor number, so right after a region was set up the open can
// fail with ENOENT or ENXIO. It waits up to 5 s for a node whose
// major:minor matches /sys/bus/dax/devices/<name>/dev; if udev is still
// behind after that, it opens a private node with the numbers from sysfs
// instead and removes it again.
func openDaxDevice(path string, readOnly bool) (*os.File, error) {
	name := filepath.Base(path)
	major, minor, numErr := kernel.New().DaxDevNumbers(name)
	deadline := time.Now().Add(openWait)
	var lastErr error
	for {
		f, err := openDaxNode(path, readOnly, major, minor, numErr == nil)
		if err == nil {
			return f, nil
		}
		lastErr = err
		if !errors.Is(err, errOtherNode) && !notYet(err) {
			return nil, err
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if numErr != nil {
		return nil, fmt.Errorf("%w (and %v)", lastErr, numErr)
	}
	return openPrivateNode(path, readOnly, major, minor, lastErr)
}

// errOtherNode is the error of a dax device node that is not the char
// device of the dax device yet.
var errOtherNode = errors.New("not the char device")

// openDaxNode opens the device node path of a dax device, which must be the
// char device major:minor when check is set.
func openDaxNode(path string, readOnly bool, major, minor int, check bool) (*os.File, error) {
	if check {
		var st syscall.Stat_t
		if err := syscall.Stat(path, &st); err == nil {
			rdev := uint64(st.Rdev)
			if st.Mode&syscall.S_IFMT != syscall.S_IFCHR || int(unix.Major(rdev)) != major || int(unix.Minor(rdev)) != minor {
				return nil, fmt.Errorf("%s is %w %d:%d yet", path, errOtherNode, major, minor)
			}
		}
	}
	return os.OpenFile(path, openFlag(readOnly), 0)
}

// openPrivateNode opens a private device node of the char device
// major:minor of the dax device of path, after the wait for its node at
// path ended with lastErr, and removes it again.
func openPrivateNode(path string, readOnly bool, major, minor int, lastErr error) (*os.File, error) {
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("cxl-lease-%s-%d", filepath.Base(path), os.Getpid()))
	_ = os.Remove(tmp)
	dev := unix.Mkdev(uint32(major), uint32(minor))
	if err := syscall.Mknod(tmp, syscall.S_IFCHR|0600, int(dev)); err != nil {
		return nil, fmt.Errorf("%w; mknod %s %d:%d: %v", lastErr, tmp, major, minor, err)
	}
	defer func() { _ = os.Remove(tmp) }()
	f, err := os.OpenFile(tmp, openFlag(readOnly), 0)
	if err != nil {
		return nil, fmt.Errorf("%w; opening private node %d:%d: %v", lastErr, major, minor, err)
	}
	klog.Warningf("lease broker: %s was not usable within 5 s (%v), opened %d:%d through a private node", path, lastErr, major, minor)
	return f, nil
}
