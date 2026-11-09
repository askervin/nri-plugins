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

//go:build !linux

package kernel

import (
	"context"
	"errors"
	"os"
)

// SysCalls is the Sys of the running system; only Linux has one.
type SysCalls struct {
	DevRoot string
	Logf    func(format string, args ...any)
}

var errNotLinux = errors.ErrUnsupported

func (s *SysCalls) Mount(source, target, fstype string, flags uintptr, data string) error {
	return errNotLinux
}
func (s *SysCalls) FsMount(source, target, fstype string, readWrite bool, options []string) error {
	return errNotLinux
}
func (s *SysCalls) Reconfigure(target string, readWrite bool) error { return errNotLinux }
func (s *SysCalls) Syncfs(target string) error                      { return errNotLinux }
func (s *SysCalls) BindReadOnly(source, target string) error        { return errNotLinux }
func (s *SysCalls) Unmount(target string) error                     { return errNotLinux }
func (s *SysCalls) SetReadOnly(dev string, readOnly bool) error     { return errNotLinux }
func (s *SysCalls) ReadOnly(dev string) (bool, error)               { return false, errNotLinux }
func (s *SysCalls) OpenExclusive(dev string) error                  { return errNotLinux }
func (s *SysCalls) AttachLoop(backing string, writable bool) (Loop, error) {
	return nil, errNotLinux
}
func (s *SysCalls) LoopRdevice(loop string) (uint64, error) { return 0, errNotLinux }
func (s *SysCalls) ZeroDax(ctx context.Context, major, minor int, size, align uint64) error {
	return errNotLinux
}
func (s *SysCalls) ProbeDax(major, minor int, size uint64) (*Aliasing, error) {
	return nil, errNotLinux
}
func (s *SysCalls) OpenDax(ctx context.Context, major, minor int, readOnly bool) (*os.File, error) {
	return nil, errNotLinux
}
