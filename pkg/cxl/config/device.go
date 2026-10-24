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

package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// forbiddenPathDirs are the directories that device.path of mode fs must
// not be in.
var forbiddenPathDirs = []string{"/dev", "/proc", "/sys", "/run/cxl", "/var/run/cxl"}

// PoolFacts are the claim status data of a pool device that its device
// section is checked against.
type PoolFacts struct {
	// Persistent: the device has persistent memory.
	Persistent bool
	// Shared: the device may be attached to several hosts.
	Shared bool
	// Exclusive: the allocation consumed all shares of a shared device.
	Exclusive bool
}

// MemdevMode returns the mode of a slice of a local memdev of volatile
// memory with the device section: numa (default) or dax for a memdev that
// is not shared, dax (default and only) for a shared memdev; readOnly
// needs dax; access and path, which are of mode fs, are refused.
func (d Device) MemdevMode(shared bool) (string, error) {
	mode := d.Mode
	switch {
	case mode == "" && shared:
		mode = ModeDax
	case mode == "":
		mode = ModeNUMA
	case mode != ModeNUMA && mode != ModeDax:
		return "", fmt.Errorf("%sdevice.mode: invalid mode %q (%s or %s)", errPrefix, d.Mode, ModeNUMA, ModeDax)
	}
	switch {
	case d.ReadOnly && mode != ModeDax:
		return "", fmt.Errorf("%sdevice.readOnly needs mode %s", errPrefix, ModeDax)
	case shared && mode != ModeDax:
		return "", fmt.Errorf("%sdevice: a shared device is used as %s only", errPrefix, ModeDax)
	case d.Access != "":
		return "", errNeedsFs("access")
	case d.Path != "":
		return "", errNeedsFs("path")
	}
	return mode, nil
}

// NUMAOnly returns an error if the device section asks a device that is
// used as numa only for another mode or for another field.
//   - what: the device type in the message, device.DeviceTypeRegion or
//     device.DeviceTypeDRAM
func (d Device) NUMAOnly(what string) error {
	mode, err := d.MemdevMode(false)
	if err == nil && mode != ModeNUMA {
		err = fmt.Errorf("%sdevice: a %s is used as %s only", errPrefix, what, ModeNUMA)
	}
	return err
}

// CheckLease returns an error if the device section sets a field: the
// lease device has no device settings.
func (d Device) CheckLease() error {
	if d != (Device{}) {
		return fmt.Errorf("%sdevice: the %s device has no device settings", errPrefix, device.DeviceTypeLease)
	}
	return nil
}

// PoolMode returns the mode of a pool device with the device section. The
// checks of the section alone come first, then those that need the facts
// of the device: block and fs are of persistent devices only and a
// persistent device has no other modes; a shared device is writable in
// mode block only exclusively; a shared device of volatile memory is dax
// (default and only); numa is the default of other volatile devices.
func (d Device) PoolMode(f PoolFacts) (string, error) {
	mode := d.Mode
	switch mode {
	case "", ModeNUMA, ModeDax, ModeBlock, ModeFs:
	default:
		return "", fmt.Errorf("%sdevice.mode: invalid mode %q (%s, %s, %s or %s)", errPrefix, mode, ModeNUMA, ModeDax, ModeBlock, ModeFs)
	}
	switch {
	case d.Access != "" && mode != ModeFs:
		return "", errNeedsFs("access")
	case d.Path != "" && mode != ModeFs:
		return "", errNeedsFs("path")
	case d.Access != "" && d.Access != AccessDirect && d.Access != AccessCached:
		return "", fmt.Errorf("%sdevice.access: invalid access %q (%s or %s)", errPrefix, d.Access, AccessDirect, AccessCached)
	case d.Path != "" && !validFsPath(d.Path):
		return "", fmt.Errorf("%sdevice.path: invalid path %q (an absolute path outside %s)", errPrefix, d.Path, listAnd(forbiddenPathDirs))
	case mode == ModeFs && !d.ReadOnly:
		return "", fmt.Errorf("%sdevice.readOnly: mode %s is read-only: set readOnly: true (write the device with mode %s)", errPrefix, ModeFs, ModeBlock)
	case d.ReadOnly && mode == ModeNUMA:
		return "", errReadOnlyMode()
	}
	switch {
	case !f.Persistent && persistentMode(mode):
		return "", fmt.Errorf("%sdevice.mode %s needs a persistent device", errPrefix, mode)
	case f.Persistent && !persistentMode(mode):
		return "", fmt.Errorf("%sdevice: a persistent device needs mode %s or %s", errPrefix, ModeBlock, ModeFs)
	case mode == ModeBlock && f.Shared && !f.Exclusive && !d.ReadOnly:
		return "", fmt.Errorf("%sdevice.mode %s: a shared device is writable only exclusively (no %s request)", errPrefix, ModeBlock, device.CapacityShares)
	case f.Persistent:
		return mode, nil
	}
	// volatile memory
	switch {
	case mode == "" && f.Shared:
		mode = ModeDax
	case mode == "":
		mode = ModeNUMA
	}
	switch {
	case f.Shared && mode != ModeDax:
		return "", fmt.Errorf("%sdevice: a shared device is used as %s only", errPrefix, ModeDax)
	case d.ReadOnly && mode != ModeDax:
		return "", errReadOnlyMode()
	}
	return mode, nil
}

// errNeedsFs returns the error of a field of mode fs in another mode.
func errNeedsFs(field string) error {
	return fmt.Errorf("%sdevice.%s needs mode %s", errPrefix, field, ModeFs)
}

// errReadOnlyMode returns the error of readOnly of a pool device in a mode
// without it.
func errReadOnlyMode() error {
	return fmt.Errorf("%sdevice.readOnly needs mode %s, %s or %s", errPrefix, ModeDax, ModeBlock, ModeFs)
}

// persistentMode tells whether a mode is a mode of persistent devices.
func persistentMode(mode string) bool {
	return mode == ModeBlock || mode == ModeFs
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

// listAnd returns the values as "a, b and c".
func listAnd(values []string) string {
	if len(values) < 2 {
		return strings.Join(values, "")
	}
	return strings.Join(values[:len(values)-1], ", ") + " and " + values[len(values)-1]
}
