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
	"testing"

	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// checkErr reports whether err is nil for "" or has the text want.
func checkErr(err error, want string) bool {
	if want == "" {
		return err == nil
	}
	return err != nil && err.Error() == want
}

func TestMemdevMode(t *testing.T) {
	for _, tc := range []struct {
		dev    Device
		shared bool
		want   string
		err    string
	}{
		{shared: true, want: ModeDax},
		{want: ModeNUMA},
		{dev: Device{Mode: "numa"}, want: ModeNUMA},
		{dev: Device{Mode: "dax"}, want: ModeDax},
		{dev: Device{Mode: "dax", ReadOnly: true}, want: ModeDax},
		{dev: Device{ReadOnly: true}, shared: true, want: ModeDax},
		{dev: Device{Mode: "dax", ReadOnly: true}, shared: true, want: ModeDax},
		{dev: Device{Mode: "numa"}, shared: true, err: "MemoryConfig: device: a shared device is used as dax only"},
		{dev: Device{ReadOnly: true}, err: "MemoryConfig: device.readOnly needs mode dax"},
		{dev: Device{Mode: "kmem"}, err: `MemoryConfig: device.mode: invalid mode "kmem" (numa or dax)`},
		// the local driver has no modes block and fs
		{dev: Device{Mode: "fs", ReadOnly: true, Access: "direct"}, err: `MemoryConfig: device.mode: invalid mode "fs" (numa or dax)`},
		{dev: Device{Mode: "block"}, err: `MemoryConfig: device.mode: invalid mode "block" (numa or dax)`},
		{dev: Device{Access: "direct"}, err: "MemoryConfig: device.access needs mode fs"},
		{dev: Device{Mode: "dax", Path: "/models"}, err: "MemoryConfig: device.path needs mode fs"},
	} {
		got, err := tc.dev.MemdevMode(tc.shared)
		if !checkErr(err, tc.err) || (tc.err == "" && got != tc.want) {
			t.Errorf("%+v shared %v: got %q %v, expected %q %q", tc.dev, tc.shared, got, err, tc.want, tc.err)
		}
	}
}

func TestNUMAOnly(t *testing.T) {
	for _, tc := range []struct {
		dev  Device
		what string
		err  string
	}{
		{Device{}, device.DeviceTypeRegion, ""},
		{Device{Mode: "numa"}, device.DeviceTypeDRAM, ""},
		{Device{Mode: "dax"}, device.DeviceTypeRegion, "MemoryConfig: device: a region is used as numa only"},
		{Device{Mode: "dax", ReadOnly: true}, device.DeviceTypeDRAM, "MemoryConfig: device: a dram is used as numa only"},
		{Device{ReadOnly: true}, device.DeviceTypeRegion, "MemoryConfig: device.readOnly needs mode dax"},
		{Device{Mode: "kmem"}, device.DeviceTypeDRAM, `MemoryConfig: device.mode: invalid mode "kmem" (numa or dax)`},
		{Device{Access: "cached"}, device.DeviceTypeRegion, "MemoryConfig: device.access needs mode fs"},
		{Device{Path: "/x"}, device.DeviceTypeDRAM, "MemoryConfig: device.path needs mode fs"},
	} {
		if err := tc.dev.NUMAOnly(tc.what); !checkErr(err, tc.err) {
			t.Errorf("%+v %s: %v, expected %q", tc.dev, tc.what, err, tc.err)
		}
	}
}

func TestCheckLease(t *testing.T) {
	const msg = "MemoryConfig: device: the lease device has no device settings"
	for _, tc := range []struct {
		dev Device
		err string
	}{
		{Device{}, ""},
		{Device{Mode: "numa"}, msg},
		{Device{ReadOnly: true}, msg},
		{Device{Access: "direct"}, msg},
		{Device{Path: "/models"}, msg},
	} {
		if err := tc.dev.CheckLease(); !checkErr(err, tc.err) {
			t.Errorf("%+v: %v, expected %q", tc.dev, err, tc.err)
		}
	}
}

func TestPoolMode(t *testing.T) {
	volatile := PoolFacts{}
	shared := PoolFacts{Shared: true}
	reader := PoolFacts{Shared: true, Persistent: true}
	writer := PoolFacts{Shared: true, Persistent: true, Exclusive: true}
	private := PoolFacts{Persistent: true}
	for _, tc := range []struct {
		dev  Device
		f    PoolFacts
		want string
		err  string
	}{
		{f: volatile, want: ModeNUMA},
		{f: shared, want: ModeDax},
		{dev: Device{Mode: "dax"}, f: volatile, want: ModeDax},
		{dev: Device{Mode: "dax", ReadOnly: true}, f: volatile, want: ModeDax},
		{dev: Device{ReadOnly: true}, f: shared, want: ModeDax},
		{dev: Device{Mode: "block"}, f: writer, want: ModeBlock},
		{dev: Device{Mode: "block"}, f: private, want: ModeBlock},
		{dev: Device{Mode: "block", ReadOnly: true}, f: reader, want: ModeBlock},
		{dev: Device{Mode: "fs", ReadOnly: true}, f: reader, want: ModeFs},
		{dev: Device{Mode: "fs", ReadOnly: true, Access: "cached", Path: "/models"}, f: writer, want: ModeFs},
		{dev: Device{Mode: "fs", ReadOnly: true, Access: "direct"}, f: private, want: ModeFs},
		// the section alone, in this order
		{dev: Device{Mode: "ext4", Access: "bogus"}, f: reader, err: `MemoryConfig: device.mode: invalid mode "ext4" (numa, dax, block or fs)`},
		{dev: Device{Mode: "block", Access: "bogus", Path: "rel"}, f: reader, err: "MemoryConfig: device.access needs mode fs"},
		{dev: Device{Access: "direct"}, f: volatile, err: "MemoryConfig: device.access needs mode fs"},
		{dev: Device{Mode: "dax", Path: "rel"}, f: reader, err: "MemoryConfig: device.path needs mode fs"},
		{dev: Device{Mode: "fs", Access: "dax", Path: "rel"}, f: volatile, err: `MemoryConfig: device.access: invalid access "dax" (direct or cached)`},
		{dev: Device{Mode: "fs", Path: "/run/cxl/fs"}, f: volatile,
			err: `MemoryConfig: device.path: invalid path "/run/cxl/fs" (an absolute path outside /dev, /proc, /sys, /run/cxl and /var/run/cxl)`},
		{dev: Device{Mode: "fs", Access: "cached"}, f: volatile, err: "MemoryConfig: device.readOnly: mode fs is read-only: set readOnly: true (write the device with mode block)"},
		{dev: Device{Mode: "numa", ReadOnly: true}, f: reader, err: "MemoryConfig: device.readOnly needs mode dax, block or fs"},
		// with the facts of the device
		{dev: Device{Mode: "block"}, f: shared, err: "MemoryConfig: device.mode block needs a persistent device"},
		{dev: Device{Mode: "fs", ReadOnly: true}, f: volatile, err: "MemoryConfig: device.mode fs needs a persistent device"},
		{f: reader, err: "MemoryConfig: device: a persistent device needs mode block or fs"},
		{dev: Device{ReadOnly: true}, f: private, err: "MemoryConfig: device: a persistent device needs mode block or fs"},
		{dev: Device{Mode: "dax"}, f: writer, err: "MemoryConfig: device: a persistent device needs mode block or fs"},
		{dev: Device{Mode: "numa"}, f: private, err: "MemoryConfig: device: a persistent device needs mode block or fs"},
		{dev: Device{Mode: "block"}, f: reader, err: "MemoryConfig: device.mode block: a shared device is writable only exclusively (no shares request)"},
		// volatile devices
		{dev: Device{Mode: "numa"}, f: shared, err: "MemoryConfig: device: a shared device is used as dax only"},
		{dev: Device{ReadOnly: true}, f: volatile, err: "MemoryConfig: device.readOnly needs mode dax, block or fs"},
	} {
		got, err := tc.dev.PoolMode(tc.f)
		if !checkErr(err, tc.err) || (tc.err == "" && got != tc.want) {
			t.Errorf("%+v %+v: got %q %v, expected %q %q", tc.dev, tc.f, got, err, tc.want, tc.err)
		}
	}
}

func TestValidFsPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/models": true, "/run/cxl-fs/C1AE0001": true, "/run/cxl-fs": true, "/devices": true, "/run/cxlfs": true, "/a/b": true,
		"": false, "/": false, "models": false, "/models/": false, "/a/../b": false, "/a//b": false,
		"/dev": false, "/dev/pmem0": false, "/proc/1": false, "/sys": false, "/run/cxl": false, "/run/cxl/fs/x": false,
		"/var/run/cxl": false, "/var/run/cxl/fs": false, "/var/run/cxl-fs": true,
	} {
		if got := validFsPath(p); got != want {
			t.Errorf("validFsPath(%q) = %v", p, got)
		}
	}
}

func TestDeviceSection(t *testing.T) {
	var nilConfig *MemoryConfig
	if got := nilConfig.DeviceSection(); got != (Device{}) {
		t.Errorf("nil config: %+v", got)
	}
	if got := (&MemoryConfig{}).DeviceSection(); got != (Device{}) {
		t.Errorf("no device section: %+v", got)
	}
	want := Device{Mode: ModeDax, ReadOnly: true}
	if got := (&MemoryConfig{Device: &want}).DeviceSection(); got != want {
		t.Errorf("device section: %+v", got)
	}
}
