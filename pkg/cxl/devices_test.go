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

package cxl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sysfsFromDump returns a sysfs root made of the dump in testdata/name,
// captured by the e2e cxl-dump helper on a VM:
//   - cxl-sysfs.txt: "path:line" for the files of /sys/bus/cxl/devices/memN,
//     regionN and endpointN (grep -r of an empty pattern in
//     /sys/bus/cxl/devices/*)
//   - memory.txt: "path:line" for block_size_bytes, memoryN/state and
//     nodeN/meminfo
//   - zoneinfo.txt: the Node, start_pfn and present lines of /proc/zoneinfo
//
// grep -r does not follow the uport links of endpoints: uports maps an
// endpoint to its memdev, whose dev and uevent are copied there. The
// online file of every memory block comes from its state.
func sysfsFromDump(t *testing.T, name string, uports map[string]string) string {
	t.Helper()
	root := t.TempDir()
	add := func(path, line string) {
		t.Helper()
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteString(line + "\n")
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"cxl-sysfs.txt", "memory.txt"} {
		data, err := os.ReadFile(filepath.Join("testdata", name, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			path, value, ok := strings.Cut(line, ":")
			if !ok {
				t.Fatalf("%s/%s: bad line %q", name, file, line)
			}
			add(path, value)
			if strings.HasSuffix(path, "/state") {
				online := "0"
				if strings.HasPrefix(value, "online") {
					online = "1"
				}
				add(filepath.Join(filepath.Dir(path), "online"), online)
			}
		}
	}
	zoneinfo, err := os.ReadFile(filepath.Join("testdata", name, "zoneinfo.txt"))
	if err != nil {
		t.Fatal(err)
	}
	add("/proc/zoneinfo", strings.TrimSpace(string(zoneinfo)))
	devices := filepath.Join(root, "sys/bus/cxl/devices")
	for endpoint, memdev := range uports {
		for _, file := range []string{"dev", "uevent"} {
			data, err := os.ReadFile(filepath.Join(devices, memdev, file))
			if err != nil {
				t.Fatal(err)
			}
			add(filepath.Join("/sys/bus/cxl/devices", endpoint, "uport", file), strings.TrimSpace(string(data)))
		}
	}
	return root
}

// region0 returns the only region of the devices of a sysfs root.
func region0(t *testing.T, root string) *RegionDevice {
	t.Helper()
	devices, err := DevicesFromSysfs(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices.RegionDevices) != 1 || devices.RegionDevices[0].Name != "region0" {
		t.Fatalf("regions %+v", devices.RegionDevices)
	}
	return devices.RegionDevices[0]
}

// A devdax region with several dax devices and no online memory has the
// node of their target_node (test14 of n4-cxl-shared-2: two dax slices and
// the empty dax0.0 of a local device).
func TestRegionNodeOfDaxSlices(t *testing.T) {
	uports := map[string]string{"endpoint4": "mem0"}
	root := sysfsFromDump(t, "test14-node-numa-b-deleted", uports)
	r := region0(t, root)
	if r.Node != 2 || !r.Enabled || r.OnlineSize != 0 || r.Mode != "ram" || r.Size != 1<<30 ||
		len(r.Memories) != 1 || r.Memories[0].Serial != 0xc100e2e1 {
		t.Fatalf("region %+v", r)
	}
	daxRegion := filepath.Join(root, "sys/bus/cxl/devices/region0/dax_region0")
	// the first dax device without a node: the next one tells it
	if err := os.WriteFile(filepath.Join(daxRegion, "dax0.0/target_node"), []byte("-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := region0(t, root); r.Node != 2 || !r.Enabled {
		t.Fatalf("region %+v", r)
	}
	// one dax device, as before
	for _, dax := range []string{"dax0.1", "dax0.3"} {
		if err := os.RemoveAll(filepath.Join(daxRegion, dax)); err != nil {
			t.Fatal(err)
		}
	}
	if r := region0(t, root); r.Node != -1 || r.Enabled {
		t.Fatalf("region of a dax device without a node %+v", r)
	}
	if err := os.WriteFile(filepath.Join(daxRegion, "dax0.0/target_node"), []byte("2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := region0(t, root); r.Node != 2 || !r.Enabled {
		t.Fatalf("region of one dax device %+v", r)
	}
	// no dax device
	if err := os.RemoveAll(filepath.Join(daxRegion, "dax0.0")); err != nil {
		t.Fatal(err)
	}
	if r := region0(t, root); r.Node != -1 || r.Enabled {
		t.Fatalf("region without dax devices %+v", r)
	}
}

// A region with online memory has the node of its zones (test14: two numa
// slices online, three blocks, and two dax slices).
func TestRegionNodeOfOnlineSlices(t *testing.T) {
	r := region0(t, sysfsFromDump(t, "test14-node-four-claims", map[string]string{"endpoint4": "mem0"}))
	if r.Node != 2 || !r.Enabled || r.OnlineSize != 3<<27 {
		t.Fatalf("region %+v", r)
	}
}
