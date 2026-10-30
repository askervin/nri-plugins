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
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// testParseFlags returns the flags of args with the environment env.
func testParseFlags(args []string, env map[string]string) (*CXLFlags, error) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return parseFlags(fs, args, func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	})
}

func TestParseFlagsDefaults(t *testing.T) {
	f, err := testParseFlags(nil, map[string]string{"NODE_NAME": "n1"})
	if err != nil {
		t.Fatal(err)
	}
	want := &CXLFlags{
		NodeName:            "n1",
		KubeAPIQPS:          5,
		KubeAPIBurst:        10,
		CDIRoot:             "/etc/cdi",
		NRIName:             "dra-driver-cxl",
		NRIIdx:              "30",
		PoolDriverName:      "cxl-pool.nri.io",
		PoolPrepareTimeout:  30 * time.Second,
		Leases:              true,
		LeaseCLI:            "/usr/local/bin/cxl-request",
		LeaseWait:           120 * time.Second,
		LeaseCompanionImage: "registry.k8s.io/pause:3.10",
	}
	if !reflect.DeepEqual(f, want) {
		t.Fatalf("flags\n%+v, expected\n%+v", f, want)
	}
	if device.PoolDriverName != want.PoolDriverName || device.DriverName != "cxl.nri.io" {
		t.Fatalf("driver names %s %s", device.DriverName, device.PoolDriverName)
	}
}

func TestParseFlagsEnvironment(t *testing.T) {
	env := map[string]string{
		"NODE_NAME":             "n1",
		"KUBECONFIG":            "/kubeconfig",
		"KUBE_API_QPS":          "7.5",
		"KUBE_API_BURST":        "20",
		"CDI_ROOT":              "/var/run/cdi",
		"SYSFS_ROOT":            "/host",
		"CONFIG_STR":            "{}",
		"NRI_PLUGIN_NAME":       "cxl",
		"NRI_PLUGIN_IDX":        "40",
		"NRI_SOCKET":            "/nri.sock",
		"POOL_DRIVER_NAME":      "",
		"POOL_PREPARE_TIMEOUT":  "1m",
		"LEASES":                "false",
		"LEASE_CLI":             "/plugins/cxl-request",
		"LEASE_CLI_SOURCE":      "/bin/cxl-request",
		"LEASE_WAIT":            "5s",
		"LEASE_COMPANION_IMAGE": "pause:test",
	}
	f, err := testParseFlags(nil, env)
	if err != nil {
		t.Fatal(err)
	}
	want := &CXLFlags{
		NodeName:            "n1",
		KubeConfig:          "/kubeconfig",
		KubeAPIQPS:          7.5,
		KubeAPIBurst:        20,
		CDIRoot:             "/var/run/cdi",
		SysfsRoot:           "/host",
		ConfigStr:           "{}",
		NRIName:             "cxl",
		NRIIdx:              "40",
		NRISocket:           "/nri.sock",
		PoolDriverName:      "",
		PoolPrepareTimeout:  time.Minute,
		Leases:              false,
		LeaseCLI:            "/plugins/cxl-request",
		LeaseCLISource:      "/bin/cxl-request",
		LeaseWait:           5 * time.Second,
		LeaseCompanionImage: "pause:test",
	}
	if !reflect.DeepEqual(f, want) {
		t.Fatalf("flags\n%+v, expected\n%+v", f, want)
	}

	// The command line overrides the environment, also with short flags.
	f, err = testParseFlags([]string{"--node-name", "n2", "-c", "a: b", "-leases=true", "--lease-wait=1s"}, env)
	if err != nil {
		t.Fatal(err)
	}
	if f.NodeName != "n2" || f.ConfigStr != "a: b" || !f.Leases || f.LeaseWait != time.Second || f.KubeAPIBurst != 20 {
		t.Fatalf("flags %+v", f)
	}
	f, err = testParseFlags([]string{"-f", "/config.yaml"}, env)
	if err != nil || f.ConfigFile != "/config.yaml" || f.ConfigStr != "{}" {
		t.Fatalf("flags %+v, error %v", f, err)
	}
}

func TestParseFlagsErrors(t *testing.T) {
	for _, tc := range []struct {
		args []string
		env  map[string]string
		want string
	}{
		{nil, nil, "--node-name"},
		{[]string{"--node-name", "n1", "extra"}, nil, "arguments not supported"},
		{[]string{"--node-name", "n1"}, map[string]string{"KUBE_API_BURST": "many"}, "KUBE_API_BURST"},
		{[]string{"--node-name", "n1"}, map[string]string{"LEASE_WAIT": "1"}, "LEASE_WAIT"},
		{[]string{"--node-name", "n1", "--lease-cli=", "--lease-cli-source", "/bin/cxl-request"}, nil, "--lease-cli"},
		{[]string{"--no-such-flag"}, nil, "no-such-flag"},
	} {
		if _, err := testParseFlags(tc.args, tc.env); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("args %v env %v: error %v, expected one with %q", tc.args, tc.env, err, tc.want)
		}
	}
}

func TestInstallLeaseCLI(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src", "cxl-request")
	dst := filepath.Join(dir, "plugins", "cxl.nri.io", "cxl-request")
	if err := installLeaseCLI(src, dst); err == nil {
		t.Fatal("missing source: expected an error")
	}
	if err := os.MkdirAll(filepath.Dir(src), 0755); err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{"v1", "v2"} {
		if err := os.WriteFile(src, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		if err := installLeaseCLI(src, dst); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(dst)
		if err != nil || string(data) != content {
			t.Fatalf("installed %q %v, expected %q", data, err, content)
		}
		info, err := os.Stat(dst)
		if err != nil || info.Mode().Perm() != 0755 {
			t.Fatalf("installed mode %v %v", info.Mode(), err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(dst))
	if err != nil || len(entries) != 1 {
		t.Fatalf("files next to the CLI: %v %v", entries, err)
	}
}

func TestEnsureDir(t *testing.T) {
	dir := t.TempDir()
	if err := ensureDir(filepath.Join(dir, "a", "b")); err != nil {
		t.Fatal(err)
	}
	if err := ensureDir(filepath.Join(dir, "a", "b")); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := ensureDir(file); err == nil {
		t.Fatal("a file: expected an error")
	}
}

func TestPreparedClaimsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), device.PreparedClaimsFileName)
	prepared, err := getOrCreatePreparedClaims(path)
	if err != nil || len(prepared) != 0 {
		t.Fatalf("new file: %v %v", prepared, err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "{}" {
		t.Fatalf("new file %q %v", data, err)
	}
	want := claimPreparations{"u1": {Devices: []kubeletplugin.Device{{
		Requests: []string{"mem"}, PoolName: "n1", DeviceName: "memdev-c100e2e1", CDIDeviceIDs: []string{"nri.io/cxl=claim-u1-0"}}}}}
	if err := writePreparedClaimsToFile(path, want); err != nil {
		t.Fatal(err)
	}
	prepared, err = getOrCreatePreparedClaims(path)
	if err != nil || !reflect.DeepEqual(prepared, want) {
		t.Fatalf("read %+v %v, expected %+v", prepared, err, want)
	}
	if err := writePreparedClaimsToFile(path, nil); err != nil {
		t.Fatal(err)
	}
	if prepared, err := readPreparedClaimsFromFile(path); err != nil || len(prepared) != 0 {
		t.Fatalf("read %+v %v, expected no claims", prepared, err)
	}
	if err := os.WriteFile(path, []byte(`{"u1": [`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := getOrCreatePreparedClaims(path); err == nil {
		t.Fatal("invalid file: expected an error")
	}
}

// The two files of the prepared claims after a crash between their writes
// (bug-07): a claim is prepared only when both have it.
func TestPreparedClaimsReconcile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, device.PreparedClaimsFileName)
	result := func(uid string) kubeletplugin.PrepareResult {
		return kubeletplugin.PrepareResult{Devices: []kubeletplugin.Device{{
			Requests: []string{"mem"}, PoolName: "n1", DeviceName: "dram0", CDIDeviceIDs: []string{"nri.io/cxl=claim-" + uid + "-0"}}}}
	}
	info := &PreparedClaimInfo{ClaimName: "ns/c", Devices: []PreparedDeviceInfo{{RequestName: "mem", DeviceName: "dram0", DeviceType: device.DeviceTypeDRAM}}}
	// u1 prepared; u2 stopped in its Prepare (the first file written);
	// u3 stopped in its Unprepare (the first file written); u4 with a null
	// info
	noErr(t, writePreparedClaimsToFile(path, claimPreparations{"u1": result("u1"), "u2": result("u2"), "u4": result("u4")}))
	noErr(t, writePreparedClaimsInfoToFile(filepath.Join(dir, preparedClaimsInfoFileName), PreparedClaimsInfo{"u1": info, "u3": info, "u4": nil}))
	prepared, infos, preparing, unpreparing, err := loadPreparedClaims(path)
	noErr(t, err)
	if !reflect.DeepEqual(prepared, claimPreparations{"u1": result("u1")}) || !reflect.DeepEqual(infos, PreparedClaimsInfo{"u1": info}) {
		t.Errorf("prepared %v info %v, expected u1 only", prepared, infos)
	}
	if !reflect.DeepEqual(preparing, []string{"u2", "u4"}) || !reflect.DeepEqual(unpreparing, []string{"u3"}) {
		t.Errorf("forgotten preparing %v unpreparing %v", preparing, unpreparing)
	}

	// missing files are created empty
	empty := filepath.Join(t.TempDir(), device.PreparedClaimsFileName)
	prepared, infos, preparing, unpreparing, err = loadPreparedClaims(empty)
	if err != nil || len(prepared) != 0 || len(infos) != 0 || preparing != nil || unpreparing != nil {
		t.Fatalf("new files: %v %v %v %v %v", prepared, infos, preparing, unpreparing, err)
	}
	for _, name := range []string{device.PreparedClaimsFileName, preparedClaimsInfoFileName} {
		if data, err := os.ReadFile(filepath.Join(filepath.Dir(empty), name)); err != nil || string(data) != "{}" {
			t.Errorf("new %s %q %v", name, data, err)
		}
	}

	// a restarted node state prepares u2 again, has no info of u3 (its
	// fenced node and lend are gone) and writes both files so
	s, err := newNodeState(device.DevicesInfo{}, t.TempDir(), path, "n1", &DriverConfig{}, nil, "boot-1")
	noErr(t, err)
	if _, found := s.preparedInfo("u2"); found {
		t.Error("u2 is prepared")
	}
	if s.GetClaimInfo("u3") != nil {
		t.Error("u3 has info")
	}
	prepared, infos, preparing, unpreparing, err = loadPreparedClaims(path)
	noErr(t, err)
	if len(prepared) != 1 || len(infos) != 1 || preparing != nil || unpreparing != nil {
		t.Errorf("files after the start: %v %v %v %v", prepared, infos, preparing, unpreparing)
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temporary file left: %v", err)
	}
}

// TestPreparedClaimsOtherBoot: the claims of cxl.nri.io prepared in another
// boot are not prepared at start (plan-13 bug-15): not in the files, no CDI
// device, the nodes of their numa slices not fenced; their Unprepare finds
// nothing, their Prepare again prepares them anew. A claim without a boot
// id (saved by an older driver) is of this boot and gets its id; with the
// boot id of the kernel unknown every claim is.
func TestPreparedClaimsOtherBoot(t *testing.T) {
	dir := t.TempDir()
	cdiDir := filepath.Join(dir, "cdi")
	noErr(t, os.MkdirAll(cdiDir, 0o755))
	path := filepath.Join(dir, device.PreparedClaimsFileName)
	result := func(uid string) kubeletplugin.PrepareResult {
		return kubeletplugin.PrepareResult{Devices: []kubeletplugin.Device{{
			Requests: []string{"mem"}, PoolName: "n1", DeviceName: "memdev-c100e2e1", CDIDeviceIDs: []string{"nri.io/cxl=claim-" + uid + "-0"}}}}
	}
	info := func(boot string, node int) *PreparedClaimInfo {
		return &PreparedClaimInfo{ClaimName: "ns/c", BootID: boot, Devices: []PreparedDeviceInfo{{RequestName: "mem", DeviceName: "memdev-c100e2e1",
			DeviceType: device.DeviceTypeMemdev, Mode: api.ModeNUMA, NUMANodes: []int{node}, Serial: "0xc100e2e1", TotalBytes: 1 << 27}}}
	}
	write := func() {
		t.Helper()
		noErr(t, writePreparedClaimsToFile(path, claimPreparations{"u1": result("u1"), "u2": result("u2"), "u3": result("u3")}))
		noErr(t, writePreparedClaimsInfoToFile(filepath.Join(dir, preparedClaimsInfoFileName),
			PreparedClaimsInfo{"u1": info("boot-1", 3), "u2": info("boot-2", 2), "u3": info("", 2)}))
	}
	cdiDevices := func() []string {
		t.Helper()
		m, _ := filepath.Glob(filepath.Join(cdiDir, device.ClaimsCDISpecName+".*"))
		if len(m) != 1 {
			t.Fatalf("CDI specs %v", m)
		}
		data, err := os.ReadFile(m[0])
		noErr(t, err)
		var names []string
		for _, line := range strings.Split(string(data), "\n") {
			if name, ok := strings.CutPrefix(strings.TrimSpace(line), "- name: "); ok {
				names = append(names, name)
			}
		}
		return names
	}
	devs := device.DevicesInfo{"dram": {Name: "dram", Dev: &device.DRAM{Nodes: []int{0}, Size: 1 << 30}}}

	write()
	s, err := newNodeState(devs, cdiDir, path, "n1", &DriverConfig{}, nil, "boot-2")
	noErr(t, err)
	if _, found := s.preparedInfo("u1"); found || s.GetClaimInfo("u3").BootID != "boot-2" {
		t.Fatalf("prepared %v, infos %v", s.Prepared, s.preparedClaims)
	}
	prepared, infos, _, _, err := loadPreparedClaims(path)
	noErr(t, err)
	if len(prepared) != 2 || len(infos) != 2 || infos["u1"] != nil || infos["u3"].BootID != "boot-2" {
		t.Fatalf("files after the start: %v %v", prepared, infos)
	}
	if got := cdiDevices(); !slices.Equal(got, []string{"claim-u2-0", "claim-u3-0"}) {
		t.Fatalf("CDI devices %v", got)
	}
	if got := preparedNodes(s, nil); got.String() != "2" {
		t.Fatalf("fenced nodes %s", got)
	}
	ctx := context.Background()
	noErr(t, s.Unprepare(ctx, "u1"))
	claim := &resourcev1.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{UID: "u1", Name: "c", Namespace: "ns"},
		Status: resourcev1.ResourceClaimStatus{Allocation: &resourcev1.AllocationResult{Devices: resourcev1.DeviceAllocationResult{
			Results: []resourcev1.DeviceRequestAllocationResult{{Request: "mem", Driver: device.DriverName, Pool: "n1", Device: "dram"}}}}},
	}
	noErr(t, s.Prepare(ctx, claim))
	if info := s.GetClaimInfo("u1"); info == nil || info.BootID != "boot-2" || info.Devices[0].DeviceType != device.DeviceTypeDRAM {
		t.Fatalf("prepared again %+v", info)
	}
	if got := cdiDevices(); !slices.Equal(got, []string{"claim-u1-0", "claim-u2-0", "claim-u3-0"}) {
		t.Fatalf("CDI devices %v", got)
	}

	// the boot id of the kernel unknown
	write()
	s, err = newNodeState(devs, cdiDir, path, "n1", &DriverConfig{}, nil, "")
	noErr(t, err)
	if len(s.Prepared) != 3 || s.GetClaimInfo("u3").BootID != "" {
		t.Fatalf("prepared %v, infos %v", s.Prepared, s.preparedClaims)
	}
}
