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
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/leases"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
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
		LeaseLimits:         leases.Limits{Connections: 64, Idle: 10 * time.Minute, LeasesPerPod: 64},
		Store:               store.Flags{},
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
		"LEASE_MAX_CONNECTIONS": "8",
		"LEASE_IDLE_TIMEOUT":    "1h",
		"LEASE_MAX_PER_POD":     "4",
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
		LeaseLimits:         leases.Limits{Connections: 8, Idle: time.Hour, LeasesPerPod: 4},
		Store:               store.Flags{},
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

func TestParseFlagsStore(t *testing.T) {
	f, err := testParseFlags([]string{"--compat-views=false", "--discard-old-state", "--new-state"}, map[string]string{"NODE_NAME": "n1"})
	if err != nil {
		t.Fatal(err)
	}
	if want := (store.Flags{DiscardOldState: true, NewState: true}); f.Store != want {
		t.Fatalf("store flags %+v, expected %+v", f.Store, want)
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

// The claims of cxl.nri.io prepared in another boot are not prepared at
// the start: their records PREPARED_STALE, no result for kubelet, no CDI device,
// no NUMA node to fence, no command; their Unprepare releases nothing and
// removes the record, their Prepare again prepares them anew in this boot.
func TestPreparedClaimsOtherBoot(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	e.mustPrepare(localClaim("u1", localBlockSize))
	e.mustPrepare(localClaim("u2", localBlockSize, localDaxConfig))
	if got := dra.NumaNodes(e.records(), device.DriverName); len(got) == 0 {
		t.Fatal("no NUMA node of the numa slice")
	}
	old := e.k.BootID()
	before := e.k.Commands()
	e.reboot()
	if got := e.k.CommandsSince(before); got != "" {
		t.Fatalf("commands at the start:\n%s", got)
	}
	for _, uid := range []string{"u1", "u2"} {
		if p := e.preparation(uid); p == nil || p.State != state.PreparationStale || e.s.ClaimInfo(uid) != nil {
			t.Fatalf("claim %s of another boot: %+v", uid, p)
		}
	}
	if got := e.prepared(); len(got) != 0 {
		t.Fatalf("kubelet gets the claims of another boot: %+v", got)
	}
	if spec := e.cdiSpec(); spec != nil && len(spec.Devices) > 0 {
		t.Fatalf("CDI devices of another boot %+v", spec.Devices)
	}
	if got := dra.NumaNodes(e.records(), device.DriverName); len(got) != 0 {
		t.Fatalf("fenced nodes %v", got)
	}
	if e.inUse() {
		t.Fatal("the memdev is in use")
	}
	before = e.k.Commands()
	e.mustUnprepare("u1")
	if got := e.k.CommandsSince(before); got != "" || e.preparation("u1") != nil {
		t.Fatalf("the Unprepare of a claim of another boot: %+v\n%s", e.preparation("u1"), got)
	}
	e.mustPrepare(localClaim("u1", localBlockSize))
	if p := e.preparation("u2"); p == nil || p.State != state.PreparationStale {
		t.Fatalf("claim u2 of another boot %+v", p)
	}
	e.mustPrepare(localClaim("u2", localBlockSize, localDaxConfig))
	if info := e.s.ClaimInfo("u1"); info == nil || info.BootID != e.k.BootID() || info.BootID == old {
		t.Fatalf("prepared again %+v", info)
	}
	if spec := e.cdiSpec(); spec == nil || len(spec.Devices) != 2 || spec.Devices[0].Name != "claim-u1-0" {
		t.Fatalf("CDI spec %+v", spec)
	}
}
