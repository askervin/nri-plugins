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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/api"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/qemu"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/server"
)

func newTestServer(t *testing.T) (string, *qemu.Fake) {
	t.Helper()
	dir := t.TempDir()
	cfg, err := server.ParseConfig([]byte(`
stateFile: "-"
pools: [{name: default, dir: ` + filepath.Join(dir, "pool") + `, capacity: 2G}]
`))
	if err != nil {
		t.Fatal(err)
	}
	fake := qemu.NewFake(map[string]int{"cxlhb0": 0}, map[string]string{"ds0": "cxlhb0", "ds1": "cxlhb0"})
	p := qemu.ParseCmdline([]string{"qemu-system-x86_64", "-uuid", "11111111-2222-3333-4444-555555555555",
		"-drive", "file=/e2e/vm1/.vagrant/machines/vm1/qemu/x/linked-box.img", "-qmp", "unix:/e2e/vm1/qmp.sock,server,nowait"})
	p.PID = 42
	srv, err := server.New(cfg, server.Options{
		Logger:       log.New(io.Discard, "", 0),
		Discover:     func() ([]*qemu.Process, error) { return []*qemu.Process{p}, nil },
		ProcessAlive: func(int, uint64) bool { return true },
		NewMonitor:   func(string, string) qemu.Monitor { return fake },
		SocketExists: func(string) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Start()
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { hs.Close(); srv.Stop() })
	return hs.URL, fake
}

func runCLI(t *testing.T, url string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := run(context.Background(), append([]string{"--server", url}, args...), &out, &errb)
	return rc, out.String(), errb.String()
}

func TestCLI(t *testing.T) {
	url, fake := newTestServer(t)
	if rc, _, _ := runCLI(t, url); rc != exitUsage {
		t.Fatalf("no command: rc %d", rc)
	}
	if rc, _, _ := runCLI(t, url, "bogus"); rc != exitUsage {
		t.Fatalf("bogus command: rc %d", rc)
	}
	if rc, _, _ := runCLI(t, url, "attach", "x"); rc != exitUsage {
		t.Fatalf("attach without host: rc %d", rc)
	}
	for _, args := range [][]string{{"guest", "--help"}, {"guest", "-h"}, {"guest", "region", "--help"}, {"guest", "wait", "--help"}, {"--help"}} {
		if rc, out, errs := runCLI(t, url, args...); rc != exitOK || !strings.Contains(out, "Usage:") || errs != "" {
			t.Fatalf("%v: rc %d stdout %q stderr %q", args, rc, out, errs)
		}
	}
	if rc, _, errs := runCLI(t, url, "--sever", "x", "hosts"); rc != exitUsage || !strings.Contains(errs, "flag provided but not defined") {
		t.Fatalf("bad global flag: rc %d stderr %q", rc, errs)
	}
	rc, out, _ := runCLI(t, url, "hosts")
	if rc != 0 || !strings.Contains(out, "vm1") || !strings.Contains(out, "2/2") {
		t.Fatalf("hosts: %d\n%s", rc, out)
	}
	rc, out, _ = runCLI(t, url, "create", "--size", "256M", "--shared", "--name", "s0", "--label", "a=b")
	if rc != 0 || !strings.Contains(out, "s0") {
		t.Fatalf("create: %d\n%s", rc, out)
	}
	rc, out, _ = runCLI(t, url, "-o", "json", "attach", "s0", "--host", "11111111-2222-3333-4444-555555555555")
	var a api.Attachment
	if rc != 0 || json.Unmarshal([]byte(out), &a) != nil || a.State != api.AttachmentAttached || a.Host != "vm1" {
		t.Fatalf("attach: %d\n%s", rc, out)
	}
	rc, out, _ = runCLI(t, url, "devices", "s0")
	if rc != 0 || !strings.Contains(out, "state:    attached") || !strings.Contains(out, "s0@vm1") {
		t.Fatalf("devices s0: %d\n%s", rc, out)
	}
	// the guest holds the device: detach times out with exit code 3
	fake.Hold(a.QemuDeviceID)
	rc, out, errs := runCLI(t, url, "detach", "s0", "--host", "vm1", "--timeout", "50ms")
	if rc != exitConflict || !strings.Contains(errs, "did not release") || !strings.Contains(out, "failed") {
		t.Fatalf("detach held: %d\n%s\n%s", rc, out, errs)
	}
	// delete of an attached device is a conflict too
	if rc, _, _ := runCLI(t, url, "delete", "s0"); rc != exitConflict {
		t.Fatalf("delete attached: rc %d", rc)
	}
	// forget the failed attachment, delete
	if rc, _, errs := runCLI(t, url, "detach", "s0", "--host", "vm1", "--force"); rc != 0 {
		t.Fatalf("detach --force: %d %s", rc, errs)
	}
	if rc, _, errs := runCLI(t, url, "delete", "s0"); rc != 0 {
		t.Fatalf("delete: %d %s", rc, errs)
	}
	if rc, _, _ := runCLI(t, url, "devices", "s0"); rc != exitError {
		t.Fatalf("deleted device: rc %d", rc)
	}
	rc, out, _ = runCLI(t, url, "attachments")
	if rc != 0 || strings.Count(out, "\n") != 1 {
		t.Fatalf("attachments: %d\n%s", rc, out)
	}
	rc, _, errs = runCLI(t, url, "guest", "wait", "0xdeadbeef", "--timeout", "10ms")
	if rc != exitConflict {
		t.Fatalf("guest wait timeout: %d %s", rc, errs)
	}
}
