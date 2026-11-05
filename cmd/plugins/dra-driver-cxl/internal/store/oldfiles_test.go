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

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFiles writes the files of contents by name into dir.
func writeFiles(t *testing.T, dir string, contents map[string]string) {
	t.Helper()
	for name, content := range contents {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOldFilesWithRecords(t *testing.T) {
	local, pool := t.TempDir(), t.TempDir()
	writeFiles(t, local, map[string]string{
		"preparedClaims.json":     `{}`,
		"preparedClaimsInfo.json": `{"uid-1": {"claimName": "ns/c", "devices": []}}`,
		"localDevices.json":       `{"bootID": "b", "devices": []}`,
		"leases.json":             `{"claims": {}, "leases": {}, "bootID": "b"}`,
		"steeredContainers.json":  `{}`,
		"poolSerials.json":        `{"serials": [], "pools": {"cxl-pool.nri.io/p": "2026-01-01T00:00:00Z"}}`,
	})
	writeFiles(t, pool, map[string]string{
		"preparingPoolClaims.json": `{"uid-2": {"claimName": "ns/p"}}`,
		"preparedPoolClaims.json":  `{"uid-3": {"claimName": "ns/q", "viewOf": "state.json"}}`,
	})
	got, err := OldFiles(local, pool)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(local, "preparedClaimsInfo.json"),
		filepath.Join(pool, "preparingPoolClaims.json"),
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("old files %v, want %v", got, want)
	}
}

func TestProbeResultsAreNoOldFile(t *testing.T) {
	local := t.TempDir()
	probes := `{"c100e2e1": {"usableSize": 268435456, "result": "aliasing above 256 MiB", "region": "region0", ` +
		`"size": 1073741824, "time": "2026-11-05T12:00:00Z"}}`
	writeFiles(t, local, map[string]string{"localProbes.json": probes})
	moved, err := HandleOldFiles(local, "", true, false)
	if err != nil || len(moved) != 0 {
		t.Errorf("HandleOldFiles with regions: moved %v, %v", moved, err)
	}
	s := open(t, local, nil, func(o *Options) { o.RegionsExist = true })
	closeStore(t, s)
	data, err := os.ReadFile(filepath.Join(local, "localProbes.json"))
	if err != nil || string(data) != probes {
		t.Errorf("localProbes.json after a first start: %q, %v", data, err)
	}
}

func TestOldFilesRefusedWithRegions(t *testing.T) {
	local := t.TempDir()
	writeFiles(t, local, map[string]string{"localDevices.json": `{"bootID": "b", "devices": [{"serial": 1}]}`})
	_, err := HandleOldFiles(local, "", true, false)
	var oe *OldStateError
	if !errors.As(err, &oe) {
		t.Fatalf("HandleOldFiles: %v, want an *OldStateError", err)
	}
	if !strings.HasPrefix(err.Error(), "old state files found; drain the node's claims or start with --discard-old-state") {
		t.Errorf("refusal %q", err)
	}
	if _, err := os.Stat(filepath.Join(local, "localDevices.json")); err != nil {
		t.Errorf("a refusal moved the file: %v", err)
	}
	_, err = Open(context.Background(), Options{Dir: local, RegionsExist: true})
	if !errors.As(err, &oe) {
		t.Errorf("Open: %v, want an *OldStateError", err)
	}
	if _, err := os.Stat(filepath.Join(local, FileName)); err == nil {
		t.Errorf("a refused Open created %s", FileName)
	}
}

func TestOldFilesMovedAside(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		regionsExist, discard bool
	}{
		{"no regions", false, false},
		{"discarded", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local := t.TempDir()
			writeFiles(t, local, map[string]string{"leases.json": `{"claims": {"u": {"uid": "u"}}, "leases": {}}`})
			moved, err := HandleOldFiles(local, "", tc.regionsExist, tc.discard)
			if err != nil || len(moved) != 1 {
				t.Fatalf("moved %v, %v", moved, err)
			}
			if _, err := os.Stat(filepath.Join(local, "leases.json"+OldSuffix)); err != nil {
				t.Errorf("not moved aside: %v", err)
			}
			if _, err := os.Stat(filepath.Join(local, "leases.json")); err == nil {
				t.Errorf("the old file is still there")
			}
		})
	}
}

func TestOldFilesIgnoredWithADocument(t *testing.T) {
	local := t.TempDir()
	writeFiles(t, local, map[string]string{
		FileName:              `{"schema": 1, "generation": 1}`,
		"preparedClaims.json": `{"uid": {"Err": null, "Devices": []}}`,
	})
	moved, err := HandleOldFiles(local, "", true, false)
	if err != nil || len(moved) != 0 {
		t.Errorf("moved %v, %v with a document", moved, err)
	}
}

func TestOpenMovesOldFilesAside(t *testing.T) {
	local := t.TempDir()
	writeFiles(t, local, map[string]string{"steeredContainers.json": `{"c1": "/cg/c1"}`})
	s := open(t, local, nil, nil)
	closeStore(t, s)
	if _, err := os.Stat(filepath.Join(local, "steeredContainers.json"+OldSuffix)); err != nil {
		t.Errorf("not moved aside: %v", err)
	}
}
