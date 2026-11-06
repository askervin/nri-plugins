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
	"slices"
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
	moved, err := HandleOldFiles(local, "", anyRegion, false)
	if err != nil || len(moved) != 0 {
		t.Errorf("HandleOldFiles with regions: moved %v, %v", moved, err)
	}
	s := open(t, local, nil, func(o *Options) { o.RegionExists = anyRegion })
	closeStore(t, s)
	data, err := os.ReadFile(filepath.Join(local, "localProbes.json"))
	if err != nil || string(data) != probes {
		t.Errorf("localProbes.json after a first start: %q, %v", data, err)
	}
}

// anyRegion tells that every region exists.
func anyRegion(string) bool { return true }

func TestOldFilesRefusedWithTheirRegions(t *testing.T) {
	local, pool := t.TempDir(), t.TempDir()
	writeFiles(t, local, map[string]string{
		"localDevices.json": `{"bootID": "b", "devices": [{"serial": 1, "region": "region0", "creating": "", "claims": {}}]}`,
		"preparedClaimsInfo.json": `{"u1": {"claimName": "n/c", "devices": [` +
			`{"deviceType": "memdev", "sysfsPath": "/sys/bus/cxl/devices/region1"}, {"deviceType": "region", "region": "region9"}]}}`,
	})
	writeFiles(t, pool, map[string]string{
		"preparingPoolClaims.json": `{"u2": {"claimName": "n/p", "regions": [{"serial": 2, "region": "region2"}]}}`,
	})
	exists := func(name string) bool { return name == "region1" || name == "region2" || name == "region9" }
	_, err := HandleOldFiles(local, pool, exists, false)
	var oe *OldStateError
	if !errors.As(err, &oe) {
		t.Fatalf("HandleOldFiles: %v, want an *OldStateError", err)
	}
	if !strings.HasPrefix(err.Error(), "old state files found; drain the node's claims or start with --discard-old-state") {
		t.Errorf("refusal %q", err)
	}
	slices.Sort(oe.Regions)
	if !slices.Equal(oe.Regions, []string{"region1", "region2"}) {
		t.Errorf("refused for regions %v, want region1 and region2 (region9 is a region device)", oe.Regions)
	}
	if _, err := os.Stat(filepath.Join(local, "localDevices.json")); err != nil {
		t.Errorf("a refusal moved the file: %v", err)
	}
	_, err = Open(context.Background(), Options{Dir: local, PoolDir: pool, RegionExists: exists})
	if !errors.As(err, &oe) {
		t.Errorf("Open: %v, want an *OldStateError", err)
	}
	if _, err := os.Stat(filepath.Join(local, FileName)); err == nil {
		t.Errorf("a refused Open created %s", FileName)
	}
}

func TestOldFilesWithoutExistingRegionsMovedAside(t *testing.T) {
	local := t.TempDir()
	writeFiles(t, local, map[string]string{"localDevices.json": `{"bootID": "b", "devices": [{"serial": 1, "region": "region0", "claims": {}}]}`})
	moved, err := HandleOldFiles(local, "", func(string) bool { return false }, false)
	if err != nil || len(moved) != 1 {
		t.Errorf("moved %v, %v: a region that is gone does not refuse", moved, err)
	}
}

// A localDevices.json of the oldest shape, a list of devices without a
// boot id, is an old state file as the object shape is: refused while a
// region that it names exists, moved aside when none does. An empty list
// holds no records.
func TestOldFilesListShaped(t *testing.T) {
	const list = `[{"serial":3238060769,"serialHex":"c100e2e1","memdev":"mem0","region":"region0","node":2,` +
		`"claims":{"u1":[{"request":"mem","region":"region0","mode":"numa","size":2097152,"dax":"dax0.1"}]}}]`
	t.Run("region exists", func(t *testing.T) {
		local := t.TempDir()
		writeFiles(t, local, map[string]string{"localDevices.json": list})
		exists := func(name string) bool { return name == "region0" }
		_, err := HandleOldFiles(local, "", exists, false)
		var oe *OldStateError
		if !errors.As(err, &oe) {
			t.Fatalf("HandleOldFiles: %v, want an *OldStateError", err)
		}
		if want := []string{filepath.Join(local, "localDevices.json")}; !slices.Equal(oe.Files, want) || !slices.Equal(oe.Regions, []string{"region0"}) {
			t.Errorf("refused for files %v regions %v, want %v and region0", oe.Files, oe.Regions, want)
		}
		if _, err := os.Stat(filepath.Join(local, "localDevices.json")); err != nil {
			t.Errorf("a refusal moved the file: %v", err)
		}
		_, err = Open(context.Background(), Options{Dir: local, RegionExists: exists})
		if !errors.As(err, &oe) {
			t.Errorf("Open: %v, want an *OldStateError", err)
		}
	})
	t.Run("region gone", func(t *testing.T) {
		local := t.TempDir()
		writeFiles(t, local, map[string]string{"localDevices.json": list})
		moved, err := HandleOldFiles(local, "", func(string) bool { return false }, false)
		if want := []string{filepath.Join(local, "localDevices.json")}; err != nil || !slices.Equal(moved, want) {
			t.Fatalf("moved %v, %v, want %v", moved, err, want)
		}
		if _, err := os.Stat(filepath.Join(local, "localDevices.json"+OldSuffix)); err != nil {
			t.Errorf("not moved aside: %v", err)
		}
		if _, err := os.Stat(filepath.Join(local, "localDevices.json")); err == nil {
			t.Errorf("the old file is still there")
		}
	})
	t.Run("empty", func(t *testing.T) {
		local := t.TempDir()
		writeFiles(t, local, map[string]string{"localDevices.json": `[]`})
		got, err := OldFiles(local, "")
		if err != nil || len(got) != 0 {
			t.Errorf("old files %v, %v of an empty list", got, err)
		}
	})
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
			var exists func(string) bool
			if tc.regionsExist {
				exists = anyRegion
			}
			moved, err := HandleOldFiles(local, "", exists, tc.discard)
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
	moved, err := HandleOldFiles(local, "", anyRegion, false)
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
