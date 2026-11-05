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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// OldSuffix is the suffix of an old state file moved aside.
const OldSuffix = ".old"

// localOldFiles and poolOldFiles are the state files whose records the
// document holds, in the plugin data directories of cxl.nri.io and of the
// pool driver. localProbes.json is not one: the address line probe keeps
// its results there.
var (
	localOldFiles = []string{
		"preparedClaims.json", "preparedClaimsInfo.json", "localDevices.json", "poolSerials.json",
		"leases.json", "steeredContainers.json",
	}
	poolOldFiles = []string{"preparedPoolClaims.json", "preparingPoolClaims.json"}
)

// OldStateError is the refusal to start with old state files whose records
// name CXL regions that exist.
type OldStateError struct {
	Files   []string
	Regions []string
}

// Error returns the refusal, the files and the regions.
func (e *OldStateError) Error() string {
	return "old state files found; drain the node's claims or start with --discard-old-state: " +
		strings.Join(e.Files, ", ") + " (regions " + strings.Join(e.Regions, ", ") + ")"
}

// OldFiles returns the old state files in the plugin data directories
// localDir and poolDir ("": none) that hold records: files that are not
// views of the document and not empty.
func OldFiles(localDir, poolDir string) ([]string, error) {
	var paths []string
	for _, name := range localOldFiles {
		paths = append(paths, filepath.Join(localDir, name))
	}
	if poolDir != "" {
		for _, name := range poolOldFiles {
			paths = append(paths, filepath.Join(poolDir, name))
		}
	}
	var out []string
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if holdsRecords(data) {
			out = append(out, path)
		}
	}
	return out, nil
}

// HandleOldFiles moves the old state files of localDir and poolDir aside
// (OldSuffix) when no document exists in localDir, and returns them. When
// a record of one of them names a CXL region that exists (regionExists,
// nil: none exists) it refuses with an *OldStateError instead, unless
// discard.
func HandleOldFiles(localDir, poolDir string, regionExists func(name string) bool, discard bool) ([]string, error) {
	for _, name := range []string{FileName, PrevName} {
		if _, err := os.Lstat(filepath.Join(localDir, name)); err == nil {
			return nil, nil
		}
	}
	files, err := OldFiles(localDir, poolDir)
	if err != nil || len(files) == 0 {
		return nil, err
	}
	if !discard && regionExists != nil {
		var existing []string
		for _, f := range files {
			for _, r := range oldRegions(f) {
				if regionExists(r) && !slices.Contains(existing, r) {
					existing = append(existing, r)
				}
			}
		}
		if len(existing) > 0 {
			return nil, &OldStateError{Files: files, Regions: existing}
		}
	}
	for _, f := range files {
		if err := os.Rename(f, f+OldSuffix); err != nil {
			return nil, fmt.Errorf("moving %s aside: %w", f, err)
		}
	}
	return files, nil
}

// oldRegions returns the CXL regions of the driver that the records of an
// old state file name: the regions and the regions being created of
// localDevices.json and of the pool's files, the regions of the local
// memdevs of preparedClaimsInfo.json. Its region devices are regions that
// the driver did not create.
func oldRegions(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var v any
	if json.Unmarshal(data, &v) != nil {
		return nil
	}
	var out []string
	add := func(name string) {
		if name != "" && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	switch filepath.Base(path) {
	case "preparedClaimsInfo.json":
		claims, _ := v.(map[string]any)
		for _, c := range claims {
			info, _ := c.(map[string]any)
			devs, _ := info["devices"].([]any)
			for _, d := range devs {
				if dev, _ := d.(map[string]any); dev["deviceType"] == "memdev" {
					if p, _ := dev["sysfsPath"].(string); p != "" {
						add(filepath.Base(p))
					}
				}
			}
		}
	case "localDevices.json", "preparedPoolClaims.json", "preparingPoolClaims.json":
		walkRegions(v, add)
	}
	return out
}

// walkRegions calls add with every string value of a key "region" or
// "creating" in v.
func walkRegions(v any, add func(string)) {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if s, ok := e.(string); ok && (k == "region" || k == "creating") {
				add(s)
				continue
			}
			walkRegions(e, add)
		}
	case []any:
		for _, e := range t {
			walkRegions(e, add)
		}
	}
}

// holdsRecords tells whether the content of an old state file has records:
// it is not empty, not a view of the document and not an object of empty
// values.
func holdsRecords(data []byte) bool {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return true
	}
	switch t := v.(type) {
	case nil:
		return false
	case []any:
		return len(t) > 0
	case map[string]any:
		if t[viewKey] == viewOf {
			return false
		}
		for k, e := range t {
			if m, ok := e.(map[string]any); ok && m[viewKey] == viewOf {
				continue
			}
			if k == "bootID" || k == "pools" || isEmpty(e) {
				continue
			}
			return true
		}
		return false
	}
	return true
}

// isEmpty tells whether a JSON value has nothing in it.
func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}
