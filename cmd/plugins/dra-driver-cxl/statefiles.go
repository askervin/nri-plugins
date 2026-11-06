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
	"encoding/json"
	"fmt"
	"io/fs"
	"sync"
)

// stateBackend keeps the content of state files somewhere else than in the
// files: the driver keeps them in its store (stateStore).
type stateBackend interface {
	// readState returns the content of the state file path, an error
	// that os.IsNotExist takes for a file that does not exist.
	readState(path string) ([]byte, error)
	// writeState replaces the content of the state file path with data.
	writeState(path string, data []byte) error
}

// stateFiles are the state files whose content a backend keeps, by path.
var stateFiles = struct {
	sync.Mutex
	backends map[string]stateBackend
}{backends: map[string]stateBackend{}}

// stateAutoBackend returns the backend of a state file that none is
// registered for: the tests' stores, or the files themselves. In the
// driver it is nil: a state file that the store does not keep is neither
// read nor written.
var stateAutoBackend func(path string) stateBackend

// registerStateFiles makes the backend b keep the state files paths and
// returns the function that ends it.
func registerStateFiles(b stateBackend, paths ...string) func() {
	stateFiles.Lock()
	defer stateFiles.Unlock()
	for _, p := range paths {
		stateFiles.backends[p] = b
	}
	return func() {
		stateFiles.Lock()
		defer stateFiles.Unlock()
		for _, p := range paths {
			if stateFiles.backends[p] == b {
				delete(stateFiles.backends, p)
			}
		}
	}
}

// stateBackendOf returns the backend of the state file path, nil for none.
func stateBackendOf(path string) stateBackend {
	stateFiles.Lock()
	b := stateFiles.backends[path]
	stateFiles.Unlock()
	if b == nil && stateAutoBackend != nil {
		b = stateAutoBackend(path)
	}
	return b
}

// notKept returns the error of a state file that no backend keeps.
func notKept(path string) error {
	return fmt.Errorf("state file %s is not kept by the state store", path)
}

// readStateFile returns the content of the state file path from its
// backend.
func readStateFile(path string) ([]byte, error) {
	b := stateBackendOf(path)
	if b == nil {
		return nil, notKept(path)
	}
	return b.readState(path)
}

// writeStateFile replaces the content of the state file path with v in
// indented JSON through its backend.
func writeStateFile(path string, v any) error {
	b := stateBackendOf(path)
	if b == nil {
		return fmt.Errorf("writing %s: %w", path, notKept(path))
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	return b.writeState(path, data)
}

// notExist returns the error of reading the state file path that does not
// exist.
func notExist(path string) error {
	return &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
}
