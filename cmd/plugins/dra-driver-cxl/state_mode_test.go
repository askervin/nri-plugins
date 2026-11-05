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
	"os"
	"testing"
)

// TestMain keeps the state files of the tests that no store keeps in the
// files, written as the driver's file writer wrote them.
func TestMain(m *testing.M) {
	stateAutoBackend = func(string) stateBackend { return fileBackend{} }
	os.Exit(m.Run())
}

// fileBackend keeps the state files in the files, written as the driver's
// file writer wrote them.
type fileBackend struct{}

func (fileBackend) readState(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (fileBackend) writeState(path string, data []byte) error {
	return writeJSONFile(path, json.RawMessage(data))
}

func (fileBackend) stateExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
