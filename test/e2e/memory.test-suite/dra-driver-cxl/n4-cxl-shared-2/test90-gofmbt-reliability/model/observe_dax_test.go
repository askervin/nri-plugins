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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestObserverDaxReads runs testdata/observe-dax.py: mbt-observe.py counts
// the online memory of a dax device of one range from its resource and
// size without reading its mappingN files, which a reader can hold against
// a shrink of the device by the driver, and that of several ranges from
// the mappings, with the same online bytes; its stacks of a slow
// observation have the marker that the executor looks for, the kernel
// stacks and the Python stacks.
func TestObserverDaxReads(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found")
	}
	script, observer := filepath.Join("testdata", "observe-dax.py"), filepath.Join("testdata", "mbt-observe.py")
	executor := filepath.Join("..", "mbt.source.sh")
	// go test caches a result only over the files that the test opens
	for _, path := range []string{script, observer, executor} {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.Command(python, "-I", "-B", script, observer, executor).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("observe-dax.py: %v\n%s", err, out)
	}
}
