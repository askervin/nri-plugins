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
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state/statetest"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

var update = flag.Bool("update", false, "write the golden file of the results")

// TestResultsGolden compares the results of every preparation of the test
// records, by driver and claim UID, with testdata/results.json.golden (go
// test -update writes it): the PrepareResult, and the devices of a claim
// of cxl.nri.io, the devices and the lend of a pool claim.
func TestResultsGolden(t *testing.T) {
	doc := fixture(statetest.BootID)
	opts := ResultOptions{PoolDriver: statetest.PoolDriver}
	out := map[string]map[string]json.RawMessage{}
	for i := range doc.Preparations {
		p := &doc.Preparations[i]
		r := map[string]json.RawMessage{}
		kind := device.CDIKind
		var err error
		if p.Driver == statetest.PoolDriver {
			kind = device.PoolCDIKind
			if r["devices"], err = PoolDevicesContent(doc, p, opts); err != nil {
				t.Fatal(err)
			}
			if r["lend"], err = PoolLendContent(doc, p); err != nil {
				t.Fatal(err)
			}
		} else if r["info"], err = ClaimInfoContent(doc, p, opts); err != nil {
			t.Fatal(err)
		}
		if r["result"], err = json.Marshal(PrepareResult(p, kind)); err != nil {
			t.Fatal(err)
		}
		out[p.Driver+"/"+p.UID] = r
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	golden := filepath.Join("testdata", "results.json.golden")
	if *update {
		if err := os.WriteFile(golden, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Errorf("the results differ from %s:\n%s", golden, data)
	}
}
