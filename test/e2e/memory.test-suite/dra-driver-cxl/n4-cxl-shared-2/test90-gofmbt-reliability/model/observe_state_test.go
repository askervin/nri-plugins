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
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// observedParts are the parts of a VM observation that mbt-observe.py
// takes from the driver's state.
type observedParts struct {
	State      *ObsDriverState          `json:"state"`
	PoolClaims map[string]*ObsPoolClaim `json:"poolClaims"`
}

// observedLeases is the part state.leases with the fields that
// checkLeaseStore decodes.
type observedLeases struct {
	Claims map[string]struct {
		UID string `json:"uid"`
	} `json:"claims"`
	Leases map[string]struct {
		ID    string `json:"id"`
		Mode  string `json:"mode"`
		State string `json:"state"`
		Node  int    `json:"node"`
		Pod   struct {
			Name string `json:"name"`
		} `json:"pod"`
	} `json:"leases"`
}

// decodeStrictly decodes data into v, refusing unknown fields.
func decodeStrictly(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// canonical returns data re-encoded with sorted keys.
func canonical(t *testing.T, data json.RawMessage) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestObserverReadsStateJSON runs mbt-observe.py over the fixture pairs
// of testdata/observe (a state.json and the five views of it, as the
// driver's store writes them): the parts that it derives from state.json
// are those that it read from the views, and they carry exactly the
// fields of the model's observation types.
func TestObserverReadsStateJSON(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found")
	}
	dirs, err := filepath.Glob(filepath.Join("testdata", "observe", "*"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no fixture pairs in testdata/observe: %v", err)
	}
	// testdata/mbt-observe.py links the observer into the module: go
	// test caches a result only over the files of the module that the
	// test opens, and these are the files that python reads
	pairs, observer := filepath.Join("testdata", "observe-pairs.py"), filepath.Join("testdata", "mbt-observe.py")
	inputs, err := filepath.Glob(filepath.Join("testdata", "observe", "*", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range append(inputs, pairs, observer) {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	args := append([]string{"-I", "-B", pairs, observer}, dirs...)
	cmd := exec.Command(python, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("observe-pairs.py: %v\n%s", err, stderr.String())
	}
	seen := 0
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(nil, 16<<20)
	for sc.Scan() {
		var pair struct {
			Dir    string          `json:"dir"`
			Views  json.RawMessage `json:"views"`
			State  json.RawMessage `json:"state"`
			Errors []string        `json:"errors"`
		}
		if err := json.Unmarshal(sc.Bytes(), &pair); err != nil {
			t.Fatal(err)
		}
		seen++
		if len(pair.Errors) > 0 {
			t.Errorf("%s: errors %v", pair.Dir, pair.Errors)
		}
		if views, st := canonical(t, pair.Views), canonical(t, pair.State); views != st {
			t.Errorf("%s: from state.json\n%s\nfrom the views\n%s", pair.Dir, st, views)
		}
		var parts observedParts
		if err := decodeStrictly(pair.State, &parts); err != nil {
			t.Errorf("%s: the parts do not decode into the observation types: %v", pair.Dir, err)
			continue
		}
		if parts.State == nil || parts.State.Leases == nil {
			t.Errorf("%s: no state, or no leases", pair.Dir)
			continue
		}
		var leases observedLeases
		if err := decodeStrictly(parts.State.Leases, &leases); err != nil {
			t.Errorf("%s: state.leases does not decode into the fields of checkLeaseStore: %v", pair.Dir, err)
		}
		if filepath.Base(pair.Dir) == "records" {
			checkRichParts(t, &parts, &leases)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if seen != len(dirs) {
		t.Errorf("%d observations of %d fixture pairs", seen, len(dirs))
	}
}

// checkRichParts checks that the parts of the fixture of every kind of
// record have something of each part.
func checkRichParts(t *testing.T, parts *observedParts, leases *observedLeases) {
	t.Helper()
	st := parts.State
	lend, block := false, false
	for _, pc := range parts.PoolClaims {
		lend = lend || pc.Lend != nil && string(*pc.Lend) != "null"
		for _, d := range pc.Devices {
			block = block || d.BlockDevice != nil
		}
	}
	uses := 0
	if st.LocalDevices != nil {
		for i := range st.LocalDevices.Devices {
			for uid := range st.LocalDevices.Devices[i].Claims {
				uses += st.LocalDevices.Devices[i].slices(uid)
			}
		}
	}
	if len(st.Prepared) == 0 || len(st.Pool) == 0 || uses == 0 || len(leases.Claims) == 0 || len(leases.Leases) == 0 || !lend || !block {
		t.Errorf("records: prepared %v, pool %v, %d local slices, %d lease claims, %d leases, a lend %v, a block device %v",
			st.Prepared, st.Pool, uses, len(leases.Claims), len(leases.Leases), lend, block)
	}
}
