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

package state

import (
	"flag"
	"fmt"
	"os"
	"sync"
	"testing"
)

// coveredTables are the tables whose every row a life-cycle test must
// apply; the rows of the other tables that no test applied are listed with
// -v.
var coveredTables = map[string]bool{
	"Preparation.State": true,
	"Grant.State":       true,
	"Lease.State":       true,
	"LeaseClaim.State":  true,
}

var (
	appliedMu sync.Mutex
	applied   = map[string]map[int]bool{}
)

// TestMain counts the rows that the tests apply and, when every test ran,
// fails if a row of coveredTables was applied by no test.
func TestMain(m *testing.M) {
	rowApplied = func(object, field string, row int) {
		appliedMu.Lock()
		defer appliedMu.Unlock()
		name := object + "." + field
		if applied[name] == nil {
			applied[name] = map[int]bool{}
		}
		applied[name][row] = true
	}
	code := m.Run()
	if f := flag.Lookup("test.run"); code == 0 && (f == nil || f.Value.String() == "") {
		code = reportRows()
	}
	os.Exit(code)
}

// reportRows prints the rows that no test applied and returns 1 if one of
// them is of a table of coveredTables.
func reportRows() int {
	code := 0
	for _, o := range Catalogue() {
		for _, tt := range o.Tables {
			name := tt.Object + "." + tt.Field
			for i, r := range tt.Rows {
				if applied[name][i] {
					continue
				}
				switch {
				case coveredTables[name]:
					fmt.Printf("FAIL: %s row %d (%v -> %v on %v) is applied by no life-cycle test\n", name, i, r.From, r.To, r.Triggers)
					code = 1
				case testing.Verbose():
					fmt.Printf("rows: %s row %d (%v -> %v on %v) is applied by no test\n", name, i, r.From, r.To, r.Triggers)
				}
			}
		}
	}
	return code
}
