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

package leases

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/fsm"
)

// notDriven are the rows of the tables of the leases and the lease claims
// that the broker does not apply, by "<object>: <from> -> <to> on
// <triggers>", with the reason.
var notDriven = map[string]string{
	"Lease: CREATING,PENDING,LENDING,READY,RELEASING,RELEASING_BUSY,FAILED -> NONE on load": "the store's load of a " +
		"document of another boot drops the leases",
}

// TestMain counts the rows of the tables of the leases and the lease
// claims that the tests apply and, when every test ran, fails if a row
// that the broker drives was applied by no test.
func TestMain(m *testing.M) {
	rows := fsm.CountRows()
	code := m.Run()
	if f := flag.Lookup("test.run"); code == 0 && (f == nil || f.Value.String() == "") {
		code = reportRows(rows)
	}
	os.Exit(code)
}

// rowName returns the name of a row in notDriven.
func rowName(t state.TableText, r fsm.RowText) string {
	to := strings.Join(r.To, ",")
	if r.Stays {
		to = "(unchanged)"
	}
	return fmt.Sprintf("%s: %s -> %s on %s", t.Object, strings.Join(r.From, ","), to, strings.Join(r.Triggers, ","))
}

// reportRows prints the rows of the lease tables that the broker drives and
// no test applied, and returns 1 if there is one, or if notDriven names a
// row that is not in the tables.
func reportRows(rows *fsm.Rows) int {
	code := 0
	names := map[string]bool{}
	for _, t := range []state.TableText{state.LeaseTable.Text(), state.LeaseClaimTable.Text()} {
		unapplied := map[int]bool{}
		for _, i := range rows.Unapplied(t) {
			unapplied[i] = true
		}
		for i, r := range t.Rows {
			name := rowName(t, r)
			names[name] = true
			switch {
			case notDriven[name] != "":
				if testing.Verbose() {
					fmt.Printf("rows: %s: not driven by the broker: %s\n", name, notDriven[name])
				}
			case unapplied[i]:
				fmt.Printf("FAIL: %s is applied by no test\n", name)
				code = 1
			}
		}
	}
	for name := range notDriven {
		if !names[name] {
			fmt.Printf("FAIL: notDriven names %q, which is no row\n", name)
			code = 1
		}
	}
	return code
}
