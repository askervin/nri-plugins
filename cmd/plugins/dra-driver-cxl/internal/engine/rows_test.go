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

package engine

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/fsm"
)

// engineTables are the tables of the records that the engine drives.
var engineTables = []fsm.TableText{
	state.GrantTable.Text(),
	state.BindTable.Text(),
	state.MemdevTable.Text(),
	state.MemdevBusyTable.Text(),
	state.RegionTable.Text(),
	state.RegionSetUpTable.Text(),
	state.DaxDeviceTable.Text(),
	state.MountTable.Text(),
}

// notDriven are the rows of engineTables that the engine does not apply,
// by "<table> <from> -> <to> on <triggers>", with the reason.
var notDriven = map[string]string{
	"Grant.State JOURNALED,REALISING,REALISED,REALISED_UNRESTORED,RELEASING -> (unchanged) on load": "the store's load " +
		"of a document of another boot",
	"Grant.State JOURNALED,REALISING,REALISED,REALISED_UNRESTORED,RELEASING -> RELEASED on load": "the store's load of " +
		"a document of another boot",
	"Memdev.State ACTIVE,IDLE_KEPT,GONE -> UNUSED on load": "the store's load of a document of another boot",
	"Region.State NOTED,CREATING,OWNED,KEPT,HOLLOW_OWNED,FOREIGN -> NONE on load": "the store's load of a document of " +
		"another boot",
	"Region.State NONE -> FOREIGN on a-observe,a-recover": "the records of foreign regions are the publisher's; the " +
		"engine refuses a memdev with a region that no record names",
	"Region.State FOREIGN -> NONE on a-observe,a-recover": "the records of foreign regions are the publisher's",
	"Memdev.State IDLE_KEPT -> UNUSED on a-recover,a-prepare": "the release of idle local memdevs (shared not " +
		"configured any more, idle persistent) at the start and the next Prepare: the local driver's",
	"Bind.State ABSENT,BOUND -> FOREIGN on a-recover": "the recovery of lease binds records foreign binds with the " +
		"leases; the engine logs them and leaves them",
	"Bind.State ABSENT,BOUND -> OTHER_CLAIM on a-recover": "the recovery of lease binds records the binds of other " +
		"claims with the leases",
	"Mount.State MOUNTED_RO,MOUNTED_RW -> STALE on a-unprepare,a-prepare,a-recover": "a busy node mount fails the " +
		"release; a stale node mount retried later is a change of behaviour still to come",
	"Mount.State STALE -> ABSENT on a-unprepare,a-prepare,a-recover,a-reconcile": "see the row to STALE",
}

// TestMain counts the rows that the tests apply and, when every test ran,
// fails if a row of engineTables that the engine drives was applied by no
// test; with -v it lists the rows that the engine does not drive.
func TestMain(m *testing.M) {
	rows := fsm.CountRows()
	code := m.Run()
	if f := flag.Lookup("test.run"); code == 0 && (f == nil || f.Value.String() == "") {
		code = reportRows(rows)
	}
	os.Exit(code)
}

// rowName returns the name of a row in notDriven.
func rowName(t fsm.TableText, r fsm.RowText) string {
	to := strings.Join(r.To, ",")
	if r.Stays {
		to = "(unchanged)"
	}
	return fmt.Sprintf("%s.%s %s -> %s on %s", t.Object, t.Field, strings.Join(r.From, ","), to, strings.Join(r.Triggers, ","))
}

// reportRows prints the rows of engineTables that no test applied and
// returns 1 if one of them is not in notDriven.
func reportRows(rows *fsm.Rows) int {
	code := 0
	for _, t := range engineTables {
		for _, i := range rows.Unapplied(t) {
			name := rowName(t, t.Rows[i])
			why, ok := notDriven[name]
			switch {
			case !ok:
				fmt.Printf("FAIL: row %d %s is applied by no test of the engine\n", i, name)
				code = 1
			case testing.Verbose():
				fmt.Printf("rows: %s: not driven by the engine: %s\n", name, why)
			}
		}
	}
	return code
}
