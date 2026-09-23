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
	"testing"
)

func TestGrantTable(t *testing.T) {
	checkTable(t, &GrantTable)
}

func TestBindTable(t *testing.T) {
	checkTable(t, &BindTable)
}

func TestGrantRefusals(t *testing.T) {
	for _, s := range GrantTable.States {
		for _, tr := range Triggers {
			if GrantTable.Allows(GrantReleased, s, tr) {
				t.Errorf("RELEASED -> %s allowed on %s", s, tr)
			}
			if GrantTable.Allows(GrantRequested, GrantRealising, tr) || GrantTable.Allows(GrantRequested, GrantRealised, tr) {
				t.Errorf("a grant is realised without its intent on %s", tr)
			}
		}
	}
}

func TestGrantLifeCycles(t *testing.T) {
	type st = step[GrantState]
	tb := &GrantTable
	walk(t, tb, "realised, unrestored, restored, released after a failed step", GrantRequested,
		st{GrantJournaled, TriggerPrepare}, st{GrantRealising, TriggerPrepare}, st{GrantRealised, TriggerPrepare},
		st{GrantUnrestored, TriggerRecover}, st{GrantRealised, TriggerRecover}, st{GrantUnrestored, TriggerRecover},
		st{GrantRealised, TriggerPrepare}, st{GrantReleasing, TriggerUnprepare}, st{GrantReleasing, TriggerUnprepare},
		st{GrantReleased, TriggerUnprepare})
	walk(t, tb, "a failed realisation rolled back", GrantRequested,
		st{GrantJournaled, TriggerPrepare}, st{GrantRealising, TriggerPrepare}, st{GrantReleasing, TriggerPrepare},
		st{GrantReleased, TriggerPrepare})
	walk(t, tb, "a rollback before the first kernel action", GrantRequested,
		st{GrantJournaled, TriggerPrepare}, st{GrantReleasing, TriggerPrepare}, st{GrantReleased, TriggerPrepare})
	walk(t, tb, "an unrestored grant released", GrantRealised,
		st{GrantUnrestored, TriggerRecover}, st{GrantReleasing, TriggerUnprepare})
	walk(t, tb, "a cut realisation kept at a start, released at the next", GrantRequested,
		st{GrantJournaled, TriggerPrepare}, st{GrantRealising, TriggerPrepare}, st{GrantJournaled, TriggerRecover},
		st{GrantReleased, TriggerRecover})
	walk(t, tb, "kept at a reboot, dropped by the Prepare again", GrantRealised,
		st{GrantRealised, TriggerLoad}, st{GrantReleased, TriggerPrepare})
	walk(t, tb, "dropped with its preparation at a reboot", GrantRealised,
		st{GrantReleased, TriggerLoad})
	walk(t, tb, "a rollback that keeps the region below a newer one, then the Unprepare", GrantRequested,
		st{GrantJournaled, TriggerPrepare}, st{GrantRealising, TriggerPrepare}, st{GrantReleasing, TriggerPrepare},
		st{GrantJournaled, TriggerPrepare}, st{GrantReleasing, TriggerUnprepare}, st{GrantReleased, TriggerUnprepare})
	walk(t, tb, "left REALISING by a failed release at a start, released by the Unprepare", GrantRealising,
		st{GrantReleasing, TriggerUnprepare}, st{GrantReleased, TriggerUnprepare})
}
