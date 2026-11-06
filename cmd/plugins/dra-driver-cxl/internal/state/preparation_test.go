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

func TestPreparationTable(t *testing.T) {
	checkTable(t, &PreparationTable)
}

func TestPreparationLifeCycles(t *testing.T) {
	type st = step[PreparationState]
	tb := &PreparationTable
	walk(t, tb, "prepared, prepared again, an Unprepare that fails once and is cut", PreparationUnknown,
		st{PreparationPreparing, TriggerPrepare}, st{PreparationPrepared, TriggerPrepare},
		st{PreparationPrepared, TriggerPrepare}, st{PreparationUnpreparing, TriggerUnprepare},
		st{PreparationUnpreparing, TriggerUnprepare}, st{PreparationUnpreparing, TriggerRecover},
		st{PreparationUnknown, TriggerUnprepare})
	walk(t, tb, "a failed Prepare whose rollback released everything", PreparationUnknown,
		st{PreparationPreparing, TriggerPrepare}, st{PreparationUnknown, TriggerPrepare})
	walk(t, tb, "a cut Prepare kept by the recovery, retried, kept again, refused again, unprepared", PreparationUnknown,
		st{PreparationPreparing, TriggerPrepare}, st{PreparationPreparing, TriggerRecover},
		st{PreparationKept, TriggerRecover}, st{PreparationPreparing, TriggerPrepare},
		st{PreparationPreparing, TriggerPrepare}, st{PreparationKept, TriggerPrepare},
		st{PreparationKept, TriggerPrepare}, st{PreparationUnknown, TriggerUnprepare})
	walk(t, tb, "a cut Prepare kept by the recovery, released in part and then in all by later starts", PreparationUnknown,
		st{PreparationPreparing, TriggerPrepare}, st{PreparationKept, TriggerRecover},
		st{PreparationKept, TriggerRecover}, st{PreparationUnknown, TriggerRecover})
	walk(t, tb, "unrestored at a start, restored at the next and by a Prepare again", PreparationPrepared,
		st{PreparationUnrestored, TriggerRecover}, st{PreparationUnrestored, TriggerRecover},
		st{PreparationUnrestored, TriggerPrepare}, st{PreparationPrepared, TriggerRecover},
		st{PreparationUnrestored, TriggerRecover}, st{PreparationPrepared, TriggerPrepare})
	walk(t, tb, "stale after a reboot, still stale after the next, unprepared", PreparationPrepared,
		st{PreparationStale, TriggerLoad}, st{PreparationStale, TriggerLoad},
		st{PreparationUnknown, TriggerUnprepare})
	walk(t, tb, "a cut Prepare of another boot, prepared anew", PreparationPreparing,
		st{PreparationStale, TriggerLoad}, st{PreparationPreparing, TriggerPrepare})
	walk(t, tb, "a preparation of another boot of a driver that drops them", PreparationPrepared,
		st{PreparationUnknown, TriggerLoad})
}

func TestPreparationPrepared(t *testing.T) {
	for _, s := range PreparationTable.States {
		p := Preparation{State: s}
		want := s == PreparationPrepared || s == PreparationUnrestored || s == PreparationUnpreparing
		if p.Prepared() != want {
			t.Errorf("%s: Prepared() %v", s, p.Prepared())
		}
	}
}
