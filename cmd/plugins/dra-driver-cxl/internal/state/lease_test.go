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

func TestLeaseTable(t *testing.T) {
	checkTable(t, &LeaseTable)
}

func TestLeaseLifeCycles(t *testing.T) {
	type st = step[LeaseState]
	tb := &LeaseTable
	walk(t, tb, "lent, announced again, released while busy", LeaseNone,
		st{LeaseCreating, TriggerRequest}, st{LeasePending, TriggerRequest}, st{LeaseLending, TriggerOnLending},
		st{LeaseLending, TriggerOnLending}, st{LeaseLending, TriggerPrepare}, st{LeaseReady, TriggerOnPrepared},
		st{LeaseReady, TriggerOnPrepared}, st{LeaseReady, TriggerOnLending}, st{LeaseReleasing, TriggerRelease},
		st{LeaseReleasing, TriggerRecover}, st{LeaseReleasingBusy, TriggerUnprepare},
		st{LeaseReleasing, TriggerReconcile}, st{LeaseNone, TriggerReconcile})
	walk(t, tb, "the companion creation failed, released in place", LeaseNone,
		st{LeaseCreating, TriggerRequest}, st{LeaseFailed, TriggerRequest}, st{LeaseFailed, TriggerRelease},
		st{LeaseNone, TriggerReconcile})
	walk(t, tb, "a lend that failed, the companion unprepared, released in place", LeaseNone,
		st{LeaseCreating, TriggerRequest}, st{LeaseLending, TriggerOnLending}, st{LeaseReady, TriggerOnPrepared},
		st{LeaseFailed, TriggerOnLendFailed}, st{LeaseFailed, TriggerOnReleasing}, st{LeaseFailed, TriggerRelease},
		st{LeaseNone, TriggerRelease})
	walk(t, tb, "the request's wait ended", LeaseNone,
		st{LeaseCreating, TriggerRequest}, st{LeasePending, TriggerRequest}, st{LeaseReleasing, TriggerRequest},
		st{LeaseNone, TriggerRelease})
	walk(t, tb, "a companion whose bind is not restored at a start", LeaseReady,
		st{LeaseFailed, TriggerRecover}, st{LeaseFailed, TriggerReconcile}, st{LeaseNone, TriggerReconcile})
	walk(t, tb, "left over in CREATING", LeaseCreating, st{LeaseReleasing, TriggerReconcile})
	walk(t, tb, "dropped at a reboot", LeaseReady, st{LeaseNone, TriggerLoad})
}
