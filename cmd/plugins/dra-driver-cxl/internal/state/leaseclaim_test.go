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

func TestLeaseClaimTable(t *testing.T) {
	checkTable(t, &LeaseClaimTable)
}

func TestLeaseClaimLifeCycle(t *testing.T) {
	type st = step[LeaseClaimState]
	walk(t, &LeaseClaimTable, "opened, listened again, closed after a cut close", LeaseClaimNone,
		st{LeaseClaimOpen, TriggerPrepare}, st{LeaseClaimOpen, TriggerRequest}, st{LeaseClaimOpen, TriggerRecover},
		st{LeaseClaimOpenNoListener, TriggerRecover}, st{LeaseClaimOpenNoListener, TriggerRecover},
		st{LeaseClaimOpen, TriggerRecover}, st{LeaseClaimOpenNoListener, TriggerRecover},
		st{LeaseClaimOpen, TriggerPrepare}, st{LeaseClaimClosing, TriggerUnprepare}, st{LeaseClaimClosing, TriggerRecover},
		st{LeaseClaimClosing, TriggerUnprepare}, st{LeaseClaimClosing, TriggerUnprepare},
		st{LeaseClaimClosed, TriggerUnprepare}, st{LeaseClaimRemoving, TriggerRelease},
		st{LeaseClaimNone, TriggerRelease})
	walk(t, &LeaseClaimTable, "a close that timed out, opened again by a Prepare", LeaseClaimNone,
		st{LeaseClaimOpen, TriggerPrepare}, st{LeaseClaimClosing, TriggerUnprepare}, st{LeaseClaimOpen, TriggerPrepare},
		st{LeaseClaimClosing, TriggerUnprepare}, st{LeaseClaimClosing, TriggerRecover}, st{LeaseClaimOpen, TriggerPrepare})
}
