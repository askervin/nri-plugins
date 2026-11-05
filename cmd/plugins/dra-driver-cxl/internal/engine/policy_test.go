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
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
)

// The values of the release policy: every cell of the matrix, with and
// without a region of another memdev above.
func TestPolicy(t *testing.T) {
	above := []string{"region9"}
	for _, c := range []struct {
		kind                    Kind
		unprepare, rollback     Decision
		recovery, recoveryAbove Decision
		idle                    Decision
	}{
		{KindLocalSliced, Destroy, InOrder, InOrder, InOrder, Destroy},
		{KindLocalShared, Keep, InOrder, Keep, Keep, Keep},
		{KindLocalUnshared, Destroy, InOrder, Keep, Keep, Destroy},
		{KindLocalPersistent, InOrder, InOrder, Keep, Keep, InOrder},
		{KindPoolExclusive, Destroy, Destroy, Destroy, Keep, Destroy},
		{KindPoolShared, Destroy, Destroy, Destroy, Keep, Destroy},
		{KindPoolPersistent, Destroy, Destroy, Destroy, Keep, Destroy},
	} {
		for _, cell := range []struct {
			release Release
			above   []string
			want    Decision
		}{
			{ReleaseUnprepare, nil, c.unprepare},
			{ReleaseUnprepare, above, c.unprepare},
			{ReleaseRollback, nil, c.rollback},
			{ReleaseRollback, above, c.rollback},
			{ReleaseRecovery, nil, c.recovery},
			{ReleaseRecovery, above, c.recoveryAbove},
			{ReleaseIdle, nil, c.idle},
			{ReleaseIdle, above, c.idle},
		} {
			if got := Policy(cell.release, c.kind, cell.above); got != cell.want {
				t.Errorf("Policy(%s, %s, %v) = %s, want %s", cell.release, c.kind, cell.above, got, cell.want)
			}
		}
	}
	if got := Policy(ReleaseUnprepare, Kind("dcd"), nil); got != Keep {
		t.Errorf("an unknown kind: %s", got)
	}
}

// The row of the policy of the grants of a memdev.
func TestKindOf(t *testing.T) {
	for _, c := range []struct {
		asked  state.Asked
		shared bool
		want   Kind
	}{
		{state.Asked{Source: state.SourcePool, Kind: state.KindExclusive}, false, KindPoolExclusive},
		{state.Asked{Source: state.SourcePool, Kind: state.KindShared, Shared: true}, false, KindPoolShared},
		{state.Asked{Source: state.SourcePool, Kind: state.KindPersistent}, false, KindPoolPersistent},
		{state.Asked{Source: state.SourceLocal, Kind: state.KindExclusive}, false, KindLocalSliced},
		{state.Asked{Source: state.SourceLocal, Kind: state.KindShared}, true, KindLocalShared},
		{state.Asked{Source: state.SourceLocal, Kind: state.KindShared}, false, KindLocalUnshared},
		{state.Asked{Source: state.SourceLocal, Kind: state.KindPersistent}, false, KindLocalPersistent},
	} {
		if got := kindOf(c.asked, c.shared); got != c.want {
			t.Errorf("kindOf(%+v, %v) = %s, want %s", c.asked, c.shared, got, c.want)
		}
	}
}
