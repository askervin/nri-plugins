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
	"github.com/containers/nri-plugins/pkg/cxl/fsm"
)

// Trigger names the action of the driver or the event that causes a
// transition.
type Trigger = fsm.Trigger

const (
	// TriggerPrepare is NodePrepareResources of either driver, its
	// rollback included.
	TriggerPrepare Trigger = "a-prepare"
	// TriggerUnprepare is NodeUnprepareResources of either driver.
	TriggerUnprepare Trigger = "a-unprepare"
	// TriggerRecover is the recovery at the start of the process, both
	// phases.
	TriggerRecover Trigger = "a-recover"
	// TriggerLoad is the store loading the document at the start of the
	// process.
	TriggerLoad Trigger = "load"
	// TriggerObserve is an observation of the kernel: a scan, a uevent,
	// a memdev that appeared or went.
	TriggerObserve Trigger = "a-observe"
	// TriggerList is a list of the pool driver's ResourceSlices or of
	// the pool claims allocated to the node.
	TriggerList Trigger = "a-list"
	// TriggerExpire is a timer of a record that ran out.
	TriggerExpire Trigger = "expire"
	// TriggerRequest is a lease request on the socket of a lease claim,
	// until its response.
	TriggerRequest Trigger = "a-request"
	// TriggerRelease is the release of a lease: by its client, at the
	// end of its requester, at a failure.
	TriggerRelease Trigger = "a-release"
	// TriggerReconcile is the periodic lease reconcile and repair pass.
	TriggerReconcile Trigger = "a-reconcile"
	// TriggerOnLending is the companion claim's Prepare passing the
	// companion gate.
	TriggerOnLending Trigger = "OnLending"
	// TriggerOnPrepared is the companion claim's Prepare handing over
	// the lent devices.
	TriggerOnPrepared Trigger = "OnPrepared"
	// TriggerOnLendFailed is a bind or lend error of the companion
	// claim's Prepare.
	TriggerOnLendFailed Trigger = "OnLendFailed"
	// TriggerOnReleasing is the companion claim's Unprepare.
	TriggerOnReleasing Trigger = "OnReleasing"
)

// Triggers are all triggers, in the order of the documentation.
var Triggers = []Trigger{
	TriggerPrepare, TriggerUnprepare, TriggerRecover, TriggerLoad, TriggerObserve, TriggerList,
	TriggerExpire, TriggerRequest, TriggerRelease, TriggerReconcile, TriggerOnLending,
	TriggerOnPrepared, TriggerOnLendFailed, TriggerOnReleasing,
}

// Transition is one row of a transition table (fsm.Transition).
type Transition[S comparable] = fsm.Transition[S]

// Refusal is a set of transitions that a table refuses on purpose
// (fsm.Refusal).
type Refusal[S comparable] = fsm.Refusal[S]

// Table is the transition table of one State field of a record: its
// states and the transitions that the code may apply (fsm.Table, applied,
// never observed). A transition that is not a row of the table is refused.
// A change of other fields of a record that keeps its state is not a
// transition; a Stays row documents an action that keeps the state, and may
// be applied for it.
type Table[S comparable] = fsm.Table[S]

// TransitionError is a transition that a table refused.
type TransitionError = fsm.TransitionError

// TableText is a transition table in words, for the documentation.
type TableText = fsm.TableText

// RowText is a row of a transition table in words.
type RowText = fsm.RowText

// ErrTransition is the kind of the error of a transition that is not in a
// table.
var ErrTransition = fsm.ErrTransition

// Apply sets *state to to if the table allows the transition on trigger,
// and returns a *TransitionError, leaving *state unchanged, otherwise.
func Apply[S comparable](t *Table[S], state *S, to S, trigger Trigger) error {
	return fsm.Apply(t, state, to, trigger)
}

// list returns its arguments as a slice.
func list[S any](values ...S) []S {
	return values
}
