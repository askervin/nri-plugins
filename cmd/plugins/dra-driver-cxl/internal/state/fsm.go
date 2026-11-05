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
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Trigger names the action of the driver or the event that causes a
// transition.
type Trigger string

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

// Transition is one row of a transition table: a record in a state of From
// goes to To (or stays in its state, Stays) when one of Triggers happens
// as When says and Guard holds, with Effects.
type Transition[S comparable] struct {
	From     []S
	To       S
	Stays    bool
	Triggers []Trigger
	When     string
	Guard    string
	Effects  string
}

// Refusal is a set of transitions that a table refuses on purpose: from a
// state of From to a state of To (every state if To is empty), on every
// trigger but those of Except.
type Refusal[S comparable] struct {
	From   []S
	To     []S
	Except []Trigger
	Why    string
}

// Table is the transition table of one State field of a record: its
// states and the transitions that the code may apply. A transition that
// is not a row of the table is refused. A change of other fields of a
// record that keeps its state is not a transition; a Stays row documents
// an action that keeps the state, and may be applied for it.
type Table[S comparable] struct {
	Object  string
	Field   string
	States  []S
	Rows    []Transition[S]
	Refused []Refusal[S]
}

// ErrTransition is the error of a transition that is not in a table.
var ErrTransition = errors.New("transition not in the table")

// TransitionError is a transition that a table refused.
type TransitionError struct {
	Object, Field string
	From, To      string
	Trigger       Trigger
}

// Error returns the refused transition in words.
func (e *TransitionError) Error() string {
	return fmt.Sprintf("%s.%s: %s -> %s on %s: %v", e.Object, e.Field, e.From, e.To, e.Trigger, ErrTransition)
}

// Is tells whether target is ErrTransition.
func (e *TransitionError) Is(target error) bool {
	return target == ErrTransition
}

// rowApplied is called with the table and the index of every row that
// Apply applies; nil outside the tests that count the rows.
var rowApplied func(object, field string, row int)

// Find returns the first row of the table that takes from to to on
// trigger, and whether there is one.
func (t *Table[S]) Find(from, to S, trigger Trigger) (*Transition[S], bool) {
	if i := t.row(from, to, trigger); i >= 0 {
		return &t.Rows[i], true
	}
	return nil, false
}

// row returns the index of the first row that takes from to to on
// trigger, -1 if there is none.
func (t *Table[S]) row(from, to S, trigger Trigger) int {
	for i := range t.Rows {
		r := &t.Rows[i]
		if !slices.Contains(r.From, from) || !slices.Contains(r.Triggers, trigger) {
			continue
		}
		if (r.Stays && to == from) || (!r.Stays && to == r.To) {
			return i
		}
	}
	return -1
}

// Allows tells whether the table has a row that takes from to to on
// trigger.
func (t *Table[S]) Allows(from, to S, trigger Trigger) bool {
	_, ok := t.Find(from, to, trigger)
	return ok
}

// Check returns nil if the table allows from -> to on trigger, a
// *TransitionError otherwise.
func (t *Table[S]) Check(from, to S, trigger Trigger) error {
	if t.Allows(from, to, trigger) {
		return nil
	}
	return &TransitionError{
		Object:  t.Object,
		Field:   t.Field,
		From:    fmt.Sprint(from),
		To:      fmt.Sprint(to),
		Trigger: trigger,
	}
}

// Apply sets *state to to if the table allows the transition on trigger,
// and returns a *TransitionError, leaving *state unchanged, otherwise.
func Apply[S comparable](t *Table[S], state *S, to S, trigger Trigger) error {
	i := t.row(*state, to, trigger)
	if i < 0 {
		return t.Check(*state, to, trigger)
	}
	if rowApplied != nil {
		rowApplied(t.Object, t.Field, i)
	}
	*state = to
	return nil
}

// TableText is a transition table in words, for the documentation.
type TableText struct {
	Object, Field string
	States        []string
	Rows          []RowText
	Refused       []string
}

// RowText is a row of a transition table in words.
type RowText struct {
	From, To []string
	Stays    bool
	Triggers []string
	When     string
	Guard    string
	Effects  string
}

// Text returns the table in words.
func (t *Table[S]) Text() TableText {
	tt := TableText{Object: t.Object, Field: t.Field, States: texts(t.States)}
	for _, r := range t.Rows {
		rt := RowText{
			From:    texts(r.From),
			Stays:   r.Stays,
			When:    r.When,
			Guard:   r.Guard,
			Effects: r.Effects,
		}
		if !r.Stays {
			rt.To = []string{fmt.Sprint(r.To)}
		}
		for _, tr := range r.Triggers {
			rt.Triggers = append(rt.Triggers, string(tr))
		}
		tt.Rows = append(tt.Rows, rt)
	}
	for _, r := range t.Refused {
		to := "any state"
		if len(r.To) > 0 {
			to = strings.Join(texts(r.To), ", ")
		}
		if len(r.Except) > 0 {
			to += " except on " + strings.Join(texts(r.Except), ", ")
		}
		tt.Refused = append(tt.Refused, fmt.Sprintf("%s -> %s: %s", strings.Join(texts(r.From), ", "), to, r.Why))
	}
	return tt
}

// texts returns the values as text.
func texts[S any](values []S) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, fmt.Sprint(v))
	}
	return out
}

// list returns its arguments as a slice.
func list[S any](values ...S) []S {
	return values
}
