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
	"testing"
)

// checkTable checks that a transition table is well formed: every row
// applies on each of its triggers from each of its states, no two rows
// have the same transition and trigger, every state of a row is a state of
// the table, every state of the table is in a row, the refused transitions
// are refused, and every transition that no row has is refused with the
// state unchanged. Its applications do not count as row coverage.
func checkTable[S comparable](t *testing.T, tb *Table[S]) {
	t.Helper()
	saved := rowApplied
	rowApplied = nil
	defer func() { rowApplied = saved }()
	inRows := map[S]bool{}
	seen := map[string]int{}
	for i := range tb.Rows {
		checkRow(t, tb, i, inRows, seen)
	}
	for _, s := range tb.States {
		if !inRows[s] {
			t.Errorf("%s.%s: state %v is in no row", tb.Object, tb.Field, s)
		}
	}
	checkRefusals(t, tb)
	checkOthersRefused(t, tb)
}

// checkRow checks row i of the table, and records its states in inRows and
// its transitions in seen.
func checkRow[S comparable](t *testing.T, tb *Table[S], i int, inRows map[S]bool, seen map[string]int) {
	t.Helper()
	var zero S
	r := tb.Rows[i]
	row := fmt.Sprintf("%s.%s row %d", tb.Object, tb.Field, i)
	if len(r.From) == 0 || len(r.Triggers) == 0 {
		t.Errorf("%s: no from state or no trigger", row)
	}
	if r.When == "" && r.Effects == "" {
		t.Errorf("%s: neither When nor Effects documented", row)
	}
	if r.Stays && r.To != zero {
		t.Errorf("%s: stays and has To %v", row, r.To)
	}
	if !r.Stays {
		if !slices.Contains(tb.States, r.To) {
			t.Errorf("%s: To %v is not a state of the table", row, r.To)
		}
		inRows[r.To] = true
	}
	for _, tr := range r.Triggers {
		if !slices.Contains(Triggers, tr) {
			t.Errorf("%s: trigger %q is not in Triggers", row, tr)
		}
	}
	for _, from := range r.From {
		if !slices.Contains(tb.States, from) {
			t.Errorf("%s: From %v is not a state of the table", row, from)
		}
		inRows[from] = true
		to := r.To
		if r.Stays {
			to = from
		}
		for _, tr := range r.Triggers {
			key := fmt.Sprintf("%v -> %v on %s", from, to, tr)
			if j, dup := seen[key]; dup {
				t.Errorf("%s: %s is also row %d", row, key, j)
			}
			seen[key] = i
			s := from
			if err := Apply(tb, &s, to, tr); err != nil || s != to {
				t.Errorf("%s: %s: %v, state %v", row, key, err, s)
			}
		}
	}
}

// checkRefusals checks that the table refuses its Refused transitions.
func checkRefusals[S comparable](t *testing.T, tb *Table[S]) {
	t.Helper()
	for _, ref := range tb.Refused {
		to := ref.To
		if len(to) == 0 {
			to = tb.States
		}
		for _, from := range ref.From {
			for _, s := range to {
				for _, tr := range Triggers {
					if !slices.Contains(ref.Except, tr) && tb.Allows(from, s, tr) {
						t.Errorf("%s.%s: refused %v -> %v is allowed on %s", tb.Object, tb.Field, from, s, tr)
					}
				}
			}
		}
	}
}

// checkOthersRefused checks that every transition and trigger that no row
// has is refused with the state unchanged.
func checkOthersRefused[S comparable](t *testing.T, tb *Table[S]) {
	t.Helper()
	for _, from := range tb.States {
		for _, to := range tb.States {
			for _, tr := range Triggers {
				if tb.Allows(from, to, tr) {
					continue
				}
				s := from
				err := Apply(tb, &s, to, tr)
				if !errors.Is(err, ErrTransition) {
					t.Errorf("%s.%s: %v -> %v on %s not in the table: error %v", tb.Object, tb.Field, from, to, tr, err)
				}
				if s != from {
					t.Errorf("%s.%s: refused %v -> %v on %s changed the state to %v", tb.Object, tb.Field, from, to, tr, s)
				}
			}
		}
	}
}

func TestApplyRefusesWithTransitionError(t *testing.T) {
	s := PreparationPrepared
	err := Apply(&PreparationTable, &s, PreparationPreparing, TriggerPrepare)
	var te *TransitionError
	if !errors.As(err, &te) {
		t.Fatalf("error %v, want a *TransitionError", err)
	}
	if !errors.Is(err, ErrTransition) {
		t.Errorf("error %v is not ErrTransition", err)
	}
	if s != PreparationPrepared {
		t.Errorf("state %s after a refused transition", s)
	}
	want := "Preparation.State: PREPARED -> PREPARING on a-prepare: transition not in the table"
	if err.Error() != want {
		t.Errorf("error %q, want %q", err, want)
	}
}

func TestApplyChecksTheTrigger(t *testing.T) {
	s := PreparationUnknown
	if err := Apply(&PreparationTable, &s, PreparationPreparing, TriggerRecover); err == nil {
		t.Errorf("UNKNOWN -> PREPARING allowed on a-recover")
	}
	if err := Apply(&PreparationTable, &s, PreparationPreparing, TriggerPrepare); err != nil || s != PreparationPreparing {
		t.Errorf("UNKNOWN -> PREPARING on a-prepare: %v, state %s", err, s)
	}
}

func TestStaysRowsKeepTheState(t *testing.T) {
	s := MountedRO
	if err := Apply(&MountTable, &s, MountedRO, TriggerPrepare); err != nil {
		t.Errorf("MOUNTED_RO stays on a-prepare: %v", err)
	}
	if MountTable.Allows(MountedRO, MountedRW, TriggerRecover) {
		t.Errorf("a stays row allows MOUNTED_RO -> MOUNTED_RW")
	}
}

func TestTextRendersEveryRow(t *testing.T) {
	for _, o := range Catalogue() {
		for _, tt := range o.Tables {
			if tt.Object != o.Name {
				t.Errorf("table %s.%s under object %s", tt.Object, tt.Field, o.Name)
			}
			if len(tt.Rows) == 0 || len(tt.States) == 0 {
				t.Errorf("table %s.%s: no rows or no states", tt.Object, tt.Field)
			}
			for i, r := range tt.Rows {
				if r.Stays != (len(r.To) == 0) {
					t.Errorf("table %s.%s row %d: stays %v, to %v", tt.Object, tt.Field, i, r.Stays, r.To)
				}
			}
			for _, r := range tt.Refused {
				if !strings.Contains(r, " -> ") {
					t.Errorf("table %s.%s: refusal %q", tt.Object, tt.Field, r)
				}
			}
		}
	}
}

func TestTriggersAreUsed(t *testing.T) {
	used := map[string]bool{}
	for _, o := range Catalogue() {
		for _, tt := range o.Tables {
			for _, r := range tt.Rows {
				for _, tr := range r.Triggers {
					used[tr] = true
				}
			}
		}
	}
	for _, tr := range Triggers {
		if !used[string(tr)] {
			t.Errorf("trigger %s is in no row", tr)
		}
	}
}

// step is one transition of a life cycle: to the state on the trigger.
type step[S comparable] struct {
	to S
	on Trigger
}

// walk applies the steps of a life cycle from the state from in turn and
// fails at the first one that the table refuses.
func walk[S comparable](t *testing.T, tb *Table[S], name string, from S, steps ...step[S]) {
	t.Helper()
	s := from
	for i, st := range steps {
		if err := Apply(tb, &s, st.to, st.on); err != nil {
			t.Errorf("%s: step %d: %v", name, i, err)
			return
		}
	}
}
