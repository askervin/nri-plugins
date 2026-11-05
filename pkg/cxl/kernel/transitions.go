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

package kernel

import (
	"errors"
	"fmt"
)

// The states of the kernel objects are the kernel's: this package observes
// them, and its operations or kernel events change them. Every object with
// a state has a Table of the transitions that the kernel makes, next to its
// state type; an observed change that the table does not have is a fact
// that the design does not know (Table.Check).

// Transition is one change of the state of a kernel object.
type Transition[S comparable] struct {
	From, To S
	// Trigger is what makes the change: an operation of this package or a
	// kernel event.
	Trigger string
	// Guard is the condition of the change, "" for none.
	Guard string
	// Effect is what else changes with it, "" for nothing.
	Effect string
}

// Table is the transitions of the state of one kind of kernel object.
type Table[S comparable] []Transition[S]

// ErrTransition is the kind of the error of a change of state that a Table
// does not have.
var ErrTransition = errors.New("unknown transition")

// Allows tells whether the table has the transition from -> to.
func (t Table[S]) Allows(from, to S) bool {
	for _, tr := range t {
		if tr.From == from && tr.To == to {
			return true
		}
	}
	return false
}

// Check returns an error of kind ErrTransition unless from equals to or
// the table has the transition from -> to.
func (t Table[S]) Check(object string, from, to S) error {
	if from == to || t.Allows(from, to) {
		return nil
	}
	return errorf(ErrTransition, "%s: %v -> %v is not a transition of the kernel that is known", object, from, to)
}

// stateText returns the name of a state, or "state(n)" for a value without
// a name.
func stateText(names []string, s int) string {
	if s >= 0 && s < len(names) {
		return names[s]
	}
	return fmt.Sprintf("state(%d)", s)
}

// parseState returns the state with the name.
func parseState(names []string, text []byte) (int, error) {
	for i, n := range names {
		if n == string(text) {
			return i, nil
		}
	}
	return 0, fmt.Errorf("unknown state %q", text)
}
