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
	"fmt"

	"github.com/containers/nri-plugins/pkg/cxl/fsm"
)

// The states of the kernel objects are the kernel's: this package observes
// them, and its operations or kernel events change them. Every object with
// a state has an observed Table of the transitions that the kernel makes,
// next to its state type; an observed change that the table does not have
// is a fact that the design does not know (Table.Check with
// fsm.AnyTrigger).

// Transition is one change of the state of a kernel object: When says what
// makes it, an operation of this package or a kernel event.
type Transition[S comparable] = fsm.Transition[S]

// Table is the observed transitions of the state of one kind of kernel
// object.
type Table[S comparable] = fsm.Table[S]

// ErrTransition is the kind of the error of a change of state that a Table
// does not have.
var ErrTransition = fsm.ErrTransition

// ObjectTables is a kind of kernel object, by the name that its header
// comment gives it, with the transition tables of its states.
type ObjectTables struct {
	Name   string
	Tables []fsm.TableText
}

// Catalogue returns the kinds of kernel objects in the order of the
// documentation.
func Catalogue() []ObjectTables {
	return []ObjectTables{
		{Name: "Memdev", Tables: []fsm.TableText{MemdevTransitions.Text()}},
		{Name: "Port"},
		{Name: "Region", Tables: []fsm.TableText{RegionTransitions.Text()}},
		{Name: "DaxRegion and DaxDevice", Tables: []fsm.TableText{DaxTransitions.Text()}},
		{Name: "MemoryBlock", Tables: []fsm.TableText{BlockTransitions.Text()}},
		{Name: "NumaNode"},
		{Name: "NdRegion, Namespace and BlockDevice",
			Tables: []fsm.TableText{NdRegionTransitions.Text(), NamespaceTransitions.Text()}},
		{Name: "Superblock and Mount"},
		{Name: "LoopDevice"},
	}
}

// list returns its arguments as a slice.
func list[S any](values ...S) []S {
	return values
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
