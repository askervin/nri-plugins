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

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

const (
	stateDir   = "../state"
	kernelDir  = "../../../../../pkg/cxl/kernel"
	statesFile = "../../../../../docs/memory/cxl/states.md"
)

// TestStatesFileIsCurrent checks that docs/memory/cxl/states.md is what
// go generate renders from the state package now.
func TestStatesFileIsCurrent(t *testing.T) {
	want, err := render(stateDir, kernelDir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(statesFile)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, want) {
		return
	}
	gl, wl := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
	for i := 0; i < len(gl) || i < len(wl); i++ {
		g, w := "", ""
		if i < len(gl) {
			g = gl[i]
		}
		if i < len(wl) {
			w = wl[i]
		}
		if g != w {
			t.Fatalf("docs/memory/cxl/states.md is stale, run go generate ./cmd/plugins/dra-driver-cxl; line %d:\n  have: %s\n  want: %s", i+1, g, w)
		}
	}
}

// TestEveryObjectHasItsHeader checks that the doc comment of every record
// type has every section of the header.
func TestEveryObjectHasItsHeader(t *testing.T) {
	docs, triggers, err := parseState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range state.Catalogue() {
		h, ok := docs[o.Name]
		if !ok {
			t.Errorf("%s: no header", o.Name)
			continue
		}
		if len(h.purpose) == 0 {
			t.Errorf("%s: no purpose", o.Name)
		}
		for _, l := range labels {
			if h.sections[l] == "" {
				t.Errorf("%s: no %q section", o.Name, l)
			}
		}
	}
	for _, tr := range state.Triggers {
		if triggers[string(tr)] == "" {
			t.Errorf("trigger %s: no doc comment", tr)
		}
	}
}

// TestEveryKernelObjectHasItsHeader checks that every kind of kernel object
// of the catalogue has a header comment with a purpose and its states.
func TestEveryKernelObjectHasItsHeader(t *testing.T) {
	docs, err := parseKernel(kernelDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range kernel.Catalogue() {
		h := docs[o.Name]
		if len(h) == 0 || h[0].label != "" || !strings.HasPrefix(h[0].text, o.Name+": ") {
			t.Errorf("%s: no header comment", o.Name)
			continue
		}
		states := false
		for _, p := range h {
			states = states || strings.HasPrefix(p.label, "State") || strings.Contains(p.text, "States:")
		}
		if !states {
			t.Errorf("%s: the header names no state", o.Name)
		}
	}
}

func TestEscape(t *testing.T) {
	if got := escape("a | b * <uid>"); got != `a \| b \* &lt;uid>` {
		t.Errorf("escape: %q", got)
	}
}
