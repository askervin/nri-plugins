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

package compat

import (
	"flag"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite strings.go from the sources")

// repoRoot is the repository root relative to this package.
const repoRoot = "../../../../.."

// TestStringsUpToDate checks that strings.go is what the e2e tests, the
// test90 observer and oracle and the documentation say now. With -update it
// rewrites strings.go instead.
func TestStringsUpToDate(t *testing.T) {
	entries, err := collect(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	want, err := render(entries)
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile("strings.go", want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile("strings.go")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == string(want) {
		return
	}
	gl, wl := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
	for i := 0; i < len(gl) || i < len(wl); i++ {
		var g, w string
		if i < len(gl) {
			g = gl[i]
		}
		if i < len(wl) {
			w = wl[i]
		}
		if g != w {
			t.Fatalf("strings.go is stale, run go generate in cmd/plugins/dra-driver-cxl/internal/compat\n"+
				"line %d is\n  %s\nthe sources say\n  %s", i+1, g, w)
		}
	}
}

func TestShellTokens(t *testing.T) {
	src := `f() { # comment
    dra-plugin-log-wait "$VM2" "a \"b\" $X: ${y:+z $y}" 60
}
n=$(dra-plugin-log "$VM2" | grep -c 'it'"'"'s')
cat <<EOF
refused 2 "not a command: heredoc body"
EOF
x="multi
line" | \
  grep -F -- y
`
	toks, err := shellTokens(src, 1)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tk := range toks {
		if tk.op != "" {
			got = append(got, "<"+strings.ReplaceAll(tk.op, "\n", "nl")+">")
		} else {
			got = append(got, tk.word)
		}
	}
	want := []string{
		"f", "<(>", "<)>", "<{>", "<nl>",
		"dra-plugin-log-wait", "$VM2", `a "b" $X: ${y:+z $y}`, "60", "<nl>",
		"<}>", "<nl>",
		"n=", "<$(>", "dra-plugin-log", "$VM2", "<|>", "grep", "-c", "it's", "<)>", "<nl>",
		"cat", "<<<>", "EOF", "<nl>",
		"x=multi\nline", "<|>", "grep", "-F", "--", "y", "<nl>",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tokens\n got %q\nwant %q", got, want)
	}
}

func TestShellStrings(t *testing.T) {
	src := `TEXT_A="device $S: refused"
declare -A BAD_TEXT=(
    [one]='first text'
    [two]="second $V"
)
helper() {
    local text="$1"
    dra-plugin-log-wait "$VM" "$text"
    log=$(dra-plugin-log "$VM")
    grep -E 'from log|var' <<< "$log"
}
dra-plugin-log-wait "$VM" "literal line"
fs-refused "$VM" n "$S" "mode: fs" "$CLASS" "$TEXT_A" "second part"
dra-plugin-log "$VM" | grep -iE 'shown only' | tail -n 3
dra-plugin-log "$VM" | grep -E 'nobody checks'
if dra-plugin-log "$VM" | grep -qF "in a condition"; then echo yes; fi
retry-until 'dra-plugin-log "$VM" | grep -qF "in a quoted command"'
dra-exec "$VM" pod/main "$CXL_REQUEST" fd --lease "$L" --exec true && error "succeeded"
[ "$COMMAND_STATUS" == 3 ] || error "exit"
grep -qF "lease $L is not a dax lease" <<< "$COMMAND_OUTPUT
$DRA_EXEC_STDERR" || error "no text"
dra-exec "$VM" pod/main "$CXL_REQUEST" fd --lease "$L" --exec sh -c "$prog"
grep -qF "program output" <<< "$COMMAND_OUTPUT"
dra-claim-condition-watch "$VM" c "$DRIVER/AttachFailed" InvalidConfig 90
grep -qF 'unknown field "x"' <<< "$COMMAND_OUTPUT" || error "no field"
grep -qF "\"$2\"" <<< "$COMMAND_OUTPUT"
`
	c := newCollection()
	f := &shellFile{c: c, path: "x/test99-x/code.var.sh", where: "test99-x", values: map[string][]string{}}
	toks, err := shellTokens(src, 1)
	if err != nil {
		t.Fatal(err)
	}
	pipes, logs := shellPipelines(toks)
	for _, p := range pipes {
		for _, cmd := range p.cmds {
			if a := assignment.FindStringSubmatch(cmd.name()); a != nil && len(cmd.args) == 1 {
				f.values[a[1]] = append(f.values[a[1]], a[2])
			}
		}
	}
	f.arrays(toks)
	f.pipelines(pipes, logs)
	got := map[string]string{}
	for _, e := range c.byKey {
		got[kinds[e.kind].prefix+": "+e.text] = strings.Join(e.pins, "; ")
	}
	want := map[string]string{
		"Event: first text":                    "test99-x (BAD_TEXT)",
		"Event: second $V":                     "test99-x (BAD_TEXT)",
		"Event: device $S: refused":            "test99-x (fs-refused)",
		"Event: second part":                   "test99-x (fs-refused)",
		"Log: from log|var":                    "test99-x helper (dra-plugin-log output | grep -E)",
		"Request: lease $L is not a dax lease": "test99-x (cxl-request output | grep -qF)",
		"Condition: unknown field \"x\"":       "test99-x (dra-claim-condition-watch | grep -qF)",
		"Log: in a condition":                  "test99-x (dra-plugin-log | grep -qF)",
		"Log: literal line":                    "test99-x (dra-plugin-log-wait)",
		"Log: in a quoted command":             "test99-x (dra-plugin-log | grep -qF)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("strings\n got %v\nwant %v", got, want)
	}
}

func TestDocStrings(t *testing.T) {
	text := "# Section\n\nThe plugin logs a line, `cxl.nri.io: device X: mounted A at B`.\n" +
		"Not a log: `some: inline code span here`.\n\n" +
		"The plugin logs:\n\n```\nline one: a\nline two: b\n```\n\nand, later,\n\n```\nline three: c\n```\n\n" +
		"An example:\n\n```\nnot: a log line\n```\n" +
		"## Configuration of a pool controller\n\nThe controller logs `ERROR: claim x: invalid configuration: y` " +
		"and the condition `MemoryConfig: pool.opaque.x: unknown field` in its log.\n"
	c := newCollection()
	collectDoc(c, "d.md", text)
	var got []string
	for _, e := range c.byKey {
		got = append(got, e.text)
	}
	want := []string{"MemoryConfig: pool.opaque.x: unknown field", "cxl.nri.io: device X: mounted A at B",
		"line one: a", "line three: c", "line two: b"}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("doc strings\n got %q\nwant %q", got, want)
	}
}

func TestDerivedName(t *testing.T) {
	for text, want := range map[string]string{
		"NRI fence: fencing CXL nodes $NUMA_NODE of prepared claims":                       "NRIFenceFencingCXLNodesNumaNodeOfPrepared",
		"(serial $DRA_LOCAL_SERIAL): not configured shared any more, releasing its region": "SerialDRALocalSerialNotConfiguredSharedAnyMoreReleasing",
		"mounted $PMEM at $MNT_DIRECT (ext4, rw, dax=always)":                              "MountedPmemAtMntDirectExt4RwDaxAlways",
		"at ${MNT_CACHED} $*": "AtMntCached",
		"$* $1":               "Text",
	} {
		if got := derivedName(text); got != want {
			t.Errorf("derivedName(%q) = %s, want %s", text, got, want)
		}
	}
}

// TestConstNames checks that a name never moves to another text: texts that
// share a derived name get hashed names, the others keep theirs whatever is
// added, and a given name that two texts share is an error.
func TestConstNames(t *testing.T) {
	long := "one two three four five six seven eight "
	a := &entry{kind: kindLog, text: long + "nine"}
	b := &entry{kind: kindLog, text: long + "ten"}
	c := &entry{kind: kindLog, text: "other text"}
	names, err := constNames([]*entry{a, c})
	if err != nil {
		t.Fatal(err)
	}
	if names[a] != "LogOneTwoThreeFourFiveSixSevenEight" || names[c] != "LogOtherText" {
		t.Fatalf("names %v", names)
	}
	names2, err := constNames([]*entry{b, c, a})
	if err != nil {
		t.Fatal(err)
	}
	if names2[c] != names[c] {
		t.Errorf("adding a colliding text renamed an unrelated one: %s -> %s", names[c], names2[c])
	}
	if names2[a] == names[a] || names2[b] == names[a] || names2[a] == names2[b] {
		t.Errorf("colliding texts: %s and %s, the bare name was %s", names2[a], names2[b], names[a])
	}
	names3, err := constNames([]*entry{a, b, c, {kind: kindLog, text: long + "eleven"}})
	if err != nil {
		t.Fatal(err)
	}
	if names3[a] != names2[a] || names3[b] != names2[b] {
		t.Errorf("a third colliding text renamed the hashed names")
	}
	_, err = constNames([]*entry{
		{kind: kindField, name: "X", text: "a"},
		{kind: kindField, name: "X", text: "b"},
	})
	if err == nil {
		t.Errorf("no error for a given name of two texts")
	}
}
