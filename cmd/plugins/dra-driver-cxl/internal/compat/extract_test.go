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

// The extractor of strings.go. It reads, relative to the repository root:
//
//   - the e2e shell code of test/e2e/memory.test-suite/dra-driver-cxl
//     (dra.source.sh, n4-cxl-shared-2/*.source.sh, the code.var.sh of every
//     test and test90's mbt.source.sh; not the demo01 copy of the suite):
//     the TEXT arguments of the matchers in shellMatchers, the patterns of
//     grep, awk and sed reading `dra-plugin-log` (a grep piped into head or
//     tail only displays lines and is skipped), the values of the *_TEXT
//     arrays, the texts of the event lists of dra-wait expressions, and the
//     readiness lines of test90's executor (executorLines). A TEXT that is
//     one variable is replaced by the value of its only assignment in the
//     same file, and skipped when there is no such value.
//   - test90's mbt-observe.py: the driver log patterns from PANIC to the end
//     of LOG_COUNTS, the names of observerNames, the state view files of
//     state() and the fields read by local_devices(), pool_claims() and the
//     CDI spec glob of cdi_pool().
//   - test90's model/oracle*.go: the string constants, and the json fields
//     of leases.json that checkLeaseStore decodes.
//   - docs/memory/cxl/*.md: the lines of fenced blocks without a language
//     that a paragraph mentioning a log introduces, and the inline code
//     spans of 20 or more characters with ": " in sentences mentioning a log.

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"hash/fnv"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const (
	suiteDir  = "test/e2e/memory.test-suite/dra-driver-cxl"
	test90Dir = suiteDir + "/n4-cxl-shared-2/test90-gofmbt-reliability"
	docsDir   = "docs/memory/cxl"
)

// kind is the class of a string: its section in strings.go and the prefix
// of its constant name.
type kind int

const (
	kindLog kind = iota
	kindEvent
	kindRequest
	kindExecutor
	kindObserver
	kindOracle
	kindName
	kindView
	kindField
	kindDoc
)

var kinds = []struct{ prefix, title, verb string }{
	kindLog:      {"Log", "Texts that the e2e tests find in the log of the driver.", "Pinned by"},
	kindEvent:    {"Event", "Texts that the e2e tests find in the Events of pods whose claims the driver refused to prepare.", "Pinned by"},
	kindRequest:  {"Request", "Texts that the e2e tests find in the output of cxl-request.", "Pinned by"},
	kindExecutor: {"Executor", "Lines of the driver log that the test90 executor waits for.", "Pinned by"},
	kindObserver: {"Observer", "Patterns of the driver log that the test90 observer counts or waits for.", "Pinned by"},
	kindOracle:   {"Oracle", "Texts of the Events of the driver that the test90 oracle matches.", "Pinned by"},
	kindName:     {"Name", "Paths, labels and names of the driver that the test90 observer reads.", "Pinned by"},
	kindView:     {"View", "State view files that the test90 observer reads.", "Pinned by"},
	kindField:    {"Field", "Fields of the state views that the test90 observer and oracle read, by view.", "Pinned by"},
	kindDoc:      {"Doc", "Log lines that docs/memory/cxl quotes.", "Quoted in"},
}

// entry is one string of strings.go.
type entry struct {
	kind kind
	name string // the name without the kind prefix, derived from text if empty
	text string
	pins []string // who depends on the string, "where (how)"
	re   *dialect // the dialect of a regular expression, nil for a template
}

// markRegexp marks e, if not nil, as a regular expression of dialect d.
func (e *entry) markRegexp(d dialect) {
	if e != nil {
		e.re = &d
	}
}

// collection is the set of entries, one per kind and text.
type collection struct {
	byKey map[string]*entry
}

// newCollection returns an empty collection.
func newCollection() *collection {
	return &collection{byKey: map[string]*entry{}}
}

// add records that pin depends on text of kind k, named name if not empty,
// and returns the entry: one per kind, name and text; nil for an empty text.
func (c *collection) add(k kind, name, text, pin string) *entry {
	if text == "" {
		return nil
	}
	key := fmt.Sprintf("%d\x00%s\x00%s", k, name, text)
	e, ok := c.byKey[key]
	if !ok {
		e = &entry{kind: k, text: text}
		c.byKey[key] = e
	}
	e.name = name
	for _, p := range e.pins {
		if p == pin {
			return e
		}
	}
	e.pins = append(e.pins, pin)
	return e
}

// collect returns the entries of the sources under the repository root.
func collect(root string) ([]*entry, error) {
	c := newCollection()
	shellFiles, err := suiteShellFiles(root)
	if err != nil {
		return nil, err
	}
	for _, f := range shellFiles {
		if err := collectShell(c, root, f); err != nil {
			return nil, err
		}
	}
	if err := collectObserver(c, root); err != nil {
		return nil, err
	}
	if err := collectOracle(c, root); err != nil {
		return nil, err
	}
	if err := collectDocs(c, root); err != nil {
		return nil, err
	}
	entries := make([]*entry, 0, len(c.byKey))
	for _, e := range c.byKey {
		sort.Strings(e.pins)
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		if a.text != b.text {
			return a.text < b.text
		}
		return a.name < b.name
	})
	return entries, nil
}

// suiteShellFiles returns the shell files of the e2e suite, relative to root.
func suiteShellFiles(root string) ([]string, error) {
	var files []string
	for _, pattern := range []string{
		suiteDir + "/dra.source.sh",
		suiteDir + "/n4-cxl-shared-2/*.source.sh",
		suiteDir + "/n4-cxl-shared-2/test*/code.var.sh",
		test90Dir + "/mbt.source.sh",
	} {
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("no files %s", pattern)
		}
		for _, m := range matches {
			rel, err := filepath.Rel(root, m)
			if err != nil {
				return nil, err
			}
			files = append(files, filepath.ToSlash(rel))
		}
	}
	sort.Strings(files)
	return files, nil
}

//
// Shell
//

// shellMatchers are the commands whose arguments are texts that the driver
// must produce: the kind of the texts and the index of the first one among
// the arguments (0 for the first argument after the command name); with all
// set every argument from the first one on is a text, up to "--".
var shellMatchers = map[string]struct {
	kind  kind
	first int
	all   bool
}{
	"dra-plugin-log-wait": {kindLog, 1, false},
	"plugin-log-has":      {kindLog, 0, false},
	"event-wait":          {kindEvent, 1, false},
	"fs-event-wait":       {kindEvent, 1, true},
	"fs-refused":          {kindEvent, 5, true},
	"refused":             {kindRequest, 1, false},
}

// executorLines are the variables of test90's executor that hold driver log
// lines, and the names of their constants.
var executorLines = map[string]string{
	"MBT_LENDS_RESTORED": "LendsRestored",
	"MBT_NRI_SYNCED":     "NRISynced",
	"MBT_FENCING_LOG":    "FencingLog",
}

// shellToken is a word or an operator of shell code.
type shellToken struct {
	op     string // the operator, empty for a word
	word   string // the word without quotes, expansions kept as written
	single bool   // the word is one single-quoted string
	line   int
}

// shellTokens returns the tokens of shell code, starting at line, without
// comments and here-document bodies.
func shellTokens(src string, line int) ([]shellToken, error) {
	var (
		toks    []shellToken
		heredoc []string // delimiters of the here-documents of the line
		i       int
	)
	emitOp := func(op string) {
		toks = append(toks, shellToken{op: op, line: line})
	}
	for i < len(src) {
		ch := src[i]
		switch {
		case ch == ' ' || ch == '\t':
			i++
		case ch == '\\' && i+1 < len(src) && src[i+1] == '\n':
			i += 2
			line++
		case ch == '\n':
			emitOp("\n")
			i++
			line++
			for _, delim := range heredoc {
				for i < len(src) {
					end := strings.IndexByte(src[i:], '\n')
					if end < 0 {
						end = len(src) - i
					}
					text := src[i : i+end]
					i += end + 1
					line++
					if strings.TrimLeft(text, "\t") == delim {
						break
					}
				}
			}
			heredoc = nil
		case ch == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case strings.HasPrefix(src[i:], "$(") && !strings.HasPrefix(src[i:], "$(("):
			emitOp("$(")
			i += 2
		case strings.ContainsRune("|&;()<>", rune(ch)):
			op := string(ch)
			for _, long := range []string{"<<<", "<<-", "&&", "||", ";;", "<<", ">>", ">&", "&>"} {
				if strings.HasPrefix(src[i:], long) {
					op = long
					break
				}
			}
			i += len(op)
			emitOp(op)
			if op == "<<" || op == "<<-" {
				for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
					i++
				}
				w, n, nl, err := shellWord(src[i:])
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", line, err)
				}
				w.line = line
				i += n
				line += nl
				heredoc = append(heredoc, w.word)
				toks = append(toks, w)
			}
		case (ch == '{' || ch == '}') && (i+1 == len(src) || strings.ContainsRune(" \t\n;|&()<>", rune(src[i+1]))):
			emitOp(string(ch))
			i++
		default:
			w, n, nl, err := shellWord(src[i:])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			w.line = line
			i += n
			line += nl
			toks = append(toks, w)
		}
	}
	return toks, nil
}

// shellWord returns the word at the start of src, the number of bytes and of
// newlines it spans.
func shellWord(src string) (shellToken, int, int, error) {
	var (
		b       strings.Builder
		i, nl   int
		parts   int
		singles int
	)
	for i < len(src) {
		ch := src[i]
		switch {
		case ch == ' ' || ch == '\t' || ch == '\n' || strings.ContainsRune("|&;()<>", rune(ch)):
			return shellToken{word: b.String(), single: parts == 1 && singles == 1}, i, nl, nil
		case ch == '\'':
			end := strings.IndexByte(src[i+1:], '\'')
			if end < 0 {
				return shellToken{}, 0, 0, fmt.Errorf("unterminated single quote")
			}
			text := src[i+1 : i+1+end]
			b.WriteString(text)
			nl += strings.Count(text, "\n")
			i += end + 2
			parts++
			singles++
		case ch == '"':
			n, lines, err := doubleQuoted(src[i:], &b)
			if err != nil {
				return shellToken{}, 0, 0, err
			}
			i += n
			nl += lines
			parts++
		case ch == '\\' && i+1 < len(src):
			if src[i+1] == '\n' {
				nl++
			} else {
				b.WriteByte(src[i+1])
			}
			i += 2
			parts++
		case ch == '$' && i+1 < len(src) && (src[i+1] == '(' || src[i+1] == '{'):
			if src[i+1] == '(' && !strings.HasPrefix(src[i:], "$((") && b.Len() > 0 {
				return shellToken{word: b.String(), single: parts == 1 && singles == 1}, i, nl, nil
			}
			n, lines, err := expansion(src[i:])
			if err != nil {
				return shellToken{}, 0, 0, err
			}
			b.WriteString(src[i : i+n])
			i += n
			nl += lines
			parts++
		default:
			b.WriteByte(ch)
			i++
			parts++
		}
	}
	return shellToken{word: b.String(), single: parts == 1 && singles == 1}, i, nl, nil
}

// doubleQuoted writes the text of the double-quoted string at the start of
// src to b and returns the number of bytes and newlines it spans.
func doubleQuoted(src string, b *strings.Builder) (int, int, error) {
	i, nl := 1, 0
	for i < len(src) {
		ch := src[i]
		switch {
		case ch == '"':
			return i + 1, nl, nil
		case ch == '\\' && i+1 < len(src):
			next := src[i+1]
			switch next {
			case '"', '\\', '$', '`':
				b.WriteByte(next)
			case '\n':
				nl++
			default:
				b.WriteByte(ch)
				b.WriteByte(next)
			}
			i += 2
		case ch == '$' && i+1 < len(src) && (src[i+1] == '(' || src[i+1] == '{'):
			n, lines, err := expansion(src[i:])
			if err != nil {
				return 0, 0, err
			}
			b.WriteString(src[i : i+n])
			i += n
			nl += lines
		default:
			if ch == '\n' {
				nl++
			}
			b.WriteByte(ch)
			i++
		}
	}
	return 0, 0, fmt.Errorf("unterminated double quote")
}

// expansion returns the length and the newlines of the $(...) or ${...} at
// the start of src, with quotes inside it honoured.
func expansion(src string) (int, int, error) {
	open, closing := src[1], byte(')')
	if open == '{' {
		closing = '}'
	}
	depth, nl := 0, 0
	for i := 1; i < len(src); i++ {
		ch := src[i]
		switch {
		case ch == open:
			depth++
		case ch == closing:
			depth--
			if depth == 0 {
				return i + 1, nl, nil
			}
		case ch == '\n':
			nl++
		case ch == '\\':
			i++
		case ch == '\'' && open == '(':
			end := strings.IndexByte(src[i+1:], '\'')
			if end < 0 {
				return 0, 0, fmt.Errorf("unterminated single quote in %.20q", src)
			}
			nl += strings.Count(src[i+1:i+1+end], "\n")
			i += end + 1
		case ch == '"':
			var discard strings.Builder
			n, lines, err := doubleQuoted(src[i:], &discard)
			if err != nil {
				return 0, 0, err
			}
			i += n - 1
			nl += lines
		}
	}
	return 0, 0, fmt.Errorf("unterminated %c in %.20q", open, src)
}

// shellCommand is a simple command: its words without keywords and
// redirections, and the word of its here-string.
type shellCommand struct {
	args []shellToken
	here string
}

// name returns the command name of c, empty if it has no words.
func (c *shellCommand) name() string {
	if len(c.args) == 0 {
		return ""
	}
	return c.args[0].word
}

// shellPipeline is a pipeline of simple commands in function fn.
type shellPipeline struct {
	cmds []*shellCommand
	fn   string
	line int
}

// shellPipelines returns the pipelines of the tokens, the functions they are
// in, and the variables assigned the output of dra-plugin-log alone, as
// "function\x00variable".
func shellPipelines(toks []shellToken) ([]*shellPipeline, map[string]bool) {
	type fnScope struct {
		name  string
		depth int
	}
	var (
		pipes      []*shellPipeline
		cur        = &shellPipeline{}
		cmd        = &shellCommand{}
		fns        []fnScope
		depth      int
		awaitBody  string
		redirect   string
		substs     []string // per open $(: the variable it is assigned to
		pluginLogs = map[string]bool{}
		prevOp     string
	)
	fn := func() string {
		if len(fns) == 0 {
			return ""
		}
		return fns[len(fns)-1].name
	}
	endCommand := func() {
		for len(cmd.args) > 0 {
			switch cmd.args[0].word {
			case "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "time":
				cmd.args = cmd.args[1:]
				continue
			}
			break
		}
		if len(cmd.args) > 0 {
			if len(cur.cmds) == 0 {
				cur.line = cmd.args[0].line
			}
			cur.cmds = append(cur.cmds, cmd)
		}
		cmd = &shellCommand{}
	}
	endPipeline := func() *shellPipeline {
		endCommand()
		done := cur
		if len(done.cmds) > 0 {
			done.fn = fn()
			pipes = append(pipes, done)
		}
		cur = &shellPipeline{}
		return done
	}
	for i, t := range toks {
		if t.op == "" {
			switch redirect {
			case "<<<":
				cmd.here = t.word
			case "":
				cmd.args = append(cmd.args, t)
			}
			redirect = ""
			prevOp = ""
			continue
		}
		switch t.op {
		case "<<<", "<<", "<<-", "<", ">", ">>", ">&", "&>":
			redirect = t.op
		case "|":
			endCommand()
		case "\n":
			if prevOp == "|" || prevOp == "&&" || prevOp == "||" {
				continue
			}
			endPipeline()
		case ";", ";;", "&", "&&", "||":
			endPipeline()
		case "$(":
			assigned := ""
			if len(cur.cmds) == 0 && len(cmd.args) == 1 && strings.HasSuffix(cmd.args[0].word, "=") {
				assigned = strings.TrimSuffix(cmd.args[0].word, "=")
			}
			endPipeline()
			substs = append(substs, assigned)
		case "(":
			if len(cur.cmds) == 0 && len(cmd.args) == 1 && i+1 < len(toks) && toks[i+1].op == ")" {
				awaitBody = cmd.args[0].word
				cmd = &shellCommand{}
				break
			}
			endPipeline()
			substs = append(substs, "")
		case ")":
			if awaitBody != "" && i > 0 && toks[i-1].op == "(" {
				break
			}
			done := endPipeline()
			if len(substs) > 0 {
				assigned := substs[len(substs)-1]
				substs = substs[:len(substs)-1]
				if assigned != "" && len(done.cmds) == 1 && done.cmds[0].name() == "dra-plugin-log" {
					pluginLogs[fn()+"\x00"+assigned] = true
				}
			}
		case "{":
			endPipeline()
			depth++
			if awaitBody != "" {
				fns = append(fns, fnScope{awaitBody, depth})
				awaitBody = ""
			}
		case "}":
			endPipeline()
			if len(fns) > 0 && fns[len(fns)-1].depth == depth {
				fns = fns[:len(fns)-1]
			}
			depth--
		}
		prevOp = t.op
	}
	endPipeline()
	return pipes, pluginLogs
}

var (
	pureVariable = regexp.MustCompile(`^\$(\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9*@#])$`)
	assignment   = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
	textArray    = regexp.MustCompile(`^([A-Z][A-Z0-9_]*_TEXT)=$`)
	arrayKey     = regexp.MustCompile(`^\[[^]]*\]=`)
	eventList    = regexp.MustCompile(`for t in \[(.*?)\]\) for e in items`)
	pyString     = regexp.MustCompile(`'((?:[^'\\]|\\.)*)'`)
	awkRegexp    = regexp.MustCompile(`/((?:[^/\\\n]|\\.)+)/`)
)

// shellFile is the context of one shell file.
type shellFile struct {
	c      *collection
	path   string
	where  string
	values map[string][]string // the values assigned to each variable
}

// collectShell adds the strings of the shell file path.
func collectShell(c *collection, root, path string) error {
	data, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		return err
	}
	toks, err := shellTokens(string(data), 1)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	f := &shellFile{c: c, path: path, where: shellWhere(path), values: map[string][]string{}}
	pipes, pluginLogs := shellPipelines(toks)
	for _, p := range pipes {
		for _, cmd := range p.cmds {
			if len(cmd.args) != 1 {
				continue
			}
			if m := assignment.FindStringSubmatch(cmd.args[0].word); m != nil {
				f.values[m[1]] = append(f.values[m[1]], m[2])
			}
		}
	}
	f.arrays(toks)
	f.pipelines(pipes, pluginLogs)
	return nil
}

// shellWhere returns the name of the test or the file of path, for pins.
func shellWhere(path string) string {
	parts := strings.Split(path, "/")
	n := len(parts)
	if n >= 2 && strings.HasPrefix(parts[n-2], "test") {
		if parts[n-1] == "code.var.sh" {
			return parts[n-2]
		}
		return parts[n-2] + " " + parts[n-1]
	}
	return parts[n-1]
}

// pin returns the pin of a string found by how in function fn.
func (f *shellFile) pin(fn, how string) string {
	if fn != "" {
		return fmt.Sprintf("%s %s (%s)", f.where, fn, how)
	}
	return fmt.Sprintf("%s (%s)", f.where, how)
}

// resolve returns text, or the value of the variable that text is, and
// whether that is a text of its own.
func (f *shellFile) resolve(text string) (string, bool) {
	if !pureVariable.MatchString(text) {
		return text, text != ""
	}
	name := strings.Trim(text, "${}")
	values := f.values[name]
	if len(values) == 0 {
		return "", false
	}
	for _, v := range values[1:] {
		if v != values[0] {
			return "", false
		}
	}
	v := values[0]
	if v == "" || pureVariable.MatchString(v) || strings.Contains(v, "$(") {
		return "", false
	}
	return v, true
}

// add adds text, resolved, as a string of kind k and returns its entry, nil
// if text does not resolve.
func (f *shellFile) add(k kind, name, text, fn, how string) *entry {
	if v, ok := f.resolve(text); ok {
		return f.c.add(k, name, v, f.pin(fn, how))
	}
	return nil
}

// arrays adds the values of the arrays *_TEXT=(...) as event texts.
func (f *shellFile) arrays(toks []shellToken) {
	for i := 0; i+1 < len(toks); i++ {
		m := textArray.FindStringSubmatch(toks[i].word)
		if toks[i].op != "" || m == nil || toks[i+1].op != "(" {
			continue
		}
		for j := i + 2; j < len(toks) && toks[j].op != ")"; j++ {
			if toks[j].op == "" {
				f.add(kindEvent, "", arrayKey.ReplaceAllString(toks[j].word, ""), "", m[1])
			}
		}
	}
}

// pipelines adds the strings of the matchers and the log readers of pipes.
func (f *shellFile) pipelines(pipes []*shellPipeline, pluginLogs map[string]bool) {
	for _, p := range pipes {
		for i, cmd := range p.cmds {
			name := cmd.name()
			args := words(cmd.args)
			if m, ok := shellMatchers[name]; ok && len(args) > 1+m.first {
				texts := args[1+m.first : 2+m.first]
				if m.all {
					texts = args[1+m.first:]
				}
				for _, t := range texts {
					if t == "--" {
						break
					}
					f.add(m.kind, "", t, p.fn, name)
				}
			}
			if strings.HasSuffix(f.path, "/mbt.source.sh") && len(args) == 1 {
				if a := assignment.FindStringSubmatch(args[0]); a != nil && executorLines[a[1]] != "" {
					f.c.add(kindExecutor, executorLines[a[1]], a[2], f.pin("", a[1]))
				}
			}
			if name == "dra-wait" {
				for _, a := range args {
					for _, list := range eventList.FindAllStringSubmatch(a, -1) {
						for _, s := range pyString.FindAllStringSubmatch(list[1], -1) {
							f.add(kindEvent, "", s[1], p.fn, "dra-wait events")
						}
					}
				}
			}
			if name == "dra-plugin-log" && i+1 < len(p.cmds) {
				next := p.cmds[i+1]
				displayOnly := i+2 < len(p.cmds) && (p.cmds[i+2].name() == "tail" || p.cmds[i+2].name() == "head")
				f.logReader(next, p.fn, "dra-plugin-log | ", displayOnly)
			}
			if name == "grep" && cmd.here != "" && pureVariable.MatchString(cmd.here) &&
				pluginLogs[p.fn+"\x00"+strings.Trim(cmd.here, "${}")] {
				f.logReader(cmd, p.fn, "dra-plugin-log output | ", false)
			}
			for _, a := range cmd.args {
				if a.single && strings.Contains(a.word, "dra-plugin-log") {
					f.reparse(a, p.fn, pluginLogs)
				}
			}
		}
	}
}

// reparse adds the strings of the shell code in the single-quoted word w.
func (f *shellFile) reparse(w shellToken, fn string, pluginLogs map[string]bool) {
	toks, err := shellTokens(w.word, w.line)
	if err != nil {
		return
	}
	pipes, _ := shellPipelines(toks)
	for _, p := range pipes {
		p.fn = fn
	}
	f.pipelines(pipes, pluginLogs)
}

// logReader adds the patterns of the grep, awk or sed command cmd that reads
// the log of the driver.
func (f *shellFile) logReader(cmd *shellCommand, fn, how string, displayOnly bool) {
	args := words(cmd.args)
	switch cmd.name() {
	case "grep":
		if displayOnly {
			return
		}
		opts, patterns := grepArgs(args[1:])
		for _, p := range patterns {
			e := f.add(kindLog, "", p, fn, how+"grep"+opts)
			if strings.Contains(opts, "E") {
				e.markRegexp(dialect{fold: strings.Contains(opts, "i")})
			}
		}
	case "awk":
		for i := 1; i < len(args); i++ {
			if args[i] == "-v" && i+1 < len(args) {
				i++
				if a := assignment.FindStringSubmatch(args[i]); a != nil {
					f.add(kindLog, "", a[2], fn, how+"awk -v "+a[1]).markRegexp(dialect{})
				}
				continue
			}
			if !strings.HasPrefix(args[i], "-") {
				for _, m := range awkRegexp.FindAllStringSubmatch(args[i], -1) {
					f.add(kindLog, "", m[1], fn, how+"awk").markRegexp(dialect{})
				}
			}
		}
	case "sed":
		for _, a := range args[1:] {
			if len(a) > 2 && a[0] == 's' {
				parts := strings.Split(a[2:], a[1:2])
				f.add(kindLog, "", parts[0], fn, how+"sed").markRegexp(dialect{basic: true})
			}
		}
	}
}

// grepArgs returns the options and the patterns of the arguments of grep.
func grepArgs(args []string) (string, []string) {
	var (
		opts     string
		patterns []string
	)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if i+1 < len(args) && len(patterns) == 0 {
				patterns = append(patterns, args[i+1])
			}
			return opts, patterns
		case a == "-e" && i+1 < len(args):
			patterns = append(patterns, args[i+1])
			i++
		case a == "-m" || a == "-A" || a == "-B" || a == "-C" || a == "-f":
			i++
		case strings.HasPrefix(a, "-") && len(a) > 1:
			opts += " " + a
		default:
			if len(patterns) == 0 {
				patterns = append(patterns, a)
			}
			return opts, patterns
		}
	}
	return opts, patterns
}

// words returns the texts of the word tokens toks.
func words(toks []shellToken) []string {
	out := make([]string, len(toks))
	for i, t := range toks {
		out[i] = t.word
	}
	return out
}

//
// test90 observer and oracle
//

// observerNames are the names of mbt-observe.py that hold paths, labels and
// names of the driver.
var observerNames = []string{
	"LOCAL_DIR", "POOL_DIR", "POOL_MOUNTS", "LEASE_FS", "LEASES_DIR", "LEASE_FS_CTR",
	"LEASE_LABEL", "REQUESTER_LABEL", "DRIVER_LABEL", "DRIVER_CONTAINER", "POOL_DRIVER", "CXL_REQUEST",
}

var (
	pyAssign    = regexp.MustCompile(`^([A-Z][A-Z0-9_]*) = (.+)$`)
	pyCompile   = regexp.MustCompile(`^re\.compile\(r"(.*)"\)$`)
	pyLiteral   = regexp.MustCompile(`^"((?:[^"\\]|\\.)*)"$`)
	pyCount     = regexp.MustCompile(`^\s+\("(\w+)", re\.compile\(r"(.*)"\)\),?$`)
	pyStateFile = regexp.MustCompile(`\("(\w+)", ([A-Z_]+) \+ "/([^"]+)", `)
	pyGet       = regexp.MustCompile(`\.get\("(\w+)"\)|\["(\w+)"\]`)
	pyTuple     = regexp.MustCompile(`(?s)(?:keys = |for k in )\(([^)]*)\)`)
	pyQuoted    = regexp.MustCompile(`"(\w+)"`)
	pyGlob      = regexp.MustCompile(`glob\.glob\(d \+ "/([^"]+)"\)`)
)

// collectObserver adds the strings of test90's mbt-observe.py.
func collectObserver(c *collection, root string) error {
	const file = "mbt-observe.py"
	data, err := os.ReadFile(filepath.Join(root, test90Dir, file))
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	pin := func(what string) string { return "test90 " + file + " " + what }

	// The log patterns, from PANIC to the end of LOG_COUNTS.
	start, end := -1, -1
	for i, l := range lines {
		if start < 0 && strings.HasPrefix(l, "PANIC = ") {
			start = i
		}
		if start >= 0 && strings.HasPrefix(l, "LOG_COUNTS = [") {
			for j := i + 1; j < len(lines); j++ {
				if lines[j] == "]" {
					end = j
					break
				}
			}
			break
		}
	}
	if start < 0 || end < 0 {
		return fmt.Errorf("%s: no PANIC ... LOG_COUNTS block", file)
	}
	for _, l := range lines[start:end] {
		if m := pyCount.FindStringSubmatch(l); m != nil {
			c.add(kindObserver, "LogCount"+camel(m[1]), m[2], pin("LOG_COUNTS "+m[1]+" (Python regular expression)")).markRegexp(dialect{})
			continue
		}
		m := pyAssign.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if r := pyCompile.FindStringSubmatch(m[2]); r != nil {
			c.add(kindObserver, camelUpper(m[1]), r[1], pin(m[1]+" (Python regular expression)")).markRegexp(dialect{})
		} else if s := pyLiteral.FindStringSubmatch(m[2]); s != nil {
			c.add(kindObserver, camelUpper(m[1]), s[1], pin(m[1]+" (substring)"))
		}
	}

	// The names, evaluated as concatenations of strings and names.
	values := map[string]string{}
	for _, l := range lines {
		m := pyAssign.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		v, ok := pyConcat(m[2], values)
		if ok {
			values[m[1]] = v
		}
	}
	for _, n := range observerNames {
		v, ok := values[n]
		if !ok {
			return fmt.Errorf("%s: no string %s", file, n)
		}
		c.add(kindName, camelUpper(n), v, pin(n))
	}

	body := func(fn string) (string, error) {
		for i, l := range lines {
			if strings.HasPrefix(l, "def "+fn+"(") {
				j := i + 1
				for j < len(lines) && (lines[j] == "" || strings.HasPrefix(lines[j], " ")) {
					j++
				}
				return strings.Join(lines[i:j], "\n"), nil
			}
		}
		return "", fmt.Errorf("%s: no function %s", file, fn)
	}

	// The state view files and the fields read from them.
	views := map[string]string{} // observer key -> file name
	b, err := body("state")
	if err != nil {
		return err
	}
	for _, m := range pyStateFile.FindAllStringSubmatch(b, -1) {
		if _, ok := values[m[2]]; !ok {
			return fmt.Errorf("%s: state(): unknown directory %s", file, m[2])
		}
		views[m[1]] = m[3]
		c.add(kindView, viewName(m[3]), m[3], pin("state() "+m[1]+", in "+m[2]))
	}
	for _, fv := range []struct{ fn, key string }{{"local_devices", "localDevices"}, {"pool_claims", "pool"}} {
		view, ok := views[fv.key]
		if !ok {
			return fmt.Errorf("%s: state() reads no %s", file, fv.key)
		}
		b, err := body(fv.fn)
		if err != nil {
			return err
		}
		var fields []string
		for _, m := range pyGet.FindAllStringSubmatch(b, -1) {
			fields = append(fields, m[1]+m[2])
		}
		for _, t := range pyTuple.FindAllStringSubmatch(b, -1) {
			for _, q := range pyQuoted.FindAllStringSubmatch(t[1], -1) {
				fields = append(fields, q[1])
			}
		}
		for _, field := range fields {
			c.add(kindField, viewName(view)+camel(field), field, pin(fv.fn+"()"))
		}
	}

	b, err = body("cdi_pool")
	if err != nil {
		return err
	}
	for _, m := range pyGlob.FindAllStringSubmatch(b, -1) {
		c.add(kindName, "CDIPoolSpecGlob", m[1], pin("cdi_pool() (glob)"))
	}
	return nil
}

// pyConcat returns the value of a Python expression of string literals and
// names joined by +.
func pyConcat(expr string, values map[string]string) (string, bool) {
	var b strings.Builder
	for _, part := range strings.Split(expr, " + ") {
		if s := pyLiteral.FindStringSubmatch(part); s != nil {
			b.WriteString(s[1])
		} else if v, ok := values[part]; ok {
			b.WriteString(v)
		} else {
			return "", false
		}
	}
	return b.String(), true
}

// collectOracle adds the string constants of test90's model/oracle*.go and
// the fields of leases.json that its checkLeaseStore decodes.
func collectOracle(c *collection, root string) error {
	files, err := filepath.Glob(filepath.Join(root, test90Dir, "model", "oracle*.go"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	found := false
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file := "model/" + filepath.Base(path)
		af, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, d := range af.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				if d.Tok != token.CONST {
					continue
				}
				for _, spec := range d.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, v := range vs.Values {
						lit, ok := v.(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING || i >= len(vs.Names) {
							continue
						}
						text, err := strconv.Unquote(lit.Value)
						if err != nil {
							return fmt.Errorf("%s: %w", file, err)
						}
						name := vs.Names[i].Name
						c.add(kindOracle, camel(name), text, "test90 "+file+" "+name)
					}
				}
			case *ast.FuncDecl:
				if d.Name.Name == "checkLeaseStore" {
					found = leaseStoreFields(c, file, d.Body) || found
				}
			}
		}
	}
	if !found {
		return fmt.Errorf("model/oracle*.go: no var store in checkLeaseStore")
	}
	return nil
}

// leaseStoreFields adds the json fields of the variable store in body and
// returns whether body has one.
func leaseStoreFields(c *collection, file string, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "store" {
			return true
		}
		found = true
		ast.Inspect(vs.Type, func(n ast.Node) bool {
			fl, ok := n.(*ast.Field)
			if !ok || fl.Tag == nil {
				return true
			}
			tag, err := strconv.Unquote(fl.Tag.Value)
			if err != nil {
				return true
			}
			name := strings.Split(reflect.StructTag(tag).Get("json"), ",")[0]
			c.add(kindField, "Leases"+camel(name), name, "test90 "+file+" checkLeaseStore")
			return true
		})
		return false
	})
	return found
}

//
// Documentation
//

var (
	mentionsLog = regexp.MustCompile(`(?i)\blog(s|ged|ging)?\b`)
	codeSpan    = regexp.MustCompile("`([^`]+)`")
	sentenceEnd = regexp.MustCompile(`[.;:]\s+`)
	spanRef     = regexp.MustCompile("\x00([0-9]+)\x00")
)

// collectDocs adds the log lines that docs/memory/cxl/*.md quote.
func collectDocs(c *collection, root string) error {
	files, err := filepath.Glob(filepath.Join(root, docsDir, "*.md"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no files %s/*.md", docsDir)
	}
	sort.Strings(files)
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		collectDoc(c, docsDir+"/"+filepath.Base(path), string(data))
	}
	return nil
}

// collectDoc adds the log lines of the markdown text of file.
func collectDoc(c *collection, file, text string) {
	var (
		lines    = strings.Split(text, "\n")
		section  string
		para     []string // the paragraph being read
		prevPara []string // the paragraph before the blank lines being read
		lastLog  bool     // the last fenced block was a block of log lines
	)
	pin := func() string {
		if section == "" {
			return file
		}
		return fmt.Sprintf("%s section %q", file, section)
	}
	flush := func() {
		if len(para) == 0 {
			return
		}
		// Split sentences outside the code spans only.
		var spans []string
		flat := codeSpan.ReplaceAllStringFunc(strings.Join(para, " "), func(m string) string {
			spans = append(spans, strings.Trim(m, "`"))
			return fmt.Sprintf("\x00%d\x00", len(spans)-1)
		})
		for _, s := range sentenceEnd.Split(flat, -1) {
			if !mentionsLog.MatchString(spanRef.ReplaceAllString(s, " ")) {
				continue
			}
			for _, m := range spanRef.FindAllStringSubmatch(s, -1) {
				n, _ := strconv.Atoi(m[1])
				if span := spans[n]; len(span) >= 20 && strings.Contains(span, ": ") && !strings.Contains(span, "{") {
					c.add(kindDoc, "", span, pin())
				}
			}
		}
		prevPara = para
		para = nil
	}
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		trimmed := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(trimmed, "```"):
			j := i + 1
			for j < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[j]), "```") {
				j++
			}
			flush()
			introPara := prevPara
			intro := strings.Join(introPara, " ")
			continuation := lastLog && len(introPara) == 1 && strings.HasSuffix(intro, ",")
			isLog := strings.TrimPrefix(trimmed, "```") == "" && (mentionsLog.MatchString(intro) || continuation)
			if isLog {
				for _, b := range lines[i+1 : min(j, len(lines))] {
					if b = strings.TrimSpace(b); b != "" {
						c.add(kindDoc, "", b, pin())
					}
				}
			}
			lastLog = isLog
			prevPara = nil
			i = j
		case trimmed == "":
			flush()
		case strings.HasPrefix(trimmed, "#"):
			flush()
			prevPara = nil
			section = strings.TrimSpace(strings.TrimLeft(trimmed, "#"))
			lastLog = false
		default:
			para = append(para, trimmed)
		}
	}
	flush()
}

//
// Names and rendering
//

var (
	nameWord = regexp.MustCompile(`[A-Za-z0-9]+`)
	// expansionVariable is the variable name in a shell expansion.
	expansionVariable = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
)

// maxNameWords is the number of words of a text that its derived name has.
const maxNameWords = 8

// camel returns s with its first letter upper-cased, or upper-cased if it
// is an initialism.
func camel(s string) string {
	if s == "" {
		return s
	}
	if initialisms[strings.ToUpper(s)] {
		return strings.ToUpper(s)
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// camelUpper returns the CamelCase of an UPPER_SNAKE name, keeping the
// initialisms of initialisms.
func camelUpper(s string) string {
	var b strings.Builder
	for _, w := range strings.Split(s, "_") {
		if initialisms[w] {
			b.WriteString(w)
		} else {
			b.WriteString(camel(strings.ToLower(w)))
		}
	}
	return b.String()
}

var initialisms = map[string]bool{"CDI": true, "CXL": true, "DRA": true, "FS": true, "ID": true, "NRI": true}

// viewName returns the name of a view file name.
func viewName(file string) string {
	return camel(strings.TrimSuffix(file, filepath.Ext(file)))
}

// derivedName returns a name of text from its first words, a shell expansion
// giving the name of its variable as a word.
func derivedName(text string) string {
	var b strings.Builder
	text = templateExpansion.ReplaceAllStringFunc(text, func(x string) string {
		return " " + camelUpper(expansionVariable.FindString(x)) + " "
	})
	for i, w := range nameWord.FindAllString(text, -1) {
		if i == maxNameWords {
			break
		}
		b.WriteString(camel(w))
	}
	if b.Len() == 0 {
		return "Text"
	}
	return b.String()
}

// constNames returns the constant name of every entry: the kind prefix and
// the given or derived name, and for derived names that several texts share,
// a suffix "H" and 6 hex digits of the FNV-1a hash of the text. So a name
// always means the same text: when a new text collides with a name, the name
// goes away and code using it stops compiling. A collision left after that
// is an error.
func constNames(entries []*entry) (map[*entry]string, error) {
	base := map[*entry]string{}
	count := map[string]int{}
	for _, e := range entries {
		name := e.name
		if name == "" {
			name = derivedName(e.text)
		}
		base[e] = kinds[e.kind].prefix + name
		count[base[e]]++
	}
	names := map[*entry]string{}
	owner := map[string]*entry{}
	for _, e := range entries {
		name := base[e]
		if count[name] > 1 {
			if e.name != "" {
				return nil, fmt.Errorf("name %s given to several texts, one is %q", name, e.text)
			}
			h := fnv.New32a()
			h.Write([]byte(e.text))
			name = fmt.Sprintf("%sH%06x", name, h.Sum32()&0xffffff)
		}
		if o, ok := owner[name]; ok {
			return nil, fmt.Errorf("name %s of both %q and %q", name, o.text, e.text)
		}
		owner[name] = e
		names[e] = name
	}
	return names, nil
}

// render returns the source of strings.go for the entries.
func render(entries []*entry) ([]byte, error) {
	names, err := constNames(entries)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(header)
	for k := range kinds {
		var group []*entry
		for _, e := range entries {
			if e.kind == kind(k) {
				group = append(group, e)
			}
		}
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n// %s\nconst (\n", kinds[k].title)
		for i, e := range group {
			if i > 0 {
				b.WriteString("\n")
			}
			for _, l := range wrap(kinds[k].verb+" "+strings.Join(e.pins, ", ")+".", 96) {
				fmt.Fprintf(&b, "\t// %s\n", l)
			}
			fmt.Fprintf(&b, "\t%s = %s\n", names[e], goString(e.text))
		}
		b.WriteString(")\n")
	}
	b.WriteString("\n// regexps are the constants that are regular expressions and their dialects.\n" +
		"var regexps = []struct {\n\tpattern string\n\tdialect\n}{\n")
	for _, e := range entries {
		if e.re != nil {
			fmt.Fprintf(&b, "\t{%s, dialect{basic: %v, fold: %v}},\n", names[e], e.re.basic, e.re.fold)
		}
	}
	b.WriteString("}\n")
	return format.Source(b.Bytes())
}

const header = `// Copyright The NRI Plugins Authors. All Rights Reserved.
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

// Code generated by go generate (TestStringsUpToDate -update); DO NOT EDIT.

package compat

// The strings are as the tests match them: $NAME, ${...} and $* stand for
// values that a test substitutes, and <...> in a documented line is a
// placeholder. The patterns of grep -E, awk, sed and the observer's Python
// are regular expressions, listed in regexps at the end: match them with
// MatchesRegexp, the other constants with Matches.
`

// goString returns text as a Go string literal, a raw one when that is
// easier to read.
func goString(text string) string {
	if strings.ContainsAny(text, "\"\\") && !strings.ContainsAny(text, "`\n") {
		return "`" + text + "`"
	}
	return strconv.Quote(text)
}

// wrap returns the words of s in lines of at most width bytes.
func wrap(s string, width int) []string {
	var (
		lines []string
		cur   string
	)
	for _, w := range strings.Fields(s) {
		if cur != "" && len(cur)+1+len(w) > width {
			lines = append(lines, cur)
			cur = w
			continue
		}
		if cur != "" {
			cur += " "
		}
		cur += w
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}
