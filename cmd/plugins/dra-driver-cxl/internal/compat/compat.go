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
	"regexp"
	"strings"
)

// dialect is the syntax of a regular expression constant.
type dialect struct {
	basic bool // POSIX basic (sed), else extended (grep -E, awk, Python re)
	fold  bool // case-insensitive (grep -i)
}

// templateExpansion matches a shell expansion in a constant: $NAME, ${...}, $1, $*,
// $@ and $#.
var templateExpansion = regexp.MustCompile(`\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9*@#]`)

// Matches returns whether line contains the text of template, a constant
// that is no regular expression, with each shell expansion of the template
// standing for any text.
func Matches(template, line string) bool {
	var b strings.Builder
	last := 0
	for _, loc := range templateExpansion.FindAllStringIndex(template, -1) {
		b.WriteString(regexp.QuoteMeta(template[last:loc[0]]))
		b.WriteString(".*")
		last = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(template[last:]))
	return regexp.MustCompile(b.String()).MatchString(line)
}

// MatchesRegexp returns whether line has a match of pattern, a constant
// that is a regular expression, in its dialect (POSIX basic for sed, extended
// otherwise, case-insensitive for grep -i), with each shell expansion of the
// pattern standing for any text. It returns an error if pattern is no
// regular expression constant or does not compile.
func MatchesRegexp(pattern, line string) (bool, error) {
	var (
		d     dialect
		found bool
	)
	for _, r := range regexps {
		if r.pattern == pattern {
			d, found = r.dialect, true
			break
		}
	}
	if !found {
		return false, &notRegexpError{pattern}
	}
	expr := templateExpansion.ReplaceAllLiteralString(pattern, "\x00")
	if d.basic {
		expr = extendedOfBasic(expr)
	}
	expr = strings.ReplaceAll(expr, "\x00", ".*")
	if d.fold {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return false, err
	}
	return re.MatchString(line), nil
}

// extendedOfBasic returns the extended regular expression of a POSIX basic
// one: \( \) \{ \} \| \+ \? are operators there, the bare characters literal.
func extendedOfBasic(expr string) string {
	var b strings.Builder
	for i := 0; i < len(expr); i++ {
		ch := expr[i]
		switch {
		case ch == '\\' && i+1 < len(expr):
			next := expr[i+1]
			if strings.IndexByte("(){}|+?", next) >= 0 {
				b.WriteByte(next)
			} else {
				b.WriteByte(ch)
				b.WriteByte(next)
			}
			i++
		case strings.IndexByte("(){}|+?", ch) >= 0:
			b.WriteByte('\\')
			b.WriteByte(ch)
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}

// notRegexpError is the error of MatchesRegexp for a pattern that is no
// regular expression constant.
type notRegexpError struct {
	pattern string
}

// Error returns the text of the error.
func (e *notRegexpError) Error() string {
	return "not a regular expression constant of compat: " + e.pattern
}
