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

// Package compat holds the texts and names of the driver that its tests and
// documentation depend on: the log lines and error texts that the e2e tests
// match, the cxl-request output they expect, the log patterns, paths, names
// and fields of state.json that the test90 observer reads, the texts that
// its oracle matches, and the log lines that docs/memory/cxl quotes.
// strings.go is generated from those sources (go generate runs
// TestStringsUpToDate with -update), and the unit tests fail when it differs
// from what the sources say now. Matches and MatchesRegexp tell whether a
// line of the driver has a constant's text, so that the unit test of the
// code that emits a pinned text can assert it.
package compat

//go:generate go test -run TestStringsUpToDate -update
