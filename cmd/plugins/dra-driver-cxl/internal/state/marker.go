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
	"strconv"
	"strings"

	"github.com/containers/nri-plugins/pkg/cxl/api"
)

// The result marker CXL_CLAIM_<uid>_<n>=1 is in the environment of the CDI
// device of every allocation result n of a claim: the NRI plugin finds the
// results that a container uses by their markers.

// ResultEnvVarName returns the name of the marker of the allocation result
// n of a claim, CXL_CLAIM_<uid>_<n> with the hyphens of the UID replaced by
// underscores (env var names have no hyphens).
func ResultEnvVarName(claimUID string, n int) string {
	return api.ClaimEnvPrefix + strings.ReplaceAll(claimUID, "-", "_") + "_" + strconv.Itoa(n)
}

// ResultFromEnvVar returns the claim UID and the allocation result of a
// result marker "CXL_CLAIM_<uid>_<n>=<value>", and false for other
// environment variables.
func ResultFromEnvVar(envVar string) (string, int, bool) {
	key, _, _ := strings.Cut(envVar, "=")
	rest, ok := strings.CutPrefix(key, api.ClaimEnvPrefix)
	if !ok {
		return "", 0, false
	}
	i := strings.LastIndexByte(rest, '_')
	if i <= 0 {
		return "", 0, false
	}
	n, err := strconv.Atoi(rest[i+1:])
	if err != nil || n < 0 || strconv.Itoa(n) != rest[i+1:] {
		return "", 0, false
	}
	return strings.ReplaceAll(rest[:i], "_", "-"), n, true
}
