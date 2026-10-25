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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/klog/v2"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"
)

// claimPreparations maps claim UIDs to the results of their Prepares.
type claimPreparations map[string]kubeletplugin.PrepareResult

// baseState is the part of the node state that every claim uses: the
// devices, the prepared claims and the file where they are kept. Its mutex
// guards Allocatable and Prepared.
type baseState struct {
	sync.Mutex
	CdiCache               *cdiapi.Cache
	Allocatable            any
	Prepared               claimPreparations
	PreparedClaimsFilePath string
	NodeName               string
}

// getOrCreatePreparedClaims returns the prepared claims of the file path,
// and creates the file with no claims if it does not exist.
func getOrCreatePreparedClaims(path string) (claimPreparations, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		klog.V(5).Infof("Creating prepared claims file %s", path)
		if err := writeJSONFile(path, claimPreparations{}); err != nil {
			return nil, fmt.Errorf("failed to create prepared claims file %s: %w", path, err)
		}
		return claimPreparations{}, nil
	}
	return readPreparedClaimsFromFile(path)
}

// loadPreparedClaims returns the prepared claims of the file path
// (preparedClaims.json) and their info from preparedClaimsInfo.json next to
// it, both created empty if missing, made consistent with
// reconcilePreparedClaims, and the UIDs of the claims that it forgot.
func loadPreparedClaims(path string) (claimPreparations, PreparedClaimsInfo, []string, []string, error) {
	prepared, err := getOrCreatePreparedClaims(path)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	infos, err := getOrCreatePreparedClaimsInfo(filepath.Join(filepath.Dir(path), preparedClaimsInfoFileName))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	preparing, unpreparing := reconcilePreparedClaims(prepared, infos)
	return prepared, infos, preparing, unpreparing, nil
}

// reconcilePreparedClaims makes the two files of the prepared claims agree
// after a crash between their writes (persist writes preparedClaims.json,
// then preparedClaimsInfo.json; bug-07): a claim is prepared only when
// both have it, and the other entries are dropped from the maps.
//   - preparing: claims that only preparedClaims.json has (or with no info),
//     a crash in their Prepare: its device work is done, its info is lost.
//     They are not prepared: the local allocator releases their memory (it
//     takes the claims of both files, newLocalHelper) and the Prepare that
//     kubelet retries prepares them again, as after a crash before the
//     first write. Kept, the claim would be "already prepared" with CDI
//     devices that the spec, built from the info, does not have.
//   - unpreparing: claims that only preparedClaimsInfo.json has, a crash in
//     their Unprepare (or the rollback of a failed Prepare): their devices
//     are released already, the second write would have dropped them. Kept,
//     their info would hold their fenced node and lend for ever, as the
//     retried Unprepare finds no prepared claim.
func reconcilePreparedClaims(prepared claimPreparations, infos PreparedClaimsInfo) (preparing, unpreparing []string) {
	for uid := range prepared {
		if infos[uid] == nil {
			delete(prepared, uid)
			delete(infos, uid)
			preparing = append(preparing, uid)
		}
	}
	for uid := range infos {
		if _, ok := prepared[uid]; !ok {
			delete(infos, uid)
			unpreparing = append(unpreparing, uid)
		}
	}
	sort.Strings(preparing)
	sort.Strings(unpreparing)
	return preparing, unpreparing
}

// readPreparedClaimsFromFile returns the prepared claims of the file path.
func readPreparedClaimsFromFile(path string) (claimPreparations, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read prepared claims file %s: %w", path, err)
	}
	prepared := claimPreparations{}
	if err := json.Unmarshal(data, &prepared); err != nil {
		return nil, fmt.Errorf("failed to parse prepared claims file %s: %w", path, err)
	}
	return prepared, nil
}

// writePreparedClaimsToFile replaces the file path with the prepared claims
// (writeJSONFile: a crash leaves the old file or the new one, never a
// truncated one).
func writePreparedClaimsToFile(path string, prepared claimPreparations) error {
	if prepared == nil {
		prepared = claimPreparations{}
	}
	return writeJSONFile(path, prepared)
}
