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
		if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
			return nil, fmt.Errorf("failed to create prepared claims file %s: %w", path, err)
		}
		return claimPreparations{}, nil
	}
	return readPreparedClaimsFromFile(path)
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

// writePreparedClaimsToFile writes the prepared claims to the file path.
func writePreparedClaimsToFile(path string, prepared claimPreparations) error {
	if prepared == nil {
		prepared = claimPreparations{}
	}
	data, err := json.MarshalIndent(prepared, "", "  ")
	if err != nil {
		return fmt.Errorf("prepared claims JSON encoding failed: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}
