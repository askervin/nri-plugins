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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// stateStore keeps the content of the state files of the driver in the
// records of the store's document: a write of a file is a commit that
// replaces the records of its owner, a read is the file as the records
// give it (the view of the file). The store writes the five views that
// test90's observer reads at the paths of the files.
type stateStore struct {
	st       *store.Store
	localDir string
	poolDir  string

	mu sync.Mutex
	// prepared is the content of preparedClaims.json that waits for the
	// write of preparedClaimsInfo.json that follows it: both go in one
	// commit.
	prepared []byte
}

// stateStoreConfig are the settings of the store of the state files.
type stateStoreConfig struct {
	// LocalDir and PoolDir are the plugin data directories of cxl.nri.io
	// and of the pool driver ("": none).
	LocalDir, PoolDir string
	PoolDriver        string
	BootID            string
	Flags             store.Flags
	// SysRoot and DevRoot are the sysfs mount point and the directory of
	// the device nodes of the memdevs.
	SysRoot, DevRoot string
	// DropOtherBoot is store.Options.DropOtherBoot: the drivers whose
	// preparations of another boot the load drops (dra.DropOtherBoot).
	DropOtherBoot func(driver string) bool
}

// openStateStore opens the store of the state files and registers them.
func openStateStore(ctx context.Context, cfg stateStoreConfig) (*stateStore, func(), error) {
	sysRoot := cfg.SysRoot
	st, err := store.Open(ctx, store.Options{
		Dir:             cfg.LocalDir,
		PoolDir:         cfg.PoolDir,
		PoolDriver:      cfg.PoolDriver,
		BootID:          cfg.BootID,
		NewState:        cfg.Flags.NewState,
		DiscardOldState: cfg.Flags.DiscardOldState,
		CompatViews:     cfg.Flags.CompatViews,
		SysRoot:         sysRoot,
		DevRoot:         cfg.DevRoot,
		RegionExists: func(name string) bool {
			_, err := os.Stat(filepath.Join(sysRoot, "bus", "cxl", "devices", name))
			return err == nil
		},
		DropOtherBoot: cfg.DropOtherBoot,
	})
	if err != nil {
		return nil, nil, err
	}
	s := &stateStore{st: st, localDir: cfg.LocalDir, poolDir: cfg.PoolDir}
	unregister := registerStateFiles(s, s.paths()...)
	// unregistered after the close: a late write gets store.ErrClosed
	return s, func() {
		if err := st.Close(); err != nil {
			klog.Errorf("closing the state store: %v", err)
		}
		unregister()
	}, nil
}

// paths returns the paths of the state files of the store.
func (s *stateStore) paths() []string {
	paths := []string{
		filepath.Join(s.localDir, device.PreparedClaimsFileName),
		filepath.Join(s.localDir, preparedClaimsInfoFileName),
		filepath.Join(s.localDir, localStateFileName),
		filepath.Join(s.localDir, leasesFileName),
		filepath.Join(s.localDir, poolSerialsFileName),
	}
	if s.poolDir != "" {
		paths = append(paths, filepath.Join(s.poolDir, poolStateFileName), filepath.Join(s.poolDir, poolPreparingFileName))
	}
	return paths
}

// lostContent is the content of a state file of a store in LOST mode: none
// for the files whose loaders start empty without them, a content that does
// not decode for those whose loaders record its loss.
var lostContent = map[string]string{
	device.PreparedClaimsFileName: "{}",
	preparedClaimsInfoFileName:    "{}",
	leasesFileName:                "lost",
	poolSerialsFileName:           "lost",
}

// readState returns the content of the state file path from the records.
func (s *stateStore) readState(path string) ([]byte, error) {
	name := filepath.Base(path)
	if s.st.Lost() != nil {
		if c, ok := lostContent[name]; ok {
			return []byte(c), nil
		}
		return nil, notExist(path)
	}
	switch name {
	case poolPreparingFileName:
		return preparingContent(s.st.Snapshot(), s.st.ViewOptions())
	case poolSerialsFileName:
		if serialsFileContent == nil {
			return nil, notExist(path)
		}
		return serialsFileContent(s.st.Snapshot())
	}
	return s.st.View(name)
}

// writeState commits the content data of the state file path: the records
// of its owner become those of the content.
func (s *stateStore) writeState(path string, data []byte) error {
	name := filepath.Base(path)
	if lost := s.st.Lost(); lost != nil {
		return s.writeLost(path, data, lost)
	}
	if name == device.PreparedClaimsFileName {
		s.mu.Lock()
		s.prepared = data
		s.mu.Unlock()
		return nil
	}
	var stashed []byte
	if name == preparedClaimsInfoFileName {
		s.mu.Lock()
		stashed, s.prepared = s.prepared, nil
		s.mu.Unlock()
	}
	err := s.st.Commit(context.Background(), store.Durable, func(doc *store.Document) error {
		return putContent(doc, s.st.ViewOptions(), name, data, stashed)
	})
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// writeLost is a write of a store in LOST mode (D-50): the content that a
// read gives succeeds without a commit (the start writes the files it
// read), any other write fails with the error of the lost state.
func (s *stateStore) writeLost(path string, data []byte, lost error) error {
	if read, err := s.readState(path); err == nil && jsonSame(read, data) {
		return nil
	}
	return fmt.Errorf("writing %s: %w", path, lost)
}

// jsonSame tells whether a and b are the same JSON value.
func jsonSame(a, b []byte) bool {
	var va, vb any
	return json.Unmarshal(a, &va) == nil && json.Unmarshal(b, &vb) == nil && reflect.DeepEqual(va, vb)
}

// putLocalContent replaces the records of cxl.nri.io in a document with
// those of the content of one of its state files of an older driver, nil
// in the driver: only the tests write those files (state_local_test.go).
var putLocalContent func(doc *store.Document, opts store.ViewOptions, name string, data, preparedData []byte) error

// putLeasesContent replaces the lease claims and the leases in a document
// with those of the content of leases.json, nil in the driver: the lease
// broker keeps them in the store itself, only the tests write that file
// (state_leases_test.go).
var putLeasesContent func(doc *store.Document, data []byte) error

// leasesFileName is the view of the lease claims and the leases in the
// plugin data directory of cxl.nri.io.
const leasesFileName = store.ViewLeases

// serialsFileContent and putSerialsFileContent read and replace the
// provenance records of the serials in a document as the content of
// poolSerials.json, nil in the driver: only the tests read and write that
// file (state_serials_test.go).
var (
	serialsFileContent    func(doc *store.Document) ([]byte, error)
	putSerialsFileContent func(doc *store.Document, data []byte) error
)

// putContent replaces the records of the owner of the state file name in
// doc with those of its content data; prepared is the content of
// preparedClaims.json written with preparedClaimsInfo.json, nil for that
// of the document.
func putContent(doc *store.Document, opts store.ViewOptions, name string, data, prepared []byte) error {
	switch name {
	case preparedClaimsInfoFileName, localStateFileName:
		if putLocalContent != nil {
			return putLocalContent(doc, opts, name, data, prepared)
		}
	case poolStateFileName, poolPreparingFileName:
		return putPoolContent(doc, opts, name, data)
	case leasesFileName:
		if putLeasesContent != nil {
			return putLeasesContent(doc, data)
		}
	case poolSerialsFileName:
		if putSerialsFileContent != nil {
			return putSerialsFileContent(doc, data)
		}
	}
	return fmt.Errorf("no records of the state file %s", name)
}

// putPoolContent replaces the records of the pool driver in doc with those
// of the content of one of its state files and the other as doc has it.
func putPoolContent(doc *store.Document, opts store.ViewOptions, name string, data []byte) error {
	preparedData, preparingData := data, data
	var err error
	if name == poolStateFileName {
		preparingData, err = preparingContent(doc, opts)
	} else {
		preparedData, err = store.ViewContent(doc, store.ViewPreparedPoolClaims, opts)
	}
	if err != nil {
		return err
	}
	prepared := map[string]*preparedPoolClaim{}
	preparing := map[string]*preparingPoolClaim{}
	if err := json.Unmarshal(preparedData, &prepared); err != nil {
		return err
	}
	if err := json.Unmarshal(preparingData, &preparing); err != nil {
		return err
	}
	putPool(doc, opts.PoolDriver, prepared, preparing, name == poolPreparingFileName)
	return nil
}
