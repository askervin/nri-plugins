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
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// stateFilesMode keeps the state files of the tests in files
// (CXL_STATE_FILES=1): the driver's file writer as it was, for the
// characterization of the content that the store must give back. By
// default every test runs on stores.
var stateFilesMode = os.Getenv("CXL_STATE_FILES") != ""

// TestMain runs the tests with every state file kept in a store of its
// directory, read and written through the adapters of the store, and
// reports the writes whose content the store does not give back.
func TestMain(m *testing.M) {
	if stateFilesMode {
		stateAutoBackend = func(string) stateBackend { return fileBackend{} }
		os.Exit(m.Run())
	}
	stateAutoBackend = autoStateBackend
	code := m.Run()
	closeAutoStores()
	mismatches.Lock()
	for _, mm := range mismatches.list {
		fmt.Printf("STATE MISMATCH %s\n  written %s\n  read    %s\n", mm.path, compact(mm.written), compact(mm.read))
	}
	if len(mismatches.list) > 0 && code == 0 {
		code = 1
	}
	fmt.Printf("state store: %d writes checked, %d known mismatches, %d mismatches\n", mismatches.checked, mismatches.known, len(mismatches.list))
	for _, text := range slices.Sorted(maps.Keys(mismatches.violations)) {
		fmt.Printf("INVARIANT %dx %s\n", mismatches.violations[text], text)
	}
	if os.Getenv("CXL_STATE_INVARIANTS") != "" {
		fmt.Printf("state store: %d documents with invariant violations\n", mismatches.violated)
	}
	mismatches.Unlock()
	os.Exit(code)
}

// fileBackendOnly skips a test of the state files themselves, which a
// store does not keep as files, unless the files keep them.
func fileBackendOnly(t *testing.T, reason string) {
	t.Helper()
	if !stateFilesMode {
		t.Skipf("on the state store: %s (CXL_STATE_FILES=1 runs it)", reason)
	}
}

// fileBackend keeps the state files in the files, written as the driver's
// file writer wrote them.
type fileBackend struct{}

func (fileBackend) readState(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (fileBackend) writeState(path string, data []byte) error {
	return writeJSONFile(path, json.RawMessage(data))
}

// knownMismatches are the writes, by test and file, of content that the
// driver never writes and the store does not give back, with why the
// difference does not matter.
var knownMismatches = map[[2]string]string{
	{"TestPrepareLocalDax", device.PreparedClaimsFileName}: "the claim \"stale\" is made with an empty PrepareResult " +
		"and a device in its info: the driver writes a device of preparedClaims.json for every device of the info",
	{"TestPoolPreparingLoad", poolPreparingFileName}: "a preparing record of a claim that is not stale but prepared " +
		"is the window between the two files of a Prepare, which one record per claim does not have",
	{"TestPoolLeaseBindErrors", poolPreparingFileName}: "the claim l4 is deleted from the prepared claims in memory " +
		"only, and prepared again: its preparing record is of a claim of the state file, which stays prepared",
	{"TestLocalStateOfAnotherBoot", localStateFileName}: "the allocator of boot-1 releases after one of boot-2 started " +
		"on its files: two drivers of different boots at once, which a node does not have",
	{"TestPoolLeaseStaleBinds", poolPreparingFileName}: "the claim l4 is deleted from the prepared claims in memory " +
		"only, and prepared again: its preparing record is of a claim of the state file, which stays prepared",
}

// mismatches are the writes of state files whose content the store does
// not give back.
var mismatches struct {
	sync.Mutex
	checked, known int
	list           []mismatch
	// violations counts the kinds of invariant violations of the
	// documents after a write (state.Check, not checked by commits), and
	// violated the documents with one.
	violations map[string]int
	violated   int
}

type mismatch struct {
	path          string
	written, read []byte
}

// check records a mismatch when the content read differs from the content
// written as the loaders of the file read them (asRead), unless it is
// known.
func check(path string, written, read []byte) {
	var w, r any
	errW, errR := json.Unmarshal(written, &w), json.Unmarshal(read, &r)
	if errW == nil && errR == nil {
		asRead(filepath.Base(path), w, r)
	}
	mismatches.Lock()
	defer mismatches.Unlock()
	mismatches.checked++
	if errW == nil && errR == nil && reflect.DeepEqual(w, r) {
		return
	}
	for key := range knownMismatches {
		if key[1] == filepath.Base(path) && strings.Contains(path, "/"+key[0]) {
			mismatches.known++
			return
		}
	}
	mismatches.list = append(mismatches.list, mismatch{path: path, written: written, read: read})
}

// violationKind replaces the names and numbers of a violation's text.
var violationKind = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f-]{27}|[uU][0-9]+|0x[0-9a-f]+|region[0-9]+|dax[0-9.]+|[0-9]+`)

// checkInvariants counts the invariant violations of the document doc
// (with CXL_STATE_INVARIANTS).
func checkInvariants(doc *store.Document) {
	vs := state.Check(&doc.Records)
	if len(vs) == 0 {
		return
	}
	mismatches.Lock()
	defer mismatches.Unlock()
	if mismatches.violations == nil {
		mismatches.violations = map[string]int{}
	}
	mismatches.violated++
	for _, v := range vs {
		mismatches.violations[violationKind.ReplaceAllString(v.String(), "#")]++
	}
}

// asRead makes the content w written to the state file name and the
// content r read back the same where the loaders of the file read them the
// same:
//   - consumedBytes 0 of a memdev is its totalBytes (PreparedDeviceInfo.memory);
//     the driver writes the two the same for a memdev
//   - a null record of poolSerials.json is no record (loadPoolSerials)
//   - leases.json without a boot id is of the running boot (forgetOtherBoot)
func asRead(name string, w, r any) {
	switch name {
	case preparedClaimsInfoFileName:
		claims, _ := w.(map[string]any)
		for _, c := range claims {
			info, _ := c.(map[string]any)
			devices, _ := info["devices"].([]any)
			for _, d := range devices {
				dev, _ := d.(map[string]any)
				if dev["deviceType"] == device.DeviceTypeMemdev && dev["consumedBytes"] == float64(0) {
					dev["consumedBytes"] = dev["totalBytes"]
				}
			}
		}
	case poolSerialsFileName:
		file, _ := w.(map[string]any)
		if serials, ok := file["serials"].([]any); ok {
			file["serials"] = slices.DeleteFunc(serials, func(s any) bool { return s == nil })
		}
	case leasesFileName:
		file, _ := w.(map[string]any)
		if _, ok := file["bootID"]; !ok {
			delete(r.(map[string]any), "bootID")
		}
	}
}

// autoStores are the stores of the directories of state files, by
// directory; boots are the boot ids of the restarts of their drivers, by
// directory.
var autoStores, boots sync.Map

// stateFileNames are the names of the files that the store keeps.
var stateFileNames = map[string]bool{
	device.PreparedClaimsFileName: true, preparedClaimsInfoFileName: true, localStateFileName: true, leasesFileName: true,
	poolSerialsFileName: true, steeredFileName: true, poolStateFileName: true, poolPreparingFileName: true,
}

// restartStore is a restart of the driver in the boot bootID ("": not
// known) on the state files of dir: the store of dir is opened again as
// the driver opens it at its start, which handles a document of another
// boot (D-21, D-33) before the restarted code reads it.
func restartStore(dir, bootID string) {
	if stateFilesMode {
		return
	}
	boots.Store(dir, bootID)
	if v, ok := autoStores.Load(dir); ok {
		if err := v.(*autoBackend).reopen(func(o *store.Options) { o.BootID = bootID }); err != nil {
			panic(fmt.Sprintf("reopening the state store of %s: %v", dir, err))
		}
	}
}

// closeAutoStores closes the stores of the tests.
func closeAutoStores() {
	autoStores.Range(func(_, v any) bool {
		b := v.(*autoBackend)
		b.open.Lock()
		defer b.open.Unlock()
		_ = b.st.Close()
		return true
	})
}

// autoBackend is the store of a directory of a test: it takes the content
// of a file that a test wrote, writes the files that are not views as a
// test reads them, and learns the roots of the paths of the views from the
// content it is given.
type autoBackend struct {
	// open guards the store, which reopen replaces.
	open sync.RWMutex
	*stateStore
	opts store.Options

	mu               sync.Mutex
	sysRoot, devRoot bool
	written          map[string][]byte
	// prepared is the last content of preparedClaims.json written.
	prepared []byte
}

// autoStateBackend returns the backend of the directory of a state file:
// its store, the files of a directory that does not exist (whose writes
// fail as they do without a store), nil for another file.
func autoStateBackend(path string) stateBackend {
	if !stateFileNames[filepath.Base(path)] {
		return nil
	}
	dir := filepath.Dir(path)
	if b, ok := autoStores.Load(dir); ok {
		return b.(*autoBackend)
	}
	if !isDir(dir) {
		return fileBackend{}
	}
	// the files of the test, which the first start moves aside
	files := testFiles(dir, nil)
	opts := store.Options{Dir: dir, PoolDir: dir, PoolDriver: device.PoolDriverName, CompatViews: true,
		DropOtherBoot: func(driver string) bool { return driver == device.DriverName }}
	if boot, ok := boots.Load(dir); ok {
		opts.BootID = boot.(string)
	}
	st, err := store.Open(context.Background(), opts)
	if err != nil {
		panic(fmt.Sprintf("opening the state store of %s: %v", dir, err))
	}
	b := &autoBackend{stateStore: &stateStore{st: st, localDir: dir, poolDir: dir}, opts: opts, written: map[string][]byte{}}
	actual, loaded := autoStores.LoadOrStore(dir, b)
	if loaded {
		_ = st.Close()
		return actual.(*autoBackend)
	}
	b.restore(files)
	return b
}

// testFiles returns the state files in dir that a test wrote and the
// store did not read, by name; b is nil for a directory without a store.
func testFiles(dir string, b *autoBackend) map[string][]byte {
	files := map[string][]byte{}
	for _, name := range importOrder {
		path := filepath.Join(dir, name)
		if data, err := os.ReadFile(path); err == nil && (b == nil || !b.ours(path, data)) {
			files[name] = data
		}
	}
	return files
}

// restore writes the files of a test back, to be taken at their next read,
// and the files that are not views as the store has them.
func (b *autoBackend) restore(files map[string][]byte) {
	for _, name := range importOrder {
		if data, ok := files[name]; ok {
			path := filepath.Join(b.localDir, name)
			if err := os.WriteFile(path, data, 0o600); err == nil {
				_, _ = b.readState(path)
			}
		}
	}
	b.open.RLock()
	defer b.open.RUnlock()
	_ = b.mirror("")
}

// reopen closes the store and opens it again with the options as change
// makes them; the files that a test wrote meanwhile stay to be taken.
func (b *autoBackend) reopen(change func(o *store.Options)) error {
	b.open.Lock()
	files := testFiles(b.localDir, b)
	change(&b.opts)
	err := b.st.Close()
	if err == nil {
		var st *store.Store
		if st, err = store.Open(context.Background(), b.opts); err == nil {
			b.st = st
		}
	}
	b.open.Unlock()
	if err != nil {
		return err
	}
	b.restore(files)
	return nil
}

// decodesStrictly tells whether the content of the state file name decodes
// strictly into the type of the file.
func decodesStrictly(name string, data []byte) bool {
	var v any
	switch name {
	case device.PreparedClaimsFileName:
		v = &claimPreparations{}
	case preparedClaimsInfoFileName:
		v = &PreparedClaimsInfo{}
	case localStateFileName:
		v = &localState{}
	case poolStateFileName:
		v = &map[string]*preparedPoolClaim{}
	case poolPreparingFileName:
		v = &map[string]*preparingPoolClaim{}
	case leasesFileName:
		v = &leaseStore{}
	case poolSerialsFileName:
		v = &poolSerialsFile{}
	case steeredFileName:
		v = &map[string]string{}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v) == nil
}

var (
	sysfsPathRE = regexp.MustCompile(`"sysfsPath": "([^"]*)/bus/cxl/devices/[^"/]*"`)
	daxDeviceRE = regexp.MustCompile(`"daxDevice": "([^"]*)/dax[^"/]*"`)
)

// readState returns the content of a state file, taking first the content
// of a file that a test wrote.
func (b *autoBackend) readState(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil && !b.oursLocking(path, data) {
		if !decodesStrictly(filepath.Base(path), data) {
			// what the loader of the file rejects or reads in an older
			// format
			return data, nil
		}
		if err := b.writeState(path, data); err != nil {
			return nil, err
		}
	}
	b.open.RLock()
	defer b.open.RUnlock()
	return b.stateStore.readState(path)
}

// ours tells whether the file path with the content data is written by
// the store or the backend, or is the content that the store has; the
// caller holds b.open.
func (b *autoBackend) ours(path string, data []byte) bool {
	b.mu.Lock()
	written := bytes.Equal(b.written[path], data)
	b.mu.Unlock()
	if written || bytes.Contains(data, []byte(`"viewOf": "state.json"`)) || bytes.Contains(data, []byte(`"viewOf":"state.json"`)) {
		return true
	}
	content, err := b.stateStore.readState(path)
	return err == nil && jsonSame(content, data)
}

// oursLocking is ours with b.open held for it.
func (b *autoBackend) oursLocking(path string, data []byte) bool {
	b.open.RLock()
	defer b.open.RUnlock()
	return b.ours(path, data)
}

// writeState commits the content of a state file, checks that the store
// gives it back and writes the files that are not views.
func (b *autoBackend) writeState(path string, data []byte) error {
	// a test fails the write of a file by a directory as its temporary
	// file: the commit fails as one whose write of state.json fails
	if isDir(path + ".tmp") {
		tmp := filepath.Join(filepath.Dir(path), store.FileName+".tmp")
		return fmt.Errorf("writing %s: writing %s: %w", path, tmp, &fs.PathError{Op: "open", Path: tmp, Err: syscall.EISDIR})
	}
	if err := b.learn(data); err != nil {
		return err
	}
	b.open.RLock()
	defer b.open.RUnlock()
	if err := b.stateStore.writeState(path, data); err != nil {
		return err
	}
	if os.Getenv("CXL_STATE_INVARIANTS") != "" {
		checkInvariants(b.st.Snapshot())
	}
	switch name := filepath.Base(path); name {
	case device.PreparedClaimsFileName:
		b.mu.Lock()
		b.prepared = data
		b.mu.Unlock()
	case preparedClaimsInfoFileName:
		b.mu.Lock()
		prepared := b.prepared
		b.mu.Unlock()
		if prepared != nil {
			p := filepath.Join(filepath.Dir(path), device.PreparedClaimsFileName)
			read, _ := b.stateStore.readState(p)
			check(p, prepared, read)
		}
		fallthrough
	default:
		read, _ := b.stateStore.readState(path)
		check(path, data, read)
	}
	return b.mirror(path)
}

// mirror writes the files that are not views as the store has them, but
// for a file of the test that the store did not read (other than path, the
// file just written).
func (b *autoBackend) mirror(path string) error {
	for _, name := range []string{poolPreparingFileName, poolSerialsFileName, steeredFileName} {
		p := filepath.Join(b.localDir, name)
		content, err := b.stateStore.readState(p)
		if err != nil {
			continue
		}
		if data, err := os.ReadFile(p); err == nil && p != path && !b.ours(p, data) {
			continue
		}
		b.mu.Lock()
		b.written[p] = content
		b.mu.Unlock()
		if err := os.WriteFile(p, content, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// isDir tells whether path is a directory.
func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// learn reopens the store with the roots of the paths of the views that a
// content has, the first time it has them.
func (b *autoBackend) learn(data []byte) error {
	b.mu.Lock()
	var sysRoot, devRoot string
	if m := sysfsPathRE.FindSubmatch(data); m != nil && !b.sysRoot {
		sysRoot, b.sysRoot = string(m[1]), true
	}
	if m := daxDeviceRE.FindSubmatch(data); m != nil && !b.devRoot {
		devRoot, b.devRoot = string(m[1]), true
	}
	b.mu.Unlock()
	if sysRoot == "" && devRoot == "" {
		return nil
	}
	return b.reopen(func(o *store.Options) {
		if sysRoot != "" {
			o.SysRoot = sysRoot
		}
		if devRoot != "" {
			o.DevRoot = devRoot
		}
	})
}

// TestBrokerOtherBootOnStore is the reboot of TestBrokerOtherBoot on the
// state store: the restart in another boot opens the store, which drops the
// leases of the old boot before the broker reads them (D-21) and keeps the
// lease claim. The numa lease is gone, its node neither lent to the
// restarted requester nor revoked, the reconcile deletes its companion,
// and the requester's new request is served.
func TestBrokerOtherBootOnStore(t *testing.T) {
	if stateFilesMode {
		t.Skip("the reboot on the state store; TestBrokerOtherBoot on the files")
	}
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	resp, _ := e.call(api.Request{Op: "request", Size: "256Mi", Wait: "0s"})
	id := resp.Lease
	e.waitClaim(companionName(id))
	_, err := e.b.OnLending(id, companionClaim(id))
	noErr(t, err)
	e.b.OnPrepared(id, []lentDevice{{Source: api.SourcePool, Serial: 0xc1ee0001, Size: 1 << 28, Mode: api.ModeNUMA, Node: 2}})
	e.waitState(id, api.StateReady)

	// a reboot: the requester restarted without the node
	e.bootID = "boot-2"
	e.lender.mu.Lock()
	e.lender.lent = map[string]map[int][]string{}
	e.lender.calls = nil
	e.lender.mu.Unlock()
	e.restart()
	if e.lease(id) != nil || e.b.LeaseNodes(testPodUID, testCtr) != nil {
		t.Fatalf("lease of another boot %+v, lease nodes %v", e.lease(id), e.b.LeaseNodes(testPodUID, testCtr))
	}
	data, err := os.ReadFile(filepath.Join(e.dir, leasesFileName))
	noErr(t, err)
	if strings.Contains(string(data), id) || !strings.Contains(string(data), `"bootID": "boot-2"`) ||
		!strings.Contains(string(data), testLeaseClaimUID) {
		t.Fatalf("leases.json after the reboot:\n%s", data)
	}
	e.start()
	list, _ := e.call(api.Request{Op: "list"})
	if list.Error != "" || list.Leases == nil || len(*list.Leases) != 0 {
		t.Fatalf("list after the reboot %+v", list)
	}
	e.b.reconcile()
	e.wantGone(companionName(id))
	if got := e.lender.LentNodes(testPodUID, testCtr); len(got) != 0 || e.lender.callLog() != "" {
		t.Fatalf("lent nodes %v, lender calls:\n%s", got, e.lender.callLog())
	}
	resp, _ = e.call(api.Request{Op: "request", Size: "256Mi", Wait: "0s"})
	if resp.Error != "" || resp.State != api.StatePending {
		t.Fatalf("new request %+v", resp)
	}
	e.waitClaim(companionName(resp.Lease))
}

// writeJSONFile replaces the file with v in JSON, readable by the owner
// only. The new content is synced before the rename, and the directory
// after it: after a crash or a power loss the file has the old content or
// the new one, never an empty or a partial one.
func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	tmp := path + ".tmp"
	if err := writeSynced(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("renaming %s: %w", tmp, err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("syncing the directory of %s: %w", path, err)
	}
	return nil
}

// writeSynced writes data to the file name and syncs it.
func writeSynced(name string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// syncDir syncs a directory, so that a rename in it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
