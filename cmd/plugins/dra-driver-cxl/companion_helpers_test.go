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
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/leases"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/lend"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// The fakes and fixtures of companion claims and lease claims that the
// tests of the drivers share: the lease broker itself is tested in
// internal/leases.

// leaseFsDirName is the directory of the lease-fs directories of the
// lease claims in the plugin data directory of cxl.nri.io.
const leaseFsDirName = "lease-fs"

// stopFunc is a lease broker whose Stop calls the function.
type stopFunc func()

// Stop calls the function.
func (f stopFunc) Stop() { f() }

// errLendingUnavailable is the error of a lend without NRI.
var errLendingUnavailable = lend.ErrLendingUnavailable

// mountInfo is a mount of a mount namespace.
type mountInfo = kernel.MountInfo

// companionName is the name of the companion claim and pod of a lease.
func companionName(id string) string {
	return leases.CompanionName(id)
}

// fakeLender is a dra.NodeLender that records the lent nodes and its
// calls.
type fakeLender struct {
	mu      sync.Mutex
	lent    map[string]map[int][]string // podUID/name -> node -> holders
	calls   []string
	lendErr error
}

// newFakeLender returns a lender that has lent nothing.
func newFakeLender() *fakeLender {
	return &fakeLender{lent: map[string]map[int][]string{}}
}

func (f *fakeLender) LendNode(ctx context.Context, podUID, name string, node int, holder string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("lend %s/%s %d", podUID, name, node))
	if f.lendErr != nil {
		return f.lendErr
	}
	k := podUID + "/" + name
	if f.lent[k] == nil {
		f.lent[k] = map[int][]string{}
	}
	if !slices.Contains(f.lent[k][node], holder) {
		f.lent[k][node] = append(f.lent[k][node], holder)
	}
	return nil
}

func (f *fakeLender) RevokeNode(ctx context.Context, podUID, name string, node int, holder string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("revoke %s/%s %d", podUID, name, node))
	k := podUID + "/" + name
	if h := slices.DeleteFunc(f.lent[k][node], func(s string) bool { return s == holder }); len(h) > 0 {
		f.lent[k][node] = h
	} else {
		delete(f.lent[k], node)
	}
	return nil
}

func (f *fakeLender) LentNodes(podUID, name string) []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	var nodes []int
	for n := range f.lent[podUID+"/"+name] {
		nodes = append(nodes, n)
	}
	slices.Sort(nodes)
	return nodes
}

func (f *fakeLender) callLog() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, "\n")
}

var _ dra.NodeLender = (*fakeLender)(nil)

const (
	testNode          = "node1"
	testNS            = "demo"
	testPod           = "borrower"
	testPodUID        = "pod-uid-1"
	testCtr           = "app"
	testLeaseClaimUID = "lc1"
)

// wantNoCDIDevices checks that a prepared claim of one device has no CDI
// device, and that the CDI spec of the pool driver has none.
func (e *poolTestEnv) wantNoCDIDevices(t *testing.T, r kubeletplugin.PrepareResult) {
	t.Helper()
	if len(r.Devices) != 1 || len(r.Devices[0].CDIDeviceIDs) != 0 || e.cdiSpec(t) != nil {
		t.Fatalf("CDI devices of a companion claim: %+v, spec %+v", r.Devices, e.cdiSpec(t))
	}
}
