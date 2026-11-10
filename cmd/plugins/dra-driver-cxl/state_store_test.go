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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/leases"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// On a store in LOST mode the driver starts (no crash loop): the device
// engine recovers nothing, the pool driver, the node state and the lease
// broker start empty, the first Prepare fails with the text of the lost
// state, and nothing is written: the document stays as it is and no other
// JSON file appears.
func TestStartOnALostStore(t *testing.T) {
	root := t.TempDir()
	local, pool := filepath.Join(root, device.DriverName), filepath.Join(root, device.PoolDriverName)
	noErr(t, os.MkdirAll(local, 0o750))
	noErr(t, os.WriteFile(filepath.Join(local, store.FileName), []byte("{"), 0o600))
	for _, d := range []string{"sys/bus/cxl/devices", "sys/devices/system/node", "cdi"} {
		noErr(t, os.MkdirAll(filepath.Join(root, d), 0o755))
	}
	ctx := context.Background()
	st, err := store.Open(ctx, store.Options{Dir: local, PoolDir: pool, PoolDriver: device.PoolDriverName, BootID: "boot-1", SysRoot: "/sys", DevRoot: "/dev"})
	noErr(t, err)
	defer func() { noErr(t, st.Close()) }()
	if st.Lost() == nil {
		t.Fatal("the store is not lost")
	}

	flags := &CXLFlags{PoolDriverName: device.PoolDriverName, PoolPrepareTimeout: time.Second, CDIRoot: filepath.Join(root, "cdi"), NodeName: "n1"}
	config := &pluginConfig{Flags: flags, KubeletPluginDir: local}
	rules := newDriverRules(config, flags)
	devices, err := newDriverDevices(config, flags, &DriverConfig{}, root, nil, st, rules)
	noErr(t, err)
	fe, err := newFrontEnds(config, flags, &DriverConfig{}, "boot-1", st, devices, nil, rules)
	noErr(t, err)
	noErr(t, fe.recover(ctx, filepath.Join(root, "cdi"), &DriverConfig{}, devices))
	p, ns := fe.pool, fe.local
	if r := p.Records(); len(r.Preparations) != 0 || len(p.Serials()) != 0 {
		t.Errorf("pool driver: preparations %v, serials %v", r.Preparations, p.Serials())
	}
	if uses := fe.publisher.LocalSnapshot().Uses; len(uses) != 0 {
		t.Errorf("local uses %v", uses)
	}
	cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(filepath.Join(root, "cdi")), cdiapi.WithAutoRefresh(false))
	noErr(t, err)
	b, err := leases.New(leases.Options{Store: st, Client: k8sfake.NewClientset(), NodeName: testNode, DataDir: local, CDI: cache,
		CLI: filepath.Join(root, "cxl-request"), WaitDefault: time.Second, PoolDriver: device.PoolDriverName})
	noErr(t, err)
	defer b.Stop()

	fe.publisher.SetDevices(device.DevicesInfo{"dram": {Name: "dram", Dev: &device.DRAM{Nodes: []int{0}, Size: 1 << 30}}})
	claim := &resourcev1.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{UID: "u1", Name: "c", Namespace: "ns"},
		Status: resourcev1.ResourceClaimStatus{Allocation: &resourcev1.AllocationResult{Devices: resourcev1.DeviceAllocationResult{
			Results: []resourcev1.DeviceRequestAllocationResult{{Request: "mem", Driver: device.DriverName, Pool: "n1", Device: "dram"}}}}},
	}
	if err := prepareOn(ctx, ns, claim); err == nil || !strings.Contains(err.Error(), "the driver state is lost") ||
		!strings.Contains(err.Error(), "--new-state") {
		t.Errorf("Prepare in LOST mode: %v", err)
	}
	if ns.ClaimInfo("u1") != nil {
		t.Error("the claim is prepared")
	}
	noErr(t, unprepareOn(ctx, ns, "u1"))
	if data, err := os.ReadFile(filepath.Join(local, store.FileName)); err != nil || string(data) != "{" {
		t.Errorf("the lost document was rewritten: %q %v", data, err)
	}
	for _, dir := range []string{local, pool} {
		files, err := filepath.Glob(filepath.Join(dir, "*.json"))
		noErr(t, err)
		for _, f := range files {
			if f != filepath.Join(local, store.FileName) {
				t.Errorf("%s written in LOST mode", f)
			}
		}
	}
}
