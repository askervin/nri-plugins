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
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/dynamic-resource-allocation/resourceslice"

	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// sliceTestClient returns a fake clientset with the node, whose creates and
// updates of ResourceSlices do what the API server does and the fake does
// not: a name from GenerateName, a resource version (the mutation cache of
// the controller needs one). stored, if not nil, changes a slice as it is
// stored.
func sliceTestClient(node string, stored func(*resourceapi.ResourceSlice)) *fake.Clientset {
	client := fake.NewSimpleClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: node, UID: types.UID("uid-" + node)}})
	var mu sync.Mutex
	rv := 0
	store := func(a k8stesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		rs := a.(interface{ GetObject() runtime.Object }).GetObject().(*resourceapi.ResourceSlice)
		rv++
		if rs.Name == "" && rs.GenerateName != "" {
			rs.Name = rs.GenerateName + strconv.Itoa(rv)
		}
		rs.ResourceVersion = strconv.Itoa(rv)
		if stored != nil {
			stored(rs)
		}
		return false, nil, nil // the tracker stores it
	}
	client.PrependReactor("create", "resourceslices", store)
	client.PrependReactor("update", "resourceslices", store)
	return client
}

// nodeSliceDevices returns the device names of the node's cxl.nri.io
// slices, nil if it has none.
func nodeSliceDevices(t *testing.T, client *fake.Clientset, node string) []string {
	t.Helper()
	list, err := client.ResourceV1().ResourceSlices().List(context.Background(), metav1.ListOptions{})
	noErr(t, err)
	var names []string
	for _, rs := range list.Items {
		if rs.Spec.Driver != device.DriverName || rs.Spec.NodeName == nil || *rs.Spec.NodeName != node {
			continue
		}
		if len(rs.OwnerReferences) != 1 || rs.OwnerReferences[0].Kind != "Node" || rs.OwnerReferences[0].UID != types.UID("uid-"+node) {
			t.Errorf("slice %s: owner references %+v, expected node %s", rs.Name, rs.OwnerReferences, node)
		}
		if names == nil {
			names = []string{} // a slice, maybe without devices
		}
		for _, d := range rs.Spec.Devices {
			names = append(names, d.Name)
		}
	}
	return names
}

// waitNodeSlice waits at most timeout until the node's slice has the
// devices, and returns how long it took.
func waitNodeSlice(t *testing.T, client *fake.Clientset, node string, timeout time.Duration, want ...string) time.Duration {
	t.Helper()
	start := time.Now()
	for {
		got := nodeSliceDevices(t, client, node)
		if fmt.Sprint(got) == fmt.Sprint(want) {
			return time.Since(start)
		}
		if time.Since(start) > timeout {
			t.Fatalf("after %v: devices of the slice of %s %v, expected %v", timeout, node, got, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func nodeResources(node string, devs ...string) resourceslice.DriverResources {
	var devices []resourceapi.Device
	for _, d := range devs {
		devices = append(devices, resourceapi.Device{Name: d})
	}
	return resourceslice.DriverResources{Pools: map[string]resourceslice.Pool{
		node: {Slices: []resourceslice.Slice{{Devices: devices}}},
	}}
}

// kubelet deletes every ResourceSlice of its node when it starts, the
// driver keeps running: the slice must be back within the short SyncDelay,
// not after the library's default of 30 s (bug-06). The driver's own
// publishes are not delayed.
func TestNodeSliceBackAfterKubeletWipe(t *testing.T) {
	const node = "n1"
	client := sliceTestClient(node, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newNodeSlices(client, node, func(_ context.Context, err error, msg string) {
		t.Errorf("unexpected error %s: %v", msg, err)
	})
	defer s.stop()
	if s.syncDelay != nodeSliceSyncDelay || nodeSliceSyncDelay >= resourceslice.DefaultSyncDelay/10 {
		t.Fatalf("sync delay %v, expected a short %v", s.syncDelay, nodeSliceSyncDelay)
	}

	noErr(t, s.publish(ctx, nodeResources(node, "dram", "lease")))
	waitNodeSlice(t, client, node, 5*time.Second, "dram", "lease")

	// kubelet's wipe: DeleteCollection of spec.nodeName (the fake
	// implements no DeleteCollection, and no field selectors).
	list, err := client.ResourceV1().ResourceSlices().List(ctx, metav1.ListOptions{})
	noErr(t, err)
	for _, rs := range list.Items {
		noErr(t, client.ResourceV1().ResourceSlices().Delete(ctx, rs.Name, metav1.DeleteOptions{}))
	}
	if got := nodeSliceDevices(t, client, node); got != nil {
		t.Fatalf("slice not deleted: %v", got)
	}
	took := waitNodeSlice(t, client, node, nodeSliceSyncDelay+5*time.Second, "dram", "lease")
	t.Logf("slice back %v after the wipe (sync delay %v)", took.Round(time.Millisecond), nodeSliceSyncDelay)

	// A publish of the driver (e.g. a udev rescan) syncs at once, also
	// right after an informer event of the slice (its re-creation above):
	// normally in milliseconds, the bound tolerates a loaded machine and
	// is still far below the default sync delay of 30 s.
	noErr(t, s.publish(ctx, nodeResources(node, "dram", "lease", "memdev-c100e2e1")))
	took = waitNodeSlice(t, client, node, 10*time.Second, "dram", "lease", "memdev-c100e2e1")
	if took >= 5*time.Second {
		t.Errorf("publish took %v, expected at once", took)
	}
	t.Logf("slice changed %v after the publish", took.Round(time.Millisecond))

	// stop leaves the slice, and nothing puts it back any more.
	s.stop()
	s.stop()
	list, err = client.ResourceV1().ResourceSlices().List(ctx, metav1.ListOptions{})
	noErr(t, err)
	if len(list.Items) != 1 {
		t.Fatalf("%d slices after stop, expected 1", len(list.Items))
	}
	noErr(t, client.ResourceV1().ResourceSlices().Delete(ctx, list.Items[0].Name, metav1.DeleteOptions{}))
	time.Sleep(nodeSliceSyncDelay + 500*time.Millisecond)
	if got := nodeSliceDevices(t, client, node); got != nil {
		t.Errorf("slice re-created after stop: %v", got)
	}
}

// The errors of publishing reach the driver's error handler as recoverable
// errors, as with the helper, with the controller's error inside.
func TestNodeSliceErrorsRecoverable(t *testing.T) {
	const node = "n1"
	// The API server drops a field, as when a feature is disabled.
	client := sliceTestClient(node, func(rs *resourceapi.ResourceSlice) {
		for i := range rs.Spec.Devices {
			rs.Spec.Devices[i].AllowMultipleAllocations = nil
		}
	})
	errs := make(chan error, 10)
	s := newNodeSlices(client, node, func(_ context.Context, err error, _ string) { errs <- err })
	defer s.stop()
	res := nodeResources(node, "lease")
	res.Pools[node].Slices[0].Devices[0].AllowMultipleAllocations = ptr(true)
	noErr(t, s.publish(context.Background(), res))
	select {
	case err := <-errs:
		var dropped *resourceslice.DroppedFieldsError
		if !errors.Is(err, kubeletplugin.ErrRecoverable) || !errors.As(err, &dropped) {
			t.Errorf("error %v (%T): not recoverable or not a DroppedFieldsError", err, err)
		}
		if err.Error() != dropped.Error() {
			t.Errorf("error message %q, expected %q", err, dropped)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no error for the dropped field")
	}
	// The controller takes the stored slice as desired: no update loop
	// with the short sync delay (the create's informer event syncs once).
	select {
	case err := <-errs:
		t.Errorf("another error: %v", err)
	case <-time.After(3 * nodeSliceSyncDelay):
	}

	if err := newNodeSlices(client, "", nil).publish(context.Background(), res); err == nil {
		t.Error("publish without a node name: no error")
	}
	var none *nodeSlices
	none.stop()
	newNodeSlices(client, node, nil).stop()
}
