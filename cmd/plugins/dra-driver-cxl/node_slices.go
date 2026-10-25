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
	"sync"
	"time"

	coreclientset "k8s.io/client-go/kubernetes"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/dynamic-resource-allocation/resourceslice"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// nodeSliceSyncDelay is the SyncDelay of the controller of the node's
// cxl.nri.io ResourceSlice: how long it waits after an informer event of
// the slice (someone else created, changed or deleted it) before it puts
// the slice back as the driver publishes it.
//
// kubelet deletes every ResourceSlice of its node when it starts
// (k8s.io/kubernetes pkg/kubelet/cm/dra/plugin/dra_plugin_manager.go,
// NewDRAPluginManager: wipeResourceSlices of all drivers), also when only
// kubelet restarts and the driver keeps running. With the default 30 s
// (resourceslice.DefaultSyncDelay) the node had no cxl.nri.io devices
// for up to 30 s after every kubelet restart, and the claims of them did
// not schedule (bug-06). The delay batches the events of a burst and lets
// the informer cache catch up with deletions; one second does both for
// the single slice of the node. Only events of that slice wait for it:
// the driver's own publishes (startup, udev rescans, pool list retries)
// call Update, which syncs at once. It also answers any other writer of
// the slice within a second instead of 30 s: two driver instances on a
// node, or a Node object re-created while the driver runs (the
// controller looks up the owner UID once, the garbage collector deletes
// the slice of the old owner) make the slice flap about once a second
// instead of once in 30 s. Accepted: one pool of one slice, one write a
// second at most.
const nodeSliceSyncDelay = time.Second

// nodeSlices publishes the ResourceSlice of the node with a resourceslice
// controller of its own, like kubeletplugin.Helper.PublishResources does
// (the same owner, names and error handling), but with SyncDelay
// nodeSliceSyncDelay: the helper starts its controller with the default
// SyncDelay and has no option for it.
type nodeSlices struct {
	client    coreclientset.Interface
	nodeName  string
	syncDelay time.Duration
	onError   func(ctx context.Context, err error, msg string)

	mu  sync.Mutex
	ctl *resourceslice.Controller // nil before the first publish
}

// newNodeSlices returns the publisher of the ResourceSlice of node
// nodeName. onError gets the errors of publishing, marked recoverable.
func newNodeSlices(client coreclientset.Interface, nodeName string, onError func(ctx context.Context, err error, msg string)) *nodeSlices {
	return &nodeSlices{
		client:    client,
		nodeName:  nodeName,
		syncDelay: nodeSliceSyncDelay,
		onError:   onError,
	}
}

// publish sets the resources of the node: the first call starts the
// controller, which runs until ctx ends or stop is called, later calls
// update its desired state. publish does not wait for the API server.
func (s *nodeSlices) publish(ctx context.Context, resources resourceslice.DriverResources) error {
	if s.nodeName == "" {
		return errors.New("no node name to publish resources")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctl != nil {
		s.ctl.Update(&resources) // a deep copy
		return nil
	}
	ctx = klog.NewContext(ctx, klog.LoggerWithName(klog.FromContext(ctx), "ResourceSlice controller"))
	ctl, err := resourceslice.StartController(ctx, resourceslice.Options{
		DriverName: device.DriverName,
		KubeClient: s.client,
		// The UID is found by the controller.
		Owner:     &resourceslice.Owner{APIVersion: "v1", Kind: "Node", Name: s.nodeName},
		Resources: &resources, // a deep copy
		SyncDelay: ptr(s.syncDelay),
		ErrorHandler: func(ctx context.Context, err error, msg string) {
			// As the helper: neither retrying nor restarting
			// fixes these errors, all are recoverable.
			if s.onError != nil {
				s.onError(ctx, recoverableSliceError{err}, msg)
			}
		},
	})
	if err != nil {
		return fmt.Errorf("start ResourceSlice controller: %w", err)
	}
	s.ctl = ctl
	return nil
}

// stop stops the controller and waits for it. The published slices stay.
func (s *nodeSlices) stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	ctl := s.ctl
	s.ctl = nil
	s.mu.Unlock()
	ctl.Stop() // nil-safe
}

// recoverableSliceError is an error of the ResourceSlice controller,
// recoverable (errors.Is kubeletplugin.ErrRecoverable) as the helper marks
// them, with an unchanged message.
type recoverableSliceError struct{ error }

func (e recoverableSliceError) Is(target error) bool { return target == kubeletplugin.ErrRecoverable }
func (e recoverableSliceError) Unwrap() error        { return e.error }
