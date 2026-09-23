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
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// readWithin runs read in a goroutine and returns whether it returned
// within 200 ms, and a channel that is closed when it has returned.
func readWithin(read func()) (bool, <-chan struct{}) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		read()
	}()
	select {
	case <-done:
		return true, done
	case <-time.After(200 * time.Millisecond):
		return false, done
	}
}

// A rescan of the publisher during the release of a dax slice, when the
// release writes size 0 to its dax device, reads no mapping of a dax
// device and ends inside the write; the observation of the verify step of
// a request, which reads the mappings, waits for the write. A reader of a
// mapping inside such a write would hold the kernel's removal of the
// mapping, and the release, forever (drivers/dax/bus.c). The Unprepare
// ends.
func TestRescanDuringDaxShrink(t *testing.T) {
	e := newSliceTestEnv(t)
	e.start()
	ctx := context.Background()
	e.mustPrepare(localClaim("u1", localBlockSize, localDaxConfig))
	e.mustPrepare(localClaim("u2", localBlockSize))
	if g1, g2 := e.grant("u1", 0), e.grant("u2", 0); g1.Got.Dax != "dax0.0" || g2.Got.Dax != "dax0.1" {
		t.Fatalf("slices %+v and %+v, expected dax0.0 and dax0.1", g1.Got, g2.Got)
	}
	// the publisher of the driver: its scan of the kernel (driver.go)
	pub, err := dra.NewPublisher(dra.PublishOptions{
		Config:    e.config.publishConfig(),
		NodeName:  testNode,
		Scan:      e.config.scanFunc(e.k.Kernel()),
		Store:     e.st,
		Probes:    e.devices.Probes,
		BlockSize: e.k.Kernel().BlockSize,
	})
	noErr(t, err)
	scanned := pub.LastScan()
	var verify *kernel.Snapshot
	var verifyErr error
	var rescanned, verified bool
	var rescanDone, verifyDone <-chan struct{}
	e.k.Before("write bus/dax/devices/dax0.0/size 0", func() {
		verified, verifyDone = readWithin(func() { verify, verifyErr = e.devices.Observe(ctx) })
		rescanned, rescanDone = readWithin(func() { pub.Rescan(ctx, false) })
	})
	unprepared := make(chan error, 1)
	go func() {
		res, err := e.s.UnprepareResourceClaims(ctx, []kubeletplugin.NamespacedObject{{UID: types.UID("u1")}})
		if err == nil {
			err = res["u1"]
		}
		unprepared <- err
	}()
	select {
	case err := <-unprepared:
		noErr(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the Unprepare of the dax slice did not end in 5 s")
	}
	if rescanDone == nil {
		t.Fatal("the release did not write size 0 to dax0.0")
	}
	<-rescanDone
	<-verifyDone
	noErr(t, verifyErr)
	if !rescanned || verified {
		t.Fatalf("inside the shrink of dax0.0: the rescan ended %v, the observation of the verify step %v", rescanned, verified)
	}
	if !pub.LastScan().After(scanned) || pub.Devices()[localDeviceName] == nil {
		t.Fatalf("the rescan did not scan the node: devices %v", pub.Devices())
	}
	if d := verify.DaxDevice("dax0.0"); d.Ranges != nil {
		t.Fatalf("dax0.0 of the verify observation %+v, expected no memory", d)
	}
	e.check("unprepared u1")
	e.mustUnprepare("u2")
}
