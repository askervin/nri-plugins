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
	"strings"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// sliceTestEnv is a localTestEnv with the checks of the slices of local
// memdevs in the fake kernel.
type sliceTestEnv struct {
	*localTestEnv
}

// newSliceTestEnv returns a node with the local memdev localSerial and the
// memdevs of specs plugged.
func newSliceTestEnv(t *testing.T, specs ...fake.MemdevSpec) *sliceTestEnv {
	t.Helper()
	return &sliceTestEnv{newLocalTestEnv(t, specs...)}
}

// prepareFails prepares a claim that must fail with an error that
// contains substr, and returns the error.
func (e *sliceTestEnv) prepareFails(claim *resourcev1.ResourceClaim, substr string) error {
	e.t.Helper()
	err := e.prepare(claim)
	wantErr(e.t, err, substr)
	return err
}

// wantUsed checks whether the engine has a record of the local memdev.
func (e *sliceTestEnv) wantUsed(used bool) {
	e.t.Helper()
	if got := e.inUse(); got != used {
		e.t.Fatalf("memdev used %v, expected %v", got, used)
	}
}

// wantRegionReleased checks that the region was released last, and the
// memdev not disabled.
func (e *sliceTestEnv) wantRegionReleased(region string) {
	e.t.Helper()
	cmds := e.commands()
	if !strings.HasSuffix(cmds, "cxl disable-region "+region+"\ncxl destroy-region "+region) || strings.Contains(cmds, "disable-memdev") {
		e.t.Fatalf("%s not released:\n%s", region, cmds)
	}
}

// The memory block size is read as hex, and again for every slice and
// every snapshot of the publisher.
func TestLocalBlockSize(t *testing.T) {
	e := newSliceTestEnv(t)
	e.start()
	// "8000000" is hex
	if bs := e.localSnapshot().BlockSize; bs != 134217728 {
		t.Fatalf("block size %d of %q", bs, e.k.Read("devices/system/memory/block_size_bytes"))
	}
	// 2 GiB blocks: a 128 MiB claim needs a 2 GiB slice
	e.k.SetBlockSize(2 << 30)
	if err := e.prepareFails(localClaim("u1", 128*mib), "the slice needs 2147483648"); !errors.Is(err, kernel.ErrNoRoom) {
		t.Fatalf("expected no room, got %v", err)
	}
	e.wantRegionReleased("region0")
	if bs := e.localSnapshot().BlockSize; bs != 2<<30 {
		t.Fatalf("block size %d after the change", bs)
	}
	e.wantUsed(false)
	e.k.Write("devices/system/memory/block_size_bytes", "bogus")
	_ = e.prepareFails(localClaim("u1", 128*mib, localDaxConfig), "memory block size")
	e.wantUsed(false)
	// unknown at start: the snapshot reads it again
	e.k.Remove("devices/system/memory/block_size_bytes")
	e.restart()
	if bs := e.localSnapshot().BlockSize; bs != 0 {
		t.Fatalf("block size %d without block_size_bytes", bs)
	}
	e.k.SetBlockSize(localBlockSize)
	if bs := e.localSnapshot().BlockSize; bs != localBlockSize {
		t.Fatalf("block size %d", bs)
	}
	off, err := dra.NewPublisher(dra.PublishOptions{Store: e.st, NodeName: "node1", Scan: func(context.Context) (*kernel.Snapshot, error) { return &kernel.Snapshot{}, nil }})
	noErr(t, err)
	if off.LocalSnapshot() != nil {
		t.Fatal("snapshot of unmanaged local devices")
	}
}
