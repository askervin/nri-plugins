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
)

// The Unprepare of a claim that the driver does not know returns without
// waiting for the Prepare of another claim, which holds the memdev for long
// when it zeroes a whole shared device.
func TestUnprepareUnknownClaimDoesNotWait(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	entered, release := make(chan struct{}), make(chan struct{})
	e.k.Before("cxl create-region", func() {
		close(entered)
		<-release
	})
	prepared := make(chan error, 1)
	go func() { prepared <- prepareOn(context.Background(), e.s, localClaim("u1", localBlockSize)) }()
	<-entered
	done := make(chan error, 1)
	go func() { done <- unprepareOn(context.Background(), e.s, "u2") }()
	select {
	case err := <-done:
		close(release)
		noErr(t, err)
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the Unprepare of an unknown claim waits for the Prepare of another claim")
	}
	noErr(t, <-prepared)
	e.mustUnprepare("u1")
	if e.inUse() {
		t.Fatal("memdev in use after the Unprepare")
	}
}
