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
	"time"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// TestCharPoolPrepareTimeout: the Prepare of a pool claim whose memdev never
// appears on the node waits for it up to the prepare timeout of the pool
// driver and fails then, with an error that names the serial and wraps
// context.DeadlineExceeded. The claim is in the preparing file during the
// wait; the failed Prepare touches no device and forgets the claim, and its
// Unprepare is no error. A timeout of 0 or less is 30 s.
func TestCharPoolPrepareTimeout(t *testing.T) {
	const timeout = 300 * time.Millisecond
	e := newPoolTestEnv(t)
	// mem0 is never plugged: no memdev has the serial of the claim
	p, err := newPoolDriver(device.PoolDriverName, e.f.manager(), e.m, e.stateFile, timeout, e.leaseFsRoot, e.bootID, config.KnownFsTypes...)
	noErr(t, err)
	claim := poolClaim("u1", "c1", "pooled0", exclusiveData)

	type result struct {
		res  kubeletplugin.PrepareResult
		took time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		res, _ := p.PrepareResourceClaims(context.Background(), []*resourceapi.ResourceClaim{claim})
		done <- result{res: res[claim.UID], took: time.Since(start)}
	}()

	// the claim is recorded in the preparing file before the wait
	var r result
	sawPreparing := false
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	stuck := time.After(10 * time.Second)
wait:
	for {
		select {
		case r = <-done:
			break wait
		case <-stuck:
			t.Fatal("the Prepare did not return in 10 s")
		case <-tick.C:
			if sawPreparing {
				continue
			}
			rec := e.preparingFile(t)["u1"]
			if rec == nil {
				continue
			}
			sawPreparing = true
			if rec.ClaimName != "default/c1" || len(rec.Devices) != 1 || rec.Devices[0].Serial != 0xc1ee0001 || rec.Devices[0].Memdev != "" {
				t.Errorf("preparing record during the wait: %+v", rec)
			}
		}
	}
	if !sawPreparing {
		t.Error("the claim was not in the preparing file during the wait")
	}

	// the error after the timeout: names the serial, wraps the deadline
	err = r.res.Err
	if err == nil {
		t.Fatalf("the Prepare succeeded: %+v", r.res)
	}
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "0xc1ee0001") {
		t.Fatalf("error %q does not name the serial or wrap context.DeadlineExceeded", err)
	}
	if r.took < timeout || r.took > 2*time.Second {
		t.Fatalf("the Prepare failed after %v, expected between %v and 2s", r.took, timeout)
	}
	if len(r.res.Devices) != 0 {
		t.Fatalf("devices of a failed Prepare: %+v", r.res.Devices)
	}

	// nothing ran: no region created, no memdev enabled or released
	if cmds := e.f.commands(); cmds != "" {
		t.Fatalf("commands of a Prepare whose memdev never appeared:\n%s", cmds)
	}
	// the failed Prepare forgot the claim in the preparing file already
	if recs := e.preparingFile(t); recs["u1"] != nil {
		t.Fatalf("the failed Prepare kept its record: %+v", recs["u1"])
	}
	noErr(t, unprepare(t, p, "u1"))
	e.wantClean(t, p)
	if cmds := e.f.commands(); cmds != "" {
		t.Fatalf("commands of the Unprepare:\n%s", cmds)
	}

	// a timeout of 0 or less is the default of 30 s
	for _, d := range []time.Duration{0, -time.Second} {
		e := newPoolTestEnv(t)
		p, err := newPoolDriver(device.PoolDriverName, e.f.manager(), e.m, e.stateFile, d, e.leaseFsRoot, e.bootID, config.KnownFsTypes...)
		noErr(t, err)
		if p.timeout != 30*time.Second {
			t.Fatalf("prepare timeout %v of the pool driver of timeout %v, expected 30s", p.timeout, d)
		}
	}
}
