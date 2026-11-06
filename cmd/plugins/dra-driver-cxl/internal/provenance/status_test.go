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

package provenance

import (
	"testing"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// TestStatusData pins the errors of the status data of a pool claim: no
// entry for the result, an entry without data, and the data of another
// device do not give a serial; the data of the result's entry does.
func TestStatusData(t *testing.T) {
	r := &resourcev1.DeviceRequestAllocationResult{Request: "mem", Driver: device.PoolDriverName, Pool: "pool-c", Device: "c-shared0"}
	c := poolClaim("c", testNode, "c-shared0", "")
	_, err := StatusData(c, r)
	wantErr(t, err, "claim status has no entry for device pool-c/c-shared0 (not attached by the pool controller yet?)")
	_, err = StatusSerial(c, r)
	wantErr(t, err, "claim status has no entry for device pool-c/c-shared0 (not attached by the pool controller yet?)")

	c.Status.Devices = []resourcev1.AllocatedDeviceStatus{{Driver: r.Driver, Pool: r.Pool, Device: r.Device}}
	_, err = StatusData(c, r)
	wantErr(t, err, "status of device pool-c/c-shared0 has no data (written by the pool controller with the Attached condition)")
	c.Status.Devices[0].Data = &runtime.RawExtension{}
	_, err = StatusData(c, r)
	wantErr(t, err, "status of device pool-c/c-shared0 has no data (written by the pool controller with the Attached condition)")

	// the entry of another device of the pool does not count
	other := poolClaim("c", testNode, "c-shared1", "0xc1ae2002")
	c.Status.Devices = append(other.Status.Devices, c.Status.Devices...)
	_, err = StatusData(c, r)
	wantErr(t, err, "status of device pool-c/c-shared0 has no data (written by the pool controller with the Attached condition)")

	c = poolClaim("c", testNode, "c-shared0", "0xc1ae2001")
	data, err := StatusData(c, r)
	noErr(t, err)
	if *data != (DeviceData{Serial: sharedPoolSerial, Shared: true, Size: 268435456}) {
		t.Fatalf("data %+v", data)
	}
	serial, err := StatusSerial(c, r)
	if err != nil || serial != sharedPoolSerial {
		t.Fatalf("serial %#x, error %v", serial, err)
	}
}

// TestParseDeviceData pins the status data of a pool device: serial, shared
// and size are required, the flags are false when missing, and the errors
// of invalid data name it.
func TestParseDeviceData(t *testing.T) {
	d, err := ParseDeviceData([]byte(`{"serial":"0xC1AE2001","shared":false,"size":1073741824,"exclusive":true,` +
		`"persistent":true,"singleHost":true,"coherent":true}`))
	noErr(t, err)
	want := DeviceData{Serial: sharedPoolSerial, Size: 1 << 30, Exclusive: true, Persistent: true, SingleHost: true, Coherent: true}
	if *d != want {
		t.Fatalf("data %+v, expected %+v", d, want)
	}
	d, err = ParseDeviceData([]byte(`{"serial":"3249414145","shared":true,"size":0}`))
	noErr(t, err)
	if *d != (DeviceData{Serial: sharedPoolSerial, Shared: true}) {
		t.Fatalf("data %+v", d)
	}
	for _, tc := range []struct{ raw, want string }{
		{`{bogus`, `invalid device data {bogus: invalid character 'b' looking for beginning of object key string`},
		{`{"serial":1}`, `invalid device data {"serial":1}: json: cannot unmarshal number into Go struct field statusData.serial of type string`},
		{`{"shared":true,"size":1}`, `device data {"shared":true,"size":1}: serial, shared and size are required`},
		{`{"serial":"0x1","size":1}`, `device data {"serial":"0x1","size":1}: serial, shared and size are required`},
		{`{"serial":"0x1","shared":true}`, `device data {"serial":"0x1","shared":true}: serial, shared and size are required`},
		{`{"serial":"0xzz","shared":true,"size":1}`, `device data: invalid serial "0xzz"`},
	} {
		_, err := ParseDeviceData([]byte(tc.raw))
		wantErr(t, err, tc.want)
	}
}
