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

package device

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"
)

// TestDeviceClassesMatchConstants checks that the DeviceClasses of the raw
// helm chart file (deployment/helm/dra-driver-cxl/templates/deviceclasses.yaml)
// are the nine classes of the Class* constants, each selecting the driver,
// type and sharing that the constant stands for, and no config: the raw
// file has none, configs come only into rendered classes with the Helm
// value deviceClassConfig.
func TestDeviceClassesMatchConstants(t *testing.T) {
	data, err := os.ReadFile("../../../deployment/helm/dra-driver-cxl/templates/deviceclasses.yaml")
	if err != nil {
		t.Fatal(err)
	}
	classes := map[string]*resourcev1.DeviceClass{}
	for _, doc := range strings.Split(string(data), "\n---\n") {
		c := &resourcev1.DeviceClass{}
		if err := yaml.UnmarshalStrict([]byte(doc), c); err != nil {
			t.Fatalf("%v in\n%s", err, doc)
		}
		if c.Kind != "DeviceClass" || c.APIVersion != "resource.k8s.io/v1" {
			t.Fatalf("not a DeviceClass: %s %s", c.APIVersion, c.Kind)
		}
		classes[c.Name] = c
	}
	selects := func(driver, typ string) string {
		return fmt.Sprintf(`device.driver == %q && device.attributes[%q].%s == %q`, driver, driver, AttrType, typ)
	}
	want := map[string]string{
		ClassLocal: selects(DriverName, DeviceTypeMemdev) + fmt.Sprintf(` && device.attributes[%q].%s == false`, DriverName, AttrShared) +
			fmt.Sprintf(` && device.attributes[%q].%s == false`, DriverName, AttrPersistent),
		ClassLocalShared: selects(DriverName, DeviceTypeMemdev) + fmt.Sprintf(` && device.attributes[%q].%s == true`, DriverName, AttrShared) +
			fmt.Sprintf(` && device.attributes[%q].%s == false`, DriverName, AttrPersistent),
		ClassLocalPersistent: selects(DriverName, DeviceTypeMemdev) + fmt.Sprintf(` && device.attributes[%q].%s == true`, DriverName, AttrPersistent),
		ClassPool: selects(PoolDriverName, DeviceTypeMemdev) + fmt.Sprintf(` && device.attributes[%q].%s == false`, PoolDriverName, AttrShared) +
			fmt.Sprintf(` && device.attributes[%q].%s == false`, PoolDriverName, AttrPersistent),
		ClassPoolShared: selects(PoolDriverName, DeviceTypeMemdev) + fmt.Sprintf(` && device.attributes[%q].%s == true`, PoolDriverName, AttrShared) +
			fmt.Sprintf(` && device.attributes[%q].%s == false`, PoolDriverName, AttrPersistent),
		ClassPoolPersistent: selects(PoolDriverName, DeviceTypeMemdev) + fmt.Sprintf(` && device.attributes[%q].%s == true`, PoolDriverName, AttrPersistent),
		ClassRegion:         selects(DriverName, DeviceTypeRegion),
		ClassDRAM:           selects(DriverName, DeviceTypeDRAM),
		ClassLease:          selects(DriverName, DeviceTypeLease),
	}
	if len(classes) != len(want) {
		names := make([]string, 0, len(classes))
		for n := range classes {
			names = append(names, n)
		}
		slices.Sort(names)
		t.Fatalf("classes %v, expected the %d classes of the constants", names, len(want))
	}
	for name, expr := range want {
		c := classes[name]
		switch {
		case c == nil:
			t.Errorf("no class %s", name)
		case len(c.Spec.Selectors) != 1 || c.Spec.Selectors[0].CEL == nil || c.Spec.Selectors[0].CEL.Expression != expr:
			t.Errorf("class %s selectors %+v, expected %s", name, c.Spec.Selectors, expr)
		case len(c.Spec.Config) != 0 || c.Spec.ExtendedResourceName != nil:
			t.Errorf("class %s has a config or an extended resource: %+v", name, c.Spec)
		}
	}
}

func wantErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || err.Error() != want {
		t.Fatalf("error %v, expected %q", err, want)
	}
}

// statusEntry returns the status entry of a device of the pool with the
// share id ("" for none) and the data ("" for none).
func statusEntry(dev, share, data string) resourcev1.AllocatedDeviceStatus {
	st := resourcev1.AllocatedDeviceStatus{Driver: PoolDriverName, Pool: "pool-c", Device: dev}
	if share != "" {
		st.ShareID = &share
	}
	if data != "" {
		st.Data = &runtime.RawExtension{Raw: []byte(data)}
	}
	return st
}

// The status data of a result is the data of its entry: an entry of the
// driver, pool and device of the result, and of its share. No entry, an
// entry without data, and the entry of another device or share give an
// error.
func TestPoolStatus(t *testing.T) {
	r := &resourcev1.DeviceRequestAllocationResult{Request: "mem", Driver: PoolDriverName, Pool: "pool-c", Device: "c-shared0"}
	c := &resourcev1.ResourceClaim{}
	_, err := PoolStatus(c, r)
	wantErr(t, err, "claim status has no entry for device pool-c/c-shared0 (not attached by the pool controller yet?)")

	c.Status.Devices = []resourcev1.AllocatedDeviceStatus{statusEntry("c-shared1", "", `{"serial":"0xc1ae2002","shared":true,"size":1}`),
		statusEntry("c-shared0", "", "")}
	_, err = PoolStatus(c, r)
	wantErr(t, err, "status of device pool-c/c-shared0 has no data (written by the pool controller with the Attached condition)")
	c.Status.Devices[1].Data = &runtime.RawExtension{}
	_, err = PoolStatus(c, r)
	wantErr(t, err, "status of device pool-c/c-shared0 has no data (written by the pool controller with the Attached condition)")

	c.Status.Devices[1] = statusEntry("c-shared0", "", `{"serial":"0xc1ae2001","shared":true,"size":268435456}`)
	d, err := PoolStatus(c, r)
	if err != nil || *d != (PoolDevice{Serial: 0xc1ae2001, Shared: true, Size: 268435456}) {
		t.Fatalf("status data %+v, %v", d, err)
	}

	// two shares of one device: each result has the entry of its share
	c.Status.Devices = []resourcev1.AllocatedDeviceStatus{
		statusEntry("c-shared0", "s1", `{"serial":"0xc1ae2001","shared":true,"size":1}`),
		statusEntry("c-shared0", "s2", `{"serial":"0xc1ae2001","shared":true,"size":2}`),
	}
	for _, share := range []string{"s1", "s2"} {
		id := types.UID(share)
		rs := *r
		rs.ShareID = &id
		if st := StatusOf(c, &rs); st == nil || *st.ShareID != share {
			t.Fatalf("entry %+v of share %s", st, share)
		}
	}
	id := types.UID("s3")
	r.ShareID = &id
	if st := StatusOf(c, r); st != nil {
		t.Fatalf("entry %+v of share s3", st)
	}
}

// The status data of a pool device: serial, shared and size are required,
// the flags are false when missing, and the errors of invalid data name it.
func TestParsePoolStatusData(t *testing.T) {
	d, err := ParsePoolStatusData([]byte(`{"serial":"0xC1AE2001","shared":false,"size":1073741824,"exclusive":true,` +
		`"persistent":true,"singleHost":true,"coherent":true}`))
	want := PoolDevice{Serial: 0xc1ae2001, Size: 1 << 30, Exclusive: true, Persistent: true, SingleHost: true, Coherent: true}
	if err != nil || *d != want {
		t.Fatalf("data %+v, %v, expected %+v", d, err, want)
	}
	d, err = ParsePoolStatusData([]byte(`{"serial":"3249414145","shared":true,"size":0}`))
	if err != nil || *d != (PoolDevice{Serial: 0xc1ae2001, Shared: true}) {
		t.Fatalf("data %+v, %v", d, err)
	}
	for _, tc := range []struct{ raw, want string }{
		{`{bogus`, `invalid device data {bogus: invalid character 'b' looking for beginning of object key string`},
		{`{"serial":1}`, `invalid device data {"serial":1}: json: cannot unmarshal number into Go struct field PoolStatusData.serial of type string`},
		{`{"shared":true,"size":1}`, `device data {"shared":true,"size":1}: serial, shared and size are required`},
		{`{"serial":"0x1","size":1}`, `device data {"serial":"0x1","size":1}: serial, shared and size are required`},
		{`{"serial":"0x1","shared":true}`, `device data {"serial":"0x1","shared":true}: serial, shared and size are required`},
		{`{"serial":"0xzz","shared":true,"size":1}`, `device data: invalid serial "0xzz"`},
	} {
		_, err := ParsePoolStatusData([]byte(tc.raw))
		wantErr(t, err, tc.want)
	}
}

// The node of an allocation is the one value of the one term of its node
// selector that matches metadata.name.
func TestAllocationNode(t *testing.T) {
	field := func(values ...string) corev1.NodeSelectorTerm {
		return corev1.NodeSelectorTerm{MatchFields: []corev1.NodeSelectorRequirement{
			{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: values}}}
	}
	for _, tc := range []struct {
		name  string
		terms []corev1.NodeSelectorTerm
		want  string
	}{
		{name: "one node", terms: []corev1.NodeSelectorTerm{field("n1")}, want: "n1"},
		{name: "no selector"},
		{name: "two values", terms: []corev1.NodeSelectorTerm{field("n1", "n2")}},
		{name: "two terms", terms: []corev1.NodeSelectorTerm{field("n1"), field("n2")}},
		{name: "a label", terms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{
			{Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpIn, Values: []string{"n1"}}}}}},
	} {
		a := &resourcev1.AllocationResult{}
		if tc.terms != nil {
			a.NodeSelector = &corev1.NodeSelector{NodeSelectorTerms: tc.terms}
		}
		if got := AllocationNode(a); got != tc.want {
			t.Errorf("%s: node %q, expected %q", tc.name, got, tc.want)
		}
	}
}
