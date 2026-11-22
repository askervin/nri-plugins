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

package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	resourcev1 "k8s.io/api/resource/v1"
	"sigs.k8s.io/yaml"

	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// samplesDir has the sample manifests of the driver.
const samplesDir = "../../../deployment/samples/dra-driver-cxl"

// classDriver is the DRA driver of each DeviceClass of the driver.
var classDriver = map[string]string{
	device.ClassLocal: device.DriverName, device.ClassLocalShared: device.DriverName,
	device.ClassLocalPersistent: device.DriverName, device.ClassRegion: device.DriverName,
	device.ClassDRAM: device.DriverName, device.ClassLease: device.DriverName,
	device.ClassPool: device.PoolDriverName, device.ClassPoolShared: device.PoolDriverName,
	device.ClassPoolPersistent: device.PoolDriverName,
}

// serialSelector matches the serial of a device selector of a sample.
var serialSelector = regexp.MustCompile(`serial == "(0x[0-9a-f]+)"`)

// TestSamples checks the sample manifests: every object decodes strictly,
// every request names a class of the driver, every MemoryConfig entry
// resolves and fits the class of its request, every claim of a pod is in
// the file, and one serial is used with one class only.
func TestSamples(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(samplesDir, "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no samples: %v", err)
	}
	classOf := map[string]string{} // serial -> class
	for _, file := range files {
		base := filepath.Base(file)
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		claims := map[string]bool{}
		var pods []*corev1.Pod
		for _, doc := range strings.Split(string(data), "\n---\n") {
			var head struct {
				Kind string `json:"kind"`
			}
			if err := yaml.Unmarshal([]byte(doc), &head); err != nil {
				t.Errorf("%s: %v", base, err)
				continue
			}
			var name string
			var spec resourcev1.ResourceClaimSpec
			switch head.Kind {
			case "ResourceClaim":
				c := &resourcev1.ResourceClaim{}
				err = yaml.UnmarshalStrict([]byte(doc), c)
				name, spec = c.Name, c.Spec
			case "ResourceClaimTemplate":
				c := &resourcev1.ResourceClaimTemplate{}
				err = yaml.UnmarshalStrict([]byte(doc), c)
				name, spec = c.Name, c.Spec.Spec
			case "Pod":
				p := &corev1.Pod{}
				err = yaml.UnmarshalStrict([]byte(doc), p)
				pods = append(pods, p)
			default:
				t.Errorf("%s: kind %q", base, head.Kind)
			}
			if err != nil {
				t.Errorf("%s: %s: %v", base, head.Kind, err)
				continue
			}
			if head.Kind != "Pod" {
				claims[name] = true
				checkSampleClaim(t, base+" "+name, spec, classOf)
			}
		}
		for _, p := range pods {
			for _, rc := range p.Spec.ResourceClaims {
				ref := rc.ResourceClaimName
				if ref == nil {
					ref = rc.ResourceClaimTemplateName
				}
				if ref == nil || !claims[*ref] {
					t.Errorf("%s: pod %s: claim %s is not in the file", base, p.Name, rc.Name)
				}
			}
		}
	}
}

// checkSampleClaim checks the requests and the MemoryConfig entries of a
// claim of a sample, and records the class of the serials it selects.
func checkSampleClaim(t *testing.T, what string, spec resourcev1.ResourceClaimSpec, classOf map[string]string) {
	t.Helper()
	claim := &resourcev1.ResourceClaim{Spec: spec}
	var cfg []resourcev1.DeviceAllocationConfiguration
	for _, c := range spec.Devices.Config {
		cfg = append(cfg, resourcev1.DeviceAllocationConfiguration{Source: resourcev1.AllocationConfigSourceClaim,
			Requests: c.Requests, DeviceConfiguration: c.DeviceConfiguration})
	}
	claim.Status.Allocation = &resourcev1.AllocationResult{Devices: resourcev1.DeviceAllocationResult{Config: cfg}}
	for _, driver := range []string{device.DriverName, device.PoolDriverName} {
		if err := CheckEntries(claim, driver); err != nil {
			t.Errorf("%s: %v", what, err)
		}
	}
	type request struct {
		name, class string
		shares      bool
		selectors   []resourcev1.DeviceSelector
	}
	var requests []request
	for _, r := range spec.Devices.Requests {
		if e := r.Exactly; e != nil {
			var shares bool
			if e.Capacity != nil {
				_, shares = e.Capacity.Requests[device.CapacityShares]
			}
			requests = append(requests, request{r.Name, e.DeviceClassName, shares, e.Selectors})
		}
		for _, s := range r.FirstAvailable {
			var shares bool
			if s.Capacity != nil {
				_, shares = s.Capacity.Requests[device.CapacityShares]
			}
			requests = append(requests, request{r.Name + "/" + s.Name, s.DeviceClassName, shares, s.Selectors})
		}
	}
	for _, r := range requests {
		driver, ok := classDriver[r.class]
		if !ok {
			t.Errorf("%s request %s: unknown class %q", what, r.name, r.class)
			continue
		}
		for _, s := range r.selectors {
			if s.CEL == nil {
				continue
			}
			for _, m := range serialSelector.FindAllStringSubmatch(s.CEL.Expression, -1) {
				if c, ok := classOf[m[1]]; ok && c != r.class {
					t.Errorf("%s request %s: serial %s with class %s, elsewhere with %s", what, r.name, m[1], r.class, c)
				}
				classOf[m[1]] = r.class
			}
		}
		res, err := Resolve(claim, driver, r.name)
		if err != nil {
			t.Errorf("%s request %s: %v", what, r.name, err)
			continue
		}
		d := res.Config.DeviceSection()
		switch r.class {
		case device.ClassLocal:
			_, err = d.MemdevMode(false)
		case device.ClassLocalShared:
			_, err = d.MemdevMode(true)
		case device.ClassLocalPersistent:
			_, err = d.PersistentMode(DeviceFacts{Exclusive: !r.shares, SingleHost: true})
		case device.ClassPool:
			_, err = d.PoolMode(DeviceFacts{Exclusive: true, SingleHost: true})
		case device.ClassPoolShared:
			_, err = d.PoolMode(DeviceFacts{Shared: true, Exclusive: !r.shares})
		case device.ClassPoolPersistent:
			// a writer of a shared device gets it ReadWriteOnce: on its
			// node only
			_, err = d.PoolMode(DeviceFacts{Persistent: true, Shared: true, Exclusive: !r.shares, SingleHost: true})
		case device.ClassRegion, device.ClassDRAM:
			err = d.NUMAOnly(r.class)
		case device.ClassLease:
			err = d.CheckLease()
		}
		if err != nil {
			t.Errorf("%s request %s: class %s: %v", what, r.name, r.class, err)
		}
	}
}
