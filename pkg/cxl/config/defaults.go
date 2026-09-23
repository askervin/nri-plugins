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
	"fmt"

	"sigs.k8s.io/yaml"
)

// Defaults are the defaults of the driver configuration (key defaults):
// the container settings of every container of the node, overlaid by the
// settings of the results that a container uses.
type Defaults struct {
	Container *Container `json:"container,omitempty"`
}

// ParseDefaults returns the defaults in data (YAML or JSON), decoded
// strictly and validated.
func ParseDefaults(data []byte) (*Defaults, error) {
	js, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, fmt.Errorf("defaults: %w", err)
	}
	d := &Defaults{}
	if err := strictUnmarshal(js, d); err != nil {
		return nil, fmt.Errorf("defaults: %w", err)
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return d, nil
}

// Validate returns an error if a value of the defaults is invalid:
// fencing allowed-mems or none (mempolicy is not implemented), and a
// steering that is valid as the effective steering of a container.
func (d *Defaults) Validate() error {
	if d == nil || d.Container == nil {
		return nil
	}
	c := d.Container
	switch c.Fencing {
	case "", FencingAllowedMems, FencingNone:
	case FencingMempolicy:
		return fmt.Errorf("%s%s: %s is not implemented yet", defaultsPrefix, FieldFencing, c.Fencing)
	default:
		return fmt.Errorf("%s%s: invalid value %q (%s, %s or %s)", defaultsPrefix, FieldFencing, c.Fencing,
			FencingAllowedMems, FencingMempolicy, FencingNone)
	}
	if s := c.normalized(); s != nil {
		return validateSteering(defaultsPrefix, s.Steering, true, nil)
	}
	return nil
}

// ContainerSettings returns the container defaults without the objects
// that set nothing, the zero Container when there are none.
func (d *Defaults) ContainerSettings() Container {
	if d == nil {
		return Container{}
	}
	if c := d.Container.normalized(); c != nil {
		return *c
	}
	return Container{}
}
