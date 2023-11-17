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

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha1 "github.com/containers/nri-plugins/pkg/apis/config/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeTopologyAwarePolicies implements TopologyAwarePolicyInterface
type FakeTopologyAwarePolicies struct {
	Fake *FakeConfigV1alpha1
	ns   string
}

var topologyawarepoliciesResource = v1alpha1.SchemeGroupVersion.WithResource("topologyawarepolicies")

var topologyawarepoliciesKind = v1alpha1.SchemeGroupVersion.WithKind("TopologyAwarePolicy")

// Get takes name of the topologyAwarePolicy, and returns the corresponding topologyAwarePolicy object, and an error if there is any.
func (c *FakeTopologyAwarePolicies) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.TopologyAwarePolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(topologyawarepoliciesResource, c.ns, name), &v1alpha1.TopologyAwarePolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.TopologyAwarePolicy), err
}

// List takes label and field selectors, and returns the list of TopologyAwarePolicies that match those selectors.
func (c *FakeTopologyAwarePolicies) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.TopologyAwarePolicyList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(topologyawarepoliciesResource, topologyawarepoliciesKind, c.ns, opts), &v1alpha1.TopologyAwarePolicyList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.TopologyAwarePolicyList{ListMeta: obj.(*v1alpha1.TopologyAwarePolicyList).ListMeta}
	for _, item := range obj.(*v1alpha1.TopologyAwarePolicyList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested topologyAwarePolicies.
func (c *FakeTopologyAwarePolicies) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(topologyawarepoliciesResource, c.ns, opts))

}

// Create takes the representation of a topologyAwarePolicy and creates it.  Returns the server's representation of the topologyAwarePolicy, and an error, if there is any.
func (c *FakeTopologyAwarePolicies) Create(ctx context.Context, topologyAwarePolicy *v1alpha1.TopologyAwarePolicy, opts v1.CreateOptions) (result *v1alpha1.TopologyAwarePolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(topologyawarepoliciesResource, c.ns, topologyAwarePolicy), &v1alpha1.TopologyAwarePolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.TopologyAwarePolicy), err
}

// Update takes the representation of a topologyAwarePolicy and updates it. Returns the server's representation of the topologyAwarePolicy, and an error, if there is any.
func (c *FakeTopologyAwarePolicies) Update(ctx context.Context, topologyAwarePolicy *v1alpha1.TopologyAwarePolicy, opts v1.UpdateOptions) (result *v1alpha1.TopologyAwarePolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(topologyawarepoliciesResource, c.ns, topologyAwarePolicy), &v1alpha1.TopologyAwarePolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.TopologyAwarePolicy), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeTopologyAwarePolicies) UpdateStatus(ctx context.Context, topologyAwarePolicy *v1alpha1.TopologyAwarePolicy, opts v1.UpdateOptions) (*v1alpha1.TopologyAwarePolicy, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(topologyawarepoliciesResource, "status", c.ns, topologyAwarePolicy), &v1alpha1.TopologyAwarePolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.TopologyAwarePolicy), err
}

// Delete takes name of the topologyAwarePolicy and deletes it. Returns an error if one occurs.
func (c *FakeTopologyAwarePolicies) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(topologyawarepoliciesResource, c.ns, name, opts), &v1alpha1.TopologyAwarePolicy{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeTopologyAwarePolicies) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(topologyawarepoliciesResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.TopologyAwarePolicyList{})
	return err
}

// Patch applies the patch and returns the patched topologyAwarePolicy.
func (c *FakeTopologyAwarePolicies) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.TopologyAwarePolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(topologyawarepoliciesResource, c.ns, name, pt, data, subresources...), &v1alpha1.TopologyAwarePolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.TopologyAwarePolicy), err
}
