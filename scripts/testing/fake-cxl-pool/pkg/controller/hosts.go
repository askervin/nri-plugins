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

package controller

import (
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/api"
)

// hostMap maps the Nodes of this cluster to pool hosts (qemu VMs).
type hostMap struct {
	nodeHost map[string]api.Host // node name -> host
	hostNode map[string]string   // host name -> node name
}

// normUUID returns a uuid in lower case without dashes.
func normUUID(u string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(u)), "-", "")
}

// mapHosts finds the host of each node: the host whose uuid equals the
// node's systemUUID (lower case, without dashes), else the host whose name
// is the node name. A host maps to one node at most; a node without a host
// is not a pool host.
func mapHosts(hosts []api.Host, nodes []*corev1.Node) hostMap {
	hm := hostMap{nodeHost: map[string]api.Host{}, hostNode: map[string]string{}}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	for _, n := range nodes {
		uuid := normUUID(n.Status.NodeInfo.SystemUUID)
		var found *api.Host
		if uuid != "" {
			for i := range hosts {
				if normUUID(hosts[i].UUID) == uuid {
					found = &hosts[i]
					break
				}
			}
		}
		if found == nil {
			for i := range hosts {
				if hosts[i].Name == n.Name {
					found = &hosts[i]
					break
				}
			}
		}
		if found == nil {
			continue
		}
		if _, taken := hm.hostNode[found.Name]; taken {
			continue
		}
		hm.nodeHost[n.Name] = *found
		hm.hostNode[found.Name] = n.Name
	}
	return hm
}

// String lists the mapping, sorted by node name.
func (hm hostMap) String() string {
	ns := make([]string, 0, len(hm.nodeHost))
	for n, h := range hm.nodeHost {
		ns = append(ns, n+"="+h.Name)
	}
	sort.Strings(ns)
	return "[" + strings.Join(ns, " ") + "]"
}
