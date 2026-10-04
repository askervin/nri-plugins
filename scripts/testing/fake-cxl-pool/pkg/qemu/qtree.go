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

package qemu

import (
	"bufio"
	"regexp"
	"strconv"
	"strings"
)

// qtreeNode is a "bus:" or "dev:" line of "info qtree" output.
type qtreeNode struct {
	isBus    bool
	name     string // bus name, or device driver
	id       string // device id
	indent   int
	props    map[string]string
	children []*qtreeNode
	parent   *qtreeNode
}

var (
	qtreeDevRe  = regexp.MustCompile(`^dev: ([^,]+), id "(.*)"$`)
	qtreeBusRe  = regexp.MustCompile(`^bus: (.+)$`)
	qtreePropRe = regexp.MustCompile(`^([A-Za-z0-9_.-]+) = (.*)$`)
)

// parseQtreeNodes parses "info qtree" or "info qtree -b" output into a
// node tree. Lines other than bus, dev and "key = value" properties are
// ignored. Nesting is decided by indentation only.
func parseQtreeNodes(text string) []*qtreeNode {
	var (
		roots []*qtreeNode
		stack []*qtreeNode
	)
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		raw := strings.TrimRight(sc.Text(), "\r ")
		trimmed := strings.TrimLeft(raw, " ")
		if trimmed == "" {
			continue
		}
		indent := len(raw) - len(trimmed)
		var n *qtreeNode
		if m := qtreeBusRe.FindStringSubmatch(trimmed); m != nil {
			n = &qtreeNode{isBus: true, name: m[1], indent: indent}
		} else if m := qtreeDevRe.FindStringSubmatch(trimmed); m != nil {
			n = &qtreeNode{name: m[1], id: m[2], indent: indent, props: map[string]string{}}
		} else if m := qtreePropRe.FindStringSubmatch(trimmed); m != nil {
			// a property of the innermost device with smaller indent
			for i := len(stack) - 1; i >= 0; i-- {
				if !stack[i].isBus && stack[i].indent < indent {
					stack[i].props[m[1]] = m[2]
					break
				}
			}
			continue
		} else {
			continue
		}
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		if len(stack) == 0 {
			roots = append(roots, n)
		} else {
			p := stack[len(stack)-1]
			n.parent = p
			p.children = append(p.children, n)
		}
		stack = append(stack, n)
	}
	return roots
}

// ParseQtree extracts the CXL topology from "info qtree" (full or brief)
// output: host bridges (pxb-cxl-host buses), cxl-downstream and cxl-rp
// ports, and cxl-type3 devices. With full output, host bridge NUMA nodes,
// and the volatile-memdev and sn properties of cxl-type3 devices are
// filled in too.
func ParseQtree(text string) *Tree {
	t := &Tree{}
	roots := parseQtreeNodes(text)
	numa := map[string]int{}
	var walk func(n *qtreeNode, hb string)
	walk = func(n *qtreeNode, hb string) {
		if !n.isBus {
			switch n.name {
			case "pxb-cxl":
				if v, ok := n.props["numa_node"]; ok {
					numa[n.id] = parseQtreeInt(v)
				}
			case "pxb-cxl-host":
				for _, c := range n.children {
					if c.isBus {
						t.HostBridges = append(t.HostBridges, TreeHostBridge{ID: c.name, NumaNode: -1})
						for _, cc := range c.children {
							walk(cc, c.name)
						}
					}
				}
				return
			case "cxl-downstream", "cxl-rp":
				if hb != "" {
					p := Port{Bus: n.id, Kind: PortDownstream, HostBridge: hb}
					if n.name == "cxl-rp" {
						p.Kind = PortRootPort
					}
					for _, c := range n.children {
						if c.isBus {
							p.Bus = c.name
							for _, d := range c.children {
								if !d.isBus {
									p.Children = append(p.Children, TreeDevice{Driver: d.name, ID: d.id})
								}
							}
							break
						}
					}
					t.Ports = append(t.Ports, p)
				}
			case "cxl-type3":
				d := Type3Device{ID: n.id}
				if n.parent != nil {
					d.Bus = n.parent.name
				}
				if v, ok := n.props["volatile-memdev"]; ok {
					v = strings.Trim(v, `"`)
					d.VolatileMemdev = strings.TrimPrefix(v, "/objects/")
				}
				if v, ok := n.props["sn"]; ok {
					if sn, err := strconv.ParseUint(strings.Fields(v)[0], 10, 64); err == nil {
						d.Serial, d.HasSerial = sn, true
					}
				}
				t.Type3 = append(t.Type3, d)
			}
		}
		for _, c := range n.children {
			walk(c, hb)
		}
	}
	for _, r := range roots {
		walk(r, "")
	}
	for i := range t.HostBridges {
		if v, ok := numa[t.HostBridges[i].ID]; ok {
			t.HostBridges[i].NumaNode = v
		}
	}
	return t
}

// parseQtreeInt parses "1 (0x1)" or "1".
func parseQtreeInt(v string) int {
	f := strings.Fields(v)
	if len(f) == 0 {
		return -1
	}
	i, err := strconv.Atoi(f[0])
	if err != nil {
		return -1
	}
	return numaOrUnknown(i)
}

// ParseInfoMemdev parses HMP "info memdev" output.
func ParseInfoMemdev(text string) []Memdev {
	var (
		out []Memdev
		cur *Memdev
	)
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if id, ok := strings.CutPrefix(line, "memory backend: "); ok {
			out = append(out, Memdev{ID: strings.TrimSpace(id)})
			cur = &out[len(out)-1]
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "size":
			cur.Size, _ = strconv.ParseUint(v, 10, 64)
		case "share":
			cur.Share = v == "true"
		}
	}
	return out
}
