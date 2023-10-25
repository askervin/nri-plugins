package wgraph

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

type WGraph struct {
	ewdesc   string // edge weight description
	eweights [][]float64
	vwdesc   string // vertex weight description
	vweights []float64
	vnames   []string // vertex names
}

type WEdge struct {
	wg       *WGraph
	src, tgt int
}

type WVertex struct {
	wg *WGraph
	v  int
}

type WEdges []*WEdge

type WVertices []*WVertex

func NewWGraph() *WGraph {
	wg := &WGraph{}
	return wg
}

func (wg *WGraph) String() string {
	return fmt.Sprintf("wgraph(vnames:%v)", wg.vnames)
}

func (e *WEdge) String() string {
	if len(e.wg.vnames) > 0 {
		return fmt.Sprintf("(%s-->%s, w:%f)",
			e.wg.vnames[e.src],
			e.wg.vnames[e.tgt],
			e.wg.eweights[e.src][e.tgt])
	}
	return fmt.Sprintf("(%d-->%d, w:%f)", e.src, e.tgt, e.wg.eweights[e.src][e.tgt])
}

func (e *WEdge) Weight() float64 {
	return e.wg.eweights[e.src][e.tgt]
}

func (e *WEdge) SetWeight(w float64) {
	e.wg.eweights[e.src][e.tgt] = w
}

func (e *WEdge) Source() *WVertex {
	return &WVertex{
		wg: e.wg,
		v: e.src,
	}
}

func (e *WEdge) Target() *WVertex {
	return &WVertex{
		wg: e.wg,
		v: e.tgt,
	}
}

func (v *WVertex) Weight() float64 {
	return v.wg.vweights[v.v]
}

func (v *WVertex) SetWeight(w float64) {
	v.wg.vweights[v.v] = w
}

func (v *WVertex) Name() string {
	if len(v.wg.vnames) > v.v {
		return v.wg.vnames[v.v]
	}
	return strconv.Itoa(v.v)
}

func (edges WEdges) String() string {
	edgeStrings := make([]string, 0, len(edges))
	for _, edge := range edges {
		edgeStrings = append(edgeStrings, edge.String())
	}
	return fmt.Sprintf("edges(%v)", strings.Join(edgeStrings, ", "))
}

func (wg *WGraph) SetEdgeWeights(eweights [][]float64) error {
	if err := wg.validateEweightTable(eweights); err != nil {
		return err
	}
	size := len(eweights)
	wg.eweights = make([][]float64, size)
	for src, weights := range eweights {
		wg.eweights[src] = make([]float64, size)
		for dst, weight := range weights {
			wg.eweights[src][dst] = weight
		}
	}
	return nil
}

func (wg *WGraph) SetVertexWeights(vweights []float64) error {
	size := len(vweights)
	wg.vweights = make([]float64, size)
	for v, weight := range vweights {
		wg.vweights[v] = weight
	}
	return nil
}

// ParseAdjMatrix parses string table and populates edge weights from it.
// Supported table format when colHead=true, rowhead=true
// description colhead1        colhead2 ...
// vname[0]    eweights[0][0]  eweights[0][1] ...
// # comment line
// vname[1]    eweights[1][0]  eweights[1][1] ...
//
// Special weights:
//
//	Inf, -Inf: positive and negative infinity
//	NaN: not a number: edge is missing
func (wg *WGraph) ParseAdjMatrix(s string, colHead, rowHead bool) error {
	lines := strings.Split(s, "\n")
	var table [][]float64
	var vnames []string

	lineNo := 0
	for lineIndex, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0][0] == '#' {
			continue
		}
		lineNo += 1
		if colHead && lineNo == 1 {
			wg.ewdesc = fields[0]
			continue
		}
		var row []float64

		for fieldIndex, field := range fields {
			if rowHead && fieldIndex == 0 {
				vnames = append(vnames, field)
				continue
			}
			value, err := strconv.ParseFloat(field, 64)
			if err != nil {
				return fmt.Errorf("edge weight parse error on line %d: %w", lineIndex+1, err)
			}
			row = append(row, value)
		}

		table = append(table, row)
	}
	if err := wg.SetEdgeWeights(table); err != nil {
		return err
	}
	if rowHead {
		wg.vnames = vnames
	}
	return nil
}

func (wg *WGraph) validateEweightTable(eweights [][]float64) error {
	// Validate size: n vertices, weights should be n x n matrix
	n := len(eweights)
	for src, weights := range wg.eweights {
		if len(weights) != n {
			return fmt.Errorf("expected %d weights from vertex %d, got %d",
				n, src, len(eweights))
		}
	}
	return nil
}

// ParseVertexWeights parses string table and populates vertex weights from it.
// Supported table format when colHead=true, rowhead=true
// [dontcare]  vwdesc
// vname0      vweights[0]
// # comment line
// vname1      vweights[1]
// ...         ...
func (wg *WGraph) ParseVertexWeights(s string, colHead, rowHead bool) error {
	lines := strings.Split(s, "\n")
	var vweights []float64

	lineNo := 0
	for lineIndex, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 || len(fields[0]) == 0 || fields[0][0] == '#' {
			continue
		}
		lineNo += 1
		if colHead && lineNo == 1 {
			wg.vwdesc = fields[len(fields)-1]
			continue
		}
		if rowHead && len(fields) != 2 {
			return fmt.Errorf("vertex weight parse error: expected vertex name and weight on line %d, found %d fields",
				lineIndex+1, len(fields))
		} else if !rowHead && len(fields) != 1 {
			return fmt.Errorf("vertex weight parse error: expected only vertex weight on line %d, found %d fields",
				lineIndex+1, len(fields))
		}
		var vweight float64
		var err error

		for fieldIndex, field := range fields {
			if rowHead && fieldIndex == 0 {
				continue
			}
			vweight, err = strconv.ParseFloat(field, 64)
			if err != nil {
				return fmt.Errorf("vertex weight parse error on line %d: %w", lineIndex+1, err)
			}
		}

		vweights = append(vweights, vweight)
	}
	wg.vweights = vweights
	return nil
}

func (wg *WGraph) ForEachEdge(edgeHandler func (e *WEdge)) {
	for src, weights := range wg.eweights {
		for dst, _ := range weights {
			edgeHandler(wg.Edge(src, dst))
		}
	}
}

func (wg *WGraph) EdgeWeights() [][]float64 {
	return wg.eweights
}

func (wg *WGraph) Edge(src, tgt int) *WEdge {
	return &WEdge{
		wg:  wg,
		src: src,
		tgt: tgt,
	}
}

func (wg *WGraph) Vertex(v int) *WVertex {
	return &WVertex{
		wg: wg,
		v:  v,
	}
}

// Edges returns all edges in the graph.
func (wg *WGraph) Edges() WEdges {
	if len(wg.eweights) == 0 {
		return []*WEdge{}
	}
	// var edges []*WEdge
	edges := make([]*WEdge, 0, len(wg.eweights) * len(wg.eweights))
	for src, eweights := range wg.eweights {
		for tgt, eweight := range eweights {
			if !math.IsNaN(eweight) {
				edges = append(edges, wg.Edge(src, tgt))
			}
		}
	}
	return edges
}

// Vertices returns all vertices in the graph.
func (wg *WGraph) Vertices() WVertices {
	if len(wg.eweights) == 0 {
		return []*WVertex{}
	}
	vertices := make([]*WVertex, len(wg.eweights))
	for v := range wg.eweights {
		vertices[v] = wg.Vertex(v)
	}
	return vertices
}

// FilterVertices removes vertices for which the filter function
// returns false.
func (wg *WGraph) FilterVertices(filter func(v *WVertex) bool) {
	includeVertices := []int{}
	for v := range wg.eweights {
		if filter(wg.Vertex(v)) {
			includeVertices = append(includeVertices, v)
		}
	}
	eweights := make([][]float64, 0, len(includeVertices))
	vweights := make([]float64, 0, len(includeVertices))
	vnames := make([]string, 0, len(includeVertices))
	for _, oldsrc := range includeVertices {
		row := make([]float64, 0, len(includeVertices))
		for _, oldtgt := range includeVertices {
			row = append(row, wg.eweights[oldsrc][oldtgt])
		}
		eweights = append(eweights, row)
		vweights = append(vweights, wg.vweights[oldsrc])
		vnames = append(vnames, wg.vnames[oldsrc])
	}
	wg.eweights = eweights
	wg.vweights = vweights
	wg.vnames = vnames
}

func (wg *WGraph) VertexCount() int {
	return len(wg.eweights)
}

func (edges WEdges) SortByWeight() {
	// slower:
	// sort.Slice(edges, func(i, j int) bool {
	// 	return edges[i].Weight() < edges[j].Weight() ||
	// 		(edges[i].Weight() == edges[j].Weight() && i < j)
	// })
	//
	// faster:
	if len(edges) == 0 {
		return
	}
	wg := edges[0].wg
	sort.Slice(edges, func(i, j int) bool {
		wi := wg.eweights[edges[i].src][edges[i].tgt]
		wj := wg.eweights[edges[j].src][edges[j].tgt]
		return wi < wj ||
			(wi == wj && i < j)
	})
}

// Return edges that is a minimum spanning tree for a set of at least
// vcount vertices.
func (wg *WGraph) MinimumSpanningSubtree(minVertices int) (WEdges, error) {
	// Run Kruskal's MST algorithm until the first found subtree
	// reaches or exceeds the size of minVertices.
	if minVertices == 0 {
		minVertices = wg.VertexCount()
	}
	edges := wg.Edges()
	edges.SortByWeight()
	subtree := WEdges{}
	children := make([][]int, wg.VertexCount())
	roots := make([]int, wg.VertexCount())
	sizes := make([]int, wg.VertexCount())
	for v := range roots {
		roots[v] = v
		sizes[v] = 1
	}
	var bigRoot, smallRoot int
	for _, edge := range edges {
		srcRoot := findRoot(roots, edge.src)
		tgtRoot := findRoot(roots, edge.tgt)
		if srcRoot != tgtRoot {
			if sizes[srcRoot] < sizes[tgtRoot] {
				bigRoot = tgtRoot
				smallRoot = srcRoot
			} else {
				bigRoot = srcRoot
				smallRoot = tgtRoot
			}
			roots[smallRoot] = bigRoot
			children[bigRoot] = append(children[bigRoot], smallRoot)
			sizes[bigRoot] += sizes[smallRoot]
			if sizes[bigRoot] >= minVertices {
				break
			}
		}
	}
	if sizes[bigRoot] < minVertices {
		return nil, fmt.Errorf("max spanning subtree of size %d is smaller than required size %d",
			sizes[bigRoot], minVertices)
	}
	subtreeVertices := []int{bigRoot}
	for len(subtreeVertices) > 0 {
		v := subtreeVertices[len(subtreeVertices)-1]
		subtreeVertices = subtreeVertices[:len(subtreeVertices)-1]
		for _, child := range children[v] {
			subtreeVertices = append(subtreeVertices, child)
			subtree = append(subtree, wg.Edge(v, child))
		}
	}
	return subtree, nil
}

func findRoot(roots []int, v int) int {
	if roots[v] != v {
		roots[v] = findRoot(roots, roots[v])
	}
	return roots[v]
}
