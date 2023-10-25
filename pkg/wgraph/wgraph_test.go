package wgraph

import (
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"
)

/*
cost := `
distance   0   1   2   3   4   5
0:  10  12  12  21  21  21
1:  12  10  12  21  21  21
2:  12  12  10  21  21  21
3:  21  21  21  10  12  12
4:  21  21  21  12  10  12
5:  21  21  21  12  12  10
`
cost2 := `
Writer_Numa_Node     0       1
0      9.2   289.4
1    289.4      9.2
`

cost3 := `
Numa_node            0       1
       0         133.4   303.3
       1         303.6   132.5
`

*/

func TestParseAdjMatrix(t *testing.T) {
	wg := NewWGraph()
	err := wg.ParseAdjMatrix(`
            my_data_desc col1head     col2head col3head
            row1head           24  42000000000    -1e10
            row2head        -.001        -1e-1      inf
            row3head          NaN          Inf     -Inf`,
		true, true)
	if err != nil {
		t.Fatalf("expected successful parsing, got error %s", err)
	}
	fmt.Printf("graph: %s\n", wg)
	fmt.Printf("matrix: %v\n", wg.EdgeWeights())
	edges := wg.Edges()
	fmt.Printf("edges: %s\n", edges)
	edges.SortByWeight()
	fmt.Printf("sorted: %s\n", edges)
}

func TestMinimumSpanningSubtree(t *testing.T) {
	wg := NewWGraph()
	err := wg.ParseAdjMatrix(`
        distance   0   1   2   3   4   5
              0:  10  12  12  21  21  21
              1:  12  10  12  21  21  21
              2:  12  12  10  21  21  21
              3:  21  21  21  10  12  12
              4:  21  21  21  12  10  12
              5:  21  21  21  12  12  10
        `, true, true)
	if err != nil {
		t.Fatalf("expected successful parsing, got error %s", err)
	}
	edges, _ := wg.MinimumSpanningSubtree(3)
	fmt.Printf("mst(3) edges: %v\n", edges)
	edges, _ = wg.MinimumSpanningSubtree(4)
	fmt.Printf("mst(5) edges: %v\n", edges)
}

func TestMultiplyEdgesWithVertices(t *testing.T) {
	wg := NewWGraph()
	err := wg.SetEdgeWeights([][]float64{
		{1, 2, 3, 4},
		{2, 1, 4, 3},
		{3, 4, 1, 2},
		{4, 3, 2, 1}})
	if err != nil {
		t.Fatalf("expected successful SetEdgeWeights, got error %s", err)
	}
	wg.SetVertexWeights([]float64{1.0, 1.0, math.Inf(1), 0.3})

	fmt.Printf("before multiply: %v\n", wg.EdgeWeights())
	fmt.Printf("multiply with: %v\n", wg.Vertices())
	wg.ForEachEdge(func(e *WEdge) {
		e.SetWeight(e.Weight() * e.Source().Weight() * e.Target().Weight())
	})
	fmt.Printf("after multiply: %v\n", wg.EdgeWeights())
}

func TestMSST(t *testing.T) {
	wg := NewWGraph()
	stepStart := time.Now()

	size := 1024
	eweights := make([][]float64, size)
	for src := range eweights {
		eweights[src] = make([]float64, size)
		for tgt := range eweights[src] {
			eweights[src][tgt] = rand.Float64()
		}
	}
	stepEnd := time.Now()
	t.Logf("\ncreated %dx%d weights: %d ms\n", size, size, stepEnd.Sub(stepStart).Milliseconds())

	stepStart = time.Now()
	err := wg.SetEdgeWeights(eweights)
	if err != nil {
		t.Fatalf("expected successful SetEdgeWeights, got error %s", err)
	}
	stepEnd = time.Now()
	t.Logf("\nSetEdgeWeight: %d ms\n", stepEnd.Sub(stepStart).Milliseconds())

	stepStart = time.Now()
	allEdges := wg.Edges()
	stepEnd = time.Now()
	t.Logf("\nEdges(): %d ms\n", stepEnd.Sub(stepStart).Milliseconds())

	stepStart = time.Now()
	allEdges.SortByWeight()
	stepEnd = time.Now()
	t.Logf("\nSortByWeight(): %d ms\n", stepEnd.Sub(stepStart).Milliseconds())

	stepStart = time.Now()
	edges, err := wg.MinimumSpanningSubtree(size)
	stepEnd = time.Now()
	t.Logf("MSST of %d edges: %d ms", len(edges), stepEnd.Sub(stepStart).Milliseconds())
}
