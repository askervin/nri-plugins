"""The two stage layouts of the presentation: one node (SINGLE) and two nodes (TWO_NODES).

Every coordinate of the presentation is in this file. Rows are shared by both layouts; a
layout only changes at a chapter card. A box line is: border, change marker (★ or space),
space, text, border; a state line keeps at least one space before the right border, so its
text budget is width - 5 (the technical-name line may use width - 4). Gaps of at most 4
columns between neighbour boxes of one zone carry straight arrows only (the router's rule).

    columns (both layouts)   cluster row: Scheduler 4-28 | API 33-80 | Pool controller 85-115
                             pool 4-115; edge wires in columns 2 and 117, badges also in 0-1, 118-119
    SINGLE (node-b)          workloads b1 4-37, b2 43-76, b3 82-115; Pod runner 4-31, agent 36-115
    TWO_NODES                node-a 4-57 | middle gutter 58-61 | node-b 62-115; per node: workloads of
                             26 columns, Pod runner 18, agent 32, hardware 54

    line  0       title bar
    line  1       zone rule: ANYWHERE IN THE CLUSTER
    lines 2-7     cluster row: Scheduler | Kubernetes API + objects | Pool controller
    line  8       zone rule(s): ONE NODE ...
    lines 9-13    workload containers (double lines)
    line  14      gutter
    lines 15-19   Pod runner | Node's CXL agent
    line  20      gutter
    lines 21-24   CXL memory seen by the node
    line  25      zone rule: OUTSIDE THE CLUSTER
    lines 26-29   Memory pool manager (technical name in its bottom border)
    lines 30-32   caption (the renderer), 33 legend, 34 blank, 35- message sequence
"""

from stageplay import Lane, Layout, Rule, Slot

WIDTH = 120
DIAGRAM_LINES = 30

# row map: (y, h) of every box row, y of every zone rule
CLUSTER = (2, 6)
WORKLOAD = (9, 5)
RUNNER = (15, 5)
HARDWARE = (21, 4)
POOL = (26, 4)
RULE_CLUSTER, RULE_NODE, RULE_OUTSIDE = 1, 8, 25
OUTSIDE_RULE_END = 108   # leaves room on line 25 for a wire from the right edge down into the pool

LEGEND = ("★ new or changed in this frame   ╔═╗ inside a container   ┄┄ not on stage yet / just gone"
          "   (n) step n   ▲►◄▼ this step")


def _slot(name, cols, row, lane, zone, **kw):
    x0, x1 = cols
    y, h = row
    return Slot(name=name, x=x0, y=y, w=x1 - x0 + 1, h=h, lane=lane, zone=zone, **kw)


def _cluster_and_pool():
    return [
        _slot("sched", (4, 28), CLUSTER, "schd", "cluster", placeholder="Scheduler"),
        _slot("api", (33, 80), CLUSTER, "api", "cluster", placeholder="Kubernetes API + objects"),
        _slot("ctrl", (85, 115), CLUSTER, "ctrl", "cluster", placeholder="Pool controller"),
        # arrows enter the pool from the top only: a side arrow would point at one device's line
        _slot("pool", (4, 115), POOL, "pool", "outside", tech="footer", placeholder="Memory pool manager",
              port_sides=("top",)),
    ]


def _node(node, cols, workloads, runner_w):
    """One node's column: workload slots, Pod runner + agent, hardware view."""
    x0, x1 = cols
    n = node[-1]          # "a" or "b"
    slots = []
    for i, (wx0, wx1) in enumerate(workloads, start=1):
        slots.append(_slot(f"{n}{i}", (wx0, wx1), WORKLOAD, f"pod-{n}", f"container-{n}", style="double"))
    slots += [
        _slot(f"runner_{n}", (x0, x0 + runner_w - 1), RUNNER, f"kblt-{n}", node, placeholder="Pod runner"),
        _slot(f"agent_{n}", (x0 + runner_w + 4, x1), RUNNER, f"agnt-{n}", node, placeholder="Node's CXL agent"),
        _slot(f"hw_{n}", (x0, x1), HARDWARE, f"hw-{n}", node, placeholder="CXL memory seen by the node"),
    ]
    return slots


def _lanes(spec):
    return tuple(Lane(key, label) for key, label in spec)


SINGLE = Layout(
    name="SINGLE",
    width=WIDTH,
    diagram_lines=DIAGRAM_LINES,
    slots={s.name: s for s in _cluster_and_pool()
           + _node("node-b", (4, 115), [(4, 37), (43, 76), (82, 115)], runner_w=28)},
    rules=(
        Rule(RULE_CLUSTER, 4, 115, "ANYWHERE IN THE CLUSTER"),
        Rule(RULE_NODE, 4, 115, "ONE NODE: node-b (VM2, control plane)"),
        Rule(RULE_OUTSIDE, 4, OUTSIDE_RULE_END, "OUTSIDE THE CLUSTER, possibly"),
    ),
    lanes=_lanes([("pod-b", "Pod"), ("agnt-b", "agnt"), ("kblt-b", "kblt"), ("hw-b", "HW"),
                  ("schd", "schd"), ("api", "API"), ("ctrl", "ctrl"), ("pool", "pool")]),
    lane_width=7,
    lane_groups=(("pod-b", "hw-b", "node-b"), ("schd", "ctrl", "cluster"), ("pool", "pool", "pool")),
    legend=LEGEND,
    badge_cols=(0, 1, 118, 119),
)

TWO_NODES = Layout(
    name="TWO_NODES",
    width=WIDTH,
    diagram_lines=DIAGRAM_LINES,
    slots={s.name: s for s in _cluster_and_pool()
           + _node("node-a", (4, 57), [(4, 29), (32, 57)], runner_w=18)
           + _node("node-b", (62, 115), [(62, 87), (90, 115)], runner_w=18)},
    rules=(
        Rule(RULE_CLUSTER, 4, 115, "ANYWHERE IN THE CLUSTER"),
        Rule(RULE_NODE, 4, 57, "ONE NODE: node-a (VM1, worker)"),
        Rule(RULE_NODE, 62, 115, "ONE NODE: node-b (VM2, control plane)"),
        Rule(RULE_OUTSIDE, 4, OUTSIDE_RULE_END, "OUTSIDE THE CLUSTER, possibly"),
    ),
    lanes=_lanes([("pod-a", "Pod"), ("agnt-a", "agnt"), ("kblt-a", "kblt"), ("hw-a", "HW"),
                  ("schd", "schd"), ("api", "API"), ("ctrl", "ctrl"), ("pool", "pool"),
                  ("hw-b", "HW"), ("kblt-b", "kblt"), ("agnt-b", "agnt"), ("pod-b", "Pod")]),
    lane_width=5,
    lane_groups=(("pod-a", "hw-a", "node-a"), ("schd", "ctrl", "cluster"), ("pool", "pool", "pool"),
                 ("hw-b", "pod-b", "node-b")),
    legend=LEGEND,
    badge_cols=(0, 1, 118, 119),
)
