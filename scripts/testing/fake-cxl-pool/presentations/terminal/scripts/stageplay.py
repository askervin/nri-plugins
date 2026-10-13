#!/usr/bin/env python3
"""stageplay -- render a scripted story as text frames for `less`.

A story is a sequence of calls on a Stage:

    s.entity(...), s.state(...), s.set(...), s.remove(...)   who is on stage and what they show
    s.send(...), s.reply(...), s.note(...)                   what happens (one sequence row each)
    s.caption(...), s.frame(...)                             narrate and take a picture
    s.chapter(...), s.card(...)                              title and recap pages
    s.finish()                                               render, check and write all files

Entities live in slots that the layout declares by name (see layouts.py); the story never
mentions coordinates or frame numbers. A frame records everything it needs (boxes with their
change markers, the arrows of the frame, the caption, the message sequence of the chapter);
the text is rendered in finish(), once the total number of frames is known.

Python 3 standard library only; the output is a pure function of the story (deterministic).
"""

from __future__ import annotations

import argparse
import heapq
import os
import re
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------------- glyphs

H, V, TL, TR, BL, BR = "─", "│", "┌", "┐", "└", "┘"
DH, DV, DTL, DTR, DBL, DBR = "═", "║", "╔", "╗", "╚", "╝"
DOT_H, DOT_V, DASH = "┄", "┆", "╌"
STAR = "★"
HEAD = {"up": "▲", "down": "▼", "right": "►", "left": "◄"}
# tee on a box border where a wire leaves the box, by (border style, side)
TEE = {
    ("single", "top"): "┴", ("single", "bottom"): "┬", ("single", "left"): "┤", ("single", "right"): "├",
    ("double", "top"): "╧", ("double", "bottom"): "╤", ("double", "left"): "╢", ("double", "right"): "╟",
}
# corner of a wire that turns: (direction before, direction after) -> glyph
TURN = {
    ("right", "down"): TR, ("right", "up"): BR, ("left", "down"): TL, ("left", "up"): BL,
    ("down", "right"): BL, ("down", "left"): BR, ("up", "right"): TL, ("up", "left"): TR,
}

UNICODE_GLYPHS = "─│┌┐└┘├┤┬┴┼═║╔╗╚╝╤╧╟╢┄┆╌►◄▲▼★"
ASCII_MAP = str.maketrans({
    "─": "-", "│": "|", "┌": "+", "┐": "+", "└": "+", "┘": "+", "├": "+", "┤": "+", "┬": "+", "┴": "+",
    "┼": "+", "═": "=", "║": "|", "╔": "+", "╗": "+", "╚": "+", "╝": "+", "╤": "+", "╧": "+", "╟": "+",
    "╢": "+", "┄": ".", "┆": ":", "╌": ".", "►": ">", "◄": "<", "▲": "^", "▼": "v", "★": "*",
})
PRINTABLE_ASCII = {chr(c) for c in range(0x20, 0x7F)}
ALLOWED_UNICODE = PRINTABLE_ASCII | set(UNICODE_GLYPHS)

# --------------------------------------------------------------------------------- colors (--colors)

# Foreground colors (xterm-256) by role; soft tones, no background, no bold, so every line stays
# readable. added: an entity that appears in this frame; changed: a state line that differs
# from the previous frame; removed: an entity shown for the last time; active: this frame's
# messages (arrow, badge, caption head, new sequence rows); muted: not on stage yet, lifelines.
PALETTES = {
    "dark": {"added": 114, "changed": 222, "removed": 174, "active": 110, "muted": 243},
    "light": {"added": 28, "changed": 130, "removed": 131, "active": 25, "muted": 248},
}
# legend words that double as the color key, colored wherever the legend contains them
LEGEND_ROLES = (("new", "added"), ("changed", "changed"), ("┄┄", "muted"), ("not on stage yet", "muted"),
                ("just gone", "removed"), ("(n) step n", "active"), ("▲►◄▼ this step", "active"))
SGR_RESET = "\x1b[0m"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

DIRS = {"up": (0, -1), "down": (0, 1), "left": (-1, 0), "right": (1, 0)}
DIR_ORDER = ("up", "down", "left", "right")
OPPOSITE = {"up": "down", "down": "up", "left": "right", "right": "left"}
OUTWARD = {"top": "up", "bottom": "down", "left": "left", "right": "right"}


class StoryError(Exception):
    """A mistake in the story (unknown entity, text too long, ...)."""


# --------------------------------------------------------------------------------- layout types

@dataclass(frozen=True)
class Slot:
    """A named place for a box. Coordinates are absolute (column x, line y), inclusive size w x h.

    tech: where the technical name of the entity goes: "line" (first inner line), "footer"
    (written into the bottom border) or "none". ports: preferred port per side ("top",
    "bottom": a column; "left", "right": a line); default the middle of the side (for side
    ports of boxes with a technical-name line: that line). port_sides: the sides that arrows
    may use.
    placeholder: drawn dotted with this title until an entity is created in the slot; None
    means the slot is blank while empty.
    """
    name: str
    x: int
    y: int
    w: int
    h: int
    lane: str
    zone: str = ""
    style: str = "single"
    tech: str = "line"
    placeholder: str | None = None
    ports: tuple = ()
    port_sides: tuple = ("top", "bottom", "left", "right")

    @property
    def state_rows(self) -> int:
        return self.h - 2 - (1 if self.tech == "line" else 0)

    @property
    def budget(self) -> int:
        """Characters of one state line: border, marker, space, text, at least one space, border."""
        return self.w - 5

    @property
    def tech_budget(self) -> int:
        """Characters of the technical-name line, which may touch the right border."""
        return self.w - 4


@dataclass(frozen=True)
class Rule:
    """A horizontal zone rule on line y from column x0 to x1, with a label at its left end."""
    y: int
    x0: int
    x1: int
    label: str


@dataclass(frozen=True)
class Lane:
    key: str     # unique, e.g. "agnt-b"
    label: str   # shown, at most lane width - 1 characters


@dataclass(frozen=True)
class Layout:
    name: str
    width: int
    diagram_lines: int
    slots: dict
    rules: tuple
    lanes: tuple
    lane_width: int
    lane_groups: tuple       # (first lane key, last lane key, label)
    legend: str
    badge_cols: tuple = ()   # columns where only badges may go, never wires

    def slot(self, name: str) -> Slot:
        return self.slots[name]


# --------------------------------------------------------------------------------- canvas

class Canvas:
    """Characters plus a color role per cell (None: default color); the roles are used only with --colors."""

    def __init__(self, width: int, height: int):
        self.width, self.height = width, height
        self.cells = [[" "] * width for _ in range(height)]
        self.roles = [[None] * width for _ in range(height)]

    def put(self, x: int, y: int, text: str, role: str | None = None) -> None:
        if not 0 <= y < self.height or x < 0 or x + len(text) > self.width:
            raise StoryError(f"text outside the canvas at ({x},{y}): {text!r}")
        row, roles = self.cells[y], self.roles[y]
        for i, ch in enumerate(text):
            row[x + i] = ch
            roles[x + i] = role

    def tint(self, x: int, y: int, length: int, role: str | None) -> None:
        """Color cells without changing their characters."""
        for i in range(length):
            self.roles[y][x + i] = role

    def lines(self) -> list:
        return ["".join(row).rstrip() for row in self.cells]

    def spans(self) -> list:
        return [runs(roles) for roles in self.roles]


# --------------------------------------------------------------------------------- recorded story

@dataclass
class Entity:
    id: str
    slot: str
    title: str
    tech: tuple
    lines: list
    name: str
    rows: tuple
    epitaph: str | None = None


@dataclass
class Step:
    n: int
    kind: str             # "request" | "reply" | "note"
    src: str | None
    dst: str | None
    src_lane: str | None
    dst_lane: str | None
    src_name: str
    dst_name: str
    label: str
    short: str | None
    draw: bool | None


@dataclass
class BoxView:
    slot: Slot
    mode: str             # "normal" | "placeholder" | "gone"
    title: str
    title_star: bool
    tech: tuple           # alternatives for the technical name (without parentheses)
    rows: list            # [(star, text)] state rows, len == slot.state_rows


@dataclass
class Snap:
    kind: str             # "diagram" | "card"
    chapter: int
    index: int
    slug: str
    title: str
    chapter_short: str
    layout: Layout | None = None
    boxes: list = field(default_factory=list)
    arrows: list = field(default_factory=list)       # Step objects drawn in this frame
    new_steps: list = field(default_factory=list)    # Step objects added in this frame
    msc: list = field(default_factory=list)          # all Step objects of the chapter so far
    narration: str = ""
    card: dict | None = None
    slots: dict = field(default_factory=dict)        # entity id -> slot name, as of this frame


# --------------------------------------------------------------------------------- routing

FREE, BOX, RULE, LABEL, BLOCKED, HONLY = range(6)
NARROW_GAP = 4          # a gap this narrow between two boxes of one zone and row is for straight arrows only

STEP_COST, TURN_COST, HUG_COST = 10, 80, 30
PORT_COST = 100         # a port at the end of a side costs this much more than one in the middle
CORNER_COST = 40        # extra for a port within 2 cells of a corner
SIDE_COST = 300         # extra for a side port between boxes of different rows
AWAY_COST = 300         # extra for a port on the side that faces away from the other box


@dataclass
class Placed:
    """A box drawn on a canvas, as the router sees it."""
    slot: Slot
    protected: set        # border cells that are not ports (corners, title, footer)


class Router:
    """Orthogonal wires in the free cells of a frame, found by a shortest-path search.

    Cost = length + a penalty per turn + a penalty for running alongside a box side + the
    distance of each end from the middle of its box side. Wires never run along a zone rule
    (they may cross it), never cross labels, boxes, the title line or another wire of the
    frame. The search is deterministic.
    """

    def __init__(self, layout: Layout, grid: list):
        self.layout = layout
        self.grid = grid
        self.width = layout.width
        self.height = len(grid)

    def ports(self, p: Placed):
        s = p.slot
        x0, y0, x1, y1 = s.x, s.y, s.x + s.w - 1, s.y + s.h - 1
        pref = dict(s.ports)
        cells = []
        for side, coords in (("top", [(x, y0) for x in range(x0 + 1, x1)]),
                             ("bottom", [(x, y1) for x in range(x0 + 1, x1)]),
                             ("left", [(x0, y) for y in range(y0 + 1, y1)]),
                             ("right", [(x1, y) for y in range(y0 + 1, y1)])):
            usable = [c for c in coords if c not in p.protected]
            if not usable or side not in s.port_sides:
                continue
            horizontal = side in ("top", "bottom")
            if side in pref:
                mid = pref[side]
            elif horizontal:
                mid = (x0 + x1) // 2
            elif s.tech == "line":
                mid = y0 + 1      # a side arrow points at the technical name, not into a state line
            else:
                mid = (y0 + y1) // 2
            # preferred port: the usable cell nearest to the middle of the side
            best = min(usable, key=lambda c: (abs((c[0] if horizontal else c[1]) - mid), c))
            b = best[0] if horizontal else best[1]
            lo, hi = (x0, x1) if horizontal else (y0, y1)
            half = max(1, (hi - lo) // 2)
            for c in usable:
                pos = c[0] if horizontal else c[1]
                cost = abs(pos - b) * PORT_COST // half
                if horizontal and min(pos - lo, hi - pos) <= 2:
                    cost += CORNER_COST
                cells.append((side, c[0], c[1], cost))
        return cells

    def hugging(self, x: int, y: int) -> bool:
        for nx in (x - 1, x + 1):
            if 0 <= nx < self.width and self.grid[y][nx] == BOX:
                return True
        return False

    def route(self, src: Placed, dst: Placed, taken: set):
        """The wire from a port of src to a port of dst, avoiding the cells in taken:
        [(x, y, glyph, direction in, direction out)], from the tee on src to the head on dst."""
        a, b = src.slot, dst.slot
        same_row = a.y < b.y + b.h and b.y < a.y + a.h

        left_edge = min(sl.x for sl in self.layout.slots.values())
        right_edge = max(sl.x + sl.w - 1 for sl in self.layout.slots.values())

        def away_cost(slot, other, side):
            # a wire does not leave (or enter) a box on the side that faces away from the other box
            above = other.y + other.h <= slot.y
            below = other.y >= slot.y + slot.h
            if (side == "bottom" and above) or (side == "top" and below):
                return AWAY_COST
            return 0

        def side_cost(slot, side):
            # boxes in different rows talk through their top and bottom; a side port only when it
            # faces the edge of the screen, where the wires that go a long way run
            if side not in ("left", "right") or same_row:
                return 0
            if (side == "left" and slot.x == left_edge) or (side == "right" and slot.x + slot.w - 1 == right_edge):
                return 0
            return SIDE_COST

        targets = {}
        for side, x, y, dev in self.ports(dst):
            if (x, y) not in taken:
                targets[(x, y)] = (OPPOSITE[OUTWARD[side]], 2 * dev + side_cost(b, side) + away_cost(b, a, side))   # heads: near the middle
        heap = []
        start_info = {}
        for side, x, y, dev in self.ports(src):
            if (x, y) in taken:
                continue
            dev += side_cost(a, side) + away_cost(a, b, side)
            d = OUTWARD[side]
            state = (x, y, d)
            start_info[state] = side
            heapq.heappush(heap, (dev, y, x, DIR_ORDER.index(d), 0))
        best = {}
        prev = {}
        arrived = {}
        done = set()
        while heap:
            cost, y, x, di, fin = heapq.heappop(heap)
            d = DIR_ORDER[di]
            state = (x, y, d)
            if fin:
                path = [state]
                cur = arrived[state]
                while cur is not None:
                    path.append(cur)
                    cur = prev.get(cur)
                path.reverse()
                return self.glyphs(path, src, dst, start_info[path[0]])
            if state in done:
                continue
            done.add(state)
            here = self.grid[y][x]
            at_port = state in start_info
            for nd in (d, *[t for t in DIR_ORDER if t not in (d, OPPOSITE[d])]):
                if nd != d and (at_port or here in (RULE, HONLY)):
                    continue
                dx, dy = DIRS[nd]
                nx, ny = x + dx, y + dy
                if not (0 <= nx < self.width and 0 <= ny < self.height):
                    continue
                step = STEP_COST + (TURN_COST if nd != d else 0)
                if (nx, ny) in targets:
                    inward, dev = targets[(nx, ny)]
                    fstate = (nx, ny, nd)
                    fcost = cost + step + dev
                    if inward == nd and fcost < best.get(("fin", fstate), 1 << 60):
                        best[("fin", fstate)] = fcost
                        arrived[fstate] = state
                        heapq.heappush(heap, (fcost, ny, nx, DIR_ORDER.index(nd), 1))
                    continue
                if (nx, ny) in taken:
                    continue
                cls = self.grid[ny][nx]
                if cls == FREE:
                    pass
                elif cls == RULE and nd in ("up", "down"):
                    pass
                elif cls == HONLY and nd in ("left", "right"):
                    pass
                else:
                    continue
                if nd in ("up", "down") and self.hugging(nx, ny):
                    step += HUG_COST
                nstate = (nx, ny, nd)
                ncost = cost + step
                if nstate in done or best.get(nstate, 1 << 60) <= ncost:
                    continue
                best[nstate] = ncost
                prev[nstate] = state
                heapq.heappush(heap, (ncost, ny, nx, DIR_ORDER.index(nd), 0))
        raise StoryError(f"no route from {src.slot.name} to {dst.slot.name}")

    def glyphs(self, path, src: Placed, dst: Placed, src_side: str):
        out = []
        n = len(path)
        for i, (x, y, d) in enumerate(path):
            if i == 0:
                style = "double" if src.slot.style == "double" else "single"
                out.append((x, y, TEE[(style, src_side)], d, d))
                continue
            if i == n - 1:
                out.append((x, y, HEAD[d], d, d))
                continue
            nd = path[i + 1][2]
            if nd == d:
                g = H if d in ("left", "right") else V
            else:
                g = TURN[(d, nd)]
            out.append((x, y, g, d, nd))
        return out


# --------------------------------------------------------------------------------- the stage

class Stage:
    def __init__(self, title: str, layout: Layout, short_title: str | None = None,
                 out_dir: Path | None = None, argv: list | None = None):
        self.title = title
        self.short_title = short_title or title
        self.layout = layout
        self.args = self._parse(argv)
        default_out = Path(__file__).resolve().parent.parent / "rendered"
        self.out_dir = Path(self.args.out) if self.args.out else (out_dir or default_out)
        self.entities: dict = {}
        self.snaps: list = []
        self.chapter_no = -1
        self.chapter_title = ""
        self.chapter_short = ""
        self.frame_index = 0
        self.steps: list = []          # steps of the current chapter
        self.pending: list = []        # steps since the last frame
        self.narration = ""
        self.shown: dict = {}          # entity id -> lines shown in the last diagram frame
        self.serial = 0                # frames recorded so far
        self.chapters: list = []       # (number, title, short, first snap index)

    # ---- command line

    @staticmethod
    def _parse(argv):
        p = argparse.ArgumentParser(description="Render the presentation frames.")
        p.add_argument("--out", help="output directory (default: ../rendered next to scripts/)")
        p.add_argument("--check", action="store_true", help="render in memory and verify every frame")
        p.add_argument("--chapter", type=int, help="write only this chapter's files")
        p.add_argument("--frame", help="write only this frame (global number NNN or slug)")
        p.add_argument("--ascii", action="store_true", help="ASCII glyphs instead of box drawing")
        p.add_argument("--colors", nargs="?", const="dark", choices=sorted(PALETTES), metavar="THEME",
                       help="color what is new, changed, gone and this frame's messages (ANSI, view with "
                            "less -R); THEME: dark (default) or light terminal background")
        p.add_argument("--list", action="store_true", help="print the index of frames, write nothing")
        return p.parse_args(argv)

    # ---- helpers

    def _where(self) -> str:
        return f"chapter {self.chapter_no}, after frame {self.chapter_no}.{self.frame_index - 1:02d}"

    def _fail(self, msg: str):
        raise StoryError(f"{self._where()}: {msg}")

    def _entity(self, eid: str) -> Entity:
        if eid not in self.entities:
            self._fail(f"unknown entity {eid!r}")
        return self.entities[eid]

    @staticmethod
    def _no_star(text: str, what: str):
        if STAR in text:
            raise StoryError(f"{what}: the change marker {STAR} is added automatically, do not write it: {text!r}")

    # ---- structure

    def chapter(self, number: int, title: str, short: str, body: list, layout: Layout | None = None,
                clear_workloads: bool = True, source: str = "", heading: str | None = None) -> None:
        """Start a chapter: renders its title card (frame N.00), resets the message sequence and the
        step numbers, optionally switches the layout (empty workload slots are cleared first)."""
        self._flush_check()
        self.chapter_no = number
        self.chapter_title = title
        self.chapter_short = short
        self.frame_index = 0
        self.steps = []
        if clear_workloads:
            for eid in [e.id for e in self.entities.values()
                        if self.layout.slot(e.slot).placeholder is None]:
                del self.entities[eid]
                self.shown.pop(eid, None)
        if layout is not None:
            for e in self.entities.values():
                if e.slot not in layout.slots:
                    self._fail(f"entity {e.id!r} is in slot {e.slot!r}, which layout {layout.name} lacks")
            self.layout = layout
        self.chapters.append((number, title, short, len(self.snaps)))
        self._card("card", heading or f"Chapter {number}    {title}", body, source=source, chapter_card=True)

    def card(self, slug: str, heading: str, body: list, source: str = "") -> None:
        """A text page inside the chapter (recap, glossary): no diagram, no message sequence."""
        self._flush_check()
        self._card(slug, heading, body, source=source, chapter_card=False)

    def _card(self, slug, heading, body, source, chapter_card):
        # cards may show the marker (to explain it): only state lines, messages and captions may not
        snap = Snap(kind="card", chapter=self.chapter_no, index=self.frame_index, slug=slug,
                    title="title card" if chapter_card else slug.replace("-", " "),
                    chapter_short=self.chapter_short,
                    card=dict(heading=heading, body=list(body), source=source, chapter_card=chapter_card))
        self.snaps.append(snap)
        self.frame_index += 1
        self.serial += 1

    def _flush_check(self):
        if self.pending:
            self._fail(f"{len(self.pending)} step(s) recorded after the last frame and never shown")

    # ---- entities

    def entity(self, eid: str, slot: str, title: str, tech, *lines: str, name: str | None = None,
               rows: tuple = ()) -> None:
        """Create an entity in a slot (or re-create it: it is then marked new again).

        tech: the technical name (shown in parentheses), or a tuple of alternatives, longest first:
        the first that fits the box is used. rows: optional names of the state lines for set()."""
        if slot not in self.layout.slots:
            self._fail(f"layout {self.layout.name} has no slot {slot!r}")
        for other in self.entities.values():
            if other.slot == slot and other.id != eid:
                if other.epitaph is None:
                    self._fail(f"slot {slot!r} is taken by {other.id!r}")
                self._fail(f"slot {slot!r} still shows {other.id!r} leaving in this frame")
        techs = (tech,) if isinstance(tech, str) else tuple(tech)
        for t in (title, *techs, *lines):
            self._no_star(t, f"entity {eid}")
        cap = self.layout.slot(slot).state_rows
        if len(lines) > cap:
            self._fail(f"entity {eid!r}: {len(lines)} state lines, slot {slot!r} has {cap}")
        self.entities[eid] = Entity(id=eid, slot=slot, title=title, tech=techs,
                                    lines=list(lines) + [""] * (cap - len(lines)),
                                    name=name or title, rows=tuple(rows))
        self.shown.pop(eid, None)

    def state(self, eid: str, *lines: str) -> None:
        """Replace all state lines of an entity (missing lines become empty)."""
        e = self._entity(eid)
        cap = self.layout.slot(e.slot).state_rows
        if len(lines) > cap:
            self._fail(f"entity {eid!r}: {len(lines)} state lines, slot {e.slot!r} has {cap}")
        for t in lines:
            self._no_star(t, f"entity {eid}")
        e.lines = list(lines) + [""] * (cap - len(lines))

    def set(self, eid: str, **rows: str) -> None:
        """Replace named state lines, e.g. set("api", claims="..."). Names come from entity(rows=...);
        without names, the lines are l1, l2, l3."""
        e = self._entity(eid)
        names = e.rows or tuple(f"l{i + 1}" for i in range(len(e.lines)))
        for key, text in rows.items():
            if key not in names:
                self._fail(f"entity {eid!r} has no state line {key!r} (has {', '.join(names)})")
            self._no_star(text, f"entity {eid}")
            e.lines[names.index(key)] = text

    def remove(self, eid: str, epitaph: str = "(gone)") -> None:
        """The entity is shown once more, dotted, with the epitaph as its last line; then it is gone."""
        e = self._entity(eid)
        self._no_star(epitaph, f"entity {eid}")
        e.epitaph = epitaph

    # ---- communication

    def _step(self, kind, src, dst, label, short, draw) -> int:
        self._no_star(label, "message")
        if short:
            self._no_star(short, "message")
        if src is None:
            step = Step(n=len(self.steps) + 1, kind=kind, src=None, dst=None, src_lane=None, dst_lane=None,
                        src_name="", dst_name="", label=label, short=short, draw=False)
        else:
            # the ends are resolved when the frame is taken: a message may name an entity that the
            # same frame creates afterwards (kubelet starts a container, then the container is there)
            step = Step(n=len(self.steps) + 1, kind=kind, src=src, dst=dst, src_lane=None, dst_lane=None,
                        src_name="", dst_name="", label=label, short=short, draw=draw)
        self.steps.append(step)
        self.pending.append(step)
        return step.n

    def send(self, src: str, dst: str, label: str, short: str | None = None, draw: bool | None = None) -> int:
        """A request from src to dst: one sequence row. draw=None: drawn if it is the last message of
        the frame and no message of the frame says draw=True."""
        return self._step("request", src, dst, label, short, draw)

    def reply(self, src: str, dst: str, label: str, short: str | None = None, draw: bool | None = None) -> int:
        """A reply: like send(), dashed in the message sequence."""
        return self._step("reply", src, dst, label, short, draw)

    def note(self, text: str, short: str | None = None) -> int:
        """Something that happens without a message between the entities (a user's kubectl, time passing)."""
        return self._step("note", None, None, text, short, False)

    def settle(self) -> None:
        """Count everything on stage now as already seen: the next frame marks only later changes.
        For the quiet reset of states at the start of a chapter."""
        self.shown = {e.id: list(e.lines) for e in self.entities.values()}

    # ---- frames

    def caption(self, *text: str) -> None:
        """Narration under the picture; wrapped automatically."""
        joined = " ".join(t.strip() for t in text)
        self._no_star(joined, "caption")
        self.narration = joined

    def frame(self, slug: str, title: str | None = None) -> None:
        """Take a picture of the current state."""
        if not re.fullmatch(r"[a-z0-9-]+", slug):
            self._fail(f"slug {slug!r}: use a-z, 0-9 and -")
        lay = self.layout
        for step in self.pending:
            if step.src is None:
                continue
            for end in (step.src, step.dst):
                if end not in self.entities:
                    self._fail(f"step {step.n} ({step.label[:40]!r}...): unknown entity {end!r}")
            a, b = self.entities[step.src], self.entities[step.dst]
            step.src_lane, step.dst_lane = lay.slot(a.slot).lane, lay.slot(b.slot).lane
            step.src_name, step.dst_name = a.name, b.name
            if step.src_lane == step.dst_lane:
                self._fail(f"step {step.n}: {step.src} and {step.dst} share the sequence lane {step.src_lane!r}")
        boxes = []
        for sname, slot in lay.slots.items():
            ent = next((e for e in self.entities.values() if e.slot == sname), None)
            if ent is None:
                if slot.placeholder:
                    boxes.append(BoxView(slot=slot, mode="placeholder", title=slot.placeholder, title_star=False,
                                         tech=(), rows=[(False, "(not on stage yet)")] +
                                         [(False, "")] * (slot.state_rows - 1)))
                continue
            new = ent.id not in self.shown
            before = self.shown.get(ent.id, [])
            rows = []
            for i, text in enumerate(ent.lines):
                old = before[i] if i < len(before) else ""
                rows.append((bool(text) and (new or text != old), text))
            mode = "normal"
            if ent.epitaph is not None:
                mode = "gone"
                rows[-1] = (True, ent.epitaph)
            boxes.append(BoxView(slot=slot, mode=mode, title=ent.title, title_star=new,
                                 tech=ent.tech, rows=rows))
        drawn = [s for s in self.pending if s.kind != "note" and s.draw is True]
        if not drawn:
            last = [s for s in self.pending if s.kind != "note" and s.draw is None]
            drawn = last[-1:]
        snap = Snap(kind="diagram", chapter=self.chapter_no, index=self.frame_index, slug=slug,
                    title=title or slug.replace("-", " "), chapter_short=self.chapter_short, layout=lay,
                    boxes=boxes, arrows=drawn, new_steps=list(self.pending), msc=list(self.steps),
                    narration=self.narration, slots={e.id: e.slot for e in self.entities.values()})
        self.snaps.append(snap)
        self.frame_index += 1
        self.serial += 1
        # after the picture: remember what was shown, drop the departed, clear per-frame things
        for eid in [e.id for e in self.entities.values() if e.epitaph is not None]:
            del self.entities[eid]
            self.shown.pop(eid, None)
        self.shown = {e.id: list(e.lines) for e in self.entities.values()}
        self.pending = []
        self.narration = ""

    # ---- rendering

    def finish(self) -> None:
        self._flush_check()
        renderer = Renderer(self)
        files = renderer.render_all()
        problems = renderer.problems
        if self.args.list:
            print(renderer.index_text(), end="")
            return
        if problems:
            # the same problem usually repeats in every later frame: report it once, with a count
            seen = {}
            for p in problems:
                frame, _, what = p.partition(": ")
                if what in seen:
                    seen[what][1] += 1
                else:
                    seen[what] = [frame, 0]
            for what, (frame, more) in seen.items():
                tail = f" (and {more} later frame{'s' if more > 1 else ''})" if more else ""
                print(f"{frame}{tail}: {what}", file=sys.stderr)
            print(f"{len(seen)} problem(s); nothing written", file=sys.stderr)
            sys.exit(1)
        if self.args.check:
            for w in sorted(renderer.warnings):
                print(f"warning: {w}")
            print(f"check OK: {len(files) - 1} frames, {len(self.chapters)} chapters"
                  f"{' (ascii)' if self.args.ascii else ''}")
            return
        selected = files
        partial = self.args.chapter is not None or self.args.frame is not None
        if partial:
            selected = [(name, text) for name, text, meta in renderer.meta_files if self._selected(name, meta)]
            if not selected:
                print("no frame matches the selection", file=sys.stderr)
                sys.exit(1)
        write_files(self.out_dir, selected, clean=not partial)
        print(f"wrote {len(selected)} file(s) to {self.out_dir}")

    def _selected(self, name, meta):
        if meta is None:
            return False
        if self.args.chapter is not None and meta.chapter != self.args.chapter:
            return False
        if self.args.frame is not None:
            f = self.args.frame
            return name.startswith(f + "-") or name[:3] == f.zfill(3) or name.endswith(f"-{f}.txt")
        return True


def write_files(out_dir: Path, files: list, clean: bool) -> None:
    """Write via a temporary directory next to out_dir, so a failure leaves the old files intact.
    With clean, remove numbered frame files of earlier runs that this run did not write."""
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".render-", dir=out_dir.parent))
    try:
        for name, text in files:
            (tmp / name).write_text(text, encoding="utf-8", newline="\n")
        for name, _ in files:
            os.replace(tmp / name, out_dir / name)
    finally:
        for leftover in tmp.iterdir():
            leftover.unlink()
        tmp.rmdir()
    if clean:
        keep = {name for name, _ in files}
        for old in sorted(out_dir.iterdir()):
            if re.fullmatch(r"[0-9]{3}-.*\.txt", old.name) and old.name not in keep:
                old.unlink()


# --------------------------------------------------------------------------------- renderer

class Renderer:
    def __init__(self, stage: Stage):
        self.stage = stage
        self.ascii = stage.args.ascii
        self.palette = PALETTES[stage.args.colors] if stage.args.colors else None
        self.spans: dict = {}          # line -> [(x0, x1, role)] of the frame being rendered
        self.problems: list = []
        self.warnings: set = set()
        self.meta_files: list = []
        self.names: list = []

    # ---- all frames

    def render_all(self):
        st = self.stage
        total = len(st.snaps)
        # file names first: the index and cards refer to them
        self.names = []
        for k, snap in enumerate(st.snaps, start=1):
            self.names.append(f"{k:03d}-ch{snap.chapter}-{snap.slug}.txt")
        seen = set()
        for snap, name in zip(st.snaps, self.names):
            key = (snap.chapter, snap.slug)
            if key in seen:
                self.problems.append(f"frame {name}: slug {snap.slug!r} used twice in chapter {snap.chapter}")
            seen.add(key)
        files = []
        self.meta_files = []
        for k, snap in enumerate(st.snaps, start=1):
            self.cur = f"frame {self.names[k - 1]}"
            self.spans = {}
            if snap.kind == "card":
                lines = self.render_card(snap, k, total)
            else:
                lines = self.render_diagram(snap, k, total)
            text = "\n".join(line.rstrip() for line in lines).rstrip("\n") + "\n"
            if self.ascii:
                text = text.translate(ASCII_MAP)
            self.check_text(text, snap)
            text = self.paint(text)
            files.append((self.names[k - 1], text))
            self.meta_files.append((self.names[k - 1], text, snap))
        index = self.index_text()
        if self.ascii:
            index = index.translate(ASCII_MAP)
        self.cur = "frame 000-index.txt"
        self.check_text(index, None)
        files.insert(0, ("000-index.txt", index))
        self.meta_files.insert(0, ("000-index.txt", index, None))
        return files

    def problem(self, msg: str):
        self.problems.append(f"{self.cur}: {msg}")

    # ---- colors

    def mark(self, y: int, x0: int, x1: int, role: str | None) -> None:
        """Color columns x0..x1-1 of output line y (with --colors; plain output ignores it)."""
        if role is not None and x1 > x0:
            self.spans.setdefault(y, []).append((x0, x1, role))

    def mark_runs(self, y: int, roles: list) -> None:
        for x0, x1, role in runs(roles):
            self.mark(y, x0, x1, role)

    def paint(self, text: str) -> str:
        """Insert the color escapes of the marked spans; the checked plain text stays the same."""
        if self.palette is None:
            return text
        out = []
        for y, line in enumerate(text.split("\n")):
            roles = [None] * len(line)
            for x0, x1, role in self.spans.get(y, ()):
                for x in range(max(0, x0), min(x1, len(line))):
                    roles[x] = role
            parts, cur = [], None
            for ch, role in zip(line, roles):
                if role != cur:
                    if cur is not None:
                        parts.append(SGR_RESET)
                    if role is not None:
                        parts.append(f"\x1b[38;5;{self.palette[role]}m")
                    cur = role
                parts.append(ch)
            if cur is not None:
                parts.append(SGR_RESET)
            out.append("".join(parts))
        painted = "\n".join(out)
        if ANSI_RE.sub("", painted) != text:
            self.problem("colored text differs from the plain text")
        return painted

    def check_text(self, text: str, snap):
        allowed = PRINTABLE_ASCII if self.ascii else ALLOWED_UNICODE
        width = self.stage.layout.width
        for no, line in enumerate(text.split("\n")[:-1]):
            if len(line) > width:
                self.problem(f"line {no} is {len(line)} characters long (max {width})")
            bad = sorted({ch for ch in line if ch not in allowed})
            if bad:
                self.problem(f"line {no} has characters outside the allowed set: {' '.join(map(repr, bad))}")
            if line != line.rstrip():
                self.problem(f"line {no} has trailing spaces")
        if snap is not None and snap.kind == "diagram":
            lines = text.split("\n")
            legend = snap.layout.legend.translate(ASCII_MAP) if self.ascii else snap.layout.legend
            if len(lines) < snap.layout.diagram_lines + 4 or lines[snap.layout.diagram_lines + 3] != legend:
                self.problem("the legend is not on its fixed line: the picture or the caption has the wrong height")

    # ---- title bar

    def title_bar(self, snap: Snap, k: int, total: int) -> str:
        st = self.stage
        parts = [st.short_title, f"Ch {snap.chapter} {snap.chapter_short}",
                 f"{snap.chapter}.{snap.index:02d} {snap.title}", f"frame {k}/{total}"]
        bar = " │ ".join(parts)
        if len(bar) > st.layout.width:
            self.problem(f"title bar is {len(bar)} characters long: shorten the frame title {snap.title!r}")
        return bar

    # ---- cards

    def render_card(self, snap: Snap, k: int, total: int) -> list:
        st = self.stage
        width = st.layout.width
        d = st.layout.diagram_lines
        card = snap.card
        inner = width - 8
        block = ["═" * inner, card["heading"], "═" * inner, ""]
        for line in card["body"]:
            block.append(line)
        footer_right = ""
        if card["chapter_card"]:
            frames = [s for s in st.snaps if s.chapter == snap.chapter and s.kind == "diagram"]
            if frames:
                footer_right = (f"frames {snap.chapter}.{frames[0].index:02d} - "
                                f"{snap.chapter}.{frames[-1].index:02d}")
        if card["source"] or footer_right:
            left = card["source"]
            pad = inner - len(left) - len(footer_right)
            block += ["", left + " " * max(2, pad) + footer_right]
        for line in block:
            if len(line) > inner:
                self.problem(f"card line is {len(line)} characters long (max {inner}): {line[:50]!r}...")
        top = max(1, (d - 1 - len(block)) // 2 + 1)
        if top + len(block) > d:
            self.problem(f"card has {len(block)} lines, more than the {d - 1} lines of the picture")
        out = [self.title_bar(snap, k, total)] + [""] * (d - 1)
        for i, line in enumerate(block):
            if top + i < d:
                out[top + i] = "    " + line
            else:
                out.append("    " + line)
        return out

    # ---- diagram frames

    def render_diagram(self, snap: Snap, k: int, total: int) -> list:
        lay = snap.layout
        canvas = Canvas(lay.width, lay.diagram_lines)
        grid = [[FREE] * lay.width for _ in range(lay.diagram_lines)]
        for x in range(lay.width):
            grid[0][x] = BLOCKED
        for y in range(lay.diagram_lines):
            for x in lay.badge_cols:
                grid[y][x] = BLOCKED
        # zone rules
        for r in lay.rules:
            text = f"{H} {r.label} "
            text += H * (r.x1 - r.x0 + 1 - len(text))
            canvas.put(r.x0, r.y, text)
            for x in range(r.x0, r.x1 + 1):
                grid[r.y][x] = RULE
            for x in range(r.x0, min(r.x1 + 1, r.x0 + len(r.label) + 4)):
                grid[r.y][x] = LABEL
        for x, y in narrow_gaps(lay):
            if grid[y][x] == FREE:
                grid[y][x] = HONLY
        # boxes
        placed = {}
        for box in snap.boxes:
            placed[box.slot.name] = self.draw_box(canvas, box)
            s = box.slot
            for y in range(s.y, s.y + s.h):
                for x in range(s.x, s.x + s.w):
                    grid[y][x] = BOX
        # arrows: drawn last, each in cells that nothing else uses
        taken = set()
        if len(snap.arrows) > 2:
            self.problem(f"{len(snap.arrows)} drawn arrows (at most 2)")
        router = Router(lay, grid)
        for step in snap.arrows:
            a = self.slot_of(snap, step.src)
            b = self.slot_of(snap, step.dst)
            if a not in placed or b not in placed:
                self.problem(f"step {step.n}: {step.src} or {step.dst} is not on stage")
                continue
            try:
                path = router.route(placed[a], placed[b], taken)
            except StoryError as exc:
                self.problem(str(exc))
                continue
            for x, y, g, _, _ in path:
                canvas.put(x, y, g, "active")
                taken.add((x, y))
            if self.place_badge(canvas, grid, path, step.n, taken) is None:
                self.problem(f"step {step.n}: no room for the badge of the arrow {a} -> {b}")
        lines = canvas.lines()
        lines[0] = self.title_bar(snap, k, total)
        for y, spans in enumerate(canvas.spans()[1:], start=1):
            for x0, x1, role in spans:
                self.mark(y, x0, x1, role)
        caption = self.caption_block(snap, len(lines))
        if len(lines) != lay.diagram_lines or len(caption) != 3:
            self.problem(f"picture of {len(lines)} lines and caption of {len(caption)}: frames would jump")
        lines += caption
        for word, role in LEGEND_ROLES:
            x = lay.legend.find(word)
            if x >= 0:
                self.mark(len(lines), x, x + len(word), role)
        lines.append(lay.legend)
        lines.append("")
        lines += self.render_msc(snap, len(lines))
        return lines

    @staticmethod
    def slot_of(snap: Snap, eid: str) -> str:
        return snap.slots.get(eid, "")

    def draw_box(self, canvas: Canvas, box: BoxView) -> Placed:
        s = box.slot
        dotted = box.mode in ("placeholder", "gone")
        # colors: the frame (border and title) tells new / gone / not yet; a marked line is new
        # text in a new box and changed text in a box that was there before
        frame_role = {"placeholder": "muted", "gone": "removed"}.get(
            box.mode, "added" if box.title_star else None)
        text_role = {"placeholder": "muted", "gone": "muted"}.get(box.mode)
        star_role = {"placeholder": "muted", "gone": "removed"}.get(
            box.mode, "added" if box.title_star else "changed")
        if dotted:
            h, v, tl, tr, bl, br = DOT_H, DOT_V, TL, TR, BL, BR
        elif s.style == "double":
            h, v, tl, tr, bl, br = DH, DV, DTL, DTR, DBL, DBR
        else:
            h, v, tl, tr, bl, br = H, V, TL, TR, BL, BR
        protected = {(s.x, s.y), (s.x + s.w - 1, s.y), (s.x, s.y + s.h - 1), (s.x + s.w - 1, s.y + s.h - 1)}
        title = box.title
        if len(title) > s.w - 6:
            self.problem(f"box {s.name}: title {title!r} longer than {s.w - 6}")
            title = title[:s.w - 6]
        top = tl + (STAR if box.title_star else h) + " " + title + " "
        top += h * (s.w - 1 - len(top)) + tr
        canvas.put(s.x, s.y, top, frame_role)
        for x in range(s.x, s.x + len(title) + 5):     # title, its spaces, one more dash
            protected.add((x, s.y))
        inner = []
        tech = self.fit_tech(s, box.tech) if box.mode != "placeholder" else None
        if s.tech == "line":
            inner.append((False, f"({tech})" if tech else ""))
        inner += box.rows
        if s.tech == "line" and box.mode == "placeholder":
            inner = list(box.rows) + [(False, "")]
        for i, (star, text) in enumerate(inner[:s.h - 2]):
            room = s.tech_budget if (i == 0 and s.tech == "line") else s.budget
            if len(text) > room:
                self.problem(f"box {s.name}: line {text!r} is {len(text)} characters, the box holds {room}")
                text = text[:room]
            y = s.y + 1 + i
            canvas.put(s.x, y, v + (STAR if star else " ") + " " + text.ljust(s.tech_budget) + v)
            canvas.tint(s.x, y, 1, frame_role)
            canvas.tint(s.x + s.w - 1, y, 1, frame_role)
            canvas.tint(s.x + 3, y, len(text), star_role if star else text_role)
            if star:
                canvas.tint(s.x + 1, y, 1, star_role)
        bottom = bl
        if s.tech == "footer" and tech:
            foot = f"({tech})"
            bottom += h + " " + foot + " "
            for x in range(s.x, s.x + len(foot) + 5):
                protected.add((x, s.y + s.h - 1))
        bottom += h * (s.w - 1 - len(bottom)) + br
        canvas.put(s.x, s.y + s.h - 1, bottom, frame_role)
        return Placed(slot=s, protected=protected)

    def fit_tech(self, s: Slot, techs: tuple):
        if not techs:
            return ""
        limit = s.tech_budget - 2 if s.tech == "line" else s.w - 7
        for t in techs:
            if len(t) <= limit:
                return t
        self.problem(f"box {s.name}: no technical name fits in {limit} characters: {techs!r}")
        return techs[-1][:limit]

    def place_badge(self, canvas: Canvas, grid: list, path: list, n: int, taken: set):
        """Put the step number next to (or into) the wire: inline on a long horizontal run, else beside
        a vertical run, else above/below a horizontal run; '(n)' preferred, a bare 'n' if needed."""
        width, height = canvas.width, canvas.height

        def ok(x, y, length):
            if y <= 0 or y >= height or x < 0 or x + length > width:
                return False
            for i in range(length):
                if (x + i, y) in taken or grid[y][x + i] not in (FREE, RULE, BLOCKED, HONLY):
                    return False
                if grid[y][x + i] == BLOCKED and not (x + i) in self.stage.layout.badge_cols:
                    return False
            return True

        runs_h, runs_v = [], []
        cur, cur_kind = [], None
        for x, y, g, din, dout in path[1:-1]:
            kind = "h" if g == H else "v" if g == V else None
            if kind != cur_kind and cur:
                (runs_h if cur_kind == "h" else runs_v).append(cur)
                cur = []
            cur_kind = kind
            if kind:
                cur.append((x, y))
        if cur and cur_kind:
            (runs_h if cur_kind == "h" else runs_v).append(cur)
        candidates = []
        for text_rank, text in enumerate((f"({n})", f"{n}")):
            ln = len(text)
            for run in runs_h:
                if len(run) >= ln + 2:
                    xs = sorted(c[0] for c in run)
                    y = run[0][1]
                    x = xs[0] + (len(xs) - ln) // 2
                    rule_row = grid[y][xs[0]] == RULE
                    candidates.append((text_rank * 100 + (5 if rule_row else 0) - len(run) * 0.01, x, y, text, "inline"))
            for run in runs_v:
                ys = sorted(c[1] for c in run)
                mid = ys[len(ys) // 2]
                x = run[0][0]
                for y in ys:
                    gut = 0 if all(grid[y][xx] != BOX for xx in range(width)) else 2
                    for side, bx, margin in (("right", x + 2, (x + 1, y)), ("left", x - 1 - ln, (x - 1, y))):
                        if ok(bx, y, ln) and margin not in taken and grid[y][margin[0]] in (FREE, RULE, BLOCKED, HONLY):
                            score = text_rank * 100 + 10 + gut + (5 if grid[y][x] == RULE else 0) \
                                + abs(y - mid) * 0.1 + (1 if side == "left" else 0)
                            candidates.append((score, bx, y, text, "beside"))
                    for side, bx in (("right", x + 1), ("left", x - ln)):
                        if ok(bx, y, ln):
                            candidates.append((text_rank * 100 + 60 + abs(y - mid) * 0.1, bx, y, text, "touch"))
            for run in runs_h:
                xs = sorted(c[0] for c in run)
                y = run[0][1]
                for dy in (1, -1):
                    for x in range(xs[0], xs[-1] - ln + 2):
                        if ok(x, y + dy, ln):
                            candidates.append((text_rank * 100 + 20 + abs(x + ln / 2 - (xs[0] + xs[-1]) / 2) * 0.01
                                               + (0.5 if dy < 0 else 0), x, y + dy, text, "above/below"))
        if not candidates:
            return None
        candidates.sort(key=lambda c: (c[0], c[2], c[1]))
        _, x, y, text, _ = candidates[0]
        canvas.put(x, y, text, "active")
        for i in range(len(text)):
            taken.add((x + i, y))
        return (x, y, text)

    # ---- caption

    def caption_block(self, snap: Snap, y0: int) -> list:
        """The caption, starting at output line y0."""
        width = snap.layout.width
        lines = []
        shown = snap.arrows or [s for s in snap.new_steps][-1:]
        for step in shown:
            self.mark(y0 + len(lines), 0, len(self.step_head(step)), "active")
            lines.append(self.step_line(step, width))
        extra = len(snap.new_steps) - len(shown)
        if extra > 0 and lines:
            first = min(s.n for s in snap.new_steps)
            last = max(s.n for s in snap.new_steps)
            tail = f"   (steps {first}-{last} below)"
            lines[-1] = self.step_line(shown[-1], width - len(tail)) + tail
        room = 3 - len(lines)
        narr = textwrap.wrap(snap.narration, width - 4, break_on_hyphens=False) if snap.narration else []
        if len(narr) > room:
            self.problem(f"caption needs {len(narr)} narration lines, {room} available: {snap.narration[:60]!r}...")
            narr = narr[:room]
        lines += ["    " + t for t in narr]
        lines += [""] * (3 - len(lines))
        return lines[:3]

    @staticmethod
    def step_head(step: Step) -> str:
        if step.kind == "note":
            return f"{STAR}{step.n} "
        return f"{STAR}{step.n} {step.src_name} -> {step.dst_name}: "

    def step_line(self, step: Step, width: int) -> str:
        """'★n from -> to: message', with the short message if the full one does not fit."""
        head = self.step_head(step)
        room = width - len(head)
        for text in (step.label, step.short):
            if text and len(text) <= room:
                return head + text
        return head + truncate(step.short or step.label, room)

    # ---- message sequence chart

    def render_msc(self, snap: Snap, y0: int) -> list:
        """The message sequence chart, starting at output line y0."""
        lay = snap.layout
        w = lay.lane_width
        keys = [ln.key for ln in lay.lanes]
        life = [2 + w * i for i in range(len(keys))]
        marker_x = life[-1] + 3
        num_x = marker_x + 2
        label_x = num_x + 4
        budget = lay.width - label_x
        steps = snap.msc
        new = {s.n for s in snap.new_steps}
        out = []
        if steps:
            head = (f"MESSAGE SEQUENCE   chapter {snap.chapter}, steps 1-{steps[-1].n}"
                    "   (earlier chapters: see their last frames)")
        else:
            head = f"MESSAGE SEQUENCE   chapter {snap.chapter}: no messages yet"
        right = f"{STAR} = new in this frame"
        out.append(head + " " * max(2, lay.width - len(head) - len(right)) + right)
        self.mark(y0, len(out[0]) - len(right), len(out[0]), "active")
        row = [" "] * (life[-1] + 3)
        for i, ln in enumerate(lay.lanes):
            x = life[i] - len(ln.label) // 2
            for j, ch in enumerate(ln.label):
                row[x + j] = ch
        lane_row = "".join(row)
        out.append(lane_row + " " * (num_x + 1 - len(lane_row)) + "#  message")
        row = [" "] * (life[-1] + 3)
        for first, last, label in lay.lane_groups:
            x0, x1 = life[keys.index(first)] - 1, life[keys.index(last)] + 1
            span = x1 - x0 + 1
            text = f" {label} "
            if len(text) > span:
                seg, x0 = label, (x0 + x1 + 1 - len(label)) // 2
            else:
                left = (span - len(text)) // 2
                seg = "-" * left + text + "-" * (span - left - len(text))
            for j, ch in enumerate(seg):
                row[x0 + j] = ch
        out.append("".join(row).rstrip())

        def base():
            r = [" "] * (life[-1] + 1)
            for x in life:
                r[x] = V
            return r

        lifeline_roles = [None] * (life[-1] + 1)
        for x in life:
            lifeline_roles[x] = "muted"

        for step in steps:
            r = base()
            roles = list(lifeline_roles)
            is_new = step.n in new
            if step.kind != "note":
                i, j = keys.index(step.src_lane), keys.index(step.dst_lane)
                a, b = life[i], life[j]
                shaft = DASH if step.kind == "reply" else H
                lo, hi = min(a, b), max(a, b)
                for x in range(lo + 1, hi):
                    r[x] = shaft
                if a < b:
                    r[a], r[b] = "├", HEAD["right"]
                else:
                    r[a], r[b] = "┤", HEAD["left"]
                for x in range(lo, hi + 1):
                    roles[x] = "active" if is_new else None
            self.mark_runs(y0 + len(out), roles)
            if is_new:
                self.mark(y0 + len(out), marker_x, num_x + 2, "active")
            prefix = "-- " if step.kind == "note" else ""
            if is_new:
                wrapped = textwrap.wrap(prefix + step.label, budget, subsequent_indent="   ",
                                        break_on_hyphens=False)
            else:
                text = step.short or step.label
                wrapped = [truncate(prefix + text, budget)]
                if len(prefix + text) > budget:
                    self.warnings.add(f"chapter {snap.chapter} step {step.n}: sequence label cut to fit, "
                                      f"give it a short=: {step.label[:50]!r}")
            if not wrapped:
                wrapped = [""]
            if step.short and len(prefix + step.short) > budget:
                self.problem(f"step {step.n}: short label is {len(prefix + step.short)} characters (max {budget})")
            line = "".join(r) + " " * (marker_x - len(r))
            line += (STAR if is_new else " ") + " " + f"{step.n:>2}" + "  " + wrapped[0]
            out.append(line)
            for more in wrapped[1:]:
                cont = "".join(base())
                self.mark_runs(y0 + len(out), lifeline_roles)
                out.append(cont + " " * (label_x - len(cont)) + more)
        if not steps:
            self.mark_runs(y0 + len(out), lifeline_roles)
            out.append("".join(base()))
        return out

    # ---- index

    def index_text(self) -> str:
        st = self.stage
        out = [f"{st.title} -- index of frames", "",
               f"Present with:  cd rendered && less {'-R ' if self.palette else ''}*"
               "     (:n next file, :p previous, :x first, q quit)", "",
               " file                                    frame  steps drawn  title"]
        for snap, name in zip(st.snaps, self.names):
            drawn = ",".join(str(s.n) for s in snap.arrows) if snap.kind == "diagram" else "card"
            out.append(f" {name:<40} {snap.chapter}.{snap.index:02d}   {drawn:<11}  {snap.title}")
        out.append("")
        for number, title, short, _ in st.chapters:
            n = sum(1 for s in st.snaps if s.chapter == number)
            out.append(f" chapter {number}: {title} ({n} files)")
        return "\n".join(line.rstrip() for line in out) + "\n"


def narrow_gaps(lay: Layout) -> list:
    """Cells between two neighbour boxes of the same zone and row, at most NARROW_GAP apart."""
    cells = []
    slots = sorted(lay.slots.values(), key=lambda s: (s.y, s.x))
    for a in slots:
        for b in slots:
            if (a.y, a.h, a.zone) == (b.y, b.h, b.zone) and 0 < b.x - (a.x + a.w) <= NARROW_GAP:
                for y in range(a.y, a.y + a.h):
                    for x in range(a.x + a.w, b.x):
                        cells.append((x, y))
    return cells


def runs(roles: list) -> list:
    """[(x0, x1, role)] for the runs of equal, non-None roles (x1 exclusive)."""
    out = []
    start = 0
    for x in range(1, len(roles) + 1):
        if x == len(roles) or roles[x] != roles[start]:
            if roles[start] is not None:
                out.append((start, x, roles[start]))
            start = x
    return out


def truncate(text: str, room: int) -> str:
    if len(text) <= room:
        return text
    cut = text[:room - 4]
    if " " in cut[room // 2:]:
        cut = cut[:cut.rfind(" ")]
    return cut.rstrip(" ,;:") + " ..."
