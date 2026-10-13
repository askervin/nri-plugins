# CXL memory from a pool, with Kubernetes DRA: a terminal presentation

A story in text frames (`rendered/`), one file per frame, made to be stepped
through with `less`. The picture on top keeps every component in its place;
`★` marks what changed, the arrow is the frame's message, and a message
sequence chart below the picture grows frame by frame. The facts follow the
e2e tests `test10`-`test13` of `n4-cxl-shared-2` and their recorded traces
(see `scripts/PLAN.md`).

## Present

    cd rendered && less *

- `:n` next frame, `:p` previous frame, `:x` the first file (the index),
  `q` quit. The first file, `000-index.txt`, lists all frames; `:n` from
  there starts the talk.
- `j`/`k` (or the arrow keys) scroll down to the message sequence,
  `G` jumps to its newest rows, `g` back to the picture.
- Terminal: at least 120 columns and 34 lines (picture and caption are
  lines 1-33); 40 lines also show the first rows of the sequence. No line is
  longer than 120 characters, so `less` never wraps. A 1080p screen at a
  24 pt monospace font fits.
- UTF-8 and a font with box drawing and `► ◄ ▲ ▼ ★` as single-width
  characters. Otherwise (for example a CJK locale that draws them double
  width) render the ASCII variant, see below.
- `less -~ *` hides the `~` lines after the end of the shorter title cards.

## Render

From this directory (`presentations/terminal/`); Python 3.9+, standard
library only:

    python3 scripts/story.py                  render all frames into rendered/, remove stale ones
    python3 scripts/story.py --check          render in memory and verify every frame, write nothing
    python3 scripts/story.py --chapter 3      write only chapter 3's files (the others stay)
    python3 scripts/story.py --frame 045      write only frame 045 (or --frame <slug>)
    python3 scripts/story.py --ascii          ASCII glyphs (- | + = > < ^ v * : .), same geometry
    python3 scripts/story.py --list           print the index of frames
    python3 scripts/story.py --out DIR        write somewhere else than rendered/

`--check` fails (exit code 1, nothing written) on a line longer than 120
characters, a character outside the allowed set, a box line or title that
does not fit its box, a caption longer than its lines, a short= label too
long for its column, more than two arrows in a frame, an arrow without a
route or room for its number, a slug used twice in a chapter, a misplaced
legend (the picture or caption changed height), or a `★` written by hand.
A normal render runs the same checks. `--check --ascii` checks the ASCII
variant. The output is deterministic: the same story gives byte-identical
files.

Files are `NNN-chC-slug.txt`: `NNN` the position in the talk, `C` the
chapter. A full render writes into a temporary directory first and then
replaces the files, and removes `NNN-*.txt` files that the story no longer
makes.

## Change the story

`scripts/story.py` is the script; `scripts/layouts.py` holds every
coordinate (box slots, zone rules, message sequence lanes);
`scripts/stageplay.py` is the library. Each frame is a block of calls that
ends with `s.frame()`: insert, change or delete a block, then render. Frame
numbers, file names, step numbers, the message sequence and the `★` marks
follow by themselves; the story never mentions coordinates. For example, a
new frame between two of chapter 1:

```python
s.send("ctrl", "api", "UpdateStatus claim.status.devices[pooled0]: Attached=True, data {serial, size}",
       short="claim status: Attached=True")         # one sequence row; full text in its first frame
s.reply("api", "ctrl", "200 OK", draw=False)          # dashed row, no arrow in the picture
s.note("kubectl get resourceclaim pooled-memory")      # a row without an arrow
api(claims="pooled-memory -> pooled0, Attached")      # change one row of the API box
s.state("ctrl", "attached pooled0 -> node-b", "status Attached written")   # replace all its lines
s.caption("Short plain-language narration; it is wrapped to the caption lines.")
s.frame("attached-condition", "the claim says Attached")   # slug: unique within the chapter
```

- Entities: `s.entity(id, slot, title, technical name, *lines, name=...)`
  puts a box into a slot of the layout (the technical name may be a tuple
  of alternatives, longest first); `s.state`, `s.set` change its lines;
  `s.remove(id, "(exited)")` shows it dotted once more, then it is gone.
- Messages: `s.send` / `s.reply` between entities; by default only the last
  message of a frame is drawn as an arrow, `draw=True` picks others (at most
  two), `draw=False` never. Several messages in one frame make a
  fast-forward: all get sequence rows and `★`.
- `s.chapter(...)` renders a chapter card, restarts the step numbers and the
  sequence and may switch the layout; `s.card(...)` adds a text page;
  `s.settle()` makes the current state count as already seen (quiet resets
  at a chapter start).
- Text that does not fit is reported by `--check` with the frame and the
  box; shorten it, or give a message a `short=` form for the sequence.
