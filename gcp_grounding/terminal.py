"""One terminal grammar for the explain surfaces: wrapping and colour, TTY ONLY.

THE RULE THIS MODULE EXISTS TO KEEP. The plain rendering is the canonical
surface. It is what every pinned test reads, what every README fragment quotes,
what a hook hands an agent, and what lands in a CI log — so a stream that is not
a terminal gets the bytes the caller assembled, unchanged and untouched, and
:func:`present` returns its input by identity in that case. Everything here
happens for a human looking at a terminal and nowhere else.

WHAT A TERMINAL GETS. Two things, gated separately because they answer
different questions:

* WIDTH. A terminal has one, a pipe does not. Lines longer than
  ``min(terminal columns, `` :data:`MAX_WIDTH` ``)`` are wrapped with a HANGING
  INDENT — the continuation carries the original line's own indentation plus
  :data:`_HANG`, so a wrapped verdict still reads as one item of the block it
  belongs to rather than as a new one. Nothing is ever truncated: wrapping
  moves bytes to the next line, it never drops them.
* COLOUR. ``NO_COLOR`` (any value, per the convention) and ``TERM=dumb`` both
  turn it off while leaving the wrapping alone — a reader who does not want
  escape codes still wants readable line lengths. Three roles and no more:
  the status mark of a verdict line, the decision, and meta lines.

The colour vocabulary is deliberately tiny. Colour that carries meaning has to
be learnable in one screen, and a palette nobody can recall is decoration.
"""

from __future__ import annotations

import os
import shutil
import textwrap
from typing import Any

__all__ = ["MAX_WIDTH", "MIN_WIDTH", "colour_enabled", "is_terminal",
           "render_width", "present"]

#: The widest line this renders, however wide the terminal is. Prose past
#: roughly this many columns is measurably harder to read, and every explain
#: block here is prose.
MAX_WIDTH = 100

#: The narrowest. Below this, wrapping shreds every line into fragments and a
#: reader is better served by the terminal's own overflow.
MIN_WIDTH = 40

#: What a continuation line adds to its own line's indentation.
_HANG = "    "

_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"

#: Status mark → colour. The four marks :mod:`gcp_grounding.report` renders,
#: and the two that fail the gate share one colour on purpose: a reader
#: scanning for "what blocked this" should not have to tell red from red.
_STATUS_COLOURS = {
    "✓": "\033[32m",   # grounded
    "⚠": "\033[31m",   # contradicted
    "✗": "\033[31m",   # ungrounded
    "?": "\033[33m",   # unverified
}

#: Lines that ARE the decision. Bold, because the whole surface exists to lead
#: here and the terminal's last line is the one a reader looks for first.
_DECISION_PREFIXES = ("decision:", "decision recap:", "result ")

#: Meta: the provenance and bookkeeping lines that qualify what is above them
#: rather than saying something new. Dim, so they recede without going away.
_META_PREFIXES = ("note: ", "reason: ", "(")


def is_terminal(stream: Any) -> bool:
    """Is *stream* a terminal? Anything that cannot answer counts as not one —
    the plain surface is the safe answer, never the decorated one."""
    try:
        return bool(stream.isatty())
    except Exception:                              # noqa: BLE001 - never crash a render
        return False


def colour_enabled(stream: Any) -> bool:
    """Terminal, no ``NO_COLOR``, no ``TERM=dumb``. Anything else is plain."""
    if not is_terminal(stream):
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    return os.environ.get("TERM", "") != "dumb"


def render_width(stream: Any) -> int:
    """``min(terminal columns,`` :data:`MAX_WIDTH` ``)``, floored at
    :data:`MIN_WIDTH`."""
    try:
        columns = shutil.get_terminal_size().columns
    except Exception:                              # noqa: BLE001 - never crash a render
        columns = MAX_WIDTH
    return max(MIN_WIDTH, min(int(columns), MAX_WIDTH))


def _wrapped(line: str, width: int) -> list[str]:
    """*line* at *width* with a hanging indent, or ``[line]`` when it fits."""
    if len(line) <= width or not line.strip():
        return [line]
    indent = line[:len(line) - len(line.lstrip(" "))]
    pieces = textwrap.wrap(line.strip(), width=width, initial_indent=indent,
                           subsequent_indent=indent + _HANG,
                           break_long_words=False, break_on_hyphens=False)
    # A single unbreakable token longer than the width wraps to nothing useful;
    # the original line is then the honest rendering of it.
    return pieces or [line]


def _role(line: str) -> str:
    """What *line* IS — ``"status"``, ``"decision"``, ``"meta"`` or ``""``.

    Read off the WHOLE line, before any wrapping: a continuation is part of the
    item above it and has no role of its own. Deciding this per wrapped piece
    is how a fragment that happens to begin with ``(`` gets dimmed in the
    middle of a finding.
    """
    body = line.lstrip(" ")
    if not body:
        return ""
    if body[0] in _STATUS_COLOURS:
        return "status"
    if body.startswith(_DECISION_PREFIXES):
        return "decision"
    if body.startswith(_META_PREFIXES):
        return "meta"
    return ""


def _paint(pieces: list[str], role: str) -> list[str]:
    """*pieces* — one line's wrapped fragments — carrying *role*'s colour.

    A status line colours its MARK and nothing else: a message full of escape
    codes is a message nobody can read out of a scrollback, and the mark is
    what a reader scans for. Decision and meta lines take their attribute over
    every fragment, so a wrapped one does not go bold or dim halfway.
    """
    if role == "status":
        head, body = pieces[0], pieces[0].lstrip(" ")
        indent = head[:len(head) - len(body)]
        colour = _STATUS_COLOURS[body[0]]
        return [f"{indent}{colour}{body[0]}{_RESET}{body[1:]}", *pieces[1:]]
    code = _BOLD if role == "decision" else _DIM
    painted = []
    for piece in pieces:
        body = piece.lstrip(" ")
        indent = piece[:len(piece) - len(body)]
        painted.append(f"{indent}{code}{body}{_RESET}" if body else piece)
    return painted


def present(text: str, stream: Any) -> str:
    """*text* as *stream* should show it.

    A non-terminal gets *text* back unchanged — that is the byte-identity
    contract the pins, the README quotes and the hook rely on. A terminal gets
    the same lines wrapped to :func:`render_width` and, unless ``NO_COLOR`` or
    ``TERM=dumb`` says otherwise, coloured.
    """
    if not is_terminal(stream):
        return text
    width = render_width(stream)
    paint = colour_enabled(stream)
    lines: list[str] = []
    for line in text.split("\n"):
        role = _role(line)
        pieces = _wrapped(line, width)
        lines.extend(_paint(pieces, role) if paint and role else pieces)
    return "\n".join(lines)
