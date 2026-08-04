"""Markdown front end: requirement documents to candidate promise records.

Deterministic and LLM-free. A security engineer drops a Markdown file into a
``sec_requirements/`` directory and this module turns each requirement section
into a :class:`Candidate` — the exact source sentence, its single-valued
headers, its vocabulary references, and either a validated typed AST or an
``error`` string naming why the sentence could not be translated.

SELF-CONTAINED — a hard rule. This module imports :mod:`gcp_grounding.sec_ast`,
:mod:`gcp_grounding.core.log` and the standard library only. It does **not**
import from any checkout outside this repository and does not vendor one:
``pyproject.toml`` declares empty ``dependencies`` and ``gcp_grounding/core/``
is the only vendored surface, so reaching outside would break a standalone
install and vendoring a large markdown-ingest module to borrow a few regexes
would add a second DO-NOT-EDIT surface. The front end is therefore built by
hand from :mod:`re`, :mod:`hashlib`, :mod:`pathlib` and :mod:`dataclasses`: a
frontmatter splitter, a heading/fence scanner, a header-line splitter, an
indentation-driven builder and a tokenizer.

The honesty contract is layered. :class:`ParseError` is raised only for
genuinely unusable input — an unreadable/undecodable file, an unterminated
fence, or an unrecognized byte in the term language (the same discipline as
``constraints._tokenize``); the caller turns it into a document-level
``unverified`` verdict. Everything else — a missing id, an unknown header key, a
malformed or ill-typed AST, an unregistered collection — becomes the candidate's
``error`` string, which ``sx-sec-compile`` renders as ``unverified`` with the
reason quoted. A section with prose but no promise block is never dropped: it
yields a candidate with a ``None`` ast and the untranslated marker.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping

from . import sec_ast
from .core.log import get_logger

logger = get_logger(__name__)

__all__ = [
    "ParseError", "Candidate", "ParsedDoc", "discover", "parse_text", "parse_file",
]


class ParseError(Exception):
    """Genuinely unusable input: unterminated fence, unreadable file, bad byte."""


class _SmtError(Exception):
    """A translatable SMT-body problem; becomes a candidate ``error`` string."""


# -- data ---------------------------------------------------------------------

@dataclass(frozen=True)
class Candidate:
    """One requirement promise (or one untranslated section)."""

    id: str
    line: int
    text: str
    headers: Mapping[str, str]
    vocab: tuple[tuple[str, str], ...]
    notes: tuple[str, ...]
    ast: dict | None
    error: str


@dataclass(frozen=True)
class ParsedDoc:
    """A whole requirement document: its digest, defaults and candidates."""

    path: Path
    sha256: str
    defaults: Mapping[str, str]
    candidates: tuple[Candidate, ...]
    problems: tuple[str, ...]


# -- discovery ----------------------------------------------------------------

def discover(directory) -> tuple[Path, ...]:
    """Sorted ``*.md`` files directly under *directory*, minus the skips.

    Skips names starting with a dot or an underscore and the exact names
    ``README.md`` and ``TEMPLATE.md``. A missing directory returns an empty
    tuple, never raising.
    """
    root = Path(directory)
    if not root.is_dir():
        return ()
    out = []
    for path in sorted(root.glob("*.md")):
        name = path.name
        if name.startswith((".", "_")) or name in ("README.md", "TEMPLATE.md"):
            continue
        out.append(path)
    return tuple(out)


# -- top-level API ------------------------------------------------------------

_FRONTMATTER_KEYS = ("domain", "state", "mode", "severity")
_SINGLE_HEADERS = ("mode", "domain", "state", "severity")


def parse_file(path) -> ParsedDoc:
    """Parse the file at *path*, computing the sha256 over its raw bytes."""
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise ParseError(f"cannot read {p}: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError(f"{p} is not valid UTF-8: {exc}") from exc
    return replace(parse_text(text, p), sha256=hashlib.sha256(raw).hexdigest())


def parse_text(text, path) -> ParsedDoc:
    """Parse *text* into a :class:`ParsedDoc`; pure and byte-deterministic."""
    lines = text.split("\n")
    defaults, problems, body_start = _split_frontmatter(lines)
    candidates = []
    for section in _scan_sections(lines, body_start):
        if section["blocks"]:
            for block in section["blocks"]:
                candidates.append(_parse_block(block, defaults, section))
        else:
            candidates.append(_untranslated(section, defaults))
    candidates = _flag_duplicate_ids(candidates, problems)
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return ParsedDoc(path=Path(path), sha256=sha, defaults=dict(defaults),
                     candidates=candidates, problems=tuple(problems))


# -- frontmatter --------------------------------------------------------------

def _split_frontmatter(lines):
    """Return ``(defaults, problems, body_start)`` for optional frontmatter."""
    defaults: dict[str, str] = {}
    problems: list[str] = []
    if not lines or lines[0].strip() != "---":
        return defaults, problems, 0
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        raise ParseError("unterminated frontmatter: missing closing '---'")
    for i in range(1, end):
        raw = lines[i]
        if not raw.strip():
            continue
        key, sep, val = raw.partition(":")
        if not sep:
            problems.append(f"frontmatter line {i + 1}: expected 'key: value', "
                            f"got {raw.strip()!r}")
            continue
        key, val = key.strip(), val.strip()
        if key in _FRONTMATTER_KEYS:
            defaults[key] = val
        else:
            problems.append(f"unrecognized frontmatter key {key!r}")
    return defaults, problems, end + 1


# -- heading and fence scan ---------------------------------------------------

def _scan_sections(lines, body_start):
    """Split the body into sections, capturing prose and promise blocks."""
    sections = []
    cur = None
    in_fence = in_promise = False
    block = None
    for idx in range(body_start, len(lines)):
        raw = lines[idx]
        lineno = idx + 1
        stripped = raw.strip()
        if in_fence:
            if stripped.startswith("```"):
                in_fence = False
                if in_promise:
                    cur["blocks"].append(block)
                    in_promise, block = False, None
            elif in_promise:
                block.append((lineno, raw))
            continue
        if stripped.startswith("```"):
            in_fence = True
            if stripped[3:].strip() == "promise" and cur is not None:
                in_promise, block = True, []
            continue
        if raw.startswith("## "):
            cur = {"heading": stripped[3:].strip(),
                   "source_line": None, "source_text": None, "blocks": []}
            sections.append(cur)
            continue
        if stripped.startswith("#"):
            continue
        if cur is not None and cur["source_line"] is None and stripped:
            cur["source_line"] = lineno
            cur["source_text"] = raw.rstrip()
    if in_fence:
        raise ParseError("unterminated fence at end of document")
    return sections


# -- one promise block --------------------------------------------------------

def _slug(text):
    """Lowercase, non-alphanumerics to hyphens, collapsed and stripped."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _untranslated(section, defaults):
    return Candidate(
        id="untranslated-" + _slug(section["heading"]),
        line=section["source_line"] or 0,
        text=section["source_text"] or "",
        headers=dict(defaults),
        vocab=(), notes=(), ast=None,
        error="no promise block — the sentence was not translated",
    )


def _parse_block(block, defaults, section):
    error = ""
    if any("\t" in raw for _, raw in block):
        error = "a tab character is not allowed in a promise block"
    headers: dict[str, str] = {}
    vocab: list[tuple[str, str]] = []
    notes: list[str] = []
    smt_body: list[tuple[int, str]] = []
    seen_smt = False
    for lineno, raw in block:
        if seen_smt:
            smt_body.append((lineno, raw))
            continue
        if not raw.strip():
            continue
        key, sep, val = raw.partition(":")
        if not sep:
            error = error or f"line {lineno}: expected 'key: value', got {raw.strip()!r}"
            continue
        key, val = key.strip(), val.strip()
        if key == "smt":
            seen_smt = True
        elif key == "id":
            headers["id"] = val
        elif key in _SINGLE_HEADERS:
            headers[key] = val
        elif key == "vocab":
            kind, _, value = val.partition(" ")
            vocab.append((kind.strip(), value.strip()))
        elif key == "note":
            notes.append(val)
        else:
            error = error or f"unknown header key {key!r}"

    ident = headers.get("id", "")
    if not ident:
        error = error or "missing required header: id"
    merged = dict(defaults)
    merged.update(headers)

    ast = None
    if not error:
        if not seen_smt:
            error = "promise block has no smt: body"
        else:
            try:
                node = _build_smt(smt_body)
                sec_ast.validate(node)
                ast = sec_ast.canonical(node)
            except _SmtError as exc:
                error = str(exc)
            except (sec_ast.InvalidAst, sec_ast.UnknownCollection) as exc:
                logger.debug("promise %r did not translate: %s", ident, exc)
                error = str(exc)
    return Candidate(id=ident, line=section["source_line"] or 0,
                     text=section["source_text"] or "", headers=merged,
                     vocab=tuple(vocab), notes=tuple(notes), ast=ast, error=error)


def _flag_duplicate_ids(candidates, problems):
    counts: dict[str, int] = {}
    for cand in candidates:
        counts[cand.id] = counts.get(cand.id, 0) + 1
    dups = {i for i, n in counts.items() if n > 1 and i}
    if not dups:
        return tuple(candidates)
    out = []
    for cand in candidates:
        if cand.id in dups:
            note = f"duplicate id {cand.id!r}"
            if note not in problems:
                problems.append(note)
            out.append(replace(cand, error=cand.error or f"{note} in this document"))
        else:
            out.append(cand)
    return tuple(out)


# -- SMT prefix notation: indentation-driven builder --------------------------

def _build_smt(smt_body):
    """Build one AST from the indented ``smt:`` body, or raise ``_SmtError``."""
    entries = []
    for lineno, raw in smt_body:
        if not raw.strip():
            continue
        if "\t" in raw:
            raise _SmtError(f"line {lineno}: a tab character is not allowed in the smt body")
        indent = len(raw) - len(raw.lstrip(" "))
        if indent % 2:
            raise _SmtError(f"line {lineno}: indentation must be a multiple of two spaces")
        entries.append((indent // 2, raw.strip(), lineno))
    if not entries:
        raise _SmtError("smt: header has no indented body")
    prev = entries[0][0]
    for level, _content, lineno in entries:
        if level > prev + 1:
            raise _SmtError(f"line {lineno}: indentation jumps more than one level")
        prev = level
    node, pos = _build_node(entries, 0, entries[0][0])
    if pos != len(entries):
        raise _SmtError(f"line {entries[pos][2]}: a promise body must be a single formula")
    return node


def _build_node(entries, i, level):
    _level, content, lineno = entries[i]
    tokens = _tokenize_line(content, lineno)
    children = []
    j = i + 1
    while j < len(entries):
        nlevel = entries[j][0]
        if nlevel <= level:
            break
        if nlevel == level + 1:
            child, j = _build_node(entries, j, level + 1)
            children.append(child)
        else:  # already screened by _build_smt, kept as a guard
            raise _SmtError(f"line {entries[j][2]}: indentation jumps more than one level")
    return _make_node(tokens, children, lineno), j


# -- keyword-to-node mapping --------------------------------------------------

_CMP_OPS = ("eq", "ne", "lt", "le", "gt", "ge")


def _make_node(tokens, children, lineno):
    if not tokens or tokens[0][0] != "word":
        raise _SmtError(f"line {lineno}: expected an smt keyword")
    kw, rest = tokens[0][1], tokens[1:]

    def kids(n=None, at_least=None):
        if n is not None and len(children) != n:
            raise _SmtError(f"line {lineno}: {kw} takes exactly {n} child line(s), "
                            f"got {len(children)}")
        if at_least is not None and len(children) < at_least:
            raise _SmtError(f"line {lineno}: {kw} takes at least {at_least} child line(s), "
                            f"got {len(children)}")

    def bare():
        if rest:
            raise _SmtError(f"line {lineno}: {kw} takes no inline arguments")

    def done(pos):
        if pos != len(rest):
            raise _SmtError(f"line {lineno}: trailing tokens after {kw} operands")

    # Logical nodes: children are the more-indented lines beneath.
    if kw in ("true", "false"):
        bare(); kids(0); return {"node": kw}
    if kw == "not":
        bare(); kids(1); return {"node": "not", "arg": children[0]}
    if kw in ("and", "or"):
        bare(); kids(at_least=1); return {"node": kw, "args": children}
    if kw == "implies":
        bare(); kids(2); return {"node": "implies", "if": children[0], "then": children[1]}
    if kw in ("atmost", "atleast"):
        if len(rest) != 1 or rest[0][0] != "int":
            raise _SmtError(f"line {lineno}: {kw} needs a single integer bound")
        kids(at_least=1); return {"node": kw, "k": rest[0][1], "args": children}
    if kw in ("forall", "exists"):
        if len(rest) != 3 or rest[0][0] != "word" or rest[1] != ("word", "in") \
                or rest[2][0] != "word":
            raise _SmtError(f"line {lineno}: {kw} needs '<var> in <collection>'")
        kids(1)
        return {"node": kw, "var": rest[0][1], "collection": rest[2][1], "body": children[0]}

    # Leaf predicates: operands are inline; they take no child lines.
    kids(0)
    if kw == "cmp":
        if not rest or rest[0][0] != "word":
            raise _SmtError(f"line {lineno}: cmp needs an operator")
        op = rest[0][1]
        left, pos = _parse_term(rest, 1, lineno)
        right, pos = _parse_term(rest, pos, lineno)
        done(pos)
        return {"node": "cmp", "op": op, "left": left, "right": right}
    if kw == "in":
        term, pos = _parse_term(rest, 0, lineno)
        setnode, pos = _parse_set(rest, pos, lineno)
        done(pos)
        return {"node": "in", "term": term, "set": setnode}
    if kw in ("prefix", "suffix", "contains"):
        term, pos = _parse_term(rest, 0, lineno)
        if pos >= len(rest) or rest[pos][0] != "str":
            raise _SmtError(f"line {lineno}: {kw} needs a quoted string operand")
        value = rest[pos][1]
        done(pos + 1)
        return {"node": kw, "term": term, "value": value}
    if kw == "cidr_contains":
        cidr, pos = _parse_term(rest, 0, lineno)
        addr, pos = _parse_term(rest, pos, lineno)
        done(pos)
        return {"node": "cidr_contains", "cidr": cidr, "addr": addr}
    if kw == "port_in":
        term, pos = _parse_term(rest, 0, lineno)
        if pos + 1 >= len(rest) or rest[pos][0] != "int" or rest[pos + 1][0] != "int":
            raise _SmtError(f"line {lineno}: port_in needs a term and two integer bounds")
        lo, hi = rest[pos][1], rest[pos + 1][1]
        done(pos + 2)
        return {"node": "port_in", "term": term, "lo": lo, "hi": hi}
    if kw == "cel":
        if len(rest) != 1 or rest[0][0] != "str":
            raise _SmtError(f"line {lineno}: cel takes exactly one quoted string")
        return {"node": "cel", "expr": rest[0][1]}
    raise _SmtError(f"line {lineno}: unknown smt keyword {kw!r}")


def _parse_term(rest, pos, lineno):
    """Consume one inline term at *pos*; return ``(term_node, new_pos)``."""
    if pos >= len(rest) or rest[pos][0] != "word":
        raise _SmtError(f"line {lineno}: expected a term")
    kw = rest[pos][1]

    def operand(kind):
        if pos + 1 >= len(rest) or rest[pos + 1][0] != kind:
            raise _SmtError(f"line {lineno}: {kw} term needs a {kind} operand")
        return rest[pos + 1][1]

    if kw == "field":
        raw = operand("word")
        var, dot, name = raw.partition(".")
        if not dot or not var or not name:
            raise _SmtError(f"line {lineno}: field term must be <var>.<field>, got {raw!r}")
        return {"node": "field", "var": var, "field": name}, pos + 2
    if kw == "str":
        return {"node": "lit", "sort": "Str", "value": operand("str")}, pos + 2
    if kw == "int":
        return {"node": "lit", "sort": "Int", "value": operand("int")}, pos + 2
    if kw == "port":
        return {"node": "lit", "sort": "Port", "value": operand("int")}, pos + 2
    if kw == "ip4":
        return {"node": "lit", "sort": "Ip4", "value": operand("str")}, pos + 2
    if kw == "cidr":
        return {"node": "lit", "sort": "Cidr", "value": operand("str")}, pos + 2
    if kw == "bool":
        flag = operand("word")
        if flag not in ("true", "false"):
            raise _SmtError(f"line {lineno}: bool literal must be true or false, got {flag!r}")
        return {"node": "lit", "sort": "Bool", "value": flag == "true"}, pos + 2
    raise _SmtError(f"line {lineno}: {kw!r} does not begin a term")


def _parse_set(rest, pos, lineno):
    """Consume a ``set[...]`` literal; the surface grammar has string sets only."""
    if pos >= len(rest) or rest[pos] != ("word", "set"):
        raise _SmtError(f"line {lineno}: 'in' predicate needs a set[...] literal")
    pos += 1
    if pos >= len(rest) or rest[pos][0] != "[":
        raise _SmtError(f"line {lineno}: expected '[' after set")
    pos += 1
    items = []
    if pos < len(rest) and rest[pos][0] == "]":
        return {"node": "set", "sort": "Str", "items": items}, pos + 1
    while True:
        if pos >= len(rest) or rest[pos][0] != "str":
            raise _SmtError(f"line {lineno}: set items must be quoted strings")
        items.append(rest[pos][1])
        pos += 1
        if pos < len(rest) and rest[pos][0] == ",":
            pos += 1
            continue
        if pos < len(rest) and rest[pos][0] == "]":
            return {"node": "set", "sort": "Str", "items": items}, pos + 1
        raise _SmtError(f"line {lineno}: expected ',' or ']' in set literal")


# -- tokenizer ----------------------------------------------------------------
#
# One regex per line, the same discipline as ``constraints._tokenize``: a
# double-quoted string, an optionally-negative integer, the bracket/comma
# punctuation, or a word starting with a letter or underscore followed by word
# characters and the symbols dot, colon, slash, at, plus and hyphen. An
# unrecognized byte raises ParseError — a genuinely unusable line.

_TOKEN = re.compile(
    r'\s*(?:'
    r'(?P<string>"[^"\\]*")'
    r'|(?P<int>-?\d+)'
    r'|(?P<punct>[\[\],])'
    r'|(?P<word>[A-Za-z_][\w./:@+-]*)'
    r')')


def _tokenize_line(text, lineno):
    tokens = []
    pos = 0
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        if match is None or match.end() == pos:
            rest = text[pos:].strip()
            if not rest:
                break
            raise ParseError(f"line {lineno}: unrecognized syntax at {rest[:20]!r}")
        pos = match.end()
        kind = match.lastgroup
        if kind == "string":
            tokens.append(("str", match.group("string")[1:-1]))
        elif kind == "int":
            tokens.append(("int", int(match.group("int"))))
        elif kind == "punct":
            char = match.group("punct")
            tokens.append((char, char))
        else:
            tokens.append(("word", match.group("word")))
    return tokens
