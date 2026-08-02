"""Integrity tests for the offline security-requirement corpus.

Stdlib only, and — deliberately — no ``gcp_grounding`` import: the parser,
compiler and AST modules these Markdown fixtures exercise do not exist yet, so
this test validates the committed corpus (and the human-facing docs) purely
structurally, in the per-module ``FIXTURES`` idiom the rest of the suite uses.
It is the pin that keeps the corpus well-formed for every later ``sx-sec-*``
task that compiles it.
"""

import re
from pathlib import Path

SEC = Path(__file__).parent / "fixtures" / "gcp" / "sec"
DOCS = Path(__file__).parent.parent / "sec_requirements"

# The requirement-id slug regex, copied from the authoring format (README.md).
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]*$")

# The corpus documents and the exact set of promise ids each must carry.
EXPECTED_IDS = {
    "iam.md": {
        "no-public-principals",
        "no-primitive-owner",
        "bindings-are-conditioned",
    },
    "orgpolicy.md": {
        "serial-port-stays-disabled",
        "no-new-owner-grants",
    },
    "degenerate.md": {
        "unsatisfiable-promise",
        "tautological-promise",
        "hallucinated-role",
        "unregistered-collection",
        "cel-bearing-promise",
    },
}

FIXTURE_NAMES = sorted(EXPECTED_IDS)


def _fence_info(line):
    """The info string of a triple-backtick fence line, or ``None``."""
    stripped = line.strip()
    if stripped.startswith("```"):
        return stripped[3:].strip()
    return None


def parse_doc(path):
    """Line-oriented structural parse of a requirement document.

    Returns ``(sections, blocks, open_fence)`` where ``sections`` is a list of
    ``{"title", "fences"}`` (one per ``##`` heading, ``fences`` counting the
    ``promise`` blocks inside it), ``blocks`` is a list of ``{"lines", "id",
    "has_smt_body", "has_tab"}`` (one per ``promise`` fence), and ``open_fence``
    is ``True`` iff a ``promise`` fence was left unclosed at end of file.
    """
    lines = path.read_text(encoding="utf-8").split("\n")

    sections = []
    blocks = []
    current = None
    in_promise = False
    body = None

    for raw in lines:
        if in_promise:
            if _fence_info(raw) is not None:
                blocks.append(_block(body))
                in_promise = False
                body = None
            else:
                body.append(raw)
            continue

        info = _fence_info(raw)
        if info is not None:
            if info == "promise":
                in_promise = True
                body = []
                if current is not None:
                    current["fences"] += 1
            continue

        if raw.startswith("## "):
            current = {"title": raw[3:].strip(), "fences": 0}
            sections.append(current)

    return sections, blocks, in_promise


def _block(body):
    """Summarise one promise block from its raw content lines."""
    ident = None
    for line in body:
        if line.startswith("id:"):
            ident = line[len("id:"):].strip()
            break

    has_smt_body = False
    seen_smt = False
    for line in body:
        if seen_smt:
            indent = len(line) - len(line.lstrip(" "))
            if line.strip() and indent >= 2:
                has_smt_body = True
                break
        elif line.strip() == "smt:":
            seen_smt = True

    return {
        "lines": body,
        "id": ident,
        "has_smt_body": has_smt_body,
        "has_tab": any("\t" in line for line in body),
    }


def test_docs_exist_and_decode():
    for name in ("README.md", "TEMPLATE.md"):
        path = DOCS / name
        assert path.is_file(), f"missing doc {path}"
        path.read_text(encoding="utf-8")  # raises on non-UTF-8


def test_fixtures_exist_and_decode():
    assert SEC.is_dir(), f"missing corpus directory {SEC}"
    for name in FIXTURE_NAMES:
        path = SEC / name
        assert path.is_file(), f"missing fixture {path}"
        path.read_text(encoding="utf-8")  # raises on non-UTF-8


def test_every_promise_fence_is_closed():
    for name in FIXTURE_NAMES:
        _, _, open_fence = parse_doc(SEC / name)
        assert not open_fence, f"{name}: an unclosed ```promise fence"


def test_every_block_has_a_valid_unique_id():
    for name in FIXTURE_NAMES:
        _, blocks, _ = parse_doc(SEC / name)
        ids = []
        for block in blocks:
            assert block["id"] is not None, f"{name}: promise block with no id"
            assert SLUG.match(block["id"]), f"{name}: bad id slug {block['id']!r}"
            ids.append(block["id"])
        assert len(ids) == len(set(ids)), f"{name}: duplicate promise ids in {ids}"


def test_every_block_has_an_smt_body_and_no_tabs():
    for name in FIXTURE_NAMES:
        _, blocks, _ = parse_doc(SEC / name)
        for block in blocks:
            assert block["has_smt_body"], (
                f"{name}/{block['id']}: no smt: header with an indented body"
            )
            assert not block["has_tab"], (
                f"{name}/{block['id']}: a tab inside the promise block"
            )


def test_exact_id_set_per_fixture():
    for name in FIXTURE_NAMES:
        _, blocks, _ = parse_doc(SEC / name)
        got = {block["id"] for block in blocks}
        assert got == EXPECTED_IDS[name], f"{name}: id set {got} != {EXPECTED_IDS[name]}"


def test_degenerate_has_exactly_one_prose_only_section():
    sections, _, _ = parse_doc(SEC / "degenerate.md")
    prose_only = [s for s in sections if s["fences"] == 0]
    assert len(prose_only) == 1, (
        f"degenerate.md: expected one prose-only section, got {[s['title'] for s in prose_only]}"
    )
