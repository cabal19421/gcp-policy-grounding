"""README §"How the gate thinks" pinned to the artifacts it quotes.

The section teaches the encoding by showing it: a real IAM allow policy, the
rows its extractor mints, the compiled s-expression, and the ground formula the
solver is handed. Every one of those is quoted verbatim on the page, which means
every one of them can drift away from the code that produces it — a renamed
field, a re-ordered sort, a change to ``sec_ast.render_sexpr``'s canonical form,
and the page teaches something the gate no longer does.

So each quoted artifact is re-derived here and compared to what the README says:

* the s-expression and the AST come from a FRESH ``compile-requirements`` run
  over ``examples/walkthrough/`` — a subprocess running the command the section
  prints, not an in-process shortcut, because the artifact on disk is what a
  reader reviews;
* the corpus digest and the ``file:line`` citation the section quotes back from
  ``show_promises.py`` and from the compile's own output come from that same
  artifact, so an edit to the requirement document that the page did not follow
  fails here rather than leaving the page citing a document nobody has;
* the three rows are what ``sec_rules.iam_bindings`` actually returns for the
  committed policy, in the order it returns them (the refutation the section
  explains names row 2, so the ORDER is load-bearing, not decoration);
* the ground formula is what ``sec_encode.ground`` builds over those rows from
  that same compiled AST, compared with whitespace normalized because z3's own
  pretty-printer chooses where to break lines and the page re-wraps to its
  column width;
* the three committed documents are quoted byte for byte.

z3-absent is not skipped silently: only the ground-formula assertion needs an
encoder backend, and it branches on the capability by name while every other
pin still runs.
"""

import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

from gcp_grounding import constraints, knowledge, sec_encode, sec_rules
from gcp_grounding.core.solver import get_solver

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
README = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
WALKTHROUGH = REPO_ROOT / "examples" / "walkthrough"
SNAPSHOT = "tests/fixtures/gcp/agentic_snapshot.json"

#: Every ```text block on the page, in order — the section's quoted artifacts
#: live in these and nowhere else.
TEXT_BLOCKS = re.findall(r"```text\n(.*?)```", README, re.S)


def _flat(text: str) -> str:
    return " ".join(text.split())


def _quoted_block(needle: str) -> str:
    """The one ```text block containing *needle* — asserted unique, so a second
    copy of a quoted artifact (exactly the drift this module exists to catch)
    fails here instead of silently pinning whichever copy came first."""
    hits = [b for b in TEXT_BLOCKS if needle in b]
    assert len(hits) == 1, \
        f"expected exactly one README block quoting {needle!r}, got {len(hits)}"
    return hits[0]


@pytest.fixture(scope="module")
def artifact(tmp_path_factory):
    """The document a fresh compile of the walkthrough corpus writes."""
    out = tmp_path_factory.mktemp("compiled-walkthrough")
    child = dict(os.environ)
    child["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(REPO_ROOT), child.get("PYTHONPATH", "")) if p)
    proc = subprocess.run(
        [sys.executable, "-m", "gcp_grounding", "compile-requirements",
         "examples/walkthrough", "--snapshot", SNAPSHOT, "--out", str(out)],
        cwd=REPO_ROOT, env=child, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr

    doc = json.loads((out / "requirements.promises.json").read_text(encoding="utf-8"))
    assert [p["id"] for p in doc["promises"]] == ["owner-stays-inside-acme"], \
        "the walkthrough corpus is deliberately one promise"
    return doc


@pytest.fixture(scope="module")
def compiled(artifact):
    """The walkthrough's one promise, as a fresh compile wrote it."""
    return artifact["promises"][0]


def _rows():
    snapshot = knowledge.GcpSnapshot.load(str(REPO_ROOT / SNAPSHOT))
    document = json.loads((WALKTHROUGH / "policy.json").read_text(encoding="utf-8"))
    ctx = sec_rules.RuleContext(snapshot=snapshot, document=document,
                                document_kind="iam_policy",
                                source="examples/walkthrough/policy.json")
    records, missing = sec_rules.iam_bindings(ctx)
    assert missing is None, missing
    return records


def test_the_quoted_sexpr_is_what_a_fresh_compile_produces(compiled):
    assert compiled["status"] == "compiled", compiled.get("reason")
    sexpr = compiled["smt"]["sexpr"]
    assert sexpr in README, \
        f"the README quotes a stale s-expression; a fresh compile produces:\n{sexpr}"
    # The sentence the artifact pinned is the sentence the page prints back,
    # and the citation the compile printed is the citation the page quotes.
    source = compiled["source"]
    assert source["text"] in README
    assert f"{source['file']}:{source['line']}" in README


def test_the_quoted_show_promises_header_is_this_artifact(artifact):
    # show_promises.py prints a 12-hex prefix of the document's own digest, so
    # an edit to the corpus that this page did not follow shows up here rather
    # than as a header quoting a document nobody has.
    digest = artifact["source_sha256"][:12]
    assert f"sha256 {digest}" in README, \
        f"the README quotes a stale corpus digest; this one is {digest}"
    assert f"snapshot {artifact['snapshot_captured_at']}" in README


def test_the_quoted_documents_are_the_committed_files():
    for name in ("policy.json", "proposal.tf.json", "terraform.tfstate"):
        body = (WALKTHROUGH / name).read_text(encoding="utf-8").rstrip("\n")
        assert body in README, f"the README no longer quotes {name} verbatim"


def test_the_quoted_rows_are_what_the_extractor_mints():
    records = _rows()
    assert records == (
        {"role": "roles/bigquery.dataViewer",
         "member": "group:data-eng@acme.example",
         "condition": "", "has_condition": False},
        {"role": "roles/owner", "member": "user:alice@acme.example",
         "condition": "", "has_condition": False},
        {"role": "roles/owner", "member": "user:mallory@outsider.example",
         "condition": "", "has_condition": False},
    )
    block = _quoted_block("iam_bindings[0]  role=")
    for index, record in enumerate(records):
        line = next(ln for ln in block.splitlines()
                    if ln.startswith(f"iam_bindings[{index}]"))
        for field, value in record.items():
            assert f"{field}={value!r}" in line, (index, field)


def test_the_quoted_ground_formula_is_what_the_encoder_builds(compiled):
    z3 = constraints._z3_module(get_solver())
    block = _quoted_block("str.suffixof")
    if z3 is None:
        # The named degradation, asserted rather than skipped: with no backend
        # the encoder refuses by name instead of returning an approximation.
        with pytest.raises(sec_encode.UnsupportedTerm, match="z3 is not available"):
            sec_encode.ground(None, compiled["smt"]["ast"],
                              {"iam_bindings": list(_rows())})
        return
    formula = sec_encode.ground(z3, compiled["smt"]["ast"],
                                {"iam_bindings": list(_rows())})
    assert _flat(block) == _flat(formula.sexpr())


def test_the_walkthrough_is_one_scenario_of_the_at_a_glance_table():
    # The runner reads that table; a section whose arc is not listed is a
    # section nobody can execute.
    assert "| w |" in README
    assert "./run_demo.sh w" in README
