"""The optional LLM assist (:mod:`gcp_grounding.sec_llm`) — fully offline.

Every test injects its own ``runner``, so the default subprocess path is never
taken; an autouse fixture makes that a hard assertion by replacing
``subprocess.run`` with a detonator for the whole module. Nothing here needs a
network, an API key or any LLM CLI on ``PATH``.

What the suite is really proving is the safety chain: the assist emits only the
authoring syntax a human writes, so a hallucinated role dies at vocabulary
grounding with a did-you-mean, a hallucinated keyword dies in the parser, and a
vacuous promise dies at the non-tautology probe. Nothing it emits is ever
silently accepted.

The z3-dependent outcomes BRANCH rather than skip, the idiom of the encode /
probe / compile suites: with z3 the real ``rejected``/``compiled`` assertions
run, and on the builtin backend the same test asserts the honest abstention.
Every test writes only into ``tmp_path``.
"""

import subprocess
from pathlib import Path

import pytest

from gcp_grounding import sec_artifact, sec_ast, sec_llm, sec_parse
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
HAVE_Z3 = get_solver().backend == "z3"

SENTENCE = "No binding may grant the primitive owner role."

OWNER_BLOCK = '''```promise
id: no-primitive-owner
mode: refute
smt:
  exists b in iam_bindings
    cmp eq field b.role str "roles/owner"
```'''

# The planted hallucination: roles/bigquery.reader does not exist; the snapshot's
# own enumeration offers roles/bigquery.dataViewer.
HALLUCINATED_VOCAB_BLOCK = '''```promise
id: no-bigquery-readers
mode: refute
vocab: role roles/bigquery.reader
smt:
  exists b in iam_bindings
    cmp eq field b.role str "roles/bigquery.reader"
```'''

# A keyword no parser knows: it must die in the parser, not become a rule.
HALLUCINATED_KEYWORD_BLOCK = '''```promise
id: no-owner-regex
mode: refute
smt:
  exists b in iam_bindings
    matches_regex field b.role str "roles/owner.*"
```'''

TAUTOLOGY_BLOCK = '''```promise
id: always-true
mode: assert_satisfiable
smt:
  forall b in iam_bindings
    or
      cmp eq field b.role str "roles/viewer"
      cmp ne field b.role str "roles/viewer"
```'''

PROSE_DOC = """---
domain: iam
state: proposal
---

# Proposed requirements

## No primitive owner grants

No binding may grant the primitive owner role.
"""


@pytest.fixture(autouse=True)
def _no_subprocess(monkeypatch):
    """The default runner is NEVER exercised by this suite."""
    def _detonate(*args, **kwargs):
        raise AssertionError("sec_llm tests must never invoke subprocess.run")
    monkeypatch.setattr(subprocess, "run", _detonate)


@pytest.fixture()
def snap() -> GcpSnapshot:
    return GcpSnapshot.load(FIXTURES / "snapshot.json")


def _runner_for(*chunks):
    """A fake runner returning fixed text, asserting it was handed the prompt."""
    text = "".join(chunks)

    def runner(prompt):
        assert isinstance(prompt, str) and SENTENCE.split()[0] in prompt
        return text
    return runner


def _document(block: str) -> str:
    return PROSE_DOC + "\n" + block + "\n"


def _by_id(doc):
    return {p.id: p for p in doc.promises}


# -- opt in twice -------------------------------------------------------------

def test_available_is_false_without_the_env_var(monkeypatch):
    monkeypatch.delenv(sec_llm.LLM_ENV, raising=False)
    monkeypatch.setenv(sec_llm.LLM_CMD_ENV, "some-llm --json")
    monkeypatch.setattr(sec_llm.shutil, "which", lambda name: "/usr/bin/" + name)
    assert sec_llm.available() is False


def test_available_is_false_without_the_command(monkeypatch):
    # GCP_SEC_LLM=1 alone is not enough: no command means unavailable, even on
    # a machine where which() would resolve anything asked of it.
    monkeypatch.setenv(sec_llm.LLM_ENV, "1")
    monkeypatch.delenv(sec_llm.LLM_CMD_ENV, raising=False)
    monkeypatch.setattr(sec_llm.shutil, "which", lambda name: "/usr/bin/" + name)
    assert sec_llm.available() is False
    # Blank and unsplittable command lines are the same honest "off".
    monkeypatch.setenv(sec_llm.LLM_CMD_ENV, "   ")
    assert sec_llm.available() is False
    monkeypatch.setenv(sec_llm.LLM_CMD_ENV, "some-llm 'unterminated")
    assert sec_llm.available() is False
    # Both halves set and argv[0] resolvable: on.
    monkeypatch.setenv(sec_llm.LLM_CMD_ENV, "some-llm --json")
    assert sec_llm.available() is True


def test_available_needs_the_executable_too(monkeypatch):
    monkeypatch.setenv(sec_llm.LLM_ENV, "1")
    monkeypatch.setenv(sec_llm.LLM_CMD_ENV, "some-llm --json")
    monkeypatch.setattr(sec_llm.shutil, "which", lambda name: None)
    assert sec_llm.available() is False
    monkeypatch.setattr(sec_llm.shutil, "which", lambda name: "/usr/bin/" + name)
    assert sec_llm.available() is True
    # Only the exact string "1" enables it.
    monkeypatch.setenv(sec_llm.LLM_ENV, "true")
    assert sec_llm.available() is False


def test_propose_block_without_a_runner_stays_off(monkeypatch):
    monkeypatch.delenv(sec_llm.LLM_ENV, raising=False)
    monkeypatch.delenv(sec_llm.LLM_CMD_ENV, raising=False)
    with pytest.raises(sec_llm.LlmUnavailable) as exc:
        sec_llm.propose_block(SENTENCE)
    assert sec_llm.LLM_ENV in str(exc.value)
    assert sec_llm.LLM_CMD_ENV in str(exc.value)


# -- the prompt ---------------------------------------------------------------

def test_build_prompt_is_deterministic():
    assert sec_llm.build_prompt(SENTENCE) == sec_llm.build_prompt(SENTENCE)


def test_build_prompt_carries_the_whole_contract():
    prompt = sec_llm.build_prompt(SENTENCE)
    assert SENTENCE in prompt
    for name, spec in sec_ast.COLLECTIONS.items():
        assert name in prompt
        for field, sort in spec.fields.items():
            assert f"{field}: {sort}" in prompt
    for keyword in sec_llm.SMT_KEYWORDS + sec_llm.TERM_KEYWORDS:
        assert keyword in prompt, keyword
    for mode in sec_artifact.MODES:
        assert mode in prompt
    assert "```promise" in prompt
    assert "exactly ONE fenced block" in prompt


def test_build_prompt_honours_an_explicit_registry():
    spec = sec_ast.CollectionSpec("toy_records", "estate", {"name": "Str"})
    prompt = sec_llm.build_prompt(SENTENCE, collections={"toy_records": spec})
    assert "toy_records (tier estate) — name: Str" in prompt
    # The quantifiable-collection table is the caller's and nothing else; the
    # worked example below it is a fixed illustration of the block's shape.
    assert "iam_bindings (tier" not in prompt


# -- extraction is strict -----------------------------------------------------

def test_a_well_formed_block_round_trips_into_a_valid_ast():
    block = sec_llm.propose_block(
        SENTENCE, runner=_runner_for("Sure, here it is:\n\n", OWNER_BLOCK, "\n"))
    assert block == OWNER_BLOCK          # verbatim: nothing was reformatted

    parsed = sec_parse.parse_text(_document(block), "proposed.md")
    cand = parsed.candidates[0]
    assert cand.error == ""
    assert cand.id == "no-primitive-owner"
    assert cand.headers["mode"] == "refute"
    sec_ast.validate(cand.ast)           # a real, typed AST


def test_prose_with_no_fence_is_unavailable():
    runner = _runner_for("I think you should just review IAM bindings manually.")
    with pytest.raises(sec_llm.LlmUnavailable) as exc:
        sec_llm.propose_block(SENTENCE, runner=runner)
    assert "no ```promise fence" in str(exc.value)


def test_two_fences_are_unavailable():
    runner = _runner_for(OWNER_BLOCK, "\n\nor maybe:\n\n", TAUTOLOGY_BLOCK)
    with pytest.raises(sec_llm.LlmUnavailable) as exc:
        sec_llm.propose_block(SENTENCE, runner=runner)
    assert "2 promise fences" in str(exc.value)


def test_an_unterminated_fence_is_unavailable():
    runner = _runner_for("```promise\nid: truncated\nmode: refute\n")
    with pytest.raises(sec_llm.LlmUnavailable) as exc:
        sec_llm.propose_block(SENTENCE, runner=runner)
    assert "unterminated" in str(exc.value)


def test_a_missing_id_is_never_filled_in():
    block = '```promise\nmode: refute\nsmt:\n  true\n```'
    got = sec_llm.propose_block(SENTENCE, runner=_runner_for(block))
    assert got == block
    cand = sec_parse.parse_text(_document(got), "proposed.md").candidates[0]
    assert cand.error == "missing required header: id"


# -- the safety chain ---------------------------------------------------------

def test_a_hallucinated_keyword_dies_in_the_parser():
    block = sec_llm.propose_block(SENTENCE, runner=_runner_for(HALLUCINATED_KEYWORD_BLOCK))
    cand = sec_parse.parse_text(_document(block), "proposed.md").candidates[0]
    assert cand.ast is None
    assert "unknown smt keyword 'matches_regex'" in cand.error


def test_a_hallucinated_role_is_rejected_with_a_did_you_mean(snap, tmp_path):
    block = sec_llm.propose_block(SENTENCE, runner=_runner_for(HALLUCINATED_VOCAB_BLOCK))
    path = tmp_path / "hallucinated.md"
    path.write_text(_document(block), encoding="utf-8")

    res = sec_llm.compile_with_review(path, snap, out_dir=tmp_path)
    promise = _by_id(res.doc)["no-bigquery-readers"]
    # Vocabulary grounding is Datalog, not z3: this verdict does not branch.
    assert promise.status == "rejected"
    assert "roles/bigquery.reader does not exist in the snapshot" in promise.reason
    ungrounded = [v for v in res.report.verdicts if v.status == "ungrounded"]
    assert [v.target for v in ungrounded] == ["roles/bigquery.reader"]
    assert "roles/bigquery.dataViewer" in ungrounded[0].suggestions
    assert res.report.ok is False


def test_a_tautological_promise_is_rejected(snap, tmp_path):
    block = sec_llm.propose_block(SENTENCE, runner=_runner_for(TAUTOLOGY_BLOCK))
    path = tmp_path / "tautology.md"
    path.write_text(_document(block), encoding="utf-8")

    res = sec_llm.compile_with_review(path, snap, out_dir=tmp_path)
    promise = _by_id(res.doc)["always-true"]
    if HAVE_Z3:
        assert promise.status == "rejected"
        assert "tautology" in promise.reason
    else:
        assert promise.status == "unverified"
        assert "z3 is not available" in promise.reason


# -- write-back and the review marker -----------------------------------------

def test_annotate_dry_run_returns_text_without_touching_disk(tmp_path):
    path = tmp_path / "requirements.md"
    path.write_text(PROSE_DOC, encoding="utf-8")
    before = sorted(p.name for p in tmp_path.iterdir())

    new_text, warnings = sec_llm.annotate_document(
        path, runner=_runner_for(OWNER_BLOCK), dry_run=True)

    assert new_text != PROSE_DOC
    assert sec_llm.MARKER in new_text
    assert warnings == ()
    assert path.read_text(encoding="utf-8") == PROSE_DOC
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_annotate_writes_the_marker(tmp_path):
    path = tmp_path / "requirements.md"
    path.write_text(PROSE_DOC, encoding="utf-8")

    new_text, warnings = sec_llm.annotate_document(
        path, runner=_runner_for(OWNER_BLOCK), dry_run=False)

    on_disk = path.read_text(encoding="utf-8")
    assert on_disk == new_text
    assert warnings == ()
    # The marker is the FIRST line inside the block, byte-exact.
    lines = on_disk.split("\n")
    fence = lines.index("```promise")
    assert lines[fence + 1] == sec_llm.MARKER
    assert sec_llm.marked_ids(on_disk) == frozenset({"no-primitive-owner"})


def test_a_section_that_already_promises_is_left_alone(tmp_path):
    path = tmp_path / "requirements.md"
    path.write_text(_document(OWNER_BLOCK), encoding="utf-8")

    new_text, warnings = sec_llm.annotate_document(
        path, runner=_runner_for(OWNER_BLOCK), dry_run=False)

    assert new_text == _document(OWNER_BLOCK)
    assert sec_llm.MARKER not in new_text
    assert len(warnings) == 1 and "already carries a promise block" in warnings[0]


def test_a_failing_runner_warns_and_changes_nothing(tmp_path):
    path = tmp_path / "requirements.md"
    path.write_text(PROSE_DOC, encoding="utf-8")

    new_text, warnings = sec_llm.annotate_document(
        path, runner=_runner_for("no fence here at all"), dry_run=False)

    assert new_text == PROSE_DOC
    assert path.read_text(encoding="utf-8") == PROSE_DOC
    assert len(warnings) == 1 and "no ```promise fence" in warnings[0]


def test_a_marked_block_compiles_to_unverified_awaiting_review(snap, tmp_path):
    path = tmp_path / "requirements.md"
    path.write_text(PROSE_DOC, encoding="utf-8")
    sec_llm.annotate_document(path, runner=_runner_for(OWNER_BLOCK), dry_run=False)

    res = sec_llm.compile_with_review(path, snap, out_dir=tmp_path)
    promise = _by_id(res.doc)["no-primitive-owner"]
    # However cleanly it probes, the marker holds it back.
    assert promise.status == "unverified"
    assert promise.reason == sec_llm.REVIEW_REASON
    assert res.report.ok                      # awaiting review never fails the gate
    statuses = {v.status for v in res.report.verdicts if v.target == "no-primitive-owner"}
    assert statuses == {"unverified"}
    # The committed artifact says the same thing as the in-memory document.
    written = sec_artifact.load(res.written)
    assert _by_id(written)["no-primitive-owner"].reason == sec_llm.REVIEW_REASON


def test_deleting_the_marker_admits_the_promise(snap, tmp_path):
    path = tmp_path / "requirements.md"
    path.write_text(PROSE_DOC, encoding="utf-8")
    marked, _warnings = sec_llm.annotate_document(
        path, runner=_runner_for(OWNER_BLOCK), dry_run=False)

    admitted = "\n".join(line for line in marked.split("\n")
                         if line.strip() != sec_llm.MARKER)
    path.write_text(admitted, encoding="utf-8")
    assert sec_llm.marked_ids(admitted) == frozenset()

    res = sec_llm.compile_with_review(path, snap, out_dir=tmp_path)
    promise = _by_id(res.doc)["no-primitive-owner"]
    if HAVE_Z3:
        assert promise.status == "compiled"
        assert promise.positive is not None and promise.negative is not None
    else:
        assert promise.status == "unverified"
        assert "z3 is not available" in promise.reason
    assert res.report.ok
