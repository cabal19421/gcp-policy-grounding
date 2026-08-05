"""CLI tests for the requirements compiler and its pickup:
``gcp-ground compile-requirements`` and ``verify-policy --requirements``.

In-process like :mod:`tests.test_gcp_cli`, calling
:func:`gcp_grounding.cli.main` and capturing with ``capsys``; ``--hook`` runs
simulate the PostToolUse event by monkeypatching ``sys.stdin``.

The load-bearing assertions here are the NEGATIVE ones. A compiled requirement
that fails to compile is designed to be non-fatal — its carry verdict is
``unverified``, so ``report.ok`` stays True — which means the only thing
standing between an operator and a silently inert guardrail is one stderr line.
Two tests pin it from both sides: a corpus with a rejected promise must emit
exactly that line without ``--abstain-notes`` and with the environment unset,
and a corpus where everything compiled must emit byte-nothing.

COMPILING NOTHING MUST NOT PASS. The walker never raises on a missing directory
and a report over zero verdicts is trivially ``ok``, so all four degenerate front
doors — a nonexistent directory, an empty one, a document with no promise block,
and a path that is a regular file — used to exit 0 printing PASSED with every
count zero and byte-empty stderr, ``--check`` included. ``_compile_floor`` is
pinned here from each of those four sides, plus the orphan artifact whose source
document was deleted and the two-document corpus whose SECOND document carries
the rejection.

Environment-honest: without z3 no witness can be minted, so every promise
compiles to ``unverified`` rather than ``compiled``, no rule is admitted, and
the enforcing/stalled split this module measures does not exist. Every test that
needs a minted witness is SKIPPED there rather than returning early — a bare
``return`` reports as a pass while asserting nothing, which is exactly the
vacuity these tests exist to remove — and :data:`_needs_no_z3` carries the
mirror-image assertions: on the fallback backend the compile still exits 0 with
every promise unverified, and the pickup says so out loud.
"""

import importlib.util
import io
import json
import os
from pathlib import Path

import pytest

from gcp_grounding.cli import REQUIREMENTS_ENV, SNAPSHOT_ENV, main
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.preflight import ground_policy
from gcp_grounding.report import PolicyReport
from gcp_grounding.sec_evidence import SEC_REPORT_SCHEMA

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"
SNAPSHOT = FIXTURES / "snapshot.json"
SEC = FIXTURES / "sec"

GOOD = POLICIES / "iam_policy_good.json"
BAD = POLICIES / "iam_policy_bad.json"

#: Every promise compiles AND holds over both policy bundles — the control for
#: the not-enforcing notice.
CLEAN_CORPUS = SEC / "clean"
#: One promise compiles, one is rejected for naming a role the snapshot does not
#: carry — the shape the notice exists to make visible.
STALLED_CORPUS = SEC / "stalled"

HAVE_Z3 = get_solver().backend == "z3"

#: A minted witness needs a solver, so without one nothing reaches ``compiled``
#: and there is no enforcing/stalled split to measure. An explicit SKIP, never a
#: bare ``return``: a skipped assertion is visible in the run, a returned one
#: reports as a pass while asserting nothing.
_needs_z3 = pytest.mark.skipif(
    not HAVE_Z3, reason="no solver: no promise compiles, so nothing enforces")
#: The mirror image — the positive assertions about the fallback backend, which
#: only mean anything when the solver really is absent.
_needs_no_z3 = pytest.mark.skipif(
    HAVE_Z3, reason="a solver is available, so the fallback backend is not live")


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def hook_event(path) -> str:
    return json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Write",
                       "tool_input": {"file_path": str(path), "content": ""}})


def run_hook(capsys, monkeypatch, *argv: str, event: str) -> tuple[int, str, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(event))
    return invoke(capsys, "verify-policy", "--hook", *argv)


@pytest.fixture(autouse=True)
def _requirements_off(monkeypatch):
    """No test in this module inherits a developer's exported requirements.

    Every assertion here is about what a GIVEN configuration prints; an ambient
    ``$GCP_GROUNDING_REQUIREMENTS`` would turn the "requirements are off" cases
    into "requirements are on" ones and quietly invert them.
    """
    monkeypatch.delenv(REQUIREMENTS_ENV, raising=False)
    monkeypatch.delenv(SNAPSHOT_ENV, raising=False)


def compile_corpus(corpus: Path, out: Path) -> int:
    """Compile *corpus* into *out*, returning the exit code."""
    return main(["compile-requirements", str(corpus), "--snapshot",
                 str(SNAPSHOT), "--out", str(out)])


@pytest.fixture
def clean_artifacts(tmp_path, capsys) -> Path:
    out = tmp_path / "clean-compiled"
    assert compile_corpus(CLEAN_CORPUS, out) == 0
    capsys.readouterr()
    return out


@pytest.fixture
def stalled_artifacts(tmp_path, capsys) -> Path:
    out = tmp_path / "stalled-compiled"
    # Exit 1: the corpus deliberately carries a rejected promise. That the
    # COMPILE fails while every later run still exits 0 is the whole problem the
    # notice addresses.
    assert compile_corpus(STALLED_CORPUS, out) == 1
    capsys.readouterr()
    return out


# -- compile-requirements ------------------------------------------------------


def test_compile_writes_artifacts_and_exits_zero(capsys, tmp_path):
    out = tmp_path / "compiled"
    code, stdout, _ = invoke(capsys, "compile-requirements", str(CLEAN_CORPUS),
                             "--snapshot", str(SNAPSHOT), "--out", str(out))
    assert code == 0
    assert [p.name for p in sorted(out.iterdir())] == ["requirements.promises.json"]
    assert "PASSED" in stdout
    doc = json.loads((out / "requirements.promises.json").read_text(encoding="utf-8"))
    assert [p["id"] for p in doc["promises"]] == ["clean-no-primitive-owner",
                                                  "clean-no-public-principals"]


def test_check_accepts_the_artifact_it_just_wrote(capsys, tmp_path):
    """--check is a fixed point over a fresh compile: no drift, nothing written."""
    out = tmp_path / "compiled"
    assert compile_corpus(CLEAN_CORPUS, out) == 0
    capsys.readouterr()
    before = (out / "requirements.promises.json").read_bytes()
    code, _, _ = invoke(capsys, "compile-requirements", str(CLEAN_CORPUS),
                        "--snapshot", str(SNAPSHOT), "--out", str(out), "--check")
    assert code == 0
    assert (out / "requirements.promises.json").read_bytes() == before


def test_check_reports_drift_on_a_hand_edited_artifact(capsys, tmp_path):
    out = tmp_path / "compiled"
    assert compile_corpus(CLEAN_CORPUS, out) == 0
    capsys.readouterr()
    artifact = out / "requirements.promises.json"
    data = json.loads(artifact.read_text(encoding="utf-8"))
    data["promises"][0]["source"]["text"] = "a sentence nobody wrote"
    artifact.write_text(json.dumps(data, indent=2), encoding="utf-8")
    code, stdout, _ = invoke(capsys, "compile-requirements", str(CLEAN_CORPUS),
                             "--snapshot", str(SNAPSHOT), "--out", str(out),
                             "--check")
    assert code == 1
    assert "does not match a fresh compile" in stdout


def test_degenerate_corpus_fails_with_the_did_you_mean_visible(capsys, tmp_path):
    """The planted typo reaches the render, suggester and all — a rejected
    requirement must be readable, not merely counted."""
    code, stdout, _ = invoke(capsys, "compile-requirements", str(SEC),
                             "--snapshot", str(SNAPSHOT),
                             "--out", str(tmp_path / "compiled"))
    assert code == 1
    assert "roles/bigquery.reader" in stdout
    assert "did you mean" in stdout
    assert "roles/bigquery.dataViewer" in stdout


def test_missing_snapshot_is_a_usage_error(capsys, tmp_path):
    """Exit 2, not the hook's fail-open: compiling without a snapshot cannot
    ground vocabulary, so a hallucinated role would compile clean."""
    code, stdout, err = invoke(capsys, "compile-requirements", str(CLEAN_CORPUS),
                               "--out", str(tmp_path / "compiled"))
    assert code == 2
    assert stdout == ""
    assert "gcp-ground compile-requirements: error:" in err
    assert SNAPSHOT_ENV in err


def test_unreadable_snapshot_is_a_usage_error(capsys, tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    code, _, err = invoke(capsys, "compile-requirements", str(CLEAN_CORPUS),
                          "--snapshot", str(broken),
                          "--out", str(tmp_path / "compiled"))
    assert code == 2
    assert "error:" in err


def test_compile_json_format_is_parseable(capsys, tmp_path):
    code, stdout, _ = invoke(capsys, "compile-requirements", str(CLEAN_CORPUS),
                             "--snapshot", str(SNAPSHOT),
                             "--out", str(tmp_path / "compiled"),
                             "--format", "json")
    assert code == 0
    doc = json.loads(stdout)
    assert doc["ok"] is True
    assert doc["source"] == str(CLEAN_CORPUS)
    assert {v["target"] for v in doc["verdicts"]} == {"clean-no-primitive-owner",
                                                      "clean-no-public-principals"}


def test_llm_degrades_to_a_note_instead_of_failing(capsys, tmp_path):
    """``--llm`` is optional in the strongest sense: absent sec_llm is one
    stderr note and a deterministic compile, never an error."""
    code, stdout, err = invoke(capsys, "compile-requirements", str(CLEAN_CORPUS),
                               "--snapshot", str(SNAPSHOT),
                               "--out", str(tmp_path / "compiled"), "--llm")
    assert code == 0
    assert "PASSED" in stdout
    # Resolved by name, never imported: this module must keep importing in a
    # checkout where gcp_grounding.sec_llm does not exist.
    if importlib.util.find_spec("gcp_grounding.sec_llm") is None:
        assert "sec_llm is not available" in err
    else:
        assert "--llm" in err or err == ""


# -- the front door: compiling nothing must not pass ---------------------------
#
# MEASURED before the fix, all four exiting 0 with `PASSED [z3] grounded=0
# ungrounded=0 contradicted=0 unverified=0` on stdout and byte-empty stderr, in
# --check too:
#
#   $ .venv/bin/python -m pytest -q tests/test_gcp_sec_cli.py \
#       -k "front_door or not_a_directory"
#   5 failed
#
# so a CI job whose corpus directory was renamed was green forever, including in
# the mode whose whole purpose is keeping committed artifacts honest.


def _corpus(tmp_path, name: str, body: str) -> Path:
    corpus = tmp_path / name
    corpus.mkdir()
    (corpus / "requirements.md").write_text(body, encoding="utf-8")
    return corpus


def _promise_doc(promise_id: str, role: str) -> str:
    """One requirement document carrying exactly one promise over *role*."""
    return (f"---\ndomain: iam\nstate: proposal\nseverity: high\n---\n\n"
            f"# Requirements\n\n## No {role} grants\n\n"
            f"No binding may grant {role}.\n\n"
            f"```promise\nid: {promise_id}\nmode: refute\n"
            f"vocab: role {role}\nsmt:\n"
            f"  exists b in iam_bindings\n"
            f'    cmp eq field b.role str "{role}"\n```\n')


def test_front_door_an_empty_directory_does_not_pass(capsys, tmp_path):
    """An existing directory with no requirement document at all.

    The walker returns an empty tuple, a report over zero verdicts is trivially
    ``ok`` and ``any`` over an empty sequence is False, so every ingredient of
    the exit code says "fine" while nothing was examined.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    code, stdout, err = invoke(capsys, "compile-requirements", str(empty),
                               "--snapshot", str(SNAPSHOT),
                               "--out", str(tmp_path / "compiled"))
    assert code == 1
    assert "nothing was compiled" in stdout
    assert str(empty) in stdout
    assert err == ""


def test_front_door_a_document_with_no_promise_block_does_not_pass(capsys, tmp_path):
    """A document that parses and yields ZERO promises is the same silence with
    a file in the way."""
    corpus = _corpus(tmp_path, "prose",
                     "---\ndomain: iam\n---\n\n# Requirements\n\nProse only.\n")
    code, stdout, _ = invoke(capsys, "compile-requirements", str(corpus),
                             "--snapshot", str(SNAPSHOT),
                             "--out", str(tmp_path / "compiled"))
    assert code == 1
    assert "nothing was compiled" in stdout


def test_front_door_an_empty_directory_does_not_pass_check_either(capsys, tmp_path):
    """--check is the mode whose whole purpose is keeping committed artifacts
    honest, so it is the one that must not be green over an empty walk."""
    empty = tmp_path / "empty"
    empty.mkdir()
    code, stdout, _ = invoke(capsys, "compile-requirements", str(empty),
                             "--snapshot", str(SNAPSHOT),
                             "--out", str(tmp_path / "compiled"), "--check")
    assert code == 1
    assert "nothing was compiled" in stdout


def test_a_missing_directory_is_a_usage_error(capsys, tmp_path):
    """Exit 2, which the module docstring reserves for usage errors: naming a
    corpus that is not there is the operator naming the wrong thing, not a
    finding about any requirement."""
    missing = tmp_path / "not-there"
    code, stdout, err = invoke(capsys, "compile-requirements", str(missing),
                               "--snapshot", str(SNAPSHOT),
                               "--out", str(tmp_path / "compiled"))
    assert code == 2
    assert stdout == ""
    assert err.splitlines() == [
        f"gcp-ground compile-requirements: error: {missing} is not a directory "
        f"— there is no requirement corpus to compile"]


def test_a_regular_file_is_a_usage_error(capsys, tmp_path):
    """Same exit code and same reason for a path that exists but is a file."""
    document = tmp_path / "requirements.md"
    document.write_text("# not a directory\n", encoding="utf-8")
    code, stdout, err = invoke(capsys, "compile-requirements", str(document),
                               "--snapshot", str(SNAPSHOT),
                               "--out", str(tmp_path / "compiled"))
    assert code == 2
    assert stdout == ""
    assert "is not a directory" in err


def test_an_unwritable_output_directory_is_a_usage_error(capsys, tmp_path):
    """It used to raise PermissionError out of main(), which the shell reports as
    exit 1 — the code the docstring gives to a REJECTED promise. Where the
    artifacts go is a usage decision and reports as one, on one line."""
    out = tmp_path / "readonly"
    out.mkdir()
    out.chmod(0o500)
    try:
        code, stdout, err = invoke(capsys, "compile-requirements",
                                   str(CLEAN_CORPUS), "--snapshot", str(SNAPSHOT),
                                   "--out", str(out))
    finally:
        out.chmod(0o700)
    assert code == 2
    assert stdout == ""
    assert "the artifacts could not be written to" in err
    assert str(out) in err


def test_check_reports_an_orphan_artifact_whose_source_was_deleted(capsys, tmp_path):
    """THE ARTIFACT THAT OUTLIVES ITS REQUIREMENT.

    ``sec_rules.load_directory`` globs the output directory and loads whatever it
    finds, so an artifact left behind by a deleted document keeps being ENFORCED.
    ``--check`` only ever compared the files a fresh compile produced, so it
    never looked at the one nobody produced.
    """
    corpus = _corpus(tmp_path, "corpus",
                     _promise_doc("orphan-me", "roles/bigquery.jobUser"))
    out = tmp_path / "compiled"
    assert compile_corpus(corpus, out) == 0
    capsys.readouterr()
    assert (out / "requirements.promises.json").is_file()
    (corpus / "requirements.md").unlink()
    code, stdout, _ = invoke(capsys, "compile-requirements", str(corpus),
                             "--snapshot", str(SNAPSHOT), "--out", str(out),
                             "--check")
    assert code == 1
    assert "an orphan artifact" in stdout
    assert "requirements.promises.json" in stdout
    # The file is still there and --requirements would still load it: the point
    # of the verdict is that CI now says so instead of passing.
    assert (out / "requirements.promises.json").is_file()


def test_a_file_that_is_not_an_artifact_is_not_an_orphan(capsys, tmp_path):
    """The control for the orphan channel: only ``*.promises.json`` is an
    artifact this compile could have produced. An output directory is an ordinary
    directory — a README, a ``.gitkeep``, an editor's backup — and calling those
    orphans would fail every honest CI job that keeps one."""
    corpus = _corpus(tmp_path, "corpus",
                     _promise_doc("keeps-its-source", "roles/bigquery.jobUser"))
    out = tmp_path / "compiled"
    assert compile_corpus(corpus, out) == 0
    capsys.readouterr()
    (out / "README.md").write_text("how these artifacts are reviewed\n",
                                   encoding="utf-8")
    (out / ".gitkeep").write_text("", encoding="utf-8")
    code, stdout, _ = invoke(capsys, "compile-requirements", str(corpus),
                             "--snapshot", str(SNAPSHOT), "--out", str(out),
                             "--check")
    assert code == 0
    assert "orphan" not in stdout


def test_a_second_document_carrying_the_rejection_still_fails_the_compile(
        capsys, tmp_path):
    """MULTI-DOCUMENT COVERAGE.

    The one multi-document test in this suite puts its rejection in the
    alphabetically FIRST file, so truncating the merge to ``results[0]`` survives
    it. Here the first document compiles cleanly and the SECOND carries the
    hallucinated role, so the exit code and the render can only be right if every
    result reached the merged report.
    """
    corpus = tmp_path / "two"
    corpus.mkdir()
    (corpus / "aaa.md").write_text(
        _promise_doc("two-first-clean", "roles/bigquery.jobUser"), encoding="utf-8")
    (corpus / "zzz.md").write_text(
        _promise_doc("two-second-rejected", "roles/bigquery.reader"),
        encoding="utf-8")
    out = tmp_path / "compiled"
    code, stdout, _ = invoke(capsys, "compile-requirements", str(corpus),
                             "--snapshot", str(SNAPSHOT), "--out", str(out))
    assert code == 1
    assert "zzz.md" in stdout
    assert "roles/bigquery.reader" in stdout
    assert sorted(p.name for p in out.iterdir()) == ["aaa.promises.json",
                                                     "zzz.promises.json"]


def test_a_corpus_outside_the_repo_says_its_paths_are_not_anchored(capsys, tmp_path):
    """PARTIAL, per the design's Non-goals.

    ``sec_compile._repo_relative`` anchors a recorded source path against the
    nearest ``pyproject.toml``; with no such ancestor it falls back to a
    CWD-relative path, so the artifact's bytes depend on where the compile ran
    from. An abstention, not a failure — the compile is honest, its recorded
    paths are merely not portable — so the exit code is untouched and only the
    silence is removed. The residual risk is ESC-GX-SECCLI-001.
    """
    corpus = _corpus(tmp_path, "outside",
                     _promise_doc("outside-repo", "roles/bigquery.jobUser"))
    code, stdout, _ = invoke(capsys, "compile-requirements", str(corpus),
                             "--snapshot", str(SNAPSHOT),
                             "--out", str(tmp_path / "compiled"))
    assert code == 0
    assert "no pyproject.toml ancestor" in stdout
    assert "ESC-GX-SECCLI-001" in stdout


def test_a_corpus_inside_the_repo_is_silent_about_anchoring(capsys, tmp_path):
    """The control: the anchoring note must not fire on the committed corpus, or
    it is noise on every healthy run."""
    code, stdout, _ = invoke(capsys, "compile-requirements", str(CLEAN_CORPUS),
                             "--snapshot", str(SNAPSHOT),
                             "--out", str(tmp_path / "compiled"))
    assert code == 0
    assert "pyproject.toml" not in stdout


@pytest.mark.xfail(strict=True, reason="ESC-GX-SECCLI-001: a corpus with no "
                                       "pyproject.toml ancestor records "
                                       "cwd-relative source paths")
def test_check_outside_the_repo_does_not_report_spurious_drift(
        capsys, tmp_path, monkeypatch):
    """THE SPEC-LITERAL ASSERTION behind ESC-GX-SECCLI-001.

    Compiling and then checking a byte-identical corpus must be a fixed point
    wherever either run happened. It is not: the recorded source path is
    ``os.path.relpath(document, os.getcwd())`` whenever no ``pyproject.toml``
    ancestor exists, so a ``--check`` from a different working directory
    re-renders a different ``source.file`` and reports drift on a corpus nobody
    touched. Root-cause path anchoring is out of scope per the Non-goals.
    """
    corpus = _corpus(tmp_path, "outside",
                     _promise_doc("outside-repo", "roles/bigquery.jobUser"))
    out = tmp_path / "compiled"
    assert compile_corpus(corpus, out) == 0
    capsys.readouterr()
    monkeypatch.chdir(tmp_path)
    code, stdout, _ = invoke(capsys, "compile-requirements", str(corpus),
                             "--snapshot", str(SNAPSHOT), "--out", str(out),
                             "--check")
    assert "does not match a fresh compile" not in stdout
    assert code == 0


# -- verify-policy --requirements: the pickup ----------------------------------


@_needs_z3
def test_requirements_add_sec_verdicts(capsys, clean_artifacts):
    code, stdout, _ = invoke(capsys, "verify-policy", str(GOOD),
                             "--snapshot", str(SNAPSHOT),
                             "--requirements", str(clean_artifacts))
    assert code == 0
    assert "[sec:iam]" in stdout
    assert "clean-no-primitive-owner" in stdout


@_needs_z3
def test_json_carries_one_top_level_sec_object(capsys, clean_artifacts):
    code, stdout, _ = invoke(capsys, "verify-policy", str(GOOD),
                             "--snapshot", str(SNAPSHOT),
                             "--requirements", str(clean_artifacts),
                             "--format", "json")
    assert code == 0
    doc = json.loads(stdout)
    assert sorted(doc["sec"]) == ["requirements", "sec_schema", "witnesses"]
    assert doc["sec"]["sec_schema"] == SEC_REPORT_SCHEMA
    assert [r["id"] for r in doc["sec"]["requirements"]] == [
        "clean-no-primitive-owner", "clean-no-public-principals"]
    assert {w["role"] for w in doc["sec"]["witnesses"]} == {"pinned-positive",
                                                            "pinned-negative"}


def test_empty_requirements_directory_still_emits_the_sec_object(capsys, tmp_path):
    """The shape follows CONFIGURATION, not load outcome.

    A consumer that turned requirements on must be able to tell "no rules
    loaded" (``sec.requirements == []``) from "requirements are off" (no ``sec``
    key), which it cannot do if a failed compile silently changes the document.

    RE-PINNED: this test used to assert ``err == ""`` for exactly this
    configuration, and that expectation WAS the bug. A resolved source that
    loaded zero rules is the state a clean checkout and a fresh CI container
    reach by default — the directory is there, the environment variable is
    exported, and the compiler has not run — and silence there is precisely what
    the module docstring says must never be indistinguishable from the rule
    working. The exit code is untouched: this is a notice, never a block.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    code, stdout, err = invoke(capsys, "verify-policy", str(GOOD),
                               "--snapshot", str(SNAPSHOT),
                               "--requirements", str(empty), "--format", "json")
    assert code == 0
    assert err.splitlines() == [
        f"gcp-ground verify-policy: 0 compiled requirement(s) loaded from "
        f"{empty} — nothing is being enforced (see compile-requirements)"]
    doc = json.loads(stdout)
    assert doc["sec"]["requirements"] == []
    assert doc["sec"]["witnesses"] == []
    assert doc["sec"]["sec_schema"] == SEC_REPORT_SCHEMA


def test_without_requirements_the_document_is_byte_identical(capsys):
    """No flag and no env var: today's output exactly, with no ``sec`` key.

    Compared against a directly-rendered PolicyReport rather than a substring —
    asserting ``"sec" not in stdout`` would be meaningless here, since the
    checkout path itself contains "sec" and the render prints it.
    """
    snapshot = GcpSnapshot.load(str(SNAPSHOT))
    expected = PolicyReport(ground_policy(str(GOOD), snapshot),
                            captured_at=snapshot.captured_at,
                            source=str(GOOD)).render("json")
    code, stdout, err = invoke(capsys, "verify-policy", str(GOOD),
                               "--snapshot", str(SNAPSHOT), "--format", "json")
    assert code == 0
    assert err == ""
    assert stdout == expected + "\n"
    assert "sec" not in json.loads(stdout)


@_needs_z3
def test_requirements_env_is_honoured(capsys, monkeypatch, clean_artifacts):
    """Configuring the env var once is how a hook or CI job turns requirements
    on globally."""
    monkeypatch.setenv(REQUIREMENTS_ENV, str(clean_artifacts))
    code, stdout, _ = invoke(capsys, "verify-policy", str(GOOD),
                             "--snapshot", str(SNAPSHOT), "--format", "json")
    assert code == 0
    doc = json.loads(stdout)
    assert [r["id"] for r in doc["sec"]["requirements"]] == [
        "clean-no-primitive-owner", "clean-no-public-principals"]


# -- --hook with requirements configured ---------------------------------------


def test_hook_blocks_a_violating_policy_with_requirements_configured(
        capsys, monkeypatch, clean_artifacts):
    code, stdout, err = run_hook(capsys, monkeypatch, "--snapshot", str(SNAPSHOT),
                                 "--requirements", str(clean_artifacts),
                                 event=hook_event(BAD))
    assert code == 2
    assert stdout == ""  # hook mode keeps stdout empty for structured output
    assert "roles/bigquery.reader" in err


def test_hook_fails_open_on_an_unreadable_requirements_directory(
        capsys, monkeypatch, tmp_path):
    """A broken requirements setup must never block an edit."""
    missing = tmp_path / "not-there"
    code, stdout, err = run_hook(capsys, monkeypatch, "--snapshot", str(SNAPSHOT),
                                 "--requirements", str(missing),
                                 event=hook_event(GOOD))
    assert code == 0
    assert stdout == ""
    assert "could not be read" in err
    assert str(missing) in err


@_needs_z3
def test_hook_announces_a_requirement_that_is_not_enforcing(
        capsys, monkeypatch, stalled_artifacts):
    """THE ASSERTION THAT A BROKEN REQUIREMENT IS NOT SILENT.

    No ``--abstain-notes`` and no environment variable: a rejected promise is
    otherwise indistinguishable from a working one, because its carry verdict is
    ``unverified`` and the gate exits 0 with empty stderr. Exactly one line, and
    the exit code is untouched.
    """
    code, stdout, err = run_hook(capsys, monkeypatch, "--snapshot", str(SNAPSHOT),
                                 "--requirements", str(stalled_artifacts),
                                 event=hook_event(GOOD))
    assert code == 0  # a notice, never a block
    assert stdout == ""
    assert err.splitlines() == [
        f"gcp-ground --hook: 1 of 2 compiled requirement(s) are not enforcing "
        f"(see compile-requirements) — {stalled_artifacts}"]


@_needs_z3
def test_hook_is_byte_silent_when_every_requirement_compiled(
        capsys, monkeypatch, clean_artifacts):
    """The control: the notice must not fire on a healthy configuration, or it
    becomes noise and gets switched off.

    Needs the solver for the same reason the stalled tests do — with none, no
    promise is admitted, so this configuration is not healthy, it is the
    zero-rules one, and its notice is asserted by
    :func:`test_no_solver_pickup_says_nothing_is_enforcing`.
    """
    code, stdout, err = run_hook(capsys, monkeypatch, "--snapshot", str(SNAPSHOT),
                                 "--requirements", str(clean_artifacts),
                                 event=hook_event(GOOD))
    assert code == 0
    assert stdout == ""
    assert err == ""


@_needs_z3
def test_hook_announces_a_directory_whose_artifact_was_deleted(
        capsys, monkeypatch, clean_artifacts):
    """THE HIGHEST-PROBABILITY REAL-WORLD FAILURE.

    Compiled output is GENERATED, so a clean checkout and a fresh CI container
    both reach this state by default: the directory is present, the environment
    variable is exported, and nothing was ever compiled into it. The notice used
    to derive its trigger from the carry verdicts, and a source with no artifacts
    produces none — zero verdicts, an empty stalled set, no line — which is
    byte-identical to the healthy control asserted directly above.
    """
    (clean_artifacts / "requirements.promises.json").unlink()
    code, stdout, err = run_hook(capsys, monkeypatch, "--snapshot", str(SNAPSHOT),
                                 "--requirements", str(clean_artifacts),
                                 event=hook_event(GOOD))
    assert code == 0  # a notice, never a block
    assert stdout == ""
    assert err.splitlines() == [
        f"gcp-ground --hook: 0 compiled requirement(s) loaded from "
        f"{clean_artifacts} — nothing is being enforced (see "
        f"compile-requirements)"]


@_needs_z3
def test_text_mode_names_the_requirements_when_the_artifact_was_deleted(
        capsys, clean_artifacts):
    """The same state in the mode an operator runs by hand: PASSED on stdout is
    fine, but it must not be the ONLY thing said about the requirements."""
    (clean_artifacts / "requirements.promises.json").unlink()
    code, stdout, err = invoke(capsys, "verify-policy", str(GOOD),
                               "--snapshot", str(SNAPSHOT),
                               "--requirements", str(clean_artifacts))
    assert code == 0
    assert "PASSED" in stdout
    assert err.splitlines() == [
        f"gcp-ground verify-policy: 0 compiled requirement(s) loaded from "
        f"{clean_artifacts} — nothing is being enforced (see "
        f"compile-requirements)"]


@_needs_z3
def test_notice_also_fires_outside_hook_mode(capsys, stalled_artifacts):
    """Same signal, ``verify-policy:`` prefix — the operator running by hand
    needs it just as much as the one running a hook."""
    code, _, err = invoke(capsys, "verify-policy", str(GOOD),
                          "--snapshot", str(SNAPSHOT),
                          "--requirements", str(stalled_artifacts))
    assert code == 0
    assert err.splitlines() == [
        f"gcp-ground verify-policy: 1 of 2 compiled requirement(s) are not "
        f"enforcing (see compile-requirements) — {stalled_artifacts}"]


@_needs_z3
def test_rejected_promise_stays_visible_as_an_unverified_carry_verdict(
        capsys, stalled_artifacts):
    """The notice is the operator signal; the carry verdict is the record. Both
    exist, and neither changes the exit code."""
    code, stdout, _ = invoke(capsys, "verify-policy", str(GOOD),
                             "--snapshot", str(SNAPSHOT),
                             "--requirements", str(stalled_artifacts),
                             "--format", "json")
    assert code == 0
    carried = [v for v in json.loads(stdout)["verdicts"]
               if v["target"] == "stalled-hallucinated-role"]
    assert len(carried) == 1
    assert carried[0]["status"] == "unverified"
    assert "rejected at compile time" in carried[0]["message"]


# -- --explain -----------------------------------------------------------------


@_needs_z3
def test_explain_prints_the_sexpr_and_both_witnesses(capsys, clean_artifacts):
    code, stdout, err = invoke(capsys, "verify-policy", str(GOOD),
                               "--snapshot", str(SNAPSHOT),
                               "--requirements", str(clean_artifacts),
                               "--format", "json", "--explain")
    assert code == 0
    json.loads(stdout)  # stdout stays JSON-parseable; the block goes to stderr
    assert "[sec:iam] clean-no-primitive-owner" in err
    assert '(exists ((b iam_bindings)) (eq b.role "roles/owner"))' in err
    assert "+ compliant:" in err
    assert "- violating:" in err


def test_explain_without_requirements_has_no_sec_block(capsys):
    code, _, err = invoke(capsys, "verify-policy", str(GOOD),
                          "--snapshot", str(SNAPSHOT), "--explain")
    assert code == 0
    assert "compiled requirements loaded this run" not in err


# -- the compiled artifacts actually enforce -----------------------------------


@_needs_z3
def test_a_compiled_requirement_can_refute_a_policy(capsys, tmp_path, monkeypatch):
    """End-to-end: a promise compiled by stage 1 refutes a real document.

    Without this the pickup could be inert — every rule registered, none of them
    ever deciding anything — and every other test here would still pass.
    """
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "requirements.md").write_text(
        "---\ndomain: iam\nstate: proposal\nseverity: high\n---\n\n"
        "# No jobUser grants\n\n"
        "## No BigQuery jobUser\n\n"
        "No binding may grant the BigQuery job-user role.\n\n"
        "```promise\n"
        "id: no-bigquery-jobuser\n"
        "mode: refute\n"
        "vocab: role roles/bigquery.jobUser\n"
        "smt:\n"
        "  exists b in iam_bindings\n"
        '    cmp eq field b.role str "roles/bigquery.jobUser"\n'
        "```\n", encoding="utf-8")
    out = tmp_path / "compiled"
    assert compile_corpus(corpus, out) == 0
    capsys.readouterr()
    # iam_policy_good.json grants roles/bigquery.jobUser, so the rule must fire.
    code, stdout, _ = invoke(capsys, "verify-policy", str(GOOD),
                             "--snapshot", str(SNAPSHOT),
                             "--requirements", str(out), "--format", "json")
    assert code == 1
    fired = [v for v in json.loads(stdout)["verdicts"]
             if v["target"] == "no-bigquery-jobuser"]
    assert len(fired) == 1
    assert fired[0]["status"] == "contradicted"
    assert "roles/bigquery.jobUser" in fired[0]["message"]


@_needs_z3
def test_a_single_promises_json_file_is_accepted(capsys, clean_artifacts):
    """``--requirements`` takes an artifact directory or one ``*.promises.json``."""
    artifact = clean_artifacts / "requirements.promises.json"
    assert os.path.isfile(artifact)
    code, stdout, _ = invoke(capsys, "verify-policy", str(GOOD),
                             "--snapshot", str(SNAPSHOT),
                             "--requirements", str(artifact), "--format", "json")
    assert code == 0
    assert [r["id"] for r in json.loads(stdout)["sec"]["requirements"]] == [
        "clean-no-primitive-owner", "clean-no-public-principals"]


# -- the fallback backend, asserted POSITIVELY ---------------------------------
#
# Every test above that needs a minted witness is SKIPPED without a solver, and a
# suite of skips asserts nothing about the world it skipped. These two say what
# the no-solver world must look like, and they only run there.


@_needs_no_z3
def test_no_solver_compile_exits_zero_with_every_promise_unverified(
        capsys, tmp_path):
    """Honest ignorance never fails the gate: with no backend no witness can be
    minted, so every promise lands ``unverified`` and the compile still exits 0.
    An artifact is still written — it simply carries no admitted promise."""
    out = tmp_path / "compiled"
    code, stdout, _ = invoke(capsys, "compile-requirements", str(CLEAN_CORPUS),
                             "--snapshot", str(SNAPSHOT), "--out", str(out),
                             "--format", "json")
    assert code == 0
    doc = json.loads(stdout)
    assert doc["ok"] is True
    statuses = {v["target"]: v["status"] for v in doc["verdicts"]}
    assert statuses == {"clean-no-primitive-owner": "unverified",
                        "clean-no-public-principals": "unverified"}
    written = json.loads(
        (out / "requirements.promises.json").read_text(encoding="utf-8"))
    assert {p["status"] for p in written["promises"]} == {"unverified"}


@_needs_no_z3
def test_no_solver_pickup_says_nothing_is_enforcing(capsys, clean_artifacts):
    """And the pickup does not pretend otherwise. No promise was admitted, so no
    rule loaded, so the zero-rules notice fires — the same line a fresh CI
    container gets, for the same reason: nothing is being enforced."""
    code, stdout, err = invoke(capsys, "verify-policy", str(GOOD),
                               "--snapshot", str(SNAPSHOT),
                               "--requirements", str(clean_artifacts))
    assert code == 0
    assert "PASSED" in stdout
    assert err.splitlines() == [
        f"gcp-ground verify-policy: 0 compiled requirement(s) loaded from "
        f"{clean_artifacts} — nothing is being enforced (see "
        f"compile-requirements)"]
