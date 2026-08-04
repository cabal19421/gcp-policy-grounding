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

Environment-honest: without z3 no witness can be minted, so every promise
compiles to ``unverified`` rather than ``compiled`` and the enforcing/stalled
split this module measures does not exist. Those tests branch on the detected
backend rather than asserting a z3-shaped world.
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


# -- verify-policy --requirements: the pickup ----------------------------------


def test_requirements_add_sec_verdicts(capsys, clean_artifacts):
    code, stdout, _ = invoke(capsys, "verify-policy", str(GOOD),
                             "--snapshot", str(SNAPSHOT),
                             "--requirements", str(clean_artifacts))
    assert code == 0
    assert "[sec:iam]" in stdout
    assert "clean-no-primitive-owner" in stdout


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
    if HAVE_Z3:
        assert {w["role"] for w in doc["sec"]["witnesses"]} == {"pinned-positive",
                                                               "pinned-negative"}


def test_empty_requirements_directory_still_emits_the_sec_object(capsys, tmp_path):
    """The shape follows CONFIGURATION, not load outcome.

    A consumer that turned requirements on must be able to tell "no rules
    loaded" (``sec.requirements == []``) from "requirements are off" (no ``sec``
    key), which it cannot do if a failed compile silently changes the document.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    code, stdout, err = invoke(capsys, "verify-policy", str(GOOD),
                               "--snapshot", str(SNAPSHOT),
                               "--requirements", str(empty), "--format", "json")
    assert code == 0
    assert err == ""
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


def test_hook_announces_a_requirement_that_is_not_enforcing(
        capsys, monkeypatch, stalled_artifacts):
    """THE ASSERTION THAT A BROKEN REQUIREMENT IS NOT SILENT.

    No ``--abstain-notes`` and no environment variable: a rejected promise is
    otherwise indistinguishable from a working one, because its carry verdict is
    ``unverified`` and the gate exits 0 with empty stderr. Exactly one line, and
    the exit code is untouched.
    """
    if not HAVE_Z3:
        return  # without z3 nothing compiles, so there is no enforcing/stalled split
    code, stdout, err = run_hook(capsys, monkeypatch, "--snapshot", str(SNAPSHOT),
                                 "--requirements", str(stalled_artifacts),
                                 event=hook_event(GOOD))
    assert code == 0  # a notice, never a block
    assert stdout == ""
    assert err.splitlines() == [
        f"gcp-ground --hook: 1 of 2 compiled requirement(s) are not enforcing "
        f"(see compile-requirements) — {stalled_artifacts}"]


def test_hook_is_byte_silent_when_every_requirement_compiled(
        capsys, monkeypatch, clean_artifacts):
    """The control: the notice must not fire on a healthy configuration, or it
    becomes noise and gets switched off."""
    code, stdout, err = run_hook(capsys, monkeypatch, "--snapshot", str(SNAPSHOT),
                                 "--requirements", str(clean_artifacts),
                                 event=hook_event(GOOD))
    assert code == 0
    assert stdout == ""
    assert err == ""


def test_notice_also_fires_outside_hook_mode(capsys, stalled_artifacts):
    """Same signal, ``verify-policy:`` prefix — the operator running by hand
    needs it just as much as the one running a hook."""
    if not HAVE_Z3:
        return
    code, _, err = invoke(capsys, "verify-policy", str(GOOD),
                          "--snapshot", str(SNAPSHOT),
                          "--requirements", str(stalled_artifacts))
    assert code == 0
    assert err.splitlines() == [
        f"gcp-ground verify-policy: 1 of 2 compiled requirement(s) are not "
        f"enforcing (see compile-requirements) — {stalled_artifacts}"]


def test_rejected_promise_stays_visible_as_an_unverified_carry_verdict(
        capsys, stalled_artifacts):
    """The notice is the operator signal; the carry verdict is the record. Both
    exist, and neither changes the exit code."""
    if not HAVE_Z3:
        return
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


def test_explain_prints_the_sexpr_and_both_witnesses(capsys, clean_artifacts):
    if not HAVE_Z3:
        return
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


def test_a_compiled_requirement_can_refute_a_policy(capsys, tmp_path, monkeypatch):
    """End-to-end: a promise compiled by stage 1 refutes a real document.

    Without this the pickup could be inert — every rule registered, none of them
    ever deciding anything — and every other test here would still pass.
    """
    if not HAVE_Z3:
        return
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
