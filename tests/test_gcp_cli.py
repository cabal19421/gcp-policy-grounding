"""CLI tests: :func:`gcp_grounding.cli.main` driven over the shared fixture
bundles — exit codes (0 pass / 1 ungrounded-or-contradicted / 2 usage or hook
block), the ``--format json`` document shape, ``--explain`` output, and the
``--hook`` PostToolUse path.

Environment-honest like the rest of the suite: z3-dependent expectations
branch on the detected solver backend, and no test needs the tf-plan
extractor or any network/credentials.
"""

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from gcp_grounding.cli import SNAPSHOT_ENV, main
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.report import SCHEMA

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"
SNAPSHOT = FIXTURES / "snapshot.json"
REPO_ROOT = Path(__file__).resolve().parent.parent

GOOD = POLICIES / "iam_policy_good.json"
BAD = POLICIES / "iam_policy_bad.json"

HAVE_Z3 = get_solver().backend == "z3"


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def hook_event(path) -> str:
    return json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Write",
                       "tool_input": {"file_path": str(path), "content": ""}})


# -- exit codes over the fixture bundles --------------------------------------


def test_good_iam_policy_exits_zero(capsys):
    code, out, _ = invoke(capsys, "verify-policy", str(GOOD),
                          "--snapshot", str(SNAPSHOT))
    assert code == 0
    assert "PASSED" in out and str(GOOD) in out


def test_bad_iam_policy_exits_one_with_findings(capsys):
    code, out, _ = invoke(capsys, "verify-policy", str(BAD),
                          "--snapshot", str(SNAPSHOT))
    assert code == 1
    assert "FAILED" in out
    assert "roles/bigquery.reader" in out
    # The renderer surfaces the reasoner's near-miss suggestion.
    assert "roles/bigquery.dataViewer" in out


def test_unrecognized_document_fails_open_to_exit_zero(capsys, tmp_path):
    mystery = tmp_path / "mystery.json"
    mystery.write_text(json.dumps({"totally": "unrelated"}), encoding="utf-8")
    code, out, _ = invoke(capsys, "verify-policy", str(mystery),
                          "--snapshot", str(SNAPSHOT))
    assert code == 0  # unverified is honest ignorance, not a gate failure
    assert "unverified=1" in out


# -- --format json ------------------------------------------------------------


def test_json_format_shape_on_the_bad_bundle(capsys):
    code, out, _ = invoke(capsys, "verify-policy", str(BAD),
                          "--snapshot", str(SNAPSHOT), "--format", "json")
    assert code == 1
    doc = json.loads(out)
    assert doc["schema"] == SCHEMA
    assert doc["ok"] is False
    assert doc["source"] == str(BAD)
    assert doc["captured_at"] == GcpSnapshot.load(SNAPSHOT).captured_at
    assert set(doc["summary"]) == {"grounded", "ungrounded", "contradicted",
                                   "unverified"}
    for verdict in doc["verdicts"]:
        assert set(verdict) == {"status", "kind", "target", "message",
                                "suggestions"}
    assert any(v["status"] == "ungrounded" and v["kind"] == "role"
               and v["target"] == "roles/bigquery.reader"
               for v in doc["verdicts"])


def test_json_format_on_the_good_bundle(capsys):
    code, out, _ = invoke(capsys, "verify-policy", str(GOOD),
                          "--snapshot", str(SNAPSHOT), "--format", "json")
    assert code == 0
    doc = json.loads(out)
    assert doc["ok"] is True
    assert doc["summary"]["ungrounded"] == 0
    assert doc["summary"]["contradicted"] == 0


# -- usage errors (exit 2) ----------------------------------------------------


def test_snapshot_is_required(capsys, monkeypatch):
    monkeypatch.delenv(SNAPSHOT_ENV, raising=False)
    code, _, err = invoke(capsys, "verify-policy", str(GOOD))
    assert code == 2
    assert SNAPSHOT_ENV in err


def test_snapshot_falls_back_to_the_environment(capsys, monkeypatch):
    monkeypatch.setenv(SNAPSHOT_ENV, str(SNAPSHOT))
    code, out, _ = invoke(capsys, "verify-policy", str(GOOD))
    assert code == 0 and "PASSED" in out


def test_unloadable_snapshot_is_a_usage_error(capsys, tmp_path):
    broken = tmp_path / "snapshot.json"
    broken.write_text("{not json", encoding="utf-8")
    code, _, err = invoke(capsys, "verify-policy", str(GOOD),
                          "--snapshot", str(broken))
    assert code == 2
    assert "snapshot" in err


def test_file_is_required_without_hook(capsys):
    code, _, err = invoke(capsys, "verify-policy")
    assert code == 2
    assert "FILE" in err


def test_file_and_hook_are_mutually_exclusive(capsys):
    code, _, err = invoke(capsys, "verify-policy", str(GOOD), "--hook",
                          "--snapshot", str(SNAPSHOT))
    assert code == 2
    assert "mutually exclusive" in err


# -- --baseline (new⊆old) -----------------------------------------------------


@pytest.fixture()
def baseline_pair(tmp_path):
    old = tmp_path / "old.json"
    old.write_text(json.dumps({"bindings": [
        {"role": "roles/viewer", "members": ["user:alice@acme.example"]}]}),
        encoding="utf-8")
    # The extra grantee is a real snapshot principal, so the existence layer
    # stays green and any failure is the subset check's alone.
    widened = tmp_path / "widened.json"
    widened.write_text(json.dumps({"version": 3, "etag": "BwX=", "bindings": [
        {"role": "roles/viewer", "members": [
            "user:alice@acme.example",
            "serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com"]}]}),
        encoding="utf-8")
    return old, widened


def test_baseline_widening_is_judged(capsys, baseline_pair):
    old, widened = baseline_pair
    code, out, _ = invoke(capsys, "verify-policy", str(widened),
                          "--snapshot", str(SNAPSHOT), "--baseline", str(old))
    if HAVE_Z3:
        assert code == 1
        assert "ci-deployer" in out
    else:
        # No z3 → new⊆old is honestly undecided, and undecided never fails.
        assert code == 0
        assert "unverified" in out


def test_unreadable_baseline_fails_open(capsys, tmp_path):
    code, out, _ = invoke(capsys, "verify-policy", str(GOOD),
                          "--snapshot", str(SNAPSHOT),
                          "--baseline", str(tmp_path / "missing.json"))
    assert code == 0
    assert "unverified" in out


# -- --explain ----------------------------------------------------------------


def test_explain_dumps_constraints_to_stderr(capsys):
    code, out, err = invoke(capsys, "verify-policy", str(GOOD),
                            "--snapshot", str(SNAPSHOT), "--explain")
    assert code == 0
    assert "z3 constraints generated this run" in err
    assert "z3 constraints" not in out  # stdout stays the plain report
    if HAVE_Z3:
        # The good bundle's time-window condition, translated to z3.
        assert "[cel]" in err and "request.time" in err
    else:
        assert "z3 is not available" in err


def test_explain_covers_the_subset_assertion(capsys, baseline_pair):
    old, widened = baseline_pair
    _, _, err = invoke(capsys, "verify-policy", str(widened),
                       "--snapshot", str(SNAPSHOT), "--baseline", str(old),
                       "--explain")
    assert "z3 constraints generated this run" in err
    if HAVE_Z3:
        assert "[subset]" in err and "ci-deployer" in err


# -- --hook (PostToolUse) -----------------------------------------------------


def run_hook(capsys, monkeypatch, stdin_text: str, *extra: str):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
    return invoke(capsys, "verify-policy", "--hook",
                  "--snapshot", str(SNAPSHOT), *extra)


def test_hook_good_policy_is_silent_and_passes(capsys, monkeypatch):
    code, out, err = run_hook(capsys, monkeypatch, hook_event(GOOD))
    assert code == 0
    assert out == "" and err == ""


def test_hook_bad_policy_blocks_with_findings_on_stderr(capsys, monkeypatch):
    code, out, err = run_hook(capsys, monkeypatch, hook_event(BAD))
    assert code == 2  # Claude Code's blocking exit code
    assert out == ""
    assert "FAILED" in err and "roles/bigquery.reader" in err


def test_hook_ignores_non_policy_files(capsys, monkeypatch):
    code, out, err = run_hook(capsys, monkeypatch,
                              hook_event("/somewhere/notes.md"))
    assert code == 0
    assert out == "" and err == ""


def test_hook_raw_tf_file_fails_open(capsys, monkeypatch, tmp_path):
    tf = tmp_path / "main.tf"
    tf.write_text('resource "google_project_iam_member" "x" {}\n',
                  encoding="utf-8")
    # Raw HCL is not `terraform show -json` output: unverified, never a block.
    code, _, _ = run_hook(capsys, monkeypatch, hook_event(tf))
    assert code == 0


def test_hook_fails_open_on_a_broken_event(capsys, monkeypatch):
    code, _, err = run_hook(capsys, monkeypatch, "{not json")
    assert code == 0
    assert "fail-open" in err
    code, _, _ = run_hook(capsys, monkeypatch, json.dumps({"tool_name": "Write"}))
    assert code == 0


def test_hook_fails_open_without_a_snapshot(capsys, monkeypatch):
    monkeypatch.delenv(SNAPSHOT_ENV, raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO(hook_event(BAD)))
    code, _, err = invoke(capsys, "verify-policy", "--hook")
    assert code == 0  # a broken hook setup must never block an edit
    assert "fail-open" in err


# -- packaging: python -m and the console script ------------------------------


def test_python_dash_m_entrypoint():
    proc = subprocess.run(
        [sys.executable, "-m", "gcp_grounding", "verify-policy", str(BAD),
         "--snapshot", str(SNAPSHOT), "--format", "json"],
        cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["ok"] is False


def test_console_script_is_declared_in_pyproject():
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'gcp-ground = "gcp_grounding.cli:main"' in text
