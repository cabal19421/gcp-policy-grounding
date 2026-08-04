"""Self-tests for the subprocess hook driver and the assertion helpers.

Everything downstream in the agentic suite asserts through
:mod:`tests.agentic.hookrunner` and :mod:`tests.agentic.asserts`, so a silent
drift here — an argv that stopped matching the CLI, a fail-open arm that
started blocking, an assertion helper that accepts anything — would be
invisible in every family at once while their tests stayed green. This module
pins the driver against the EXISTING toy fixtures, which are already covered by
``tests/test_gcp_cli.py`` in-process: if the two ever disagree, one of them is
wrong and both are red.

Roughly a dozen real spawns. They cost about 0.05s each, so the module runs in
well under a second; if that ever changes, drop CASES rather than the
subprocess boundary, which is the entire point of the module.
"""

from __future__ import annotations

import json
import os

import pytest

from tests.agentic import hookrunner
from tests.agentic.asserts import (
    assert_abstained,
    assert_blocked,
    assert_no_verdictless_pass,
    assert_not_silently_dropped,
    assert_passed,
    assert_recorded,
)
from tests.agentic.hookrunner import (
    HookOutcome,
    SCRUBBED_ENV,
    bound_subprocess_budget,  # noqa: F401 — autouse: bind spawns to the budget
    child_env,
    ground_json,
    run_hook,
    run_hook_explain,
    run_hook_raw,
)


def hook_event(path) -> dict:
    """A Claude-Code PostToolUse event naming *path* as the edited file."""
    return {
        "session_id": "hookrunner-self-test",
        "hook_event_name": "PostToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": str(path)},
    }


@pytest.fixture
def good_policy(policies_dir):
    return policies_dir / "iam_policy_good.json"


@pytest.fixture
def bad_policy(policies_dir):
    return policies_dir / "iam_policy_bad.json"


# -- the three outcomes -------------------------------------------------------


def test_clean_policy_passes_byte_silently(good_policy, toy_snapshot_path):
    outcome = run_hook(hook_event(good_policy), snapshot=toy_snapshot_path)
    assert_passed(outcome)
    # argv is part of the contract every downstream family inherits.
    assert outcome.argv[1:5] == ("-m", "gcp_grounding", "verify-policy", "--hook")
    assert outcome.argv[-2:] == ("--snapshot", str(toy_snapshot_path))
    assert outcome.event == hook_event(good_policy)


def test_hallucinated_role_blocks_with_the_suggestion(bad_policy, toy_snapshot_path):
    outcome = run_hook(hook_event(bad_policy), snapshot=toy_snapshot_path)
    assert_blocked(outcome, "roles/bigquery.reader", "did you mean",
                   "roles/bigquery.dataViewer")
    assert outcome.stdout == ""


def test_unparsable_document_abstains_on_the_record(tmp_path, toy_snapshot_path):
    """A raw ``.tf`` file is not ``terraform show -json`` output: the gate
    cannot judge it, so it must pass AND say so — the abstain sidecar is the
    only place that says so, because the hook run is silent by design."""
    unparsable = tmp_path / "main.tf"
    unparsable.write_text('resource "google_project_iam_binding" "x" {}\n',
                          encoding="utf-8")
    outcome = run_hook(hook_event(unparsable), snapshot=toy_snapshot_path)
    report = ground_json(unparsable, snapshot=toy_snapshot_path)
    assert_abstained(outcome, report, "nothing was checked")


# -- stdin: the events that are not events ------------------------------------


def test_empty_stdin_fails_open(toy_snapshot_path):
    outcome = run_hook_raw(b"", snapshot=toy_snapshot_path)
    assert outcome.exit_code == 0, str(outcome)
    assert outcome.stdout == "", str(outcome)
    assert "fail-open" in outcome.stderr, str(outcome)
    assert outcome.event is None


def test_json_null_event_fails_open(toy_snapshot_path):
    outcome = run_hook_raw(b"null", snapshot=toy_snapshot_path)
    assert outcome.exit_code == 0, str(outcome)
    assert outcome.stdout == "", str(outcome)
    assert "not an object" in outcome.stderr, str(outcome)


def test_five_megabyte_event_neither_hangs_nor_traps(good_policy, toy_snapshot_path):
    """Padded with a key the gate ignores: the size must not change the
    verdict, and must not produce a timeout or a traceback either."""
    event = hook_event(good_policy)
    event["ignored_padding"] = "x" * (5 * 1024 * 1024)
    payload = json.dumps(event).encode("utf-8")
    assert len(payload) > 5 * 1024 * 1024
    outcome = run_hook_raw(payload, snapshot=toy_snapshot_path)  # no TimeoutExpired
    assert outcome.exit_code in (0, 2), str(outcome)
    assert outcome.stdout == "", str(outcome)
    assert "Traceback" not in outcome.stderr, str(outcome)


# -- the environment is the child's, not the developer's ----------------------


def test_no_snapshot_fails_open_even_with_the_env_var_exported(
        bad_policy, toy_snapshot_path, monkeypatch):
    """``snapshot=None`` means "spawn with no ``--snapshot``". The developer
    having ``GCP_GROUNDING_SNAPSHOT`` exported must not quietly supply one —
    that would turn this fail-open test green on a clean machine and red on
    theirs, or worse, the reverse."""
    monkeypatch.setenv("GCP_GROUNDING_SNAPSHOT", str(toy_snapshot_path))
    outcome = run_hook(hook_event(bad_policy), snapshot=None)
    assert outcome.exit_code == 0, str(outcome)
    assert outcome.stdout == "", str(outcome)
    assert "fail-open" in outcome.stderr, str(outcome)
    assert "--snapshot" not in outcome.argv


def test_child_env_is_scrubbed_and_offline(monkeypatch):
    for name in SCRUBBED_ENV:
        monkeypatch.setenv(name, "developer-shell-leftover")
    built = child_env()
    assert built["GCP_SEC_LLM"] == "0"  # explicit, not merely absent
    leaked = [name for name in SCRUBBED_ENV
              if name != "GCP_SEC_LLM" and name in built]
    assert leaked == []
    assert built["PATH"] == os.environ["PATH"]  # inherited, not a bare env
    # The caller's overrides win: the degraded-world overlays put
    # GCP_TEST_BLOCK_IMPORTS back deliberately.
    overridden = child_env({"GCP_TEST_BLOCK_IMPORTS": "z3"})
    assert overridden["GCP_TEST_BLOCK_IMPORTS"] == "z3"


# -- the sidecar and the report-shaped helpers --------------------------------


def test_ground_json_returns_the_report_document(bad_policy, estate_snapshot_path):
    report = ground_json(bad_policy, snapshot=estate_snapshot_path)
    assert report["schema"] == "gcp-grounding-report/1"
    assert set(report) >= {"schema", "ok", "backend", "captured_at", "source",
                           "summary", "verdicts"}
    assert report["ok"] is False
    verdict = assert_recorded(report, status="ungrounded", kind="role",
                              target="roles/bigquery.reader")
    assert "does not exist in the snapshot" in verdict["message"]
    assert_not_silently_dropped(report, "roles/bigquery.reader")


def test_a_recognized_document_never_passes_verdictless(good_policy, toy_snapshot_path):
    outcome = run_hook(hook_event(good_policy), snapshot=toy_snapshot_path)
    report = ground_json(good_policy, snapshot=toy_snapshot_path)
    assert_no_verdictless_pass(outcome, report)


def test_explain_is_the_visible_channel_on_an_exit_zero_run(
        good_policy, toy_snapshot_path):
    """cli.py:183-184 prints the explain lines before the ``report.ok`` check,
    so this is the one thing a passing hook run can be asserted on."""
    outcome = run_hook_explain(hook_event(good_policy), snapshot=toy_snapshot_path)
    assert outcome.exit_code == 0, str(outcome)
    assert outcome.stdout == "", str(outcome)
    assert "z3 constraints generated this run" in outcome.stderr, str(outcome)
    assert "--explain" in outcome.argv


# -- the driver's own bookkeeping (no spawn) ----------------------------------


def test_outcome_str_renders_everything_a_failure_needs():
    outcome = HookOutcome(exit_code=2, stdout="", stderr="FAILED: nope",
                          argv=("python", "-m", "gcp_grounding"),
                          event={"tool_input": {}}, stdin_bytes=b"{}")
    rendered = str(outcome)
    assert "python -m gcp_grounding" in rendered
    assert "exit code: 2" in rendered
    assert "FAILED: nope" in rendered
    assert "(empty)" in rendered  # stdout, named rather than blank


def test_every_spawn_was_counted_against_the_session_budget(
        good_policy, toy_snapshot_path, subprocess_budget):
    before = subprocess_budget.counts.get(hookrunner.BUDGET_LABEL, 0)
    run_hook(hook_event(good_policy), snapshot=toy_snapshot_path)
    assert subprocess_budget.counts[hookrunner.BUDGET_LABEL] == before + 1
    assert hookrunner.current_budget() is subprocess_budget
