"""Self-tests for the subprocess hook driver and the assertion helpers.

Everything downstream in the agentic suite asserts through
:mod:`tests.agentic.hookrunner` and :mod:`tests.agentic.asserts`, so a silent
drift here — an argv that stopped matching the CLI, a fail-open arm that
started blocking, an assertion helper that accepts anything — would be
invisible in every family at once while their tests stayed green. This module
pins the driver against the EXISTING toy fixtures, which are already covered by
``tests/test_gcp_cli.py`` in-process: if the two ever disagree, one of them is
wrong and both are red.

Eighteen real spawns, measured off the budget's own per-label breakdown.
Seventeen are gate children at about 0.05s each; the eighteenth is a pytest
child, and it costs most of the module's ~1.0s wall clock. It earns that: a
session-scoped autouse fixture cannot be observed from inside the session it
governs, so the only way to prove that a module which never imports a budget
fixture is enrolled anyway is to run such a module in its own session. If the
cost ever has to come down, drop CASES rather than the subprocess boundary,
which is the entire point of the module.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from tests.agentic import env, hookrunner
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


#: ``cli._explain_lines``' degraded-world line, verbatim (``cli.py:227-228``).
NO_Z3_EXPLAIN_NOTE = ("  (z3 is not available — no constraints were generated; "
                      "cel and subset checks degraded to 'unverified')")


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
    so this is the one thing a passing hook run can be asserted on.

    The header alone is NOT the assertion. ``cli._explain_lines`` builds that
    header unconditionally — an early ``return lines`` right after it leaves
    this module green while no constraint is ever translated, and in the
    degraded world the header is printed *precisely* when nothing was
    generated. So the semantics are asserted instead: the backend tag on the
    header, and a line naming the constraint this fixture must produce.
    ``iam_policy_good.json``'s third binding carries the time-window condition
    ``request.time < timestamp("2027-01-01T00:00:00Z")``, so exactly one
    ``[cel]`` line for ``bindings[2].condition.expression`` has to appear,
    carrying a real s-expression over ``request.time``.
    """
    outcome = run_hook_explain(hook_event(good_policy), snapshot=toy_snapshot_path)
    assert outcome.exit_code == 0, str(outcome)
    assert outcome.stdout == "", str(outcome)
    assert "--explain" in outcome.argv
    lines = outcome.stderr.splitlines()
    backend = "z3" if env.HAVE_Z3 else "builtin"
    assert f"z3 constraints generated this run [{backend}]:" in lines, str(outcome)
    if env.HAVE_Z3:
        prefix = "  [cel] bindings[2].condition.expression: "
        translated = [line for line in lines if line.startswith(prefix)]
        assert len(translated) == 1, str(outcome)
        constraint = translated[0][len(prefix):]
        assert constraint.startswith("("), str(outcome)
        assert "request.time" in constraint, str(outcome)
    else:
        assert NO_Z3_EXPLAIN_NOTE in lines, str(outcome)


# -- the no-z3 banner: scrubbed at the boundary, never at the assertion -------


def test_the_no_z3_fallback_banner_is_scrubbed_from_the_asserted_stream(
        good_policy, toy_snapshot_path, no_z3_env):
    """A clean policy through the no-z3 overlay: the ASSERTED stream is
    byte-empty and the RAW stream carries the banner.

    ``assert_passed``'s byte-empty-both-streams contract is not relaxed for the
    degraded world; the banner is filtered at the harness boundary and retained
    verbatim on the outcome, so the failure report still shows it.
    """
    outcome = run_hook(hook_event(good_policy), snapshot=toy_snapshot_path,
                       env=no_z3_env)
    assert_passed(outcome)
    assert outcome.stderr == "", str(outcome)
    assert outcome.stderr_raw == hookrunner.NO_Z3_FALLBACK_BANNER + "\n", str(outcome)
    assert hookrunner.NO_Z3_FALLBACK_BANNER in str(outcome)  # nothing is hidden


def test_the_stderr_allowlist_is_pinned_and_may_only_shrink():
    """One entry. This number may only go DOWN — a scrub list that grows is a
    hole in every byte-silence assertion downstream of it."""
    assert len(hookrunner.STDERR_ALLOWLIST) == 1


def test_every_allowlist_entry_matches_a_line_the_product_really_emits(
        good_policy, toy_snapshot_path, no_z3_env):
    """An entry that matches nothing is a licence to filter whatever it
    eventually does match, so every entry is checked against a real child's raw
    stderr rather than against a copy of the source string."""
    outcome = run_hook(hook_event(good_policy), snapshot=toy_snapshot_path,
                       env=no_z3_env)
    emitted = set(outcome.stderr_raw.split("\n"))
    assert set(hookrunner.STDERR_ALLOWLIST) <= emitted, str(outcome)


def test_any_stderr_byte_outside_the_allowlist_still_fails_assert_passed(
        good_policy, toy_snapshot_path, no_z3_env):
    """The same degraded child with ``--explain``: the banner is filtered, the
    two explain lines are not, and ``assert_passed`` still rejects the run."""
    outcome = run_hook_explain(hook_event(good_policy), snapshot=toy_snapshot_path,
                               env=no_z3_env)
    assert hookrunner.NO_Z3_FALLBACK_BANNER not in outcome.stderr, str(outcome)
    with pytest.raises(AssertionError, match="byte-silent"):
        assert_passed(outcome)
    # And literally one byte, so "any" is not read as "any whole extra line":
    # the allowlisted banner plus a single stray character.
    raw = hookrunner.NO_Z3_FALLBACK_BANNER + "\nx"
    stray = HookOutcome(exit_code=0, stdout="", stderr=hookrunner.scrub_stderr(raw),
                        argv=("python", "-m", "gcp_grounding"), stderr_raw=raw)
    assert stray.stderr == "x"
    with pytest.raises(AssertionError, match="byte-silent"):
        assert_passed(stray)


def test_explain_in_the_no_z3_world_names_the_builtin_backend_and_says_why(
        good_policy, toy_snapshot_path, no_z3_env):
    """The degraded branch of the explain channel, asserted in the world that
    really produces it rather than only on a machine that happens to lack z3."""
    outcome = run_hook_explain(hook_event(good_policy), snapshot=toy_snapshot_path,
                               env=no_z3_env)
    lines = outcome.stderr.splitlines()
    assert "z3 constraints generated this run [builtin]:" in lines, str(outcome)
    assert NO_Z3_EXPLAIN_NOTE in lines, str(outcome)


def test_the_scrub_matches_whole_lines_not_substrings():
    """No spawn: the filter's own contract. An entry is an EXACT line — a
    prefix match would swallow a real finding that quoted the banner."""
    banner = hookrunner.NO_Z3_FALLBACK_BANNER
    assert hookrunner.scrub_stderr(banner + "\n") == ""
    assert hookrunner.scrub_stderr("") == ""
    assert hookrunner.scrub_stderr(banner + "\nboom\n") == "boom\n"
    assert hookrunner.scrub_stderr("x" + banner + "\n") == "x" + banner + "\n"
    assert hookrunner.scrub_stderr(banner + " \n") == banner + " \n"


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
    """Counted under THIS module's name, not the driver's: a breakdown that
    attributes every spawn to ``tests.agentic.hookrunner`` names the one module
    that can never be the offender."""
    before = subprocess_budget.counts.get(__name__, 0)
    run_hook(hook_event(good_policy), snapshot=toy_snapshot_path)
    assert subprocess_budget.counts[__name__] == before + 1
    assert hookrunner.current_budget() is subprocess_budget


def test_current_budget_refuses_to_absorb_spawns_when_nothing_is_bound():
    """No module-level fallback counter. An unbound ``current_budget()`` raises
    rather than quietly counting into an object whose ``check()`` nobody ever
    calls — which is how three real spawns were recorded against a ceiling that
    was never enforced."""
    previous = hookrunner.bind_budget(None)
    try:
        with pytest.raises(RuntimeError, match="no subprocess budget is bound"):
            hookrunner.current_budget()
    finally:
        hookrunner.bind_budget(previous)


# A throwaway test module that imports ``run_hook`` and NOTHING about the
# budget — the exact shape that spawned three uncounted children. Written to a
# tmp dir and run by a real pytest child so the binding under test is the one
# in ``tests/conftest.py``, reached without this file's cooperation.
_UNENROLLED_MODULE = '''\
"""Imports run_hook. Imports no budget fixture. Opts out of nothing."""

from tests.agentic.hookrunner import current_budget, run_hook

EVENT = {event}
SNAPSHOT = {snapshot!r}


def test_an_unenrolled_module_still_spends_the_session_budget(subprocess_budget):
    budget = current_budget()
    assert budget is subprocess_budget
    before = budget.total
    run_hook(EVENT, snapshot=SNAPSHOT)
    assert budget.total == before + 1
    assert budget.counts[__name__] == 1, budget.counts
'''


def test_a_module_that_imports_only_run_hook_cannot_opt_out_of_the_budget(
        good_policy, toy_snapshot_path, tmp_path, subprocess_budget):
    """The binding is session-scoped and autouse in ``tests/conftest.py``, so a
    module that never imports a budget fixture still has its spawns counted —
    under its OWN name, so the per-label breakdown can name the offender.

    A real pytest child, because that is the only way to observe a session
    fixture this module cannot be inside.
    """
    module = tmp_path / "test_unenrolled_importer.py"
    module.write_text(
        _UNENROLLED_MODULE.format(event=json.dumps(hook_event(good_policy)),
                                  snapshot=str(toy_snapshot_path)),
        encoding="utf-8")
    subprocess_budget.increment(__name__)  # the pytest child is a spawn too
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "-p", "tests.conftest", str(module)],
        capture_output=True, text=True, cwd=str(env.REPO_ROOT),
        env=hookrunner.child_env({"PYTHONPATH": str(env.REPO_ROOT)}),
        timeout=hookrunner.DEFAULT_TIMEOUT)
    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
