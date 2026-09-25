"""Acceptance for audit rows R31, R32, R33 and R47: four output defects.

None of the four moves an exit code — every one of them is what the operator
READS about a run whose decision was already correct, which is exactly why they
survived a suite this size. The four are kept in one module because they share
that character and nothing else; each section below states the defect it pins.

**R31 — the state block printed twice.** ``--explain``'s narrative ends by
appending the provenance block (``cli._narrative_lines``), and ``--state-explain``
then printed it again: one run with both flags carried ``state used this run:``,
``settings:``, ``targets:`` and ``drift:`` twice each. ``cli.py``'s own flag
documentation says ``--explain`` "appends the same lines", so the second copy
was never the documented shape. A ``DOMAIN:KEY`` argument is a DIFFERENT block
(``explain_state.fact_lines``) that the narrative never carries, so that form
stays additional — the distinction the fix turns on.

**R32 — a ceiling named as a ceiling nobody configured.** The staleness verdict
rendered the CONFIGURED limit through the same whole-unit formatter it uses for
a MEASURED age, so ``--max-age 36h`` reported "past the 1 day freshness limit"
— a tighter ceiling than the gate was applying — and anything under an hour
reported "the 0 hours freshness limit", which reads as no ceiling at all. The
gate's behaviour was right in every case; only the prose rounded.

**R33 — an escape clause advising the flag already in force.** The bash-mutation
banner closed with "or pass ``--bash-policy=warn`` if the command is
intentional" under ``warn`` too. The audit measured byte-identical stderr under
both policies, differing only in the headline word and the exit code.

**R47 — "1 enforcing" about a promise the run never put to a document.** The
narrative marks a promise ``not checked`` when no verdict of its own domain
channel judged it (``CompiledRule.applies_to`` gates on document kind), while
the closing summary listed the same promise unmarked and counted it in a bare
"N enforcing". Both halves are true statements about different properties, and
a reader of the summary alone got only the one that overstates the run.

In-process throughout: every assertion drives ``cli.main`` directly or calls a
renderer, so nothing here spawns a child or lands on the suite's spawn budget.
Tests that are about a ceiling or an age pin their own clock, overriding the
session default.
"""

from __future__ import annotations

import io
import json
from datetime import timedelta
from pathlib import Path

import pytest

from gcp_grounding import freshness
from gcp_grounding.cli import EXIT_BLOCK, EXIT_OK, main
from gcp_grounding.core.solver import get_solver
from gcp_grounding.freshness import parse_duration

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"
GOOD = POLICIES / "iam_policy_good.json"
SNAPSHOT = FIXTURES / "snapshot.json"

AGENTIC = FIXTURES / "agentic"
AGENTIC_SNAPSHOT = FIXTURES / "agentic_snapshot.json"
AGENTIC_REQUIREMENTS = FIXTURES / "sec_requirements"
A10_POLICY = AGENTIC / "iam" / "A10_owner_to_external.policy.json"

#: The audit's own bypass command, and the one the banner is printed for.
OWNER_GRANT = ("gcloud projects add-iam-policy-binding zolt-prod "
               "--member=allUsers --role=roles/owner")

#: The clause R33 is about, quoted from the banner.
ESCAPE_CLAUSE = "--bash-policy=warn if the command is intentional"

#: A clock far past every committed fixture stamp, so the ceiling is the only
#: thing deciding the staleness verdict the prose is read off.
AGED = "2027-06-01T00:00:00Z"

SUMMARY_HEADER = "summary — what just happened:"

HAVE_Z3 = get_solver().backend == "z3"
_needs_z3 = pytest.mark.skipif(
    not HAVE_Z3, reason="no solver: no promise compiles, so nothing enforces")


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def hook_invoke(capsys, monkeypatch, event: dict,
                *argv: str) -> tuple[int, str, str]:
    """One hook run over *event*, in process: the event is handed to the real
    stdin reader the way the agent's harness hands it over."""
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(event)))
    return invoke(capsys, *argv)


# -- R31: --explain --state-explain prints the state block once ----------------


STATE_BLOCK_MARKERS = ("state used this run:", "settings:", "targets:", "drift:")


def test_explain_and_state_explain_print_the_state_block_once(capsys):
    """Both flags, one block. The audit counted ``state used this run:`` twice
    in one run; the assertion here is the stronger one it implies — stderr
    under both flags is BYTE-IDENTICAL to stderr under ``--explain`` alone,
    because the flag's whole unargumented output is what the narrative already
    ends with."""
    common = ["verify-policy", str(GOOD), "--snapshot", str(SNAPSHOT),
              "--no-config"]
    _code, _out, explained = invoke(capsys, *common, "--explain")
    code, _out, both = invoke(capsys, *common, "--explain", "--state-explain")
    assert code == EXIT_OK
    for marker in STATE_BLOCK_MARKERS:
        assert both.count(marker) == explained.count(marker) <= 1, marker
    assert both == explained


def test_state_explain_alone_still_prints_the_block(capsys):
    """The other half of the same predicate: without ``--explain`` there is no
    narrative to have appended it, so the flag is still the only thing that
    prints the block."""
    code, _out, err = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                             str(SNAPSHOT), "--no-config", "--state-explain")
    assert code == EXIT_OK
    assert err.count("state used this run:") == 1
    assert SUMMARY_HEADER not in err


def test_a_state_explain_target_stays_additional_under_explain(capsys):
    """``--state-explain DOMAIN:KEY`` is a drill-down the narrative never
    carries, so it is NOT the repeat the fix skips: it is still printed under
    ``--explain``, after the block the narrative ended with."""
    common = ["verify-policy", str(GOOD), "--snapshot", str(SNAPSHOT),
              "--no-config", "--explain"]
    _code, _out, plain = invoke(capsys, *common)
    code, _out, drilled = invoke(capsys, *common, "--state-explain",
                                 "iam_bindings:roles/bigquery.dataViewer")
    assert code == EXIT_OK
    assert drilled.count("state used this run:") == 1
    assert len(drilled) > len(plain)
    assert drilled.startswith(plain[:plain.index("\n")])


def test_the_hook_prints_the_state_block_once_too(capsys, monkeypatch):
    """The hook's stderr carries the same two writers in the same order, so it
    carried the same duplicate. One predicate governs both modes."""
    event = {"hook_event_name": "PostToolUse", "tool_name": "Write",
             "tool_input": {"file_path": str(GOOD), "content": ""}}
    argv = ["verify-policy", "--hook", "--snapshot", str(SNAPSHOT),
            "--no-config", "--explain"]
    _code, _out, explained = hook_invoke(capsys, monkeypatch, event, *argv)
    code, _out, both = hook_invoke(capsys, monkeypatch, event, *argv,
                                   "--state-explain")
    assert code == EXIT_OK
    assert both == explained
    assert both.count("state used this run:") == 1


# -- R32: the configured ceiling is named as it was configured -----------------


@pytest.mark.parametrize("token, limit", [
    ("36h", "36 hours"),       # the audit's own case: NOT "1 day"
    ("90m", "90 minutes"),     # NOT "1 hour"
    ("30s", "30 seconds"),     # NOT "0 hours", which reads as no ceiling
    ("129600", "36 hours"),    # the same ceiling in seconds reads the same
    ("7d", "7 days"),          # MAX_AGE_DEFAULT's spelling is unmoved
    ("1w", "7 days"),          # and a week is the default, not a new unit
    ("1d", "1 day"),
    ("1h", "1 hour"),
    ("60m", "1 hour"),
    ("90s", "90 seconds"),     # a remainder in no unit is named in seconds
])
def test_a_configured_ceiling_is_named_in_the_unit_that_divides_it(token, limit):
    """One unit, chosen because it divides the ceiling EXACTLY — never a
    flooring division, which renames the number the operator typed."""
    assert freshness._describe_limit(parse_duration(token)) == limit


def test_a_measured_age_still_rounds_to_whole_units():
    """``_describe`` is unchanged and still renders an AGE, where the order of
    magnitude is what a reader wants: the two callers are kept apart rather
    than one formatter being bent to serve both."""
    assert freshness._describe(timedelta(hours=36)) == "1 day"
    assert freshness._describe(timedelta(minutes=90)) == "1 hour"
    assert freshness._describe(timedelta(days=92)) == "92 days"


def test_a_zero_ceiling_is_named_in_seconds_not_as_zero_hours():
    """Nothing can be fresh under a zero ceiling, and "0 seconds" says that;
    "0 hours" reads as the ceiling being off."""
    assert freshness._describe_limit(timedelta(0)) == "0 seconds"


@pytest.mark.parametrize("token, limit", [("36h", "36 hours"),
                                          ("90m", "90 minutes"),
                                          ("1d", "1 day")])
def test_the_staleness_verdict_quotes_the_ceiling_the_run_was_given(
        capsys, monkeypatch, token, limit):
    """End to end, the way the audit measured it: a snapshot far past the
    ceiling, and the verdict names the ceiling that was configured."""
    monkeypatch.setenv(freshness.NOW_ENV, AGED)
    code, out, _err = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                             str(SNAPSHOT), "--no-config", "--max-age", token)
    assert code == EXIT_OK
    assert f"past the {limit} freshness limit" in out
    assert "0 hours" not in out


# -- R33: the escape clause belongs to `block` ---------------------------------


def bash_event(command: str = OWNER_GRANT) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}}


def test_the_escape_clause_is_printed_under_block(capsys, monkeypatch):
    """Under ``block`` the advice is the operator's way out, and the banner is
    byte-unchanged by this fix."""
    code, _out, err = hook_invoke(
        capsys, monkeypatch, bash_event(), "verify-policy", "--hook",
        "--snapshot", str(SNAPSHOT), "--no-config", "--bash-policy", "block")
    assert code == EXIT_BLOCK
    assert "BLOCKED — unchecked GCP mutation in a shell command" in err
    assert ESCAPE_CLAUSE in err


def test_warn_does_not_advise_the_policy_it_is_already_running_under(
        capsys, monkeypatch):
    """``warn`` drops the clause and keeps the FINDING, which is the whole
    reason to run this mode rather than ``off``: the verdict line is
    byte-identical to ``block``'s, and only the headline, the timing line (the
    command was not stopped) and the advice that no longer applies differ."""
    argv = ["verify-policy", "--hook", "--snapshot", str(SNAPSHOT),
            "--no-config", "--bash-policy"]
    blocked_code, _out, blocked = hook_invoke(capsys, monkeypatch, bash_event(),
                                              *argv, "block")
    warned_code, _out, warned = hook_invoke(capsys, monkeypatch, bash_event(),
                                            *argv, "warn")
    assert (blocked_code, warned_code) == (EXIT_BLOCK, EXIT_OK)
    assert ESCAPE_CLAUSE not in warned
    assert "WARNING — unchecked GCP mutation in a shell command" in warned
    for finding in ("? [bash-mutation]", "add-iam-policy-binding",
                    "roles/owner", "allUsers"):
        assert finding in warned and finding in blocked
    assert warned.splitlines()[1] == blocked.splitlines()[1]
    # The half of the advice that holds under both policies still prints, and
    # it is the same sentence up to the clause.
    warned_advice, blocked_advice = (text.splitlines()[-1]
                                     for text in (warned, blocked))
    assert warned_advice == ("  Express this change as a policy document or "
                             "`terraform show -json` plan output so the gate "
                             "can check it.")
    assert blocked_advice.startswith(warned_advice[:-1])


# -- R47: the summary carries the narrative's `not checked` --------------------


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    """The agentic corpus compiled once for this module. Exit 1 by design —
    the corpus carries a deliberately rejected promise — and the artifacts are
    written either way."""
    out = tmp_path_factory.mktemp("cosmetics") / "compiled"
    assert main(["compile-requirements", str(AGENTIC_REQUIREMENTS), "--snapshot",
                 str(AGENTIC_SNAPSHOT), "--out", str(out)]) == 1
    return out


def narrative_markers(err: str) -> set[str]:
    """The promise ids the narrative's stanzas mark ``not checked``."""
    narrative = err.split(SUMMARY_HEADER)[0]
    return {line.split()[2] for line in narrative.splitlines()
            if line.startswith("  not checked  ")}


def summary_markers(err: str) -> set[str]:
    """The promise ids the closing summary's block marks ``not checked``."""
    summary = err.split(SUMMARY_HEADER)[1]
    return {line.split()[2] for line in summary.splitlines()
            if line.startswith("      not checked  ")}


@_needs_z3
def test_the_summary_marks_every_promise_the_narrative_left_unchecked(
        capsys, compiled):
    """The join the audit found broken: an IAM document reaches neither the
    firewall, the perimeter nor the org-policy promise, the narrative says so
    for each, and the summary five lines later listed all three unmarked. The
    ids are compared BOTH WAYS against the narrative's own markers rather than
    against a list typed here, so neither surface can drift from the other."""
    _code, _out, err = invoke(capsys, "verify-policy", str(A10_POLICY),
                              "--snapshot", str(AGENTIC_SNAPSHOT),
                              "--requirements", str(compiled), "--explain")
    unchecked = narrative_markers(err)
    assert unchecked == {"no-open-ssh-rdp-ingress", "perimeter-restricts-storage",
                         "sa-key-creation-disabled"}
    assert summary_markers(err) == unchecked


@_needs_z3
def test_the_promises_row_counts_what_the_run_did_not_check(capsys, compiled):
    """And the count agrees with the marks: the row still reports six promises
    in force — they are — and no longer reports six promises put to this
    document, which is how a reader of the summary alone read it."""
    _code, _out, err = invoke(capsys, "verify-policy", str(A10_POLICY),
                              "--snapshot", str(AGENTIC_SNAPSHOT),
                              "--requirements", str(compiled), "--explain")
    row = next(line for line in err.splitlines()
               if line.startswith("  promises in force "))
    unchecked = summary_markers(err)
    assert f"6 enforcing ({len(unchecked)} not checked), 2 not" in row
    # The stalled two are counted apart from the unreached three: a promise
    # that never compiled is not a promise this run failed to reach.
    assert unchecked.isdisjoint({"bigquery-reader-only",
                                 "untranslated-security-review-before-merge"})


@_needs_z3
def test_a_run_that_checks_every_promise_keeps_the_bare_count(capsys, tmp_path):
    """The clause is printed only when the run left something unreached, so a
    run that reached everything it loaded reads exactly as it always did —
    which is what keeps every README block quoting this row byte-unchanged.

    The org-policy scenario is that run: eleven promises of one domain, and a
    proposal of that domain, so nothing is left over.
    """
    example = REPO_ROOT / "examples" / "terraform-orgpolicy"
    out = tmp_path / "compiled-orgpolicy"
    assert main(["compile-requirements", str(example),
                 "--snapshot", str(example / "snapshot.json"),
                 "--out", str(out)]) == 0
    capsys.readouterr()
    _code, _out, err = invoke(capsys, "verify-policy",
                              "--proposal", str(example / "base.tf.json"),
                              "--snapshot", str(example / "snapshot.json"),
                              "--terraform-state",
                              str(example / "terraform.tfstate"),
                              "--requirements", str(out), "--explain")
    assert not narrative_markers(err)
    row = next(line for line in err.splitlines()
               if line.startswith("  promises in force "))
    assert "not checked" not in row
    assert row.startswith("  promises in force       : 11 enforcing, 0 not — ")


@_needs_z3
def test_an_unchecked_promise_keeps_its_place_and_its_sentence(capsys, compiled):
    """A promise this run did not reach is still in force and still the
    author's: it keeps its id-sorted place in the enforcing list and the
    sentence the artifact stored, and gains only the marker. Moving it in with
    the stalled promises would say the compile rejected it."""
    _code, _out, err = invoke(capsys, "verify-policy", str(A10_POLICY),
                              "--snapshot", str(AGENTIC_SNAPSHOT),
                              "--requirements", str(compiled), "--explain")
    summary = err.split(SUMMARY_HEADER)[1].splitlines()
    start = next(i for i, line in enumerate(summary)
                 if line.startswith("  promises in force "))
    assert summary[start + 1] == "      impersonation-sre-only"
    assert summary[start + 3] == "      not checked  no-open-ssh-rdp-ingress"
    assert summary[start + 4] == (
        "        “No ingress firewall rule may allow tcp/22 or tcp/3389 "
        "from 0.0.0.0/0.”")
