"""README demo steps 3 and 4 — the two the at-a-glance table maps no arc to.

``run_demo.sh`` checks one arc per row of the README's "scenarios at a glance"
table, and neither of these steps is a row: step 3 (the REST attack judged with
the compiled promises in force) and step 4 (the hallucinated role and its
did-you-mean) are documented in the page's own ``bash`` block and nowhere else.
So this module is their guard, and what it guards is what the page CLAIMS they
show:

* step 3 — "the principal provably absent from the snapshot, the violated
  domain promise, and the escalation warning": three findings, of which two are
  existence answers read out of the snapshot's captured tables;
* step 4 — "a made-up role fails existence grounding and the report suggests
  the real name": one ``ungrounded`` finding carrying the two nearest real role
  names.

Both claims are only true INSIDE the freshness ceiling, and both fixture
snapshots carry a frozen ``captured_at`` — so at the wall clock every one of
those existence answers is correctly replaced by a named abstention. What made
that worth pinning rather than just documenting is the exit code: both steps
still exit 1 afterwards (step 3 on the promise refutation, step 4 on the
dead-binding ``[cel]`` finding), so a reader following the page sees the exit it
promises and no sign that the evidence it promises is gone. The page therefore
pins ``GCP_GROUNDING_NOW`` to each fixture's own capture era, and the pins here
are the same instants, asserted against the page's commands at the bottom.

The decayed halves are pinned too, under an explicitly stated later clock rather
than the calendar: an assertion about what staleness costs must not be able to
start passing for a different reason.

z3: the promise verdicts ride the solver, so the step-3 pins that need a
refutation line — and the step-4 decay pin, whose exit rests on the ``[cel]``
satisfiability finding — are skipped without it rather than branched.
"""

import os
import re
from pathlib import Path

import pytest

from gcp_grounding import freshness
from gcp_grounding.cli import main
from gcp_grounding.core.solver import get_solver

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"
FIXTURES = Path(__file__).parent / "fixtures" / "gcp"

#: Step 3's inputs: the agentic estate (captured 2026-07-25T08:00:00Z) and the
#: demo requirement corpus the page compiles in step 1.
STEP3_POLICY = FIXTURES / "agentic" / "iam" / "A10_owner_to_external.policy.json"
STEP3_SNAPSHOT = FIXTURES / "agentic_snapshot.json"
CORPUS = FIXTURES / "sec_requirements"

#: Step 4's inputs: the booby-trapped policy and the older estate snapshot
#: (captured 2026-07-18T09:30:00Z).
STEP4_POLICY = FIXTURES / "policies" / "iam_policy_bad.json"
STEP4_SNAPSHOT = FIXTURES / "snapshot.json"

#: The clocks the README's own step 3 and step 4 commands pin — each its
#: fixture's capture era.
STEP3_NOW = "2026-07-25T12:00:00Z"
STEP4_NOW = "2026-07-18T12:00:00Z"

#: A clock well past both ceilings, stated rather than inherited from the
#: calendar: this is "the same command, read a month later".
LATER = "2026-09-01T12:00:00Z"

ATTACKER = "user:attacker@evil.example"
PROMISE = "no-primitive-roles-outside-domain"
HALLUCINATED = "roles/bigquery.reader"

HAVE_Z3 = get_solver().backend == "z3"

_needs_z3 = pytest.mark.skipif(
    not HAVE_Z3, reason="no z3: the promise verdicts and the [cel] "
                        "satisfiability finding abstain on the builtin "
                        "backend, so no refutation line can pin")


@pytest.fixture(autouse=True)
def _no_inherited_configuration(monkeypatch):
    """Every input these steps use is named on their command line, and the clock
    each test states is the point — so nothing ambient may supply either."""
    for name in list(os.environ):
        if name.startswith("GCP_GROUNDING"):
            monkeypatch.delenv(name, raising=False)


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture
def compiled(tmp_path, capsys):
    """Step 1's compile of the demo corpus, to a scratch directory instead of
    ``demo/compiled``. EXIT 1 BY DESIGN: one document in the corpus names a
    hallucinated role, and a rejected promise fails the compile loudly — the
    artifacts, the rejection record included, are still written."""
    out = tmp_path / "compiled"
    assert main(["compile-requirements", str(CORPUS), "--snapshot",
                 str(STEP3_SNAPSHOT), "--out", str(out)]) == 1
    capsys.readouterr()
    return out


def _step3(capsys, monkeypatch, compiled, now: str) -> tuple[int, str, str]:
    """README step 3, with the clock stated the way its command states it."""
    monkeypatch.setenv(freshness.NOW_ENV, now)
    return invoke(capsys, "verify-policy", str(STEP3_POLICY),
                  "--snapshot", str(STEP3_SNAPSHOT),
                  "--requirements", str(compiled), "--explain")


def _step4(capsys, monkeypatch, now: str) -> tuple[int, str, str]:
    """README step 4 — no requirements configured, exactly as the page runs it."""
    monkeypatch.setenv(freshness.NOW_ENV, now)
    return invoke(capsys, "verify-policy", str(STEP4_POLICY),
                  "--snapshot", str(STEP4_SNAPSHOT))


# -- step 3: the attack, and all three pieces of the evidence the page names ----


@_needs_z3
def test_step_3_shows_the_absent_principal_the_promise_and_the_escalation(
        compiled, capsys, monkeypatch):
    code, out, _err = _step3(capsys, monkeypatch, compiled, STEP3_NOW)
    assert code == 1
    assert "FAILED" in out
    # 1. the principal provably absent from the snapshot
    assert (f"✗ [principal] bindings[0].members[0]: principal '{ATTACKER}' "
            f"does not exist in the snapshot") in out
    # 2. the violated domain promise, quoting the row that refutes it
    assert (f"⚠ [sec:iam] {PROMISE}: refuted by iam_bindings[0] "
            f"has_condition=False member='{ATTACKER}' role='roles/owner'") in out
    # 3. the escalation warning, naming the classes and the principal
    assert "✓ [iam_escalation] bindings[0].role: warning — roles/owner grants" \
        in out
    assert "(named-admin-role)" in out and f"to {ATTACKER}" in out


@_needs_z3
def test_step_3_read_a_month_later_keeps_the_exit_and_loses_two_thirds(
        compiled, capsys, monkeypatch):
    """Why the page pins the clock rather than only warning about it: past the
    ceiling the two estate reads abstain BY NAME — which is the ceiling working
    — while the run still exits 1 on the promise refutation. The exit the page
    documents survives; two of the three findings it documents do not."""
    code, out, _err = _step3(capsys, monkeypatch, compiled, LATER)
    assert code == 1, "the exit is unchanged, which is what hides the decay"
    assert (f"? [principal] bindings[0].members[0]: snapshot did not capture "
            f"principals — existence of '{ATTACKER}' is undecidable offline") \
        in out
    assert ("? [iam_escalation] snapshot did not capture roles — escalation "
            "classes were not decided") in out
    assert "✗ [principal]" not in out
    assert f"⚠ [sec:iam] {PROMISE}: refuted by" in out


# -- step 4: the hallucinated role and the did-you-mean ------------------------


def test_step_4_denies_the_made_up_role_and_suggests_the_real_names(
        capsys, monkeypatch):
    code, out, _err = _step4(capsys, monkeypatch, STEP4_NOW)
    assert code == 1
    assert (f"✗ [role] bindings[0].role: role '{HALLUCINATED}' does not exist "
            f"in the snapshot") in out
    assert "(did you mean: roles/bigquery.jobUser, roles/bigquery.dataViewer?)" \
        in out


@_needs_z3
def test_step_4_read_a_month_later_keeps_the_exit_and_loses_the_suggestion(
        capsys, monkeypatch):
    """The same trap on the other step: the did-you-mean is an existence answer,
    so a stale capture replaces it with the abstention — and the run still exits
    1, on the dead-binding [cel] finding it also carries."""
    code, out, _err = _step4(capsys, monkeypatch, LATER)
    assert code == 1
    assert "⚠ [cel] bindings[2].condition.expression: condition is never true" \
        in out
    assert (f"? [role] bindings[0].role: snapshot did not capture roles — "
            f"existence of '{HALLUCINATED}' is undecidable offline") in out
    assert "did you mean" not in out
    assert "? [staleness]" in out, "the ceiling names the source to re-capture"


# -- the page's own commands carry these pins ----------------------------------


def test_the_readme_pins_the_same_clocks_on_the_same_two_steps():
    """The conformance half: these assertions are only about the README's steps
    while the README's commands are the commands run here."""
    text = README.read_text(encoding="utf-8")
    commands = []
    for block in re.findall(r"```bash\n(.*?)```", text, re.S):
        pending = ""
        for line in block.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.endswith("\\"):
                pending += stripped[:-1].strip() + " "
                continue
            commands.append((pending + stripped).strip())
            pending = ""

    for policy, now in ((STEP3_POLICY, STEP3_NOW), (STEP4_POLICY, STEP4_NOW)):
        documented = [c for c in commands
                      if policy.name in c and "verify-policy" in c
                      and "--hook" not in c]
        assert len(documented) == 1, (policy.name, documented)
        assert documented[0].startswith(f"{freshness.NOW_ENV}={now} "), \
            documented[0]
