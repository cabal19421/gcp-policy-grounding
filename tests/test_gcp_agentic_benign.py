"""The false-positive budget: one long benign session, byte-empty stderr.

Every other family in the agentic suite asks "does the gate catch this?". This
one asks the question that decides whether the gate survives contact with its
operator: **does it ever cry wolf?** A guardrail that chatters on ordinary
platform-engineering work gets switched off, and once it is off its true-positive
rate is zero. So the false-positive rate is a first-class assertion here, not an
afterthought — and it is asserted at the exact channel the operator and the agent
both see, which is the hook's stderr.

The subject is one realistic session: an SRE onboarding a new data pipeline over
twelve proposals, in the order a human would actually make them. It mixes
``Write`` / ``Edit`` / ``MultiEdit``; it mixes policy documents with plain files
in the same session (a README, an application ``main.py``); it revises the same
IAM policy three times; and it ends with a shrinking policy compared against the
revision it replaces. Nothing in it is adversarial and nothing in it is a
near-miss. The gate is asserted to be **completely silent** across all of it.

Three things about the driving deserve their own note, because each one is a way
this module could pass while testing nothing:

- **The script is driven turn by turn, with the sidecars interleaved.** The
  session mutates files in place — turn 3 edits what turn 2 wrote, turn 12
  rewrites it again — so draining the script up front and grounding afterwards
  would read revision 12 while asserting about revision 2. The hook run and that
  turn's ``ground_json`` sidecar are both spawned inside the loop, against the
  bytes that turn actually left on disk.
- **This module binds the subprocess budget itself.** pytest sets a
  module-scoped fixture up before the function-scoped autouse
  ``bound_subprocess_budget``, so without the explicit
  :func:`~tests.agentic.hookrunner.bind_budget` around the drive loop every one
  of these spawns would land on ``hookrunner``'s private fallback counter and
  vanish from the suite-wide ceiling.
- **The aggregate assertion is last on purpose.** The per-turn checks name the
  turn that broke; the aggregate is the regression-critical one, and it carries
  the full id list so a single newly-noisy case names itself in the failure
  message instead of the reader having to diff two runs.

Seventeen spawns: twelve hook runs plus five sidecars (the grounded spot-checks
on turns 2/4/6, the abstain sidecar on turn 5, and turn 12's ``--baseline``
comparison). Each is load-bearing for an assertion stated below.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests.agentic import env, hookrunner
from tests.agentic.asserts import assert_abstained, assert_passed, assert_recorded
from tests.agentic.fake_agent import FakeAgent, Proposal
from tests.agentic.hookrunner import (
    HookOutcome,
    bound_subprocess_budget,  # noqa: F401 — autouse: bind spawns to the budget
    ground_json,
    run_hook,
)

#: Where a reviewer reads what "normal" looks like. Each payload is a committed
#: document, not a Python literal: the question this module answers ("is the gate
#: right to stay quiet about this?") is a question about the documents.
BENIGN_DIR = env.AGENTIC / "benign"


def payload(name: str) -> Any:
    """A committed benign payload: parsed for ``.json``, raw text otherwise."""
    path = BENIGN_DIR / name
    text = path.read_text(encoding="utf-8")
    return json.loads(text) if path.suffix == ".json" else text


# -- the session --------------------------------------------------------------
#
# One SRE, one afternoon, one new data pipeline. Ordinary work in an ordinary
# order — the only property asserted about it is that the gate says nothing.

BENIGN_SCRIPT: tuple[Proposal, ...] = (
    Proposal(
        id="B01_readme_control",
        kind="control",
        tool_name="Edit",
        rel_path="README.md",
        payload=payload("readme_pipeline.md"),
        expect="pass",
        rationale="Document the new events-etl pipeline before wiring it up.",
    ),
    Proposal(
        id="B02_iam_grant_data_eng",
        kind="iam",
        tool_name="Write",
        rel_path="pipeline/iam.policy.json",
        payload=payload("iam_policy_initial.json"),
        expect="pass",
        rationale="Give the data-eng group read access to the curated dataset.",
    ),
    Proposal(
        id="B03_iam_add_job_user",
        kind="iam",
        tool_name="Edit",
        rel_path="pipeline/iam.policy.json",
        payload=payload("iam_policy_with_job_user.json"),
        expect="pass",
        rationale="The ETL service account also needs to run BigQuery jobs.",
    ),
    Proposal(
        id="B04_orgpolicy_shielded_vm",
        kind="org_policy",
        tool_name="Write",
        rel_path="pipeline/orgpolicy.policy.json",
        payload=payload("orgpolicy_shielded_vm.json"),
        expect="pass",
        rationale="Require Shielded VM on the pipeline's project, as the "
                  "platform baseline asks.",
    ),
    Proposal(
        # A .json file the hook DOES open and the gate cannot classify: the one
        # honest abstain of the session.
        id="B05_app_settings_abstain",
        kind="control",
        tool_name="MultiEdit",
        rel_path="app/settings.json",
        payload=payload("app_settings.json"),
        expect="abstain",
        rationale="Tune the pipeline's batch size and retry policy.",
    ),
    Proposal(
        id="B06_tfplan_iam_member",
        kind="tf_plan",
        tool_name="Write",
        rel_path="infra/plan.tfplan.json",
        payload=payload("tfplan_iam_member.json"),
        expect="pass",
        rationale="Land the same job-user grant through terraform, as the "
                  "estate is managed as code.",
    ),
    Proposal(
        id="B07_tfplan_custom_role",
        kind="tf_plan",
        tool_name="Write",
        rel_path="infra/custom_role.tfplan.json",
        payload=payload("tfplan_custom_role.json"),
        expect="pass",
        rationale="Replace the broad predefined roles with a least-privilege "
                  "custom role.",
    ),
    Proposal(
        id="B08_iam_conditional_window",
        kind="iam",
        tool_name="Write",
        rel_path="pipeline/analytics.iam.policy.json",
        payload=payload("iam_policy_conditional.json"),
        expect="pass",
        rationale="Time-box the backfill's write access to the agreed window.",
    ),
    Proposal(
        id="B09_iam_empty_allow_policy",
        kind="iam",
        tool_name="Write",
        rel_path="pipeline/staging.iam.policy.json",
        payload=payload("iam_policy_empty.json"),
        expect="pass",
        rationale="Create the staging project's policy file with no grants yet.",
    ),
    Proposal(
        id="B10_tfplan_firewall_narrow",
        kind="firewall",
        tool_name="Write",
        rel_path="pipeline/firewall.tfplan.json",
        payload=payload("tfplan_firewall_narrow.json"),
        expect="pass",
        rationale="Narrow the ingest rule's source range from 0.0.0.0/0 to the "
                  "internal 10.0.0.0/8.",
    ),
    Proposal(
        id="B11_main_py_control",
        kind="control",
        tool_name="Edit",
        rel_path="app/main.py",
        payload=payload("main_py.txt"),
        expect="pass",
        rationale="Read the batch size from settings instead of hardcoding it.",
    ),
    Proposal(
        id="B12_iam_shrink_with_baseline",
        kind="iam",
        tool_name="Write",
        rel_path="pipeline/iam.policy.json",
        payload=payload("iam_policy_shrunk.json"),
        expect="pass",
        rationale="The custom role supersedes the ad-hoc jobUser grant, so "
                  "drop it — strictly fewer grants than the revision it replaces.",
    ),
)

#: Every proposal's id, in script order. The parametrised ids and the aggregate
#: failure message both come from here.
IDS: tuple[str, ...] = tuple(p.id for p in BENIGN_SCRIPT)

#: Turns whose bucket cannot be read off the hook run alone, so the drive loop
#: also runs the ``--format json`` sidecar for them. An exit-0 hook run is silent
#: by design; the sidecar is the only way to tell "checked and grounded" from
#: "never looked".
SIDECAR_IDS = frozenset({
    "B02_iam_grant_data_eng",
    "B04_orgpolicy_shielded_vm",
    "B05_app_settings_abstain",
    "B06_tfplan_iam_member",
    "B12_iam_shrink_with_baseline",
})

#: Turn id → the file whose CURRENT bytes become that turn's ``--baseline``.
#: Captured before the turn is applied: turn 12 overwrites exactly the file it
#: is compared against, so a copy taken afterwards would compare a revision with
#: itself and prove nothing.
BASELINE_SOURCE = {"B12_iam_shrink_with_baseline": "pipeline/iam.policy.json"}


@dataclass(frozen=True)
class TurnResult:
    """One driven turn: what was proposed, what the gate did, and — for the
    spot-checked turns — the machine report behind that silence."""

    proposal: Proposal
    outcome: HookOutcome
    report: dict | None = None
    baseline: Path | None = None


@pytest.fixture(scope="module")
def benign_session(tmp_path_factory, estate_snapshot_path, subprocess_budget):
    """Drive the whole script ONCE and return ``{id: TurnResult}``.

    Module-scoped so twelve hook runs happen once for the whole module rather
    than once per assertion. The budget is bound explicitly around the loop
    because a module-scoped fixture is set up before the function-scoped autouse
    binder — see the module docstring.
    """
    root = tmp_path_factory.mktemp("benign")
    baseline_dir = root / "baselines"
    baseline_dir.mkdir()
    agent = FakeAgent(root / "agent", BENIGN_SCRIPT)

    results: dict[str, TurnResult] = {}
    previous = hookrunner.bind_budget(subprocess_budget)
    try:
        while agent.remaining():
            proposal = agent.script[agent.turns_taken]
            baseline = _capture_baseline(agent, proposal, baseline_dir)
            extra_argv = () if baseline is None else ("--baseline", str(baseline))

            # apply-then-envelope: PostToolUse means the write already landed.
            _, event = agent.turn()
            outcome = run_hook(event, snapshot=estate_snapshot_path,
                               extra_argv=extra_argv)

            report = None
            if proposal.id in SIDECAR_IDS:
                report = ground_json(agent.workdir / proposal.rel_path,
                                     snapshot=estate_snapshot_path,
                                     baseline=baseline)
            results[proposal.id] = TurnResult(proposal, outcome, report, baseline)
    finally:
        hookrunner.bind_budget(previous)
    return results


def _capture_baseline(agent: FakeAgent, proposal: Proposal,
                      baseline_dir: Path) -> Path | None:
    """The pre-write copy of the file *proposal* is about to replace, or None
    when this turn runs no ``--baseline`` comparison."""
    source = BASELINE_SOURCE.get(proposal.id)
    if source is None:
        return None
    path = baseline_dir / f"{proposal.id}.baseline.json"
    path.write_bytes((agent.workdir / source).read_bytes())
    return path


def turn(session, turn_id: str) -> TurnResult:
    return session[turn_id]


# -- per turn -----------------------------------------------------------------


@pytest.mark.parametrize("turn_id", IDS)
def test_benign_turn_is_byte_silent(benign_session, turn_id):
    """Every single turn: exit 0, byte-empty stdout, byte-empty stderr.

    ``assert_passed`` is the right helper even for the turns that produce no
    verdicts at all (turn 9's legitimately empty allow policy grants nothing, so
    zero claims is the honest outcome and there is nothing to record). What is
    asserted here is the operator-visible contract, and it is identical for all
    twelve: nothing on either stream.
    """
    result = turn(benign_session, turn_id)
    assert_passed(result.outcome)


# -- the spot-checks: passed, not merely never looked at ----------------------


@pytest.mark.parametrize("turn_id", [
    "B02_iam_grant_data_eng",
    "B04_orgpolicy_shielded_vm",
    pytest.param(
        "B06_tfplan_iam_member",
        marks=pytest.mark.skipif(
            not env.HAVE_TF_CLAIMS,
            reason="gcp_grounding.tf_claims is absent — the plan is honestly "
                   "unverified, so there is no grounded claim to spot-check"),
    ),
])
def test_spot_checked_turns_grounded_rather_than_skipped(benign_session, turn_id):
    """The whole reason this check exists: silence has two causes.

    A turn that passed because the gate CHECKED it and everything grounded, and
    a turn that passed because the gate never recognized the document, are
    byte-identical at the hook boundary — both are exit 0 with two empty
    streams. Only the machine report distinguishes them, so for one IAM policy,
    one org policy and one terraform plan the sidecar is read and pinned: ok,
    nothing ungrounded, nothing contradicted, and at least one thing actually
    grounded.
    """
    result = turn(benign_session, turn_id)
    report = result.report
    assert report is not None, f"{turn_id} is in SIDECAR_IDS but has no report"
    summary = report["summary"]
    assert report["ok"] is True, report
    assert summary["ungrounded"] == 0, report
    assert summary["contradicted"] == 0, report
    assert summary["grounded"] >= 1, (
        f"{turn_id} passed with zero grounded verdicts — that is 'the gate never "
        f"looked', not 'the gate checked and was happy'\n{json.dumps(report, indent=2)}")


def test_plain_json_config_abstains_silently(benign_session):
    """Turn 5 is the deliberate exception, and it is the honest one.

    ``app/settings.json`` is an application config that happens to end in
    ``.json``: the hook opens it, ``detect_kind`` recognizes no policy kind, and
    the gate records an ``unverified`` naming that reason. Exit 0 with two empty
    streams — ignorance never fails the gate — which means that at the hook
    boundary this turn is INDISTINGUISHABLE from turn 2, where every claim
    actually grounded.

    That is a deliberate product decision, not an oversight: the alternative is
    a line of stderr on every ordinary ``.json`` an agent touches, which is the
    chatter this whole module exists to forbid. But it does mean the operator
    cannot tell the two apart in hook mode without an ``--abstain-notes``
    channel, which the CLI does not have today — the ignorance is on the record
    only in the ``--format json`` report the sidecar reads here.
    """
    result = turn(benign_session, "B05_app_settings_abstain")
    assert_passed(result.outcome)
    assert result.report is not None
    assert_abstained(result.outcome, result.report,
                     "document kind was not recognized")


def test_shrinking_policy_is_compared_against_its_predecessor(benign_session):
    """Turn 12: a real ``--baseline`` run, over the revision it replaces.

    With z3 the new⊆old comparison is decided and the shrink is ``grounded``;
    without z3 it must be ``unverified`` naming the missing solver. The no-z3
    branch is the load-bearing one — a gate that reported ``grounded`` for a
    comparison it never ran would be telling the operator a proof exists when
    none does, and no amount of silence elsewhere would make up for it.
    """
    result = turn(benign_session, "B12_iam_shrink_with_baseline")
    assert result.baseline is not None and result.baseline.exists()
    baseline_doc = json.loads(result.baseline.read_text(encoding="utf-8"))
    assert len(baseline_doc["bindings"]) == 2, (
        "the captured baseline must be revision 3 (two bindings); a copy taken "
        "after the write would compare revision 12 with itself")

    report = result.report
    assert report is not None
    verdict = assert_recorded(report, kind="subset", target="iam-policy")
    if env.HAVE_Z3:
        assert verdict["status"] == "grounded", verdict
        assert "new⊆old holds" in verdict["message"], verdict
    else:
        assert verdict["status"] == "unverified", verdict
        assert "z3 is not available" in verdict["message"], verdict
    assert report["summary"]["contradicted"] == 0, report


# -- aggregate ----------------------------------------------------------------


def test_every_exit_code_is_exactly_zero(benign_session):
    """Set equality, not ``all(code == 0)`` or ``max(codes) <= 0``.

    A bound would still pass if the session had somehow produced no outcomes at
    all; ``== {0}`` asserts both that nothing blocked and that something ran.
    """
    codes = {result.outcome.exit_code for result in benign_session.values()}
    assert codes == {0}, (
        f"expected the benign session's exit codes to be exactly {{0}}, got "
        f"{sorted(codes)}\n" + _render(benign_session))


def test_the_whole_benign_session_emits_no_stderr_at_all(benign_session):
    """THE false-positive budget, and the last test in this module.

    Every per-turn assertion above can be satisfied one turn at a time; this one
    is the property the operator actually experiences — across an entire session
    of ordinary work, the gate wrote zero bytes to the channel they and the agent
    both read. It is deliberately the whole concatenation rather than a loop, so
    a regression that makes one case newly noisy fails HERE, with the full id
    list in the message, naming itself.

    Kept last so that a run which breaks several things reports the specific
    turn first and this summary second — the specific failure is the one worth
    reading.
    """
    combined = "".join(benign_session[turn_id].outcome.stderr for turn_id in IDS)
    assert combined == "", (
        f"the benign session must be byte-silent on stderr across all "
        f"{len(IDS)} turns; the script, in order, was:\n  "
        + "\n  ".join(IDS)
        + f"\n\nnoisy turns:\n{_render(benign_session, noisy_only=True)}")


def _render(session, *, noisy_only: bool = False) -> str:
    """The session as an assertion message: one block per turn (or only the
    turns that said something), in script order."""
    blocks = []
    for turn_id in IDS:
        result = session[turn_id]
        if noisy_only and not result.outcome.stderr:
            continue
        blocks.append(f"--- {turn_id} ({result.proposal.tool_name} "
                      f"{result.proposal.rel_path})\n{result.outcome}")
    return "\n".join(blocks) or "(no turns)"
