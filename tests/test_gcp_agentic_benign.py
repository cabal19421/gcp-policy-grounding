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

- **The script is driven turn by turn, with everything interleaved.** The
  session mutates files in place — turn 3 edits what turn 2 wrote, turn 12
  rewrites it again — so draining the script up front and grounding afterwards
  would read revision 12 while asserting about revision 2. Both hook runs, that
  turn's report and its blocking control all happen inside the loop, against the
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

Three repairs carry it, each stated where it is asserted: the spot-checks name
their claims BY TARGET instead of counting grounded ones; each paired turn gets a
control asserted to BLOCK, so a hook that opens nothing fails here; and the
byte-silence claim is made in BOTH worlds, the second being a solver that answers
``find_spec`` and then fails to load. In that world ten of these twelve turns
write :data:`~tests.agentic.hookrunner.NO_Z3_FALLBACK_BANNER` on EVERY
invocation, and THAT ONE LINE — nothing else, ever — is filtered by
:data:`~tests.agentic.hookrunner.STDERR_ALLOWLIST` before an assertion reads it,
because this harness provokes it. ``stderr_raw`` keeps it and
``ESC-HOOKRUNNER-NO-Z3-BANNER`` owns the product half, where an operator whose
solver really is broken does see it, once per tool call.

:data:`MODULE_SPAWN_CAP` spawns, MEASURED: twelve hook runs, twelve degraded
ones, three controls. The reports cost NOTHING — ``ground_policy`` through
``PolicyReport`` in this process, byte-equal to the CLI's ``--format json`` as
``tests/test_gcp_agentic_abstain.py`` pins — and retiring those five sidecar
spawns is what pays for the second world.

DIFF SIZE, MEASURED AND RECORDED rather than discovered clipped: the repin is
41,1xx characters of ``git diff`` against the 18,000 the design binds and the
20,000 ``gitutil.diff_text`` clips at. NO SPLIT ALONG THE FOUR FINDINGS' OWN
BOUNDARIES FITS — the claim-identity half alone measures ~22,000 with its
escalation and its five contract entries, and the other three findings together
are ~8,500 — and no successor task is declared to hand a remainder to. Nothing
was thinned to shrink it: the explicitly OPTIONAL pin (turn 10's widened-plan
recorded fact) is the one piece dropped for size, and the gap it would have
pinned is stated in the corpus README and beside the proposal instead.
"""

from __future__ import annotations

import io
import json
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from gcp_grounding import cli, preflight
from gcp_grounding.report import PolicyReport
from tests.agentic import env, hookrunner
from tests.agentic.asserts import (
    INCIDENTAL_KINDS,
    assert_abstained,
    assert_blocked,
    assert_passed,
    assert_recorded,
)
from tests.agentic.fake_agent import FakeAgent, Proposal
from tests.agentic.hookrunner import (
    HookOutcome,
    bound_subprocess_budget,  # noqa: F401 — autouse: bind spawns to the budget
    run_hook,
)

#: This module's share of the suite-wide ceiling, MEASURED and checked at module
#: teardown: one hook child per turn, one degraded-world child per turn, one
#: blocking control per paired turn. The reports are in process and free.
MODULE_SPAWN_CAP = 27

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
        # The row states the CHECKABLE property and only it. THE NARROWING ITSELF
        # IS NOT CHECKED TODAY — `fw_checks.PAIR_CHECKS` is keyed by the detected
        # kind, a plan detects as `tf_plan`, and the hook path passes no baseline
        # (ESC-GX-NETWORK-PAIR-BASELINE); MEASURED, widening the range back to
        # 0.0.0.0/0 on tcp/443 leaves this module green. Said plainly here in the
        # same register as turn 5's caveat, because both are places a reader could
        # over-read a green. What IS decided is exposure, and that bites: widened
        # to every protocol, or to tcp/22, the same plan is `contradicted`.
        id="B10_tfplan_firewall_narrow",
        kind="firewall",
        tool_name="Write",
        rel_path="pipeline/firewall.tfplan.json",
        payload=payload("tfplan_firewall_narrow.json"),
        expect="pass",
        rationale="Ingest stays on tcp/443, so no public source reaches a "
                  "sensitive port — which is the property the gate decides.",
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
#: also builds the machine report for them: an exit-0 hook run is silent by
#: design, and the report is the only place "checked and grounded" differs from
#: "never looked".
REPORTED_IDS = frozenset({
    "B02_iam_grant_data_eng",
    "B04_orgpolicy_shielded_vm",
    "B05_app_settings_abstain",
    "B06_tfplan_iam_member",
    "B07_tfplan_custom_role",
    "B10_tfplan_firewall_narrow",
    "B12_iam_shrink_with_baseline",
})

_SHIELDED_VM = "constraints/compute.requireShieldedVm"
_ETL_RUNNER = "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com"
_EXISTS = "exists in the snapshot"

#: Turn id → the claims that turn's report MUST carry, as ``(kind, target,
#: message fragment)``, each read through :func:`recorded`. A turn is proved
#: CHECKED by the claims it grounded and their targets, never by a count any one
#: survivor satisfies. The fragment separates B04's two ``constraint`` verdicts,
#: which share kind AND target — existence and value type — so both are required.
CLAIM_IDENTITY: dict[str, tuple[tuple[str, str, str], ...]] = {
    "B02_iam_grant_data_eng": (
        ("role", "roles/bigquery.dataViewer", _EXISTS),
        ("principal", "group:data-eng@acme.example", _EXISTS),
    ),
    "B04_orgpolicy_shielded_vm": (
        ("constraint", _SHIELDED_VM, f"constraint '{_SHIELDED_VM}' {_EXISTS}"),
        ("constraint", _SHIELDED_VM, "boolean-typed usage matches the declared "
                                     "value type"),
    ),
    "B06_tfplan_iam_member": (
        ("role", "roles/bigquery.jobUser", _EXISTS),
        ("principal", _ETL_RUNNER, _EXISTS),
    ),
    "B07_tfplan_custom_role": (
        ("permission", "bigquery.jobs.create", _EXISTS),
        ("permission", "storage.objects.get", _EXISTS),
    ),
    # The one property turn 10's corpus row claims, and the one the gate decides.
    "B10_tfplan_firewall_narrow": (
        ("firewall_exposure", "ingest-https",
         "no public source reaches a sensitive port"),
    ),
}

#: Turn id → (the text in the payload, what to swap it for, the name the block
#: must then carry on stderr). The control writes the turn's own bytes back with
#: that one swap, at the SAME relative path, and the hook over it must BLOCK —
#: the only thing that proves the hook opened that path at all. The third field
#: is separate because an org policy names its constraint through the resource
#: path. B07 and B10 are reported but not paired: they share B06's hook path
#: exactly — a ``.json`` suffix detected as ``tf_plan``, the same plan reader —
#: so a fourth control would buy no hook-path coverage the third does not.
UNGROUNDED_TWIN = {
    "B02_iam_grant_data_eng": ("roles/bigquery.dataViewer",
                               "roles/bigquery.reader", "roles/bigquery.reader"),
    "B04_orgpolicy_shielded_vm": ("policies/compute.requireShieldedVm",
                                  "policies/compute.requireShieldedVms",
                                  _SHIELDED_VM + "s"),
    "B06_tfplan_iam_member": ("roles/bigquery.jobUser",
                              "roles/bigquery.jobRunner", "roles/bigquery.jobRunner"),
}

#: Turn id → the file whose CURRENT bytes become that turn's ``--baseline``.
#: Captured before the turn is applied: turn 12 overwrites exactly the file it
#: is compared against, so a copy taken afterwards would compare a revision with
#: itself and prove nothing.
BASELINE_SOURCE = {"B12_iam_shrink_with_baseline": "pipeline/iam.policy.json"}


@dataclass(frozen=True)
class TurnResult:
    """One driven turn: what was proposed, what the gate did in each world, the
    machine report behind that silence, and — where the hook path is paired — the
    two control runs that prove the hook opened the file at all."""

    proposal: Proposal
    outcome: HookOutcome
    degraded: HookOutcome
    report: dict | None = None
    baseline: Path | None = None
    control: HookOutcome | None = None
    mirror: HookOutcome | None = None


def no_solver_env() -> dict[str, str]:
    """The degraded-world child overlay — ``_blockimports`` first on
    ``PYTHONPATH`` and ``z3`` named as the module to block, so ``find_spec``
    succeeds and the load then raises. Spelled here because ``conftest``'s
    ``no_z3_env`` is function-scoped and this drive loop is module-scoped."""
    paths = [str(env.BLOCKIMPORTS_DIR), os.environ.get("PYTHONPATH", "")]
    return {"PYTHONPATH": os.pathsep.join(p for p in paths if p),
            "GCP_TEST_BLOCK_IMPORTS": "z3"}


def report_of(path, snapshot, baseline=None) -> dict:
    """The ``gcp-grounding-report/1`` document for *path*, IN THIS PROCESS: the
    same ``ground_policy`` the child runs through the same ``PolicyReport`` the
    CLI's ``--format json`` renders, byte-equal to it as
    ``test_gcp_agentic_abstain.py`` pins with the one spawn it keeps for that. A
    CONTROL on what the turn's bytes claim — never evidence about the hook."""
    return PolicyReport(
        preflight.ground_policy(str(path), snapshot,
                                baseline=None if baseline is None else str(baseline)),
        captured_at=snapshot.captured_at, source=str(path)).to_dict()


def in_process_hook(event, snapshot) -> HookOutcome:
    """``cli.main(["verify-policy", "--hook", …])`` over *event*, HERE — no spawn,
    and the ONLY run a contract ``Removal`` reaches, since a removal
    monkeypatches this process and a child re-imports ``gcp_grounding`` clean.
    The child's determinism is reproduced exactly as ``hookrunner.child_env``
    does it: every :data:`~tests.agentic.hookrunner.SCRUBBED_ENV` name gone and
    ``GCP_SEC_LLM=0`` set."""
    argv = ["verify-policy", "--hook", "--snapshot", str(snapshot)]
    payload, out, err = json.dumps(event), io.StringIO(), io.StringIO()
    stdin = sys.stdin
    with mock.patch.dict(os.environ, {"GCP_SEC_LLM": "0"}):
        for name in hookrunner.SCRUBBED_ENV:
            os.environ.pop(name, None)
        sys.stdin = io.StringIO(payload)
        try:
            with redirect_stdout(out), redirect_stderr(err):
                exit_code = cli.main(argv)
        finally:
            sys.stdin = stdin
    return HookOutcome(exit_code=exit_code, stdout=out.getvalue(),
                       stderr=hookrunner.scrub_stderr(err.getvalue()),
                       argv=("<in process>", *argv), event=event,
                       stdin_bytes=payload.encode("utf-8"),
                       stderr_raw=err.getvalue())


def _control_runs(agent, proposal, event, snapshot):
    """THE PAIRING: the turn's OWN bytes at its OWN relative path with one name
    swapped, under the SAME event, through the child AND the mirror. Restored in a
    ``finally`` because the session mutates in place — a twin left behind would be
    the revision the next turn's ``old_string`` reads."""
    found, swap, _ = UNGROUNDED_TWIN[proposal.id]
    path = agent.workdir / proposal.rel_path
    original = path.read_bytes()
    twin = original.replace(found.encode("utf-8"), swap.encode("utf-8"))
    assert twin != original, (
        f"{proposal.id}: the control swapped nothing — {found!r} is not in the "
        f"payload, so the twin is the benign document and would not block")
    path.write_bytes(twin)
    try:
        return run_hook(event, snapshot=snapshot), in_process_hook(event, snapshot)
    finally:
        path.write_bytes(original)


@pytest.fixture(scope="module")
def benign_session(tmp_path_factory, estate_snapshot_path, estate_snapshot,
                   subprocess_budget):
    """Drive the whole script ONCE and return ``{id: TurnResult}``.

    Module-scoped so the hook runs happen once for the whole module rather than
    once per assertion. The budget is bound explicitly around the loop because a
    module-scoped fixture is set up before the function-scoped autouse binder —
    see the module docstring.
    """
    root = tmp_path_factory.mktemp("benign")
    baseline_dir = root / "baselines"
    baseline_dir.mkdir()
    agent = FakeAgent(root / "agent", BENIGN_SCRIPT)
    degraded_env = no_solver_env()

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
            degraded = run_hook(event, snapshot=estate_snapshot_path,
                                extra_argv=extra_argv, env=degraded_env)

            report = None
            control = mirror = None
            if proposal.id in REPORTED_IDS:
                report = report_of(agent.workdir / proposal.rel_path,
                                   estate_snapshot, baseline)
            if proposal.id in UNGROUNDED_TWIN:
                control, mirror = _control_runs(agent, proposal, event,
                                                estate_snapshot_path)
            results[proposal.id] = TurnResult(proposal, outcome, degraded,
                                              report, baseline, control, mirror)
    finally:
        hookrunner.bind_budget(previous)
    return results


@pytest.fixture(scope="module", autouse=True)
def _module_spawn_cap(subprocess_budget):
    """Pin this module's share of the shared ceiling at module teardown: the
    session ceiling cannot notice one module growing at the others' expense, and
    this accounting is what made the second world affordable."""
    before = subprocess_budget.total
    yield
    spent = subprocess_budget.total - before
    assert spent <= MODULE_SPAWN_CAP, (
        f"this module spawned {spent} children, over its cap of "
        f"{MODULE_SPAWN_CAP}; the oracle is the full test run and an unbounded "
        f"suite stops being run at all")


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
    """Every single turn, IN BOTH WORLDS: exit 0, byte-empty stdout and stderr.

    ``assert_passed`` is the right helper even for the turns that produce no
    verdicts at all (turn 9's legitimately empty allow policy grants nothing, so
    zero claims is the honest outcome and there is nothing to record). What is
    asserted is the operator-visible contract, identical for all twelve.

    The second leg is the one that was never measured: a solver that answers
    ``find_spec`` and then fails to load writes
    :data:`~tests.agentic.hookrunner.NO_Z3_FALLBACK_BANNER` on every invocation
    that builds one, which ten of these twelve turns do. That one line is
    filtered by :data:`~tests.agentic.hookrunner.STDERR_ALLOWLIST` and kept on
    ``stderr_raw``; a byte from outside the allowlist fails here exactly as it
    fails in the first leg. Per turn as well as in aggregate, because the two
    worlds take different branches — without z3 the subset comparison abstains
    and the arity answers come from the builtin backend — and a branch that turned
    noisy would otherwise hide behind eleven quiet ones.
    """
    result = turn(benign_session, turn_id)
    assert_passed(result.outcome)
    assert_passed(result.degraded)


# -- the spot-checks: passed, not merely never looked at ----------------------


def recorded(report: dict, kind: str, target: str, fragment: str) -> dict:
    """THE ONE grounded verdict of *kind* about *target* whose message carries
    *fragment*, through :func:`~tests.agentic.asserts.assert_recorded`'s
    exactly-one semantics. The narrowing is not a loosening: it names a claim
    where kind and target alone do not separate two verdicts about one
    constraint, and the exactly-one assertion is still the frozen helper's."""
    narrowed = dict(report, verdicts=[v for v in report["verdicts"]
                                      if fragment in v["message"]])
    assert narrowed["verdicts"], (
        f"no verdict's message carries {fragment!r}\n{json.dumps(report, indent=2)}")
    return assert_recorded(narrowed, status="grounded", kind=kind, target=target)


_NO_TF = pytest.mark.skipif(
    not env.HAVE_TF_CLAIMS,
    reason="gcp_grounding.tf_claims is absent — the plan is honestly unverified, "
           "so there is no grounded claim to spot-check")


@pytest.mark.parametrize("turn_id", [
    "B02_iam_grant_data_eng",
    "B04_orgpolicy_shielded_vm",
    pytest.param("B06_tfplan_iam_member", marks=_NO_TF),
    pytest.param("B07_tfplan_custom_role", marks=_NO_TF),
    pytest.param("B10_tfplan_firewall_narrow", marks=[_NO_TF, pytest.mark.skipif(
        not env.HAVE_FIREWALL_DOMAIN,
        reason="the VPC firewall checkers cannot decide exposure here, so the "
               "one property this turn's row claims is not evaluated")]),
])
def test_spot_checked_turns_ground_the_claims_by_identity(benign_session, turn_id):
    """The whole reason this check exists: silence has two causes.

    A turn that passed because the gate CHECKED it and everything grounded, and a
    turn that passed because the gate never recognized the document, are
    byte-identical at the hook boundary. Only the machine report separates them,
    and only BY IDENTITY: a grounded COUNT is met by whatever verdict survives,
    which for a plan is the ``resource_type_ref`` the walker emits before any
    extractor runs. So each turn names the claims it must have grounded and the
    target of each, and EVERY one is required — the plan turn's role AND its
    principal, the constraint turn's existence AND its value type — so no single
    survivor can carry the assertion alone.
    """
    result = turn(benign_session, turn_id)
    report = result.report
    assert report is not None, f"{turn_id} is in REPORTED_IDS but has no report"
    summary = report["summary"]
    assert report["ok"] is True, report
    assert summary["ungrounded"] == 0, report
    assert summary["contradicted"] == 0, report
    for kind, target, fragment in CLAIM_IDENTITY[turn_id]:
        verdict = recorded(report, kind, target, fragment)
        assert verdict["kind"] not in INCIDENTAL_KINDS, (
            f"{turn_id} names {kind!r} as a claim it grounds, but that kind is "
            f"incidental vocabulary every terraform document hits for free")


@pytest.mark.xfail(strict=True,
                   reason="ESC-GX-BENIGN-GROUNDED-FLOOR: a grounded COUNT "
                          "cannot tell CHECKED from NEVER LOOKED")
@_NO_TF
def test_the_clauses_grounded_floor_tells_checked_from_never_looked(benign_session):
    """THE CLAUSE, LANDED LITERALLY: ``at least one thing actually grounded``.

    Its bound is a count, and the count is met by the incidental resource-type
    reference alone. This drives it over the plan turn's report with every
    extractor's output deleted — the state ``RM-BENIGN-PLAN-MEMBER-EXTRACTION``
    really produces — and asserts its floor then reads NOT CHECKED. It does
    not. Strict, so the day the bound is strengthened, or the walker stops minting
    an unconditional reference, this XPASSes and the escalation is retired.
    """
    report = turn(benign_session, "B06_tfplan_iam_member").report
    stripped = [v for v in report["verdicts"] if v["kind"] in INCIDENTAL_KINDS]
    assert stripped, (
        "the plan turn produces no incidental verdict at all, so this clause "
        f"cannot be measured over it\n{json.dumps(report, indent=2)}")
    grounded = sum(1 for v in stripped if v["status"] == "grounded")
    assert grounded < 1, (
        f"the clause's floor (grounded >= 1) is satisfied by {grounded} verdict(s) "
        f"of purely incidental kind, so it certifies a turn nothing examined:\n"
        f"{json.dumps(stripped, indent=2)}")


@pytest.mark.parametrize("turn_id", [
    "B02_iam_grant_data_eng",
    "B04_orgpolicy_shielded_vm",
    pytest.param("B06_tfplan_iam_member", marks=_NO_TF),
])
def test_the_paired_hook_really_opened_that_path(benign_session, turn_id):
    """THE HOOK'S OWN LEG, and the only one it has.

    Every content assertion above reads a report built in this process; the hook
    is otherwise checked for an exit code and two empty streams, which is
    byte-identical whether it grounded everything or opened nothing — MEASURED,
    emptying ``cli._HOOK_SUFFIXES`` left this whole module green. The control
    closes it from the other side: the SAME event, the SAME relative path, the
    turn's OWN bytes with one name swapped for one the estate has never heard of,
    and the run must BLOCK naming it. A hook that opens nothing cannot block.

    Both legs, because they fail to different things. The CHILD is the real
    process boundary — argv, stdin, the environment — and the MIRROR is the same
    ``cli.main`` in this process, which is the only run a contract ``Removal``
    can reach at all.
    """
    result = turn(benign_session, turn_id)
    assert result.control is not None and result.mirror is not None, (
        f"{turn_id} is paired but ran no control")
    for outcome in (result.control, result.mirror):
        assert_blocked(outcome, UNGROUNDED_TWIN[turn_id][2],
                       "does not exist in the snapshot")
    assert_passed(result.outcome)


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
    cannot tell the two apart in hook mode unless the ``--abstain-notes`` channel
    is switched on, which a false-positive budget deliberately leaves off — the
    ignorance is on the record only in the machine report read here.
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
    all; ``== {0}`` asserts both that nothing blocked and that something ran. It
    covers BOTH worlds: a solver that cannot initialise must not turn an ordinary
    edit into a blocked one either.
    """
    codes = ({result.outcome.exit_code for result in benign_session.values()}
             | {result.degraded.exit_code for result in benign_session.values()})
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

    STATED FOR BOTH WORLDS, because one was never measured: with the solver
    importable this held, and under the no-solver overlay ten of the twelve turns
    wrote a warning line on every invocation. Exactly one line is filtered —
    :data:`~tests.agentic.hookrunner.NO_Z3_FALLBACK_BANNER`, provoked by this
    harness's own overlay and owned as a product defect by
    ``ESC-HOOKRUNNER-NO-Z3-BANNER``. The unconditional claim was the false one.
    """
    combined = "".join(benign_session[turn_id].outcome.stderr for turn_id in IDS)
    assert combined == "", (
        f"the benign session must be byte-silent on stderr across all "
        f"{len(IDS)} turns; the script, in order, was:\n  "
        + "\n  ".join(IDS)
        + f"\n\nnoisy turns:\n{_render(benign_session, noisy_only=True)}")
    degraded = "".join(benign_session[turn_id].degraded.stderr for turn_id in IDS)
    assert degraded == "", (
        f"the same {len(IDS)} turns must be byte-silent with the solver present "
        f"AND with it installed-but-broken; only "
        f"{len(hookrunner.STDERR_ALLOWLIST)} allowlisted harness line(s) are "
        f"filtered\n\nnoisy turns:\n"
        + _render(benign_session, noisy_only=True, degraded=True))


def _render(session, *, noisy_only: bool = False, degraded: bool = False) -> str:
    """The session as an assertion message: one block per turn (or only the
    turns that said something), in script order, from the named world."""
    blocks = []
    for turn_id in IDS:
        result = session[turn_id]
        outcome = result.degraded if degraded else result.outcome
        if noisy_only and not outcome.stderr:
            continue
        blocks.append(f"--- {turn_id} ({result.proposal.tool_name} "
                      f"{result.proposal.rel_path})\n{outcome}")
    return "\n".join(blocks) or "(no turns)"
