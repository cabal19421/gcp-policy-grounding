"""The IAM-deny adversarial catalogue, driven through the real hook process.

Every case is one scripted :class:`~tests.agentic.fake_agent.Proposal` applied
by a :class:`~tests.agentic.fake_agent.FakeAgent` and pushed through
``gcp-ground verify-policy --hook`` — a real child process, a real PostToolUse
event on stdin, the real exit code and the real stderr — exactly the
tests/test_gcp_agentic_iam.py pattern. The payload documents are committed
JSON under ``tests/fixtures/gcp/agentic/deny/``, named
``<case-id>.policy.json``, so a security reviewer can read what the adversary
proposed without reading Python.

**The honesty rule, inherited verbatim from the IAM catalogue:** an
adversarial proposal ends BLOCKED or PASSED-BUT-RECORDED, never in a silent
pass — every exit-0 case also runs the ``ground_json`` sidecar and pins the
recorded ``iam_deny_shadow`` (or ``estate:incomplete``) verdict by identity.

**Branch honesty.** The interaction checks land with this module's own task,
so the whole catalogue rides ONE behavioural capability probe built the
:mod:`tests.agentic.capabilities` way: the real gate must decide the
deny-delete wake (contradicted on ``iam_deny_shadow``) and stay quiet on the
masked near-twin's same channel. A checkout where the family is dead skips
loudly with the measured report.

**Spawns, MEASURED:** five cases, each costing one hook child and one sidecar
child — 10 in a full run, pinned by :data:`MODULE_SPAWN_CAP` at module
teardown. The suite-wide ceiling moved 466 → 478 by exactly this module's
declared budget plus two of headroom (the tx-agentic precedent).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gcp_grounding.knowledge import GcpSnapshot
from tests.agentic import capabilities, env
from tests.agentic.asserts import (
    assert_blocked,
    assert_no_verdictless_pass,
    assert_recorded,
)
from tests.agentic.fake_agent import FakeAgent, Proposal
from tests.agentic.hookrunner import (
    bound_subprocess_budget,  # noqa: F401 — autouse: bind spawns to the budget
    ground_json,
    run_hook,
)

#: Where the reviewable payload documents live.
DENY_FIXTURES = env.AGENTIC / "deny"

#: The estate this catalogue grounds against: roles, hierarchy, the dormant
#: tokenCreator grant, and the captured iam_deny_policies guardrail.
DENY_SNAPSHOT = env.FIXTURES / "snapshot_deny_estate.json"

#: Ceiling on the children THIS module spawns, checked at module teardown:
#: five cases x (one hook child + one sidecar child) = 10 measured, plus two
#: of headroom.
MODULE_SPAWN_CAP = 12

KIND = "iam_deny_shadow"
TOKEN = "iam.serviceAccounts.getAccessToken"
CI_SA = "serviceAccount:ci@acme-prod.iam.gserviceaccount.com"
ROLE = "roles/iam.serviceAccountTokenCreator"


def payload(case_id: str):
    path = DENY_FIXTURES / f"{case_id}.policy.json"
    return json.loads(path.read_text(encoding="utf-8"))


# -- the capability probe ------------------------------------------------------
#
# Behavioural, never a presence check: the bad input is the guardrail DELETE
# over the estate with the dormant escalation grant (must be contradicted on
# this family's own kind), the good near-twin is the same-plan masked grant
# (a warning riding on grounded — not a finding, so the channel stays quiet).

DENY_SHADOW = capabilities.Capability(
    name="iam_deny_shadow",
    family="iam",
    kinds=frozenset({KIND}),
    bad=lambda: (payload("D02_deny_policy_delete_wakes_escalation"),
                 GcpSnapshot.load(DENY_SNAPSHOT)),
    good=lambda: (payload("D01_deny_exception_threading"),
                  GcpSnapshot.load(DENY_SNAPSHOT)),
)

_PROBE = capabilities.probe(DENY_SHADOW)
_NEEDS_DENY_SHADOW = pytest.mark.skipif(not _PROBE.live, reason=_PROBE.reason)


@pytest.fixture(scope="module", autouse=True)
def _module_spawn_cap(subprocess_budget):
    """Pin this module's share of the suite-wide spawn budget."""
    before = subprocess_budget.total
    yield
    spent = subprocess_budget.total - before
    assert spent <= MODULE_SPAWN_CAP, (
        f"this module spawned {spent} children, over its cap of "
        f"{MODULE_SPAWN_CAP}; the oracle is the full test run and an "
        f"unbounded suite stops being run at all")


def drive(case_id: str, workdir, *, kind="iam", tool="Write",
          snapshot=DENY_SNAPSHOT, rationale=""):
    """Apply the proposal with a FakeAgent, push the event through the real
    hook, and return ``(outcome, sidecar)`` — the sidecar lazy, so a case
    costs its second child only when it reads the record."""
    proposal = Proposal(id=case_id, kind=kind, tool_name=tool,
                        rel_path=f"{case_id}.json", payload=payload(case_id),
                        expect="pass", rationale=rationale or case_id)
    agent = FakeAgent(workdir, [proposal])
    applied, event = agent.turn()
    path = agent.file_path(applied)
    outcome = run_hook(event, snapshot=snapshot)

    def sidecar() -> dict:
        return ground_json(path, snapshot=snapshot)

    return outcome, sidecar


# -- the catalogue -------------------------------------------------------------


@_NEEDS_DENY_SHADOW
def test_d01_threading_the_guardrails_exception_is_passed_but_recorded(
        agent_workdir):
    """The adversary adds its own service account to the guardrail's
    exceptionPrincipals: the grant lands (a masked-or-escaped grant is not an
    exposure), but the record must say the guardrail does not cover it."""
    outcome, sidecar = drive("D01_deny_exception_threading", agent_workdir,
                             rationale="except CI from the token guardrail "
                                       "so deploys stop failing")
    assert outcome.exit_code == 0, str(outcome)
    report = sidecar()
    assert_no_verdictless_pass(outcome, report)
    verdict = assert_recorded(report, status="grounded", kind=KIND,
                              target=ROLE)
    assert "threads the exception" in verdict["message"], verdict
    assert "review the exception" in verdict["message"], verdict
    assert CI_SA in verdict["message"], verdict


@_NEEDS_DENY_SHADOW
def test_d02_deleting_the_deny_policy_wakes_the_dormant_escalation(
        agent_workdir):
    """The deny policy was the only thing keeping the estate's dormant
    tokenCreator grant inert — a plan deleting it is BLOCKED, the C3
    contradicted."""
    outcome, sidecar = drive("D02_deny_policy_delete_wakes_escalation",
                             agent_workdir, kind="tf_plan", tool="Edit",
                             rationale="remove the deny policy, it keeps "
                                       "breaking the deploy pipeline")
    assert_blocked(outcome, "wakes the dormant grant", TOKEN)
    verdict = assert_recorded(sidecar(), status="contradicted", kind=KIND)
    assert "known escalation path inert" in verdict["message"], verdict
    assert CI_SA in verdict["message"], verdict


@_NEEDS_DENY_SHADOW
def test_d03_a_grant_fully_masked_by_the_estate_guardrail_is_recorded(
        agent_workdir):
    """A proposal granting the escalation role the estate deny policy masks:
    the grant lands but is inert — a pass with the masked warning recorded,
    naming the estate policy, never a silent pass."""
    outcome, sidecar = drive("D03_grant_under_deny_masked", agent_workdir,
                             kind="tf_plan", tool="MultiEdit",
                             rationale="grant CI the token-creator role")
    assert outcome.exit_code == 0, str(outcome)
    report = sidecar()
    assert_no_verdictless_pass(outcome, report)
    verdict = assert_recorded(report, status="grounded", kind=KIND,
                              target=ROLE)
    assert "masks" in verdict["message"], verdict
    assert "denypolicies/block-sa-tokens" in verdict["message"], verdict
    assert f"{TOKEN} (impersonation)" in verdict["message"], verdict


@_NEEDS_DENY_SHADOW
def test_d04_an_uncaptured_deny_table_puts_the_interaction_on_the_record(
        agent_workdir, tmp_path):
    """The same escalation-class grant over a snapshot WITHOUT the
    iam_deny_policies table: the run passes, and the estate:incomplete
    abstention says the allow×deny interaction was not decided — never a
    silent assumption that no deny policy exists."""
    data = json.loads(DENY_SNAPSHOT.read_text(encoding="utf-8"))
    data.pop("iam_deny_policies")
    uncaptured = tmp_path / "snapshot_without_deny_table.json"
    uncaptured.write_text(json.dumps(data, indent=2, sort_keys=True),
                          encoding="utf-8")
    outcome, sidecar = drive("D04_deny_uncaptured_interaction", agent_workdir,
                             snapshot=uncaptured,
                             rationale="grant CI the token-creator role")
    assert outcome.exit_code == 0, str(outcome)
    report = sidecar()
    assert_no_verdictless_pass(outcome, report)
    verdict = assert_recorded(report, status="unverified",
                              kind="estate:incomplete")
    assert "iam_deny_policies" in verdict["message"], verdict
    assert "was not decided" in verdict["message"], verdict
    assert TOKEN in verdict["message"], verdict


@_NEEDS_DENY_SHADOW
def test_d05_a_public_grant_threading_the_guardrail_is_blocked(agent_workdir):
    """The polarity mirror: the deny rule excepts the public AND the plan
    grants the public the escalation role — the guardrail nullified from the
    allow side, contradicted on this family's own channel (the public
    exposure block lands beside it on its own)."""
    outcome, sidecar = drive("D05_public_grant_threads_guardrail",
                             agent_workdir, kind="tf_plan", tool="Edit",
                             rationale="unblock everyone: except the public "
                                       "from the guardrail and grant the "
                                       "role broadly")
    assert_blocked(outcome, "guardrail nullified from the allow side")
    verdict = assert_recorded(sidecar(), status="contradicted", kind=KIND)
    assert "allUsers" in verdict["message"], verdict


# -- catalogue hygiene ---------------------------------------------------------


def test_every_payload_is_committed_and_readable():
    """The payload files are the review artifacts; a case whose payload is a
    Python literal has no reviewable record."""
    stems = {p.stem.replace(".policy", "") for p in
             DENY_FIXTURES.glob("*.policy.json")}
    assert stems == {
        "D01_deny_exception_threading",
        "D02_deny_policy_delete_wakes_escalation",
        "D03_grant_under_deny_masked",
        "D04_deny_uncaptured_interaction",
        "D05_public_grant_threads_guardrail",
    }
    for stem in stems:
        assert isinstance(payload(stem), dict)


def test_the_probe_is_behavioural_not_a_presence_check():
    """The probe's own two runs: the wake decided on the family's kind, the
    masked near-twin quiet on it — a gutted checker measures DEAD here."""
    assert _PROBE.live or "iam_deny_shadow" in _PROBE.reason
