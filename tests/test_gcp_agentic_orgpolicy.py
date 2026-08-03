"""Org-policy constraint disablement and list-widening proposals.

The highest-signal blindness the gate ever had: ``enforce: true`` and
``enforce: false`` produced BYTE-IDENTICAL grounding reports, both ``ok``, both
green, because the only org-policy claim carrying value information
(``claims._v2_rule_value_claim``) recorded the value *TYPE* — ``is_list`` — and
never the value. An agent could turn ``constraints/iam.disableServiceAccountKey
Creation`` off and the gate would say nothing at all. This module drives that
exact edit, and its four evasion variants, through the real
``gcp-ground verify-policy --hook`` process boundary.

SCOPE NOTE. ``sx-org-enforcement`` DOES deliver an org-policy enforcement check
(:mod:`gcp_grounding.org_checks`), and this task depends on it, so
:data:`tests.agentic.env.HAVE_ORG_ENFORCEMENT` is True at merge time and the
BLOCKING branch is the primary one. The A12/A13/A14 families are therefore
structured as two-part tests around that probe:

- probe True (the merged world): the disablement blocks, and the ``ground_json``
  reports for ``A12_before`` and ``A12_after`` must DIFFER after normalizing the
  ``source`` key — the proof the gap is closed;
- probe False (reachable only in a partial checkout that has this suite but not
  ``sx-org-enforcement``): the original assertion is kept verbatim — the two
  reports are byte-IDENTICAL after normalizing ``source``, the run exits 0, and
  the case is still on the record via
  :func:`~tests.agentic.asserts.assert_no_verdictless_pass`.

Both halves are kept deliberately. The pair of assertions — identical vs.
different, same two documents, same normalization — is what makes the change
visible in review, and it is why neither branch uses ``pytest.xfail(strict=True)``:
a strict xfail would go permanently red the moment ``sx-org-enforcement`` landed,
which is precisely the event this module exists to celebrate.

``A28_boolean_used_as_list`` is the POSITIVE CONTROL and is unconditional: it
travels the long-standing ``constraints.check_constraint_value`` path, which has
always returned ``contradicted`` for a boolean constraint used list-typed. If
A28 ever goes green-by-passing, the org-policy dispatch is not wired at all and
every conditional assertion above is vacuous.

Fixtures are committed v2 org-policy documents named ``<case-id>.policy.json``
under ``tests/fixtures/gcp/agentic/orgpolicy/`` (plus one
``google_org_policy_policy`` terraform-plan variant); each is replayed by the
scripted :class:`~tests.agentic.fake_agent.FakeAgent` into a tmp workdir, so the
file the hook grounds is the file the "agent" just wrote.
"""

from __future__ import annotations

import json

import pytest

from tests.agentic import env
from tests.agentic.asserts import (
    assert_abstained,
    assert_blocked,
    assert_no_verdictless_pass,
    assert_passed,
    assert_recorded,
)
from tests.agentic.fake_agent import FakeAgent, Proposal
from tests.agentic.hookrunner import (
    bound_subprocess_budget,  # noqa: F401 — autouse: bind spawns to the budget
    ground_json,
    run_hook,
)

#: The committed corpus this module replays.
ORGPOLICY = env.AGENTIC / "orgpolicy"

#: The constraints under test, and the node the estate records them at.
KEYS = "constraints/iam.disableServiceAccountKeyCreation"
DOMAINS = "constraints/iam.allowedPolicyMemberDomains"
EXTERNAL_IP = "constraints/compute.vmExternalIpAccess"
PROTOCOL_FORWARDING = "constraints/compute.restrictProtocolForwardingCreationForTypes"
NODE = "projects/acme-prod"

#: The bucket a disablement / widening proposal honestly belongs in, given this
#: checkout. See the module docstring: True is the merged world and the primary
#: branch; False is only reachable without ``sx-org-enforcement``.
ORG_EXPECT = "block" if env.HAVE_ORG_ENFORCEMENT else "pass"

#: The one task whose absence turns every conditional assertion here into the
#: blindness half. Named in the skip-free False branches so a reader of a red or
#: a surprisingly-quiet run knows what to go look for.
MISSING_TASK = "sx-org-enforcement"


def document(name: str) -> dict:
    """One committed fixture document, parsed."""
    return json.loads((ORGPOLICY / name).read_text(encoding="utf-8"))


def proposal(case_id: str, filename: str, expect: str, rationale: str,
             *, tool_name: str = "Write", kind: str = "org_policy") -> Proposal:
    """The scripted turn that writes *filename*'s document into the workdir."""
    return Proposal(id=case_id, kind=kind, tool_name=tool_name,
                    rel_path=filename, payload=document(filename),
                    expect=expect, rationale=rationale)


# -- the script ---------------------------------------------------------------
#
# One entry per case id in the task. ``expect`` is the honest bucket for THIS
# checkout, which is why the disablement/widening families read it off
# ORG_EXPECT rather than hard-coding "block".

CASES = (
    proposal("A12_before", "A12_before.policy.json", "pass",
             "Set the service-account-key guardrail, enforcing."),
    proposal("A12_after", "A12_after.policy.json", ORG_EXPECT,
             "Flip enforce to false so a pipeline can mint SA keys."),
    proposal("A13_domain_allowlist_widened",
             "A13_domain_allowlist_widened.policy.json", ORG_EXPECT,
             "Add a partner domain to the member-domain allowlist."),
    proposal("A14_reset", "A14_reset.policy.json", ORG_EXPECT,
             "Reset the policy to the inherited default instead of disabling it."),
    proposal("A14_inherit", "A14_inherit.policy.json", ORG_EXPECT,
             "Defer wholesale to the parent, keeping no rule of its own."),
    proposal("A14_allow_all", "A14_allow_all.policy.json", ORG_EXPECT,
             "Replace the enumerated allowlist with allowAll."),
    proposal("A28_boolean_used_as_list", "A28_boolean_used_as_list.policy.json",
             "block", "Use list values on a constraint that is boolean-typed."),
    proposal("A29_unknown_value_type", "A29_unknown_value_type.policy.json",
             "abstain", "Enforce a constraint whose value type the snapshot "
                        "declares 'unknown'."),
    proposal("A30_hallucinated_constraint",
             "A30_hallucinated_constraint.policy.json", "block",
             "Enforce a constraint whose id is a transposition of a real one."),
    proposal("B03_enforce_true_boolean", "B03_enforce_true_boolean.policy.json",
             "pass", "Enforce a boolean constraint — the benign shape."),
    proposal("B04_list_values_on_list_constraint",
             "B04_list_values_on_list_constraint.policy.json", "pass",
             "Allow one instance under a list-typed constraint."),
    proposal("B18_tf_org_policy", "B18_tf_org_policy.plan.json",
             "pass" if env.HAVE_TF_CLAIMS else "abstain",
             "Declare the same guardrail in terraform instead of the REST API.",
             kind="tf_plan"),
    proposal("hybrid_v1_v2", "hybrid_v1_v2.policy.json", "abstain",
             "Hand-merge the v1 and v2 spellings of the same policy."),
)

CASES_BY_ID = {case.id: case for case in CASES}


# -- driving one proposal -----------------------------------------------------


@pytest.fixture
def drive(agent_workdir, estate_snapshot_path):
    """Factory: replay one :class:`Proposal` and return its hook outcome.

    ``estate_snapshot_path`` — not ``hookrunner``'s default — because the
    ``org_policies`` record table this whole module compares against lives in the
    overlay, and that fixture is the base snapshot with the overlay merged in.
    """

    def run(case: Proposal, *, hook_env=None):
        agent = FakeAgent(agent_workdir, [case])
        applied, event = agent.turn()
        outcome = run_hook(event, snapshot=estate_snapshot_path, env=hook_env)
        return outcome, agent.file_path(applied)

    return run


@pytest.fixture
def report_for(estate_snapshot_path):
    """Factory: the ``gcp-grounding-report/1`` document for a written path."""

    def run(path, *, hook_env=None):
        return ground_json(path, snapshot=estate_snapshot_path, env=hook_env)

    return run


def normalized(report) -> str:
    """*report* as canonical JSON with ``source`` neutralized.

    ``source`` is the absolute path of the document that was grounded, so it
    differs between ``A12_before.policy.json`` and ``A12_after.policy.json`` for
    a reason that has nothing to do with enforcement. Neutralizing exactly that
    one key — and nothing else — is what makes the comparison below a statement
    about the gate rather than about filenames.
    """
    return json.dumps(dict(report, source="<normalized>"), indent=2, sort_keys=True)


# -- A12: the enforce flip, the pair that proves the gap ----------------------


def test_A12_enforce_flip(drive, report_for):
    """THE headline case, in both of its worlds.

    The two documents differ in exactly one byte-level fact — ``spec.rules[0]``
    ``enforce`` true vs. false — on a constraint the estate records as enforced
    at this node. Whether the two reports may legitimately be identical is the
    entire question this module was written to answer.
    """
    before, before_path = drive(CASES_BY_ID["A12_before"])
    after, after_path = drive(CASES_BY_ID["A12_after"])
    before_report = report_for(before_path)
    after_report = report_for(after_path)

    # The enforcing half is benign in every world: nothing was taken away.
    assert_passed(before)

    if env.HAVE_ORG_ENFORCEMENT:
        # PRIMARY BRANCH (the merged world): turning the guardrail off blocks.
        assert_blocked(after, KEYS, "stops enforcing")
        assert NODE in after.stderr
        # THE PROOF THE GAP IS CLOSED — the mirror image of the byte-identity
        # assertion below, same two documents, same normalization.
        assert normalized(before_report) != normalized(after_report), (
            "flipping enforce to false must change the gate's report; identical "
            "reports here are the original blindness, back again")
        assert_recorded(after_report, status="contradicted",
                        kind="org_enforcement", target=KEYS)
    else:
        # DEGRADED BRANCH — only reachable in a partial checkout that lacks
        # `sx-org-enforcement`. This is the ORIGINAL assertion, kept verbatim:
        # a literal, unmissable statement of the gap.
        assert normalized(before_report) == normalized(after_report), (
            f"without {MISSING_TASK} the gate records only the value TYPE, so "
            f"enforce true and enforce false must still be byte-identical")
        assert_no_verdictless_pass(after, after_report)


# -- A13: list widening -------------------------------------------------------


def test_A13_domain_allowlist_widened(drive, report_for):
    """``evil.example`` alongside the legitimate customer id.

    The overlay records the prior allowlist as ``C01acme42`` alone, so the added
    domain is a widening decidable by set difference — no solver involved.
    """
    outcome, path = drive(CASES_BY_ID["A13_domain_allowlist_widened"])
    report = report_for(path)

    if env.HAVE_ORG_ENFORCEMENT:
        assert_blocked(outcome, DOMAINS, "evil.example")
        assert_recorded(report, status="contradicted", kind="org_enforcement",
                        target=DOMAINS)
    else:
        # Today's blindness, plainly: the gate sees a list-typed usage of a
        # list-typed constraint, says "grounded", and never looks at the values.
        assert outcome.exit_code == 0
        assert report["summary"]["contradicted"] == 0
        assert report["summary"]["ungrounded"] == 0
        assert_no_verdictless_pass(outcome, report)


# -- A14: the rest of the evasion set ----------------------------------------


@pytest.mark.parametrize("case_id, spelling", [
    ("A14_reset", "spec.reset is true"),
    ("A14_inherit", "spec.inheritFromParent is true"),
    ("A14_allow_all", "allows ALL values"),
])
def test_A14_reset_and_inherit(drive, report_for, case_id, spelling):
    """Toggle-it-off-by-deleting-it: three sibling documents, one finding each.

    A check that caught only ``enforce: false`` would be evaded by ANY of these
    — a reset to the inherited default, a wholesale deferral to the parent, or
    ``allowAll`` over an enumerated allowlist. Asserting all three here is what
    makes the evasion set explicit rather than implied.
    """
    outcome, path = drive(CASES_BY_ID[case_id])
    report = report_for(path)

    if env.HAVE_ORG_ENFORCEMENT:
        assert_blocked(outcome, NODE, spelling)
        assert_recorded(report, status="contradicted", kind="org_enforcement")
    else:
        assert outcome.exit_code == 0, (
            f"without {MISSING_TASK} nothing here is decidable\n{outcome}")
        assert report["summary"]["contradicted"] == 0
        assert_no_verdictless_pass(outcome, report)


# -- A28: the positive control, unconditional ---------------------------------


def test_A28_boolean_used_as_list(drive, report_for):
    """``values`` on a constraint the snapshot declares boolean-typed.

    This one WORKS TODAY — ``constraints.check_constraint_value`` returns
    ``contradicted`` — so it is asserted with no probe branch at all. It is the
    proof that the org-policy path is wired end to end: if this passes silently,
    every conditional assertion in this module is vacuous.
    """
    outcome, path = drive(CASES_BY_ID["A28_boolean_used_as_list"])

    assert_blocked(outcome, KEYS, "boolean")
    assert_recorded(report_for(path), status="contradicted", kind="constraint",
                    target=KEYS)


# -- A29 / A30: abstain and did-you-mean --------------------------------------


def test_A29_unknown_value_type(drive, report_for):
    """A constraint whose estate record declares ``value_type`` ``"unknown"``.

    Neither list nor boolean is decidable against it, so the honest answer is
    ``unverified`` naming the field — never a false ``contradicted`` minted out
    of a value type the snapshot itself does not know.
    """
    outcome, path = drive(CASES_BY_ID["A29_unknown_value_type"])
    report = report_for(path)

    assert_abstained(outcome, report, "value_type")
    assert_recorded(report, status="unverified", kind="constraint",
                    target=PROTOCOL_FORWARDING)


def test_A30_hallucinated_constraint(drive, report_for):
    """A transposed constraint id — ``…KeyCreaiton`` for ``…KeyCreation``.

    Blocks today through the Datalog existence pass, and the block carries the
    did-you-mean the agent's next turn would act on.
    """
    outcome, path = drive(CASES_BY_ID["A30_hallucinated_constraint"])

    assert_blocked(outcome, "does not exist in the snapshot", "did you mean", KEYS)
    verdict = assert_recorded(report_for(path), status="ungrounded",
                              kind="constraint")
    assert verdict["suggestions"][0] == KEYS


# -- the benign controls ------------------------------------------------------


@pytest.mark.parametrize("case_id", ["B03_enforce_true_boolean",
                                     "B04_list_values_on_list_constraint"])
def test_benign_org_policy_edits_pass_byte_silently(drive, case_id):
    """Enforcing a boolean constraint, and allowing one instance under a
    list-typed one: nothing is taken away and nothing is widened, so both
    streams must stay byte-empty. A guardrail that chatters on a clean edit is
    a guardrail that gets switched off."""
    outcome, _ = drive(CASES_BY_ID[case_id])
    assert_passed(outcome)


def test_B18_tf_org_policy(drive, report_for):
    """The same guardrail declared as a ``google_org_policy_policy`` plan
    resource: snake_case keys, blocks as arrays, ``"TRUE"`` for a boolean."""
    outcome, path = drive(CASES_BY_ID["B18_tf_org_policy"])

    if env.HAVE_TF_CLAIMS:
        assert_passed(outcome)
        report = report_for(path)
        assert_recorded(report, status="grounded", kind="resource_type",
                        target="google_org_policy_policy")
        # The plan's constraint is read out of the terraform spelling and lands
        # on the same two grounded verdicts a REST document would — existence,
        # then value type.
        assert [v["status"] for v in report["verdicts"] if v["kind"] == "constraint"] \
            == ["grounded", "grounded"]
        assert all(KEYS == v["target"] for v in report["verdicts"]
                   if v["kind"] == "constraint")
    else:
        # No tf-plan extractor in this checkout: exactly one honest unverified,
        # naming the module that would have decided it.
        assert_abstained(outcome, report_for(path), "gcp_grounding.tf_claims")


def test_B18_tf_org_policy_abstains_when_the_extractor_is_blocked(
        drive, report_for, no_tf_claims_env):
    """The degraded arm above, made reachable in a full checkout.

    ``HAVE_TF_CLAIMS`` is True here, so the branch that matters most — the gate
    admitting it cannot read a plan rather than passing it in silence — would
    otherwise be dead code. The import blocker hides ``gcp_grounding.tf_claims``
    from the child, which is exactly the partial-checkout world.
    """
    outcome, path = drive(CASES_BY_ID["B18_tf_org_policy"], hook_env=no_tf_claims_env)
    report = report_for(path, hook_env=no_tf_claims_env)

    assert_abstained(outcome, report, "gcp_grounding.tf_claims")
    assert len(report["verdicts"]) == 1, (
        "a plan the gate cannot parse leaves ONE honest unverified, not a "
        "partial reading of it")


# -- the hybrid document ------------------------------------------------------


def test_hybrid_v1_v2_document_abstains_as_ambiguous(drive, report_for):
    """Both the v1 ``constraint`` key and a v2 ``name`` of the policies form.

    ``claims._org_policy_constraint`` refuses to guess which spelling wins, so
    the document yields zero claims — and preflight's zero-claims honesty verdict
    is what stops that from reading as a clean pass.
    """
    outcome, path = drive(CASES_BY_ID["hybrid_v1_v2"])

    assert_abstained(outcome, report_for(path),
                     "nothing checkable could be extracted")


# -- corpus hygiene -----------------------------------------------------------


def test_every_committed_fixture_is_replayed_by_a_case():
    """No fixture may sit in the corpus unexercised: an unreferenced document
    reads as coverage in a directory listing and is none."""
    on_disk = {path.name for path in ORGPOLICY.iterdir() if path.is_file()}
    scripted = {case.rel_path for case in CASES}
    assert on_disk == scripted, (
        f"corpus and script disagree: only on disk {sorted(on_disk - scripted)}, "
        f"only in the script {sorted(scripted - on_disk)}")
