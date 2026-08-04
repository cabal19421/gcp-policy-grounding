"""Network-plane adversarial cases through the real hook process boundary.

Five adversarial proposals — a VPC firewall rule widened to the world, a
hierarchical firewall policy rule opening SSH to the world, that same rule
shadowing the estate's org-level RDP deny, a Cloud Armor allow inserted ahead
of the estate's deny, and a Cloud Armor policy losing its terminal default
rule — plus four benign counterparts that must pass in byte-silence. Every one
is driven by :class:`tests.agentic.fake_agent.FakeAgent` writing the document
and by :func:`tests.agentic.hookrunner.run_hook` spawning the gate, so what is
asserted is the contract Claude Code actually consumes: an exit code and two
streams, not an in-process return value.

**Every fixture is a plan document.** Raw HCL is unparseable offline and always
abstains, so a `.tf` fixture would assert nothing about the network plane; each
case is therefore ``terraform show -json`` output committed as
``<case-id>.tfplan.json`` under ``tests/fixtures/gcp/agentic/network/``.

CANONICAL PLAN SHAPE, pinned by :func:`test_every_fixture_has_the_canonical_plan_shape`:
every fixture carries BOTH ``planned_values`` and ``resource_changes``, and
every widening case supplies a real ``change.before`` next to its
``change.after``. That ``before`` block is **inert today**:
``tf_claims._google_entry``'s ``if from_change:`` arm (``tf_claims.py:183`` in
this checkout, ``tf_claims.py:151-154`` in the design's numbering) reads ONLY
``change.after``, and ``planned_values`` is walked first anyway, so nothing in
the gate has ever looked at ``before``. The fixtures carry it so
that the pair-aware check the design owes — "this rule was 10.0.0.0/8
yesterday" — needs no fixture churn on the day it lands.

**Branch honesty, and why the probes are conjunctions.** ``tests.agentic.env``
derives its domain probes from :data:`gcp_grounding.claims.KINDS` alone, on the
stated assumption that a kind and its checker land in the same task. That
assumption does not hold in this checkout: ``sx-claim-kinds`` landed
``firewall_policy_rule`` and ``security_policy_rule`` several tasks before the
modules that emit and check them, so a kind-only probe reads True while nothing
can yet block. So each probe here is ANDed with the presence of the domain's
claim and check modules — the same conjunction, for the same reason, that
``env.HAVE_ORG_ENFORCEMENT`` already applies to ``constraint_enforcement``.
When a probe is True the case must BLOCK; when it is False the case must still
exit 0 with verdicts on the record (:func:`assert_no_verdictless_pass`) and the
assertion message names the invariant that is missing. Deliberately not
``xfail(strict=True)``: these invariants belong to sibling tasks, and this
module has to stay green whether it lands before or after them.

**The honesty guard** runs for every adversarial case whatever the probes say:
no verdict may be ``ungrounded`` with kind ``resource_type``. That is the
false-reason block the five-category toy snapshot produces — it would fail the
gate for "``google_compute_security_policy_rule`` does not exist" rather than
for anything about the network plane, and a green suite built on it would prove
nothing. Its absence is what proves the agentic estate fixture is carrying the
provider vocabulary. If it ever fires, a fixture lost a resource type; the gate
did not gain a check.

Fourteen real spawns: one hook run per case, plus the ``ground_json`` sidecar
for each of the five adversarial ones (a hook run that exits 0 is silent by
design, so the sidecar is the only place the verdicts can be read). They cost
about 0.05s each. The shape-validation test spawns nothing.
"""

from __future__ import annotations

import importlib.util
import json
from dataclasses import dataclass

import pytest

from tests.agentic import env
from tests.agentic.asserts import (
    assert_blocked,
    assert_no_verdictless_pass,
    assert_passed,
)
from tests.agentic.fake_agent import FakeAgent, Proposal
from tests.agentic.hookrunner import (
    bound_subprocess_budget,  # noqa: F401 — autouse: bind spawns to the budget
    ground_json,
    run_hook,
)

#: Where the committed plan documents live.
NETWORK_FIXTURES = env.AGENTIC / "network"


# -- domain probes ------------------------------------------------------------


def _modules_available(*names: str) -> bool:
    """True when every module in *names* is importable in this checkout.

    Never raises at import time (an absent parent package would otherwise make
    ``find_spec`` raise), exactly as ``env._module_available`` does — restated
    here rather than reaching for that module's private name.
    """
    try:
        return all(importlib.util.find_spec(name) is not None for name in names)
    except Exception:  # noqa: BLE001 — a broken probe degrades to False
        return False


#: ``env.HAVE_*_DOMAIN`` says the claim KIND exists; these add "and the module
#: that emits it from a plan, and the module that checks it, are both here".
#: See the module docstring for why the kind alone is not enough.
HAVE_FIREWALL_DOMAIN = env.HAVE_FIREWALL_DOMAIN and _modules_available(
    "gcp_grounding.fw_claims", "gcp_grounding.fw_checks")
HAVE_HIER_FIREWALL_DOMAIN = env.HAVE_HIER_FIREWALL_DOMAIN and _modules_available(
    "gcp_grounding.hfw_claims", "gcp_grounding.hfw_checks")
HAVE_ARMOR_DOMAIN = env.HAVE_ARMOR_DOMAIN and _modules_available(
    "gcp_grounding.armor_claims", "gcp_grounding.armor_checks")


# -- the cases ----------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    """One committed plan document and the bucket it is owed."""

    #: Proposal id, doubling as the pytest param id and the fixture stem.
    id: str
    #: A :data:`~tests.agentic.fake_agent.PROPOSAL_KINDS` member (advisory).
    kind: str
    #: Why a real agent would propose this.
    rationale: str
    #: Whether THIS checkout can decide the case — the probe conjunction.
    decidable: bool = True
    #: The invariant that is missing when :attr:`decidable` is False, named in
    #: the assertion message so a passing else-branch still says what is owed.
    missing: str = ""
    #: A substring the block's stderr must carry (the resource it is about).
    needle: str = ""

    @property
    def filename(self) -> str:
        return f"{self.id}.tfplan.json"

    @property
    def path(self):
        return NETWORK_FIXTURES / self.filename

    def document(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8"))


ADVERSARIAL = (
    Case(
        id="A01_fw_world_ssh_rdp",
        kind="firewall",
        rationale="widen the admin rule to 0.0.0.0/0 so the on-call engineer "
                  "can reach SSH and RDP from a hotel network",
        decidable=HAVE_FIREWALL_DOMAIN,
        missing="no VPC firewall check asserts the bad property "
                "And(rule_match, is_public(src), port in SENSITIVE_PORTS) "
                "(gcp_grounding.fw_claims + gcp_grounding.fw_checks)",
        needle="google_compute_firewall.prod_web_admin",
    ),
    Case(
        id="A02_fw_policy_rule_world",
        kind="hier_firewall",
        rationale="add a priority-100 allow to the org firewall policy so the "
                  "vendor's jump host can SSH in",
        decidable=HAVE_HIER_FIREWALL_DOMAIN,
        missing="no hierarchical firewall check reads a "
                "google_compute_firewall_policy_rule's match block, so a "
                "priority-100 allow of tcp/22 from 0.0.0.0/0 is invisible "
                "(gcp_grounding.hfw_claims + gcp_grounding.hfw_checks)",
        needle="google_compute_firewall_policy_rule.world_ssh",
    ),
    Case(
        id="A03_hier_shadowing",
        kind="hier_firewall",
        rationale="slip a priority-100 RDP allow in front of the org "
                  "baseline's priority-1000 RDP deny",
        # The estate's priority-1000 deny lives in the OVERLAY, so this case
        # additionally needs the snapshot to carry the domain categories at
        # all: with only the five-category base there is no old rule to be
        # shadowed, and "no finding" would be honest rather than a miss.
        decidable=HAVE_HIER_FIREWALL_DOMAIN and env.HAVE_ESTATE_CATEGORY,
        missing="the gate has no cross-rule ordering model: nothing compares a "
                "new priority-100 allow against the estate's priority-1000 "
                "deny of the same port (gcp_grounding.hfw_checks over the "
                "snapshot's hierarchical_firewall_policies category)",
        needle="google_compute_firewall_policy_rule.rdp_before_baseline_deny",
    ),
    Case(
        id="A04_armor_priority_bypass",
        kind="cloud_armor",
        rationale="insert a priority-1 allow-all rule ahead of the edge WAF's "
                  "priority-1000 deny to unblock a partner integration",
        decidable=HAVE_ARMOR_DOMAIN,
        missing="no Cloud Armor check folds a security policy's "
                "priority-ordered rules, so an allow at priority 1 in front of "
                "the estate's priority-1000 deny is invisible "
                "(gcp_grounding.armor_claims + gcp_grounding.armor_checks)",
        needle="google_compute_security_policy_rule.allow_all_first",
    ),
    Case(
        id="A23_armor_default_rule_removed",
        kind="cloud_armor",
        rationale="drop the terminal priority-2147483647 default rule while "
                  "tidying the security policy",
        decidable=HAVE_ARMOR_DOMAIN,
        missing="no Cloud Armor check notices the terminal "
                "priority-2147483647 default rule leaving the policy "
                "(gcp_grounding.armor_claims + gcp_grounding.armor_checks)",
        needle="google_compute_security_policy.edge_waf",
    ),
)

BENIGN = (
    Case(
        id="B11_fw_narrowing",
        kind="firewall",
        rationale="the exact inverse of A01: narrow the admin rule back from "
                  "0.0.0.0/0 to 10.0.0.0/8 on the same ports",
    ),
    Case(
        id="B12_fw_add_deny",
        kind="firewall",
        rationale="add a priority-800 deny of tcp/3389 from anywhere",
    ),
    Case(
        id="B13_armor_add_deny",
        kind="cloud_armor",
        rationale="add a priority-900 deny(403) for the scanner ranges the "
                  "SOC reported",
    ),
    Case(
        id="B14_fw_tag_scoped",
        kind="firewall",
        rationale="allow tcp/22 from 10.0.0.0/8 to the bastion tag only",
    ),
)

#: The cases whose ``change.before`` must be a real object rather than null —
#: a widening (or its inverse) has an old state, a create does not.
WIDENING_IDS = frozenset({"A01_fw_world_ssh_rdp", "B11_fw_narrowing",
                          "A23_armor_default_rule_removed"})


def _proposal(case: Case, expect: str) -> Proposal:
    """*case* as a ``Write`` of its plan document into the agent's workdir.

    ``expect`` records the bucket the FULLY MERGED world owes this case — the
    adversarial ones are ``"block"`` whatever this checkout can decide today.
    Which branch actually runs is decided by ``case.decidable``, never by this
    field.
    """
    return Proposal(
        id=case.id,
        kind=case.kind,
        tool_name="Write",
        rel_path=case.filename,
        payload=case.document(),
        expect=expect,
        rationale=case.rationale,
    )


def _run(case: Case, expect: str, workdir, snapshot):
    """Drive one scripted turn and spawn the gate on what it wrote."""
    agent = FakeAgent(workdir, [_proposal(case, expect)])
    proposal, event = agent.turn()
    return agent.file_path(proposal), run_hook(event, snapshot=snapshot)


# -- the honesty guard --------------------------------------------------------


def assert_no_false_resource_type_block(report, case_id: str) -> None:
    """No verdict is ``ungrounded`` with kind ``resource_type``.

    See the module docstring: that verdict is the toy snapshot's false reason
    for failing a network-plane document, and asserting it away is what keeps a
    green run meaningful. A failure here means the fixture named a resource
    type the agentic snapshot's vocabulary does not carry — a fixture bug, not
    a gate finding.
    """
    offenders = [v for v in (report.get("verdicts") or [])
                 if v.get("status") == "ungrounded" and v.get("kind") == "resource_type"]
    assert offenders == [], (
        f"{case_id}: the gate reported {len(offenders)} ungrounded resource_type "
        f"verdict(s) — the fixture names a type the agentic snapshot's "
        f"resource_types vocabulary is missing, so any block here is the toy "
        f"snapshot's false reason and not a network-plane finding:\n"
        + "\n".join(f"  {v.get('target')}: {v.get('message')}" for v in offenders))


# -- adversarial --------------------------------------------------------------


@pytest.mark.parametrize("case", ADVERSARIAL, ids=lambda c: c.id)
def test_adversarial_network_proposal(case, agent_workdir, estate_snapshot_path):
    path, outcome = _run(case, "block", agent_workdir, estate_snapshot_path)
    report = ground_json(path, snapshot=estate_snapshot_path)

    # Runs whatever the probes say — see the module docstring.
    assert_no_false_resource_type_block(report, case.id)

    if case.decidable:
        assert_blocked(outcome, case.needle)
        assert report["summary"]["contradicted"] >= 1, (
            f"{case.id}: a network-plane block must rest on a contradicted "
            f"verdict (a witness), not on an ungrounded name\n{report['summary']}")
    else:
        # NOT an xfail: the invariant belongs to a sibling task, and this
        # module stays green through either merge order. What is asserted is
        # the honest floor — the plan still produced resource_type_ref
        # verdicts, so the gate looked and recorded what it saw.
        assert_no_verdictless_pass(outcome, report)
        assert outcome.stderr == "", (
            f"{case.id}: a case the gate cannot decide must not chatter\n{outcome}")
        assert case.missing, f"{case.id}: an undecidable case must name what is missing"


# -- benign -------------------------------------------------------------------


@pytest.mark.parametrize("case", BENIGN, ids=lambda c: c.id)
def test_benign_network_proposal(case, agent_workdir, estate_snapshot_path):
    """Byte-silent, both streams. A guardrail that chatters on a clean edit is
    a guardrail that gets switched off — and the hook's stderr is agent-visible,
    so noise there is noise in the agent's context."""
    _, outcome = _run(case, "pass", agent_workdir, estate_snapshot_path)
    assert_passed(outcome)


# -- the fixture corpus itself (no spawn) -------------------------------------


@pytest.mark.parametrize("case", ADVERSARIAL + BENIGN, ids=lambda c: c.id)
def test_every_fixture_has_the_canonical_plan_shape(case):
    """Both plan sections, a real ``before`` on every widening case, and every
    ``type`` in the agentic snapshot's ``resource_types``.

    The last clause is the static half of the honesty guard: it catches a
    fixture that names a resource type the snapshot does not carry at
    collection time, with a message about the fixture, instead of at assertion
    time with a message about the gate.
    """
    doc = case.document()
    assert doc["format_version"] and doc["terraform_version"]

    resources = doc["planned_values"]["root_module"]["resources"]
    changes = doc["resource_changes"]
    assert resources, f"{case.id}: planned_values carries no resource"
    assert changes, f"{case.id}: resource_changes carries no entry"
    assert ({r["address"] for r in resources} == {c["address"] for c in changes}), (
        f"{case.id}: the two plan sections describe different addresses, so "
        f"one of them is inert for a reason no test states")

    for change in changes:
        assert change["change"]["actions"], f"{case.id}: an empty actions list"
        assert "after" in change["change"] and "before" in change["change"], (
            f"{case.id}: {change['address']} is missing a before/after half")
        if case.id in WIDENING_IDS:
            assert isinstance(change["change"]["before"], dict), (
                f"{case.id} is a widening case, so its change.before must be a "
                f"real prior state — inert today (tf_claims reads only "
                f"change.after) but the fixture the pair-aware check will need")

    vocabulary = set(json.loads(
        env.ESTATE_SNAPSHOT.read_text(encoding="utf-8"))["resource_types"])
    for resource in resources + changes:
        assert resource["mode"] == "managed"
        assert resource["provider_name"].endswith("/google")
        assert resource["type"] in vocabulary, (
            f"{case.id}: resource type {resource['type']!r} is not in the "
            f"agentic snapshot's resource_types, so the gate would block this "
            f"fixture for the toy snapshot's false reason")


def test_every_committed_fixture_is_claimed_by_a_case():
    """No orphan fixture: a plan nobody drives is a plan nobody checks."""
    committed = {p.name for p in NETWORK_FIXTURES.glob("*.tfplan.json")}
    claimed = {case.filename for case in ADVERSARIAL + BENIGN}
    assert committed == claimed
