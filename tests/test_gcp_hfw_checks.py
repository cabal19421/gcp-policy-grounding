"""Hierarchical-firewall cross-level checks.

Pins the three findings of :mod:`gcp_grounding.hfw_checks` and — above all —
their POLARITY, because inverting one silently inverts a security verdict:

* FINDING A (``hfw_shadow``) is family (c), COVERAGE: **UNSAT** of
  ``And(match(r), Not(preempt))`` is the finding. The pin is asserted in BOTH
  directions — the folder allow of tcp/3389 under the org deny MUST be
  ``contradicted hfw_shadow``, and a folder allow of tcp/8080 from 10.0.0.0/8,
  which no ancestor policy touches, MUST yield an EMPTY list of ``hfw_shadow``
  verdicts. An implementation that swapped UNSAT and sat passes neither leg.
* FINDING B (``hfw_reopen``) is family (a): **sat** is the finding, with a
  witness packet.
* FINDING C (``hfw_widen`` / ``hfw_effect``) is family (b): unsat both ways is
  the ``grounded`` no-effect note, sat is the widening.

``goto_next`` gets its own proof at the encoding level: a high-precedence
``goto_next`` at a folder must let the VPC-layer decision stand even though a
lower-precedence deny at the same folder would otherwise have denied it.

Environment-honest: every assertion that needs a solver is skipped without z3,
because the check abstains on the builtin backend *before* it looks at anything
else — which is itself asserted, together with ``report.ok`` staying True.
"""

import json
from pathlib import Path

import pytest

from gcp_grounding import hfw_checks, packet, registry
from gcp_grounding.core.report import GroundingReport
from gcp_grounding.core.solver import BuiltinSolver, get_solver
from gcp_grounding.hfw_checks import (
    DOCUMENT_CHECKS, _as_vpc_shape, check_hierarchical_order, effective_decision)
from gcp_grounding.hfw_claims import firewall_policy_claims
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.preflight import ground_policy
from gcp_grounding.registry import CheckContext
from gcp_grounding.tf_claims import terraform_plan_claims

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"

HAVE_Z3 = get_solver().backend == "z3"
needs_z3 = pytest.mark.skipif(not HAVE_Z3, reason="requires the z3 backend")

POLICY = "organizations/1/locations/global/firewallPolicies/pol-hfw"
BASELINE = "organizations/1/locations/global/firewallPolicies/fp-baseline"


@pytest.fixture(autouse=True)
def _fresh_registry():
    # terraform_plan_claims resolves the hfw TF extractors through the lazy
    # provider registry; reset so discovery never depends on test ordering.
    registry.reset_cache()
    yield
    registry.reset_cache()


@pytest.fixture
def snap():
    return GcpSnapshot.load(FIXTURES / "estate_snapshot.json")


@pytest.fixture
def partial():
    return GcpSnapshot.load(FIXTURES / "estate_partial_snapshot.json")


# -- proposal builders --------------------------------------------------------


def tf_plan(*resources: dict) -> dict:
    return {"format_version": "1.2", "terraform_version": "1.9.5",
            "resource_changes": [
                {"address": r["address"], "mode": "managed", "type": r["type"],
                 "name": r["address"].rsplit(".", 1)[-1],
                 "provider_name": "registry.terraform.io/hashicorp/google",
                 "change": {"actions": ["create"], "before": None, "after": r["after"]}}
                for r in resources]}


def rule_resource(**overrides) -> dict:
    """The ``hfw_tf_plan.json`` rule — an INGRESS allow of tcp/3389 from
    0.0.0.0/0 at priority 200 — with fields overridden per test."""
    after = {
        "firewall_policy": POLICY,
        "priority": 200, "action": "allow", "direction": "INGRESS", "disabled": False,
        "match": [{"src_ip_ranges": ["0.0.0.0/0"], "dest_ip_ranges": [],
                   "layer4_config": [{"ip_protocol": "tcp", "ports": ["3389"]}]}],
        "target_resources": [], "target_service_accounts": [], "target_secure_tags": [],
    }
    after.update(overrides)
    return {"address": "google_compute_firewall_policy_rule.proposed",
            "type": "google_compute_firewall_policy_rule", "after": after}


def association(node: str, policy: str = POLICY) -> dict:
    return {"address": "google_compute_firewall_policy_association.attach",
            "type": "google_compute_firewall_policy_association",
            "after": {"firewall_policy": policy, "attachment_target": node,
                      "name": "attach"}}


def context(doc, snapshot, solver=None) -> CheckContext:
    claims = terraform_plan_claims(doc)
    return CheckContext(snapshot=snapshot, solver=solver or get_solver(),
                        document=doc, document_kind="tf_plan",
                        source="<proposal>", claims=tuple(claims))


def run(doc, snapshot, solver=None):
    return check_hierarchical_order(context(doc, snapshot, solver))


def of_kind(verdicts, kind):
    return [v for v in verdicts if v.kind == kind]


# -- the registry seam --------------------------------------------------------


def test_registered_as_a_document_check():
    assert DOCUMENT_CHECKS == (check_hierarchical_order,)
    assert check_hierarchical_order in registry.document_checks()


def test_a_document_with_no_hierarchical_rule_gets_no_verdicts(snap):
    # The registry runs this on EVERY document; it must stay silent unless the
    # proposal actually carries a hierarchical firewall rule.
    doc = {"bindings": [{"role": "roles/bigquery.jobUser",
                         "members": ["user:alice@acme.example"]}]}
    ctx = CheckContext(snapshot=snap, solver=get_solver(), document=doc,
                       document_kind="iam_policy", source="<iam>", claims=())
    assert check_hierarchical_order(ctx) == []


# -- FINDING A, leg 1: the shadowed folder allow ------------------------------


@needs_z3
def test_committed_fixture_folder_allow_of_3389_is_shadowed_by_the_org_deny(snap):
    # organizations/1's fp-baseline denies tcp/3389 from 0.0.0.0/0 at priority
    # 100; the folder-level allow at priority 200 can never run. UNSAT is the
    # finding here, and there is deliberately no witness packet to show.
    report = ground_policy(POLICIES / "hfw_tf_plan.json", snap)
    shadow = of_kind(report.verdicts, "hfw_shadow")
    assert len(shadow) == 1
    assert shadow[0].status == "contradicted"
    assert shadow[0].target == POLICY
    assert "organizations/1" in shadow[0].message
    assert "unreachable" in shadow[0].message
    assert shadow[0].suggestions == ()


@needs_z3
def test_shadowed_rule_is_also_reported_as_having_no_effect(snap):
    # The two findings tell one consistent story: the rule is unreachable, so
    # the effective decision is identical with and without it.
    verdicts = run(tf_plan(rule_resource(), association("folders/2")), snap)
    effect = of_kind(verdicts, "hfw_effect")
    assert [v.status for v in effect] == ["grounded"]
    assert "no effect on the effective decision at projects/acme-prod" in effect[0].message
    assert of_kind(verdicts, "hfw_widen") == []


# -- FINDING A, leg 2: the polarity pin ---------------------------------------


@needs_z3
def test_polarity_pin_a_rule_no_ancestor_touches_yields_zero_shadow_verdicts(snap):
    # tcp/8080 from 10.0.0.0/8 is touched by no ancestor policy, so
    # And(match(r), Not(preempt)) is SAT — the healthy case, asserted as an
    # EMPTY list. Together with the leg above this pins the polarity in both
    # directions: swapping UNSAT and sat fails one leg or the other.
    doc = tf_plan(rule_resource(match=[{
        "src_ip_ranges": ["10.0.0.0/8"], "dest_ip_ranges": [],
        "layer4_config": [{"ip_protocol": "tcp", "ports": ["8080"]}]}]),
        association("folders/2"))
    assert of_kind(run(doc, snap), "hfw_shadow") == []


# -- FINDING C: the effective-decision delta ----------------------------------


@needs_z3
def test_folder_allow_of_8080_from_rfc1918_has_no_effect(snap):
    # The VPC layer's allow-internal already allows every tcp port from
    # 10.0.0.0/8, so this rule changes nothing anywhere: unsat both ways.
    doc = tf_plan(rule_resource(match=[{
        "src_ip_ranges": ["10.0.0.0/8"], "dest_ip_ranges": [],
        "layer4_config": [{"ip_protocol": "tcp", "ports": ["8080"]}]}]),
        association("folders/2"))
    verdicts = run(doc, snap)
    effect = of_kind(verdicts, "hfw_effect")
    assert [v.status for v in effect] == ["grounded"]
    assert "no effect on the effective decision at projects/acme-prod" in effect[0].message
    assert of_kind(verdicts, "hfw_widen") == []


@needs_z3
def test_org_level_allow_widens_the_effective_decision(snap):
    # Moved to the org level at priority 50 the rule DOES change the outcome,
    # so family (b) reads the other way: sat, contradicted, with a witness.
    doc = tf_plan(rule_resource(priority=50), association("organizations/1"))
    widen = of_kind(run(doc, snap), "hfw_widen")
    assert [v.status for v in widen] == ["contradicted"]
    assert "port=3389" in widen[0].message
    assert "projects/acme-prod" in widen[0].message


# -- FINDING B: cross-level (and same-level) re-opening -----------------------


@needs_z3
def test_org_level_allow_at_priority_50_reopens_the_org_deny(snap):
    doc = tf_plan(rule_resource(priority=50), association("organizations/1"))
    reopen = of_kind(run(doc, snap), "hfw_reopen")
    assert [v.status for v in reopen] == ["contradicted"]
    message = reopen[0].message
    assert BASELINE in message                       # the deny it re-opens
    assert "organizations/1" in message              # both nodes
    assert "priority 50" in message and "priority 100" in message
    assert "witness packet" in message and "port=3389" in message


@needs_z3
def test_the_shadowed_folder_allow_does_not_reopen_anything(snap):
    # r loses to the org deny rather than winning over it, so family (a) must
    # stay silent — this is the finding that would fire if the level ordering
    # were read inside-out.
    verdicts = run(tf_plan(rule_resource(), association("folders/2")), snap)
    assert of_kind(verdicts, "hfw_reopen") == []


# -- goto_next: the value of the level INSIDE this one ------------------------


@needs_z3
def test_goto_next_lets_the_inner_decision_stand(snap):
    """A ``goto_next`` at priority 50 covering 10.0.0.0/8 delegates to the level
    inside it: the effective decision for a 10.x packet equals the VPC-layer
    decision, even though a lower-precedence deny at the same folder would
    otherwise have denied it."""
    z3 = get_solver()._z3
    v = packet.packet_vars(z3, tags=sorted(snap.network_tags),
                           service_accounts=sorted(snap.service_accounts))
    vpc_rules = [snap.firewall_rules[name] for name in sorted(snap.firewall_rules)]
    org_rules = list(snap.hierarchical_firewall_policies[BASELINE]["rules"])

    def hrule(priority, action):
        return {"priority": priority, "action": action, "direction": "INGRESS",
                "disabled": False,
                "match": {"src_ip_ranges": ["10.0.0.0/8"], "dest_ip_ranges": [],
                          "layer4": []},
                "target_resources": [], "target_service_accounts": [],
                "target_secure_tags": []}

    deny = hrule(100, "deny")
    goto = hrule(50, "goto_next")

    vpc_only = packet.effective_allow(z3, v, vpc_rules, "INGRESS", default_allow=False)
    with_goto = effective_decision(
        z3, v, [("organizations/1", org_rules), ("folders/2", [goto, deny])],
        vpc_rules, "INGRESS")
    without_goto = effective_decision(
        z3, v, [("organizations/1", org_rules), ("folders/2", [deny])],
        vpc_rules, "INGRESS")

    # A concrete 10.x packet the org level does not decide (it only denies 3389).
    concrete = [v.src == z3.BitVecVal(0x0A010203, 32),   # 10.1.2.3
                v.dst == z3.BitVecVal(0x0A000005, 32),   # 10.0.0.5
                v.proto == z3.BitVecVal(6, 8), v.port == z3.BitVecVal(8080, 16)]

    def unsat(*claims):
        s = z3.Solver()
        s.add(concrete + list(claims))
        return s.check() == z3.unsat

    # The VPC layer allows it (allow-internal), and goto_next hands the decision
    # straight back to that layer.
    assert unsat(z3.Not(vpc_only))
    assert unsat(with_goto != vpc_only)
    assert unsat(with_goto != z3.BoolVal(True))
    # Without the goto_next the same folder's deny takes it — proving the
    # goto_next arm is what restored the inner decision, not a no-op fold.
    assert unsat(z3.Not(z3.Not(without_goto)))


# -- abstention: never guess a level ------------------------------------------


@needs_z3
def test_partial_snapshot_abstains_for_every_proposed_rule(partial):
    # estate_partial_snapshot captures no resource_hierarchy, no hierarchical
    # firewall policies and no firewall rules: there is no honest level to read.
    verdicts = run(tf_plan(rule_resource(), association("folders/2")), partial)
    assert verdicts
    assert {v.status for v in verdicts} == {"unverified"}
    assert {v.kind for v in verdicts} == {"hfw_order"}
    assert "resource_hierarchy" in verdicts[0].message


def test_partial_snapshot_end_to_end_never_contradicts(partial):
    report = ground_policy(POLICIES / "hfw_tf_plan.json", partial)
    assert report.contradicted == []
    assert of_kind(report.verdicts, "hfw_order")
    assert {v.status for v in of_kind(report.verdicts, "hfw_order")} == {"unverified"}


def test_builtin_backend_abstains_and_the_report_stays_ok(snap):
    verdicts = run(tf_plan(rule_resource(), association("folders/2")), snap,
                   solver=BuiltinSolver())
    assert verdicts
    assert {v.status for v in verdicts} == {"unverified"}
    assert all("z3 is not available" in v.message for v in verdicts)
    report = GroundingReport()
    report.backend = "builtin"
    for v in verdicts:
        report.add(v)
    assert report.ok is True


@needs_z3
def test_a_policy_with_no_resolvable_attachment_node_abstains(snap):
    # No association resource, and pol-hfw is not in the estate — so nothing
    # says where this policy takes effect. Never guess a level.
    verdicts = run(tf_plan(rule_resource()), snap)
    assert [v.status for v in verdicts] == ["unverified"]
    assert "no resolvable attachment node" in verdicts[0].message


@needs_z3
def test_an_attachment_node_outside_the_hierarchy_abstains(snap):
    verdicts = run(tf_plan(rule_resource(), association("folders/999")), snap)
    assert [v.status for v in verdicts] == ["unverified"]
    assert "folders/999" in verdicts[0].message
    assert "absent from the captured resource hierarchy" in verdicts[0].message


@needs_z3
def test_an_unencodable_proposed_rule_abstains_the_whole_comparison(snap):
    # An INGRESS rule with no source ranges is carried by hfw_claims with an
    # `unsupported` payload key, never dropped; the comparison must abstain
    # rather than silently compare a hierarchy with a hole in it.
    doc = tf_plan(rule_resource(match=[{
        "src_ip_ranges": [], "dest_ip_ranges": ["10.0.0.0/8"],
        "layer4_config": [{"ip_protocol": "tcp", "ports": ["3389"]}]}]),
        association("folders/2"))
    verdicts = run(doc, snap)
    assert [v.status for v in verdicts] == ["unverified"]
    assert "cannot be encoded" in verdicts[0].message
    assert "no source IP ranges" in verdicts[0].message


@needs_z3
def test_an_unencodable_estate_rule_abstains_rather_than_being_dropped(snap):
    # The dangerous direction: an ANCESTOR rule the packet algebra cannot
    # encode. Dropping it would delete a deny from the preemption set and mint
    # a clean bill of health for a rule that is in fact fully shadowed.
    data = json.loads((FIXTURES / "estate_snapshot.json").read_text(encoding="utf-8"))
    broken = dict(data["hierarchical_firewall_policies"][BASELINE])
    rules = [dict(r) for r in broken["rules"]]
    rules[0] = dict(rules[0])
    rules[0]["match"] = dict(rules[0]["match"])
    rules[0]["match"]["layer4"] = [{"protocol": "kryptonite", "ports": ["3389"]}]
    broken["rules"] = rules
    data["hierarchical_firewall_policies"] = {BASELINE: broken}
    verdicts = run(tf_plan(rule_resource(), association("folders/2")),
                   GcpSnapshot.from_dict(data))
    assert [v.status for v in verdicts] == ["unverified"]
    assert "kryptonite" in verdicts[0].message


# -- the REST spelling, and a policy the estate already places ----------------


@needs_z3
def test_a_rule_added_to_an_attached_estate_policy_resolves_its_level(snap):
    # No association resource here: the level comes from the estate record for
    # fp-baseline, which is attached to organizations/1. The added allow sits
    # below that policy's own deny of tcp/3389, so it can never run.
    doc = {"kind": "compute#firewallPolicy", "name": BASELINE,
           "shortName": "fp-baseline", "parent": "organizations/1",
           "rules": [{"priority": 500, "action": "allow", "direction": "INGRESS",
                      "disabled": False,
                      "match": {"srcIpRanges": ["0.0.0.0/0"], "destIpRanges": [],
                                "layer4Configs": [{"ipProtocol": "tcp",
                                                   "ports": ["3389"]}]},
                      "targetResources": [], "targetServiceAccounts": [],
                      "targetSecureTags": []}]}
    claims = firewall_policy_claims(doc)
    ctx = CheckContext(snapshot=snap, solver=get_solver(), document=doc,
                       document_kind="firewall_policy", source="<rest>",
                       claims=tuple(claims))
    shadow = of_kind(check_hierarchical_order(ctx), "hfw_shadow")
    assert [v.status for v in shadow] == ["contradicted"]
    assert shadow[0].target == BASELINE
    assert "organizations/1" in shadow[0].message


# -- the shape mapping --------------------------------------------------------


def test_as_vpc_shape_maps_the_match_block_onto_packet_field_names():
    shaped = _as_vpc_shape({
        "priority": 200, "action": "allow", "direction": "INGRESS", "disabled": False,
        "match": {"src_ip_ranges": ["10.0.0.0/8"], "dest_ip_ranges": ["192.168.0.0/16"],
                  "layer4": [{"protocol": "tcp", "ports": ["22"]}]},
        "target_resources": ["projects/acme-prod/global/networks/vpc-main"],
        "target_service_accounts": ["etl-runner@acme-prod.iam.gserviceaccount.com"],
        "target_secure_tags": ["web"]})
    assert shaped["source_ranges"] == ["10.0.0.0/8"]
    assert shaped["destination_ranges"] == ["192.168.0.0/16"]
    assert shaped["layer4"] == [{"protocol": "tcp", "ports": ["22"]}]
    # target_resources restricts the match exactly the way a target tag does.
    assert shaped["target_tags"] == ["web",
                                     "projects/acme-prod/global/networks/vpc-main"]
    assert shaped["target_service_accounts"] == [
        "etl-runner@acme-prod.iam.gserviceaccount.com"]


def test_as_vpc_shape_drops_an_empty_layer4_rather_than_making_the_rule_inert():
    # packet.layer4_match reads [] as "matches nothing"; a hierarchical rule
    # with no layer4 config restricts nothing at layer 4, and reading it as
    # inert would silently drop it from the preemption set.
    shaped = _as_vpc_shape({"priority": 1, "action": "goto_next",
                            "direction": "INGRESS", "disabled": False,
                            "match": {"src_ip_ranges": ["0.0.0.0/0"],
                                      "dest_ip_ranges": [], "layer4": []}})
    assert "layer4" not in shaped


# -- the module states its polarity families ----------------------------------


def test_each_finding_names_its_polarity_family_in_its_docstring():
    assert "family (c)" in hfw_checks._finding_unreachable.__doc__.lower()
    assert "family (a)" in hfw_checks._finding_reopen.__doc__.lower()
    assert "family (b)" in hfw_checks._finding_delta.__doc__.lower()
