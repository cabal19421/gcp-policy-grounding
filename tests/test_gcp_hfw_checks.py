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
from dataclasses import replace
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
    # A secure tag restricts the match exactly the way a target tag does; a
    # target NETWORK does not — it is a separate dimension and gets its own
    # channel, because two disjoint networks in one Or are satisfiable together.
    assert shaped["target_tags"] == ["web"]
    assert shaped["target_networks"] == [
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


def test_as_vpc_shape_treats_an_absent_layer4_key_the_same_as_an_empty_one():
    # ABSENT and positively EMPTY both legitimately mean "no layer-4
    # restriction" — the distinction the fix draws is against a PRESENT key
    # nobody could read, not against a rule that declares no layer-4 criteria.
    shaped = _as_vpc_shape({"priority": 1, "action": "goto_next",
                            "direction": "INGRESS", "disabled": False,
                            "match": {"src_ip_ranges": ["0.0.0.0/0"]}})
    assert "layer4" not in shaped
    assert shaped["destination_ranges"] == []


def test_as_vpc_shape_raises_for_a_present_but_unreadable_layer4_entry():
    # The filter that used to drop this entry is the whole defect:
    # packet.layer4_match itself RAISES on a string, so filtering it away
    # actively converted an honest abstention into a confident verdict.
    with pytest.raises(packet.UnsupportedPacket, match="not a layer-4 config"):
        _as_vpc_shape({"priority": 1, "action": "deny", "direction": "INGRESS",
                       "disabled": False,
                       "match": {"src_ip_ranges": ["0.0.0.0/0"],
                                 "layer4": ["tcp:3389"]}},
                      what="the org deny")


def test_as_vpc_shape_raises_for_a_non_bool_disabled():
    # bool("false") is True, which is how the string deleted a live DENY from
    # both the preemption set and the fold. Mirrors _rank's non-int priority.
    with pytest.raises(packet.UnsupportedPacket, match="'disabled' is 'false'"):
        _as_vpc_shape({"priority": 1, "action": "deny", "direction": "INGRESS",
                       "disabled": "false",
                       "match": {"src_ip_ranges": ["0.0.0.0/0"]}})


# -- unreadable records abstain, they never default ---------------------------
#
# Three defaults manufactured confidence out of a record nobody could read.
# Each is measured against the committed estate fixture; where a polarity
# exists both legs are pinned, and every case also asserts that the INTACT
# fixture still decides — an abstention that fired on everything would be
# worth nothing.

#: A second captured policy, at the folder level, used by the layer-4 legs.
FOLDER_POLICY = "folders/2/locations/global/firewallPolicies/fp-folder"

#: The proposal the design's preamble names: a folder allow of the RDP port
#: from a private range, which the intact fixture correctly calls shadowed.
RDP_FROM_PRIVATE = [{"src_ip_ranges": ["10.0.0.0/8"], "dest_ip_ranges": [],
                     "layer4_config": [{"ip_protocol": "tcp", "ports": ["3389"]}]}]

#: A rule no ancestor policy touches — the healthy control of the FALSE-BLOCK
#: leg, pinned as yielding zero shadow verdicts by the polarity test above.
HIGH_PORT_FROM_PRIVATE = [{"src_ip_ranges": ["10.0.0.0/8"], "dest_ip_ranges": [],
                           "layer4_config": [{"ip_protocol": "tcp",
                                              "ports": ["8080"]}]}]


def estate_data(mutate=None) -> dict:
    """The committed estate fixture as raw JSON, its hierarchical firewall
    policies optionally drifted by *mutate*."""
    data = json.loads((FIXTURES / "estate_snapshot.json").read_text(encoding="utf-8"))
    if mutate is not None:
        mutate(data["hierarchical_firewall_policies"])
    return data


def estate(mutate=None) -> GcpSnapshot:
    return GcpSnapshot.from_dict(estate_data(mutate))


def folder_allow(layer4):
    """A folder-level allow of everything from anywhere at layer 3, restricted
    at layer 4 by *layer4* — the field whose readability is under test."""
    def mutate(policies):
        policies[FOLDER_POLICY] = {
            "attachments": ["folders/2"],
            "rules": [{"action": "allow", "direction": "INGRESS",
                       "disabled": False, "priority": 300,
                       "match": {"src_ip_ranges": ["0.0.0.0/0"],
                                 "dest_ip_ranges": [], "layer4": layer4},
                       "target_resources": [], "target_secure_tags": [],
                       "target_service_accounts": []}]}
    return mutate


def org_deny_layer4(layer4):
    def mutate(policies):
        policies[BASELINE]["rules"][0]["match"]["layer4"] = layer4
    return mutate


# -- (1) an unreadable layer-4 match, both polarities -------------------------


@needs_z3
def test_false_clean_an_unreadable_folder_layer4_no_longer_grounds_no_effect(snap):
    """Item (1), the FALSE-CLEAN leg. MEASURED: a folder allow whose layer-4
    list holds strings was filtered down to no entries and then omitted, which
    :func:`packet.rule_match` reads as no layer-4 restriction — so the folder
    rule appeared to allow every port from everywhere and an org-level proposed
    allow of a high port from everywhere reported ``grounded`` no-effect."""
    proposal = tf_plan(rule_resource(priority=50, match=[{
        "src_ip_ranges": ["0.0.0.0/0"], "dest_ip_ranges": [],
        "layer4_config": [{"ip_protocol": "tcp", "ports": ["8080"]}]}]),
        association("organizations/1"))

    drifted = run(proposal, estate(folder_allow(["tcp:3389"])))
    assert [v.status for v in drifted] == ["unverified"]
    assert [v.kind for v in drifted] == ["hfw_order"]
    assert FOLDER_POLICY in drifted[0].message      # the offending policy
    assert "match.layer4[0]" in drifted[0].message  # and the offending field
    assert of_kind(drifted, "hfw_effect") == []

    # The identical field made readable: the same proposal is a widening, which
    # is what the drifted run was hiding.
    readable = run(proposal,
                   estate(folder_allow([{"protocol": "tcp", "ports": ["3389"]}])))
    assert [v.status for v in of_kind(readable, "hfw_widen")] == ["contradicted"]
    assert of_kind(readable, "hfw_order") == []


@needs_z3
def test_false_block_an_unreadable_org_deny_layer4_no_longer_shadows(snap):
    """Item (1), the FALSE-BLOCK leg — the same drift on an org DENY. Erasing
    its layer-4 restriction made it match every port, so a healthy live rule
    (tcp/8080 from a private range, which no ancestor policy touches) was
    reported ``contradicted hfw_shadow``."""
    healthy = tf_plan(rule_resource(match=HIGH_PORT_FROM_PRIVATE),
                      association("folders/2"))

    drifted = run(healthy, estate(org_deny_layer4(["tcp:3389"])))
    assert [v.status for v in drifted] == ["unverified"]
    assert [v.kind for v in drifted] == ["hfw_order"]
    assert BASELINE in drifted[0].message
    assert "match.layer4[0]" in drifted[0].message
    assert of_kind(drifted, "hfw_shadow") == []

    # The intact fixture still decides, and decides the healthy way.
    intact = run(healthy, snap)
    assert of_kind(intact, "hfw_shadow") == []
    assert [v.status for v in of_kind(intact, "hfw_effect")] == ["grounded"]


# -- (2) a non-bool `disabled` ------------------------------------------------


def _org_deny_disabled(value) -> GcpSnapshot:
    """The estate with the org deny's ``disabled`` set to *value*, built past
    the loader (which now rejects the same drift — see the test below), so the
    check's own handling of it is what is under test here."""
    intact = estate()
    record = dict(intact.hierarchical_firewall_policies[BASELINE])
    rules = [dict(rule) for rule in record["rules"]]
    rules[0] = dict(rules[0], disabled=value)
    record["rules"] = tuple(rules)
    return replace(intact,
                   hierarchical_firewall_policies={BASELINE: record})


@needs_z3
def test_a_non_bool_disabled_no_longer_deletes_a_live_estate_deny(snap):
    """Item (2). MEASURED: ``bool("false")`` is ``True``, so the string deleted
    the org DENY from both the preemption set and the effective-decision fold
    and turned the shadowed rule into a single ``grounded`` no-effect verdict
    with ``report.ok`` True."""
    proposal = tf_plan(rule_resource(match=RDP_FROM_PRIVATE),
                       association("folders/2"))

    drifted = run(proposal, _org_deny_disabled("false"))
    assert [v.status for v in drifted] == ["unverified"]
    assert [v.kind for v in drifted] == ["hfw_order"]
    assert BASELINE in drifted[0].message
    assert "'disabled'" in drifted[0].message
    assert of_kind(drifted, "hfw_effect") == []

    # The intact fixture still calls the same rule shadowed by the org deny.
    intact = run(proposal, snap)
    assert [v.status for v in of_kind(intact, "hfw_shadow")] == ["contradicted"]
    assert [v.status for v in of_kind(intact, "hfw_effect")] == ["grounded"]


def test_the_loader_rejects_a_non_bool_disabled_in_a_hierarchical_rule():
    """The same field validation ``_parse_firewall_rules`` already applies, now
    applied to the hierarchical table too: a half-parsed record would mark the
    category captured with wrong content."""
    def drift(policies):
        policies[BASELINE]["rules"][0]["disabled"] = "false"

    with pytest.raises(ValueError, match="'disabled' must be a bool"):
        GcpSnapshot.from_dict(estate_data(drift))


def test_the_loader_rejects_a_non_int_priority_in_a_hierarchical_rule():
    def drift(policies):
        policies[BASELINE]["rules"][0]["priority"] = "100"

    with pytest.raises(ValueError, match="'priority' must be an int"):
        GcpSnapshot.from_dict(estate_data(drift))


# -- (3) a fold that consumed no rule at all ----------------------------------


def _drop_rules_key(policies):
    del policies[BASELINE]["rules"]


def _empty_rules_array(policies):
    policies[BASELINE]["rules"] = []


def _drop_attachments(policies):
    policies[BASELINE]["attachments"] = []


@needs_z3
@pytest.mark.parametrize("mutate", [_drop_rules_key, _empty_rules_array],
                         ids=["rules-key-dropped", "rules-array-empty"])
def test_a_fold_that_consumed_no_rule_abstains_naming_what_contributed_nothing(
        snap, mutate):
    """Item (3), first clause. MEASURED: the fold emitted a positive verdict
    asserting the 3-level order decides every packet identically while having
    read rules from no level at all, with zero unverified."""
    proposal = tf_plan(rule_resource(match=RDP_FROM_PRIVATE),
                       association("folders/2"))

    drifted = run(proposal, estate(mutate))
    assert [v.status for v in drifted] == ["unverified"]
    assert [v.kind for v in drifted] == ["hfw_order"]
    assert BASELINE in drifted[0].message    # the policy that contributed none
    assert "'rules'" in drifted[0].message   # and the field it was read from
    assert of_kind(drifted, "hfw_effect") == []

    intact = run(proposal, snap)
    assert [v.status for v in of_kind(intact, "hfw_effect")] == ["grounded"]
    assert "3-level order" in of_kind(intact, "hfw_effect")[0].message


@needs_z3
def test_a_captured_policy_that_declares_no_attachments_is_never_ignored(snap):
    """Item (3), second clause. A policy whose NAME is scoped under a node on
    the evaluation path but which declares no attachments is an input about
    this project's order that could not be read; ignoring it is how a whole
    level silently disappears from the fold."""
    proposal = tf_plan(rule_resource(match=RDP_FROM_PRIVATE),
                       association("folders/2"))

    drifted = run(proposal, estate(_drop_attachments))
    assert [v.status for v in drifted] == ["unverified"]
    assert [v.kind for v in drifted] == ["hfw_order"]
    assert BASELINE in drifted[0].message
    assert "'attachments'" in drifted[0].message
    assert of_kind(drifted, "hfw_effect") == []

    assert [v.status for v in of_kind(run(proposal, snap), "hfw_effect")] == [
        "grounded"]


@needs_z3
def test_a_policy_scoped_off_the_evaluation_path_is_still_ignored(snap):
    """The other side of that clause: an unattached policy under a node the
    project does not sit below says nothing about this project's order, so it
    must NOT abstain — otherwise the check would go silent estate-wide."""
    def elsewhere(policies):
        policies["folders/99/locations/global/firewallPolicies/fp-other"] = {
            "attachments": [], "rules": []}

    proposal = tf_plan(rule_resource(match=RDP_FROM_PRIVATE),
                       association("folders/2"))
    verdicts = run(proposal, estate(elsewhere))
    assert [v.status for v in of_kind(verdicts, "hfw_shadow")] == ["contradicted"]
    assert of_kind(verdicts, "hfw_order") == []


# -- the named must-kill pins, MK-H01 … MK-H05 --------------------------------
#
# AMENDMENT 3 replaced this task's mutation ratio with five named must-kill
# entries. Each pins ONE guard of the three numbered items above in BOTH
# directions, because every one of them is a guard an inverting mutant turns
# inside out: a test that only drives the drift case leaves the inversion
# alive, and a test that only drives the healthy case leaves the default alive.
# The entries name these node ids, so they stay UNPARAMETRIZED and keep their
# spelling.


def _org_deny_omits_disabled(policies):
    del policies[BASELINE]["rules"][0]["disabled"]


def _policy_in_another_folder(policies):
    policies["folders/99/locations/global/firewallPolicies/fp-other"] = {
        "attachments": [], "rules": []}


def hierarchical_rule(**overrides) -> dict:
    """A captured org-level DENY of tcp/3389 from anywhere, in the hierarchical
    spelling ``_as_vpc_shape`` reads, with fields overridden per leg."""
    rule = {"action": "deny", "direction": "INGRESS", "disabled": False,
            "priority": 100,
            "match": {"src_ip_ranges": ["0.0.0.0/0"], "dest_ip_ranges": [],
                      "layer4": [{"protocol": "tcp", "ports": ["3389"]}]}}
    rule.update(overrides)
    return rule


def two_level_estate(mutate=None) -> GcpSnapshot:
    """The committed estate plus a project sitting DIRECTLY under the
    organization, so its evaluation path is exactly TWO levels — the boundary
    the zero-rules-folded abstention is asserted at."""
    data = estate_data(mutate)
    data["resource_hierarchy"]["projects/acme-lab"] = {
        "display_name": "Acme Lab", "number": "654321",
        "parent": "organizations/1", "type": "project"}
    return GcpSnapshot.from_dict(data)


@needs_z3
def test_a_rule_omitting_disabled_is_enabled_and_still_preempts(snap):
    """MK-H01 — ``_as_vpc_shape``'s ``rule.get("disabled", False)``.

    A captured rule that OMITS the key is ENABLED. Defaulting it to disabled
    would silently take every such rule out of both the preemption set and the
    effective-decision fold — item (2)'s measured defect reached through an
    ABSENT key rather than a non-bool one, and the more common shape in a real
    capture. Asserted through the verdicts the rule produces, not through the
    shape helper's return value alone: the org deny still shadows the folder
    allow of tcp/3389 from 0.0.0.0/0 (it is still in the preemption set), and
    the proposal is still ``grounded`` no-effect rather than the widening it
    becomes once that deny leaves the fold.
    """
    proposal = tf_plan(rule_resource(), association("folders/2"))

    omitted = run(proposal, estate(_org_deny_omits_disabled))
    shadow = of_kind(omitted, "hfw_shadow")
    assert [v.status for v in shadow] == ["contradicted"]
    assert "organizations/1" in shadow[0].message
    assert [v.status for v in of_kind(omitted, "hfw_effect")] == ["grounded"]
    assert of_kind(omitted, "hfw_widen") == []   # still folded, so nothing widens
    assert of_kind(omitted, "hfw_order") == []

    # It decides exactly as the committed fixture, whose rule spells the key.
    intact = run(proposal, snap)
    assert ([(v.status, v.kind) for v in omitted]
            == [(v.status, v.kind) for v in intact])


@needs_z3
def test_an_unreadable_layer4_entry_abstains_while_a_readable_one_decides(snap):
    """MK-H02 — ``_layer4_entries``' ``not isinstance(entry, Mapping)`` guard,
    in both directions.

    A PRESENT but unreadable layer-4 entry raises the unsupported-packet
    abstain instead of being filtered away into "no layer-4 restriction", which
    matches every port; AND a readable layer-4 config is not refused. Driving
    only the drift leg leaves an inverted guard alive — the readable direction,
    where the committed fixture must still decide, is what kills it.
    """
    proposal = tf_plan(rule_resource(), association("folders/2"))

    drifted = run(proposal, estate(org_deny_layer4(["tcp:3389"])))
    assert [(v.status, v.kind) for v in drifted] == [("unverified", "hfw_order")]
    assert BASELINE in drifted[0].message           # the offending policy
    assert "match.layer4[0]" in drifted[0].message  # and the offending field

    # The same field READABLE: the committed fixture decides, and decides the
    # RDP allow shadowed. A guard that refused this would abstain estate-wide.
    intact = run(proposal, snap)
    assert of_kind(intact, "hfw_order") == []
    assert [v.status for v in of_kind(intact, "hfw_shadow")] == ["contradicted"]
    assert [v.status for v in of_kind(intact, "hfw_effect")] == ["grounded"]


@needs_z3
def test_a_two_level_chain_that_folded_no_rule_abstains():
    """MK-H03 — ``_place``'s ``len(chain) > 1``, at its BOUNDARY.

    A TWO-level chain whose captured policies declare no rule at all must
    abstain naming the policies that contributed nothing. Raising the boundary
    by one restores, for every two-level chain, exactly the RC1 instance this
    task exists to close: "the N-level order decides every packet identically"
    stated over zero rules. The three-level chain the fixture already has must
    keep abstaining too, which is the other side of the boundary.
    """
    proposal = tf_plan(rule_resource(match=RDP_FROM_PRIVATE),
                       association("projects/acme-lab"))

    two_level = run(proposal, two_level_estate(_empty_rules_array))
    assert [(v.status, v.kind) for v in two_level] == [("unverified", "hfw_order")]
    assert "2 levels (organizations/1 > projects/acme-lab)" in two_level[0].message
    assert BASELINE in two_level[0].message   # the policy that contributed none

    three_level = run(tf_plan(rule_resource(match=RDP_FROM_PRIVATE),
                              association("folders/2")),
                      estate(_empty_rules_array))
    assert [(v.status, v.kind) for v in three_level] == [("unverified", "hfw_order")]
    assert ("3 levels (organizations/1 > folders/2 > projects/acme-prod)"
            in three_level[0].message)


@needs_z3
def test_an_off_chain_policy_without_attachments_does_not_abstain(snap):
    """MK-H04 — ``_unattached_under``'s ``scope is None or scope not in chain``
    filter, in both directions.

    A captured policy scoped OUTSIDE the evaluation path says nothing about
    this project's order, so an empty ``attachments`` on it must NOT abstain;
    treating every captured policy as on-chain would manufacture a false
    abstention from an unrelated folder and stop the fixture deciding at all.
    On the chain, the same shape IS the abstention item (3) mandates.
    """
    proposal = tf_plan(rule_resource(match=RDP_FROM_PRIVATE),
                       association("folders/2"))

    off_chain = run(proposal, estate(_policy_in_another_folder))
    assert of_kind(off_chain, "hfw_order") == []
    assert [v.status for v in of_kind(off_chain, "hfw_shadow")] == ["contradicted"]

    on_chain = run(proposal, estate(_drop_attachments))
    assert [(v.status, v.kind) for v in on_chain] == [("unverified", "hfw_order")]
    assert BASELINE in on_chain[0].message
    assert "'attachments'" in on_chain[0].message


def test_a_non_bool_disabled_raises_while_a_real_bool_encodes():
    """MK-H05 — ``_as_vpc_shape``'s ``not isinstance(disabled, bool)`` guard,
    in both directions.

    A non-bool ``disabled`` — the string ``"false"``, whose ``bool()`` is True,
    or a bare ``0`` — is UNENCODABLE and raises; AND a real boolean passes
    through and reaches the applicable set with its own value. Inverting the
    guard refuses every well-formed rule and accepts every malformed one, so
    only a test carrying both cases kills it.
    """
    with pytest.raises(packet.UnsupportedPacket, match="'disabled' is 'false'"):
        _as_vpc_shape(hierarchical_rule(disabled="false"), what="the org deny")
    with pytest.raises(packet.UnsupportedPacket, match="'disabled' is 0"):
        _as_vpc_shape(hierarchical_rule(disabled=0))

    # A real boolean encodes either way round, and the enabled one is the one
    # the preemption set and the fold go on to keep.
    enabled = _as_vpc_shape(hierarchical_rule(disabled=False))
    turned_off = _as_vpc_shape(hierarchical_rule(disabled=True))
    assert (enabled["disabled"], turned_off["disabled"]) == (False, True)
    assert hfw_checks._applicable([enabled, turned_off], "INGRESS") == [enabled]


# -- placement: the stale twin, siblings, and network scope --------------------
#
# Three placement defects, each MEASURED against the committed estate fixture
# before the fix and asserted here in the polarity it must now read.

#: The two networks the estate captures. Only ``vpc-main`` carries VPC rules.
VPC_MAIN = "projects/acme-prod/global/networks/vpc-main"
VPC_DMZ = "projects/acme-prod/global/networks/vpc-dmz"

#: A target resource that is NOT a network self-link, so whether it can hold a
#: packet on ``vpc-main`` cannot be decided from the tables this module reads.
SUBNET_SCOPE = "projects/acme-prod/regions/us-central1/subnetworks/sn-main"


def tf_update(*resources: dict) -> dict:
    """A plan whose resources are UPDATED in place, carrying the pre-edit
    payload — the shape the stale-twin defect was measured on."""
    return {"format_version": "1.2", "terraform_version": "1.9.5",
            "resource_changes": [
                {"address": r["address"], "mode": "managed", "type": r["type"],
                 "name": r["address"].rsplit(".", 1)[-1],
                 "provider_name": "registry.terraform.io/hashicorp/google",
                 "change": {"actions": ["update"], "before": r.get("before"),
                            "after": r["after"]}}
                for r in resources]}


def estate_snapshot(mutate=None) -> GcpSnapshot:
    """The committed estate as a WHOLE document, optionally drifted by *mutate*
    — ``estate()`` above can only reach the hierarchical policies."""
    data = json.loads((FIXTURES / "estate_snapshot.json").read_text(encoding="utf-8"))
    if mutate is not None:
        mutate(data)
    return GcpSnapshot.from_dict(data)


# -- (4) THE STALE TWIN -------------------------------------------------------


def rdp_edit(**overrides) -> dict:
    """The design's first measured proposal: an in-place UPDATE of
    ``fp-baseline``'s own priority-100 rule, flipping it from deny to allow and
    opening the RDP port from everywhere org-wide. No association resource —
    the level comes from the estate record, which is what makes the estate's
    copy of this very rule the thing the fold must drop."""
    before = {
        "firewall_policy": BASELINE,
        "priority": 100, "action": "deny", "direction": "INGRESS",
        "disabled": False,
        "match": [{"src_ip_ranges": ["0.0.0.0/0"], "dest_ip_ranges": [],
                   "layer4_config": [{"ip_protocol": "tcp", "ports": ["3389"]}]}],
        "target_resources": [], "target_service_accounts": [],
        "target_secure_tags": [],
    }
    after = dict(before, action="allow")
    after.update(overrides)
    return {"address": "google_compute_firewall_policy_rule.rdp",
            "type": "google_compute_firewall_policy_rule",
            "before": before, "after": after}


@needs_z3
def test_an_in_place_edit_drops_the_estate_copy_of_the_rule_it_replaces(snap):
    """Item (4). MEASURED before the fix: the world-without-the-proposed-rule
    kept ``fp-baseline``'s priority-100 DENY, so flipping that very rule to an
    allow of tcp/3389 from 0.0.0.0/0 reported ``contradicted hfw_shadow``
    (unreachable because of an ancestor policy that is its own pre-edit
    version) plus a ``grounded hfw_effect`` no-effect note. At equal priority
    deny sorts before allow, so the stale copy won the tie both times — it
    suppressed the widening as well as manufacturing the contradiction."""
    verdicts = run(tf_update(rdp_edit()), snap)

    assert of_kind(verdicts, "hfw_shadow") == []      # it is not its own ancestor
    assert of_kind(verdicts, "hfw_effect") == []      # and it is not inert
    assert of_kind(verdicts, "hfw_order") == []
    widen = of_kind(verdicts, "hfw_widen")
    assert [v.status for v in widen] == ["contradicted"]
    assert "port=3389" in widen[0].message
    assert "projects/acme-prod" in widen[0].message


@needs_z3
def test_a_rule_at_a_different_priority_is_not_read_as_the_twin(snap):
    """The other side of the identity: the SAME edit moved to priority 300 does
    not replace the estate's priority-100 deny, which therefore stays in the
    preemption set and shadows it. Dropping every estate rule of the named
    policy — rather than the one slot the proposal occupies — passes the leg
    above and fails this one."""
    verdicts = run(tf_update(rdp_edit(priority=300)), snap)

    shadow = of_kind(verdicts, "hfw_shadow")
    assert [v.status for v in shadow] == ["contradicted"]
    assert "organizations/1" in shadow[0].message
    assert [v.status for v in of_kind(verdicts, "hfw_effect")] == ["grounded"]
    assert of_kind(verdicts, "hfw_widen") == []


@needs_z3
def test_an_unidentifiable_twin_abstains_rather_than_double_counting():
    """When the estate holds MORE THAN ONE rule in the slot the proposal edits,
    which of them is being replaced cannot be established — so the check
    abstains naming the ambiguity instead of guessing, or of keeping both and
    double-counting the rule."""
    def duplicate_slot(policies):
        rules = policies[BASELINE]["rules"]
        rules.append(dict(rules[0], action="allow"))

    verdicts = run(tf_update(rdp_edit()), estate(duplicate_slot))
    assert [(v.status, v.kind) for v in verdicts] == [("unverified", "hfw_order")]
    assert BASELINE in verdicts[0].message
    assert "priority 100" in verdicts[0].message
    assert "cannot be identified" in verdicts[0].message


# -- (5) SIBLING PROPOSALS ----------------------------------------------------


ORG_POLICY = "organizations/1/locations/global/firewallPolicies/pol-org"
FOLDER_POLICY_B = "folders/2/locations/global/firewallPolicies/pol-folder"

#: Traffic the VPC layer already allows (allow-internal covers every tcp port
#: from 10.0.0.0/8) and no hierarchical policy touches, so each half of the
#: apply is a `grounded` note when graded on its own.
INTERNAL_8080 = [{"src_ip_ranges": ["10.0.0.0/8"], "dest_ip_ranges": [],
                  "layer4_config": [{"ip_protocol": "tcp", "ports": ["8080"]}]}]


def sibling_apply() -> dict:
    """One apply that adds an org-level DENY and a folder-level ALLOW of the
    same traffic — the second is dead the moment the first lands."""
    def rule(address, policy, priority, action):
        return {"address": address, "type": "google_compute_firewall_policy_rule",
                "after": {"firewall_policy": policy, "priority": priority,
                          "action": action, "direction": "INGRESS",
                          "disabled": False, "match": INTERNAL_8080,
                          "target_resources": [], "target_service_accounts": [],
                          "target_secure_tags": []}}

    def attach(address, policy, node):
        return {"address": address,
                "type": "google_compute_firewall_policy_association",
                "after": {"firewall_policy": policy, "attachment_target": node,
                          "name": address.rsplit(".", 1)[-1]}}

    return tf_plan(
        rule("google_compute_firewall_policy_rule.org_deny", ORG_POLICY, 50, "deny"),
        attach("google_compute_firewall_policy_association.org", ORG_POLICY,
               "organizations/1"),
        rule("google_compute_firewall_policy_rule.folder_allow", FOLDER_POLICY_B,
             100, "allow"),
        attach("google_compute_firewall_policy_association.folder",
               FOLDER_POLICY_B, "folders/2"))


@needs_z3
def test_a_sibling_proposal_at_another_node_is_placed_on_the_same_chain(snap):
    """Item (5). MEASURED before the fix: a proposed rule attaching at a
    DIFFERENT node was excluded from the placement, so an org-level deny plus a
    folder-level allow of the same traffic were each graded as if they were the
    only change — two ``grounded`` verdicts and NO shadow finding for the
    allow, which is dead the moment the deny lands."""
    verdicts = run(sibling_apply(), snap)

    shadow = of_kind(verdicts, "hfw_shadow")
    assert [v.status for v in shadow] == ["contradicted"]
    assert shadow[0].target == FOLDER_POLICY_B
    assert "organizations/1" in shadow[0].message      # the sibling's own node
    assert of_kind(verdicts, "hfw_order") == []


@needs_z3
def test_a_proposal_off_this_chain_is_not_placed_on_it(snap):
    """The boundary of the same clause: a sibling whose node is NOT on this
    project's evaluation path says nothing about this project's order, so it
    must not be folded in — it abstains on its own turn, which is the only
    proposal it can speak for. Placing every sibling regardless of node would
    make this allow shadowed by a deny in a folder it does not sit under."""
    def elsewhere(data):
        data["resource_hierarchy"]["folders/3"] = {
            "display_name": "Lab", "number": "3", "parent": "organizations/1",
            "type": "folder"}

    doc = json.loads(json.dumps(sibling_apply()))
    for change in doc["resource_changes"]:
        if change["address"].endswith(".org"):
            change["change"]["after"]["attachment_target"] = "folders/3"

    verdicts = run(doc, estate_snapshot(elsewhere))
    assert of_kind(verdicts, "hfw_shadow") == []
    # The off-chain deny still gets its own answer, on its own chain.
    assert [v.status for v in of_kind(verdicts, "hfw_order")] == ["unverified"]
    assert "folders/3" in of_kind(verdicts, "hfw_order")[0].message


# -- (6) NETWORK SCOPE --------------------------------------------------------


def org_deny_scoped_to(*resources):
    def mutate(policies):
        policies[BASELINE]["rules"][0]["target_resources"] = list(resources)
    return mutate


def scoped_proposal() -> dict:
    return tf_plan(rule_resource(priority=50, target_resources=[VPC_MAIN]),
                   association("organizations/1"))


@needs_z3
def test_rules_on_provably_disjoint_networks_are_never_compared(snap):
    """Item (6). MEASURED before the fix: a network self-link was OR-ed into
    the same ``target_tags`` channel as a secure tag, and nothing forbids the
    solver satisfying two disjoint networks at once — so an org deny scoped to
    ``vpc-dmz`` and a proposed allow scoped to ``vpc-main`` were treated as able
    to match one packet, reported as ``contradicted hfw_reopen`` with a witness
    packet that cannot exist."""
    disjoint = run(scoped_proposal(), estate(org_deny_scoped_to(VPC_DMZ)))
    assert of_kind(disjoint, "hfw_reopen") == []
    assert of_kind(disjoint, "hfw_order") == []

    # NEVER WIDENED TO THE DECIDABLE CASE: the same two rules on the SAME
    # network still re-open, so the mitigation cannot be read as "skip network
    # comparisons".
    same = run(scoped_proposal(), estate(org_deny_scoped_to(VPC_MAIN)))
    assert [v.status for v in of_kind(same, "hfw_reopen")] == ["contradicted"]
    assert of_kind(same, "hfw_order") == []


@needs_z3
def test_an_undecidable_network_overlap_abstains_loudly_and_names_both(snap):
    """The recorded PRICE of that mitigation. ``unverified`` PASSES the gate, so
    declining an undecidable overlap converts a would-be block into a pass: the
    re-open finding this run would otherwise carry is gone. That is acceptable
    only because the abstention is LOUD — one ``unverified`` on the
    hierarchical channel naming both sides' networks and the rule it declined
    to compare — and never spelled as silence."""
    verdicts = run(scoped_proposal(), estate(org_deny_scoped_to(SUBNET_SCOPE)))

    order = of_kind(verdicts, "hfw_order")
    assert [v.status for v in order] == ["unverified"]
    assert VPC_MAIN in order[0].message             # the proposal's own scope
    assert SUBNET_SCOPE in order[0].message         # the scope it could not read
    assert BASELINE in order[0].message             # the rule it declined
    assert of_kind(verdicts, "hfw_reopen") == []    # the price, asserted


def test_a_network_self_link_is_not_a_target_tag():
    """The channel itself: ``target_resources`` no longer shares the OR-ed tag
    channel with secure tags, because two disjoint networks in one Or are
    satisfiable together and a secure tag and a network are not the same
    dimension."""
    shaped = _as_vpc_shape({
        "priority": 200, "action": "allow", "direction": "INGRESS",
        "disabled": False,
        "match": {"src_ip_ranges": ["10.0.0.0/8"], "dest_ip_ranges": [],
                  "layer4": [{"protocol": "tcp", "ports": ["22"]}]},
        "target_resources": [VPC_MAIN], "target_secure_tags": ["web"],
        "target_service_accounts": []})
    assert shaped["target_tags"] == ["web"]
    assert shaped["target_networks"] == [VPC_MAIN]


# -- (7) the three unpinned polarities ----------------------------------------


@needs_z3
def test_an_internal_only_overlap_reopens_nothing_while_the_public_one_does(snap):
    """POLARITY 1 — ``_finding_reopen``'s public-peer restriction, in BOTH
    directions. An allow that wins over a deny is only a re-opening when the
    peer it lets in is PUBLIC; deleting ``packet.is_public`` from the comparison
    currently costs nothing against the whole suite, because every case that
    asserts a re-opening drives a public peer. The internal leg is what pins
    it: both peers private must yield ZERO re-open verdicts."""
    def private_deny(policies):
        policies[BASELINE]["rules"][0]["match"]["src_ip_ranges"] = ["10.0.0.0/8"]

    internal = run(
        tf_plan(rule_resource(priority=50, match=[{
            "src_ip_ranges": ["10.0.0.0/8"], "dest_ip_ranges": [],
            "layer4_config": [{"ip_protocol": "tcp", "ports": ["3389"]}]}]),
            association("organizations/1")),
        estate(private_deny))
    assert of_kind(internal, "hfw_reopen") == []
    assert of_kind(internal, "hfw_order") == []      # zero, not "could not tell"

    public = run(tf_plan(rule_resource(priority=50), association("organizations/1")),
                 snap)
    reopen = of_kind(public, "hfw_reopen")
    assert [v.status for v in reopen] == ["contradicted"]
    assert len(reopen) == 1


@needs_z3
def test_traffic_no_lower_layer_touches_widens_unless_it_was_already_allowed(snap):
    """POLARITY 2 — the implied-deny default the INGRESS fold starts from.
    ``effective_decision`` seeds ``packet.effective_allow`` with
    ``default_allow=(direction == "EGRESS")``; flipping that to allow-by-default
    currently costs nothing against the whole suite, because every widening
    case in it opens traffic an estate rule already denies, so the delta
    survives the flip. A proposal whose traffic NO lower-layer rule touches is
    what pins it — udp/53 is matched by no VPC rule and no hierarchical rule, so
    only the implied deny stands between it and the allow."""
    proposal = tf_plan(rule_resource(priority=50, match=[{
        "src_ip_ranges": ["0.0.0.0/0"], "dest_ip_ranges": [],
        "layer4_config": [{"ip_protocol": "udp", "ports": ["53"]}]}]),
        association("organizations/1"))

    widen = of_kind(run(proposal, snap), "hfw_widen")
    assert [v.status for v in widen] == ["contradicted"]
    assert "proto=17" in widen[0].message and "port=53" in widen[0].message

    # The same proposal against a snapshot that ALREADY allows it: the honest
    # no-effect note, which is what makes the leg above a polarity and not just
    # an assertion that something is always reported.
    def already_allowed(data):
        data["firewall_rules"]["projects/acme-prod/global/firewalls/allow-dns"] = {
            "network": VPC_MAIN, "direction": "INGRESS", "action": "allow",
            "priority": 100, "disabled": False,
            "source_ranges": ["0.0.0.0/0"], "destination_ranges": [],
            "layer4": [{"protocol": "udp", "ports": ["53"]}],
            "source_tags": [], "target_tags": [],
            "source_service_accounts": [], "target_service_accounts": []}

    settled = run(proposal, estate_snapshot(already_allowed))
    assert [v.status for v in of_kind(settled, "hfw_effect")] == ["grounded"]
    assert "no effect on the effective decision" in of_kind(settled, "hfw_effect")[0].message
    assert of_kind(settled, "hfw_widen") == []


@needs_z3
def test_an_omitted_lower_layer_category_abstains_naming_it(snap):
    """POLARITY 3 — the docstring's third abstention clause, which no test
    reached: ``firewall_rules`` is the BASE of the effective decision, so a
    snapshot that captured the hierarchy and the hierarchical policies but not
    that category has nothing to fold onto. Deleting the guard currently costs
    nothing against the whole suite, because the only snapshot that exercises
    it captures no hierarchy either and abstains one clause earlier."""
    def omit_lower_layer(data):
        del data["firewall_rules"]

    partial_vpc = estate_snapshot(omit_lower_layer)
    assert partial_vpc.resource_hierarchy is not None
    assert partial_vpc.hierarchical_firewall_policies is not None
    assert partial_vpc.firewall_rules is None

    verdicts = run(tf_plan(rule_resource(), association("folders/2")), partial_vpc)
    assert [(v.status, v.kind) for v in verdicts] == [("unverified", "hfw_order")]
    assert "firewall_rules" in verdicts[0].message

    # The identical proposal against the intact fixture still decides.
    assert [v.status for v in of_kind(run(
        tf_plan(rule_resource(), association("folders/2")), snap), "hfw_shadow")
    ] == ["contradicted"]


# -- the module states its polarity families ----------------------------------


def test_each_finding_names_its_polarity_family_in_its_docstring():
    assert "family (c)" in hfw_checks._finding_unreachable.__doc__.lower()
    assert "family (a)" in hfw_checks._finding_reopen.__doc__.lower()
    assert "family (b)" in hfw_checks._finding_delta.__doc__.lower()
