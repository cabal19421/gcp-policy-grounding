"""Hierarchical firewall claim-extraction tests.

Pins the discipline of :mod:`gcp_grounding.hfw_claims`: the REST and terraform
spellings normalize to one identical rule (``goto_next`` preserved verbatim); a
rule resource references the policy it attaches to while a policy resource
references nothing about itself; a numeric ``tagValues/`` secure tag is not a
network tag; an unresolved interpolation yields no reference claim and no crash;
and a rule the packet algebra cannot encode is carried as an ``unsupported``
claim, never dropped.

Environment-honest about ``detect_kind``: recognizing ``firewall_policy`` as a
document kind is the sibling ``sx-detect-kind`` task, absent from this isolated
checkout, so the detection assertion branches on whether ``firewall_policy`` is
yet in :data:`~gcp_grounding.preflight.DOCUMENT_KINDS`.
"""

import json
from pathlib import Path

import pytest

from gcp_grounding import registry
from gcp_grounding.claims import KINDS, Claim
from gcp_grounding.hfw_claims import TF_EXTRACTORS, firewall_policy_claims
from gcp_grounding.preflight import DOCUMENT_KINDS, detect_kind
from gcp_grounding.tf_claims import terraform_plan_claims

POLICIES = Path(__file__).parent / "fixtures" / "gcp" / "policies"

_RULE = TF_EXTRACTORS["google_compute_firewall_policy_rule"]
_POLICY = TF_EXTRACTORS["google_compute_firewall_policy"]
_ASSOCIATION = TF_EXTRACTORS["google_compute_firewall_policy_association"]


@pytest.fixture(autouse=True)
def _fresh_registry():
    # terraform_plan_claims resolves this module's TF extractors through the
    # lazy provider registry; reset so discovery does not depend on ordering.
    registry.reset_cache()
    yield
    registry.reset_cache()


def load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


def only(claims, kind: str) -> Claim:
    matches = [c for c in claims if c.kind == kind]
    assert len(matches) == 1, f"expected exactly one {kind}, got {matches}"
    return matches[0]


def kinds(claims, kind: str):
    return [c for c in claims if c.kind == kind]


def tf_plan(*resources: dict) -> dict:
    return {"format_version": "1.2", "terraform_version": "1.9.5",
            "resource_changes": [
                {"address": r["address"], "mode": "managed", "type": r["type"],
                 "name": r["address"].rsplit(".", 1)[-1],
                 "provider_name": "registry.terraform.io/hashicorp/google",
                 "change": {"actions": ["create"], "before": None, "after": r["after"]}}
                for r in resources]}


# -- the claim kinds this module emits are all declared ----------------------


def test_emitted_kinds_are_known():
    for kind in ("firewall_policy_rule", "firewall_policy_ref",
                 "hierarchy_node_ref", "network_tag_ref", "service_account_ref"):
        assert kind in KINDS


# -- REST and terraform normalizations agree; goto_next survives -------------


def test_rest_and_tf_normalizations_agree_and_goto_next_survives():
    policy = "organizations/1/locations/global/firewallPolicies/p"
    rest_doc = {
        "name": policy, "parent": "organizations/1",
        "rules": [{
            "priority": 500, "action": "goto_next", "direction": "INGRESS",
            "disabled": False,
            "match": {"srcIpRanges": ["10.0.0.0/8"], "destIpRanges": [],
                      "layer4Configs": [{"ipProtocol": "tcp", "ports": ["3389"]}]},
            "targetResources": ["vpc-main"], "targetServiceAccounts": [],
            "targetSecureTags": []}]}
    tf_after = {
        "firewall_policy": policy, "priority": 500, "action": "goto_next",
        "direction": "INGRESS", "disabled": False,
        "match": [{"src_ip_ranges": ["10.0.0.0/8"], "dest_ip_ranges": [],
                   "layer4_config": [{"ip_protocol": "tcp", "ports": ["3389"]}]}],
        "target_resources": ["vpc-main"], "target_service_accounts": [],
        "target_secure_tags": []}

    rest_rule = only(firewall_policy_claims(rest_doc), "firewall_policy_rule")
    tf_rule = only(_RULE("google_compute_firewall_policy_rule.r", tf_after),
                   "firewall_policy_rule")

    assert rest_rule.fields()["rule"] == tf_rule.fields()["rule"]
    # goto_next is preserved verbatim, not folded into allow/deny.
    assert rest_rule.fields()["rule"]["action"] == "goto_next"
    assert "unsupported" not in rest_rule.fields()
    # the normalized shape matches the estate record field-for-field.
    assert rest_rule.fields()["rule"] == {
        "priority": 500, "action": "goto_next", "direction": "INGRESS",
        "disabled": False,
        "match": {"src_ip_ranges": ["10.0.0.0/8"], "dest_ip_ranges": [],
                  "layer4": [{"protocol": "tcp", "ports": ["3389"]}]},
        "target_resources": ["vpc-main"], "target_service_accounts": [],
        "target_secure_tags": []}


# -- committed REST fixture ---------------------------------------------------


def test_rest_policy_fixture_claims():
    claims = firewall_policy_claims(load("hfw_policy.json"))
    # owning node, and no self-referential ref (the policy is being created).
    node = only(claims, "hierarchy_node_ref")
    assert node.value == "organizations/1"
    assert kinds(claims, "firewall_policy_ref") == []
    # one rule claim per rules[] entry, deny then goto_next.
    rules = kinds(claims, "firewall_policy_rule")
    assert [r.fields()["rule"]["action"] for r in rules] == ["deny", "goto_next"]
    assert [r.fields()["rule"]["priority"] for r in rules] == [100, 500]
    assert rules[0].fields()["rule"]["target_resources"] == ["vpc-main"]
    assert all(r.value == "organizations/1/locations/global/firewallPolicies/pol-hfw"
               for r in rules)


# -- committed terraform fixture ----------------------------------------------


def test_tf_plan_fixture_rule_and_association():
    claims = terraform_plan_claims(load("hfw_tf_plan.json"))
    rule = only(claims, "firewall_policy_rule")
    assert rule.fields()["rule"]["action"] == "allow"
    assert rule.fields()["rule"]["priority"] == 200
    assert rule.fields()["rule"]["match"]["src_ip_ranges"] == ["0.0.0.0/0"]
    assert rule.fields()["rule"]["match"]["layer4"] == [{"protocol": "tcp",
                                                         "ports": ["3389"]}]
    # the rule and the association each reference the (existing) policy.
    refs = kinds(claims, "firewall_policy_ref")
    assert len(refs) == 2
    assert {r.value for r in refs} == {
        "organizations/1/locations/global/firewallPolicies/pol-hfw"}
    # the association attaches to folders/2.
    node = only(claims, "hierarchy_node_ref")
    assert node.value == "folders/2"


# -- a rule resource: exactly one ref and one rule ----------------------------


def test_rule_resource_emits_one_ref_and_one_rule():
    after = {"firewall_policy": "orgpol-1", "priority": 200, "action": "allow",
             "direction": "INGRESS", "disabled": False,
             "match": [{"src_ip_ranges": ["0.0.0.0/0"], "dest_ip_ranges": [],
                        "layer4_config": [{"ip_protocol": "tcp", "ports": ["3389"]}]}]}
    claims = _RULE("google_compute_firewall_policy_rule.r", after)
    assert len(kinds(claims, "firewall_policy_rule")) == 1
    assert len(kinds(claims, "firewall_policy_ref")) == 1
    assert only(claims, "firewall_policy_ref").value == "orgpol-1"


# -- a policy resource: no self-referential ref -------------------------------


def test_policy_resource_has_no_self_ref():
    after = {"short_name": "pol-hfw", "parent": "folders/2"}
    claims = _POLICY("google_compute_firewall_policy.p", after)
    assert kinds(claims, "firewall_policy_ref") == []
    assert only(claims, "hierarchy_node_ref").value == "folders/2"


# -- secure tags: plain name yes, tagValues/123 no ----------------------------


def test_tag_values_reference_yields_no_network_tag_ref():
    after = {"firewall_policy": "orgpol-1", "priority": 10, "action": "allow",
             "direction": "INGRESS",
             "match": [{"src_ip_ranges": ["0.0.0.0/0"], "layer4_config": []}],
             "target_secure_tags": [{"name": "web"}, {"name": "tagValues/123"}],
             "target_service_accounts": ["sa@acme.iam.gserviceaccount.com"]}
    claims = _RULE("google_compute_firewall_policy_rule.r", after)
    tags = kinds(claims, "network_tag_ref")
    assert [t.value for t in tags] == ["web"]
    # the numeric tag is skipped, not turned into a bogus network tag.
    assert "tagValues/123" not in {t.value for t in tags}
    # a service-account reference is emitted per target service account.
    assert only(claims, "service_account_ref").value == \
        "sa@acme.iam.gserviceaccount.com"


# -- unresolved interpolation: no ref, no crash -------------------------------


@pytest.mark.parametrize("fp", ["${google_compute_firewall_policy.p.id}", None, ""])
def test_unresolved_firewall_policy_yields_no_ref(fp):
    after = {"priority": 5, "action": "allow", "direction": "INGRESS",
             "match": [{"src_ip_ranges": ["0.0.0.0/0"], "layer4_config": []}]}
    if fp is not None:
        after["firewall_policy"] = fp
    claims = _RULE("google_compute_firewall_policy_rule.r", after)
    # the rule is still emitted...
    assert len(kinds(claims, "firewall_policy_rule")) == 1
    # ...but no reference to a policy whose final name is unknown.
    assert kinds(claims, "firewall_policy_ref") == []


def test_association_unresolved_policy_yields_no_ref():
    after = {"firewall_policy": "${google_compute_firewall_policy.p.id}",
             "attachment_target": "folders/2"}
    claims = _ASSOCIATION("google_compute_firewall_policy_association.a", after)
    assert kinds(claims, "firewall_policy_ref") == []
    assert only(claims, "hierarchy_node_ref").value == "folders/2"


# -- unsupported shapes are flagged, never dropped ----------------------------


def _one_rule(rule: dict) -> Claim:
    doc = {"name": "organizations/1/locations/global/firewallPolicies/p",
           "rules": [rule]}
    return only(firewall_policy_claims(doc), "firewall_policy_rule")


def test_unsupported_action():
    claim = _one_rule({"priority": 1, "action": "reject", "direction": "INGRESS",
                       "match": {"srcIpRanges": ["0.0.0.0/0"]}})
    assert "action" in claim.fields()["unsupported"]


def test_unsupported_non_integer_priority():
    claim = _one_rule({"priority": "high", "action": "allow", "direction": "INGRESS",
                       "match": {"srcIpRanges": ["0.0.0.0/0"]}})
    assert "priority" in claim.fields()["unsupported"]


def test_unsupported_boolean_priority_is_not_an_integer():
    claim = _one_rule({"priority": True, "action": "allow", "direction": "INGRESS",
                       "match": {"srcIpRanges": ["0.0.0.0/0"]}})
    assert "priority" in claim.fields()["unsupported"]


def test_unsupported_absent_match():
    claim = _one_rule({"priority": 1, "action": "allow", "direction": "INGRESS"})
    assert "match" in claim.fields()["unsupported"]


def test_unsupported_no_ranges_in_declared_direction():
    claim = _one_rule({"priority": 1, "action": "allow", "direction": "INGRESS",
                       "match": {"srcIpRanges": [], "destIpRanges": []}})
    assert "range" in claim.fields()["unsupported"].lower()


# -- detect_kind: firewall_policy, not security_policy ------------------------


def test_detect_kind_firewall_policy_not_security_policy():
    doc = load("hfw_policy.json")
    if "firewall_policy" in DOCUMENT_KINDS:
        # sx-detect-kind has landed: the org-level policy is a firewall policy.
        assert detect_kind(doc) == "firewall_policy"
        assert detect_kind(doc) != "security_policy"
    else:
        # In this isolated checkout detect_kind does not yet know the six
        # security domains. Verify the fixture carries the exact disambiguator
        # the merged detect_kind keys on — a rule with a `direction` and a
        # `match` bearing CIDR fields — so it will resolve to firewall_policy
        # (which is checked before security_policy) rather than a Cloud Armor
        # security policy (whose rules never carry `direction`).
        assert detect_kind(doc) in (None, "firewall_policy")
        rule = doc["rules"][0]
        assert "direction" in rule
        assert set(rule["match"]) & {"srcIpRanges", "destIpRanges"}
        assert "versionedExpr" not in rule["match"]
