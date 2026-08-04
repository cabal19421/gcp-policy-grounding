"""Cloud Armor claim extraction: the REST and Terraform spellings of a
security policy / rule normalise to one field layout, the default rule and its
``["*"]`` wildcard are recognised, a standalone rule references its policy while
a full policy does not, unsupported shapes abstain, and the document kind is
detected as ``security_policy`` — never a neighbouring domain."""

import json
from pathlib import Path

from gcp_grounding import registry
from gcp_grounding.armor_claims import (
    DEFAULT_RULE_PRIORITY,
    DOCUMENT_EXTRACTORS,
    TF_EXTRACTORS,
    _tf_security_policy_claims,
    _tf_security_policy_rule_claims,
    security_policy_claims,
)
from gcp_grounding.preflight import DOCUMENT_KINDS, detect_kind
from gcp_grounding.tf_claims import terraform_plan_claims

POLICIES = Path(__file__).parent / "fixtures" / "gcp" / "policies"


def _load(name):
    return json.loads((POLICIES / name).read_text())


def _rules(claims):
    return [c for c in claims if c.kind == "security_policy_rule"]


def _normal(fields):
    """Just the normalised-rule keys of a claim payload — dropping the
    document-context keys (``policy`` / ``rule_count`` / …) so a REST rule and a
    Terraform rule can be compared directly."""
    return {k: fields[k] for k in ("priority", "action", "preview", "match")}


# -- REST fixture: the whole policy ------------------------------------------


def test_detect_kind_is_security_policy_not_a_neighbour():
    # Recognising ``security_policy`` is the ``sx-detect-kind`` task, which is
    # not part of this isolated worktree — so branch on whether it has landed.
    # Either way the fixture must never read as a neighbouring domain, and must
    # carry the Cloud Armor disambiguator (an ``action``+``match`` rule, and no
    # rule with a ``direction`` key — that would make it a firewall policy) so
    # it *will* classify as ``security_policy`` once detection lands.
    doc = _load("armor_policy.json")
    kind = detect_kind(doc)
    assert kind not in ("firewall_policy", "iam_deny_policy")
    if "security_policy" in DOCUMENT_KINDS:
        assert kind == "security_policy"
    else:
        assert kind in (None, "security_policy")
    rules = doc["rules"]
    assert all("direction" not in r for r in rules)
    assert any(isinstance(r.get("action"), str) and isinstance(r.get("match"), dict)
               for r in rules)


def test_rest_policy_emits_one_rule_claim_each_and_no_ref_for_itself():
    claims = security_policy_claims(_load("armor_policy.json"))
    assert len(_rules(claims)) == 3
    assert all(c.kind == "security_policy_rule" for c in claims)
    # A full policy makes no existence claim about *itself*.
    assert not any(c.kind == "security_policy_ref" for c in claims)


def test_first_rule_of_a_document_marks_policy_document():
    rules = _rules(security_policy_claims(_load("armor_policy.json")))
    assert rules[0].fields().get("policy_document") is True
    assert all("policy_document" not in c.fields() for c in rules[1:])


def test_document_rules_carry_policy_count_and_has_default():
    for c in _rules(security_policy_claims(_load("armor_policy.json"))):
        fields = c.fields()
        assert fields["policy"] == "armor-policy-prod"
        assert fields["rule_count"] == 3
        assert fields["has_default"] is True


def test_deny_403_action_survives_verbatim():
    first = _rules(security_policy_claims(_load("armor_policy.json")))[0]
    assert first.fields()["action"] == "deny-403"


def test_wildcard_normalizes_and_is_default_only_at_reserved_priority():
    rules = _rules(security_policy_claims(_load("armor_policy.json")))
    by_priority = {c.fields()["priority"]: c.fields() for c in rules}

    default = by_priority[DEFAULT_RULE_PRIORITY]
    assert default["match"]["src_ip_ranges"] == ["0.0.0.0/0"]  # ["*"] normalised
    assert default["is_default"] is True

    for priority, fields in by_priority.items():
        if priority != DEFAULT_RULE_PRIORITY:
            assert "is_default" not in fields


# -- Terraform fixture: a standalone rule ------------------------------------


def test_standalone_rule_emits_exactly_one_security_policy_ref():
    claims = terraform_plan_claims(_load("armor_tf_plan.json"))
    refs = [c for c in claims if c.kind == "security_policy_ref"]
    assert len(refs) == 1
    assert refs[0].value == "armor-policy-prod"
    assert len(_rules(claims)) == 1


def test_standalone_rule_never_marks_policy_document():
    rule = _rules(terraform_plan_claims(_load("armor_tf_plan.json")))[0]
    assert "policy_document" not in rule.fields()


def test_unresolved_security_policy_interpolation_emits_no_ref():
    interpolation = "${google_compute_security_policy.p.id}"
    values = {"priority": 1, "action": "allow",
              "match": [{"config": [{"src_ip_ranges": ["0.0.0.0/0"]}]}],
              "security_policy": interpolation}
    claims = _tf_security_policy_rule_claims("google_compute_security_policy_rule.r",
                                             values)
    assert [c.kind for c in claims] == ["security_policy_rule"]


# -- REST and Terraform agree ------------------------------------------------


def test_rest_and_terraform_normalizations_agree():
    rest_doc = {"kind": "compute#securityPolicy", "name": "p", "rules": [
        {"priority": 1, "action": "allow", "preview": False,
         "match": {"config": {"srcIpRanges": ["0.0.0.0/0"]}}}]}
    tf_values = {"name": "p", "rule": [
        {"priority": 1, "action": "allow", "preview": False,
         "match": [{"config": [{"src_ip_ranges": ["0.0.0.0/0"]}]}]}]}

    rest = _rules(security_policy_claims(rest_doc))[0].fields()
    tf = _rules(_tf_security_policy_claims("google_compute_security_policy.p",
                                           tf_values))[0].fields()
    assert _normal(rest) == _normal(tf)
    assert _normal(rest) == {
        "priority": 1, "action": "allow", "preview": False,
        "match": {"src_ip_ranges": ["0.0.0.0/0"], "versioned_expr": None, "expr": None},
    }


# -- unsupported shapes abstain, they are never dropped ----------------------


def _only(doc):
    rules = _rules(security_policy_claims(doc))
    assert len(rules) == 1
    return rules[0].fields()


def test_both_versioned_expr_and_expr_is_unsupported():
    doc = {"name": "p", "rules": [
        {"priority": 100, "action": "deny-403", "match": {
            "versionedExpr": "SRC_IPS_V1",
            "config": {"srcIpRanges": ["203.0.113.0/24"]},
            "expr": {"expression": "inIpRange(origin.ip, '203.0.113.0/24')"}}}]}
    assert "unsupported" in _only(doc)


def test_non_integer_priority_is_unsupported():
    doc = {"name": "p", "rules": [
        {"priority": "1000", "action": "allow",
         "match": {"config": {"srcIpRanges": ["0.0.0.0/0"]}}}]}
    assert "unsupported" in _only(doc)


def test_unknown_action_is_unsupported():
    doc = {"name": "p", "rules": [
        {"priority": 1, "action": "quarantine",
         "match": {"config": {"srcIpRanges": ["0.0.0.0/0"]}}}]}
    assert "unsupported" in _only(doc)


def test_match_without_config_or_expr_is_unsupported():
    doc = {"name": "p", "rules": [
        {"priority": 1, "action": "allow", "match": {"versionedExpr": "SRC_IPS_V1"}}]}
    assert "unsupported" in _only(doc)


def test_supported_action_verbs_all_normalize():
    for action in ("allow", "deny", "deny-403", "deny-404", "deny-502",
                   "rate_based_ban", "throttle", "redirect"):
        doc = {"name": "p", "rules": [
            {"priority": 1, "action": action,
             "match": {"config": {"srcIpRanges": ["0.0.0.0/0"]}}}]}
        assert _only(doc)["action"] == action


# -- wiring ------------------------------------------------------------------


def test_module_wires_document_and_tf_extractors():
    assert DOCUMENT_EXTRACTORS["security_policy"] is security_policy_claims
    assert TF_EXTRACTORS["google_compute_security_policy"] is _tf_security_policy_claims
    assert (TF_EXTRACTORS["google_compute_security_policy_rule"]
            is _tf_security_policy_rule_claims)


def test_registry_discovers_the_armor_extractors():
    registry.reset_cache()
    try:
        assert registry.document_extractor("security_policy") is security_policy_claims
        tf = registry.tf_extractors()
        assert tf.get("google_compute_security_policy") is _tf_security_policy_claims
        assert (tf.get("google_compute_security_policy_rule")
                is _tf_security_policy_rule_claims)
    finally:
        registry.reset_cache()
