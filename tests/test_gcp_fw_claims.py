"""VPC firewall claim-extraction tests: the REST (``compute#firewall``) and
Terraform (``google_compute_firewall``) spellings collapse to one normalized
mapping; the conservative skip rules of :mod:`gcp_grounding.claims` are honored;
and the target-tag / source-tag asymmetry that guards against a false
``ungrounded`` is pinned by value, not just by count."""

import json
from pathlib import Path

import pytest

from gcp_grounding import registry
from gcp_grounding.claims import Claim
from gcp_grounding.fw_claims import (
    detect_kind,
    firewall_rule_claims,
    normalize_network,
    normalize_rest,
    normalize_tf,
)
from gcp_grounding.tf_claims import terraform_plan_claims

POLICIES = Path(__file__).parent / "fixtures" / "gcp" / "policies"

SELF_LINK = ("https://www.googleapis.com/compute/v1/"
             "projects/acme-prod/global/networks/vpc-main")
CANONICAL = "projects/acme-prod/global/networks/vpc-main"


def load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def _fresh_registry():
    """Resolve the real PROVIDER_MODULES fresh, regardless of what a prior test
    module injected into the lazy provider cache."""
    registry.reset_cache()
    yield
    registry.reset_cache()


def of_kind(claims, kind):
    return [c for c in claims if c.kind == kind]


# -- REST and Terraform produce one identical normalized payload --------------


def test_rest_and_tf_spellings_normalize_identically():
    rest = load("fw_rule_good.json")
    tf_values = {
        "name": "fw-allow-web",
        "network": SELF_LINK,
        "direction": "INGRESS",
        "priority": 1000,
        "disabled": False,
        "source_ranges": ["10.0.0.0/8"],
        "target_tags": ["web"],
        "allow": [{"protocol": "tcp", "ports": ["443"]}],
    }
    normalized = normalize_rest(rest)
    assert normalize_tf(tf_values) == normalized
    # The full contract, spelled out once.
    assert normalized == {
        "name": "fw-allow-web",
        "network": CANONICAL,
        "direction": "INGRESS",
        "action": "allow",
        "priority": 1000,
        "disabled": False,
        "source_ranges": ["10.0.0.0/8"],
        "destination_ranges": [],
        "source_tags": [],
        "target_tags": ["web"],
        "source_service_accounts": [],
        "target_service_accounts": [],
        "layer4": [{"protocol": "tcp", "ports": ["443"]}],
    }


def test_firewall_rule_payload_round_trips_the_whole_mapping():
    [claim] = of_kind(firewall_rule_claims(load("fw_rule_good.json")), "firewall_rule")
    assert claim.value == "fw-allow-web"
    assert claim.location == "name"
    assert claim.fields() == normalize_rest(load("fw_rule_good.json"))


# -- the target-tag / source-tag false-positive guard -------------------------


def test_target_tags_emit_no_network_tag_ref_but_source_tags_do():
    doc = {
        "kind": "compute#firewall",
        "name": "fw-tags",
        "network": SELF_LINK,
        "sourceTags": ["bastion"],
        "targetTags": ["brand-new-tag"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
    }
    tag_refs = of_kind(firewall_rule_claims(doc), "network_tag_ref")
    # Exactly one, and it is the source tag — asserted by value: the brand-new
    # target tag must never reach the captured vocabulary as a reference.
    assert [c.value for c in tag_refs] == ["bastion"]
    assert "brand-new-tag" not in {c.value for c in tag_refs}


# -- every claim's location points at the exact field -------------------------


def test_rest_claim_locations_point_at_the_exact_field():
    doc = {
        "kind": "compute#firewall",
        "name": "fw-loc",
        "network": SELF_LINK,
        "sourceTags": ["bastion"],
        "sourceServiceAccounts": ["src@acme-prod.iam.gserviceaccount.com"],
        "targetServiceAccounts": ["serviceAccount:tgt@acme-prod.iam.gserviceaccount.com"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
    }
    claims = firewall_rule_claims(doc)
    located = {(c.kind, c.value): c.location for c in claims}
    assert located[("network_ref", CANONICAL)] == "network"
    assert located[("network_tag_ref", "bastion")] == "sourceTags[0]"
    # bare-email form: the leading serviceAccount: prefix is stripped.
    assert located[("service_account_ref",
                    "src@acme-prod.iam.gserviceaccount.com")] == "sourceServiceAccounts[0]"
    assert located[("service_account_ref",
                    "tgt@acme-prod.iam.gserviceaccount.com")] == "targetServiceAccounts[0]"
    assert located[("firewall_rule", "fw-loc")] == "name"


def test_tf_claim_locations_point_at_the_resource_address():
    plan = load("fw_tf_plan.json")
    claims = terraform_plan_claims(plan)
    located = {(c.kind, c.value): c.location for c in claims}
    addr = "google_compute_firewall.web"
    assert located[("network_ref", CANONICAL)] == f"{addr}.network"
    assert located[("network_tag_ref", "bastion")] == f"{addr}.source_tags[0]"
    assert located[("firewall_rule", "fw-allow-web")] == addr


# -- network canonicalization -------------------------------------------------


def test_self_link_network_normalizes():
    assert normalize_network(SELF_LINK) == CANONICAL


def test_already_canonical_network_passes_through():
    assert normalize_network(CANONICAL) == CANONICAL


def test_bare_network_name_yields_no_network_ref_and_no_crash():
    doc = {
        "kind": "compute#firewall",
        "name": "fw-bare",
        "network": "vpc-main",
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
    }
    claims = firewall_rule_claims(doc)  # must not raise
    assert of_kind(claims, "network_ref") == []
    # The rule itself is still claimed, carrying the network as written.
    [rule] = of_kind(claims, "firewall_rule")
    assert rule.fields()["network"] == "vpc-main"
    assert normalize_network("vpc-main") is None


# -- source ranges survive verbatim, never merged -----------------------------


def test_two_half_space_source_ranges_both_survive():
    doc = {
        "kind": "compute#firewall",
        "name": "fw-halves",
        "network": SELF_LINK,
        "sourceRanges": ["0.0.0.0/1", "128.0.0.0/1"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
    }
    assert normalize_rest(doc)["source_ranges"] == ["0.0.0.0/1", "128.0.0.0/1"]


# -- undecidable shapes: kept, flagged, never silently dropped ----------------


def test_rule_with_neither_allow_nor_deny_is_unsupported():
    doc = {
        "kind": "compute#firewall",
        "name": "fw-empty",
        "network": SELF_LINK,
    }
    normalized = normalize_rest(doc)
    assert "unsupported" in normalized
    assert "action" not in normalized and "layer4" not in normalized
    # The rule still becomes a claim, so it is never dropped from a comparison.
    [rule] = of_kind(firewall_rule_claims(doc), "firewall_rule")
    assert "unsupported" in rule.fields()


# -- the terraform plan hook --------------------------------------------------


def test_plan_fixture_yields_type_reference_plus_fw_claims_and_filters_provider():
    claims = terraform_plan_claims(load("fw_tf_plan.json"))
    kinds = {c.kind for c in claims}
    assert {"resource_type_ref", "firewall_rule", "network_ref",
            "network_tag_ref"} <= kinds
    assert Claim("resource_type_ref", "google_compute_firewall",
                 "google_compute_firewall.web") in claims
    # The random_id resource is filtered out by the google-provider gate: it
    # contributes neither a type reference nor any claim.
    assert not any("random_id" in c.location or c.value == "random_id"
                   for c in claims)


# -- document-kind detection --------------------------------------------------


def test_detect_kind_recognizes_a_rest_firewall_document():
    assert detect_kind(load("fw_rule_good.json")) == "firewall_rule"
    assert detect_kind(load("fw_rule_open.json")) == "firewall_rule"
    assert detect_kind({"kind": "compute#network"}) is None
    assert detect_kind(["not", "a", "mapping"]) is None
