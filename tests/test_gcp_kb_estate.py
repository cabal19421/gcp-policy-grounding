"""Tests for the seven record-table estate categories added to
:class:`GcpSnapshot`: firewall_rules, hierarchical_firewall_policies,
cloud_armor_policies, vpc_sc_perimeters, resource_hierarchy, iam_bindings and
org_policies.

They carry the same UNKNOWN-vs-absent honesty contract as the flat
vocabularies, but their records nest list-valued fields whose ORDER is semantic
(rule/hierarchy order), so those fields normalize to tuples without sorting and
must survive a to_dict/from_dict round-trip exactly.
"""

import json
import re
from pathlib import Path

import pytest

from gcp_grounding.knowledge import UNKNOWN, GcpSnapshot

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
SNAPSHOT_PATH = FIXTURES / "snapshot.json"

RECORD_TABLES = (
    "firewall_rules", "hierarchical_firewall_policies", "cloud_armor_policies",
    "vpc_sc_perimeters", "resource_hierarchy", "iam_bindings", "org_policies",
)

# A fully-populated snapshot exercising every table, every field, and every
# nested list — including the ones whose order is semantic.
FULL = {
    "captured_at": "2026-07-18T09:30:00Z",
    "firewall_rules": {
        "projects/acme-prod/global/firewalls/allow-web": {
            "network": "projects/acme-prod/global/networks/vpc-main",
            "direction": "INGRESS",
            "action": "allow",
            "priority": 1000,
            "disabled": False,
            "source_ranges": ["0.0.0.0/0"],
            "destination_ranges": [],
            "source_tags": [],
            "target_tags": ["web"],
            "source_service_accounts": [],
            "target_service_accounts": [],
            "layer4": [{"protocol": "tcp", "ports": ["80", "443"]}],
        },
        "projects/acme-prod/global/firewalls/deny-ssh": {
            "network": "projects/acme-prod/global/networks/vpc-other",
            "direction": "INGRESS",
            "action": "deny",
            "priority": 900,
            "disabled": False,
            "source_ranges": ["10.0.0.0/8"],
            "destination_ranges": [],
            "source_tags": [],
            "target_tags": [],
            "source_service_accounts": [],
            "target_service_accounts": [],
            "layer4": [{"protocol": "tcp", "ports": ["22"]}],
        },
    },
    "hierarchical_firewall_policies": {
        "organizations/1/locations/global/firewallPolicies/pol-1": {
            "attachments": ["organizations/1", "folders/2"],
            "rules": [
                {"priority": 100, "action": "deny", "direction": "INGRESS",
                 "disabled": False,
                 "match": {"src_ip_ranges": ["0.0.0.0/0"], "dest_ip_ranges": [],
                           "layer4": [{"protocol": "tcp", "ports": ["3389"]}]},
                 "target_resources": [], "target_service_accounts": [],
                 "target_secure_tags": []},
            ],
        },
    },
    "cloud_armor_policies": {
        "projects/acme-prod/global/securityPolicies/edge": {
            "type": "CLOUD_ARMOR_EDGE",
            "rules": [
                {"priority": 1000, "action": "deny(403)", "preview": False,
                 "match": {"src_ip_ranges": ["1.2.3.0/24"],
                           "versioned_expr": "SRC_IPS_V1", "expr": None}},
            ],
        },
    },
    "vpc_sc_perimeters": {
        "accessPolicies/123/servicePerimeters/prod": {
            "perimeter_type": "PERIMETER_TYPE_REGULAR",
            "use_explicit_dry_run_spec": True,
            "status": {"resources": ["projects/111"],
                       "restricted_services": ["storage.googleapis.com"],
                       "access_levels": ["accessPolicies/123/accessLevels/trusted"],
                       "ingress_policies": [], "egress_policies": []},
            "spec": None,
        },
    },
    "resource_hierarchy": {
        "organizations/1": {"parent": None, "type": "organization",
                            "number": "1", "display_name": "acme"},
        "folders/2": {"parent": "organizations/1", "type": "folder",
                      "number": "2", "display_name": "prod"},
        "projects/acme-prod": {"parent": "folders/2", "type": "project",
                               "number": "123456", "display_name": "Acme Prod"},
    },
    "iam_bindings": {
        "//cloudresourcemanager.googleapis.com/projects/acme-prod": {
            "bindings": [
                {"role": "roles/owner", "members": ["user:alice@acme.example"],
                 "condition": None},
                {"role": "roles/viewer", "members": ["group:data-eng@acme.example"],
                 "condition": {"title": "biz-hours", "expression": "true"}},
            ],
        },
    },
    "org_policies": {
        "projects/acme-prod|constraints/compute.requireShieldedVm": {
            "node": "projects/acme-prod",
            "constraint": "constraints/compute.requireShieldedVm",
            "reset": False,
            "inherit_from_parent": False,
            "rules": [{"enforce": True, "allow_all": None, "deny_all": None,
                       "allowed_values": [], "denied_values": [], "condition": None}],
        },
    },
}


def _full() -> GcpSnapshot:
    return GcpSnapshot.from_dict(FULL)


def _empty() -> GcpSnapshot:
    return GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z"})


# -- round-trip -----------------------------------------------------------


def test_round_trip_exact_fully_populated():
    snap = _full()
    assert snap.captured_categories() == RECORD_TABLES
    clone = GcpSnapshot.from_dict(snap.to_dict())
    assert clone == snap
    assert clone.to_dict() == snap.to_dict()
    # to_dict must be plain, JSON-serializable data (no stray tuples).
    json.dumps(snap.to_dict())


def test_round_trip_preserves_list_order_not_sorted():
    # layer4 ports and firewall priority order are semantic — never sorted.
    snap = _full()
    rule = snap.firewall_rule("projects/acme-prod/global/firewalls/allow-web")
    assert rule["layer4"][0]["ports"] == ("80", "443")
    # attachments keep source order too.
    pol = snap.hierarchical_firewall_policy(
        "organizations/1/locations/global/firewallPolicies/pol-1")
    assert pol["attachments"] == ("organizations/1", "folders/2")


def test_none_captured_round_trip_and_no_leak():
    snap = _empty()
    clone = GcpSnapshot.from_dict(snap.to_dict())
    assert clone == snap
    for table in RECORD_TABLES:
        assert table not in snap.to_dict()


# -- accessors: UNKNOWN when uncaptured -----------------------------------


def test_single_key_accessors_unknown_when_uncaptured():
    snap = _empty()
    assert snap.firewall_rule("x") is UNKNOWN
    assert snap.hierarchical_firewall_policy("x") is UNKNOWN
    assert snap.cloud_armor_policy("x") is UNKNOWN
    assert snap.vpc_sc_perimeter("x") is UNKNOWN
    assert snap.hierarchy_node("x") is UNKNOWN
    assert snap.iam_binding_set("x") is UNKNOWN
    assert snap.org_policy("n", "c") is UNKNOWN


def test_table_wide_accessors_unknown_when_uncaptured():
    snap = _empty()
    assert snap.firewall_rules_for_network("net") is UNKNOWN
    assert snap.firewall_policies_attached_to("organizations/1") is UNKNOWN
    assert snap.hierarchy_names() is UNKNOWN


def test_uncaptured_accessor_refuses_truthiness():
    snap = _empty()
    with pytest.raises(TypeError):
        bool(snap.firewall_rule("x"))


# -- accessors: None for a missing key inside a captured table ------------


def test_single_key_accessors_none_for_missing_key_when_captured():
    snap = _full()
    assert snap.firewall_rule("projects/acme-prod/global/firewalls/ghost") is None
    assert snap.hierarchical_firewall_policy(
        "organizations/1/locations/global/firewallPolicies/ghost") is None
    assert snap.cloud_armor_policy(
        "projects/acme-prod/global/securityPolicies/ghost") is None
    assert snap.vpc_sc_perimeter(
        "accessPolicies/123/servicePerimeters/ghost") is None
    assert snap.hierarchy_node("projects/ghost") is None
    assert snap.iam_binding_set("//cloudresourcemanager.googleapis.com/projects/ghost") is None
    assert snap.org_policy("projects/ghost", "constraints/x") is None


def test_single_key_accessors_return_the_record_when_present():
    snap = _full()
    assert snap.firewall_rule(
        "projects/acme-prod/global/firewalls/allow-web")["action"] == "allow"
    assert snap.cloud_armor_policy(
        "projects/acme-prod/global/securityPolicies/edge")["type"] == "CLOUD_ARMOR_EDGE"
    per = snap.vpc_sc_perimeter("accessPolicies/123/servicePerimeters/prod")
    assert per["use_explicit_dry_run_spec"] is True and per["spec"] is None
    bset = snap.iam_binding_set(
        "//cloudresourcemanager.googleapis.com/projects/acme-prod")
    assert bset["bindings"][0]["role"] == "roles/owner"


# -- hierarchy number alias -----------------------------------------------


def test_hierarchy_node_resolves_project_number_alias():
    snap = _full()
    node = snap.hierarchy_node("projects/123456")
    assert node is not None
    assert node["display_name"] == "Acme Prod"
    # same record as the canonical id-keyed lookup.
    assert node == snap.hierarchy_node("projects/acme-prod")


def test_hierarchy_names_includes_project_number_alias():
    snap = _full()
    names = snap.hierarchy_names()
    assert "projects/123456" in names
    assert "projects/acme-prod" in names
    # organizations/folders keep their number but get NO projects/<n> alias.
    assert "projects/1" not in names
    assert "projects/2" not in names


# -- firewall_rules_for_network -------------------------------------------


def test_firewall_rules_for_network_filters_by_network():
    snap = _full()
    rules = snap.firewall_rules_for_network(
        "projects/acme-prod/global/networks/vpc-main")
    assert len(rules) == 1
    assert all(r["network"] == "projects/acme-prod/global/networks/vpc-main"
               for r in rules)


def test_firewall_rules_for_network_empty_tuple_when_captured_but_no_match():
    snap = _full()
    assert snap.firewall_rules_for_network(
        "projects/acme-prod/global/networks/nope") == ()


def test_firewall_rules_for_network_unknown_when_uncaptured():
    assert _empty().firewall_rules_for_network("net") is UNKNOWN


def test_firewall_policies_attached_to_filters_by_node():
    snap = _full()
    assert len(snap.firewall_policies_attached_to("organizations/1")) == 1
    assert len(snap.firewall_policies_attached_to("folders/2")) == 1
    assert snap.firewall_policies_attached_to("folders/999") == ()


# -- org_policy: node/constraint composite key ----------------------------


def test_org_policy_returns_effective_set_policy():
    snap = _full()
    rec = snap.org_policy("projects/acme-prod",
                          "constraints/compute.requireShieldedVm")
    assert rec is not None
    assert rec["rules"][0]["enforce"] is True


def test_org_policy_none_for_uncaptured_node_inside_captured_table():
    snap = _full()
    assert snap.org_policy("projects/other",
                           "constraints/compute.requireShieldedVm") is None


def test_org_policy_unknown_when_table_uncaptured():
    assert _empty().org_policy("projects/acme-prod", "constraints/x") is UNKNOWN


# -- missing required field fails loudly, naming table and key ------------


def test_firewall_missing_network_raises_naming_table_and_key():
    key = "projects/acme-prod/global/firewalls/x"
    with pytest.raises(ValueError) as ei:
        GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z",
                               "firewall_rules": {key: {"direction": "INGRESS",
                                                        "action": "allow"}}})
    msg = str(ei.value)
    assert "firewall_rules" in msg and key in msg and "network" in msg


def test_firewall_bad_direction_raises():
    with pytest.raises(ValueError, match="direction"):
        GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z",
                               "firewall_rules": {"projects/p/global/firewalls/x":
                                                  {"network": "n", "direction": "BOTH",
                                                   "action": "allow"}}})


def test_hierarchy_missing_type_raises_naming_table_and_key():
    with pytest.raises(ValueError) as ei:
        GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z",
                               "resource_hierarchy": {"projects/p": {"parent": None}}})
    msg = str(ei.value)
    assert "resource_hierarchy" in msg and "projects/p" in msg


def test_hierarchy_missing_parent_key_raises():
    with pytest.raises(ValueError, match="parent"):
        GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z",
                               "resource_hierarchy": {"projects/p": {"type": "project"}}})


def test_org_policy_missing_node_raises_naming_table_and_key():
    key = "projects/p|constraints/c"
    with pytest.raises(ValueError) as ei:
        GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z",
                               "org_policies": {key: {"constraint": "constraints/c"}}})
    msg = str(ei.value)
    assert "org_policies" in msg and key in msg and "node" in msg


# -- org_policies composite-key integrity ---------------------------------


def test_org_policy_key_without_bar_raises_naming_key():
    with pytest.raises(ValueError, match=re.escape("projects/p")):
        GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z",
                               "org_policies": {"projects/p": {"node": "projects/p",
                                                               "constraint": "c"}}})


def test_org_policy_key_with_two_bars_raises_naming_key():
    key = "projects/p|constraints/c|extra"
    with pytest.raises(ValueError, match=re.escape(key)):
        GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z",
                               "org_policies": {key: {"node": "projects/p",
                                                      "constraint": "constraints/c"}}})


def test_org_policy_key_halves_must_match_record():
    key = "projects/acme-prod|constraints/compute.requireShieldedVm"
    with pytest.raises(ValueError, match=re.escape(key)):
        GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z",
                               "org_policies": {key: {
                                   "node": "projects/other",
                                   "constraint": "constraints/compute.requireShieldedVm"}}})


# -- org_policies is distinct from constraints ----------------------------


def test_org_policies_and_constraints_coexist():
    # The constraint DEFINITION and its EFFECTIVE set-policy at a node are two
    # separate categories; capturing one must not answer the other.
    snap = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T09:30:00Z",
        "constraints": {"constraints/compute.requireShieldedVm": {"value_type": "boolean"}},
        "org_policies": {"projects/acme-prod|constraints/compute.requireShieldedVm": {
            "node": "projects/acme-prod",
            "constraint": "constraints/compute.requireShieldedVm",
            "rules": [{"enforce": True}]}},
    })
    assert snap.constraint("constraints/compute.requireShieldedVm")["value_type"] == "boolean"
    assert snap.org_policy("projects/acme-prod",
                           "constraints/compute.requireShieldedVm")["rules"][0]["enforce"] is True


# -- committed fixture is undisturbed -------------------------------------


def test_committed_snapshot_still_five_captured_categories():
    snap = GcpSnapshot.load(SNAPSHOT_PATH)
    assert snap.captured_categories() == (
        "roles", "permissions", "principals", "constraints", "resource_types",
    )
    # The seven estate tables were never captured → every accessor abstains.
    assert snap.firewall_rule("x") is UNKNOWN
    assert snap.org_policy("n", "c") is UNKNOWN
    assert snap.hierarchy_names() is UNKNOWN
