"""Document-shape detection tests for :func:`gcp_grounding.preflight.detect_kind`.

The gate learns six new security document shapes (IAM deny policy, VPC-SC
service perimeter, access level, VPC firewall rule, hierarchical/network
firewall policy, Cloud Armor security policy) on top of the three it already
knew (IAM allow policy, Org Policy, terraform plan). Two things must hold at
once and this suite pins both:

* **Recognition** — every new kind is detected from both its REST/API
  (camelCase) spelling and its terraform-ish (snake_case / bare block) spelling.
* **No regression** — the seven committed fixtures, a bare ``{}``, a
  package.json-shaped document, and the snapshot fixture itself all classify
  exactly as they did before, and the four rules-shaped documents that could
  collide (IAM deny vs Org Policy v2, perimeter vs Org Policy, Cloud Armor vs
  firewall policy vs IAM deny) each resolve to the one right kind.
"""

import json
from pathlib import Path

import pytest

from gcp_grounding.gate import PolicyGroundingGate
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.preflight import DOCUMENT_KINDS, detect_kind, ground_policy

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"
SNAPSHOT = FIXTURES / "snapshot.json"


@pytest.fixture()
def snap() -> GcpSnapshot:
    return GcpSnapshot.load(SNAPSHOT)


# -- positive documents, one REST spelling and one terraform-ish per new kind --

#: kind -> {"rest": <camelCase/API document>, "tf": <snake_case/bare-block doc>}.
POSITIVE = {
    "iam_deny_policy": {
        # v3 deny policy: top-level `rules` list with a denyRule item.
        "rest": {"rules": [{"denyRule": {
            "deniedPrincipals": ["principalSet://goog/public:all"],
            "deniedPermissions": ["iam.serviceAccounts.getAccessToken"]}}]},
        # google_iam_deny_policy: snake_case deny_rule block.
        "tf": {"rules": [{"deny_rule": {
            "denied_principals": ["*"],
            "denied_permissions": ["iam.serviceAccounts.create"]}}]},
    },
    "vpc_sc_perimeter": {
        # REST perimeter: `…/servicePerimeters/…` name + a status block.
        "rest": {"name": "accessPolicies/123/servicePerimeters/prod",
                 "status": {"resources": ["projects/111"],
                            "restrictedServices": ["bigquery.googleapis.com"]}},
        # google_access_context_manager_service_perimeter: snake_case spec block.
        "tf": {"spec": {"restricted_services": ["storage.googleapis.com"],
                        "access_levels": ["accessPolicies/123/accessLevels/lvl"]}},
    },
    "access_level": {
        # REST access level: `…/accessLevels/…` name + a basic block.
        "rest": {"name": "accessPolicies/123/accessLevels/trusted",
                 "basic": {"conditions": [{"ipSubnetworks": ["10.0.0.0/8"]}]}},
        # google_access_context_manager_access_level: custom { expr } block.
        "tf": {"custom": {"expr": {"expression": "origin.region_code == 'US'"}}},
    },
    "firewall_rule": {
        # REST firewall: compute#firewall kind + `allowed` list.
        "rest": {"kind": "compute#firewall", "name": "allow-ssh",
                 "network": "projects/p/global/networks/default",
                 "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
        # google_compute_firewall: `network` + bare `allow` block.
        "tf": {"network": "default",
               "allow": [{"protocol": "tcp", "ports": ["22"]}]},
    },
    "firewall_policy": {
        # REST hierarchical firewall policy: compute#firewallPolicy kind.
        "rest": {"kind": "compute#firewallPolicy", "name": "orgfw",
                 "rules": [{"direction": "INGRESS", "action": "allow",
                            "match": {"srcIpRanges": ["10.0.0.0/8"]}}]},
        # google_compute_firewall_policy_rule: direction + snake_case match.
        "tf": {"rules": [{"direction": "INGRESS", "action": "deny",
                          "match": {"src_ip_ranges": ["0.0.0.0/0"]}}]},
    },
    "security_policy": {
        # REST Cloud Armor policy: compute#securityPolicy kind, no direction.
        "rest": {"kind": "compute#securityPolicy", "name": "armor",
                 "rules": [{"action": "deny(403)", "priority": 1000,
                            "match": {"versionedExpr": "SRC_IPS_V1",
                                      "config": {"srcIpRanges": ["1.2.3.4/32"]}}}]},
        # google_compute_security_policy: rule { action, match { expr } }.
        "tf": {"rules": [{"action": "allow", "priority": 2000,
                          "match": {"expr": {
                              "expression": "request.path.matches('/admin')"}}}]},
    },
}


@pytest.mark.parametrize("kind", list(POSITIVE))
@pytest.mark.parametrize("spelling", ["rest", "tf"])
def test_each_new_kind_detected_in_both_spellings(kind, spelling):
    assert kind in DOCUMENT_KINDS
    assert detect_kind(POSITIVE[kind][spelling]) == kind


# -- no regression: everything that classified as X before still does ---------

#: (fixture filename, expected kind) for the seven committed policy bundles.
_FIXTURE_EXPECTATIONS = [
    ("iam_policy_good.json", "iam_policy"),
    ("iam_policy_bad.json", "iam_policy"),
    ("org_policy_good.json", "org_policy"),
    ("org_policy_bad.json", "org_policy"),
    ("tf_plan_good.json", "tf_plan"),
    ("tf_plan_bad.json", "tf_plan"),
    ("tf_plan_full.json", "tf_plan"),
]


@pytest.mark.parametrize("name,expected", _FIXTURE_EXPECTATIONS)
def test_committed_fixtures_classify_exactly_as_before(name, expected):
    doc = json.loads((POLICIES / name).read_text(encoding="utf-8"))
    assert detect_kind(doc) == expected


def test_non_policy_shapes_still_classify_as_before():
    # A bare object, a package.json, and the snapshot fixture itself are not
    # policy documents and must stay None with the six new predicates in play.
    assert detect_kind({}) is None
    assert detect_kind({
        "name": "my-package", "version": "1.0.0",
        "dependencies": {"lodash": "^4.17.21"},
        "scripts": {"test": "jest"}}) is None
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert detect_kind(snapshot) is None


def test_non_mapping_input_is_none():
    assert detect_kind(["not", "an", "object"]) is None
    assert detect_kind("a string") is None


# -- the four rules-shaped collisions each resolve to the one right kind ------


def test_perimeter_with_spec_block_beats_org_policy():
    # A perimeter carries a `spec` block; without perimeter detection running
    # before the bare-`spec` Org Policy fallback this reads as an org_policy.
    perimeter = {"spec": {"restricted_services": ["storage.googleapis.com"],
                          "resources": ["projects/9"]}}
    assert detect_kind(perimeter) == "vpc_sc_perimeter"


def test_bare_spec_org_policy_still_detected():
    # The tightened bare-`spec` arm still fires for a genuine Org Policy v2
    # whose spec carries `rules` (and the committed name-arm fixtures too).
    assert detect_kind({"spec": {"rules": [{"enforce": True}]}}) == "org_policy"
    assert detect_kind({"spec": {"inheritFromParent": True}}) == "org_policy"
    # A spec block with none of the Org Policy v2 markers is NOT an org policy.
    assert detect_kind({"spec": {"displayName": "x"}}) is None


def test_cloud_armor_is_security_policy_not_deny_or_firewall_policy():
    armor = POSITIVE["security_policy"]["rest"]
    assert detect_kind(armor) == "security_policy"
    assert detect_kind(armor) not in ("iam_deny_policy", "firewall_policy")


def test_hierarchical_firewall_policy_is_not_security_policy():
    # Has a str `action` and a `match` (the security_policy shape) but also a
    # `direction` key — firewall-policy-first + the direction exclusion win.
    hfw = {"rules": [{"priority": 100, "direction": "INGRESS", "action": "allow",
                      "match": {"srcIpRanges": ["10.0.0.0/8"]}}]}
    assert detect_kind(hfw) == "firewall_policy"


def test_iam_deny_is_not_org_policy_or_security_policy():
    deny = POSITIVE["iam_deny_policy"]["rest"]
    assert detect_kind(deny) == "iam_deny_policy"


# -- an unrecognized document is None and grounds to an honest unverified -----


def test_unrecognized_document_is_none_and_unverified(snap):
    doc = {"totally": "unrelated"}
    assert detect_kind(doc) is None
    report = ground_policy(doc, snap)
    assert report.ok  # unverified never fails the gate
    [v] = report.verdicts
    assert (v.status, v.kind) == ("unverified", "document")
    assert "not recognized" in v.message


# -- gate: a .json of each new kind now sniffs as policy-relevant -------------


@pytest.mark.parametrize("kind", list(POSITIVE))
@pytest.mark.parametrize("spelling", ["rest", "tf"])
def test_gate_sniffs_each_new_kind_as_policy(kind, spelling, tmp_path):
    gate = PolicyGroundingGate(SNAPSHOT)
    path = tmp_path / f"{kind}_{spelling}.json"
    path.write_text(json.dumps(POSITIVE[kind][spelling]), encoding="utf-8")
    assert gate._sniffs_as_policy(str(path)) is True
