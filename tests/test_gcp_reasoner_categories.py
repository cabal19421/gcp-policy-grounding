"""Reasoner tests for the ten estate existence kinds: each one grounds against
the fully captured estate snapshot, surfaces edit-distance suggestions on a
near miss, and abstains ('unverified', never 'ungrounded') when its category
was not captured — plus the additivity regression proving the expansion changed
nothing for the original five categories.

``network_tag`` is the documented asymmetric case: its members prove existence
but never absence, so a typo'd tag abstains against a *fully captured*
snapshot instead of blocking a legitimate firewall change.
"""

import json
from pathlib import Path

import pytest

from gcp_grounding.claims import Claim, iam_policy_claims, org_policy_claims
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.reasoner import (
    EXISTENCE_KINDS,
    _enumerated,
    ground_existence,
    suggest,
)

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"

GHOST = "serviceAccount:ghost-runner@acme-prod.iam.gserviceaccount.com"

VPC_MAIN = "projects/acme-prod/global/networks/vpc-main"
SN_APP = "projects/acme-prod/regions/us-central1/subnetworks/sn-app"
ETL_SA = "etl-runner@acme-prod.iam.gserviceaccount.com"
TRUSTED = "accessPolicies/987/accessLevels/trusted_corp"
PERIMETER = "accessPolicies/987/servicePerimeters/prod"
FIREWALL_POLICY = "organizations/1/locations/global/firewallPolicies/fp-baseline"
SECURITY_POLICY = "projects/acme-prod/global/securityPolicies/edge-waf"

#: (claim kind, verdict kind, a name the estate snapshot proves exists,
#:  a near miss of it, the suggestion that near miss must surface).
ESTATE_KINDS = [
    ("network_ref", "network", VPC_MAIN,
     "projects/acme-prod/global/networks/vpc-mian", VPC_MAIN),
    ("subnetwork_ref", "subnetwork", SN_APP,
     "projects/acme-prod/regions/us-central1/subnetworks/sn-ap", SN_APP),
    ("network_tag_ref", "network_tag", "web", "bastian", "bastion"),
    ("service_account_ref", "service_account", ETL_SA,
     "etl-ruuner@acme-prod.iam.gserviceaccount.com", ETL_SA),
    ("access_level_ref", "access_level", TRUSTED,
     "accessPolicies/987/accessLevels/trusted_crop", TRUSTED),
    ("restricted_service_ref", "restricted_service", "storage.googleapis.com",
     "storag.googleapis.com", "storage.googleapis.com"),
    ("perimeter_ref", "perimeter", PERIMETER,
     "accessPolicies/987/servicePerimeters/prd", PERIMETER),
    ("firewall_policy_ref", "firewall_policy", FIREWALL_POLICY,
     "organizations/1/locations/global/firewallPolicies/fp-baselin", FIREWALL_POLICY),
    ("security_policy_ref", "security_policy", SECURITY_POLICY,
     "projects/acme-prod/global/securityPolicies/edge-wag", SECURITY_POLICY),
    ("hierarchy_node_ref", "hierarchy_node", "projects/acme-prod",
     "folders/22", "folders/2"),
]

#: The one category whose absence is never provable — see the presence-only
#: arm of ``_enumerated``.
PRESENCE_ONLY = "network_tag_ref"

TABLE_BACKED = ("perimeter_ref", "firewall_policy_ref", "security_policy_ref",
                "hierarchy_node_ref")


@pytest.fixture()
def snap() -> GcpSnapshot:
    """The original five-category vocabulary snapshot."""
    return GcpSnapshot.load(FIXTURES / "snapshot.json")


@pytest.fixture()
def estate() -> GcpSnapshot:
    """The fully captured estate snapshot: all ten new categories present."""
    return GcpSnapshot.load(FIXTURES / "estate_snapshot.json")


@pytest.fixture()
def partial() -> GcpSnapshot:
    """Vocabularies captured, record tables absent."""
    return GcpSnapshot.load(FIXTURES / "estate_partial_snapshot.json")


def load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


def ids(cases):
    return [case[0] for case in cases]


# -- grounded against the full estate snapshot ----------------------------


@pytest.mark.parametrize("kind,category,present,_miss,_hint", ESTATE_KINDS,
                         ids=ids(ESTATE_KINDS))
def test_estate_name_grounds(estate, kind, category, present, _miss, _hint):
    report = ground_existence([Claim(kind, present, "spec.ref")], estate)
    assert report.ok
    [v] = report.verdicts
    # The verdict kind is the category (the claim kind minus its _ref suffix).
    assert (v.status, v.kind, v.target) == ("grounded", category, present)


def test_hierarchy_node_grounds_through_the_number_alias(estate):
    # VPC-SC references a project by number while CRM keys it by id;
    # hierarchy_names() folds the alias in, so both spellings ground.
    report = ground_existence([
        Claim("hierarchy_node_ref", "projects/123456", "perimeter.resources[0]"),
        Claim("hierarchy_node_ref", "projects/acme-prod", "perimeter.resources[1]"),
    ], estate)
    assert report.ok
    assert [(v.status, v.kind) for v in report.verdicts] == [
        ("grounded", "hierarchy_node"), ("grounded", "hierarchy_node")]


# -- near misses: ungrounded with a suggestion ----------------------------


@pytest.mark.parametrize(
    "kind,category,_present,miss,hint",
    [case for case in ESTATE_KINDS if case[0] != PRESENCE_ONLY],
    ids=[case[0] for case in ESTATE_KINDS if case[0] != PRESENCE_ONLY])
def test_estate_near_miss_is_ungrounded_with_suggestion(
        estate, kind, category, _present, miss, hint):
    report = ground_existence([Claim(kind, miss, "spec.ref")], estate)
    assert not report.ok
    [v] = report.ungrounded
    assert (v.kind, v.target) == (category, miss)
    assert hint in v.suggestions
    names, _ = _enumerated(estate, category)
    assert set(v.suggestions) <= set(names)  # never invents a name


# -- the network_tag exception: a miss abstains, it never blocks ----------


def test_network_tag_members_prove_existence_but_never_absence(estate):
    # Presence-only: the members are usable, `captured` is reported False.
    names, captured = _enumerated(estate, "network_tag")
    assert names == frozenset({"bastion", "db", "web"})
    assert captured is False


def test_typod_network_tag_is_unverified_never_ungrounded(estate):
    # THE FALSE-POSITIVE GUARD. Against the FULLY CAPTURED estate snapshot a
    # tag that is not in `network_tags` still abstains, because GCP has no tag
    # registry: a tag exists as soon as a rule names it, so the captured set
    # is only ever a subset of reality.
    report = ground_existence([Claim("network_tag_ref", "bastian",
                                     "spec.source_tags[0]")], estate)
    assert report.ok  # abstain, not a block
    assert report.counts() == {"grounded": 0, "ungrounded": 0,
                               "contradicted": 0, "unverified": 1}
    [v] = report.by_status("unverified")
    assert (v.kind, v.target) == ("network_tag", "bastian")
    assert report.ungrounded == []
    # The suggester still finds the near miss off the captured vocabulary —
    # ground_existence renders suggestions on `ungrounded` verdicts only, so
    # the hint reaches a reviewer through the vocabulary, not the verdict.
    names, _ = _enumerated(estate, "network_tag")
    assert "bastion" in suggest("bastian", names)


def test_known_network_tag_still_grounds(estate):
    report = ground_existence([Claim("network_tag_ref", "web",
                                     "spec.target_tags[0]")], estate)
    assert [(v.status, v.kind, v.target) for v in report.verdicts] == [
        ("grounded", "network_tag", "web")]


# -- uncaptured categories abstain: the honesty invariant -----------------


@pytest.mark.parametrize("kind", [case[0] for case in ESTATE_KINDS
                                  if case[0] in TABLE_BACKED])
def test_table_backed_kinds_are_unverified_against_the_partial_snapshot(
        partial, kind):
    # estate_partial_snapshot.json captures the vocabularies but none of the
    # record tables.
    report = ground_existence([Claim(kind, "whatever-it-is", "spec.ref")], partial)
    assert report.ok
    assert report.counts() == {"grounded": 0, "ungrounded": 0,
                               "contradicted": 0, "unverified": 1}


@pytest.mark.parametrize("kind,category,present,_miss,_hint", ESTATE_KINDS,
                         ids=ids(ESTATE_KINDS))
def test_uncaptured_category_never_refutes(kind, category, present, _miss, _hint):
    # HONESTY INVARIANT: against a snapshot that captured nothing at all, a
    # claim of any new kind is exactly one 'unverified' — never 'ungrounded'.
    bare = GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z"})
    report = ground_existence([Claim(kind, present, "spec.ref")], bare)
    assert report.ok
    assert [(v.status, v.kind, v.target) for v in report.verdicts] == [
        ("unverified", category, present)]


def test_unknown_existence_kind_still_raises():
    bare = GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z"})
    with pytest.raises(ValueError, match="unknown existence kind"):
        _enumerated(bare, "wormhole")


# -- additivity regression: the original five are untouched ---------------


def test_good_iam_policy_still_all_grounded(snap):
    report = ground_existence(iam_policy_claims(load("iam_policy_good.json")), snap)
    assert report.ok
    assert report.counts() == {"grounded": 7, "ungrounded": 0,
                               "contradicted": 0, "unverified": 0}
    assert {v.kind for v in report.verdicts} == {"role", "principal"}


def test_bad_iam_policy_still_yields_the_same_two_ungrounded(snap):
    report = ground_existence(iam_policy_claims(load("iam_policy_bad.json")), snap)
    assert {(v.kind, v.target) for v in report.ungrounded} == {
        ("role", "roles/bigquery.reader"),
        ("principal", GHOST),
    }
    assert report.counts() == {"grounded": 4, "ungrounded": 2,
                               "contradicted": 0, "unverified": 0}
    [reader] = [v for v in report.ungrounded if v.kind == "role"]
    assert "roles/bigquery.dataViewer" in reader.suggestions


def test_good_org_policy_still_one_grounded_constraint(snap):
    report = ground_existence(org_policy_claims(load("org_policy_good.json")), snap)
    assert [(v.status, v.kind, v.target) for v in report.verdicts] == [
        ("grounded", "constraint",
         "constraints/iam.disableServiceAccountKeyCreation")]


def test_resource_type_ref_still_verdicts_as_resource_type(snap):
    report = ground_existence(
        [Claim("resource_type_ref", "compute.googleapis.com/Instance",
               "resources[0].type")], snap)
    [v] = report.verdicts
    assert (v.status, v.kind) == ("grounded", "resource_type")


@pytest.mark.parametrize("kind,category,present,_miss,_hint", ESTATE_KINDS,
                         ids=ids(ESTATE_KINDS))
def test_new_kinds_are_purely_additive_over_the_old_snapshot(
        snap, kind, category, present, _miss, _hint):
    # The five-category snapshot never captured these categories, so the ten
    # new kinds cannot retroactively refute anything it said.
    report = ground_existence([Claim(kind, present, "spec.ref")], snap)
    assert report.ok
    assert report.counts() == {"grounded": 0, "ungrounded": 0,
                               "contradicted": 0, "unverified": 1}
    [v] = report.verdicts
    assert (v.kind, v.target) == (category, present)


def test_every_new_kind_is_an_existence_kind_and_a_claim_kind():
    for kind, _category, _present, _miss, _hint in ESTATE_KINDS:
        assert kind in EXISTENCE_KINDS
        Claim(kind, "some-name", "some.location")
