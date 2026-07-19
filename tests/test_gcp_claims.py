"""Claim-extraction tests: exact claims (kind + value + location) from the
shared fixture policies, plus the conservative skip rules — malformed or
request-time constructs yield no claim, never a guess."""

import json
from pathlib import Path

import pytest

from gcp_grounding.claims import KINDS, Claim, iam_policy_claims, org_policy_claims

POLICIES = Path(__file__).parent / "fixtures" / "gcp" / "policies"


def load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


# -- IAM policy fixtures: exact claims ------------------------------------


def test_iam_policy_good_exact_claims():
    assert iam_policy_claims(load("iam_policy_good.json")) == [
        Claim("role", "roles/bigquery.dataViewer", "bindings[0].role"),
        Claim("principal", "group:data-eng@acme.example", "bindings[0].members[0]"),
        Claim("principal", "user:alice@acme.example", "bindings[0].members[1]"),
        Claim("role", "roles/bigquery.jobUser", "bindings[1].role"),
        Claim("principal", "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com",
              "bindings[1].members[0]"),
        Claim("role", "roles/storage.objectViewer", "bindings[2].role"),
        Claim("principal", "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com",
              "bindings[2].members[0]"),
        Claim("cel", 'request.time < timestamp("2027-01-01T00:00:00Z")',
              "bindings[2].condition.expression"),
    ]


def test_iam_policy_bad_exact_claims():
    # Extraction does not judge: the hallucinated role, the ghost service
    # account and the never-true condition all still become claims — the
    # reasoner is what refutes them against the snapshot.
    assert iam_policy_claims(load("iam_policy_bad.json")) == [
        Claim("role", "roles/bigquery.reader", "bindings[0].role"),
        Claim("principal", "group:data-eng@acme.example", "bindings[0].members[0]"),
        Claim("role", "roles/storage.objectViewer", "bindings[1].role"),
        Claim("principal", "serviceAccount:ghost-runner@acme-prod.iam.gserviceaccount.com",
              "bindings[1].members[0]"),
        Claim("role", "roles/bigquery.jobUser", "bindings[2].role"),
        Claim("principal", "user:alice@acme.example", "bindings[2].members[0]"),
        Claim("cel",
              'request.time < timestamp("2020-01-01T00:00:00Z") && '
              'request.time >= timestamp("2025-01-01T00:00:00Z")',
              "bindings[2].condition.expression"),
    ]


# -- Org Policy fixtures (v2 format): exact claims ------------------------


def test_org_policy_good_exact_claims():
    assert org_policy_claims(load("org_policy_good.json")) == [
        Claim("constraint", "constraints/iam.disableServiceAccountKeyCreation", "name"),
        Claim("constraint_value", "constraints/iam.disableServiceAccountKeyCreation",
              "spec.rules[0].enforce", is_list=False),
    ]


def test_org_policy_bad_exact_claims():
    # List-typed rule on what the snapshot knows is a boolean constraint:
    # the extractor faithfully records is_list=True and lets the reasoner
    # contradict it.
    assert org_policy_claims(load("org_policy_bad.json")) == [
        Claim("constraint", "constraints/compute.disableSerialPortAccess", "name"),
        Claim("constraint_value", "constraints/compute.disableSerialPortAccess",
              "spec.rules[0].values", is_list=True),
    ]


# -- Org Policy legacy v1 format ------------------------------------------


def test_legacy_list_policy_on_boolean_constraint_yields_is_list_true():
    claims = org_policy_claims({
        "constraint": "constraints/compute.disableSerialPortAccess",
        "listPolicy": {"allowedValues": ["true"]},
    })
    assert claims == [
        Claim("constraint", "constraints/compute.disableSerialPortAccess", "constraint"),
        Claim("constraint_value", "constraints/compute.disableSerialPortAccess",
              "listPolicy", is_list=True),
    ]
    assert claims[1].is_list is True


def test_legacy_boolean_policy_yields_is_list_false():
    assert org_policy_claims({
        "constraint": "constraints/iam.disableServiceAccountKeyCreation",
        "booleanPolicy": {"enforced": True},
    }) == [
        Claim("constraint", "constraints/iam.disableServiceAccountKeyCreation", "constraint"),
        Claim("constraint_value", "constraints/iam.disableServiceAccountKeyCreation",
              "booleanPolicy", is_list=False),
    ]


def test_v2_deny_all_rule_is_list_typed():
    assert org_policy_claims({
        "name": "projects/acme-prod/policies/compute.vmExternalIpAccess",
        "spec": {"rules": [{"denyAll": True}]},
    }) == [
        Claim("constraint", "constraints/compute.vmExternalIpAccess", "name"),
        Claim("constraint_value", "constraints/compute.vmExternalIpAccess",
              "spec.rules[0].denyAll", is_list=True),
    ]


# -- conservative skips: IAM ----------------------------------------------


def test_tag_condition_yields_no_cel_claim():
    # Tags resolve at request time — skip, don't guess.
    claims = iam_policy_claims({"bindings": [{
        "role": "roles/viewer",
        "members": ["user:alice@acme.example"],
        "condition": {"expression": "resource.matchTag('tagKeys/123', 'prod')"},
    }]})
    assert claims == [
        Claim("role", "roles/viewer", "bindings[0].role"),
        Claim("principal", "user:alice@acme.example", "bindings[0].members[0]"),
    ]


def test_runtime_only_attribute_condition_yields_no_cel_claim():
    claims = iam_policy_claims({"bindings": [{
        "role": "roles/viewer",
        "members": [],
        "condition": {"expression": "'lvl' in request.auth.access_levels"},
    }]})
    assert claims == [Claim("role", "roles/viewer", "bindings[0].role")]


def test_non_principal_members_are_skipped():
    # allUsers/allAuthenticatedUsers, deleted members and federated identity
    # pools are not estate principals — no claim, so no false 'ungrounded'.
    claims = iam_policy_claims({"bindings": [{
        "role": "roles/viewer",
        "members": [
            "allUsers",
            "allAuthenticatedUsers",
            "deleted:serviceAccount:gone@acme-prod.iam.gserviceaccount.com?uid=123",
            "principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*",
            "user:alice@acme.example",
        ],
    }]})
    assert claims == [
        Claim("role", "roles/viewer", "bindings[0].role"),
        Claim("principal", "user:alice@acme.example", "bindings[0].members[4]"),
    ]


def test_malformed_binding_fields_are_skipped_individually():
    claims = iam_policy_claims({"bindings": [
        {"role": 42, "members": ["user:alice@acme.example"]},
        "not-an-object",
        {"role": "roles/viewer", "members": "not-an-array",
         "condition": {"title": "no expression here"}},
    ]})
    assert claims == [
        Claim("principal", "user:alice@acme.example", "bindings[0].members[0]"),
        Claim("role", "roles/viewer", "bindings[2].role"),
    ]


def test_empty_iam_policy_yields_no_claims():
    assert iam_policy_claims({}) == []
    assert iam_policy_claims({"bindings": []}) == []


# -- conservative skips: Org Policy ---------------------------------------


def test_org_policy_without_resolvable_constraint_yields_nothing():
    assert org_policy_claims({}) == []
    assert org_policy_claims({"spec": {"rules": [{"enforce": True}]}}) == []
    # A v2 name that does not embed exactly one constraint id.
    assert org_policy_claims({"name": "projects/acme-prod", "spec": {"rules": []}}) == []
    # v1 and v2 spellings at once — ambiguous.
    assert org_policy_claims({
        "constraint": "constraints/compute.disableSerialPortAccess",
        "name": "projects/acme-prod/policies/compute.vmExternalIpAccess",
    }) == []


def test_v2_rule_with_two_value_type_keys_is_ambiguous():
    claims = org_policy_claims({
        "name": "projects/acme-prod/policies/compute.disableSerialPortAccess",
        "spec": {"rules": [{"enforce": True, "values": {"allowedValues": ["x"]}}]},
    })
    assert claims == [
        Claim("constraint", "constraints/compute.disableSerialPortAccess", "name"),
    ]


# -- claim model invariants -----------------------------------------------


def test_claim_rejects_unknown_kind():
    with pytest.raises(ValueError):
        Claim("permission_maybe", "x", "somewhere")


def test_is_list_is_exactly_the_constraint_value_field():
    with pytest.raises(ValueError):
        Claim("constraint_value", "constraints/x", "listPolicy")  # missing is_list
    with pytest.raises(ValueError):
        Claim("role", "roles/viewer", "bindings[0].role", is_list=True)
    assert "constraint_value" in KINDS


def test_extractors_reject_non_mapping_input():
    with pytest.raises(ValueError):
        iam_policy_claims(["not", "a", "policy"])
    with pytest.raises(ValueError):
        org_policy_claims(None)
