"""VPC Service Controls claim-extraction tests.

Pins the honesty contract of :mod:`gcp_grounding.vpcsc_claims`: a REST
Access Context Manager document and its terraform spelling normalize to the
same perimeter; a perimeter *resource* creates the perimeter and claims no
``perimeter_ref`` for itself while a standalone egress-policy resource
references one; wildcards are preserved in the payload but never minted into an
existence claim; and the ``spec``-block document that would otherwise be
misread as an Org Policy v2 is detected as ``vpc_sc_perimeter``.
"""

import json
from pathlib import Path

import pytest

from gcp_grounding import registry
from gcp_grounding.claims import KINDS
from gcp_grounding.preflight import DOCUMENT_KINDS, detect_kind
from gcp_grounding.tf_claims import terraform_plan_claims
from gcp_grounding.vpcsc_claims import (
    DOCUMENT_EXTRACTORS, TF_EXTRACTORS, access_level_claims, perimeter_claims,
)

POLICIES = Path(__file__).parent / "fixtures" / "gcp" / "policies"

#: Claim kinds that assert something exists in the estate — the kinds a
#: wildcard must never produce.
EXISTENCE_KINDS = {"hierarchy_node_ref", "restricted_service_ref",
                   "access_level_ref", "service_account_ref", "perimeter_ref",
                   "principal", "public_principal"}

TF_PERIMETER = "google_access_context_manager_service_perimeter"


@pytest.fixture(autouse=True)
def _clean_registry():
    """Discover the real (default) provider modules — this task's included —
    fresh for every test, and never leak a warm cache into the next."""
    registry.reset_cache()
    yield
    registry.reset_cache()


def load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


def kv(claims) -> set:
    return {(c.kind, c.value) for c in claims}


# -- the terraform mirror of vpcsc_perimeter.json -----------------------------
# Same perimeter, terraform's shape: snake_case keys and nested blocks encoded
# as single-element arrays, with unset string attributes present as "".

TF_PERIMETER_VALUES = {
    "name": "accessPolicies/987/servicePerimeters/prod",
    "title": "prod perimeter",
    "perimeter_type": "PERIMETER_TYPE_REGULAR",
    "use_explicit_dry_run_spec": False,
    "status": [{
        "resources": ["projects/123456"],
        "restricted_services": ["storage.googleapis.com", "bigquery.googleapis.com"],
        "access_levels": ["accessPolicies/987/accessLevels/trusted"],
        "ingress_policies": [],
        "egress_policies": [{
            "egress_from": [{
                "identity_type": "",
                "identities": ["serviceAccount:exporter@acme-prod.iam.gserviceaccount.com"],
                "sources": [],
            }],
            "egress_to": [{
                "resources": ["projects/700700"],
                "external_resources": [],
                "operations": [{
                    "service_name": "storage.googleapis.com",
                    "method_selectors": [
                        {"method": "google.storage.objects.get", "permission": ""}
                    ],
                }],
            }],
        }],
    }],
    "spec": [{
        "resources": ["projects/123456"],
        "restricted_services": ["storage.googleapis.com"],
        "access_levels": [],
        "ingress_policies": [],
        "egress_policies": [],
    }],
}


# -- REST ↔ terraform normalization agree -------------------------------------


def test_rest_and_terraform_normalizations_agree():
    [rest_cfg] = [c for c in perimeter_claims(load("vpcsc_perimeter.json"))
                  if c.kind == "perimeter_config"]
    [tf_cfg] = [c for c in TF_EXTRACTORS[TF_PERIMETER](
                    f"{TF_PERIMETER}.prod", TF_PERIMETER_VALUES)
                if c.kind == "perimeter_config"]
    assert rest_cfg.fields() == tf_cfg.fields()
    # …and the normalized shape is what the design pins, snake_case throughout.
    normalized = rest_cfg.fields()
    assert normalized["perimeter_type"] == "PERIMETER_TYPE_REGULAR"
    assert normalized["use_explicit_dry_run_spec"] is False
    assert normalized["status"]["restricted_services"] == [
        "storage.googleapis.com", "bigquery.googleapis.com"]
    [egress] = normalized["status"]["egress_policies"]
    assert egress["egress_to"]["operations"] == [{
        "service_name": "storage.googleapis.com",
        "method_selectors": [{"method": "google.storage.objects.get"}],
    }]


# -- perimeter_ref only for referencing documents -----------------------------


def test_perimeter_resource_emits_no_self_referential_perimeter_ref():
    claims = TF_EXTRACTORS[TF_PERIMETER](f"{TF_PERIMETER}.prod", TF_PERIMETER_VALUES)
    assert not any(c.kind == "perimeter_ref" for c in claims)
    # it does describe the perimeter it creates
    assert any(c.kind == "perimeter_config" for c in claims)


def test_egress_policy_resource_emits_exactly_one_perimeter_ref():
    claims = terraform_plan_claims(load("vpcsc_tf_plan.json"))
    refs = [c for c in claims if c.kind == "perimeter_ref"]
    assert len(refs) == 1
    assert refs[0].value == "accessPolicies/987/servicePerimeters/prod"
    # the referencing resource still carries its normalized policy
    assert any(c.kind == "perimeter_egress" for c in claims)


def test_resource_and_ingress_policy_resources_reference_a_perimeter():
    added = TF_EXTRACTORS[
        "google_access_context_manager_service_perimeter_resource"](
        "google_access_context_manager_service_perimeter_resource.add",
        {"perimeter_name": "accessPolicies/987/servicePerimeters/prod",
         "resource": "projects/555"})
    assert ("perimeter_ref", "accessPolicies/987/servicePerimeters/prod") in kv(added)
    assert ("hierarchy_node_ref", "projects/555") in kv(added)

    ingress = TF_EXTRACTORS[
        "google_access_context_manager_service_perimeter_ingress_policy"](
        "google_access_context_manager_service_perimeter_ingress_policy.in",
        {"perimeter": "accessPolicies/987/servicePerimeters/prod",
         "ingress_from": [{"identities": ["user:alice@example.com"], "sources": []}],
         "ingress_to": [{"resources": ["*"]}]})
    refs = [c for c in ingress if c.kind == "perimeter_ref"]
    assert [c.value for c in refs] == ["accessPolicies/987/servicePerimeters/prod"]
    assert ("principal", "user:alice@example.com") in kv(ingress)


# -- wildcards: verbatim in the payload, never an existence claim -------------


def test_wildcards_produce_no_existence_claims():
    claims = perimeter_claims(load("vpcsc_perimeter_shrunk.json"))
    assert all(not (c.kind in EXISTENCE_KINDS and c.value == "*") for c in claims)
    # ANY_IDENTITY names no enumerable identity, so no principal family at all
    assert not any(c.kind in {"principal", "service_account_ref", "public_principal"}
                   for c in claims)
    # the widened wildcards survive verbatim inside the egress payload
    [egress] = [c for c in claims if c.kind == "perimeter_egress"]
    fields = egress.fields()
    assert fields["egress_from"]["identity_type"] == "ANY_IDENTITY"
    assert fields["egress_to"]["external_resources"] == ["*"]


def test_wildcard_service_and_method_and_resource_are_never_grounded():
    doc = {
        "name": "accessPolicies/987/servicePerimeters/wide",
        "status": {"ingressPolicies": [{
            "ingressFrom": {"identityType": "ANY_IDENTITY"},
            "ingressTo": {
                "resources": ["*"],
                "operations": [{"serviceName": "*",
                                "methodSelectors": [{"method": "*"}]}],
            },
        }]},
    }
    claims = perimeter_claims(doc)
    assert all(c.value != "*" for c in claims)
    [ingress] = [c for c in claims if c.kind == "perimeter_ingress"]
    op = ingress.fields()["ingress_to"]["operations"][0]
    assert op["service_name"] == "*"
    assert op["method_selectors"] == [{"method": "*"}]


# -- hierarchy nodes, restricted services, access levels ----------------------


def test_project_resource_yields_hierarchy_node_ref():
    claims = perimeter_claims(load("vpcsc_perimeter.json"))
    assert ("hierarchy_node_ref", "projects/123456") in kv(claims)
    # both status.resources and spec.resources contribute
    assert sum(1 for c in claims if c.kind == "hierarchy_node_ref"
               and c.value == "projects/123456") == 2


def test_restricted_services_and_status_access_levels_are_grounded():
    claims = perimeter_claims(load("vpcsc_perimeter.json"))
    values = kv(claims)
    assert ("restricted_service_ref", "storage.googleapis.com") in values
    assert ("restricted_service_ref", "bigquery.googleapis.com") in values
    assert ("access_level_ref", "accessPolicies/987/accessLevels/trusted") in values


# -- identities: principal, service_account_ref, public_principal -------------


def test_service_account_identity_yields_principal_and_bare_ref():
    claims = perimeter_claims(load("vpcsc_perimeter.json"))
    values = kv(claims)
    assert ("principal",
            "serviceAccount:exporter@acme-prod.iam.gserviceaccount.com") in values
    assert ("service_account_ref",
            "exporter@acme-prod.iam.gserviceaccount.com") in values


def test_all_users_identity_yields_a_public_principal():
    doc = {
        "name": "accessPolicies/987/servicePerimeters/pub",
        "status": {"ingressPolicies": [{
            "ingressFrom": {
                "identities": ["allUsers",
                               "serviceAccount:svc@p.iam.gserviceaccount.com",
                               "user:x@example.com",
                               "principalSet://iam.example/federated"],
                "sources": [{"accessLevel": "accessPolicies/987/accessLevels/lvl"}],
            },
            "ingressTo": {"resources": ["projects/42"]},
        }]},
    }
    claims = perimeter_claims(doc)
    public = [c for c in claims if c.kind == "public_principal"]
    assert len(public) == 1
    assert public[0].value == "allUsers"
    assert public[0].fields() == {"polarity": "grant"}

    values = kv(claims)
    assert ("principal", "serviceAccount:svc@p.iam.gserviceaccount.com") in values
    assert ("service_account_ref", "svc@p.iam.gserviceaccount.com") in values
    assert ("principal", "user:x@example.com") in values
    # the source access level grounds
    assert ("access_level_ref", "accessPolicies/987/accessLevels/lvl") in values
    # the federated principal is not enumerable — skipped, not guessed at
    assert not any("federated" in c.value for c in claims)


# -- access-level documents ---------------------------------------------------


def test_access_level_emits_cel_only_when_offline_decidable():
    good = {"name": "accessPolicies/987/accessLevels/lvl",
            "custom": {"expr": {"expression":
                                'request.time < timestamp("2027-01-01T00:00:00Z")'}}}
    assert [(c.kind, c.value) for c in access_level_claims(good)] == [
        ("cel", 'request.time < timestamp("2027-01-01T00:00:00Z")')]
    # a runtime-only construct is screened out, not guessed at
    runtime = {"name": "accessPolicies/987/accessLevels/lvl",
               "custom": {"expr": {"expression": 'origin.ip == "1.2.3.4"'}}}
    assert access_level_claims(runtime) == []
    # a basic access level has no custom expression: no claim
    basic = {"name": "accessPolicies/987/accessLevels/lvl",
             "basic": {"conditions": [{"members": ["user:x@example.com"]}]}}
    assert access_level_claims(basic) == []


def test_access_level_emits_no_self_ref_and_no_restricted_service():
    claims = access_level_claims(
        {"name": "accessPolicies/987/accessLevels/lvl",
         "custom": {"expr": {"expression":
                             'request.time < timestamp("2027-01-01T00:00:00Z")'}}})
    assert not any(c.kind in {"access_level_ref", "restricted_service_ref"}
                   for c in claims)


def test_terraform_access_level_matches_rest():
    tf = TF_EXTRACTORS["google_access_context_manager_access_level"](
        "google_access_context_manager_access_level.lvl",
        {"name": "accessPolicies/987/accessLevels/lvl",
         "custom": [{"expr": [{"expression":
                               'request.time < timestamp("2027-01-01T00:00:00Z")'}]}]})
    assert [(c.kind, c.value) for c in tf] == [
        ("cel", 'request.time < timestamp("2027-01-01T00:00:00Z")')]


# -- detection: the spec-block misclassification hazard -----------------------


def test_detect_kind_perimeter_is_vpc_sc_not_org_policy():
    doc = load("vpcsc_perimeter.json")
    assert isinstance(doc.get("spec"), dict)  # the exact org-policy-v2 hazard
    assert detect_kind(doc) == "vpc_sc_perimeter"
    assert detect_kind(doc) != "org_policy"


def test_detect_kind_recognizes_access_level():
    assert detect_kind({"name": "accessPolicies/987/accessLevels/lvl",
                        "basic": {"conditions": []}}) == "access_level"


def test_new_document_kinds_are_declared_and_wired():
    assert "vpc_sc_perimeter" in DOCUMENT_KINDS
    assert "access_level" in DOCUMENT_KINDS
    assert DOCUMENT_EXTRACTORS == {"vpc_sc_perimeter": perimeter_claims,
                                   "access_level": access_level_claims}
    assert set(TF_EXTRACTORS) == {
        "google_access_context_manager_service_perimeter",
        "google_access_context_manager_service_perimeter_resource",
        "google_access_context_manager_service_perimeter_ingress_policy",
        "google_access_context_manager_service_perimeter_egress_policy",
        "google_access_context_manager_access_level",
    }


def test_every_emitted_kind_is_in_the_claim_vocabulary():
    claims = perimeter_claims(load("vpcsc_perimeter.json"))
    assert claims  # non-trivial
    assert {c.kind for c in claims} <= set(KINDS)
