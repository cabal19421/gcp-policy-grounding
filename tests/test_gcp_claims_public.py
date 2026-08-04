"""Public / unmodelled principal honesty tests.

Before this change ``iam_policy_claims`` silently dropped every member that was
not a ``user:``/``serviceAccount:``/``group:``/``domain:`` estate principal, so
a binding opening a resource to ``allUsers`` produced grounded=1, unverified=0
— public exposure was UNRECORDED. Now the members loop is a three-way split:
estate principals still yield ``principal`` claims byte-for-byte; ``allUsers``
and ``allAuthenticatedUsers`` yield ``public_principal`` grants carrying the
role; everything else yields ``unmodelled_principal``. A skipped member always
leaves a trace.
"""

import json
from pathlib import Path

import pytest

from gcp_grounding.claims import PUBLIC_PRINCIPALS, Claim, iam_policy_claims
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.preflight import ground_policy

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"


@pytest.fixture()
def snap() -> GcpSnapshot:
    return GcpSnapshot.load(FIXTURES / "snapshot.json")


PUBLIC_POLICY = {
    "bindings": [{
        "role": "roles/storage.objectViewer",
        "members": ["allUsers", "allAuthenticatedUsers"],
    }]
}


# -- extraction: public principals ------------------------------------------


def test_public_members_yield_public_principal_grants():
    claims = iam_policy_claims(PUBLIC_POLICY)
    assert claims == [
        Claim("role", "roles/storage.objectViewer", "bindings[0].role"),
        Claim.of("public_principal", "allUsers", "bindings[0].members[0]",
                 polarity="grant", role="roles/storage.objectViewer"),
        Claim.of("public_principal", "allAuthenticatedUsers", "bindings[0].members[1]",
                 polarity="grant", role="roles/storage.objectViewer"),
    ]


def test_public_principal_payload_carries_grant_polarity_and_role():
    publics = [c for c in iam_policy_claims(PUBLIC_POLICY) if c.kind == "public_principal"]
    assert len(publics) == 2
    for claim, member in zip(publics, PUBLIC_PRINCIPALS):
        assert claim.value == member
        assert claim.fields() == {"polarity": "grant", "role": "roles/storage.objectViewer"}


def test_public_principal_records_empty_role_when_binding_has_none():
    # A binding with no resolvable role still records the public member; the
    # role field is the empty string, never a guess.
    claims = iam_policy_claims({"bindings": [{"members": ["allUsers"]}]})
    assert claims == [
        Claim.of("public_principal", "allUsers", "bindings[0].members[0]",
                 polarity="grant", role=""),
    ]


# -- extraction: unmodelled principals --------------------------------------


def test_deleted_member_yields_one_unmodelled_principal():
    claims = iam_policy_claims({"bindings": [{
        "role": "roles/viewer",
        "members": ["deleted:user:bob@acme.example?uid=1"],
    }]})
    assert claims == [
        Claim("role", "roles/viewer", "bindings[0].role"),
        Claim("unmodelled_principal", "deleted:user:bob@acme.example?uid=1",
              "bindings[0].members[0]"),
    ]


def test_principal_set_member_yields_one_unmodelled_principal():
    member = "principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*"
    claims = iam_policy_claims({"bindings": [{
        "role": "roles/viewer",
        "members": [member],
    }]})
    assert claims == [
        Claim("role", "roles/viewer", "bindings[0].role"),
        Claim("unmodelled_principal", member, "bindings[0].members[0]"),
    ]


def test_non_string_member_yields_unmodelled_principal():
    claims = iam_policy_claims({"bindings": [{"role": "roles/viewer", "members": [42]}]})
    assert claims == [
        Claim("role", "roles/viewer", "bindings[0].role"),
        Claim("unmodelled_principal", "42", "bindings[0].members[0]"),
    ]


# -- byte-identical for prefixed-only policies ------------------------------


def test_prefixed_only_policy_is_byte_identical_to_before():
    # A policy using only estate principals emits exactly the same claims the
    # pre-change extractor did — the honesty fix is additive, not disruptive.
    policy = {"bindings": [
        {"role": "roles/bigquery.dataViewer",
         "members": ["group:data-eng@acme.example", "user:alice@acme.example"]},
        {"role": "roles/storage.objectViewer",
         "members": ["serviceAccount:etl@acme-prod.iam.gserviceaccount.com",
                     "domain:acme.example"]},
    ]}
    assert iam_policy_claims(policy) == [
        Claim("role", "roles/bigquery.dataViewer", "bindings[0].role"),
        Claim("principal", "group:data-eng@acme.example", "bindings[0].members[0]"),
        Claim("principal", "user:alice@acme.example", "bindings[0].members[1]"),
        Claim("role", "roles/storage.objectViewer", "bindings[1].role"),
        Claim("principal", "serviceAccount:etl@acme-prod.iam.gserviceaccount.com",
              "bindings[1].members[0]"),
        Claim("principal", "domain:acme.example", "bindings[1].members[1]"),
    ]
    # None of them is a public/unmodelled claim.
    assert all(c.kind in ("role", "principal") for c in iam_policy_claims(policy))


# -- end-to-end: the hole is now visible ------------------------------------


def test_public_policy_no_longer_grounds_silently(snap):
    # roles/storage.objectViewer grounds, but the two public_principal claims
    # are now DECIDED: `sx-iam-escalation` landed gcp_grounding.iam_checks,
    # whose public-principal check turns each grant into a contradicted
    # `iam_public` verdict. Before the claims existed the members were dropped
    # and the report was grounded=1, unverified=0 — a byte-identical clean pass;
    # while they existed but had no checker they recorded as unverified; now the
    # exposure blocks outright.
    report = ground_policy(PUBLIC_POLICY, snap)
    counts = report.counts()
    non_grounded = sum(v for s, v in counts.items() if s != "grounded")
    assert non_grounded >= 1
    public = [v for v in report.verdicts if v.kind == "iam_public"]
    assert len(public) == 2
    assert {v.status for v in public} == {"contradicted"}
    assert {v.target for v in public} == set(PUBLIC_PRINCIPALS)
    assert report.ok is False
