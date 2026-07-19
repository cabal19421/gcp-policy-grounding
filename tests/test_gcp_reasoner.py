"""Reasoner tests: the Datalog existence pass over the shared fixtures —
good policies ground every claim, bad ones surface exactly the hallucinated
names (with near-miss suggestions), and a category the snapshot never
captured yields an honest 'unverified', never 'ungrounded'."""

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from gcp_grounding.claims import iam_policy_claims, org_policy_claims
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.reasoner import (
    EXISTENCE_KINDS,
    existence_program,
    ground_existence,
    suggest,
)

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"

GHOST = "serviceAccount:ghost-runner@acme-prod.iam.gserviceaccount.com"


@dataclass(frozen=True)
class TfClaim:
    """Stand-in for tf_claims kinds ('permission', 'resource_type') that
    claims.Claim cannot mint — the reasoner is duck-typed over kind/value/
    location, so any claim-shaped object participates."""

    kind: str
    value: str
    location: str


@pytest.fixture()
def snap() -> GcpSnapshot:
    return GcpSnapshot.load(FIXTURES / "snapshot.json")


def load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


# -- good fixtures: everything grounds ------------------------------------


def test_good_iam_policy_all_grounded(snap):
    report = ground_existence(iam_policy_claims(load("iam_policy_good.json")), snap)
    assert report.ok
    # 3 role + 4 principal claims ground; the cel claim is not an existence
    # question and gets no verdict here.
    assert report.counts() == {"grounded": 7, "ungrounded": 0,
                               "contradicted": 0, "unverified": 0}
    assert {v.kind for v in report.verdicts} == {"role", "principal"}


def test_good_org_policy_all_grounded(snap):
    report = ground_existence(org_policy_claims(load("org_policy_good.json")), snap)
    assert report.ok
    # The constraint existence claim grounds; the constraint_value claim is
    # the solver layer's, not existence.
    assert [(v.status, v.kind, v.target) for v in report.verdicts] == [
        ("grounded", "constraint", "constraints/iam.disableServiceAccountKeyCreation")]


# -- bad fixtures: the specific hallucinations surface ---------------------


def test_bad_iam_policy_specific_ungrounded(snap):
    report = ground_existence(iam_policy_claims(load("iam_policy_bad.json")), snap)
    assert not report.ok
    assert {(v.kind, v.target) for v in report.ungrounded} == {
        ("role", "roles/bigquery.reader"),
        ("principal", GHOST),
    }
    # Everything real still grounds; nothing is contradicted or unverified.
    assert report.counts() == {"grounded": 4, "ungrounded": 2,
                               "contradicted": 0, "unverified": 0}


def test_bad_role_suggests_the_near_miss(snap):
    report = ground_existence(iam_policy_claims(load("iam_policy_bad.json")), snap)
    [reader] = [v for v in report.ungrounded if v.kind == "role"]
    assert reader.target == "roles/bigquery.reader"
    assert "roles/bigquery.dataViewer" in reader.suggestions
    assert set(reader.suggestions) <= set(snap.roles)  # never invents a name
    assert reader.lineno == 0
    assert "bindings[0].role" in reader.message  # json-path anchors the finding


def test_bad_org_policy_is_existence_clean(snap):
    # org_policy_bad's badness is a value-type mismatch — a solver-layer
    # contradiction, not an existence question; its constraint is real.
    report = ground_existence(org_policy_claims(load("org_policy_bad.json")), snap)
    assert report.ok
    assert [(v.status, v.kind) for v in report.verdicts] == [("grounded", "constraint")]


def test_hallucinated_constraint_is_ungrounded_with_suggestion(snap):
    claims = org_policy_claims({
        "constraint": "constraints/compute.disableSerialPort",
        "booleanPolicy": {"enforced": True},
    })
    report = ground_existence(claims, snap)
    [v] = report.ungrounded
    assert v.kind == "constraint"
    assert v.suggestions[0] == "constraints/compute.disableSerialPortAccess"


# -- UNKNOWN category → unverified, never ungrounded -----------------------


def test_uncaptured_category_yields_unverified_never_ungrounded():
    partial = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T09:30:00Z",
        "roles": {"roles/viewer": {"included_permissions": ["resourcemanager.projects.get"]}},
    })
    claims = iam_policy_claims({"bindings": [
        {"role": "roles/viewer", "members": ["user:alice@acme.example"]}]})
    report = ground_existence(claims, partial)
    assert report.ok  # unverified is honest, not a failure
    assert [(v.status, v.kind) for v in report.verdicts] == [
        ("grounded", "role"), ("unverified", "principal")]
    [principal] = report.by_status("unverified")
    assert principal.suggestions == ()  # nothing to suggest from an uncaptured set


def test_captured_empty_category_is_ungrounded_not_unverified():
    # The dual: principals *were* enumerated (as empty), so absence is provable
    # → ungrounded; roles were never captured → unverified.
    empty = GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z",
                                   "principals": []})
    claims = iam_policy_claims({"bindings": [
        {"role": "roles/viewer", "members": ["user:alice@acme.example"]}]})
    report = ground_existence(claims, empty)
    assert not report.ok
    assert [(v.status, v.kind) for v in report.verdicts] == [
        ("unverified", "role"), ("ungrounded", "principal")]
    [v] = report.ungrounded
    assert v.suggestions == ()


# -- permission / resource_type rules --------------------------------------


def test_permission_and_resource_type_existence(snap):
    claims = [
        TfClaim("permission", "bigquery.jobs.create", "perms[0]"),
        TfClaim("permission", "bigquery.jobs.imagine", "perms[1]"),
        TfClaim("resource_type", "compute.googleapis.com/Instance", "resources[0].type"),
        TfClaim("resource_type", "compute.googleapis.com/Droplet", "resources[1].type"),
    ]
    report = ground_existence(claims, snap)
    assert not report.ok
    assert {(v.status, v.kind, v.target) for v in report.verdicts} == {
        ("grounded", "permission", "bigquery.jobs.create"),
        ("ungrounded", "permission", "bigquery.jobs.imagine"),
        ("grounded", "resource_type", "compute.googleapis.com/Instance"),
        ("ungrounded", "resource_type", "compute.googleapis.com/Droplet"),
    }
    [perm] = [v for v in report.ungrounded if v.kind == "permission"]
    assert "bigquery.jobs.create" in perm.suggestions


def test_permission_proven_by_role_inclusion_without_enumeration():
    # No flat permission enumeration, but a captured role includes the
    # permission → it provably exists (grounded); an unknown name in the
    # same partial snapshot is only unverified, never ungrounded.
    partial = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T09:30:00Z",
        "roles": {"roles/viewer": {"included_permissions": ["resourcemanager.projects.get"]}},
    })
    claims = [TfClaim("permission", "resourcemanager.projects.get", "perms[0]"),
              TfClaim("permission", "resourcemanager.projects.imagine", "perms[1]")]
    report = ground_existence(claims, partial)
    assert report.ok
    assert [v.status for v in report.verdicts] == ["grounded", "unverified"]


# -- the Datalog program itself --------------------------------------------


def test_datalog_relations_are_derived_by_name(snap):
    dl = existence_program(iam_policy_claims(load("iam_policy_bad.json")), snap)
    dl.run()
    assert dl.query("ungrounded_role") == {("roles/bigquery.reader", "bindings[0].role")}
    assert dl.query("ungrounded_principal") == {(GHOST, "bindings[1].members[0]")}
    assert ("roles/bigquery.jobUser", "bindings[2].role") in dl.query("grounded_role")
    # The other existence relations exist but derive nothing for this policy.
    assert dl.query("ungrounded_permission") == set()
    assert dl.query("ungrounded_constraint") == set()
    assert dl.query("ungrounded_resource_type") == set()


def test_existence_kinds_cover_the_five_categories():
    assert set(EXISTENCE_KINDS) == {"role", "permission", "principal",
                                    "constraint", "resource_type"}


# -- suggestions -----------------------------------------------------------


def test_suggest_canonical_near_miss(snap):
    assert "roles/bigquery.dataViewer" in suggest("roles/bigquery.reader", snap.roles)


def test_suggest_never_makes_wild_guesses():
    assert suggest("roles/bigquery.reader",
                   ["roles/somethingCompletely.differentAltogether"]) == ()
    assert suggest("roles/viewer", []) == ()


def test_render_carries_location_and_suggestion(snap):
    report = ground_existence(iam_policy_claims(load("iam_policy_bad.json")), snap)
    text = report.render("policy.json")
    assert "FAILED" in text
    assert "bindings[0].role" in text
    assert "roles/bigquery.dataViewer" in text
