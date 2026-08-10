"""Reasoner tests: the Datalog existence pass over the shared fixtures —
good policies ground every claim, bad ones surface exactly the hallucinated
names (with near-miss suggestions), and a category the snapshot never
captured yields an honest 'unverified', never 'ungrounded'."""

import importlib.util
import json
from pathlib import Path

import pytest

from gcp_grounding.claims import Claim, iam_policy_claims, org_policy_claims
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.reasoner import (
    EXISTENCE_KINDS,
    existence_program,
    ground_existence,
    suggest,
)
from tests.lineno_invariant import assert_no_line_numbers

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"

GHOST = "serviceAccount:ghost-runner@acme-prod.iam.gserviceaccount.com"

HAVE_TF_CLAIMS = importlib.util.find_spec("gcp_grounding.tf_claims") is not None


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
    # The real extractor kinds: 'permission' and 'resource_type_ref'
    # (tf_claims emits both as claims.Claim records); a resource_type_ref
    # claim is decided against snapshot.resource_types and its verdict keeps
    # the category name 'resource_type'.
    claims = [
        Claim("permission", "bigquery.jobs.create", "perms[0]"),
        Claim("permission", "bigquery.jobs.imagine", "perms[1]"),
        Claim("resource_type_ref", "compute.googleapis.com/Instance", "resources[0].type"),
        Claim("resource_type_ref", "compute.googleapis.com/Droplet", "resources[1].type"),
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
    claims = [Claim("permission", "resourcemanager.projects.get", "perms[0]"),
              Claim("permission", "resourcemanager.projects.imagine", "perms[1]")]
    report = ground_existence(claims, partial)
    assert report.ok
    assert [v.status for v in report.verdicts] == ["grounded", "unverified"]


def test_null_included_permissions_cannot_crash_the_reasoner():
    # Belt and suspenders: from_dict rejects a null included_permissions, but
    # a hand-constructed snapshot may still carry None — the reasoner must
    # read it as "nothing included", never raise.
    snap = GcpSnapshot(captured_at="2026-07-18T09:30:00Z",
                       roles={"roles/viewer": {"included_permissions": None}})
    claims = [Claim("role", "roles/viewer", "bindings[0].role"),
              Claim("permission", "storage.objects.get", "perms[0]")]
    report = ground_existence(claims, snap)
    assert [(v.status, v.kind) for v in report.verdicts] == [
        ("grounded", "role"), ("unverified", "permission")]


# -- resource_type_ref end-to-end (tf_claims -> ground_existence) -----------


@pytest.mark.skipif(not HAVE_TF_CLAIMS,
                    reason="the tf-plan claim extractor is not part of this checkout")
def test_invented_tf_resource_type_is_ungrounded_end_to_end():
    # The full path the gate exercises: tf_claims emits 'resource_type_ref',
    # and the reasoner decides it against snapshot.resource_types — an
    # invented type is ungrounded when the vocabulary was captured, with the
    # real name suggested.
    from gcp_grounding.tf_claims import terraform_plan_claims
    plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": [
        {"mode": "managed", "address": "google_project_iam_bindng.x",
         "type": "google_project_iam_bindng",
         "provider_name": "registry.terraform.io/hashicorp/google", "values": {}}]}}}
    claims = terraform_plan_claims(plan)
    assert [c.kind for c in claims] == ["resource_type_ref"]
    captured = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T09:30:00Z",
        "resource_types": ["google_project_iam_binding", "google_project_iam_member"],
    })
    report = ground_existence(claims, captured)
    assert not report.ok
    [v] = report.ungrounded
    assert (v.kind, v.target) == ("resource_type", "google_project_iam_bindng")
    assert "google_project_iam_binding" in v.suggestions
    assert "google_project_iam_bindng.x" in v.message  # the resource address


@pytest.mark.skipif(not HAVE_TF_CLAIMS,
                    reason="the tf-plan claim extractor is not part of this checkout")
def test_tf_resource_type_without_captured_vocabulary_is_unverified():
    # The honest dual: no resource_types enumeration → the same invented type
    # is unverified, never ungrounded.
    from gcp_grounding.tf_claims import terraform_plan_claims
    plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": [
        {"mode": "managed", "address": "google_project_iam_bindng.x",
         "type": "google_project_iam_bindng",
         "provider_name": "registry.terraform.io/hashicorp/google", "values": {}}]}}}
    uncaptured = GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z"})
    report = ground_existence(terraform_plan_claims(plan), uncaptured)
    assert report.ok
    [v] = report.verdicts
    assert (v.status, v.kind) == ("unverified", "resource_type")


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


def test_existence_kinds_cover_the_fifteen_categories():
    assert set(EXISTENCE_KINDS) == {
        "role", "permission", "principal", "constraint", "resource_type_ref",
        "network_ref", "subnetwork_ref", "network_tag_ref", "service_account_ref",
        "access_level_ref", "restricted_service_ref", "perimeter_ref",
        "firewall_policy_ref", "security_policy_ref", "hierarchy_node_ref"}
    # The five originals survive as a subset: swapping one out fails loudly
    # even if the count still matches.
    assert frozenset({"role", "permission", "principal", "constraint",
                      "resource_type_ref"}) <= set(EXISTENCE_KINDS)
    # Appended, not reordered.
    assert EXISTENCE_KINDS[:5] == ("role", "permission", "principal",
                                   "constraint", "resource_type_ref")
    assert len(EXISTENCE_KINDS) == len(set(EXISTENCE_KINDS)) == 15
    # Every existence kind must be a kind an extractor can actually emit —
    # a spelling drift here (e.g. 'resource_type' vs 'resource_type_ref')
    # silently severs the whole category from the reasoner.
    for kind in EXISTENCE_KINDS:
        Claim(kind, "some-name", "some.location")


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


# -- the shared lineno invariant ----------------------------------------------


def test_no_existence_verdict_carries_a_line_number(snap):
    """The invariant ``ground_existence``'s own docstring states — see
    lineno_invariant. All three arms are driven: grounded, ungrounded and the
    uncaptured-category abstention, the last through a snapshot that captured
    no roles at all.
    """
    blind = GcpSnapshot.from_dict(
        {k: v for k, v in snap.to_dict().items() if k != "roles"})
    reports = [ground_existence(iam_policy_claims(load(n)), s)
               for n in ("iam_policy_good.json", "iam_policy_bad.json")
               for s in (snap, blind)]
    reports += [ground_existence(org_policy_claims(load(n)), snap)
                for n in ("org_policy_good.json", "org_policy_bad.json")]

    # Non-vacuity: all three existence arms really fired.
    assert {v.status for r in reports for v in r.verdicts} == {
        "grounded", "ungrounded", "unverified"}
    for report in reports:
        assert_no_line_numbers(report)
