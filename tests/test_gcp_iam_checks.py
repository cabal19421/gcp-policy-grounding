"""Acceptance tests for IAM public-principal and escalation grounding.

:mod:`gcp_grounding.iam_checks` is the decision layer for the two IAM claim
kinds that used to fall through to ``ground_policy``'s honest catch-all: a
``public_principal`` (recorded by ``sx-iam-public-principal``) and a
``denied_permission`` (recorded by ``sx-iam-deny-claims``). Recording them
closed the *silence*; deciding them is what turns the worst silent pass — a
binding granting a role to ``allUsers`` — into a block.

Every assertion is run twice, once per solver backend: the module uses no z3 at
all, so a ``prefer="builtin"`` run must produce identical verdicts. The
parametrization patches ``preflight.get_solver`` (``ground_policy`` resolves the
backend itself and takes no solver argument), which exercises the real
end-to-end path under both backends rather than a hand-built context.
"""

import json
from pathlib import Path

import pytest

from gcp_grounding import preflight, registry
from gcp_grounding.claims import Claim
from gcp_grounding.core.solver import get_solver
from gcp_grounding.iam_checks import (CLAIM_CHECKS, DOCUMENT_CHECKS,
                                      ESCALATION_PERMISSIONS, ESCALATION_ROLES,
                                      check_escalation, check_public_principal)
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.preflight import ground_policy
from gcp_grounding.registry import CheckContext

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"
ESTATE = FIXTURES / "estate_snapshot.json"
DENY_GOOD = POLICIES / "iam_deny_good.json"

CI_DEPLOYER = "serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com"


@pytest.fixture(params=[None, "builtin"], ids=["default", "builtin"])
def backend(request, monkeypatch):
    """Force ``ground_policy`` onto one solver backend.

    ``iam_checks`` never touches the solver, so every verdict below must be
    identical under both — that equality is the point of the parametrization.
    """
    solver = get_solver(prefer=request.param)
    monkeypatch.setattr(preflight, "get_solver", lambda *a, **kw: solver)
    return solver


@pytest.fixture()
def snapshot() -> GcpSnapshot:
    return GcpSnapshot.load(ESTATE)


@pytest.fixture(autouse=True)
def _fresh_registry():
    # iam_checks is discovered through the lazy provider registry; drop any
    # cache a stub-injecting test elsewhere may have left behind.
    registry.reset_cache()
    yield
    registry.reset_cache()


def binding(role: str, *members: str) -> dict:
    return {"bindings": [{"role": role, "members": list(members)}]}


def kinds(report, kind: str, status: str | None = None) -> list:
    return [v for v in report.verdicts
            if v.kind == kind and (status is None or v.status == status)]


# -- the curated table --------------------------------------------------------


def test_table_is_curated_static_data_not_a_snapshot_category():
    # Committed constants, versioned with the code: neither is derivable from a
    # GcpSnapshot, and nothing in this module fetches them.
    assert ESCALATION_PERMISSIONS["iam.serviceAccounts.actAs"] == "impersonation"
    assert ESCALATION_PERMISSIONS["iam.serviceAccountKeys.create"] == "impersonation"
    assert ESCALATION_PERMISSIONS["compute.instances.setServiceAccount"] == "impersonation"
    assert ESCALATION_PERMISSIONS["iam.roles.update"] == "role-mutation"
    assert ESCALATION_PERMISSIONS["iam.denypolicies.update"] == "policy-mutation"
    assert ESCALATION_PERMISSIONS["resourcemanager.organizations.setIamPolicy"] \
        == "policy-mutation"
    assert ESCALATION_PERMISSIONS["orgpolicy.policy.set"] == "guardrail-removal"
    assert ESCALATION_PERMISSIONS["cloudbuild.builds.create"] == "build-pivot"
    assert ESCALATION_PERMISSIONS["serviceusage.services.enable"] == "surface-expansion"
    assert set(ESCALATION_PERMISSIONS.values()) == {
        "impersonation", "role-mutation", "policy-mutation", "guardrail-removal",
        "build-pivot", "surface-expansion"}
    assert "roles/owner" in ESCALATION_ROLES
    assert "roles/iam.serviceAccountTokenCreator" in ESCALATION_ROLES
    assert len(ESCALATION_ROLES) == 10
    assert "roles/bigquery.dataViewer" not in ESCALATION_ROLES


def test_registry_hooks_are_the_documented_ones():
    assert set(CLAIM_CHECKS) == {"public_principal", "denied_permission"}
    assert DOCUMENT_CHECKS == (check_escalation,)
    assert "gcp_grounding.iam_checks" in registry.PROVIDER_MODULES


# -- CHECK A: public principals -----------------------------------------------


def test_public_grant_of_object_viewer_is_contradicted_and_blocks(backend, snapshot):
    report = ground_policy(binding("roles/storage.objectViewer", "allUsers"), snapshot)
    public = kinds(report, "iam_public")
    assert len(public) == 1
    assert public[0].status == "contradicted"
    assert public[0].target == "allUsers"
    assert "publicly accessible" in public[0].message
    assert report.ok is False


def test_public_grant_of_owner_is_both_public_and_escalation(backend, snapshot):
    report = ground_policy(binding("roles/owner", "allUsers"), snapshot)
    public = kinds(report, "iam_public", "contradicted")
    escalation = kinds(report, "iam_escalation", "contradicted")
    assert len(public) == 1
    assert len(escalation) == 1
    assert escalation[0].target == "roles/owner"
    assert "anyone can escalate" in escalation[0].message
    assert "allUsers" in escalation[0].message
    assert report.ok is False


def test_all_authenticated_users_is_contradicted_too(backend, snapshot):
    report = ground_policy(
        binding("roles/storage.objectViewer", "allAuthenticatedUsers"), snapshot)
    public = kinds(report, "iam_public", "contradicted")
    assert [v.target for v in public] == ["allAuthenticatedUsers"]


def test_deny_polarity_public_principal_is_grounded(backend, snapshot):
    # allUsers inside an IAM *deny* policy is a guardrail, not an exposure.
    report = ground_policy(DENY_GOOD, snapshot)
    public = kinds(report, "iam_public")
    assert len(public) == 1
    assert public[0].status == "grounded"
    assert public[0].target == "allUsers"
    assert "guardrail, not an exposure" in public[0].message
    assert report.ok is True


def test_public_principal_without_polarity_abstains():
    claim = Claim("public_principal", "allUsers", "bindings[0].members[0]")
    verdict = check_public_principal(claim, None)
    assert verdict.status == "unverified"
    assert "polarity" in verdict.message


# -- CHECK B: escalation ------------------------------------------------------


def test_token_creator_to_a_real_principal_warns_without_blocking(backend, snapshot):
    report = ground_policy(
        binding("roles/iam.serviceAccountTokenCreator", CI_DEPLOYER), snapshot)
    escalation = kinds(report, "iam_escalation")
    assert len(escalation) == 1
    assert escalation[0].status == "grounded"
    assert escalation[0].target == "roles/iam.serviceAccountTokenCreator"
    assert "warning" in escalation[0].message
    assert "review the principal" in escalation[0].message
    assert CI_DEPLOYER in escalation[0].message
    assert report.ok is True


def test_benign_role_yields_zero_escalation_verdicts(backend, snapshot):
    report = ground_policy(
        binding("roles/bigquery.dataViewer", "user:alice@acme.example"), snapshot)
    assert kinds(report, "iam_escalation") == []
    assert report.ok is True


def test_escalation_message_names_permission_and_class(backend, snapshot):
    report = ground_policy(binding("roles/orgpolicy.policyAdmin",
                                   "user:alice@acme.example"), snapshot)
    escalation = kinds(report, "iam_escalation")
    assert len(escalation) == 1
    assert "orgpolicy.policy.set (guardrail-removal)" in escalation[0].message
    # membership in ESCALATION_ROLES rides along as its own class
    assert "roles/orgpolicy.policyAdmin (named-admin-role)" in escalation[0].message


def test_enumerated_permissions_are_capped_at_three(backend, snapshot):
    # roles/owner carries five escalation permissions plus the named-admin-role
    # hit; the render must stay one readable line.
    report = ground_policy(binding("roles/owner", "user:alice@acme.example"), snapshot)
    escalation = kinds(report, "iam_escalation")
    assert len(escalation) == 1
    assert "+3 more" in escalation[0].message


def test_uncaptured_roles_yield_unverified_escalation(backend):
    snapshot = GcpSnapshot(captured_at="2026-07-18T09:30:00Z",
                           principals=frozenset({"user:alice@acme.example"}))
    report = ground_policy(binding("roles/owner", "user:alice@acme.example"), snapshot)
    escalation = kinds(report, "iam_escalation")
    assert len(escalation) == 1
    assert escalation[0].status == "unverified"
    assert escalation[0].message == ("snapshot did not capture roles — escalation "
                                     "classes were not decided")
    assert report.ok is True


def test_role_without_included_permissions_yields_unverified_naming_it(backend):
    snapshot = GcpSnapshot(captured_at="2026-07-18T09:30:00Z",
                           roles={"roles/owner": {"title": "Owner", "stage": "GA"}},
                           principals=frozenset({"user:alice@acme.example"}))
    report = ground_policy(binding("roles/owner", "user:alice@acme.example"), snapshot)
    escalation = kinds(report, "iam_escalation")
    assert len(escalation) == 1
    assert escalation[0].status == "unverified"
    assert escalation[0].target == "roles/owner"
    assert "roles/owner" in escalation[0].message
    assert "included_permissions" in escalation[0].message


def test_ungroupable_location_abstains_exactly_once(backend, snapshot):
    # Neither `bindings[0].role` nor a terraform address: the pairing step
    # cannot tell a benign binding from a parse failure, so it must say so
    # rather than silently drop the check for this role.
    ctx = CheckContext(snapshot=snapshot, solver=backend, document={},
                       document_kind="iam_policy", source="<test>",
                       claims=(Claim("role", "roles/owner", "spec.somewhere.weird"),))
    verdicts = check_escalation(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].status == "unverified"
    assert verdicts[0].kind == "iam_escalation"
    assert verdicts[0].target == "roles/owner"
    assert "could not associate" in verdicts[0].message


def test_terraform_anchored_binding_groups_by_resource_address(backend, snapshot):
    ctx = CheckContext(
        snapshot=snapshot, solver=backend, document={}, document_kind="tf_plan",
        source="<test>",
        claims=(Claim("role", "roles/owner", "google_project_iam_member.pub.role"),
                Claim.of("public_principal", "allUsers",
                         "google_project_iam_member.pub.member",
                         polarity="grant", role="roles/owner")))
    verdicts = check_escalation(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].status == "contradicted"
    assert "anyone can escalate" in verdicts[0].message


def test_policy_data_bindings_are_not_merged_across_indices(backend, snapshot):
    # google_project_iam_policy anchors two bindings under ONE address; keying
    # on the address alone would hand binding 0's public member to binding 1.
    address = "google_project_iam_policy.main.policy_data"
    ctx = CheckContext(
        snapshot=snapshot, solver=backend, document={}, document_kind="tf_plan",
        source="<test>",
        claims=(Claim("role", "roles/owner", f"{address}.bindings[0].role"),
                Claim("principal", "user:alice@acme.example",
                      f"{address}.bindings[0].members[0]"),
                Claim("role", "roles/iam.serviceAccountUser",
                      f"{address}.bindings[1].role"),
                Claim.of("public_principal", "allUsers",
                         f"{address}.bindings[1].members[0]",
                         polarity="grant", role="roles/iam.serviceAccountUser")))
    by_role = {v.target: v.status for v in check_escalation(ctx)}
    assert by_role == {"roles/owner": "grounded",
                       "roles/iam.serviceAccountUser": "contradicted"}


def test_binding_index_ten_does_not_borrow_binding_one_members(backend, snapshot):
    ctx = CheckContext(
        snapshot=snapshot, solver=backend, document={}, document_kind="iam_policy",
        source="<test>",
        claims=(Claim("role", "roles/owner", "bindings[1].role"),
                Claim("role", "roles/owner", "bindings[10].role"),
                Claim.of("public_principal", "allUsers", "bindings[10].members[0]",
                         polarity="grant", role="roles/owner")))
    statuses = [v.status for v in check_escalation(ctx)]
    assert statuses == ["grounded", "contradicted"]


def test_absent_role_leaves_escalation_to_the_existence_pass(backend, snapshot):
    report = ground_policy(binding("roles/bigquery.reader",
                                   "user:alice@acme.example"), snapshot)
    assert kinds(report, "iam_escalation") == []
    assert [v.status for v in kinds(report, "role")] == ["ungrounded"]


# -- CHECK C: permissions an IAM deny policy names ----------------------------


def test_denied_escalation_permission_is_grounded_with_its_class(backend, snapshot):
    report = ground_policy(DENY_GOOD, snapshot)
    named = [v for v in report.verdicts
             if v.target == "iam.serviceAccountKeys.create"
             and "escalation path" in v.message]
    assert len(named) == 1
    assert named[0].status == "grounded"
    assert "(impersonation)" in named[0].message
    assert report.ok is True


def test_denied_permission_no_longer_hits_the_catch_all(backend, snapshot):
    report = ground_policy(DENY_GOOD, snapshot)
    catchall = [v for v in report.verdicts
                if v.kind == "denied_permission" and "no offline check is wired"
                in v.message]
    assert catchall == []


def test_underivable_denied_permission_abstains_naming_it(backend, snapshot):
    # A wildcard: the extractor refuses to guess a normalized name, so no
    # sibling `permission` claim exists and the class cannot be decided.
    doc = {"rules": [{"denyRule": {
        "deniedPermissions": ["iam.googleapis.com/roles.*"]}}]}
    report = ground_policy(doc, snapshot)
    abstained = [v for v in report.verdicts
                 if v.status == "unverified"
                 and v.target == "iam.googleapis.com/roles.*"]
    assert len(abstained) == 1
    assert "escalation class was not decided" in abstained[0].message


def test_non_escalation_denied_permission_is_grounded_quietly(backend, snapshot):
    doc = {"rules": [{"denyRule": {
        "deniedPermissions": ["storage.googleapis.com/objects.get"]}}]}
    report = ground_policy(doc, snapshot)
    named = [v for v in report.verdicts if v.kind == "iam_escalation"]
    assert len(named) == 1
    assert named[0].status == "grounded"
    assert "not in the curated escalation table" in named[0].message


def test_excepted_escalation_permission_is_flagged_as_a_carve_out(backend, snapshot):
    doc = {"rules": [{"denyRule": {
        "deniedPermissions": ["iam.googleapis.com/serviceAccountKeys.create"],
        "exceptionPermissions": ["iam.googleapis.com/roles.update"]}}]}
    report = ground_policy(doc, snapshot)
    carve = [v for v in report.verdicts if v.target == "iam.roles.update"
             and v.kind == "iam_escalation"]
    assert len(carve) == 1
    assert carve[0].status == "grounded"
    assert "excepted from this deny rule" in carve[0].message
    assert report.ok is True


# -- backend independence, stated as one explicit assertion -------------------


def test_verdicts_are_identical_on_both_backends(snapshot):
    doc = json.loads(DENY_GOOD.read_text(encoding="utf-8"))
    ctx_args = dict(snapshot=snapshot, document=doc, document_kind="iam_deny_policy",
                    source="<test>")
    from gcp_grounding.iam_deny import iam_deny_policy_claims

    claims = tuple(iam_deny_policy_claims(doc))
    rendered = []
    for prefer in (None, "builtin"):
        ctx = CheckContext(solver=get_solver(prefer=prefer), claims=claims, **ctx_args)
        verdicts = list(check_escalation(ctx))
        for claim in claims:
            check = CLAIM_CHECKS.get(claim.kind)
            if check is not None:
                verdicts.append(check(claim, ctx))
        rendered.append([(v.status, v.kind, v.target, v.message) for v in verdicts])
    assert rendered[0] == rendered[1]
    assert rendered[0]  # the deny fixture really does exercise both checks
