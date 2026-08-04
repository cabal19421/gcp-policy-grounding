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

from gcp_grounding import evidence, preflight, registry
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
    # The check reads the role's permission set through the evidence channel,
    # so it runs inside the one ledger its invoker (registry._invoke) opens.
    with evidence.ledger():
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
    with evidence.ledger():
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
    with evidence.ledger():
        verdicts = check_escalation(ctx)
    # bindings[1] has no member claim of its own AND no readable `members` in
    # the (empty) document, so it abstains rather than borrowing binding 10's
    # allUsers — which is what the pairing bug would have done — and rather than
    # grounding over a members list nobody read.
    assert [v.status for v in verdicts] == ["unverified", "contradicted"]
    assert "anyone can escalate" not in verdicts[0].message


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


# =============================================================================
# ESCALATION EVIDENCE — members, exceptions and uncaptured permissions
#
# Four positive verdicts used to be returned over things this module never
# examined. Each section below names the thing that was not read; the closing
# assertions of each pin the ordinary cases in BOTH directions, so the repairs
# cannot be mistaken for "abstain on everything".
# =============================================================================

#: A federated wildcard: a real member that ``claims.iam_policy_claims``
#: deliberately refuses to model, so it produces an ``unmodelled_principal``
#: and NO ``principal``/``public_principal`` claim to pair with its role.
WORKLOAD_WILDCARD = ("principalSet://iam.googleapis.com/projects/1234/locations/"
                     "global/workloadIdentityPools/github/*")

#: A deny rule that names an escalation permission and then exempts EVERYONE
#: from the denial: a guardrail that applies to nobody.
DENY_EXEMPTING_EVERYONE = {"rules": [{"denyRule": {
    "deniedPrincipals": ["group:data-eng@acme.example"],
    "exceptionPrincipals": ["allUsers"],
    "deniedPermissions": ["iam.googleapis.com/serviceAccountKeys.create"]}}]}

#: The same rule exempting a principal the gate cannot enumerate — the denial's
#: real reach is unknown rather than nullified.
DENY_EXEMPTING_A_WILDCARD = {"rules": [{"denyRule": {
    "deniedPrincipals": ["group:data-eng@acme.example"],
    "exceptionPrincipals": [WORKLOAD_WILDCARD],
    "deniedPermissions": ["iam.googleapis.com/serviceAccountKeys.create"]}}]}

BLOCKS = "blocks a known escalation path"
UNDECIDED_GRANTEE = "whether the grantee is public was not decided"


def escalation_of(report, target: str) -> list:
    return [v for v in report.verdicts
            if v.kind == "iam_escalation" and v.target == target]


def role_ctx(snapshot, solver, *claims, document=None, kind="iam_policy"):
    return CheckContext(snapshot=snapshot, solver=solver,
                        document={} if document is None else document,
                        document_kind=kind, source="<test>", claims=tuple(claims))


# -- (1) a deny rule's exception principals are never read --------------------


def test_deny_rule_exempting_everyone_is_not_a_working_guardrail(backend, snapshot):
    # The rule denies iam.serviceAccountKeys.create and then excepts allUsers:
    # the denial applies to NOBODY, so reporting it as a blocked escalation path
    # is a positive standing on an exception list that was never examined.
    report = ground_policy(DENY_EXEMPTING_EVERYONE, snapshot)
    assert [v for v in report.verdicts if BLOCKS in v.message] == []
    named = escalation_of(report, "iam.serviceAccountKeys.create")
    assert len(named) == 1
    assert named[0].status == "contradicted"
    assert "allUsers" in named[0].message


def test_deny_rule_exempting_an_unenumerable_principal_abstains(backend, snapshot):
    # The exception cannot be classified, so the rule's reach is unknown: the
    # abstention must NAME the member rather than assert a working guardrail.
    report = ground_policy(DENY_EXEMPTING_A_WILDCARD, snapshot)
    assert [v for v in report.verdicts if BLOCKS in v.message] == []
    named = escalation_of(report, "iam.serviceAccountKeys.create")
    assert len(named) == 1
    assert named[0].status == "unverified"
    assert WORKLOAD_WILDCARD in named[0].message


def test_a_denied_permission_without_a_rule_index_cannot_correlate(backend, snapshot):
    # The rule index is the documented discriminator for exactly this
    # correlation; with none, the rule's exceptions are unexaminable and no
    # positive asserting a working guardrail may be emitted for it.
    from gcp_grounding.iam_checks import check_denied_permission

    loc = "rules[0].denyRule.deniedPermissions[0]"
    claim = Claim("denied_permission",
                  "iam.googleapis.com/serviceAccountKeys.create", loc)
    ctx = role_ctx(snapshot, backend, claim,
                   Claim("permission", "iam.serviceAccountKeys.create", loc),
                   kind="iam_deny_policy")
    verdict = check_denied_permission(claim, ctx)
    assert verdict.status == "unverified"
    assert BLOCKS not in verdict.message
    assert "rule index" in verdict.message


def test_an_exception_the_gate_can_enumerate_leaves_the_positive_alone(backend,
                                                                      snapshot):
    # BOTH DIRECTIONS: the good fixture's exception is a named service account,
    # which IS examined and IS non-public, so the guardrail verdict stands.
    report = ground_policy(DENY_GOOD, snapshot)
    named = escalation_of(report, "iam.serviceAccountKeys.create")
    assert len(named) == 1
    assert named[0].status == "grounded"
    assert BLOCKS in named[0].message


# -- (2) an excepted public principal is reported as a guardrail --------------


def test_excepted_public_principal_is_a_bypass_not_a_guardrail(backend, snapshot):
    report = ground_policy(DENY_EXEMPTING_EVERYONE, snapshot)
    public = kinds(report, "iam_public")
    assert len(public) == 1
    assert public[0].target == "allUsers"
    assert public[0].status == "contradicted"
    assert "guardrail, not an exposure" not in public[0].message
    assert "exempts" in public[0].message


def test_a_deny_polarity_claim_without_the_discriminator_abstains():
    # Until the payload distinguishes a DENIED principal from an EXCEPTED one,
    # no positive whose text asserts a denial may be emitted.
    claim = Claim.of("public_principal", "allUsers",
                     "rules[0].denyRule.deniedPrincipals[0]", polarity="deny")
    verdict = check_public_principal(claim, None)
    assert verdict.status == "unverified"
    assert "guardrail, not an exposure" not in verdict.message
    assert "excepted" in verdict.message


# -- (3) a binding with no usable members grounds -----------------------------


def test_a_member_that_could_not_be_modelled_abstains_naming_it(backend, snapshot):
    report = ground_policy(binding("roles/owner", WORKLOAD_WILDCARD), snapshot)
    escalation = kinds(report, "iam_escalation")
    assert len(escalation) == 1
    assert escalation[0].status == "unverified"
    assert escalation[0].target == "roles/owner"
    assert WORKLOAD_WILDCARD in escalation[0].message
    assert UNDECIDED_GRANTEE in escalation[0].message


def test_an_absent_members_key_is_unreadable_not_empty(backend, snapshot):
    # House rule 3 and the evidence contract: an absent key is UNREADABLE, so
    # the read raises and the verdict names the binding it could not read.
    report = ground_policy({"bindings": [{"role": "roles/owner"}]}, snapshot)
    escalation = kinds(report, "iam_escalation")
    assert len(escalation) == 1
    assert escalation[0].status == "unverified"
    assert escalation[0].target == "roles/owner"
    assert "'members'" in escalation[0].message
    assert UNDECIDED_GRANTEE in escalation[0].message


def test_a_present_empty_members_list_says_it_was_observed_empty(backend, snapshot):
    # The ONLY reading under which "nothing to grant to" is honest — and it must
    # say the list was observed empty rather than imply members were reviewed.
    report = ground_policy({"bindings": [{"role": "roles/owner", "members": []}]},
                           snapshot)
    escalation = kinds(report, "iam_escalation")
    assert len(escalation) == 1
    assert escalation[0].status == "grounded"
    assert escalation[0].target == "roles/owner"
    assert "observed empty" in escalation[0].message
    assert report.ok is True


# -- (4) an empty permission list is treated as captured-and-benign -----------


#: A CUSTOM role — deliberately not one of ESCALATION_ROLES, so the verdict
#: turns on the captured permissions and nothing else.
KEY_MINTER = "projects/acme-prod/roles/keyMinter"


def _snapshot_with(permissions):
    # Built through from_dict, the path a real capture takes: `fetch.py` writes
    # `included_permissions` for EVERY role and defaults it to [].
    return GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T09:30:00Z",
        "roles": {KEY_MINTER: {"title": "Key minter", "stage": "GA",
                               "included_permissions": permissions}},
        "principals": ["user:alice@acme.example"]})


def test_a_role_whose_permissions_were_never_captured_abstains(backend):
    # The fetch path always writes the key and defaults it to [], so a KEY
    # PRESENCE test lets an uncaptured role intersect the escalation table
    # emptily and produce NO verdict of any status — no reason, no record.
    report = ground_policy(binding(KEY_MINTER, "user:alice@acme.example"),
                           _snapshot_with([]))
    escalation = kinds(report, "iam_escalation")
    assert len(escalation) == 1
    assert escalation[0].status == "unverified"
    assert escalation[0].target == KEY_MINTER
    assert "included_permissions" in escalation[0].message


def test_the_same_role_with_permissions_captured_still_warns(backend):
    # BOTH DIRECTIONS: the abstention above is about the CAPTURE, not the role.
    report = ground_policy(
        binding(KEY_MINTER, "user:alice@acme.example"),
        _snapshot_with(["iam.serviceAccountKeys.create", "iam.serviceAccounts.get"]))
    escalation = kinds(report, "iam_escalation")
    assert len(escalation) == 1
    assert escalation[0].status == "grounded"
    assert "iam.serviceAccountKeys.create (impersonation)" in escalation[0].message


# -- the complement to the Gate 0 fix -----------------------------------------


def test_an_iam_policy_with_no_role_claim_abstains_on_the_escalation_channel(
        backend, snapshot):
    # Bindings were present and carried content, but not one role name was
    # extracted from them: silence here reads as "no escalation was found".
    report = ground_policy({"bindings": [{"members": ["user:alice@acme.example"]}]},
                           snapshot)
    escalation = kinds(report, "iam_escalation")
    assert len(escalation) == 1
    assert escalation[0].status == "unverified"
    assert "no role" in escalation[0].message
    assert report.ok is True


def test_an_empty_allow_policy_stays_silent_on_the_escalation_channel(backend,
                                                                     snapshot):
    # BOTH DIRECTIONS: `bindings: []` was READ and observed empty, which is a
    # fact about the document rather than a hole in it.
    report = ground_policy({"bindings": []}, snapshot)
    assert kinds(report, "iam_escalation") == []


def test_a_deny_policy_gets_no_missing_role_abstention(backend, snapshot):
    # Channel discipline in the other direction: a deny policy carries no
    # bindings by construction, so "no role claim" says nothing about it.
    report = ground_policy(DENY_GOOD, snapshot)
    assert [v for v in kinds(report, "iam_escalation") if "no role" in v.message] == []


# -- the shape gate, exercised ------------------------------------------------


@pytest.mark.parametrize("location", [
    "spec.somewhere.weird.role",
    "notgoogle_project_iam_member.pub.role",
    "policy_data.bindings[0].role",
    "bindings[x].role",
])
def test_a_location_that_is_not_a_binding_address_abstains_for_that_reason(
        backend, snapshot, location):
    # Relaxing the binding-address patterns to match anything survived the whole
    # suite, because the only ungroupable location exercised did not even end in
    # `.role` and so never reached them. These four do.
    ctx = role_ctx(snapshot, backend, Claim("role", "roles/owner", location))
    with evidence.ledger():
        verdicts = check_escalation(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].status == "unverified"
    assert verdicts[0].kind == "iam_escalation"
    assert "could not associate" in verdicts[0].message


@pytest.mark.parametrize("location", [
    "bindings[0].role",
    "google_project_iam_member.pub.role",
    'module.iam.google_project_iam_binding.viewers["a"].role',
    "google_project_iam_policy.main.policy_data.bindings[0].role",
])
def test_a_real_binding_address_still_pairs_with_its_members(backend, snapshot,
                                                             location):
    # BOTH DIRECTIONS for the gate above: each of these IS a binding address and
    # must still be paired with the member claim anchored under it.
    member = location[: -len(".role")] + ".members[0]"
    ctx = role_ctx(snapshot, backend,
                   Claim("role", "roles/owner", location),
                   Claim.of("public_principal", "allUsers", member,
                            polarity="grant", role="roles/owner"))
    with evidence.ledger():
        verdicts = check_escalation(ctx)
    assert [v.status for v in verdicts] == ["contradicted"]
    assert "anyone can escalate" in verdicts[0].message


# -- the named must-kill pins (MK-E01 .. MK-E06) ------------------------------
#
# AMENDMENT 3 replaced this task's `(mutation: 0.8)` ratio with named pins, so
# each owned survivor gets a STABLE, UNPARAMETRIZED handle of its own: a
# bracketed node id moves when a case is added to a parametrize list, and a
# SKIPPED param never satisfies a `must_fail`.
#
# Four of them mutate the LINENO positional of a `Verdict`. Per the
# admissibility ruling, each is phrased against the SERIALIZED report payload —
# the surface a consumer actually reads, one step further from the mutated
# literal than the constructor call — and each also pins the IDENTITY of the
# path it stands on: status, kind, target, and the reason named in the message.
# Three of the four sit on abstention paths this task created, so asserting that
# identity per path is coverage of exactly those fail-open branches.


def _payload_verdicts(report, kind: str) -> list[dict]:
    """The serialized ``to_dict()`` verdicts of one kind — a consumer's view."""
    return [v for v in report.to_dict()["verdicts"] if v["kind"] == kind]


def test_deny_polarity_public_principal_reports_no_source_line(snapshot):
    # MK-E01, gcp_grounding/iam_checks.py `def check_public_principal`.
    # A deny policy is a JSON document, so there is no source line to point a
    # consumer at; the json-path location leads the message instead.
    public = _payload_verdicts(ground_policy(DENY_GOOD, snapshot), "iam_public")
    assert len(public) == 1
    assert public[0]["lineno"] == 0
    assert public[0]["status"] == "grounded"
    assert public[0]["kind"] == "iam_public"
    assert public[0]["target"] == "allUsers"
    assert "guardrail, not an exposure" in public[0]["message"]


def test_bindings_without_a_role_claim_abstain_with_no_source_line(snapshot):
    # MK-E02, gcp_grounding/iam_checks.py `def _no_role_claims`.
    # The abstention was derived from the DOCUMENT — one binding present, no
    # role extracted from it — and not from any line of it.
    report = ground_policy({"bindings": [{"members": ["user:alice@acme.example"]}]},
                           snapshot)
    abstained = _payload_verdicts(report, "iam_escalation")
    assert len(abstained) == 1
    assert abstained[0]["lineno"] == 0
    assert abstained[0]["status"] == "unverified"
    assert abstained[0]["kind"] == "iam_escalation"
    assert abstained[0]["target"] == "<policy object>"
    assert "1 binding(s) were present but no role claim was extracted" \
        in abstained[0]["message"]


def test_an_unmodelled_member_abstention_reports_no_source_line(snapshot):
    # MK-E03, gcp_grounding/iam_checks.py `def _no_usable_members`.
    # Item (3)'s unmodelled-principal abstention: the member exists in the
    # document but the extractor refused it, and no line is quotable for it.
    report = ground_policy(binding("roles/owner", WORKLOAD_WILDCARD), snapshot)
    escalation = _payload_verdicts(report, "iam_escalation")
    assert len(escalation) == 1
    assert escalation[0]["lineno"] == 0
    assert escalation[0]["status"] == "unverified"
    assert escalation[0]["kind"] == "iam_escalation"
    assert escalation[0]["target"] == "roles/owner"
    assert "could not be modelled as principals" in escalation[0]["message"]
    assert WORKLOAD_WILDCARD in escalation[0]["message"]
    assert UNDECIDED_GRANTEE in escalation[0]["message"]


def test_a_binding_index_at_the_boundary_abstains_and_does_not_raise(snapshot):
    # MK-E04, gcp_grounding/iam_checks.py `def _binding_members`. NOT a lineno:
    # `index >= len(bindings)` is the boundary that keeps a claim key of the
    # form bindings[N], against a document holding exactly N bindings, from
    # indexing off the end. Off by one, `bindings[2]` on a two-binding document
    # raises IndexError out of the helper; the caller's `try` catches only
    # evidence.NotEvaluated, so it would ESCAPE the check entirely rather than
    # resolve as "not a document index" and abstain. Nothing may propagate.
    document = {"bindings": [
        {"role": "roles/owner", "members": ["user:alice@acme.example"]},
        {"role": "roles/viewer", "members": ["user:alice@acme.example"]}]}
    ctx = role_ctx(snapshot, get_solver(),
                   Claim("role", "roles/owner", "bindings[2].role"),
                   document=document)
    with evidence.ledger():
        verdicts = check_escalation(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].status == "unverified"
    assert verdicts[0].kind == "iam_escalation"
    assert verdicts[0].target == "roles/owner"
    assert verdicts[0].message.startswith("bindings[2].role: ")
    assert "members could not be located in the document" in verdicts[0].message
    assert UNDECIDED_GRANTEE in verdicts[0].message


def test_four_members_render_the_plus_one_more_marker(snapshot):
    # MK-E05, gcp_grounding/iam_checks.py `def _capped`. The render boundary at
    # exactly _RENDER_CAP + 1: with four members the tail marker must appear, or
    # the verdict UNDERSTATES how wide the binding is and drops the fourth
    # member with nothing saying anything was omitted. Three or five members
    # both leave that unsaid, so the case count is part of the pin.
    members = [f"principalSet://iam.googleapis.com/pool-{i}/*" for i in range(4)]
    escalation = kinds(ground_policy(binding("roles/owner", *members), snapshot),
                       "iam_escalation")
    assert len(escalation) == 1
    assert escalation[0].status == "unverified"
    assert f"{', '.join(members[:3])} +1 more" in escalation[0].message
    assert members[3] not in escalation[0].message


def test_the_nullified_guardrail_verdict_reports_no_source_line(snapshot):
    # MK-E06, gcp_grounding/iam_checks.py `def check_denied_permission`.
    # Item (1)'s nullified guardrail — the deny rule whose exception list exempts
    # everyone — is read out of the rule's sibling claims, not off a line.
    report = ground_policy(DENY_EXEMPTING_EVERYONE, snapshot)
    named = [v for v in _payload_verdicts(report, "iam_escalation")
             if v["target"] == "iam.serviceAccountKeys.create"]
    assert len(named) == 1
    assert named[0]["lineno"] == 0
    assert named[0]["status"] == "contradicted"
    assert named[0]["kind"] == "iam_escalation"
    assert "allUsers" in named[0]["message"]
    assert BLOCKS not in named[0]["message"]
