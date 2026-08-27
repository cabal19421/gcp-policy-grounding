"""Tests for :mod:`gcp_grounding.iam_deny_checks` — the allow×deny interaction.

Four sections: the coverage TRI-STATE truth table (every row of the curated
containment algebra, conditions included); the four checks' verdict matrices
(masked / threaded / public-threaded / undecided / woken-escalation /
woken-ordinary / clean / self-gated); the two seam pins (the
``iam_deny_policies`` parser in :mod:`gcp_grounding.knowledge` and the CLI
decision block's JUDGMENT taste seat); and backend identity — **no z3
anywhere** in the module under test, asserted the way the iam_checks suites
assert it: the builtin backend produces byte-identical verdicts.

NAMED MUTATION MUST-KILLS PINNED HERE: MK-D06 (the public:all universal arm),
MK-D07 (group containment stays UNDECIDED), MK-D08 (a conditional rule cannot
prove coverage), MK-D09 (the woken-escalation polarity), MK-D10 (the C4
self-gate), MK-D11 (the CLI taste seat), MK-D12 (the parser's key/record
agreement). Each was measured against a copy of this tree with the mutant
applied alone before being seeded — see tests/mutation_entries.py's
DENY_ENTRIES block for the register-side story.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gcp_grounding import cli, evidence, iam_deny_checks, provenance, registry
from gcp_grounding.core.report import GroundingReport, Verdict
from gcp_grounding.core.solver import get_solver
from gcp_grounding.iam_deny_checks import (
    KIND,
    _covered,
    _member_in,
    _translate,
    check_deny_pair,
    check_deny_shadow_estate,
    check_deny_shadow_plan,
    check_deny_wake_plan,
)
from gcp_grounding.knowledge import UNKNOWN, GcpSnapshot
from gcp_grounding.preflight import ground_policy
from gcp_grounding.registry import CheckContext

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"

SNAP = GcpSnapshot.load(FIXTURES / "snapshot_deny_estate.json")

STRONG = json.loads((POLICIES / "deny_policy_strong.json").read_text())
PLAN = json.loads((POLICIES / "plan_deny_and_grant.json").read_text())
PLAN_DELETE = json.loads((POLICIES / "plan_deny_delete.json").read_text())

TOKEN = "iam.serviceAccounts.getAccessToken"
PUBLIC_ALL = "principalSet://goog/public:all"
CI_SA = "serviceAccount:ci@acme-prod.iam.gserviceaccount.com"
CI_SA_V2 = ("principal://iam.googleapis.com/projects/-/serviceAccounts/"
            "ci@acme-prod.iam.gserviceaccount.com")
GROUP_SET = "principalSet://goog/group/eng@acme.example"
PROJECT_SET = ("principalSet://cloudresourcemanager.googleapis.com/"
               "projects/111111111111")


def rule(**kw):
    """A normalized `_DenyRule` with the strong rule's defaults."""
    fields = {
        "denied_principals": kw.pop("denied", (PUBLIC_ALL,)),
        "exception_principals": kw.pop("excepted", ()),
        "denied_permissions": kw.pop(
            "permissions", ("iam.googleapis.com/serviceAccounts.getAccessToken",)),
        "exception_permissions": kw.pop("exception_permissions", ()),
    }
    state = kw.pop("condition_state", "none")
    condition = kw.pop("condition", "")
    assert not kw, kw
    return iam_deny_checks._normalized_rule(0, fields, state, condition)


def ctx(document, kind, *, snapshot=SNAP, baseline=None, baseline_kind=None,
        source="policy.json"):
    return CheckContext(snapshot=snapshot, solver=get_solver(),
                        document=document, document_kind=kind, source=source,
                        claims=(), baseline=baseline,
                        baseline_kind=baseline_kind)


def run(check, context):
    """One check under its own evidence ledger — what registry._invoke opens."""
    with evidence.ledger():
        return check(context)


class _PartialView:
    """A snapshot stand-in whose OWN completeness predicate refuses a
    category — the reconciled-view shape the self-gates consult."""

    def __init__(self, snapshot, refuse):
        self._snapshot = snapshot
        self._refuse = set(refuse)

    def __getattr__(self, name):
        return getattr(self._snapshot, name)

    def require_complete(self, category, rule=None):
        if category in self._refuse:
            return (f"category '{category}' has partial coverage from "
                    f"terraform-state - absence within a partial capture is "
                    f"not absence")
        return None


# -- the v1→v2 translation -------------------------------------------------


@pytest.mark.parametrize("member, expected", [
    ("user:alice@acme.example", "principal://goog/subject/alice@acme.example"),
    (CI_SA, CI_SA_V2),
    ("group:eng@acme.example", GROUP_SET),
    ("allUsers", PUBLIC_ALL),
])
def test_the_curated_translation_covers_exactly_the_four_forms(member, expected):
    assert _translate(member) == (expected, "")


@pytest.mark.parametrize("member", [
    "allAuthenticatedUsers", "domain:acme.example", "deleted:user:x?uid=1",
    "principalSet://iam.googleapis.com/locations/global/workforcePools/p/*",
    "serviceAccount:", "",
])
def test_everything_uncurated_translates_to_a_named_abstention(member):
    spelling, why = _translate(member)
    assert spelling is None
    assert "no curated v2 spelling" in why


# -- the containment truth table -------------------------------------------


def test_public_all_is_the_universal_set():
    """MK-D06's behaviour: EVERY translated member is in public:all — an
    exact-match-only reading would let a deny of everyone cover nobody."""
    tri = _member_in(CI_SA, CI_SA_V2, PUBLIC_ALL, SNAP)
    assert tri.state == "yes"


def test_exact_equality_and_exact_subject_disjointness():
    assert _member_in(CI_SA, CI_SA_V2, CI_SA_V2, SNAP).state == "yes"
    other = "principal://goog/subject/alice@acme.example"
    assert _member_in("user:alice@acme.example", other, CI_SA_V2, SNAP).state \
        == "no"


def test_group_membership_is_undecided_by_name():
    """MK-D07's behaviour: no snapshot category enumerates group membership,
    so containment of a non-group member in a group set is UNDECIDED naming
    the group — never TRUE, which would fabricate masking."""
    tri = _member_in("user:alice@acme.example",
                     "principal://goog/subject/alice@acme.example",
                     GROUP_SET, SNAP)
    assert tri.state == "undecided"
    assert GROUP_SET in tri.reason
    # the group ITSELF is in its own set — exact equality, not membership
    assert _member_in("group:eng@acme.example", GROUP_SET, GROUP_SET,
                      SNAP).state == "yes"


def test_the_project_set_decides_through_the_hierarchy_number():
    assert _member_in(CI_SA, CI_SA_V2, PROJECT_SET, SNAP).state == "yes"
    other = ("principalSet://cloudresourcemanager.googleapis.com/"
             "projects/999999999999")
    assert _member_in(CI_SA, CI_SA_V2, other, SNAP).state == "no"
    # a non-SA member is not decidable from its spelling
    assert _member_in("user:alice@acme.example",
                      "principal://goog/subject/alice@acme.example",
                      PROJECT_SET, SNAP).state == "undecided"
    # an uncaptured hierarchy abstains naming the gap
    bare = GcpSnapshot(captured_at="2026-07-18T09:00:00Z")
    tri = _member_in(CI_SA, CI_SA_V2, PROJECT_SET, bare)
    assert tri.state == "undecided" and "resource_hierarchy" in tri.reason


def test_an_uncurated_principal_set_is_undecided_by_name():
    weird = "principalSet://goog/cloudIdentityCustomerId/C123"
    tri = _member_in(CI_SA, CI_SA_V2, weird, SNAP)
    assert tri.state == "undecided" and weird in tri.reason


# -- the member×rule tri-state ---------------------------------------------


def test_covered_requires_every_exception_examined():
    covered = _covered(CI_SA, rule(), SNAP)
    assert covered == ("covered", "")
    escapes = _covered(CI_SA, rule(excepted=(CI_SA_V2,)), SNAP)
    assert escapes[0] == "escapes" and escapes[1] == CI_SA_V2
    undecided = _covered(CI_SA, rule(excepted=(GROUP_SET,)), SNAP)
    assert undecided[0] == "undecided"
    assert "no positive coverage claim" in undecided[1]


def test_a_member_outside_the_denied_set_is_clear():
    state, _ = _covered("user:alice@acme.example",
                        rule(denied=(CI_SA_V2,)), SNAP)
    assert state == "clear"


def test_a_conditional_rule_cannot_prove_coverage():
    """MK-D08's behaviour: a denialCondition may be false at request time, so
    a would-be covered is UNDECIDED naming the condition — and clear stays
    clear, conservative in both directions."""
    state, reason = _covered(
        CI_SA, rule(condition_state="present",
                    condition="request.time < timestamp('2027-01-01')"), SNAP)
    assert state == "undecided"
    assert "covered only under condition" in reason
    assert "request.time" in reason
    still_clear, _ = _covered(
        "user:alice@acme.example",
        rule(denied=(CI_SA_V2,), condition_state="present", condition="x"),
        SNAP)
    assert still_clear == "clear"


def test_an_untranslatable_member_is_undecided_before_any_set_math():
    state, reason = _covered("allAuthenticatedUsers", rule(), SNAP)
    assert state == "undecided" and "no curated v2 spelling" in reason


# -- C1: same-plan grants × same-plan deny policies ------------------------


def test_c1_masks_the_grant_and_names_rule_resource_and_class():
    verdicts = run(check_deny_shadow_plan, ctx(PLAN, "tf_plan"))
    (masked,) = [v for v in verdicts if v.kind == KIND]
    assert masked.status == "grounded"
    assert "warning" in masked.message and "masks" in masked.message
    assert "rule 0 of google_iam_deny_policy.guardrail" in masked.message
    assert f"{TOKEN} (impersonation)" in masked.message
    assert CI_SA in masked.message
    # one permission of two expanded is masked, so the grant is not fully inert
    assert "the entire grant is inert" not in masked.message


def test_c1_says_the_entire_grant_is_inert_when_every_permission_is_covered():
    doc = json.loads(json.dumps(PLAN))
    deny = doc["planned_values"]["root_module"]["resources"][0]["values"]
    deny["rules"][0]["deny_rule"][0]["denied_permissions"] = [
        "iam.googleapis.com/serviceAccounts.getAccessToken",
        "iam.googleapis.com/serviceAccounts.getOpenIdToken"]
    verdicts = run(check_deny_shadow_plan, ctx(doc, "tf_plan"))
    (masked,) = [v for v in verdicts if v.kind == KIND]
    assert "the entire grant is inert" in masked.message


def test_c1_a_threading_exception_is_a_warning_naming_the_exception():
    doc = json.loads(json.dumps(PLAN))
    deny = doc["planned_values"]["root_module"]["resources"][0]["values"]
    deny["rules"][0]["deny_rule"][0]["exception_principals"] = [CI_SA_V2]
    verdicts = run(check_deny_shadow_plan, ctx(doc, "tf_plan"))
    (threaded,) = [v for v in verdicts if v.kind == KIND]
    assert threaded.status == "grounded"
    assert "threads the exception" in threaded.message
    assert "review the exception" in threaded.message


def test_c1_a_public_grant_threading_the_guardrail_is_contradicted():
    doc = json.loads(json.dumps(PLAN))
    deny = doc["planned_values"]["root_module"]["resources"][0]["values"]
    deny["rules"][0]["deny_rule"][0]["exception_principals"] = [PUBLIC_ALL]
    binding = doc["planned_values"]["root_module"]["resources"][1]["values"]
    binding["members"] = ["allUsers"]
    verdicts = run(check_deny_shadow_plan, ctx(doc, "tf_plan"))
    (nullified,) = [v for v in verdicts if v.kind == KIND
                    and v.status == "contradicted"]
    assert "guardrail nullified from the allow side" in nullified.message


def test_c1_group_coverage_abstains_naming_the_group_not_a_warning():
    """MK-D07's check-level behaviour."""
    doc = json.loads(json.dumps(PLAN))
    deny = doc["planned_values"]["root_module"]["resources"][0]["values"]
    deny["rules"][0]["deny_rule"][0]["denied_principals"] = [GROUP_SET]
    binding = doc["planned_values"]["root_module"]["resources"][1]["values"]
    binding["members"] = ["user:alice@acme.example"]
    binding["role"] = "roles/iam.serviceAccountTokenCreator"
    verdicts = run(check_deny_shadow_plan, ctx(doc, "tf_plan"))
    ours = [v for v in verdicts if v.kind == KIND]
    assert [v.status for v in ours] == ["unverified"], ours
    assert GROUP_SET in ours[0].message
    assert "was not decided" in ours[0].message


def test_c1_a_conditional_deny_rule_abstains_naming_the_condition():
    """MK-D08's check-level behaviour."""
    doc = json.loads(json.dumps(PLAN))
    deny = doc["planned_values"]["root_module"]["resources"][0]["values"]
    deny["rules"][0]["deny_rule"][0]["denial_condition"] = [
        {"expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
         "title": "window"}]
    verdicts = run(check_deny_shadow_plan, ctx(doc, "tf_plan"))
    ours = [v for v in verdicts if v.kind == KIND]
    assert [v.status for v in ours] == ["unverified"], ours
    assert "covered only under condition" in ours[0].message


def test_c1_a_conditional_grant_abstains_by_name():
    doc = json.loads(json.dumps(PLAN))
    binding = doc["planned_values"]["root_module"]["resources"][1]["values"]
    binding["condition"] = [{"expression": "request.time < t", "title": "w"}]
    verdicts = run(check_deny_shadow_plan, ctx(doc, "tf_plan"))
    ours = [v for v in verdicts if v.kind == KIND]
    assert [v.status for v in ours] == ["unverified"], ours
    assert "ESC-DENY-ALLOW-CONDITIONS" in ours[0].message


def test_c1_expands_a_same_plan_custom_role_without_the_snapshot():
    doc = json.loads(json.dumps(PLAN))
    resources = doc["planned_values"]["root_module"]["resources"]
    resources[1]["values"]["role"] = "projects/acme-prod/roles/tokenMinter"
    resources.append({
        "address": "google_project_iam_custom_role.token_minter",
        "mode": "managed", "type": "google_project_iam_custom_role",
        "name": "token_minter",
        "provider_name": "registry.terraform.io/hashicorp/google",
        "values": {"project": "acme-prod", "role_id": "tokenMinter",
                    "permissions": [TOKEN]},
    })
    verdicts = run(check_deny_shadow_plan, ctx(doc, "tf_plan"))
    (masked,) = [v for v in verdicts if v.kind == KIND]
    assert masked.status == "grounded" and "masks" in masked.message
    assert "the entire grant is inert" in masked.message


def test_c1_is_silent_without_both_halves_and_abstains_on_count():
    only_binding = {"format_version": "1.2", "planned_values": {"root_module": {
        "resources": [PLAN["planned_values"]["root_module"]["resources"][1]]}}}
    assert run(check_deny_shadow_plan, ctx(only_binding, "tf_plan")) == []
    only_deny = {"format_version": "1.2", "planned_values": {"root_module": {
        "resources": [PLAN["planned_values"]["root_module"]["resources"][0]]}}}
    assert run(check_deny_shadow_plan, ctx(only_deny, "tf_plan")) == []
    counted = json.loads(json.dumps(PLAN))
    counted["planned_values"]["root_module"]["resources"][0]["values"]["count"] = 2
    verdicts = run(check_deny_shadow_plan, ctx(counted, "tf_plan"))
    assert any("'count'" in v.message and v.status == "unverified"
               for v in verdicts)


def test_c1_an_iam_policy_resource_abstains_instead_of_vanishing():
    doc = json.loads(json.dumps(PLAN))
    doc["planned_values"]["root_module"]["resources"].append({
        "address": "google_project_iam_policy.authoritative",
        "mode": "managed", "type": "google_project_iam_policy",
        "name": "authoritative",
        "provider_name": "registry.terraform.io/hashicorp/google",
        "values": {"project": "acme-prod", "policy_data": "{}"}})
    verdicts = run(check_deny_shadow_plan, ctx(doc, "tf_plan"))
    assert any("policy_data grants were not correlated" in v.message
               for v in verdicts)


# -- C2: a grant proposal × the estate deny table --------------------------


def grant_plan(role="roles/iam.serviceAccountTokenCreator", member=CI_SA):
    return {"format_version": "1.2", "planned_values": {"root_module": {
        "resources": [{
            "address": "google_project_iam_binding.ci", "mode": "managed",
            "type": "google_project_iam_binding", "name": "ci",
            "provider_name": "registry.terraform.io/hashicorp/google",
            "values": {"project": "acme-prod", "role": role,
                        "members": [member]}}]}}}


def test_c2_masks_a_plan_grant_against_the_captured_estate_table():
    verdicts = run(check_deny_shadow_estate, ctx(grant_plan(), "tf_plan"))
    (masked,) = [v for v in verdicts if v.kind == KIND]
    assert masked.status == "grounded" and "masks" in masked.message
    assert "denypolicies/block-sa-tokens" in masked.message


def test_c2_an_iam_policy_document_abstains_on_the_unlocatable_project():
    document = {"bindings": [{
        "role": "roles/iam.serviceAccountTokenCreator", "members": [CI_SA]}]}
    verdicts = run(check_deny_shadow_estate, ctx(document, "iam_policy"))
    ours = [v for v in verdicts if v.kind == KIND]
    assert [v.status for v in ours] == ["unverified"], ours
    assert "no readable project" in ours[0].message


def test_c2_uncaptured_table_abstains_only_for_escalation_material_grants():
    bare = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T09:00:00Z",
        "roles": SNAP.to_dict()["roles"]})
    escalation = run(check_deny_shadow_estate,
                     ctx(grant_plan(), "tf_plan", snapshot=bare))
    (gate,) = escalation
    assert gate.status == "unverified"
    assert gate.kind == iam_deny_checks.ESTATE_INCOMPLETE == registry.ESTATE_INCOMPLETE
    assert "iam_deny_policies" in gate.message
    assert f"{TOKEN}" in gate.message
    ordinary = run(check_deny_shadow_estate,
                   ctx(grant_plan(role="roles/bigquery.dataViewer"),
                       "tf_plan", snapshot=bare))
    assert ordinary == []  # a non-escalation grant keeps the old silence


def test_c2_is_silent_for_an_empty_policy_and_for_deny_carrying_plans():
    assert run(check_deny_shadow_estate,
               ctx({"bindings": []}, "iam_policy")) == []
    assert run(check_deny_shadow_estate, ctx(PLAN, "tf_plan")) == [], \
        "a plan with its own deny resources is C1's and C3's business"


# -- C3: the plan wake arc -------------------------------------------------


def test_c3_deleting_the_guardrail_wakes_the_escalation_grant():
    """MK-D09's behaviour: the woken permission is escalation-class, so the
    verdict is contradicted — a guardrail removal making a live path
    reachable, the firewall-widening polarity."""
    verdicts = run(check_deny_wake_plan, ctx(PLAN_DELETE, "tf_plan"))
    (woken,) = [v for v in verdicts if v.kind == KIND]
    assert woken.status == "contradicted"
    assert "wakes the dormant grant" in woken.message
    assert f"{TOKEN} (impersonation)" in woken.message
    assert CI_SA in woken.message
    assert "known escalation path inert" in woken.message


def test_c3_an_ordinary_woken_pair_is_a_warning_on_grounded():
    doc = json.loads(json.dumps(PLAN_DELETE))
    before = doc["resource_changes"][0]["change"]["before"]
    before["rules"][0]["deny_rule"][0]["denied_permissions"] = [
        "bigquery.googleapis.com/tables.getData"]
    snapshot = GcpSnapshot.from_dict({**SNAP.to_dict(), "roles": {
        "roles/iam.serviceAccountTokenCreator": {
            "title": "x", "included_permissions": ["bigquery.tables.getData"]}}})
    verdicts = run(check_deny_wake_plan, ctx(doc, "tf_plan",
                                             snapshot=snapshot))
    (woken,) = [v for v in verdicts if v.kind == KIND]
    assert woken.status == "grounded"
    assert "warning" in woken.message
    assert "belongs to the promise layer" in woken.message


def test_c3_an_unreadable_old_side_never_passes_silently():
    doc = json.loads(json.dumps(PLAN_DELETE))
    doc["resource_changes"][0]["change"]["before"] = None
    verdicts = run(check_deny_wake_plan, ctx(doc, "tf_plan"))
    (unread,) = verdicts
    assert unread.status == "unverified"
    assert "old rules could not be read" in unread.message
    assert "google_iam_deny_policy.guardrail" in unread.message


def test_c3_a_narrowing_update_that_keeps_coverage_wakes_nothing():
    doc = json.loads(json.dumps(PLAN_DELETE))
    change = doc["resource_changes"][0]["change"]
    change["actions"] = ["update"]
    change["after"] = json.loads(json.dumps(change["before"]))
    verdicts = run(check_deny_wake_plan, ctx(doc, "tf_plan"))
    (clean,) = verdicts
    assert clean.status == "grounded"
    assert "no dormant grant wakes" in clean.message


def test_c3_is_silent_without_a_deny_change_and_abstains_on_unknown_roles():
    create_only = json.loads(json.dumps(PLAN_DELETE))
    create_only["resource_changes"][0]["change"]["actions"] = ["create"]
    assert run(check_deny_wake_plan, ctx(create_only, "tf_plan")) == []
    no_roles = GcpSnapshot.from_dict({k: v for k, v in SNAP.to_dict().items()
                                      if k != "roles"})
    verdicts = run(check_deny_wake_plan,
                   ctx(PLAN_DELETE, "tf_plan", snapshot=no_roles))
    assert any(v.status == "unverified"
               and "did not capture roles" in v.message for v in verdicts)


# -- C4: the REST pair arc -------------------------------------------------


def new_policy(*, drop_rule=False):
    doc = json.loads(json.dumps(STRONG))
    if drop_rule:
        doc["rules"] = [{"denyRule": {
            "deniedPrincipals": [PUBLIC_ALL],
            "deniedPermissions": ["iam.googleapis.com/serviceAccountKeys.create"],
        }}]
    return doc


def test_c4_dropping_the_rule_wakes_the_dormant_grant():
    verdicts = run(check_deny_pair,
                   ctx(new_policy(drop_rule=True), "iam_deny_policy",
                       baseline=STRONG, baseline_kind="iam_deny_policy"))
    (woken,) = [v for v in verdicts if v.status == "contradicted"]
    assert "wakes the dormant grant" in woken.message
    assert f"{TOKEN} (impersonation)" in woken.message


def test_c4_an_unchanged_policy_wakes_nothing_over_a_complete_view():
    verdicts = run(check_deny_pair,
                   ctx(new_policy(), "iam_deny_policy", baseline=STRONG,
                       baseline_kind="iam_deny_policy"))
    (clean,) = verdicts
    assert clean.status == "grounded"
    assert "no dormant grant wakes" in clean.message


def test_c4_self_gates_the_clean_answer_on_iam_bindings_coverage():
    """MK-D10's behaviour: PAIR checks bypass the registry's estate gate, so
    C4 consults require_complete ITSELF before the clean answer — a partial
    grant population cannot license 'wakes nothing'."""
    partial = _PartialView(SNAP, refuse={"iam_bindings"})
    verdicts = run(check_deny_pair,
                   ctx(new_policy(), "iam_deny_policy", baseline=STRONG,
                       baseline_kind="iam_deny_policy", snapshot=partial))
    (gated,) = verdicts
    assert gated.status == "unverified"
    assert "needs the whole grant population" in gated.message
    assert "partial coverage" in gated.message


def test_c4_witness_findings_stand_on_the_same_partial_view():
    partial = _PartialView(SNAP, refuse={"iam_bindings"})
    verdicts = run(check_deny_pair,
                   ctx(new_policy(drop_rule=True), "iam_deny_policy",
                       baseline=STRONG, baseline_kind="iam_deny_policy",
                       snapshot=partial))
    assert [v.status for v in verdicts] == ["contradicted"]


def test_c4_refuses_a_non_deny_baseline_by_name():
    verdicts = run(check_deny_pair,
                   ctx(new_policy(), "iam_deny_policy",
                       baseline={"bindings": []}, baseline_kind="iam_policy"))
    (refused,) = verdicts
    assert refused.status == "unverified"
    assert "the baseline is not an IAM deny policy" in refused.message


def test_c4_an_undecodable_policy_name_abstains_by_name():
    doc = new_policy()
    doc["name"] = "denypolicies/not-the-v2-shape"
    verdicts = run(check_deny_pair,
                   ctx(doc, "iam_deny_policy", baseline=STRONG,
                       baseline_kind="iam_deny_policy"))
    (refused,) = verdicts
    assert refused.status == "unverified"
    assert "attachment point was not decoded" in refused.message


# -- registration, soundness and drift-shape ------------------------------


def test_the_module_is_a_registered_provider_with_the_pair_seat():
    assert "gcp_grounding.iam_deny_checks" in registry.PROVIDER_MODULES
    assert registry.pair_check("iam_deny_policy") is check_deny_pair
    for fn in iam_deny_checks.DOCUMENT_CHECKS:
        assert fn in registry.document_checks()


def test_c1_is_registered_subset_safe_on_roles_and_downgrades_its_warning():
    identity = "gcp_grounding.iam_deny_checks.check_deny_shadow_plan"
    assert provenance.estate_soundness(identity) == "subset_safe"
    assert provenance.estate_soundness_category(identity) == "roles"
    partial = _PartialView(SNAP, refuse={"roles"})
    context = ctx(PLAN, "tf_plan", snapshot=partial)
    downgraded = [v for v in registry.run_document_checks(context)
                  if v.kind == KIND]
    assert downgraded, "the check must still run over a partial view"
    assert all(v.status == "unverified" for v in downgraded)
    assert any("masks" in v.message and "not decided" in v.message
               for v in downgraded), downgraded


def test_the_kind_is_not_exempted_from_drift_adjudication():
    from gcp_grounding import drift
    assert KIND not in drift.NON_ESTATE_KINDS


def test_every_verdict_is_byte_identical_on_the_builtin_backend():
    """No z3 anywhere: the whole family decides by set arithmetic, so the
    builtin backend produces byte-identical verdicts."""
    builtin = get_solver(prefer="builtin")

    def both(check, document, kind, **kw):
        default = run(check, ctx(document, kind, **kw))
        degraded = run(check, CheckContext(
            snapshot=kw.get("snapshot", SNAP), solver=builtin,
            document=document, document_kind=kind, source="policy.json",
            claims=(), baseline=kw.get("baseline"),
            baseline_kind=kw.get("baseline_kind")))
        assert default == degraded

    both(check_deny_shadow_plan, PLAN, "tf_plan")
    both(check_deny_shadow_estate, grant_plan(), "tf_plan")
    both(check_deny_wake_plan, PLAN_DELETE, "tf_plan")
    both(check_deny_pair, new_policy(drop_rule=True), "iam_deny_policy",
         baseline=STRONG, baseline_kind="iam_deny_policy")


def test_end_to_end_the_masked_plan_still_passes_the_gate():
    report = ground_policy(POLICIES / "plan_deny_and_grant.json", SNAP)
    assert report.ok, [str(v) for v in report.verdicts]
    (masked,) = [v for v in report.verdicts if v.kind == KIND]
    assert masked.status == "grounded" and "masks" in masked.message


def test_end_to_end_the_deny_delete_blocks_the_gate():
    report = ground_policy(POLICIES / "plan_deny_delete.json", SNAP)
    assert not report.ok
    assert any(v.kind == KIND and v.status == "contradicted"
               for v in report.verdicts)


# -- the iam_deny_policies parser (knowledge.py) ---------------------------


DENY_KEY = ("policies/cloudresourcemanager.googleapis.com%2Fprojects%2F"
            "acme-prod/denypolicies/block-sa-tokens")


def snapshot_dict(record):
    return {"captured_at": "2026-07-18T09:00:00Z",
            "iam_deny_policies": {DENY_KEY: record}}


def deny_record(**kw):
    record = {
        "attachment_point": "projects/acme-prod",
        "rules": [{
            "denied_principals": [PUBLIC_ALL],
            "exception_principals": [],
            "denied_permissions": ["iam.googleapis.com/serviceAccounts.getAccessToken"],
            "exception_permissions": [],
        }],
    }
    record.update(kw)
    return record


def test_the_table_parses_and_round_trips_deterministically():
    snap = GcpSnapshot.from_dict(snapshot_dict(deny_record()))
    once = snap.to_dict()
    again = GcpSnapshot.from_dict(once).to_dict()
    assert once == again
    assert json.dumps(once, sort_keys=True) == json.dumps(again, sort_keys=True)
    record = snap.iam_deny_policy(DENY_KEY)
    assert record["attachment_point"] == "projects/acme-prod"
    assert record["rules"][0]["denied_principals"] == (PUBLIC_ALL,)


def test_the_accessors_answer_record_none_and_unknown():
    snap = GcpSnapshot.from_dict(snapshot_dict(deny_record()))
    assert snap.iam_deny_policy("policies/x/denypolicies/y") is None
    attached = snap.iam_deny_policies_attached_to("projects/acme-prod")
    assert len(attached) == 1
    assert snap.iam_deny_policies_attached_to("projects/other") == ()
    bare = GcpSnapshot(captured_at="t")
    assert bare.iam_deny_policy(DENY_KEY) is UNKNOWN
    assert bare.iam_deny_policies_attached_to("projects/acme-prod") is UNKNOWN


def test_a_mismatched_key_and_attachment_point_is_rejected():
    """MK-D12's behaviour: a mismatched key would let the containment walk
    govern the wrong node, so the parser REJECTS disagreement outright."""
    with pytest.raises(ValueError) as exc:
        GcpSnapshot.from_dict(snapshot_dict(
            deny_record(attachment_point="projects/other-project")))
    assert "disagrees with the key's encoded attachment segment" in str(exc.value)
    assert DENY_KEY in str(exc.value)


@pytest.mark.parametrize("mutate, complaint", [
    (lambda r: r.pop("attachment_point"), "'attachment_point'"),
    (lambda r: r.update(rules="not-a-list"), "'rules' must be an array"),
    (lambda r: r["rules"][0].update(denied_principals=[42]),
     "must be non-empty strings"),
    (lambda r: r["rules"][0].update(denial_condition={"title": "no expr"}),
     "'denial_condition' must be null or an object"),
    (lambda r: r["rules"][0].update(denial_condition={"expression": ""}),
     "'denial_condition' must be null or an object"),
])
def test_a_half_parsed_record_is_rejected_naming_the_defect(mutate, complaint):
    record = deny_record()
    mutate(record)
    with pytest.raises(ValueError) as exc:
        GcpSnapshot.from_dict(snapshot_dict(record))
    assert complaint in str(exc.value)


def test_a_key_outside_the_v2_shape_is_rejected():
    with pytest.raises(ValueError) as exc:
        GcpSnapshot.from_dict({
            "captured_at": "t",
            "iam_deny_policies": {"denypolicies/bare": deny_record()}})
    assert "policies/<url-encoded-attachment-point>" in str(exc.value)


# -- the CLI taste seat ----------------------------------------------------


def test_the_deny_shadow_abstention_leads_the_decision_blocks_taste():
    """MK-D11's behaviour: an ``iam_deny_shadow`` abstention says something
    about THIS change and must lead the taste over coverage noise — asserted
    with the deny verdict added LAST, so losing its JUDGMENT seat drops it
    behind five coverage abstentions and out of the capped block."""
    report = GroundingReport()
    for i, kind in enumerate(("role", "permission", "principal", "network",
                              "subnetwork", "constraint")):
        report.add(Verdict("unverified", kind, f"target-{i}", 0,
                           f"snapshot did not capture {kind} — coverage {i}"))
    report.add(Verdict("unverified", KIND, "roles/x", 0,
                       "the allow×deny interaction was not decided"))
    lines = cli._decision_lines(report, hook=False)
    assert any(f"[{KIND}]" in line for line in lines), lines


# -- the escalation register's activation hook ----------------------------


@pytest.mark.xfail(strict=True, reason=(
    "ESC-DENY-REGISTER-ACTIVATION: the twelve MK-D entries are seeded as "
    "PARKED data (tests/mutation_entries.py DENY_ENTRIES) — the frozen flip "
    "test executes every ACTIVE entry against a `git archive HEAD` copy, so "
    "activating them into ENTRIES requires the deny pair to be AT HEAD; the "
    "session that built them may not commit"))
def test_the_deny_mutation_entries_are_active_in_the_register():
    from tests.mutation_contract import register
    seeded = {entry.id for entry in register()}
    required = {f"MK-D{n:02d}" for n in range(1, 13)}
    assert required <= seeded, sorted(required - seeded)
