"""Constraint-layer tests: CEL satisfiability, org-policy value-type
consistency, and new⊆old IAM policy subset — each against tiny fixtures.

z3-only assertions are skipped when the z3 solver backend is unavailable
(HAS_Z3 guard — mirrors the runtime degradation, like the preflight/cli
suites); the degradation tests — builtin backend → an honest 'unverified' —
and the value-type check (which needs no solver) run everywhere.
"""

import json
from pathlib import Path

import pytest

from gcp_grounding.claims import Claim, iam_policy_claims
from gcp_grounding.constraints import (
    check_cel,
    check_constraint_value,
    check_policy_subset,
)
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot

# Mirror the code's own degradation: z3 may import yet Z3Solver() can fail,
# in which case get_solver() falls back to the builtin backend and every
# check honestly degrades to 'unverified' — skip the definite-verdict tests.
HAS_Z3 = get_solver().backend == "z3"
needs_z3 = pytest.mark.skipif(not HAS_Z3, reason="z3 solver backend is not available")

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"

BUILTIN = get_solver(prefer="builtin")


@pytest.fixture(scope="module")
def snapshot():
    return GcpSnapshot.load(FIXTURES / "snapshot.json")


def cel(expression: str) -> Claim:
    return Claim("cel", expression, "bindings[0].condition.expression")


# -- (a) CEL condition satisfiability --------------------------------------


@needs_z3
def test_satisfiable_time_window_is_grounded():
    v = check_cel(cel('request.time < timestamp("2027-01-01T00:00:00Z")'))
    assert v.status == "grounded"
    assert v.kind == "cel"


@needs_z3
def test_empty_time_window_is_contradicted_dead_binding():
    v = check_cel(cel('request.time < timestamp("2020-01-01T00:00:00Z") && '
                      'request.time >= timestamp("2025-01-01T00:00:00Z")'))
    assert v.status == "contradicted"
    assert "never true" in v.message
    assert "dead binding" in v.message


@needs_z3
def test_tautology_is_grounded_with_always_true_warning():
    v = check_cel(cel('request.time < timestamp("2030-01-01T00:00:00Z") || '
                      'request.time >= timestamp("2030-01-01T00:00:00Z")'))
    assert v.status == "grounded"
    assert "always true" in v.message


@needs_z3
def test_resource_name_prefix_conflicting_with_equality_is_contradicted():
    v = check_cel(cel('resource.name.startsWith("projects/acme-prod/") && '
                      'resource.name == "projects/other/buckets/b"'))
    assert v.status == "contradicted"


@needs_z3
def test_resource_name_prefix_consistent_with_equality_is_grounded():
    v = check_cel(cel('resource.name.startsWith("projects/acme-prod/") && '
                      'resource.name == "projects/acme-prod/buckets/b"'))
    assert v.status == "grounded"


@needs_z3
def test_negation_and_parentheses_are_translated():
    v = check_cel(cel('!(request.time >= timestamp("2027-01-01T00:00:00Z")) && '
                      'request.time >= timestamp("2027-06-01T00:00:00Z")'))
    assert v.status == "contradicted"


@needs_z3
def test_unsupported_cel_function_is_unverified_never_a_false_verdict():
    v = check_cel(cel("resource.name.extract('{x}')"))
    assert v.status == "unverified"
    assert "not decided" in v.message


@needs_z3
def test_runtime_attribute_cel_is_unverified():
    assert check_cel(cel("request.auth.claims.admin == true")).status == "unverified"


@needs_z3
def test_malformed_timestamp_is_unverified():
    assert check_cel(cel('request.time < timestamp("not-a-time")')).status == "unverified"


@needs_z3
def test_cross_type_comparison_is_unverified():
    assert check_cel(cel('request.time == "2027-01-01"')).status == "unverified"


@needs_z3
def test_sub_microsecond_timestamps_are_unverified_never_contradicted():
    # datetime.fromisoformat would truncate the ns digits, collapsing this
    # genuinely satisfiable window to t > c && t < c → a false 'contradicted'.
    v = check_cel(cel('request.time > timestamp("2026-01-01T00:00:00.000000100Z") && '
                      'request.time < timestamp("2026-01-01T00:00:00.000000900Z")'))
    assert v.status == "unverified"
    assert "not decided" in v.message
    # The dual: two ns-distinct instants must not collapse to a false 'grounded'.
    v = check_cel(cel('request.time == timestamp("2026-01-01T00:00:00.000000100Z") && '
                      'request.time == timestamp("2026-01-01T00:00:00.000000900Z")'))
    assert v.status == "unverified"


@needs_z3
def test_microsecond_timestamps_stay_decidable():
    # Exactly six fractional digits are representable — no false degradation.
    v = check_cel(cel('request.time > timestamp("2026-01-01T00:00:00.000001Z") && '
                      'request.time < timestamp("2026-01-01T00:00:00.000009Z")'))
    assert v.status == "grounded"


@needs_z3
def test_offsetless_timestamp_is_unverified_never_a_tautology():
    # RFC 3339 mandates a UTC offset; in production this literal errors at
    # evaluation time and the binding never grants — 'always true' would be
    # the exact inverse.
    v = check_cel(cel('request.time < timestamp("2026-01-01T00:00:00") || '
                      'request.time >= timestamp("2026-01-01T00:00:00")'))
    assert v.status == "unverified"
    assert "not decided" in v.message


@needs_z3
def test_date_only_timestamp_is_unverified():
    assert check_cel(cel('request.time < timestamp("2020-01-01")')).status == "unverified"


@needs_z3
def test_deeply_nested_expression_is_unverified_not_a_crash():
    # The recursive-descent parser must degrade, not let RecursionError
    # escape check_cel's 'never a false verdict / never a traceback' contract.
    v = check_cel(cel("(" * 20000 + "true" + ")" * 20000))
    assert v.status == "unverified"
    assert "not decided" in v.message
    assert check_cel(cel("!" * 20000 + "true")).status == "unverified"


@needs_z3
def test_bang_before_a_comparison_is_unverified():
    # In CEL '!' binds tighter than comparisons: this expression means
    # (!request.time) < ts — a type error, not Not(request.time < ts).
    v = check_cel(cel('!request.time < timestamp("2026-01-01T00:00:00Z")'))
    assert v.status == "unverified"
    assert "not decided" in v.message
    assert check_cel(cel('!resource.name == "projects/p"')).status == "unverified"
    # '!' before '(' / boolean literals / another '!' keeps its CEL meaning.
    assert check_cel(cel("!false")).status == "grounded"
    assert check_cel(cel("!!true")).status == "grounded"


@needs_z3
def test_fixture_policy_conditions_end_to_end():
    # The shared fixture policies: the good one's time window is open, the
    # bad one's is empty (before 2020 AND on/after 2025).
    policies = FIXTURES / "policies"
    good = json.loads((policies / "iam_policy_good.json").read_text(encoding="utf-8"))
    bad = json.loads((policies / "iam_policy_bad.json").read_text(encoding="utf-8"))
    good_cels = [c for c in iam_policy_claims(good) if c.kind == "cel"]
    bad_cels = [c for c in iam_policy_claims(bad) if c.kind == "cel"]
    assert good_cels and bad_cels
    assert [check_cel(c).status for c in good_cels] == ["grounded"]
    assert [check_cel(c).status for c in bad_cels] == ["contradicted"]


def test_cel_without_z3_degrades_to_unverified():
    v = check_cel(cel('request.time < timestamp("2027-01-01T00:00:00Z")'), solver=BUILTIN)
    assert v.status == "unverified"
    assert "z3" in v.message


def test_check_cel_rejects_non_cel_claims():
    with pytest.raises(ValueError):
        check_cel(Claim("role", "roles/viewer", "bindings[0].role"))


# -- (b) constraint value-type (no solver needed — works without z3) -------


def test_list_usage_of_boolean_constraint_is_contradicted(snapshot):
    claim = Claim("constraint_value", "constraints/compute.disableSerialPortAccess",
                  "spec.rules[0].values", is_list=True)
    v = check_constraint_value(claim, snapshot)
    assert v.status == "contradicted"
    assert v.kind == "constraint"
    assert "boolean" in v.message


def test_boolean_usage_of_list_constraint_is_contradicted(snapshot):
    claim = Claim("constraint_value", "constraints/compute.vmExternalIpAccess",
                  "spec.rules[0].enforce", is_list=False)
    assert check_constraint_value(claim, snapshot).status == "contradicted"


def test_matching_value_types_are_grounded(snapshot):
    boolean = Claim("constraint_value", "constraints/iam.disableServiceAccountKeyCreation",
                    "spec.rules[0].enforce", is_list=False)
    listy = Claim("constraint_value", "constraints/compute.vmExternalIpAccess",
                  "spec.rules[0].values", is_list=True)
    assert check_constraint_value(boolean, snapshot).status == "grounded"
    assert check_constraint_value(listy, snapshot).status == "grounded"


def test_value_type_without_captured_constraints_is_unverified():
    empty = GcpSnapshot(captured_at="2026-07-18T09:30:00Z")
    claim = Claim("constraint_value", "constraints/compute.disableSerialPortAccess",
                  "booleanPolicy", is_list=False)
    assert check_constraint_value(claim, empty).status == "unverified"


def test_value_type_of_unenumerated_constraint_is_unverified(snapshot):
    # Existence is the reasoner's verdict; this check must not double-report.
    claim = Claim("constraint_value", "constraints/notreal.someConstraint",
                  "booleanPolicy", is_list=False)
    assert check_constraint_value(claim, snapshot).status == "unverified"


def test_value_type_outside_boolean_and_list_is_unverified():
    # fetch stores value_type='unknown' for constraints that are neither
    # booleanConstraint nor listConstraint; that record shape must degrade
    # to unverified, never mint a contradicted/grounded verdict.
    snap = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T09:30:00Z",
        "constraints": {"constraints/example.mystery": {"value_type": "unknown"}},
    })
    claim = Claim("constraint_value", "constraints/example.mystery",
                  "booleanPolicy", is_list=False)
    v = check_constraint_value(claim, snap)
    assert v.status == "unverified"
    assert "unknown" in v.message


def test_check_constraint_value_rejects_other_kinds(snapshot):
    with pytest.raises(ValueError):
        check_constraint_value(Claim("constraint", "constraints/x", "name"), snapshot)


# -- (c) IAM policy subset (opt-in: baseline provided) ---------------------


OLD = {"bindings": [
    {"role": "roles/bigquery.dataViewer",
     "members": ["group:data-eng@acme.example", "user:alice@acme.example"]},
    {"role": "roles/bigquery.jobUser",
     "members": ["serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com"]},
]}


@needs_z3
def test_dropping_a_grant_is_still_a_subset():
    new = {"bindings": [{"role": "roles/bigquery.dataViewer",
                         "members": ["user:alice@acme.example"]}]}
    v = check_policy_subset(new, OLD)
    assert v.status == "grounded"
    assert v.kind == "subset"


@needs_z3
def test_identical_policies_are_a_subset():
    assert check_policy_subset(OLD, OLD).status == "grounded"


@needs_z3
def test_added_member_is_contradicted_with_the_extra_grant_named():
    new = {"bindings": [{"role": "roles/bigquery.dataViewer",
                         "members": ["user:alice@acme.example",
                                     "user:mallory@acme.example"]}]}
    v = check_policy_subset(new, OLD)
    assert v.status == "contradicted"
    assert "roles/bigquery.dataViewer" in v.message
    assert "user:mallory@acme.example" in v.message


@needs_z3
def test_existing_member_gaining_a_new_role_is_contradicted():
    new = {"bindings": [{"role": "roles/owner", "members": ["user:alice@acme.example"]}]}
    assert check_policy_subset(new, OLD).status == "contradicted"


@needs_z3
def test_empty_new_policy_is_a_subset_of_anything():
    assert check_policy_subset({"bindings": []}, OLD).status == "grounded"
    assert check_policy_subset({"bindings": []}, {"bindings": []}).status == "grounded"


def test_binding_with_an_unrecognized_key_is_unverified():
    # 'member' (singular) is exactly the LLM typo this gate exists to catch:
    # ignoring the key would affirm new⊆old for a policy that grants more.
    new = {"bindings": [
        {"role": "roles/bigquery.dataViewer", "members": ["user:alice@acme.example"]},
        {"role": "roles/owner", "member": ["user:mallory@acme.example"]},
    ]}
    v = check_policy_subset(new, OLD)
    assert v.status == "unverified"
    assert "member" in v.message
    # v2 vocabulary ('principals') must be refused the same way.
    principals = {"bindings": [
        {"role": "roles/owner", "principals": ["user:mallory@acme.example"]}]}
    assert check_policy_subset(principals, OLD).status == "unverified"


def test_missing_bindings_key_is_unverified_not_an_empty_grant_set():
    # A document with no 'bindings' at all is not an IAM allow-policy shape;
    # treating it as zero grants would mint a vacuous 'subset holds'.
    assert check_policy_subset({}, OLD).status == "unverified"
    assert check_policy_subset(OLD, {"etag": "abc", "version": 3}).status == "unverified"


def test_deny_policy_documents_are_unverified():
    # IAM v2 deny policies carry access rules under 'rules[].denyRule'; both
    # grant sets would extract as empty, affirming subset-ness even when the
    # new document strips a deny rule (strictly widening effective access).
    deny_old = {"name": "policies/x/denypolicies/d", "etag": "abc",
                "rules": [{"denyRule": {
                    "deniedPrincipals": ["principalSet://goog/public:all"],
                    "deniedPermissions": ["iam.googleapis.com/roles.delete"]}}]}
    deny_new = {"name": "policies/x/denypolicies/d", "etag": "abc", "rules": []}
    v = check_policy_subset(deny_new, deny_old)
    assert v.status == "unverified"
    assert "deny" in v.message


def test_conditional_bindings_make_subset_unverified():
    new = {"bindings": [{
        "role": "roles/viewer",
        "members": ["user:alice@acme.example"],
        "condition": {"expression": 'request.time < timestamp("2027-01-01T00:00:00Z")'},
    }]}
    v = check_policy_subset(new, OLD)
    assert v.status == "unverified"
    assert "conditional" in v.message


def test_subset_without_z3_degrades_to_unverified():
    v = check_policy_subset(OLD, OLD, solver=BUILTIN)
    assert v.status == "unverified"
    assert "z3" in v.message


def test_subset_rejects_non_mapping_policies():
    with pytest.raises(ValueError):
        check_policy_subset(None, OLD)
    with pytest.raises(ValueError):
        check_policy_subset(OLD, ["not", "a", "policy"])
