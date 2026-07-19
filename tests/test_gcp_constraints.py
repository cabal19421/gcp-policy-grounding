"""Constraint-layer tests: CEL satisfiability, org-policy value-type
consistency, and new⊆old IAM policy subset — each against tiny fixtures.

z3-only assertions are skipped when z3 is unimportable (HAS_Z3 guard); the
degradation tests — builtin backend → an honest 'unverified' — and the
value-type check (which needs no solver) run everywhere.
"""

import importlib.util
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

HAS_Z3 = importlib.util.find_spec("z3") is not None
needs_z3 = pytest.mark.skipif(not HAS_Z3, reason="z3 is not importable")

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
    assert check_policy_subset({}, OLD).status == "grounded"
    assert check_policy_subset({"bindings": []}, {}).status == "grounded"


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
