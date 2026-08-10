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


@needs_z3
def test_conditional_bindings_are_first_class_not_unverified():
    # Conditional bindings used to downgrade the whole check to 'unverified';
    # now a NEW conditional grant absent from OLD is judged a real widening.
    # (The residual-evasion and narrowing cases live in
    # tests/test_gcp_subset_conditional.py.)
    new = {"bindings": [{
        "role": "roles/viewer",
        "members": ["user:alice@acme.example"],
        "condition": {"expression": 'request.time < timestamp("2027-01-01T00:00:00Z")'},
    }]}
    v = check_policy_subset(new, OLD)
    assert v.status == "contradicted"
    assert "roles/viewer" in v.message


def test_subset_without_z3_degrades_to_unverified():
    v = check_policy_subset(OLD, OLD, solver=BUILTIN)
    assert v.status == "unverified"
    assert "z3" in v.message


def test_subset_rejects_non_mapping_policies():
    with pytest.raises(ValueError):
        check_policy_subset(None, OLD)
    with pytest.raises(ValueError):
        check_policy_subset(OLD, ["not", "a", "policy"])


# ---------------------------------------------------------------------------
# MUTATION PAYDOWN RECORD — gcp_grounding/constraints.py (gx-debt-constraints).
# TEST-ONLY: this diff adds the tests below and changes no product source. It
# sits here, not above, so that tests/agentic/env.py's citation of line 27
# stays true.
#
# Instrument — AMENDMENT 4's focused validation. `harness` is not installed in
# this venv, so it is reached with
#   sys.path.insert(0, "/home/jones/Downloads/harness")
#   from harness.pipeline.mutation import collect_sites, mutation_score
# over `git worktree add --detach <scratch> <ref>` copies (never a `git
# archive` copy — this base is red under a bare python, and every mutant then
# scores "killed"), with
#   target_files = ["gcp_grounding/constraints.py"]   (this module, no other)
#   validation   = ["<venv>/bin/python -m pytest -q tests/test_gcp_constraints.py"]
#   PYTHONDONTWRITEBYTECODE=1 in the driver's environment (a stale __pycache__
#   invents survivors)
# Each row's copy was asserted GREEN unmutated first — before "37 passed",
# after "51 passed" — because a score taken over a red leg is worthless.
#
#   row     tree      sites  exhaustive (max_mutants=1000)   40-draw
#   before  c1c56047    125  72/125  = 0.576 (53 survivors)  23/40 = 0.575
#   after   fa6e9437    125  121/125 = 0.968 (4 survivors)   39/40 = 0.975
#
# The `after` tree's ONLY delta from the commit you are reading is this comment
# block, written into it afterwards.
#
# The ~0.75 wall is cleared on both legs. MUST-FAIL-FIRST, in the only form a
# paydown can take: the 49 sites that move from survivor to killed between
# those rows each had its mutant applied ALONE to an isolated copy, one suite
# run per mutant, and the focused suite reported FAILED there and PASSED on
# clean source — that is exactly what the survivor-set difference measures.
#
# Killed here, by group (line numbers are constraints.py's at c1c56047):
#   verdict lineno 0 x19  305 312 320 325 328 331 334 352 356 361 365 368 476
#                         483 499 504 524 528 540 — 325 and 528 are the "solver
#                         gave up" arms, which no offline document reaches and
#                         _AlwaysUnknown below does
#   `where` fallback      302 349      comparison encoding  242 244 246 248
#   tokenizer / parser    124 126 128 158 203 234 273
#   timestamp literals    81 x3 108 111               grant extraction  420 425 431
#   witness world         116 492 507 508 535 538 551
#   grant ordering        518 (`1`->`2` and `or`->`and`)
#
# The 4 survivors, NAMED rather than excluded, each EQUIVALENT by argument:
#   122 `while pos < len(expression)` -> `<=`: at pos == len every branch of
#     _TOKEN needs at least one character, so the match is None, `rest` is empty
#     and the loop breaks with the same token list — one idle iteration, no
#     observable difference.
#   518 `t[0]` -> `t[1]` in the sort key: the sort only orders the disjuncts of
#     a z3 `Or`, which is commutative, so the formula and its decision are
#     unchanged; the key stays a total order over the same finite set, so the
#     search stays deterministic.
#   531, 532 `model_completion=True` on `role` / `member`: a sat model asserts
#     granted(new_grants), an `Or` of `And`s each pinning both variables to a
#     StringVal, so neither is ever unassigned and completion cannot fire. The
#     SAME flag on request.time / resource.name (535, 538) is NOT equivalent —
#     a condition can put those in the world while the witness grant constrains
#     neither — and both are killed above.
# ---------------------------------------------------------------------------

# -- (d) mutation paydown: every arm, boundary and witness -----------------


class _AlwaysUnknown:
    """The real z3 behind a ``Solver`` that always answers ``unknown``.

    Nothing an offline document can say drives z3 to give up, yet both
    solver-backed checks carry an arm for it and each must abstain there
    rather than read "not unsat" as "satisfiable". ``constraints`` takes the
    z3 module off whatever solver front-end it is handed, so one stand-in
    plays both parts.
    """

    backend = "z3-always-unknown"

    class _Solver:
        def __init__(self, z3):
            self._z3 = z3

        def add(self, *_formulas):
            pass

        def check(self):
            return self._z3.unknown

    def __init__(self, z3):
        self._real = z3
        self._z3 = self

    def __getattr__(self, name):
        return getattr(self._real, name)

    def Solver(self):
        return self._Solver(self._real)


GAVE_UP = _AlwaysUnknown(getattr(get_solver(), "_z3", None)) if HAS_Z3 else None

WHERE = "bindings[0].condition.expression"
K = 'timestamp("2027-01-01T00:00:00Z")'
OPEN = f"request.time < {K}"
NESTED = "(" * 20000 + "true" + ")" * 20000
DAY = (f"request.time >= {K} && "
       'request.time < timestamp("2027-01-02T00:00:00Z")')
PREFIX = 'resource.name.startsWith("projects/acme-prod/")'
EXTRA = {"role": "roles/owner", "members": ["user:mallory@acme.example"]}


def _new(**extra):
    """A one-binding new policy granting a role OLD grants to nobody."""
    return {"bindings": [dict(EXTRA, **extra)]}


def _pins(arms, kind):
    """Each arm decided something, named its own reason, and pointed at no
    source line — a policy document is JSON, so every verdict carries 0."""
    for verdict, status, reason in arms:
        assert (verdict.status, verdict.kind, verdict.lineno) == (status, kind, 0), verdict
        assert reason in verdict.message, verdict.message


@needs_z3
def test_every_cel_arm_decides_names_its_reason_and_its_location():
    arms = [
        (check_cel(cel(OPEN), solver=BUILTIN), "unverified", "z3 is not available"),
        (check_cel(cel("resource.name.extract('x')")), "unverified",
         "outside the supported subset"),
        (check_cel(cel(NESTED)), "unverified", "too deeply nested"),
        (check_cel(cel(OPEN), solver=GAVE_UP), "unverified", "solver returned unknown"),
        (check_cel(cel(f'{OPEN} && request.time >= timestamp("2028-01-01T00:00:00Z")')),
         "contradicted", "dead binding"),
        (check_cel(cel("true")), "grounded", "always true"),
        (check_cel(cel(OPEN)), "grounded", "condition is satisfiable"),
    ]
    _pins(arms, "cel")
    for verdict, _status, _reason in arms:
        assert verdict.message.startswith(WHERE + ": "), verdict.message


def test_every_constraint_value_arm_decides_and_names_its_location(snapshot):
    def claim(name, is_list=False):
        return Claim("constraint_value", name, "spec.rules[0]", is_list=is_list)

    serial = "constraints/compute.disableSerialPortAccess"
    mystery = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T09:30:00Z",
        "constraints": {"constraints/example.mystery": {"value_type": "unknown"}}})
    arms = [
        (check_constraint_value(claim(serial),
                                GcpSnapshot(captured_at="2026-07-18T09:30:00Z")),
         "unverified", "were not captured"),
        (check_constraint_value(claim("constraints/notreal.x"), snapshot),
         "unverified", "is not in the snapshot"),
        (check_constraint_value(claim("constraints/example.mystery"), mystery),
         "unverified", "value_type='unknown'"),
        (check_constraint_value(claim(serial), snapshot),
         "grounded", "matches the declared value type"),
        (check_constraint_value(claim(serial, is_list=True), snapshot),
         "contradicted", "declares it boolean-typed"),
    ]
    _pins(arms, "constraint")
    for verdict, _status, _reason in arms:
        assert verdict.message.startswith("spec.rules[0]: "), verdict.message


@needs_z3
def test_every_subset_arm_decides_and_points_at_no_line():
    runtime = {"expression": "request.auth.claims.admin == true"}
    _pins([
        (check_policy_subset({}, OLD), "unverified", "no 'bindings'"),
        (check_policy_subset(OLD, OLD, solver=BUILTIN), "unverified", "z3 is not available"),
        (check_policy_subset(_new(condition=runtime), OLD), "unverified",
         "outside the supported subset"),
        (check_policy_subset(_new(condition={"expression": NESTED}), OLD),
         "unverified", "too deeply nested"),
        (check_policy_subset(OLD, OLD, solver=GAVE_UP), "unverified",
         "solver returned unknown"),
        (check_policy_subset({"bindings": []}, OLD), "grounded", "new⊆old holds"),
        (check_policy_subset(_new(), OLD), "contradicted", "new⊈old"),
    ], "subset")


@needs_z3
@pytest.mark.parametrize("expr,status", [
    (f"request.time < {K} && request.time >= {K}", "contradicted"),
    (f"request.time <= {K} && request.time >= {K}", "grounded"),
    (f"request.time > {K} && request.time <= {K}", "contradicted"),
    ('resource.name != "projects/p" && resource.name == "projects/p"', "contradicted"),
])
def test_each_comparison_operator_decides_its_own_boundary(expr, status):
    assert check_cel(cel(expr)).status == status


@needs_z3
def test_the_parser_names_the_token_it_could_not_read():
    v = check_cel(cel("request.time > " + "9" * 25))
    assert v.status == "unverified"
    # The unreadable remainder is quoted, and clipped so a runaway tail
    # cannot run away with the message.
    assert "unrecognized syntax at '" + "9" * 20 + "'" in v.message, v.message
    assert "unsupported trailing syntax at 'false'" in check_cel(cel("true false")).message
    assert "expected ')', got 'true'" in check_cel(cel("(true true)")).message
    assert check_cel(cel(f"request.time ! {K}")).status == "unverified"
    # A boolean literal consumes exactly one token, so the operator standing
    # after it is still there to parse.
    assert check_cel(cel("true && false")).status == "contradicted"


@needs_z3
def test_timestamp_literal_precision_and_zone_case():
    # Seven fractional digits: fromisoformat truncates them away, collapsing
    # this satisfiable window into t > c && t < c — a false 'contradicted'.
    assert check_cel(cel('request.time > timestamp("2026-01-01T00:00:00.0000001Z") && '
                         'request.time < timestamp("2026-01-01T00:00:00.0000009Z")')
                     ).status == "unverified"
    # RFC 3339 allows a lowercase zone designator and the shape regex admits
    # one, so it must be decided — fromisoformat alone refuses it.
    assert check_cel(cel('request.time < timestamp("2027-01-01T00:00:00z")')).status == "grounded"


@needs_z3
def test_the_witness_names_only_the_world_its_conditions_use():
    plain = check_policy_subset(_new(), OLD)
    assert plain.status == "contradicted"
    assert "request.time" not in plain.message and "resource.name" not in plain.message
    # A time-bounded condition puts an instant in the witness, and that
    # instant really is one the condition admits.
    timed = check_policy_subset(_new(condition={"expression": DAY}), OLD)
    when = timed.message.split("at request.time ")[1].split(",")[0]
    assert when.startswith("2027-01-01"), timed.message
    named = check_policy_subset(_new(condition={"expression": PREFIX}), OLD)
    assert "with resource.name 'projects/acme-prod/" in named.message, named.message
    # A condition somewhere else in the estate puts both variables in the
    # world while constraining neither at the witness grant: the model is
    # completed, so the witness still names an instant and a name rather
    # than the free variables themselves.
    free = check_policy_subset(_new(), {"bindings": [dict(
        OLD["bindings"][0], condition={"expression": f"{DAY} && {PREFIX}"})]})
    assert free.message.split("at request.time ")[1].startswith("1970-01-01"), free.message
    assert "with resource.name ''" in free.message, free.message


@needs_z3
def test_the_same_grant_conditional_and_unconditional_is_ordered():
    both = {"bindings": [EXTRA, dict(EXTRA, condition={"expression": DAY})]}
    assert check_policy_subset(both, OLD).status == "contradicted"
    assert check_policy_subset(both, both).status == "grounded"


@pytest.mark.parametrize("binding,named", [
    ({"role": "roles/owner", "members": ["user:m@acme.example"],
      "condition": {"expression": "  "}}, "bindings[0].condition"),
    ({"role": "", "members": ["user:m@acme.example"]}, "bindings[0].role"),
    ({"role": "roles/owner", "members": [""]}, "bindings[0].members[0]"),
])
def test_a_malformed_binding_is_refused_by_name(binding, named):
    v = check_policy_subset({"bindings": [binding]}, OLD)
    assert v.status == "unverified"
    assert named in v.message, v.message
