"""Conditional-binding IAM subset proofs (check_policy_subset).

`_grant_pairs` used to raise `_Undecidable` on ANY binding carrying a
`condition`, so an agent could append `"condition": {"expression": "true"}`
to every binding and silently downgrade new⊆old to 'unverified'. These tests
pin the generalization: the condition's CEL formula is conjoined into the
grant predicate, so a translatable time/name window yields a real verdict,
and an *untranslatable* condition abstains while NAMING the offending
expression (the only trace the residual evasion now leaves).

z3-dependent verdicts (grounded / contradicted, and the named-expression
message) are guarded with `needs_z3`, mirroring the sibling constraint suite;
the shape guards that abstain before z3 is even consulted run everywhere.
"""

import re
from datetime import datetime

import pytest

from gcp_grounding.constraints import check_policy_subset
from gcp_grounding.core.report import GroundingReport
from gcp_grounding.core.solver import get_solver

HAS_Z3 = get_solver().backend == "z3"
needs_z3 = pytest.mark.skipif(not HAS_Z3, reason="z3 solver backend is not available")

WINDOW = 'request.time < timestamp("2027-01-01T00:00:00Z")'
ALICE = "user:alice@acme.example"
MALLORY = "user:mallory@acme.example"
# A condition outside the subset _CelToZ3 supports (claims._RUNTIME_ONLY_MARKERS
# already recognizes resource.matchTag as runtime-only).
UNTRANSLATABLE = "resource.matchTag('12345/env', 'prod')"


def _binding(role, member, expression=None):
    binding = {"role": role, "members": [member]}
    if expression is not None:
        binding["condition"] = {"expression": expression}
    return binding


# -- translatable conditions become real verdicts -----------------------------


@needs_z3
def test_narrowing_a_grant_with_a_time_window_is_grounded():
    old = {"bindings": [_binding("roles/viewer", ALICE)]}
    new = {"bindings": [_binding("roles/viewer", ALICE, WINDOW)]}
    v = check_policy_subset(new, old)
    assert v.status == "grounded"


@needs_z3
def test_removing_a_time_window_is_contradicted_with_a_time_outside_the_window():
    old = {"bindings": [_binding("roles/viewer", ALICE, WINDOW)]}
    new = {"bindings": [_binding("roles/viewer", ALICE)]}
    v = check_policy_subset(new, old)
    assert v.status == "contradicted"
    assert "request.time" in v.message
    # The witness names an instant at or beyond the window's exclusive bound.
    match = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", v.message)
    assert match is not None
    assert datetime.fromisoformat(match.group(0)) >= datetime(2027, 1, 1)


@needs_z3
def test_same_condition_and_same_grants_is_a_subset():
    doc = {"bindings": [_binding("roles/viewer", ALICE, WINDOW),
                        _binding("roles/editor", ALICE, WINDOW)]}
    # Identical condition strings must translate to the SAME z3 term so the
    # grants cancel; otherwise this would spuriously read as a widening.
    assert check_policy_subset(doc, doc).status == "grounded"


# -- the headline: a trivially-true condition no longer hides a widening -------


@needs_z3
def test_trivially_true_condition_on_every_binding_does_not_hide_a_widening():
    old = {"bindings": [_binding("roles/viewer", ALICE)]}
    new = {"bindings": [_binding("roles/viewer", ALICE, "true"),
                        _binding("roles/owner", MALLORY, "true")]}
    v = check_policy_subset(new, old)
    # The evasion is closed: the added roles/owner grant is a real widening.
    assert v.status == "contradicted"
    assert "roles/owner" in v.message
    assert MALLORY in v.message


# -- residual evasion: untranslatable conditions abstain, naming themselves ----


def test_untranslatable_condition_is_unverified_naming_the_expression():
    old = {"bindings": [_binding("roles/viewer", ALICE)]}
    new = {"bindings": [_binding("roles/owner", MALLORY, UNTRANSLATABLE)]}
    v = check_policy_subset(new, old)
    assert v.status == "unverified"
    # unverified never fails the gate — report.ok stays True.
    report = GroundingReport()
    report.add(v)
    assert report.ok is True
    if HAS_Z3:
        # The named expression is the only trace the residual evasion leaves.
        assert UNTRANSLATABLE in v.message


def test_full_evasion_every_binding_untranslatable_never_a_false_grounded():
    # EVERY binding in BOTH documents carries an untranslatable condition and
    # new adds a grant: this still disables new⊆old (exactly as before), but
    # abstains honestly — it must never fabricate a 'grounded' proof.
    old = {"bindings": [_binding("roles/viewer", ALICE, UNTRANSLATABLE)]}
    new = {"bindings": [_binding("roles/viewer", ALICE, UNTRANSLATABLE),
                        _binding("roles/owner", MALLORY, UNTRANSLATABLE)]}
    v = check_policy_subset(new, old)
    assert v.status == "unverified"
    assert v.status != "grounded"
    if HAS_Z3:
        assert UNTRANSLATABLE in v.message


# -- malformed condition shapes abstain before z3 is consulted -----------------


def test_condition_that_is_a_string_not_an_object_is_unverified():
    # A string condition (not {expression: ...}) must not be read as
    # unconditional; it abstains in _grant_pairs, before z3 is even needed.
    new = {"bindings": [{"role": "roles/viewer", "members": [ALICE],
                         "condition": WINDOW}]}
    old = {"bindings": [_binding("roles/viewer", ALICE)]}
    v = check_policy_subset(new, old)
    assert v.status == "unverified"
    assert "condition" in v.message
