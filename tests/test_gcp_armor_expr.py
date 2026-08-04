"""Cloud Armor match-expression translator tests.

The z3-backed assertions are skipped when no z3 backend is available (mirroring
the constraints suite); the pure static-analysis checks — ``referenced_expr_ids``
and the curated-vocabulary tuple — run everywhere. ``translate`` takes the z3
module as an argument, so the module imports without z3 present.
"""

import pytest

from gcp_grounding import packet
from gcp_grounding.armor_expr import (
    ArmorVars,
    PRECONFIGURED_EXPR_IDS,
    UnsupportedArmorExpr,
    armor_vars,
    referenced_expr_ids,
    translate,
)
from gcp_grounding.core.solver import get_solver

# Reuse core.solver's own z3 detection: the module the Z3Solver imported, or
# None on the builtin backend (z3 absent / broken).
_SOLVER = get_solver()
z3 = getattr(_SOLVER, "_z3", None)
needs_z3 = pytest.mark.skipif(z3 is None, reason="z3 backend is not available")


def _sat(formula) -> bool:
    s = z3.Solver()
    s.add(formula)
    return s.check() == z3.sat


def _unsat(formula) -> bool:
    s = z3.Solver()
    s.add(formula)
    return s.check() == z3.unsat


# -- inIpRange + negated preconfigured: translates and is satisfiable --------


@needs_z3
def test_ip_range_and_negated_preconfigured_is_satisfiable():
    v = armor_vars(z3)
    formula = translate(
        z3,
        "inIpRange(origin.ip, '203.0.113.0/24') "
        "&& !evaluatePreconfiguredExpr('xss-v33-stable')",
        v,
    )
    assert _sat(formula)
    # The paren'd negation form is equally in the subset.
    assert _sat(translate(
        z3, "!(evaluatePreconfiguredExpr('xss-v33-stable'))", armor_vars(z3)))


@needs_z3
def test_bang_before_a_region_comparison_is_unsupported():
    # '!' binds tighter than the comparison: !origin.region_code == 'US' means
    # (!origin.region_code) == 'US', a type error — not Not(region == 'US').
    with pytest.raises(UnsupportedArmorExpr):
        translate(z3, "!origin.region_code == 'US'", armor_vars(z3))


# -- CIDR containment: a /16 provably implies the enclosing /8 ----------------


@needs_z3
def test_narrower_cidr_implies_wider_cidr():
    v = armor_vars(z3)
    wider = translate(z3, "inIpRange(origin.ip, '10.0.0.0/8')", v)
    narrower = translate(z3, "inIpRange(origin.ip, '10.0.0.0/16')", v)
    assert _unsat(z3.And(narrower, z3.Not(wider)))
    # ...and the implication is not vacuous: the wider does not imply narrower.
    assert _sat(z3.And(wider, z3.Not(narrower)))


@needs_z3
def test_ipv6_and_malformed_cidr_raise_unsupported():
    with pytest.raises(UnsupportedArmorExpr):
        translate(z3, "inIpRange(origin.ip, '2001:db8::/32')", armor_vars(z3))
    with pytest.raises(UnsupportedArmorExpr):
        translate(z3, "inIpRange(origin.ip, 'not-a-cidr')", armor_vars(z3))


# -- region membership: satisfiable, and excludes a region not listed --------


@needs_z3
def test_region_in_list_is_satisfiable_and_excludes_others():
    v = armor_vars(z3)
    formula = translate(z3, "origin.region_code in ['US', 'CA']", v)
    assert _sat(formula)
    assert _unsat(z3.And(formula, v.region == z3.StringVal("DE")))
    assert _sat(z3.And(formula, v.region == z3.StringVal("US")))


@needs_z3
def test_region_equality_and_inequality():
    v = armor_vars(z3)
    eq = translate(z3, "origin.region_code == 'US'", v)
    ne = translate(z3, "origin.region_code != 'US'", v)
    assert _unsat(z3.And(eq, ne))
    assert _sat(z3.And(eq, v.region == z3.StringVal("US")))


# -- opaque Bool is cached per ArmorVars -------------------------------------


@needs_z3
def test_repeated_expr_id_returns_the_same_bool():
    v = armor_vars(z3)
    translate(z3, "evaluatePreconfiguredExpr('sqli-v33-stable')", v)
    first = v.preconfigured["sqli-v33-stable"]
    translate(z3, "evaluatePreconfiguredExpr('sqli-v33-stable')", v)
    second = v.preconfigured["sqli-v33-stable"]
    assert first is second
    # A negated reference to the same id is the negation of the same Bool, so
    # asserting both is unsatisfiable rather than two independent Bools.
    both = translate(
        z3,
        "evaluatePreconfiguredExpr('sqli-v33-stable') "
        "&& !evaluatePreconfiguredExpr('sqli-v33-stable')",
        armor_vars(z3),
    )
    assert _unsat(both)


@needs_z3
def test_preconfigured_waf_second_argument_is_parsed_and_discarded():
    v = armor_vars(z3)
    formula = translate(
        z3,
        "evaluatePreconfiguredWaf('sqli-v33-stable', "
        "{'sensitivity': 1, 'opt_out_rule_ids': ['owasp-crs-v030001-id942350-sqli']})",
        v,
    )
    assert _sat(formula)
    assert v.preconfigured["sqli-v33-stable"].eq(z3.Bool("waf:sqli-v33-stable"))


@needs_z3
def test_unknown_expr_id_still_translates_to_an_opaque_bool():
    # The curated list is incomplete: an unknown id is ignorance, not a
    # hallucination — it must translate, not raise.
    v = armor_vars(z3)
    assert "made-up-ruleset-v99" not in PRECONFIGURED_EXPR_IDS
    formula = translate(z3, "evaluatePreconfiguredExpr('made-up-ruleset-v99')", v)
    assert _sat(formula)
    assert "made-up-ruleset-v99" in v.preconfigured


# -- unsupported tokens raise, naming the offending token --------------------


@needs_z3
def test_unsupported_predicates_raise_naming_the_token():
    with pytest.raises(UnsupportedArmorExpr) as exc:
        translate(z3, "request.path.matches('/admin')", armor_vars(z3))
    assert "request.path.matches" in str(exc.value)

    with pytest.raises(UnsupportedArmorExpr) as exc:
        translate(z3, "origin.asn == 15169", armor_vars(z3))
    assert "origin.asn" in str(exc.value)

    with pytest.raises(UnsupportedArmorExpr) as exc:
        translate(z3, "inIpRange(origin.ip, '10.0.0.0/8') &&", armor_vars(z3))
    assert "&&" in str(exc.value)


@needs_z3
def test_deeply_nested_expression_raises_recursionerror_for_the_caller():
    # translate does NOT swallow RecursionError — the caller's abstain path
    # handles it, exactly as it does for _CelToZ3.
    with pytest.raises(RecursionError):
        translate(z3, "(" * 2000 + "true" + ")" * 2000, armor_vars(z3))


# -- static analysis (no z3 needed) ------------------------------------------


def test_referenced_expr_ids_finds_ids_in_nested_structure():
    expr = ("inIpRange(origin.ip, '10.0.0.0/8') && "
            "(evaluatePreconfiguredExpr('sqli-v33-stable') || "
            "!evaluatePreconfiguredExpr('unknown-id-x')) && "
            "evaluatePreconfiguredWaf('rce-v33-stable', {'sensitivity': 2})")
    ids = referenced_expr_ids(expr)
    assert ids == ("sqli-v33-stable", "unknown-id-x", "rce-v33-stable")


def test_referenced_expr_ids_deduplicates():
    expr = ("evaluatePreconfiguredExpr('sqli-v33-stable') || "
            "evaluatePreconfiguredExpr('sqli-v33-stable')")
    assert referenced_expr_ids(expr) == ("sqli-v33-stable",)


def test_referenced_expr_ids_empty_when_none_named():
    assert referenced_expr_ids("origin.region_code == 'US'") == ()


def test_curated_vocabulary_matches_the_design():
    assert "xss-v33-stable" in PRECONFIGURED_EXPR_IDS
    assert "json-sqli-canary" in PRECONFIGURED_EXPR_IDS
    assert len(PRECONFIGURED_EXPR_IDS) == len(set(PRECONFIGURED_EXPR_IDS))


def test_armor_vars_src_is_shared_with_packet_vars_src():
    # The shared source-address variable: same z3 name/sort → same constant.
    if z3 is None:
        pytest.skip("z3 backend is not available")
    assert armor_vars(z3).src.eq(packet.packet_vars(z3).src)
