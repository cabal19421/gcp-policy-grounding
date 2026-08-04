"""Tests for :mod:`gcp_grounding.solve` — the one bounded, tri-state solver
front-end that keeps a slow formula from hanging the hook.

The z3-dependent assertions are skipped when z3 is not the active backend
(HAVE_Z3 guard, mirroring the constraints/preflight/cli suites); ``solve``
itself never imports z3 — the module the caller passes in comes from
``constraints._z3_module(get_solver())``, exactly as the runtime supplies it.
The abstain-on-absent-z3 tests run everywhere.
"""

import time

import pytest

from gcp_grounding import solve
from gcp_grounding.constraints import _z3_module
from gcp_grounding.core.solver import get_solver

# The exact module the runtime hands to solve.solver/decide: the z3 module the
# solver's own detection imported, or None on the builtin backend.
Z3 = _z3_module(get_solver())
HAVE_Z3 = Z3 is not None
needs_z3 = pytest.mark.skipif(not HAVE_Z3, reason="z3 solver backend is not available")


def _hard_unsat_formula(z3):
    """A formula z3 provably cannot finish inside a tiny timeout.

    Bitvector "factor a Mersenne prime": find x, y in [2, 2**31) with
    x * y == 2**61 - 1. The prime has no such factors, so the formula is
    UNSAT — but bitvectors are a *decidable* theory, so z3 never abandons it
    by incompleteness; it bit-blasts and searches, which for a prime is
    effectively integer factorization. The only way ``check()`` returns
    ``unknown`` is the timeout firing, which is what makes this a faithful
    probe that the ``"timeout"`` option is actually honored.
    """
    x = z3.BitVec("x", 64)
    y = z3.BitVec("y", 64)
    prime = 2305843009213693951  # 2**61 - 1, a Mersenne prime
    return z3.And(
        z3.ULT(x, 1 << 31),
        z3.ULT(y, 1 << 31),
        z3.UGT(x, 1),
        z3.UGT(y, 1),
        x * y == prime,
    )


# -- the abstain path is reachable without z3 --------------------------------


def test_decide_none_z3_abstains():
    # An absent z3 flows into the same abstain path as a timeout: None, no raise.
    assert solve.decide(None, "anything at all") is None


def test_model_or_none_none_z3_abstains():
    assert solve.model_or_none(None, "anything at all") == (None, None)


def test_timeout_constant_is_five_seconds():
    assert solve.SOLVE_TIMEOUT_MS == 5000


# -- tri-state decide over trivially sat / unsat -----------------------------


@needs_z3
def test_decide_true_for_sat():
    p = Z3.Bool("p")
    assert solve.decide(Z3, p) is True


@needs_z3
def test_decide_false_for_unsat():
    p = Z3.Bool("p")
    assert solve.decide(Z3, Z3.And(p, Z3.Not(p))) is False


@needs_z3
def test_model_or_none_returns_the_witness():
    x = Z3.Int("x")
    ok, model = solve.model_or_none(Z3, x == 5)
    assert ok is True
    assert model is not None
    assert model.eval(x, model_completion=True).as_long() == 5


@needs_z3
def test_model_or_none_unsat_is_false_no_model():
    p = Z3.Bool("p")
    ok, model = solve.model_or_none(Z3, Z3.And(p, Z3.Not(p)))
    assert ok is False
    assert model is None


@needs_z3
def test_string_and_cardinality_operators_go_through_the_wrapper():
    # sec_encode admits AtMost/AtLeast cardinality and Contains/PrefixOf/SuffixOf
    # string operators; the wrapper must decide them like anything else.
    bools = [Z3.Bool(f"b{i}") for i in range(8)]
    s0 = Z3.String("s0")
    formula = Z3.And(Z3.AtMost(*bools, 3), Z3.Contains(s0, Z3.StringVal("x")))
    # Clearly satisfiable (all bools false, s0 == "x"): the wrapper must not
    # report a false UNSAT. A sat verdict (True) or an honest abstain (None,
    # were the string solver to give up) are both acceptable; only False is a bug.
    assert solve.decide(Z3, formula) is not False


# -- the timeout is real: a hard formula abstains instead of hanging ---------


@needs_z3
def test_hard_formula_times_out_to_none_quickly():
    started = time.perf_counter()
    result = solve.decide(Z3, _hard_unsat_formula(Z3), timeout_ms=50)
    elapsed = time.perf_counter() - started
    # unknown -> None (the abstain), never True/False on a formula it did not finish.
    assert result is None
    # And it abstained by *stopping*, not by hanging: well under a second.
    assert elapsed < 1.0


@needs_z3
def test_timeout_option_is_actually_set():
    # Re-read that "timeout" took effect rather than trusting the set() call: on
    # a decidable-but-hard formula the ONLY route to unknown is the timeout, so
    # a typo in the option name (leaving the solver unbounded) could not produce
    # a prompt unknown here — it would grind past the wall-clock bound.
    s = solve.solver(Z3, timeout_ms=50)
    s.add(_hard_unsat_formula(Z3))
    started = time.perf_counter()
    result = s.check()
    elapsed = time.perf_counter() - started
    assert result == Z3.unknown
    assert elapsed < 1.0


# -- unsat_core plumbing for the O(n^2) independence probe -------------------


@needs_z3
def test_solver_unsat_core_supports_assert_and_track():
    s = solve.solver(Z3, unsat_core=True)
    p = Z3.Bool("p")
    s.assert_and_track(p, "tp")
    s.assert_and_track(Z3.Not(p), "tnp")
    assert s.check() == Z3.unsat
    core = s.unsat_core()
    assert len(core) >= 1
    names = {str(c) for c in core}
    assert names <= {"tp", "tnp"}
