"""One bounded, tri-state solver front-end so no check can hang the hook.

Every check in the security expansion creates its z3 solver here — this is the
single place. The module is tiny by design: no snapshot, no
:class:`~gcp_grounding.core.report.Verdict`, no domain knowledge. It never
``import z3`` itself; the caller passes the module obtained from
``constraints._z3_module(get_solver())`` (z3 when importable, ``None`` on the
builtin backend), exactly as :mod:`gcp_grounding.constraints` already does.

WHY IT EXISTS. ``constraints._decide`` builds a bare ``z3.Solver()`` with no
timeout. The expansion multiplies both the number of solves and the formula
complexity by an order of magnitude (per-candidate shadow re-checks, O(n^2)
promise-independence with unsat cores, and an encoding that admits string
operators — ``Contains`` / ``PrefixOf`` / ``SuffixOf`` — plus ``AtMost`` /
``AtLeast`` cardinality, on which z3 can run unbounded). Without a timeout the
``unknown -> unverified`` abstain path is unreachable for a *hang*, and in hook
mode a hang is worse than a crash: the agent's tool call never returns and there
is no watchdog in the fail-open contract. So every solver created anywhere in
the expansion is bounded here.

TIMEOUT IS AN ABSTAIN. A timeout surfaces as ``unknown``, which — through the
same tri-state contract as ``constraints._decide`` (True = sat, False = unsat,
None = unknown) — every check maps to ``unverified`` naming the reason. A
timeout is therefore NEVER a pass and NEVER a block: it is an abstain. Raising
:data:`SOLVE_TIMEOUT_MS` trades latency for coverage but can never trade safety.
And ``decide(None, ...)`` returns ``None`` too, so an absent z3 flows into the
same abstain path as a timeout rather than raising.
"""

from __future__ import annotations

from typing import Any, Optional, Tuple

__all__ = ["SOLVE_TIMEOUT_MS", "solver", "decide", "model_or_none"]

# Milliseconds. The bound is a latency/coverage knob, never a safety knob: a
# formula that does not finish in this budget abstains (``unknown`` ->
# ``unverified``); it is never silently passed or blocked.
SOLVE_TIMEOUT_MS = 5000


def solver(z3, *, timeout_ms: int = SOLVE_TIMEOUT_MS, unsat_core: bool = False):
    """A fresh ``z3.Solver()`` with ``timeout`` already applied.

    ``s.set("timeout", timeout_ms)`` bounds every ``check()`` on the returned
    solver; pass ``unsat_core=True`` to also enable ``assert_and_track`` /
    ``unsat_core`` for callers that need cores.
    """
    s = z3.Solver()
    s.set("timeout", timeout_ms)
    if unsat_core:
        s.set(unsat_core=True)
    return s


def decide(z3, formula, *, timeout_ms: int = SOLVE_TIMEOUT_MS) -> Optional[bool]:
    """Bounded tri-state satisfiability, the drop-in for ``constraints._decide``.

    True = satisfiable, False = unsatisfiable, None = ``unknown`` (the solver
    gave up or hit the timeout). ``decide(None, ...)`` returns None, so an
    absent z3 abstains exactly like a timeout instead of raising.
    """
    if z3 is None:
        return None
    s = solver(z3, timeout_ms=timeout_ms)
    s.add(formula)
    result = s.check()
    if result == z3.sat:
        return True
    if result == z3.unsat:
        return False
    return None


def model_or_none(
    z3, formula, *, timeout_ms: int = SOLVE_TIMEOUT_MS
) -> Tuple[Optional[bool], Optional[Any]]:
    """Like :func:`decide`, but returns the witness for callers that need it.

    ``(True, model)`` when satisfiable, ``(False, None)`` when unsatisfiable and
    ``(None, None)`` when ``unknown`` (timeout, solver gave up, or ``z3`` is
    ``None``) — the same tri-state abstain, carrying the model only on sat.
    """
    if z3 is None:
        return None, None
    s = solver(z3, timeout_ms=timeout_ms)
    s.add(formula)
    result = s.check()
    if result == z3.sat:
        return True, s.model()
    if result == z3.unsat:
        return False, None
    return None, None
