"""Constraint layer: the z3-backed satisfiability / consistency checks.

Three checks, each returning one :class:`~gcp_grounding.core.report.Verdict`;
the solver front-end is reused verbatim from
:func:`gcp_grounding.core.solver.get_solver` (z3 when importable, builtin
fallback otherwise — this module never imports z3 itself):

- :func:`check_cel` — is an IAM Condition ever true? The supported CEL
  subset (``request.time`` vs ``timestamp("…")`` comparisons, equality and
  ``startsWith`` on ``resource.name``, ``&&``/``||``/``!`` and parentheses)
  is translated to z3. Unsatisfiable → ``contradicted`` ("never true — dead
  binding"); a tautology → ``grounded`` with an always-true warning in the
  message. Anything outside the subset → ``unverified``, never a false
  verdict.
- :func:`check_constraint_value` — does a ``constraint_value`` claim's
  list/boolean usage match the ``value_type`` the snapshot declares for the
  org-policy constraint? A mismatch → ``contradicted``. Pure comparison —
  works identically with or without z3.
- :func:`check_policy_subset` — opt-in, only called when a baseline policy
  is provided: does the new IAM policy grant a subset of the old one? The
  (role, member) grant sets are encoded in z3 and "some new grant is not an
  old grant" is checked for satisfiability; a witness grant →
  ``contradicted``. Conditional bindings make the comparison
  request-time-dependent → ``unverified``.

Where z3 is absent, :func:`check_cel` and :func:`check_policy_subset`
degrade to ``unverified`` with the reason spelled out;
:func:`check_constraint_value` needs no solver at all.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional

from .claims import Claim
from .core.log import get_logger
from .core.report import Verdict
from .core.solver import ConstraintSolver, get_solver
from .knowledge import UNKNOWN, GcpSnapshot

logger = get_logger(__name__)

__all__ = ["UnsupportedCel", "check_cel", "check_constraint_value", "check_policy_subset"]


class UnsupportedCel(Exception):
    """The expression uses CEL outside the supported offline-decidable subset."""


def _z3_module(solver: ConstraintSolver):
    """The z3 module the solver's own detection imported — or None on the
    builtin backend. Reuses core.solver's detection; no second import path."""
    return getattr(solver, "_z3", None)


# -- (a) CEL condition satisfiability -----------------------------------------


_TOKEN = re.compile(
    r"\s*(?:(?P<op>&&|\|\||==|!=|<=|>=|<|>|!|\(|\))"
    r"|(?P<string>\"[^\"\\]*\"|'[^'\\]*')"
    r"|(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*))"
)

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _epoch_micros(text: str) -> int:
    """A CEL timestamp literal → integer microseconds since the epoch."""
    iso = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        raise UnsupportedCel(f"timestamp({text!r}) is not an ISO-8601 instant") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - _EPOCH) // timedelta(microseconds=1)


def _tokenize(expression: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(expression):
        match = _TOKEN.match(expression, pos)
        if match is None or match.end() == pos:
            rest = expression[pos:].strip()
            if not rest:
                break
            raise UnsupportedCel(f"unrecognized syntax at {rest[:20]!r}")
        pos = match.end()
        if match.lastgroup == "string":
            tokens.append(("str", match.group("string")[1:-1]))
        else:
            group = match.lastgroup or "op"
            tokens.append((group, match.group(group)))
    return tokens


_COMPARISON_OPS = ("==", "!=", "<", "<=", ">", ">=")


class _CelToZ3:
    """Recursive-descent translation of the supported CEL subset to a z3
    boolean formula. ``request.time`` is a Real (microseconds since epoch,
    so between any two distinct instants more instants exist);
    ``resource.name`` is a String. Anything else raises UnsupportedCel."""

    def __init__(self, z3, expression: str) -> None:
        self._z3 = z3
        self._tokens = _tokenize(expression)
        self._pos = 0
        self._time = z3.Real("request.time")
        self._name = z3.String("resource.name")

    def translate(self):
        formula = self._or()
        tok = self._peek()
        if tok is not None:
            raise UnsupportedCel(f"unsupported trailing syntax at {tok[1]!r}")
        return formula

    # grammar: or := and ("||" and)* ; and := unary ("&&" unary)* ;
    # unary := "!" unary | "(" or ")" | atom

    def _or(self):
        formula = self._and()
        while self._match("op", "||"):
            formula = self._z3.Or(formula, self._and())
        return formula

    def _and(self):
        formula = self._unary()
        while self._match("op", "&&"):
            formula = self._z3.And(formula, self._unary())
        return formula

    def _unary(self):
        if self._match("op", "!"):
            return self._z3.Not(self._unary())
        if self._match("op", "("):
            formula = self._or()
            self._expect(")")
            return formula
        return self._atom()

    def _atom(self):
        tok = self._peek()
        if tok is None:
            raise UnsupportedCel("expression ends where a condition was expected")
        kind, value = tok
        if kind == "name" and value in ("true", "false"):
            self._pos += 1
            return self._z3.BoolVal(value == "true")
        if kind == "name" and value == "resource.name.startsWith":
            self._pos += 1
            prefix = self._call_string_arg("resource.name.startsWith")
            return self._z3.PrefixOf(self._z3.StringVal(prefix), self._name)
        left_sort, left = self._operand()
        op = self._comparison_op()
        right_sort, right = self._operand()
        if left_sort != right_sort:
            raise UnsupportedCel(f"cannot compare {left_sort} with {right_sort}")
        if left_sort == "string" and op not in ("==", "!="):
            raise UnsupportedCel(f"operator {op!r} is not supported on strings")
        return self._compare(op, left, right)

    def _operand(self):
        kind, value = self._next("an operand")
        if kind == "str":
            return "string", self._z3.StringVal(value)
        if kind == "name":
            if value == "request.time":
                return "time", self._time
            if value == "resource.name":
                return "string", self._name
            if value == "timestamp":
                return "time", self._z3.RealVal(
                    _epoch_micros(self._call_string_arg("timestamp")))
        raise UnsupportedCel(f"unsupported operand {value!r}")

    def _comparison_op(self) -> str:
        kind, value = self._next("a comparison operator")
        if kind != "op" or value not in _COMPARISON_OPS:
            raise UnsupportedCel(f"expected a comparison operator, got {value!r}")
        return value

    def _compare(self, op: str, left, right):
        if op == "==":
            return left == right
        if op == "!=":
            return left != right
        if op == "<":
            return left < right
        if op == "<=":
            return left <= right
        if op == ">":
            return left > right
        return left >= right

    def _call_string_arg(self, func: str) -> str:
        self._expect("(")
        kind, value = self._next(f"the string argument of {func}")
        if kind != "str":
            raise UnsupportedCel(f"{func}() takes a string literal, got {value!r}")
        self._expect(")")
        return value

    # -- token plumbing -------------------------------------------------------

    def _peek(self) -> Optional[tuple[str, str]]:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _match(self, kind: str, value: str) -> bool:
        if self._peek() == (kind, value):
            self._pos += 1
            return True
        return False

    def _expect(self, op: str) -> None:
        if not self._match("op", op):
            tok = self._peek()
            got = "end of expression" if tok is None else repr(tok[1])
            raise UnsupportedCel(f"expected {op!r}, got {got}")

    def _next(self, what: str) -> tuple[str, str]:
        tok = self._peek()
        if tok is None:
            raise UnsupportedCel(f"expression ends where {what} was expected")
        self._pos += 1
        return tok


def _decide(z3, formula) -> Optional[bool]:
    """True = satisfiable, False = unsatisfiable, None = solver gave up."""
    s = z3.Solver()
    s.add(formula)
    result = s.check()
    if result == z3.sat:
        return True
    if result == z3.unsat:
        return False
    return None


def check_cel(claim: Claim, solver: Optional[ConstraintSolver] = None) -> Verdict:
    """Satisfiability verdict for a ``cel`` claim's IAM Condition."""
    if claim.kind != "cel":
        raise ValueError(f"check_cel needs a 'cel' claim, got kind={claim.kind!r}")
    solver = solver if solver is not None else get_solver()
    z3 = _z3_module(solver)
    where = claim.location or "condition"
    if z3 is None:
        logger.debug("cel check degraded to unverified: backend=%s has no z3", solver.backend)
        return Verdict("unverified", "cel", claim.value, 0,
                       f"{where}: z3 is not available (solver backend "
                       f"{solver.backend!r}) — CEL satisfiability was not decided")
    try:
        formula = _CelToZ3(z3, claim.value).translate()
    except UnsupportedCel as exc:
        logger.debug("cel check unverified (unsupported subset): %s", exc)
        return Verdict("unverified", "cel", claim.value, 0,
                       f"{where}: CEL outside the supported subset ({exc}) — "
                       "satisfiability was not decided")
    satisfiable = _decide(z3, formula)
    if satisfiable is None:
        return Verdict("unverified", "cel", claim.value, 0,
                       f"{where}: solver returned unknown — satisfiability was not decided")
    if satisfiable is False:
        return Verdict("contradicted", "cel", claim.value, 0,
                       f"{where}: condition is never true — dead binding")
    if _decide(z3, z3.Not(formula)) is False:
        return Verdict("grounded", "cel", claim.value, 0,
                       f"{where}: warning — condition is always true (a tautology); "
                       "the binding is effectively unconditional")
    return Verdict("grounded", "cel", claim.value, 0,
                   f"{where}: condition is satisfiable")


# -- (b) org-policy constraint value-type -------------------------------------


def check_constraint_value(claim: Claim, snapshot: GcpSnapshot) -> Verdict:
    """Does a ``constraint_value`` claim's list/boolean usage match the
    ``value_type`` the snapshot declares? Needs no solver: the comparison is
    decidable directly, so this check works identically with or without z3."""
    if claim.kind != "constraint_value":
        raise ValueError(f"check_constraint_value needs a 'constraint_value' claim, "
                         f"got kind={claim.kind!r}")
    usage = "list" if claim.is_list else "boolean"
    where = claim.location or "policy"
    record = snapshot.constraint(claim.value)
    if record is UNKNOWN:
        return Verdict("unverified", "constraint", claim.value, 0,
                       f"{where}: constraints were not captured in the snapshot — "
                       f"the {usage}-typed usage of {claim.value} was not checked")
    if record is None:
        return Verdict("unverified", "constraint", claim.value, 0,
                       f"{where}: {claim.value} is not in the snapshot (existence is the "
                       f"reasoner's verdict) — its value type cannot be checked")
    declared = record.get("value_type")
    if declared not in ("boolean", "list"):
        return Verdict("unverified", "constraint", claim.value, 0,
                       f"{where}: snapshot declares value_type={declared!r} for "
                       f"{claim.value} — not a type this check decides")
    if declared == usage:
        return Verdict("grounded", "constraint", claim.value, 0,
                       f"{where}: {usage}-typed usage matches the declared value type "
                       f"of {claim.value}")
    return Verdict("contradicted", "constraint", claim.value, 0,
                   f"{where}: {usage}-typed usage of {claim.value}, but the snapshot "
                   f"declares it {declared}-typed")


# -- (c) IAM policy subset (opt-in, baseline required) ------------------------


class _Undecidable(Exception):
    """The grant sets cannot be extracted faithfully — compare nothing
    rather than mint a false subset verdict."""


def _grant_pairs(policy: Mapping[str, Any], label: str) -> frozenset[tuple[str, str]]:
    """The (role, member) grant set of an IAM policy. Every member string
    counts (allUsers widens the grant surface like any principal does);
    malformed fields and conditional bindings raise :class:`_Undecidable`."""
    bindings = policy.get("bindings")
    if bindings is None:
        return frozenset()
    if not isinstance(bindings, list):
        raise _Undecidable(f"the {label} policy's 'bindings' is "
                           f"{type(bindings).__name__}, not an array")
    pairs: set[tuple[str, str]] = set()
    for i, binding in enumerate(bindings):
        if not isinstance(binding, Mapping):
            raise _Undecidable(f"the {label} policy's bindings[{i}] is not an object")
        if "condition" in binding:
            raise _Undecidable(f"the {label} policy's bindings[{i}] is conditional — "
                               "grant comparison is request-time-dependent")
        role = binding.get("role")
        if not isinstance(role, str) or not role:
            raise _Undecidable(f"the {label} policy's bindings[{i}].role is not a role name")
        members = binding.get("members", [])
        if not isinstance(members, list):
            raise _Undecidable(f"the {label} policy's bindings[{i}].members is not an array")
        for j, member in enumerate(members):
            if not isinstance(member, str) or not member:
                raise _Undecidable(f"the {label} policy's bindings[{i}].members[{j}] "
                                   "is not a member id")
            pairs.add((role, member))
    return frozenset(pairs)


def check_policy_subset(new_policy: Mapping[str, Any], old_policy: Mapping[str, Any],
                        solver: Optional[ConstraintSolver] = None) -> Verdict:
    """Does the new IAM policy grant a subset of the old (baseline) one?

    Encodes both (role, member) grant sets in z3 and asks whether "some new
    grant is not an old grant" is satisfiable: unsat → new⊆old (grounded);
    a model → that witness grant contradicts the subset claim.
    """
    for label, policy in (("new", new_policy), ("old", old_policy)):
        if not isinstance(policy, Mapping):
            raise ValueError(f"the {label} IAM policy must be a mapping, "
                             f"got {type(policy).__name__}")
    try:
        new_grants = _grant_pairs(new_policy, "new")
        old_grants = _grant_pairs(old_policy, "old")
    except _Undecidable as exc:
        logger.debug("subset check unverified: %s", exc)
        return Verdict("unverified", "subset", "iam-policy", 0,
                       f"new⊆old was not decided: {exc}")
    solver = solver if solver is not None else get_solver()
    z3 = _z3_module(solver)
    if z3 is None:
        logger.debug("subset check degraded to unverified: backend=%s has no z3",
                     solver.backend)
        return Verdict("unverified", "subset", "iam-policy", 0,
                       f"z3 is not available (solver backend {solver.backend!r}) — "
                       "new⊆old was not decided")
    role = z3.String("role")
    member = z3.String("member")

    def granted(pairs: frozenset[tuple[str, str]]):
        if not pairs:
            return z3.BoolVal(False)
        return z3.Or([z3.And(role == z3.StringVal(r), member == z3.StringVal(m))
                      for r, m in sorted(pairs)])

    s = z3.Solver()
    s.add(granted(new_grants), z3.Not(granted(old_grants)))
    result = s.check()
    if result == z3.unsat:
        return Verdict("grounded", "subset", "iam-policy", 0,
                       f"new⊆old holds: all {len(new_grants)} grants in the new policy "
                       "are already granted by the old policy")
    if result != z3.sat:
        return Verdict("unverified", "subset", "iam-policy", 0,
                       f"solver returned {result} — new⊆old was not decided")
    model = s.model()
    extra_role = model.eval(role, model_completion=True).as_string()
    extra_member = model.eval(member, model_completion=True).as_string()
    return Verdict("contradicted", "subset", "iam-policy", 0,
                   f"new⊈old: the new policy grants {extra_role} to {extra_member}, "
                   "which the old policy does not")
