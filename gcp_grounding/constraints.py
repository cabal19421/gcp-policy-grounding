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
  (role, member, condition) grant triples are encoded in z3 — each binding's
  CEL condition conjoined into its grant via :class:`_CelToZ3` — and "some
  new grant is not an old grant" is checked for satisfiability over a shared
  ``request.time`` / ``resource.name`` world; a witness grant →
  ``contradicted``. RESIDUAL EVASION: this closes the conditional-binding hole
  only for the ``request.time`` / ``resource.name`` CEL subset ``_CelToZ3``
  supports. ANY condition outside it — ``resource.matchTag(...)`` (which
  ``claims._RUNTIME_ONLY_MARKERS`` already flags runtime-only),
  ``request.auth.claims[...]``, or anything else the translator cannot
  represent — still returns the WHOLE check to ``unverified`` (with
  ``report.ok`` True) NAMING the offending expression, so an agent that
  appends such a condition to every binding still disables new⊆old exactly as
  before; the improvement is only that the abstain is now on the record rather
  than invisible. Closing it fully would need either a translator extension or
  a policy decision to treat an untranslatable condition as widening — neither
  is in scope here. A document whose grant set cannot be extracted faithfully
  (deny policies, no ``bindings`` array, unrecognized binding keys) is
  likewise ``unverified``.

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

# The literal shapes the encoding represents exactly: a full RFC 3339 instant
# with an explicit UTC offset. datetime.fromisoformat is too lenient to gate
# this itself — it silently truncates fractional digits beyond microseconds
# and accepts naive/date-only strings, all of which must land in unverified.
_TIMESTAMP_SHAPE = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}"
    r"(?:\.(?P<frac>\d+))?"
    r"(?:[Zz]|[+-]\d{2}:\d{2})")


def _epoch_micros(text: str) -> int:
    """A CEL timestamp literal → integer microseconds since the epoch.

    Only full RFC 3339 instants with an explicit UTC offset and at most
    microsecond precision are representable. Anything else — nanosecond
    digits (fromisoformat would silently truncate them, collapsing distinct
    instants), a missing offset, or a date-only literal (both invalid CEL:
    timestamp() requires RFC 3339, and an erroring condition never grants) —
    raises :class:`UnsupportedCel` → unverified, never a false verdict.
    """
    shape = _TIMESTAMP_SHAPE.fullmatch(text)
    if shape is None:
        raise UnsupportedCel(f"timestamp({text!r}) is not an RFC 3339 instant "
                             "with an explicit UTC offset")
    frac = shape.group("frac")
    if frac is not None and len(frac) > 6:
        raise UnsupportedCel(f"timestamp({text!r}) has sub-microsecond precision, "
                             "which the encoding cannot represent")
    iso = text[:-1] + "+00:00" if text[-1] in "Zz" else text
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        raise UnsupportedCel(f"timestamp({text!r}) is not an ISO-8601 instant") from None
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
    # unary := "!" ("!" | "(" | "true" | "false") ... | "(" or ")" | atom
    # — '!' binds tighter than comparisons in CEL, so '!' before anything
    # but a parenthesized formula, a boolean literal or another '!' would
    # mean e.g. (!request.time) < ts, a type error the encoding cannot
    # represent; it raises UnsupportedCel instead of mis-parsing.

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
            tok = self._peek()
            if tok not in (("op", "!"), ("op", "("),
                           ("name", "true"), ("name", "false")):
                got = "end of expression" if tok is None else repr(tok[1])
                raise UnsupportedCel(
                    f"'!' immediately before {got} — in CEL '!' binds tighter "
                    "than comparisons, so only '!(...)', '!true', '!false' and "
                    "'!!' are in the supported subset")
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
    except RecursionError:
        # The recursive-descent translation recurses once per nesting level;
        # a deeply nested expression must degrade, not crash the fail-open
        # ground_policy/CLI paths with a traceback.
        logger.debug("cel check unverified: expression too deeply nested to translate")
        return Verdict("unverified", "cel", claim.value, 0,
                       f"{where}: expression is too deeply nested to translate — "
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


def _grant_pairs(policy: Mapping[str, Any], label: str) -> frozenset[tuple[str, str, str | None]]:
    """The (role, member, condition) grant triples of an IAM policy. Every
    member string counts (allUsers widens the grant surface like any principal
    does); the third element is the binding's CEL condition expression, or
    ``None`` for an unconditional binding. Deny-policy documents ('rules'),
    documents without a 'bindings' array, malformed fields, unrecognized
    binding keys, and a ``condition`` present but not shaped as a mapping with
    a non-empty str ``expression`` all raise :class:`_Undecidable` — an
    unparseable condition must not be read as unconditional. Only
    ``"bindings": []`` is the empty set."""
    if "rules" in policy:
        raise _Undecidable(f"the {label} policy has 'rules' — a deny policy's "
                           "access surface is not a (role, member) grant set")
    bindings = policy.get("bindings")
    if bindings is None:
        raise _Undecidable(f"the {label} policy has no 'bindings' — "
                           "not an IAM allow-policy shape")
    if not isinstance(bindings, list):
        raise _Undecidable(f"the {label} policy's 'bindings' is "
                           f"{type(bindings).__name__}, not an array")
    triples: set[tuple[str, str, str | None]] = set()
    for i, binding in enumerate(bindings):
        if not isinstance(binding, Mapping):
            raise _Undecidable(f"the {label} policy's bindings[{i}] is not an object")
        unrecognized = sorted(repr(k) for k in binding
                              if k not in ("role", "members", "condition"))
        if unrecognized:
            raise _Undecidable(f"the {label} policy's bindings[{i}] has "
                               f"unrecognized key(s) {', '.join(unrecognized)} — "
                               "the grant set cannot be extracted faithfully")
        condition = binding.get("condition")
        if condition is None:
            expression: str | None = None
        elif not isinstance(condition, Mapping):
            raise _Undecidable(f"the {label} policy's bindings[{i}].condition is "
                               f"{type(condition).__name__}, not an object — an "
                               "unparseable condition must not be read as unconditional")
        else:
            expression = condition.get("expression")
            if not isinstance(expression, str) or not expression.strip():
                raise _Undecidable(f"the {label} policy's bindings[{i}].condition has no "
                                   "non-empty 'expression' string — an unparseable "
                                   "condition must not be read as unconditional")
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
            triples.add((role, member, expression))
    return frozenset(triples)


def _condition_formula(z3, expr: Optional[str], cache: dict):
    """The z3 boolean a binding's CEL condition contributes to its grant.

    ``None`` (an unconditional binding) is ``BoolVal(True)``. Every other
    expression is translated exactly once via :class:`_CelToZ3` and memoized
    by its string in *cache*, so an identical condition in the old and new
    policies produces the SAME z3 term — which is what lets the subset solver
    cancel a grant that is present under the same condition on both sides.
    """
    if expr is None:
        return z3.BoolVal(True)
    if expr not in cache:
        cache[expr] = _CelToZ3(z3, expr).translate()
    return cache[expr]


def check_policy_subset(new_policy: Mapping[str, Any], old_policy: Mapping[str, Any],
                        solver: Optional[ConstraintSolver] = None) -> Verdict:
    """Does the new IAM policy grant a subset of the old (baseline) one?

    Encodes both (role, member, condition) grant sets in z3 — each binding's
    CEL condition conjoined into its grant — and asks whether "some new grant
    is not an old grant" is satisfiable over a shared ``request.time`` /
    ``resource.name`` world: unsat → new⊆old (grounded); a model → that witness
    grant (with any request time / resource name a condition pinned it to)
    contradicts the subset claim. A condition ``_CelToZ3`` cannot represent in
    EITHER policy returns ``unverified`` naming it — never silently treated as
    ``True`` (which would fabricate a widening) nor ``False`` (a false proof).
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

    # Translate every distinct condition once, up front, so an untranslatable
    # one names itself in the abstain instead of surfacing as a bare grant.
    # The shared request.time/resource.name free variables the supported subset
    # references drive the witness, so track which the conditions actually use.
    cond_cache: dict = {}
    uses_time = uses_name = False
    for expr in sorted({c for grants in (new_grants, old_grants)
                        for (_, _, c) in grants if c is not None}):
        try:
            _condition_formula(z3, expr, cond_cache)
        except UnsupportedCel as exc:
            logger.debug("subset check unverified (unsupported condition): %s", exc)
            return Verdict("unverified", "subset", "iam-policy", 0,
                           f"new⊆old was not decided: condition {expr!r} is CEL "
                           f"outside the supported subset ({exc})")
        except RecursionError:
            logger.debug("subset check unverified: condition too deeply nested")
            return Verdict("unverified", "subset", "iam-policy", 0,
                           f"new⊆old was not decided: condition {expr!r} is too "
                           "deeply nested to translate")
        uses_time = uses_time or "request.time" in expr
        uses_name = uses_name or "resource.name" in expr

    role = z3.String("role")
    member = z3.String("member")

    def granted(grants: frozenset[tuple[str, str, str | None]]):
        if not grants:
            return z3.BoolVal(False)
        return z3.Or([z3.And(role == z3.StringVal(r), member == z3.StringVal(m),
                             _condition_formula(z3, c, cond_cache))
                      for r, m, c in sorted(grants, key=lambda t: (t[0], t[1], t[2] or ""))])

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
    witness = [f"the new policy grants {extra_role} to {extra_member}"]
    if uses_time:
        micros = model.eval(z3.Real("request.time"), model_completion=True)
        witness.append(f"at request.time {_iso_from_micros(micros)}")
    if uses_name:
        extra_name = model.eval(z3.String("resource.name"), model_completion=True).as_string()
        witness.append(f"with resource.name {extra_name!r}")
    return Verdict("contradicted", "subset", "iam-policy", 0,
                   f"new⊈old: {', '.join(witness)}, which the old policy does not")


def _iso_from_micros(value) -> str:
    """A z3 model value for ``request.time`` (microseconds since the epoch, a
    Real) rendered back to an ISO-8601 instant via the module's :data:`_EPOCH`.
    Falls back to the raw z3 rendering if the value is not a plain rational or
    is too far from the epoch for :class:`~datetime.datetime` to represent."""
    try:
        micros = value.as_fraction()
        return (_EPOCH + timedelta(microseconds=float(micros))).isoformat()
    except (AttributeError, OverflowError, ValueError, OSError):
        return str(value)
