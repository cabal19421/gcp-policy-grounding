"""The one place a :mod:`gcp_grounding.sec_ast` AST becomes a z3 formula.

Structurally modelled on :class:`gcp_grounding.constraints._CelToZ3`
(constraints.py:129-269): a closed node set, one recursive descent, and a single
exception type — :class:`UnsupportedTerm` — that means *abstain*. Every caller
maps :class:`UnsupportedTerm` to ``unverified``; it never becomes a verdict.

This module NEVER ``import z3``. The z3 module is obtained the way the whole repo
obtains it — ``from .constraints import _z3_module`` (constraints.py:54-57) over a
``from .core.solver import get_solver`` (core/solver.py:105) — by the *caller*,
which passes the resulting module (or ``None``) in as the first argument. When
that argument is ``None`` — the builtin backend, where ``_z3_module(solver) is
None`` — both entry points raise :class:`UnsupportedTerm` immediately: an honest
abstention, never a silent pass.

Two encoding modes, one walker
------------------------------

Both modes share ONE recursive walker (:func:`_walk`) parameterized by a
leaf-resolution callback, so the node semantics (and/or/not/implies/quantifiers/
comparisons/…) cannot drift between them. Only quantifier expansion and leaf
resolution differ.

``symbolic(z3, ast) -> (formula, consts)`` maps each :func:`sec_ast.free_consts`
name to its z3 constant via ``z3.Const(name, z3_sort(...))``. BOTH ``forall`` and
``exists`` collapse to their body over ONE hypothetical record per
``(collection, var)`` pair. This is a *compile-time abstraction*: it proves the
body is neither dead (unsatisfiable) nor vacuous (a tautology) PER RECORD. It
does NOT decide the quantified obligation over arbitrary estates — that is
:func:`ground`'s job. ``consts`` is ordered by sorted name so formula
construction is deterministic.

``ground(z3, ast, instance) -> formula`` unrolls the quantifiers over the real
records in ``instance`` (a ``Mapping[str, Sequence[Mapping[str, Any]]]``):
``forall`` becomes ``z3.And([...])`` (empty → ``BoolVal(True)``), ``exists``
becomes ``z3.Or([...])`` (empty → ``BoolVal(False)``). Records are consumed in
the order given; callers sort. Every ``field`` resolves to a concrete literal, so
the resulting formula is CLOSED (its only free constants are exactly the symbolic
consts, and in ground mode there are none). A missing key, a ``None``, a value
whose Python type does not match the declared sort, or a collection referenced by
the AST yet absent from ``instance`` raises :class:`UnsupportedTerm` naming the
collection, index and field — never a guessed default.

Why ``cel`` is refused in BOTH modes
------------------------------------

``cel`` raises ``UnsupportedTerm("cel cannot be decided by this encoder — not
decided")`` in both modes. It is the one node the encoder refuses, and refusing
it is a *correctness requirement*, not a convenience. ``_CelToZ3`` mints free
symbols ``z3.Real("request.time")`` and ``z3.String("resource.name")``
(constraints.py:139-140) that are NOT in :func:`sec_ast.free_consts`, and two
invariants depend on every formula's free constants being exactly that set:

1. GROUND MODE IS ONLY SOUND ON A CLOSED FORMULA. ``sec_rules`` maps
   ``decide(obl) is True`` — sat — to ``grounded``, valid only because every
   ``field`` resolves to a literal so sat means *true*. With a ``cel`` node the
   formula is open; sat then means merely "there EXISTS some ``request.time``
   making the obligation hold", and for a ``refute`` promise over a time-bounded
   condition that is satisfiable for essentially any document — a genuinely
   violating policy would return ``grounded`` and the gate would exit 0. A silent
   pass is the worst outcome in the four-bucket contract.

2. WITNESS RE-CLASSIFICATION WOULD NEVER CONVERGE. ``sec_probes.classify``
   substitutes only the :func:`sec_ast.free_consts`, so a substituted ``cel``
   formula still has free variables; ``decide(sub) is True and decide(Not(sub))
   is False`` can never both hold, ``classify`` returns ``None``, ``reclassify``
   returns ``None``, and the promise flips from ``compiled`` on first compile to
   ``unverified`` on the second — breaking both the byte-identical-artifact
   invariant and the ``--check`` CI guarantee.

Refusing ``cel`` outright makes a cel-bearing promise compile to ``unverified``
DETERMINISTICALLY, which is honest, idempotent, and cheap. The node stays in
``sec_ast``'s grammar and in the parser so the sentence is never silently
dropped; it is the ENCODER that abstains. ``sec_rules`` carries the matching
closed-formula guard for encoders registered through :func:`register_encoder`.

Guards
------

:data:`MAX_DEPTH` (64) is re-checked here and not trusted from the parser.
:data:`MAX_UNROLL` (10_000) bounds the running count of leaf instantiations in
ground mode; exceeding it raises ``UnsupportedTerm("instance too large to unroll
— not decided")``. The top-level entry points wrap ``RecursionError`` into
:class:`UnsupportedTerm`, exactly as ``check_cel`` does at constraints.py:303-310,
so a deep artifact degrades instead of crashing the fail-open gate.

Extension hook
--------------

:data:`ENCODERS` is a ``dict[str, Callable]`` keyed by node kind, pre-populated
with the built-ins; :func:`register_encoder` supersedes an entry (e.g. a richer
``cidr_contains`` or ``port_in``) without editing this module.
:data:`ENCODER_VERSION` is written into the artifact's ``encoder`` field; bump it
whenever a built-in encoder's semantics change.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Mapping, Sequence

from .core.log import get_logger
from .sec_ast import COLLECTIONS, free_consts

logger = get_logger(__name__)

__all__ = [
    "UnsupportedTerm",
    "MAX_DEPTH", "MAX_UNROLL", "ENCODER_VERSION",
    "ENCODERS", "register_encoder",
    "z3_sort", "z3_literal", "dotted_quad_to_int", "parse_cidr",
    "symbolic", "ground",
]


# -- exception ----------------------------------------------------------------

class UnsupportedTerm(Exception):
    """The encoder cannot represent this term; every caller maps it to
    ``unverified`` — never to a verdict."""


# -- guards / version ---------------------------------------------------------

#: Re-checked here rather than trusted from the parser (mirrors sec_ast.MAX_DEPTH).
MAX_DEPTH = 64

#: The running count of leaf instantiations ground mode may unroll before it
#: abstains rather than build an unbounded formula.
MAX_UNROLL = 10_000

#: Written into the artifact's ``encoder`` field; bump on a built-in semantics
#: change so a stale artifact re-compiles instead of silently drifting.
ENCODER_VERSION = "gcp-sec-encode/1"


# -- sort / literal construction ----------------------------------------------

def z3_sort(z3, sort: str):
    """The z3 sort for a :data:`sec_ast.SORTS` name.

    ``Bool``→BoolSort, ``Str``→StringSort, ``Int``→IntSort, ``Real``→RealSort,
    ``Ip4``/``Cidr``→BitVecSort(32), ``Port``→BitVecSort(16), ``Proto``→
    BitVecSort(8).
    """
    if sort == "Bool":
        return z3.BoolSort()
    if sort == "Str":
        return z3.StringSort()
    if sort == "Int":
        return z3.IntSort()
    if sort == "Real":
        return z3.RealSort()
    if sort in ("Ip4", "Cidr"):
        return z3.BitVecSort(32)
    if sort == "Port":
        return z3.BitVecSort(16)
    if sort == "Proto":
        return z3.BitVecSort(8)
    raise UnsupportedTerm(f"no z3 sort for {sort!r} — not decided")


def z3_literal(z3, sort: str, value):
    """The z3 literal for a SCALAR ``value`` of ``sort``.

    ``sort == "Cidr"`` RAISES — a CIDR is a ``(base, mask)`` pair, never a scalar
    operand; it is resolved by the sort-directed leaf resolver, never here.
    """
    if sort == "Str":
        return z3.StringVal(value)
    if sort == "Bool":
        return z3.BoolVal(value)
    if sort == "Int":
        return z3.IntVal(value)
    if sort == "Real":
        return z3.RealVal(value)
    if sort == "Ip4":
        return z3.BitVecVal(dotted_quad_to_int(value), 32)
    if sort == "Port":
        return z3.BitVecVal(int(value), 16)
    if sort == "Proto":
        return z3.BitVecVal(int(value), 8)
    if sort == "Cidr":
        raise UnsupportedTerm(
            "a CIDR is never a scalar operand — it resolves to a (base, mask) "
            "pair, not via z3_literal — not decided")
    raise UnsupportedTerm(f"no z3 literal for sort {sort!r} — not decided")


# -- IPv4 / CIDR parsing (strict regex, abstain on anything else) -------------

_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
_PREFIX = r"(?:3[0-2]|[12]?[0-9])"
_DOTTED_RE = re.compile(rf"^{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}$")
_CIDR_RE = re.compile(rf"^({_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET})(?:/({_PREFIX}))?$")


def dotted_quad_to_int(s) -> int:
    """A strict dotted-quad IPv4 string → its 32-bit integer.

    Leading zeros and out-of-range octets are rejected; anything that is not a
    plain dotted quad raises :class:`UnsupportedTerm`.
    """
    if not isinstance(s, str) or _DOTTED_RE.match(s) is None:
        raise UnsupportedTerm(f"{s!r} is not a dotted-quad IPv4 address — not decided")
    a, b, c, d = (int(part) for part in s.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def parse_cidr(s) -> tuple[int, int]:
    """A strict ``"base"`` or ``"base/prefix"`` CIDR string → ``(base, mask)``.

    A missing prefix is treated as ``/32``. Anything else raises
    :class:`UnsupportedTerm`.
    """
    match = _CIDR_RE.match(s) if isinstance(s, str) else None
    if match is None:
        raise UnsupportedTerm(f"{s!r} is not a CIDR block — not decided")
    base = dotted_quad_to_int(match.group(1))
    prefix = 32 if match.group(2) is None else int(match.group(2))
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return base, mask


# -- shared sort lookup (works for either resolver's env shape) ----------------

def _sort_of(term: Mapping, env: Mapping) -> str:
    """The declared sort of a leaf ``term``.

    ``env`` maps a bound var to its collection name (symbolic mode) or to a
    ``(collection, record, index)`` tuple (ground mode); this reads the
    collection from either shape.
    """
    if term.get("node") == "lit":
        return term["sort"]
    var = term.get("var")
    binding = env.get(var)
    if binding is None:
        raise UnsupportedTerm(f"field variable {var!r} is not bound — not decided")
    coll = binding if isinstance(binding, str) else binding[0]
    spec = COLLECTIONS.get(coll)
    if spec is None:
        raise UnsupportedTerm(f"collection {coll!r} is not registered — not decided")
    fname = term.get("field")
    if fname not in spec.fields:
        raise UnsupportedTerm(f"{coll!r} has no field {fname!r} — not decided")
    return spec.fields[fname]


# -- leaf resolvers -----------------------------------------------------------
#
# A leaf resolver dispatches on the DECLARED SORT before touching z3_literal:
# a term of sort Cidr resolves to a (base, mask) PAIR of BitVec(32) terms, never
# to a single term, so a Cidr-sorted field can be the cidr operand of
# cidr_contains — the one shape a single z3_literal path could not express.

def _python_type_ok(sort: str, value) -> bool:
    if sort == "Bool":
        return isinstance(value, bool)
    if sort == "Str":
        return isinstance(value, str)
    if sort in ("Int", "Port", "Proto"):
        return isinstance(value, int) and not isinstance(value, bool)
    if sort == "Real":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if sort == "Ip4":
        return isinstance(value, str) and _DOTTED_RE.match(value) is not None
    return False


class _SymbolicResolver:
    """Resolves each ``field`` to a free z3 constant named
    ``<collection>#<var>.<field>``, and collapses every quantifier to its body
    over one hypothetical record."""

    def __init__(self, z3, consts: dict) -> None:
        self._z3 = z3
        self._consts = consts

    def quantify(self, kind, var, collection, body, env, walk):
        inner = dict(env)
        inner[var] = collection
        return walk(body, inner)

    def leaf(self, term, env):
        z3 = self._z3
        sort = _sort_of(term, env)
        if term.get("node") == "lit":
            if sort == "Cidr":
                base, mask = parse_cidr(term["value"])
                return (z3.BitVecVal(base, 32), z3.BitVecVal(mask, 32))
            return z3_literal(z3, sort, term["value"])
        var = term["var"]
        coll = env[var]
        fname = term["field"]
        name = f"{coll}#{var}.{fname}"
        if sort == "Cidr":
            base = self._consts.get(name)
            if base is None:
                base = z3.Const(name, z3.BitVecSort(32))
            # The Ip4 companion is a declared field, not a free_const; sec_ast
            # guarantees it exists, so build it directly as a BitVec(32) symbol.
            mask = z3.Const(f"{name}_mask", z3.BitVecSort(32))
            return (base, mask)
        const = self._consts.get(name)
        if const is None:
            const = z3.Const(name, z3_sort(z3, sort))
        return const


class _GroundResolver:
    """Unrolls each quantifier over the real records and resolves each ``field``
    to the record's concrete value."""

    def __init__(self, z3, instance: Mapping) -> None:
        self._z3 = z3
        self._instance = instance
        self._unrolled = 0

    def quantify(self, kind, var, collection, body, env, walk):
        z3 = self._z3
        records = self._instance.get(collection)
        if records is None:
            raise UnsupportedTerm(
                f"collection {collection!r} is referenced by the AST but absent "
                "from the instance — not decided")
        parts = []
        for index, record in enumerate(records):
            self._unrolled += 1
            if self._unrolled > MAX_UNROLL:
                raise UnsupportedTerm("instance too large to unroll — not decided")
            inner = dict(env)
            inner[var] = (collection, record, index)
            parts.append(walk(body, inner))
        if kind == "forall":
            return z3.And(parts) if parts else z3.BoolVal(True)
        return z3.Or(parts) if parts else z3.BoolVal(False)

    def leaf(self, term, env):
        z3 = self._z3
        sort = _sort_of(term, env)
        if term.get("node") == "lit":
            if sort == "Cidr":
                base, mask = parse_cidr(term["value"])
                return (z3.BitVecVal(base, 32), z3.BitVecVal(mask, 32))
            return z3_literal(z3, sort, term["value"])
        var = term["var"]
        coll, record, index = env[var]
        fname = term["field"]
        if sort == "Cidr":
            raw = self._require(coll, index, fname, record)
            if isinstance(raw, str) and "/" in raw:
                base, mask = parse_cidr(raw)
                return (z3.BitVecVal(base, 32), z3.BitVecVal(mask, 32))
            base = self._dotted(coll, index, fname, raw)
            mask_name = f"{fname}_mask"
            mask = self._dotted(coll, index, mask_name,
                                self._require(coll, index, mask_name, record))
            return (z3.BitVecVal(base, 32), z3.BitVecVal(mask, 32))
        value = self._require(coll, index, fname, record)
        if not _python_type_ok(sort, value):
            raise UnsupportedTerm(
                f"{coll}[{index}].{fname} = {value!r} does not match declared "
                f"sort {sort} — not decided")
        return z3_literal(z3, sort, value)

    @staticmethod
    def _require(coll, index, fname, record):
        if not isinstance(record, Mapping) or fname not in record:
            raise UnsupportedTerm(
                f"{coll}[{index}].{fname} is missing from the record — not decided")
        value = record[fname]
        if value is None:
            raise UnsupportedTerm(
                f"{coll}[{index}].{fname} is None — not decided")
        return value

    @staticmethod
    def _dotted(coll, index, fname, value) -> int:
        if not isinstance(value, str):
            raise UnsupportedTerm(
                f"{coll}[{index}].{fname} = {value!r} is not a dotted-quad "
                "string — not decided")
        try:
            return dotted_quad_to_int(value)
        except UnsupportedTerm:
            raise UnsupportedTerm(
                f"{coll}[{index}].{fname} = {value!r} is not a dotted quad — "
                "not decided") from None


# -- node encoders ------------------------------------------------------------
#
# Every encoder has the signature ``(z3, node, resolver, env, depth)`` and calls
# ``_walk`` for its boolean children. Quantifier expansion and leaf resolution go
# through the resolver so the two modes share this node vocabulary.

def _enc_true(z3, node, resolver, env, depth):
    return z3.BoolVal(True)


def _enc_false(z3, node, resolver, env, depth):
    return z3.BoolVal(False)


def _enc_and(z3, node, resolver, env, depth):
    return z3.And([_walk(z3, arg, resolver, env, depth + 1) for arg in node["args"]])


def _enc_or(z3, node, resolver, env, depth):
    return z3.Or([_walk(z3, arg, resolver, env, depth + 1) for arg in node["args"]])


def _enc_not(z3, node, resolver, env, depth):
    return z3.Not(_walk(z3, node["arg"], resolver, env, depth + 1))


def _enc_implies(z3, node, resolver, env, depth):
    return z3.Implies(_walk(z3, node["if"], resolver, env, depth + 1),
                      _walk(z3, node["then"], resolver, env, depth + 1))


def _enc_atmost(z3, node, resolver, env, depth):
    args = [_walk(z3, arg, resolver, env, depth + 1) for arg in node["args"]]
    return z3.AtMost(*args, node["k"])


def _enc_atleast(z3, node, resolver, env, depth):
    args = [_walk(z3, arg, resolver, env, depth + 1) for arg in node["args"]]
    return z3.AtLeast(*args, node["k"])


def _enc_forall(z3, node, resolver, env, depth):
    return resolver.quantify(
        "forall", node["var"], node["collection"], node["body"], env,
        lambda body, inner: _walk(z3, body, resolver, inner, depth + 1))


def _enc_exists(z3, node, resolver, env, depth):
    return resolver.quantify(
        "exists", node["var"], node["collection"], node["body"], env,
        lambda body, inner: _walk(z3, body, resolver, inner, depth + 1))


def _enc_cmp(z3, node, resolver, env, depth):
    op = node["op"]
    left = resolver.leaf(node["left"], env)
    right = resolver.leaf(node["right"], env)
    if op == "eq":
        return left == right
    if op == "ne":
        return left != right
    sort = _sort_of(node["left"], env)
    if sort in ("Ip4", "Port", "Proto"):
        # A bitvector address/port is unsigned; signed comparison is a bug.
        return {"lt": z3.ULT, "le": z3.ULE, "gt": z3.UGT, "ge": z3.UGE}[op](left, right)
    if op == "lt":
        return left < right
    if op == "le":
        return left <= right
    if op == "gt":
        return left > right
    return left >= right


def _set_literal(z3, sort, item):
    if sort == "Bool":
        return z3.BoolVal(item == "true")
    if sort == "Int":
        return z3.IntVal(int(item))
    if sort == "Real":
        return z3.RealVal(item)
    return z3_literal(z3, sort, item)


def _enc_in(z3, node, resolver, env, depth):
    term = resolver.leaf(node["term"], env)
    setnode = node["set"]
    sort = setnode["sort"]
    items = sorted(set(setnode["items"]))
    if not items:
        return z3.BoolVal(False)
    return z3.Or([term == _set_literal(z3, sort, item) for item in items])


def _enc_prefix(z3, node, resolver, env, depth):
    term = resolver.leaf(node["term"], env)
    return z3.PrefixOf(z3.StringVal(node["value"]), term)


def _enc_suffix(z3, node, resolver, env, depth):
    term = resolver.leaf(node["term"], env)
    return z3.SuffixOf(z3.StringVal(node["value"]), term)


def _enc_contains(z3, node, resolver, env, depth):
    term = resolver.leaf(node["term"], env)
    return z3.Contains(term, z3.StringVal(node["value"]))


def _enc_cidr_contains(z3, node, resolver, env, depth):
    base, mask = resolver.leaf(node["cidr"], env)
    addr = resolver.leaf(node["addr"], env)
    # Extract-free masking: (addr & mask) == (base & mask).
    return (addr & mask) == (base & mask)


def _enc_port_in(z3, node, resolver, env, depth):
    term = resolver.leaf(node["term"], env)
    return z3.And(z3.UGE(term, z3.BitVecVal(node["lo"], 16)),
                  z3.ULE(term, z3.BitVecVal(node["hi"], 16)))


def _enc_cel(z3, node, resolver, env, depth):
    raise UnsupportedTerm("cel cannot be decided by this encoder — not decided")


#: Keyed by node kind, pre-populated with the built-ins. Supersede an entry via
#: :func:`register_encoder`.
ENCODERS: dict[str, Callable] = {
    "true": _enc_true,
    "false": _enc_false,
    "and": _enc_and,
    "or": _enc_or,
    "not": _enc_not,
    "implies": _enc_implies,
    "atmost": _enc_atmost,
    "atleast": _enc_atleast,
    "forall": _enc_forall,
    "exists": _enc_exists,
    "cmp": _enc_cmp,
    "in": _enc_in,
    "prefix": _enc_prefix,
    "suffix": _enc_suffix,
    "contains": _enc_contains,
    "cidr_contains": _enc_cidr_contains,
    "port_in": _enc_port_in,
    "cel": _enc_cel,
}


def register_encoder(node_kind: str, fn: Callable) -> None:
    """Supersede the encoder for ``node_kind`` (e.g. a richer ``cidr_contains``
    or ``port_in``) without editing this module."""
    ENCODERS[node_kind] = fn


# -- the shared walker --------------------------------------------------------

def _walk(z3, node, resolver, env, depth):
    if depth > MAX_DEPTH:
        raise UnsupportedTerm(f"AST depth exceeds MAX_DEPTH ({MAX_DEPTH}) — not decided")
    if not isinstance(node, Mapping):
        raise UnsupportedTerm(f"expected a node object, got {node!r} — not decided")
    kind = node.get("node")
    enc = ENCODERS.get(kind)
    if enc is None:
        raise UnsupportedTerm(f"the encoder cannot represent node {kind!r} — not decided")
    return enc(z3, node, resolver, env, depth)


# -- entry points -------------------------------------------------------------

def symbolic(z3, ast: Mapping) -> tuple[Any, dict]:
    """Compile-time symbolic encoding: one free z3 const per field reference.

    Returns ``(formula, consts)`` where ``consts`` maps each
    :func:`sec_ast.free_consts` name to its ``z3.Const``, ordered by sorted name.
    Raises :class:`UnsupportedTerm` on any unsupported term, on a missing z3
    backend (``z3 is None``), or — degrading a deep artifact — on
    ``RecursionError``.
    """
    if z3 is None:
        raise UnsupportedTerm(
            "z3 is not available (builtin backend) — symbolic encoding not decided")
    try:
        consts: dict = {}
        for name, sort in free_consts(ast):
            consts[name] = z3.Const(name, z3_sort(z3, sort))
        resolver = _SymbolicResolver(z3, consts)
        formula = _walk(z3, ast, resolver, {}, 0)
    except RecursionError:
        logger.debug("symbolic encoding degraded: AST too deeply nested")
        raise UnsupportedTerm(
            "AST is too deeply nested to encode — not decided") from None
    return formula, consts


def ground(z3, ast: Mapping,
           instance: Mapping[str, Sequence[Mapping[str, Any]]]) -> Any:
    """Evaluation-time ground encoding: unroll quantifiers over ``instance``.

    Every ``field`` resolves to a concrete literal, so the formula is closed.
    Raises :class:`UnsupportedTerm` on any unsupported term, a missing/None/
    wrong-typed field, an absent collection, a missing z3 backend, an instance
    that would exceed :data:`MAX_UNROLL`, or a ``RecursionError``.
    """
    if z3 is None:
        raise UnsupportedTerm(
            "z3 is not available (builtin backend) — ground encoding not decided")
    try:
        resolver = _GroundResolver(z3, instance)
        formula = _walk(z3, ast, resolver, {}, 0)
    except RecursionError:
        logger.debug("ground encoding degraded: AST too deeply nested")
        raise UnsupportedTerm(
            "AST is too deeply nested to encode — not decided") from None
    return formula
