"""Compile-time z3 well-formedness probes, witness minting and re-classification.

This is stage 2's *symbolic* layer: the checks the ``sec_requirements/`` compiler
runs once, at compile time, over :func:`gcp_grounding.sec_encode.symbolic`
formulas (one free z3 constant per ``<collection>#<var>.<field>``). It decides
whether a promise is well-formed, mints the mandatory positive/negative
witnesses from real z3 models, and re-classifies pinned witnesses so drift is a
compile failure rather than silent rot.

OBLIGATION AND POLARITY
-----------------------
:func:`obligation` is the SINGLE place polarity is applied. It returns ``formula``
when ``mode == "assert_satisfiable"`` (the pattern P must hold) and
``z3.Not(formula)`` when ``mode == "refute"`` (P must NOT hold). Everything
downstream — :func:`probe`, :func:`mint`, :func:`classify`, :func:`independence`
— reasons about the *obligation*, so ``positive`` always denotes a COMPLIANT
record and ``negative`` always denotes a VIOLATING record regardless of mode.
Getting this backwards inverts every security rule the compiler emits, so it is
done exactly once, here.

TRI-STATE DECISION
------------------
Every decision goes through :func:`gcp_grounding.solve.decide`, which has the
same contract as ``constraints._decide`` (constraints.py:272-281: True = sat,
False = unsat, None = unknown) but bounds the solver it builds with a timeout, so
a hard formula ABSTAINS (``unknown`` -> ``None``) instead of hanging the hook.
This module is the one that most needs it: :func:`independence` is O(n^2) over
promise pairs and the probes run over string-theory and cardinality formulas.
Every solver created here — the two in :func:`mint` and the tracked one in
:func:`independence` — comes from :func:`gcp_grounding.solve.solver`. We never
edit ``constraints.py`` and never reimplement the tri-state logic.

PROBES ARE FATAL, NOT ADVISORY
------------------------------
:func:`probe` computes ``satisfiable`` (``decide(obl)``: False means no record
can ever satisfy the promise) and ``non_tautological`` (``decide(Not(obl))``:
False means the promise forbids nothing). Both are deliberately FATAL here,
whereas ``check_cel`` only WARNS on a tautology at constraints.py:318-321. The
difference is intentional: a vacuous security requirement is worse than none,
because it reads as coverage. Both probes are per-record, matching
:mod:`sec_encode`'s symbolic mode, which collapses every quantifier to one
hypothetical record; the caller records ``probe_scope="per_record"`` and, when
the AST contains an ``exists`` (per :func:`sec_ast.has_existential`), a note
saying so.

INDEPENDENCE: WHEN A JOINT-UNSAT IS FATAL
-----------------------------------------
:func:`independence` looks for pairs of promises no single record can satisfy at
once. Conflicts are ADVISORY, not fatal, except in one case: a joint-unsat is
fatal ONLY when both promises are forall-rooted over a shared collection with no
existential anywhere, because only then does every document with at least one
such record necessarily fail one of them. In every other shape the two promises
can coexist over different records, so unconditional rejection would throw away
sound rules for a per-record artifact of the probe. :func:`independence` returns
the conflicting-id tuples with that fatal bit set; ``sx-sec-compile`` rejects
only the forall/forall case and otherwise records an ``unverified`` advisory
naming the pair. This is the repo's first use of ``assert_and_track`` /
``unsat_core``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

from . import sec_artifact, sec_ast, sec_encode, solve
from .core.log import get_logger

logger = get_logger(__name__)

__all__ = [
    "MAX_INDEPENDENCE",
    "ProbeResult", "Conflict", "IndependenceResult",
    "obligation", "probe", "mint", "classify", "reclassify", "independence",
]

#: Above this many promises the O(n^2) independence probe is skipped rather than
#: run; the caller leaves ``wellformedness.independent`` None with a note.
MAX_INDEPENDENCE = 64


# -- obligation (the one place polarity is applied) ---------------------------

def obligation(z3, formula, mode: str):
    """Apply the promise's polarity to *formula* — the single place it happens.

    Returns *formula* unchanged for ``assert_satisfiable`` and ``z3.Not(formula)``
    for ``refute``. A record satisfying the returned obligation is COMPLIANT
    (positive); a record satisfying its negation is VIOLATING (negative).
    """
    if mode == "assert_satisfiable":
        return formula
    if mode == "refute":
        return z3.Not(formula)
    raise ValueError(f"unknown mode {mode!r}; expected one of {sec_artifact.MODES}")


# -- probes -------------------------------------------------------------------

@dataclass(frozen=True)
class ProbeResult:
    """The two well-formedness verdicts for one obligation.

    ``satisfiable`` False means the promise can never be met by any record (a
    hard failure); None means the solver gave up, so we abstain. ``non_tautological``
    False means the promise forbids nothing (a hard failure). Both are per-record.
    """

    satisfiable: Optional[bool]
    non_tautological: Optional[bool]
    notes: tuple[str, ...] = ()


def probe(z3, obl, ast: Optional[Mapping] = None) -> ProbeResult:
    """Decide ``satisfiable`` and ``non_tautological`` for the obligation *obl*.

    ``satisfiable = decide(z3, obl)`` and ``non_tautological = decide(z3, Not(obl))``.
    With no z3 the two verdicts abstain (None) rather than raising. When *ast* is
    supplied and contains an existential, a per-record note is appended, since the
    symbolic probe collapses that existential to one hypothetical record.
    """
    notes: list[str] = []
    if ast is not None and sec_ast.has_existential(ast):
        notes.append("probe_scope=per_record: the symbolic probe collapses the "
                     "existential to one hypothetical record")
    if z3 is None:
        notes.append("z3 is not available — well-formedness was not decided")
        return ProbeResult(None, None, tuple(notes))
    satisfiable = solve.decide(z3, obl)
    non_tautological = solve.decide(z3, z3.Not(obl))
    return ProbeResult(satisfiable, non_tautological, tuple(notes))


# -- witnesses: minting -------------------------------------------------------

def _int_to_dotted(n: int) -> str:
    """A 32-bit unsigned integer -> its dotted-quad IPv4 string."""
    n &= 0xFFFFFFFF
    return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"


def _stringify(z3, model, const) -> str:
    """Sort-directed, round-trip-exact stringification of ``model``'s value.

    Str via ``.as_string()``, Bool as "true"/"false", Int and Real as ``str(int)``,
    Ip4 and Cidr as a dotted quad, Port and Proto as ``str(int)``. Every value is
    a plain string so the witness assignment is ``dict[str, str]``.
    """
    sort = const.sort()
    value = model.eval(const, model_completion=True)
    if sort.eq(z3.BoolSort()):
        return "true" if z3.is_true(value) else "false"
    if sort.eq(z3.StringSort()):
        return value.as_string()
    if sort.eq(z3.IntSort()):
        return str(value.as_long())
    if sort.eq(z3.RealSort()):
        return str(value.numerator_as_long() // value.denominator_as_long())
    # By elimination the sort is a fixed-width bitvector: Ip4/Cidr (32) render as
    # a dotted quad, Port (16) and Proto (8) as their integer.
    n = value.as_long()
    if sort.size() == 32:
        return _int_to_dotted(n)
    return str(n)


def _mint_one(z3, formula, consts: Mapping) -> Optional[dict]:
    """Solve *formula* in a fresh bounded solver; on sat, stringify every const."""
    ok, model = solve.model_or_none(z3, formula)
    if ok is not True:
        return None
    return {name: _stringify(z3, model, const) for name, const in consts.items()}


def mint(z3, obl, consts: Mapping):
    """Mint ``(positive, negative)`` witness assignments from z3 models.

    Solves ``obl`` (the positive/compliant witness) and ``z3.Not(obl)`` (the
    negative/violating witness) in two fresh solvers; each assignment stringifies
    EVERY const in *consts* with ``model_completion=True`` and is always
    ``dict[str, str]`` (the sort lives in ``consts`` / ``free_consts``). A side
    that is unsat or times out yields None rather than a guessed witness. With no
    z3 both sides abstain to None.
    """
    if z3 is None:
        return None, None
    positive = _mint_one(z3, obl, consts)
    negative = _mint_one(z3, z3.Not(obl), consts)
    return positive, negative


# -- witnesses: classification ------------------------------------------------

def _literal_from_string(z3, const, text: str):
    """Rebuild the z3 literal a :func:`_stringify` string round-trips to.

    Raises ``ValueError`` / :class:`sec_encode.UnsupportedTerm` on an
    unparseable literal, which every caller turns into an abstention.
    """
    sort = const.sort()
    if sort.eq(z3.BoolSort()):
        if text == "true":
            return z3.BoolVal(True)
        if text == "false":
            return z3.BoolVal(False)
        raise ValueError(f"not a bool literal: {text!r}")
    if sort.eq(z3.StringSort()):
        return z3.StringVal(text)
    if sort.eq(z3.IntSort()):
        return z3.IntVal(int(text))
    if sort.eq(z3.RealSort()):
        return z3.RealVal(int(text))
    if sort.size() == 32:
        return z3.BitVecVal(sec_encode.dotted_quad_to_int(text), 32)
    return z3.BitVecVal(int(text), sort.size())


def _assignment_of(witness) -> Optional[Mapping]:
    """The free-const -> literal mapping of *witness* (a Witness or a raw dict)."""
    if witness is None:
        return None
    if isinstance(witness, sec_artifact.Witness):
        return witness.assignment
    if isinstance(witness, Mapping):
        return witness
    return None


def classify(z3, ast: Mapping, mode: str, witness) -> Optional[bool]:
    """Re-classify a pinned *witness* against the symbolic obligation.

    Rebuilds the symbolic formula, applies :func:`obligation`, substitutes every
    pinned literal, then answers True when the substituted obligation is valid
    (``decide(sub) is True and decide(Not(sub)) is False``) — a compliant record;
    the mirror (unsat) for False — a violating record; and None for anything else
    (unknown, a witness that does not cover every free const, a missing key, or an
    unparseable literal). Never guesses.
    """
    if z3 is None:
        return None
    assignment = _assignment_of(witness)
    if assignment is None:
        return None
    try:
        formula, consts = sec_encode.symbolic(z3, ast)
    except sec_encode.UnsupportedTerm:
        return None
    try:
        obl = obligation(z3, formula, mode)
    except ValueError:
        return None
    subs = []
    for name, const in consts.items():
        if name not in assignment:
            return None  # does not cover every free const -> abstain, never guess
        try:
            literal = _literal_from_string(z3, const, assignment[name])
        except (ValueError, sec_encode.UnsupportedTerm):
            return None
        subs.append((const, literal))
    sub = z3.substitute(obl, subs)
    yes = solve.decide(z3, sub)
    no = solve.decide(z3, z3.Not(sub))
    if yes is True and no is False:
        return True
    if yes is False and no is True:
        return False
    return None


def reclassify(z3, promise):
    """Re-classify a promise's pinned witnesses: ``(positive_ok, negative_ok)``.

    ``positive_ok`` is True when the pinned positive still satisfies the
    obligation, False when it has drifted to violating, and None when the answer
    is undecided. ``negative_ok`` is True when the pinned negative still violates
    the obligation, False when it has drifted to compliant, and None when
    undecided. ``sx-sec-compile`` turns a False into a ``rejected`` promise
    ("witness drift: the pinned <positive|negative> witness no longer classifies
    as expected") and a None into ``unverified``.
    """
    ast = promise.ast
    mode = promise.mode
    positive = classify(z3, ast, mode, promise.positive)   # expected: True
    negative = classify(z3, ast, mode, promise.negative)   # expected: False

    positive_ok = positive  # True satisfies / False drifted / None undecided
    if negative is None:
        negative_ok = None
    else:
        negative_ok = negative is False  # still violates iff it classifies False
    return positive_ok, negative_ok


# -- independence probe -------------------------------------------------------

@dataclass(frozen=True)
class Conflict:
    """A joint-unsat between two promises: no single record satisfies both.

    ``fatal`` is True only for the forall/forall-over-a-shared-collection,
    no-existential shape; every other conflict is an advisory the compiler
    records as ``unverified`` rather than a rejection.
    """

    ids: tuple[str, str]
    fatal: bool
    shared_collections: tuple[str, ...] = ()


@dataclass(frozen=True)
class IndependenceResult:
    """The independence verdict over a promise set.

    ``independent`` is True when the probe ran and found no conflict, False when
    it found at least one, and None when the whole probe was skipped (too many
    entries, ``enabled=False``, or no z3) — never silently True.
    """

    independent: Optional[bool]
    conflicts: tuple[Conflict, ...] = ()
    notes: tuple[str, ...] = ()


def _free_const_names(z3, expr) -> set:
    """The names of every uninterpreted (free) constant in *expr*."""
    names: set = set()
    seen: set = set()
    stack = [expr]
    while stack:
        node = stack.pop()
        node_id = node.get_id()
        if node_id in seen:
            continue
        seen.add(node_id)
        if z3.is_const(node):
            if node.decl().kind() == z3.Z3_OP_UNINTERPRETED:
                names.add(node.decl().name())
        else:
            stack.extend(node.children())
    return names


def independence(z3, entries: Sequence, *, enabled: bool = True) -> IndependenceResult:
    """Probe a promise set for pairwise joint-unsatisfiability.

    *entries* is a sequence of ``(promise_id, obligation, forall_rooted,
    collections)`` in artifact sorted-id order, where ``forall_rooted`` is True
    only for a promise forall-rooted with no existential anywhere. Only pairs
    sharing at least one free-const name are solved — disjoint vocabularies are
    trivially independent and must not cost a solve. Each candidate pair is
    checked in one ``solve.solver(z3, unsat_core=True)`` via ``assert_and_track``;
    an unsat pair is a conflict (fatal only when both are ``forall_rooted`` over a
    shared collection), an ``unknown`` pair records no conflict with a note. The
    probe is skipped — leaving ``independent`` None with a note — when there are
    more than :data:`MAX_INDEPENDENCE` entries, when ``enabled`` is False, or when
    z3 is absent.
    """
    entries = list(entries)
    if not enabled:
        logger.debug("independence probe disabled by caller")
        return IndependenceResult(
            None, (), ("independence probe disabled by caller (enabled=False)",))
    if len(entries) > MAX_INDEPENDENCE:
        logger.debug("independence probe skipped: %d entries exceed MAX_INDEPENDENCE (%d)",
                     len(entries), MAX_INDEPENDENCE)
        return IndependenceResult(
            None, (),
            (f"independence probe skipped: {len(entries)} entries exceed "
             f"MAX_INDEPENDENCE ({MAX_INDEPENDENCE})",))
    if z3 is None:
        return IndependenceResult(
            None, (), ("z3 is not available — independence was not decided",))

    names = [_free_const_names(z3, obl) for (_pid, obl, _fa, _coll) in entries]

    conflicts: list[Conflict] = []
    notes: list[str] = []
    for i in range(len(entries)):
        id_i, obl_i, forall_i, coll_i = entries[i]
        for j in range(i + 1, len(entries)):
            id_j, obl_j, forall_j, coll_j = entries[j]
            if not (names[i] & names[j]):
                continue  # disjoint vocabularies: trivially independent, no solve
            track = {f"p:{id_i}": id_i, f"p:{id_j}": id_j}
            s = solve.solver(z3, unsat_core=True)
            s.assert_and_track(obl_i, z3.Bool(f"p:{id_i}"))
            s.assert_and_track(obl_j, z3.Bool(f"p:{id_j}"))
            result = s.check()
            if result == z3.unsat:
                core_ids = {track[str(c)] for c in s.unsat_core() if str(c) in track}
                if len(core_ids) < 2:
                    # A single-id core means one promise is self-unsat, already
                    # caught by its own satisfiable probe — not a pair conflict.
                    continue
                shared = tuple(sorted(set(coll_i) & set(coll_j)))
                fatal = bool(forall_i and forall_j and shared)
                conflicts.append(Conflict((id_i, id_j), fatal, shared))
            elif result == z3.unknown:
                notes.append(f"pair ({id_i}, {id_j}) undecided (solver gave up) — "
                             "no conflict recorded")
            # sat -> the pair coexists over one record: no conflict.

    return IndependenceResult(len(conflicts) == 0, tuple(conflicts), tuple(notes))
