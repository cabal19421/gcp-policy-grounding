"""Stage 2: the artifact-to-``CompiledRule`` registry and tiered evaluation.

Pure, deterministic and LLM-free. This module turns a committed
``*.promises.json`` artifact (:mod:`~gcp_grounding.sec_artifact`) into z3 rules
that run in the same dispatch and render through the same
:class:`gcp_grounding.core.report.Verdict` channel as the built-in checks. It
imports :mod:`~gcp_grounding.sec_artifact`, :mod:`~gcp_grounding.sec_ast`,
:mod:`~gcp_grounding.sec_encode`, :mod:`~gcp_grounding.sec_probes`,
:mod:`~gcp_grounding.constraints`, :mod:`~gcp_grounding.solve`,
:mod:`gcp_grounding.core.report`, :mod:`gcp_grounding.core.solver` and
:mod:`~gcp_grounding.knowledge`; it never edits ``constraints.py`` or ``core/``
and never touches an LLM, ``eval``, ``exec`` or the network.

NOT-APPLICABLE IS NOT NOT-DECIDED.  There is exactly one honesty channel here —
``unverified`` — and conflating "this rule has nothing to say about this kind of
document" with "this rule should have decided and could not" floods it. With
``GCP_GROUNDING_REQUIREMENTS`` on (the global switch that turns requirements on),
a naive ``for rule in rules: report.add(rule.evaluate(ctx))`` would emit one
``unverified sec:iam`` per IAM promise on every firewall edit, one per org-policy
promise on every IAM edit, and so on. So :meth:`CompiledRule.applies_to` gates
evaluation on the document kind and the promise's domain:

* silence (``evaluate`` returns ``None``, the caller adds nothing) means "this
  rule has nothing to say about this kind of document";
* ``unverified`` means "this rule should have decided and could not" — a missing
  baseline, an uncaptured estate collection, an unregistered collection, an
  absent z3, an unsupported term.

THE DEFAULT IS LOUD.  When the document kind is ``None``, unrecognized, or not in
the applicability table, applicability CANNOT be determined, so the rule is
treated as applicable and still emits its ``unverified`` rather than vanishing.
Only a *recognized* kind that a domain genuinely cannot speak about is silent.

CLOSED-FORMULA GUARD.  ``decide(obl) is True => grounded`` is sound ONLY for a
CLOSED formula: every ``field`` resolved to a literal, so ``sat`` is equivalent
to ``true``. On an OPEN formula ``sat`` means merely "there exists an assignment
to the free symbols under which the obligation holds", and a violating document
would grade ``grounded`` — a silent pass. :mod:`sec_encode` refuses the one
built-in node that opens a formula (``cel``), but :func:`sec_encode.register_encoder`
can install an arbitrary encoder, so this module VERIFIES the precondition rather
than trusting it: after building the ground formula it compares
``z3.z3util.get_vars(f)`` against the empty set. If any free constant remains it
does not use the sat test; it falls back to a VALIDITY test (``contradicted`` iff
``decide(Not(obl)) is True`` with the counter-model as the witness, ``grounded``
iff it is ``False``, ``unverified`` otherwise) and says so in the message. That
guard is what keeps ``decide(obl) is True => grounded`` true no matter what an
encoder override does.

``ungrounded`` is NEVER produced at evaluation time — it belongs exclusively to
vocabulary grounding at compile time. Keeping it out of this module is what keeps
the four buckets semantically distinct.

WHY A ``rejected`` REQUIREMENT CARRIES ``unverified``, NOT ``contradicted``.  A
non-compiled promise re-emits a CARRY VERDICT on every run so its absence never
reads as coverage. A ``rejected`` status maps to ``unverified`` (not
``contradicted``) deliberately: the ``contradicted`` for a broken requirement
belongs to ``compile-requirements``, not to every policy verification — otherwise
one bad requirement file would fail every unrelated policy run.

Every solve in this module goes through :func:`gcp_grounding.solve.decide` /
:func:`gcp_grounding.solve.solver`, so a pathological formula abstains
(``unknown`` -> ``unverified``) instead of hanging the hook.
"""

from __future__ import annotations

import glob
import importlib
import os
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from . import constraints, sec_artifact, sec_ast, sec_encode, sec_probes, solve
from .core.log import get_logger
from .core.report import Verdict
from .core.solver import get_solver
from .knowledge import GcpSnapshot

logger = get_logger(__name__)

__all__ = [
    "RuleContext", "CompiledRule",
    "EXTRACTORS", "register_extractor",
    "iam_bindings", "new_iam_bindings", "old_iam_bindings", "org_policy_rules",
    "RULES", "load_rules", "load_directory", "by_state", "by_domain",
    "last_witness",
]


# -- applicability table ------------------------------------------------------
#
# A promise's domain maps to the document kinds it can speak about. ``tf_plan``
# is special: a terraform plan can carry ANY domain's resources, so it matches
# every domain. The union of these values plus ``tf_plan`` is the set of kinds
# the table "recognizes"; a kind outside it is unrecognized and therefore loud.

_DOMAIN_KINDS: dict[str, frozenset] = {
    "iam": frozenset({"iam_policy", "iam_deny_policy"}),
    "org_policy": frozenset({"org_policy"}),
    "vpc_firewall": frozenset({"firewall_rule"}),
    "hier_firewall": frozenset({"firewall_policy"}),
    "cloud_armor": frozenset({"security_policy"}),
    "vpc_sc": frozenset({"vpc_sc_perimeter", "access_level"}),
}
_TF_PLAN = "tf_plan"
_TABLE_KINDS = frozenset({_TF_PLAN}).union(*_DOMAIN_KINDS.values())


# -- context and rule ---------------------------------------------------------

@dataclass(frozen=True)
class RuleContext:
    """Everything the three tiers may consult, in one frozen record.

    ``snapshot`` is the estate; ``document`` is the parsed proposal under review
    (or ``None``); ``document_kind`` is one of
    :data:`gcp_grounding.preflight.DOCUMENT_KINDS` or ``None``; ``baseline`` is
    the parsed old document for the pair tier; ``estate`` and ``solver`` are
    optional overrides a domain extractor / the evaluator may use.
    """

    snapshot: GcpSnapshot
    document: Any = None
    document_kind: Optional[str] = None
    source: str = ""
    baseline: Any = None
    estate: Optional[Mapping[str, Any]] = None
    solver: Any = None


@dataclass(frozen=True)
class CompiledRule:
    """One admitted promise, evaluable through a single tier-agnostic signature.

    The tier differences live in :meth:`missing_inputs` (which collections must
    resolve) and in which extractors run — not in three separate code paths.
    """

    promise: sec_artifact.Promise

    # -- applicability --------------------------------------------------------

    def applies_to(self, ctx: RuleContext) -> bool:
        """Does this rule have anything to say about ``ctx``'s document kind?

        Loud by default: an unknown / unrecognized / untabled kind is treated as
        applicable so a rule that should have run still emits its ``unverified``.
        Only a recognized kind that this domain genuinely cannot speak about is
        non-applicable (and therefore silent).
        """
        kind = ctx.document_kind
        if kind is None or kind not in _TABLE_KINDS:
            return True  # applicability cannot be determined -> loud default
        if kind == _TF_PLAN:
            return True  # a plan can carry any domain's resources
        return kind in _DOMAIN_KINDS.get(self.promise.domain, frozenset())

    # -- inputs ---------------------------------------------------------------

    def _collect(self, ctx: RuleContext):
        """``[(collection, records, missing_reason)]`` for every collection the
        AST quantifies over, in :func:`sec_ast.collections_used` order."""
        out = []
        for name in sec_ast.collections_used(self.promise.ast):
            fn = EXTRACTORS.get(name)
            if fn is None:
                # An AST collection with no extractor is an estate collection the
                # snapshot did not capture (mirrors reasoner.py's captured-bit).
                out.append((name, (),
                            f"snapshot did not capture {name} — the estate-tier "
                            "rule was not evaluated"))
                continue
            records, missing = fn(ctx)
            out.append((name, records, missing))
        return out

    def missing_inputs(self, ctx: RuleContext) -> tuple:
        """The missing_reasons of every collection the AST uses (empty if all
        resolved). A non-empty result makes :meth:`evaluate` abstain loudly —
        never skip a rule silently."""
        return tuple(m for (_name, _records, m) in self._collect(ctx) if m)

    # -- evaluation -----------------------------------------------------------

    def evaluate(self, ctx: RuleContext) -> Optional[Verdict]:
        """Decide this rule against ``ctx`` — or return ``None`` (adding nothing)
        when the rule is not applicable to the document under review."""
        if not self.applies_to(ctx):
            logger.debug("rule %s is not applicable to document_kind=%r; the caller "
                         "adds nothing", self.promise.id, ctx.document_kind)
            return None

        domain = self.promise.domain
        pid = self.promise.id
        ast = self.promise.ast
        mode = self.promise.mode

        collected = self._collect(ctx)
        missing = tuple(m for (_name, _records, m) in collected if m)
        if missing:
            return Verdict("unverified", f"sec:{domain}", pid, 0,
                           f"{pid}: not evaluated — " + "; ".join(missing))

        solver = ctx.solver if ctx.solver is not None else get_solver()
        z3 = constraints._z3_module(solver)
        if z3 is None:
            backend = getattr(solver, "backend", "builtin")
            return Verdict("unverified", f"sec:{domain}", pid, 0,
                           f"{pid}: z3 is not available (solver backend {backend!r}) — "
                           "the rule was not decided")

        instance = {name: list(records) for (name, records, _m) in collected}
        try:
            f = sec_encode.ground(z3, ast, instance)
            obl = sec_probes.obligation(z3, f, mode)
            if _free_vars(z3, f):
                return self._decide_open(z3, obl, domain, pid)
            return self._decide_closed(z3, obl, instance, domain, pid)
        except sec_encode.UnsupportedTerm as exc:
            return Verdict("unverified", f"sec:{domain}", pid, 0, f"{pid}: {exc}")
        except RecursionError:
            return Verdict("unverified", f"sec:{domain}", pid, 0,
                           f"{pid}: the formula was too deeply nested to decide — "
                           "not decided")

    # -- the closed (sound) path ----------------------------------------------

    def _decide_closed(self, z3, obl, instance, domain, pid) -> Verdict:
        result = solve.decide(z3, obl)
        if result is True:
            _LAST_WITNESS.pop(pid, None)
            return Verdict("grounded", f"sec:{domain}", pid, 0,
                           f"{pid}: the obligation holds over the document — grounded")
        if result is None:
            return Verdict("unverified", f"sec:{domain}", pid, 0,
                           f"{pid}: the solver returned unknown (timeout) — not decided")
        # False -> contradicted: find the offending record deterministically.
        witness = self._find_witness(z3, instance)
        if witness is not None:
            name, index, record = witness
            _LAST_WITNESS[pid] = {"collection": name, "index": index,
                                  "record": dict(record)}
            return Verdict("contradicted", f"sec:{domain}", pid, 0,
                           f"{pid}: refuted by {_fmt_record(name, index, record)}")
        _LAST_WITNESS.pop(pid, None)
        return Verdict("contradicted", f"sec:{domain}", pid, 0,
                       f"{pid}: the obligation is violated but no single record "
                       "witnesses it — not fabricating one")

    # -- the open (validity) fallback -----------------------------------------

    def _decide_open(self, z3, obl, domain, pid) -> Verdict:
        note = ("; the obligation was decided by validity because the formula was "
                "not closed (an encoder override left a free constant)")
        ok, model = solve.model_or_none(z3, z3.Not(obl))
        if ok is True:
            witness = _render_model(z3, obl, model)
            return Verdict("contradicted", f"sec:{domain}", pid, 0,
                           f"{pid}: refuted by counter-model {witness}{note}")
        if ok is False:
            return Verdict("grounded", f"sec:{domain}", pid, 0,
                           f"{pid}: the obligation is valid — grounded{note}")
        return Verdict("unverified", f"sec:{domain}", pid, 0,
                       f"{pid}: the solver returned unknown (timeout) — not decided{note}")

    # -- runtime witness search -----------------------------------------------

    def _find_witness(self, z3, instance):
        """The first record, in collection then index order, whose single-record
        ground obligation is unsatisfiable — the deterministic witness."""
        ast = self.promise.ast
        mode = self.promise.mode
        for name in sec_ast.collections_used(ast):
            records = instance.get(name, [])
            for index, record in enumerate(records):
                single = dict(instance)
                single[name] = [record]
                try:
                    f_i = sec_encode.ground(z3, ast, single)
                    obl_i = sec_probes.obligation(z3, f_i, mode)
                except (sec_encode.UnsupportedTerm, ValueError, RecursionError):
                    continue
                if solve.decide(z3, obl_i) is False:
                    return name, index, record
        return None


# -- free-symbol detection (the closed-formula guard) -------------------------

def _free_vars(z3, formula) -> set:
    """The names of the free constants in *formula*; an empty set means CLOSED.

    Uses ``z3.z3util.get_vars`` per the guard's contract, falling back to
    :func:`sec_probes._free_const_names` if that helper is unavailable so the
    guard never crashes the fail-open path.
    """
    try:
        return {str(v) for v in z3.z3util.get_vars(formula)}
    except AttributeError:
        return sec_probes._free_const_names(z3, formula)


def _render_model(z3, obl, model) -> str:
    """Best-effort rendering of a counter-model over an open obligation's free
    constants, for the validity-fallback witness. Never fabricates: an
    un-renderable model degrades to a placeholder."""
    try:
        terms = list(z3.z3util.get_vars(obl))
    except AttributeError:
        return "<counter-model>"
    parts = []
    for term in sorted(terms, key=str):
        try:
            parts.append(f"{term}={model.eval(term, model_completion=True)}")
        except Exception:  # noqa: BLE001 - a model we cannot render is not a crash
            continue
    return " ".join(parts) if parts else "<counter-model>"


def _fmt_record(collection: str, index: int, record: Mapping) -> str:
    """``"collection[i] k=v ..."`` with keys sorted, for the witness message."""
    fields = " ".join(f"{k}={v!r}" for k, v in sorted(record.items()))
    return f"{collection}[{index}] {fields}".rstrip()


# -- structured witness store -------------------------------------------------

_LAST_WITNESS: dict[str, dict] = {}


def last_witness(rule_id: str) -> Optional[dict]:
    """The structured witness (``{"collection", "index", "record"}``) of the last
    ``contradicted`` verdict for *rule_id*, for the evidence table — or ``None``."""
    return _LAST_WITNESS.get(rule_id)


# -- instance extractors ------------------------------------------------------
#
# Each extractor returns ``(records, missing_reason)``: the tuple of record
# mappings the encoder unrolls over, and ``None`` (or a reason string naming the
# missing input). Estate collections are NOT registered here — a domain section
# installs its own via ``register_extractor``.

def _iam_records(policy: Any, label: str):
    """Extract ``iam_bindings``-shaped records from an IAM allow policy.

    Mirrors ``constraints._grant_pairs``'s extract-faithfully-or-refuse
    discipline: a non-mapping binding, a missing/non-string role, a non-list
    members, or ANY unrecognized binding key returns a missing_reason naming it —
    the member-versus-members LLM-typo guard. One record per (binding, member)
    pair in document order, then sorted by (role, member) for determinism.
    """
    if not isinstance(policy, Mapping):
        return (), f"the {label} is not a JSON object"
    if "rules" in policy:
        return (), (f"the {label} has 'rules' — a deny policy is not an IAM allow "
                    "policy")
    bindings = policy.get("bindings")
    if bindings is None:
        return (), f"the {label} has no 'bindings' array"
    if not isinstance(bindings, list):
        return (), (f"the {label}'s 'bindings' is {type(bindings).__name__}, not an "
                    "array")
    records: list[dict] = []
    for i, binding in enumerate(bindings):
        if not isinstance(binding, Mapping):
            return (), f"the {label}'s bindings[{i}] is not an object"
        unrecognized = sorted(repr(k) for k in binding
                              if k not in ("role", "members", "condition"))
        if unrecognized:
            return (), (f"the {label}'s bindings[{i}] has unrecognized key(s) "
                        f"{', '.join(unrecognized)} — the member-vs-members typo guard")
        role = binding.get("role")
        if not isinstance(role, str) or not role:
            return (), f"the {label}'s bindings[{i}].role is not a role name"
        members = binding.get("members", [])
        if not isinstance(members, list):
            return (), f"the {label}'s bindings[{i}].members is not an array"
        condition = binding.get("condition")
        has_condition = condition is not None
        expression = ""
        if isinstance(condition, Mapping):
            expr = condition.get("expression")
            expression = expr if isinstance(expr, str) else ""
        for j, member in enumerate(members):
            if not isinstance(member, str) or not member:
                return (), (f"the {label}'s bindings[{i}].members[{j}] is not a "
                            "member id")
            records.append({"role": role, "member": member,
                            "condition": expression, "has_condition": has_condition})
    records.sort(key=lambda r: (r["role"], r["member"]))
    return tuple(records), None


def iam_bindings(ctx: RuleContext):
    """Proposal-tier ``iam_bindings`` records from ``ctx.document``.

    A wrong ``document_kind`` or a ``None`` document returns the missing_reason
    "the document under review is not an IAM allow policy".
    """
    if ctx.document_kind != "iam_policy" or ctx.document is None:
        return (), "the document under review is not an IAM allow policy"
    return _iam_records(ctx.document, "document under review")


def new_iam_bindings(ctx: RuleContext):
    """Pair-tier ``new_iam_bindings`` — identical to :func:`iam_bindings`."""
    return iam_bindings(ctx)


def old_iam_bindings(ctx: RuleContext):
    """Pair-tier ``old_iam_bindings`` from ``ctx.baseline``.

    A ``None`` baseline returns the missing_reason "no baseline document was
    given — the pair-tier rule was not evaluated".
    """
    if ctx.baseline is None:
        return (), "no baseline document was given — the pair-tier rule was not evaluated"
    return _iam_records(ctx.baseline, "baseline document")


def _org_constraint_name(policy: Mapping) -> str:
    """The constraint id in an org-policy document's ``name`` (the ``…/policies/``
    tail), or the raw name if that shape is absent."""
    name = policy.get("name")
    if not isinstance(name, str):
        return ""
    marker = "/policies/"
    return name.split(marker, 1)[1] if marker in name else name


def org_policy_rules(ctx: RuleContext):
    """Proposal-tier ``org_policy_rules`` from an org-policy document.

    One record per list value (``value`` carries the entry), plus one record with
    an empty ``value`` for a boolean rule. Refuses on any surprise the same way
    :func:`_iam_records` does.
    """
    if ctx.document_kind != "org_policy" or ctx.document is None:
        return (), "the document under review is not an Org Policy"
    policy = ctx.document
    if not isinstance(policy, Mapping):
        return (), "the Org Policy is not a JSON object"
    constraint = _org_constraint_name(policy)
    spec = policy.get("spec")
    if not isinstance(spec, Mapping):
        return (), "the Org Policy has no 'spec' object"
    rules = spec.get("rules")
    if rules is None:
        return (), "the Org Policy's spec has no 'rules' array"
    if not isinstance(rules, list):
        return (), f"the Org Policy's 'rules' is {type(rules).__name__}, not an array"
    records: list[dict] = []
    for i, rule in enumerate(rules):
        if not isinstance(rule, Mapping):
            return (), f"the Org Policy's rules[{i}] is not an object"
        recognized = {"enforce", "values", "allow_all", "deny_all", "condition"}
        unrecognized = sorted(repr(k) for k in rule if k not in recognized)
        if unrecognized:
            return (), (f"the Org Policy's rules[{i}] has unrecognized key(s) "
                        f"{', '.join(unrecognized)} — the surprise guard")
        enforce = bool(rule.get("enforce", False))
        values = rule.get("values")
        if values is None:
            records.append({"constraint": constraint, "is_list": False,
                            "enforce": enforce, "value": ""})
            continue
        if not isinstance(values, Mapping):
            return (), f"the Org Policy's rules[{i}].values is not an object"
        listed: list[str] = []
        for key in ("allowedValues", "deniedValues"):
            entries = values.get(key, [])
            if not isinstance(entries, list):
                return (), f"the Org Policy's rules[{i}].values.{key} is not an array"
            for entry in entries:
                if not isinstance(entry, str):
                    return (), (f"the Org Policy's rules[{i}].values.{key} has a "
                                "non-string entry")
                listed.append(entry)
        for entry in listed:
            records.append({"constraint": constraint, "is_list": True,
                            "enforce": enforce, "value": entry})
    records.sort(key=lambda r: (r["constraint"], r["value"]))
    return tuple(records), None


#: The built-in extractors, keyed by collection name. Estate collections are not
#: registered here; a domain section installs its own via
#: :func:`register_extractor`.
EXTRACTORS: dict[str, Callable[[RuleContext], tuple]] = {
    "iam_bindings": iam_bindings,
    "new_iam_bindings": new_iam_bindings,
    "old_iam_bindings": old_iam_bindings,
    "org_policy_rules": org_policy_rules,
}


def register_extractor(name: str, fn: Callable[[RuleContext], tuple]) -> None:
    """Register the extractor for collection *name* — the hook a domain section
    uses to make an estate collection evaluable."""
    EXTRACTORS[name] = fn


# -- registry and loading -----------------------------------------------------

#: Every admitted rule, keyed by promise id. Populated by :func:`load_rules` /
#: :func:`load_directory`.
RULES: dict[str, CompiledRule] = {}


def _carry_verdict(promise: sec_artifact.Promise, label: str) -> Verdict:
    """The re-emitted carry verdict for a non-compiled promise, so its absence
    never reads as coverage. Both ``unverified`` and ``rejected`` carry an
    ``unverified`` verdict (see the module docstring for why ``rejected`` is not
    ``contradicted``)."""
    src = promise.source
    where = f"{src.file}:{src.line}"
    if promise.status == "rejected":
        return Verdict("unverified", f"sec:{promise.domain}", promise.id, 0,
                       f"{where}: {src.text!r} — requirement was rejected at compile "
                       f"time ({promise.reason}); it did not run")
    return Verdict("unverified", f"sec:{promise.domain}", promise.id, 0,
                   f"{where}: {src.text!r} — {promise.reason}")


def _stage1_sexpr(ast) -> Optional[str]:
    """*ast* rendered the way :mod:`~gcp_grounding.sec_compile` stores it, or
    ``None`` when that renderer cannot be resolved.

    Resolved with importlib rather than imported at module scope: stage 2 must
    keep loading committed artifacts in a checkout where the compiler is absent.
    """
    try:
        sec_compile = importlib.import_module("gcp_grounding.sec_compile")
    except ImportError:  # pragma: no cover - the compiler ships with stage 2
        return None
    try:
        return sec_compile._render_sexpr(ast)
    except (KeyError, TypeError, RecursionError):
        # A shape the AST renderer does not know is not a tamper signal; the z3
        # rendering below is still authoritative.
        logger.debug("the stage-1 renderer could not render the stored ast",
                     exc_info=True)
        return None


def _admit(promise: sec_artifact.Promise, z3, label: str):
    """Integrity-check a compiled promise. Returns ``(verdicts, register)``.

    (1) SEXPR AGREEMENT: re-render the stored ast and compare to the stored
    ``sexpr``. A mismatch is a detected inconsistency in a committed file, so it
    is ``contradicted`` (refuse to register), not ``unverified``.

    There are TWO faithful renderings of one ast and an artifact may carry
    either. ``compile-requirements`` stores :func:`sec_compile._render_sexpr`'s
    output — deliberately z3-INDEPENDENT, so a committed artifact survives a z3
    upgrade — while this module historically recomputed
    ``symbolic(z3, ast)[0].sexpr()``. The two never agree textually
    (``(exists ((b iam_bindings)) (eq b.role "roles/owner"))`` versus
    ``(= |iam_bindings#b.role| "roles/owner")``), so demanding the z3 form alone
    refused EVERY artifact stage 1 wrote. Accepting either is not a weakening:
    both are pure functions of the stored ast, so editing the ast changes both
    and a stale ``sexpr`` still fails to match either one.
    (2) WITNESS RE-CLASSIFICATION: ``sec_probes.reclassify``; a drifted witness is
    ``contradicted`` (refuse). An undecided witness or an absent z3 records an
    ``unverified sec:artifact`` note and registers the rule anyway — the rules
    abstain on the builtin backend regardless.
    """
    if z3 is None:
        return ([Verdict("unverified", "sec:artifact", promise.id, 0,
                         f"{label}: z3 is not available — the artifact's integrity "
                         "(sexpr agreement, witness re-classification) was not "
                         "verified; the rule was registered but abstains on the "
                         "builtin backend")], True)

    try:
        formula, _consts = sec_encode.symbolic(z3, promise.ast)
        fresh = formula.sexpr()
    except sec_encode.UnsupportedTerm as exc:
        return ([Verdict("unverified", "sec:artifact", promise.id, 0,
                         f"{label}: the stored ast could not be re-encoded ({exc}) — "
                         "integrity was not verified; the rule was registered")], True)

    if promise.sexpr not in (fresh, _stage1_sexpr(promise.ast)):
        return ([Verdict("contradicted", "sec:artifact", promise.id, 0,
                         f"{label}: the stored sexpr does not match a fresh encoding "
                         "of the stored ast — the artifact was edited by hand or the "
                         "encoder changed; re-run compile-requirements")], False)

    positive_ok, negative_ok = sec_probes.reclassify(z3, promise)
    drifted = []
    if positive_ok is False:
        drifted.append("positive")
    if negative_ok is False:
        drifted.append("negative")
    if drifted:
        direction = " and ".join(drifted)
        return ([Verdict("contradicted", "sec:artifact", promise.id, 0,
                         f"{label}: the pinned {direction} witness no longer "
                         "classifies — the promise's mode or ast was changed without "
                         "recompiling")], False)

    if positive_ok is None or negative_ok is None:
        return ([Verdict("unverified", "sec:artifact", promise.id, 0,
                         f"{label}: a pinned witness could not be re-classified "
                         "(solver undecided) — integrity was not fully verified; the "
                         "rule was registered")], True)

    return ([], True)


def load_rules(paths_or_docs, *, snapshot=None, solver=None):
    """Load artifacts (paths or :class:`~gcp_grounding.sec_artifact.PromiseDoc`
    objects) into rules. Returns ``(rules, verdicts)``.

    Only ``compiled`` promises that pass both admission checks become rules and
    are added to :data:`RULES`. Non-compiled promises produce carry verdicts; a
    duplicate id across artifacts refuses BOTH; an artifact that fails to load
    yields one ``unverified sec:artifact`` verdict while the others still load.
    """
    # Resolve the domain collections lazily and fail-open BEFORE reading any
    # artifact, so an artifact naming e.g. ``firewall_rules`` validates instead
    # of being rejected as an unknown collection.
    sec_ast._ensure_domains()
    z3 = constraints._z3_module(solver if solver is not None else get_solver())

    verdicts: list[Verdict] = []
    loaded = []  # (doc, label)
    for item in paths_or_docs:
        if isinstance(item, sec_artifact.PromiseDoc):
            loaded.append((item, item.source_doc or "<in-memory>"))
            continue
        label = os.fspath(item)
        try:
            doc = sec_artifact.load(item)
        except (ValueError, OSError) as exc:
            verdicts.append(Verdict("unverified", "sec:artifact", label, 0,
                                    f"{label}: could not be loaded ({exc}) — its "
                                    "requirements did not run"))
            continue
        loaded.append((doc, label))

    # Duplicate promise id across artifacts: refuse both, register neither.
    occurrences: dict[str, list] = defaultdict(list)
    for doc, label in loaded:
        for promise in doc.promises:
            occurrences[promise.id].append(label)
    dup_ids = {pid for pid, labels in occurrences.items() if len(labels) > 1}
    for pid in sorted(dup_ids):
        files = sorted(set(occurrences[pid]))
        verdicts.append(Verdict("contradicted", "sec:artifact", pid, 0,
                                f"duplicate promise id {pid!r} across artifacts "
                                f"{files} — neither was registered"))

    registered: list[CompiledRule] = []
    for doc, label in loaded:
        for promise in doc.promises:
            if promise.id in dup_ids:
                continue
            if promise.status != "compiled":
                verdicts.append(_carry_verdict(promise, label))
                continue
            admit_verdicts, register = _admit(promise, z3, label)
            verdicts.extend(admit_verdicts)
            if register:
                rule = CompiledRule(promise=promise)
                RULES[promise.id] = rule
                registered.append(rule)

    return tuple(registered), tuple(verdicts)


def load_directory(directory, *, snapshot=None, solver=None):
    """Load every ``*.promises.json`` in *directory* (sorted) via
    :func:`load_rules`."""
    paths = sorted(glob.glob(os.path.join(os.fspath(directory), "*.promises.json")))
    return load_rules(paths, snapshot=snapshot, solver=solver)


def by_state(state: str) -> tuple:
    """The registered rules whose promise tier is *state*."""
    return tuple(r for r in RULES.values() if r.promise.state == state)


def by_domain(domain: str) -> tuple:
    """The registered rules whose promise domain is *domain*."""
    return tuple(r for r in RULES.values() if r.promise.domain == domain)
