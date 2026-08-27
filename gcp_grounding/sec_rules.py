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

DRIFT ADJUDICATION, AND WHY IT MATTERS MOST HERE.  A user-authored promise
evaluates OUTSIDE the check registry — ``preflight`` calls
:meth:`CompiledRule.evaluate` directly — so without the two guards below a
promise that reads a disputed estate fact would still return ``grounded``. A
``sec_requirements/`` promise is the one rule a human wrote down and expects to
be enforced, which is exactly why the silent pass is worst here.

* :func:`_adjudicate_one` re-grades the decided verdict against the estate facts
  the rule ACTUALLY read, through :func:`gcp_grounding.drift.adjudicate`. Because
  this module never produces ``ungrounded`` at evaluation time (the invariant
  stated above), the only adjudications reachable from here are drift's rule 1 —
  a ``grounded`` resting on a tainted fact downgraded to ``unverified`` — and its
  rule 2/3 annotation of a ``contradicted``, which keeps its status under
  ``annotate`` and flips only under ``abstain`` or the phantom carve-out. Rule 4
  (the ``ungrounded`` rewrite) is unreachable and rule 5 is a no-op.
* :meth:`CompiledRule._incomplete_estate` is the ESTATE-TIER COMPLETENESS GATE. A
  terraform capture emits ``firewall_rules`` at scope ``partial`` — captured, not
  UNKNOWN — so the estate extractors' captured-bit check passes and a promise of
  the form "no ingress firewall rule may allow tcp/22 from 0.0.0.0/0" would find
  nothing and return ``grounded``: a confident estate-wide clean bill of health
  from a view that sees only what terraform manages. Before the solve, every
  ESTATE collection the AST uses is resolved to its snapshot category through
  :data:`gcp_grounding.provenance.COLLECTION_CATEGORIES` and put through
  :func:`gcp_grounding.provenance.require_complete`; the first refusal abstains.

THE CARVE-OUT: a verdict of kind :data:`ARTIFACT_KIND` is never adjudicated. The
two artifact-integrity verdicts are statements about a COMMITTED FILE, not about
the estate, and tainting them would let estate drift mask a hand-edited promise.

Both guards resolve their modules with the lazy try-import-except-``ImportError``
idiom ``preflight`` and ``registry`` use, so a checkout without the
reconciliation spine degrades to exactly today's behaviour.
"""

from __future__ import annotations

import contextlib
import glob
import importlib
import os
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from . import (constraints, evidence, sec_artifact, sec_ast, sec_encode,
               sec_probes, solve)
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
    "last_witness", "ARTIFACT_KIND", "WITNESS_ADDRESS_FIELD",
]

#: The kind the two artifact-integrity verdicts carry — and the one kind drift
#: adjudication never touches. See the module docstring's carve-out.
ARTIFACT_KIND = "sec:artifact"

#: The optional record key carrying the proposing document's own locator — the
#: terraform block address (``google_compute_firewall.allow_ssh_world``) a
#: proposal-tier extractor threads through its rows. No collection spec
#: declares it, so the encoder never reads it and no promise can quantify over
#: it; its one consumer is :func:`_fmt_record`, which prints it in parentheses
#: after the record's index so a refutation names the block an operator must
#: edit rather than only the flattened row that witnessed it. A record without
#: the key renders exactly as it always has.
WITNESS_ADDRESS_FIELD = "address"


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

    ``drift_policy`` is the one drift policy of
    :data:`gcp_grounding.drift.DRIFT_POLICIES` this evaluation runs under, empty
    meaning :data:`gcp_grounding.drift.DEFAULT_DRIFT_POLICY`. It is carried here
    rather than read from a global because the caller that resolved the current
    state is the caller that knows what a disagreement should cost; an
    unrecognised value costs the default and a debug line, never a raise (see
    ``drift._policy``).
    """

    snapshot: GcpSnapshot
    document: Any = None
    document_kind: Optional[str] = None
    source: str = ""
    baseline: Any = None
    estate: Optional[Mapping[str, Any]] = None
    solver: Any = None
    drift_policy: str = ""


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
        """``[(collection, records, missing_reason, empty_because)]`` for every
        collection the AST quantifies over, in :func:`sec_ast.collections_used`
        order.

        Every extractor result goes through :func:`_normalize_extraction`, which
        is where the EVIDENCE FLOOR lives for this funnel: an extractor that
        produced no records and said nothing about why is rewritten to a
        missing_reason, so the vacuous path — a ``forall`` over an empty instance
        encoding to a trivially true formula and grounding — is unreachable
        without an explicit attestation.
        """
        out = []
        for name in sec_ast.collections_used(self.promise.ast):
            fn = EXTRACTORS.get(name)
            if fn is None:
                # An AST collection with no extractor is an estate collection the
                # snapshot did not capture (mirrors reasoner.py's captured-bit).
                out.append((name, (),
                            f"snapshot did not capture {name} — the estate-tier "
                            "rule was not evaluated", None))
                continue
            records, missing, empty_because = _normalize_extraction(name, fn(ctx))
            out.append((name, records, missing, empty_because))
        return out

    def missing_inputs(self, ctx: RuleContext) -> tuple:
        """The missing_reasons of every collection the AST uses (empty if all
        resolved). A non-empty result makes :meth:`evaluate` abstain loudly —
        never skip a rule silently."""
        return tuple(m for (_name, _records, m, _empty) in self._collect(ctx) if m)

    # -- evaluation -----------------------------------------------------------

    def evaluate(self, ctx: RuleContext) -> Optional[Verdict]:
        """Decide this rule against ``ctx`` — or return ``None`` (adding nothing)
        when the rule is not applicable to the document under review.

        The estate reads are TAPPED and the decided verdict is adjudicated: see
        the module docstring. The tap opens around the region that touches estate
        data — the instance extractors plus the solve — and NOT around the
        applicability gate, so a rule that is simply not applicable is still
        silently skipped and leaks no read context. The missing-input and
        estate-completeness gates return from INSIDE the tap and are therefore
        never re-graded either: a rule with a missing baseline emits its own
        ``unverified`` rather than one rewritten with the drift suffix.
        """
        if not self.applies_to(ctx):
            logger.debug("rule %s is not applicable to document_kind=%r; the caller "
                         "adds nothing", self.promise.id, ctx.document_kind)
            return None

        off_subject = self._off_subject(ctx)
        if off_subject is not None:
            return off_subject

        domain = self.promise.domain
        pid = self.promise.id
        ast = self.promise.ast
        mode = self.promise.mode

        with _read_tap(pid) as read_set:
            # The extractors ARE the estate reads, so they run inside the tap;
            # their missing_reason still returns unadjudicated.
            collected = self._collect(ctx)
            missing = tuple(m for (_name, _records, m, _empty) in collected if m)
            if missing:
                return Verdict("unverified", f"sec:{domain}", pid, 0,
                               f"{pid}: not evaluated — " + "; ".join(missing))
            observed_empty = tuple(e for (_name, _records, _m, e) in collected if e)

            incomplete = self._incomplete_estate(ctx)
            if incomplete is not None:
                return incomplete

            solver = ctx.solver if ctx.solver is not None else get_solver()
            z3 = constraints._z3_module(solver)
            if z3 is None:
                backend = getattr(solver, "backend", "builtin")
                return Verdict("unverified", f"sec:{domain}", pid, 0,
                               f"{pid}: z3 is not available (solver backend {backend!r}) — "
                               "the rule was not decided")

            instance = {name: list(records) for (name, records, _m, _e) in collected}
            try:
                f = sec_encode.ground(z3, ast, instance)
                obl = sec_probes.obligation(z3, f, mode)
                if _free_vars(z3, f):
                    verdict = self._decide_open(z3, obl, domain, pid)
                else:
                    verdict = self._decide_closed(z3, obl, instance, domain, pid,
                                                  observed_empty)
            except sec_encode.UnsupportedTerm as exc:
                return Verdict("unverified", f"sec:{domain}", pid, 0, f"{pid}: {exc}")
            except RecursionError:
                return Verdict("unverified", f"sec:{domain}", pid, 0,
                               f"{pid}: the formula was too deeply nested to decide — "
                               "not decided")
        return _adjudicate_one(verdict, ctx, read_set)

    # -- the named-subject non-vacuity gate -----------------------------------

    def _off_subject(self, ctx: RuleContext) -> Optional[Verdict]:
        """One ``unverified`` when this promise is SCOPED to a named subject and
        the document under review is about a DIFFERENT one — else ``None``.

        THE NAMED-SUBJECT VACUITY. Some document kinds are *about* exactly one
        named thing: an Org Policy document is about one constraint, and every
        record its proposal-tier extractor yields carries that constraint's name.
        A refute-mode existential over those rows is unsatisfiable over a
        document about ANOTHER constraint — not because the promise holds, but
        because there was never a row it could speak about — and refute mode
        turns that into ``grounded``: an affirmatively false statement that the
        obligation holds. The document is silent about the promise; the honest
        answer is an abstention that NAMES the subject it is silent about.

        The scope comes from the promise's own ``vocab:`` line — the value
        :func:`gcp_grounding.reasoner.ground_existence` already proved exists in
        the estate before the promise was admitted — and never from the formula,
        so an author cannot widen the scope by editing the encoding alone. A
        promise that names no subject of the kind :data:`SUBJECTS` maps this
        document kind to is not scoped, and this gate is silent for it: "no
        binding may grant roles/owner" is genuinely SATISFIED by a document that
        grants no owner, and rewriting that into an abstention would be the
        opposite error.
        """
        scoped = SUBJECTS.get(ctx.document_kind or "")
        if scoped is None or not isinstance(ctx.document, Mapping):
            return None
        kind, prefix, subjects_of = scoped
        wanted = sorted({ref.value[len(prefix):] if ref.value.startswith(prefix)
                         else ref.value
                         for ref in self.promise.vocabulary if ref.kind == kind})
        if not wanted:
            return None
        subjects = subjects_of(ctx.document)
        if subjects is None:
            # Subjects undecidable (an unreadable plan, a plan with nothing of
            # this kind at all): stay SILENT so the extractor's own named
            # abstention speaks instead of a second, vaguer one.
            return None
        if set(wanted) & set(subjects):
            return None
        pid = self.promise.id
        named = ", ".join(repr(s) for s in sorted(subjects))
        return Verdict(
            "unverified", f"sec:{self.promise.domain}", pid, 0,
            f"{pid}: the document under review sets policies for the {kind} "
            f"{named} and never mentions {', '.join(wanted)} — a promise "
            f"scoped to a named {kind} is not decided by a document about a "
            f"different one")

    # -- the estate-tier completeness gate ------------------------------------

    def _incomplete_estate(self, ctx: RuleContext) -> Optional[Verdict]:
        """One ``unverified`` when this rule reasons over an estate collection
        whose snapshot category may not be read as complete — else ``None``.

        THE UNIVERSAL-NEGATIVE ABSTENTION. An estate extractor honours only the
        CAPTURED bit, and a terraform capture emits e.g. ``firewall_rules`` at
        scope ``partial`` — captured, not UNKNOWN. Without this gate a promise
        asserting a universally-quantified negative would sweep a partial table,
        find nothing, and return ``grounded``: an estate-wide clean bill of
        health from a view that sees only what terraform manages.

        The gate lives here rather than in ``sec_domains``, which is owned
        elsewhere and which predates :mod:`gcp_grounding.provenance` and
        therefore cannot call it. Only ESTATE collections are checked — a
        proposal- or pair-tier collection describes the document under review and
        not the estate — so a rule whose derived tier is weaker than ``estate``
        never enters the loop body at all.
        """
        provenance = _optional("provenance")
        if provenance is None:
            return None                      # no provenance in this checkout
        pid = self.promise.id
        domain = self.promise.domain
        for name in sec_ast.collections_used(self.promise.ast):
            spec = sec_ast.COLLECTIONS.get(name)
            if spec is None or spec.tier != "estate":
                continue
            category = provenance.COLLECTION_CATEGORIES.get(name)
            if category is None:
                # A collection nobody mapped to a snapshot category: there is no
                # coverage record to consult, so there is nothing to refuse on.
                logger.debug("rule %s: estate collection %r maps to no snapshot "
                             "category; completeness was not checked", pid, name)
                continue
            reason = _require_complete(ctx.snapshot, category, pid, provenance)
            if reason is not None:
                return Verdict(
                    "unverified", f"sec:{domain}", pid, 0,
                    f"{pid}: not evaluated over the estate collection {name!r} "
                    f"(snapshot category {category!r}): {reason} — a promise that "
                    f"reasons over an estate collection abstains over an "
                    f"incomplete view rather than reporting a clean bill of "
                    f"health from a view that sees only part of the estate")
        return None

    # -- the closed (sound) path ----------------------------------------------

    def _decide_closed(self, z3, obl, instance, domain, pid,
                       observed_empty=()) -> Verdict:
        result = solve.decide(z3, obl)
        if result is True:
            _LAST_WITNESS.pop(pid, None)
            # A genuinely-empty-but-KNOWN collection still grounds, and says so:
            # the attestation that made grounding-over-nothing reachable never
            # travels silently.
            note = ("; " + "; ".join(observed_empty)) if observed_empty else ""
            return Verdict("grounded", f"sec:{domain}", pid, 0,
                           f"{pid}: the obligation holds over the document — "
                           f"grounded{note}")
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


# -- the reconciliation spine, resolved lazily --------------------------------
#
# The three modules below are part of the current-state spine and may be absent
# from a checkout. Every use goes through ``_optional``, the same lazy
# try-import-except-ImportError idiom as ``preflight._tf_plan_extractor`` and
# ``registry._providers``, so a checkout without them degrades to exactly the
# behaviour this module shipped with rather than failing to import.

def _optional(name: str):
    """``gcp_grounding.<name>``, or ``None`` where it is not in this checkout."""
    try:
        return importlib.import_module(f"gcp_grounding.{name}")
    except ImportError:
        logger.debug("sec_rules: gcp_grounding.%s is not part of this checkout; "
                     "the rules run without it", name)
        return None


def _read_tap(label: str):
    """The estate read collector for one evaluation.

    :func:`gcp_grounding.reconciled.reads` where the spine is present, and an
    inert context yielding no reads where it is not — so
    :meth:`CompiledRule.evaluate` is written once. Either way the set is popped
    in a ``finally``, so an early return or an exception mid-rule leaks nothing.
    """
    reconciled = _optional("reconciled")
    if reconciled is None:
        return contextlib.nullcontext(())
    return reconciled.reads(label)


def _require_complete(snapshot: Any, category: str, rule: str,
                      provenance: Any) -> Optional[str]:
    """Why absence in *category* may not be read as non-existence, or ``None``.

    Asks the SNAPSHOT's own predicate when it has one, because that is what
    consults its ledger: a reconciled snapshot built from a terraform capture
    holds a very much captured ``firewall_rules`` field at scope ``partial``, and
    :func:`gcp_grounding.provenance.require_complete` over the OBJECT would read
    that captured field as complete and license the negative this gate exists to
    refuse. A plain :class:`~gcp_grounding.knowledge.GcpSnapshot` has no such
    method and goes to ``provenance`` directly, where a captured category reads
    as complete — today's semantics, unchanged.
    """
    own = getattr(snapshot, "require_complete", None)
    if callable(own):
        return own(category, rule=rule)
    return provenance.require_complete(snapshot, category, rule=rule)


def _adjudicate_one(verdict: Optional[Verdict], ctx: RuleContext,
                    read_set: Any = ()) -> Optional[Verdict]:
    """*verdict*, re-graded against the estate facts the rule actually read.

    Unchanged when :mod:`gcp_grounding.drift` is not part of this checkout, when
    ``ctx.snapshot`` is not a
    :class:`~gcp_grounding.reconciled.ReconciledSnapshot` (it then carries no
    provenance to adjudicate against), and — THE CARVE-OUT — for a verdict of
    kind :data:`ARTIFACT_KIND`, which is a statement about a committed file
    rather than about the estate: tainting it would let estate drift mask a
    hand-edited promise.
    """
    if verdict is None or verdict.kind == ARTIFACT_KIND:
        return verdict
    drift = _optional("drift")
    if drift is None:
        return verdict
    if not isinstance(ctx.snapshot, drift.ReconciledSnapshot):
        return verdict
    policy = ctx.drift_policy or drift.DEFAULT_DRIFT_POLICY
    graded = drift.adjudicate((verdict,), read_set, ctx.snapshot, policy)
    return graded[0] if graded else verdict


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


#: The one record field whose value is a CODE rather than something an operator
#: wrote: the flattening stores a layer-4 match's IANA protocol number, and
#: ``protocol=6`` asks its reader to go and look 6 up. Spelled back through
#: :data:`gcp_grounding.sec_domains.PROTOCOL_NUMBERS` — the table the number came
#: out of, read in reverse rather than restated here.
_PROTOCOL_FIELD = "protocol"


def _protocol_names() -> Mapping:
    """``{6: "tcp", 17: "udp", ...}`` — empty where ``sec_domains`` is not part
    of this checkout, which leaves the number printed as the number."""
    domains = _optional("sec_domains")
    numbers = getattr(domains, "PROTOCOL_NUMBERS", {}) if domains else {}
    return {number: name for name, number in numbers.items()}


def _fmt_record(collection: str, index: int, record: Mapping) -> str:
    """``"collection[i] (address) k=v ..."`` with keys sorted, for the witness
    message.

    The parenthesized address prints only when the record carries
    :data:`WITNESS_ADDRESS_FIELD` — the terraform block address its extractor
    threaded through — and is excluded from the ``k=v`` fields: it locates the
    record, it is not a value the obligation was decided over.

    TIGHTENED ONCE, HERE, AT MINT TIME, because every surface that reprints a
    refutation reprints this string — the report line, the ``--explain``
    narrative, the JSON message — so shortening it anywhere else would be three
    chances to shorten it differently:

    * a field whose value is the EMPTY STRING is dropped. The flattening mints
      ``source_tag=''``/``target_tag=''`` for a rule that names no tag (the
      "no tag" value of a ``Str`` field, so the cross product still has a row),
      and a refutation that spends two fields saying "no tag" buries the ones
      that carry the violation. The row itself is unchanged: the structured
      witness :func:`last_witness` hands the evidence table still carries every
      key, so nothing that reads the record loses a field.
    * ``protocol`` is spelled as its name (see :data:`_PROTOCOL_FIELD`).
    """
    address = record[WITNESS_ADDRESS_FIELD] if WITNESS_ADDRESS_FIELD in record \
        else ""
    names = _protocol_names()
    fields = " ".join(
        f"{key}={(names.get(value, value) if key == _PROTOCOL_FIELD else value)!r}"
        for key, value in sorted(record.items())
        if key != WITNESS_ADDRESS_FIELD and value != "")
    where = f"({address}) " if address else ""
    return f"{collection}[{index}] {where}{fields}".rstrip()


# -- structured witness store -------------------------------------------------

_LAST_WITNESS: dict[str, dict] = {}


def last_witness(rule_id: str) -> Optional[dict]:
    """The structured witness (``{"collection", "index", "record"}``) of the last
    ``contradicted`` verdict for *rule_id*, for the evidence table — or ``None``."""
    return _LAST_WITNESS.get(rule_id)


# -- instance extractors ------------------------------------------------------
#
# Each extractor returns either an :class:`gcp_grounding.evidence.Extraction` or
# the legacy ``(records, missing_reason)`` two-tuple: the tuple of record
# mappings the encoder unrolls over, and ``None`` (or a reason string naming the
# missing input). Estate collections are NOT registered here — a domain section
# installs its own via ``register_extractor``.

def _normalize_extraction(name: str, result: Any) -> tuple:
    """One extractor result as ``(records, missing_reason, empty_because)``.

    THE EVIDENCE FLOOR for the compiled-rule funnel. Three cases:

    * an :class:`~gcp_grounding.evidence.Extraction` passes through — it has
      already been forced to carry one of the two reasons when it has no records;
    * a legacy two-tuple of records and missing_reason is accepted unchanged;
    * the FORCED case is records empty with BOTH reasons unset, which is an
      extractor that did not say whether it looked. It becomes a missing_reason,
      and :meth:`CompiledRule.missing_inputs` / :meth:`CompiledRule.evaluate`
      already turn any non-empty reason into one ``unverified sec:<domain>`` — so
      a ``forall`` over an empty instance can no longer encode to a trivially
      true formula and ground on nobody's authority.
    """
    if isinstance(result, evidence.Extraction):
        return result.records, result.missing_reason, result.empty_because
    records, missing = result
    records = tuple(records)
    if not records and missing is None:
        return (), (f"the {name} extractor produced no records and did not say "
                    f"whether {name} is empty or unreadable — the rule was not "
                    f"evaluated"), None
    return records, missing, None


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


def _org_policy_subjects(policy: Mapping) -> frozenset:
    """The one-element subject set of an org-policy document — the set
    spelling of :func:`_org_constraint_name`, which stays byte-identical."""
    return frozenset({_org_constraint_name(policy)})


def _tf_plan_subjects(plan: Mapping):
    """The constraints a terraform plan's org-policy resources set — prefix
    stripped for comparison — or ``None`` (subjects undecidable) for a plan
    that is unreadable or carries no org-policy constraint claim at all, so
    the gate stays silent and the extractor's own abstention (A2/A3/A4 in the
    org_effective design's index) speaks instead of a second, vaguer one."""
    try:
        from . import tf_claims  # a checkout without tf_claims decides nothing
        claims = tf_claims.terraform_plan_claims(plan)
    except Exception:  # noqa: BLE001 — an unreadable plan names no subject
        return None
    marker = "constraints/"
    subjects = {claim.value[len(marker):] if claim.value.startswith(marker)
                else claim.value
                for claim in claims if claim.kind == "constraint"}
    return frozenset(subjects) if subjects else None


#: Document kind → ``(vocabulary kind, the prefix the vocab spelling carries,
#: the reader naming the SET of subjects THIS document is about — or ``None``
#: when that set is undecidable, which keeps the gate silent)``. A document of
#: one of these kinds is ABOUT named subjects, which is what makes
#: :meth:`CompiledRule._off_subject`'s abstention sound: everything the
#: proposal-tier extractors yield describes those subjects and nothing else.
#: The ``tf_plan`` entry closes the terraform half of the named-subject
#: vacuity: a constraint-scoped promise over a plan that sets only OTHER
#: constraints abstains by name instead of grounding vacuously over rows the
#: plan never had.
SUBJECTS: dict[str, tuple] = {
    "org_policy": ("constraint", "constraints/", _org_policy_subjects),
    "tf_plan": ("constraint", "constraints/", _tf_plan_subjects),
}


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
    if not rules:
        # A present-but-empty rules array. Falling through would hand back no
        # records and no reason, and _normalize_extraction's floor would abstain
        # naming only the COLLECTION — leaving the reader of a scoped promise's
        # abstention unable to see WHICH constraint went undecided.
        return (), (f"the Org Policy for {constraint!r} carries an empty 'rules' "
                    "array, so it enforces nothing and refutes nothing — the "
                    "rule was not evaluated")
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


def _admit(promise: sec_artifact.Promise, z3, label: str):
    """Integrity-check a compiled promise. Returns ``(verdicts, register)``.

    (1) SEXPR AGREEMENT: re-render the stored ast and compare to the stored
    ``sexpr``, REFUSING TO REGISTER on mismatch. A disagreement is a detected
    inconsistency in a committed file, so it is ``contradicted``, not
    ``unverified``.

    There is exactly ONE accepted rendering — :func:`sec_ast.render_sexpr`, the
    z3-INDEPENDENT form ``compile-requirements`` commits, so an artifact survives
    a z3 upgrade — and the comparison against it is a strict inequality. The z3
    encoding of the same ast is a DIFFERENT string
    (``(exists ((b iam_bindings)) (eq b.role "roles/owner"))`` versus
    ``(= |iam_bindings#b.role| "roles/owner")``) and is refused like any other
    stored value that is not the one form. The renderer lives in
    :mod:`~gcp_grounding.sec_ast`, the leaf both stages already import, so
    neither stage reaches across for the other's copy. The stored ast is still
    re-encoded first: a shape that no longer encodes is an honest abstention, and
    that check is what this comparison rests on.
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
        sec_encode.symbolic(z3, promise.ast)
        one_form = sec_ast.render_sexpr(promise.ast)
    except (sec_encode.UnsupportedTerm, KeyError, TypeError, RecursionError) as exc:
        # A stored ast that will not re-encode or will not re-render cannot be
        # integrity-checked at all. That is an abstention naming the reason, never
        # a second accepted spelling of the one form.
        return ([Verdict("unverified", "sec:artifact", promise.id, 0,
                         f"{label}: the stored ast could not be re-encoded ({exc}) — "
                         "integrity was not verified; the rule was registered")], True)

    if promise.sexpr != one_form:
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
