"""THE three-input evaluation entry point: a proposal, the current state, rules.

This is the one place the three inputs meet. It COMPOSES with
:func:`gcp_grounding.preflight.ground_policy` rather than replacing it, and it
edits no existing module: everything here is additive, so wiring the engine in
front of the gate changes nothing when no state source is configured.

    PROPOSED                 CURRENT                     RULES
    the edit under review    the reconciled estate       built-in checks
    (already SANITIZED)      + its source ledger         + compiled promises

THE TIER CONTRACT, WHICH IS NORMATIVE
-------------------------------------

:data:`TIERS` is ``("proposal", "pair", "estate")`` and :data:`TIER_INPUTS`
declares, per tier, exactly which inputs a check of that tier may receive::

    proposal  the document, the vocabulary
    pair      the document, the vocabulary, the baseline
    estate    the document, the vocabulary, the baseline, the whole current state

**A check never receives an input its tier did not ask for, and a tier whose
input is MISSING abstains with a stated reason rather than being skipped** — a
skipped check and a passing check are indistinguishable to the agent reading
stderr, and the whole value of this gate is that the difference is visible.

THE PARTIAL-BASELINE ASYMMETRY, WHICH IS EASY TO GET BACKWARDS
--------------------------------------------------------------

A baseline derived from a PARTIAL source (a terraform artifact covers only what
terraform manages) is a SUBSET of the real current state. Two directions, and
they are not symmetric:

- A widening check that reasons "the proposal grants something the baseline does
  not" is an OVER-APPROXIMATION over a subset baseline: rows the partial view
  never saw look like new grants, so its ``contradicted`` may be a phantom. That
  finding is rewritten to ``unverified`` naming the partial source. Leaving it as
  a block is a FALSE BLOCK on a view that was never entitled to the finding.
- The same check's ``grounded`` is UNDER-APPROXIMATED and is NEVER downgraded:
  new ⊆ old-subset ⊆ reality, so "the change adds nothing" still holds against
  the whole estate.
- A ``subset_safe`` check is the mirror image. It looks for a WITNESS, so a
  subset can only make it quieter: its ``contradicted`` stands (the witness is
  real) and its ``grounded`` — "I found no witness" — is the one that becomes
  ``unverified``, because a subset is exactly where a witness hides.

Getting this backwards produces either false blocks (rewriting the wrong status)
or silent passes (trusting a "clean" answer a partial view could not have
earned). :data:`BASELINE_SOUNDNESS` records which mode a check is in;
:data:`gcp_grounding.provenance.DEFAULT_SOUNDNESS` — ``requires_complete`` — is
the conservative default for a check nobody has classified.

WHY STAGE 4 RUNS NOTHING
------------------------

``registry.run_document_checks`` is called from INSIDE ``ground_policy``, and
stage 1 calls ``ground_policy`` with the reconciled snapshot as the vocabulary —
so every registry DOCUMENT_CHECK has ALREADY RUN by the time the estate tier is
reached. An engine-side gate here would have to either re-run them (duplicating
verdicts and counts, while the ungated stage-1 copy still emits its answer, so
the abstention is defeated) or skip (making the gate a no-op). ``preflight.py``
is on the never-edit list, so the engine cannot suppress the first run. THE GATE
THEREFORE LIVES AT THE ONE CHOKE POINT INSIDE THE EDITABLE SET,
``registry.run_document_checks``, which knows both the provider identity and
``ctx.snapshot`` and reads ``provenance.ESTATE_SOUNDNESS`` /
``provenance.COLLECTION_CATEGORIES``; compiled estate-tier rules are gated the
same way inside ``sec_rules.CompiledRule.evaluate``. This stage collects what
those two produced and adds NOTHING.

WHERE THE RULESET COMES FROM
----------------------------

The engine does NOT load rules — it is handed a :class:`RuleSet`. The two real
entry points must both build one or the third input reaches neither: the CLI
loads ``sec_rules.load_rules(settings.requirements)`` in both normal and hook
mode and passes the result, and the gate does the same from its per-file
discovered settings. Both fail open with one note on ``ImportError`` or a parse
failure. It is restated here so the obligation is visible from the consuming
side: with no owner named, ``ground_policy``'s ``rules=`` parameter is bypassed
the moment the CLI routes through this engine, and every promise-related claim
goes unexercised end to end.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Mapping, Sequence

from . import baseline, claims as claims_module, compare, constraints, drift, facts, preflight, provenance, redact, registry, solver_census
from .core.log import get_logger
from .core.report import GroundingReport, Verdict
from .core.solver import get_solver
from .knowledge import GcpSnapshot
from .registry import CheckContext

logger = get_logger(__name__)

__all__ = [
    "EVAL_SCHEMA",
    "TIERS",
    "TIER_INPUTS",
    "DRIFT_MODES",
    "DEFAULT_DRIFT_MODE",
    "TF_PLAN_KIND",
    "IAM_SUBSET_IDENTITY",
    "NO_SNAPSHOT_KIND",
    "UNRESOLVED_KIND",
    "CRASHED_KIND",
    "TIER_INPUT_KIND",
    "PAIR_UNCHECKED_KIND",
    "RULES_KIND",
    "BASELINE_SOUNDNESS",
    "register_baseline_soundness",
    "baseline_soundness",
    "Proposal",
    "RuleSet",
    "EvalOptions",
    "EvaluationResult",
    "prepare_proposal",
    "evaluate",
]


# -- the vocabulary -----------------------------------------------------------

#: The schema of one :class:`EvaluationResult`. Neither ``report.SCHEMA`` nor
#: ``gate.GATE_SCHEMA`` is bumped by this module: an evaluation is a NEW
#: document, not a new version of either of those.
EVAL_SCHEMA = "gcp-grounding-eval/1"

#: The fallback definition of the tier ladder, used where
#: :mod:`gcp_grounding.sec_rules` is not part of this checkout or does not
#: export one. Defined locally so this module never hard-depends on the
#: requirements compiler.
_LOCAL_TIERS = ("proposal", "pair", "estate")


def _sec_rules_module() -> Any:
    """:mod:`gcp_grounding.sec_rules`, or ``None`` where it is not part of this
    checkout — resolved dynamically exactly like
    :func:`gcp_grounding.preflight._sec_rules_module`, so a missing compiler
    degrades to one honest note instead of an import error."""
    try:
        return importlib.import_module("gcp_grounding.sec_rules")
    except ImportError:
        return None


def _resolved_tiers() -> tuple[str, ...]:
    module = _sec_rules_module()
    found = getattr(module, "TIERS", None) if module is not None else None
    if isinstance(found, tuple) and found:
        return tuple(str(t) for t in found)
    return _LOCAL_TIERS


#: The tier ladder, weakest first.
TIERS = _resolved_tiers()

#: THE NORMATIVE TABLE: tier → the inputs a check of that tier receives. See the
#: module docstring — a check never receives an input its tier did not ask for,
#: and a tier whose input is missing ABSTAINS with a stated reason.
TIER_INPUTS: Mapping[str, tuple[str, ...]] = {
    "proposal": ("document", "vocabulary"),
    "pair": ("document", "vocabulary", "baseline"),
    "estate": ("document", "vocabulary", "baseline", "current"),
}

#: What a drift disagreement costs. ``report`` never blocks; ``block`` turns the
#: material drift verdict itself into a ``contradicted``.
DRIFT_MODES = ("report", "block")

#: The default: reporting is always on, blocking is opt-in.
DEFAULT_DRIFT_MODE = "report"

#: The document kind a terraform plan proposal carries.
TF_PLAN_KIND = "tf_plan"

#: The check identity of the BUILT-IN new⊆old comparison — the one pair check
#: that is not a registry registration and therefore has no document kind to be
#: keyed by.
IAM_SUBSET_IDENTITY = "iam-policy-subset"

#: "There is no current state at all, so every existence question is UNKNOWN".
NO_SNAPSHOT_KIND = "state:no-snapshot"

#: "This attribute could not be resolved statically and was removed."
UNRESOLVED_KIND = "proposal:unresolved"

#: "A stage raised." :func:`evaluate` never propagates an exception.
CRASHED_KIND = "engine:crashed"

#: "A tier was asked for and one of its declared inputs was not supplied."
TIER_INPUT_KIND = "tier:input"

#: "A baseline resolved, and no widening check is defined for its kind."
PAIR_UNCHECKED_KIND = "pair:no-check"

#: Compiled-rule plumbing, spelled exactly as ``preflight`` spells it.
RULES_KIND = "sec:compile"


# -- the pair-tier soundness registry -----------------------------------------

#: Check identity → soundness mode, where the identity is the DOCUMENT KIND for
#: a registry ``PAIR_CHECKS`` registration and :data:`IAM_SUBSET_IDENTITY` for
#: the built-in new⊆old comparison. Empty by construction: ``subset_safe`` is a
#: claim a check makes ABOUT ITSELF, so a domain module registers its own entry
#: and everything else defaults to
#: :data:`gcp_grounding.provenance.DEFAULT_SOUNDNESS`.
BASELINE_SOUNDNESS: dict[str, str] = {}


def register_baseline_soundness(identity: str, mode: str) -> None:
    """Declare how a pair check behaves against a PARTIAL baseline.

    Validated against :data:`gcp_grounding.provenance.SOUNDNESS_MODES` so the
    two soundness registries cannot drift into two vocabularies.
    """
    if not identity:
        raise ValueError("register_baseline_soundness needs a check identity "
                         "(a document kind, or the built-in subset identity)")
    if mode not in provenance.SOUNDNESS_MODES:
        raise ValueError(f"soundness mode {mode!r} is not one of "
                         f"{list(provenance.SOUNDNESS_MODES)}")
    BASELINE_SOUNDNESS[identity] = mode


def baseline_soundness(identity: str) -> str:
    """*identity*'s mode, defaulting to the conservative
    :data:`gcp_grounding.provenance.DEFAULT_SOUNDNESS`. Never raises."""
    return BASELINE_SOUNDNESS.get(identity, provenance.DEFAULT_SOUNDNESS)


# -- the four records ---------------------------------------------------------


@dataclass(frozen=True)
class Proposal:
    """The edit under review, ALREADY SANITIZED.

    ``document`` has been through :func:`gcp_grounding.facts.strip_unresolved`,
    and ``unresolved`` names every path that removal took out. The engine never
    sees a raw interpolation: stripping rather than nulling is what makes the
    existing conservative extractors do the right thing with ZERO edits to
    ``claims.py``, because they already skip an absent key and would read an
    explicit ``null`` as a value.
    """

    source: str
    document: Any
    kind: str | None
    unresolved: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "unresolved",
                           tuple(sorted({str(p) for p in self.unresolved})))
        object.__setattr__(self, "notes", tuple(self.notes))


@dataclass(frozen=True)
class RuleSet:
    """The THIRD input: the built-in checks, plus compiled requirement rules.

    ``builtin`` is the built-in claim/document/pair checks, which are always
    available; ``compiled`` are ``sec_rules.CompiledRule`` objects; and
    ``carry_verdicts`` are the compiler's own verdicts about promises it could
    NOT admit, carried through verbatim so a requirement that failed to compile
    is visible rather than silently absent.
    """

    builtin: bool = True
    compiled: tuple[Any, ...] = ()
    carry_verdicts: tuple[Verdict, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "compiled", tuple(self.compiled))
        object.__setattr__(self, "carry_verdicts", tuple(self.carry_verdicts))


@dataclass(frozen=True)
class EvalOptions:
    """Everything the caller decides about one evaluation.

    ``as_of`` and ``max_age_seconds`` are the FRESHNESS parameters
    :mod:`gcp_grounding.freshness` applies when the sources are loaded, which
    happens before this module is reached; they are carried here so ONE options
    record describes the whole run and the explain surface can say what the
    evaluation was configured with, rather than reconstructing it from the
    environment.
    """

    as_of: str | None = None
    max_age_seconds: int | None = None
    drift: str = DEFAULT_DRIFT_MODE
    auto_baseline: bool = True
    hints: baseline.Hints = field(default_factory=baseline.Hints)
    tiers: tuple[str, ...] = TIERS

    def __post_init__(self) -> None:
        object.__setattr__(self, "tiers", tuple(self.tiers))
        if self.drift not in DRIFT_MODES:
            raise ValueError(f"EvalOptions.drift {self.drift!r} is not one of "
                             f"{list(DRIFT_MODES)}")


@dataclass(frozen=True)
class EvaluationResult:
    """One report, and everything needed to explain where it came from."""

    report: GroundingReport
    proposal: Proposal
    current: Any = None
    derivation: Any = None
    provenance: tuple[Mapping[str, Any], ...] = ()
    schema: str = EVAL_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "provenance", tuple(self.provenance))


# -- building a proposal ------------------------------------------------------


def prepare_proposal(document: Any, kind: str | None, *, source: str,
                     unknown_paths: Iterable[str] = ()) -> Proposal:
    """The one way a :class:`Proposal` is built. The gate and the CLI both use it.

    Runs :func:`gcp_grounding.facts.strip_unresolved`, unions the removed paths
    with *unknown_paths*, and — for a terraform plan — derives the plan's OWN
    after-unknown paths here rather than leaving that to callers.

    AFTER-UNKNOWN IS DERIVED HERE AND NOT LEFT TO CALLERS. An unknown attribute
    is OMITTED from ``change.after`` entirely, so ``strip_unresolved`` finds
    nothing, no path is reported, no ``proposal:unresolved`` is emitted and the
    downgrade never fires — which would give the plan's LEAST CERTAIN attributes
    the CLEANEST pass in the whole system. Putting it in the one function every
    proposal is built through is what makes it impossible for a call site to
    forget.
    """
    sanitized, stripped = facts.strip_unresolved(document)
    paths = {str(p) for p in stripped} | {str(p) for p in unknown_paths}
    notes: list[str] = []
    if kind == TF_PLAN_KIND and isinstance(document, Mapping) \
            and document.get("resource_changes") is not None:
        derived, note = _after_unknown_paths(document)
        paths |= derived
        if note:
            notes.append(note)
    proposal = Proposal(source=source, document=sanitized, kind=kind,
                        unresolved=tuple(sorted(paths)), notes=tuple(notes))
    logger.debug("prepare_proposal(%s, kind=%s): %d unresolved path(s), %d note(s)",
                 source, kind, len(proposal.unresolved), len(proposal.notes))
    return proposal


def _after_unknown_paths(document: Mapping[str, Any]) -> tuple[set[str], str]:
    """``(address-prefixed after-unknown paths, note)`` for a plan document.

    Resolved through the ONE plan reader, lazily, so a checkout without the
    terraform readers degrades to a stated note rather than an import error —
    and never to silence, because silence here is exactly the clean pass this
    derivation exists to prevent.
    """
    try:
        plan = importlib.import_module("gcp_grounding.tfsource.plan")
    except ImportError:
        return set(), ("the plan's after_unknown mirror could not be read: "
                       "gcp_grounding.tfsource.plan is not part of this checkout, so "
                       "an attribute terraform has not resolved yet may have passed "
                       "unremarked")
    entries = document.get("resource_changes")
    if not isinstance(entries, (list, tuple)):
        return set(), ""
    found: set[str] = set()
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        address = str(entry.get("address") or "").strip()
        for path in plan.after_unknown_paths(entry):
            found.add(f"{address}.{path}" if address else str(path))
    return found, ""


# -- evaluation ---------------------------------------------------------------


_DEFAULT_OPTIONS = EvalOptions()


def evaluate(proposal: Proposal, current: Any, rules: RuleSet, *,
             options: EvalOptions = _DEFAULT_OPTIONS) -> EvaluationResult:
    """Evaluate one proposal against the current state and the rules.

    NEVER RAISES. Every stage is wrapped, and an escaping exception becomes one
    ``unverified`` verdict of kind ``engine:crashed`` targeted at the proposal
    source: the gate's fail-open contract does not stop being true because the
    call went through one more module.
    """
    report = GroundingReport()
    solver = get_solver()
    report.backend = solver.backend
    derivation = None
    rows: tuple[Mapping[str, Any], ...] = ()

    try:
        vocabulary, ledger, have_state = _stage_vocabulary(report, proposal, current)

        # STAGE 1 — the proposal tier.
        _stage(report, proposal, "proposal-tier",
               lambda: _stage_proposal(report, proposal, vocabulary))

        # STAGE 2 — the baseline.
        derivation = _stage(report, proposal, "baseline",
                            lambda: _stage_baseline(report, proposal, current,
                                                    have_state, options))

        # STAGE 3 — the pair tier, one dispatch per baseline ENTRY. The proposed
        # side is projected ONCE and shared with stage 6, so the two runs cannot
        # disagree about what the proposal says.
        pair_results: dict[int, tuple[Verdict, ...]] = {}
        projected: dict[str, tuple[Any, str | None]] = {}
        if derivation is not None:
            projected = _stage(report, proposal, "proposal-projection",
                               lambda: _proposed_projections(proposal, options),
                               default={}) or {}
            pair_results = _stage(
                report, proposal, "pair-tier",
                lambda: _stage_pair(report, proposal, vocabulary, solver,
                                    derivation, ledger, options, projected),
                default={}) or {}

        # STAGE 4 — the estate tier: collect and report, run NOTHING.
        _stage(report, proposal, "estate-tier",
               lambda: _stage_estate(report))

        # STAGE 5 — the compiled rules.
        _stage(report, proposal, "compiled-rules",
               lambda: _stage_rules(report, proposal, vocabulary, solver,
                                    derivation, rules))

        # STAGE 6 — per-source drift.
        drift_paths: dict[int, tuple[str, ...]] = {}
        if derivation is not None:
            drift_paths = _stage(
                report, proposal, "drift",
                lambda: _stage_drift(report, proposal, vocabulary, solver,
                                     derivation, ledger, pair_results, options,
                                     projected),
                default={}) or {}

        # THE DOWNGRADE — applied last, so a `grounded` minted by ANY stage over
        # a document part of which could not be resolved is caught. See
        # _downgrade_grounded for why `contradicted` and `ungrounded` stand.
        _downgrade_grounded(report, proposal)

        rows = _stage(report, proposal, "provenance",
                      lambda: _provenance_rows(ledger, derivation, drift_paths),
                      default=()) or ()
    except Exception as exc:                        # noqa: BLE001 — never raise
        logger.debug("engine.evaluate(%s) raised outside a stage", proposal.source,
                     exc_info=True)
        report.add(Verdict("unverified", CRASHED_KIND, proposal.source, 0,
                           f"{proposal.source}: the evaluation raised "
                           f"{type(exc).__name__}: {exc} — nothing after that point "
                           f"was decided"))

    logger.debug("engine.evaluate(%s): %s ok=%s", proposal.source, report.counts(),
                 report.ok)
    return EvaluationResult(report=report, proposal=proposal, current=current,
                            derivation=derivation, provenance=rows)


def _stage(report: GroundingReport, proposal: Proposal, name: str, call: Any,
           default: Any = None) -> Any:
    """Run one stage fail-open: a raised exception becomes exactly ONE
    ``engine:crashed`` verdict naming the stage, never a propagated error."""
    try:
        return call()
    except Exception as exc:                        # noqa: BLE001 — fail-open
        logger.debug("engine stage %s raised for %s — abstaining", name,
                     proposal.source, exc_info=True)
        report.add(Verdict("unverified", CRASHED_KIND, proposal.source, 0,
                           f"{proposal.source}: the {name} stage raised "
                           f"{type(exc).__name__}: {exc} — that stage decided nothing"))
        return default


# -- stage 1: the vocabulary and the proposal tier ----------------------------


def _stage_vocabulary(report: GroundingReport, proposal: Proposal, current: Any
                      ) -> tuple[GcpSnapshot, Any, bool]:
    """``(vocabulary, ledger, have_state)``.

    With no current state the vocabulary is an EMPTY snapshot plus one
    ``state:no-snapshot`` verdict saying so: every existence question was
    answered UNKNOWN, no counterpart was looked up for the pair tier, and the
    estate tier had nothing to read. That single verdict is the stated reason
    the later tiers abstain, which is what keeps a skipped check from looking
    like a passing one.
    """
    snapshot = ledger = None
    try:
        snapshot, ledger = baseline.current_view(current)
    except TypeError as exc:
        report.add(Verdict("unverified", NO_SNAPSHOT_KIND, proposal.source, 0,
                           f"{proposal.source}: the current state could not be read "
                           f"({exc}) — every existence question was answered UNKNOWN "
                           f"and no counterpart was looked up"))
    if snapshot is None:
        report.add(Verdict("unverified", NO_SNAPSHOT_KIND, proposal.source, 0,
                           f"{proposal.source}: no current state was configured, so an "
                           f"EMPTY vocabulary was used: every existence question was "
                           f"answered UNKNOWN, the pair tier's baseline input "
                           f"{TIER_INPUTS['pair'][-1]!r} was not supplied and the "
                           f"estate tier had nothing to read"))
        return GcpSnapshot(captured_at=""), None, False
    return snapshot, ledger, True


def _stage_proposal(report: GroundingReport, proposal: Proposal,
                    vocabulary: GcpSnapshot) -> None:
    """Ground the document against the vocabulary, then put every stripped
    attribute on the record.

    ``ground_policy`` is called with NO baseline: the pair tier is dispatched per
    baseline entry in stage 3, and handing a whole multi-resource plan to a
    single pair check would compare an entire plan against one resource's
    counterpart.
    """
    merged = preflight.ground_policy(proposal.document, vocabulary)
    report.backend = merged.backend
    for verdict in merged.verdicts:
        report.add(verdict)
    for path in proposal.unresolved:
        report.add(Verdict("unverified", UNRESOLVED_KIND, path, 0,
                           f"{proposal.source}: '{path}' could not be resolved "
                           f"statically; it was REMOVED from the document before any "
                           f"check ran, so every check that would have read it "
                           f"abstained"))
    for note in proposal.notes:
        report.add(Verdict("unverified", UNRESOLVED_KIND, proposal.source, 0,
                           f"{proposal.source}: {note}"))


def _downgrade_grounded(report: GroundingReport, proposal: Proposal) -> None:
    """THE DOWNGRADE that keeps a stripped document from passing.

    When anything was stripped, every ``grounded`` verdict becomes
    ``unverified``: part of the document could not be resolved statically, so a
    clean result cannot be claimed. ``contradicted`` and ``ungrounded`` STAND —
    they are statements about what IS there, and an unreadable neighbour does
    not make a present finding go away. The verdict TUPLE is rebuilt rather than
    mutated, because a ``Verdict`` is frozen.
    """
    if not proposal.unresolved:
        return
    suffix = (f" — part of this document ({len(proposal.unresolved)} attribute(s)) "
              f"could not be resolved statically, so a clean result cannot be claimed")
    report.verdicts = [
        replace(v, status="unverified", message=v.message + suffix)
        if v.status == "grounded" else v
        for v in report.verdicts
    ]


# -- stage 2: the baseline ----------------------------------------------------


def _stage_baseline(report: GroundingReport, proposal: Proposal, current: Any,
                    have_state: bool, options: EvalOptions) -> Any:
    """The current counterpart of every row this proposal changes, or ``None``.

    Skipped when auto-baseline is off — with one verdict naming the pair tier's
    unsupplied input, because a silently absent baseline makes every pair check
    vanish. Skipped with no verdict when there is no current state at all: the
    ``state:no-snapshot`` verdict already said exactly that, and repeating it
    per target trains a reader to ignore the channel.
    """
    if not options.auto_baseline:
        report.add(Verdict("unverified", TIER_INPUT_KIND, proposal.source, 0,
                           f"{proposal.source}: auto-baseline is off, so the pair "
                           f"tier's declared inputs {list(TIER_INPUTS['pair'])} were "
                           f"not all supplied — no current counterpart was derived "
                           f"and every pair check abstained"))
        return None
    if not have_state:
        return None
    derivation = baseline.derive(proposal.document, proposal.kind, current,
                                 hints=options.hints, source=proposal.source)
    for verdict in derivation.verdicts:
        report.add(verdict)
    return derivation


# -- stage 3: the pair tier ---------------------------------------------------


def _stage_pair(report: GroundingReport, proposal: Proposal,
                vocabulary: GcpSnapshot, solver: Any, derivation: Any,
                ledger: Any, options: EvalOptions,
                projected: Mapping[str, tuple[Any, str | None]]
                ) -> dict[int, tuple[Verdict, ...]]:
    """DISPATCHED PER BASELINE ENTRY AND NEVER PER FILE.

    ``registry.PAIR_CHECKS`` is keyed by DOCUMENT KIND, and the gate hands every
    ``.tf`` / ``.tf.json`` edit to this engine as a terraform-plan-kind proposal.
    Dispatching on the PROPOSAL kind therefore means ``pair_check("tf_plan")`` is
    None, the IAM fallback does not apply, and NO pair check ever runs for a
    terraform edit at all — and worse, the whole multi-resource plan would be
    passed as ``ctx.document``, so even a matching kind would compare an entire
    plan against one resource's baseline.

    So: ``baseline.targets_for`` already yields one target per managed resource,
    each entry's kind comes from ``baseline.project_record``, the PROPOSED
    resource is projected into that same kind's document shape, and
    ``registry.pair_check`` is called with THAT kind. It is never called with the
    plan kind.
    """
    if "pair" not in options.tiers:
        return {}
    results: dict[int, tuple[Verdict, ...]] = {}
    for index, entry in enumerate(derivation.entries):
        # `comparable` is a document AND a kind: an entry with one and not the
        # other would send the PROPOSAL's kind — `tf_plan` for every terraform
        # edit — into `pair_check`, which is the exact dispatch bug above.
        if not entry.comparable:
            continue
        document = _proposed_document(projected, entry, proposal)
        verdicts, identity = _run_pair(entry.kind, document, entry, vocabulary,
                                       solver, proposal)
        verdicts = _apply_baseline_soundness(verdicts, identity,
                                             _entry_scope(ledger, entry),
                                             entry.source_id or "the current state")
        verdicts = tuple(_attributed(v, entry) for v in verdicts)
        for verdict in verdicts:
            report.add(verdict)
        results[index] = verdicts
    return results


def _proposed_document(projected: Mapping[str, tuple[Any, str | None]], entry: Any,
                       proposal: Proposal) -> Any:
    """The PROPOSED side for one entry: that resource's own projection when the
    proposal is a terraform plan, and the whole document otherwise (which is
    exactly one resource for a REST proposal)."""
    projection = projected.get(entry.target.address)
    return projection[0] if projection is not None else proposal.document


def _run_pair(kind: str | None, document: Any, entry: Any,
              vocabulary: GcpSnapshot, solver: Any, proposal: Proposal
              ) -> tuple[tuple[Verdict, ...], str]:
    """``(verdicts, check identity)`` for one baseline entry.

    A registered domain widening check first, then — for an IAM policy ONLY —
    the built-in new⊆old comparison, and otherwise one honest abstention: a
    counterpart that resolved and has no check defined for it is a gap, and a
    gap that emits nothing is indistinguishable from a pass.
    """
    fn = registry.pair_check(kind)
    if fn is not None:
        # THE CLAIMS ARE THE PROPOSED SIDE. A registered pair check reads
        # ``ctx.claims`` for the NEW rule set (``fw_checks.check_packet_set_pair``
        # does, and abstains with "no VPC firewall rule was extracted from the
        # document" when it is empty), so handing it an empty tuple made every
        # registered pair check structurally undecidable: the check ran, said it
        # could not compare, and the row it was dispatched for was never judged.
        ctx = CheckContext(snapshot=vocabulary, solver=solver, document=document,
                           document_kind=kind, source=proposal.source,
                           claims=_pair_claims(kind, document),
                           baseline=entry.document, baseline_kind=entry.kind)
        row = entry.key or entry.target.key
        return tuple(_addressed(v, row)
                     for v in registry.run_pair_check(fn, ctx)), str(kind)
    if kind == "iam_policy":
        try:
            return (constraints.check_policy_subset(document, entry.document, solver),), \
                IAM_SUBSET_IDENTITY
        except ValueError as exc:
            return (Verdict("unverified", "subset", "iam-policy", 0,
                            f"new⊆old was not decided: {exc}"),), IAM_SUBSET_IDENTITY
    return (Verdict("unverified", PAIR_UNCHECKED_KIND, entry.key or entry.target.key, 0,
                    f"a current counterpart resolved for "
                    f"'{entry.key or entry.target.key}', but no widening check is "
                    f"defined for document kind {kind!r} — the change was NOT compared "
                    f"against it"),), str(kind)


def _pair_claims(kind: str | None, document: Any) -> tuple[Any, ...]:
    """The claims the PROJECTED PROPOSED document makes, for a pair check that
    reads them.

    The same extractor resolution ``preflight._extract_claims`` uses — the
    registry's document extractor, with the two built-in kinds spelled out — so
    the pair tier and the claim tier read one document the same way. Extraction
    trouble is empty claims plus a debug line: the check's own "nothing was
    extracted" abstention is the honest answer and it already exists.
    """
    if kind is None or not isinstance(document, Mapping):
        return ()
    if kind == "iam_policy":
        extract: Any = claims_module.iam_policy_claims
    elif kind == "org_policy":
        extract = claims_module.org_policy_claims
    else:
        extract = registry.document_extractor(kind)
    if extract is None:
        return ()
    try:
        return tuple(extract(document))
    except Exception:                   # noqa: BLE001 — the engine never raises
        logger.debug("the pair tier could not extract %s claims from the projected "
                     "proposal", kind, exc_info=True)
        return ()


def _addressed(verdict: Verdict, row: str) -> Verdict:
    """*verdict* re-addressed to the ROW the pair tier was dispatched for.

    ``registry.PAIR_CHECKS`` is dispatched once per baseline entry, so its
    findings are about that row — but a check names its own answer's scope in
    ``target`` (``fw_checks`` names the ``(network, direction)`` group), which
    leaves a per-row report with no verdict addressed to the row. The check's
    own spelling is kept in the message rather than dropped, and the built-in
    new⊆old comparison is deliberately NOT re-addressed: its ``iam-policy``
    target is the historical one and is pinned elsewhere.
    """
    if not row or verdict.target == row:
        return verdict
    return replace(verdict, target=row,
                   message=f"{verdict.message} [pair scope {verdict.target}]")


def _attributed(verdict: Verdict, entry: Any) -> Verdict:
    """*verdict* with the entry's attribution appended — an unattributed pair
    finding is not auditable, because a reader cannot tell WHICH resource, WHICH
    source and WHICH identification produced it."""
    return replace(verdict, message=(
        f"{verdict.message} [target {entry.key or entry.target.key} | source "
        f"{entry.source_id or 'unattributed'} | how {entry.how}]"))


def _apply_baseline_soundness(verdicts: Sequence[Verdict], identity: str,
                              scope: str, source_label: str) -> tuple[Verdict, ...]:
    """THE PARTIAL-BASELINE ASYMMETRY, applied. See the module docstring.

    A ``complete`` baseline is left entirely alone. Otherwise a
    ``requires_complete`` check has its ``contradicted`` rewritten to
    ``unverified`` (an over-approximation over a subset baseline is a phantom
    block) and keeps its ``grounded`` (new ⊆ subset ⊆ reality); a
    ``subset_safe`` check keeps its ``contradicted`` (the witness is real) and
    has its ``grounded`` rewritten instead (a subset is where a witness hides).
    """
    if scope == "complete":
        return tuple(verdicts)
    mode = baseline_soundness(identity)
    out: list[Verdict] = []
    for verdict in verdicts:
        if mode == "requires_complete" and verdict.status == "contradicted":
            out.append(replace(verdict, status="unverified", message=(
                f"{verdict.message} — NOT a block: the baseline came from "
                f"'{source_label}', whose coverage of this domain is '{scope}', and a "
                f"check that reasons from what the baseline does NOT contain cannot "
                f"tell a real widening from a row that view never saw")))
        elif mode == "subset_safe" and verdict.status == "grounded":
            out.append(replace(verdict, status="unverified", message=(
                f"{verdict.message} — NOT a clean result: the baseline came from "
                f"'{source_label}', whose coverage of this domain is '{scope}', and a "
                f"witness-seeking check that found nothing in a subset has not looked "
                f"at the whole estate")))
        else:
            out.append(verdict)
    return tuple(out)


def _proposed_projections(proposal: Proposal, options: EvalOptions
                          ) -> dict[str, tuple[Any, str | None]]:
    """``terraform address → (projected proposal document, kind)``.

    The PROPOSED side of a plan goes through the same
    ``canonical_from_object`` → ``project_record`` path the baseline side uses,
    so one resource cannot acquire two spellings across the comparison.
    """
    objects = tuple(options.hints.objects)
    if not objects and proposal.kind in baseline.TF_KINDS:
        objects = _plan_objects(proposal.document, proposal.source)
    if not objects:
        return {}
    try:
        mapping = importlib.import_module("gcp_grounding.tfsource.mapping")
    except ImportError:
        logger.debug("gcp_grounding.tfsource.mapping is not part of this checkout "
                     "— a terraform proposal projects no per-resource document")
        return {}
    hints = options.hints
    aliases = dict(hints.aliases)
    if hints.project_number and hints.project:
        aliases.setdefault(hints.project_number, hints.project.split("/")[-1])
    context = mapping.MapContext(
        project=hints.project, project_number=hints.project_number,
        region=hints.region, organization=hints.organization, folder=hints.folder,
        access_policy=hints.access_policy, aliases=aliases)
    out: dict[str, tuple[Any, str | None]] = {}
    for obj in objects:
        if not mapping.is_managed(obj):
            continue
        resolved = mapping.canonical_from_object(obj, context)
        if resolved is None:
            continue
        category, key, record = resolved
        if not isinstance(key, str) or not key:
            continue
        document, kind = baseline.project_record(category, key, record)
        if document is not None:
            out[obj.address] = (document, kind)
    return out


def _plan_objects(document: Any, source: str) -> tuple[Any, ...]:
    """The PROPOSED terraform objects of a plan, through the one plan reader."""
    try:
        plan = importlib.import_module("gcp_grounding.tfsource.plan")
    except ImportError:
        return ()
    read = plan.read_plan_document(document, origin=source or "<proposal>")
    if not read.ok:
        logger.debug("the plan proposal was refused: %s", "; ".join(read.notes))
        return ()
    return tuple(read.proposed)


# -- stage 4: the estate tier -------------------------------------------------


def _stage_estate(report: GroundingReport) -> tuple[Verdict, ...]:
    """Collect what the estate tier already produced, and add NOTHING.

    See the module docstring: every registry ``DOCUMENT_CHECK`` and every
    estate-tier compiled rule has ALREADY run — inside ``ground_policy`` — by the
    time this stage is reached, and both are gated at their own choke points.
    Re-running them here would duplicate every verdict while the ungated copy
    still emits its answer; skipping would make the gate a no-op. So this stage
    reports and returns.
    """
    collected = tuple(v for v in report.verdicts if v.kind.startswith("estate:"))
    logger.debug("estate tier: %d verdict(s) already produced upstream; the engine "
                 "adds none", len(collected))
    return collected


# -- stage 5: the compiled rules ----------------------------------------------


def _stage_rules(report: GroundingReport, proposal: Proposal,
                 vocabulary: GcpSnapshot, solver: Any, derivation: Any,
                 rules: RuleSet) -> None:
    """Evaluate the compiled requirement rules, and carry the compiler's verdicts.

    The estate-tier soundness gate is NOT re-applied here — ``CompiledRule``
    applies it inside ``evaluate``, and a second application is the same
    duplicate-verdict trap stage 4 just avoided. The PAIR-tier
    :data:`BASELINE_SOUNDNESS` rewrite still applies to a rule whose tier is
    pair, because nothing else does it for a rule.
    """
    for verdict in rules.carry_verdicts:
        report.add(verdict)
    if not rules.compiled:
        return
    module = _sec_rules_module()
    if module is None:
        report.add(Verdict("unverified", RULES_KIND, proposal.source, 0,
                           f"{proposal.source}: {len(rules.compiled)} compiled "
                           f"requirement(s) were supplied, but gcp_grounding.sec_rules "
                           f"is not available — they were not run"))
        return
    primary = derivation.primary() if derivation is not None else None
    rule_ctx = module.RuleContext(
        snapshot=vocabulary, document=proposal.document,
        document_kind=proposal.kind, source=proposal.source,
        baseline=primary.document if primary is not None else None,
        estate=_estate_records(vocabulary), solver=solver)
    for rule in rules.compiled:
        verdict = solver_census.evaluate_rule(rule, rule_ctx)
        if verdict is None:
            continue
        tier = getattr(getattr(rule, "promise", None), "state", "")
        if tier == "pair" and primary is not None:
            identity = getattr(getattr(rule, "promise", None), "id", "") or "rule"
            rewritten = _apply_baseline_soundness(
                (verdict,), identity, primary.scope,
                primary.source_id or "the current state")
            verdict = rewritten[0]
        report.add(verdict)


def _estate_records(snapshot: GcpSnapshot) -> dict[str, tuple[Any, ...]]:
    """ESTATE COLLECTION → the current state's records for it.

    Keyed through :data:`gcp_grounding.provenance.COLLECTION_CATEGORIES` — the
    one mapping from a promise's collection name to a snapshot category — rather
    than by restating the correspondence here.
    """
    out: dict[str, tuple[Any, ...]] = {}
    for collection, category in provenance.COLLECTION_CATEGORIES.items():
        table = getattr(snapshot, category, None)
        if table is None:
            continue
        if isinstance(table, Mapping):
            out[collection] = tuple(dict(record) for _key, record in sorted(table.items())
                                    if isinstance(record, Mapping))
        else:
            out[collection] = tuple(sorted(str(item) for item in table))
    return out


# -- stage 6: per-source drift ------------------------------------------------


def _stage_drift(report: GroundingReport, proposal: Proposal,
                 vocabulary: GcpSnapshot, solver: Any, derivation: Any,
                 ledger: Any, pair_results: Mapping[int, tuple[Verdict, ...]],
                 options: EvalOptions,
                 projected: Mapping[str, tuple[Any, str | None]]
                 ) -> dict[int, tuple[str, ...]]:
    """One drift verdict per conflicting entry, then the pair check ONCE PER
    CONFLICTING SOURCE.

    EVERY PER-SOURCE VERDICT PASSES THROUGH THE SAME
    :func:`_apply_baseline_soundness` REWRITE AS STAGE 3, KEYED ON THAT SOURCE'S
    OWN SCOPE. Without that, this stage is a back door through the
    partial-baseline asymmetry: a terraform alternate is structurally at most
    ``partial``, the widening check is ``requires_complete`` by default, and
    stage 3 would have rewritten its ``contradicted`` to ``unverified`` — so
    letting the same verdict through here as a hard block reinstates exactly the
    false block the asymmetry forbids, arriving by a different code path.

    ALL per-source verdicts are added AFTER the rewrite, so a ``contradicted``
    that SURVIVES it — one from a source that covers the domain completely —
    still makes the report not-ok. Fail-safe on disagreement, honest in
    reporting, and never fail-safe on a view that was never entitled to the
    finding. Precedence decides only which document is PRIMARY; it never
    suppresses the other side's finding.
    """
    paths_by_entry: dict[int, tuple[str, ...]] = {}
    if "pair" not in options.tiers:
        return paths_by_entry
    for index, entry in enumerate(derivation.entries):
        if entry.status != "conflict":
            continue
        category = entry.target.category
        differing = _differing_paths(category, entry)
        paths_by_entry[index] = tuple(path for path, _values in differing)
        status = "contradicted" if options.drift == "block" else "unverified"
        report.add(Verdict(status, drift.DRIFT_MATERIAL,
                           entry.key or entry.target.key, 0,
                           _drift_message(entry, differing)))
        if not entry.comparable:
            continue

        document = _proposed_document(projected, entry, proposal)
        statuses = {v.status for v in pair_results.get(index, ())}
        for candidate in entry.others:
            verdicts = _per_source_verdicts(candidate, category, entry, entry.kind,
                                            document, vocabulary, solver, proposal,
                                            ledger)
            statuses.update(v.status for v in verdicts)
            for verdict in verdicts:
                report.add(verdict)
        if len(statuses) > 1:
            report.add(Verdict("unverified", drift.DRIFT_VERDICT,
                               entry.key or entry.target.key, 0,
                               f"ONE CHECK, TWO ANSWERS for '{entry.key or entry.target.key}': "
                               f"one source reports {sorted(statuses)[0]!r} and another "
                               f"reports {sorted(statuses)[-1]!r} for the same change. The "
                               f"gate is reporting both and picking neither: precedence "
                               f"decides which document is primary, never which finding is "
                               f"true"))
    return paths_by_entry


def _per_source_verdicts(candidate: Any, category: str, entry: Any,
                         kind: str | None, document: Any, vocabulary: GcpSnapshot,
                         solver: Any, proposal: Proposal, ledger: Any
                         ) -> tuple[Verdict, ...]:
    """The pair check re-run against ONE losing source's whole record.

    The alternate's record is projected exactly as the winner's was, so the two
    runs differ only in which view of the resource they compared against.
    """
    alt_document, alt_kind = baseline.project_record(category, entry.key,
                                                     candidate.record)
    if alt_document is None:
        return (Verdict("unverified", drift.DRIFT_MATERIAL,
                        entry.key or entry.target.key, 0,
                        f"source '{candidate.source_id or 'unattributed'}' disagrees "
                        f"about '{entry.key}', but its record has no counterpart "
                        f"document form — its answer was NOT computed"),)
    alternate = replace(entry, document=alt_document, kind=alt_kind or entry.kind,
                        record=candidate.record, source_id=candidate.source_id,
                        others=())
    verdicts, identity = _run_pair(kind, document, alternate, vocabulary, solver,
                                   proposal)
    scope = _source_scope(ledger, candidate.source_id)
    verdicts = _apply_baseline_soundness(verdicts, identity, scope,
                                         candidate.source_id or "an unnamed source")
    label = candidate.source_id or "unattributed"
    key = entry.key or entry.target.key
    return tuple(replace(v, message=(f"{v.message} [per-source: {label} "
                                     f"(scope {scope}) | target {key}]"))
                 for v in verdicts)


def _source_scope(ledger: Any, source_id: str) -> str:
    """That source's own declared scope, or ``undeclared`` when nobody said.

    Never ``complete`` by default: a source the ledger cannot describe has not
    earned the right to a hard block.
    """
    record = getattr(ledger, "sources", {}).get(source_id) if ledger is not None else None
    scope = getattr(record, "scope", "") if record is not None else ""
    return scope or "undeclared"


def _entry_scope(ledger: Any, entry: Any) -> str:
    """THE COVERAGE THAT GOVERNS ONE BASELINE ENTRY: the stronger of the merged
    category scope and the OWN declared scope of the source the entry's document
    came from.

    A resolved entry's document is one source's record, taken wholesale — the
    merge picks a winner per row and backfills, it does not blend two readings —
    and ``entry.source_id`` names that source. The merged CATEGORY scope is
    composed across every source and is capped by views that did not supply this
    row: most visibly by the terraform cap, which holds any category a terraform
    artifact touched at ``partial`` however completely an API capture enumerated
    it. Reading only that is how PRECEDENCE ends up SUPPRESSING a finding —
    winning the merge would demote a source's own answer to a scope it never
    declared, and the same source's finding would have survived as a losing
    alternate in stage 6, which routes through exactly this declaration. The
    per-source answers and the primary's answer are graded by one rule.

    STRONGER, never weaker, and that direction is the whole safety argument: the
    merge can license a row past what its own source declared (a complete peer
    backfilling it), so the composition may add, but it may not take away what
    the source that supplied the row said about itself. ``BASELINE_SOUNDNESS``
    is empty by construction, so every check is ``requires_complete`` and the
    only reachable effect is a ``contradicted`` SURVIVING — fail-safe.

    THE ONE PLACE THE SOURCE'S OWN CLAIM IS REFUSED is a BOUNDARY MISMATCH.
    ``complete within organizations/1`` and ``complete`` are different claims
    about different universes, which is why ``compose_scope`` demotes a category
    whose contributors name different boundaries and drops the boundary with it.
    Re-reading one contributor's ``complete`` there would undo that demotion by
    the back door, so the upgrade applies only where the source is speaking
    about the SAME universe the merged category describes.
    """
    scope = getattr(entry, "scope", "") or "uncaptured"
    source_id = getattr(entry, "source_id", "")
    sources = getattr(ledger, "sources", None) if ledger is not None else None
    record = sources.get(source_id) if (source_id and sources is not None) else None
    if record is None:
        return scope
    category = getattr(getattr(entry, "target", None), "category", "")
    scope_of = getattr(ledger, "scope_of", None)
    if not callable(scope_of):
        # A ledger that cannot be asked what the category's boundary is cannot
        # have the boundary check applied to it, and an unchecked upgrade is
        # the back door the paragraph above closes.
        return scope
    if getattr(scope_of(category), "boundary", "") != getattr(record, "boundary", ""):
        return scope
    declared = getattr(record, "scope", "") or "uncaptured"
    try:
        return max((scope, declared), key=provenance.scope_rank)
    except ValueError:
        # A ledger written by a future version may spell a scope this lattice
        # does not know; the merged answer is the one that was already trusted.
        logger.debug("source %s declares unknown scope %r — keeping the merged "
                     "category scope %r", source_id, declared, scope)
        return scope


def _differing_paths(category: str, entry: Any
                     ) -> tuple[tuple[str, tuple[tuple[str, str], ...]], ...]:
    """``((path, ((source, rendered value), ...)), ...)`` over every alternate.

    Rendered through :func:`_wire`, so a value the loading boundary already
    replaced with a digest is named by its digest and never by its plaintext.
    """
    collected: dict[str, dict[str, str]] = {}
    winner = entry.source_id or "unattributed"
    for candidate in entry.others:
        try:
            diffs = compare.compare(category, entry.record, candidate.record)
        except compare.Incomparable as exc:
            collected.setdefault("<record>", {})[
                candidate.source_id or "unattributed"] = f"incomparable ({exc.detail})"
            continue
        for diff in diffs:
            bucket = collected.setdefault(diff.path, {})
            bucket.setdefault(winner, _render(diff.left))
            bucket[candidate.source_id or "unattributed"] = _render(diff.right)
    return tuple((path, tuple(sorted(collected[path].items())))
                 for path in sorted(collected))


def _drift_message(entry: Any, differing: Sequence[tuple[str, tuple[tuple[str, str], ...]]]
                   ) -> str:
    key = entry.key or entry.target.key
    sources = ", ".join(sorted({entry.source_id or "unattributed"} |
                               {c.source_id or "unattributed" for c in entry.others}))
    if not differing:
        return (f"the sources describing '{key}' ({sources}) are recorded as "
                f"disagreeing, but no comparable field difference was found — the "
                f"disagreement is reported and no side is picked")
    rendered = "; ".join(
        f"{path}: " + ", ".join(f"{source}={value}" for source, value in values)
        for path, values in differing)
    return (f"{len(differing)} field(s) of '{key}' differ between the sources that "
            f"describe it ({sources}): {rendered} — the gate reports every source's "
            f"value and picks none")


def _render(value: Any) -> str:
    return repr(_wire(value))


def _wire(value: Any) -> Any:
    """*value* with every :class:`gcp_grounding.redact.Redacted` replaced by its
    wire form, so a drift message can name a sensitive field's DIFFERENCE
    without carrying either secret."""
    if isinstance(value, redact.Redacted):
        return value.wire()
    if isinstance(value, Mapping):
        return {str(k): _wire(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (set, frozenset)):
        return sorted((_wire(item) for item in value), key=repr)
    if isinstance(value, (list, tuple)):
        return [_wire(item) for item in value]
    return value


# -- provenance ---------------------------------------------------------------


def _provenance_rows(ledger: Any, derivation: Any,
                     drift_paths: Mapping[int, tuple[str, ...]]
                     ) -> tuple[Mapping[str, Any], ...]:
    """The current state's rows, then one row per baseline entry carrying the
    target, key, how, status, chosen source and the paths that drifted."""
    rows: list[Mapping[str, Any]] = []
    sources = getattr(ledger, "sources", {}) if ledger is not None else {}
    for source_id in sorted(sources):
        record = sources[source_id]
        rows.append({"row": "source", "source": source_id,
                     "kind": getattr(record, "kind", ""),
                     "origin": getattr(record, "origin", ""),
                     "scope": getattr(record, "scope", ""),
                     "boundary": getattr(record, "boundary", ""),
                     "captured_at": getattr(record, "captured_at", "")})
    if derivation is not None:
        for index, entry in enumerate(derivation.entries):
            row = dict(entry.row())
            row["row"] = "baseline"
            row["drift"] = tuple(drift_paths.get(index, ()))
            rows.append(row)
    return tuple(rows)
