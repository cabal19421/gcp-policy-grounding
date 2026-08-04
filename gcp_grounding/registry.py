"""The single extension seam for the twelve later grounding-domain modules.

:func:`~gcp_grounding.preflight.ground_policy` consults this registry before
its honest catch-all, so a domain module (VPC firewall, hierarchical firewall,
Cloud Armor, VPC-SC, IAM deny, the missing half of Org Policy) becomes a
self-contained new file rather than an edit to a shared one. A provider module
opts in *purely* by defining any of a handful of module-level names — none is
required — and is discovered lazily:

``DOCUMENT_EXTRACTORS``  ``dict[str, Callable[[Mapping], list[Claim]]]`` keyed by
    document kind — claims for a whole new document kind.
``TF_EXTRACTORS``  ``dict[str, Callable[[str, Mapping], list[Claim]]]`` keyed by
    terraform resource type — claims for a new google-provider resource.
``CLAIM_CHECKS``  ``dict[str, Callable[[Claim, CheckContext], Verdict |
    Sequence[Verdict] | None]]`` keyed by claim kind — the offline check(s) for
    a claim kind (run for existence kinds too: the IAM escalation check attaches
    to ``role``).
``DOCUMENT_CHECKS``  ``tuple[Callable[[CheckContext], Sequence[Verdict]], ...]``
    — whole-document checks that do not hang off a single claim.
``PAIR_CHECKS``  ``dict[str, Callable[[CheckContext], Sequence[Verdict]]]`` keyed
    by document kind, run only when a baseline was supplied (widening/delta).

Resolution is lazy and **fail-open**, exactly like
:func:`gcp_grounding.preflight._tf_plan_extractor`: :func:`_providers` walks
:data:`PROVIDER_MODULES` with :func:`importlib.import_module`, swallows
``ImportError`` with a ``logger.debug`` and caches the survivors; a domain
module that is not part of this checkout simply does not contribute. Every
provider callable is then invoked inside a ``try/except Exception`` in the
``run_*`` helpers, so a crashing domain module records one honest ``unverified``
verdict naming it rather than breaking the gate.

**THE CONTRACT FOR PROVIDER AUTHORS, and the one half of it that is not
automatic.** A check that reads estate facts through the snapshot's own
accessors gets drift adjudication FOR FREE and has to do nothing: the three
``run_*`` helpers invoke it through :func:`gcp_grounding.drift.guarded`, which
records exactly the facts it touched and downgrades a ``grounded`` resting on a
disputed or stale one to ``unverified`` naming that fact — so a check cannot
mint a clean bill of health from evidence the sources disagree about, whether or
not its author thought about drift. THE OTHER HALF IS NOT AUTOMATIC. A check
that wants to assert a UNIVERSALLY-QUANTIFIED NEGATIVE — "no rule anywhere
allows this" — must still call :func:`gcp_grounding.provenance.require_complete`
itself (and should declare itself through
:func:`gcp_grounding.provenance.register_estate_soundness`, which is what lets
:func:`run_document_checks` gate it), because no read tap can tell the
difference between having read the whole table and found nothing and having read
the whole table and found something: both are the same set of reads, and only
the check knows which conclusion it drew from them.
"""

from __future__ import annotations

import importlib
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping

from .core.log import get_logger
from .core.report import Verdict

if TYPE_CHECKING:  # annotations only — no runtime import weight, no cycle
    from collections.abc import Callable, Sequence

    from .claims import Claim
    from .knowledge import GcpSnapshot

logger = get_logger(__name__)

__all__ = [
    "PROVIDER_MODULES", "CheckContext", "reset_cache",
    "document_extractor", "tf_extractors", "claim_checks", "document_checks",
    "pair_check", "run_claim_checks", "run_document_checks", "run_pair_check",
    "DRIFT_POLICY_ENV", "ESTATE_INCOMPLETE",
]

#: Provider modules consulted, in order. Naming one that is absent from this
#: checkout is not an error — it is simply skipped (see :func:`_providers`).
PROVIDER_MODULES = (
    "gcp_grounding.fw_claims", "gcp_grounding.fw_checks", "gcp_grounding.fw_estate",
    "gcp_grounding.hfw_claims", "gcp_grounding.hfw_checks",
    "gcp_grounding.armor_claims", "gcp_grounding.armor_checks",
    "gcp_grounding.vpcsc_claims", "gcp_grounding.vpcsc_checks",
    "gcp_grounding.iam_deny", "gcp_grounding.iam_checks",
    "gcp_grounding.org_checks",
)


@dataclass(frozen=True)
class CheckContext:
    """Everything a domain check may read about one grounding run.

    Frozen and hashable-by-intent: a check receives it, never mutates it. When
    a baseline was supplied, :attr:`baseline` is the *parsed* document (not the
    path) and :attr:`baseline_kind` its :func:`~gcp_grounding.preflight.detect_kind`
    — the baseline is read exactly once, upstream, and shared by every check.
    """

    snapshot: "GcpSnapshot"
    solver: Any
    document: Any
    document_kind: str | None
    source: str
    claims: tuple[Any, ...]
    baseline: Any = None
    baseline_kind: str | None = None


# -- lazy, fail-open provider discovery ---------------------------------------

#: The imported provider modules, or None until first resolved. Reset for tests
#: with :func:`reset_cache`.
_PROVIDERS: tuple[Any, ...] | None = None


def _providers() -> tuple[Any, ...]:
    """The importable provider modules, in :data:`PROVIDER_MODULES` order.

    A module that is not part of this checkout is skipped with a ``debug`` log,
    never raised — exactly the degradation of
    :func:`gcp_grounding.preflight._tf_plan_extractor`. Cached; call
    :func:`reset_cache` after mutating :data:`PROVIDER_MODULES`.
    """
    global _PROVIDERS
    if _PROVIDERS is None:
        modules = []
        for name in PROVIDER_MODULES:
            try:
                modules.append(importlib.import_module(name))
            except ImportError:
                logger.debug("provider module %s is not part of this checkout "
                             "— skipped", name)
        _PROVIDERS = tuple(modules)
    return _PROVIDERS


def reset_cache() -> None:
    """Drop the cached provider modules so the next lookup re-resolves them.

    For tests that inject a stub into ``sys.modules`` and monkeypatch
    :data:`PROVIDER_MODULES`; production never needs it."""
    global _PROVIDERS
    _PROVIDERS = None


# -- resolvers (what a provider registered) -----------------------------------


def document_extractor(kind: str) -> "Callable | None":
    """The first provider's ``DOCUMENT_EXTRACTORS[kind]``, or None."""
    for module in _providers():
        table = getattr(module, "DOCUMENT_EXTRACTORS", None)
        if isinstance(table, Mapping) and kind in table:
            return table[kind]
    return None


def tf_extractors() -> "dict[str, Callable]":
    """The merged ``TF_EXTRACTORS`` across providers, keyed by resource type;
    earlier providers win on a duplicate key."""
    merged: dict[str, Any] = {}
    for module in _providers():
        table = getattr(module, "TF_EXTRACTORS", None)
        if isinstance(table, Mapping):
            for key, fn in table.items():
                merged.setdefault(key, fn)
    return merged


def claim_checks(kind: str) -> "tuple[Callable, ...]":
    """Every provider's ``CLAIM_CHECKS[kind]``, in provider order."""
    checks: list[Any] = []
    for module in _providers():
        table = getattr(module, "CLAIM_CHECKS", None)
        if isinstance(table, Mapping) and kind in table:
            checks.append(table[kind])
    return tuple(checks)


def document_checks() -> "tuple[Callable, ...]":
    """Every provider's ``DOCUMENT_CHECKS``, concatenated in provider order."""
    checks: list[Any] = []
    for module in _providers():
        table = getattr(module, "DOCUMENT_CHECKS", None)
        if isinstance(table, (tuple, list)):
            checks.extend(table)
    return tuple(checks)


def pair_check(kind: str | None) -> "Callable | None":
    """The first provider's ``PAIR_CHECKS[kind]``, or None."""
    for module in _providers():
        table = getattr(module, "PAIR_CHECKS", None)
        if isinstance(table, Mapping) and kind in table:
            return table[kind]
    return None


# -- the drift guard and the estate gate, both lazy and both fail-open --------
#
# Every resolution below follows `preflight._tf_plan_extractor` exactly: an
# import inside a `try`, `None` on `ImportError`, a `logger.debug` and no cache —
# so a checkout without the reconciliation modules keeps the seam it had, and a
# test can simulate their absence by putting `None` in `sys.modules` without a
# reset hook. THROUGH `importlib.import_module` AND NOT `from . import drift`:
# a `from`-import is answered from the already-set package ATTRIBUTE and would
# sail straight past the `None` sentinel, so the degradation this whole edit
# rests on would be untestable and, on a real broken install, unobserved.

#: Where the drift policy is configured. Unset, or set to anything
#: :data:`gcp_grounding.drift.DRIFT_POLICIES` does not name, costs the default
#: and a debug line — see :func:`_drift_policy`.
DRIFT_POLICY_ENV = "GCP_GROUNDING_DRIFT_POLICY"

#: The kind of the estate-tier completeness refusal :func:`run_document_checks`
#: emits INSTEAD OF running a check whose conclusion needs a whole category.
#: A new KIND, not a new status: ``unverified`` already means "not decided".
ESTATE_INCOMPLETE = "estate:incomplete"

#: The bracketed clause a completeness downgrade appends. Deliberately the SAME
#: SHAPE as :data:`gcp_grounding.drift.NOT_DECIDED`, so a reader greps one form,
#: and spelled here rather than imported because the estate gate must keep
#: working on a checkout that has no drift module.
NOT_DECIDED = "  [not decided: {reason}]"


def _sibling(name: str) -> Any:
    """The sibling module *name*, or ``None`` where it is not part of this
    checkout."""
    try:
        return importlib.import_module(f".{name}", __package__)
    except ImportError:
        logger.debug("gcp_grounding.%s is not part of this checkout — skipped", name)
        return None


def _guard() -> "Callable | None":
    """:func:`gcp_grounding.drift.guarded`, or ``None`` where the drift module
    is not part of this checkout — in which case every call site below keeps the
    call it had."""
    drift = _sibling("drift")
    return None if drift is None else drift.guarded


def _provenance() -> Any:
    """The provenance module, or ``None`` — with no soundness registry there is
    no estate-tier completeness to gate."""
    return _sibling("provenance")


def _reconciled(snapshot: Any) -> bool:
    """Whether *snapshot* carries provenance to adjudicate against."""
    reconciled = _sibling("reconciled")
    return (reconciled is not None
            and isinstance(snapshot, reconciled.ReconciledSnapshot))


def _drift_policy() -> str:
    """The drift policy for this run: :data:`DRIFT_POLICY_ENV` when it names one
    of :data:`gcp_grounding.drift.DRIFT_POLICIES`, else
    :data:`gcp_grounding.drift.DEFAULT_DRIFT_POLICY`.

    An unrecognised value FALLS BACK AND LOGS AT DEBUG rather than raising: this
    runs deep inside the call stack, once per provider callable, and a bad
    environment variable must not turn every grounding run into a crash.
    ``sources.load_current`` is where a bad value is reported to a human as a
    usage error.

    Called only from the guarded arm of :func:`_invoke`, where :func:`_guard`
    has already resolved the module; with no drift module there is no policy
    vocabulary to validate against and nothing that would read the answer.
    """
    drift = _sibling("drift")
    if drift is None:
        return ""
    value = os.environ.get(DRIFT_POLICY_ENV, "").strip()
    if not value:
        return drift.DEFAULT_DRIFT_POLICY
    if value in drift.DRIFT_POLICIES:
        return value
    logger.debug("unrecognised %s value %r — falling back to %r (expected one of "
                 "%s)", DRIFT_POLICY_ENV, value, drift.DEFAULT_DRIFT_POLICY,
                 list(drift.DRIFT_POLICIES))
    return drift.DEFAULT_DRIFT_POLICY


# -- fail-open invocation -----------------------------------------------------


def _label(fn: Any) -> str:
    """``<module>.<qualname>`` for the crash message, defensively."""
    module = getattr(fn, "__module__", "?")
    name = getattr(fn, "__qualname__", getattr(fn, "__name__", repr(fn)))
    return f"{module}.{name}"


def _as_verdicts(result: Any) -> "list[Verdict]":
    """Normalise a provider return (``None`` / one ``Verdict`` / a sequence)."""
    if result is None:
        return []
    if isinstance(result, Verdict):
        return [result]
    return list(result)


def _invoke(fn: Any, ctx: CheckContext, *args: Any) -> "list[Verdict]":
    """Call ``fn(*args)`` fail-open, THROUGH THE DRIFT GUARD.

    A raised exception becomes exactly one honest ``unverified`` verdict naming
    the provider, never propagated — a crashing domain module must not break the
    gate. That handler is deliberately OUTSIDE the guard and unchanged:
    :func:`gcp_grounding.drift.guarded` lets an exception through precisely so
    this one keeps owning it, and a second handler would either duplicate the
    verdict or replace it with a worse one.

    ZERO OVERHEAD WHERE THERE IS NOTHING TO GUARD. With no drift module, or with
    a snapshot that carries no provenance, the call below is the one this seam
    shipped with — same call, same ``try``/``except``, same verdict list, no read
    context opened and nothing allocated. That is the property that makes routing
    every domain check through the guard safe to land on top of the seam.
    """
    guard = _guard()
    try:
        if guard is None or not _reconciled(ctx.snapshot):
            return _as_verdicts(fn(*args))
        # The normalisation happens INSIDE the guard so the adjudicator always
        # receives a list: a provider may return None or a single Verdict, and
        # neither is the iterable of verdicts `drift.adjudicate` re-grades.
        return _as_verdicts(guard(lambda: _as_verdicts(fn(*args)), ctx.snapshot,
                                  _drift_policy(), label=_label(fn)))
    except Exception as exc:  # noqa: BLE001 — fail-open by contract
        logger.debug("provider %s raised — abstaining", _label(fn), exc_info=True)
        return [Verdict("unverified", "document", ctx.source, 0,
                        f"{_label(fn)} raised {type(exc).__name__}: {exc} "
                        f"— not decided")]


def run_claim_checks(claim: "Claim", ctx: CheckContext) -> "list[Verdict]":
    """Every registered check for *claim*'s kind, run fail-open and adjudicated
    against the estate facts it actually read (see :func:`_invoke`)."""
    verdicts: list[Verdict] = []
    for fn in claim_checks(claim.kind):
        verdicts.extend(_invoke(fn, ctx, claim, ctx))
    return verdicts


def run_document_checks(ctx: CheckContext) -> "list[Verdict]":
    """Every registered whole-document check, run fail-open and adjudicated —
    behind THE ESTATE-TIER COMPLETENESS GATE.

    THIS IS THE ONLY CHOKE POINT FOR A DOCUMENT CHECK, which is why the gate is
    here rather than in the engine: ``preflight.ground_policy`` calls this helper
    itself, so by the time any caller further out could gate anything every
    ``DOCUMENT_CHECK`` has already run against whatever view it was handed. A
    gate out there would either duplicate every estate verdict or be a no-op, and
    the unsound universally-quantified claim would be emitted either way.

    Per check, resolved from its ``module.function`` identity through
    :data:`gcp_grounding.provenance.ESTATE_SOUNDNESS` and defaulting to
    ``("requires_complete", None)``:

    - ``requires_complete`` with a declared category that
      :func:`gcp_grounding.provenance.require_complete` refuses — THE PROVIDER IS
      NOT INVOKED, and exactly one ``estate:incomplete`` verdict says so. This is
      the point where the completeness marker actually stops an unsound negative:
      a check concluding "no rule anywhere allows X" over a terraform-only view
      would otherwise return a confident clean bill of health, and the firewall
      table is exactly the category such a view under-enumerates;
    - ``requires_complete`` with NO category resolvable, or ``subset_safe`` over
      a view that is not complete — the check RUNS, and every ``grounded`` it
      returns is downgraded to ``unverified`` naming the incomplete view. NEVER
      FAIL SILENT HERE: an undeclared category must cost a clean pass, not buy
      one, and a witness-finder over a subset can miss a witness (so its
      ``contradicted`` stands and only its clean answer is doubted);
    - anything else — invoked normally, exactly as before.
    """
    verdicts: list[Verdict] = []
    for fn in document_checks():
        identity = _label(fn)
        mode, category = _soundness(identity)
        reason = _incomplete_reason(ctx.snapshot, category)
        if mode == "requires_complete" and category and reason:
            verdicts.append(_estate_incomplete(ctx, identity, category, reason))
            continue
        produced = _invoke(fn, ctx, ctx)
        if reason:
            produced = [_downgraded(v, identity, reason) for v in produced]
        verdicts.extend(produced)
    return verdicts


def run_pair_check(fn: Any, ctx: CheckContext) -> "list[Verdict]":
    """Run one resolved pair check fail-open and adjudicated (baseline already
    parsed on *ctx*)."""
    return _invoke(fn, ctx, ctx)


# -- the estate-tier completeness gate ----------------------------------------


def _soundness(identity: str) -> tuple[str, str | None]:
    """``(mode, category)`` for *identity*, defaulting to
    ``("requires_complete", None)``.

    With no provenance module there is no soundness registry to consult AND no
    reconciled view to gate against, so the pair degrades to the never-gate,
    never-downgrade case rather than to a second spelling of the default mode
    that :mod:`gcp_grounding.provenance` owns.
    """
    provenance = _provenance()
    if provenance is None:
        return "", None
    return (provenance.estate_soundness(identity),
            provenance.estate_soundness_category(identity))


def _incomplete_reason(snapshot: Any, category: str | None) -> str:
    """Why this view cannot support an estate-wide claim, or ``""``.

    With a category, THE question is that category's — the check named exactly
    what it needs, so nothing else in the view can gate or downgrade it. Without
    one, the question is asked of the whole view, because a check that declared
    nothing could have read anything.
    """
    if category:
        return _require_complete(snapshot, category) or ""
    return _incomplete_view(snapshot)


def _require_complete(snapshot: Any, category: str) -> str | None:
    """:func:`gcp_grounding.provenance.require_complete` over *snapshot*.

    Through the snapshot's OWN method where it has one — a
    :class:`~gcp_grounding.reconciled.ReconciledSnapshot` answers from its
    ledger, and asking the module directly would read the merged object as an
    unattributed capture and hand back ``complete`` for a partial view.
    """
    own = getattr(snapshot, "require_complete", None)
    if callable(own):
        return own(category)
    provenance = _provenance()
    if provenance is None:
        return None
    try:
        return provenance.require_complete(snapshot, category)
    except Exception:  # noqa: BLE001 — fail-open by contract
        # Not a partial view: not a view at all. The gate's pre-existing
        # fail-open contract owns bad input, and refusing every check on it
        # would be a worse answer than the crash handler already gives.
        logger.debug("require_complete could not read the snapshot for category "
                     "%r — the estate gate abstains", category, exc_info=True)
        return None


def _incomplete_view(snapshot: Any) -> str:
    """What is not complete about *snapshot* as a whole, or ``""``.

    A snapshot with no ledger is the PLAIN-``GcpSnapshot`` case and reads as
    complete — exactly the semantics :func:`~gcp_grounding.provenance
    .require_complete` gives it, and what keeps this gate byte-identical on the
    single-capture path it must not disturb. A ledger that declares no category
    at all licenses nothing, which is not the same thing and is not silently
    read as one.
    """
    ledger = getattr(snapshot, "ledger", None)
    if ledger is None:
        return ""
    declared = ledger.declared_categories()
    if not declared:
        return ("this view's source ledger declares no category at all, so no "
                "category's coverage is known and none can license a negative")
    weak = [name for name in declared
            if not ledger.scope_of(name).existence_licensed]
    if not weak:
        return ""
    named = ", ".join(f"'{name}' is {ledger.scope_of(name).scope}"
                      f"{_taint_note(ledger.scope_of(name))}" for name in weak)
    return (f"{len(weak)} of this view's {len(declared)} declared category(ies) "
            f"cannot license a negative ({named})")


def _taint_note(scope: Any) -> str:
    return f" and tainted '{scope.taint}'" if scope.taint else ""


def _coverage(snapshot: Any, category: str) -> str:
    """Who supplied *category* and with what scope, for the refusal message."""
    ledger = getattr(snapshot, "ledger", None)
    if ledger is None:
        return (f"'{category}' comes from a single unattributed capture, which "
                f"declared no coverage")
    scope = ledger.scope_of(category)
    sources = ", ".join(scope.source_kinds) or "no declared source"
    return (f"'{category}' comes from {sources} with '{scope.scope}' scope"
            f"{_taint_note(scope)}")


def _estate_incomplete(ctx: CheckContext, identity: str, category: str,
                       reason: str) -> Verdict:
    """The ONE verdict a gated estate-tier check yields instead of running."""
    return Verdict(
        "unverified", ESTATE_INCOMPLETE, ctx.source, 0,
        f"{identity} is registered as needing a COMPLETE '{category}', and this "
        f"current-state view does not supply one: {reason}. {_coverage(ctx.snapshot, category)}. "
        f"AN ESTATE-WIDE CLAIM CANNOT BE MADE FROM A PARTIAL VIEW — 'nothing "
        f"anywhere does X' is a universally-quantified negative, and an "
        f"enumeration that never claimed to be whole cannot support one — so "
        f"THIS CHECK DID NOT RUN and nothing about '{category}' was decided")


def _downgraded(verdict: Verdict, identity: str, reason: str) -> Verdict:
    """A ``grounded`` re-graded to ``unverified`` naming the incomplete view;
    every other status is returned unchanged. A finding stands on a partial
    view — only a CLEAN answer needs the whole table."""
    if verdict.status != "grounded":
        return verdict
    return Verdict(
        "unverified", verdict.kind, verdict.target, verdict.lineno,
        verdict.message + NOT_DECIDED.format(reason=(
            f"{identity} did not declare which category its conclusion needs "
            f"complete, or declared itself safe over a subset, and this view is "
            f"not complete: {reason}. An undeclared category must cost a clean "
            f"pass, not buy one")),
        suggestions=verdict.suggestions)
