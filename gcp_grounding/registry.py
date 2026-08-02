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
"""

from __future__ import annotations

import importlib
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
    """Call ``fn(*args)`` fail-open: a raised exception becomes exactly one
    honest ``unverified`` verdict naming the provider, never propagated. A
    crashing domain module must not break the gate."""
    try:
        return _as_verdicts(fn(*args))
    except Exception as exc:  # noqa: BLE001 — fail-open by contract
        logger.debug("provider %s raised — abstaining", _label(fn), exc_info=True)
        return [Verdict("unverified", "document", ctx.source, 0,
                        f"{_label(fn)} raised {type(exc).__name__}: {exc} "
                        f"— not decided")]


def run_claim_checks(claim: "Claim", ctx: CheckContext) -> "list[Verdict]":
    """Every registered check for *claim*'s kind, run fail-open."""
    verdicts: list[Verdict] = []
    for fn in claim_checks(claim.kind):
        verdicts.extend(_invoke(fn, ctx, claim, ctx))
    return verdicts


def run_document_checks(ctx: CheckContext) -> "list[Verdict]":
    """Every registered whole-document check, run fail-open."""
    verdicts: list[Verdict] = []
    for fn in document_checks():
        verdicts.extend(_invoke(fn, ctx, ctx))
    return verdicts


def run_pair_check(fn: Any, ctx: CheckContext) -> "list[Verdict]":
    """Run one resolved pair check fail-open (baseline already parsed on *ctx*)."""
    return _invoke(fn, ctx, ctx)
