"""The one shared fact vocabulary: what a terraform-derived fact IS, and how
ignorance about one is spelled.

This module is deliberately FLAT (``gcp_grounding.facts``, not
``gcp_grounding.tfsource.facts``): both the terraform readers under
``tfsource/`` and the source-agnostic proposal sanitizer need it, and the
layering rule is that ``tfsource`` imports DOWN into the flat vocabulary and
never the reverse. It depends on the standard library and ``core.log`` only —
it imports neither :mod:`gcp_grounding.knowledge` nor anything under
``tfsource``, so nothing here can grow a cycle back into the estate model.

Three things live here and nowhere else:

- :class:`Unresolved`, the ignorance marker. Terraform is a program, not a
  document: a value can be an interpolation, a ``count`` expansion, a
  ``for_each`` key or an ``(known after apply)`` placeholder. Every such value
  becomes a marker naming WHY it could not be resolved. Like
  ``knowledge.UNKNOWN``, a marker refuses truthiness, so
  ``if not values["network"]`` cannot silently turn *could not resolve* into
  *empty*. Its ``repr`` never carries ``detail``, so a marker that captured a
  fragment of a secret cannot leak through a log line, a traceback or a pytest
  assertion dump.
- :class:`TfObject` and :class:`Fact`, the two intermediates every layer-1
  reader produces and every mapper emits.
- The category partition — :data:`FLAT_CATEGORIES`, :data:`TABLE_CATEGORIES`
  and their union :data:`TF_CATEGORIES` — which says exactly which estate
  categories a terraform artifact is allowed to speak for.

Attribute values NEVER go into a log line raw; :func:`safe_repr` is the only
rendering any module in this design may use for one.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping, Sequence

from .core.log import get_logger

logger = get_logger(__name__)

__all__ = [
    "MAX_DETAIL",
    "MAX_DEPTH",
    "UNRESOLVED_REASONS",
    "Unresolved",
    "unresolved_in",
    "is_unresolved",
    "has_unresolved",
    "first_unresolved",
    "truncate",
    "is_interpolated",
    "strip_unresolved",
    "safe_repr",
    "PROPOSED_SOURCES",
    "SIDES",
    "TfObject",
    "Fact",
    "FLAT_CATEGORIES",
    "TABLE_CATEGORIES",
    "TF_CATEGORIES",
    "EXCLUDED_CATEGORIES",
]

#: Longest ``detail`` an :class:`Unresolved` may carry. A marker is a
#: diagnostic, not a copy of the artifact — anything longer is a payload, and a
#: payload is what leaks.
MAX_DETAIL = 200

#: How deep the walkers descend before they degrade. A document deeper than
#: this is answered with one ``depth_cap`` marker, never a ``RecursionError``:
#: a crash inside a gate is a gate that decided nothing.
MAX_DEPTH = 64

#: Every reason a value may be unresolved. Closed on purpose: a free-text
#: reason is a reason nobody can grep for, and a typo'd one is a category of
#: ignorance that silently never appears in a report.
UNRESOLVED_REASONS = frozenset({
    "interpolation",       # "${var.x}" — the value is a program, not a literal
    "count",               # count.index expansion; the object is a template
    "for_each",            # each.key/each.value expansion
    "dynamic_block",       # a dynamic "…" block; the body is generated
    "function_call",       # cidrsubnet(...), join(...) — needs an evaluator
    "heredoc",             # <<EOT … EOT; embedded document, not a scalar
    "provider_alias",      # provider = google.other; the project is elsewhere
    "missing_project",     # no project attribute and no provider default
    "unknown_after_apply", # plan says (known after apply)
    "sensitive",           # marked sensitive; the value must not be captured
    "unparsed",            # syntax this reader does not implement
    "ambiguous_key",       # two artifacts name the same key different things
    "depth_cap",           # nesting beyond MAX_DEPTH; minted by the walkers
})

#: The two spellings that mean "this fact describes a PROPOSED change, not
#: reality". Defined HERE rather than in ``provenance`` because it is
#: structural to what a fact IS, and because it must be DISJOINT from
#: ``provenance.SOURCES``: every member of that tuple is a CURRENT-state
#: spelling and there is no proposed member in it.
#:
#: ``tfplan-planned`` is what ``tfsource/plan.py`` stamps on a
#: ``resource_changes`` / ``planned_values`` object; ``hcl-proposed`` is what
#: ``tfsource/hcl.py`` stamps when configuration is read as a PROPOSAL rather
#: than as a desired-state current view.
#:
#: The reasoning behind the disjointness: a proposed fact never participates in
#: a winner selection, because ``merge.resolve`` partitions it into ``dropped``
#: at step 1. Ranking a proposal against reality is never a meaningful
#: question, so ``provenance.fidelity_rank`` raises on these spellings rather
#: than inventing an order for them.
PROPOSED_SOURCES = ("tfplan-planned", "hcl-proposed")

#: The two sides of the engine. A fact is either part of the current-state view
#: or part of the change under review; there is no third option and no default.
SIDES = ("current", "proposed")

_ROOT_PATH = "<root>"


# -- the ignorance marker -----------------------------------------------------


@dataclass(frozen=True, repr=False)
class Unresolved:
    """A value terraform did not hand us as a literal, and why.

    ``path`` is where the marker was minted (``"values.source_ranges"``), which
    is NOT necessarily where it later sits in a document — the walkers below
    report that separately. ``detail`` is an optional short diagnostic and is
    never rendered by :meth:`__repr__`.
    """

    reason: str
    path: str
    detail: str = ""

    def __post_init__(self) -> None:
        if self.reason not in UNRESOLVED_REASONS:
            raise ValueError(f"unresolved reason {self.reason!r} is not one of "
                             f"{sorted(UNRESOLVED_REASONS)}")
        if not self.path:
            raise ValueError("Unresolved.path must name where the value came from; "
                             "an unattributed marker cannot be turned into a verdict")
        if len(self.detail) > MAX_DETAIL:
            raise ValueError(f"Unresolved.detail is {len(self.detail)} characters, "
                             f"over MAX_DETAIL={MAX_DETAIL}; clip it with truncate()")
        # A "sensitive" marker exists precisely because the value must not be
        # captured. Carrying a detail alongside it is the exact leak the reason
        # was invented to prevent, so it is refused at construction.
        if self.reason == "sensitive" and self.detail:
            raise ValueError("Unresolved(reason='sensitive') must carry no detail — "
                             "the detail is the value the marker exists to withhold")

    def __repr__(self) -> str:
        # detail is DELIBERATELY absent: a marker minted from a heredoc or a
        # provider block may hold a fragment of a secret, and a repr lands in
        # log lines, tracebacks and pytest assertion dumps.
        return f"Unresolved(reason={self.reason!r}, path={self.path!r})"

    def __bool__(self) -> bool:
        raise TypeError(
            "Unresolved is neither True nor False — this value could not be "
            "resolved from the terraform artifact; compare with "
            "`facts.is_unresolved(...)` and emit an 'unverified' verdict, "
            "never 'ungrounded'"
        )


def is_unresolved(value: Any) -> bool:
    """True if ``value`` IS a marker (not if it merely contains one)."""
    return isinstance(value, Unresolved)


def _is_sequence(value: Any) -> bool:
    """A JSON-ish array — a string is a scalar here, never a sequence."""
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def _walk(value: Any, path: str, depth: int) -> Iterator[tuple[str, Unresolved]]:
    if is_unresolved(value):
        yield path or _ROOT_PATH, value
        return
    if isinstance(value, Mapping):
        if depth >= MAX_DEPTH:
            yield path or _ROOT_PATH, _depth_marker(path)
            return
        # Sorted, so the yield order depends on the document's CONTENT and not
        # on how the reader happened to build its dicts.
        for key, item in sorted(value.items(), key=lambda kv: str(kv[0])):
            child = f"{path}.{key}" if path else str(key)
            yield from _walk(item, child, depth + 1)
    elif _is_sequence(value):
        if depth >= MAX_DEPTH:
            yield path or _ROOT_PATH, _depth_marker(path)
            return
        for index, item in enumerate(value):
            yield from _walk(item, f"{path}[{index}]", depth + 1)


def _depth_marker(path: str) -> Unresolved:
    return Unresolved("depth_cap", path or _ROOT_PATH,
                      f"nesting past MAX_DEPTH={MAX_DEPTH}")


def unresolved_in(value: Any) -> Iterator[tuple[str, Unresolved]]:
    """Yield ``(path, marker)`` for every marker in ``value``, depth-first in
    deterministic path order — mapping keys sorted, sequences in index order,
    so the order depends on the document's content and not on how the reader
    happened to build its dicts.

    Paths are dotted-and-indexed — ``allow[0].ports``, ``rule[1].match.expr`` —
    so a caller can name the attribute a verdict is about. Nesting past
    :data:`MAX_DEPTH` appends one ``depth_cap`` marker for that branch and
    stops descending; a document deep enough to blow the stack degrades to
    unresolved rather than crashing the gate.
    """
    yield from _walk(value, "", 0)


def has_unresolved(value: Any) -> bool:
    """True if ``value`` is or contains a marker. Short-circuits on the first."""
    return next(unresolved_in(value), None) is not None


def first_unresolved(value: Any) -> tuple[str, Unresolved] | None:
    """The earliest ``(path, marker)`` pair in ``value``, or ``None``."""
    return next(unresolved_in(value), None)


def truncate(text: str, limit: int = MAX_DETAIL) -> str:
    """Clip ``text`` to at most ``limit`` characters INCLUDING the ellipsis, so
    ``truncate(x)`` is always a legal :class:`Unresolved` detail."""
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit - 1] + "…"


def is_interpolated(text: Any) -> bool:
    """True if ``text`` contains terraform interpolation anywhere in it.

    This is a SUBSTRING test, never a ``startswith`` test: ``roles/${var.tier}.admin``
    is PARTIALLY interpolated, and emitting it as a literal role name produces a
    guaranteed false ``ungrounded`` against a value terraform never intended to
    exist. The escaped literal ``$${`` is ALSO refused, because it contains
    ``${`` — deliberately conservative, and stated here so nobody later "fixes"
    it into a leak: mistaking an escaped literal for an interpolation costs one
    honest abstention, while mistaking an interpolation for a literal costs a
    false verdict against a name nobody wrote.
    """
    return isinstance(text, str) and "${" in text


#: Returned by :func:`_strip` for a value the caller must OMIT — distinct from
#: ``None``, which is a value a document may legitimately carry.
_DROP = object()


def _strip(value: Any, path: str, depth: int, removed: list[str]) -> Any:
    if is_unresolved(value):
        # REMOVE, never null: every extractor in this repo skips an absent key
        # conservatively and would read an explicit null as a value.
        removed.append(path or _ROOT_PATH)
        return _DROP
    if isinstance(value, Mapping):
        if depth >= MAX_DEPTH:
            removed.append(path or _ROOT_PATH)
            return _DROP
        out: dict[Any, Any] = {}
        for key, item in value.items():          # key order preserved
            child = f"{path}.{key}" if path else str(key)
            kept = _strip(item, child, depth + 1, removed)
            if kept is not _DROP:
                out[key] = kept
        return out
    if _is_sequence(value):
        if depth >= MAX_DEPTH:
            removed.append(path or _ROOT_PATH)
            return _DROP
        out_list: list[Any] = []
        for index, item in enumerate(value):
            kept = _strip(item, f"{path}[{index}]", depth + 1, removed)
            if kept is not _DROP:
                out_list.append(kept)
        return out_list
    return copy.deepcopy(value)


def strip_unresolved(document: Any) -> tuple[Any, tuple[str, ...]]:
    """Sanitize a PROPOSAL: return ``(deep copy without the unresolved
    attributes, sorted tuple of the paths removed)``.

    An attribute that fails resolution is REMOVED rather than nulled, because
    the repo's extractors already skip an absent key conservatively and would
    treat an explicit ``null`` as a value. Paths are the ORIGINAL document's
    dotted-and-indexed paths, so they still name the attribute after a sibling
    list element has been dropped. A document that is ITSELF a marker (or is
    nested past :data:`MAX_DEPTH` at its root) sanitizes to ``None`` with
    ``("<root>",)`` removed — there is nothing left to hand a check.

    **The caller's obligation, in one sentence: a caller MUST emit one verdict
    per returned path, because a silently stripped attribute is an attribute
    that bought a clean pass.**
    """
    removed: list[str] = []
    sanitized = _strip(document, "", 0, removed)
    if sanitized is _DROP:
        sanitized = None
    if removed:
        logger.debug("stripped %d unresolved path(s) from %s: %s",
                     len(removed), safe_repr(document), sorted(removed))
    return sanitized, tuple(sorted(removed))


def safe_repr(value: Any) -> str:
    """Render an attribute value for a log line WITHOUT its content.

    A ``str`` renders as ``<str len=N>`` and never raw: an attribute value is
    exactly where a token, a key or a customer identifier lives. This is the
    only rendering of an attribute value any module in this design may log.
    """
    if isinstance(value, str):
        return f"<str len={len(value)}>"
    if isinstance(value, (bytes, bytearray)):
        return f"<{type(value).__name__} len={len(value)}>"
    if isinstance(value, Unresolved):
        return repr(value)          # already detail-free by construction
    if value is None or isinstance(value, (bool, int, float)):
        return repr(value)          # shape-only scalars, nothing to leak
    if isinstance(value, Mapping):
        return f"<mapping keys={len(value)}>"
    if _is_sequence(value):
        return f"<{type(value).__name__} len={len(value)}>"
    return f"<{type(value).__name__}>"


# -- the types ----------------------------------------------------------------


def _check_source_side(source: str, side: str, where: str) -> None:
    """The structural invariant, in one place: ``source in PROPOSED_SOURCES``
    and ``side == "proposed"`` imply each other IN BOTH DIRECTIONS."""
    if side not in SIDES:
        raise ValueError(f"{where}.side must be one of {list(SIDES)}, got {side!r}")
    if not source:
        raise ValueError(f"{where}.source must name the artifact spelling it came from")
    proposed_source = source in PROPOSED_SOURCES
    if proposed_source and side != "proposed":
        raise ValueError(f"{where}: source {source!r} is a proposed spelling but "
                         f"side is {side!r} — a proposed change can never be "
                         f"constructed as current state")
    if side == "proposed" and not proposed_source:
        raise ValueError(f"{where}: side is 'proposed' but source {source!r} is a "
                         f"current-state spelling — a current-state spelling can "
                         f"never be smuggled onto the proposed side; use one of "
                         f"{list(PROPOSED_SOURCES)}")


def _as_tuple(value: Any) -> tuple[Any, ...]:
    return tuple(value) if isinstance(value, (list, tuple)) else value


@dataclass(frozen=True)
class TfObject:
    """One terraform object as a layer-1 reader saw it — the single
    intermediate a state, plan or HCL reader produces, before any mapping into
    estate categories has happened.

    ``values`` is the object's attributes with unresolved ones already replaced
    by :class:`Unresolved` markers; ``unresolved`` is the flat roll-up of those
    markers, and ``sensitive_paths`` the attribute paths the artifact itself
    flagged sensitive.
    """

    address: str
    type: str
    name: str
    module: str = ""
    index_key: Any = None
    provider: str = ""
    source: str = ""
    side: str = "current"
    values: Mapping[str, Any] = field(default_factory=dict)
    sensitive_paths: tuple[str, ...] = ()
    unresolved: tuple[Unresolved, ...] = ()
    notes: tuple[str, ...] = ()
    artifact: str = ""

    def __post_init__(self) -> None:
        if not self.address:
            raise ValueError("TfObject.address must be the terraform address "
                             "(e.g. 'google_compute_firewall.allow_ssh')")
        if not self.type:
            raise ValueError(f"TfObject({self.address!r}).type must be the resource type")
        _check_source_side(self.source, self.side, f"TfObject({self.address!r})")
        object.__setattr__(self, "sensitive_paths", _as_tuple(self.sensitive_paths))
        object.__setattr__(self, "unresolved", _as_tuple(self.unresolved))
        object.__setattr__(self, "notes", _as_tuple(self.notes))


# -- the category partition ---------------------------------------------------

#: Categories whose snapshot value is a flat set of names. A fact about one of
#: these carries a ``key`` and no ``record``.
FLAT_CATEGORIES = ("networks", "subnetworks", "network_tags", "service_accounts",
                   "access_levels", "restricted_services")

#: Categories whose snapshot value is a name → record table. A fact about one
#: of these carries the ``record`` the mapper built, and may name the
#: ``fragment`` of it that this artifact spoke for. ``roles`` is here — a
#: terraform custom role carries its own ``permissions`` list, so it is a
#: record, not a bare name.
TABLE_CATEGORIES = ("roles", "firewall_rules", "hierarchical_firewall_policies",
                    "cloud_armor_policies", "vpc_sc_perimeters",
                    "resource_hierarchy", "iam_bindings", "org_policies")

#: The fourteen estate categories a terraform artifact can produce.
TF_CATEGORIES = FLAT_CATEGORIES + TABLE_CATEGORIES

#: The estate categories terraform is NOT allowed to speak for, and why. Each
#: is a provider or platform vocabulary that terraform never enumerates, so
#: treating a terraform capture as authoritative for one manufactures existence
#: answers — a name absent from the capture would read as a name that does not
#: exist.
EXCLUDED_CATEGORIES = {
    "permissions": "the IAM permission vocabulary is Google's; terraform names roles, never the permissions behind one",
    "principals": "identities are created outside terraform (directory, workload identity), so a capture is never the population",
    "constraints": "org-policy constraint DEFINITIONS ship with the platform; terraform sets policies, it does not define constraints",
    "resource_types": "the asset-type vocabulary is the provider's; a configuration mentions the types it happens to use and no more",
}


@dataclass(frozen=True)
class Fact:
    """One mapped claim about one estate category, with where it came from.

    ``record is None`` if and only if the category is flat; a table category
    always carries the record the mapper built. ``fragment`` names the part of
    a record this artifact spoke for (e.g. ``"rules"``) and is meaningful only
    for a table category. ``origin`` is the artifact this fact was read from,
    ``address`` the terraform address inside it.
    """

    category: str
    key: str
    record: Mapping[str, Any] | None = None
    source: str = ""
    side: str = "current"
    origin: str = ""
    address: str = ""
    fragment: str = ""
    unresolved: tuple[Unresolved, ...] = ()
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.category not in TF_CATEGORIES:
            if self.category in EXCLUDED_CATEGORIES:
                raise ValueError(
                    f"category {self.category!r} is deliberately outside "
                    f"TF_CATEGORIES: {EXCLUDED_CATEGORIES[self.category]}")
            raise ValueError(f"category {self.category!r} is not one of "
                             f"{list(TF_CATEGORIES)}")
        if not self.key:
            raise ValueError(f"Fact({self.category!r}).key must name the thing "
                             f"the fact is about")
        flat = self.category in FLAT_CATEGORIES
        if flat and self.record is not None:
            raise ValueError(f"Fact({self.category!r}) is a flat category, so record "
                             f"must be None; a flat category has names, not records")
        if not flat and self.record is None:
            raise ValueError(f"Fact({self.category!r}) is a table category, so it must "
                             f"carry the record the mapper built, not just a name")
        if self.fragment and flat:
            raise ValueError(f"Fact({self.category!r}) is a flat category, so fragment "
                             f"{self.fragment!r} names nothing")
        _check_source_side(self.source, self.side, f"Fact({self.category!r})")
        object.__setattr__(self, "unresolved", _as_tuple(self.unresolved))
        object.__setattr__(self, "notes", _as_tuple(self.notes))
