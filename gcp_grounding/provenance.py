"""The one source ledger: where a fact came from, and what its absence licenses.

This module owns the whole provenance vocabulary of the design and the ONLY
sidecar schema. There is no scope sidecar, no bridge file and no
tolerate-either-file rule, which removes an entire class of
which-file-is-authoritative bug: a reader that cannot find the ledger has no
second place to look, so it abstains instead of guessing.

**The fidelity order** (:data:`SOURCES`, weakest first) is the total order every
winner selection uses. Its positions are deliberate:

- ``fixture`` — test-only. It must lose to everything, so a fixture accidentally
  left in a capture directory can never outrank real evidence.
- ``hcl`` — DESIRED state. Configuration may never have been applied (or may
  have been applied to a different workspace), so it is the weakest real
  evidence there is.
- ``tfplan-prior`` — a REFRESHED read of reality, but only of the resources that
  plan happened to touch. Fresher than configuration, narrower than state.
- ``tfstate`` — the last applied truth for what terraform manages. Authoritative
  for its own resources and silent about everything else.
- ``unattributed`` — a legacy bare snapshot with no declared source. It sits
  just under ``api`` so today's behaviour is preserved exactly, WITHOUT letting
  an undeclared file outrank a capture that did declare itself.
- ``api`` — a live provider read.
- ``explicit-baseline`` — highest, because a human typed the path.

**The scope lattice** (:data:`SCOPES`, weakest first) says what may be concluded
from an absence. ``undeclared`` is the interesting one: it means COVERED but not
licensed to conclude an absence — facts resolve, drift is computed, and only the
negative inference is withheld. :func:`compose_scope` is the lattice max, which
is what makes a merge order-independent.

**The boundary demotion.** :func:`compose_scope` returns a ``(scope, boundary)``
PAIR, because a composed scope with no boundary string is one the explain
surface cannot print and the next composition cannot re-check. The composed
boundary is the shared string when every contributor that is not ``uncaptured``
carries the same one, and the empty string otherwise; whenever they are not all
identical the result is capped at ``partial``. That includes the
empty-versus-named case, which is the one that under-fires if it is left out: a
boundary-less terraform source composed with an API capture that is complete
within ``organizations/1`` would otherwise yield ``complete`` with no boundary
at all, licensing an estate-wide negative over merged content that includes
projects outside that organization. Complete-within-one-named-organization and
complete are different claims. An ``uncaptured`` contributor is ignored for the
boundary test, since it contributes no content to describe.

**The on-disk format is part of the contract**, not an implementation detail.
:meth:`SourceLedger.write` serialises with ``indent=2``, ``sort_keys=True`` and
exactly one trailing newline, mirroring ``fetch.write_snapshot`` — which is the
blessed deterministic writer for snapshots but cannot serialise a ledger, so
this is the one place that discipline has to be restated rather than reused. The
reason is the whole workflow: CI commits a reconciled estate and reviews drift
BY DIFF, and a single-line ``json.dumps`` satisfies both "a round trip is
byte-stable" and "running twice produces byte-identical output" while making
every committed sidecar undiffable. Do not collapse it to one line for
compactness.

**Where the soundness registries live.** :data:`ESTATE_SOUNDNESS` and
:data:`COLLECTION_CATEGORIES` live HERE rather than in ``engine.py`` because
each has more than one consumer, and a declaration with two copies is a
declaration that will disagree. ``ESTATE_SOUNDNESS``' consumers are
``registry.run_document_checks`` and ``sec_rules.CompiledRule.evaluate``:
neither imports the engine, and ``preflight.py`` — which calls both — is never
edited. ``BASELINE_SOUNDNESS`` deliberately stays in ``engine.py``, because
Stage 3 is its only consumer; the asymmetry is a decision, not an oversight.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any, Iterable, Mapping, Sequence

from .core.log import get_logger
from .core.report import Verdict
from .facts import PROPOSED_SOURCES
from .knowledge import GcpSnapshot

logger = get_logger(__name__)

__all__ = [
    "SCHEMA",
    "SOURCES",
    "TERRAFORM_SOURCES",
    "SCOPES",
    "TAINTS",
    "SEVERITIES",
    "CATEGORIES",
    "DELIBERATELY_UNMAPPED",
    "fidelity_rank",
    "scope_rank",
    "taint_rank",
    "compose_scope",
    "compose_taint",
    "SourceRecord",
    "CategoryScope",
    "FactOrigin",
    "Dispute",
    "ArtifactRef",
    "Alternate",
    "Census",
    "SourceLedger",
    "LedgerBuilder",
    "UNCAPTURED",
    "origins_path",
    "require_complete",
    "scope_verdict",
    "summarize",
    "SOUNDNESS_MODES",
    "DEFAULT_SOUNDNESS",
    "ESTATE_SOUNDNESS",
    "COLLECTION_CATEGORIES",
    "VERDICT_KIND_CATEGORIES",
    "register_estate_soundness",
    "estate_soundness",
    "estate_soundness_category",
]

#: The one sidecar schema id. Bumped only by a format change that an existing
#: reader could misread; :meth:`SourceLedger.from_dict` names both the expected
#: and the found string, so a mismatch is a diagnosis rather than a traceback.
SCHEMA = "gcp-source-ledger/1"

#: THE ONE FIDELITY ORDER, weakest first. See the module docstring for the
#: rationale behind each position.
SOURCES = ("fixture", "hcl", "tfplan-prior", "tfstate", "unattributed", "api",
           "explicit-baseline")

#: The source spellings a terraform artifact produces. A terraform capture
#: speaks only for the resources terraform manages, so a scope claimed by one is
#: capped at ``partial`` — see :class:`SourceRecord` and :class:`CategoryScope`.
TERRAFORM_SOURCES = ("hcl", "tfplan-prior", "tfstate")

#: THE ONE SCOPE LATTICE, weakest first. ``undeclared`` = covered, but not
#: licensed to conclude an absence.
SCOPES = ("uncaptured", "undeclared", "partial", "complete")

#: Taints, ordered so a later one wins a composition. ``""`` is untainted.
TAINTS = ("", "disputed", "stale", "unmergeable")

#: :class:`Dispute` severities.
SEVERITIES = ("benign", "material", "unmanaged", "unmergeable")

#: The estate categories a ledger can speak about — derived from the snapshot
#: model itself rather than restated, so a new category cannot be forgotten here.
CATEGORIES = tuple(f.name for f in dataclasses.fields(GcpSnapshot)
                   if f.name != "captured_at")

#: Terraform resource types no mapper builds a fact from ON PURPOSE, with the
#: reason. The census separates these from genuinely unrecognized types, because
#: "we chose not to" and "we have never seen this" are different findings: the
#: first is noise in a coverage report, the second is a gap in the mappers.
DELIBERATELY_UNMAPPED = {
    "google_project_service": "API enablement is not an estate category; a snapshot has no 'enabled services' vocabulary",
    "google_service_account_key": "a key is a credential — a capture must never carry one, not even by reference",
    "google_storage_bucket": "buckets are not part of the policy vocabulary this gate reasons about",
    "null_resource": "provisioner scaffolding; it describes no GCP object",
    "random_id": "a value generator; it describes no GCP object",
    "local_file": "a local artifact; it describes no GCP object",
}


# -- the orders ---------------------------------------------------------------


def fidelity_rank(source: str) -> int:
    """Index of *source* in :data:`SOURCES` — higher wins a reconciliation.

    Raises on an unknown spelling, and specifically on a
    :data:`gcp_grounding.facts.PROPOSED_SOURCES` member: a proposed fact never
    participates in a winner selection (``merge.resolve`` partitions it into
    ``dropped`` first), so ranking one against reality is not a meaningful
    question and inventing an order for it would answer it wrongly.
    """
    if source in PROPOSED_SOURCES:
        raise ValueError(
            f"source {source!r} is a PROPOSED spelling ({list(PROPOSED_SOURCES)}) and "
            f"has no fidelity rank — a proposed change is never ranked against "
            f"current state; it is partitioned out before reconciliation")
    try:
        return SOURCES.index(source)
    except ValueError:
        raise ValueError(f"unknown source {source!r}; expected one of "
                         f"{list(SOURCES)}") from None


def scope_rank(scope: str) -> int:
    """Index of *scope* in :data:`SCOPES`; raises on an unknown spelling."""
    try:
        return SCOPES.index(scope)
    except ValueError:
        raise ValueError(f"unknown scope {scope!r}; expected one of "
                         f"{list(SCOPES)}") from None


def taint_rank(taint: str) -> int:
    """Index of *taint* in :data:`TAINTS`; raises on an unknown spelling."""
    try:
        return TAINTS.index(taint)
    except ValueError:
        raise ValueError(f"unknown taint {taint!r}; expected one of "
                         f"{list(TAINTS)}") from None


def _contribution(item: Any) -> tuple[str, str]:
    """Normalise a :func:`compose_scope` argument into ``(scope, boundary)``.

    A bare scope string means "no boundary declared"; a :class:`CategoryScope`
    or :class:`SourceRecord` contributes its own pair, so a merge can hand over
    the records it already has.
    """
    if isinstance(item, str):
        scope, boundary = item, ""
    elif isinstance(item, (CategoryScope, SourceRecord)):
        scope, boundary = item.scope, item.boundary
    elif isinstance(item, Sequence) and len(item) == 2:
        scope, boundary = item[0], item[1]
    else:
        raise ValueError(f"compose_scope takes scope strings or (scope, boundary) "
                         f"pairs, got {type(item).__name__}")
    scope_rank(scope)                      # raises on an unknown spelling
    if not isinstance(boundary, str):
        raise ValueError(f"boundary must be a string naming what the coverage is "
                         f"complete WITHIN, got {type(boundary).__name__}")
    return scope, boundary


def compose_scope(*contributors: Any) -> tuple[str, str]:
    """The lattice max over ``(scope, boundary)`` contributors, with the
    boundary demotion applied — returns a ``(scope, boundary)`` pair.

    Commutative in every case. Associative over the lattice itself (all
    contributors sharing one boundary), which is the property that makes a merge
    order-independent. Where boundaries DIFFER the demotion is a statement about
    the contributor set as a whole, so callers compose every contributor for a
    category in ONE call rather than folding pairwise: folding
    ``(complete,'A')`` with ``(complete,'B')`` and only then with
    ``(complete,'')`` would re-derive the cap from a result that no longer
    carries the two names that caused it.

    Composing nothing is ``("uncaptured", "")`` — the identity, and the honest
    answer for a category no source spoke for.
    """
    scopes: list[str] = []
    boundaries: set[str] = set()
    for item in contributors:
        scope, boundary = _contribution(item)
        scopes.append(scope)
        if scope != "uncaptured":
            # An uncaptured contributor describes no content, so it names no
            # boundary and cannot make the boundaries "differ".
            boundaries.add(boundary)
    if not scopes:
        return "uncaptured", ""
    best = max(scopes, key=scope_rank)
    if len(boundaries) > 1:
        # THE BOUNDARY DEMOTION. Complete-within-'organizations/1' and complete
        # are different claims, and so are two different withins.
        return min(best, "partial", key=scope_rank), ""
    boundary = next(iter(boundaries)) if boundaries else ""
    if best == "uncaptured":
        boundary = ""
    return best, boundary


def compose_taint(*taints: str) -> str:
    """The strongest taint among *taints* — a later :data:`TAINTS` member wins."""
    worst = ""
    for taint in taints:
        if taint_rank(taint) > taint_rank(worst):
            worst = taint
    return worst


# -- the sidecar records ------------------------------------------------------


def _as_tuple(value: Any) -> tuple[Any, ...]:
    return tuple(value) if isinstance(value, (list, tuple)) else value


@dataclass(frozen=True)
class SourceRecord:
    """One artifact (or API capture) that contributed to the current-state view.

    ``origin`` is where it was read from — a path for a file, an API method or
    endpoint for a live read. ``serial`` and ``lineage`` are terraform STATE
    identity and are legal only for a ``tfstate`` kind; carrying them on any
    other kind would invent a state identity for a document that has none.
    """

    source_id: str
    kind: str
    origin: str = ""
    captured_at: str = ""
    scope: str = "uncaptured"
    boundary: str = ""
    note: str = ""
    serial: int | None = None
    lineage: str = ""

    def __post_init__(self) -> None:
        if not self.source_id:
            raise ValueError("SourceRecord.source_id must name the source; an "
                             "unattributed record cannot be looked up by a fact")
        if self.kind not in SOURCES:
            raise ValueError(f"SourceRecord({self.source_id!r}).kind {self.kind!r} is "
                             f"not one of {list(SOURCES)}")
        scope_rank(self.scope)
        if self.kind != "tfstate":
            for name in ("serial", "lineage"):
                if getattr(self, name):
                    raise ValueError(
                        f"SourceRecord({self.source_id!r}).{name} is terraform STATE "
                        f"identity and is legal only for kind='tfstate', not "
                        f"{self.kind!r} — a non-state document has no state identity")
        if self.kind in TERRAFORM_SOURCES and scope_rank(self.scope) > scope_rank("partial"):
            # COERCE, never raise: a buggy reader must be able neither to lie
            # about coverage nor to crash the gate. Terraform speaks only for
            # the resources terraform manages.
            object.__setattr__(self, "scope", "partial")
            object.__setattr__(self, "note", _note(
                self.note, f"scope coerced to 'partial': a {self.kind} artifact "
                           f"covers only the resources terraform manages"))


def _note(existing: str, addition: str) -> str:
    """Append *addition* to *existing*, keeping both readable in one line."""
    if not existing:
        return addition
    if addition in existing:
        return existing
    return f"{existing}; {addition}"


@dataclass(frozen=True)
class CategoryScope:
    """What is known about one estate category's coverage.

    ``reasons`` is the sorted distinct set of ``facts.Unresolved`` reasons that
    killed records in this category, so a report can say WHY the holes are
    there. ``existence_licensed`` can only ever be narrowed by construction: a
    caller may withhold the licence, never widen it past what the scope, taint
    and drop count support.

    Two structural invariants are enforced here, both by COERCION:

    1. a terraform-sourced scope (see :data:`TERRAFORM_SOURCES`, declared
       through ``source_kinds``) is capped at ``partial``;
    2. ``dropped > 0`` caps the scope at ``partial`` too — ``estate.py`` is
       deliberately source-agnostic, and a complete API source with contributing
       terraform facts joins to ``complete``, so a category could otherwise be
       declared complete while demonstrably missing rows.

    Plus the emitted invariant: ``emitted is False`` implies ``keys == 0`` and
    scope ``uncaptured``, coerced toward ignorance because a mapper that never
    ran cannot have produced keys.
    """

    scope: str = "uncaptured"
    boundary: str = ""
    taint: str = ""
    keys: int = 0
    dropped: int = 0
    reasons: tuple[str, ...] = ()
    existence_licensed: bool = True
    note: str = ""
    source_kinds: tuple[str, ...] = ()
    emitted: bool = True

    def __post_init__(self) -> None:
        scope_rank(self.scope)
        taint_rank(self.taint)
        for name in ("keys", "dropped"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"CategoryScope.{name} must be a non-negative int, "
                                 f"got {value!r}")
        object.__setattr__(self, "reasons",
                           tuple(sorted({str(r) for r in self.reasons})))
        kinds = tuple(sorted({str(k) for k in self.source_kinds}))
        for kind in kinds:
            if kind not in SOURCES:
                raise ValueError(f"CategoryScope.source_kinds {kind!r} is not one of "
                                 f"{list(SOURCES)}")
        object.__setattr__(self, "source_kinds", kinds)
        object.__setattr__(self, "emitted", bool(self.emitted))

        if any(kind in TERRAFORM_SOURCES for kind in kinds) and \
                scope_rank(self.scope) > scope_rank("partial"):
            object.__setattr__(self, "scope", "partial")
            object.__setattr__(self, "note", _note(
                self.note, "scope coerced to 'partial': a terraform artifact covers "
                           "only the resources terraform manages"))
        if self.dropped > 0 and scope_rank(self.scope) > scope_rank("partial"):
            object.__setattr__(self, "scope", "partial")
            object.__setattr__(self, "note", _note(
                self.note, f"scope coerced to 'partial': {self.dropped} record(s) were "
                           f"dropped, so the category has known holes"))
        if not self.emitted and (self.keys or self.scope != "uncaptured"):
            object.__setattr__(self, "note", _note(
                self.note, "coerced to uncaptured: nothing was emitted for this "
                           "category, so it can license nothing"))
            object.__setattr__(self, "scope", "uncaptured")
            object.__setattr__(self, "keys", 0)
        object.__setattr__(self, "existence_licensed",
                           bool(self.existence_licensed) and self.can_license())

    def can_license(self) -> bool:
        """Whether absence in this category may be read as non-existence."""
        return self.scope == "complete" and not self.taint and self.dropped == 0


#: The answer :meth:`SourceLedger.scope_of` gives for a category no source
#: declared. Nothing was captured, so nothing may be concluded.
UNCAPTURED = CategoryScope(scope="uncaptured", emitted=False)


@dataclass(frozen=True)
class FactOrigin:
    """Where one ``(category, key)`` fact came from.

    ``locator`` holds the terraform resource ADDRESS for a terraform-derived
    fact and the API method or path otherwise. That field is what makes
    :meth:`SourceLedger.by_locator` the primary lookup, and is why no second
    address index exists anywhere in this design.
    """

    source_id: str
    locator: str = ""
    taint: str = ""

    def __post_init__(self) -> None:
        if not self.source_id:
            raise ValueError("FactOrigin.source_id must name the source the fact won "
                             "from; an unattributed origin cannot be explained")
        taint_rank(self.taint)


@dataclass(frozen=True)
class Dispute:
    """Two sources disagreeing about one field of one key."""

    category: str
    key: str
    field: str = ""
    severity: str = "material"
    left: str = ""
    right: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"Dispute.severity {self.severity!r} is not one of "
                             f"{list(SEVERITIES)}")


@dataclass(frozen=True)
class ArtifactRef:
    """One file a capture read, identified well enough to detect a re-read."""

    path: str
    kind: str = ""
    source: str = ""
    sha256: str = ""
    mtime: float = 0.0
    size: int = 0

    def __post_init__(self) -> None:
        if self.source and self.source not in SOURCES:
            raise ValueError(f"ArtifactRef.source {self.source!r} is not one of "
                             f"{list(SOURCES)}")

    @classmethod
    def of(cls, path: str | os.PathLike[str], *, kind: str = "",
           source: str = "") -> "ArtifactRef":
        """Build a reference by reading *path* — the one definition of how an
        artifact is fingerprinted, so two writers cannot hash it differently."""
        fspath = os.fspath(path)
        with open(fspath, "rb") as fh:
            payload = fh.read()
        stat = os.stat(fspath)
        return cls(path=fspath, kind=kind, source=source,
                   sha256=hashlib.sha256(payload).hexdigest(),
                   mtime=float(stat.st_mtime), size=len(payload))


@dataclass(frozen=True)
class Alternate:
    """A LOSING source's whole record for one key.

    Kept whole rather than field-by-field because ``engine.py`` re-runs a pair
    check against the loser's DOCUMENT, and a field-level :class:`Dispute`
    cannot supply a document.
    """

    source_id: str
    locator: str = ""
    record: Mapping[str, Any] | None = None
    reason: str = ""


@dataclass(frozen=True)
class Census:
    """Terraform resource types seen with no mapper.

    ``unrecognized`` is a gap in the mappers; ``unmapped`` is
    :data:`DELIBERATELY_UNMAPPED` and is expected noise. Separating them is the
    difference between "we have never seen this" and "we chose not to".
    """

    unrecognized: Mapping[str, int] = field(default_factory=dict)
    unmapped: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("unrecognized", "unmapped"):
            value = getattr(self, name)
            if not isinstance(value, Mapping):
                raise ValueError(f"Census.{name} must be a mapping of terraform type "
                                 f"→ count, got {type(value).__name__}")
            object.__setattr__(self, name, {str(k): int(v) for k, v in value.items()})

    def total(self) -> int:
        return sum(self.unrecognized.values()) + sum(self.unmapped.values())


# -- strict (de)serialization helpers -----------------------------------------


def _field_names(cls: type) -> tuple[str, ...]:
    return tuple(f.name for f in dataclasses.fields(cls))


def _strict(data: Any, cls: type, where: str) -> dict[str, Any]:
    """Reject anything that is not an object of exactly *cls*' fields.

    Strict at EVERY nesting level on purpose: a typo'd key in a sidecar would
    otherwise silently drop the provenance of a whole category, and a category
    with no provenance is one every absence-reasoning rule reads as complete.
    """
    if not isinstance(data, Mapping):
        raise ValueError(f"{where} must be an object, got {type(data).__name__}")
    allowed = _field_names(cls)
    unknown = sorted(str(k) for k in data if k not in allowed)
    if unknown:
        raise ValueError(f"unrecognized key(s) {unknown} in {where} - a typo would "
                         f"silently drop provenance; expected only {list(allowed)}")
    return {str(k): v for k, v in data.items()}


def _jsonify(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _jsonify(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonify(v) for v in value]
    if dataclasses.is_dataclass(value):
        return {name: _jsonify(getattr(value, name)) for name in _field_names(type(value))}
    return value


def _record_to_dict(record: Any) -> dict[str, Any]:
    return {name: _jsonify(getattr(record, name)) for name in _field_names(type(record))}


def _record_from_dict(cls: type, data: Any, where: str) -> Any:
    try:
        return cls(**_strict(data, cls, where))
    except TypeError as exc:                     # wrong value type for a field
        raise ValueError(f"{where}: {exc}") from exc


# -- the ledger ---------------------------------------------------------------


@dataclass(frozen=True)
class SourceLedger:
    """THE ONE SIDECAR: every source, every category's coverage, every fact's
    origin, and everything that disagreed.

    The read API below is TOTAL and never raises: every method answers for an
    absent category, key or locator, because a provenance lookup that raises
    inside a check turns a coverage question into a crashed gate.
    """

    schema: str = SCHEMA
    sources: Mapping[str, SourceRecord] = field(default_factory=dict)
    categories: Mapping[str, CategoryScope] = field(default_factory=dict)
    facts: Mapping[str, Mapping[str, FactOrigin]] = field(default_factory=dict)
    disputes: tuple[Dispute, ...] = ()
    artifacts: tuple[ArtifactRef, ...] = ()
    census: Census = field(default_factory=Census)
    alternates: Mapping[str, Mapping[str, tuple[Alternate, ...]]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise ValueError(f"source ledger schema mismatch: expected {SCHEMA!r}, "
                             f"found {self.schema!r}")
        object.__setattr__(self, "sources", dict(self.sources))
        object.__setattr__(self, "categories", dict(self.categories))
        object.__setattr__(self, "facts",
                           {category: dict(keys) for category, keys in self.facts.items()})
        object.__setattr__(self, "disputes", _as_tuple(self.disputes))
        object.__setattr__(self, "artifacts", _as_tuple(self.artifacts))
        object.__setattr__(self, "alternates",
                           {category: {key: _as_tuple(values) for key, values in keys.items()}
                            for category, keys in self.alternates.items()})
        for source_id, record in self.sources.items():
            if not isinstance(record, SourceRecord):
                raise ValueError(f"sources[{source_id!r}] must be a SourceRecord, got "
                                 f"{type(record).__name__}")
        for category, scope in self.categories.items():
            if not isinstance(scope, CategoryScope):
                raise ValueError(f"categories[{category!r}] must be a CategoryScope, "
                                 f"got {type(scope).__name__}")

    # -- construction ---------------------------------------------------------

    @classmethod
    def unattributed(cls, snapshot: GcpSnapshot, *, scope: str = "complete",
                     source_id: str = "unattributed", origin: str = "",
                     boundary: str = "") -> "SourceLedger":
        """A ledger for a snapshot that declared no sources — THE SCOPE IS A
        PARAMETER.

        The ``complete`` default is reserved for the legacy bare-API path, where
        it reproduces today's behaviour exactly, and is never reachable from a
        terraform capture: every terraform path passes its own scope and every
        terraform source kind is capped at ``partial`` anyway.
        """
        scope_rank(scope)
        record = SourceRecord(source_id=source_id, kind="unattributed", origin=origin,
                              captured_at=snapshot.captured_at, scope=scope,
                              boundary=boundary)
        categories: dict[str, CategoryScope] = {}
        for category in snapshot.captured_categories():
            value = getattr(snapshot, category)
            categories[category] = CategoryScope(
                scope=scope, boundary=boundary, keys=len(value),
                source_kinds=("unattributed",),
                note="declared by an unattributed snapshot (no source ledger)")
        return cls(sources={record.source_id: record}, categories=categories)

    # -- the total read API ---------------------------------------------------

    def scope_of(self, category: str) -> CategoryScope:
        """This category's coverage record, or :data:`UNCAPTURED` if no source
        declared it. Never raises."""
        found = self.categories.get(category)
        return found if found is not None else UNCAPTURED

    def origin_of(self, category: str, key: str) -> FactOrigin | None:
        """Where the winning fact for ``(category, key)`` came from, or ``None``."""
        return self.facts.get(category, {}).get(key)

    @cached_property
    def _locator_index(self) -> dict[str, set[tuple[str, str]]]:
        index: dict[str, set[tuple[str, str]]] = {}
        for category, keys in self.facts.items():
            for key, origin in keys.items():
                if origin.locator:
                    index.setdefault(origin.locator, set()).add((category, key))
        return index

    def by_locator(self, locator: str, *,
                   category: str | None = None) -> set[tuple[str, str]]:
        """Every ``(category, key)`` fact *locator* produced — A SET, never one hit.

        ONE ADDRESS IS MANY FACTS. ``map_network`` emits SIDE facts from a single
        address — one ``network_tags`` fact per tag, one ``service_accounts``
        fact per member — plus FRAGMENT facts, and ``map_policy`` emits IAM
        fragments the same way; two state files or two workspaces carrying the
        same address multiply it again. A single-valued lookup would hand back a
        counterpart from the WRONG CATEGORY — a ``network_tags`` fact as the
        baseline for a firewall target — and the secondary key check would not
        catch it, because the primary hit looks successful. That is exactly the
        wrong-counterpart failure the ambiguity guard exists to prevent,
        arriving through the guard's blind spot.

        With *category* given, hits in other categories are IGNORED, and more
        than one hit WITHIN that category is the caller's ``baseline:ambiguous``
        case (``baseline.derive`` always passes the target's domain). With
        *category* omitted the whole hit set comes back, for the explain surface.
        """
        hits = set(self._locator_index.get(locator, ()))
        if category is not None:
            hits = {hit for hit in hits if hit[0] == category}
        return hits

    def taint_of(self, category: str, key: str) -> str:
        """The fact's taint if it has one, else the category's. Never raises."""
        origin = self.origin_of(category, key)
        if origin is not None and origin.taint:
            return origin.taint
        return self.scope_of(category).taint

    def tainted_categories(self) -> tuple[str, ...]:
        """Every category whose COVERAGE is tainted, sorted. A per-key taint is
        read through :meth:`taint_of`; one disputed key does not taint the
        enumeration it sits in."""
        return tuple(sorted(name for name, scope in self.categories.items() if scope.taint))

    def merged_captured_at(self) -> str:
        """The MINIMUM ``captured_at`` over the contributing sources, or ``""``.

        ``PolicyReport`` stamps every line with one timestamp, so a merge must
        present its OLDEST constituent: claiming the newest would date a stale
        fact by the freshness of an unrelated one.
        """
        stamps = sorted(r.captured_at for r in self.sources.values() if r.captured_at)
        return stamps[0] if stamps else ""

    def alternates_for(self, category: str, key: str) -> tuple[Alternate, ...]:
        """The losing sources' whole records for ``(category, key)``."""
        return tuple(self.alternates.get(category, {}).get(key, ()))

    def declared_categories(self) -> tuple[str, ...]:
        """Every category some source declared, in snapshot order then extras."""
        known = [c for c in CATEGORIES if c in self.categories]
        extra = sorted(c for c in self.categories if c not in CATEGORIES)
        return tuple(known + extra)

    # -- persistence ----------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """The sidecar document. Inverse of :meth:`from_dict`."""
        return {
            "schema": self.schema,
            "sources": {sid: _record_to_dict(r) for sid, r in self.sources.items()},
            "categories": {c: _record_to_dict(s) for c, s in self.categories.items()},
            "facts": {c: {k: _record_to_dict(o) for k, o in keys.items()}
                      for c, keys in self.facts.items()},
            "disputes": [_record_to_dict(d) for d in self.disputes],
            "artifacts": [_record_to_dict(a) for a in self.artifacts],
            "census": _record_to_dict(self.census),
            "alternates": {c: {k: [_record_to_dict(a) for a in values]
                               for k, values in keys.items()}
                           for c, keys in self.alternates.items()},
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SourceLedger":
        """Parse a sidecar document, rejecting an unrecognised key at EVERY
        nesting level and naming both schema strings on a mismatch."""
        top = _strict(data, cls, "source ledger")
        schema = top.get("schema", SCHEMA)
        if schema != SCHEMA:
            raise ValueError(f"source ledger schema mismatch: expected {SCHEMA!r}, "
                             f"found {schema!r}")
        sources = {}
        for sid, raw in _mapping(top.get("sources"), "sources").items():
            sources[sid] = _record_from_dict(SourceRecord, raw, f"sources[{sid!r}]")
        categories = {}
        for name, raw in _mapping(top.get("categories"), "categories").items():
            categories[name] = _record_from_dict(CategoryScope, raw,
                                                 f"categories[{name!r}]")
        facts: dict[str, dict[str, FactOrigin]] = {}
        for name, keys in _mapping(top.get("facts"), "facts").items():
            facts[name] = {
                key: _record_from_dict(FactOrigin, raw, f"facts[{name!r}][{key!r}]")
                for key, raw in _mapping(keys, f"facts[{name!r}]").items()}
        disputes = tuple(_record_from_dict(Dispute, raw, f"disputes[{i}]")
                         for i, raw in enumerate(_sequence(top.get("disputes"), "disputes")))
        artifacts = tuple(_record_from_dict(ArtifactRef, raw, f"artifacts[{i}]")
                          for i, raw in enumerate(_sequence(top.get("artifacts"), "artifacts")))
        census = _record_from_dict(Census, top.get("census") or {}, "census")
        alternates: dict[str, dict[str, tuple[Alternate, ...]]] = {}
        for name, keys in _mapping(top.get("alternates"), "alternates").items():
            alternates[name] = {}
            for key, values in _mapping(keys, f"alternates[{name!r}]").items():
                where = f"alternates[{name!r}][{key!r}]"
                alternates[name][key] = tuple(
                    _record_from_dict(Alternate, raw, f"{where}[{i}]")
                    for i, raw in enumerate(_sequence(values, where)))
        return cls(schema=SCHEMA, sources=sources, categories=categories, facts=facts,
                   disputes=disputes, artifacts=artifacts, census=census,
                   alternates=alternates)

    def write(self, path: str | os.PathLike[str]) -> None:
        """Write the sidecar ATOMICALLY: a temp file in the same directory, then
        ``os.replace``, so a crashed capture never leaves a half-written ledger
        that a reader would parse as authoritative.

        The format — ``indent=2``, ``sort_keys=True``, exactly one trailing
        newline — is part of the contract; see the module docstring.
        """
        fspath = os.fspath(path)
        directory = os.path.dirname(os.path.abspath(fspath)) or "."
        handle, temp = tempfile.mkstemp(dir=directory, prefix=".origins-", suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as fh:
                json.dump(self.to_dict(), fh, indent=2, sort_keys=True)
                fh.write("\n")
            os.replace(temp, fspath)
        except BaseException:
            try:
                os.unlink(temp)
            except OSError:                       # already gone; nothing to clean
                pass
            raise
        logger.debug("wrote source ledger %s (%d source(s), %d categor(y|ies))",
                     fspath, len(self.sources), len(self.categories))

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "SourceLedger":
        """Load a sidecar, raising :class:`ValueError` NAMING the path."""
        fspath = os.fspath(path)
        try:
            with open(fspath, encoding="utf-8") as fh:
                data = json.load(fh)
        except OSError as exc:
            raise ValueError(f"source ledger {fspath}: cannot be read: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"source ledger {fspath}: not valid JSON: {exc}") from exc
        try:
            return cls.from_dict(data)
        except ValueError as exc:
            raise ValueError(f"source ledger {fspath}: {exc}") from exc


def _mapping(value: Any, where: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{where} must be an object, got {type(value).__name__}")
    return {str(k): v for k, v in value.items()}


def _sequence(value: Any, where: str) -> Sequence[Any]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{where} must be an array, got {type(value).__name__}")
    return value


def origins_path(snapshot_path: str | os.PathLike[str]) -> str:
    """The sidecar path for *snapshot_path* — THE single definition of where the
    ledger lives, called by the writer and by every reader.

    A ``.json`` spelling becomes ``.origins.json``; any other spelling has the
    suffix appended, so a snapshot named without an extension still has exactly
    one sidecar and no reader has to guess between two candidates.
    """
    fspath = os.fspath(snapshot_path)
    if fspath.endswith(".json"):
        return fspath[:-len(".json")] + ".origins.json"
    return fspath + ".origins.json"


# -- the builder --------------------------------------------------------------


class LedgerBuilder:
    """Accumulates sources, categories, facts, artifacts and disputes.

    :meth:`fact` RAISES on a category that was never declared, so a fact cannot
    acquire coverage its category never claimed — the failure mode that would
    otherwise let a mapper emit rows into a category nobody said was captured,
    and have an absence-reasoning rule read that category as complete.
    """

    def __init__(self) -> None:
        self._sources: dict[str, SourceRecord] = {}
        self._categories: dict[str, dict[str, Any]] = {}
        self._keys: dict[str, set[str]] = {}
        self._facts: dict[str, dict[str, FactOrigin]] = {}
        self._disputes: list[Dispute] = []
        self._artifacts: list[ArtifactRef] = []
        self._alternates: dict[str, dict[str, list[Alternate]]] = {}
        self._unrecognized: dict[str, int] = {}
        self._unmapped: dict[str, int] = {}

    # -- sources --------------------------------------------------------------

    def source(self, source_id: str, kind: str, **kwargs: Any) -> SourceRecord:
        """Declare a contributing source and return the stored record."""
        record = SourceRecord(source_id=source_id, kind=kind, **kwargs)
        self._sources[record.source_id] = record
        return record

    def add_source(self, record: SourceRecord) -> SourceRecord:
        self._sources[record.source_id] = record
        return record

    # -- categories -----------------------------------------------------------

    def declare(self, category: str, *, scope: str, boundary: str = "", taint: str = "",
                keys: int = 0, source_kinds: Iterable[str] = (),
                existence_licensed: bool = True, note: str = "",
                emitted: bool = True) -> None:
        """Declare (or re-declare, composing) this category's coverage.

        Re-declaring composes the two scopes through :func:`compose_scope`, so
        two sources contributing to one category cannot depend on their order.
        """
        scope_rank(scope)
        existing = self._categories.get(category)
        if existing is None:
            self._categories[category] = {
                "scope": scope, "boundary": boundary, "taint": taint, "keys": keys,
                "dropped": 0, "reasons": set(), "source_kinds": set(source_kinds),
                "existence_licensed": bool(existence_licensed), "note": note,
                "emitted": bool(emitted),
            }
            return
        composed, composed_boundary = compose_scope(
            (existing["scope"], existing["boundary"]), (scope, boundary))
        existing["scope"] = composed
        existing["boundary"] = composed_boundary
        existing["taint"] = compose_taint(existing["taint"], taint)
        existing["keys"] = max(existing["keys"], keys)
        existing["source_kinds"].update(source_kinds)
        existing["existence_licensed"] = existing["existence_licensed"] and bool(existence_licensed)
        existing["note"] = _note(existing["note"], note) if note else existing["note"]
        existing["emitted"] = existing["emitted"] or bool(emitted)

    def drop(self, category: str, *, count: int = 1, reasons: Iterable[str] = ()) -> None:
        """Record that *count* records were dropped from *category*, and why.

        The reasons are ``facts.Unresolved`` reason strings. A category with
        drops is demoted to at most ``partial`` when the record is built.
        """
        entry = self._require(category, "drop")
        entry["dropped"] += int(count)
        entry["reasons"].update(str(r) for r in reasons)

    # -- facts ----------------------------------------------------------------

    def fact(self, category: str, key: str, *, source_id: str, locator: str = "",
             taint: str = "") -> FactOrigin:
        """Record the winning origin for ``(category, key)``.

        Raises on a category that was never declared, and on a source that was
        never added: both are provenance a later reader could not reconstruct.
        """
        self._require(category, "fact")
        if source_id not in self._sources:
            raise ValueError(f"fact({category!r}, {key!r}) names source {source_id!r}, "
                             f"which was never added; known sources: "
                             f"{sorted(self._sources)}")
        origin = FactOrigin(source_id=source_id, locator=locator, taint=taint)
        self._facts.setdefault(category, {})[key] = origin
        self._keys.setdefault(category, set()).add(key)
        return origin

    def alternate(self, category: str, key: str, *, source_id: str, locator: str = "",
                  record: Mapping[str, Any] | None = None, reason: str = "") -> None:
        """Keep a LOSING source's whole record for ``(category, key)``."""
        self._require(category, "alternate")
        self._alternates.setdefault(category, {}).setdefault(key, []).append(
            Alternate(source_id=source_id, locator=locator, record=record, reason=reason))

    # -- everything else ------------------------------------------------------

    def dispute(self, dispute: Dispute) -> None:
        self._disputes.append(dispute)

    def artifact(self, artifact: ArtifactRef) -> None:
        self._artifacts.append(artifact)

    def saw_unmapped(self, resource_type: str, count: int = 1) -> None:
        """Count one terraform resource type that produced no fact, into the
        deliberate or the unrecognized half of the census."""
        bucket = self._unmapped if resource_type in DELIBERATELY_UNMAPPED else self._unrecognized
        bucket[resource_type] = bucket.get(resource_type, 0) + int(count)

    def _require(self, category: str, method: str) -> dict[str, Any]:
        entry = self._categories.get(category)
        if entry is None:
            raise ValueError(
                f"{method}({category!r}) on a category that was never declared — a "
                f"fact cannot acquire coverage its category never claimed; call "
                f"declare({category!r}, scope=...) first")
        return entry

    def build(self) -> SourceLedger:
        categories = {}
        for name, entry in self._categories.items():
            categories[name] = CategoryScope(
                scope=entry["scope"], boundary=entry["boundary"], taint=entry["taint"],
                keys=max(entry["keys"], len(self._keys.get(name, ()))),
                dropped=entry["dropped"], reasons=tuple(sorted(entry["reasons"])),
                existence_licensed=entry["existence_licensed"], note=entry["note"],
                source_kinds=tuple(sorted(entry["source_kinds"])),
                emitted=entry["emitted"])
        return SourceLedger(
            sources=dict(self._sources), categories=categories,
            facts={c: dict(keys) for c, keys in self._facts.items()},
            disputes=tuple(self._disputes), artifacts=tuple(self._artifacts),
            census=Census(unrecognized=dict(self._unrecognized),
                          unmapped=dict(self._unmapped)),
            alternates={c: {k: tuple(v) for k, v in keys.items()}
                        for c, keys in self._alternates.items()})


# -- the absence predicate ----------------------------------------------------


def _who(rule: str | None) -> str:
    return f"rule '{rule}'" if rule else "this check"


def require_complete(source: Any, category: str, *, rule: str | None = None) -> str | None:
    """``None`` if absence in *category* may be read as non-existence, else the
    exact reason it may not — THE single predicate every absence-reasoning rule
    calls.

    *source* is a :class:`SourceLedger`, a plain
    :class:`~gcp_grounding.knowledge.GcpSnapshot` (where a non-``None`` category
    reads as complete, reproducing today's semantics exactly so adoption is
    incremental), or ``None``.

    Four refusals, in order of specificity: an uncaptured category, a category
    with KNOWN HOLES (naming the drop count and the killing reasons), a tainted
    category, and a partial or undeclared scope (naming the origin). The
    known-holes arm is not optional: ``estate.drop_unresolved`` drops whole
    records, and the mapper's failures, its skipped multiplicity rows and its
    per-mapper crash isolation each remove records too, so a category can
    otherwise be declared complete while demonstrably missing rows.

    Every reason is ASCII and hyphenated — it is embedded in verdict messages
    that are compared, grepped and diffed.
    """
    who = _who(rule)
    if isinstance(source, SourceLedger):
        scope = source.scope_of(category)
    elif isinstance(source, GcpSnapshot):
        captured = category in CATEGORIES and getattr(source, category, None) is not None
        scope = CategoryScope(scope="complete", source_kinds=("unattributed",)) \
            if captured else UNCAPTURED
    elif source is None:
        scope = UNCAPTURED
    else:
        raise TypeError(f"require_complete needs a SourceLedger, a GcpSnapshot or "
                        f"None, got {type(source).__name__}")

    if scope.scope == "uncaptured":
        return (f"{who} reasons from absence, but category '{category}' was not "
                f"captured - an uncaptured category cannot be read as an empty one")
    if scope.dropped > 0:
        reasons = ", ".join(scope.reasons) or "no reason recorded"
        return (f"{who} reasons from absence, but category '{category}' dropped "
                f"{scope.dropped} record(s) ({reasons}) - a category with known holes "
                f"cannot license a negative")
    if scope.taint:
        return (f"{who} reasons from absence, but category '{category}' is tainted "
                f"'{scope.taint}' - a {scope.taint} category cannot license a negative")
    if scope.scope != "complete":
        origin = ", ".join(scope.source_kinds) or "an undeclared source"
        within = f" within '{scope.boundary}'" if scope.boundary else " with no declared boundary"
        return (f"{who} reasons from absence, but category '{category}' has "
                f"{scope.scope} coverage from {origin}{within} - absence within a "
                f"{scope.scope} capture is not absence")
    if not scope.existence_licensed:
        return (f"{who} reasons from absence, but category '{category}' withheld its "
                f"existence licence - the capture declined to license a negative")
    return None


def scope_verdict(source: Any, category: str, *, rule: str | None = None,
                  target: str = "", lineno: int = 0) -> Verdict | None:
    """:func:`require_complete` as an ``unverified`` verdict of kind ``scope``,
    or ``None`` when absence may be reasoned from.

    No new STATUS is introduced — ``unverified`` already means "not decided" —
    and the kind is what lets a report group every coverage refusal together.
    """
    reason = require_complete(source, category, rule=rule)
    if reason is None:
        return None
    return Verdict("unverified", "scope", target or category, lineno, reason)


#: Reasoner existence-verdict kind → snapshot category. ``ground_existence``
#: emits ``Verdict(kind=<category>)`` in the SINGULAR ("role", "resource_type"),
#: and the snapshot names its categories in the plural; this mapping is what
#: makes ``drift.postpass`` — which must re-examine every existence verdict
#: against the category it was decided from — possible at all.
#:
#: EVERY kind in :data:`gcp_grounding.reasoner.EXISTENCE_KINDS` must appear —
#: the five original vocabularies and the ten estate kinds the reasoner grew —
#: because an existence verdict whose kind is missing here is one
#: ``drift.postpass`` cannot re-examine, i.e. one that would keep a clean
#: ``grounded`` over a disputed or stale fact. ``perimeter`` /
#: ``firewall_policy`` / ``security_policy`` / ``hierarchy_node`` are the record
#: tables' singulars, each mapping to the table it was decided from.
VERDICT_KIND_CATEGORIES = {
    "role": "roles",
    "permission": "permissions",
    "principal": "principals",
    "constraint": "constraints",
    "resource_type": "resource_types",
    "network": "networks",
    "subnetwork": "subnetworks",
    "network_tag": "network_tags",
    "service_account": "service_accounts",
    "access_level": "access_levels",
    "restricted_service": "restricted_services",
    "perimeter": "vpc_sc_perimeters",
    "firewall_policy": "hierarchical_firewall_policies",
    "security_policy": "cloud_armor_policies",
    "hierarchy_node": "resource_hierarchy",
}


# -- the two soundness registries ---------------------------------------------

#: How a check behaves when the estate it reads is not complete.
#: ``requires_complete`` — its conclusion needs the whole category (it reasons
#: from absence). ``subset_safe`` — it looks for a WITNESS, so a subset can only
#: make it quieter, never wrong.
SOUNDNESS_MODES = ("requires_complete", "subset_safe")

#: The conservative default for a check nobody has classified.
DEFAULT_SOUNDNESS = "requires_complete"

#: Check identity → soundness mode. The identity is the provider's
#: ``module.function`` string for a registry DOCUMENT_CHECK (exactly what
#: ``registry._label`` builds) and the rule id for a compiled promise. Empty by
#: construction: ``subset_safe`` is a claim a check makes ABOUT ITSELF, so a
#: domain module registers its own entries at import time and everything else
#: defaults to :data:`DEFAULT_SOUNDNESS`.
ESTATE_SOUNDNESS: dict[str, str] = {}

#: Identity → the category whose completeness that check depends on, when it
#: named one. Written only through :func:`register_estate_soundness`, so it
#: cannot drift out of step with :data:`ESTATE_SOUNDNESS`.
_ESTATE_SOUNDNESS_CATEGORY: dict[str, str] = {}


def register_estate_soundness(identity: str, mode: str,
                              category: str | None = None) -> None:
    """Declare how *identity* behaves against an incomplete estate."""
    if not identity:
        raise ValueError("register_estate_soundness needs a check identity "
                         "('<module>.<function>' or a rule id)")
    if mode not in SOUNDNESS_MODES:
        raise ValueError(f"soundness mode {mode!r} is not one of {list(SOUNDNESS_MODES)}")
    ESTATE_SOUNDNESS[identity] = mode
    if category is None:
        _ESTATE_SOUNDNESS_CATEGORY.pop(identity, None)
    else:
        _ESTATE_SOUNDNESS_CATEGORY[identity] = category


def estate_soundness(identity: str) -> str:
    """*identity*'s mode, defaulting to the conservative
    :data:`DEFAULT_SOUNDNESS`. Never raises."""
    return ESTATE_SOUNDNESS.get(identity, DEFAULT_SOUNDNESS)


def estate_soundness_category(identity: str) -> str | None:
    """The category *identity* declared it needs complete, or ``None``."""
    return _ESTATE_SOUNDNESS_CATEGORY.get(identity)


#: ESTATE collection name → snapshot category, so a compiled promise can resolve
#: the category whose completeness it must check without restating the mapping.
#: ``firewall_rules`` and ``hier_firewall_rules`` are the estate-tier
#: collections ``sec_domains`` registers today; the rest are listed because
#: their records describe the same estate category whichever tier supplies them,
#: and a promise that reaches the estate must not fall off the map.
COLLECTION_CATEGORIES = {
    "firewall_rules": "firewall_rules",
    "hier_firewall_rules": "hierarchical_firewall_policies",
    "armor_rules": "cloud_armor_policies",
    "perimeter_resources": "vpc_sc_perimeters",
    "perimeter_restricted_services": "vpc_sc_perimeters",
    "iam_bindings": "iam_bindings",
    "org_policy_rules": "org_policies",
}


# -- the human coverage table -------------------------------------------------


def summarize(ledger: SourceLedger) -> str:
    """The human coverage table: one line per declared category, then the
    artifacts, then the unrecognized-type census.

    A FUNCTION and not a second module: this is what ``capture-terraform``
    prints and what the explain surface embeds, and two renderings of one
    ledger would be two chances to describe the same coverage differently.
    """
    lines = [f"source coverage ({ledger.schema})"]
    stamp = ledger.merged_captured_at()
    for source_id in sorted(ledger.sources):
        record = ledger.sources[source_id]
        within = f" within {record.boundary}" if record.boundary else ""
        lines.append(f"  source {source_id} [{record.kind}] {record.origin or '-'}"
                     f" scope={record.scope}{within}"
                     f" captured_at={record.captured_at or '-'}")
    lines.append(f"  merged captured_at: {stamp or '-'}")
    lines.append("  category                              scope       keys  dropped  reasons")
    for category in ledger.declared_categories():
        scope = ledger.scope_of(category)
        reasons = ",".join(scope.reasons) if scope.reasons else "-"
        taint = f" taint={scope.taint}" if scope.taint else ""
        lines.append(f"  {category:<36}  {scope.scope:<10}  {scope.keys:>4}  "
                     f"{scope.dropped:>7}  {reasons}{taint}")
    if not ledger.categories:
        lines.append("  (no category was declared - nothing may be concluded from absence)")
    lines.append(f"  artifacts: {len(ledger.artifacts)}")
    for artifact in ledger.artifacts:
        lines.append(f"    {artifact.path} [{artifact.kind or '-'}] "
                     f"{artifact.size} bytes sha256={artifact.sha256[:12] or '-'}")
    census = ledger.census
    lines.append(f"  unrecognized terraform types: {len(census.unrecognized)}")
    for name in sorted(census.unrecognized):
        lines.append(f"    {name} x{census.unrecognized[name]}")
    lines.append(f"  deliberately unmapped types: {len(census.unmapped)}")
    for name in sorted(census.unmapped):
        lines.append(f"    {name} x{census.unmapped[name]}")
    if ledger.disputes:
        lines.append(f"  disputes: {len(ledger.disputes)}")
        for dispute in ledger.disputes:
            lines.append(f"    [{dispute.severity}] {dispute.category}/{dispute.key}"
                         f".{dispute.field or '-'}: {dispute.reason or '-'}")
    return "\n".join(lines)
