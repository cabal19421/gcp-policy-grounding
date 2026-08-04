"""Resolutions in, a :class:`~gcp_grounding.knowledge.GcpSnapshot` plus a
:class:`~gcp_grounding.provenance.SourceLedger` out.

A FLAT top-level module and deliberately NOT a member of ``tfsource``: turning
resolutions into a snapshot plus a ledger is source-agnostic and must work for
an API-derived fact set as readily as a terraform one, and it imports
:mod:`gcp_grounding.knowledge`, which ``tfsource`` must not. The terraform
readers are reached LAZILY, inside :func:`capture` — the one boundary at which a
flat module needs a reader at call time.

THE EMIT POLICY, AND WHY IT IS THIS LIST
----------------------------------------
:data:`DEFAULT_EMIT` is ``firewall_rules``, ``iam_bindings``, ``org_policies``
and ``network_tags``. The reasoner's enumeration helper never reads the first
three, so a partial table there cannot produce an ``ungrounded``; and
``network_tags`` is presence-only at the Datalog layer — a tag is created
implicitly by the rule naming it, so ``knowledge.network_tag_exists`` answers
``True`` or UNKNOWN and never ``False``. For all four, a missing key makes a
check MISS a finding rather than BLOCK a valid change, which is the only
direction a partial view may err in.

:data:`EXISTENCE_LICENSING` is every OTHER :data:`gcp_grounding.facts.TF_CATEGORIES`
member. Those are OPT-IN ONLY, and opting one in sets ``existence_licensed`` on
its :class:`~gcp_grounding.provenance.CategoryScope`. The consequence is the
whole reason it is opt-in: populating one lets the reasoner answer ``False`` for
a name that is simply absent from terraform, which over a terraform-only view is
a MANUFACTURED false positive — the same failure ``fetch.py`` refuses when it
declines to fold CAI asset types into ``resource_types``.

The licence is therefore WITHHELD from the :data:`DEFAULT_EMIT` four, and that
is a consequence of their own justification rather than an extra rule: they are
emitted unconditionally BECAUSE a missing key in one of them can only make a
check miss a finding. Licensing an absence there is exactly the property that
would let a partial table BLOCK a valid change instead, which is the one
direction the emit policy rules out. ``CategoryScope`` narrows the flag further
on its own — nothing that is not ``complete``, untainted and undamaged can
license anything — so over a terraform capture the flag is ``False`` either way;
the difference is visible only where a caller DECLARED a complete source.

NEVER EMIT AN EMPTY CATEGORY. A category in the emit set with zero surviving
resolutions is OMITTED from the snapshot dict, so every lookup against it
answers :data:`~gcp_grounding.knowledge.UNKNOWN`; its ``CategoryScope`` is
``uncaptured`` with ``keys == 0`` and :data:`EMPTY_CATEGORY_NOTE`. "No
terraform-managed firewall rules" is not "no firewall rules".

EVERY EMITTED CATEGORY IS AT MOST ``partial`` for a terraform capture, and there
is NO code path in this module that writes ``complete``. Coverage is whatever
:func:`gcp_grounding.merge.resolve` composed from the sources the caller
DECLARED; this module never upgrades it.

COMPLETENESS IS NEVER INFERRED FROM CONTENT. A terraform capture writes a
snapshot byte-INDISTINGUISHABLE from an API one — the same writer, the same
schema — so concluding ``complete`` from category-is-not-``None`` would declare
a terraform capture authoritative for firewall, IAM and org policy. Completeness
is declared by a caller or read from the sidecar and is ``undeclared``
otherwise; ``undeclared`` still means the category is COVERED, with facts
resolving and drift computed, withholding only the right to conclude an absence.

THE REDACTION BOUNDARY IS ONE PASS, HERE, AND NOWHERE ELSE. Readers, mappers and
``merge`` carry :class:`gcp_grounding.redact.Redacted` OBJECTS, so digest
comparison, the ``__bool__`` guard and the walkers all work where the checks
live. But ``GcpSnapshot.from_dict`` is the strict path and
``fetch.write_snapshot`` is ``json.dumps``, and ``knowledge.py``, ``fetch.py``
and ``core/`` are all on the never-edit list, so an object cannot cross either
boundary. Immediately before ``from_dict`` every surviving record is walked once
through :func:`gcp_grounding.redact.to_wire`. Two conversion sites would be two
places for the spelling to diverge, and diverged spellings compare unequal,
which reinstates the phantom-drift failure the digest exists to prevent. From
that line on, the snapshot, the sidecar and every rendered value hold the wire
string, which ``redact.has_redacted`` still recognises, so a check reading the
snapshot still abstains.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from . import facts, fetch, merge, redact
from .core.log import get_logger
from .knowledge import GcpSnapshot
from .provenance import (
    ArtifactRef,
    LedgerBuilder,
    SourceLedger,
    SourceRecord,
    origins_path,
)

logger = get_logger(__name__)

__all__ = [
    "DEFAULT_EMIT",
    "EXISTENCE_LICENSING",
    "EMPTY_CATEGORY_NOTE",
    "MTIME_CAVEAT",
    "LICENSING_WARNING",
    "NO_TIMESTAMP",
    "READER_FAILED",
    "DroppedRecord",
    "drop_unresolved",
    "CaptureOptions",
    "Capture",
    "build",
    "capture",
    "write_capture",
]

#: The categories a capture emits without being asked. See the module docstring
#: for why it is exactly these four: a partial table in any of them makes a
#: check MISS a finding rather than BLOCK a valid change.
DEFAULT_EMIT = ("firewall_rules", "iam_bindings", "org_policies", "network_tags")

#: Every other terraform-producible category. OPT-IN ONLY, and opting in sets
#: ``existence_licensed`` on that category's scope — which is what lets the
#: reasoner answer ``False`` for a name terraform simply does not manage.
EXISTENCE_LICENSING = tuple(c for c in facts.TF_CATEGORIES if c not in DEFAULT_EMIT)

#: The note on an emit-set category that produced nothing.
EMPTY_CATEGORY_NOTE = (
    "no terraform-managed resources of this kind were found, so the category is "
    "OMITTED rather than emitted empty: 'no terraform-managed firewall rules' is "
    "not 'no firewall rules', and an emitted empty table would answer False for "
    "every name in the estate"
)

#: What a ``captured_at`` derived from an artifact really is. Carried on every
#: source record the fallback stamped, because an operator reading the ledger
#: has to know they are looking at a file's write time.
MTIME_CAVEAT = (
    "captured_at is this artifact's FILE MODIFICATION TIME and NOT an estate "
    "capture time: it says when the file was last written, not when the estate "
    "it describes was true"
)

#: The note an ``EXISTENCE_LICENSING`` opt-in earns its category.
LICENSING_WARNING = (
    "existence licensing was opted into for this category: an absence in it may "
    "now be read as non-existence, and over a terraform-only view that is a "
    "MANUFACTURED false positive, because terraform enumerates only what "
    "terraform manages"
)

#: Why a capture with neither an artifact nor an override refuses to exist.
NO_TIMESTAMP = (
    "a capture needs a defensible captured_at: no artifact was read, so there is "
    "no file modification time to fall back on, and a snapshot without a "
    "timestamp must not exist - pass captured_at explicitly"
)

#: A reader that RAISED, as a note. Parameterised so the capture can name the
#: artifact it lost without aborting the ones it still has.
READER_FAILED = (
    "{path}: the {kind} reader raised {error}; NOTHING was captured from this "
    "artifact and the capture continued with the others - a capture that "
    "partially failed must SAY SO rather than silently shrink"
)


def _mtime_stamp(mtime: float) -> str:
    """A POSIX mtime in the snapshot's ``...Z`` form.

    The same FORMAT ``fetch.fresh_captured_at`` and
    ``tfsource.state.mtime_utc`` render, spelled here so :func:`build` stays
    free of ``tfsource`` — it must work for an API-derived fact set too.
    """
    return datetime.fromtimestamp(mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- drop-unresolved ----------------------------------------------------------


@dataclass(frozen=True)
class DroppedRecord:
    """One resolution this module refused to emit, and the marker that killed it.

    ``path`` is where inside the record the marker sat (``"source_ranges"``,
    ``"rules[1].match"``) or ``"<key>"`` when the KEY itself was unresolved.
    """

    category: str
    key: str
    path: str = ""
    reason: str = ""
    detail: str = ""


def _key_text(key: Any) -> str:
    """A key as a string. An :class:`~gcp_grounding.facts.Unresolved` renders
    through its own ``repr``, which is detail-free by construction."""
    return key if isinstance(key, str) else repr(key)


def drop_unresolved(resolutions: Iterable[Any]
                    ) -> tuple[tuple[Any, ...], tuple[DroppedRecord, ...]]:
    """Partition *resolutions* into ``(kept, dropped)``.

    A resolution whose record holds ANY :class:`~gcp_grounding.facts.Unresolved`
    at ANY depth — or whose KEY is unresolved, which is how a flat vocabulary
    fails, since a flat category's name IS its content — is dropped WHOLE and
    counted together with the marker that killed it.

    **Why whole, and not field by field.** A firewall rule whose
    ``source_ranges`` failed to resolve and was written as an empty list reads
    as MATCHES-NOTHING to every packet-algebra consumer: the record would look
    complete, answer every question, and answer them wrongly. Dropping is the
    honest partial-coverage answer, and the ledger — ``CategoryScope.dropped``
    plus ``CategoryScope.reasons``, which ``provenance.require_complete``
    refuses a negative over — is what makes the hole countable rather than
    invisible.
    """
    kept: list[Any] = []
    dropped: list[DroppedRecord] = []
    for resolution in resolutions:
        found = facts.first_unresolved(resolution.key)
        where = "<key>"
        if found is None and resolution.record is not None:
            found = facts.first_unresolved(resolution.record)
            where = ""
        if found is None:
            kept.append(resolution)
            continue
        path, marker = found
        dropped.append(DroppedRecord(
            category=resolution.category, key=_key_text(resolution.key),
            path=where or path, reason=marker.reason, detail=marker.detail))
        logger.debug("dropped %s/%s whole: %s at %s", resolution.category,
                     _key_text(resolution.key), marker.reason, where or path)
    return tuple(kept), tuple(dropped)


# -- the options --------------------------------------------------------------


@dataclass(frozen=True)
class CaptureOptions:
    """What a capture emits, how it qualifies bare terraform names, and when it
    says it happened.

    ``emit`` defaults to :data:`DEFAULT_EMIT`. ``include`` may name only
    :data:`EXISTENCE_LICENSING` members: naming a ``DEFAULT_EMIT`` category
    there would be a request to LICENSE it, and those four are emitted
    precisely because they must never license an absence.

    The five qualifier fields are what a bare terraform name cannot supply — a
    ``google_compute_firewall`` names ``allow-ssh``, the estate keys
    ``projects/<p>/global/firewalls/allow-ssh``. They are carried as plain
    strings rather than as a ``tfsource`` object so this module keeps no
    import-time dependency on the readers.
    """

    emit: tuple[str, ...] = DEFAULT_EMIT
    include: tuple[str, ...] = ()
    captured_at: str = ""
    project: str = ""
    project_number: str = ""
    region: str = ""
    organization: str = ""
    folder: str = ""
    access_policy: str = ""
    precedence: merge.PrecedencePolicy | None = None
    include_backups: bool = False
    follow_symlinks: bool = False

    def __post_init__(self) -> None:
        emit = tuple(dict.fromkeys(str(c) for c in self.emit))
        for category in emit:
            if category not in facts.TF_CATEGORIES:
                detail = facts.EXCLUDED_CATEGORIES.get(category)
                raise ValueError(
                    f"CaptureOptions.emit names {category!r}, which is not one of "
                    f"{list(facts.TF_CATEGORIES)}"
                    + (f" - {detail}" if detail else ""))
        include = tuple(dict.fromkeys(str(c) for c in self.include))
        for category in include:
            if category in DEFAULT_EMIT:
                raise ValueError(
                    f"CaptureOptions.include names {category!r}, which is in "
                    f"DEFAULT_EMIT: those four are emitted BECAUSE they cannot "
                    f"license an absence, so opting one into existence licensing "
                    f"is refused rather than quietly honoured")
            if category not in EXISTENCE_LICENSING:
                raise ValueError(
                    f"CaptureOptions.include names {category!r}, which is not one "
                    f"of {list(EXISTENCE_LICENSING)}")
        if self.precedence is not None and \
                not isinstance(self.precedence, merge.PrecedencePolicy):
            raise ValueError(f"CaptureOptions.precedence must be a "
                             f"merge.PrecedencePolicy, got "
                             f"{type(self.precedence).__name__}")
        object.__setattr__(self, "emit", emit)
        object.__setattr__(self, "include", include)

    def categories(self) -> tuple[str, ...]:
        """The emit set, in :data:`gcp_grounding.facts.TF_CATEGORIES` order so
        two option objects that name the same categories declare them in the
        same order and their ledgers diff cleanly."""
        wanted = set(self.emit) | set(self.include)
        return tuple(c for c in facts.TF_CATEGORIES if c in wanted)


@dataclass(frozen=True)
class Capture:
    """One capture: the snapshot, the ledger that must travel with it, every
    note the run produced and every record it refused to emit.

    ``dropped`` is deliberately here rather than only inside the ledger's
    counts: a caller that wants to explain a hole needs the key and the marker,
    and a count cannot supply either.
    """

    snapshot: GcpSnapshot
    ledger: SourceLedger
    notes: tuple[str, ...] = ()
    dropped: tuple[DroppedRecord, ...] = ()


# -- assembly -----------------------------------------------------------------


def _dedupe(notes: Iterable[str]) -> tuple[str, ...]:
    """Order-preserving de-duplication: reader notes arrive in a meaningful
    order and sorting them would scramble the story a capture tells."""
    seen: set[str] = set()
    out: list[str] = []
    for note in notes:
        if note and note not in seen:
            seen.add(note)
            out.append(note)
    return tuple(out)


def _oldest_stamp(artifacts: Sequence[ArtifactRef]) -> str:
    """The OLDEST contributing artifact mtime, rendered.

    Worst-case freshness is the only honest default when several artifacts of
    different ages are combined: stamping the merged view with the newest one
    would date a stale fact by the freshness of an unrelated file.
    """
    stamps = [a.mtime for a in artifacts if a.mtime]
    if not stamps:
        return ""
    return _mtime_stamp(min(stamps))


def build(result: merge.MergeResult, *, options: CaptureOptions | None = None,
          sources: Iterable[SourceRecord] = (),
          artifacts: Iterable[ArtifactRef] = (),
          notes: Iterable[str] = (),
          unmapped_types: Iterable[str] = ()) -> Capture:
    """Turn one :class:`~gcp_grounding.merge.MergeResult` into a snapshot plus
    its ledger.

    SOURCE-AGNOSTIC on purpose: *result* may hold terraform facts, API facts or
    both, and nothing below inspects which. Coverage comes from the scopes
    ``merge`` composed out of the sources the caller DECLARED and is never
    inferred from how much content arrived.

    Raises :class:`ValueError` when there is no defensible ``captured_at``
    (see :data:`NO_TIMESTAMP`) and when ``GcpSnapshot.from_dict`` refuses a
    record — the STRICT path, deliberately, so a malformed record fails AT
    CAPTURE TIME naming the table and the key rather than poisoning verdicts
    later.
    """
    options = options if options is not None else CaptureOptions()
    artifacts = tuple(artifacts)
    declared = {record.source_id: record for record in sources}
    emit = options.categories()

    kept, dropped = drop_unresolved(result.resolutions)

    stamp = options.captured_at or _oldest_stamp(artifacts)
    if not stamp:
        raise ValueError(NO_TIMESTAMP)

    # -- the snapshot payload -------------------------------------------------
    flat: dict[str, list[str]] = {}
    tables: dict[str, dict[str, Any]] = {}
    surviving: dict[str, list[Any]] = {}
    for resolution in kept:
        category = resolution.category
        if category not in emit:
            continue
        surviving.setdefault(category, []).append(resolution)
        if category in facts.FLAT_CATEGORIES:
            flat.setdefault(category, []).append(resolution.key)
        else:
            # THE REDACTION BOUNDARY, in ONE pass and in ONE place.
            tables.setdefault(category, {})[resolution.key] = \
                redact.to_wire(resolution.record)

    payload: dict[str, Any] = {"captured_at": stamp}
    for category in emit:
        if category in flat and flat[category]:
            payload[category] = sorted(set(flat[category]))
        elif category in tables and tables[category]:
            payload[category] = tables[category]
        # NEVER EMIT AN EMPTY CATEGORY: an absent key answers UNKNOWN, an empty
        # one answers False for every name in the estate.

    try:
        snapshot = GcpSnapshot.from_dict(payload)
    except ValueError as exc:
        raise ValueError(
            f"capture refused at GcpSnapshot.from_dict: {exc}. The strict path "
            f"is deliberate - a malformed record must fail at capture time, "
            f"naming the table and the key, rather than poisoning verdicts "
            f"later") from exc

    # -- the ledger -----------------------------------------------------------
    builder = LedgerBuilder()
    known = set(declared)
    stamped_by_mtime = not options.captured_at and bool(artifacts)
    for source_id in sorted(declared):
        record = declared[source_id]
        if stamped_by_mtime and record.captured_at:
            record = SourceRecord(
                source_id=record.source_id, kind=record.kind, origin=record.origin,
                captured_at=record.captured_at, scope=record.scope,
                boundary=record.boundary,
                note=_join(record.note, MTIME_CAVEAT),
                serial=record.serial, lineage=record.lineage)
        builder.add_source(record)

    all_notes = list(notes)
    for category in emit:
        scope = result.scopes.get(category)
        rows = surviving.get(category, ())
        licensed = category in options.include
        if licensed:
            all_notes.append(f"{category}: {LICENSING_WARNING}")
        if not rows:
            builder.declare(
                category, scope="uncaptured", keys=0, emitted=False,
                existence_licensed=False,
                source_kinds=tuple(sorted({r.kind for r in declared.values()})),
                note=EMPTY_CATEGORY_NOTE)
        else:
            builder.declare(
                category,
                scope=scope.scope if scope is not None else "undeclared",
                boundary=scope.boundary if scope is not None else "",
                taint=scope.taint if scope is not None else "",
                keys=len(rows),
                source_kinds=scope.source_kinds if scope is not None else (),
                existence_licensed=licensed,
                note=_join(scope.note if scope is not None else "",
                           LICENSING_WARNING if licensed else ""))
        killed = [row for row in dropped if row.category == category]
        if killed:
            builder.drop(category, count=len(killed),
                         reasons={row.reason for row in killed})
        for resolution in rows:
            builder.fact(category, resolution.key,
                         source_id=_source_id(builder, known, resolution),
                         locator=resolution.origin.locator,
                         taint=resolution.taint or resolution.origin.taint)
            for alternate in result.alternates.get(category, {}).get(resolution.key, ()):
                builder.alternate(category, resolution.key,
                                  source_id=alternate.source_id,
                                  locator=alternate.locator,
                                  record=redact.to_wire(alternate.record),
                                  reason=alternate.reason)

    for dispute in result.disputes:
        builder.dispute(dispute)
    for artifact in sorted(artifacts, key=lambda a: a.path):
        builder.artifact(artifact)
    for resource_type in unmapped_types:
        builder.saw_unmapped(resource_type)

    ledger = builder.build()
    logger.debug("built capture: %d categor(y|ies) emitted, %d record(s) dropped",
                 len(snapshot.captured_categories()), len(dropped))
    return Capture(snapshot=snapshot, ledger=ledger,
                   notes=_dedupe(all_notes), dropped=dropped)


def _join(existing: str, addition: str) -> str:
    if not addition:
        return existing
    if not existing:
        return addition
    if addition in existing:
        return existing
    return f"{existing}; {addition}"


def _source_id(builder: LedgerBuilder, known: set[str], resolution: Any) -> str:
    """The winning source's id, DECLARING it as ``undeclared`` if the caller
    never did.

    Completeness is never inferred from content, so a source that contributed
    facts but was not declared is covered and unlicensed, exactly as
    ``merge.resolve`` treats the same case. ``LedgerBuilder.fact`` refuses an
    unknown source outright, so the alternative here is a crashed capture over
    provenance nobody supplied.

    The fidelity KIND is taken from the contributing fact's own spelling rather
    than flattened to ``unattributed``: the spelling is a property of the
    artifact and is known, while the COVERAGE is not, and only the second one
    may be guessed at conservatively.
    """
    source_id = resolution.origin.source_id
    if source_id and source_id not in known:
        kind = next((f.source for f in resolution.contributors
                     if (f.origin or f.source) == source_id and f.source), "")
        builder.add_source(SourceRecord(
            source_id=source_id, kind=kind or "unattributed", scope="undeclared",
            note="contributed facts but was never declared; its coverage is "
                 "'undeclared' - covered, but not licensed to conclude an "
                 "absence"))
        known.add(source_id)
    return source_id


# -- the whole pipeline -------------------------------------------------------


def capture(root_or_paths: Any, *, options: CaptureOptions | None = None) -> Capture:
    """Discover, read, map, resolve and :func:`build`, in that order.

    *root_or_paths* is one path or an iterable of them; each is walked by
    :func:`gcp_grounding.tfsource.discover.discover`, which classifies BY
    CONTENT. Every artifact is dispatched to the reader that owns its kind.

    A READER-LEVEL FAILURE BECOMES A NOTE AND NEVER ABORTS. The readers already
    return a refusal rather than raising; this catches the case where one
    raises anyway, because a capture that partially failed must SAY SO rather
    than silently shrink into a smaller estate that looks clean.

    ``tfsource`` is imported HERE rather than at module scope: this is the one
    boundary at which a flat module needs a reader at call time, and keeping
    the import lazy is what lets :func:`build` serve an API-derived fact set
    with no terraform in the picture at all.
    """
    from .tfsource import discover, hcl, mapping, plan, state

    options = options if options is not None else CaptureOptions()
    if isinstance(root_or_paths, (str, os.PathLike)):
        roots = [os.fspath(root_or_paths)]
    else:
        roots = [os.fspath(root) for root in root_or_paths]

    notes: list[str] = []
    found: list[Any] = []
    seen: set[str] = set()
    for root in roots:
        discovery = discover.discover(
            root, include_backups=options.include_backups,
            follow_symlinks=options.follow_symlinks)
        notes.extend(discovery.notes)
        notes.extend(artifact.reason for artifact in discovery.rejected)
        for artifact in discovery.artifacts:
            if artifact.path in seen:
                continue
            seen.add(artifact.path)
            found.append(artifact)
    found.sort(key=lambda artifact: artifact.path)

    ctx = mapping.MapContext(
        project=options.project, project_number=options.project_number,
        region=options.region, organization=options.organization,
        folder=options.folder, access_policy=options.access_policy)

    vault = redact.SecretVault()
    stamp = options.captured_at or None
    collected: list[facts.Fact] = []
    sources: list[SourceRecord] = []
    refs: list[ArtifactRef] = []
    unmapped: list[str] = []

    for artifact in found:
        try:
            if artifact.kind == "tfstate":
                read = state.read_state(artifact.path, captured_at=stamp,
                                        vault=vault)
                objects = read.objects
            elif artifact.kind in ("plan_json", "state_json"):
                read = plan.read_plan(artifact.path, captured_at=stamp,
                                      vault=vault)
                objects = read.current
            else:
                read = hcl.read_file(artifact.path, side="current",
                                     captured_at=stamp)
                objects = read.objects
        except Exception as exc:            # noqa: BLE001 - isolation is the point
            notes.append(READER_FAILED.format(
                path=artifact.path, kind=artifact.kind,
                error=f"{type(exc).__name__}: {facts.truncate(str(exc))}"))
            logger.warning("reader for %s (%s) raised %s: %s - the artifact "
                           "contributes nothing and the capture continues",
                           artifact.path, artifact.kind, type(exc).__name__, exc)
            continue

        notes.extend(read.notes)
        if artifact.ref is not None:
            refs.append(artifact.ref)
        sources.append(SourceRecord(
            source_id=artifact.path, kind=artifact.source, origin=artifact.path,
            captured_at=read.captured_at, scope="partial",
            serial=getattr(read, "serial", None) if artifact.kind == "tfstate" else None,
            lineage=getattr(read, "lineage", "") if artifact.kind == "tfstate" else ""))

        try:
            mapped = mapping.map_objects(objects, ctx)
        except Exception as exc:            # noqa: BLE001 - isolation is the point
            notes.append(READER_FAILED.format(
                path=artifact.path, kind=f"{artifact.kind} mapper",
                error=f"{type(exc).__name__}: {facts.truncate(str(exc))}"))
            continue
        collected.extend(mapped.facts)
        notes.extend(mapped.notes)
        for row in mapped.unrecognized + mapped.unmapped:
            unmapped.append(row.type)
        for row in mapped.skipped:
            notes.append(f"{row.address} ({row.type}): {row.detail}")
        for failure in mapped.failures:
            notes.append(f"{failure.address} ({failure.type}): mapper "
                         f"{failure.module} raised {failure.exception}: "
                         f"{failure.detail}")

    result = merge.resolve(collected, sources=sources, policy=options.precedence)
    notes.extend(result.notes)
    for drop in result.dropped:
        notes.append(drop.note)

    return build(result, options=options, sources=sources, artifacts=refs,
                 notes=[vault.scrub_text(note) for note in notes],
                 unmapped_types=unmapped)


# -- persistence --------------------------------------------------------------


def write_capture(result: Capture,
                  path: str | os.PathLike[str]) -> tuple[str, str]:
    """Write EXACTLY TWO files — the snapshot at *path* and the ledger at
    :func:`gcp_grounding.provenance.origins_path` of it — and return both paths.

    The snapshot goes through ``fetch.write_snapshot``, REUSED and not
    reimplemented because it is the blessed deterministic writer: sorted keys,
    two-space indent, one trailing newline, so two captures of unchanged inputs
    diff cleanly by construction.

    THE LEDGER IS NOT OPTIONAL AND NOT FLAG-GATED. A snapshot that travels
    without one is precisely the artifact that gets read back at scope
    ``complete``, and a capture that emitted ZERO categories still writes a
    ledger declaring every emit-set category ``uncaptured`` — which is what
    makes an empty terraform capture prove nothing rather than everything.
    """
    if not isinstance(result, Capture):
        raise TypeError(f"write_capture takes an estate.Capture, got "
                        f"{type(result).__name__}")
    snapshot_path = os.fspath(path)
    fetch.write_snapshot(result.snapshot, snapshot_path)
    ledger_path = origins_path(snapshot_path)
    result.ledger.write(ledger_path)
    logger.debug("wrote capture: %s + %s", snapshot_path, ledger_path)
    return snapshot_path, ledger_path
