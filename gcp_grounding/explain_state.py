"""Show me what state you used: the auditable render of the current-state view.

A guardrail whose inputs cannot be audited will not be trusted, and an operator
who cannot see WHICH state the tool compared against has no way to tell a real
finding from a stale one. This module is PURE RENDERING over three objects the
caller already holds — an :class:`gcp_grounding.engine.EvaluationResult`, a
:class:`gcp_grounding.provenance.SourceLedger` and a
:class:`gcp_grounding.discovery.Settings`. No I/O, no solver, no clock, and no
re-derivation of anything any of those three already decided.

NAMING NOTE, BECAUSE THE TWO MODULES ARE EASY TO CONFUSE. This module is
``explain_state.py`` and NOT ``provenance.py``:
:mod:`gcp_grounding.provenance` owns the source ledger, the fidelity order, the
scope lattice and the completeness predicate, and this one owns nothing but the
rendering of them. They must never be merged: a renderer that also decides what
coverage MEANS is a second place for the completeness rule to live, and two
copies of that rule is exactly the class of bug the one-sidecar design removes.

THE FOUR BLOCKS, and what each one answers:

1. SOURCES — "where did the current state come from, and how old is it". One
   line per source, with its per-domain scope pairs QUALIFIED BY THEIR BOUNDARY
   STRING: complete-within-one-project and complete are different claims, and
   printing them identically is how a reader is misled into trusting an
   estate-wide negative that was only ever true inside one project. The
   coverage table itself is :func:`gcp_grounding.provenance.summarize`,
   EMBEDDED rather than re-derived, so there is one rendering of one ledger.
2. SETTINGS — "why did it use that state file". One line per field with the
   origin label :func:`gcp_grounding.discovery.resolve_settings` recorded, so a
   surprised reader can see that the path came from a named config file rather
   than from a default nobody chose.
3. TARGETS — "what did it compare each changed row against". A NEW-RESOURCE
   line and an UNQUERIED line read visibly differently on purpose: "we looked
   with a source that enumerates this domain and there is no predecessor" and
   "we did not look" license opposite conclusions, and collapsing them is the
   single most dangerous thing this surface could do.
4. DRIFT — "which sources disagreed, and about what". Every differing path with
   every source's value, already masked wherever the loading boundary replaced
   one.

SILENCE IS NOT AN OPTION. With nothing configured the renderer emits exactly
ONE line saying so and naming the consequence — only proposal-tier checks ran —
because an empty block reads as a clean estate check, which is the strongest
claim this tool can make and the one it has least earned.

THE REDACTION BELT. Both renderers call
:func:`gcp_grounding.redact.ensure_log_filter` FIRST: this is a render boundary,
``core.log.setup_logging`` removes and re-adds its own handlers, and a filter
installed once in ``sources.py`` is gone the moment anything reconfigures
logging — the explain surface being exactly where a value would then be logged.
Both then run a final pass asserting that no rendered scalar is (or contains) a
plaintext the process vault remembers, raising :class:`AssertionError` rather
than shipping a leak. In production the values were already replaced at load
time; this is a belt, and it is cheap. A rendered
:class:`gcp_grounding.redact.Redacted` prints its ``wire()`` form,
``redacted:sha256:<digest>`` — never the digest bare (which is what its ``repr``
would give) and never the original.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterator, Mapping, Sequence

from . import compare, discovery, freshness, provenance, redact, sources
from .core.log import get_logger

#: This module logs COUNTS and never content. It renders values that were
#: withheld at the loading boundary, and a debug line carrying one of them
#: would defeat the very filter the renderers re-attach on the way in.
logger = get_logger(__name__)

__all__ = [
    "PROVENANCE_SCHEMA",
    "HEADER",
    "NONE_CONFIGURED",
    "STATUS_PHRASES",
    "state_lines",
    "state_document",
    "fact_lines",
]

#: The machine document's schema. A NEW document rather than a new version of
#: anything: neither ``report.SCHEMA``, ``gate.GATE_SCHEMA`` nor the ledger's
#: ``gcp-source-ledger/1`` is bumped by rendering them.
PROVENANCE_SCHEMA = "gcp-grounding-provenance/1"

#: The first line's fixed prefix. Every render starts with it — including the
#: nothing-configured one — so the block is greppable from a log nobody parsed.
HEADER = "state used this run"

#: The WHOLE render when no source was configured. One line, and it names the
#: consequence: silence here would read as a clean estate check.
NONE_CONFIGURED = (
    f"{HEADER}: none configured - no current-state source was read, so only "
    f"proposal-tier checks ran; nothing was compared against the estate")

#: Baseline status → how the line reads. TOTAL over
#: :data:`gcp_grounding.baseline.RESOLUTION_STATUSES`, and the ``absent`` and
#: ``unqueried`` phrasings are deliberately nothing alike: one says a source
#: that enumerates the domain was queried and holds no predecessor, the other
#: says we never looked. A reader who cannot tell those apart cannot tell a new
#: resource from an unchecked one.
STATUS_PHRASES = {
    "resolved": "resolved - a current counterpart was found and compared against",
    "absent": ("NEW RESOURCE - a source that enumerates this domain completely was "
               "queried and holds no predecessor for this key"),
    "unqueried": ("NOT LOOKED UP - no source covering this domain could be queried, "
                  "so nothing was compared and no absence may be concluded"),
    "conflict": ("conflict - two or more sources describe this row differently; both "
                 "readings are reported and neither is picked"),
    "stale": ("stale - the source describing this row is past its freshness limit, so "
              "its counterpart cannot justify a pass"),
    "unresolved": ("unresolved - the row could not be identified in the current state, "
                   "so no counterpart was compared"),
    "opaque": ("opaque - a counterpart exists but has no comparable document form, so "
               "no widening check could run against it"),
}

#: How a missing scalar renders. One spelling, so a reader never has to wonder
#: whether an empty column means absent or means empty.
DASH = "-"


# -- the boundary helpers -----------------------------------------------------


def _vault() -> redact.SecretVault:
    """THE process-wide vault, and the single install of the log filter.

    Owned by ``sources.py`` because that is where every source is READ; asking
    for it here rather than building a second one is what keeps the belt below
    checking against the plaintexts that were actually seen.
    """
    return sources.vault()


def _enter() -> None:
    """Re-attach the secret filter to the live handler set.

    Called first by every renderer. ``core.log.setup_logging`` is
    idempotent-but-RECONFIGURING — it removes and re-adds its own handlers — so
    a single install in ``sources.py`` is gone the moment a CLI configures
    logging lazily or a second gate is constructed, and this surface is exactly
    where a withheld value would then be logged. The no-change path allocates
    nothing.
    """
    redact.ensure_log_filter(_vault())


def _scalars(value: Any, depth: int = 0) -> Iterator[str]:
    """Every rendered string under *value*, keys included."""
    if depth > 8:                                # a render is never deeper
        return
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _scalars(item, depth + 1)
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _scalars(item, depth + 1)


def _belt(rendered: Any) -> None:
    """THE REDACTION ASSERTION BELT: refuse to hand back a render carrying a
    plaintext the vault remembers.

    Equality catches a value rendered whole; the vault's own scrub catches one
    embedded in a longer line, which is the shape a hand-built message takes.
    The :class:`AssertionError` names the length and the position and NEVER the
    value — an assertion that prints the secret to prove the secret leaked is
    the leak.
    """
    vault = _vault()
    if not vault:                                # nothing was ever collected
        return
    for text in _scalars(rendered):
        if text in vault:
            raise AssertionError(
                f"explain_state rendered a scalar of length {len(text)} that IS a "
                f"plaintext held in the process vault - refusing to ship a leak; "
                f"the value should have been replaced at the loading boundary")
        if vault.scrub_text(text) is not text:
            raise AssertionError(
                f"explain_state rendered a line of length {len(text)} CONTAINING a "
                f"plaintext held in the process vault - refusing to ship a leak; "
                f"the value should have been replaced at the loading boundary")


# -- value rendering ----------------------------------------------------------


def _stable(value: Any, depth: int = 0) -> Any:
    """*value* with every :class:`~gcp_grounding.redact.Redacted` replaced by
    its wire string and every unordered container put in a fixed order.

    The masking is :func:`gcp_grounding.redact.to_wire` — the ONE conversion —
    rather than a second spelling of it. The ordering is this module's own
    business: ``compare`` normalises a set-valued field to a ``frozenset``,
    whose iteration order is not a rendering anybody can diff.
    """
    if depth == 0:
        value = redact.to_wire(value)
    if depth > 8:
        return value
    if isinstance(value, Mapping):
        return {str(k): _stable(v, depth + 1)
                for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (set, frozenset)):
        return sorted((_stable(v, depth + 1) for v in value), key=repr)
    if isinstance(value, (list, tuple)):
        return [_stable(v, depth + 1) for v in value]
    return value


def _render(value: Any) -> str:
    """One value as a stable, masked, single-line string."""
    return repr(_stable(value))


def _scope_text(scope: Any, boundary: Any) -> str:
    """``complete`` or ``complete within 'organizations/1'``.

    The qualifier is never dropped: complete-within-one-named-boundary and
    complete are different claims, and a reader who sees the second where the
    first was meant will trust an estate-wide negative that was only ever true
    inside that boundary.
    """
    text = str(scope or "uncaptured")
    if boundary:
        return f"{text} within '{boundary}'"
    return text


def _age(captured_at: str, now: datetime | None) -> str:
    """The source's age against the INJECTED clock, or ``unknown``.

    Three ways to be unknown, and they are all honest: no capture time at all,
    a capture time :func:`gcp_grounding.freshness.parse_timestamp` refuses (a
    naive stamp is refused rather than assumed UTC), and no injected clock —
    this module never reads the wall clock, because nothing below the gate's
    own boundary may.
    """
    if now is None:
        return "unknown (no clock was injected)"
    captured = freshness.parse_timestamp(captured_at)
    if captured is None:
        return "unknown (no aware capture timestamp)"
    delta = now - captured
    if delta.total_seconds() < 0:
        return "unknown (captured after the injected clock)"
    return freshness._describe(delta)


def _now(settings: Any) -> datetime | None:
    """The clock the run was configured with, or ``None``.

    Read from the settings' wrapped options, which is where the gate and the
    CLI put the once-per-run :func:`gcp_grounding.freshness.resolve_now` value.
    """
    options = getattr(settings, "options", None)
    return freshness.parse_timestamp(getattr(options, "now", None))


# -- reading the three inputs -------------------------------------------------


def _records(ledger: Any) -> tuple[Any, ...]:
    """Every source record, ordered by FIDELITY then source id.

    One order for the lines and the document, so a reader comparing the two is
    comparing the same list. An unknown spelling sorts first rather than
    raising: a ledger written by a future version must not crash an explain.
    """
    sources_map = getattr(ledger, "sources", None) or {}

    def rank(record: Any) -> int:
        try:
            return provenance.fidelity_rank(getattr(record, "kind", ""))
        except ValueError:
            return -1

    return tuple(sorted(sources_map.values(),
                        key=lambda r: (rank(r), getattr(r, "source_id", ""))))


def _entries(result: Any) -> tuple[Any, ...]:
    """Every baseline entry the derivation produced, in derivation order."""
    return tuple(getattr(getattr(result, "derivation", None), "entries", ()) or ())


def _fact_count(ledger: Any, source_id: str) -> int:
    facts = getattr(ledger, "facts", None) or {}
    return sum(1 for keys in facts.values() for origin in keys.values()
               if getattr(origin, "source_id", "") == source_id)


def _domain_pairs(ledger: Any, source_id: str) -> tuple[str, ...]:
    """``domain=scope within 'boundary'`` for every domain this source supplies.

    Who supplies what is :func:`gcp_grounding.freshness.sourced_categories` —
    the one answer to that question in the tree — and not a second walk of the
    facts table that could disagree with the staleness ceiling about which
    categories a source speaks for.
    """
    if ledger is None:
        return ()
    out: list[str] = []
    for category in freshness.sourced_categories(ledger, source_id):
        scope = ledger.scope_of(category)
        out.append(f"{category}={_scope_text(scope.scope, scope.boundary)}")
    return tuple(out)


def _notes(record: Any) -> tuple[str, ...]:
    """The notes printed under one source line.

    A terraform source ALWAYS gets the coercion note, even when its reader
    declared ``partial`` directly and no coercion actually fired: the line says
    ``partial`` either way, and a reader who does not know that is structural
    reads it as a capture bug and goes looking for the missing rows.
    """
    out: list[str] = []
    if getattr(record, "kind", "") in provenance.TERRAFORM_SOURCES:
        out.append("a terraform artifact covers only the resources terraform "
                   "manages, so this scope is capped at 'partial' by construction - "
                   "it is not a capture bug")
    for part in str(getattr(record, "note", "") or "").split("; "):
        if part.strip():
            out.append(part.strip())
    serial, lineage = getattr(record, "serial", None), getattr(record, "lineage", "")
    if serial is not None or lineage:
        out.append(f"terraform state identity: serial={serial if serial is not None else DASH}"
                   f" lineage={lineage or DASH}")
    seen: set[str] = set()
    return tuple(note for note in out if not (note in seen or seen.add(note)))


def _key_of(entry: Any) -> str:
    return getattr(entry, "key", "") or getattr(getattr(entry, "target", None), "key", "")


def _domain_of(entry: Any) -> str:
    return getattr(getattr(entry, "target", None), "category", "")


def _phrase(status: str) -> str:
    """*status* as a sentence, falling back to the bare status.

    Never raises on a status this table has not heard of: a renderer that
    crashed on a new baseline status would take the whole report with it.
    """
    return STATUS_PHRASES.get(status, str(status))


def _ordered_entries(entries: Sequence[Any]) -> tuple[Any, ...]:
    """Entries by domain then key — the document's declared order, reused for
    the lines so the two renderings cannot disagree."""
    return tuple(sorted(entries, key=lambda e: (_domain_of(e), _key_of(e))))


# -- the field-level differences ----------------------------------------------


def _differing(entry: Any) -> tuple[tuple[str, tuple[tuple[str, str], ...]], ...]:
    """``((path, ((source, value), ...)), ...)`` over one entry's alternates.

    THE DIFF RULE IS ``compare.compare`` and is not restated here; this
    function only groups its answers by path and renders them. An
    :class:`gcp_grounding.compare.Incomparable` pair is reported AS a difference
    at the pseudo-path ``<record>``, because two views that cannot be compared
    at all is the most important thing on the block, not the least.
    """
    collected: dict[str, dict[str, str]] = {}
    category = _domain_of(entry)
    winner = getattr(entry, "source_id", "") or "unattributed"
    for candidate in getattr(entry, "others", ()) or ():
        label = getattr(candidate, "source_id", "") or "unattributed"
        try:
            diffs = compare.compare(category, getattr(entry, "record", None),
                                    getattr(candidate, "record", None))
        except compare.Incomparable as exc:
            collected.setdefault("<record>", {})[label] = f"incomparable ({exc.detail})"
            continue
        for diff in diffs:
            bucket = collected.setdefault(diff.path, {})
            bucket.setdefault(winner, _render(diff.left))
            bucket[label] = _render(diff.right)
    return tuple((path, tuple(sorted(collected[path].items())))
                 for path in sorted(collected))


# -- BLOCK ONE: the sources ---------------------------------------------------


def _source_block(ledger: Any, records: Sequence[Any],
                  now: datetime | None) -> list[str]:
    lines = ["sources:"]
    for record in records:
        pairs = ", ".join(_domain_pairs(ledger, record.source_id)) or DASH
        lines.append(
            f"  [{record.kind}] {record.source_id} origin={record.origin or DASH} "
            f"captured_at={record.captured_at or DASH} "
            f"age={_age(record.captured_at, now)} "
            f"scope={_scope_text(record.scope, record.boundary)} "
            f"domains=[{pairs}] facts={_fact_count(ledger, record.source_id)}")
        for note in _notes(record):
            lines.append(f"    note: {note}")
    lines.append("  coverage:")
    lines.extend(f"    {line}"
                 for line in provenance.summarize(ledger, embed=True).splitlines())
    return lines


# -- BLOCK TWO: the settings --------------------------------------------------


def _setting_value(settings: Any, name: str) -> str:
    """One settings field rendered.

    ``origins`` is the trap and it is deliberate: ``Settings.origins`` is the
    per-field ORIGIN LABEL map while ``settings.options.origins`` is the
    snapshot's SIDECAR PATH. The VALUE column comes from the options and the
    bracketed label from :meth:`Settings.origin_of`; reading one as the other
    prints a path where a label belongs.
    """
    if name == "targets":
        targets = getattr(settings, "targets", None) or {}
        return ", ".join(
            f"{path}={getattr(ref, 'category', '')}:{getattr(ref, 'key', '')}"
            for path, ref in sorted(targets.items())) or DASH
    if name == "requirements":
        return str(getattr(settings, "requirements", "") or DASH)
    value = getattr(getattr(settings, "options", None), name, None)
    if value is None or value == "":
        return DASH
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value) or DASH
    return str(value)


def _settings_block(settings: Any) -> list[str]:
    if settings is None:
        return []
    lines = ["settings:"]
    for name in discovery.SETTINGS_FIELDS:
        lines.append(f"  {name} = {_setting_value(settings, name)} "
                     f"[{settings.origin_of(name)}]")
    return lines


# -- BLOCK THREE: the targets -------------------------------------------------


def _targets_block(entries: Sequence[Any]) -> list[str]:
    if not entries:
        return ["targets: none - no baseline target was derived for this proposal, "
                "so no pair check had a counterpart to compare against"]
    lines = ["targets:"]
    for entry in entries:
        lines.append(
            f"  {_domain_of(entry)} {_key_of(entry) or DASH} -> "
            f"{getattr(entry, 'source_id', '') or DASH} "
            f"[{getattr(entry, 'how', '') or DASH}] {_phrase(entry.status)}")
        if entry.status != "resolved":
            reason = getattr(entry, "reason", "") or "no reason was recorded"
            lines.append(f"    reason: {reason}")
    return lines


# -- BLOCK FOUR: the drift ----------------------------------------------------


def _drift_block(conflicts: Sequence[Any]) -> list[str]:
    if not conflicts:
        return ["drift: none - no source disagreed about a row that was looked up"]
    lines = ["drift:"]
    for entry in conflicts:
        lines.append(f"  {_domain_of(entry)} {_key_of(entry) or DASH}")
        differing = _differing(entry)
        if not differing:
            lines.append("    (recorded as disagreeing, but no comparable field "
                         "difference was found)")
        for path, values in differing:
            rendered = ", ".join(f"{source}={value}" for source, value in values)
            lines.append(f"    {path}: {rendered}")
    return lines


# -- the human renderer -------------------------------------------------------


def state_lines(result: Any, ledger: Any, settings: Any = None) -> list[str]:
    """The four blocks, as lines, for an operator reading stderr.

    *result* is an :class:`gcp_grounding.engine.EvaluationResult`, *ledger* the
    :class:`gcp_grounding.provenance.SourceLedger` its current state travelled
    with, and *settings* the :class:`gcp_grounding.discovery.Settings` that
    chose the sources (optional: a library caller may have none).

    With NO source configured this is exactly one line — see
    :data:`NONE_CONFIGURED`. Nothing here re-derives a decision: every scope,
    status, reason and source name is read from the objects the caller passes.
    """
    _enter()
    records = _records(ledger)
    if not records:
        lines = [NONE_CONFIGURED]
        _belt(lines)
        return lines
    entries = _ordered_entries(_entries(result))
    conflicts = [entry for entry in entries if entry.status == "conflict"]
    lines = [f"{HEADER}: {len(records)} source(s), {len(entries)} target(s), "
             f"{len(conflicts)} conflicting"]
    lines.extend(_source_block(ledger, records, _now(settings)))
    lines.extend(_settings_block(settings))
    lines.extend(_targets_block(entries))
    lines.extend(_drift_block(conflicts))
    _belt(lines)
    logger.debug("explain_state: %d line(s) over %d source(s), %d target(s), "
                 "%d conflicting", len(lines), len(records), len(entries),
                 len(conflicts))
    return lines


# -- the machine renderer -----------------------------------------------------


def _source_rows(ledger: Any, records: Sequence[Any],
                 now: datetime | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        domains = []
        for category in freshness.sourced_categories(ledger, record.source_id):
            scope = ledger.scope_of(category)
            domains.append({"domain": category, "scope": scope.scope,
                            "boundary": scope.boundary, "keys": scope.keys,
                            "dropped": scope.dropped, "taint": scope.taint})
        rows.append({
            "source": record.source_id,
            "kind": record.kind,
            "origin": record.origin,
            "captured_at": record.captured_at,
            "age": _age(record.captured_at, now),
            "scope": record.scope,
            "boundary": record.boundary,
            "facts": _fact_count(ledger, record.source_id),
            "domains": domains,
            "notes": list(_notes(record)),
        })
    return rows


def _target_rows(entries: Sequence[Any]) -> list[dict[str, Any]]:
    return [{
        "domain": _domain_of(entry),
        "key": _key_of(entry),
        "source": getattr(entry, "source_id", ""),
        "how": getattr(entry, "how", ""),
        "status": entry.status,
        "scope": getattr(entry, "scope", ""),
        "kind": getattr(entry, "kind", None) or "",
        "reason": getattr(entry, "reason", ""),
        "flags": list(getattr(entry, "flags", ()) or ()),
        "alternates": sorted(getattr(candidate, "source_id", "") or "unattributed"
                             for candidate in getattr(entry, "others", ()) or ()),
    } for entry in entries]


def _drift_rows(conflicts: Sequence[Any]) -> list[dict[str, Any]]:
    """One row per (domain, key, path), sorted by path within a key.

    FLAT on purpose: a consumer diffing two runs compares rows, and a nested
    per-key object hides a path that moved between keys.
    """
    rows: list[dict[str, Any]] = []
    for entry in conflicts:
        for path, values in _differing(entry):
            rows.append({
                "domain": _domain_of(entry),
                "key": _key_of(entry),
                "path": path,
                "values": [{"source": source, "value": value}
                           for source, value in values],
            })
    return sorted(rows, key=lambda row: (row["domain"], row["key"], row["path"]))


def _as_of(settings: Any, ledger: Any) -> str:
    """The instant this render describes: the injected clock when the run
    pinned one, else the ledger's OLDEST contributing capture time.

    Never the wall clock. Falling back to the merged capture time keeps the
    document self-dating without making a render non-reproducible — two calls
    over the same inputs must produce the same bytes.
    """
    now = _now(settings)
    if now is not None:
        return now.isoformat()
    if ledger is None:
        return ""
    return ledger.merged_captured_at()


def state_document(result: Any, ledger: Any, settings: Any = None) -> dict[str, Any]:
    """The same content as :func:`state_lines`, in machine form.

    Keys: ``schema``, ``as_of``, ``sources``, ``settings``, ``targets`` and
    ``drift``. EVERY list is deterministically ordered — sources by fidelity
    then source id, targets by domain then key, drift by path — so two runs over
    the same inputs produce byte-identical JSON and a committed document diffs
    cleanly. Only JSON-native types appear, so a dump-and-load round trip is an
    identity.
    """
    _enter()
    records = _records(ledger)
    entries = _ordered_entries(_entries(result))
    document = {
        "schema": PROVENANCE_SCHEMA,
        "as_of": _as_of(settings, ledger),
        "sources": _source_rows(ledger, records, _now(settings)),
        "settings": [] if settings is None else [
            {"field": name,
             "value": _setting_value(settings, name),
             "origin": settings.origin_of(name)}
            for name in discovery.SETTINGS_FIELDS],
        "targets": _target_rows(entries),
        "drift": _drift_rows([e for e in entries if e.status == "conflict"]),
    }
    _belt(document)
    return document


# -- the drill-down -----------------------------------------------------------


def _entry_for(result: Any, domain: str, key: str) -> Any:
    for entry in _entries(result):
        if _domain_of(entry) == domain and _key_of(entry) == key:
            return entry
    return None


def _snapshot_record(result: Any, domain: str, key: str) -> Any:
    """The winning record straight off the current state, for a key no baseline
    entry covered — an explain must be able to answer about a row nobody
    changed."""
    table = getattr(getattr(result, "current", None), domain, None)
    if isinstance(table, Mapping):
        return table.get(key)
    return None


def fact_lines(result: Any, ledger: Any, domain: str, key: str) -> list[str]:
    """One target, in full: the chosen record with its provenance, then every
    alternate, then the field-level differences.

    This is what the state-explain CLI flag renders when it is given an
    argument. Same belt, same masking, same one diff rule as the drift block.
    """
    _enter()
    entry = _entry_for(result, domain, key)
    origin = ledger.origin_of(domain, key) if ledger is not None else None
    scope = ledger.scope_of(domain) if ledger is not None else provenance.UNCAPTURED
    record = getattr(entry, "record", None) if entry is not None else None
    if record is None:
        record = _snapshot_record(result, domain, key)
    lines = [f"state fact {domain} {key}:"]

    source_id = (getattr(origin, "source_id", "") or
                 (getattr(entry, "source_id", "") if entry is not None else ""))
    source_record = (getattr(ledger, "sources", {}) or {}).get(source_id)
    taint = ledger.taint_of(domain, key) if ledger is not None else ""
    lines.append(
        f"  chosen: source={source_id or DASH} "
        f"[{getattr(source_record, 'kind', '') or DASH}] "
        f"origin={getattr(source_record, 'origin', '') or DASH} "
        f"locator={getattr(origin, 'locator', '') or DASH} "
        f"captured_at={getattr(source_record, 'captured_at', '') or DASH} "
        f"domain-scope={_scope_text(scope.scope, scope.boundary)} "
        f"taint={taint or DASH}")
    if record is None:
        lines.append("    record: none - nothing in the current state describes this "
                     "row, so there is no winning record to show")
    else:
        lines.append(f"    record: {_render(record)}")

    alternates = (ledger.alternates_for(domain, key) if ledger is not None else ())
    lines.append(f"  alternates: {len(alternates)}")
    for alternate in alternates:
        lines.append(
            f"    alternate: source={alternate.source_id or DASH} "
            f"locator={alternate.locator or DASH} "
            f"reason={alternate.reason or DASH}")
        lines.append(f"      record: {_render(alternate.record)}")

    lines.append("  differences:")
    differing = _differing(entry) if entry is not None else ()
    if not differing:
        lines.append("    none - no comparable field difference was recorded for "
                     "this key")
    for path, values in differing:
        rendered = ", ".join(f"{source}={value}" for source, value in values)
        lines.append(f"    {path}: {rendered}")
    _belt(lines)
    return lines
