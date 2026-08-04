"""The one clock boundary, the one staleness ceiling, and tfstate supersession.

**THIS MODULE IS THE ONLY PLACE IN THE TREE THAT READS THE WALL CLOCK.**
:func:`resolve_now` is that boundary, and it is resolved exactly once per run at
the gate or CLI entry point. Every module below it takes an injected ``as_of`` /
``now`` argument and never calls :func:`datetime.datetime.now` itself, so the
whole suite is deterministic and offline and a CI run can pin its own clock
through ``GCP_GROUNDING_NOW``. That sentence is normative, not advisory: a
second clock read is a second answer to "how old is this estate", and the two
would disagree across a midnight boundary in exactly the runs nobody re-runs.

**THE CEILING IS ON BY DEFAULT.** :data:`MAX_AGE_DEFAULT` is seven days and is
the ONLY staleness ceiling constant anywhere in this package; no other module
defines its own. Seven days because a week-old estate snapshot is routinely
wrong — roles are granted, firewall rules are opened and perimeters are widened
inside a week — while a week never trips a weekly CI capture, which is the
cadence that would otherwise turn the ceiling into noise everybody disables.

A ``None`` ceiling is therefore an explicit OPT-OUT and never the default value
of any parameter here. The reason is the hook: a ``PostToolUse`` hook is invoked
with one fixed command line that nobody edits per-run, so a ceiling that only
applies when a flag is typed is a ceiling that never applies. Defaulting to
:data:`MAX_AGE_DEFAULT` and making ``max_age=None`` the typed opt-out puts the
burden of proof on the side that wants the gate quieter.

**Age abstains; it never contradicts.** A source past the ceiling produces one
``unverified`` verdict of kind ``staleness`` per SOURCE — never one per category
— and :func:`demote_stale` rewrites the categories it supplies to scope
``uncaptured`` with taint ``stale``. The DATA is left exactly as it was, and
that asymmetry is deliberate: a stale source may no longer justify a pass, but a
``contradicted`` finding it supports still stands. Downgrading findings on age
would make letting a snapshot rot a way to switch the gate off, which is a
strictly easier attack than fixing the finding.

**Timestamps are strict, and naive means unknown.** :func:`parse_timestamp`
returns ``None`` for a stamp with no offset rather than assuming UTC, because
assuming UTC on a local-time stamp silently shifts an age by up to a day, and it
shifts it in the unsafe direction exactly when the local zone is behind UTC.
An unreadable or naive stamp abstains through the same ``staleness`` verdict as
an over-age one: we cannot show the source is fresh, and the ceiling is on by
default.
"""

from __future__ import annotations

import dataclasses
import json
import os
import stat as stat_module
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Mapping

from .core.log import get_logger
from .core.report import Verdict
from .provenance import SourceLedger, compose_taint

logger = get_logger(__name__)

__all__ = [
    "MAX_AGE_DEFAULT",
    "MAX_STATE_BYTES",
    "NOW_ENV",
    "OFF_SPELLINGS",
    "DURATION_UNITS",
    "STATE_HEADER_KEYS",
    "STALENESS_KINDS",
    "parse_timestamp",
    "parse_duration",
    "resolve_now",
    "read_state_header",
    "sourced_categories",
    "check_freshness",
    "state_supersession",
    "demote_stale",
    "evaluate",
]

#: THE ONE CEILING. Seven days; see the module docstring for why seven.
MAX_AGE_DEFAULT = timedelta(days=7)

#: The environment variable that pins the clock for a test or a CI run. Set but
#: unparseable is an ERROR, never a fallback — see :func:`resolve_now`.
NOW_ENV = "GCP_GROUNDING_NOW"

#: Spellings of "no ceiling" accepted by :func:`parse_duration`. The empty
#: string is included because an unset ``--max-age`` flag arrives as one.
OFF_SPELLINGS = ("", "off", "none")

#: Suffix → seconds. Deliberately small: a duration grammar nobody can hold in
#: their head is a grammar whose typos become silent opt-outs.
DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

#: The ONLY keys :func:`read_state_header` returns. A ``terraform.tfstate``
#: stores sensitive values in PLAINTEXT inside ``resources``, so the header
#: reader must never hand one back — supersession needs identity, not content.
STATE_HEADER_KEYS = ("version", "serial", "lineage")

#: Largest tfstate this module will open. A state file bigger than this is
#: refused BY SIZE, before any read: the reader wants three scalars, and reading
#: a hundred megabytes of plaintext secrets into a gate's memory to find them is
#: a trade nobody made on purpose.
MAX_STATE_BYTES = 64 * 1024 * 1024

#: The verdict kinds this module emits, and therefore the kinds
#: :func:`demote_stale` acts on. Both are ``unverified``; no new STATUS is
#: introduced, because "not decided" already exists.
STALENESS_KINDS = ("staleness", "staleness:serial")


# -- parsing ------------------------------------------------------------------


def parse_timestamp(text: Any) -> datetime | None:
    """An AWARE :class:`~datetime.datetime` for *text*, or ``None``.

    Strict on purpose, in two ways:

    - a trailing ``Z`` is normalised to an explicit ``+00:00`` offset, because
      :meth:`datetime.datetime.fromisoformat` does not accept it before 3.11 and
      this package supports 3.10;
    - a NAIVE result returns ``None`` DELIBERATELY rather than being assumed to
      be UTC. Assuming UTC on a local-time stamp shifts the computed age by up
      to a day, and in the unsafe direction whenever the writer's zone is behind
      UTC — a snapshot that is eight days old reads as seven and passes.

    ``None`` here always means "this is not a timestamp I can reason about",
    which every caller turns into an abstention rather than a pass.
    """
    if isinstance(text, datetime):
        return text if _is_aware(text) else None
    if not isinstance(text, str):
        return None
    candidate = text.strip()
    if not candidate:
        return None
    if candidate.endswith(("Z", "z")):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return parsed if _is_aware(parsed) else None


def _is_aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.tzinfo.utcoffset(value) is not None


def parse_duration(text: Any) -> timedelta | None:
    """A :class:`~datetime.timedelta` ceiling for *text*, or ``None`` for none.

    Accepts an ``s``/``m``/``h``/``d``/``w`` suffix, a bare integer meaning
    SECONDS, and the three :data:`OFF_SPELLINGS` — ``off``, ``none`` and the
    empty string — meaning no limit at all.

    Anything else RAISES :class:`ValueError`. Returning ``None`` for a typo
    would spell an unreadable ceiling exactly the way the opt-out is spelled,
    so ``--max-age 7dd`` would silently switch staleness off; the ceiling is on
    by default and a typo must not be a way around that.
    """
    if text is None:
        return None
    if isinstance(text, timedelta):
        return text
    candidate = str(text).strip().lower()
    if candidate in OFF_SPELLINGS:
        return None
    unit = 1
    digits = candidate
    if candidate[-1] in DURATION_UNITS:
        unit = DURATION_UNITS[candidate[-1]]
        digits = candidate[:-1]
    # Not int() alone: it accepts surrounding whitespace and non-ASCII digits,
    # so "7 d" would silently mean seven days and "٧d" would parse at all.
    body = digits[1:] if digits.startswith("-") else digits
    if not (body.isascii() and body.isdigit()):
        raise ValueError(
            f"cannot read {text!r} as a duration; expected an integer with an "
            f"optional {sorted(DURATION_UNITS)} suffix (a bare integer is "
            f"seconds), or one of {list(OFF_SPELLINGS)} for no limit")
    count = int(digits)
    if count < 0:
        raise ValueError(f"duration {text!r} is negative; a ceiling in the past "
                         f"would make every source stale")
    return timedelta(seconds=count * unit)


# -- the clock boundary -------------------------------------------------------


def resolve_now(explicit: Any = None,
                env: Mapping[str, str] | None = None) -> datetime:
    """THE clock boundary: *explicit*, then :data:`NOW_ENV`, then the wall clock.

    Resolve this ONCE per run, at the gate or CLI entry point, and inject the
    result downwards. Nothing below this function reads the clock.

    Raises :class:`ValueError` NAMING :data:`NOW_ENV` when the variable is set
    to something unparseable, instead of falling through to the wall clock. A
    silently ignored test clock is a suite that lies: every age assertion in it
    would be measured against the real time and would keep passing for the wrong
    reason until the fixture aged out.

    An empty variable is treated as unset, which is what an exported-but-blank
    shell variable means; only a non-blank unparseable value is an error.
    """
    if explicit is not None:
        resolved = parse_timestamp(explicit)
        if resolved is None:
            raise ValueError(
                f"resolve_now(explicit={explicit!r}) is not an aware ISO-8601 "
                f"timestamp - a naive stamp is refused rather than assumed UTC, "
                f"because assuming UTC shifts an age by up to a day")
        return resolved
    environ = os.environ if env is None else env
    raw = environ.get(NOW_ENV)
    if raw is not None and raw.strip():
        resolved = parse_timestamp(raw)
        if resolved is None:
            raise ValueError(
                f"{NOW_ENV}={raw!r} is not an aware ISO-8601 timestamp - refusing "
                f"to fall back to the wall clock, because a silently ignored test "
                f"clock is a suite that lies; a naive stamp is refused too rather "
                f"than assumed UTC")
        logger.debug("clock pinned by %s=%s", NOW_ENV, raw)
        return resolved
    return datetime.now(timezone.utc)


# -- rendering ----------------------------------------------------------------


def _describe(delta: timedelta) -> str:
    """*delta* in whole days, or in whole hours when it is under a day."""
    seconds = int(delta.total_seconds())
    if seconds >= DURATION_UNITS["d"]:
        days = seconds // DURATION_UNITS["d"]
        return f"{days} day{'' if days == 1 else 's'}"
    hours = seconds // DURATION_UNITS["h"]
    return f"{hours} hour{'' if hours == 1 else 's'}"


def _annotate(existing: str, addition: str) -> str:
    if not existing:
        return addition
    if addition in existing:
        return existing
    return f"{existing}; {addition}"


_DEMOTED = "every category it supplies is demoted to 'uncaptured'"


# -- who supplies what --------------------------------------------------------


def sourced_categories(ledger: SourceLedger, source_id: str) -> tuple[str, ...]:
    """Every category *source_id* supplies, sorted. Never raises.

    Two routes, unioned, because a ledger may carry either kind of attribution:
    a category with a per-fact :class:`~gcp_grounding.provenance.FactOrigin`
    naming this source, and a declared category whose ``source_kinds`` carries
    this source's KIND. The second route is what keeps the legacy
    :meth:`~gcp_grounding.provenance.SourceLedger.unattributed` path — which
    declares categories but records no per-fact origins — inside the ceiling.

    Where two sources share one kind the second route over-attributes, and that
    is the deliberate direction: over-attributing costs an abstention on a
    category that was in fact fresh, under-attributing costs a pass justified by
    a snapshot nobody can show is current.
    """
    record = ledger.sources.get(source_id)
    kind = record.kind if record is not None else ""
    supplied = {category for category, keys in ledger.facts.items()
                if any(origin.source_id == source_id for origin in keys.values())}
    if kind:
        supplied.update(category for category, scope in ledger.categories.items()
                        if kind in scope.source_kinds)
    return tuple(sorted(supplied))


# -- the age check ------------------------------------------------------------


def check_freshness(ledger: SourceLedger, *, now: datetime,
                    max_age: timedelta | None = MAX_AGE_DEFAULT) -> tuple[Verdict, ...]:
    """One ``staleness`` verdict per over-age SOURCE, in source-id order.

    ONE PER SOURCE, never one per category: a source supplying nine categories
    is one thing that went stale, and nine verdicts saying so would bury the one
    fact a reader needs — which source to re-capture.

    ``max_age`` defaults to :data:`MAX_AGE_DEFAULT`; passing ``None`` is the
    explicit opt-out. Three arms produce a verdict — an over-age stamp, a stamp
    that is not an aware timestamp, and a source that declares no capture time
    at all — because under an on-by-default ceiling "we cannot tell how old this
    is" and "this is too old" license exactly the same conclusion: nothing.
    """
    if max_age is None:
        logger.debug("staleness ceiling explicitly disabled (max_age=None)")
        return ()
    if not _is_aware(now):
        raise ValueError(f"check_freshness(now={now!r}) needs an AWARE datetime; "
                         f"resolve it through resolve_now(), which refuses a naive one")
    limit = _describe(max_age)
    verdicts: list[Verdict] = []
    for source_id in sorted(ledger.sources):
        record = ledger.sources[source_id]
        origin = record.origin or "no origin recorded"
        if not record.captured_at:
            verdicts.append(Verdict(
                "unverified", "staleness", source_id, 0,
                f"source '{source_id}' ({origin}) declares no capture time, so its "
                f"age cannot be checked against the {limit} freshness limit - "
                f"{_DEMOTED}"))
            continue
        captured = parse_timestamp(record.captured_at)
        if captured is None:
            verdicts.append(Verdict(
                "unverified", "staleness", source_id, 0,
                f"source '{source_id}' ({origin}) records capture time "
                f"'{record.captured_at}', which is not an aware ISO-8601 timestamp, "
                f"so its age cannot be checked against the {limit} freshness limit - "
                f"a naive stamp is refused rather than assumed UTC; {_DEMOTED}"))
            continue
        age = now - captured
        if age <= max_age:
            continue
        verdicts.append(Verdict(
            "unverified", "staleness", source_id, 0,
            f"source '{source_id}' ({origin}) was captured at "
            f"'{record.captured_at}', {_describe(age)} before now, which is past "
            f"the {limit} freshness limit - {_DEMOTED}"))
    return tuple(verdicts)


# -- tfstate supersession -----------------------------------------------------


def read_state_header(path: str | os.PathLike[str]) -> dict[str, Any] | None:
    """The ``version``/``serial``/``lineage`` header of the tfstate at *path*.

    ``None`` — never an exception — for a missing path, a NON-REGULAR file (a
    directory, a fifo, a device: a gate must not block on one), a file larger
    than :data:`MAX_STATE_BYTES`, unreadable bytes or invalid JSON. The size
    refusal happens on the ``stat``, BEFORE the file is opened.

    The returned dict holds ONLY :data:`STATE_HEADER_KEYS`. A tfstate stores
    sensitive values in plaintext under ``resources``, and this reader exists to
    answer an identity question; handing the body back would put every secret in
    the file one attribute access away from a verdict message.
    """
    fspath = os.fspath(path)
    try:
        info = os.stat(fspath)
    except OSError as exc:
        logger.debug("state header %s: cannot stat (%s)", fspath, exc)
        return None
    if not stat_module.S_ISREG(info.st_mode):
        logger.debug("state header %s: not a regular file", fspath)
        return None
    if info.st_size > MAX_STATE_BYTES:
        logger.debug("state header %s: %d bytes exceeds MAX_STATE_BYTES=%d; refusing "
                     "to read it", fspath, info.st_size, MAX_STATE_BYTES)
        return None
    try:
        with open(fspath, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.debug("state header %s: cannot be read as JSON (%s)", fspath, exc)
        return None
    if not isinstance(data, Mapping):
        logger.debug("state header %s: top level is %s, not an object",
                     fspath, type(data).__name__)
        return None
    return {key: data[key] for key in STATE_HEADER_KEYS if key in data}


def state_supersession(
        ledger: SourceLedger, *,
        reader: Callable[[str], Mapping[str, Any] | None] | None = None,
) -> tuple[Verdict, ...]:
    """``staleness:serial`` verdicts where a tfstate on disk has moved on.

    Compares each ``tfstate`` source's RECORDED ``serial`` and ``lineage``
    against the header the file carries now. The lineage is checked first and
    short-circuits: a different lineage is a different state history, so its
    serial is not a later version of ours — it is a different number line, and
    comparing the two would report "advanced" or "fine" with equal confidence
    and equal meaninglessness.

    A *reader* returning ``None`` emits NOTHING. Absence of the file is not
    evidence about the snapshot: state moves to a remote backend, a workspace is
    checked out elsewhere, CI captures on one machine and grounds on another.
    Treating "I cannot see it" as "it changed" would make every such setup fail
    permanently, and a check that always fires is a check everybody disables.
    """
    read = read_state_header if reader is None else reader
    verdicts: list[Verdict] = []
    for source_id in sorted(ledger.sources):
        record = ledger.sources[source_id]
        if record.kind != "tfstate" or not record.origin:
            continue
        try:
            header = read(record.origin)
        except OSError as exc:                     # a custom reader may raise
            logger.debug("supersession %s: reader failed (%s)", source_id, exc)
            continue
        if header is None:
            continue
        found_lineage = header.get("lineage")
        if record.lineage and isinstance(found_lineage, str) and found_lineage \
                and found_lineage != record.lineage:
            verdicts.append(Verdict(
                "unverified", "staleness:serial", source_id, 0,
                f"source '{source_id}' ({record.origin}) was captured from tfstate "
                f"lineage '{record.lineage}', but the file on disk carries lineage "
                f"'{found_lineage}' - a different lineage is a different state "
                f"history, so this capture does not describe it; {_DEMOTED}"))
            continue
        found_serial = header.get("serial")
        if record.serial is None or not isinstance(found_serial, int) \
                or isinstance(found_serial, bool):
            continue
        if found_serial > record.serial:
            verdicts.append(Verdict(
                "unverified", "staleness:serial", source_id, 0,
                f"source '{source_id}' ({record.origin}) was captured at tfstate "
                f"serial {record.serial}, but the file on disk is at serial "
                f"{found_serial} - the state has been applied {found_serial - record.serial} "
                f"time(s) since this capture, so it is superseded; {_DEMOTED}"))
    return tuple(verdicts)


# -- the demotion -------------------------------------------------------------


def demote_stale(ledger: SourceLedger,
                 verdicts: Iterable[Verdict]) -> SourceLedger:
    """A NEW ledger whose stale sources' categories are ``uncaptured``/``stale``.

    THE DATA IS UNTOUCHED. Only ``categories`` changes: the facts, the sources,
    the disputes, the artifacts, the census and the alternates come across
    unchanged, and the snapshot the ledger travels beside is never even seen by
    this function.

    THE ASYMMETRY, stated so nobody "fixes" it: a stale source may no longer
    justify a PASS — every absence-reasoning rule calls
    :func:`~gcp_grounding.provenance.require_complete`, which refuses an
    ``uncaptured`` or tainted category — but a ``contradicted`` finding the same
    source supports still STANDS. Verdicts are not rewritten here at all.
    Downgrading findings on age would hand anyone who wants the gate quiet a
    universal suppressor that costs nothing to pull: stop capturing, wait a
    week, and every finding becomes an abstain.
    """
    stale_sources = {v.target for v in verdicts
                     if v.kind in STALENESS_KINDS and v.target}
    if not stale_sources:
        return ledger
    affected: set[str] = set()
    for source_id in sorted(stale_sources):
        affected.update(sourced_categories(ledger, source_id))
    if not affected:
        return ledger
    reason = (f"demoted to 'uncaptured' and tainted 'stale': supplied by "
              f"{', '.join(sorted(stale_sources))}, which is past the freshness "
              f"limit or superseded on disk")
    categories = dict(ledger.categories)
    for category in sorted(affected):
        scope = ledger.scope_of(category)
        categories[category] = dataclasses.replace(
            scope, scope="uncaptured", boundary="",
            taint=compose_taint(scope.taint, "stale"),
            existence_licensed=False, note=_annotate(scope.note, reason))
    logger.debug("demoted %d categor(y|ies) from %d stale source(s)",
                 len(affected), len(stale_sources))
    return dataclasses.replace(ledger, categories=categories)


def evaluate(
        ledger: SourceLedger, *, now: datetime,
        max_age: timedelta | None = MAX_AGE_DEFAULT,
        reader: Callable[[str], Mapping[str, Any] | None] | None = None,
) -> tuple[SourceLedger, tuple[Verdict, ...]]:
    """:func:`check_freshness` then :func:`state_supersession`, then the demotion.

    Returns ``(demoted_ledger, verdicts)`` with the verdicts in that fixed
    order — age first, supersession second — so a report renders the same lines
    in the same sequence on every run.
    """
    verdicts = check_freshness(ledger, now=now, max_age=max_age) \
        + state_supersession(ledger, reader=reader)
    return demote_stale(ledger, verdicts), verdicts
