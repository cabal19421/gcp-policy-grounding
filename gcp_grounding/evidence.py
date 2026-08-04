"""The evidence channel: a typed abstain, a collection-read contract and a
per-invocation ledger.

A check that reads nothing and a check that read a full table and found it
empty are different facts about the world, and the difference is exactly the
one a raw ``doc.get("rules", [])`` throws away. That idiom turns *unreadable*
and *never looked* into *no records*, and "no records" reads as agreement:
the fold reports that the 3-level order decides every packet identically,
having read rules from zero levels. This module is the sanctioned way to
touch a collection so the difference survives to the verdict:

- :class:`NotEvaluated` — the typed abstain. It carries *what* could not be
  evaluated and *why*, and it is an exception so it PROPAGATES: an invoker
  rewrites the whole check to ``unverified`` naming the reason. A return
  value would have been swallowed by the next line.
- :class:`Extraction` — the extraction contract. ``missing_reason`` means
  UNREADABLE or NEVER LOOKED; ``empty_because`` means POSITIVELY OBSERVED
  EMPTY. They are mutually exclusive, and neither may travel with records.
- :class:`Ledger` / :func:`ledger` — what one invocation actually examined.
  An invoker opens exactly one ledger per check and reads it afterwards:
  collections read above zero with rows examined at zero, and no explicit
  attestation, is a decided verdict standing on nothing.

Asymmetry is the point. Every default is abstention::

    rows(policy, "rules", what="policy 'fp-baseline'")
    # absent key           → NotEvaluated("… has no 'rules' key")
    # {"count": 3}         → NotEvaluated("… got dict")
    # []                   → () and an entry in ledger.empty_observed
    # [ {...}, {...} ]     → the two records, both counted

Grounding over nothing stays possible, but it costs one explicit call —
:func:`emptiness_is_dispositive` — whose reason string is greppable, reviewable
and required to be printed in the verdict by the invoker.

This is a LEAF: it imports :mod:`gcp_grounding.core.log` and nothing else from
the package, so every domain module can depend on it and no cycle is possible.
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, Mapping, Sequence

from .core.log import get_logger

logger = get_logger(__name__)

#: :func:`scalar` spells its parameter ``type`` (the name the call sites want),
#: which shadows the builtin inside it; this keeps the builtin reachable.
_type_of = type

__all__ = [
    "NotEvaluated", "Extraction", "Ledger",
    "ledger", "rows", "scalar", "examined",
    "observed_empty", "emptiness_is_dispositive",
]


class NotEvaluated(Exception):
    """The typed abstain: *what* could not be evaluated, and *why*.

    Raised by every read in this module when the input's shape is not the one
    the caller declared. Domain code is expected to let it propagate; the
    invoker turns it into an honest ``unverified`` carrying :attr:`reason`::

        raise NotEvaluated("hierarchical firewall policy 'fp-baseline'",
                           "has no readable 'rules' list, got dict")
    """

    def __init__(self, what: str, reason: str) -> None:
        super().__init__(f"{what}: {reason}")
        #: The thing that could not be evaluated, in reviewer-readable prose.
        self.what = what
        #: Why it could not be — names the offending shape, never just "failed".
        self.reason = reason

    def __str__(self) -> str:
        return f"{self.what}: {self.reason}"


#: What :class:`Extraction` says on behalf of a caller who returned no records
#: and gave no reason. Abstention is the default, including for forgetfulness.
_UNEXPLAINED = ("no records and no reason given: the extractor did not say "
                "whether it looked")


@dataclass(frozen=True)
class Extraction:
    """Records plus the reason there are none — the two never both empty.

    ``missing_reason`` is UNREADABLE or NEVER LOOKED; ``empty_because`` is
    POSITIVELY OBSERVED EMPTY. A caller who returns nothing and explains
    nothing gets :data:`_UNEXPLAINED` synthesized, so the funnel downstream
    always has a sentence to print.
    """

    records: tuple = ()
    missing_reason: str | None = None
    empty_because: str | None = None

    def __post_init__(self) -> None:
        records = self.records
        if (isinstance(records, (str, bytes, Mapping))
                or not isinstance(records, Sequence)):
            raise TypeError(
                f"Extraction.records must be a sequence of records, "
                f"got {type(records).__name__}")
        if not isinstance(records, tuple):
            object.__setattr__(self, "records", tuple(records))

        if self.missing_reason is not None and self.empty_because is not None:
            raise ValueError(
                "Extraction cannot be both unreadable and positively empty: "
                "pass missing_reason OR empty_because, never both")
        if self.records:
            if self.missing_reason is not None:
                raise ValueError(
                    "Extraction with records cannot carry a missing_reason "
                    f"({self.missing_reason!r}): the records were read")
            if self.empty_because is not None:
                raise ValueError(
                    "Extraction with records cannot carry an empty_because "
                    f"({self.empty_because!r}): the records were read")
        elif self.missing_reason is None and self.empty_because is None:
            object.__setattr__(self, "missing_reason", _UNEXPLAINED)


@dataclass
class Ledger:
    """What one invocation examined — the invoker's evidence for a verdict.

    ``collections_read`` counts every read ATTEMPTED through this module,
    including the ones that abstained, so a caller who swallows a
    :class:`NotEvaluated` and decides anyway still shows up as "read
    something, examined nothing".
    """

    collections_read: int = 0
    rows_examined: int = 0
    empty_observed: tuple[str, ...] = ()
    dispositive: str | None = None

    def _note_empty(self, note: str) -> None:
        self.empty_observed = self.empty_observed + (note,)


_LEDGER: contextvars.ContextVar[Ledger | None] = contextvars.ContextVar(
    "gcp_grounding_evidence_ledger", default=None)


@contextmanager
def ledger() -> Iterator[Ledger]:
    """Open THE ledger for one invocation. Only an invoker may call this.

    Nesting is an error rather than a silent reset — two nested opens would
    mean two checks sharing one invocation's evidence, and the inner exit
    would erase the outer's counts. The var is reset in a ``finally`` so a
    check that raises cannot leak its ledger into the next invocation.
    """
    live = _LEDGER.get()
    if live is not None:
        raise RuntimeError(
            "an evidence ledger is already open (collections_read="
            f"{live.collections_read}); ledger() is opened once per invocation "
            "by the invoker, and nesting would hide one check's evidence "
            "inside another's")
    fresh = Ledger()
    token = _LEDGER.set(fresh)
    try:
        yield fresh
    finally:
        _LEDGER.reset(token)


def _bound(operation: str) -> Ledger:
    """The open ledger, or a programming error naming the unbound operation."""
    live = _LEDGER.get()
    if live is None:
        raise RuntimeError(
            f"{operation} was called with no evidence ledger open: every "
            "check runs inside `with ledger():` opened by its invoker, so "
            "that what it examined can be counted")
    return live


def rows(container: Any, key: str, *, what: str) -> tuple:
    """Read ``container[key]`` as a list of records. The only sanctioned read.

    Returns the records as a tuple. Returns an EMPTY tuple only when *key* is
    present and holds an empty list — a positive observation, recorded in the
    ledger's ``empty_observed``. Everything else abstains: an absent key, a
    non-Mapping container, and any non-list value (a string and a Mapping
    included — both are iterable, and both are how "no records" gets faked).

    The type that showed up instead is always named in the reason, because
    "could not read the rules" is not actionable and "got dict" is.
    """
    led = _bound("rows()")
    led.collections_read += 1

    if not isinstance(container, Mapping):
        raise NotEvaluated(
            what, f"has no readable {key!r} list: expected a mapping to read "
                  f"{key!r} from, got {type(container).__name__}")
    if key not in container:
        raise NotEvaluated(
            what, f"has no {key!r} key, so its records were never captured")

    value = container[key]
    if not isinstance(value, list):
        raise NotEvaluated(
            what, f"has no readable {key!r} list, got {type(value).__name__}")

    led.rows_examined += len(value)
    if not value:
        led._note_empty(f"{what}: {key!r} is present and holds no records")
        logger.debug("evidence: %s — %r present and empty", what, key)
    return tuple(value)


#: Sentinel for "no default was passed", so ``absent=None`` stays a real,
#: usable default distinct from "raise if the key is missing".
_RAISE = object()


def scalar(container: Any, key: str, *, what: str, type: Any,
           absent: Any = _RAISE) -> Any:
    """Read ``container[key]`` as a single field of *type*.

    Abstains on a wrong type, and — unless an explicit *absent* default is
    passed — on an absent key. A default never excuses a wrong type: a key
    that is there with the wrong shape is unreadable, not missing.

    Needs no ledger: a single field is not a collection, and nothing about it
    can make a verdict non-vacuous.
    """
    expected = type
    if not isinstance(container, Mapping):
        raise NotEvaluated(
            what, f"has no readable {key!r} field: expected a mapping to read "
                  f"{key!r} from, got {_type_of(container).__name__}")
    if key not in container:
        if absent is _RAISE:
            raise NotEvaluated(
                what, f"has no {key!r} key, so its value was never captured")
        return absent

    value = container[key]
    # bool is an int subclass; a flag where a number belongs is a shape
    # surprise, not a number.
    wrong_bool = expected is int and isinstance(value, bool)
    if wrong_bool or not isinstance(value, expected):
        raise NotEvaluated(
            what, f"has a {key!r} that is not a {expected.__name__}, "
                  f"got {_type_of(value).__name__}")
    return value


def examined(n: int, *, what: str) -> None:
    """Count *n* rows reached through a snapshot accessor, not a Mapping read.

    Snapshot tables arrive as attributes, not as ``doc[key]``; without this,
    a check that folded a whole table would look, to the ledger, exactly like
    one that never opened anything. Zero rows out of an accessor is the same
    positive observation :func:`rows` records for a present empty list.
    """
    if isinstance(n, bool) or not isinstance(n, int):
        raise TypeError(f"examined() takes a row count, got {type(n).__name__}")
    if n < 0:
        raise ValueError(f"examined() takes a non-negative row count, got {n}")

    led = _bound("examined()")
    led.collections_read += 1
    led.rows_examined += n
    if n == 0:
        led._note_empty(f"{what}: accessor returned no records")
        logger.debug("evidence: %s — accessor returned no records", what)


def observed_empty(what: str, detail: str) -> Extraction:
    """An extraction that POSITIVELY observed emptiness, and says how it knows.

    This is the honest opposite of ``Extraction()``: the collection was there
    and it held nothing, which is a fact about the estate rather than a hole
    in the capture.
    """
    if not detail or not detail.strip():
        raise ValueError(
            "observed_empty() needs a detail saying how emptiness was "
            "observed; without one the caller means Extraction(), which "
            "abstains")
    return Extraction(empty_because=f"{what}: {detail}")


def emptiness_is_dispositive(reason: str) -> None:
    """Attest that deciding over ZERO examined rows is correct here, and why.

    The one sanctioned way to ground over nothing. Deliberately explicit,
    deliberately greppable: every call site is a line a reviewer can read, and
    the invoker is required to print *reason* in the verdict it emits, so the
    claim "nothing was there, and that settles it" never travels silently.
    """
    if not reason or not reason.strip():
        raise ValueError(
            "emptiness_is_dispositive() needs a reason a reviewer can read; "
            "grounding over nothing is never the default")
    led = _bound("emptiness_is_dispositive()")
    led.dispositive = reason
    logger.debug("evidence: emptiness attested dispositive — %s", reason)
