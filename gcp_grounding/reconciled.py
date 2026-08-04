"""THE canonical current-state object: a snapshot that knows where it came from.

A :class:`ReconciledSnapshot` is what the merge engine hands the grounding
engine — the merged estate data, plus the :class:`~gcp_grounding.provenance
.SourceLedger` that says which source won every fact, the disputes nobody could
resolve, and the name of the precedence policy that decided them.

WHY A SUBCLASS AND NOT A WRAPPER. ``gate.py`` does a real
``isinstance(snapshot, GcpSnapshot)`` check, and ``preflight``, the reasoner,
``constraints.py`` and every domain accessor are typed against ``GcpSnapshot``.
Subclassing the frozen dataclass puts the merged data in the PARENT'S OWN
FIELDS, so every un-overridden method — ``role_exists``, ``org_policy``,
``to_dict``, the lot — works verbatim and not one consumer needs an edit. A
wrapper would have needed a shim per accessor, and every shim is a place for
the merged view and the plain view to answer differently.

THE READ TAP. Inside a :func:`reads` block every category a check touches is
recorded on a :class:`ReadSet`, so an answer can afterwards be qualified by the
coverage and the taints of exactly the facts it was computed from — see
:meth:`ReconciledSnapshot.taints_for`. The tap is a ``__getattribute__``
override over the raw category fields plus a small table of accessor wrappers
installed at import time.

THE CONTRACT, and the three rules that make holding provenance alongside the
data safe:

1. **It is inert when there is nothing to report.** Built with no ledger and no
   disputes, a reconciled snapshot is indistinguishable from the plain snapshot
   it was built from: same equality, same ``to_dict`` bytes, same verdicts out
   of ``preflight.ground_policy``. Provenance is an ADDITION to the estate view,
   never a modification of it.
2. **The tap only RECORDS; it never changes an answer.** Every accessor returns
   exactly what the parent returns, and the recording happens beside the return
   value, not in place of it. A tap that could alter an answer would make the
   estate depend on who was watching.
3. **No lookup result is ever suppressed.** It is tempting to hide a fact whose
   provenance is weak — a fact only terraform saw, a disputed record. That would
   be unsound in the one direction that matters: a category declared *complete*
   licenses reasoning from absence, so removing a row from it would let a check
   prove a non-existence that is not proven. Weak provenance is REPORTED
   (through the ledger and :meth:`ReconciledSnapshot.require_complete`), never
   subtracted.
"""

from __future__ import annotations

import dataclasses
from contextlib import contextmanager
from typing import Any, Iterable, Iterator

from . import provenance
from .core.log import get_logger
from .knowledge import GcpSnapshot
from .provenance import Dispute, SourceLedger

logger = get_logger(__name__)

__all__ = [
    "ReadSet",
    "ReconciledSnapshot",
    "WRAPPED_ACCESSORS",
    "active_reads",
    "note_read",
    "reads",
]


# -- the read tap -------------------------------------------------------------
#
# `_TAPPED` and `_ACTIVE_READS` are MODULE-level, deliberately: the
# `__getattribute__` override below must be able to decide whether to record
# without touching instance state, because reading instance state is the very
# thing it intercepts. A per-instance flag would recurse on its own first read.

#: The raw snapshot fields a read is recorded for — the estate categories and
#: nothing else. ``captured_at`` is capture metadata, not a fact any check
#: reasons from, so tapping it would only add noise to every read set.
_TAPPED = frozenset(provenance.CATEGORIES)

#: The LIFO stack of read sets currently collecting. Every active set receives
#: every read (see :func:`note_read`), so an outer set is a superset of every
#: set nested inside it and a caller never has to re-run a check to widen it.
_ACTIVE_READS: list["ReadSet"] = []


class ReadSet:
    """The ``(category, key)`` facts one check read, in first-seen order.

    A key of ``""`` means the WHOLE category was read: either a raw field access
    (``snapshot.firewall_rules``) or a table-wide accessor, whose answer depends
    on every row and therefore on the category's whole coverage.

    Deduplicated, because a check that consults one key twice has not read
    anything more than a check that consults it once.
    """

    __slots__ = ("label", "_reads", "_seen")

    def __init__(self, label: str = "") -> None:
        self.label = label
        self._reads: list[tuple[str, str]] = []
        self._seen: set[tuple[str, str]] = set()

    def record(self, category: str, key: str = "") -> None:
        """Note a read of *key* in *category* (``""`` = the whole category)."""
        item = (category, key)
        if item not in self._seen:
            self._seen.add(item)
            self._reads.append(item)

    @property
    def reads(self) -> tuple[tuple[str, str], ...]:
        """Every recorded ``(category, key)``, in first-seen order."""
        return tuple(self._reads)

    def categories(self) -> tuple[str, ...]:
        """Every category touched, sorted."""
        return tuple(sorted({category for category, _ in self._reads}))

    def keys_of(self, category: str) -> tuple[str, ...]:
        """The individual keys read in *category*, in first-seen order. A
        whole-category read contributes no key, so an empty tuple here does NOT
        mean the category went untouched — ask :meth:`categories` for that."""
        return tuple(key for name, key in self._reads if name == category and key)

    def __contains__(self, item: object) -> bool:
        return tuple(item) in self._seen if isinstance(item, tuple) else False

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self._reads)

    def __len__(self) -> int:
        return len(self._reads)

    def __repr__(self) -> str:
        label = f"{self.label!r}, " if self.label else ""
        return f"ReadSet({label}{len(self._reads)} read(s))"


def note_read(category: str, key: str = "") -> None:
    """Record a read on EVERY active read set, innermost and outermost alike.

    Nesting is additive rather than exclusive: a sidecar that opens its own set
    inside a check the caller is already watching must not steal the read from
    the caller's set, or the outer set would describe a check that demonstrably
    read more than it says.
    """
    for read_set in _ACTIVE_READS:
        read_set.record(category, key)


@contextmanager
def reads(label: str = "") -> Iterator[ReadSet]:
    """Collect every estate read made inside the block.

    The set is popped in a ``finally``, so an exception mid-check unwinds the
    stack exactly as a clean return does — a leaked entry would go on silently
    collecting another check's reads for the rest of the process.
    """
    read_set = ReadSet(label)
    _ACTIVE_READS.append(read_set)
    try:
        yield read_set
    finally:
        # By identity and from the top: LIFO in every ordinary case, and correct
        # even if a caller closed two blocks out of order.
        for index in range(len(_ACTIVE_READS) - 1, -1, -1):
            if _ACTIVE_READS[index] is read_set:
                del _ACTIVE_READS[index]
                break


def active_reads() -> tuple[ReadSet, ...]:
    """The read sets currently collecting, outermost first."""
    return tuple(_ACTIVE_READS)


# -- which accessor reads which category --------------------------------------

#: Keyed accessor → the category its answer comes from. The read key is the
#: accessor's FIRST positional argument.
#:
#: ``permission_exists`` is listed under ``permissions`` even though it also
#: consults every captured role: only the explicit enumeration can prove the
#: negative, and the roles it reads on the way are recorded anyway by the raw
#: field tap.
_KEYED_ACCESSORS = {
    "role_exists": "roles",
    "permission_exists": "permissions",
    "principal_exists": "principals",
    "constraint": "constraints",
    "resource_type_exists": "resource_types",
    "network_exists": "networks",
    "subnetwork_exists": "subnetworks",
    "network_tag_exists": "network_tags",
    "service_account_exists": "service_accounts",
    "access_level_exists": "access_levels",
    "restricted_service_exists": "restricted_services",
    "firewall_rule": "firewall_rules",
    "hierarchical_firewall_policy": "hierarchical_firewall_policies",
    "cloud_armor_policy": "cloud_armor_policies",
    "vpc_sc_perimeter": "vpc_sc_perimeters",
    "hierarchy_node": "resource_hierarchy",
    "iam_binding_set": "iam_bindings",
}

#: The one accessor whose key has two parts. ``org_policy(node, constraint)``
#: builds the ``"<node>|<constraint>"`` key itself so no caller hand-joins it,
#: and the read is noted under that SAME composite key — noting the node alone
#: would name a key the ledger has no origin for.
_COMPOSITE_ACCESSORS = {
    "org_policy": "org_policies",
}

#: Table-wide accessors. Their result is a sweep, so it depends on every row:
#: the read is the WHOLE category and no key is noted. Recording the argument as
#: a key would be a lie — the network name is a filter, not a lookup key, and a
#: missing row changes the answer just as much as the matching ones do.
_TABLE_ACCESSORS = {
    "firewall_rules_for_network": "firewall_rules",
    "firewall_policies_attached_to": "hierarchical_firewall_policies",
}


def _keyed_wrapper(name: str, category: str, method: Any) -> Any:
    def wrapper(self: "ReconciledSnapshot", key: str, *args: Any, **kwargs: Any) -> Any:
        note_read(category, str(key))
        return method(self, key, *args, **kwargs)

    return _named(wrapper, name, method,
                  f"Reads ``{category}[<key>]``; recorded on every active ReadSet.")


def _composite_wrapper(name: str, category: str, method: Any) -> Any:
    def wrapper(self: "ReconciledSnapshot", node: str, constraint: str,
                *args: Any, **kwargs: Any) -> Any:
        note_read(category, f"{node}|{constraint}")
        return method(self, node, constraint, *args, **kwargs)

    return _named(wrapper, name, method,
                  f"Reads ``{category}['<node>|<constraint>']`` — the COMPOSITE "
                  f"key, which is the key the ledger holds an origin for.")


def _table_wrapper(name: str, category: str, method: Any) -> Any:
    def wrapper(self: "ReconciledSnapshot", *args: Any, **kwargs: Any) -> Any:
        note_read(category)
        return method(self, *args, **kwargs)

    return _named(wrapper, name, method,
                  f"Sweeps ``{category}``, so the read is the WHOLE category: "
                  f"the answer depends on every row, present and absent.")


def _named(wrapper: Any, name: str, method: Any, note: str) -> Any:
    """Give *wrapper* the wrapped method's identity, keeping its docstring
    reachable — a tap that hid the parent's contract would cost more than it
    records."""
    wrapper.__name__ = name
    wrapper.__qualname__ = f"ReconciledSnapshot.{name}"
    inherited = getattr(method, "__doc__", "") or ""
    wrapper.__doc__ = f"{note}\n\n{inherited}".rstrip()
    return wrapper


def _install_wrappers() -> tuple[str, ...]:
    """Install one wrapper per accessor the parent ACTUALLY HAS, at import time.

    The ``hasattr`` guard is what lets this module import on a tree where the
    estate record tables have not landed: a missing accessor is simply not
    wrapped, rather than an ``AttributeError`` at import that would take the
    whole gate down with it.
    """
    installed: list[str] = []
    for table, factory in ((_KEYED_ACCESSORS, _keyed_wrapper),
                           (_COMPOSITE_ACCESSORS, _composite_wrapper),
                           (_TABLE_ACCESSORS, _table_wrapper)):
        for name, category in table.items():
            method = getattr(GcpSnapshot, name, None)
            if method is None:
                logger.debug("reconciled: %s has no %s accessor — not tapped",
                             GcpSnapshot.__name__, name)
                continue
            setattr(ReconciledSnapshot, name, factory(name, category, method))
            installed.append(name)
    return tuple(installed)


# -- the snapshot -------------------------------------------------------------


class ReconciledSnapshot(GcpSnapshot):
    """A :class:`~gcp_grounding.knowledge.GcpSnapshot` that knows its sources.

    NOT decorated as a dataclass, on purpose. ``@dataclass`` would regenerate
    ``__eq__``, and a generated ``__eq__`` returns ``NotImplemented`` unless
    ``other.__class__ is self.__class__`` — so a reconciled snapshot would
    compare UNEQUAL to a plain one holding identical fields, and every
    golden-output test in the repo would start failing for a reason that has
    nothing to do with what it tests. See :meth:`__eq__`.
    """

    #: The provenance sidecar for the merged data, or ``None`` when this object
    #: was built from a single unattributed capture.
    ledger: SourceLedger | None
    #: Disagreements the merge could not resolve. Reported, never subtracted.
    disputes: tuple[Dispute, ...]
    #: The precedence policy that decided the winners, named so a report can
    #: say which rules produced this view.
    policy_name: str

    def __init__(self, *args: Any, ledger: SourceLedger | None = None,
                 disputes: Iterable[Dispute] = (), policy_name: str = "",
                 **kwargs: Any) -> None:
        # The parent's generated __init__ takes captured_at plus the eighteen
        # categories and writes them through object.__setattr__; forwarding
        # verbatim keeps ONE definition of what a snapshot's fields are.
        super().__init__(*args, **kwargs)
        if ledger is not None and not isinstance(ledger, SourceLedger):
            raise ValueError(f"ReconciledSnapshot.ledger must be a SourceLedger or "
                             f"None, got {type(ledger).__name__}")
        object.__setattr__(self, "ledger", ledger)
        object.__setattr__(self, "disputes", tuple(disputes))
        object.__setattr__(self, "policy_name", str(policy_name))

    @classmethod
    def from_snapshot(cls, snapshot: GcpSnapshot, *,
                      ledger: SourceLedger | None = None,
                      disputes: Iterable[Dispute] = (),
                      policy_name: str = "") -> "ReconciledSnapshot":
        """Re-seat an existing snapshot's fields on a reconciled one.

        Field-by-field off the PARENT's field list, so a category added to
        ``GcpSnapshot`` is carried across without an edit here.
        """
        fields = {f.name: getattr(snapshot, f.name)
                  for f in dataclasses.fields(GcpSnapshot)}
        return cls(ledger=ledger, disputes=disputes, policy_name=policy_name, **fields)

    # -- equality across the class boundary -----------------------------------

    def __eq__(self, other: object) -> bool:
        """Field-by-field against ANY ``GcpSnapshot``, plain or reconciled.

        The whole point of the hand-written version: the dataclass-generated one
        compares ``other.__class__ is self.__class__`` first, which would make
        ``ReconciledSnapshot(...) == GcpSnapshot(...)`` false for two objects
        holding byte-identical estate data. Provenance is not part of estate
        identity, so it is not compared — two views of the same estate that
        merged from different sources ARE the same estate.
        """
        if not isinstance(other, GcpSnapshot):
            return NotImplemented
        return all(getattr(self, f.name) == getattr(other, f.name)
                   for f in dataclasses.fields(GcpSnapshot))

    def __ne__(self, other: object) -> bool:
        """The negation of :meth:`__eq__`, propagating ``NotImplemented`` so
        Python still gets to try the reflected operand."""
        equal = self.__eq__(other)
        if equal is NotImplemented:
            return NotImplemented
        return not equal

    #: Explicitly unhashable, matching the parent in practice: its dict-valued
    #: categories make ``hash()`` raise on any snapshot that captured a record
    #: table, and a subclass that was hashable for SOME field combinations would
    #: be a worse contract than one that is never hashable.
    __hash__ = None  # type: ignore[assignment]

    # -- the raw field tap ----------------------------------------------------

    def __getattribute__(self, name: str) -> Any:
        """Record a whole-category read of the raw estate fields.

        CANNOT RECURSE: the value comes from ``object.__getattribute__`` and the
        decision to record is made entirely from module-level state, so nothing
        here re-enters this method.

        Recording happens AFTER the lookup, so an attribute that does not exist
        raises exactly as it always did and is not recorded as a read.
        """
        value = object.__getattribute__(self, name)
        if name in _TAPPED and _ACTIVE_READS:
            note_read(name)
        return value

    # -- provenance surface ---------------------------------------------------

    def require_complete(self, category: str, *, rule: str | None = None) -> str | None:
        """``None`` if absence in *category* may be read as non-existence, else
        the reason it may not — :func:`gcp_grounding.provenance.require_complete`
        over this snapshot's own ledger.

        Delegated rather than reimplemented: the absence predicate is THE rule
        that decides whether a negative is earned, and a second copy of it here
        would be a second place for it to be wrong. With no ledger the snapshot
        itself is the source, which is the plain-``GcpSnapshot`` semantics
        (a captured category reads as complete) — so an inert reconciled
        snapshot answers exactly as the object it was built from.
        """
        source = self.ledger if self.ledger is not None else self
        return provenance.require_complete(source, category, rule=rule)

    def taints_for(self, read_set: Iterable[tuple[str, str]]
                   ) -> tuple[tuple[str, str, str], ...]:
        """Every taint the reads in *read_set* touched, as sorted
        ``(category, key, taint)`` triples. Untainted reads are omitted, so an
        answer computed from clean facts produces an empty tuple.

        COARSENESS, stated rather than hidden: the category arm reports a
        CATEGORY-WIDE taint for a read of any single key in it, because
        :meth:`~gcp_grounding.provenance.SourceLedger.taint_of` falls back to the
        category's taint when the individual fact carries none. A stale capture
        therefore taints every key read out of it, including keys that happen to
        agree with every other source. That is deliberate: a coarse taint over-
        reports doubt, and over-reported doubt costs a re-capture while
        under-reported doubt costs a wrong verdict.
        """
        if self.ledger is None:
            return ()
        found: dict[tuple[str, str], str] = {}
        for category, key in read_set:
            if key:
                taint = self.ledger.taint_of(category, key)
            else:
                taint = self.ledger.scope_of(category).taint
            if taint:
                found[(category, key)] = taint
        return tuple((category, key, found[(category, key)])
                     for category, key in sorted(found))

    def disputes_for(self, category: str, key: str) -> tuple[Dispute, ...]:
        """Every unresolved disagreement about ``(category, key)``. Never
        raises, and never filters the estate: a disputed record is still
        returned by its accessor."""
        return tuple(d for d in self.disputes
                     if d.category == category and d.key == key)


#: The accessors actually tapped on this tree, in installation order — short of
#: the full table wherever the parent has not grown that accessor yet.
WRAPPED_ACCESSORS = _install_wrappers()
