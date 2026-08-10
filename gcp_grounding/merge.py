"""PRECEDENCE SELECTS A VALUE, IT NEVER SUPPRESSES A FINDING.

Whichever side wins a reconciliation, the loser is RECORDED — as a
:class:`gcp_grounding.provenance.Dispute` for the field-level disagreement and
as a whole record in :attr:`MergeResult.alternates` so a pair check can be
re-run against it. That is what stops ``--precedence`` from becoming a way to
silence a disagreement, and it is asserted end to end by running the same
disagreement under two OPPOSITE precedences and checking that both report it.

THE ONE resolution engine. :func:`resolve` consumes an iterable of
:class:`gcp_grounding.facts.Fact` from ANY mix of sources and returns a
:class:`MergeResult`. Assembling three terraform tiers and merging an API
snapshot with a terraform snapshot are LITERALLY THE SAME CALL: there is no
tier merger inside ``tfsource``, no snapshot-level merger beside this one, and
no per-target precedence resolution anywhere else. A second implementation of a
winner rule is a second place for it to be wrong, silently.

PURE: no snapshot, no I/O, no clock. This module never imports
:mod:`gcp_grounding.knowledge`.

THE ALGORITHM, in exactly this order, and the reason each step is where it is:

1. PARTITION proposed-side facts into :attr:`MergeResult.dropped` with a note.
   This is the SECOND enforcement point after :class:`~gcp_grounding.facts.TfObject`'s
   side invariant, so a proposed change can never be laundered into current state.
2. CANONICALISE keys through :func:`gcp_grounding.identity.canonical_key` with
   an alias map built from EVERY contributor's ``resource_hierarchy``. An
   :class:`~gcp_grounding.identity.AmbiguousKey` is NOT merged: the fact is kept
   under its RAW key, tainted ``unmergeable``, recorded in
   :attr:`MergeResult.unresolved_aliases`, and yields one unmergeable dispute
   carrying the exception's reason.
3. GROUP by ``(category, key)``.
4. FRAGMENT ASSEMBLY, per source. A fragment fact contributes only its
   LIST-valued fields, concatenated onto that source's base record or onto an
   empty record plus a note when a rule resource's parent policy is not in the
   same artifact. Fragments are ordered by the record's ``priority`` (defaulting
   to a very large number) then by address, because priority is SEMANTIC for
   firewall and Cloud Armor rules. Exact duplicates collapse. A list field that
   is not being assembled from fragments is NEVER sorted.
5. WINNER. The highest-rank source under the policy takes the record WHOLESALE.
   A merged record is never field-spliced, because a half-and-half record would
   describe a configuration that exists nowhere and every downstream check would
   be reasoning about a fiction.
6. BACKFILL, the one exception to step 5 and deliberately a narrow one. A field
   the winner left UNRESOLVED — carrying a marker, or absent while the winning
   fact's own ``unresolved`` names it — is taken from a lower-fidelity RESOLVED
   value and named in :attr:`MergeResult.backfilled`. A resolved fact at lower
   fidelity genuinely beats an unresolved one at higher fidelity. A field the
   winner is simply SILENT about is not backfilled: that silence is the winner's
   record, and splicing over it is the fiction step 5 refuses.
7. DISPUTES from :func:`gcp_grounding.compare.compare` on every co-present pair,
   after a canonicalisation pass so a spurious row cannot come from an encoding
   difference, and only where the other side has a genuine differing VALUE
   rather than simply being absent.
8. EXISTENCE DISAGREEMENT, with its directionality. Present in a source and
   ABSENT from a COMPLETE enumeration is ``material``: the fact is KEPT, tainted
   ``disputed``, and the reason says it may have been destroyed or moved out of
   band. The REVERSE — present in a complete enumeration and absent from a
   terraform source — is severity ``unmanaged``, NEVER material, because
   unmanaged resources are normal in a partially adopted estate. And when the
   other side's scope is not ``complete``, the key is simply sole-sourced and
   produces NO dispute at all, because absence from a partial view is not
   evidence.
9. FLAT VOCABULARIES ARE UNIONED and precedence is not consulted — but the union
   is RESTRICTED BY FIDELITY, and this restriction is load-bearing. "A union
   never loses a positive" is true of sources that OBSERVED reality and exactly
   BACKWARDS for a desired-state one: ``hcl`` is configuration that may never
   have been applied, so unioning it into the existence vocabulary MANUFACTURES
   positives, and ``reasoner.ground_existence`` then answers ``grounded`` for a
   network, subnetwork, service account, access level or restricted service that
   does not exist. That defeats hallucination detection, which is this repo's
   primary value. So only sources at or above :data:`EMIT_FIDELITY_FLOOR`
   contribute to the EMITTED vocabulary; a name seen ONLY below it goes into
   :attr:`MergeResult.declared_not_applied` and NOT into any flat table, so it
   can never mint a ``grounded``. It must not mint a false ``ungrounded``
   either: ``drift.postpass`` rewrites an ``ungrounded`` naming a member of that
   set to ``unverified`` with :data:`DECLARED_NOT_APPLIED_REASON`. Net effect:
   ``unverified``, never ``grounded``, never a confident false absence.
9a. THE SYSTEMATIC-MISS DIAGNOSTIC, merge's analogue of
   ``baseline:key-mismatch``. Step 8 only fires when the OTHER side's scope is
   ``complete``, so in the very common terraform-plus-terraform configuration a
   systematic key mismatch yields two rows for one resource in one table, ZERO
   disputes and no drift detection for that category. So: per category, when two
   sources EACH contributed at least :data:`MIN_KEYS_FOR_MISMATCH` facts and the
   intersection of their canonical key sets is EMPTY, emit exactly one
   ``unverified`` verdict of kind ``drift:key-mismatch``. It never changes a
   resolution and never suppresses a fact.
10. SCOPE COMPOSITION through :func:`gcp_grounding.provenance.compose_scope`,
   whose commutativity and associativity is what makes merge ORDER-INDEPENDENT.
11. DETERMINISM everywhere, plus the postcondition that EVERY input fact appears
   in exactly one resolution's ``contributors`` or in ``dropped``.

SINGLE-SOURCE MERGE IS AN EXACT IDENTITY, including ``captured_at`` and the
captured-category set. The merged ``captured_at`` is the MINIMUM over
contributors, because ``PolicyReport`` stamps every line with it and a merge
must present its OLDEST constituent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from . import claims, compare, facts, identity
from .core.log import get_logger
from .core.report import Verdict
from .provenance import (
    TERRAFORM_SOURCES,
    Alternate,
    CategoryScope,
    Dispute,
    FactOrigin,
    SourceRecord,
    compose_scope,
    compose_taint,
    fidelity_rank,
    scope_rank,
)

logger = get_logger(__name__)

__all__ = [
    "PRECEDENCE",
    "DEFAULT_PRECEDENCE",
    "DEFAULT_CATEGORY_PRECEDENCE",
    "MIN_KEYS_FOR_MISMATCH",
    "EMIT_FIDELITY_FLOOR",
    "FRAGMENT_PRIORITY_LAST",
    "KEY_MISMATCH_KIND",
    "DECLARED_NOT_APPLIED_REASON",
    "PROPOSED_DROP_REASON",
    "PrecedencePolicy",
    "parse_policy",
    "Dropped",
    "Resolution",
    "MergeResult",
    "resolve",
]


# -- the precedence surface ---------------------------------------------------

#: Every precedence mode. ``highest-fidelity-wins`` is the default because it
#: degrades to ``api-wins`` for the api-plus-terraform pair (``api`` already
#: outranks every terraform spelling) while still ordering ``tfstate`` above
#: ``hcl`` when there is no API at all. ``require-agreement`` is defined as
#: exactly ``highest-fidelity-wins`` PLUS escalation of every material
#: disagreement.
PRECEDENCE = ("api-wins", "terraform-wins", "highest-fidelity-wins",
              "require-agreement")

#: The default mode. See :data:`PRECEDENCE` for why it is this one.
DEFAULT_PRECEDENCE = "highest-fidelity-wins"

# FLAT VOCABULARIES NEVER CONSULT PRECEDENCE (step 9 unions them under a fidelity
# floor), and `resource_types` is not a terraform-producible category at all —
# facts.EXCLUDED_CATEGORIES refuses it — so neither has an entry here.
#: Category → precedence mode. ``iam_bindings`` is ``api-wins`` because
#: terraform's IAM view is non-authoritative and additive: a
#: ``google_project_iam_member`` speaks for one member and says nothing about
#: the rest of the policy. NOTHING ELSE belongs here.
DEFAULT_CATEGORY_PRECEDENCE: Mapping[str, str] = {
    "iam_bindings": "api-wins",
}

#: How many facts each of two sources must contribute to one category before an
#: empty key intersection is read as a systematic key-form mismatch. One key
#: each is far too easily a legitimately different single resource.
MIN_KEYS_FOR_MISMATCH = 2

#: The weakest source whose names may enter the EMITTED flat vocabulary. See
#: step 9 in the module docstring: everything below this floor is desired state
#: or test scaffolding, and unioning it in manufactures existence positives.
EMIT_FIDELITY_FLOOR = "tfstate"

#: The ``priority`` a fragment with none sorts at — LAST, because a fragment
#: that declines to name its slot must never displace one that did.
FRAGMENT_PRIORITY_LAST = 2 ** 31 - 1

#: The verdict kind step 9a emits. Not a new STATUS: ``unverified`` already
#: means "not decided".
KEY_MISMATCH_KIND = "drift:key-mismatch"

#: Why a name below :data:`EMIT_FIDELITY_FLOOR` is withheld from the emitted
#: vocabulary — and the exact sentence ``drift.postpass`` rewrites a false
#: ``ungrounded`` with.
DECLARED_NOT_APPLIED_REASON = (
    "the name is declared in terraform configuration but not applied"
)

#: Why step 1 partitions a fact out. Stated once so the note cannot drift.
PROPOSED_DROP_REASON = (
    "a PROPOSED change is never current state; it is partitioned out before "
    "reconciliation so it can never be laundered into the merged estate"
)

# Preference TIERS, consulted before fidelity. A mode names the kinds it
# promotes; everything else sits at tier 0 and is ordered by fidelity alone,
# which is what "then falls back to fidelity" means.
_API_TIER = {"explicit-baseline": 2, "api": 1}
_TERRAFORM_TIER = {"tfstate": 3, "tfplan-prior": 2, "hcl": 1}

# compare's severities are this module's severities, spelled once.
_SEVERITY = {
    compare.MATERIAL: "material",
    compare.BENIGN: "benign",
    compare.UNMERGEABLE: "unmergeable",
}

# Which taint a dispute earns the fact it is about. A ``benign`` difference
# grants nothing and an ``unmanaged`` one is normal in a partially adopted
# estate, so neither taints; both are still REPORTED.
_TAINT = {"material": "disputed", "unmergeable": "unmergeable"}


@dataclass(frozen=True)
class PrecedencePolicy:
    """A default mode plus per-category overrides, validating its own fields."""

    default: str = DEFAULT_PRECEDENCE
    categories: Mapping[str, str] = field(
        default_factory=lambda: dict(DEFAULT_CATEGORY_PRECEDENCE))

    def __post_init__(self) -> None:
        if self.default not in PRECEDENCE:
            raise ValueError(f"precedence {self.default!r} is not one of "
                             f"{list(PRECEDENCE)}")
        if not isinstance(self.categories, Mapping):
            raise ValueError(f"PrecedencePolicy.categories must be a mapping of "
                             f"category → precedence, got "
                             f"{type(self.categories).__name__}")
        resolved: dict[str, str] = {}
        for category, mode in self.categories.items():
            name = str(category)
            if name not in identity.SPECS:
                raise ValueError(f"precedence category {name!r} is not an estate "
                                 f"category; expected one of {sorted(identity.SPECS)}")
            if mode not in PRECEDENCE:
                raise ValueError(f"precedence {mode!r} for category {name!r} is not "
                                 f"one of {list(PRECEDENCE)}")
            resolved[name] = mode
        object.__setattr__(self, "categories", resolved)

    def for_category(self, category: str) -> str:
        """The mode that decides a winner in *category*."""
        return self.categories.get(category, self.default)


def parse_policy(spec: str, *, base: PrecedencePolicy | None = None) -> PrecedencePolicy:
    """Parse a precedence spec, MERGING onto the defaults rather than replacing
    them.

    Three accepted shapes, freely combined: a bare mode name
    (``"terraform-wins"``), a mode name plus category assignments
    (``"terraform-wins,iam_bindings=api-wins"``), or assignments alone
    (``"org_policies=terraform-wins"``). Tokens are comma- or
    whitespace-separated.

    Merging rather than replacing is deliberate: ``--precedence terraform-wins``
    must not silently drop the ``iam_bindings`` rule, because terraform's IAM
    view is additive and taking it as authoritative would erase every binding
    terraform does not manage.

    Raises :class:`ValueError` NAMING the offending token.
    """
    policy = base if base is not None else PrecedencePolicy()
    default = policy.default
    categories = dict(policy.categories)
    for token in str(spec).replace(",", " ").split():
        if "=" in token:
            name, _, mode = token.partition("=")
            name, mode = name.strip(), mode.strip()
            if name not in identity.SPECS:
                raise ValueError(f"precedence token {token!r} names category {name!r}, "
                                 f"which is not an estate category; expected one of "
                                 f"{sorted(identity.SPECS)}")
            if mode not in PRECEDENCE:
                raise ValueError(f"precedence token {token!r} names precedence "
                                 f"{mode!r}, which is not one of {list(PRECEDENCE)}")
            categories[name] = mode
            continue
        if token not in PRECEDENCE:
            raise ValueError(f"unknown precedence token {token!r}; expected one of "
                             f"{list(PRECEDENCE)} or '<category>=<precedence>'")
        default = token
    return PrecedencePolicy(default=default, categories=categories)


# -- the output ---------------------------------------------------------------


@dataclass(frozen=True)
class Dropped:
    """One input fact that reached no resolution, and why.

    Every input fact appears in exactly one resolution's ``contributors`` or
    here; nothing evaporates.
    """

    fact: facts.Fact
    note: str = ""


@dataclass(frozen=True)
class Resolution:
    """One ``(category, key)``, resolved.

    ``record`` is ``None`` for a flat vocabulary, whose name IS its content.
    ``origin`` names the WINNING source and its locator (the terraform address
    for a terraform-derived fact), which is what makes
    :meth:`gcp_grounding.provenance.SourceLedger.by_locator` the primary lookup.
    ``contributors`` is every input fact that landed on this key, winner and
    losers alike.
    """

    category: str
    key: str
    record: Mapping[str, Any] | None
    origin: FactOrigin
    contributors: tuple[facts.Fact, ...] = ()
    taint: str = ""
    backfilled: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class MergeResult:
    """Everything one reconciliation decided, and everything it refused to.

    The first eight fields are the design's output tuple. ``captured_at``,
    ``declared_not_applied`` and ``verdicts`` follow it because steps 9, 9a and
    the ``captured_at`` minimum have to be observable somewhere and none of them
    fits inside a resolution: a withheld vocabulary name has no resolution by
    construction, a key-mismatch verdict is about a CATEGORY rather than a key,
    and the merged timestamp is a property of the source set.
    """

    resolutions: tuple[Resolution, ...] = ()
    disputes: tuple[Dispute, ...] = ()
    scopes: Mapping[str, CategoryScope] = field(default_factory=dict)
    alternates: Mapping[str, Mapping[str, tuple[Alternate, ...]]] = field(
        default_factory=dict)
    unresolved_aliases: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    backfilled: Mapping[str, Mapping[str, tuple[str, ...]]] = field(default_factory=dict)
    dropped: tuple[Dropped, ...] = ()
    notes: tuple[str, ...] = ()
    captured_at: str = ""
    declared_not_applied: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    verdicts: tuple[Verdict, ...] = ()

    def resolution(self, category: str, key: str) -> Resolution | None:
        """The resolution for ``(category, key)``, or ``None``. Never raises."""
        for item in self.resolutions:
            if item.category == category and item.key == key:
                return item
        return None

    def keys_of(self, category: str) -> tuple[str, ...]:
        """Every resolved key in *category*, sorted."""
        return tuple(sorted(r.key for r in self.resolutions if r.category == category))

    def origins(self) -> dict[str, dict[str, FactOrigin]]:
        """``category → key → FactOrigin``, exactly the shape
        :attr:`gcp_grounding.provenance.SourceLedger.facts` holds — so the
        ledger is BUILT from this rather than indexed a second time."""
        out: dict[str, dict[str, FactOrigin]] = {}
        for item in self.resolutions:
            out.setdefault(item.category, {})[item.key] = item.origin
        return out

    def disputes_for(self, category: str, key: str) -> tuple[Dispute, ...]:
        """Every dispute about ``(category, key)``."""
        return tuple(d for d in self.disputes
                     if d.category == category and d.key == key)


# -- small shared helpers -----------------------------------------------------


def _source_id(fact: facts.Fact) -> str:
    """The fact's SOURCE identity: the artifact it was read from, falling back
    to its fidelity spelling when the reader named no artifact."""
    return fact.origin or fact.source


def _is_list(value: Any) -> bool:
    return isinstance(value, (list, tuple))


def _frozen(value: Any) -> Any:
    """A hashable form for duplicate collapse. A value :func:`claims.freeze`
    refuses (an :class:`~gcp_grounding.facts.Unresolved`, say) falls back to its
    repr, which is stable and — for a marker — detail-free by construction."""
    try:
        return claims.freeze(value)
    except ValueError:
        return ("<unfrozen>", repr(value))


def _render(value: Any) -> str:
    """A bounded rendering for a :class:`Dispute` side."""
    return facts.truncate(repr(value))


def _fragment_priority(record: Any) -> int:
    """A fragment's slot, defaulting to LAST. Priority is SEMANTIC for firewall
    and Cloud Armor rules, which is the whole reason fragments are ordered."""
    value = record.get("priority") if isinstance(record, Mapping) else None
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return FRAGMENT_PRIORITY_LAST
    try:
        return int(str(value).strip())
    except ValueError:
        return FRAGMENT_PRIORITY_LAST


def _fact_sort_key(fact: facts.Fact) -> tuple[str, str, str, str]:
    return (_source_id(fact), fact.address, fact.fragment, fact.key)


class _AliasSource:
    """The one attribute :func:`gcp_grounding.identity.alias_map` reads. Built
    from EVERY contributor's ``resource_hierarchy`` facts, because a project
    number captured by one source is resolved by another source's node table."""

    __slots__ = ("resource_hierarchy",)

    def __init__(self, table: Mapping[str, Any]) -> None:
        self.resource_hierarchy = table


class _Pending:
    """One ``(category, key)`` under construction. Mutable on purpose: step 8
    can taint a resolution built in step 5, and a frozen
    :class:`Resolution` is minted only once every step has run."""

    __slots__ = ("category", "key", "record", "source_id", "locator",
                 "contributors", "taint", "backfilled", "notes")

    def __init__(self, category: str, key: str) -> None:
        self.category = category
        self.key = key
        self.record: Mapping[str, Any] | None = None
        self.source_id = ""
        self.locator = ""
        self.contributors: list[facts.Fact] = []
        self.taint = ""
        self.backfilled: list[str] = []
        self.notes: list[str] = []

    def freeze(self) -> Resolution:
        return Resolution(
            category=self.category, key=self.key, record=self.record,
            origin=FactOrigin(source_id=self.source_id, locator=self.locator,
                              taint=self.taint),
            contributors=tuple(sorted(self.contributors, key=_fact_sort_key)),
            taint=self.taint, backfilled=tuple(self.backfilled),
            notes=tuple(self.notes))


# -- the engine ---------------------------------------------------------------


def resolve(input_facts: Iterable[facts.Fact], *,
            sources: Iterable[SourceRecord] = (),
            policy: PrecedencePolicy | None = None,
            category_scopes: Mapping[str, Mapping[str, str]] | None = None,
            ) -> MergeResult:
    """Reconcile *input_facts* from ANY mix of sources into one
    :class:`MergeResult`.

    *sources* declares each contributor: its fidelity ``kind``, its
    ``captured_at`` and the coverage it claims. A source a fact names but which
    was never declared is treated as ``undeclared`` coverage — covered, but not
    licensed to conclude an absence — and noted, because inferring completeness
    from content is exactly how a terraform capture gets read as an API one.

    *category_scopes* refines a source's scope PER CATEGORY (``source_id →
    category → scope``). Without it a source's declared scope applies to every
    category it contributed a fact to, and to no others: a category a source
    said nothing about is ``uncaptured`` from that source, never empty. The
    override is what lets a source declare a COMPLETE enumeration that happens
    to be empty — the one coverage claim its facts cannot express.

    Order-independent, deterministic, and pure: no snapshot, no I/O, no clock.
    """
    return _Merger(input_facts, sources=sources, policy=policy,
                   category_scopes=category_scopes).run()


class _Merger:
    """One :func:`resolve` call's state. Private: the entry point is the
    function, so there is exactly one way to run a merge."""

    def __init__(self, input_facts: Iterable[facts.Fact], *,
                 sources: Iterable[SourceRecord],
                 policy: PrecedencePolicy | None,
                 category_scopes: Mapping[str, Mapping[str, str]] | None) -> None:
        self.inputs = list(input_facts)
        for item in self.inputs:
            if not isinstance(item, facts.Fact):
                raise TypeError(f"merge.resolve takes facts.Fact objects, got "
                                f"{type(item).__name__}")
        if policy is not None and not isinstance(policy, PrecedencePolicy):
            raise TypeError(f"merge.resolve policy must be a PrecedencePolicy, got "
                            f"{type(policy).__name__}")
        self.policy = policy if policy is not None else PrecedencePolicy()
        self.declared: dict[str, SourceRecord] = {}
        for record in sources:
            if not isinstance(record, SourceRecord):
                raise TypeError(f"merge.resolve sources must be provenance."
                                f"SourceRecord objects, got {type(record).__name__}")
            self.declared[record.source_id] = record
        self.category_scopes = {str(sid): {str(c): str(s) for c, s in table.items()}
                                for sid, table in (category_scopes or {}).items()}

        self.notes: list[str] = []
        self.dropped: list[Dropped] = []
        self.disputes: list[Dispute] = []
        self.verdicts: list[Verdict] = []
        self.unresolved_aliases: dict[str, dict[str, str]] = {}
        self.backfilled: dict[str, dict[str, tuple[str, ...]]] = {}
        self.alternates: dict[str, dict[str, list[Alternate]]] = {}
        self.declared_not_applied: dict[str, set[str]] = {}
        self.pending: dict[tuple[str, str], _Pending] = {}

        self.kinds: dict[str, str] = {}
        self.contributed: dict[str, set[str]] = {}

    # -- source bookkeeping ---------------------------------------------------

    def _kind(self, source_id: str) -> str:
        record = self.declared.get(source_id)
        if record is not None:
            return record.kind
        return self.kinds.get(source_id, "unattributed")

    def _record(self, source_id: str) -> SourceRecord:
        record = self.declared.get(source_id)
        if record is not None:
            return record
        # UNDECLARED, never complete: completeness is declared by a caller or
        # read from a sidecar, and is never inferred from content.
        synthesized = SourceRecord(source_id=source_id, kind=self._kind(source_id),
                                   scope="undeclared")
        self.declared[source_id] = synthesized
        self.notes.append(
            f"source '{source_id}' contributed facts but was never declared; its "
            f"coverage is 'undeclared' - covered, but not licensed to conclude an "
            f"absence")
        return synthesized

    def _scope_of(self, source_id: str, category: str) -> tuple[str, str]:
        """What *source_id* claims to cover in *category*, as a
        ``(scope, boundary)`` pair :func:`compose_scope` accepts."""
        record = self._record(source_id)
        override = self.category_scopes.get(source_id, {}).get(category)
        if override is not None:
            scope = override
            scope_rank(scope)                    # raises on an unknown spelling
        elif category in self.contributed.get(source_id, ()):
            scope = record.scope
        else:
            return "uncaptured", ""
        if scope == "uncaptured":
            return "uncaptured", ""
        if record.kind in TERRAFORM_SOURCES and scope_rank(scope) > scope_rank("partial"):
            # A terraform artifact covers only what terraform manages. Coerced
            # rather than refused, exactly as SourceRecord does it.
            scope = "partial"
        return scope, record.boundary

    def _sources_over(self, category: str) -> list[str]:
        """Every source that declared coverage of *category*, sorted."""
        out = {sid for sid, cats in self.contributed.items() if category in cats}
        for sid, table in self.category_scopes.items():
            if table.get(category, "uncaptured") != "uncaptured":
                out.add(sid)
        return sorted(out)

    # -- the run --------------------------------------------------------------

    def run(self) -> MergeResult:
        kept = self._partition()                                  # step 1
        canonical = self._canonicalise(kept)                      # step 2
        groups = self._group(canonical)                           # step 3
        for (category, key) in sorted(groups):
            group = groups[(category, key)]
            if category in facts.FLAT_CATEGORIES:
                self._resolve_flat(category, key, group)          # step 9
            else:
                self._resolve_table(category, key, group)         # steps 4-7
        self._existence()                                         # step 8
        self._key_mismatch(canonical)                             # step 9a
        scopes = self._compose_scopes()                           # step 10
        return self._build(scopes)                                # step 11

    # -- step 1 ---------------------------------------------------------------

    def _partition(self) -> list[facts.Fact]:
        """PROPOSED facts out, and any fact whose source has no fidelity rank.

        The second enforcement point after ``TfObject``'s side invariant. A
        source spelling outside the fidelity order is dropped with a note rather
        than raised on: a merge that crashes on one malformed fact decides
        nothing about the other nine hundred.
        """
        kept: list[facts.Fact] = []
        for fact in self.inputs:
            if fact.side == "proposed" or fact.source in facts.PROPOSED_SOURCES:
                self.dropped.append(Dropped(fact, (
                    f"{fact.category}/{fact.key} arrived at source '{fact.source}' on "
                    f"side '{fact.side}': {PROPOSED_DROP_REASON}")))
                continue
            try:
                fidelity_rank(fact.source)
            except ValueError as exc:
                self.dropped.append(Dropped(fact, (
                    f"{fact.category}/{fact.key} names source '{fact.source}', which "
                    f"has no fidelity rank ({exc}); it cannot be ranked against "
                    f"anything, so it is dropped rather than guessed at")))
                continue
            source_id = _source_id(fact)
            known = self.kinds.setdefault(source_id, fact.source)
            if known != fact.source:
                self.notes.append(
                    f"source '{source_id}' arrived with two fidelity spellings "
                    f"('{known}' and '{fact.source}'); the first is used and the "
                    f"disagreement is recorded rather than arbitrated silently")
            kept.append(fact)
        return kept

    # -- step 2 ---------------------------------------------------------------

    def _aliases(self, kept: Iterable[facts.Fact]) -> dict[str, str]:
        table: dict[str, Any] = {}
        for fact in kept:
            if fact.category == "resource_hierarchy" and isinstance(fact.record, Mapping):
                table.setdefault(fact.key, fact.record)
        return identity.alias_map(_AliasSource(table))

    def _canonicalise(self, kept: list[facts.Fact]
                      ) -> list[tuple[facts.Fact, str, bool]]:
        """``[(fact, key, canonical)]``. An ``AmbiguousKey`` keeps its RAW key,
        is tainted ``unmergeable``, is recorded in ``unresolved_aliases`` and
        yields one unmergeable dispute carrying the exception's reason — it is
        never merged onto a key somebody guessed."""
        aliases = self._aliases(kept)
        out: list[tuple[facts.Fact, str, bool]] = []
        for fact in kept:
            try:
                key = identity.canonical_key(fact.category, aliases=aliases,
                                             name=fact.key)
                canonical = True
            except identity.AmbiguousKey as exc:
                key, canonical = fact.key, False
                reason = (f"{fact.category}/{fact.key} could not be canonicalised "
                          f"[{exc.reason}]: {exc.detail or exc.reason}; it is kept "
                          f"under its RAW key and never merged onto a key nobody "
                          f"could build")
                self.unresolved_aliases.setdefault(fact.category, {})[fact.key] = reason
                self.disputes.append(Dispute(
                    category=fact.category, key=fact.key, field="",
                    severity="unmergeable", left=_source_id(fact), right="",
                    reason=reason))
            self.contributed.setdefault(_source_id(fact), set()).add(fact.category)
            out.append((fact, key, canonical))
        return out

    # -- step 3 ---------------------------------------------------------------

    def _group(self, canonical: list[tuple[facts.Fact, str, bool]]
               ) -> dict[tuple[str, str], list[facts.Fact]]:
        groups: dict[tuple[str, str], list[facts.Fact]] = {}
        for fact, key, _canonical in canonical:
            groups.setdefault((fact.category, key), []).append(fact)
        return groups

    # -- steps 4-7 ------------------------------------------------------------

    def _assemble(self, category: str, key: str, source_id: str,
                  group: list[facts.Fact]) -> tuple[Mapping[str, Any], str, list[str]]:
        """ONE source's record for ``(category, key)``: its base record with
        every fragment's LIST fields concatenated on, in priority-then-address
        order, exact duplicates collapsed.

        A list field no fragment speaks for is left exactly as the base wrote
        it — NEVER sorted — because a list whose order the source chose is not
        this module's to reorder.
        """
        notes: list[str] = []
        bases = sorted((f for f in group if not f.fragment), key=_fact_sort_key)
        fragments = sorted((f for f in group if f.fragment),
                           key=lambda f: (_fragment_priority(f.record), f.address,
                                          f.fragment))
        if bases:
            base = bases[0]
            record: Mapping[str, Any] = base.record if base.record is not None else {}
            locator = base.address
            if len(bases) > 1:
                notes.append(
                    f"source '{source_id}' carries {len(bases)} base records for "
                    f"{category}/{key}; the one at address "
                    f"'{base.address or '-'}' is used and the rest are kept as "
                    f"contributors rather than silently merged")
        else:
            record = {}
            locator = fragments[0].address if fragments else ""
            notes.append(
                f"source '{source_id}' contributed only fragments for "
                f"{category}/{key}: the parent resource is not in the same "
                f"artifact, so the fragments were assembled onto an EMPTY record "
                f"and nothing may be concluded from the fields it does not carry")
        if not fragments:
            # The identity case: one source, one base record, returned UNTOUCHED
            # so a single-source merge is exact.
            return record, locator, notes
        assembled = dict(record)
        for fragment in fragments:
            if not isinstance(fragment.record, Mapping):
                continue
            for name, value in fragment.record.items():
                if not _is_list(value):
                    continue
                existing = assembled.get(name)
                if existing is None:
                    merged: list[Any] = []
                elif _is_list(existing):
                    merged = list(existing)
                else:
                    notes.append(
                        f"fragment '{fragment.fragment}' at '{fragment.address}' "
                        f"offers a list for field '{name}', which the base record "
                        f"holds as a scalar; the base value is kept")
                    continue
                seen = {_frozen(item) for item in merged}
                for item in value:
                    frozen = _frozen(item)
                    if frozen in seen:
                        continue           # an exact duplicate collapses
                    seen.add(frozen)
                    merged.append(item)
                assembled[name] = merged
        return assembled, locator, notes

    def _order(self, source_ids: Iterable[str], mode: str) -> list[str]:
        """*source_ids* best-first under *mode*. Ties break on the source id, so
        the ordering never depends on the order facts arrived in."""
        def rank(source_id: str) -> tuple[int, int, str]:
            kind = self._kind(source_id)
            fidelity = fidelity_rank(kind)
            if mode == "api-wins":
                tier = _API_TIER.get(kind, 0)
            elif mode == "terraform-wins":
                tier = _TERRAFORM_TIER.get(kind, 0)
            else:                       # highest-fidelity-wins, require-agreement
                tier = 0
            return (-tier, -fidelity, source_id)
        return sorted(source_ids, key=rank)

    def _needs_backfill(self, record: Mapping[str, Any], group: list[facts.Fact],
                        name: str) -> bool:
        """Whether the winner left *name* UNRESOLVED.

        Either the value it carries holds a marker, or it carries no value at
        all AND the winning fact's own ``unresolved`` names that path — which is
        how a reader that REMOVES an unresolved attribute (rather than nulling
        it) still says so. A field the winner is simply silent about is not
        backfilled: see step 5.
        """
        if name in record:
            return facts.has_unresolved(record[name])
        for fact in group:
            for marker in fact.unresolved:
                path = marker.path
                if path == name or path.startswith(f"{name}.") or path.startswith(f"{name}["):
                    return True
        return False

    def _resolve_table(self, category: str, key: str, group: list[facts.Fact]) -> None:
        pending = _Pending(category, key)
        pending.contributors.extend(group)
        self.pending[(category, key)] = pending

        by_source: dict[str, list[facts.Fact]] = {}
        for fact in group:
            by_source.setdefault(_source_id(fact), []).append(fact)

        records: dict[str, Mapping[str, Any]] = {}
        locators: dict[str, str] = {}
        for source_id in sorted(by_source):
            record, locator, notes = self._assemble(category, key, source_id,
                                                    by_source[source_id])
            records[source_id] = record
            locators[source_id] = locator
            pending.notes.extend(notes)

        mode = self.policy.for_category(category)
        ordered = self._order(records, mode)
        winner = ordered[0]
        pending.source_id = winner
        pending.locator = locators[winner]
        pending.record = records[winner]                          # step 5: WHOLESALE

        # A key nobody could canonicalise is unmergeable however it resolves.
        if key in self.unresolved_aliases.get(category, {}):
            pending.taint = compose_taint(pending.taint, "unmergeable")

        self._backfill(pending, records, ordered, by_source)       # step 6
        for loser in ordered[1:]:
            self.alternates.setdefault(category, {}).setdefault(key, []).append(
                Alternate(source_id=loser, locator=locators[loser],
                          record=records[loser],
                          reason=f"lost to '{winner}' under precedence '{mode}'; the "
                                 f"losing record is kept WHOLE so a pair check can be "
                                 f"re-run against it"))
            self._compare_pair(pending, winner, loser, records, mode)   # step 7

    def _backfill(self, pending: _Pending, records: Mapping[str, Mapping[str, Any]],
                  ordered: list[str], by_source: Mapping[str, list[facts.Fact]]) -> None:
        winner = ordered[0]
        record = records[winner]
        if not isinstance(record, Mapping):
            return
        fills: dict[str, Any] = {}
        for loser in ordered[1:]:
            candidate = records[loser]
            if not isinstance(candidate, Mapping):
                continue
            for name in sorted(candidate):
                if name in fills:
                    continue            # a higher-fidelity loser already answered
                if not self._needs_backfill(record, by_source[winner], name):
                    continue
                value = candidate[name]
                if value is None or facts.has_unresolved(value):
                    continue            # an unresolved value rescues nothing
                fills[name] = value
        if not fills:
            return
        pending.record = dict(record, **fills)
        pending.backfilled.extend(sorted(fills))
        self.backfilled.setdefault(pending.category, {})[pending.key] = tuple(
            sorted(fills))

    def _compare_pair(self, pending: _Pending, winner: str, loser: str,
                      records: Mapping[str, Mapping[str, Any]], mode: str) -> None:
        left = pending.record
        right = records[loser]
        try:
            # THE CANONICALISATION PASS. Two records with equal canonical forms
            # disagree about nothing, so an encoding difference — a set written
            # in another order, 'TCP' against 'tcp', '22' against '22-22' —
            # can never manufacture a dispute row.
            if compare.comparable(pending.category, left) == \
                    compare.comparable(pending.category, right):
                return
            diffs = compare.compare(pending.category, left, right)
        except compare.Incomparable as exc:
            self._dispute(pending, Dispute(
                category=pending.category, key=pending.key, field="",
                severity="unmergeable", left=winner, right=loser,
                reason=f"'{winner}' and '{loser}' cannot be compared at all: "
                       f"{exc.detail}"))
            return
        for diff in diffs:
            if diff.left is None or diff.right is None:
                # ABSENCE, not a differing value. One side simply not carrying
                # the field is step 8's question, not step 7's.
                continue
            severity = _SEVERITY[diff.severity]
            reason = (f"'{winner}' and '{loser}' disagree about '{diff.path}' in "
                      f"{pending.category}/{pending.key}")
            if diff.note:
                reason = f"{reason}; {diff.note}"
            self._dispute(pending, Dispute(
                category=pending.category, key=pending.key, field=diff.path,
                severity=severity, left=_render(diff.left), right=_render(diff.right),
                reason=reason))
            if severity == "material" and mode == "require-agreement":
                # require-agreement is highest-fidelity-wins PLUS escalation. The
                # key is NOT dropped: dropping it from a complete category would
                # let the merged snapshot prove an absence that is not proven.
                self.verdicts.append(Verdict(
                    "contradicted", "drift:material",
                    f"{pending.category}/{pending.key}", 0,
                    f"precedence 'require-agreement' requires the sources to agree, "
                    f"and {reason}; the key is KEPT and resolved from '{winner}' - "
                    f"dropping it would let the merged view prove an absence that is "
                    f"not proven"))

    def _dispute(self, pending: _Pending, dispute: Dispute) -> None:
        self.disputes.append(dispute)
        taint = _TAINT.get(dispute.severity, "")
        if taint:
            pending.taint = compose_taint(pending.taint, taint)

    # -- step 9 (flat vocabularies) -------------------------------------------

    def _resolve_flat(self, category: str, key: str, group: list[facts.Fact]) -> None:
        """UNION, with a fidelity floor. Precedence is never consulted here."""
        floor = fidelity_rank(EMIT_FIDELITY_FLOOR)
        source_ids = sorted({_source_id(f) for f in group})
        emitting = [sid for sid in source_ids
                    if fidelity_rank(self._kind(sid)) >= floor]
        if not emitting:
            self.declared_not_applied.setdefault(category, set()).add(key)
            kinds = sorted({self._kind(sid) for sid in source_ids})
            for fact in sorted(group, key=_fact_sort_key):
                self.dropped.append(Dropped(fact, (
                    f"'{key}' is named only by {kinds} source(s), below the "
                    f"'{EMIT_FIDELITY_FLOOR}' fidelity floor, so it is withheld from "
                    f"the emitted '{category}' vocabulary and recorded in "
                    f"declared_not_applied instead: {DECLARED_NOT_APPLIED_REASON}, "
                    f"and unioning it in would mint a 'grounded' for a name that may "
                    f"not exist")))
            return
        pending = _Pending(category, key)
        pending.contributors.extend(group)
        # The origin is the HIGHEST-FIDELITY emitting source, not the winner of a
        # precedence contest: a flat vocabulary is a union and has no contest.
        winner = sorted(emitting, key=lambda sid: (-fidelity_rank(self._kind(sid)), sid))[0]
        pending.source_id = winner
        pending.locator = next((f.address for f in sorted(group, key=_fact_sort_key)
                                if _source_id(f) == winner and f.address), "")
        pending.record = None
        withheld = [sid for sid in source_ids if sid not in emitting]
        if withheld:
            pending.notes.append(
                f"'{key}' is also named by {withheld}, below the "
                f"'{EMIT_FIDELITY_FLOOR}' fidelity floor; the name is emitted because "
                f"a source that observed reality also names it")
        if key in self.unresolved_aliases.get(category, {}):
            pending.taint = compose_taint(pending.taint, "unmergeable")
        self.pending[(category, key)] = pending

    # -- step 8 ---------------------------------------------------------------

    def _existence(self) -> None:
        """Present here, absent there — and what that licenses, in both
        directions."""
        for (category, key), pending in sorted(self.pending.items()):
            present = sorted({_source_id(f) for f in pending.contributors})
            present_complete = [sid for sid in present
                                if self._scope_of(sid, category)[0] == "complete"]
            for other in self._sources_over(category):
                if other in present:
                    continue
                scope, _boundary = self._scope_of(other, category)
                if scope == "uncaptured":
                    continue
                if scope == "complete":
                    # MATERIAL. The other side enumerated everything and this is
                    # not in it, so the fact and the enumeration cannot both be
                    # right. The fact is KEPT and tainted, never dropped.
                    self._dispute(pending, Dispute(
                        category=category, key=key, field="",
                        severity="material", left=present[0], right=other,
                        reason=f"'{key}' is present in {present} but ABSENT from "
                               f"'{other}', which enumerated '{category}' completely; "
                               f"it may have been destroyed or moved out of band"))
                elif present_complete and self._kind(other) in TERRAFORM_SOURCES:
                    # UNMANAGED, never material: an unmanaged resource is normal
                    # in a partially adopted estate. Aggregated later into one
                    # verdict per category rather than one per key.
                    self.disputes.append(Dispute(
                        category=category, key=key, field="",
                        severity="unmanaged", left=present_complete[0], right=other,
                        reason=f"'{key}' is present in '{present_complete[0]}', a "
                               f"complete enumeration of '{category}', and absent "
                               f"from terraform source '{other}'; it exists but "
                               f"terraform does not manage it"))
                # Otherwise the key is simply SOLE-SOURCED: absence from a view
                # that never claimed to be complete is not evidence of anything.

    # -- step 9a --------------------------------------------------------------

    def _key_mismatch(self, canonical: list[tuple[facts.Fact, str, bool]]) -> None:
        """One ``drift:key-mismatch`` verdict per pair of sources whose key sets
        do not intersect at all. It never changes a resolution and never
        suppresses a fact — it only says that drift detection for this category
        is not actually reporting anything."""
        per: dict[str, dict[str, set[str]]] = {}
        for fact, key, is_canonical in canonical:
            if not is_canonical:
                continue           # a raw key is not a canonical key set member
            per.setdefault(fact.category, {}).setdefault(_source_id(fact), set()).add(key)
        for category in sorted(per):
            source_ids = sorted(per[category])
            for index, left in enumerate(source_ids):
                for right in source_ids[index + 1:]:
                    left_keys, right_keys = per[category][left], per[category][right]
                    if len(left_keys) < MIN_KEYS_FOR_MISMATCH or \
                            len(right_keys) < MIN_KEYS_FOR_MISMATCH:
                        continue
                    if left_keys & right_keys:
                        continue
                    self.verdicts.append(Verdict(
                        "unverified", KEY_MISMATCH_KIND, category, 0,
                        f"sources '{left}' and '{right}' each contributed to "
                        f"'{category}' ({len(left_keys)} and {len(right_keys)} keys) "
                        f"and zero keys matched - for example '{min(left_keys)}' "
                        f"against '{min(right_keys)}'. That usually means the two "
                        f"layers disagree about the KEY FORM rather than that the "
                        f"estate genuinely changed completely, so no drift is being "
                        f"detected for this category at all"))

    # -- step 10 --------------------------------------------------------------

    def _compose_scopes(self) -> dict[str, CategoryScope]:
        categories = {category for category, _key in self.pending}
        categories.update(self.contributed_categories())
        out: dict[str, CategoryScope] = {}
        for category in sorted(categories):
            contributors = self._sources_over(category)
            pairs = [self._scope_of(sid, category) for sid in contributors]
            scope, boundary = compose_scope(*pairs)
            kinds = tuple(sorted({self._kind(sid) for sid in contributors}))
            keys = sum(1 for (name, _key) in self.pending if name == category)
            out[category] = CategoryScope(
                scope=scope, boundary=boundary, keys=keys, source_kinds=kinds,
                note=f"merged from {len(contributors)} source(s)")
        return out

    def contributed_categories(self) -> set[str]:
        out: set[str] = set()
        for categories in self.contributed.values():
            out.update(categories)
        for table in self.category_scopes.values():
            out.update(name for name, scope in table.items() if scope != "uncaptured")
        return out

    # -- step 11 --------------------------------------------------------------

    def _captured_at(self) -> str:
        """The MINIMUM over contributors. ``PolicyReport`` stamps every line with
        one timestamp, so a merge must present its OLDEST constituent: claiming
        the newest would date a stale fact by the freshness of an unrelated one."""
        stamps = sorted(record.captured_at for record in self.declared.values()
                        if record.captured_at)
        return stamps[0] if stamps else ""

    def _build(self, scopes: Mapping[str, CategoryScope]) -> MergeResult:
        resolutions = tuple(self.pending[key].freeze()
                            for key in sorted(self.pending))
        disputes = tuple(sorted(self.disputes, key=lambda d: (
            d.category, d.key, d.field, d.severity, d.left, d.right, d.reason)))
        dropped = tuple(sorted(self.dropped, key=lambda d: (
            d.fact.category, d.fact.key, _fact_sort_key(d.fact), d.note)))
        verdicts = tuple(sorted(self.verdicts, key=lambda v: (
            v.kind, v.target, v.status, v.message)))
        alternates = {category: {key: tuple(values) for key, values in sorted(keys.items())}
                      for category, keys in sorted(self.alternates.items())}
        aliases = {category: dict(sorted(rows.items()))
                   for category, rows in sorted(self.unresolved_aliases.items())}
        backfilled = {category: dict(sorted(rows.items()))
                      for category, rows in sorted(self.backfilled.items())}
        withheld = {category: tuple(sorted(names))
                    for category, names in sorted(self.declared_not_applied.items())}
        seen: set[str] = set()
        notes: list[str] = []
        for note in sorted(self.notes):
            if note not in seen:
                seen.add(note)
                notes.append(note)
        result = MergeResult(
            resolutions=resolutions, disputes=disputes, scopes=dict(scopes),
            alternates=alternates, unresolved_aliases=aliases, backfilled=backfilled,
            dropped=dropped, notes=tuple(notes), captured_at=self._captured_at(),
            declared_not_applied=withheld, verdicts=verdicts)
        self._check_accounting(result)
        return result

    def _check_accounting(self, result: MergeResult) -> None:
        """THE POSTCONDITION: every input fact appears in exactly one
        resolution's contributors or in ``dropped``. Logged rather than raised —
        a merge that crashes on its own bookkeeping decides nothing — but logged
        at ERROR, because a fact that evaporated is a finding nobody will see."""
        counted: dict[int, int] = {}
        for resolution in result.resolutions:
            for fact in resolution.contributors:
                counted[id(fact)] = counted.get(id(fact), 0) + 1
        for drop in result.dropped:
            counted[id(drop.fact)] = counted.get(id(drop.fact), 0) + 1
        missing = [f for f in self.inputs if counted.get(id(f), 0) != 1]
        if missing:
            logger.error("merge accounting: %d of %d input fact(s) are not in exactly "
                         "one resolution or drop - a fact that evaporated is a finding "
                         "nobody will see", len(missing), len(self.inputs))
