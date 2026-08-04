"""The CURRENT counterpart of a proposed document — or precisely why there is none.

This module answers ONE question: *what is the current counterpart of this
target, and how sure are we?* It answers it in one place, reading the single
scope lattice that :mod:`gcp_grounding.provenance` owns, rather than
recomputing completeness from a second vocabulary. Every completeness question
here goes through :func:`gcp_grounding.provenance.require_complete`, so there is
exactly one implementation of "may an absence be read as a non-existence".

THE DISTINCTION THIS MODULE EXISTS TO PROTECT
---------------------------------------------

``baseline:new`` means we LOOKED with a source that enumerated the domain
COMPLETELY and there genuinely is no predecessor. ``baseline:unqueried`` means
we did NOT look — either no configured state source covers the domain at all,
or every source that does is ``partial`` or ``undeclared``. Different statuses,
different verdict kinds, and deliberately different messages: a test asserts the
two messages differ and that neither contains the other. Collapsing them turns
"we never captured firewall rules" into "this firewall rule is brand new", which
is a confident comparison against nothing.

WHAT IS DELIBERATELY NOT HERE
-----------------------------

- **Filename-derived targets.** Guessing a resource from a file name is exactly
  the near-miss that produces a confident comparison against the WRONG policy.
  An IAM allow policy does not name its own resource, so it needs a hint, a
  config entry or the tool input — and when it has none it gets NO target and
  one ``baseline:target`` verdict naming all three remedies.
- **Fuzzy matching.** No nearest-name, no edit distance, no reasoner suggestion
  helper. A near-miss baseline is worse than none: it silently redefines what
  the widening check compares against. A key that disagrees simply never
  matches, and the miss reads as ``absent`` — which the systematic-miss
  diagnostic (:func:`key_mismatch_verdicts`) then surfaces.
- **File I/O.** :func:`derive` never opens a file. An EXPLICIT baseline
  short-circuits by being loaded into an ``explicit-baseline`` source BEFORE
  ``derive`` runs: it then wins by ordinary fidelity precedence (it is the
  highest member of :data:`gcp_grounding.provenance.SOURCES`) and still appears
  in the provenance rows, instead of being a second, invisible code path.

THE PROJECTION, AND WHY IT IS OWNED HERE
----------------------------------------

:func:`derive` supplies counterpart documents built from estate RECORDS, but a
domain's pair check extracts its baseline by calling that domain's registered
``DOCUMENT_EXTRACTORS`` callable, which understands the REST wire spelling and
NOT the estate record spelling — ``fw_claims.firewall_rule_claims`` reads
``allowed``/``denied`` and ``sourceRanges`` while the record carries ``action``,
``layer4`` and ``source_ranges``. Fed a raw record such an extractor produces a
claim carrying an ``unsupported`` payload key, and the never-drop-a-rule
discipline of the firewall checks then turns EVERY auto-derived pair check into
an ``unverified``: the headline capability doing nothing at all, on the path
that has no baseline flag to tell you it did not run.

So :func:`project_record` emits, per domain, the exact document shape that
domain's extractor consumes, and :attr:`BaselineEntry.kind` comes FROM THE
PROJECTION and never from ``preflight.detect_kind`` on a record (which answers
``None`` for a firewall record, and answers ``iam_policy`` for an IAM record
only by accident, because ``{"bindings": [...]}`` already IS a valid IAM policy
document).

The projection is a pure spelling translation. The EMPTINESS rule is separate
and lives in :func:`derive`: a record whose projected document carries no
comparable rules at all resolves ``opaque``, never ``resolved``, because an
empty baseline makes a widening trivially provable and manufactures a confident
block.

MATCHING
--------

PRIMARY by terraform address through
:meth:`~gcp_grounding.provenance.SourceLedger.by_locator`, which is live
precisely because ``FactOrigin.locator`` already holds the address — no second
index is built. THE CATEGORY ARGUMENT IS MANDATORY: one address legitimately
produces several facts in several categories, so an unscoped lookup can hand
back a ``network_tags`` side fact as the baseline for a firewall target, and the
secondary key check would not catch it because the primary hit LOOKS successful.
More than one hit within the requested category is ``baseline:ambiguous`` with
no baseline; hits in other categories are ignored.

SECONDARY by canonical key, then once more after self-link normalisation, both
with the ambiguity guard. A primary and a secondary hit on DIFFERENT existing
keys is ``baseline:ambiguous`` and no baseline. A renamed resource — the primary
misses, the secondary hits — IS resolved, with ``how`` rewritten to
``tf-attributes`` so the explain surface says which side identified it.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from . import facts, identity, provenance
from .core.log import get_logger
from .core.report import Verdict
from .knowledge import GcpSnapshot
from .provenance import CategoryScope, SourceLedger

logger = get_logger(__name__)

__all__ = [
    "RESOLUTION_STATUSES",
    "FLAG_ORDER",
    "HOWS",
    "STATUS_KINDS",
    "TARGET_KIND",
    "AMBIGUOUS_KIND",
    "KEY_MISMATCH_KIND",
    "KIND_CATEGORIES",
    "HINTED_KINDS",
    "TF_KINDS",
    "TOOL_INPUT_KEYS",
    "REMEDIES",
    "RULE_CHANNELS",
    "Hints",
    "TargetRef",
    "Candidate",
    "BaselineEntry",
    "Derivation",
    "current_view",
    "covering_sources",
    "project_record",
    "rule_count",
    "targets_for",
    "resolve",
    "derive",
    "status_verdict",
    "key_mismatch_verdicts",
]


# -- the vocabulary -----------------------------------------------------------

#: Every answer :func:`resolve` can give. ``resolved`` is a counterpart we can
#: compare against; the other six each say something different about why we
#: cannot, and none of them is "no".
RESOLUTION_STATUSES = ("resolved", "absent", "unqueried", "conflict", "stale",
                       "unresolved", "opaque")

#: The order in which a carried flag becomes the status. Every flag is CARRIED
#: on the entry even when it does not win, so an explain surface can say that a
#: conflicting baseline was also stale.
FLAG_ORDER = ("conflict", "unresolved", "stale", "opaque")

#: How a target was identified. Carried into the explain output, because an
#: operator must be able to see WHY the tool thought two documents were
#: counterparts — "the address matched" and "the name matched after
#: normalisation" are very different levels of confidence.
HOWS = ("explicit-flag", "config-map", "tool-input", "document-name",
        "tf-address", "tf-attributes")

#: Status → verdict kind. TOTAL over :data:`RESOLUTION_STATUSES`, and every
#: verdict built from it is ``unverified``: no baseline status ever fails the
#: gate by itself. A finding is something a CHECK says; a baseline status is
#: only ever a statement about what the check was given.
STATUS_KINDS = {
    "resolved": "baseline",
    "absent": "baseline:new",
    "unqueried": "baseline:unqueried",
    "conflict": "baseline:conflict",
    "stale": "baseline:stale",
    "unresolved": "baseline:unresolved",
    "opaque": "baseline:opaque",
}

#: The kind for "this document does not name its own resource and nobody told
#: us which one it is".
TARGET_KIND = "baseline:target"

#: The kind for "two lookups disagreed about which row is the counterpart".
AMBIGUOUS_KIND = "baseline:ambiguous"

#: The kind for the systematic-miss diagnostic.
KEY_MISMATCH_KIND = "baseline:key-mismatch"

#: Document kind → the estate category its counterpart lives in.
KIND_CATEGORIES = {
    "iam_policy": "iam_bindings",
    "iam_deny_policy": "iam_bindings",
    "org_policy": "org_policies",
    "firewall_rule": "firewall_rules",
    "firewall_policy": "hierarchical_firewall_policies",
    "security_policy": "cloud_armor_policies",
    "vpc_sc_perimeter": "vpc_sc_perimeters",
    "access_level": "access_levels",
}

#: Kinds whose document does NOT name its own resource. An IAM allow policy is
#: the archetype: ``{"bindings": [...]}`` says nothing about what it is attached
#: to, and a deny policy's own name is its policy id rather than its attachment
#: point. Their targets come from a hint, the config map or the tool input, in
#: that order, and from nothing else.
HINTED_KINDS = ("iam_policy", "iam_deny_policy")

#: Kinds read as a set of terraform resources rather than as one document. A
#: configuration proposal is read by the CALLER (``derive`` never opens a file)
#: and handed over as :attr:`Hints.objects`.
TF_KINDS = ("tf_plan",)

#: Keys a tool input may carry the target under, most specific first.
TOOL_INPUT_KEYS = ("baseline_target", "target", "resource", "resource_name")

#: The three ways to give a hinted document its target, named in the
#: ``baseline:target`` verdict. Listing all three is the point: one of them is
#: always available, and a verdict that says only "no baseline" teaches nobody
#: how to get one.
REMEDIES = (
    "pass the target explicitly (the --baseline-target flag)",
    "add an entry for this file to the config file's targets map",
    "invoke the tool with the resource in its input",
)

#: Document kind → where its comparable rules live, for :func:`rule_count`. A
#: kind absent from this table has no rule channel and is never judged empty.
RULE_CHANNELS = {
    "iam_policy": "bindings",
    "org_policy": "spec.rules",
    "firewall_rule": "allowed+denied",
    "firewall_policy": "rules",
    "security_policy": "rules",
    "vpc_sc_perimeter": "status+spec",
}


# -- inputs -------------------------------------------------------------------


@dataclass(frozen=True)
class Hints:
    """Everything the caller knows that the document itself cannot say.

    ``target`` is the explicit flag; ``targets`` is the config file's map from
    an edited path to its target; ``tool_input`` is the invoking tool's own
    input. They are consulted in exactly that order and nothing else is: see the
    module docstring on why a file NAME is never one of them.

    ``objects`` carries already-read :class:`gcp_grounding.facts.TfObject` rows
    for a CONFIGURATION proposal, because this module never opens a file.

    The qualifier fields are what a bare terraform or REST name cannot supply —
    a firewall rule names ``allow-ssh``, the estate keys
    ``projects/<p>/global/firewalls/allow-ssh``. A missing qualifier yields no
    target and one verdict, NEVER a key built from an assumed project.
    """

    target: str = ""
    category: str = ""
    targets: Mapping[str, str] = field(default_factory=dict)
    tool_input: Any = None
    source: str = ""
    objects: tuple[Any, ...] = ()
    project: str = ""
    project_number: str = ""
    region: str = ""
    organization: str = ""
    folder: str = ""
    access_policy: str = ""
    aliases: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "targets", dict(self.targets))
        object.__setattr__(self, "aliases", dict(self.aliases))
        object.__setattr__(self, "objects", tuple(self.objects))

    def parent(self) -> str:
        """The hierarchy parent these qualifiers name, or ``""``."""
        if self.organization:
            bare = self.organization.split("/")[-1]
            return f"organizations/{bare}"
        if self.folder:
            bare = self.folder.split("/")[-1]
            return f"folders/{bare}"
        return ""

    def node(self) -> str:
        """The hierarchy NODE these qualifiers name — organization, then folder,
        then project — or ``""``. An org policy with only a ``constraint`` needs
        one to name its row."""
        parent = self.parent()
        if parent:
            return parent
        if self.project:
            return f"projects/{self.project.split('/')[-1]}"
        return ""

    def from_tool_input(self) -> str:
        """The target the tool input names, or ``""``. Only the
        :data:`TOOL_INPUT_KEYS` are read: a tool input is an arbitrary mapping,
        and scanning it for something resource-shaped is the same guess a
        filename would be."""
        if not isinstance(self.tool_input, Mapping):
            return ""
        for key in TOOL_INPUT_KEYS:
            value = self.tool_input.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""


@dataclass(frozen=True)
class TargetRef:
    """One thing to look up: which estate category, which key, and HOW we know.

    ``address`` is the terraform resource address when there is one; it is the
    PRIMARY lookup and it is scoped by ``category`` — see the module docstring
    on why an unscoped locator lookup is a wrong-counterpart bug that looks like
    a success.
    """

    category: str
    key: str
    how: str
    address: str = ""
    note: str = ""

    def __post_init__(self) -> None:
        if self.category not in provenance.CATEGORIES:
            raise ValueError(f"TargetRef.category {self.category!r} is not an estate "
                             f"category; expected one of {list(provenance.CATEGORIES)}")
        if not self.key:
            raise ValueError("TargetRef.key must name the row to look for; an "
                             "unnamed target cannot be looked up or explained")
        if self.how not in HOWS:
            raise ValueError(f"TargetRef.how {self.how!r} is not one of {list(HOWS)} — "
                             f"an operator must be able to see WHY two documents "
                             f"were thought to be counterparts")


@dataclass(frozen=True)
class Candidate:
    """One source's whole record for a key: the winner, or a losing alternate.

    Kept whole rather than field by field, because a pair check re-run against
    the loser needs a DOCUMENT and a field-level dispute cannot supply one.
    """

    source_id: str
    kind: str = "unattributed"
    record: Mapping[str, Any] | None = None
    locator: str = ""
    reason: str = ""

    def rank(self) -> int:
        """This source's fidelity rank, or ``-1`` for a spelling
        :data:`gcp_grounding.provenance.SOURCES` does not know. Never raises: a
        ledger written by a future version must not crash a lookup."""
        try:
            return provenance.fidelity_rank(self.kind)
        except ValueError:
            logger.debug("candidate %s carries unknown source kind %r — ranked last",
                         self.source_id, self.kind)
            return -1


@dataclass(frozen=True)
class BaselineEntry:
    """One target's answer: the counterpart document, or why there is none."""

    target: TargetRef
    status: str
    key: str = ""
    document: Any = None
    kind: str | None = None
    record: Mapping[str, Any] | None = None
    source_id: str = ""
    scope: str = "uncaptured"
    how: str = ""
    others: tuple[Candidate, ...] = ()
    flags: tuple[str, ...] = ()
    reason: str = ""

    def __post_init__(self) -> None:
        if self.status not in RESOLUTION_STATUSES:
            raise ValueError(f"BaselineEntry.status {self.status!r} is not one of "
                             f"{list(RESOLUTION_STATUSES)}")
        object.__setattr__(self, "others", tuple(self.others))
        object.__setattr__(self, "flags", tuple(self.flags))
        if not self.how:
            object.__setattr__(self, "how", self.target.how)

    @property
    def comparable(self) -> bool:
        """Whether a pair check may be run against this entry. A document plus a
        kind, and nothing else: the STATUS says how much to trust the answer,
        never whether one exists."""
        return self.document is not None and self.kind is not None

    def row(self) -> dict[str, Any]:
        """This entry as one provenance row."""
        return {
            "target": self.target.key,
            "category": self.target.category,
            "key": self.key,
            "how": self.how,
            "status": self.status,
            "source": self.source_id,
            "scope": self.scope,
            "kind": self.kind or "",
            "others": tuple(c.source_id for c in self.others),
            "flags": self.flags,
        }


@dataclass(frozen=True)
class Derivation:
    """Every entry, every verdict, and the notes that explain the shortfalls."""

    entries: tuple[BaselineEntry, ...] = ()
    verdicts: tuple[Verdict, ...] = ()
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "entries", tuple(self.entries))
        object.__setattr__(self, "verdicts", tuple(self.verdicts))
        object.__setattr__(self, "notes", tuple(self.notes))

    def primary(self) -> BaselineEntry | None:
        """The first entry a pair check can actually use, or ``None``."""
        for entry in self.entries:
            if entry.comparable:
                return entry
        return None

    def rows(self) -> tuple[dict[str, Any], ...]:
        """One provenance row per entry, in entry order."""
        return tuple(entry.row() for entry in self.entries)


# -- reading the current state ------------------------------------------------


def current_view(current: Any) -> tuple[GcpSnapshot | None, SourceLedger | None]:
    """``(snapshot, ledger)`` from whatever the caller calls "the current state".

    Accepts a ``sources.CurrentState``, a ``reconciled.ReconciledSnapshot``, a
    plain :class:`~gcp_grounding.knowledge.GcpSnapshot` or ``None``. Duck-typed
    on purpose: this module must not import the assembler, which imports the
    world.
    """
    if current is None:
        return None, None
    inner = getattr(current, "snapshot", None)
    if isinstance(inner, GcpSnapshot):
        ledger = getattr(current, "ledger", None)
        if ledger is None:
            ledger = getattr(inner, "ledger", None)
        return inner, ledger if isinstance(ledger, SourceLedger) else None
    if isinstance(current, GcpSnapshot):
        ledger = getattr(current, "ledger", None)
        return current, ledger if isinstance(ledger, SourceLedger) else None
    raise TypeError(f"baseline needs a current state (CurrentState, "
                    f"ReconciledSnapshot, GcpSnapshot or None), got "
                    f"{type(current).__name__}")


def covering_sources(ledger: SourceLedger | None, category: str) -> tuple[str, ...]:
    """Every source id that could have contributed to *category*, sorted.

    Read off the category's own :class:`~gcp_grounding.provenance.CategoryScope`
    — the single scope lattice — rather than from a second per-source table: a
    source whose KIND contributed to the category is a covering source, and an
    uncaptured category is covered by nobody.
    """
    if ledger is None:
        return ()
    scope = ledger.scope_of(category)
    if scope.scope == "uncaptured":
        return ()
    kinds = set(scope.source_kinds)
    found = tuple(sid for sid in sorted(ledger.sources)
                  if not kinds or ledger.sources[sid].kind in kinds)
    return found or tuple(sorted(ledger.sources))


def _scope_of(ledger: SourceLedger | None, snapshot: GcpSnapshot | None,
              category: str) -> CategoryScope:
    """The category's coverage, from the ledger when there is one and from the
    snapshot's own captured/not-captured answer when there is not."""
    if ledger is not None:
        return ledger.scope_of(category)
    if snapshot is not None and category in provenance.CATEGORIES \
            and getattr(snapshot, category, None) is not None:
        return CategoryScope(scope="complete", source_kinds=("unattributed",))
    return provenance.UNCAPTURED


def _completeness_reason(ledger: SourceLedger | None, snapshot: GcpSnapshot | None,
                         category: str) -> str | None:
    """:func:`gcp_grounding.provenance.require_complete` over whichever source
    describes this view — THE single absence predicate, never a second one."""
    source: Any = ledger if ledger is not None else snapshot
    return provenance.require_complete(source, category, rule="baseline")


def _completing_source(ledger: SourceLedger | None, category: str) -> str:
    """The source id whose complete coverage licenses an absence in *category*."""
    covering = covering_sources(ledger, category)
    if ledger is None:
        return ""
    for source_id in covering:
        if ledger.sources[source_id].scope == "complete":
            return source_id
    return covering[0] if covering else ""


def _table(snapshot: GcpSnapshot | None, category: str) -> Any:
    if snapshot is None or category not in provenance.CATEGORIES:
        return None
    return getattr(snapshot, category, None)


def _held_keys(snapshot: GcpSnapshot | None, category: str) -> tuple[str, ...]:
    table = _table(snapshot, category)
    if isinstance(table, Mapping):
        return tuple(sorted(str(k) for k in table))
    if isinstance(table, (frozenset, set, tuple, list)):
        return tuple(sorted(str(k) for k in table))
    return ()


# -- the projection -----------------------------------------------------------


def _short(key: str) -> str:
    """The last segment of a slash-separated key."""
    return key.rsplit("/", 1)[-1]


def _listed(record: Mapping[str, Any], name: str) -> list[Any]:
    value = record.get(name)
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def _clean(value: Any) -> Any:
    """Drop ``None``-valued mapping entries, recursively.

    An estate record spells "this field is absent" as an explicit ``None``,
    while every REST document simply OMITS the key — and every extractor in
    this tree skips an absent key conservatively and reads an explicit null as a
    value. Translating one spelling into the other is the whole job here.
    """
    if isinstance(value, Mapping):
        return {k: _clean(v) for k, v in value.items() if v is not None}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    return value


def _camel(name: str) -> str:
    """``restricted_services`` → ``restrictedServices``."""
    head, *rest = name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


def _camelised(value: Any) -> Any:
    """*value* with every mapping KEY camelCased and every ``None`` dropped."""
    if isinstance(value, Mapping):
        return {_camel(str(k)): _camelised(v) for k, v in value.items() if v is not None}
    if isinstance(value, (list, tuple)):
        return [_camelised(v) for v in value]
    return value


def _layer4_rest(entries: Iterable[Any], protocol_key: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        item: dict[str, Any] = {protocol_key: entry.get("protocol")}
        ports = entry.get("ports")
        if isinstance(ports, (list, tuple)) and ports:
            item["ports"] = list(ports)
        out.append(item)
    return out


def _project_firewall_rule(key: str, record: Mapping[str, Any]) -> dict[str, Any]:
    """An estate firewall record as a ``compute#firewall`` REST document."""
    doc: dict[str, Any] = {
        "kind": "compute#firewall",
        "name": _short(key),
        "selfLink": key,
        "network": record.get("network", ""),
        "direction": record.get("direction", "INGRESS"),
        "priority": record.get("priority", 1000),
        "disabled": record.get("disabled", False),
    }
    layer4 = _layer4_rest(_listed(record, "layer4"), "IPProtocol")
    # The action decides WHICH channel the rule set lands in, which is exactly
    # the translation an extractor reading `allowed`/`denied` needs and the
    # estate record's flat `action` field does not give it.
    doc["denied" if record.get("action") == "deny" else "allowed"] = layer4
    for stored, rest in (("source_ranges", "sourceRanges"),
                         ("destination_ranges", "destinationRanges"),
                         ("source_tags", "sourceTags"),
                         ("target_tags", "targetTags"),
                         ("source_service_accounts", "sourceServiceAccounts"),
                         ("target_service_accounts", "targetServiceAccounts")):
        values = _listed(record, stored)
        if values:
            doc[rest] = values
    return doc


def _project_firewall_policy(key: str, record: Mapping[str, Any]) -> dict[str, Any]:
    """An estate hierarchical-firewall-policy record as a
    ``compute#firewallPolicy`` REST document."""
    rules = []
    for rule in _listed(record, "rules"):
        if not isinstance(rule, Mapping):
            continue
        match = rule.get("match") if isinstance(rule.get("match"), Mapping) else {}
        rest_match: dict[str, Any] = {}
        for stored, name in (("src_ip_ranges", "srcIpRanges"),
                             ("dest_ip_ranges", "destIpRanges")):
            values = _listed(match, stored)
            if values:
                rest_match[name] = values
        layer4 = _layer4_rest(_listed(match, "layer4"), "ipProtocol")
        if layer4:
            rest_match["layer4Configs"] = layer4
        item: dict[str, Any] = {
            "action": rule.get("action"),
            "direction": rule.get("direction"),
            "priority": rule.get("priority"),
            "disabled": rule.get("disabled", False),
            "match": rest_match,
        }
        for stored, name in (("target_resources", "targetResources"),
                             ("target_secure_tags", "targetSecureTags"),
                             ("target_service_accounts", "targetServiceAccounts")):
            values = _listed(rule, stored)
            if values:
                item[name] = values
        rules.append(_clean(item))
    doc: dict[str, Any] = {
        "kind": "compute#firewallPolicy",
        "name": _short(key),
        "selfLink": key,
        "rules": rules,
    }
    attachments = _listed(record, "attachments")
    if attachments:
        doc["associations"] = [{"attachmentTarget": target} for target in attachments]
    return doc


def _project_security_policy(key: str, record: Mapping[str, Any]) -> dict[str, Any]:
    """An estate Cloud Armor record as a ``compute#securityPolicy`` REST
    document — ``match.config.srcIpRanges`` and ``match.expr.expression``, the
    two shapes ``detect_kind`` and the armor extractor read."""
    rules = []
    for rule in _listed(record, "rules"):
        if not isinstance(rule, Mapping):
            continue
        match = rule.get("match") if isinstance(rule.get("match"), Mapping) else {}
        rest_match: dict[str, Any] = {}
        versioned = match.get("versioned_expr") or match.get("versionedExpr")
        ranges = _listed(match, "src_ip_ranges") or _listed(match, "srcIpRanges")
        if versioned:
            rest_match["versionedExpr"] = versioned
        if ranges:
            rest_match["config"] = {"srcIpRanges": ranges}
        expr = match.get("expr")
        if isinstance(expr, str) and expr:
            rest_match["expr"] = {"expression": expr}
        elif isinstance(expr, Mapping) and expr:
            rest_match["expr"] = _camelised(expr)
        item = {
            "action": rule.get("action"),
            "priority": rule.get("priority"),
            "preview": rule.get("preview", False),
            "match": rest_match,
        }
        rules.append(_clean(item))
    doc: dict[str, Any] = {
        "kind": "compute#securityPolicy",
        "name": _short(key),
        "selfLink": key,
        "rules": rules,
    }
    if record.get("type") is not None:
        doc["type"] = record.get("type")
    return doc


def _project_perimeter(key: str, record: Mapping[str, Any]) -> dict[str, Any]:
    """An estate VPC-SC record as a service-perimeter REST document.

    The status/spec blocks are camelCased WHOLE — every nested key, at every
    depth — because the perimeter extractor normalises the REST and terraform
    spellings onto one shape and the REST one is what its own detector reads.
    """
    doc: dict[str, Any] = {"name": key, "title": _short(key)}
    if record.get("perimeter_type") is not None:
        doc["perimeterType"] = record.get("perimeter_type")
    if record.get("use_explicit_dry_run_spec") is not None:
        doc["useExplicitDryRunSpec"] = record.get("use_explicit_dry_run_spec")
    for side in ("status", "spec"):
        block = record.get(side)
        if isinstance(block, Mapping) and block:
            doc[side] = _camelised(block)
    return doc


def _project_iam_bindings(key: str, record: Mapping[str, Any]) -> dict[str, Any]:
    """An estate IAM binding set as an IAM allow policy document.

    The one domain where the record already IS the document — but the nulls
    still have to go, because an explicit ``"condition": null`` reads as a
    condition to any extractor that tests for the key's presence.
    """
    bindings = [_clean(b) for b in _listed(record, "bindings") if isinstance(b, Mapping)]
    return {"bindings": bindings}


def _project_org_policy(key: str, record: Mapping[str, Any]) -> dict[str, Any]:
    """An estate org-policy record as a v2 Org Policy document.

    EXACTLY ONE value-type-bearing key per rule, because the extractor refuses a
    rule that carries two as ambiguous — and an estate record carries all six
    slots with five of them null.
    """
    node = record.get("node") or key.split("|", 1)[0]
    constraint = record.get("constraint") or key.split("|", 1)[-1]
    short = constraint.rsplit("/", 1)[-1]
    rules = []
    for rule in _listed(record, "rules"):
        if not isinstance(rule, Mapping):
            continue
        item: dict[str, Any] = {}
        enforce = rule.get("enforce")
        allowed = _listed(rule, "allowed_values")
        denied = _listed(rule, "denied_values")
        if isinstance(enforce, bool):
            item["enforce"] = enforce
        elif rule.get("allow_all") is True:
            item["allowAll"] = True
        elif rule.get("deny_all") is True:
            item["denyAll"] = True
        elif allowed or denied:
            values: dict[str, Any] = {}
            if allowed:
                values["allowedValues"] = allowed
            if denied:
                values["deniedValues"] = denied
            item["values"] = values
        condition = rule.get("condition")
        if isinstance(condition, Mapping) and condition:
            item["condition"] = _clean(condition)
        rules.append(item)
    spec: dict[str, Any] = {"rules": rules}
    if record.get("inherit_from_parent") is not None:
        spec["inheritFromParent"] = bool(record.get("inherit_from_parent"))
    if record.get("reset") is not None:
        spec["reset"] = bool(record.get("reset"))
    return {"name": f"{node}/policies/{short}", "spec": spec}


#: category → (projector, document kind). The five categories with no entry
#: have no document form: a flat vocabulary has names and not records, and
#: ``roles`` and ``resource_hierarchy`` are compared field-wise by the estate
#: tier rather than as documents.
_PROJECTIONS = {
    "firewall_rules": (_project_firewall_rule, "firewall_rule"),
    "hierarchical_firewall_policies": (_project_firewall_policy, "firewall_policy"),
    "cloud_armor_policies": (_project_security_policy, "security_policy"),
    "vpc_sc_perimeters": (_project_perimeter, "vpc_sc_perimeter"),
    "iam_bindings": (_project_iam_bindings, "iam_policy"),
    "org_policies": (_project_org_policy, "org_policy"),
}


def project_record(category: str, key: str, record: Any
                   ) -> tuple[Any | None, str | None]:
    """One estate RECORD as ``(document, kind)`` in the spelling that domain's
    extractor consumes — or ``(None, None)``.

    ``(None, None)`` means there is no document form for this category, which is
    an honest "no pair check here", never an empty document: an empty document
    is a baseline that answers every widening question with "yes, this is new".

    The KIND comes from here and is never re-derived by sniffing the projected
    document, let alone the raw record — ``detect_kind`` answers ``None`` for a
    firewall record and would leave the entry kindless.
    """
    entry = _PROJECTIONS.get(category)
    if entry is None or not isinstance(record, Mapping):
        return None, None
    project, kind = entry
    try:
        return project(key, record), kind
    except Exception as exc:                        # noqa: BLE001 - never crash a gate
        logger.debug("projecting %s/%s failed (%s: %s) — no counterpart document",
                     category, key, type(exc).__name__, exc, exc_info=True)
        return None, None


def rule_count(kind: str | None, document: Any) -> int | None:
    """How many comparable rules *document* carries, or ``None`` when its kind
    has no rule channel.

    ``0`` is the dangerous answer and the reason this function exists: an empty
    baseline makes "the change grants nothing new" trivially FALSE and every
    widening check trivially provable, which manufactures a confident block out
    of a record that simply had nothing in it.
    """
    if kind not in RULE_CHANNELS or not isinstance(document, Mapping):
        return None
    if kind == "iam_policy":
        return len(_listed(document, "bindings"))
    if kind == "org_policy":
        spec = document.get("spec")
        return len(_listed(spec, "rules")) if isinstance(spec, Mapping) else 0
    if kind == "firewall_rule":
        return len(_listed(document, "allowed")) + len(_listed(document, "denied"))
    if kind == "vpc_sc_perimeter":
        return sum(1 for side in ("status", "spec")
                   if isinstance(document.get(side), Mapping) and document[side])
    return len(_listed(document, "rules"))


# -- targets ------------------------------------------------------------------


def _accepted_parts(category: str, hints: Hints, name: str) -> dict[str, Any]:
    """The key parts this category ACCEPTS, filled from *hints*.

    Filtered against the spec rather than passed wholesale, because
    ``identity`` raises on a part name a category does not read — a qualifier
    nobody reads is a qualifier silently dropped from a key.
    """
    spec = identity.SPECS.get(category)
    parts: dict[str, Any] = {"name": name}
    if spec is None:
        return parts
    for part, value in (("project", hints.project),
                        ("region", hints.region),
                        ("organization", hints.organization),
                        ("access_policy", hints.access_policy),
                        ("parent", hints.parent())):
        if value and part in spec.parts:
            parts[part] = value
    return parts


def _aliases(hints: Hints) -> dict[str, str]:
    table = dict(hints.aliases)
    if hints.project_number and hints.project:
        table.setdefault(hints.project_number, hints.project.split("/")[-1])
    return table


def _canonical(category: str, hints: Hints, **parts: Any) -> tuple[str, str]:
    """``(key, "")`` or ``("", reason)`` — never a key built from a guess."""
    try:
        return identity.canonical_key(category, aliases=_aliases(hints), **parts), ""
    except identity.AmbiguousKey as exc:
        return "", str(exc)
    except ValueError as exc:                       # a caller bug, reported as one
        return "", f"identity.{category}: {exc}"


def _unresolved_verdict(target: str, reason: str, source: str) -> Verdict:
    return Verdict("unverified", STATUS_KINDS["unresolved"], target or source, 0,
                   f"the current counterpart of {target or 'this document'} was not "
                   f"looked up: {reason} - no key was built, because a key built "
                   f"from an assumed qualifier is a confident answer about some "
                   f"other resource")


def _target_verdict(kind: str | None, source: str) -> Verdict:
    remedies = "; ".join(f"{i + 1}) {r}" for i, r in enumerate(REMEDIES))
    return Verdict("unverified", TARGET_KIND, source or "<document>", 0,
                   f"a {kind or 'policy'} document does not name the resource it is "
                   f"attached to, and no target was supplied, so no baseline was "
                   f"derived and every pair check was skipped. Three ways to fix it: "
                   f"{remedies}. A target is never guessed from the file name: a "
                   f"near-miss baseline silently redefines what the widening check "
                   f"compares against")


def _hinted_target(kind: str | None, hints: Hints, source: str
                   ) -> tuple[tuple[TargetRef, ...], tuple[Verdict, ...]]:
    """The explicit hint, then the config map, then the tool input — and then
    NOTHING, with one verdict naming all three."""
    category = hints.category or KIND_CATEGORIES.get(kind or "", "")
    candidates = (
        (hints.target.strip() if isinstance(hints.target, str) else "", "explicit-flag"),
        (str(hints.targets.get(hints.source or source, "")).strip(), "config-map"),
        (hints.from_tool_input(), "tool-input"),
    )
    for value, how in candidates:
        if not value:
            continue
        if not category:
            return (), (_unresolved_verdict(
                value, f"no estate category is known for document kind "
                       f"{kind!r}", source),)
        key, reason = _canonical(category, hints, **_accepted_parts(category, hints, value))
        if not key:
            return (), (_unresolved_verdict(value, reason, source),)
        return (TargetRef(category=category, key=key, how=how),), ()
    return (), (_target_verdict(kind, source),)


def _named_target(document: Mapping[str, Any], kind: str, hints: Hints, source: str
                  ) -> tuple[tuple[TargetRef, ...], tuple[Verdict, ...]]:
    """A document that names itself: its ``name``, else its ``selfLink``."""
    category = KIND_CATEGORIES.get(kind, "")
    if kind == "org_policy":
        return _org_policy_target(document, hints, source)
    name = ""
    for field_name in ("name", "selfLink"):
        value = document.get(field_name)
        if isinstance(value, str) and value.strip():
            name = value.strip()
            break
    if not name:
        return (), (_unresolved_verdict(
            "", f"the {kind} document carries neither a 'name' nor a 'selfLink', so "
                f"it names no resource", source),)
    normalised = identity.normalize_self_link(name)
    key, reason = _canonical(category, hints,
                             **_accepted_parts(category, hints, normalised))
    if not key:
        return (), (_unresolved_verdict(normalised, reason, source),)
    return (TargetRef(category=category, key=key, how="document-name"),), ()


def _org_policy_target(document: Mapping[str, Any], hints: Hints, source: str
                       ) -> tuple[tuple[TargetRef, ...], tuple[Verdict, ...]]:
    """An org policy: from its v2 ``<node>/policies/<id>`` name, else from the
    v1 ``constraint`` plus the node the qualifiers name."""
    name = document.get("name")
    if isinstance(name, str) and name.count("/policies/") == 1:
        node, _, short = name.partition("/policies/")
        if node.strip() and short.strip() and "/" not in short:
            key, reason = _canonical("org_policies", hints, node=node.strip(),
                                     constraint=short.strip())
            if not key:
                return (), (_unresolved_verdict(name, reason, source),)
            return (TargetRef(category="org_policies", key=key,
                              how="document-name"),), ()
    constraint = document.get("constraint")
    if isinstance(constraint, str) and constraint.strip():
        node = hints.node()
        if not node:
            return (), (_unresolved_verdict(
                constraint.strip(),
                "a legacy org policy names its constraint but not the node it is set "
                "on; pass the organization, folder or project it applies to", source),)
        key, reason = _canonical("org_policies", hints, node=node,
                                 constraint=constraint.strip())
        if not key:
            return (), (_unresolved_verdict(constraint.strip(), reason, source),)
        return (TargetRef(category="org_policies", key=key, how="document-name"),), ()
    return (), (_unresolved_verdict(
        "", "the org policy names no unambiguous constraint, so it names no row",
        source),)


def _mapping_module() -> Any:
    """``tfsource.mapping``, or ``None`` where it is not part of this checkout.

    Imported LAZILY: ``tfsource`` imports DOWN into this layer and is never a
    hard dependency of it, so a checkout without the readers degrades to zero
    terraform targets rather than to an ImportError inside a gate.
    """
    try:
        return importlib.import_module("gcp_grounding.tfsource.mapping")
    except ImportError:
        logger.debug("gcp_grounding.tfsource.mapping is not part of this checkout "
                     "— terraform proposals yield no targets")
        return None


def _plan_objects(document: Any) -> tuple[Any, ...]:
    """The PROPOSED terraform objects a plan document carries, read through the
    one plan reader. Lazily imported, and an unreadable plan yields none."""
    try:
        plan = importlib.import_module("gcp_grounding.tfsource.plan")
    except ImportError:
        logger.debug("gcp_grounding.tfsource.plan is not part of this checkout "
                     "— a plan proposal yields no targets")
        return ()
    read = plan.read_plan_document(document, origin="<proposal>")
    if not read.ok:
        logger.debug("the plan proposal was refused: %s", "; ".join(read.notes))
        return ()
    return tuple(read.proposed)


def _terraform_targets(objects: Sequence[Any], hints: Hints, source: str
                       ) -> tuple[tuple[TargetRef, ...], tuple[Verdict, ...]]:
    """One target per terraform-MANAGED resource, keyed through the same
    ``canonical_from_object`` the capture side uses.

    A resource behind ``count`` or ``for_each`` yields NO TARGET and one
    ``baseline:unresolved``: a 0..N resource set has no single identity, the
    capture side already refuses exactly this construct, and the proposal side
    must not be more credulous about it than the capture side is.
    """
    mapping_module = _mapping_module()
    if mapping_module is None:
        return (), ()
    context = mapping_module.MapContext(
        project=hints.project, project_number=hints.project_number,
        region=hints.region, organization=hints.organization, folder=hints.folder,
        access_policy=hints.access_policy, aliases=_aliases(hints))
    targets: list[TargetRef] = []
    verdicts: list[Verdict] = []
    for obj in objects:
        if not mapping_module.is_managed(obj):
            continue
        resolved = mapping_module.canonical_from_object(obj, context)
        if resolved is None:
            continue                                # no mapper claims this type
        category, key, _record = resolved
        if facts.is_unresolved(key):
            verdicts.append(Verdict(
                "unverified", STATUS_KINDS["unresolved"], obj.address, 0,
                f"{obj.address}: no current counterpart was looked up because the "
                f"resource has no single identity ({key.reason}"
                f"{': ' + key.detail if key.detail else ''}) - a 0..N resource set "
                f"must not acquire a single-resource counterpart, and the capture "
                f"side refuses the same construct"))
            continue
        if not isinstance(key, str) or not key:
            continue
        targets.append(TargetRef(category=category, key=key, how="tf-address",
                                 address=obj.address))
    return tuple(targets), tuple(verdicts)


def targets_for(document: Any, kind: str | None, hints: Hints | None = None, *,
                source: str = "") -> tuple[tuple[TargetRef, ...], tuple[Verdict, ...]]:
    """Every current-state row *document* proposes to change, and the verdicts
    for the ones that could not be named.

    Four shapes, and no fifth: a terraform plan or configuration (one target per
    managed resource, primary by address), a self-naming REST document (its name
    or self-link), an org policy (its v2 name, or its v1 constraint plus the
    node), and a HINTED document (an IAM allow or deny policy, which names no
    resource of its own).
    """
    hints = hints or Hints()
    source = source or hints.source
    if kind in TF_KINDS:
        return _terraform_targets(_plan_objects(document), hints, source)
    if hints.objects:
        return _terraform_targets(hints.objects, hints, source)
    if kind in HINTED_KINDS or kind is None:
        return _hinted_target(kind, hints, source)
    if kind in KIND_CATEGORIES and isinstance(document, Mapping):
        return _named_target(document, kind, hints, source)
    return (), (_target_verdict(kind, source),)


# -- matching -----------------------------------------------------------------


@dataclass(frozen=True)
class _Match:
    """Which row a target matched, how, and the ambiguity that stopped it."""

    key: str = ""
    how: str = ""
    ambiguous: str = ""


def _primary(ledger: SourceLedger | None, target: TargetRef) -> tuple[str, str]:
    """``(key, ambiguity)`` from the locator index, SCOPED to the target's own
    category — see the module docstring on the side-fact trap."""
    if ledger is None or not target.address:
        return "", ""
    hits = ledger.by_locator(target.address, category=target.category)
    if not hits:
        return "", ""
    if len(hits) > 1:
        keys = ", ".join(sorted(key for _category, key in hits))
        return "", (f"terraform address '{target.address}' produced "
                    f"{len(hits)} facts in category '{target.category}' ({keys}); "
                    f"no single row is the counterpart")
    return sorted(hits)[0][1], ""


def _secondary(snapshot: GcpSnapshot | None, target: TargetRef
               ) -> tuple[str, bool, str]:
    """``(key, normalised, ambiguity)`` from the canonical key, then from the key
    after self-link normalisation."""
    held = _held_keys(snapshot, target.category)
    if not held:
        return "", False, ""
    if target.key in held:
        return target.key, False, ""
    wanted = identity.normalize_self_link(target.key)
    matches = sorted({key for key in held
                      if identity.normalize_self_link(key) == wanted})
    if len(matches) > 1:
        return "", True, (f"'{target.key}' normalises onto {len(matches)} rows of "
                          f"'{target.category}' ({', '.join(matches)}); no single "
                          f"row is the counterpart")
    if matches:
        return matches[0], True, ""
    return "", False, ""


def _match(snapshot: GcpSnapshot | None, ledger: SourceLedger | None,
           target: TargetRef) -> _Match:
    primary_key, primary_ambiguity = _primary(ledger, target)
    if primary_ambiguity:
        return _Match(ambiguous=primary_ambiguity)
    secondary_key, normalised, secondary_ambiguity = _secondary(snapshot, target)
    if secondary_ambiguity:
        return _Match(ambiguous=secondary_ambiguity)
    if primary_key and secondary_key and primary_key != secondary_key:
        return _Match(ambiguous=(
            f"the terraform address '{target.address}' names "
            f"'{primary_key}' while the resource's own attributes name "
            f"'{secondary_key}'; both rows exist in '{target.category}' and "
            f"neither is provably the counterpart"))
    if primary_key:
        return _Match(key=primary_key, how=target.how)
    if secondary_key:
        # A RENAMED resource: the address moved, the identity did not — so the
        # ATTRIBUTES are what identified it, and `how` says so.
        rewritten = bool(target.address) or normalised
        return _Match(key=secondary_key,
                      how="tf-attributes" if rewritten else target.how)
    return _Match()


def _candidates(ledger: SourceLedger | None, category: str, key: str,
                record: Any) -> tuple[Candidate, ...]:
    """Every source's whole record for this key, best fidelity first.

    The ledger's own winner leads a tie, because it won under the configured
    precedence and re-deciding that here would be a second merge algorithm.
    """
    if ledger is None:
        return (Candidate(source_id="", kind="unattributed", record=record),)
    origin = ledger.origin_of(category, key)
    winner = Candidate(
        source_id=origin.source_id if origin is not None else "",
        kind=(ledger.sources[origin.source_id].kind
              if origin is not None and origin.source_id in ledger.sources
              else "unattributed"),
        record=record,
        locator=origin.locator if origin is not None else "")
    others = [
        Candidate(source_id=alt.source_id,
                  kind=(ledger.sources[alt.source_id].kind
                        if alt.source_id in ledger.sources else "unattributed"),
                  record=alt.record, locator=alt.locator, reason=alt.reason)
        for alt in ledger.alternates_for(category, key)]
    ordered = [winner] + others
    ordered.sort(key=lambda c: (-c.rank(), 0 if c is winner else 1, c.source_id))
    return tuple(ordered)


def _conflicted(ledger: SourceLedger | None, category: str, key: str) -> bool:
    """Whether some source DISAGREED about this key.

    A losing alternate is recorded for every loser, agreeing or not, so the
    alternates alone are not the signal: a dispute or a ``disputed`` taint is.
    """
    if ledger is None:
        return False
    if ledger.taint_of(category, key) == "disputed":
        return True
    return any(d.category == category and d.key == key for d in ledger.disputes)


# -- resolution ---------------------------------------------------------------


def _absent_entry(target: TargetRef, scope: CategoryScope, source_id: str
                  ) -> BaselineEntry:
    return BaselineEntry(
        target=target, status="absent", scope=scope.scope,
        source_id=source_id,
        reason=(f"no current counterpart exists for '{target.key}': source "
                f"'{source_id or 'the current state'}' enumerated "
                f"'{target.category}' COMPLETELY and holds no such row, so this is "
                f"a new resource with no predecessor to compare it against"))


def _unqueried_entry(target: TargetRef, scope: CategoryScope,
                     covering: Sequence[str], reason: str | None) -> BaselineEntry:
    if not covering:
        detail = (f"no configured state source covers '{target.category}' at all, "
                  f"so nothing was looked up")
    else:
        detail = (f"every source covering '{target.category}' "
                  f"({', '.join(covering)}) is {scope.scope}, and absence within a "
                  f"{scope.scope} capture is NOT evidence of absence")
    return BaselineEntry(
        target=target, status="unqueried", scope=scope.scope,
        reason=(f"the current counterpart of '{target.key}' was NOT looked up: "
                f"{detail}. {reason or ''}").strip())


def resolve(target: TargetRef, snapshot: GcpSnapshot | None,
            ledger: SourceLedger | None) -> tuple[BaselineEntry, tuple[Verdict, ...]]:
    """One target's answer, plus any ``baseline:ambiguous`` verdict it earned.

    THE RESOLUTION ALGORITHM, reading the ledger:

    - no covering source at all → ``unqueried``, saying so;
    - covered, no hit, at least one COMPLETE covering scope → ``absent``,
      naming that source;
    - covered, no hit, only ``partial`` or ``undeclared`` scopes → ``unqueried``,
      listing every covering source and saying absence is not evidence;
    - a hit → the candidates sorted by fidelity, the first chosen and the rest
      carried in ``others``, with the ``conflict``, ``unresolved``, ``stale``
      and ``opaque`` flags carried even when they do not win and the status the
      first flag present in that order, else ``resolved``.
    """
    category = target.category
    scope = _scope_of(ledger, snapshot, category)
    matched = _match(snapshot, ledger, target)
    if matched.ambiguous:
        entry = BaselineEntry(target=target, status="opaque", scope=scope.scope,
                              flags=("opaque",), reason=matched.ambiguous)
        return entry, (Verdict("unverified", AMBIGUOUS_KIND, target.key, 0,
                               f"no baseline was used for '{target.key}': "
                               f"{matched.ambiguous} - a near-miss baseline is worse "
                               f"than none, because it silently redefines what the "
                               f"widening check compares against"),)
    if not matched.key:
        covering = covering_sources(ledger, category)
        reason = _completeness_reason(ledger, snapshot, category)
        if scope.scope == "uncaptured" or not covering:
            return _unqueried_entry(target, scope, (), None), ()
        if reason is None:
            return _absent_entry(target, scope, _completing_source(ledger, category)), ()
        return _unqueried_entry(target, scope, covering, reason), ()

    table = _table(snapshot, category)
    record = table.get(matched.key) if isinstance(table, Mapping) else None
    candidates = _candidates(ledger, category, matched.key, record)
    chosen = candidates[0]
    document, kind = project_record(category, matched.key, record)

    flags: list[str] = []
    reasons: list[str] = []
    if _conflicted(ledger, category, matched.key):
        flags.append("conflict")
        reasons.append(f"{len(candidates)} source(s) disagree about this row; the "
                       f"chosen document is '{chosen.source_id}' and every "
                       f"conflicting record is carried")
    if facts.has_unresolved(record) or facts.has_unresolved(matched.key):
        flags.append("unresolved")
        reasons.append("the current record carries a value terraform never "
                       "resolved, so it cannot be compared field by field")
    taint = ledger.taint_of(category, matched.key) if ledger is not None else ""
    if taint == "stale":
        flags.append("stale")
        reasons.append("the source this row came from is past its age ceiling")
    if document is None:
        flags.append("opaque")
        reasons.append(f"'{category}' has no counterpart DOCUMENT form, so a pair "
                       f"check has nothing to read")
    elif taint == "unmergeable":
        flags.append("opaque")
        reasons.append("this row could not be merged, so no single reading of it "
                       "is the baseline")
    elif rule_count(kind, document) == 0:
        flags.append("opaque")
        reasons.append(f"the current '{RULE_CHANNELS.get(kind or '', 'rule')}' set "
                       f"is EMPTY, and comparing against an empty baseline makes "
                       f"every widening trivially provable - a confident block "
                       f"manufactured out of a record with nothing in it")

    status = next((flag for flag in FLAG_ORDER if flag in flags), "resolved")
    entry = BaselineEntry(
        target=target, status=status, key=matched.key, document=document, kind=kind,
        record=record, source_id=chosen.source_id, scope=scope.scope,
        how=matched.how or target.how, others=candidates[1:], flags=tuple(flags),
        reason="; ".join(reasons))
    return entry, ()


def status_verdict(entry: BaselineEntry) -> Verdict:
    """*entry* as one ``unverified`` verdict — the full status-to-verdict
    mapping, TOTAL over :data:`RESOLUTION_STATUSES` and ``unverified``
    throughout, so no baseline status ever fails the gate by itself."""
    kind = STATUS_KINDS[entry.status]
    target = entry.key or entry.target.key
    reason = entry.reason or f"the baseline for '{target}' resolved {entry.status}"
    return Verdict("unverified", kind, target, 0,
                   f"{reason} [{entry.target.category} via {entry.how}]")


def key_mismatch_verdicts(entries: Sequence[BaselineEntry],
                          snapshot: GcpSnapshot | None,
                          ledger: SourceLedger | None) -> tuple[Verdict, ...]:
    """THE SYSTEMATIC-MISS DIAGNOSTIC: exactly one verdict per domain where
    every target missed against a source that demonstrably holds rows.

    Three conditions, all required: every target in the domain resolved
    ``absent``, at least TWO were looked up, and the covering complete source
    holds at least one key of its own. It never changes a status and never
    replaces the per-target verdicts — it is the guard against the failure
    ``baseline:ambiguous`` structurally cannot catch, because a key-form
    regression makes every lookup miss cleanly and every miss then reads as a
    perfectly confident "this resource is new".
    """
    by_category: dict[str, list[BaselineEntry]] = {}
    for entry in entries:
        by_category.setdefault(entry.target.category, []).append(entry)
    verdicts: list[Verdict] = []
    for category in sorted(by_category):
        group = by_category[category]
        if len(group) < 2 or any(e.status != "absent" for e in group):
            continue
        held = _held_keys(snapshot, category)
        if not held:
            continue
        looked_up = sorted(e.target.key for e in group)
        verdicts.append(Verdict(
            "unverified", KEY_MISMATCH_KIND, category, 0,
            f"all {len(group)} '{category}' target(s) resolved absent against a "
            f"complete source that holds {len(held)} row(s) of its own - for "
            f"example '{looked_up[0]}' was looked up while '{held[0]}' is held. "
            f"ZERO matched, which usually means the two layers disagree on the KEY "
            f"FORM rather than that every resource is new"))
    return tuple(verdicts)


def derive(document: Any, kind: str | None, current: Any, *,
           hints: Hints | None = None, source: str = "") -> Derivation:
    """The current counterpart of every row *document* proposes to change.

    Never opens a file. An EXPLICIT baseline is not a special case here: it is
    loaded into an ``explicit-baseline`` source before this function runs, wins
    by ordinary fidelity precedence, and appears in the provenance rows like
    every other source.

    One verdict per entry that did NOT resolve cleanly, and none for one that
    did: a ``resolved`` baseline is carried in :meth:`Derivation.rows` where the
    explain surface can read it, and emitting an ``unverified`` for every clean
    resolution would train a reader to ignore the channel the shortfalls arrive
    on. :func:`status_verdict` still maps every status, ``resolved`` included,
    so a caller that wants the row as a verdict can have it.
    """
    hints = hints or Hints()
    source = source or hints.source
    snapshot, ledger = current_view(current)
    if snapshot is not None and not hints.aliases:
        hints = _with_aliases(hints, snapshot)

    targets, verdicts = targets_for(document, kind, hints, source=source)
    entries: list[BaselineEntry] = []
    collected: list[Verdict] = list(verdicts)
    for target in targets:
        entry, ambiguity = resolve(target, snapshot, ledger)
        entries.append(entry)
        collected.extend(ambiguity)
        if not ambiguity and entry.status != "resolved":
            collected.append(status_verdict(entry))
    collected.extend(key_mismatch_verdicts(entries, snapshot, ledger))

    notes: list[str] = []
    if snapshot is None:
        notes.append("no current state was configured, so every counterpart is "
                     "unqueried rather than absent")
    logger.debug("baseline.derive(%s): %d target(s), %d entr(y|ies), %d verdict(s)",
                 source or kind, len(targets), len(entries), len(collected))
    return Derivation(entries=tuple(entries), verdicts=tuple(collected),
                      notes=tuple(notes))


def _with_aliases(hints: Hints, snapshot: GcpSnapshot) -> Hints:
    """*hints* carrying the snapshot's project-number alias map, so a key built
    here resolves a number exactly as the capture side does."""
    try:
        table = identity.alias_map(snapshot)
    except Exception:                               # noqa: BLE001 - never crash a gate
        logger.debug("the alias map could not be read — numbers stay distinct",
                     exc_info=True)
        return hints
    if not table:
        return hints
    return Hints(target=hints.target, category=hints.category, targets=hints.targets,
                 tool_input=hints.tool_input, source=hints.source,
                 objects=hints.objects, project=hints.project,
                 project_number=hints.project_number, region=hints.region,
                 organization=hints.organization, folder=hints.folder,
                 access_policy=hints.access_policy, aliases=table)
