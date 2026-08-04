"""THE one mapper registry: the single seam between the three readers and the
two domain mappers.

There is no second registry and no per-reader adapter table. A tfstate object, a
plan object and an HCL object all arrive here as the same
:class:`gcp_grounding.facts.TfObject` and leave as the same
:class:`gcp_grounding.facts.Fact` values, so a domain mapper is written once and
serves all three.

THE MAPPER CONTRACT
-------------------

``obj.values`` is ALWAYS in the plan-JSON encoding — snake_case attribute names,
repeated blocks as LISTS of objects (``values["allow"]`` is
``[{"protocol": "tcp", "ports": ["22"]}]`` even for a single block) — regardless
of which reader produced the object. Normalising to one encoding is layer 1's
job precisely so that a mapper is written once; a mapper that sniffs which
reader it is talking to has re-created the per-reader adapter table this module
exists to prevent.

A mapper is ``map(obj, ctx) -> Sequence[Fact]``. It may return zero facts (an
object it cannot resolve a key for), one, or several — a resource that speaks
for two categories emits one fact per category. It builds every key through
:meth:`MapContext.key`, which is :func:`gcp_grounding.identity.key_or_unresolved`
with this context's qualifiers filled in.

WHAT THIS MODULE PROMISES
-------------------------

- **Lazy, forgiving module resolution.** :data:`MAP_MODULES` is resolved on
  first use and an ``ImportError`` is swallowed, so a checkout missing one
  domain mapper degrades to missing COVERAGE — recorded in
  :attr:`MapResult.unrecognized` and counted in the census note — rather than to
  an import crash that decides nothing at all.
- **Deterministic duplicate resolution.** Two registrations of one resource type
  keep the FIRST and log a warning naming both modules. Two mappers for one type
  is two answers for one object, and picking the last would make the answer
  depend on import order.
- **Per-mapper crash isolation.** An exception from a domain mapper becomes a
  :class:`Failure` row naming the address, the type and the exception, and the
  other mappers still run. A crashing mapper degrades to missing coverage and
  never to a broken capture.
- **A known gap reads differently from an oversight.** A type in
  :data:`DELIBERATELY_UNMAPPED` lands in :attr:`MapResult.unmapped` with the
  reason it is not modelled; a type nobody has considered lands in
  :attr:`MapResult.unrecognized` and is counted by the census note.

THE MULTIPLICITY RULE
---------------------

The most important rule in this module. An object behind ``count`` or
``for_each`` is 0..N real objects, so NO keyed fact can be attributed to it:
:func:`map_objects` emits ZERO facts for it and one :class:`MapRow` in
:attr:`MapResult.skipped` naming the address and the reason. Emitting one fact
would attribute a name to a resource SET whose membership is unknown, and
dropping it silently would make the gap invisible.

**The same rule applies on the PROPOSED side, and it is the same rule, not a
second one.** :func:`canonical_from_object` returns a
:class:`gcp_grounding.facts.Unresolved` in the KEY position rather than a string
for such an object, because a 0..N resource set has no single identity on either
side. Without it, ``targets_for`` would hand a single-resource counterpart to a
resource set whose membership is unknown — the capture side refuses exactly
that, and the proposal side must not be more credulous than the capture side
about the same terraform construct.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Sequence

from .. import facts, identity
from ..core.log import get_logger

logger = get_logger(__name__)

__all__ = [
    "MAP_MODULES",
    "DELIBERATELY_UNMAPPED",
    "MULTIPLICITY_META",
    "MULTIPLICITY_REASONS",
    "CENSUS_SAMPLE",
    "MapContext",
    "Mapper",
    "MapRow",
    "Failure",
    "MapResult",
    "register",
    "mappers",
    "reset_cache",
    "is_managed",
    "multiplicity",
    "canonical_from_object",
    "map_objects",
]

#: The domain mapper modules, resolved LAZILY and by NAME. Importing them
#: eagerly at module import would make this seam depend on both domains being
#: present, which is the crash this list exists to avoid: a missing module is
#: missing coverage, recorded and counted, and never an import error inside a
#: gate. A module registers its types at import time by calling :func:`register`.
MAP_MODULES = (
    "gcp_grounding.tfsource.map_network",
    "gcp_grounding.tfsource.map_iam",
)

#: Terraform resource types this design does NOT model, and why. A type here
#: reads as a KNOWN GAP rather than as an oversight: it is excluded from the
#: census note, because the census exists to surface types nobody has considered
#: yet. Each reason names the estate category the type would have to belong to
#: and why it does not.
DELIBERATELY_UNMAPPED = {
    "google_project_service": (
        "enabling an API is not one of the estate categories; the service "
        "vocabulary is Google's and a configuration names only the services it "
        "happens to use"),
    "google_compute_instance": (
        "workload inventory is not policy: an instance is reached BY the "
        "firewall rules this design models, and modelling it would grow an "
        "existence answer about a population terraform never enumerates"),
    "google_storage_bucket": (
        "bucket existence is not an estate category; the bucket's IAM policy is, "
        "and that is a google_storage_bucket_iam_* resource"),
    "google_compute_route": (
        "routes are reachability, not authorization; nothing in the rule set "
        "reads them, so a captured route would be a fact no check could use"),
    "google_service_account_key": (
        "the estate models the ACCOUNT, never its keys: a key is a secret, and "
        "capturing one would put credential material in a snapshot on disk"),
}

#: The meta-arguments that turn one resource block into 0..N real objects.
MULTIPLICITY_META = ("count", "for_each")

#: The :data:`gcp_grounding.facts.UNRESOLVED_REASONS` spellings a reader uses
#: for those meta-arguments. A generated BLOCK has its own spelling
#: (``dynamic_block``), so a marker carrying one of THESE is the resource's own
#: multiplicity — and where a reader is imprecise the cost is one honestly
#: recorded ``skipped`` row, never a fact attributed to a resource set.
MULTIPLICITY_REASONS = frozenset(MULTIPLICITY_META)

#: How many addresses the census note lists before it summarises.
CENSUS_SAMPLE = 5

#: Qualifier parts that are ALTERNATIVES to one another. A category that accepts
#: both means "one or the other" — a custom role lives in a project OR an
#: organization, never both — so a context that happens to know both must not
#: turn a mapper's explicit qualifier into an ambiguity.
_EXCLUSIVE_PARTS = (("project", "organization"),)


# -- the context --------------------------------------------------------------


def _bare(value: str, prefix: str) -> str:
    """``organizations/1`` → ``1``; anything else unchanged."""
    return value[len(prefix):] if value.startswith(prefix) else value


@dataclass(frozen=True)
class MapContext:
    """The qualifiers a bare terraform name cannot supply.

    A terraform ``google_compute_firewall`` names ``allow-internal``; the estate
    keys ``projects/acme-prod/global/firewalls/allow-internal``. The project,
    region, organization, folder and access policy that close that gap come from
    the artifact's provider block, its backend or its workspace — never from the
    resource — and a MISSING one yields a
    :class:`gcp_grounding.facts.Unresolved` through
    :func:`gcp_grounding.identity.key_or_unresolved`, NEVER a guess: a key built
    from an assumed project is a confident answer about a resource in some other
    project.

    ``aliases`` is :func:`gcp_grounding.identity.alias_map`'s output, read by the
    three categories that key on a hierarchy node.
    """

    project: str = ""
    project_number: str = ""
    region: str = ""
    organization: str = ""
    folder: str = ""
    access_policy: str = ""
    aliases: Mapping[str, str] = field(default_factory=dict)

    def alias_table(self) -> dict[str, str]:
        """The alias map this context can answer with — the captured one, plus
        its own ``project_number`` → ``project`` pair when both are known. The
        CAPTURED alias always wins: an estate that disagrees with a workspace's
        idea of its own number is a conflict to keep, not one to overwrite."""
        table = dict(self.aliases)
        if self.project_number and self.project:
            table.setdefault(self.project_number, self.project)
        return table

    def parts_for(self, category: str) -> dict[str, str]:
        """The key parts THIS context can supply for ``category`` — only the
        parts that category's spec actually accepts, so a qualifier nobody reads
        is never silently dropped into a key build."""
        spec = identity.SPECS.get(category)
        if spec is None:
            return {}
        out: dict[str, str] = {}
        if "project" in spec.parts and self.project:
            out["project"] = _bare(self.project, "projects/")
        if "region" in spec.parts and self.region:
            out["region"] = _bare(self.region, "regions/")
        if "organization" in spec.parts and self.organization:
            out["organization"] = _bare(self.organization, "organizations/")
        if "access_policy" in spec.parts and self.access_policy:
            out["access_policy"] = _bare(self.access_policy, "accessPolicies/")
        if "parent" in spec.parts:
            if self.organization:
                out["parent"] = f"organizations/{_bare(self.organization, 'organizations/')}"
            elif self.folder:
                out["parent"] = f"folders/{_bare(self.folder, 'folders/')}"
        return out

    def key(self, category: str, *, path: str = "",
            **parts: Any) -> str | facts.Unresolved:
        """THE key for one mapped object: every qualifier the caller could not
        supply filled in from this context, then
        :func:`gcp_grounding.identity.key_or_unresolved`.

        A part the caller passes as ``None`` or blank counts as NOT SUPPLIED and
        lets the context's qualifier stand; a part the caller does supply always
        WINS, including over a context qualifier that would contradict it. An
        unknown part name still raises, because that is a bug in a mapper and
        not ignorance about the artifact.
        """
        merged: dict[str, Any] = dict(self.parts_for(category))
        supplied: dict[str, Any] = {}
        for name, value in parts.items():
            if value is None or (isinstance(value, str) and not value.strip()):
                continue
            supplied[name] = value
        for group in _EXCLUSIVE_PARTS:
            claimed = [name for name in group if name in supplied]
            if claimed:
                for name in group:
                    if name not in claimed:
                        merged.pop(name, None)
                continue
            present = [name for name in group if name in merged]
            for name in present[1:]:
                logger.debug("context supplies %s and %s for %s, which are "
                             "alternatives — keeping %s", present[0], name,
                             category, present[0])
                merged.pop(name, None)
        merged.update(supplied)
        return identity.key_or_unresolved(
            category, aliases=self.alias_table(),
            path=path or f"tfsource.mapping.{category}", **merged)


# -- the registry -------------------------------------------------------------


@dataclass(frozen=True)
class Mapper:
    """One registered domain mapper, and the module that claimed the type.

    ``category`` is the estate category this resource type's OWN identity lives
    in — the one :func:`canonical_from_object` reports. A mapper may emit facts
    in other categories too (a firewall rule names a network tag), which is why
    the category is a property of the type and not a filter on the output.
    """

    resource_type: str
    category: str
    map: Callable[..., Any]
    module: str
    note: str = ""


_REGISTRY: dict[str, Mapper] = {}
_LOADED = False


def _ensure_loaded() -> None:
    """Resolve :data:`MAP_MODULES` exactly once. An ``ImportError`` is
    swallowed at DEBUG: a checkout missing one domain mapper must degrade to
    missing coverage, which the census note makes visible, and never to an
    import crash inside a gate."""
    global _LOADED
    if _LOADED:
        return
    # Set BEFORE importing: a mapper module registers its types at import time,
    # and that call must not recurse back into this function.
    _LOADED = True
    for name in MAP_MODULES:
        try:
            importlib.import_module(name)
        except ImportError as exc:
            logger.debug("mapper module %s is not in this checkout (%s: %s) — the "
                         "types it would claim stay unrecognized and are counted "
                         "in the census note", name, type(exc).__name__, exc)


def register(resource_type: str, mapper: Callable[..., Any], *, category: str,
             module: str = "", note: str = "") -> Mapper:
    """Register THE mapper for one terraform resource type, and return the entry
    that is in force afterwards.

    A DUPLICATE registration keeps the FIRST deterministically and logs a
    warning naming both modules: two mappers for one type is two answers for one
    object, and keeping the last would make which answer wins depend on import
    order. The returned entry is therefore the incumbent, not necessarily the
    one just passed in.

    Raises for a CALLER error — an empty type, a non-callable mapper, a category
    outside :data:`gcp_grounding.facts.TF_CATEGORIES`, or a type that is also
    listed in :data:`DELIBERATELY_UNMAPPED`. Those are bugs in a mapper, and a
    bug swallowed here would read as an honest gap.
    """
    if not resource_type:
        raise ValueError("mapping.register needs the terraform resource type "
                         "(e.g. 'google_compute_firewall')")
    if not callable(mapper):
        raise ValueError(f"mapping.register({resource_type!r}): the mapper must be "
                         f"callable, got {type(mapper).__name__}")
    if category not in facts.TF_CATEGORIES:
        detail = facts.EXCLUDED_CATEGORIES.get(category)
        raise ValueError(
            f"mapping.register({resource_type!r}): category {category!r} is not one "
            f"of {list(facts.TF_CATEGORIES)}"
            + (f" — {detail}" if detail else ""))
    if resource_type in DELIBERATELY_UNMAPPED:
        raise ValueError(
            f"mapping.register({resource_type!r}): this type is in "
            f"DELIBERATELY_UNMAPPED ({DELIBERATELY_UNMAPPED[resource_type]}); a "
            f"type cannot be both a stated gap and a mapped one — remove it from "
            f"the list in the same change that maps it")
    _ensure_loaded()
    module = module or getattr(mapper, "__module__", "") or "<unknown>"
    existing = _REGISTRY.get(resource_type)
    if existing is not None:
        logger.warning(
            "terraform type %s is claimed by two mappers: %s registered it first "
            "and KEEPS it, %s is ignored — two mappers for one type is two answers "
            "for one object", resource_type, existing.module, module)
        return existing
    entry = Mapper(resource_type, category, mapper, module, note)
    _REGISTRY[resource_type] = entry
    return entry


def mappers() -> Mapping[str, Mapper]:
    """The resolved registry, resource type → :class:`Mapper`, read-only."""
    _ensure_loaded()
    return MappingProxyType(_REGISTRY)


def reset_cache() -> None:
    """Forget the resolved registry so the next lookup re-resolves
    :data:`MAP_MODULES`. For TESTS: registration is import-time and therefore
    process-global, and a test that registers a stub would otherwise leak it
    into every test that runs after it."""
    global _LOADED
    _REGISTRY.clear()
    _LOADED = False


# -- the objects --------------------------------------------------------------


@dataclass(frozen=True)
class MapRow:
    """One object that produced no facts, and why. ``reason`` is a short
    greppable token (an :data:`gcp_grounding.facts.UNRESOLVED_REASONS` spelling
    for a skipped row); ``detail`` is the sentence a reader of the ledger needs.
    """

    address: str
    type: str
    reason: str
    detail: str = ""


@dataclass(frozen=True)
class Failure:
    """A domain mapper that RAISED, named by address, type and exception.

    A failure is not an abstention: it is a bug in a mapper, recorded so the
    missing coverage it caused is visible instead of looking like a resource
    that simply had nothing to say.
    """

    address: str
    type: str
    exception: str
    detail: str = ""
    module: str = ""


@dataclass(frozen=True)
class MapResult:
    """Everything one mapping pass produced, including everything it did not.

    ``unrecognized`` (nobody has considered this type) is kept separate from
    ``unmapped`` (:data:`DELIBERATELY_UNMAPPED` — a stated gap), so a known gap
    reads differently from an oversight. ``skipped`` holds the multiplicity rows
    and ``failures`` the mapper crashes; ``notes`` carries the census.
    """

    facts: tuple[facts.Fact, ...] = ()
    unrecognized: tuple[MapRow, ...] = ()
    unmapped: tuple[MapRow, ...] = ()
    failures: tuple[Failure, ...] = ()
    skipped: tuple[MapRow, ...] = ()
    notes: tuple[str, ...] = ()


# -- the multiplicity rule ----------------------------------------------------


def is_managed(obj: facts.TfObject) -> bool:
    """False for a data SOURCE. Terraform READS a data source and does not
    manage it, so its absence from a configuration says nothing about the estate
    — and the census counts terraform-MANAGED resources only."""
    segments = obj.address.split(".")
    for index, segment in enumerate(segments[:-1]):
        if segment != "data" or index + 1 >= len(segments):
            continue
        if segments[index + 1].split("[")[0] == obj.type:
            return False
    return True


def multiplicity(obj: facts.TfObject) -> facts.Unresolved | None:
    """THE MULTIPLICITY RULE: the marker for an object that is 0..N objects, or
    ``None`` for one that is exactly one.

    Three signals, in order: a ``count``/``for_each`` key in the object's own
    attributes (a reader that passes the meta-argument through), a
    ``count``/``for_each`` marker in the object's roll-up, and one nested
    anywhere in its values. A marker a reader already minted is returned
    UNCHANGED, so the skipped row keeps the path the reader named.
    """
    values = obj.values if isinstance(obj.values, Mapping) else {}
    for meta in MULTIPLICITY_META:
        if meta not in values:
            continue
        value = values[meta]
        if facts.is_unresolved(value) and value.reason in MULTIPLICITY_REASONS:
            return value
        return facts.Unresolved(
            meta, f"{obj.address}.{meta}",
            f"{obj.type} is behind {meta}: 0..N objects, not one")
    for marker in obj.unresolved:
        if marker.reason in MULTIPLICITY_REASONS:
            return marker
    for _path, marker in facts.unresolved_in(values):
        if marker.reason in MULTIPLICITY_REASONS:
            return marker
    return None


# -- mapping ------------------------------------------------------------------


def _as_facts(produced: Any, entry: Mapper) -> tuple[facts.Fact, ...]:
    """A mapper's return value as facts, or ``TypeError``. Called INSIDE the
    crash-isolated block, so a mapper that returns junk is recorded exactly like
    a mapper that raises rather than poisoning the capture with it."""
    if produced is None:
        return ()
    if isinstance(produced, facts.Fact):
        return (produced,)
    if isinstance(produced, (str, bytes, bytearray)) or not isinstance(produced, Iterable):
        raise TypeError(f"mapper for {entry.resource_type} returned "
                        f"{type(produced).__name__}, not a sequence of facts.Fact")
    rows = tuple(produced)
    for row in rows:
        if not isinstance(row, facts.Fact):
            raise TypeError(f"mapper for {entry.resource_type} returned a "
                            f"{type(row).__name__} where a facts.Fact was expected")
    return rows


def canonical_from_object(obj: facts.TfObject, ctx: MapContext
                          ) -> tuple[str, str | facts.Unresolved,
                                     Mapping[str, Any] | None] | None:
    """The ``(category, key, record)`` triple for ONE object — the translation
    BOTH sides use.

    Exported for the PROPOSED side: ``baseline.derive`` computes a proposed
    terraform resource's key through this function, so the capture side and the
    proposal side cannot drift apart into two spellings of one resource.

    Returns ``None`` when no mapper claims the type — there is nothing to say
    about it, which is different from having something unresolved to say. When
    the object is behind ``count`` or ``for_each`` the KEY position holds a
    :class:`gcp_grounding.facts.Unresolved` with that reason instead of a
    string: a 0..N resource set has no single identity on either side, and the
    proposal side must not be more credulous than the capture side about the
    same construct. A mapper that raises degrades the same way — an unresolved
    identity, never a guessed one.
    """
    entry = mappers().get(obj.type)
    if entry is None:
        return None
    marker = multiplicity(obj)
    if marker is not None:
        return (entry.category, marker, None)
    try:
        produced = _as_facts(entry.map(obj, ctx), entry)
    except Exception as exc:                       # noqa: BLE001 - isolation is the point
        logger.warning("mapper %s raised on %s (%s): %s: %s — the object's identity "
                       "is unresolved rather than guessed", entry.module, obj.address,
                       obj.type, type(exc).__name__, exc)
        return (entry.category,
                facts.Unresolved("unparsed", obj.address,
                                 f"mapper {entry.module} raised "
                                 f"{type(exc).__name__}"), None)
    for fact in produced:
        if fact.category == entry.category:
            return (fact.category, fact.key, fact.record)
    if produced:
        first = produced[0]
        return (first.category, first.key, first.record)
    return (entry.category,
            facts.Unresolved("ambiguous_key", obj.address,
                             "the mapper produced no fact for this object"), None)


def _census(addresses: Sequence[str]) -> tuple[str, ...]:
    """The census note: how many terraform-managed ``google_*`` resources have
    no mapper, and the first :data:`CENSUS_SAMPLE` addresses.

    Counts the UNRECOGNIZED types only. A :data:`DELIBERATELY_UNMAPPED` type is
    a stated gap and reads as one; this note exists to make the gaps nobody has
    considered visible in the ledger rather than silent.
    """
    if not addresses:
        return ()
    sample = ", ".join(addresses[:CENSUS_SAMPLE])
    note = (f"{len(addresses)} terraform-managed google_* resource(s) have no "
            f"mapper: {sample}")
    if len(addresses) > CENSUS_SAMPLE:
        note += f" (first {CENSUS_SAMPLE} of {len(addresses)})"
    return (note,)


def map_objects(objects: Iterable[facts.TfObject], ctx: MapContext) -> MapResult:
    """Map every object through the one registry, keeping every gap.

    Nothing here can fail the pass: a type nobody maps, a type deliberately not
    mapped, a resource set behind ``count``/``for_each`` and a mapper that
    raises each produce a ROW and the loop continues, so one bad object costs
    one object's coverage instead of the whole capture.
    """
    table = mappers()
    collected: list[facts.Fact] = []
    unrecognized: list[MapRow] = []
    unmapped: list[MapRow] = []
    failures: list[Failure] = []
    skipped: list[MapRow] = []
    census: list[str] = []
    for obj in objects:
        marker = multiplicity(obj)
        if marker is not None:
            skipped.append(MapRow(
                obj.address, obj.type, marker.reason,
                marker.detail or (f"{obj.type} is behind {marker.reason}: 0..N "
                                  f"objects, so no keyed fact can name it")))
            logger.debug("%s is behind %s — zero facts and one skipped row",
                         obj.address, marker.reason)
            continue
        entry = table.get(obj.type)
        if entry is None:
            stated = DELIBERATELY_UNMAPPED.get(obj.type)
            if stated is not None:
                unmapped.append(MapRow(obj.address, obj.type, "deliberate", stated))
                continue
            unrecognized.append(MapRow(
                obj.address, obj.type, "no_mapper",
                "no mapper claims this terraform type, and it is not a stated gap"))
            if obj.type.startswith("google_") and is_managed(obj):
                census.append(obj.address)
            continue
        try:
            produced = _as_facts(entry.map(obj, ctx), entry)
        except Exception as exc:                   # noqa: BLE001 - isolation is the point
            failures.append(Failure(obj.address, obj.type, type(exc).__name__,
                                    facts.truncate(str(exc)), entry.module))
            logger.warning("mapper %s crashed on %s (%s): %s: %s — the object "
                           "contributes no facts and the capture continues",
                           entry.module, obj.address, obj.type,
                           type(exc).__name__, exc)
            continue
        collected.extend(produced)
    return MapResult(tuple(collected), tuple(unrecognized), tuple(unmapped),
                     tuple(failures), tuple(skipped), _census(census))
