"""THE single entry point that builds the current-state view: resolve, merge,
age, reconcile — and never raise.

Everything above this module is pure and everything below it is a caller. There
is no second assembler, no provider-module protocol and no api-view adapter:
:class:`~gcp_grounding.knowledge.GcpSnapshot` IS the canonical current-state
object, so the API side's "adapter" is the identity function and does not exist
as code. What does exist here is the ORDER the pieces run in, and the fail-open
boundary around every one of them.

THE ENVIRONMENT, AND WHY EVERY OPTION HAS ONE
---------------------------------------------
Env-first resolution is deliberate: the whole capability ships even if a CLI
task is deferred, so a library caller, a hook and a CI job can configure a
second source today.

============================== ================================================
``GCP_GROUNDING_SNAPSHOT``     the primary snapshot (the existing ``--snapshot``
                               spelling, reused rather than renamed)
``GCP_GROUNDING_ORIGINS``      that snapshot's sidecar, when it is not beside it
``GCP_GROUNDING_MERGE_SOURCES`` additional snapshot paths, ``os.pathsep``-separated
``GCP_GROUNDING_TF_STATE``     terraform state paths, same separator
``GCP_GROUNDING_TF_PLAN``      terraform plan-JSON paths, same separator
``GCP_GROUNDING_TF_DIR``       terraform directories to walk, same separator
``GCP_GROUNDING_PRECEDENCE``   a :func:`gcp_grounding.merge.parse_policy` spec
``GCP_GROUNDING_DRIFT_POLICY`` one of :data:`gcp_grounding.drift.DRIFT_POLICIES`
``GCP_GROUNDING_MAX_AGE``      a :func:`gcp_grounding.freshness.parse_duration` ceiling
``GCP_GROUNDING_NOW``          the pinned clock (:data:`gcp_grounding.freshness.NOW_ENV`)
``GCP_GROUNDING_REDACT_SALT``  the digest salt (:data:`gcp_grounding.redact.SALT_ENV`)
``GCP_GROUNDING_PROVIDER_SCHEMA`` captured ``terraform providers schema -json``
                               path(s), ``os.pathsep``-separated
                               (:data:`gcp_grounding.provider_schema.PROVIDER_SCHEMA_ENV`)
``GCP_GROUNDING_SCHEMA_POLICY`` one of :data:`gcp_grounding.provider_schema.SCHEMA_POLICIES`
============================== ================================================

The two provider-schema options ride on :class:`SourceOptions` so the settings
layers, the origin tracking and ``--state-explain`` treat them like every other
setting — but they are NOT current-state sources: :meth:`SourceOptions
.configured` does not list them, ``load_current`` never reads them, and the
schema file is consumed by :mod:`gcp_grounding.tf_schema_checks` through
:mod:`gcp_grounding.provider_schema` alone.

``completeness`` is the ONE option with no environment variable, on purpose. It
is the licence to read an absence as a non-existence, and an exported variable
is exactly the kind of thing a shell inherits into a run nobody meant to license.
It is set explicitly — ``--completeness`` or the config key — or not at all.

WHAT ``from_env`` KNOWS, AND WHAT IT DOES NOT
---------------------------------------------
:func:`from_env` resolves ENV AND EXPLICIT OVERRIDES ONLY. It knows nothing
about a config file and nothing about auto-detection, and those limits are
NORMATIVE: any caller that has a CLI layer MUST route through
``discovery.resolve_settings`` and hand this module the ``SourceOptions`` that
produces. Building options with :func:`from_env` on a path that also promises
config-file discovery silently bypasses the config-file and auto-detect layers —
a snapshot path the user wrote in a config file is ignored with NO error. The
run succeeds; it just used the wrong state.

THE UNATTRIBUTED DEFAULT IS DECIDED BY SNAPSHOT SHAPE, NOT BY SOURCE COUNT
-------------------------------------------------------------------------
A snapshot that arrives without a sidecar has to be given a coverage scope, and
getting that choice wrong is the single failure this whole design exists to
prevent. The rule, in :func:`default_completeness`:

- a snapshot carrying AT LEAST ONE estate RECORD TABLE (:data:`ESTATE_TABLES`)
  defaults to ``undeclared``;
- only the LEGACY VOCABULARY-ONLY shape — no estate record table at all, which
  is exactly ``tests/fixtures/gcp/snapshot.json`` — defaults to ``complete``,
  where it reproduces today's behaviour exactly.

SOURCE COUNT IS THE WRONG DISCRIMINATOR. ``gcp-ground verify-policy --snapshot
terraform-snapshot.json`` with the sidecar lost, renamed or simply not copied is
a SINGLE source; under a count-based rule it would be read as a licensed-complete
view of a terraform-only estate — false ``baseline:new`` instead of
``baseline:unqueried``, false ``ungrounded`` on every licensed category, and
``contradicted`` from requires-complete widening checks.

This is NOT completeness inferred from CONTENT: nothing here reads how POPULATED
a category is. It reads which SCHEMA SHAPE the document is, to choose which
default applies. The estate-table shape did not exist before this design, so no
legacy behaviour depends on it. To license absence for an estate table with no
sidecar the operator must say so explicitly, with ``completeness="complete"``;
there is no way to get it by accident.

THE FAIL-OPEN CONTRACT
----------------------
:func:`load_current` NEVER RAISES. Every step is wrapped, an unexpected
exception becomes ONE ``provenance`` verdict naming the step and the exception
type, and the primary snapshot comes back UNRECONCILED — so a merge bug can
never take down a gate that worked yesterday. A configured source that FAILS
becomes one ``state:source`` verdict naming the path and saying that source
contributed nothing, because a failing source must never silently reduce
coverage. Zero configured sources returns an empty current state and zero
verdicts: configuring nothing is not an error.

ONE SOURCE IS THE IDENTITY PATH. With exactly one source there is nothing to
reconcile, so the snapshot and its resolved ledger ARE the current state, byte
for byte. A merge runs only when two or more sources are in play, and a merged
view withholds the existence LICENCE (``estate.build`` grants it only to a
category opted in by name, and the four unconditionally emitted categories can
never be opted in) — absence reasoning over a merged view abstains, which is the
safe direction.
"""

from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable, Mapping, Sequence

from . import (drift, estate, facts, freshness, knowledge, merge, provenance,
               provider_schema, redact)
from .core.log import get_logger
from .core.report import Verdict
from .knowledge import GcpSnapshot
from .provenance import SourceLedger, SourceRecord
from .reconciled import ReconciledSnapshot

logger = get_logger(__name__)

__all__ = [
    "PRIMARY_ENV",
    "ORIGINS_ENV",
    "MERGE_SOURCES_ENV",
    "TF_STATE_ENV",
    "TF_PLAN_ENV",
    "TF_DIR_ENV",
    "PRECEDENCE_ENV",
    "DRIFT_POLICY_ENV",
    "MAX_AGE_ENV",
    "NOW_ENV",
    "SALT_ENV",
    "PROVIDER_SCHEMA_ENV",
    "SCHEMA_POLICY_ENV",
    "PATH_FIELDS",
    "ENV_FIELDS",
    "ESTATE_TABLES",
    "SOURCE_KINDS",
    "PROVENANCE_KINDS",
    "NOTE_ORDER",
    "SourceOptions",
    "from_env",
    "sidecar_path",
    "default_completeness",
    "has_estate_table",
    "LoadedSource",
    "CurrentState",
    "vault",
    "snapshot_facts",
    "load_source",
    "load_terraform",
    "load_current",
    "write_reconciled",
    "order_notes",
]

# -- the environment ----------------------------------------------------------

#: The primary snapshot. The SAME spelling ``cli.SNAPSHOT_ENV`` already uses —
#: reused rather than renamed, because two names for one snapshot is two states
#: a user can be in without knowing which one the gate read.
PRIMARY_ENV = "GCP_GROUNDING_SNAPSHOT"
#: The primary snapshot's sidecar, when it does not live beside the snapshot.
ORIGINS_ENV = "GCP_GROUNDING_ORIGINS"
#: Additional snapshot paths, separated by :data:`os.pathsep`.
MERGE_SOURCES_ENV = "GCP_GROUNDING_MERGE_SOURCES"
#: Terraform state paths, same separator.
TF_STATE_ENV = "GCP_GROUNDING_TF_STATE"
#: Terraform plan-JSON paths, same separator.
TF_PLAN_ENV = "GCP_GROUNDING_TF_PLAN"
#: Terraform directories to walk, same separator.
TF_DIR_ENV = "GCP_GROUNDING_TF_DIR"
#: A :func:`gcp_grounding.merge.parse_policy` spec.
PRECEDENCE_ENV = "GCP_GROUNDING_PRECEDENCE"
#: One of :data:`gcp_grounding.drift.DRIFT_POLICIES`.
DRIFT_POLICY_ENV = "GCP_GROUNDING_DRIFT_POLICY"
#: A :func:`gcp_grounding.freshness.parse_duration` ceiling.
MAX_AGE_ENV = "GCP_GROUNDING_MAX_AGE"
#: The pinned clock. Owned by ``freshness`` — read from there rather than
#: respelled, so the two can never disagree about the name of the test clock.
NOW_ENV = freshness.NOW_ENV
#: The digest salt. Owned by ``redact``, for the same reason.
SALT_ENV = redact.SALT_ENV
#: The captured provider schema path(s). Owned by ``provider_schema``, for the
#: same reason.
PROVIDER_SCHEMA_ENV = provider_schema.PROVIDER_SCHEMA_ENV
#: The schema policy. Owned by ``provider_schema``.
SCHEMA_POLICY_ENV = provider_schema.SCHEMA_POLICY_ENV

#: The :class:`SourceOptions` fields holding a LIST of paths. Everything else is
#: a single value, and the split rule is applied by field name rather than by
#: sniffing the value, so a path containing a separator cannot change the shape.
PATH_FIELDS = ("extra", "terraform_state", "terraform_plan", "terraform_dir",
               "provider_schema")

#: Field → environment variable. ``completeness`` is deliberately absent; see
#: the module docstring.
ENV_FIELDS = {
    "primary": PRIMARY_ENV,
    "origins": ORIGINS_ENV,
    "extra": MERGE_SOURCES_ENV,
    "terraform_state": TF_STATE_ENV,
    "terraform_plan": TF_PLAN_ENV,
    "terraform_dir": TF_DIR_ENV,
    "precedence": PRECEDENCE_ENV,
    "drift_policy": DRIFT_POLICY_ENV,
    "max_age": MAX_AGE_ENV,
    "now": NOW_ENV,
    "provider_schema": PROVIDER_SCHEMA_ENV,
    "schema_policy": SCHEMA_POLICY_ENV,
}

# -- the vocabulary this module decides with ----------------------------------

#: The estate RECORD TABLES, read from the snapshot model that defines them
#: rather than restated here: a table added there must not need an edit here to
#: be recognised, because a table this module does not know about is a table
#: whose absence gets licensed by accident.
ESTATE_TABLES = tuple(knowledge._RECORD_TABLES)

#: The source kinds :class:`SourceOptions` can name, in the order
#: :meth:`SourceOptions.configured` reports them.
SOURCE_KINDS = ("primary", "extra", "terraform-state", "terraform-plan",
                "terraform-dir")

#: Verdict kinds this module emits in the PROVENANCE family. ``state:source``
#: is one of them: a source that contributed nothing is a fact about where the
#: view came from, which is what provenance means.
PROVENANCE_KINDS = ("provenance", "state:source")

#: THE FIXED NOTE ORDER. Asserted by the acceptance suite, because a report
#: whose lines move between runs cannot be diffed.
NOTE_ORDER = ("provenance", "staleness", "drift")

_FAMILY: dict[str, str] = {}
for _kind in PROVENANCE_KINDS:
    _FAMILY[_kind] = "provenance"
for _kind in freshness.STALENESS_KINDS:
    _FAMILY[_kind] = "staleness"
for _kind in drift.DRIFT_KINDS:
    _FAMILY[_kind] = "drift"
del _kind

#: Categories no :class:`gcp_grounding.facts.Fact` can speak for — the four
#: platform vocabularies in :data:`gcp_grounding.facts.EXCLUDED_CATEGORIES`.
#: They cannot travel through a merge, so a merged view CARRIES them across from
#: the first source that captured one; see :func:`_carry_over`.
CARRIED_CATEGORIES = tuple(c for c in provenance.CATEGORIES
                           if c not in facts.TF_CATEGORIES)


# -- the options --------------------------------------------------------------


@dataclass(frozen=True)
class SourceOptions:
    """THE options object for current-state assembly.

    There is exactly one definition of what a source option is: a CLI layer's
    settings object WRAPS one of these rather than restating its fields, so
    ``to_source_options`` is a field access and not a field-by-field re-mapping
    that can silently lose a field.

    Every scalar is ``None`` when unset — DISTINCT from an empty string, which
    is a user who set the variable to nothing — so this module's own defaults
    apply exactly when nobody chose.
    """

    primary: str | None = None
    origins: str | None = None
    extra: tuple[str, ...] = ()
    terraform_state: tuple[str, ...] = ()
    terraform_plan: tuple[str, ...] = ()
    terraform_dir: tuple[str, ...] = ()
    precedence: str | None = None
    drift_policy: str | None = None
    max_age: str | None = None
    now: str | None = None
    completeness: str | None = None
    #: Captured ``terraform providers schema -json`` path(s) — NOT a
    #: current-state source (absent from :meth:`configured`); consumed by
    #: :mod:`gcp_grounding.tf_schema_checks` alone.
    provider_schema: tuple[str, ...] = ()
    #: One of :data:`gcp_grounding.provider_schema.SCHEMA_POLICIES`, or
    #: ``None`` when nobody chose (the checks then apply their own default).
    schema_policy: str | None = None

    def __post_init__(self) -> None:
        for name in PATH_FIELDS:
            object.__setattr__(self, name, _paths(getattr(self, name)))

    def configured(self) -> tuple[tuple[str, str], ...]:
        """``((kind, path), ...)`` in THE fixed load order: the primary first,
        then extra snapshots, then state, plan and directory paths.

        The order is the merge's input order and the provenance note's line
        order, so both are stable across runs.
        """
        out: list[tuple[str, str]] = []
        if self.primary:
            out.append(("primary", self.primary))
        for path in self.extra:
            out.append(("extra", path))
        for path in self.terraform_state:
            out.append(("terraform-state", path))
        for path in self.terraform_plan:
            out.append(("terraform-plan", path))
        for path in self.terraform_dir:
            out.append(("terraform-dir", path))
        return tuple(out)

    @property
    def any_source(self) -> bool:
        """Whether ANY source is configured. Zero is not an error."""
        return bool(self.configured())


def _paths(value: Any) -> tuple[str, ...]:
    """A path list field's value as a tuple. A lone string is ONE path, never a
    string iterated into characters — the single most destructive way this
    field could be got wrong."""
    if value is None:
        return ()
    if isinstance(value, (str, os.PathLike)):
        return (os.fspath(value),)
    return tuple(os.fspath(item) if isinstance(item, os.PathLike) else str(item)
                 for item in value if str(item))


def _split(raw: str) -> tuple[str, ...]:
    """An environment path list, split on :data:`os.pathsep`. Empty segments are
    dropped, so a trailing separator is not a path named ``''``."""
    return tuple(part for part in raw.split(os.pathsep) if part)


def from_env(env: Mapping[str, str] | None = None, **overrides: Any) -> SourceOptions:
    """Options from THE ENVIRONMENT AND EXPLICIT OVERRIDES, and nothing else.

    An explicit non-``None`` override always beats the environment; a value
    absent from both leaves the field ``None`` so this module's defaults apply.

    **THIS IS THE LIBRARY AND NO-CLI PATH, and its limits are normative.** It
    knows nothing about a config file and nothing about auto-detection. A caller
    that has a CLI layer MUST route through ``discovery.resolve_settings``
    instead: building options here on a path that also promises config-file
    discovery silently bypasses the config-file and auto-detect layers, so a
    snapshot path the user wrote in a config file is IGNORED with no error. The
    failure is invisible — the run succeeds, it just used the wrong state.

    Raises :class:`TypeError` for an override that is not a field, which is a
    caller bug rather than bad input: a typo'd keyword silently dropped is the
    same invisible failure one layer up.
    """
    environ = os.environ if env is None else env
    known = {f.name for f in dataclasses.fields(SourceOptions)}
    unknown = sorted(set(overrides) - known)
    if unknown:
        raise TypeError(f"from_env got unknown option(s) {unknown}; "
                        f"SourceOptions has {sorted(known)}")
    values: dict[str, Any] = {}
    for name in known:
        override = overrides.get(name)
        if override is not None:
            values[name] = override
            continue
        variable = ENV_FIELDS.get(name)
        raw = environ.get(variable) if variable else None
        if raw is None:
            continue
        values[name] = _split(raw) if name in PATH_FIELDS else raw
    resolved = SourceOptions(**values)
    logger.debug("resolved source options from env: %d source(s) configured",
                 len(resolved.configured()))
    return resolved


# -- where the sidecar lives --------------------------------------------------


def sidecar_path(snapshot_path: str | os.PathLike[str]) -> str:
    """The ledger path for *snapshot_path*.

    A ONE-LINE DELEGATION to :func:`gcp_grounding.provenance.origins_path` and
    deliberately not a second suffix rule: the writer in ``estate.py`` and this
    discovery path must never disagree about where the sidecar lives, and two
    implementations of the same string surgery is exactly how they would.
    """
    return provenance.origins_path(snapshot_path)


def has_estate_table(snapshot: GcpSnapshot) -> bool:
    """Whether *snapshot* carries at least one :data:`ESTATE_TABLES` table.

    SHAPE, not content: a table that is captured and EMPTY still counts, because
    the question is which schema the document is, never how populated it is.
    """
    return any(getattr(snapshot, category, None) is not None
               for category in ESTATE_TABLES)


def default_completeness(snapshot: GcpSnapshot) -> str:
    """The scope an unattributed *snapshot* falls back to — ``undeclared`` for
    the estate-table shape, ``complete`` only for the legacy vocabulary-only one.

    See the module docstring: source COUNT is the wrong discriminator, and a
    terraform capture whose sidecar was lost is a single source.
    """
    return "undeclared" if has_estate_table(snapshot) else "complete"


# -- what one loaded source is ------------------------------------------------


@dataclass(frozen=True)
class LoadedSource:
    """One source that loaded: its snapshot, the ledger that travels with it,
    and the identity the merge will know it by.

    ``source_id`` is the configured PATH. Disputes, fact origins and the
    provenance note all name it, so an operator reading a finding can go
    straight to the file that produced it.
    """

    kind: str
    path: str
    snapshot: GcpSnapshot
    ledger: SourceLedger
    notes: tuple[str, ...] = ()

    @property
    def source_id(self) -> str:
        return self.path

    @property
    def captured_at(self) -> str:
        return self.snapshot.captured_at

    def fidelity(self) -> str:
        """The WEAKEST fidelity spelling among the ledger's own sources.

        Weakest rather than strongest, and never guessed upward: a snapshot with
        no sidecar carries the ``unattributed`` spelling, which is a real
        position in :data:`gcp_grounding.provenance.SOURCES` meaning exactly
        "nobody said". Reading a terraform-derived snapshot as ``api`` because
        it is passed as ``--snapshot`` would hand it API fidelity it never had.
        """
        kinds = [record.kind for record in self.ledger.sources.values()
                 if record.kind]
        if not kinds:
            return "unattributed"
        return min(kinds, key=provenance.fidelity_rank)

    def declared_scope(self) -> str:
        """The WEAKEST coverage this source's own ledger declares for itself.

        Weakest rather than strongest and never guessed upward, exactly as
        :meth:`fidelity` does it, and ``undeclared`` — "nobody said" — for a
        ledger that names no source at all.

        THIS IS THE SOURCE'S OWN COMPLETENESS DECLARATION, and it is the only
        thing a reader downstream can ask "what did THIS view claim to cover"
        of: ``--completeness`` (or the config key) lands here because
        :func:`load_source` builds the fallback ledger AT THE DECLARED SCOPE,
        and a real ``gcp-source-ledger/1`` sidecar lands here because its own
        source records carry it. Flattening it away — which this method used to
        do — meant a source could declare itself complete and have no way to
        say so to anything reading the merged ledger.
        """
        scopes = [record.scope for record in self.ledger.sources.values()
                  if record.scope]
        if not scopes:
            return "undeclared"
        return min(scopes, key=provenance.scope_rank)

    def record(self) -> SourceRecord:
        """This source as one :class:`~gcp_grounding.provenance.SourceRecord`
        for the merge.

        The record carries :meth:`declared_scope`, and the REAL PER-CATEGORY
        coverage still travels in :meth:`category_scopes` — which
        :func:`load_current` always supplies and which ``merge`` prefers, so
        this flattened claim never licenses a category the ledger described
        differently.

        NO NOTE. The record used to carry ``"<kind> source loaded in memory"``,
        which every explain surface then printed under the source line — and
        "loaded in memory" is what happened to EVERY source in the list, so it
        distinguished nothing while crowding out the notes that do (the
        terraform ``partial`` cap, the state serial and lineage). The kind and
        the origin the sentence restated are already the line's own first two
        columns.
        """
        return SourceRecord(source_id=self.source_id, kind=self.fidelity(),
                            origin=self.path, captured_at=self.captured_at,
                            scope=self.declared_scope())

    def category_scopes(self) -> dict[str, str]:
        """``category → scope``, so the merge composes THIS source's real
        per-category coverage rather than one flattened claim."""
        return {category: scope.scope
                for category, scope in self.ledger.categories.items()}


@dataclass(frozen=True)
class CurrentState:
    """The assembled current state, plus everything that was not decided.

    ``snapshot`` is ``None`` only when nothing loaded at all. ``reconciled`` is
    ``False`` when a step failed and the primary came back untouched — the
    fail-open path — so a caller can say so instead of presenting a single
    source as a merged view.
    """

    snapshot: ReconciledSnapshot | None = None
    ledger: SourceLedger | None = None
    notes: tuple[Verdict, ...] = ()
    problem: str = ""
    sources: tuple[str, ...] = ()
    reconciled: bool = False

    @property
    def ok(self) -> bool:
        """Whether a usable current state came back. A state with notes is
        still ``ok``: a note is a fact about coverage, not a failure."""
        return self.snapshot is not None and not self.problem


# -- the process-wide secret boundary -----------------------------------------

_VAULT: redact.SecretVault | None = None


def vault() -> redact.SecretVault:
    """THE process-wide :class:`~gcp_grounding.redact.SecretVault`.

    It lives here because this is the one place every source is read, and the
    log filter is installed ONCE, from here, on first use. ``ensure_log_filter``
    at the report boundaries handles a later ``setup_logging`` that reconfigures
    the handler set; this is the single INSTALL.
    """
    global _VAULT
    if _VAULT is None:
        vault_ = redact.SecretVault()
        redact.install_log_filter(vault_)
        _VAULT = vault_
    return _VAULT


# -- snapshot → facts ---------------------------------------------------------


def snapshot_facts(snapshot: GcpSnapshot, *, source: str,
                   origin: str, ledger: SourceLedger | None = None
                   ) -> tuple[facts.Fact, ...]:
    """Every :data:`gcp_grounding.facts.TF_CATEGORIES` row of *snapshot* as a
    fact the merge can rank.

    This is an ADAPTER, not a second assembler: it moves rows the snapshot
    already holds into the one vocabulary ``merge.resolve`` consumes, and adds
    nothing. When *ledger* is given each fact keeps the LOCATOR its origin
    recorded, so a dispute raised over a merged row can still name the terraform
    address it came from.

    The four :data:`gcp_grounding.facts.EXCLUDED_CATEGORIES` vocabularies are
    absent by construction — ``Fact`` refuses them — and are carried across a
    merge instead; see :data:`CARRIED_CATEGORIES`.
    """
    out: list[facts.Fact] = []
    for category in facts.TF_CATEGORIES:
        table = getattr(snapshot, category, None)
        if table is None:
            continue
        flat = category in facts.FLAT_CATEGORIES
        for key in sorted(table):
            found = ledger.origin_of(category, key) if ledger is not None else None
            out.append(facts.Fact(
                category=category, key=key,
                record=None if flat else dict(table[key]),
                source=source, origin=origin,
                address=found.locator if found is not None else ""))
    return tuple(out)


# -- loading one source -------------------------------------------------------


def load_source(path: str | os.PathLike[str], *, origins: str | None = None,
                completeness: str | None = None,
                vault: redact.SecretVault | None = None,
                multi: bool = False,
                kind: str = "extra"
                ) -> tuple[LoadedSource | None, tuple[Verdict, ...]]:
    """One snapshot plus its ledger, or ``None`` — never an exception.

    THE LEDGER RESOLUTION ORDER, WHICH IS NEVER REORDERED:

    1. an explicit *origins* path;
    2. else the derived ``.origins.json`` when it EXISTS;
    3. else :meth:`gcp_grounding.provenance.SourceLedger.unattributed` at the
       scope the caller DECLARED (*completeness*);
    4. else that fallback at the scope :func:`default_completeness` chooses from
       the snapshot's SHAPE.

    A snapshot that does not load at all is ONE ``state:source`` verdict — the
    same shape every failing source uses — and ``None``. A ledger that fails to
    load is a ``provenance`` verdict naming the path, and resolution falls back
    to the NEXT step: a broken sidecar must never make a usable snapshot
    unusable, and must never silently promote it to ``complete``.

    The sidecar-MISSING note is emitted only when *multi* is set — more than one
    source is in play. A note on every single-source run would train users to
    ignore the channel.
    """
    fspath = os.fspath(path)
    scrub = vault.scrub_text if vault is not None else (lambda text: text)
    notes: list[Verdict] = []

    try:
        snapshot = GcpSnapshot.load(fspath)
    except (OSError, ValueError) as exc:
        return None, (_source_failed(
            kind, fspath, scrub(f"{type(exc).__name__}: "
                                f"{facts.truncate(str(exc))}")),)

    ledger: SourceLedger | None = None
    derived = sidecar_path(fspath)
    for candidate, why in ((origins, "the configured origins path"),
                           (derived if os.path.exists(derived) else None,
                            "the sidecar beside the snapshot")):
        if not candidate:
            continue
        try:
            ledger = SourceLedger.load(candidate)
            break
        except (OSError, ValueError) as exc:
            notes.append(Verdict(
                "unverified", "provenance", candidate, 0,
                scrub(f"{why} {candidate} could not be read ({type(exc).__name__}: "
                      f"{facts.truncate(str(exc))}) - the snapshot is still used, "
                      f"and its coverage falls back rather than being promoted to "
                      f"'complete'")))

    if ledger is None:
        declared = completeness or default_completeness(snapshot)
        ledger = SourceLedger.unattributed(
            snapshot, scope=declared, source_id=fspath, origin=fspath)
        if multi and not completeness:
            notes.append(Verdict(
                "unverified", "provenance", fspath, 0,
                f"snapshot {fspath} arrived with no source ledger (looked for "
                f"{derived}), so every category it declares is "
                f"'{declared}' - "
                + ("a vocabulary-only snapshot keeps the legacy 'complete' default"
                   if declared == "complete" else
                   "a snapshot carrying an estate record table is NOT read as a "
                   "licensed-complete view of the estate; pass completeness="
                   "'complete' to say otherwise")))

    return LoadedSource(kind=kind, path=fspath, snapshot=snapshot, ledger=ledger,
                        notes=tuple(note.message for note in notes)), tuple(notes)


def load_terraform(path: str | os.PathLike[str], *, options: SourceOptions,
                   kind: str = "terraform-dir",
                   precedence: merge.PrecedencePolicy | None = None,
                   vault: redact.SecretVault | None = None
                   ) -> tuple[LoadedSource | None, tuple[Verdict, ...]]:
    """A configured state, plan or directory path as an IN-MEMORY source.

    Dispatched through ``tfsource`` discovery plus
    :func:`gcp_grounding.estate.capture`, which is what makes terraform a
    first-class source rather than only a CLI capture step: nothing is written,
    and the seam where one half of the design ended at a written file and the
    other began at a loaded one does not exist.

    *vault* is handed STRAIGHT DOWN to the capture, and :func:`load_current`
    always passes :func:`vault`. Terraform is the ONE source kind that carries
    plaintext secrets — a tfstate stores them unmasked and its
    ``sensitive_attributes`` is a display marker — so this call is where the
    process-wide vault learns anything at all. Without it the log filter and
    ``redact.scrub_report`` are installed over an empty vault and scrub nothing,
    which is indistinguishable from working right up until something logs a
    value the attribute-level replacement did not reach.

    A capture that fails — an unreadable tree, a refused artifact, a reader that
    raised — comes back as ``None`` plus one ``state:source`` verdict. It never
    raises.
    """
    fspath = os.fspath(path)
    try:
        captured = estate.capture(
            fspath, options=estate.CaptureOptions(precedence=precedence),
            vault=vault)
    except Exception as exc:                # noqa: BLE001 - isolation is the point
        return None, (_source_failed(kind, fspath,
                                     f"{type(exc).__name__}: "
                                     f"{facts.truncate(str(exc))}"),)
    if not captured.snapshot.captured_categories():
        return None, (_source_failed(
            kind, fspath, "the capture produced no estate category at all"),)
    logger.debug("terraform source %s: %s", fspath,
                 ",".join(captured.snapshot.captured_categories()))
    return LoadedSource(kind=kind, path=fspath, snapshot=captured.snapshot,
                        ledger=captured.ledger, notes=captured.notes), ()


def _source_failed(kind: str, path: str, reason: str) -> Verdict:
    """THE ONE SHAPE for "a configured source contributed nothing"."""
    return Verdict(
        "unverified", "state:source", path, 0,
        f"the configured {kind} source {path} could not be loaded ({reason}) - "
        f"it contributed NOTHING to the current state, so coverage is smaller "
        f"than what was configured and every check reading a category it would "
        f"have supplied is answering from less evidence")


# -- resolving the options ----------------------------------------------------


@dataclass(frozen=True)
class _Resolved:
    """The parsed, validated form of one :class:`SourceOptions`."""

    options: SourceOptions
    precedence: merge.PrecedencePolicy
    precedence_name: str
    drift_policy: str
    max_age: timedelta | None
    now: datetime
    completeness: str | None


def _resolve(options: SourceOptions) -> tuple[_Resolved | None, str]:
    """→ ``(resolved, problem)`` — exactly one is meaningful.

    A malformed precedence, drift policy, max age, clock or completeness is a
    USAGE error naming the flag and the token. It is NEVER a silent fall back to
    the default: a typo that quietly restores the default changes what the gate
    enforces, and nothing says so.
    """
    try:
        policy = merge.parse_policy(options.precedence) \
            if options.precedence else merge.PrecedencePolicy()
    except ValueError as exc:
        return None, (f"--precedence / ${PRECEDENCE_ENV} {options.precedence!r}: "
                      f"{exc}")
    name = options.precedence or policy.default

    drift_policy = options.drift_policy or drift.DEFAULT_DRIFT_POLICY
    if drift_policy not in drift.DRIFT_POLICIES:
        return None, (f"--drift-policy / ${DRIFT_POLICY_ENV} "
                      f"{options.drift_policy!r} is not one of "
                      f"{list(drift.DRIFT_POLICIES)}")

    try:
        max_age = freshness.parse_duration(options.max_age) \
            if options.max_age is not None else freshness.MAX_AGE_DEFAULT
    except ValueError as exc:
        return None, f"--max-age / ${MAX_AGE_ENV} {options.max_age!r}: {exc}"

    try:
        now = freshness.resolve_now(options.now)
    except ValueError as exc:
        return None, f"--now / ${NOW_ENV} {options.now!r}: {exc}"

    completeness = options.completeness
    if completeness is not None and completeness not in provenance.SCOPES:
        return None, (f"--completeness {completeness!r} is not one of "
                      f"{list(provenance.SCOPES)}")

    if options.schema_policy is not None \
            and options.schema_policy not in provider_schema.SCHEMA_POLICIES:
        return None, (f"--schema-policy / ${SCHEMA_POLICY_ENV} "
                      f"{options.schema_policy!r} is not one of "
                      f"{list(provider_schema.SCHEMA_POLICIES)}")

    return _Resolved(options=options, precedence=policy, precedence_name=name,
                     drift_policy=drift_policy, max_age=max_age, now=now,
                     completeness=completeness), ""


# -- the fixed sequence -------------------------------------------------------


class _StepFailed(Exception):
    """One wrapped step raised. Carries the step name and the original."""

    def __init__(self, step: str, exc: BaseException) -> None:
        self.step = step
        self.exc = exc
        super().__init__(f"{step}: {type(exc).__name__}: {exc}")


def _step(name: str, call: Callable[[], Any]) -> Any:
    """Run *call*, turning ANY exception into a :class:`_StepFailed` naming the
    step. Every step of :func:`load_current` goes through here — that is the
    fail-open contract applied to source assembly."""
    try:
        return call()
    except Exception as exc:                # noqa: BLE001 - isolation is the point
        raise _StepFailed(name, exc) from exc


def load_current(options: SourceOptions) -> CurrentState:
    """THE current-state entry point. Resolve, load, merge, age, reconcile.

    The sequence is FIXED: resolve the options, load the primary, load every
    extra snapshot and every terraform path, hand all of them to ONE
    :func:`gcp_grounding.merge.resolve` plus :func:`gcp_grounding.estate.build`,
    age through :func:`gcp_grounding.freshness.evaluate` and REPLACE the ledger
    with the demoted one, render :func:`gcp_grounding.drift.drift_verdicts`,
    build the :class:`~gcp_grounding.reconciled.ReconciledSnapshot`, and emit the
    multi-source provenance note listing each source's kind, capture time and
    origin — which is what keeps the single ``captured_at`` in a report header
    from being read as the whole truth.

    NEVER RAISES. An unexpected exception in any step becomes one ``provenance``
    verdict naming the step and the exception type, and the primary snapshot
    comes back UNRECONCILED. Notes come back in the fixed order
    :data:`NOTE_ORDER`.
    """
    resolved, problem = _resolve(options)
    if resolved is None:
        logger.debug("source options refused: %s", problem)
        return CurrentState(problem=problem)

    secrets = vault()
    configured = options.configured()
    if not configured:
        # Configuring nothing is not an error, and an empty current state with a
        # note would be a channel every no-source run trains its user to ignore.
        return CurrentState()

    loaded: list[LoadedSource] = []
    notes: list[Verdict] = []
    multi = len(configured) > 1
    for kind, path in configured:
        if kind in ("primary", "extra"):
            source, verdicts = load_source(
                path,
                origins=options.origins if kind == "primary" else None,
                completeness=resolved.completeness, vault=secrets,
                multi=multi, kind=kind)
        else:
            source, verdicts = load_terraform(
                path, options=options, kind=kind,
                precedence=resolved.precedence, vault=secrets)
        notes.extend(verdicts)
        if source is not None:
            loaded.append(source)

    if not loaded:
        return CurrentState(notes=order_notes(notes),
                            sources=tuple(path for _kind, path in configured))

    try:
        snapshot, ledger, extra_notes = _assemble(loaded, resolved)
    except _StepFailed as failure:
        return _unreconciled(loaded[0], failure, notes, secrets)
    notes.extend(extra_notes)

    return CurrentState(snapshot=snapshot, ledger=ledger,
                        notes=order_notes(notes),
                        sources=tuple(source.path for source in loaded),
                        reconciled=True)


def _assemble(loaded: Sequence[LoadedSource], resolved: _Resolved
              ) -> tuple[ReconciledSnapshot, SourceLedger, list[Verdict]]:
    """Merge (or not), age, and render drift. Every step is wrapped."""
    if len(loaded) == 1:
        # THE IDENTITY PATH. One source has nothing to reconcile against, so the
        # snapshot and its resolved ledger ARE the current state — including the
        # categories no fact can carry, which a merge would have to hand across.
        snapshot: GcpSnapshot = loaded[0].snapshot
        ledger = loaded[0].ledger
        merge_verdicts: tuple[Verdict, ...] = ()
    else:
        snapshot, ledger, merge_verdicts = _step(
            "merge", lambda: _merge(loaded, resolved))

    aged, staleness = _step(
        "age", lambda: freshness.evaluate(ledger, now=resolved.now,
                                          max_age=resolved.max_age))
    drift_notes = _step(
        "drift", lambda: drift.drift_verdicts(
            aged, policy=resolved.drift_policy, verdicts=merge_verdicts,
            precedence=resolved.precedence.default))
    reconciled = _step(
        "reconcile", lambda: ReconciledSnapshot.from_snapshot(
            snapshot, ledger=aged, disputes=aged.disputes,
            policy_name=resolved.precedence_name))

    notes: list[Verdict] = []
    if len(loaded) > 1:
        notes.append(_provenance_note(loaded, aged))
    notes.extend(staleness)
    notes.extend(drift_notes)
    return reconciled, aged, notes


def _merge(loaded: Sequence[LoadedSource], resolved: _Resolved
           ) -> tuple[GcpSnapshot, SourceLedger, tuple[Verdict, ...]]:
    """ONE ``merge.resolve`` plus ONE ``estate.build`` over every source."""
    collected: list[facts.Fact] = []
    records: list[SourceRecord] = []
    scopes: dict[str, Mapping[str, str]] = {}
    for source in loaded:
        record = source.record()
        records.append(record)
        scopes[source.source_id] = source.category_scopes()
        collected.extend(snapshot_facts(
            source.snapshot, source=record.kind, origin=source.source_id,
            ledger=source.ledger))

    result = merge.resolve(collected, sources=records,
                           policy=resolved.precedence, category_scopes=scopes)
    emitted = {resolution.category for resolution in result.resolutions}
    stamp = result.captured_at or min(source.captured_at for source in loaded)
    capture = estate.build(
        result,
        options=estate.CaptureOptions(
            emit=tuple(c for c in facts.TF_CATEGORIES if c in emitted),
            captured_at=stamp, precedence=resolved.precedence),
        sources=records, notes=result.notes)
    snapshot, ledger = _carry_over(capture, loaded)
    logger.debug("merged %d source(s) into %d categor(y|ies)", len(loaded),
                 len(snapshot.captured_categories()))
    return snapshot, ledger, result.verdicts


def _carry_over(capture: estate.Capture, loaded: Sequence[LoadedSource]
                ) -> tuple[GcpSnapshot, SourceLedger]:
    """Hand the four platform vocabularies across a merge they cannot travel.

    ``facts.Fact`` refuses :data:`gcp_grounding.facts.EXCLUDED_CATEGORIES` by
    design — terraform never enumerates a permission vocabulary — so a merged
    snapshot would otherwise LOSE the categories only a snapshot source can
    supply. The FIRST source that captured one wins, which is the configured
    order (the primary first), and that source's own scope for it comes across
    with the data rather than being re-derived.
    """
    payload = capture.snapshot.to_dict()
    categories = dict(capture.ledger.categories)
    for category in CARRIED_CATEGORIES:
        for source in loaded:
            if getattr(source.snapshot, category, None) is None:
                continue
            payload[category] = source.snapshot.to_dict()[category]
            categories[category] = source.ledger.scope_of(category)
            break
    snapshot = GcpSnapshot.from_dict(payload)
    return snapshot, dataclasses.replace(capture.ledger, categories=categories)


def _provenance_note(loaded: Sequence[LoadedSource],
                     ledger: SourceLedger) -> Verdict:
    """THE multi-source note: every source's kind, capture time and origin.

    A report header carries ONE ``captured_at`` — the oldest — and without this
    note that single stamp reads as the whole truth about a view assembled from
    several artifacts of different ages.
    """
    lines = "; ".join(
        f"{source.fidelity()} '{source.path}' captured "
        f"{source.captured_at or 'at an unrecorded time'}"
        for source in loaded)
    return Verdict(
        "unverified", "provenance", "current-state", 0,
        f"the current state was merged from {len(loaded)} sources: {lines} - the "
        f"report header stamps every line with {ledger.merged_captured_at() or '?'}, "
        f"which is the OLDEST of these and not the capture time of any single fact")


def _unreconciled(primary: LoadedSource, failure: _StepFailed,
                  notes: list[Verdict],
                  secrets: redact.SecretVault) -> CurrentState:
    """The fail-open answer: the primary snapshot, untouched, plus ONE verdict
    naming the step that raised.

    A merge bug must never take down a gate that worked yesterday, so what comes
    back is exactly what a single-source run would have produced — and it says
    so, rather than presenting one source as a reconciled view.
    """
    logger.warning("source assembly step '%s' raised %s: %s - returning the "
                   "primary snapshot UNRECONCILED", failure.step,
                   type(failure.exc).__name__, failure.exc)
    notes = list(notes)
    notes.append(Verdict(
        "unverified", "provenance", f"step:{failure.step}", 0,
        secrets.scrub_text(
            f"the '{failure.step}' step of current-state assembly raised "
            f"{type(failure.exc).__name__}: {facts.truncate(str(failure.exc))} - "
            f"the primary snapshot {primary.path} is returned UNRECONCILED and "
            f"every other source contributed nothing")))
    try:
        snapshot = ReconciledSnapshot.from_snapshot(
            primary.snapshot, ledger=primary.ledger)
    except Exception:                       # noqa: BLE001 - the last resort
        return CurrentState(notes=order_notes(notes), sources=(primary.path,))
    return CurrentState(snapshot=snapshot, ledger=primary.ledger,
                        notes=order_notes(notes), sources=(primary.path,),
                        reconciled=False)


# -- note order ---------------------------------------------------------------


def note_family(kind: str) -> str:
    """The :data:`NOTE_ORDER` family *kind* belongs to. An unrecognised kind
    sorts LAST rather than being dropped: an unplaceable note is still a note."""
    found = _FAMILY.get(kind)
    if found is not None:
        return found
    if kind.startswith("drift"):
        return "drift"
    if kind.startswith("staleness"):
        return "staleness"
    return ""


def order_notes(notes: Iterable[Verdict]) -> tuple[Verdict, ...]:
    """Notes in THE fixed order: provenance, then staleness, then drift.

    A STABLE sort, so the order WITHIN a family is the order it was produced in
    — which for staleness is age-then-supersession and for drift is the
    dispute order the ledger recorded.
    """
    def rank(verdict: Verdict) -> int:
        family = note_family(verdict.kind)
        return NOTE_ORDER.index(family) if family in NOTE_ORDER else len(NOTE_ORDER)

    return tuple(sorted(notes, key=rank))


# -- persistence --------------------------------------------------------------


def write_reconciled(state: CurrentState,
                     path: str | os.PathLike[str]) -> tuple[str, str]:
    """Write the merged snapshot and its ledger, and return both paths.

    THE SAME TWO WRITERS, reached through :func:`gcp_grounding.estate.write_capture`
    rather than re-spelled: ``fetch.write_snapshot`` for the snapshot and
    ``SourceLedger.write`` for the sidecar, so a reconciled artifact and a
    terraform capture are byte-comparable by construction.

    Raises :class:`ValueError` when there is nothing to write — unlike the load
    path, writing is a caller's explicit request and a silent no-op would leave
    them believing a file exists.
    """
    if state.snapshot is None or state.ledger is None:
        raise ValueError(f"write_reconciled has no current state to write "
                         f"({state.problem or 'no source produced a snapshot'})")
    return estate.write_capture(
        estate.Capture(snapshot=state.snapshot, ledger=state.ledger), path)
