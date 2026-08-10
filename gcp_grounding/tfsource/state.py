"""THE ``terraform.tfstate`` v4 reader, and the five hazards that make one
necessary.

Layer 1 of the pipeline described in :mod:`gcp_grounding.tfsource`: this module
turns one v4 state document into :class:`gcp_grounding.facts.TfObject` values
stamped at source ``tfstate``, side ``current``. There is no second v4 reader in
the tree; every hazard below is handled once, here.

WHY TERRAFORM CAN NEVER BE COMPLETE
-----------------------------------
**This paragraph is normative and must not be deleted.** A state file describes
what ONE terraform workspace applied, and nothing else. Resources created by
hand in the console, by another pipeline, by another workspace, by another state
file, and every ``data``-mode entry in this very file, are all INVISIBLE here.
So a name this reader did not produce is a name it did not look for, and nothing
downstream may conclude an absence from it: ``provenance.CategoryScope`` caps a
``tfstate`` scope at ``partial`` for exactly this reason, and
``provenance.require_complete`` is what every absence-reasoning check calls
before it decides anything from a missing row.

THE FIVE v4 HAZARDS
-------------------
1. **The provider string.** The real spelling is
   ``provider["registry.terraform.io/hashicorp/google"]``. A naive
   ``rsplit("/", 1)[-1]`` over it yields ``google"]``, which matches no
   allowlist, so EVERY google resource silently disappears and the capture
   reports a clean empty estate. :func:`parse_provider` extracts the source
   address and its optional alias with one compiled regex, and the ``rsplit``
   happens on the EXTRACTED address, where it is correct.
2. **The missing address.** v4 has no ``address`` key. :func:`compose_address`
   builds one: the optional dotted module prefix, the type, the name, then
   either a JSON-escaped quoted string index or a bare integer index.
3. **Deposed.** ``deposed`` is a per-INSTANCE generation marker, not a
   per-resource one. A deposed instance is skipped and COUNTED, and the LIVE
   instance at the same address survives — losing the live object behind a stale
   one is silent and total.
4. **Data mode.** ``mode == "data"`` entries are skipped and counted: a data
   source is present in the estate but is NOT terraform-managed, so counting it
   as captured would overstate coverage.
5. **The backend stub.** A document with no ``resources`` array is the backend
   configuration ``init`` writes, and it is byte-for-byte as convincing as a
   clean empty estate. It is REFUSED loudly, with
   :data:`gcp_grounding.tfsource.discover.REMOTE_BACKEND_STUB` — the same string
   the discoverer uses, so no entry point can say something different about the
   same file.

EVERY GATE PRODUCES ``ok=False`` WITH AN EXPLICIT NOTE, AND NEVER AN EMPTY
SUCCESS. An empty success here is a clean bill of health for an estate nobody
read. An EMPTY ``resources`` list is the one legal way to read zero objects, and
it still yields a note saying it covers NOTHING.

REDACTION runs BEFORE the :class:`~gcp_grounding.facts.TfObject` is built,
through the one boundary in :mod:`gcp_grounding.redact`, driven by the
instance's ``sensitive_attributes`` cty paths plus the name heuristic — a
``terraform.tfstate`` stores sensitive values in PLAINTEXT and
``sensitive_attributes`` is a DISPLAY marker only. No logger call in this module
formats an attribute value except through :func:`gcp_grounding.facts.safe_repr`.
``outputs`` are read only far enough to note that a sensitive output exists.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from ..core.log import get_logger
from ..facts import TfObject, safe_repr
from ..redact import SecretVault, redact
from .discover import MAX_ARTIFACT_BYTES, REMOTE_BACKEND_STUB

logger = get_logger(__name__)

__all__ = [
    "SOURCE",
    "STATE_VERSION",
    "GOOGLE_SOURCE",
    "MTIME_NOTE",
    "NEVER_COMPLETE_NOTE",
    "EMPTY_STATE_NOTE",
    "STATE_VERSION_REFUSED",
    "FLATMAP_NOTE",
    "ProviderRef",
    "parse_provider",
    "index_suffix",
    "compose_address",
    "mtime_utc",
    "StateRead",
    "read_state",
    "read_state_document",
]

#: The ``provenance.SOURCES`` spelling every object this reader emits carries.
#: It is the CURRENT-state side by construction: ``facts.TfObject`` refuses a
#: current-state source on the proposed side and vice versa, so a state file can
#: never be laundered into a proposal.
SOURCE = "tfstate"

#: The only state format this reader decodes. A v3 file is REFUSED rather than
#: read partially — see :data:`STATE_VERSION_REFUSED`.
STATE_VERSION = 4

#: The canonical google provider source address, used only by the fallback arm
#: of :func:`parse_provider`.
GOOGLE_SOURCE = "registry.terraform.io/hashicorp/google"


# -- the notes ----------------------------------------------------------------

#: THE MTIME NOTE, in plain words, because the distinction is invisible on
#: disk. A ``terraform state pull`` into a fresh file, a checkout, a copy or a
#: restore all reset the mtime, so a file that is newer than the estate it
#: describes looks fresher than it is. The caller may pass its own
#: ``captured_at``; then this note is not emitted, because it would be false.
MTIME_NOTE = (
    "{path}: captured_at {stamp} is the state FILE's modification time and NOT "
    "the time the estate was read. A 'terraform state pull' into a fresh file, "
    "a checkout, a copy or a restore all reset it, so a state file can look "
    "fresher than the estate it describes."
)

#: Carried by every successful read. The scope cap in
#: ``provenance.CategoryScope`` enforces this structurally; the note is what
#: makes it readable in the ledger.
NEVER_COMPLETE_NOTE = (
    "{path}: terraform state describes only what THIS workspace applied. "
    "Clickops resources, other pipelines, other workspaces, other state files "
    "and this file's own data sources are all invisible to it, so no category "
    "may be resolved absent from this file."
)

EMPTY_STATE_NOTE = (
    "{path}: the state carries an EMPTY 'resources' array. That is legal — a "
    "workspace that manages nothing — and it yields zero facts covering "
    "NOTHING; it is not an empty estate."
)

NOTHING_SURVIVED_NOTE = (
    "{path}: {entries} resource entr(y|ies) were read and ZERO objects "
    "survived. That is coverage of NOTHING, not an empty estate; the notes "
    "above name every entry that was skipped and why."
)

STATE_VERSION_REFUSED = (
    "{path}: this is Terraform state version {version!r}, and only version "
    "{expected} is readable here. It is REFUSED rather than read partially, "
    "because a state file this reader cannot decode yields zero resources, and "
    "zero resources is indistinguishable from a clean empty estate. Migrate it "
    "to version {expected} with a current terraform before capturing it."
)

FLATMAP_NOTE = (
    "{address}: instance {index} carries the legacy 'attributes_flat' flatmap "
    "and no 'attributes' object. It is SKIPPED whole rather than half-parsed: "
    "a flatmap spells a nested block as dotted keys plus a '.#' count, and a "
    "half-decoded rule reads as a rule with fewer ranges than it has."
)

_NO_LINEAGE_NOTE = (
    "{path}: this version-4 state carries no 'lineage', so two captures of it "
    "cannot be told apart and freshness cannot detect a superseded serial."
)


# -- HAZARD 1: the provider string --------------------------------------------

#: THE ONE PROVIDER REGEX. Two accepted top-level shapes, each with an optional
#: ``.alias`` suffix:
#:
#: - ``provider["registry.terraform.io/hashicorp/google"]`` — what terraform
#:   0.13 and later actually write, and the shape the naive split destroys;
#: - ``provider.google`` / ``google`` / ``registry.terraform.io/hashicorp/google``
#:   — the unwrapped legacy and bare spellings.
#:
#: The alias group deliberately admits no ``.`` and no ``/``, which is what
#: keeps a dotted SOURCE ADDRESS (``registry.terraform.io/...``) from being
#: mistaken for a name plus an alias.
_PROVIDER_RE = re.compile(
    r"""
    ^\s*
    (?:
        provider\s*\[\s*"(?P<bracketed>[^"\]]+)"\s*\]
      |
        (?:provider\.)?(?P<bare>[A-Za-z0-9][A-Za-z0-9._/\-]*?)
    )
    (?:\.(?P<alias>[A-Za-z_][A-Za-z0-9_\-]*))?
    \s*$
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class ProviderRef:
    """One decoded ``provider`` entry.

    ``source`` is the full source address, ``name`` its last path segment (the
    thing an allowlist matches), ``alias`` the optional configuration alias.
    ``inferred`` marks the fallback arm, where the provider was read off the
    resource type's ``google_`` prefix rather than declared. A ref with no
    ``name`` is a REFUSAL and always carries a ``note``.
    """

    source: str = ""
    name: str = ""
    alias: str = ""
    raw: str = ""
    inferred: bool = False
    note: str = ""

    @property
    def ok(self) -> bool:
        """Whether the entry was decoded at all."""
        return bool(self.name)

    @property
    def spelling(self) -> str:
        """``google`` or ``google.eu`` — what ``TfObject.provider`` carries."""
        if not self.name:
            return ""
        return f"{self.name}.{self.alias}" if self.alias else self.name


def parse_provider(raw: Any, *, resource_type: str = "") -> ProviderRef:
    """Decode a v4 ``provider`` entry — THE four accepted shapes, in one place.

    ARM 1 ``provider["registry.terraform.io/hashicorp/google"]``, ARM 2 the same
    with a trailing ``.alias``, ARM 3 the bare unwrapped form (``google``,
    ``provider.google``, or a naked source address), and ARM 4 the fallback for
    an entry carrying NO provider information at all, where a ``google_`` type
    prefix is the only evidence there is.

    Anything else is REFUSED with a note rather than guessed at. Guessing is
    what the hazard is: an entry decoded to a provider name nobody wrote is an
    entry that disappears from every allowlisted mapper, silently.
    """
    text = raw.strip() if isinstance(raw, str) else ""
    if not text:
        # ARM 4. The type prefix is real evidence, but it is not proof: the
        # google and google-beta providers write the same `google_` types, so
        # the inference is recorded as an inference.
        if resource_type.startswith("google_"):
            return ProviderRef(
                source=GOOGLE_SOURCE, name="google", inferred=True,
                note=(f"resource type {resource_type!r} carries no provider entry; "
                      f"the provider was INFERRED from its 'google_' prefix and "
                      f"may equally have been 'google-beta'"))
        return ProviderRef(
            note=(f"the entry names no provider and its type {resource_type!r} "
                  f"carries no 'google_' prefix to infer one from"))

    match = _PROVIDER_RE.match(text)
    if match is None:
        return ProviderRef(
            raw=text,
            note=(f"provider {text!r} is in none of the spellings this reader "
                  f"decodes (bracketed, bracketed-with-alias, bare, or absent "
                  f"with a 'google_' type prefix)"))

    source = match.group("bracketed") or match.group("bare") or ""
    # THE SPLIT THAT IS ONLY SAFE HERE: the regex has already stripped the
    # `provider["..."]` wrapper, so the last path segment is the provider name
    # and not `google"]`.
    name = source.rsplit("/", 1)[-1]
    if not name:
        return ProviderRef(
            raw=text,
            note=f"provider {text!r} decodes to an empty provider name")
    return ProviderRef(source=source, name=name,
                       alias=match.group("alias") or "", raw=text)


# -- HAZARD 2: the missing address --------------------------------------------


def index_suffix(index_key: Any) -> str:
    """The ``[...]`` an address ends with, or ``""``.

    A string key is JSON-escaped — terraform writes ``["prod"]`` and a key
    holding a quote must not produce an address that cannot be parsed back. An
    integer key (``count``) is bare. ``bool`` is excluded from the integer arm
    deliberately: it is an ``int`` subclass in Python and terraform never writes
    one, so rendering ``[True]`` would invent an address.
    """
    if index_key is None:
        return ""
    if isinstance(index_key, bool):
        return f"[{json.dumps(str(index_key))}]"
    if isinstance(index_key, int):
        return f"[{index_key}]"
    if isinstance(index_key, str):
        return f"[{json.dumps(index_key)}]"
    return f"[{json.dumps(str(index_key))}]"


def compose_address(resource_type: str, name: str, *, module: str = "",
                    index_key: Any = None) -> str:
    """Build the address v4 does not store: optional ``module.<path>`` prefix,
    then type, then name, then the index suffix.

    The module prefix is used VERBATIM, because v4 already stores it in its
    addressed form (``module.net``, ``module.net["prod"].module.inner``).
    """
    if not resource_type:
        raise ValueError("compose_address needs the resource type")
    if not name:
        raise ValueError("compose_address needs the resource name")
    head = f"{module}." if module else ""
    return f"{head}{resource_type}.{name}{index_suffix(index_key)}"


# -- the capture time ---------------------------------------------------------


def mtime_utc(mtime: float) -> str:
    """A POSIX mtime in the snapshot's ``...Z`` form, mirroring
    ``fetch.fresh_captured_at`` so two captures stamp comparably."""
    return datetime.fromtimestamp(mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- the result ---------------------------------------------------------------


@dataclass(frozen=True)
class StateRead:
    """One state file, read.

    ``version``, ``terraform_version``, ``serial`` and ``lineage`` are the state
    HEADER — ``freshness.state_supersession`` compares the serial and lineage
    against the file on disk, and the ledger's ``SourceRecord`` carries both.
    ``data_sources`` counts the ``mode == "data"`` ENTRIES skipped and
    ``deposed`` the deposed INSTANCES skipped; both are coverage the capture
    does NOT have and are counted rather than ignored.

    ``ok is False`` always comes with at least one note saying why, and never
    with objects: an empty success is a clean bill of health for an estate
    nobody read.
    """

    ok: bool = False
    objects: tuple[TfObject, ...] = ()
    notes: tuple[str, ...] = ()
    version: Any = None
    terraform_version: str = ""
    serial: int | None = None
    lineage: str = ""
    data_sources: int = 0
    deposed: int = 0
    captured_at: str = ""
    path: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "objects", tuple(self.objects))
        object.__setattr__(self, "notes", tuple(self.notes))
        if not self.ok and self.objects:
            raise ValueError("a refused StateRead carries no objects; a partial "
                             "read of a state file is a partial estate nobody "
                             "declared")
        if not self.ok and not self.notes:
            raise ValueError("a refused StateRead must say why; a silent refusal "
                             "is indistinguishable from an empty estate")

    @property
    def addresses(self) -> tuple[str, ...]:
        """Every address read, in document order."""
        return tuple(obj.address for obj in self.objects)

    def by_address(self) -> dict[str, TfObject]:
        """Address → object. A duplicated address keeps the LAST entry and is
        noted at read time; state files do not normally carry one."""
        return {obj.address: obj for obj in self.objects}


# -- the reader ---------------------------------------------------------------


def read_state(path: str | os.PathLike[str], *, captured_at: str | None = None,
               vault: SecretVault | None = None,
               max_bytes: int = MAX_ARTIFACT_BYTES) -> StateRead:
    """Read one ``terraform.tfstate`` v4 file. NEVER RAISES.

    An unreadable file, an oversize one, undecodable bytes and unparseable JSON
    each come back as ``ok=False`` with a note — a reader that throws inside a
    capture is a capture that decided nothing.

    ``captured_at`` defaults to the file's mtime rendered UTC-Z, with
    :data:`MTIME_NOTE` attached saying what that timestamp really is. Pass it
    explicitly for a deterministic capture; then the note is not emitted,
    because it would no longer be true.
    """
    fspath = os.fspath(path)
    try:
        stat = os.stat(fspath)
        if stat.st_size > max_bytes:
            return StateRead(
                ok=False, path=fspath, captured_at=captured_at or "",
                notes=(f"{fspath}: the file is {stat.st_size} bytes, over the "
                       f"{max_bytes}-byte artifact limit, and was not opened; "
                       f"NOTHING was captured from it.",))
        with open(fspath, "rb") as handle:
            payload = handle.read(max_bytes + 1)
    except OSError as exc:
        return StateRead(
            ok=False, path=fspath, captured_at=captured_at or "",
            notes=(f"{fspath}: the state file could not be read ({exc}) — "
                   f"NOTHING was captured from it.",))
    if len(payload) > max_bytes:
        return StateRead(
            ok=False, path=fspath, captured_at=captured_at or "",
            notes=(f"{fspath}: the file grew past the {max_bytes}-byte artifact "
                   f"limit while it was being read; NOTHING was captured.",))

    try:
        document = json.loads(payload.decode("utf-8"))
    except UnicodeDecodeError as exc:
        return StateRead(
            ok=False, path=fspath, captured_at=captured_at or "",
            notes=(f"{fspath}: the state file is not UTF-8 text ({exc}); "
                   f"NOTHING was captured.",))
    except json.JSONDecodeError as exc:
        return StateRead(
            ok=False, path=fspath, captured_at=captured_at or "",
            notes=(f"{fspath}: the state file is not valid JSON ({exc}); "
                   f"NOTHING was captured.",))
    except RecursionError:
        return StateRead(
            ok=False, path=fspath, captured_at=captured_at or "",
            notes=(f"{fspath}: the state document nests deeper than this reader "
                   f"will descend; NOTHING was captured.",))

    stamp = captured_at if captured_at is not None else mtime_utc(stat.st_mtime)
    read = read_state_document(document, origin=fspath, captured_at=stamp,
                               vault=vault)
    if captured_at is None:
        read = replace(read, notes=(MTIME_NOTE.format(path=fspath, stamp=stamp),)
                       + read.notes)
    return read


def read_state_document(document: Any, *, origin: str = "", captured_at: str = "",
                        vault: SecretVault | None = None) -> StateRead:
    """Read one already-parsed v4 state document. NEVER RAISES.

    Split from :func:`read_state` so the five gates can be exercised without a
    file, and so a caller that already holds the document (a test, a future
    ``terraform state pull`` consumer) reads it through the SAME code.
    """
    path = origin or "<document>"
    notes: list[str] = []

    if not isinstance(document, Mapping):
        return StateRead(
            ok=False, path=origin, captured_at=captured_at,
            notes=(f"{path}: a terraform state document is a JSON object, and "
                   f"this is a {type(document).__name__}; NOTHING was captured.",))

    version = document.get("version")
    terraform_version = document.get("terraform_version")
    serial = document.get("serial")
    lineage = document.get("lineage")
    # The header is built BEFORE the gates, so even a refusal can say which
    # state file it was refusing.
    header: dict[str, Any] = {
        "path": origin,
        "captured_at": captured_at,
        "version": version,
        "terraform_version": (terraform_version
                              if isinstance(terraform_version, str) else ""),
        "serial": (serial if isinstance(serial, int)
                   and not isinstance(serial, bool) else None),
        "lineage": lineage if isinstance(lineage, str) else "",
    }

    resources = document.get("resources")

    # HAZARD 5, first, and BEFORE the version refusal: `init` stamps the backend
    # stub with a version of its own, so "wrong version" would be a true
    # statement that sends the reader looking in entirely the wrong place.
    if "backend" in document and not isinstance(resources, list):
        return StateRead(ok=False, notes=(REMOTE_BACKEND_STUB.format(path=path),),
                         **header)
    if version != STATE_VERSION:
        return StateRead(
            ok=False, **header,
            notes=(STATE_VERSION_REFUSED.format(path=path, version=version,
                                                expected=STATE_VERSION),))
    if not isinstance(resources, list):
        return StateRead(ok=False, notes=(REMOTE_BACKEND_STUB.format(path=path),),
                         **header)

    notes.append(NEVER_COMPLETE_NOTE.format(path=path))
    if not header["lineage"]:
        notes.append(_NO_LINEAGE_NOTE.format(path=path))
    if "serial" in document and header["serial"] is None:
        notes.append(f"{path}: 'serial' is {safe_repr(serial)}, not an integer; "
                     f"supersession cannot be checked against it.")
    notes.extend(_read_outputs(document.get("outputs"), path, vault))

    objects: list[TfObject] = []
    data_addresses: list[str] = []
    deposed_addresses: list[str] = []
    seen: set[str] = set()

    for position, entry in enumerate(resources):
        if not isinstance(entry, Mapping):
            notes.append(f"{path}: resources[{position}] is a "
                         f"{type(entry).__name__} and not an object; skipped.")
            continue

        resource_type = entry.get("type")
        name = entry.get("name")
        module = entry.get("module") or ""
        if not isinstance(module, str):
            notes.append(f"{path}: resources[{position}] has a non-string "
                         f"'module'; skipped, because its address cannot be "
                         f"composed.")
            continue
        if not isinstance(resource_type, str) or not resource_type \
                or not isinstance(name, str) or not name:
            notes.append(f"{path}: resources[{position}] has no usable "
                         f"'type'/'name' pair; skipped, because its address "
                         f"cannot be composed.")
            continue

        stem = compose_address(resource_type, name, module=module)

        # HAZARD 4. Counted, not ignored: a data source IS in the estate, but
        # terraform does not manage it, so folding it into the capture would
        # claim coverage terraform does not have.
        if entry.get("mode") == "data":
            data_addresses.append(f"data.{stem}")
            continue

        # HAZARD 1.
        provider = parse_provider(entry.get("provider"),
                                  resource_type=resource_type)
        if not provider.ok:
            notes.append(f"{path}: {stem} was REFUSED: {provider.note}. The "
                         f"resource is NOT in this capture — it is refused "
                         f"loudly rather than attributed to a provider nobody "
                         f"wrote.")
            continue
        if provider.inferred:
            notes.append(f"{path}: {stem}: {provider.note}.")

        instances = entry.get("instances")
        if not isinstance(instances, list):
            notes.append(f"{path}: {stem} carries no 'instances' array; "
                         f"skipped.")
            continue

        for index, instance in enumerate(instances):
            if not isinstance(instance, Mapping):
                notes.append(f"{path}: {stem} instance {index} is a "
                             f"{type(instance).__name__} and not an object; "
                             f"skipped.")
                continue

            # HAZARD 3, per INSTANCE. The live instance at this very address is
            # usually the NEXT element, so this must never skip the resource.
            if instance.get("deposed"):
                deposed_addresses.append(
                    compose_address(resource_type, name, module=module,
                                    index_key=instance.get("index_key")))
                continue

            index_key = instance.get("index_key")
            if index_key is not None and (isinstance(index_key, bool)
                                          or not isinstance(index_key, (int, str))):
                notes.append(f"{path}: {stem} instance {index} has an index key "
                             f"of type {type(index_key).__name__}, which "
                             f"terraform does not write; it was rendered as a "
                             f"quoted string.")
            address = compose_address(resource_type, name, module=module,
                                      index_key=index_key)

            attributes = instance.get("attributes")
            if not isinstance(attributes, Mapping):
                if "attributes_flat" in instance:
                    notes.append(FLATMAP_NOTE.format(address=address, index=index))
                else:
                    notes.append(f"{address}: instance {index} carries no "
                                 f"'attributes' object ({safe_repr(attributes)}); "
                                 f"skipped rather than read as empty.")
                continue

            declared = instance.get("sensitive_attributes")
            if not isinstance(declared, (list, tuple)):
                if declared is not None:
                    notes.append(f"{address}: 'sensitive_attributes' is a "
                                 f"{type(declared).__name__} and not a list of "
                                 f"cty paths; the name heuristic alone guarded "
                                 f"this instance.")
                declared = ()

            # REDACTION, before the object exists. The routes and their
            # fail-safes belong to redact.py; this reader only carries the notes.
            values, redaction_notes = redact(attributes, sensitive_paths=declared,
                                             vault=vault)
            for note in redaction_notes:
                notes.append(f"{address}: {note}")

            if address in seen:
                notes.append(f"{path}: two entries compose the address "
                             f"{address}; BOTH were kept and the merge will see "
                             f"them as two facts about one key.")
            seen.add(address)

            objects.append(TfObject(
                address=address, type=resource_type, name=name, module=module,
                index_key=index_key, provider=provider.spelling, source=SOURCE,
                side="current", values=values,
                sensitive_paths=tuple(_spell_cty_path(steps) for steps in declared),
                notes=tuple(redaction_notes), artifact=origin))

    if data_addresses:
        notes.append(
            f"{path}: {len(data_addresses)} data-mode entr(y|ies) were SKIPPED "
            f"({_sample(data_addresses)}): a data source is present in the "
            f"estate but is NOT terraform-managed, so capturing it would "
            f"overstate coverage.")
    if deposed_addresses:
        notes.append(
            f"{path}: {len(deposed_addresses)} DEPOSED instance(s) were SKIPPED "
            f"({_sample(deposed_addresses)}): a deposed generation is the old "
            f"object a create-before-destroy left behind, and the live instance "
            f"at the same address is the one this capture kept.")
    if not objects:
        notes.append(EMPTY_STATE_NOTE.format(path=path) if not resources
                     else NOTHING_SURVIVED_NOTE.format(path=path,
                                                       entries=len(resources)))

    logger.debug("tfstate %s: %d object(s), %d data source(s), %d deposed, "
                 "%d note(s)", path, len(objects), len(data_addresses),
                 len(deposed_addresses), len(notes))
    return StateRead(ok=True, objects=tuple(objects), notes=tuple(notes),
                     data_sources=len(data_addresses),
                     deposed=len(deposed_addresses), **header)


# -- helpers ------------------------------------------------------------------


def _sample(addresses: Sequence[str], limit: int = 5) -> str:
    """Name the first few skipped addresses; a note that says only "12 were
    skipped" is a note nobody can act on."""
    shown = ", ".join(addresses[:limit])
    extra = len(addresses) - limit
    return f"{shown} and {extra} more" if extra > 0 else shown


def _spell_cty_path(steps: Any) -> str:
    """Render one ``sensitive_attributes`` cty step list as the dotted-and-
    indexed attribute path this repo's walkers use (``basic[0].members``).

    Diagnostic only — it names an attribute and never a value, so it is safe in
    a note, a log line and a verdict. The DECODING that decides what to redact
    lives in ``redact.redact_cty_paths`` and is not repeated here.
    """
    if not isinstance(steps, (list, tuple)):
        return "<unrecognised sensitive-attribute path>"
    out = ""
    for step in steps:
        if not isinstance(step, Mapping):
            out += "[?]"
            continue
        kind, value = step.get("type"), step.get("value")
        if kind == "get_attr" and isinstance(value, str) and value:
            out = f"{out}.{value}" if out else value
        elif kind == "index":
            if isinstance(value, Mapping):
                for spelling in ("number", "string", "value"):
                    if spelling in value:
                        value = value[spelling]
                        break
            out += f"[{value}]" if isinstance(value, (int, str)) else "[?]"
        else:
            out += "[?]"
    return out or "<root>"


def _read_outputs(outputs: Any, path: str, vault: SecretVault | None) -> list[str]:
    """Read ``outputs`` ONLY far enough to say that a sensitive one exists.

    An output value is stored in PLAINTEXT and the ``sensitive`` flag is a
    display marker, so the value is never returned, never logged and never
    noted — only the NAME is. When a vault is supplied the plaintext is handed
    to it, which is what lets the final scrub catch the value if some other
    module later renders it.
    """
    if outputs is None:
        return []
    if not isinstance(outputs, Mapping):
        return [f"{path}: 'outputs' is a {type(outputs).__name__} and not an "
                f"object; it was not read."]
    sensitive: list[str] = []
    for name, body in sorted(outputs.items(), key=lambda item: str(item[0])):
        if isinstance(body, Mapping) and body.get("sensitive") is True:
            sensitive.append(str(name))
            if vault is not None:
                value = body.get("value")
                if isinstance(value, str):
                    vault.add(value)
    if not sensitive:
        return []
    return [f"{path}: {len(sensitive)} of {len(outputs)} state output(s) are "
            f"marked sensitive ({_sample(sensitive)}) and terraform stores "
            f"their values in PLAINTEXT — the flag is a DISPLAY marker only. "
            f"Outputs are not read as facts here; only their names appear."]
