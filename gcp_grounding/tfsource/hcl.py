"""THE one HCL and ``.tf.json`` reader, in the PLAN-JSON ENCODING, with poison
at ATTRIBUTE granularity.

Layer 1 of the pipeline described in :mod:`gcp_grounding.tfsource`, for the
weakest of the three current-state artifacts. It turns terraform CONFIGURATION —
``.tf`` through :mod:`gcp_grounding.tfsource.hcl_lite`, ``.tf.json`` through
``json.load`` — into :class:`gcp_grounding.facts.TfObject` values.

TWO STAMPINGS, ONE PARSE, CHOSEN BY THE CALLER
----------------------------------------------
The same file read the same way is stamped either

- ``source="hcl"``, ``side="current"`` — configuration read as a DESIRED-STATE
  current view, or
- ``source="hcl-proposed"``, ``side="proposed"`` — the same configuration read
  as the CHANGE UNDER REVIEW,

selected by the explicit ``side`` argument every reading entry point requires.
It is never inferred from the path, the directory or the caller: a file in a
working tree is both things at different moments, and a reader that guessed
would silently rank a proposal against reality.
:func:`gcp_grounding.facts.TfObject`'s biconditional enforces the pairing in
BOTH directions, so neither stamping can be half-applied.

**Callers import this module DIRECTLY.** There is no adapter module in front of
it and none may be added: a pure indirection layer is a second place for the
contract to drift.

THE INTEROP RULE — why one mapper table serves three readers
------------------------------------------------------------
``TfObject.values`` is in the PLAN-JSON ENCODING, whichever syntax it was read
from:

- repeated nested blocks fold into a LIST OF OBJECTS, in source order;
- a SINGLE block is still a ONE-ELEMENT list, so a mapper never has to ask which
  shape it is holding;
- a block name colliding with an ATTRIBUTE of the same name in the same body
  emits NO object for that block, plus a note. Terraform itself rejects such a
  body, so there is no configuration to be right about; picking one of the two
  spellings would answer about a configuration nobody wrote. The attribute's own
  value stays at its own key, and the RESOURCE is still emitted — dropping it
  would take it out of the census, which is the hazard the poison rules below
  exist to prevent.

That is what lets :mod:`gcp_grounding.tfsource.mapping` hold ONE mapper per
resource type for the state, plan and HCL readers alike. A mapper that had to
sniff which reader produced an object would be the per-reader adapter table this
encoding exists to prevent.

THE ONE ASYMMETRY, stated so nobody reads it as a bug: in HCL a block
(``allow { … }``) and a map-valued attribute (``allow = { … }``) are different
syntax, so the fold is exact. In ``.tf.json`` they are the same JSON object and
only the provider's schema could tell them apart — this reader has no schema, so
a JSON object VALUE is normalised to a one-element list of objects, which is the
block reading. Every attribute this design's categories care about is a block;
the cost of the rule is that a genuinely map-typed JSON attribute arrives
wrapped, and the benefit is that both legal JSON encodings and HCL land on one
shape.

POISON RULES, AT ATTRIBUTE GRANULARITY
--------------------------------------
- ``count`` / ``for_each`` set the object's MULTIPLICITY to unknown —
  ``values["count"]`` is an :class:`~gcp_grounding.facts.Unresolved` carrying
  that reason, which is exactly what :func:`gcp_grounding.tfsource.mapping.multiplicity`
  reads — plus a note. The object is **not dropped**: it stays visible in the
  census, because a resource silently removed reads as a resource that is not
  there.
- A ``dynamic "X"`` block makes ``values["X"]`` the STATIC ``X`` blocks with ONE
  ``Unresolved("dynamic_block", "X[]")`` APPENDED. Spelled out because the
  failure it prevents is silent and one-directional: a ``dynamic "rule"`` block
  beside one static ``rule`` makes the body look like it has exactly one rule,
  so a naive reader concludes NO PERMISSIVE RULE EXISTS — a false negative on
  precisely the checks that matter. The appended marker makes the generated
  blocks unresolvable instead of invisible.
- A PROVIDER ALIAS (``provider = google.eu``) yields a note and the object is
  STILL EMITTED; ``values["provider"]`` carries a ``provider_alias`` marker,
  because which provider block an alias resolves to — and therefore which
  project and region a bare name lives in — is a configuration-wide question
  this resource cannot answer by itself.
- An ``Unresolved`` attribute value stays exactly at ITS OWN KEY: nothing
  dropped, nothing coerced, no sibling poisoned. One unresolvable
  ``source_ranges`` does not cost the literal ``priority`` beside it.

NEVER SUBSTITUTE — a hard non-goal
----------------------------------
A ``variable`` block's ``default`` is **never** used to resolve a reference to
that variable. A ``.tfvars`` file, a ``TF_VAR_`` environment variable and a
``-var`` flag each override it, so the default is one candidate among several
and substituting it would emit a value that the run under review may never use —
a confident answer about a name nobody wrote. ``module`` blocks are NOT followed
either, not even for a local ``source``: a module's inputs come from the call
site and its resources belong to a different address space. Both gaps are
NOTED rather than silent.

THE CONFIG-DIRECTORY CONTRACT
-----------------------------
:func:`parse_config_file` and :func:`parse_config_dir` are the gate's raw-``.tf``
arm, exposed as functions ON THIS MODULE rather than in a file of their own for
the same reason there is no adapter: one contract, one place.

:func:`parse_config_dir` walks ONE directory NON-RECURSIVELY, in sorted order,
because terraform itself does not recurse for a module's own configuration —
recursing would silently pull a sibling module's resources into this module's
view and report resources this directory does not declare. A per-file read
failure is recorded as ONE unresolved path and the rest of the directory is
still read, rather than aborting it.

A resource bearing ``count``, ``for_each`` or a ``dynamic`` block contributes
its triple AND an unresolved path naming the CONTAINING resource. Never silently
dropped: the gate needs that path to downgrade every ``grounded`` on the file,
and a silently dropped resource reads as a resource that is not there.

CAPTURE TIME AND THE DESIRED-STATE NOTE
---------------------------------------
The capture time is the FILE MTIME (the newest one, for a directory) — see
:data:`MTIME_NOTE` for what that timestamp really is. Every view carries
:data:`DESIRED_STATE_NOTE`: configuration is DESIRED state, which may never have
been applied, and is the weakest current-state evidence in this design.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from ..core.log import get_logger
from ..facts import (SIDES, TfObject, Unresolved, is_interpolated, safe_repr,
                     truncate, unresolved_in)
from . import hcl_lite

logger = get_logger(__name__)

__all__ = [
    "SOURCE",
    "PROPOSED_SOURCE",
    "SOURCE_FOR_SIDE",
    "CONFIG_SUFFIXES",
    "MULTIPLICITY_META",
    "COMMENT_KEY",
    "DESIRED_STATE_NOTE",
    "MTIME_NOTE",
    "NO_TERRAFORM_NOTE",
    "ALL_UNPARSED_NOTE",
    "NOT_CONFIG_NOTE",
    "COLLISION_NOTE",
    "MULTIPLICITY_NOTE",
    "DYNAMIC_NOTE",
    "PROVIDER_ALIAS_NOTE",
    "MODULE_NOTE",
    "VARIABLE_DEFAULT_NOTE",
    "DATA_SOURCE_NOTE",
    "MALFORMED_NOTE",
    "UNPARSED_PATH",
    "source_for",
    "UnparsedFile",
    "HclRead",
    "config_files",
    "read_file",
    "read_dir",
    "parse_config_file",
    "parse_config_dir",
]

#: The ``provenance.SOURCES`` spelling for configuration read as a DESIRED-STATE
#: current view.
SOURCE = "hcl"

#: The :data:`gcp_grounding.facts.PROPOSED_SOURCES` spelling for the same parse
#: read as the CHANGE UNDER REVIEW.
PROPOSED_SOURCE = "hcl-proposed"

#: side → source. The two stampings are a closed table rather than a rule a
#: caller could compute, so there is no third spelling to invent.
SOURCE_FOR_SIDE: Mapping[str, str] = MappingProxyType({
    "current": SOURCE,
    "proposed": PROPOSED_SOURCE,
})

#: The file names terraform itself reads for a module's own configuration. A
#: bare ``.json`` is NOT configuration, and neither is anything in a
#: subdirectory.
CONFIG_SUFFIXES = (".tf", ".tf.json")

#: The meta-arguments that turn one resource block into 0..N real objects. The
#: same two :mod:`gcp_grounding.tfsource.mapping` reads off ``values``.
MULTIPLICITY_META = ("count", "for_each")

#: Terraform's JSON syntax spells a comment as a ``"//"`` PROPERTY. It is
#: dropped at every level: it is documentation, not an attribute, and carrying
#: it would put prose in a record.
COMMENT_KEY = "//"


# -- the notes ----------------------------------------------------------------

#: Carried by EVERY view this module returns, successful or refused.
DESIRED_STATE_NOTE = (
    "{path}: terraform CONFIGURATION is DESIRED state, and the weakest "
    "current-state evidence in this design. It may never have been applied, it "
    "may have been applied and then changed by hand or by another pipeline, and "
    "it describes only what this directory declares — so no category may be "
    "resolved ABSENT from it."
)

#: THE MTIME NOTE. A checkout, a copy, a rebase or an editor save all reset the
#: mtime, so a configuration file can look far fresher than the estate it
#: describes — and, unlike a state file, it was never a claim about the estate
#: in the first place. A caller that passes ``captured_at`` does not get this
#: note, because it would then be false.
MTIME_NOTE = (
    "{path}: captured_at {stamp} is the configuration FILE's modification time "
    "and NOT the time anything was applied or read. A checkout, a copy, a "
    "rebase or an editor save all reset it."
)

NO_TERRAFORM_NOTE = (
    "{path}: this directory contains no .tf or .tf.json file at all — there is "
    "no terraform configuration here to read. That is NOT the same answer as a "
    "directory whose terraform files were all refused."
)

ALL_UNPARSED_NOTE = (
    "{path}: ALL {count} terraform file(s) in this directory were refused and "
    "ZERO were read. This directory declares terraform that nothing here "
    "understands; it is NOT a directory with no terraform in it, and nothing "
    "may be concluded absent from it."
)

NOT_CONFIG_NOTE = (
    "{path}: not a terraform configuration file (expected one of "
    "{suffixes}); nothing was read from it."
)

COLLISION_NOTE = (
    "{address}: {name!r} is BOTH an attribute and a block in the same body. The "
    "block emits no object: terraform rejects such a body outright, so there is "
    "no configuration to be right about, and choosing one of the two spellings "
    "would answer about a configuration nobody wrote. The attribute's own value "
    "stays at its own key."
)

MULTIPLICITY_NOTE = (
    "{address}: {meta!r} makes this 0..N objects rather than one, so the "
    "object's MULTIPLICITY is unknown and no keyed fact may name it. It is "
    "still emitted and still counted — a silently dropped resource reads as a "
    "resource that is not there."
)

DYNAMIC_NOTE = (
    "{address}: a dynamic {label!r} block generates {label} blocks this reader "
    "cannot see, so values[{label!r}] is the {static} static block(s) plus ONE "
    "appended dynamic_block marker. A dynamic rule block beside one static rule "
    "makes the body look like it has exactly one rule, so a naive reader "
    "concludes no permissive rule exists — a silent false negative on precisely "
    "the checks that matter."
)

PROVIDER_ALIAS_NOTE = (
    "{address}: provider = {provider} names an ALIASED provider whose project "
    "and region defaults live in a provider block elsewhere in the "
    "configuration. The object is still emitted and the alias is marked "
    "unresolved; which qualifiers it would supply is not decided here."
)

MODULE_NOTE = (
    "{path}: module {name!r} is NOT followed, even for a local source. Its "
    "inputs come from this call site and its resources live in another address "
    "space, so whatever it declares is missing from this view."
)

VARIABLE_DEFAULT_NOTE = (
    "{path}: {count} variable default(s) were read as DECLARATIONS only and "
    "NEVER substituted into a reference. A .tfvars file, a TF_VAR_ environment "
    "variable or a -var flag each override a default, so substituting one would "
    "emit a value the run under review may never use."
)

DATA_SOURCE_NOTE = (
    "{path}: {count} data source(s) were skipped. Terraform READS a data source "
    "and does not manage it, so counting one as captured would overstate what "
    "this configuration covers."
)

MALFORMED_NOTE = "{path}: {detail}; nothing was read from that entry."

#: The unresolved path a refused FILE contributes, in place of the per-resource
#: paths it never produced. It is not a dotted attribute path because there is
#: no address to prefix — the file itself is what could not be resolved.
UNPARSED_PATH = "{path}:<unparsed>"

_MULTIPLICITY_DETAIL = "{meta} makes this 0..N objects, not one"
_DYNAMIC_DETAIL = "a dynamic {label!r} block generates blocks this reader cannot see"
_PROVIDER_DETAIL = "provider alias {provider}: the project is configured elsewhere"
_JSON_TEMPLATE_DETAIL = "a JSON string carrying '${'"

_REFUSAL_PREFIXES = (
    hcl_lite.SYNTAX_NOTE_PREFIX,
    hcl_lite.DEPTH_NOTE_PREFIX,
    hcl_lite.ENCODING_NOTE_PREFIX,
    hcl_lite.READ_NOTE_PREFIX,
    hcl_lite.INTERNAL_NOTE_PREFIX,
)


def source_for(side: str) -> str:
    """The source spelling for ``side`` — the ONE place the two stampings pair.

    Raises for anything else, including an omitted one: the side is a caller's
    declaration of what the file is being read AS, and a default would let a
    proposal be read as reality by accident.
    """
    try:
        return SOURCE_FOR_SIDE[side]
    except (KeyError, TypeError):
        raise ValueError(
            f"hcl: side must be one of {list(SIDES)} and must be passed "
            f"explicitly, got {side!r}. Configuration read as a desired-state "
            f"current view is stamped {SOURCE!r}/'current'; the same file read "
            f"as the change under review is stamped {PROPOSED_SOURCE!r}/"
            f"'proposed'. Which one it is cannot be inferred from the path."
        ) from None


# -- the results --------------------------------------------------------------


@dataclass(frozen=True)
class UnparsedFile:
    """One configuration file that was REFUSED, and why.

    A refused file is recorded rather than skipped, because a directory whose
    files were all refused and a directory with no terraform in it are the same
    empty answer otherwise — and only one of them means nothing was there.
    """

    path: str
    note: str


@dataclass(frozen=True)
class HclRead:
    """One configuration file or directory, read.

    ``ok`` is True when at least one file was parsed, even if it declared
    nothing: parsed-and-empty is a real answer, while refused-and-empty is not.
    ``unparsed`` names every file that was refused; ``files`` every file that
    was read. A refused read carries no objects and always says why.
    """

    ok: bool = False
    objects: tuple[TfObject, ...] = ()
    notes: tuple[str, ...] = ()
    unparsed: tuple[UnparsedFile, ...] = ()
    files: tuple[str, ...] = ()
    captured_at: str = ""
    path: str = ""
    source: str = ""
    side: str = "current"

    def __post_init__(self) -> None:
        object.__setattr__(self, "objects", tuple(self.objects))
        object.__setattr__(self, "notes", tuple(self.notes))
        object.__setattr__(self, "unparsed", tuple(self.unparsed))
        object.__setattr__(self, "files", tuple(self.files))
        if not self.ok and self.objects:
            raise ValueError("a refused HclRead carries no objects; a partial "
                             "reading of a configuration is a configuration "
                             "nobody declared")
        if not self.notes:
            raise ValueError("every HclRead states that configuration is DESIRED "
                             "state; a view without that note is a view whose "
                             "reader nobody can weigh")

    @property
    def addresses(self) -> tuple[str, ...]:
        """Every address read, in document order."""
        return tuple(obj.address for obj in self.objects)

    def triples(self) -> tuple[tuple[str, str, Mapping[str, Any]], ...]:
        """``(address, resource_type, values)`` for every object — the shape the
        gate's raw-``.tf`` arm consumes."""
        return tuple((obj.address, obj.type, obj.values) for obj in self.objects)

    def unresolved_paths(self) -> tuple[str, ...]:
        """Every unresolved dotted path, each PREFIXED WITH ITS OWNING ADDRESS,
        plus one path per refused file.

        Order is document order and duplicates are dropped, so the tuple is a
        stable answer about one directory rather than a bag.
        """
        out: list[str] = []
        for obj in self.objects:
            for path, _marker in unresolved_in(obj.values):
                out.append(f"{obj.address}.{path}")
        for row in self.unparsed:
            out.append(UNPARSED_PATH.format(path=row.path))
        seen: set[str] = set()
        unique: list[str] = []
        for path in out:
            if path not in seen:
                seen.add(path)
                unique.append(path)
        return tuple(unique)


# -- the capture time ---------------------------------------------------------


def _stamp(mtime: float) -> str:
    """A POSIX mtime in the snapshot's ``...Z`` form, mirroring
    :func:`gcp_grounding.fetch.fresh_captured_at` so two captures stamp
    comparably."""
    return datetime.fromtimestamp(mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- HCL bodies to the plan-JSON encoding -------------------------------------


def _provider_spelling(span: Sequence[hcl_lite.Token]) -> str:
    """``google`` or ``google.eu`` from a ``provider =`` span, or ``""``.

    Only the two shapes terraform accepts are read; anything else yields no
    spelling at all rather than a guess at one.
    """
    tokens = tuple(token for token in span if token.kind != "NEWLINE")
    if len(tokens) == 1 and tokens[0].kind == "STRING":
        return tokens[0].text.strip()
    parts: list[str] = []
    for index, token in enumerate(tokens):
        if index % 2 == 0:
            if token.kind != "IDENT":
                return ""
            parts.append(token.text)
        elif not (token.kind == "PUNCT" and token.text == "."):
            return ""
    if len(tokens) % 2 == 0:            # a trailing '.' names nothing
        return ""
    return ".".join(parts)


def _block_values(body: hcl_lite.Body, *, prefix: str, address: str,
                  notes: list[str], meta: dict[str, Any] | None = None
                  ) -> dict[str, Any]:
    """One HCL body in the plan-JSON encoding.

    ``meta is not None`` marks the RESOURCE's own body, where ``count``,
    ``for_each`` and ``provider`` are meta-arguments; deeper in, a key with one
    of those names is an ordinary attribute of a nested block and is decoded as
    one.
    """
    top = meta is not None
    values: dict[str, Any] = {}
    attributes = set(body.attributes)

    for name, span in body.attributes.items():
        path = f"{prefix}{name}"
        if top and name in MULTIPLICITY_META:
            values[name] = Unresolved(name, path,
                                      _MULTIPLICITY_DETAIL.format(meta=name))
            notes.append(MULTIPLICITY_NOTE.format(address=address, meta=name))
            continue
        if top and name == "provider":
            spelling = _provider_spelling(span)
            meta["provider"] = spelling                      # type: ignore[index]
            if "." in spelling:
                values[name] = Unresolved(
                    "provider_alias", path,
                    truncate(_PROVIDER_DETAIL.format(provider=spelling)))
                notes.append(PROVIDER_ALIAS_NOTE.format(address=address,
                                                        provider=spelling))
            continue
        values[name] = hcl_lite.classify_expr(span, path)

    # Repeated blocks fold into a LIST of objects, in source order; a single
    # block is still a one-element list.
    grouped: dict[str, list[hcl_lite.Block]] = {}
    for block in body.blocks:
        grouped.setdefault(block.type, []).append(block)
    for block_type, blocks in grouped.items():
        if block_type in attributes:
            notes.append(COLLISION_NOTE.format(address=address, name=block_type))
            continue
        values[block_type] = [
            _block_values(block.body, prefix=f"{prefix}{block_type}[{index}].",
                          address=address, notes=notes)
            for index, block in enumerate(blocks)
        ]

    # A dynamic block's generated bodies are invisible here, so the label's list
    # gets ONE marker appended to the static blocks rather than being left to
    # look complete.
    for label in body.dynamic:
        if label in attributes:
            notes.append(COLLISION_NOTE.format(address=address, name=label))
            continue
        static = values.get(label) or []
        values[label] = list(static) + [
            Unresolved("dynamic_block", f"{prefix}{label}[]",
                       truncate(_DYNAMIC_DETAIL.format(label=label)))]
        notes.append(DYNAMIC_NOTE.format(address=address, label=label,
                                         static=len(static)))
    return values


def _hcl_objects(body: hcl_lite.Body, *, artifact: str, source: str,
                 side: str) -> tuple[list[TfObject], list[str]]:
    """Every ``resource`` block in one parsed file, plus the file's notes."""
    objects: list[TfObject] = []
    notes: list[str] = []
    data_sources = 0
    variable_defaults = 0
    for block in body.blocks:
        if block.type == "data":
            data_sources += 1
            continue
        if block.type == "module":
            name = block.labels[0] if block.labels else "<unnamed>"
            notes.append(MODULE_NOTE.format(path=artifact, name=name))
            continue
        if block.type == "variable":
            if "default" in block.body.attributes:
                variable_defaults += 1
            continue
        if block.type != "resource":
            continue                    # locals, provider, output, terraform, …
        if len(block.labels) != 2 or not all(block.labels):
            notes.append(MALFORMED_NOTE.format(
                path=artifact,
                detail=(f"a resource block at line {block.line} carries "
                        f"{len(block.labels)} label(s) and needs exactly two "
                        f"(type and name)")))
            continue
        resource_type, name = block.labels
        address = f"{resource_type}.{name}"
        own_notes: list[str] = []
        meta: dict[str, Any] = {}
        values = _block_values(block.body, prefix="", address=address,
                               notes=own_notes, meta=meta)
        objects.append(_object(address, resource_type, name, values,
                               provider=meta.get("provider", ""),
                               own_notes=own_notes, artifact=artifact,
                               source=source, side=side))
        notes.extend(own_notes)
    if data_sources:
        notes.append(DATA_SOURCE_NOTE.format(path=artifact, count=data_sources))
    if variable_defaults:
        notes.append(VARIABLE_DEFAULT_NOTE.format(path=artifact,
                                                  count=variable_defaults))
    return objects, notes


def _object(address: str, resource_type: str, name: str,
            values: Mapping[str, Any], *, provider: str, own_notes: list[str],
            artifact: str, source: str, side: str) -> TfObject:
    """One :class:`~gcp_grounding.facts.TfObject`, with its markers rolled up.

    The roll-up is taken from the VALUES rather than accumulated by hand, so a
    marker can never be in the document and missing from the roll-up.
    """
    markers = tuple(marker for _path, marker in unresolved_in(values))
    logger.debug("hcl read %s (%s) with %d attribute(s) and %d marker(s)",
                 address, source, len(values), len(markers))
    return TfObject(address=address, type=resource_type, name=name,
                    provider=provider, source=source, side=side, values=values,
                    unresolved=markers, notes=tuple(own_notes), artifact=artifact)


# -- .tf.json bodies to the same encoding -------------------------------------


def _json_value(value: Any, *, path: str, address: str,
                notes: list[str]) -> Any:
    """One JSON attribute value in the plan-JSON encoding.

    A string carrying ``${`` becomes an :class:`~gcp_grounding.facts.Unresolved`
    exactly as in the HCL path — the SUBSTRING rule, so ``roles/${var.tier}.admin``
    is refused too. A JSON OBJECT is read as a nested block and normalised to a
    one-element list of objects; an ARRAY of objects keeps its length. See the
    module docstring for why the object case is decided this way.
    """
    if isinstance(value, str):
        if is_interpolated(value):
            return Unresolved("interpolation", path, _JSON_TEMPLATE_DETAIL)
        return value
    if isinstance(value, Mapping):
        return [_json_body(value, prefix=f"{path}[0].", address=address, notes=notes)]
    if isinstance(value, list):
        out: list[Any] = []
        for index, item in enumerate(value):
            item_path = f"{path}[{index}]"
            if isinstance(item, Mapping):
                out.append(_json_body(item, prefix=f"{item_path}.",
                                      address=address, notes=notes))
            else:
                out.append(_json_value(item, path=item_path, address=address,
                                       notes=notes))
        return out
    return value                        # numbers, booleans and null are literals


def _dynamic_labels(spec: Any) -> list[str]:
    """The labels of a JSON ``dynamic`` entry, in either legal spelling: a
    mapping of label to body, or a LIST of such mappings."""
    labels: list[str] = []
    entries = spec if isinstance(spec, list) else [spec]
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        for label in entry:
            if label != COMMENT_KEY and label not in labels:
                labels.append(label)
    return labels


def _json_body(body: Mapping[str, Any], *, prefix: str, address: str,
               notes: list[str], meta: dict[str, Any] | None = None
               ) -> dict[str, Any]:
    """One JSON body in the plan-JSON encoding, with the same meta-argument and
    dynamic-block poison the HCL path applies."""
    top = meta is not None
    values: dict[str, Any] = {}
    dynamic: Any = None
    for key, value in body.items():
        if key == COMMENT_KEY:
            continue
        path = f"{prefix}{key}"
        if top and key in MULTIPLICITY_META:
            values[key] = Unresolved(key, path,
                                     _MULTIPLICITY_DETAIL.format(meta=key))
            notes.append(MULTIPLICITY_NOTE.format(address=address, meta=key))
            continue
        if top and key == "provider":
            spelling = value.strip() if isinstance(value, str) else ""
            meta["provider"] = spelling                      # type: ignore[index]
            if "." in spelling:
                values[key] = Unresolved(
                    "provider_alias", path,
                    truncate(_PROVIDER_DETAIL.format(provider=spelling)))
                notes.append(PROVIDER_ALIAS_NOTE.format(address=address,
                                                        provider=spelling))
            continue
        if top and key == "dynamic":
            dynamic = value
            continue
        values[key] = _json_value(value, path=path, address=address, notes=notes)
    for label in _dynamic_labels(dynamic) if dynamic is not None else ():
        static = values.get(label)
        if static is None:
            static = []
        elif not (isinstance(static, list)
                  and all(isinstance(item, Mapping) for item in static)):
            # JSON cannot tell a block from a map-valued attribute, so a label
            # already holding something that is NOT a list of objects is the
            # collision case and the generated blocks emit no object.
            notes.append(COLLISION_NOTE.format(address=address, name=label))
            continue
        values[label] = list(static) + [
            Unresolved("dynamic_block", f"{prefix}{label}[]",
                       truncate(_DYNAMIC_DETAIL.format(label=label)))]
        notes.append(DYNAMIC_NOTE.format(address=address, label=label,
                                         static=len(static)))
    return values


def _json_resource_entries(document: Mapping[str, Any], *, artifact: str,
                           notes: list[str]) -> list[tuple[str, str, Mapping[str, Any]]]:
    """``(type, name, body)`` for both legal ``resource`` encodings.

    A MAPPING of type to name to body, and a LIST of single-key mappings of the
    same shape. Anything else is noted and skipped rather than guessed at.
    """
    block = document.get("resource")
    containers: list[Mapping[str, Any]] = []
    if isinstance(block, Mapping):
        containers.append(block)
    elif isinstance(block, list):
        for index, element in enumerate(block):
            if isinstance(element, Mapping):
                containers.append(element)
            else:
                notes.append(MALFORMED_NOTE.format(
                    path=artifact,
                    detail=(f"resource[{index}] is {safe_repr(element)} and not "
                            f"a mapping of type to name to body")))
    elif block is not None:
        notes.append(MALFORMED_NOTE.format(
            path=artifact,
            detail=(f"'resource' is {safe_repr(block)}; the two legal encodings "
                    f"are a mapping of type to name to body and a list of "
                    f"single-key mappings")))
    entries: list[tuple[str, str, Mapping[str, Any]]] = []
    for container in containers:
        for resource_type, named in container.items():
            if resource_type == COMMENT_KEY:
                continue
            if not isinstance(named, Mapping):
                notes.append(MALFORMED_NOTE.format(
                    path=artifact,
                    detail=(f"resource type {resource_type!r} maps to "
                            f"{safe_repr(named)} and not to a mapping of name "
                            f"to body")))
                continue
            for name, body in named.items():
                if name == COMMENT_KEY:
                    continue
                if isinstance(body, list) and len(body) == 1:
                    body = body[0]      # the one-element array spelling of a body
                if not isinstance(body, Mapping):
                    notes.append(MALFORMED_NOTE.format(
                        path=artifact,
                        detail=(f"{resource_type}.{name} has a body of "
                                f"{safe_repr(body)} and not one object")))
                    continue
                entries.append((resource_type, name, body))
    return entries


def _json_objects(document: Mapping[str, Any], *, artifact: str, source: str,
                  side: str) -> tuple[list[TfObject], list[str]]:
    """Every resource in one ``.tf.json`` document, plus the file's notes."""
    objects: list[TfObject] = []
    notes: list[str] = []
    for resource_type, name, body in _json_resource_entries(
            document, artifact=artifact, notes=notes):
        address = f"{resource_type}.{name}"
        own_notes: list[str] = []
        meta: dict[str, Any] = {}
        values = _json_body(body, prefix="", address=address, notes=own_notes,
                            meta=meta)
        objects.append(_object(address, resource_type, name, values,
                               provider=meta.get("provider", ""),
                               own_notes=own_notes, artifact=artifact,
                               source=source, side=side))
        notes.extend(own_notes)
    modules = document.get("module")
    if isinstance(modules, Mapping):
        for name in modules:
            if name != COMMENT_KEY:
                notes.append(MODULE_NOTE.format(path=artifact, name=name))
    variables = document.get("variable")
    if isinstance(variables, Mapping):
        defaults = sum(1 for name, spec in variables.items()
                       if name != COMMENT_KEY and isinstance(spec, Mapping)
                       and "default" in spec)
        if defaults:
            notes.append(VARIABLE_DEFAULT_NOTE.format(path=artifact, count=defaults))
    data = document.get("data")
    if isinstance(data, Mapping):
        count = sum(len(named) for named in data.values()
                    if isinstance(named, Mapping))
        if count:
            notes.append(DATA_SOURCE_NOTE.format(path=artifact, count=count))
    return objects, notes


# -- one file -----------------------------------------------------------------


def _is_config(name: str) -> bool:
    return name.endswith(CONFIG_SUFFIXES)


def _read_one(fspath: str, *, source: str, side: str
              ) -> tuple[list[TfObject], list[str], UnparsedFile | None]:
    """Read ONE configuration file. NEVER RAISES.

    Returns ``(objects, notes, refusal or None)``. A refusal carries no objects:
    a half-read configuration file looks like a complete reading of a smaller
    configuration, which is the reading nobody declared.
    """
    if fspath.endswith(".tf.json"):
        try:
            # json.load on the BINARY handle: it decodes utf-8 itself, and a
            # file that is not utf-8 raises UnicodeDecodeError below rather
            # than arriving as mojibake nobody can tell from a value.
            with open(fspath, "rb") as handle:
                document = json.load(handle)
        except OSError as exc:
            return [], [], UnparsedFile(
                fspath, f"{hcl_lite.READ_NOTE_PREFIX}: {fspath} "
                        f"({type(exc).__name__}); nothing in it was read")
        except UnicodeDecodeError:
            return [], [], UnparsedFile(
                fspath, f"{hcl_lite.ENCODING_NOTE_PREFIX}: {fspath} is not "
                        f"decodable as utf-8, so nothing in it was read")
        except ValueError as exc:
            return [], [], UnparsedFile(
                fspath, f"{hcl_lite.SYNTAX_NOTE_PREFIX}: {fspath} is not JSON "
                        f"({type(exc).__name__}); nothing in it was read")
        if not isinstance(document, Mapping):
            return [], [], UnparsedFile(
                fspath, f"{hcl_lite.SYNTAX_NOTE_PREFIX}: {fspath} decodes to "
                        f"{safe_repr(document)} and not to a terraform JSON "
                        f"object; nothing in it was read")
        objects, notes = _json_objects(document, artifact=fspath, source=source,
                                       side=side)
        return objects, notes, None

    parsed = hcl_lite.parse_file(fspath)
    for note in parsed.notes:
        if note.startswith(_REFUSAL_PREFIXES):
            return [], [], UnparsedFile(fspath, note)
    objects, notes = _hcl_objects(parsed.body, artifact=fspath, source=source,
                                  side=side)
    return objects, list(parsed.notes) + notes, None


def _view(fspath: str, *, side: str, captured_at: str | None,
          mtime: float | None, files: Sequence[str],
          objects: Sequence[TfObject], notes: Sequence[str],
          unparsed: Sequence[UnparsedFile], ok: bool) -> HclRead:
    """Assemble one view, with the two notes every view carries."""
    stamp = captured_at if captured_at is not None else (
        _stamp(mtime) if mtime is not None else "")
    head = [DESIRED_STATE_NOTE.format(path=fspath)]
    if captured_at is None and mtime is not None:
        head.append(MTIME_NOTE.format(path=fspath, stamp=stamp))
    return HclRead(ok=ok, objects=tuple(objects), notes=tuple(head) + tuple(notes),
                   unparsed=tuple(unparsed), files=tuple(files),
                   captured_at=stamp, path=fspath, source=source_for(side),
                   side=side)


def read_file(path: str | os.PathLike[str], *, side: str,
              captured_at: str | None = None) -> HclRead:
    """Read ONE ``.tf`` or ``.tf.json`` file as ``side``. NEVER RAISES.

    ``side`` is required and is the caller's declaration of what this file is
    being read AS; see :func:`source_for`. ``captured_at`` defaults to the file's
    mtime rendered UTC-Z, with :data:`MTIME_NOTE` attached saying what that
    timestamp really is; pass it explicitly for a deterministic capture and the
    note is not emitted, because it would then be false.
    """
    source = source_for(side)
    fspath = os.fspath(path)
    try:
        mtime: float | None = os.stat(fspath).st_mtime
    except OSError:
        mtime = None
    if not _is_config(fspath):
        return _view(fspath, side=side, captured_at=captured_at, mtime=mtime,
                     files=(), objects=(),
                     notes=(NOT_CONFIG_NOTE.format(path=fspath,
                                                   suffixes=list(CONFIG_SUFFIXES)),),
                     unparsed=(), ok=False)
    objects, notes, refusal = _read_one(fspath, source=source, side=side)
    if refusal is not None:
        return _view(fspath, side=side, captured_at=captured_at, mtime=mtime,
                     files=(), objects=(), notes=(refusal.note,),
                     unparsed=(refusal,), ok=False)
    return _view(fspath, side=side, captured_at=captured_at, mtime=mtime,
                 files=(fspath,), objects=objects, notes=notes, unparsed=(),
                 ok=True)


# -- one directory, non-recursively -------------------------------------------


def config_files(path: str | os.PathLike[str]) -> tuple[str, ...]:
    """The ``.tf`` and ``.tf.json`` files in ONE directory, sorted by name.

    NON-RECURSIVE, deliberately: terraform does not recurse for a module's own
    configuration, so a subdirectory holds a DIFFERENT module. Descending into
    one would report resources this directory does not declare, silently, and a
    resource attributed to the wrong module is a resource nobody can find.

    Raises :class:`OSError` for a directory that cannot be listed; the readers
    turn that into a note.
    """
    fspath = os.fspath(path)
    return tuple(
        os.path.join(fspath, name)
        for name in sorted(os.listdir(fspath))
        if _is_config(name) and os.path.isfile(os.path.join(fspath, name))
    )


def read_dir(path: str | os.PathLike[str], *, side: str,
             captured_at: str | None = None) -> HclRead:
    """Read ONE directory of configuration as ``side``. NEVER RAISES.

    The capture time is the NEWEST file mtime in the directory, which is the
    freshest thing any file here can claim. An unreadable file costs that file
    and not the directory.
    """
    source = source_for(side)
    fspath = os.fspath(path)
    try:
        candidates = config_files(fspath)
    except OSError as exc:
        return _view(fspath, side=side, captured_at=captured_at, mtime=None,
                     files=(), objects=(),
                     notes=(f"{hcl_lite.READ_NOTE_PREFIX}: {fspath} "
                            f"({type(exc).__name__}); nothing in it was read",),
                     unparsed=(), ok=False)
    if not candidates:
        mtime = _mtime_or_none(fspath)
        return _view(fspath, side=side, captured_at=captured_at, mtime=mtime,
                     files=(), objects=(),
                     notes=(NO_TERRAFORM_NOTE.format(path=fspath),),
                     unparsed=(), ok=False)
    objects: list[TfObject] = []
    notes: list[str] = []
    unparsed: list[UnparsedFile] = []
    read: list[str] = []
    newest: float | None = None
    for candidate in candidates:
        stamp = _mtime_or_none(candidate)
        if stamp is not None:
            newest = stamp if newest is None else max(newest, stamp)
        found, file_notes, refusal = _read_one(candidate, source=source, side=side)
        if refusal is not None:
            unparsed.append(refusal)
            notes.append(refusal.note)
            continue
        read.append(candidate)
        objects.extend(found)
        notes.extend(file_notes)
    if not read:
        notes.insert(0, ALL_UNPARSED_NOTE.format(path=fspath,
                                                 count=len(candidates)))
    return _view(fspath, side=side, captured_at=captured_at, mtime=newest,
                 files=read, objects=objects, notes=notes, unparsed=unparsed,
                 ok=bool(read))


def _mtime_or_none(fspath: str) -> float | None:
    try:
        return os.stat(fspath).st_mtime
    except OSError:
        return None


# -- the config-directory contract --------------------------------------------


def parse_config_file(path: str | os.PathLike[str]
                      ) -> tuple[tuple[tuple[str, str, Mapping[str, Any]], ...],
                                 tuple[str, ...]]:
    """``((address, resource_type, values) triples, unresolved dotted paths)``
    for ONE configuration file. NEVER RAISES.

    Each unresolved path is PREFIXED WITH ITS OWNING ADDRESS, so a caller can
    name the resource a downgrade is about. A file that could not be read
    contributes one :data:`UNPARSED_PATH` instead of any triple.

    The file is read at side ``current`` because these triples describe what the
    configuration DECLARES; a caller reviewing the same file as a proposal wants
    :func:`read_file` with ``side="proposed"`` and the objects themselves.
    """
    view = read_file(path, side="current")
    return view.triples(), view.unresolved_paths()


def parse_config_dir(path: str | os.PathLike[str]
                     ) -> tuple[tuple[tuple[str, str, Mapping[str, Any]], ...],
                                tuple[str, ...]]:
    """The same pair for ONE directory, walked NON-RECURSIVELY in sorted order.

    See :func:`config_files` for why a subdirectory is not descended into. A
    per-file read failure is recorded as one unresolved path and the remaining
    files are still read: aborting the directory would turn one bad file into a
    directory that declares nothing.
    """
    view = read_dir(path, side="current")
    return view.triples(), view.unresolved_paths()
