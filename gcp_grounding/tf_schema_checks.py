"""Terraform proposals judged against the captured provider schema.

The story this check family exists for: an agent (or a hurried human) writes
``src_ranges`` where the provider spells it ``source_ranges``, or uses an
attribute that arrived in a provider newer than the one this checkout pins.
Every existing channel is silent about exactly that: the estate snapshot
enumerates ROLES and RULES, not the provider's attribute vocabulary, so the
typo sails through existence grounding and fails hours later, in CI, at
``terraform plan``. With a captured ``terraform providers schema -json`` in
hand (see :mod:`gcp_grounding.provider_schema` — the gate never runs
terraform), the same refusal happens at write time, from a file, in the same
report as the rule's ports and ranges.

- CHECK — :func:`check_provider_schema` (``DOCUMENT_CHECKS``, document-level):
  for a terraform proposal (``.tf.json`` / ``.tf`` / plan JSON — everything the
  gate assembles into the one synthetic-plan shape), every ``google_*``
  resource block's attributes and nested blocks are validated against the
  captured schema. One check family, three verdict kinds:

  ``tf_attribute``
      an attribute the schema does not know: ``ungrounded``, with an
      edit-distance did-you-mean over that resource type's REAL attribute and
      block names (:func:`gcp_grounding.reasoner.suggest` — the same
      suggestion machinery the role/permission pass uses). When nothing is
      close, the message carries the recapture guidance instead: the name may
      be real in a NEWER provider than the captured one.
  ``tf_block``
      a shape the provider cannot accept: an attribute written as a nested
      block, a block written as a plain attribute, a scalar where a list is
      declared — each ``contradicted``, because the schema positively declares
      the other shape.
  ``tf_resource_type``
      a resource type absent from the captured schema entirely:
      ``ungrounded`` with a did-you-mean over the schema's real types —
      enriching the snapshot's ``resource_types`` story wherever a schema is
      supplied.

WHAT ABSTAINS BY NAME, NEVER GUESSED (the ``unverified`` bucket, kind
``tf_attribute``/``tf_block``/``tf_schema``): a ``dynamic`` block (expanded at
plan time — what it generates is not in the configuration); a value written
under a purely-COMPUTED attribute in a configuration-derived proposal (the
provider owns that value; on a REAL plan document computed attributes are the
provider's own output riding in ``planned_values`` and are read silently); a
resource whose planned values are unreadable; a configured schema file that
will not load; a schema past the freshness ceiling (every finding demotes,
with the recapture command). What the schema CANNOT express — ``conflicts_with``,
``exactly_one_of``, server-side validation of VALUES — is named in the README's
honesty limits: the schema decides names and shapes, nothing else, and this
module never pretends otherwise. Map- and object-typed attributes get no shape
judgment either: terraform's JSON configuration encodes an object attribute and
a one-element block list identically, and a shape verdict that cannot tell them
apart would fabricate contradictions.

OFF-BY-ABSENCE. With nothing configured — no schema path, no policy, in any of
the three layers — this module is byte-silent, exactly as unconfigured
requirements are: the report only ever claims what it checked. The one LOUD
exception: a policy that was explicitly configured while no schema loads earns
a single named abstention per document ("N google_* resource block(s) were NOT
judged"), because an operator who asked for schema judgment must not receive
silence indistinguishable from a pass.

POLICY (:data:`gcp_grounding.provider_schema.SCHEMA_POLICIES`): ``block``
(default) keeps the honest statuses; ``annotate`` demotes every finding to an
``unverified`` warning carrying the same text; ``off`` ignores the captured
schema. The hook respects the same resolved policy — an ``unverified`` is
invisible in hook mode unless ``--abstain-notes`` is on, which is exactly the
hook-annotates-while-CI-blocks pattern.

NO ESTATE READS. Every decision here rests on the captured schema file and the
proposal's own text — no snapshot table is consulted, so the registry's drift
guard and evidence floor have nothing to adjudicate, and this module never
returns ``grounded``: a clean resource is silence, a finding stands on the
schema, and there is no clean bill of health to mint from an incomplete view.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Iterator, Mapping

from . import provider_schema
from .core.log import get_logger
from .core.report import Verdict
from .reasoner import suggest

logger = get_logger(__name__)

__all__ = ["DOCUMENT_CHECKS", "check_provider_schema",
           "KIND_ATTRIBUTE", "KIND_BLOCK", "KIND_RESOURCE_TYPE", "KIND_NOTE"]

#: Attribute-level verdicts: unknown names (with did-you-mean), computed-
#: attribute abstentions.
KIND_ATTRIBUTE = "tf_attribute"
#: Shape verdicts: attribute-vs-block and scalar-vs-list contradictions,
#: ``dynamic``-block abstentions.
KIND_BLOCK = "tf_block"
#: A resource type the captured schema does not define at all.
KIND_RESOURCE_TYPE = "tf_resource_type"
#: Document-level notes: the no-schema abstention, unreadable schema files,
#: the staleness note, unreadable planned values.
KIND_NOTE = "tf_schema"

# This family's finding kinds decide from the CAPTURED SCHEMA FILE and read no
# estate table, so they are registered as non-estate evidence: without this,
# `drift.adjudicate` rule 4 would rewrite every unknown-attribute `ungrounded`
# to `unverified` with a clause claiming the CURRENT-STATE VIEW could not prove
# the absence — a fabricated reason, since the current-state view never fed the
# verdict. Registered at import time, the way domain modules register estate
# soundness; a checkout without the drift module has no guard to exempt from.
try:
    from . import drift as _drift
except ImportError:                         # pragma: no cover — stripped checkout
    pass
else:
    _drift.NON_ESTATE_KINDS.update({KIND_ATTRIBUTE, KIND_BLOCK,
                                    KIND_RESOURCE_TYPE})

#: The document kind this family reads; everything else is silence.
_TF_PLAN = "tf_plan"

#: Terraform meta-arguments, legal on every resource and never in a provider
#: schema. Skipped at the resource's top level only — inside a nested block
#: they are ordinary (unknown) names.
_META_ARGUMENTS = frozenset({"count", "for_each", "provider", "depends_on",
                             "lifecycle", "provisioner", "connection"})

#: Terraform's JSON comment key, legal at every level and never an attribute.
_COMMENT_KEY = "//"

#: The ``dynamic`` block name — expanded at plan time, abstained on by name.
_DYNAMIC = "dynamic"

#: JSON scalar types. ``bool`` before ``int`` matters nowhere here because the
#: tuple is only used for isinstance.
_SCALARS = (str, int, float, bool)

#: How deep nested blocks are followed. Real provider schemas nest three or
#: four levels; the cap only bounds pathological input.
_MAX_DEPTH = 8

#: The statuses this family's POLICY tiers act on.
_FINDING_STATUSES = ("ungrounded", "contradicted")

#: The target of document-level notes that are about the CONFIGURATION rather
#: than about any one resource — the engine route grounds a parsed object whose
#: source label is ``<policy object>``, which would read as noise.
_NOTE_TARGET = "provider-schema"

#: The tail an ``annotate``-demoted finding carries — same text, warning grade.
_ANNOTATE_TAIL = (" [schema-policy 'annotate': demoted to a warning — "
                  "'terraform plan' under the captured provider would still "
                  "refuse it]")


def check_provider_schema(ctx: Any) -> list[Verdict]:
    """Every provider-schema verdict for one terraform proposal.

    Document-level rather than claim-level because the unit of judgment is the
    resource BLOCK — the whole attribute set against the whole schema — and no
    extracted claim carries a resource's full body.
    """
    if getattr(ctx, "document_kind", None) != _TF_PLAN:
        return []
    document = getattr(ctx, "document", None)
    if not isinstance(document, Mapping):
        return []
    source = str(getattr(ctx, "source", "") or "<proposal>")

    runtime = provider_schema.runtime_for(source)
    if not runtime.configured:
        return []                           # off-by-absence: byte-silent
    policy = runtime.effective_policy
    if policy not in provider_schema.SCHEMA_POLICIES:
        return [_note(_NOTE_TARGET,
                      f"the configured schema policy {policy!r} is not one of "
                      f"{list(provider_schema.SCHEMA_POLICIES)} — nothing was "
                      f"judged against the captured provider schema, and "
                      f"nothing was guessed")]
    if policy == "off":
        logger.debug("schema policy 'off' — the captured provider schema was "
                     "not consulted for %s", source)
        return []

    resources = list(_google_resources(document))
    if not resources:
        return []                           # nothing google-shaped to judge

    verdicts: list[Verdict] = []
    schemas: list[provider_schema.ProviderSchema] = []
    for path in runtime.paths:
        schema, problems = provider_schema.load_cached(path)
        for problem in problems:
            verdicts.append(_note(path, f"{problem} — the proposal was NOT "
                                        f"judged against it"))
        if schema is not None:
            schemas.append(schema)
    if not schemas:
        verdicts.append(_no_schema(runtime, len(resources)))
        return verdicts

    stale = ""
    for schema in schemas:
        reason = provider_schema.staleness(schema, runtime)
        if reason:
            verdicts.append(_note(schema.path, reason))
            stale = stale or reason

    #: Configuration-derived proposals (the synthetic plan the gate assembles
    #: from .tf/.tf.json) carry only what the AUTHOR wrote; a real
    #: `terraform show -json` plan also carries the provider's own computed
    #: output, which must not be read as the author writing a computed
    #: attribute.
    config_route = ("resource_changes" not in document
                    and "terraform_version" not in document)

    findings: list[Verdict] = []
    for address, rtype, values in resources:
        blocks = _blocks_for(schemas, rtype)
        if not blocks:
            findings.append(_unknown_type(address, rtype, schemas))
            continue
        if not isinstance(values, Mapping):
            verdicts.append(_note(address,
                                  f"{address}: this resource has no readable "
                                  f"planned values — its attributes were NOT "
                                  f"judged against the captured provider "
                                  f"schema"))
            continue
        _check_body(findings, address, rtype, values,
                    [block for _address, block in blocks], schemas,
                    depth=0, top=True, config_route=config_route)

    verdicts.extend(_apply_policy(findings, policy, stale))
    return verdicts


# -- one body against one (merged) block schema --------------------------------


def _check_body(out: list[Verdict], path: str, rtype: str,
                body: Mapping[str, Any], blocks: list[Mapping[str, Any]],
                schemas: list, *, depth: int, top: bool,
                config_route: bool) -> None:
    if depth > _MAX_DEPTH:
        out.append(_note(path, f"{path}: nesting deeper than {_MAX_DEPTH} "
                               f"levels was not followed — nothing below it "
                               f"was judged"))
        return
    for key, value in body.items():
        name = str(key)
        if name == _COMMENT_KEY or (top and name in _META_ARGUMENTS):
            continue
        if name == _DYNAMIC:
            out.append(Verdict(
                "unverified", KIND_BLOCK, path, 0,
                f"{path}: 'dynamic' block(s) are expanded at plan time — "
                f"which blocks they generate is not decided from the "
                f"configuration, so they were not judged against the captured "
                f"schema; gate the rendered plan for full coverage"))
            continue
        specs = [table[name] for block in blocks
                 if isinstance(table := block.get("attributes"), Mapping)
                 and isinstance(table.get(name), Mapping)]
        if specs:
            _check_attribute(out, path, rtype, name, value, specs,
                             config_route=config_route)
            continue
        nested = [entry for block in blocks
                  if isinstance(table := block.get("block_types"), Mapping)
                  and isinstance(entry := table.get(name), Mapping)]
        if nested:
            _check_block(out, path, rtype, name, value, nested, schemas,
                         depth=depth, config_route=config_route)
            continue
        out.append(_unknown_attribute(path, rtype, name, blocks, schemas))


def _check_attribute(out: list[Verdict], path: str, rtype: str, name: str,
                     value: Any, specs: list[Mapping[str, Any]], *,
                     config_route: bool) -> None:
    if value is None:
        return                              # null is "unset", never a shape
    if config_route and all(_computed_only(spec) for spec in specs):
        out.append(Verdict(
            "unverified", KIND_ATTRIBUTE, f"{rtype}.{name}", 0,
            f"{path}.{name}: '{name}' is a COMPUTED attribute of {rtype} — "
            f"the provider computes its value, so a value written in the "
            f"configuration was not judged against the schema (terraform "
            f"itself will refuse to configure it)"))
        return
    # The shape verdict must hold for EVERY supplied provider's declaration:
    # if any provider declares a type this value fits, the value may be meant
    # for that provider, and a finding would be a guess about which one
    # actuates.
    findings = [_shape_finding(path, rtype, name, value, spec.get("type"))
                for spec in specs]
    if all(finding is not None for finding in findings):
        out.append(findings[0])


def _check_block(out: list[Verdict], path: str, rtype: str, name: str,
                 value: Any, nested: list[Mapping[str, Any]], schemas: list, *,
                 depth: int, config_route: bool) -> None:
    if value is None:
        return
    if isinstance(value, _SCALARS):
        modes = sorted({mode if isinstance(mode := entry.get("nesting_mode"),
                                           str) and mode else "?"
                        for entry in nested})
        out.append(Verdict(
            "contradicted", KIND_BLOCK, f"{rtype}.{name}", 0,
            f"{path}.{name}: written as a plain attribute value "
            f"({type(value).__name__}), but the captured schema declares "
            f"'{name}' as a nested BLOCK of {rtype} (nesting mode "
            f"{'/'.join(modes)}) — the provider cannot accept a scalar here"))
        return
    inner = [block for entry in nested
             if isinstance(block := entry.get("block"), Mapping)]
    if not inner:
        return                              # a block schema with no body: skip
    # The shape is read EXPLICITLY, and an entry that is not an object earns a
    # named abstention rather than a silent skip: a wrong-shaped block entry
    # laundered into "no blocks" would be exactly the zero-finding clean pass
    # the evidence lint forbids.
    if isinstance(value, Mapping):
        entries: list[tuple[Mapping[str, Any], str]] = [(value, name)]
    elif isinstance(value, list):
        entries = []
        for index, item in enumerate(value):
            if isinstance(item, Mapping):
                entries.append((item, f"{name}[{index}]"))
            else:
                out.append(_note(
                    f"{rtype}.{name}",
                    f"{path}.{name}[{index}]: this nested-block entry is not "
                    f"an object ({type(item).__name__}) — it was NOT judged "
                    f"against the captured schema"))
    else:
        out.append(_note(
            f"{rtype}.{name}",
            f"{path}.{name}: this nested block's value could not be read "
            f"({type(value).__name__}) — it was NOT judged against the "
            f"captured schema"))
        return
    for item, fragment in entries:
        _check_body(out, f"{path}.{fragment}", rtype, item, inner, schemas,
                    depth=depth + 1, top=False, config_route=config_route)


# -- shape ---------------------------------------------------------------------


def _computed_only(spec: Mapping[str, Any]) -> bool:
    """Whether an attribute is PURELY computed: the provider sets it and the
    configuration may not."""
    return bool(spec.get("computed")) and not spec.get("optional") \
        and not spec.get("required")


def _shape_finding(path: str, rtype: str, name: str, value: Any,
                   declared: Any) -> Verdict | None:
    """A ``contradicted`` when *value*'s shape provably cannot satisfy the
    declared type, else ``None``. Conservative on purpose: map- and
    object-typed attributes are never judged (the JSON configuration encodes
    them like blocks), and an unrecognized type expression judges nothing."""
    if isinstance(declared, str):
        if declared not in ("string", "number", "bool"):
            return None                     # 'dynamic' or something newer
        if isinstance(value, Mapping) or (
                isinstance(value, list)
                and any(isinstance(item, Mapping) for item in value)):
            return Verdict(
                "contradicted", KIND_BLOCK, f"{rtype}.{name}", 0,
                f"{path}.{name}: written as a nested block, but the captured "
                f"schema declares '{name}' as a plain attribute of {rtype} "
                f"with type {declared} — the provider cannot accept a block "
                f"here")
        if isinstance(value, list):
            return Verdict(
                "contradicted", KIND_BLOCK, f"{rtype}.{name}", 0,
                f"{path}.{name}: a LIST where the captured schema declares a "
                f"single {declared} for '{name}' of {rtype}")
        return None
    if isinstance(declared, list) and declared:
        mode = declared[0]
        if mode not in ("list", "set"):
            return None                     # map/object: the encoding is
        if isinstance(value, _SCALARS):     # ambiguous, judge nothing
            return Verdict(
                "contradicted", KIND_BLOCK, f"{rtype}.{name}", 0,
                f"{path}.{name}: a SCALAR ({type(value).__name__}) where the "
                f"captured schema declares {_render_type(declared)} for "
                f"'{name}' of {rtype} — the provider expects a list")
        element = declared[1] if len(declared) == 2 else None
        if element in ("string", "number", "bool") and (
                isinstance(value, Mapping)
                or (isinstance(value, list)
                    and any(isinstance(item, Mapping) for item in value))):
            return Verdict(
                "contradicted", KIND_BLOCK, f"{rtype}.{name}", 0,
                f"{path}.{name}: written as a nested block, but the captured "
                f"schema declares '{name}' as a plain attribute of {rtype} "
                f"with type {_render_type(declared)} — the provider cannot "
                f"accept a block here")
        return None
    return None


def _render_type(declared: Any) -> str:
    """A terraform type expression as humans spell it: ``set(string)``."""
    if isinstance(declared, str):
        return declared
    if isinstance(declared, list) and declared:
        head = str(declared[0])
        if len(declared) == 2:
            return f"{head}({_render_type(declared[1])})"
        return head
    return "?"


# -- the findings' vocabulary ---------------------------------------------------


def _unknown_attribute(path: str, rtype: str, name: str,
                       blocks: list[Mapping[str, Any]],
                       schemas: list) -> Verdict:
    candidates = sorted(_declared_names(blocks))
    suggestions = suggest(name, candidates)
    message = (f"{path}: '{name}' is not an attribute or nested block of "
               f"{rtype} in the captured provider schema"
               f"{_version_clause(schemas)} — 'terraform plan' under the "
               f"provider this schema was captured from would refuse it")
    if not suggestions:
        message += (f"; if '{name}' arrived in a provider NEWER than the "
                    f"captured schema, recapture it where terraform init has "
                    f"run ({provider_schema.CAPTURE_COMMAND}) and re-judge")
    return Verdict("ungrounded", KIND_ATTRIBUTE, f"{rtype}.{name}", 0, message,
                   suggestions=suggestions)


def _unknown_type(address: str, rtype: str, schemas: list) -> Verdict:
    """A type absent from the capture ABSTAINS — it is never provably fake.

    A schema capture is complete per PROVIDER, but the estate may actuate
    through providers nobody captured (google-beta beside google), and a
    type's provider membership cannot be read off its name. Blocking here
    would let a partial capture prove an absence it never enumerated — the
    exact fabrication the four-bucket contract forbids. Attributes are the
    opposite case: once a type IS found in a captured provider, that
    provider's enumeration of its attributes is complete, so an unknown
    attribute stays ungrounded."""
    known: set[str] = set()
    for schema in schemas:
        known.update(schema.resource_types())
    suggestions = suggest(rtype, sorted(known))
    message = (f"{address}: resource type '{rtype}' is not defined by the "
               f"captured provider schema ({_providers_label(schemas)}"
               f"{_version_clause(schemas)}) — under the captured provider(s) "
               f"'terraform plan' would refuse it, but it may belong to a "
               f"provider that was not captured; its attributes were NOT "
               f"judged")
    if not suggestions:
        message += (f"; if it belongs to another or a newer provider, capture "
                    f"that provider too ({provider_schema.CAPTURE_COMMAND})")
    return Verdict("unverified", KIND_RESOURCE_TYPE, rtype, 0, message,
                   suggestions=suggestions)


def _no_schema(runtime: provider_schema.Runtime, count: int) -> Verdict:
    if runtime.paths:
        why = "no configured provider schema could be read"
    else:
        why = (f"a schema policy is configured "
               f"('{runtime.effective_policy}') but NO provider schema is "
               f"supplied")
    return _note(_NOTE_TARGET, (
        f"{why} — {count} google_* resource block(s) were NOT judged against "
        f"any provider schema. Capture one, locally and credential-free, "
        f"where terraform init has already run "
        f"({provider_schema.CAPTURE_COMMAND}), then name it with "
        f"--provider-schema, ${provider_schema.PROVIDER_SCHEMA_ENV} or the "
        f"'provider_schema' key in .gcp-grounding.json"))


def _note(target: str, message: str) -> Verdict:
    return Verdict("unverified", KIND_NOTE, target, 0, message)


def _declared_names(blocks: list[Mapping[str, Any]]) -> set[str]:
    names: set[str] = set()
    for block in blocks:
        for table_name in ("attributes", "block_types"):
            table = block.get(table_name)
            if isinstance(table, Mapping):
                names.update(map(str, table))
    return names


def _blocks_for(schemas: list, rtype: str) -> list[tuple[str, Mapping[str, Any]]]:
    """Every supplied provider's block for *rtype*, ``(address, block)``,
    schemas in configured order and addresses sorted within each — the UNION a
    check consults, because the gate cannot always know which provider
    actuates a block and a finding must hold under every candidate."""
    merged: list[tuple[str, Mapping[str, Any]]] = []
    seen: set[str] = set()
    for schema in schemas:
        for address, block in sorted(schema.blocks_for(rtype).items()):
            if address not in seen:
                seen.add(address)
                merged.append((address, block))
    return merged


def _providers_label(schemas: list) -> str:
    addresses: list[str] = []
    for schema in schemas:
        for address in schema.providers:
            if address not in addresses:
                addresses.append(address)
    return ", ".join(address.rsplit("/", 1)[-1] for address in addresses) \
        or "no provider"


def _version_clause(schemas: list) -> str:
    """``", captured at google 6.8.0"`` where a version was truly recorded —
    and NOTHING where it was not: the raw capture names no version, and this
    clause never invents one."""
    labels = [label for schema in schemas if (label := schema.version_label())]
    return f", provider version {'; '.join(labels)}" if labels else ""


# -- policy and staleness -------------------------------------------------------


def _apply_policy(findings: list[Verdict], policy: str,
                  stale: str) -> list[Verdict]:
    """The findings as the run's policy and the schema's freshness permit them
    to be stated. ``block`` keeps the honest statuses; a STALE schema demotes
    every finding whatever the policy — a vocabulary nobody recaptured cannot
    block — and ``annotate`` demotes with its own tail."""
    if not findings:
        return []
    out: list[Verdict] = []
    for verdict in findings:
        if verdict.status not in _FINDING_STATUSES:
            out.append(verdict)
        elif stale:
            out.append(replace(
                verdict, status="unverified",
                message=verdict.message + f"  [not decided: {stale}]"))
        elif policy == "annotate":
            out.append(replace(verdict, status="unverified",
                               message=verdict.message + _ANNOTATE_TAIL))
        else:
            out.append(verdict)
    return out


# -- plan walking ---------------------------------------------------------------


def _google_resources(document: Mapping[str, Any]
                      ) -> Iterator[tuple[str, str, Any]]:
    """(address, type, planned values) — through ``tf_claims``' OWN plan
    walker, resolved lazily so a checkout without the terraform extractor
    keeps this check silent instead of broken (the same degradation as
    :func:`gcp_grounding.preflight._tf_plan_extractor`)."""
    try:
        from . import tf_claims
    except ImportError:
        logger.debug("tf_claims is not part of this checkout — the schema "
                     "check has no plan walker and stays silent")
        return
    yield from tf_claims._google_resources(document)


#: Registry hook consulted by :mod:`gcp_grounding.preflight` — see
#: :mod:`gcp_grounding.registry`.
DOCUMENT_CHECKS = (check_provider_schema,)
