"""IAM, org policy, VPC Service Controls and the resource hierarchy: terraform
objects to estate RECORDS.

Same contract as :mod:`gcp_grounding.tfsource.map_network`. This module emits
``sx-kb-estate-tables`` RECORDS and nothing else: there is no second,
REST-shaped document form for these domains, because the estate record schema
IS the canonical shape and the per-target document a pair check wants is a
projection of it. A second shape is a second place for the same policy to be
spelled, and two spellings of one policy never compare equal.

It imports :mod:`gcp_grounding.facts`, :mod:`gcp_grounding.identity` and this
package's :mod:`~gcp_grounding.tfsource.mapping` and
:mod:`~gcp_grounding.tfsource.normalize` — never
:mod:`gcp_grounding.knowledge`, which is the layering rule ``tfsource`` obeys in
one direction only.

THE AUTHORITATIVENESS NOTE
--------------------------

:data:`AUTHORITATIVENESS_NOTE` rides on EVERY ``iam_bindings`` fact this module
emits, because the three provider spellings have three different authorities and
only one of them describes a whole policy:

- ``google_*_iam_policy`` is authoritative for the WHOLE resource;
- ``google_*_iam_binding`` is authoritative for ONE role;
- ``google_*_iam_member`` is purely ADDITIVE — it names one member of one role
  and says nothing about the rest.

So a capture that saw only ``_iam_member`` resources holds a strict SUBSET of
the real policy. That is what makes ``iam_bindings`` one of the two categories
whose terraform ABSENCE is never authoritative, and it is what triggers the
engine's partial-baseline downgrade. The note travels on the fact so the ledger
can say it out loud instead of a reader having to know it.

``google_project_iam_policy`` COVERAGE FROM RAW HCL IS EFFECTIVELY ZERO
----------------------------------------------------------------------

:func:`_iam_policy` parses ``policy_data`` with :func:`json.loads` and emits NO
fact plus one note when the attribute is not a string, is a heredoc-mangled
string, or is not valid JSON. In real configuration ``policy_data`` is almost
always ``data.google_iam_policy.x.policy_data`` (an interpolation a static
reader resolves to an :class:`~gcp_grounding.facts.Unresolved`) or a heredoc, so
from raw HCL this resource contributes nothing far more often than it
contributes a policy. It must not be advertised otherwise: an unread
``_iam_policy`` is a policy whose bindings are MISSING from the capture, never
an empty one.

THE DRY-RUN DECISION (org policy)
---------------------------------

``dry_run_spec`` is NEVER folded into ``rules``. A dry-run policy is not
enforced, and reading it as enforcement would report an estate that blocks
something it does not. Silently ignoring it is defensible; silently treating it
as enforced is not — so its presence rides on the fact as
:data:`DRY_RUN_NOTE` and its content is not read.

The legacy ``google_project_organization_policy`` is translated from
``boolean_policy`` and ``list_policy``, and a ``restore_policy`` makes the
record's rules UNRESOLVED rather than flattening to an empty rule set: an empty
rule set reads as "no restriction", which is the opposite of what a restore
means.

VPC SERVICE CONTROLS: THE NAMING IS GENUINELY COUNTERINTUITIVE
--------------------------------------------------------------

A perimeter's ``status`` block is the ENFORCED configuration and its ``spec``
block is the DRY-RUN configuration. Nothing here conflates them in either
direction: the sibling ``_resource``, ``_ingress_policy`` and ``_egress_policy``
resources emit fragments onto ``status``, the ``_dry_run_`` variants onto
``spec``, and the ``restricted_services`` and ``access_levels`` side facts are
derived from the ENFORCED ``status`` only. Reading a ``spec`` as enforcement
would let a dry-run perimeter read as a perimeter that protects the estate.

Perimeter ``resources`` are kept in the project-NUMBER form terraform and the
API both write; the hierarchy-names alias reconciles them at merge time, and
resolving a number here would key one project's perimeter onto another's row.

FRAGMENTS
---------

The IAM resources and the perimeter siblings emit FRAGMENT facts — a fact
carrying only the record field it speaks for, named by ``Fact.fragment`` — which
``merge``'s fragment assembly turns into one record per target, ordering by
priority then address, collapsing exact duplicates and (for ``iam_bindings``)
merging bindings of the same role and identical condition with their members
sorted. There is no bespoke cross-resource aggregator here: fragment assembly is
the general mechanism for exactly this shape, and a second implementation of it
would be a second place for the assembly order to be wrong.

WHAT A REFUSAL LOOKS LIKE
-------------------------

Any target that fails key resolution produces NO fact and one note naming the
address — never a fact under a guessed key, because a key built from an assumed
project is a confident answer about a resource in some other project. Those
notes come back on :class:`Mapped`, which is what :func:`map_one` returns; the
registry's ``map(obj, ctx) -> Sequence[Fact]`` contract has no per-object note
channel, so a refusal is additionally logged rather than being silently dropped.
"""

from __future__ import annotations

import functools
import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from .. import facts
from ..core.log import get_logger
from . import mapping, normalize

logger = get_logger(__name__)

__all__ = [
    "AUTHORITATIVENESS_NOTE",
    "DRY_RUN_NOTE",
    "DELIBERATELY_UNMAPPED",
    "IAM_FAMILIES",
    "PERIMETER_FRAGMENTS",
    "SERVICE_ACCOUNT_HOST",
    "Mapped",
    "map_one",
    "register_all",
]

#: On EVERY ``iam_bindings`` fact. See the module docstring: the three provider
#: spellings have three different authorities, and the additive one makes a
#: terraform-only capture a strict SUBSET of the real policy.
AUTHORITATIVENESS_NOTE = (
    "terraform's IAM view is NOT authoritative and its absence never proves an "
    "absence: a *_iam_policy resource speaks for the WHOLE resource, a "
    "*_iam_binding for ONE role, and a *_iam_member is purely ADDITIVE, so a "
    "capture that saw only _iam_member resources holds a strict SUBSET of the "
    "real policy — which is what downgrades the baseline to partial")

#: On an org-policy fact whose object carries a ``dry_run_spec``.
DRY_RUN_NOTE = (
    "dry_run_spec is present on this policy and is deliberately NOT read: a "
    "dry-run policy is not enforced, and folding it into 'rules' would report "
    "an estate that enforces something it does not")

#: The host of a service-account IAM target's full resource name — the spelling
#: ``identity.iam_bindings`` stores and ``tests/test_gcp_identity.py`` pins.
SERVICE_ACCOUNT_HOST = "iam.googleapis.com"

#: The IAM resource families this module claims, and the attribute each one
#: names its target with. A family absent from this table is not mapped: its
#: full resource name would have to be guessed, and a key built on a guessed
#: spelling never matches — the miss then reads as an absence.
IAM_FAMILIES = {
    "google_project_iam": "project",
    "google_folder_iam": "folder",
    "google_organization_iam": "org_id",
    "google_service_account_iam": "service_account_id",
}

#: Which perimeter side each sibling resource speaks for, and the field it
#: contributes. ``status`` is ENFORCED and ``spec`` is DRY-RUN; the ``dry_run_``
#: spellings land on ``spec`` and NOTHING else does.
PERIMETER_FRAGMENTS = {
    "google_access_context_manager_service_perimeter_resource":
        ("status", "resources"),
    "google_access_context_manager_service_perimeter_dry_run_resource":
        ("spec", "resources"),
    "google_access_context_manager_service_perimeter_ingress_policy":
        ("status", "ingress_policies"),
    "google_access_context_manager_service_perimeter_dry_run_ingress_policy":
        ("spec", "ingress_policies"),
    "google_access_context_manager_service_perimeter_egress_policy":
        ("status", "egress_policies"),
    "google_access_context_manager_service_perimeter_dry_run_egress_policy":
        ("spec", "egress_policies"),
}

#: Policy-domain terraform types this module knowingly does NOT model, and why.
#: Merged into :data:`gcp_grounding.tfsource.mapping.DELIBERATELY_UNMAPPED` at
#: import time, because that is the table :func:`~gcp_grounding.tfsource.mapping.map_objects`
#: consults: a type named here reads as a STATED gap, while a type nobody has
#: considered is counted by the census note.
DELIBERATELY_UNMAPPED = {
    "google_project_iam_audit_config": (
        "audit logging configuration is not one of the estate categories: "
        "iam_bindings holds bindings, and reading an audit config as one would "
        "invent members nobody was granted"),
    "google_org_policy_custom_constraint": (
        "a custom constraint is a constraint DEFINITION, and 'constraints' is "
        "deliberately outside TF_CATEGORIES — the definition vocabulary is the "
        "platform's, so a terraform capture is never the population"),
    "google_access_context_manager_access_policy": (
        "the access policy is the CONTAINER the estate keys access levels and "
        "perimeters by, not a category of its own, and its numeric id is "
        "generated at apply time"),
    "google_iam_workload_identity_pool": (
        "a pool mints principals, and 'principals' is deliberately outside "
        "TF_CATEGORIES: identities are created outside terraform, so a capture "
        "is never the population"),
    "google_storage_bucket_iam_binding": (
        "a bucket's IAM policy IS an estate category, but its full resource "
        "name has two spellings in Google's own surfaces "
        "('//storage.googleapis.com/<bucket>' in asset inventory, "
        "'projects/_/buckets/<bucket>' in the IAM API) and identity.py has no "
        "rule that picks one; a key on the wrong spelling never matches"),
}
DELIBERATELY_UNMAPPED["google_storage_bucket_iam_member"] = (
    DELIBERATELY_UNMAPPED["google_storage_bucket_iam_binding"])
DELIBERATELY_UNMAPPED["google_storage_bucket_iam_policy"] = (
    DELIBERATELY_UNMAPPED["google_storage_bucket_iam_binding"])

#: Attributes the provider spells as ONE nested block and the API stores as an
#: OBJECT. Every reader hands blocks over as LISTS (the plan-JSON encoding), so
#: these are unwrapped to the object the estate stores and an EMPTY list means
#: the block is absent, not an empty one. Everything else keeps its list shape,
#: because a repeated block is a list on both sides.
_SINGLE_BLOCKS = frozenset({
    "status", "spec", "egress_from", "egress_to", "ingress_from", "ingress_to",
    "vpc_accessible_services", "condition",
})

#: The fields an ingress/egress policy entry carries, in the API's own shape.
_INGRESS_FIELDS = ("ingress_from", "ingress_to")
_EGRESS_FIELDS = ("egress_from", "egress_to")


# -- the result ---------------------------------------------------------------


@dataclass(frozen=True)
class Mapped:
    """What one object produced: its facts, and the notes that explain what it
    did NOT produce.

    The registry's contract is ``map(obj, ctx) -> Sequence[Fact]``, so the
    ``notes`` half is visible to a caller of :func:`map_one` and to the log, and
    a registered mapper hands the registry the ``facts`` half. One
    implementation, two views — a second entry point with its own logic would be
    a second answer for one object.
    """

    facts: tuple[facts.Fact, ...] = ()
    notes: tuple[str, ...] = ()


# -- shared helpers -----------------------------------------------------------


def _values(obj: Any) -> Mapping[str, Any]:
    return obj.values if isinstance(obj.values, Mapping) else {}


def _attribute(values: Mapping[str, Any], name: str, fallback: Any = "") -> Any:
    """One attribute, or ``fallback`` when the artifact does not carry one.

    An :class:`~gcp_grounding.facts.Unresolved` is returned UNCHANGED: ignorance
    in the artifact is never replaced by a workspace default, because a default
    substituted for an unknown is a confident answer about the wrong resource.
    An empty string counts as absent — that is how a v4 state spells an
    unset ``org_id``.
    """
    value = values.get(name)
    if value is None or (isinstance(value, str) and not value.strip()):
        return fallback
    return value


def _blocks(values: Any, name: str) -> tuple[Mapping[str, Any], ...]:
    """One repeated block as a tuple of objects.

    Never truth-tests its input: a marker in the block position yields an empty
    tuple here and is picked up by :func:`_markers` instead, so an unresolved
    block is recorded rather than read as an absent one.
    """
    if not isinstance(values, Mapping):
        return ()
    block = values.get(name)
    if isinstance(block, Mapping):          # a reader that already unwrapped it
        return (block,)
    if isinstance(block, (list, tuple)):
        return tuple(item for item in block if isinstance(item, Mapping))
    return ()


def _members_of(block: Any, name: str) -> tuple[Any, ...]:
    """One list-valued attribute as a tuple, and ``()`` for anything else —
    including a marker, which :func:`_markers` reports separately."""
    if not isinstance(block, Mapping):
        return ()
    value = block.get(name)
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return ()


def _markers(*values: Any) -> tuple[facts.Unresolved, ...]:
    """Every marker anywhere in ``values``, de-duplicated, in walk order. Rolled
    onto the fact so an attribute this mapper could not resolve is visible on
    the fact it belongs to rather than only inside the record."""
    out: list[facts.Unresolved] = []
    for value in values:
        for _path, marker in facts.unresolved_in(value):
            if marker not in out:
                out.append(marker)
    return tuple(out)


def _fact(obj: Any, category: str, key: str, record: Any = None, *,
          fragment: str = "", notes: Sequence[str] = ()) -> facts.Fact:
    """One fact, with this object's provenance and its unresolved roll-up."""
    return facts.Fact(category=category, key=key, record=record,
                      source=obj.source, side=obj.side, origin=obj.artifact,
                      address=obj.address, fragment=fragment,
                      unresolved=_markers(record), notes=tuple(notes))


def _refusal(obj: Any, category: str, marker: Any, what: str) -> str:
    """The note a refusal leaves behind, naming the address. A refusal that left
    nothing behind would look exactly like a resource that had nothing to say."""
    reason = marker.reason if facts.is_unresolved(marker) else "ambiguous_key"
    note = (f"{obj.address} ({obj.type}): no {category} fact — {what} "
            f"[{reason}]; this is a MISSING record, never an empty one")
    logger.debug("%s", note)
    return note


def _block_shape(value: Any, name: str = "") -> Any:
    """A block tree in the shape the estate stores: single blocks unwrapped to
    objects, repeated blocks kept as tuples, markers passed through.

    The plan-JSON encoding every reader produces renders EVERY block as a list,
    so ``status = [{...}]`` and ``egress_from = [{...}]`` have to be unwrapped
    or the record would carry a one-element list where the API carries an
    object — two spellings of one perimeter, which never compare equal.
    """
    if facts.is_unresolved(value):
        return value
    if isinstance(value, Mapping):
        return {key: _block_shape(item, key) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        items = [_block_shape(item, name) for item in value]
        if name in _SINGLE_BLOCKS:
            # An EMPTY single block means the block is absent (that is how a v4
            # state spells "no spec"), and absent is None, not [].
            return items[0] if items else None
        return tuple(items)
    return value


def _condition(block: Any) -> Any:
    """One IAM / org-policy condition as the object the estate stores, or
    ``None`` when the block is absent."""
    conditions = _blocks(block, "condition")
    if not conditions:
        return None
    return _block_shape(dict(conditions[0]))


def _tri_bool(value: Any, *, path: str) -> Any:
    """A boolean, ``None`` for an attribute the provider left null, or a marker.

    ``None`` is a VALUE here and not ignorance: the org-policy rule schema
    spells "this rule says nothing about enforcement" as a null ``enforce``, and
    the estate stores that null.
    """
    if value is None:
        return None
    return normalize.bool_or(value, path=path)


def _flag(block: Any, name: str, *, path: str) -> Any:
    """One of the two org-policy FLAGS, which are false when unset.

    Unlike :func:`_tri_bool` this reads an absent or null value as ``False``,
    because the org-policy API defines both flags that way and
    ``knowledge.GcpSnapshot`` reads them the same way — a null here is the
    schema's own default and not a value nobody wrote.
    """
    value = block.get(name) if isinstance(block, Mapping) else None
    if value is None:
        return False
    return normalize.bool_or(value, path=path)


def _principals(value: Any, *, path: str) -> Any:
    """A member list, canonicalised and SORTED, or one marker for the whole
    list.

    ALL-OR-NOTHING for :func:`gcp_grounding.tfsource.normalize.cidrs`' reason: a
    member list with one entry quietly dropped describes a policy that grants
    less than it grants. Sorted because ``members`` is a terraform TypeSet whose
    array order is hash-determined and changes between applies, so the same
    binding captured twice would otherwise not be byte-identical.
    """
    members = normalize.string_list(value, path=path)
    if facts.is_unresolved(members):
        return members
    out: list[str] = []
    for index, member in enumerate(members):
        principal = normalize.principal(member, path=f"{path}[{index}]")
        if facts.is_unresolved(principal):
            return principal
        out.append(principal)
    return tuple(sorted(set(out)))


def _binding(role: Any, members: Any, condition: Any) -> dict[str, Any]:
    """One binding in the estate's own shape: role, members, condition."""
    return {"condition": condition, "members": members, "role": role}


def _supplied(value: Any) -> Any:
    """A key part as :meth:`~gcp_grounding.tfsource.mapping.MapContext.key`
    wants it: ``None`` for NOT SUPPLIED, the value — or its marker — otherwise.

    Never truth-tests, because an :class:`~gcp_grounding.facts.Unresolved`
    refuses truthiness by design and ``value or None`` on one is a crash inside
    a mapper rather than the honest abstention the marker exists to carry.
    """
    if isinstance(value, str) and not value.strip():
        return None
    return value


# -- IAM ----------------------------------------------------------------------


def _iam_family(resource_type: str) -> str:
    for prefix, attribute in IAM_FAMILIES.items():
        if resource_type.startswith(f"{prefix}_"):
            return attribute
    return ""


def _hierarchy_target(value: Any, kind: str, *, path: str) -> Any:
    """``folders/2`` / ``organizations/1`` from either spelling the provider
    accepts (the bare id or the qualified node), or a marker."""
    text = normalize.strip_self_link(value, path=path)
    if facts.is_unresolved(text):
        return text
    segments = text.split("/")
    if len(segments) == 2 and segments[0] == kind and segments[1]:
        return text
    if len(segments) == 1 and segments[0]:
        return f"{kind}/{segments[0]}"
    return facts.Unresolved("ambiguous_key", path,
                            f"{facts.safe_repr(text)} does not name one {kind} node")


def _iam_target(obj: Any, ctx: Any) -> Any:
    """The full-resource-name INPUT for this IAM resource's ``iam_bindings``
    key, or a marker. The key itself is built by
    :meth:`gcp_grounding.tfsource.mapping.MapContext.key`, which is the only
    place an estate key is ever built."""
    values = _values(obj)
    attribute = _iam_family(obj.type)
    path = f"{obj.address}.{attribute or 'target'}"
    if attribute == "project":
        raw = _attribute(values, "project", ctx.project)
        ident = normalize.project_of(raw, path=path)
        if facts.is_unresolved(ident):
            return ident
        return f"projects/{ident}"
    if attribute == "folder":
        return _hierarchy_target(_attribute(values, "folder", ctx.folder),
                                 "folders", path=path)
    if attribute == "org_id":
        return _hierarchy_target(_attribute(values, "org_id", ctx.organization),
                                 "organizations", path=path)
    if attribute == "service_account_id":
        text = normalize.strip_self_link(_attribute(values, "service_account_id"),
                                         path=path)
        if facts.is_unresolved(text):
            return text
        if "/serviceAccounts/" not in text:
            # A bare email names no project, and a service account may live in
            # any project — filling in the workspace's would key one account's
            # policy onto another project's resource.
            return facts.Unresolved(
                "ambiguous_key", path,
                "a service-account IAM target is "
                "'projects/<p>/serviceAccounts/<email>'; a bare email names no "
                "project and one must not be assumed")
        return f"//{SERVICE_ACCOUNT_HOST}/{text}"
    return facts.Unresolved("ambiguous_key", path,
                            f"{obj.type} is not one of the IAM families this "
                            f"module claims")


def _iam_fact(obj: Any, ctx: Any, bindings: Sequence[Mapping[str, Any]]) -> Mapped:
    """The shared tail of the three IAM spellings: one FRAGMENT fact carrying
    only the ``bindings`` this resource speaks for, under the target's canonical
    key, with the authoritativeness note on it."""
    target = _iam_target(obj, ctx)
    key = ctx.key("iam_bindings", name=target, path=obj.address)
    if facts.is_unresolved(key):
        return Mapped((), (_refusal(obj, "iam_bindings", key,
                                    "the target could not be resolved to a full "
                                    "resource name"),))
    record = {"bindings": tuple(bindings)}
    return Mapped((_fact(obj, "iam_bindings", key, record, fragment="bindings",
                         notes=(AUTHORITATIVENESS_NOTE,)),))


def _iam_binding(obj: Any, ctx: Any) -> Mapped:
    """``google_*_iam_binding`` — authoritative for ONE role on the target."""
    values = _values(obj)
    members = _principals(_members_of(values, "members"),
                          path=f"{obj.address}.members")
    return _iam_fact(obj, ctx, (_binding(_attribute(values, "role", None), members,
                                         _condition(values)),))


def _iam_member(obj: Any, ctx: Any) -> Mapped:
    """``google_*_iam_member`` — purely ADDITIVE: one member of one role, and
    silent about every other member of it."""
    values = _values(obj)
    members = _principals([_attribute(values, "member", None)]
                          if "member" in values else (),
                          path=f"{obj.address}.member")
    return _iam_fact(obj, ctx, (_binding(_attribute(values, "role", None), members,
                                         _condition(values)),))


def _iam_policy(obj: Any, ctx: Any) -> Mapped:
    """``google_*_iam_policy`` — authoritative for the WHOLE resource, and
    readable only when ``policy_data`` is literal JSON.

    See the module docstring: from raw HCL that attribute is almost always an
    interpolation or a heredoc, so this resource's coverage there is effectively
    zero. Every unreadable spelling produces NO fact and one note, because an
    unread policy is a policy whose bindings are MISSING and never an empty set.
    """
    values = _values(obj)
    raw = values.get("policy_data")
    if facts.is_unresolved(raw):
        return Mapped((), (_refusal(obj, "iam_bindings", raw,
                                    "policy_data could not be resolved to a "
                                    "literal, so no binding can be read from it"),))
    if not isinstance(raw, str):
        return Mapped((), (_refusal(
            obj, "iam_bindings", None,
            f"policy_data is {facts.safe_repr(raw)}, not a JSON string"),))
    try:
        document = json.loads(raw)
    except ValueError:
        return Mapped((), (_refusal(
            obj, "iam_bindings", None,
            "policy_data is not valid JSON (a heredoc reaches a static reader "
            "with its markers attached), so no binding can be read from it"),))
    if not isinstance(document, Mapping):
        return Mapped((), (_refusal(
            obj, "iam_bindings", None,
            "policy_data parsed to "
            f"{facts.safe_repr(document)}, not an IAM policy object"),))
    bindings = []
    for index, entry in enumerate(_members_of(document, "bindings")):
        if not isinstance(entry, Mapping):
            return Mapped((), (_refusal(
                obj, "iam_bindings", None,
                f"policy_data binding {index} is not an object"),))
        bindings.append(_binding(
            entry.get("role"),
            _principals(_members_of(entry, "members"),
                        path=f"{obj.address}.policy_data.bindings[{index}].members"),
            _block_shape(entry["condition"], "condition")
            if isinstance(entry.get("condition"), Mapping) else None))
    return _iam_fact(obj, ctx, bindings)


# -- roles and service accounts -----------------------------------------------


def _custom_role(obj: Any, ctx: Any) -> Mapped:
    """``google_*_iam_custom_role`` → one ``roles`` record.

    ``included_permissions`` is a SORTED tuple, which is exactly
    ``knowledge.GcpSnapshot.from_dict``'s own normalisation of the same field,
    so a terraform-derived role and an API-derived one compare equal instead of
    differing in the order the configuration happened to list them.
    """
    values = _values(obj)
    # A custom role lives in a project OR an organization, never both, so the
    # resource type decides which qualifier is even read.
    organization: Any = ""
    project: Any = ""
    if obj.type.startswith("google_organization"):
        organization = _attribute(values, "org_id", ctx.organization)
    else:
        project = _attribute(values, "project", ctx.project)
    key = ctx.key("roles", name=_attribute(values, "role_id", None),
                  project=_supplied(project), organization=_supplied(organization),
                  path=f"{obj.address}.role_id")
    if facts.is_unresolved(key):
        return Mapped((), (_refusal(obj, "roles", key,
                                    "the role id and its parent could not be "
                                    "resolved to one role name"),))
    record: dict[str, Any] = {}
    for field in ("title", "stage", "description"):
        value = _attribute(values, field, None)
        if value is not None:
            record[field] = value
    if "permissions" in values:
        permissions = normalize.string_list(values.get("permissions"),
                                            path=f"{obj.address}.permissions")
        record["included_permissions"] = (
            permissions if facts.is_unresolved(permissions)
            else tuple(sorted(set(permissions))))
    return Mapped((_fact(obj, "roles", key, record),))


def _service_account(obj: Any, ctx: Any) -> Mapped:
    """``google_service_account`` → one ``service_accounts`` name.

    The literal ``email`` is PREFERRED; the account-id form is derived only when
    the account id and the project are BOTH literals, because an email built
    from an unresolved half names an account in a project nobody wrote.
    """
    values = _values(obj)
    path = f"{obj.address}.email"
    email = _attribute(values, "email", None)
    if email is None:
        account = _attribute(values, "account_id", None)
        project = _attribute(values, "project", ctx.project or None)
        if (isinstance(account, str) and account
                and isinstance(project, str) and project):
            email = f"{account}@{project}.iam.gserviceaccount.com"
        else:
            # NEITHER half may be guessed: an email built from an unresolved
            # account id or project names an account nobody wrote.
            email = account if facts.is_unresolved(account) else project
    # normalize.service_account_email is itself a delegation to identity's
    # builder, so the value-level '@' check comes for free and no second key
    # form is invented here.
    canonical = normalize.service_account_email(email, path=path)
    key = ctx.key("service_accounts", name=canonical, path=path)
    if facts.is_unresolved(key):
        return Mapped((), (_refusal(obj, "service_accounts", key,
                                    "neither a literal email nor a literal "
                                    "account id plus project was available"),))
    return Mapped((_fact(obj, "service_accounts", key),))


# -- org policy ---------------------------------------------------------------


def _org_policy_key(obj: Any, ctx: Any, node: Any, constraint: Any) -> Any:
    return ctx.key("org_policies", node=node, constraint=constraint,
                   path=f"{obj.address}.name")


def _org_rule(rule: Mapping[str, Any], *, path: str) -> dict[str, Any]:
    """One v2 ``spec.rules`` block in the estate's own rule shape.

    The provider nests the two value lists inside a ``values`` block while the
    estate stores them flat, so they are lifted here — and the provider's STRING
    booleans go through :func:`gcp_grounding.tfsource.normalize.bool_or`, which
    refuses anything that is not one of the four spellings rather than
    defaulting a policy into "enforced".
    """
    values_block = _blocks(rule, "values")
    allowed: Any = ()
    denied: Any = ()
    if values_block:
        allowed = normalize.string_list(_members_of(values_block[0], "allowed_values"),
                                        path=f"{path}.values.allowed_values")
        denied = normalize.string_list(_members_of(values_block[0], "denied_values"),
                                       path=f"{path}.values.denied_values")
    return {
        "allow_all": _tri_bool(rule.get("allow_all"), path=f"{path}.allow_all"),
        "allowed_values": allowed,
        "condition": _condition(rule),
        "denied_values": denied,
        "deny_all": _tri_bool(rule.get("deny_all"), path=f"{path}.deny_all"),
        "enforce": _tri_bool(rule.get("enforce"), path=f"{path}.enforce"),
    }


def _org_policy(obj: Any, ctx: Any) -> Mapped:
    """``google_org_policy_policy`` (the v2 resource) → one ``org_policies``
    record, from the ``spec`` block ONLY. ``dry_run_spec`` is never folded in;
    see :data:`DRY_RUN_NOTE`."""
    values = _values(obj)
    name = _attribute(values, "name", None)
    parent = _attribute(values, "parent", None)
    node: Any = parent
    constraint: Any = name
    if isinstance(name, str) and "/policies/" in name:
        head, _, tail = name.rpartition("/policies/")
        constraint = tail
        if node is None:
            node = head
    key = _org_policy_key(obj, ctx, node, constraint)
    if facts.is_unresolved(key):
        return Mapped((), (_refusal(obj, "org_policies", key,
                                    "the policy's node and constraint could not "
                                    "be resolved to one key"),))
    # The two halves are read back OUT of the canonical key: knowledge.py
    # refuses a record whose node/constraint disagree with its key, and the only
    # way to guarantee they agree is to let identity.py build both.
    node_half, _, constraint_half = key.partition("|")
    spec = _blocks(values, "spec")
    spec_block = spec[0] if spec else {}
    rules = tuple(_org_rule(rule, path=f"{obj.address}.spec.rules[{index}]")
                  for index, rule in enumerate(_blocks(spec_block, "rules")))
    record = {
        "constraint": constraint_half,
        "inherit_from_parent": _flag(spec_block, "inherit_from_parent",
                                     path=f"{obj.address}.spec.inherit_from_parent"),
        "node": node_half,
        "reset": _flag(spec_block, "reset", path=f"{obj.address}.spec.reset"),
        "rules": rules,
    }
    notes = (DRY_RUN_NOTE,) if _blocks(values, "dry_run_spec") else ()
    return Mapped((_fact(obj, "org_policies", key, record, notes=notes),))


def _legacy_org_policy(obj: Any, ctx: Any) -> Mapped:
    """``google_project_organization_policy`` and its folder / organization
    siblings → one ``org_policies`` record, translated from ``boolean_policy``
    and ``list_policy``.

    A ``restore_policy`` makes ``rules`` UNRESOLVED rather than empty: an empty
    rule set reads as "no restriction", which is the OPPOSITE of what a restore
    means, and a policy that reads as unrestricted is a policy no check will
    complain about.
    """
    values = _values(obj)
    if obj.type.startswith("google_folder"):
        node = _hierarchy_target(_attribute(values, "folder", ctx.folder), "folders",
                                 path=f"{obj.address}.folder")
    elif obj.type.startswith("google_organization"):
        node = _hierarchy_target(_attribute(values, "org_id", ctx.organization),
                                 "organizations", path=f"{obj.address}.org_id")
    else:
        project = normalize.project_of(_attribute(values, "project", ctx.project),
                                       path=f"{obj.address}.project")
        node = project if facts.is_unresolved(project) else f"projects/{project}"
    key = _org_policy_key(obj, ctx, node, _attribute(values, "constraint", None))
    if facts.is_unresolved(key):
        return Mapped((), (_refusal(obj, "org_policies", key,
                                    "the policy's node and constraint could not "
                                    "be resolved to one key"),))
    node_half, _, constraint_half = key.partition("|")
    boolean_policy = _blocks(values, "boolean_policy")
    list_policy = _blocks(values, "list_policy")
    restore = _blocks(values, "restore_policy")
    inherit: Any = False
    rules: Any
    if restore:
        # A restore RESETS the policy to its inherited/default value. The reset
        # flag is the v2 spelling of exactly that, so it is carried; the rule
        # set is not invented.
        rules = facts.Unresolved(
            "unparsed", f"{obj.address}.restore_policy",
            "a restore_policy resets the policy to its default; flattening it "
            "to an empty rule set would read as 'no restriction'")
    elif boolean_policy and list_policy:
        rules = facts.Unresolved(
            "ambiguous_key", f"{obj.address}.boolean_policy",
            "this policy carries BOTH a boolean_policy and a list_policy, which "
            "are alternatives; neither is read rather than one being guessed")
    elif boolean_policy:
        rules = ({"allow_all": None, "allowed_values": (), "condition": None,
                  "denied_values": (), "deny_all": None,
                  "enforce": _tri_bool(boolean_policy[0].get("enforced"),
                                       path=f"{obj.address}.boolean_policy.enforced")},)
    elif list_policy:
        block = list_policy[0]
        inherit = _flag(block, "inherit_from_parent",
                        path=f"{obj.address}.list_policy.inherit_from_parent")
        allow = _blocks(block, "allow")
        deny = _blocks(block, "deny")
        rules = ({
            "allow_all": _tri_bool(allow[0].get("all"),
                                   path=f"{obj.address}.list_policy.allow.all")
                        if allow else None,
            "allowed_values": normalize.string_list(
                _members_of(allow[0], "values") if allow else (),
                path=f"{obj.address}.list_policy.allow.values"),
            "condition": None,
            "denied_values": normalize.string_list(
                _members_of(deny[0], "values") if deny else (),
                path=f"{obj.address}.list_policy.deny.values"),
            "deny_all": _tri_bool(deny[0].get("all"),
                                  path=f"{obj.address}.list_policy.deny.all")
                        if deny else None,
            "enforce": None,
        },)
    else:
        rules = facts.Unresolved(
            "unparsed", f"{obj.address}",
            "this policy carries none of boolean_policy, list_policy or "
            "restore_policy, so its rule set is unknown rather than empty")
    record = {
        "constraint": constraint_half,
        "inherit_from_parent": inherit,
        "node": node_half,
        "reset": bool(restore),
        "rules": rules,
    }
    return Mapped((_fact(obj, "org_policies", key, record),))


# -- VPC Service Controls -----------------------------------------------------


def _perimeter(obj: Any, ctx: Any) -> Mapped:
    """``google_access_context_manager_service_perimeter`` → one
    ``vpc_sc_perimeters`` record, plus the ENFORCED side's flat side facts.

    ``status`` is the ENFORCED configuration and ``spec`` is the DRY-RUN one —
    the naming is genuinely counterintuitive, so it is spelled out here and
    nothing below reads one for the other.
    """
    values = _values(obj)
    parent = _attribute(values, "parent", None)
    key = ctx.key("vpc_sc_perimeters", name=_attribute(values, "name", None),
                  access_policy=parent, path=f"{obj.address}.name")
    if facts.is_unresolved(key):
        return Mapped((), (_refusal(obj, "vpc_sc_perimeters", key,
                                    "the perimeter name and its access policy "
                                    "could not be resolved to one key"),))
    status = _block_shape(values.get("status"), "status")
    record = {
        "perimeter_type": _attribute(values, "perimeter_type", None),
        "spec": _block_shape(values.get("spec"), "spec"),
        "status": status,
        "use_explicit_dry_run_spec": _tri_bool(
            values.get("use_explicit_dry_run_spec", False),
            path=f"{obj.address}.use_explicit_dry_run_spec"),
    }
    produced = [_fact(obj, "vpc_sc_perimeters", key, record)]
    notes: list[str] = []
    # SIDE FACTS FROM THE ENFORCED STATUS ONLY. A dry-run spec's services and
    # access levels protect nothing, and emitting them into the existence
    # vocabulary would let a check ground a restriction that is not in force.
    for index, service in enumerate(_members_of(status, "restricted_services")):
        name = normalize.restricted_service(
            service, path=f"{obj.address}.status.restricted_services[{index}]")
        service_key = ctx.key("restricted_services", name=name,
                              path=f"{obj.address}.status.restricted_services[{index}]")
        if facts.is_unresolved(service_key):
            notes.append(_refusal(obj, "restricted_services", service_key,
                                  f"status.restricted_services[{index}] is not a "
                                  f"service hostname"))
            continue
        produced.append(_fact(obj, "restricted_services", service_key))
    for index, level in enumerate(_members_of(status, "access_levels")):
        level_key = ctx.key("access_levels", name=level, access_policy=parent,
                            path=f"{obj.address}.status.access_levels[{index}]")
        if facts.is_unresolved(level_key):
            notes.append(_refusal(obj, "access_levels", level_key,
                                  f"status.access_levels[{index}] could not be "
                                  f"resolved to one access level"))
            continue
        produced.append(_fact(obj, "access_levels", level_key))
    return Mapped(tuple(produced), tuple(notes))


def _perimeter_fragment(obj: Any, ctx: Any) -> Mapped:
    """A sibling perimeter resource → one FRAGMENT fact on the side it belongs
    to: the plain resources onto ``status`` (ENFORCED) and the ``dry_run_``
    ones onto ``spec`` (DRY-RUN), never the other way round."""
    side, field = PERIMETER_FRAGMENTS[obj.type]
    values = _values(obj)
    target = _attribute(values, "perimeter_name", None)
    if target is None:
        target = _attribute(values, "perimeter", None)
    key = ctx.key("vpc_sc_perimeters", name=target, path=obj.address)
    if facts.is_unresolved(key):
        return Mapped((), (_refusal(obj, "vpc_sc_perimeters", key,
                                    "the parent perimeter could not be resolved "
                                    "to one key"),))
    if field == "resources":
        # Kept in the project-NUMBER form terraform and the API both write; the
        # hierarchy alias reconciles it at merge time, and resolving it here
        # would key one project's perimeter onto another's row.
        contributed: Any = (_attribute(values, "resource", None),)
    else:
        names = _INGRESS_FIELDS if field == "ingress_policies" else _EGRESS_FIELDS
        contributed = ({name: _block_shape(values.get(name), name)
                        for name in names if name in values},)
    record = {side: {field: contributed}}
    return Mapped((_fact(obj, "vpc_sc_perimeters", key, record, fragment=side),))


def _access_level(obj: Any, ctx: Any) -> Mapped:
    """``google_access_context_manager_access_level`` → one ``access_levels``
    name."""
    values = _values(obj)
    key = ctx.key("access_levels", name=_attribute(values, "name", None),
                  access_policy=_attribute(values, "parent", None),
                  path=f"{obj.address}.name")
    if facts.is_unresolved(key):
        return Mapped((), (_refusal(obj, "access_levels", key,
                                    "the level name and its access policy could "
                                    "not be resolved to one key"),))
    return Mapped((_fact(obj, "access_levels", key),))


# -- the resource hierarchy ---------------------------------------------------


def _project_node(obj: Any, ctx: Any) -> Mapped:
    """``google_project`` → one ``resource_hierarchy`` node.

    THE NUMBER IS None FROM HCL, and that is correct rather than a gap: the
    project number is assigned by GCP at apply time and cannot appear in
    configuration. An organization node is NEVER synthesized from ``org_id``:
    a parent REFERENCE is not an observation that the parent exists, and
    minting one would let an existence check ground an organization nobody
    captured.
    """
    values = _values(obj)
    ident = _attribute(values, "project_id", ctx.project)
    node: Any = ident
    if isinstance(ident, str) and ident:
        node = f"projects/{ident}"
    key = ctx.key("resource_hierarchy", name=node,
                  path=f"{obj.address}.project_id")
    if facts.is_unresolved(key):
        return Mapped((), (_refusal(obj, "resource_hierarchy", key,
                                    "the project id could not be resolved"),))
    folder = _attribute(values, "folder_id", None)
    organization = _attribute(values, "org_id", None)
    parent: Any = None
    if folder is not None:
        parent = _hierarchy_target(folder, "folders", path=f"{obj.address}.folder_id")
    elif organization is not None:
        parent = _hierarchy_target(organization, "organizations",
                                   path=f"{obj.address}.org_id")
    record = {
        "display_name": _attribute(values, "name", None),
        "number": _attribute(values, "number", None),
        "parent": parent,
        "type": "project",
    }
    return Mapped((_fact(obj, "resource_hierarchy", key, record),))


def _folder_node(obj: Any, ctx: Any) -> Mapped:
    """``google_folder`` → one ``resource_hierarchy`` node. As with a project,
    the parent is recorded and never SYNTHESIZED into a node of its own."""
    values = _values(obj)
    number = _attribute(values, "folder_id", None)
    name = _attribute(values, "name", None)
    if number is None and isinstance(name, str) and name.startswith("folders/"):
        number = name[len("folders/"):]
    node: Any = number
    if isinstance(number, str) and number:
        node = f"folders/{number}"
    key = ctx.key("resource_hierarchy", name=node,
                  path=f"{obj.address}.folder_id")
    if facts.is_unresolved(key):
        return Mapped((), (_refusal(obj, "resource_hierarchy", key,
                                    "the folder id is generated at apply time and "
                                    "no literal one was available"),))
    parent = _attribute(values, "parent", None)
    record = {
        "display_name": _attribute(values, "display_name", None),
        # None from raw HCL, exactly as a project's number is: the folder id is
        # generated at apply time. A marker is KEPT rather than nulled.
        "number": number,
        "parent": None if parent is None else normalize.strip_self_link(
            parent, path=f"{obj.address}.parent"),
        "type": "folder",
    }
    return Mapped((_fact(obj, "resource_hierarchy", key, record),))


# -- registration -------------------------------------------------------------


def _facts_only(mapper: Callable[..., Mapped]) -> Callable[..., Sequence[facts.Fact]]:
    """The registry's view of a mapper: the facts half of :class:`Mapped`. One
    implementation, two views — see :class:`Mapped`."""

    @functools.wraps(mapper)
    def wrapped(obj: Any, ctx: Any) -> Sequence[facts.Fact]:
        return mapper(obj, ctx).facts

    return wrapped


def _iam_registrations() -> tuple[tuple[str, Callable[..., Mapped], str], ...]:
    rows = []
    for prefix in IAM_FAMILIES:
        for suffix, mapper in (("binding", _iam_binding), ("member", _iam_member),
                               ("policy", _iam_policy)):
            rows.append((f"{prefix}_{suffix}", mapper, "iam_bindings"))
    return tuple(rows)


#: Every terraform type this module claims, its mapper and the estate category
#: the type's OWN identity lives in.
_REGISTRATIONS: tuple[tuple[str, Callable[..., Mapped], str], ...] = (
    _iam_registrations()
    + (("google_project_iam_custom_role", _custom_role, "roles"),
       ("google_organization_iam_custom_role", _custom_role, "roles"),
       ("google_service_account", _service_account, "service_accounts"),
       ("google_org_policy_policy", _org_policy, "org_policies"),
       ("google_project_organization_policy", _legacy_org_policy, "org_policies"),
       ("google_folder_organization_policy", _legacy_org_policy, "org_policies"),
       ("google_organization_policy", _legacy_org_policy, "org_policies"),
       ("google_access_context_manager_service_perimeter", _perimeter,
        "vpc_sc_perimeters"),
       ("google_access_context_manager_access_level", _access_level,
        "access_levels"),
       ("google_project", _project_node, "resource_hierarchy"),
       ("google_folder", _folder_node, "resource_hierarchy"))
    + tuple((resource_type, _perimeter_fragment, "vpc_sc_perimeters")
            for resource_type in PERIMETER_FRAGMENTS)
)

#: Dispatch for :func:`map_one`, which is the notes-carrying view of the same
#: table the registry holds.
_MAPPERS: dict[str, Callable[..., Mapped]] = {
    resource_type: mapper for resource_type, mapper, _category in _REGISTRATIONS}


def map_one(obj: Any, ctx: Any) -> Mapped:
    """Map ONE object and keep its notes — the view a ledger wants.

    Returns an empty :class:`Mapped` for a type this module does not claim,
    which is different from having something unresolved to say about one.
    """
    mapper = _MAPPERS.get(obj.type)
    if mapper is None:
        return Mapped()
    return mapper(obj, ctx)


def register_all() -> None:
    """Register every type this module claims, and merge its stated gaps into
    :data:`gcp_grounding.tfsource.mapping.DELIBERATELY_UNMAPPED`.

    Called at import time, which is how a domain module joins the registry. It
    is also idempotent and callable again after
    :func:`gcp_grounding.tfsource.mapping.reset_cache`, because registration is
    process-global while the cache is not: a test that resets the registry must
    be able to put the real mappers back.
    """
    for resource_type, reason in DELIBERATELY_UNMAPPED.items():
        mapping.DELIBERATELY_UNMAPPED.setdefault(resource_type, reason)
    for resource_type, mapper, category in _REGISTRATIONS:
        mapping.register(resource_type, _facts_only(mapper), category=category,
                         module=__name__)


register_all()
