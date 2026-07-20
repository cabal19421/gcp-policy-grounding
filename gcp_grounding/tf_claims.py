"""Claim extraction: ``terraform show -json`` plan output → grounding claims.

Walks a Terraform plan document for ``google``/``google-beta`` provider
resources and emits the same :class:`~gcp_grounding.claims.Claim` records the
API-document extractors produce, anchored to the Terraform resource address
(extended by the attribute path inside the resource) instead of a json-path
into an API document.

Handled resource types:

- ``google_project_iam_binding`` / ``google_project_iam_member`` — role,
  principal and (offline-decidable) cel claims, extracted by feeding a
  synthetic single-binding policy through
  :func:`~gcp_grounding.claims.iam_policy_claims`, so the conservative skip
  rules (non-estate members, request-time conditions) are shared, not
  duplicated.
- ``google_project_iam_policy`` — the ``policy_data`` JSON string is parsed
  and fed through :func:`~gcp_grounding.claims.iam_policy_claims` unchanged.
- ``google_org_policy_policy`` — constraint + constraint_value claims from
  the Terraform spelling of the org-policy v2 shape: snake_case keys,
  nested blocks as arrays, "TRUE"/"FALSE" string booleans.
- ``google_project_iam_custom_role`` — one ``permission`` claim per entry in
  ``permissions[]``, each of which must exist; the role itself is being
  created, so no ``role`` claim.

Every google-provider managed resource — handled or not — additionally
yields one ``resource_type_ref`` claim for its ``type``, so an invented
resource type is catchable against the provider vocabulary.

Resources are read from ``planned_values`` (root module and child modules,
recursively) first; ``resource_changes`` entries then contribute only
addresses not already seen, with ``change.after`` as the planned values.
A plan carrying only one of the two sections still yields full claims, and
one carrying both does not double-claim. A destroyed resource
(``change.after`` is null) yields only its ``resource_type_ref``, and a
``deposed``-keyed delete entry (the doomed half of a create_before_destroy
replacement) never shadows the created object's entry at the same address.
As in
:mod:`~gcp_grounding.claims`, anything that does not resolve unambiguously
is skipped, never guessed at.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, Iterator, Mapping

from .claims import Claim, _org_policy_constraint, iam_policy_claims
from .core.log import get_logger

logger = get_logger(__name__)

__all__ = ["terraform_plan_claims"]

#: Provider short names whose resources are ours to ground. ``provider_name``
#: in plan JSON is source-addressed ("registry.terraform.io/hashicorp/google").
_GOOGLE_PROVIDERS = ("google", "google-beta")

#: Value-type-bearing keys of a ``google_org_policy_policy`` rule block —
#: Terraform's spelling of the org-policy v2 rule. Exactly one must be *set*
#: (unset attributes appear as null or an empty block array in plan JSON)
#: for the rule's type usage to be unambiguous.
_TF_BOOLEAN_KEYS = ("enforce",)
_TF_LIST_KEYS = ("values", "allow_all", "deny_all")

#: The provider encodes rule booleans as enum strings, not JSON booleans.
_TF_BOOLEANS = {"TRUE": True, "FALSE": False}


def terraform_plan_claims(plan: Mapping[str, Any]) -> list[Claim]:
    """Claims made by one ``terraform show -json`` plan document."""
    if not isinstance(plan, Mapping):
        raise ValueError(f"terraform plan must be a mapping, got {type(plan).__name__}")
    claims: list[Claim] = []
    for address, rtype, values in _google_resources(plan):
        claims.append(Claim("resource_type_ref", rtype, address))
        extractor = _EXTRACTORS.get(rtype)
        if extractor is None:
            continue
        if isinstance(values, Mapping):
            claims.extend(extractor(address, values))
        else:
            logger.debug("%s has no planned values — only its type reference is claimed",
                         address)
    return claims


# -- plan walking -------------------------------------------------------------


def _google_resources(plan: Mapping[str, Any]) -> Iterator[tuple[str, str, Any]]:
    """(address, type, planned values) for every google managed resource,
    ``planned_values`` first, then ``resource_changes`` for unseen addresses.

    A create_before_destroy replacement carries two ``resource_changes``
    entries at one address: the created object's, and a ``deposed``-keyed
    delete whose ``change.after`` is null. Non-deposed entries are taken
    first (the sort is stable, so order is otherwise unchanged) so a
    deposed delete listed earlier cannot claim the address and silently
    drop the created object's claims."""
    seen: set[str] = set()
    planned = plan.get("planned_values")
    if isinstance(planned, Mapping):
        for resource in _module_resources(planned.get("root_module")):
            entry = _google_entry(resource, from_change=False)
            if entry is not None and entry[0] not in seen:
                seen.add(entry[0])
                yield entry
    changes = plan.get("resource_changes")
    if isinstance(changes, list):
        for resource in sorted(changes, key=_is_deposed):
            entry = _google_entry(resource, from_change=True)
            if entry is not None and entry[0] not in seen:
                seen.add(entry[0])
                yield entry


def _is_deposed(resource: Any) -> bool:
    """Whether a ``resource_changes`` entry describes a deposed object — the
    old copy a create_before_destroy replacement is about to delete."""
    return isinstance(resource, Mapping) and bool(resource.get("deposed"))


def _module_resources(module: Any) -> Iterator[Any]:
    if not isinstance(module, Mapping):
        return
    resources = module.get("resources")
    if isinstance(resources, list):
        yield from resources
    children = module.get("child_modules")
    if isinstance(children, list):
        for child in children:
            yield from _module_resources(child)


def _google_entry(resource: Any, from_change: bool) -> tuple[str, str, Any] | None:
    if not isinstance(resource, Mapping) or resource.get("mode") != "managed":
        return None
    address = resource.get("address")
    rtype = resource.get("type")
    if not isinstance(address, str) or not address or not isinstance(rtype, str) or not rtype:
        return None
    provider = resource.get("provider_name")
    if isinstance(provider, str) and provider:
        if provider.rsplit("/", 1)[-1] not in _GOOGLE_PROVIDERS:
            return None
    elif not rtype.startswith("google_"):
        return None
    if from_change:
        change = resource.get("change")
        values = change.get("after") if isinstance(change, Mapping) else None
    else:
        values = resource.get("values")
    return address, rtype, values


# -- IAM binding / member / policy resources ----------------------------------


def _iam_binding_claims(address: str, values: Mapping[str, Any]) -> list[Claim]:
    binding: dict[str, Any] = {"role": values.get("role"), "members": values.get("members")}
    condition, condition_path = _first_block(values.get("condition"), "condition")
    if condition is not None:
        binding["condition"] = condition
    return _reanchored(iam_policy_claims({"bindings": [binding]}), address, {
        "bindings[0].condition.expression": f"{address}.{condition_path}.expression",
    })


def _iam_member_claims(address: str, values: Mapping[str, Any]) -> list[Claim]:
    binding: dict[str, Any] = {"role": values.get("role")}
    member = values.get("member")
    if member is not None:
        binding["members"] = [member]
    condition, condition_path = _first_block(values.get("condition"), "condition")
    if condition is not None:
        binding["condition"] = condition
    return _reanchored(iam_policy_claims({"bindings": [binding]}), address, {
        "bindings[0].members[0]": f"{address}.member",
        "bindings[0].condition.expression": f"{address}.{condition_path}.expression",
    })


def _iam_policy_resource_claims(address: str, values: Mapping[str, Any]) -> list[Claim]:
    policy_data = values.get("policy_data")
    if not isinstance(policy_data, str) or not policy_data.strip():
        logger.debug("%s.policy_data is absent or not a string — skipped", address)
        return []
    try:
        policy = json.loads(policy_data)
    except json.JSONDecodeError:
        logger.debug("%s.policy_data is not valid JSON — skipped, not guessed at", address)
        return []
    if not isinstance(policy, Mapping):
        logger.debug("%s.policy_data is not a policy object — skipped", address)
        return []
    return [replace(claim, location=f"{address}.policy_data.{claim.location}")
            for claim in iam_policy_claims(policy)]


def _reanchored(claims: list[Claim], address: str,
                overrides: Mapping[str, str]) -> list[Claim]:
    """Re-anchor synthetic single-binding locations (``bindings[0].<field>``)
    onto the resource address."""
    return [replace(claim, location=overrides.get(
                claim.location, f"{address}.{claim.location.removeprefix('bindings[0].')}"))
            for claim in claims]


# -- custom roles -------------------------------------------------------------


def _custom_role_claims(address: str, values: Mapping[str, Any]) -> list[Claim]:
    claims: list[Claim] = []
    permissions = values.get("permissions")
    if not isinstance(permissions, list):
        if permissions is not None:
            logger.debug("%s.permissions is not an array — skipped", address)
        return claims
    for i, permission in enumerate(permissions):
        if isinstance(permission, str) and permission:
            claims.append(Claim("permission", permission, f"{address}.permissions[{i}]"))
        else:
            logger.debug("%s.permissions[%d] (%r) is not a permission name — skipped",
                         address, i, permission)
    return claims


# -- org policy ---------------------------------------------------------------


def _org_policy_resource_claims(address: str, values: Mapping[str, Any]) -> list[Claim]:
    resolved = _org_policy_constraint(values)
    if resolved is None:
        logger.debug("%s names no unambiguous constraint — no claims", address)
        return []
    constraint, name_location = resolved
    claims = [Claim("constraint", constraint, f"{address}.{name_location}")]
    spec, spec_path = _first_block(values.get("spec"), "spec")
    rules = spec.get("rules") if spec is not None else None
    if isinstance(rules, list):
        for i, rule in enumerate(rules):
            claim = _tf_rule_value_claim(constraint, rule, f"{address}.{spec_path}.rules[{i}]")
            if claim is not None:
                claims.append(claim)
    return claims


def _tf_rule_value_claim(constraint: str, rule: Any, location: str) -> Claim | None:
    if not isinstance(rule, Mapping):
        logger.debug("%s is not an object — skipped", location)
        return None
    present = {key: rule[key] for key in (*_TF_BOOLEAN_KEYS, *_TF_LIST_KEYS)
               if rule.get(key) not in (None, [])}
    if len(present) != 1:
        logger.debug("%s sets %d value-type keys (%s) — ambiguous, skipped",
                     location, len(present), ", ".join(present) or "none")
        return None
    (key, value), = present.items()
    if key == "values":
        if _first_block(value, key)[0] is None:
            logger.debug("%s.values is not a block — skipped", location)
            return None
        return Claim("constraint_value", constraint, f"{location}.values", is_list=True)
    if not isinstance(value, bool):
        value = _TF_BOOLEANS.get(value) if isinstance(value, str) else None
        if value is None:
            logger.debug("%s.%s is not a boolean — skipped", location, key)
            return None
    return Claim("constraint_value", constraint, f"{location}.{key}",
                 is_list=key in _TF_LIST_KEYS)


def _first_block(value: Any, name: str) -> tuple[Mapping[str, Any] | None, str]:
    """A nested-block attribute → (its object, its path fragment). Plan JSON
    encodes blocks as arrays (``[{...}]`` → ``name[0]``); a bare object is
    accepted too. Absent/empty/other shapes → (None, name)."""
    if isinstance(value, Mapping):
        return value, name
    if isinstance(value, list) and value and isinstance(value[0], Mapping):
        return value[0], f"{name}[0]"
    return None, name


_EXTRACTORS = {
    "google_project_iam_binding": _iam_binding_claims,
    "google_project_iam_member": _iam_member_claims,
    "google_project_iam_policy": _iam_policy_resource_claims,
    "google_project_iam_custom_role": _custom_role_claims,
    "google_org_policy_policy": _org_policy_resource_claims,
}
