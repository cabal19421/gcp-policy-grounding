"""Claim extraction: GCP IAM policy / Org Policy JSON → grounding claims.

Pure parsing — no snapshot, no reasoning. Each :class:`Claim` records one
checkable assertion the document makes ("this role name exists", "this
constraint is used list-typed") together with a json-path ``location`` into
the source document, so a verdict can point back at the exact field.

The extractor is deliberately conservative: a claim is emitted only when the
field resolves unambiguously. Anything else — malformed fields, request-time
constructs (tag-based conditions, IAM Conditions referencing runtime-only
attributes), members that are not estate principals (``allUsers``,
``deleted:…``) — is *skipped*, never guessed at: no claim means the reasoner
stays silent rather than minting a false verdict. ``request.time`` conditions
are NOT skipped — time-window satisfiability is exactly what the z3 layer
decides offline.

Claim kinds:

- ``role`` — the binding's role name should exist (value = role name).
- ``principal`` — the member should exist in the estate (value = member id).
- ``cel`` — an IAM Condition whose satisfiability is offline-decidable
  (value = the CEL expression).
- ``constraint`` — the org-policy constraint should exist
  (value = canonical ``constraints/<id>`` name).
- ``constraint_value`` — the policy uses the constraint with a value type
  (``is_list``: list-typed True, boolean-typed False); checked against the
  constraint's declared ``value_type`` in the snapshot.
- ``permission`` — the referenced IAM permission should exist (value =
  permission name; emitted by :mod:`~gcp_grounding.tf_claims` for custom-role
  ``permissions[]``).
- ``resource_type_ref`` — the referenced resource type should exist (value =
  the type name; emitted by :mod:`~gcp_grounding.tf_claims` once per
  google-provider resource).

The following existence kinds are grounded later by the Datalog pass, one per
new snapshot category:

- ``network_ref`` — the referenced VPC network should exist.
- ``subnetwork_ref`` — the referenced subnetwork should exist.
- ``network_tag_ref`` — the referenced network tag should exist.
- ``service_account_ref`` — the referenced service account should exist.
- ``access_level_ref`` — the referenced access level should exist.
- ``restricted_service_ref`` — the referenced VPC-SC restricted service should exist.
- ``perimeter_ref`` — the referenced service perimeter should exist.
- ``firewall_policy_ref`` — the referenced hierarchical firewall policy should exist.
- ``security_policy_ref`` — the referenced Cloud Armor security policy should exist.
- ``hierarchy_node_ref`` — the referenced resource-hierarchy node should exist.

The following structured kinds carry their data in the frozen ``payload``
channel for the z3 checkers rather than in ``value`` alone:

- ``firewall_rule`` — a VPC firewall rule, structured for the packet algebra.
- ``firewall_policy_rule`` — a hierarchical firewall policy rule, structured.
- ``security_policy_rule`` — a Cloud Armor security policy rule, structured.
- ``perimeter_config`` — a VPC-SC service perimeter configuration, structured.
- ``perimeter_ingress`` — a VPC-SC ingress policy, structured.
- ``perimeter_egress`` — a VPC-SC egress policy, structured.
- ``public_principal`` — a principal opening a resource to the public.
- ``unmodelled_principal`` — a principal the snapshot cannot enumerate.
- ``denied_principal`` — a principal named by an IAM deny rule.
- ``denied_permission`` — a permission named by an IAM deny rule.
- ``constraint_enforcement`` — an org-policy ``enforce`` flag / list values.

Both Org Policy formats are parsed: legacy v1 (``constraint`` +
``booleanPolicy``/``listPolicy``) and v2 (``name`` ending in
``/policies/<id>`` + ``spec.rules[]`` with ``enforce`` vs
``values``/``allowAll``/``denyAll``). Tag-based ``spec.rules[].condition``
expressions are request-time constructs and yield no ``cel`` claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .core.log import get_logger

logger = get_logger(__name__)

__all__ = ["KINDS", "Claim", "freeze", "unfreeze",
           "iam_policy_claims", "org_policy_claims"]

KINDS = (
    # -- the original seven, kept first and in order --------------------------
    "role", "permission", "principal", "cel", "constraint", "constraint_value",
    "resource_type_ref",
    # -- existence kinds, grounded later by the Datalog pass ------------------
    "network_ref", "subnetwork_ref", "network_tag_ref", "service_account_ref",
    "access_level_ref", "restricted_service_ref", "perimeter_ref",
    "firewall_policy_ref", "security_policy_ref", "hierarchy_node_ref",
    # -- structured / checker kinds, carrying a frozen payload ----------------
    "firewall_rule", "firewall_policy_rule", "security_policy_rule",
    "perimeter_config", "perimeter_ingress", "perimeter_egress",
    "public_principal", "unmodelled_principal", "denied_principal",
    "denied_permission", "constraint_enforcement",
)

#: Member prefixes that name estate principals a snapshot can enumerate.
#: Everything else (allUsers, allAuthenticatedUsers, deleted:…, principal://
#: and principalSet:// federated identities) is skipped, not guessed at.
_PRINCIPAL_PREFIXES = ("user:", "serviceAccount:", "group:", "domain:")

#: Substrings marking CEL constructs resolvable only at request time — tag
#: lookups and caller/transport attributes. An expression mentioning any of
#: these yields no ``cel`` claim. ``request.time`` is deliberately absent:
#: time-window satisfiability is offline-decidable.
_RUNTIME_ONLY_MARKERS = (
    "resource.matchTag",  # also covers resource.matchTagId
    "resource.hasTagKey",
    "request.auth",
    "destination.ip",
    "destination.port",
    "origin.ip",
)

#: Value-type-bearing keys of an org-policy v2 rule. Exactly one must be
#: present for the rule's type usage to be unambiguous.
_V2_BOOLEAN_KEYS = ("enforce",)
_V2_LIST_KEYS = ("values", "allowAll", "denyAll")


def freeze(value: Any) -> Any:
    """Turn a JSON-ish *value* into a deterministic, hashable form.

    A ``Mapping`` becomes ``("__map__", <key-sorted pairs>)``; a list or tuple
    becomes a tuple of frozen items; scalars (``str``/``int``/``float``/
    ``bool``/``None``) pass through. Anything else raises :class:`ValueError`
    naming the type — a firewall rule must not smuggle an unhashable object
    into a :class:`Claim`. :func:`unfreeze` is the exact inverse.
    """
    if isinstance(value, Mapping):
        return ("__map__", tuple(sorted((str(k), freeze(v)) for k, v in value.items())))
    if isinstance(value, (list, tuple)):
        return tuple(freeze(v) for v in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError(f"cannot freeze value of type {type(value).__name__}")


def unfreeze(value: Any) -> Any:
    """Inverse of :func:`freeze`: ``("__map__", pairs)`` becomes a ``dict``,
    every other tuple becomes a ``list``, scalars pass through."""
    if isinstance(value, tuple):
        if len(value) == 2 and value[0] == "__map__":
            return {k: unfreeze(v) for k, v in value[1]}
        return [unfreeze(v) for v in value]
    return value


def _is_frozen(value: Any) -> bool:
    """Whether *value* is a frozen form :func:`freeze` could have produced: a
    scalar, or a tuple whose every element is itself frozen (which subsumes the
    ``("__map__", pairs)`` shape). Rejects raw lists, dicts and objects."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, tuple):
        return all(_is_frozen(v) for v in value)
    return False


@dataclass(frozen=True)
class Claim:
    """One checkable assertion, anchored to its source field."""

    kind: str
    value: str
    #: json-path into the source document, e.g. ``bindings[0].role``.
    location: str
    #: ``constraint_value`` claims only: list-typed (True) vs boolean (False).
    is_list: bool | None = None
    #: Frozen structured channel for checker kinds: sorted ``(key, frozen)``
    #: pairs, kept hashable so :class:`Claim` stays frozen and comparable.
    #: Built via :meth:`of`; read back via :meth:`fields`.
    payload: tuple[tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown claim kind {self.kind!r}; expected one of {KINDS}")
        if (self.kind == "constraint_value") != (self.is_list is not None):
            raise ValueError("is_list must be set on 'constraint_value' claims and only there "
                             f"(kind={self.kind!r}, is_list={self.is_list!r})")
        if not isinstance(self.payload, tuple):
            raise ValueError(f"payload must be a tuple, got {type(self.payload).__name__}")
        prev: str | None = None
        for entry in self.payload:
            if not (isinstance(entry, tuple) and len(entry) == 2):
                raise ValueError(f"payload entry {entry!r} is not a (key, value) 2-tuple")
            key, val = entry
            if not isinstance(key, str) or not key:
                raise ValueError(f"payload key {key!r} must be a non-empty str")
            if prev is not None and key == prev:
                raise ValueError(f"payload key {key!r} is duplicated")
            if prev is not None and key < prev:
                raise ValueError(f"payload key {key!r} is out of ascending order")
            if not _is_frozen(val):
                raise ValueError(f"payload key {key!r} has a non-frozen value {val!r}")
            prev = key

    @classmethod
    def of(cls, kind: str, value: str, location: str, *,
           is_list: bool | None = None, **fields: Any) -> "Claim":
        """Build a claim whose keyword *fields* become a frozen ``payload``."""
        payload = tuple(sorted((k, freeze(v)) for k, v in fields.items()))
        return cls(kind, value, location, is_list=is_list, payload=payload)

    def fields(self) -> dict[str, Any]:
        """The structured payload as a plain ``dict``, inverting :meth:`of`."""
        return {k: unfreeze(v) for k, v in self.payload}


# -- IAM allow/deny policy ----------------------------------------------------


def iam_policy_claims(policy: Mapping[str, Any]) -> list[Claim]:
    """Claims made by one IAM policy document (``getIamPolicy`` JSON)."""
    if not isinstance(policy, Mapping):
        raise ValueError(f"IAM policy must be a mapping, got {type(policy).__name__}")
    claims: list[Claim] = []
    bindings = policy.get("bindings")
    if not isinstance(bindings, list):
        if bindings is not None:
            logger.debug("bindings is %s, not an array — no claims", type(bindings).__name__)
        return claims
    for i, binding in enumerate(bindings):
        if not isinstance(binding, Mapping):
            logger.debug("bindings[%d] is not an object — skipped", i)
            continue
        role = binding.get("role")
        if isinstance(role, str) and role:
            claims.append(Claim("role", role, f"bindings[{i}].role"))
        else:
            logger.debug("bindings[%d].role does not resolve to a name — skipped", i)
        members = binding.get("members")
        if isinstance(members, list):
            for j, member in enumerate(members):
                if isinstance(member, str) and member.startswith(_PRINCIPAL_PREFIXES):
                    claims.append(Claim("principal", member, f"bindings[{i}].members[{j}]"))
                else:
                    logger.debug("bindings[%d].members[%d] (%r) is not an estate principal "
                                 "— skipped", i, j, member)
        condition = binding.get("condition")
        if isinstance(condition, Mapping):
            expression = condition.get("expression")
            if not isinstance(expression, str) or not expression.strip():
                logger.debug("bindings[%d].condition has no expression — skipped", i)
            elif any(marker in expression for marker in _RUNTIME_ONLY_MARKERS):
                logger.debug("bindings[%d].condition references runtime-only attributes "
                             "— skipped, not guessed at", i)
            else:
                claims.append(Claim("cel", expression, f"bindings[{i}].condition.expression"))
    return claims


# -- Org Policy (legacy v1 and v2) --------------------------------------------


def org_policy_claims(policy: Mapping[str, Any]) -> list[Claim]:
    """Claims made by one Org Policy document, legacy v1 or v2 format."""
    if not isinstance(policy, Mapping):
        raise ValueError(f"org policy must be a mapping, got {type(policy).__name__}")
    claims: list[Claim] = []
    resolved = _org_policy_constraint(policy)
    if resolved is None:
        logger.debug("org policy names no unambiguous constraint — no claims")
        return claims
    constraint, location = resolved
    claims.append(Claim("constraint", constraint, location))

    # Legacy v1: the typed-policy field itself declares the value type.
    if isinstance(policy.get("booleanPolicy"), Mapping):
        claims.append(Claim("constraint_value", constraint, "booleanPolicy", is_list=False))
    if isinstance(policy.get("listPolicy"), Mapping):
        claims.append(Claim("constraint_value", constraint, "listPolicy", is_list=True))

    # v2: each rule carries one value-type-bearing key.
    spec = policy.get("spec")
    rules = spec.get("rules") if isinstance(spec, Mapping) else None
    if isinstance(rules, list):
        for i, rule in enumerate(rules):
            claim = _v2_rule_value_claim(constraint, rule, f"spec.rules[{i}]")
            if claim is not None:
                claims.append(claim)
    return claims


def _org_policy_constraint(policy: Mapping[str, Any]) -> tuple[str, str] | None:
    """The canonical ``constraints/<id>`` name and its source location — or
    None when the document does not name exactly one constraint."""
    constraint = policy.get("constraint")
    name = policy.get("name")
    if constraint is not None and name is not None:
        return None  # v1 and v2 spellings at once — ambiguous
    if constraint is not None:
        if isinstance(constraint, str) and constraint:
            return constraint, "constraint"
        return None
    if isinstance(name, str) and name.count("/policies/") == 1:
        suffix = name.split("/policies/", 1)[1]
        if suffix and "/" not in suffix:
            return f"constraints/{suffix}", "name"
    return None


def _v2_rule_value_claim(constraint: str, rule: Any, location: str) -> Claim | None:
    if not isinstance(rule, Mapping):
        logger.debug("%s is not an object — skipped", location)
        return None
    typed = [k for k in (*_V2_BOOLEAN_KEYS, *_V2_LIST_KEYS) if k in rule]
    if len(typed) != 1:
        logger.debug("%s carries %d value-type keys (%s) — ambiguous, skipped",
                     location, len(typed), ", ".join(typed) or "none")
        return None
    key = typed[0]
    value = rule[key]
    if key == "values":
        if not isinstance(value, Mapping):
            logger.debug("%s.values is not an object — skipped", location)
            return None
        return Claim("constraint_value", constraint, f"{location}.values", is_list=True)
    if not isinstance(value, bool):
        logger.debug("%s.%s is not a boolean — skipped", location, key)
        return None
    return Claim("constraint_value", constraint, f"{location}.{key}",
                 is_list=key in _V2_LIST_KEYS)
