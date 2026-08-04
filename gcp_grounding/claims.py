"""Claim extraction: GCP IAM policy / Org Policy JSON → grounding claims.

Pure parsing — no snapshot, no reasoning. Each :class:`Claim` records one
checkable assertion the document makes ("this role name exists", "this
constraint is used list-typed") together with a json-path ``location`` into
the source document, so a verdict can point back at the exact field.

The extractor is deliberately conservative: a claim is emitted only when the
field resolves unambiguously. Malformed fields and request-time constructs
(tag-based conditions, IAM Conditions referencing runtime-only attributes)
are *skipped*, never guessed at: no claim means the reasoner stays silent
rather than minting a false verdict. ``request.time`` conditions are NOT
skipped — time-window satisfiability is exactly what the z3 layer decides
offline.

Binding members are the one place nothing is silently dropped. An estate
principal (``user:``/``serviceAccount:``/``group:``/``domain:``) yields a
``principal`` claim; the public principals ``allUsers`` and
``allAuthenticatedUsers`` yield a ``public_principal`` claim carrying the
grant polarity and the binding's role; every other member — ``deleted:…``,
``principal://…``, ``principalSet://…``, a non-string — yields an
``unmodelled_principal`` claim. A member the snapshot cannot enumerate is
recorded (as unverified downstream), never omitted, so public exposure can
no longer hide in a byte-identical clean report.

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

An org-policy rule yields TWO claims, and the distinction matters: the
long-standing ``constraint_value`` records only the value *type*
(``is_list``), which is why ``enforce: true`` and ``enforce: false`` used to
produce byte-identical reports; the ``constraint_enforcement`` claim added
beside it carries the value ITSELF — the enforce flag, the allow/deny-all
flags, the concrete allowed/denied value lists, and the document-level
``reset`` / ``inheritFromParent`` switches — in the frozen payload, so
:mod:`~gcp_grounding.org_checks` can compare a proposal against the estate's
recorded policy.

A SKIPPED RULE IS NOT A SILENT ONE. The conservative value-type extractor
still refuses to guess what an ambiguous, malformed or shapeless rule sets, so
no ``constraint_value`` claim is emitted for it — but an enforcement claim IS,
carrying the skip in its ``unreadable`` payload field (a tuple of reasons, each
naming the offending json-path and the shape found there) and no values at all.
Silence was a one-key evasion: the surviving ``constraint`` claim keeps such a
document out of the zero-claims honesty guard, so a rules array nobody could
read used to produce a clean PASS. The same field carries a malformed value
list — a non-array where ``allowedValues`` belongs, or entries that are not
non-empty strings — which otherwise degraded to an empty list indistinguishable
from an observed-empty one. An explicitly empty ``rules`` array is the opposite
case and stays claim-free: it was read, and it holds nothing.

The document-level claim (``rule_index`` :data:`NO_RULE_INDEX`, location
``spec``) is emitted whenever ``spec.reset`` or ``spec.inheritFromParent`` is
true and NO rule of the document's own was read, INDEPENDENT of whether the
rules array is absent, empty, unreadable or full of decoys — two of the three
disablement spellings hang off nothing else, and one skipped entry used to hide
them both. It is suppressed only when a rule-level claim already carried the
same switches.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .core.log import get_logger

logger = get_logger(__name__)

__all__ = ["KINDS", "NO_RULE_INDEX", "PUBLIC_PRINCIPALS", "Claim", "freeze",
           "unfreeze", "iam_policy_claims", "org_policy_claims"]

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
#: A member matching one yields a ``principal`` claim; the public principals
#: below yield ``public_principal``; anything else (deleted:…, principal://
#: and principalSet:// federated identities, a non-string) yields
#: ``unmodelled_principal`` — no member is silently dropped.
_PRINCIPAL_PREFIXES = ("user:", "serviceAccount:", "group:", "domain:")

#: The two members that open a resource to everyone. In an IAM *allow* policy
#: each is a public-exposure hole (emitted with ``polarity="grant"``); the same
#: member named by an IAM *deny* policy is a guardrail, which is why
#: :mod:`~gcp_grounding.iam_deny` emits it with ``polarity="deny"`` instead.
PUBLIC_PRINCIPALS = ("allUsers", "allAuthenticatedUsers")

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

#: The value-bearing half of a ``constraint_enforcement`` payload, with the
#: "this rule does not state it" default for each field. ``None`` is that
#: default for the three booleans precisely so an *explicit* ``false`` stays
#: distinguishable from silence — the whole point of the claim.
_ENFORCEMENT_DEFAULTS: dict[str, Any] = {
    "enforce": None, "allow_all": None, "deny_all": None,
    "allowed_values": (), "denied_values": (),
}

#: ``rule_index`` of the one claim a v2 spec with NO rules of its own still
#: emits, so a bare ``spec.reset``/``spec.inheritFromParent`` — disablement
#: spellings that carry no rule to hang off — remain checkable.
#:
#: Deliberately NOT an integer. Every consumer compares it symbolically
#: (``fields["rule_index"] == NO_RULE_INDEX``) and every real index comes out of
#: ``enumerate()``, so a non-integer sentinel reads identically for them while
#: being unable to collide with a real rule index BY CONSTRUCTION rather than by
#: the arithmetic accident that no index is negative.
NO_RULE_INDEX = "document"


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
                loc = f"bindings[{i}].members[{j}]"
                if isinstance(member, str) and member.startswith(_PRINCIPAL_PREFIXES):
                    claims.append(Claim("principal", member, loc))
                elif member in PUBLIC_PRINCIPALS:
                    claims.append(Claim.of("public_principal", member, loc,
                                           polarity="grant",
                                           role=role if isinstance(role, str) else ""))
                else:
                    logger.debug("bindings[%d].members[%d] (%r) is not an estate "
                                 "principal — recorded as unmodelled", i, j, member)
                    claims.append(Claim("unmodelled_principal", str(member), loc))
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
    constraint, name_location = resolved
    claims.append(Claim("constraint", constraint, name_location))
    node = _org_policy_node(policy, name_location)
    spec = policy.get("spec") if isinstance(policy.get("spec"), Mapping) else None

    # Legacy v1: the typed-policy field itself declares the value type. Both
    # halves map onto the same enforcement payload as their v2 spellings.
    boolean_policy = policy.get("booleanPolicy")
    if isinstance(boolean_policy, Mapping):
        claims.append(Claim("constraint_value", constraint, "booleanPolicy", is_list=False))
        claims.append(_enforcement_claim(
            constraint, "booleanPolicy", node, 0,
            dict(_ENFORCEMENT_DEFAULTS, enforce=_bool_or_none(boolean_policy, "enforced")),
            reset=_v1_reset(policy), inherit=None))
    list_policy = policy.get("listPolicy")
    if isinstance(list_policy, Mapping):
        claims.append(Claim("constraint_value", constraint, "listPolicy", is_list=True))
        all_values = list_policy.get("allValues")
        values, unreadable = _values_shape(list_policy, "listPolicy")
        claims.append(_enforcement_claim(
            constraint, "listPolicy", node, 0,
            dict(_ENFORCEMENT_DEFAULTS,
                 allow_all=True if all_values == "ALLOW" else None,
                 deny_all=True if all_values == "DENY" else None,
                 **values),
            reset=_v1_reset(policy),
            inherit=_bool_or_none(list_policy, "inheritFromParent",
                                  "inherit_from_parent"),
            unreadable=unreadable))

    # v2: each rule carries one value-type-bearing key; the spec-level reset /
    # inheritFromParent switches ride along on every rule's payload.
    rules = spec.get("rules") if spec is not None else None
    reset = _bool_or_none(spec, "reset") if spec is not None else None
    inherit = (_bool_or_none(spec, "inheritFromParent", "inherit_from_parent")
               if spec is not None else None)
    read_any_rule = False
    if isinstance(rules, list):
        for i, rule in enumerate(rules):
            location = f"spec.rules[{i}]"
            claim, skipped = _v2_rule_value_claim(constraint, rule, location)
            if claim is None:
                # A rule nobody could read is not a rule that sets nothing: the
                # skip travels as an abstain-carrying claim so the check can
                # name the location and the reason instead of staying silent.
                claims.append(_enforcement_claim(
                    constraint, location, node, i, dict(_ENFORCEMENT_DEFAULTS),
                    reset=reset, inherit=inherit, unreadable=(skipped,)))
                continue
            shape, unreadable = _v2_rule_shape(rule, location)
            claims.append(claim)
            claims.append(_enforcement_claim(constraint, location, node, i, shape,
                                             reset=reset, inherit=inherit,
                                             unreadable=unreadable))
            if not unreadable:
                read_any_rule = True
    elif spec is not None and rules is not None:
        claims.append(_enforcement_claim(
            constraint, "spec.rules", node, NO_RULE_INDEX,
            dict(_ENFORCEMENT_DEFAULTS), reset=reset, inherit=inherit,
            unreadable=(f"spec.rules is not an array, "
                        f"got {type(rules).__name__}",)))
    if spec is not None and not read_any_rule and (reset is True or inherit is True):
        # A spec that resets to the inherited default, or defers wholesale to
        # the parent, carries no rule to hang a claim off — yet those are two of
        # the three ways to stop enforcing a constraint. Record one claim
        # against the spec itself so the check can still see them. This is
        # INDEPENDENT of the rules array: an absent one, an empty one, an
        # unreadable one and one holding nothing but decoys all hide the
        # switches equally well. It is suppressed only when a rule of the
        # document's own was read, because that claim carries the same switches.
        claims.append(_enforcement_claim(constraint, "spec", node, NO_RULE_INDEX,
                                         dict(_ENFORCEMENT_DEFAULTS),
                                         reset=reset, inherit=inherit))
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


def _v2_rule_value_claim(constraint: str, rule: Any,
                         location: str) -> tuple[Claim | None, str | None]:
    """→ (the value-type claim, None), or (None, why the rule was skipped).

    Exactly one half is not None. The extractor is unchanged in what it accepts
    — it still refuses to guess at an ambiguous or malformed rule — but the
    refusal now carries a REASON out, because the caller has to say what it
    could not read rather than emitting nothing at all.
    """
    if not isinstance(rule, Mapping):
        logger.debug("%s is not an object — skipped", location)
        return None, f"{location} is not an object, got {type(rule).__name__}"
    typed = [k for k in (*_V2_BOOLEAN_KEYS, *_V2_LIST_KEYS) if k in rule]
    if len(typed) > 1:
        logger.debug("%s carries %d value-type keys (%s) — ambiguous, skipped",
                     location, len(typed), ", ".join(typed))
        return None, (f"{location} carries {len(typed)} value-type keys "
                      f"({', '.join(typed)}) at once, so which value type it "
                      f"sets is ambiguous")
    if not typed:
        logger.debug("%s carries no value-type key — skipped", location)
        return None, (f"{location} carries none of the value-type keys "
                      f"({', '.join((*_V2_BOOLEAN_KEYS, *_V2_LIST_KEYS))}), so "
                      f"what it sets could not be read")
    key = typed[0]
    value = rule[key]
    if key == "values":
        if not isinstance(value, Mapping):
            logger.debug("%s.values is not an object — skipped", location)
            return None, (f"{location}.values is not an object, "
                          f"got {type(value).__name__}")
        return Claim("constraint_value", constraint, f"{location}.values",
                     is_list=True), None
    if not isinstance(value, bool):
        logger.debug("%s.%s is not a boolean — skipped", location, key)
        return None, (f"{location}.{key} is not a boolean, "
                      f"got {type(value).__name__}")
    return Claim("constraint_value", constraint, f"{location}.{key}",
                 is_list=key in _V2_LIST_KEYS), None


# -- the enforcement payload (the values themselves) --------------------------


def _enforcement_claim(constraint: str, location: str, node: str,
                       rule_index: int | str,
                       shape: Mapping[str, Any], *, reset: bool | None,
                       inherit: bool | None,
                       unreadable: tuple[str, ...] = ()) -> Claim:
    """One ``constraint_enforcement`` claim: *shape*'s value fields plus the
    node, the rule index, the document-level reset/inherit switches and the
    reasons anything about the rule could not be read, all frozen into the
    payload so the values — and the holes in them — travel to the checker."""
    return Claim.of("constraint_enforcement", constraint, location,
                    node=node, rule_index=rule_index, reset=reset,
                    inherit_from_parent=inherit, unreadable=tuple(unreadable),
                    **shape)


def _v2_rule_shape(rule: Mapping[str, Any],
                   location: str) -> tuple[dict[str, Any], tuple[str, ...]]:
    """→ (a v2 rule's value fields, the reasons any of them was unreadable).

    Only reached for a rule the value-type extractor already accepted, so
    exactly one of the four keys is present and well-formed; the rest keep
    their "not stated" default. The ``values`` block's own lists are the one
    part that can still be malformed, and a malformation there is reported
    rather than folded into an empty list.
    """
    shape = dict(_ENFORCEMENT_DEFAULTS)
    if isinstance(rule.get("enforce"), bool):
        shape["enforce"] = rule["enforce"]
    if isinstance(rule.get("allowAll"), bool):
        shape["allow_all"] = rule["allowAll"]
    if isinstance(rule.get("denyAll"), bool):
        shape["deny_all"] = rule["denyAll"]
    values = rule.get("values")
    if not isinstance(values, Mapping):
        return shape, ()
    lists, unreadable = _values_shape(values, f"{location}.values")
    shape.update(lists)
    return shape, unreadable


def _values_shape(values: Mapping[str, Any],
                  location: str) -> tuple[dict[str, tuple[str, ...]], tuple[str, ...]]:
    """→ (the allowed/denied lists, the reasons either could not be read).

    Read from a v2 ``values`` block or a v1 ``listPolicy``, in either the REST
    (``allowedValues``) or the terraform (``allowed_values``) spelling;
    *location* is the json-path of the block itself, so a reason names the
    field a verdict must point at.
    """
    shape: dict[str, tuple[str, ...]] = {}
    unreadable: list[str] = []
    for field, keys in (("allowed_values", ("allowedValues", "allowed_values")),
                        ("denied_values", ("deniedValues", "denied_values"))):
        shape[field], reason = _string_tuple(values, keys, location)
        if reason is not None:
            unreadable.append(reason)
    return shape, tuple(unreadable)


def _string_tuple(mapping: Mapping[str, Any], keys: tuple[str, ...],
                  location: str) -> tuple[tuple[str, ...], str | None]:
    """→ (the non-empty string entries of the first of *keys* present in
    *mapping*, why anything was dropped).

    A non-array reads as NO values, and an entry that is not a non-empty string
    is dropped — but neither is silence any more: an empty tuple that came out
    of a malformed field is indistinguishable from one the document really set
    empty, and downstream that difference is a positive verdict against an
    abstention. The type guard is load-bearing in its own right: without it a
    string is iterated character by character. A reason names the spelling
    actually found under *location* — the REST one or the terraform one — so it
    points at a field the document really carries.
    """
    for key in keys:
        if key not in mapping:
            continue
        path = f"{location}.{key}"
        raw = mapping[key]
        if not isinstance(raw, list):
            logger.debug("%s is %s, not an array — no values read",
                         path, type(raw).__name__)
            return (), f"{path} is not an array, got {type(raw).__name__}"
        out = tuple(v for v in raw if isinstance(v, str) and v)
        if len(out) != len(raw):
            logger.debug("%s: %d of %d entries are not non-empty strings — dropped",
                         path, len(raw) - len(out), len(raw))
            return out, (f"{path}: {len(raw) - len(out)} of {len(raw)} entries "
                         f"are not non-empty strings")
        return out, None
    return (), None


def _bool_or_none(mapping: Mapping[str, Any], *keys: str) -> bool | None:
    """The first of *keys* whose value is a real boolean — else None, which
    reads as "the document does not state it", never as False."""
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, bool):
            return value
    return None


def _v1_reset(policy: Mapping[str, Any]) -> bool | None:
    """The v1 spelling of ``spec.reset``: a ``restoreDefault`` block restores
    the constraint's default, i.e. stops enforcing whatever was set here."""
    return True if isinstance(policy.get("restoreDefault"), Mapping) else None


def _org_policy_node(policy: Mapping[str, Any], location: str) -> str:
    """The resource node a v2 policy is set on — the ``name`` prefix before
    ``/policies/``. A v1 document names no node (its parent is the API call's,
    not the document's), so it yields ``""``."""
    if location != "name":
        return ""
    name = policy.get("name")
    if not isinstance(name, str):  # unreachable: _org_policy_constraint checked
        return ""
    return name.split("/policies/", 1)[0]
