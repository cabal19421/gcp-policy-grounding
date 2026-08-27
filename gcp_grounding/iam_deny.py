"""Claim extraction for IAM v2 deny policies (``policies.denypolicies``).

``README.md`` and :mod:`~gcp_grounding.claims` both promise "allow/deny", but
until now no code path ever parsed a deny policy: :func:`detect_kind` did not
classify it and it emitted zero claims — a silent pass on a real policy
artifact. ``sx-detect-kind`` added the ``iam_deny_policy`` document kind; this
module is the extractor it routes to, wired into
:func:`gcp_grounding.preflight.ground_policy` through the lazy provider
:mod:`~gcp_grounding.registry`.

DOCUMENT SHAPE — the v2 form has a top-level ``name`` such as
``policies/cloudresourcemanager.googleapis.com%2Fprojects%2Facme-prod/denypolicies/block-sa-keys``
and a ``rules`` list whose items each carry a ``denyRule`` object with
``deniedPrincipals``, ``exceptionPrincipals``, ``deniedPermissions``,
``exceptionPermissions`` and ``denialCondition.expression``. The Terraform
``google_iam_deny_policy`` spelling uses ``rules[].deny_rule`` with snake_case
field names (and, in plan JSON, repeated blocks encoded as single-element
arrays); both spellings are accepted and normalize to identical claims with
camelCase ``location`` paths.

CLAIMS per rule (``location`` of the form ``rules[<i>].denyRule.<field>[<j>]``):

- ``deniedPrincipals`` / ``exceptionPrincipals`` — a prefixed member yields a
  ``principal`` claim (grounded against the estate principals like any binding
  member); ``allUsers`` / ``allAuthenticatedUsers`` yield a ``public_principal``
  claim with ``polarity="deny"`` (in a deny policy a DENIED public principal is
  a guardrail, and the polarity key is what stops the IAM public-principal check
  from flagging it) plus ``excepted``, which says which of the two fields it
  came from — an EXCEPTED public principal is a bypass, not a guardrail, and
  polarity alone cannot tell the two apart because both fields run through one
  branch; anything else yields ``unmodelled_principal``. Every entry of
  ``deniedPrincipals`` additionally yields a ``denied_principal`` claim carrying
  ``rule_index`` for the escalation check in :mod:`~gcp_grounding.iam_checks`.
- ``deniedPermissions`` / ``exceptionPermissions`` — the service-qualified form
  ``iam.googleapis.com/roles.update``. Each entry always yields a
  ``denied_permission`` claim carrying ``rule_index`` and ``excepted``.
  Additionally, when the rewrite is unambiguous, a plain ``permission``
  existence claim with the normalized short form (``iam.roles.update``): split
  on the single ``/``, take the host's first label as the service prefix, and
  join. The existence claim is skipped (debug-logged) when the string contains a
  wildcard, has no ``/``, has more than one ``/``, or the host has no dot —
  guessing a permission name there would manufacture a false ``ungrounded``.
- ``denialCondition.expression`` — screened by the exact IAM-Condition marker
  list (:data:`gcp_grounding.claims._RUNTIME_ONLY_MARKERS`): a ``cel`` claim is
  emitted only when no runtime-only marker matches, so :func:`check_cel` decides
  the window's satisfiability with the existing translator.

The document's own ``name`` yields no claim — the deny policy is being created.

MALFORMED SHAPES follow the conservative-skip rule: a ``rules`` entry that is
not a mapping, a ``denyRule`` that is not a mapping, or a non-list principal or
permission field is skipped with a debug log. A recognized deny policy that
yields zero claims is caught by preflight's existing zero-claims-honesty guard,
which records an ``unverified`` — this module does not duplicate that logic.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any, Mapping

from .claims import (PUBLIC_PRINCIPALS, Claim, _PRINCIPAL_PREFIXES,
                     _RUNTIME_ONLY_MARKERS)
from .core.log import get_logger

logger = get_logger(__name__)

__all__ = ["DOCUMENT_EXTRACTORS", "TF_EXTRACTORS", "iam_deny_policy_claims"]

# -- the claim-location grammar, written once ---------------------------------
#
# The locations this module anchors claims at, as regexes the consumers group
# by (`sec_domains`' deny collections and `iam_deny_checks`' coverage walk are
# both thin over these — defining them beside the extractor is what stops the
# two growing a second, drifting spelling). Matched against the WHOLE location
# with the head captured, so a terraform prefix is kept and two resources'
# rule 0 stay apart — the `iam_checks._rule_prefix` convention.

DENIED_PRINCIPAL_AT = re.compile(
    r"^(?P<head>.*)rules\[(?P<i>\d+)\]\.denyRule\.deniedPrincipals\[(?P<j>\d+)\]$")
EXCEPTION_PRINCIPAL_AT = re.compile(
    r"^(?P<head>.*)rules\[(?P<i>\d+)\]\.denyRule\.exceptionPrincipals\[(?P<j>\d+)\]$")
DENIED_PERMISSION_AT = re.compile(
    r"^(?P<head>.*)rules\[(?P<i>\d+)\]\.denyRule\.deniedPermissions\[(?P<j>\d+)\]$")
EXCEPTION_PERMISSION_AT = re.compile(
    r"^(?P<head>.*)rules\[(?P<i>\d+)\]\.denyRule\.exceptionPermissions\[(?P<j>\d+)\]$")

#: The plan-side census: deny-policy resource addresses a deny-collection
#: extraction is responsible for, mirroring ``sec_domains._IAM_BINDING_ADDRESS``.
#: A plan block of this type that yielded NO deny claim must abstain by name —
#: a policy whose rules were stripped or malformed denies nobody nobody read.
DENY_POLICY_ADDRESS = re.compile(r"^google_iam_deny_policy\.[^.]+$")

#: (canonical location field, accepted spellings, emit ``denied_principal``?).
#: Only ``deniedPrincipals`` entries additionally get a ``denied_principal``
#: claim; ``exceptionPrincipals`` carve out of the denial, so they do not.
_PRINCIPAL_FIELDS = (
    ("deniedPrincipals", ("deniedPrincipals", "denied_principals"), True),
    ("exceptionPrincipals", ("exceptionPrincipals", "exception_principals"), False),
)

#: (canonical location field, accepted spellings, ``excepted`` flag). The flag
#: rides on every ``denied_permission`` claim so the escalation check can tell a
#: real denial from a carve-out.
_PERMISSION_FIELDS = (
    ("deniedPermissions", ("deniedPermissions", "denied_permissions"), False),
    ("exceptionPermissions", ("exceptionPermissions", "exception_permissions"), True),
)

_DENY_RULE_KEYS = ("denyRule", "deny_rule")
_DENIAL_CONDITION_KEYS = ("denialCondition", "denial_condition")


def iam_deny_policy_claims(policy: Mapping[str, Any]) -> list[Claim]:
    """Claims made by one IAM v2 deny policy (``policies.denypolicies`` JSON).

    Accepts both the REST camelCase spelling and the Terraform snake_case /
    block-array spelling; both normalize to identical claims.
    """
    if not isinstance(policy, Mapping):
        raise ValueError(f"IAM deny policy must be a mapping, got {type(policy).__name__}")
    claims: list[Claim] = []
    rules = policy.get("rules")
    if not isinstance(rules, list):
        if rules is not None:
            logger.debug("deny policy 'rules' is %s, not an array — no claims",
                         type(rules).__name__)
        return claims
    for i, rule in enumerate(rules):
        if not isinstance(rule, Mapping):
            logger.debug("rules[%d] is not an object — skipped", i)
            continue
        deny_rule = _as_mapping(_get(rule, _DENY_RULE_KEYS))
        if deny_rule is None:
            logger.debug("rules[%d].denyRule is not an object — skipped", i)
            continue
        base = f"rules[{i}].denyRule"
        _principal_claims(deny_rule, i, base, claims)
        _permission_claims(deny_rule, i, base, claims)
        _condition_claim(deny_rule, base, claims)
    return claims


def _principal_claims(deny_rule: Mapping[str, Any], i: int, base: str,
                      claims: list[Claim]) -> None:
    for field, spellings, is_denied in _PRINCIPAL_FIELDS:
        members = _get(deny_rule, spellings)
        if members is None:
            continue
        if not isinstance(members, list):
            logger.debug("%s.%s is not an array — skipped", base, field)
            continue
        for j, member in enumerate(members):
            loc = f"{base}.{field}[{j}]"
            if isinstance(member, str) and member.startswith(_PRINCIPAL_PREFIXES):
                claims.append(Claim("principal", member, loc))
            elif member in PUBLIC_PRINCIPALS:
                # polarity="deny" says this came from a deny policy rather than
                # a grant; `excepted` says WHICH of the two fields above it came
                # from, mirroring the flag already set on permission claims.
                # Both principal fields run through this one branch, so without
                # the second key an EXCEPTED allUsers — a bypass of the denial —
                # is indistinguishable from a denied one, which is a guardrail.
                claims.append(Claim.of("public_principal", member, loc,
                                       polarity="deny", excepted=not is_denied))
            else:
                logger.debug("%s (%r) is not an estate principal — recorded as "
                             "unmodelled", loc, member)
                claims.append(Claim("unmodelled_principal", str(member), loc))
            if is_denied:
                claims.append(Claim.of("denied_principal", str(member), loc,
                                       rule_index=i))


def _permission_claims(deny_rule: Mapping[str, Any], i: int, base: str,
                       claims: list[Claim]) -> None:
    for field, spellings, excepted in _PERMISSION_FIELDS:
        permissions = _get(deny_rule, spellings)
        if permissions is None:
            continue
        if not isinstance(permissions, list):
            logger.debug("%s.%s is not an array — skipped", base, field)
            continue
        for j, permission in enumerate(permissions):
            loc = f"{base}.{field}[{j}]"
            if not isinstance(permission, str) or not permission:
                logger.debug("%s (%r) is not a permission name — skipped", loc, permission)
                continue
            claims.append(Claim.of("denied_permission", permission, loc,
                                   rule_index=i, excepted=excepted))
            normalized = _normalize_permission(permission)
            if normalized is not None:
                claims.append(Claim("permission", normalized, loc))
            else:
                logger.debug("%s: %r is not an unambiguous service-qualified "
                             "permission — no existence claim, not guessed at",
                             loc, permission)


def _condition_claim(deny_rule: Mapping[str, Any], base: str,
                     claims: list[Claim]) -> None:
    condition = _as_mapping(_get(deny_rule, _DENIAL_CONDITION_KEYS))
    if condition is None:
        return
    expression = condition.get("expression")
    loc = f"{base}.denialCondition.expression"
    if not isinstance(expression, str) or not expression.strip():
        logger.debug("%s has no expression — skipped", loc)
        return
    if any(marker in expression for marker in _RUNTIME_ONLY_MARKERS):
        logger.debug("%s references runtime-only attributes — skipped, not "
                     "guessed at", loc)
        return
    claims.append(Claim("cel", expression, loc))


def _normalize_permission(permission: str) -> str | None:
    """The normalized short form of a service-qualified deny permission, or None
    when the rewrite is ambiguous.

    ``iam.googleapis.com/roles.update`` → ``iam.roles.update``. None (skip) when
    the string has a wildcard, no ``/``, more than one ``/``, or a host with no
    dot — the exact conditions under which a normalized name would be a guess.
    """
    if "*" in permission:
        return None
    if permission.count("/") != 1:
        return None
    host, rest = permission.split("/", 1)
    if "." not in host:
        return None
    service = host.split(".", 1)[0]
    return f"{service}.{rest}"


def _get(mapping: Mapping[str, Any], spellings: tuple[str, ...]) -> Any:
    """The first present *spelling* of a field, or None."""
    for key in spellings:
        if key in mapping:
            return mapping[key]
    return None


def _as_mapping(value: Any) -> Mapping[str, Any] | None:
    """A block value as a mapping: a bare object, or the single element of a
    one-item block array (how Terraform plan JSON encodes a repeated block).
    Any other shape (a non-mapping, an empty or multi-item list) → None."""
    if isinstance(value, Mapping):
        return value
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], Mapping):
        return value[0]
    return None


def _tf_deny_policy_claims(address: str, values: Mapping[str, Any]) -> list[Claim]:
    """Claims for a ``google_iam_deny_policy`` terraform resource.

    The plan ``values`` carry the same rule shape as the API document (snake_case
    fields, blocks as single-element arrays), so the document walker handles it;
    the synthetic ``rules[...]`` locations are re-anchored onto the resource
    *address*."""
    return [replace(claim, location=f"{address}.{claim.location}")
            for claim in iam_deny_policy_claims(values)]


#: Registry hooks consulted by :mod:`gcp_grounding.preflight` /
#: :mod:`gcp_grounding.tf_claims` — see :mod:`gcp_grounding.registry`.
DOCUMENT_EXTRACTORS = {"iam_deny_policy": iam_deny_policy_claims}
TF_EXTRACTORS = {"google_iam_deny_policy": _tf_deny_policy_claims}
