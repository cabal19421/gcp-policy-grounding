"""Claim extraction: VPC Service Controls perimeters and access levels.

Two document kinds and five terraform resource types are grounded here, all
reduced to one NORMALIZED PERIMETER / access-level shape so a REST document
(Access Context Manager JSON, camelCase, single nested objects) and its
terraform spelling (``terraform show -json``, snake_case, nested *blocks*
encoded as single-element arrays) produce byte-identical claims.

Normalized perimeter (snake_case throughout):

- ``name``, ``perimeter_type``, ``use_explicit_dry_run_spec``
- ``status`` and ``spec``, each a config holding ``resources``,
  ``restricted_services``, ``access_levels``, ``ingress_policies`` and
  ``egress_policies``.

A normalized ingress policy is ``ingress_from`` (``identity_type``,
``identities``, ``sources`` — each source an ``access_level`` or a
``resource``) plus ``ingress_to`` (``resources``, ``operations`` — each an
``service_name`` and ``method_selectors`` of ``method`` or ``permission``).
An egress policy is the ``egress_from`` / ``egress_to`` analogue where
``egress_to`` additionally carries ``external_resources``.

Claims. A ``hierarchy_node_ref`` per ``status.resources`` / ``spec.resources``
entry; a ``restricted_service_ref`` per ``restricted_services`` entry; an
``access_level_ref`` per ``status.access_levels`` entry and per
``ingress_from.sources[].access_level``. Per ``identities`` entry, chosen by
prefix: ``serviceAccount:`` yields both a ``principal`` (full prefixed form)
and a ``service_account_ref`` (bare email); ``user:`` / ``group:`` yields a
``principal``; ``allUsers`` / ``allAuthenticatedUsers`` yields a
``public_principal`` with ``polarity="grant"``. One ``perimeter_config`` claim
carrying the whole normalized perimeter, and one ``perimeter_ingress`` /
``perimeter_egress`` claim per policy carrying the normalized policy plus its
``perimeter`` and ``index``.

A ``perimeter_ref`` is emitted ONLY by documents that *reference* an existing
perimeter (the ``_service_perimeter_resource``, ``_ingress_policy`` and
``_egress_policy`` terraform resources); a ``google_access_context_manager_
service_perimeter`` resource is *creating* the perimeter and emits none for
itself, exactly as ``google_project_iam_custom_role`` emits no ``role`` for the
role it creates. For an access-level document no ``access_level_ref`` is
emitted for the level being created and no ``restricted_service_ref`` at all; a
``cel`` claim is emitted for a ``custom.expr.expression`` only when it passes
the shared :data:`~gcp_grounding.claims._RUNTIME_ONLY_MARKERS` screen.

Wildcards are preserved verbatim in the payload and never expanded, and never
yield an existence claim: ``"*"`` in ``resources`` / ``external_resources``, an
``identity_type`` of ``ANY_IDENTITY`` / ``ANY_USER_ACCOUNT`` /
``ANY_SERVICE_ACCOUNT``, a ``service_name`` of ``"*"`` and a ``method`` of
``"*"``.
"""

from __future__ import annotations

from typing import Any, Mapping

from .claims import Claim, _RUNTIME_ONLY_MARKERS
from .core.log import get_logger

logger = get_logger(__name__)

__all__ = ["DOCUMENT_EXTRACTORS", "TF_EXTRACTORS",
           "perimeter_claims", "access_level_claims"]

#: Prefixes that name estate principals, mirroring
#: :data:`gcp_grounding.claims._PRINCIPAL_PREFIXES` for the subset VPC-SC
#: identities use (``domain:`` is not a VPC-SC identity form).
_SA_PREFIX = "serviceAccount:"
_PRINCIPAL_PREFIXES = ("user:", "group:")
_PUBLIC_IDENTITIES = ("allUsers", "allAuthenticatedUsers")


# -- REST / terraform key access ----------------------------------------------


def _camel(snake: str) -> str:
    """``restricted_services`` → ``restrictedServices``: the REST spelling of a
    normalized snake_case field name."""
    head, *tail = snake.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in tail)


def _get(obj: Any, snake: str) -> Any:
    """The value of *snake* on *obj*, accepting either the terraform snake_case
    key or the REST camelCase spelling; None when *obj* is not a mapping or the
    field is absent."""
    if not isinstance(obj, Mapping):
        return None
    if snake in obj:
        return obj[snake]
    camel = _camel(snake)
    if camel in obj:
        return obj[camel]
    return None


def _obj(value: Any) -> Mapping[str, Any] | None:
    """A single nested block: a REST bare object, or the first element of a
    terraform single-element block array. Anything else → None."""
    if isinstance(value, Mapping):
        return value
    if isinstance(value, list) and value and isinstance(value[0], Mapping):
        return value[0]
    return None


def _obj_list(value: Any) -> list[Mapping[str, Any]]:
    """Every object of a repeated block / list: REST and terraform both encode
    these as a list of objects. A bare mapping is accepted as a one-element
    list; anything else is empty."""
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _str_list(value: Any) -> list[str]:
    """The string entries of a list attribute, preserving order and wildcards
    (``"*"``) verbatim; non-strings are dropped."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _scalar(value: Any) -> str | None:
    """A non-empty string, or None. Terraform emits unset string attributes as
    ``""``; those read as absent so REST and terraform normalize alike."""
    return value if isinstance(value, str) and value != "" else None


def _bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


# -- normalization ------------------------------------------------------------


def _normalize_perimeter(raw: Mapping[str, Any]) -> dict[str, Any]:
    """One perimeter — REST or terraform — reduced to the normalized shape."""
    return {
        "name": _scalar(_get(raw, "name")),
        "perimeter_type": _scalar(_get(raw, "perimeter_type")),
        "use_explicit_dry_run_spec": _bool(_get(raw, "use_explicit_dry_run_spec")),
        "status": _normalize_config(_get(raw, "status")),
        "spec": _normalize_config(_get(raw, "spec")),
    }


def _normalize_config(raw: Any) -> dict[str, Any] | None:
    obj = _obj(raw)
    if obj is None:
        return None
    return {
        "resources": _str_list(_get(obj, "resources")),
        "restricted_services": _str_list(_get(obj, "restricted_services")),
        "access_levels": _str_list(_get(obj, "access_levels")),
        "ingress_policies": [_normalize_ingress(p)
                             for p in _obj_list(_get(obj, "ingress_policies"))],
        "egress_policies": [_normalize_egress(p)
                            for p in _obj_list(_get(obj, "egress_policies"))],
    }


def _normalize_ingress(raw: Any) -> dict[str, Any]:
    obj = _obj(raw) or {}
    return {
        "ingress_from": _normalize_from(_get(obj, "ingress_from")),
        "ingress_to": _normalize_to(_get(obj, "ingress_to"), external=False),
    }


def _normalize_egress(raw: Any) -> dict[str, Any]:
    obj = _obj(raw) or {}
    return {
        "egress_from": _normalize_from(_get(obj, "egress_from")),
        "egress_to": _normalize_to(_get(obj, "egress_to"), external=True),
    }


def _normalize_from(raw: Any) -> dict[str, Any]:
    obj = _obj(raw) or {}
    return {
        "identity_type": _scalar(_get(obj, "identity_type")),
        "identities": _str_list(_get(obj, "identities")),
        "sources": [_normalize_source(s) for s in _obj_list(_get(obj, "sources"))],
    }


def _normalize_source(raw: Any) -> dict[str, str]:
    obj = _obj(raw) or {}
    source: dict[str, str] = {}
    access_level = _scalar(_get(obj, "access_level"))
    if access_level is not None:
        source["access_level"] = access_level
    resource = _scalar(_get(obj, "resource"))
    if resource is not None:
        source["resource"] = resource
    return source


def _normalize_to(raw: Any, *, external: bool) -> dict[str, Any]:
    obj = _obj(raw) or {}
    to: dict[str, Any] = {
        "resources": _str_list(_get(obj, "resources")),
        "operations": [_normalize_operation(o)
                       for o in _obj_list(_get(obj, "operations"))],
    }
    if external:
        to["external_resources"] = _str_list(_get(obj, "external_resources"))
    return to


def _normalize_operation(raw: Any) -> dict[str, Any]:
    obj = _obj(raw) or {}
    return {
        "service_name": _scalar(_get(obj, "service_name")),
        "method_selectors": [_normalize_selector(s)
                             for s in _obj_list(_get(obj, "method_selectors"))],
    }


def _normalize_selector(raw: Any) -> dict[str, str]:
    obj = _obj(raw) or {}
    selector: dict[str, str] = {}
    method = _scalar(_get(obj, "method"))
    if method is not None:
        selector["method"] = method
    permission = _scalar(_get(obj, "permission"))
    if permission is not None:
        selector["permission"] = permission
    return selector


# -- claim emission from a normalized perimeter -------------------------------


def _at(prefix: str, path: str) -> str:
    return f"{prefix}.{path}" if prefix else path


def _perimeter_claims(perimeter: Mapping[str, Any], prefix: str) -> list[Claim]:
    """Every claim a whole perimeter (already normalized) makes; *prefix* is the
    location root ("" for a REST document, the resource address for terraform)."""
    name = perimeter.get("name") or ""
    claims: list[Claim] = [Claim.of(
        "perimeter_config", name, prefix or (name or "servicePerimeter"),
        name=perimeter.get("name"),
        perimeter_type=perimeter.get("perimeter_type"),
        use_explicit_dry_run_spec=perimeter.get("use_explicit_dry_run_spec"),
        status=perimeter.get("status"),
        spec=perimeter.get("spec"),
    )]
    for kind in ("status", "spec"):
        config = perimeter.get(kind)
        if not config:
            continue
        base = _at(prefix, kind)
        for i, resource in enumerate(config.get("resources") or []):
            if resource == "*":
                continue  # a wildcard is not a groundable hierarchy node
            claims.append(Claim("hierarchy_node_ref", resource,
                                f"{base}.resources[{i}]"))
        for i, service in enumerate(config.get("restricted_services") or []):
            if service == "*":
                continue
            claims.append(Claim("restricted_service_ref", service,
                                f"{base}.restricted_services[{i}]"))
        if kind == "status":
            for i, level in enumerate(config.get("access_levels") or []):
                claims.append(Claim("access_level_ref", level,
                                    f"{base}.access_levels[{i}]"))
        for i, policy in enumerate(config.get("ingress_policies") or []):
            claims.extend(_policy_claims(policy, "ingress", name, i,
                                         f"{base}.ingress_policies[{i}]"))
        for i, policy in enumerate(config.get("egress_policies") or []):
            claims.extend(_policy_claims(policy, "egress", name, i,
                                         f"{base}.egress_policies[{i}]"))
    return claims


def _policy_claims(policy: Mapping[str, Any], direction: str, perimeter: str,
                   index: int, prefix: str) -> list[Claim]:
    """Claims for one normalized ingress/egress policy at location *prefix*."""
    from_key = f"{direction}_from"
    claims: list[Claim] = [Claim.of(
        f"perimeter_{direction}", perimeter, prefix,
        perimeter=perimeter, index=index, **policy)]
    frm = policy.get(from_key) or {}
    for i, source in enumerate(frm.get("sources") or []):
        level = source.get("access_level")
        if level:
            claims.append(Claim("access_level_ref", level,
                                f"{prefix}.{from_key}.sources[{i}].access_level"))
    for i, identity in enumerate(frm.get("identities") or []):
        claims.extend(_identity_claims(
            identity, f"{prefix}.{from_key}.identities[{i}]"))
    return claims


def _identity_claims(identity: Any, location: str) -> list[Claim]:
    """Principal-family claims for one identity, chosen by prefix. An identity
    the snapshot cannot enumerate (federated principals, ``deleted:…``) is
    skipped, never guessed at, exactly as in :mod:`gcp_grounding.claims`."""
    if not isinstance(identity, str) or not identity:
        return []
    if identity.startswith(_SA_PREFIX):
        claims = [Claim("principal", identity, location)]
        email = identity[len(_SA_PREFIX):]
        if email:
            claims.append(Claim("service_account_ref", email, location))
        return claims
    if identity.startswith(_PRINCIPAL_PREFIXES):
        return [Claim("principal", identity, location)]
    if identity in _PUBLIC_IDENTITIES:
        return [Claim.of("public_principal", identity, location, polarity="grant")]
    logger.debug("identity %r is not an estate principal — skipped", identity)
    return []


# -- document extractors ------------------------------------------------------


def perimeter_claims(document: Mapping[str, Any]) -> list[Claim]:
    """Claims made by one Access Context Manager service-perimeter REST document.

    A perimeter document describes the perimeter it *is*, so it emits no
    ``perimeter_ref`` for itself.
    """
    if not isinstance(document, Mapping):
        raise ValueError(f"perimeter must be a mapping, got {type(document).__name__}")
    return _perimeter_claims(_normalize_perimeter(document), "")


def access_level_claims(document: Mapping[str, Any]) -> list[Claim]:
    """Claims made by one Access Context Manager access-level REST document.

    The level being created is not itself grounded (no ``access_level_ref``);
    a custom-level ``custom.expr.expression`` yields a ``cel`` claim only when
    it is offline-decidable, and there is no ``restricted_service_ref``.
    """
    if not isinstance(document, Mapping):
        raise ValueError(f"access level must be a mapping, got {type(document).__name__}")
    return _access_level_claims(document, "")


def _access_level_claims(values: Mapping[str, Any], prefix: str) -> list[Claim]:
    custom = _obj(_get(values, "custom"))
    if custom is None:
        return []
    expr = _obj(_get(custom, "expr"))
    if expr is None:
        return []
    expression = _scalar(_get(expr, "expression"))
    if expression is None or not expression.strip():
        return []
    if any(marker in expression for marker in _RUNTIME_ONLY_MARKERS):
        logger.debug("access-level expression references runtime-only attributes "
                     "— skipped, not guessed at")
        return []
    return [Claim("cel", expression, _at(prefix, "custom.expr.expression"))]


# -- terraform resource extractors --------------------------------------------


def _tf_perimeter(address: str, values: Mapping[str, Any]) -> list[Claim]:
    return _perimeter_claims(_normalize_perimeter(values), address)


def _tf_perimeter_resource(address: str, values: Mapping[str, Any]) -> list[Claim]:
    claims: list[Claim] = []
    perimeter = _scalar(_get(values, "perimeter_name"))
    if perimeter is not None:
        claims.append(Claim("perimeter_ref", perimeter, f"{address}.perimeter_name"))
    resource = _scalar(_get(values, "resource"))
    if resource is not None and resource != "*":
        claims.append(Claim("hierarchy_node_ref", resource, f"{address}.resource"))
    return claims


def _tf_ingress_policy(address: str, values: Mapping[str, Any]) -> list[Claim]:
    return _tf_policy(address, values, "ingress")


def _tf_egress_policy(address: str, values: Mapping[str, Any]) -> list[Claim]:
    return _tf_policy(address, values, "egress")


def _tf_policy(address: str, values: Mapping[str, Any], direction: str) -> list[Claim]:
    claims: list[Claim] = []
    perimeter = _scalar(_get(values, "perimeter"))
    if perimeter is not None:
        claims.append(Claim("perimeter_ref", perimeter, f"{address}.perimeter"))
    normalize = _normalize_ingress if direction == "ingress" else _normalize_egress
    claims.extend(_policy_claims(normalize(values), direction, perimeter or "",
                                 0, address))
    return claims


def _tf_access_level(address: str, values: Mapping[str, Any]) -> list[Claim]:
    return _access_level_claims(values, address)


# -- registry wiring ----------------------------------------------------------

DOCUMENT_EXTRACTORS = {
    "vpc_sc_perimeter": perimeter_claims,
    "access_level": access_level_claims,
}

TF_EXTRACTORS = {
    "google_access_context_manager_service_perimeter": _tf_perimeter,
    "google_access_context_manager_service_perimeter_resource": _tf_perimeter_resource,
    "google_access_context_manager_service_perimeter_ingress_policy": _tf_ingress_policy,
    "google_access_context_manager_service_perimeter_egress_policy": _tf_egress_policy,
    "google_access_context_manager_access_level": _tf_access_level,
}
