"""Claim extraction: Cloud Armor security policies and rules → grounding claims.

A Cloud Armor *security policy* is an ordered list of rules, each a
``priority`` / ``action`` / ``preview`` triple plus a ``match`` deciding which
requests it fires on. This module normalises both spellings of that record —
the REST ``rules[]`` shape and the two Terraform resources — into the ONE field
layout the :mod:`~gcp_grounding.knowledge` estate table uses for
``cloud_armor_policies[].rules[]`` (``priority`` int, ``action`` str,
``preview`` bool, and ``match`` with ``src_ip_ranges`` /  ``versioned_expr`` /
``expr``), so a proposal rule and a captured rule are directly comparable.

Two rule spellings, one normal form:

- REST: ``rules[].match.versionedExpr`` + ``rules[].match.config.srcIpRanges``,
  or ``rules[].match.expr.expression``.
- Terraform ``google_compute_security_policy`` nests repeated ``rule`` blocks,
  each with a repeated ``match`` block containing a repeated ``config`` block —
  walked with :func:`gcp_grounding.tf_claims._blocks` /
  :func:`~gcp_grounding.tf_claims._first_block` at every level.
- Terraform ``google_compute_security_policy_rule`` is a standalone resource
  carrying one rule plus a ``security_policy`` attribute naming its policy.

The default rule sits at priority ``2147483647``; its ``config.srcIpRanges`` is
conventionally ``["*"]``, which normalises to the single range ``0.0.0.0/0``,
and its payload records ``"is_default": True``.

Claims. A full ``google_compute_security_policy`` / REST policy emits one
``security_policy_rule`` claim per rule — payload = the normalised rule plus the
``policy`` name, ``rule_count`` and ``has_default`` — and NO ``security_policy_ref``
for itself. The FIRST rule claim of such a document additionally carries
``"policy_document": True`` so :mod:`~gcp_grounding.armor_checks` knows the
default-rule check applies. A standalone ``google_compute_security_policy_rule``
emits one ``security_policy_rule`` claim plus one ``security_policy_ref`` claim
for its ``security_policy`` attribute (skipped when that attribute is an
unresolved interpolation), and never sets ``policy_document``.

For a rule whose ``match`` uses ``expr``, the payload additionally records
``referenced_expr_ids`` via :func:`gcp_grounding.armor_expr.referenced_expr_ids`
— guarded by ``try/except`` (its module may be absent, or the expression
unparseable) so a bad expression records ``"unsupported": "expression could not
be scanned"`` rather than breaking extraction.

Unsupported shapes use the shared ``"unsupported": "<reason>"`` payload
convention rather than a dropped claim: a non-integer priority, an ``action``
outside the eight known verbs, a ``match`` carrying neither
``config.srcIpRanges`` nor ``expr``, or a ``match`` setting both a
``versionedExpr`` and an ``expr``. A dropped rule would let a check fabricate a
verdict from an incomplete picture; a claim marked unsupported abstains
honestly.
"""

from __future__ import annotations

from typing import Any, Mapping

from .claims import Claim
from .core.log import get_logger
from .tf_claims import _blocks, _first_block

logger = get_logger(__name__)

__all__ = [
    "DEFAULT_RULE_PRIORITY", "security_policy_claims",
    "DOCUMENT_EXTRACTORS", "TF_EXTRACTORS",
]

#: The reserved priority of a security policy's default rule.
DEFAULT_RULE_PRIORITY = 2147483647

#: The action verbs a security-policy rule may carry. Anything else is recorded
#: ``unsupported`` rather than guessed at — an unknown action could allow or
#: deny, and the encoding must not pick one.
_ACTIONS = frozenset({
    "allow", "deny", "deny-403", "deny-404", "deny-502",
    "rate_based_ban", "throttle", "redirect",
})


# -- normalisation (shared by every spelling) ---------------------------------


def _normalize_src_ip_ranges(ranges: Any) -> list[str]:
    """The source CIDRs of a rule's ``config``, with the ``"*"`` wildcard mapped
    to ``0.0.0.0/0``. Non-string entries pass through untouched — normalising is
    not this module's job to validate CIDR syntax."""
    out: list[str] = []
    for item in ranges:
        out.append("0.0.0.0/0" if item == "*" else item)
    return out


def _normalize_rule(*, priority: Any, action: Any, preview: Any,
                    versioned_expr: Any, expr_expression: Any,
                    src_ip_ranges: Any) -> dict[str, Any]:
    """One rule's parsed parts → its normal form, or ``{"unsupported": …}``.

    ``src_ip_ranges`` is the ``config.srcIpRanges`` list when present, else
    None; ``expr_expression`` the ``expr.expression`` string when present, else
    None. The result is identical for the REST and Terraform spellings — that
    is what makes the two agree — and carries ``is_default`` only at the
    reserved default priority."""
    if not isinstance(priority, int) or isinstance(priority, bool):
        return {"unsupported": "priority is not an integer"}
    if not isinstance(action, str) or action not in _ACTIONS:
        return {"unsupported": f"action {action!r} is outside the supported set"}
    has_config = isinstance(src_ip_ranges, list)
    has_expr = expr_expression is not None
    if versioned_expr is not None and has_expr:
        return {"unsupported": "match sets both a versionedExpr and an expr"}
    if not has_config and not has_expr:
        return {"unsupported": "match carries neither config.srcIpRanges nor expr"}
    match = {
        "src_ip_ranges": _normalize_src_ip_ranges(src_ip_ranges) if has_config else [],
        "versioned_expr": versioned_expr if isinstance(versioned_expr, str) else None,
        "expr": expr_expression if isinstance(expr_expression, str) else None,
    }
    rule: dict[str, Any] = {
        "priority": priority,
        "action": action,
        "preview": bool(preview),
        "match": match,
    }
    if priority == DEFAULT_RULE_PRIORITY:
        rule["is_default"] = True
    return rule


def _referenced_expr_ids(expression: str) -> dict[str, Any]:
    """The ``referenced_expr_ids`` payload fragment for an ``expr`` rule, or an
    ``unsupported`` marker when the expression cannot be scanned.

    :mod:`~gcp_grounding.armor_expr` may not be part of this checkout and an
    expression may be malformed; both degrade to the honest ``unsupported``
    convention rather than breaking extraction (a scan that returns no ids is a
    different, legitimate outcome — an empty tuple)."""
    try:
        from . import armor_expr  # lazy: its module may be absent
        return {"referenced_expr_ids": list(armor_expr.referenced_expr_ids(expression))}
    except Exception:  # noqa: BLE001 — never break extraction on a bad expr
        logger.debug("expression %r could not be scanned for expr ids", expression,
                     exc_info=True)
        return {"unsupported": "expression could not be scanned"}


# -- parsing each spelling into the shared normal form ------------------------


def _parse_rest_rule(rule: Any, location: str) -> tuple[Any, dict[str, Any], Any, str]:
    """A REST ``rules[]`` record → (raw priority, normalised rule, raw expr
    expression, location)."""
    if not isinstance(rule, Mapping):
        return None, {"unsupported": "rule is not an object"}, None, location
    match = rule.get("match")
    match = match if isinstance(match, Mapping) else {}
    config = match.get("config")
    src_ip_ranges = config.get("srcIpRanges") if isinstance(config, Mapping) else None
    expr = match.get("expr")
    expr_expression = expr.get("expression") if isinstance(expr, Mapping) else None
    priority = rule.get("priority")
    normalized = _normalize_rule(
        priority=priority, action=rule.get("action"), preview=rule.get("preview"),
        versioned_expr=match.get("versionedExpr"), expr_expression=expr_expression,
        src_ip_ranges=src_ip_ranges)
    return priority, normalized, expr_expression, location


def _parse_tf_rule(rule: Any, location: str) -> tuple[Any, dict[str, Any], Any, str]:
    """A Terraform rule block (nested in a policy, or a standalone resource's own
    attributes) → (raw priority, normalised rule, raw expr expression,
    location). Repeated ``match`` / ``config`` / ``expr`` blocks are read with
    the plan-JSON block helpers, taking the first of each."""
    if not isinstance(rule, Mapping):
        return None, {"unsupported": "rule is not an object"}, None, location
    match, _ = _first_block(rule.get("match"), "match")
    match = match if match is not None else {}
    config, _ = _first_block(match.get("config"), "config")
    src_ip_ranges = config.get("src_ip_ranges") if config is not None else None
    expr, _ = _first_block(match.get("expr"), "expr")
    expr_expression = expr.get("expression") if expr is not None else None
    priority = rule.get("priority")
    normalized = _normalize_rule(
        priority=priority, action=rule.get("action"), preview=rule.get("preview"),
        versioned_expr=match.get("versioned_expr"), expr_expression=expr_expression,
        src_ip_ranges=src_ip_ranges)
    return priority, normalized, expr_expression, location


# -- claim assembly -----------------------------------------------------------


def _rule_claim(policy: str, location: str, normalized: dict[str, Any],
                expr_expression: Any, extra: Mapping[str, Any]) -> Claim:
    """One ``security_policy_rule`` claim: the normalised rule, the document
    context in *extra*, and — for a supported ``expr`` rule — its referenced
    expression ids (or an ``unsupported`` marker)."""
    payload: dict[str, Any] = {**normalized, **extra}
    if expr_expression is not None and "unsupported" not in normalized:
        payload.update(_referenced_expr_ids(expr_expression))
    return Claim.of("security_policy_rule", policy, location, **payload)


def _policy_name(doc: Mapping[str, Any]) -> str | None:
    name = doc.get("name")
    return name if isinstance(name, str) and name else None


def _full_policy_claims(parsed: list[tuple[Any, dict[str, Any], Any, str]],
                        policy: str | None) -> list[Claim]:
    """The per-rule claims for a whole policy document: every rule carries the
    ``policy`` name, ``rule_count`` and ``has_default``, and the first carries
    ``policy_document`` so the default-rule check knows to run."""
    rule_count = len(parsed)
    has_default = any(p == DEFAULT_RULE_PRIORITY for p, _, _, _ in parsed
                      if isinstance(p, int) and not isinstance(p, bool))
    value = policy or "security_policy"
    claims: list[Claim] = []
    for i, (_, normalized, expr_expression, location) in enumerate(parsed):
        extra: dict[str, Any] = {
            "policy": policy, "rule_count": rule_count, "has_default": has_default,
        }
        if i == 0:
            extra["policy_document"] = True
        claims.append(_rule_claim(value, location, normalized, expr_expression, extra))
    return claims


# -- REST document extractor --------------------------------------------------


def security_policy_claims(doc: Mapping[str, Any]) -> list[Claim]:
    """Claims made by one REST Cloud Armor security-policy document."""
    if not isinstance(doc, Mapping):
        raise ValueError(f"security policy must be a mapping, got {type(doc).__name__}")
    rules = doc.get("rules")
    if not isinstance(rules, list):
        if rules is not None:
            logger.debug("rules is %s, not an array — no claims", type(rules).__name__)
        return []
    policy = _policy_name(doc)
    parsed = [_parse_rest_rule(rule, f"rules[{i}]") for i, rule in enumerate(rules)]
    return _full_policy_claims(parsed, policy)


# -- Terraform extractors -----------------------------------------------------


def _tf_security_policy_claims(address: str, values: Mapping[str, Any]) -> list[Claim]:
    """Claims for a full ``google_compute_security_policy`` resource."""
    policy = _policy_name(values)
    parsed = [_parse_tf_rule(rule, path)
              for rule, path in _blocks(values.get("rule"), f"{address}.rule")]
    return _full_policy_claims(parsed, policy)


def _tf_security_policy_rule_claims(address: str,
                                    values: Mapping[str, Any]) -> list[Claim]:
    """Claims for a standalone ``google_compute_security_policy_rule`` resource:
    the rule itself, plus one ``security_policy_ref`` for its ``security_policy``
    attribute unless that attribute is an unresolved interpolation."""
    _, normalized, expr_expression, _ = _parse_tf_rule(values, address)
    security_policy = values.get("security_policy")
    resolved = (security_policy if isinstance(security_policy, str)
                and security_policy and "${" not in security_policy else None)
    value = resolved or address
    extra = {"policy": resolved} if resolved is not None else {}
    claims = [_rule_claim(value, address, normalized, expr_expression, extra)]
    if resolved is not None:
        claims.append(Claim("security_policy_ref", resolved, f"{address}.security_policy"))
    else:
        logger.debug("%s.security_policy is absent or an unresolved interpolation "
                     "— no security_policy_ref claim", address)
    return claims


#: Whole-document extractor for the ``security_policy`` document kind.
DOCUMENT_EXTRACTORS = {"security_policy": security_policy_claims}

#: Terraform resource extractors contributed to :mod:`gcp_grounding.tf_claims`.
TF_EXTRACTORS = {
    "google_compute_security_policy": _tf_security_policy_claims,
    "google_compute_security_policy_rule": _tf_security_policy_rule_claims,
}
