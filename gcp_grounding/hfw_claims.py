"""Claim extraction: hierarchical firewall policies, rules and associations.

Same discipline as the VPC firewall extractor (:mod:`~gcp_grounding.fw_claims`)
and :mod:`~gcp_grounding.claims`: pure parsing, unambiguous or skipped. A field
that does not resolve cleanly yields no claim (it is logged, never guessed at) —
the one exception being a rule the packet algebra cannot encode, which is
*never dropped* but carried as a ``firewall_policy_rule`` claim whose payload
gains an ``"unsupported": "<reason>"`` key, so a widening check can never
silently lose a rule it failed to model.

The module owns three Terraform resource types and one REST document kind and
opts into the grounding gate purely through :data:`DOCUMENT_EXTRACTORS` and
:data:`TF_EXTRACTORS`, discovered lazily by :mod:`~gcp_grounding.registry` and
:mod:`~gcp_grounding.tf_claims`.

NORMALIZED HIERARCHICAL RULE. Both spellings collapse to one dict whose field
names are identical to the ``hierarchical_firewall_policies[].rules[]`` records
the estate snapshot stores, so a rule read from a proposal and a rule read from
the estate compare structurally:

    {"priority": int, "action": "allow"|"deny"|"goto_next", "direction": str,
     "disabled": bool,
     "match": {"src_ip_ranges": [str], "dest_ip_ranges": [str],
               "layer4": [{"protocol": str, "ports": [str]}]},
     "target_resources": [str], "target_service_accounts": [str],
     "target_secure_tags": [str]}

REST spells ``match.srcIpRanges`` / ``match.destIpRanges``,
``match.layer4Configs[].ipProtocol`` and ``.ports``, ``targetResources``,
``targetServiceAccounts`` and ``targetSecureTags[].name``. Terraform's
``google_compute_firewall_policy_rule`` uses snake_case with a nested ``match``
block and repeated ``layer4_config`` / ``target_secure_tags`` blocks (read with
the ``tf_claims._first_block`` / ``tf_claims._blocks`` helpers). GCP's
``goto_next`` action string is preserved verbatim — the whole point of the
cross-level check is that a ``goto_next`` rule delegates to the next level.

CLAIMS emitted:

- ``firewall_policy_rule`` — one per rule, payload being the normalized rule,
  the owning ``policy`` (name or terraform address) and ``attachment_nodes``
  when known.
- ``firewall_policy_ref`` — the policy a ``…_rule`` or ``…_association``
  resource attaches to *must already exist*; skipped for an unresolved
  interpolation. A ``google_compute_firewall_policy`` resource / REST policy
  document emits **no** self-referential ref (it is being created).
- ``hierarchy_node_ref`` — the policy's ``parent`` / owning node, or an
  association's ``attachment_target`` normalized to ``organizations/1`` /
  ``folders/2``.
- ``network_tag_ref`` — one per ``target_secure_tags`` entry that is a plain
  short name; a numeric ``tagValues/123`` reference is not a network tag and is
  skipped with a log.
- ``service_account_ref`` — one per ``target_service_accounts`` entry.
"""

from __future__ import annotations

from typing import Any, Mapping

from .claims import Claim
from .core.log import get_logger
from .tf_claims import _blocks, _first_block

logger = get_logger(__name__)

__all__ = ["DOCUMENT_EXTRACTORS", "TF_EXTRACTORS", "firewall_policy_claims"]

#: The three action strings GCP's cross-level check reasons about. ``goto_next``
#: is kept verbatim — normalising it away would erase the delegation semantics.
_ACTIONS = ("allow", "deny", "goto_next")

#: Resource-hierarchy node prefixes an ``organizations/1``-style reference uses.
_NODE_TYPES = ("organizations", "folders", "projects")


# -- small shape helpers ------------------------------------------------------


def _str_list(value: Any) -> list[str]:
    """A JSON string array → a list of the non-empty strings in it, order kept;
    anything else → an empty list. Conservative: a non-string entry is dropped,
    never coerced."""
    if not isinstance(value, (list, tuple)):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _resolved_ref(value: Any) -> str | None:
    """A reference attribute as a resolvable name, or None when it is absent or
    an unresolved terraform interpolation (``${…}``). Skipping the latter is
    what keeps a plan that has not been applied yet from claiming a policy that
    does not exist under its final name."""
    if not isinstance(value, str) or not value.strip():
        return None
    if "${" in value:
        return None
    return value


def _normalize_node(value: Any) -> str | None:
    """A hierarchy reference → its ``organizations/<id>`` / ``folders/<id>`` /
    ``projects/<id>`` node, or None. Tolerates a full resource path
    (``organizations/1/locations/global/firewallPolicies/…``) and a
    resource-manager URL (``//cloudresourcemanager.googleapis.com/folders/2``)
    by scanning for the first ``<type>/<id>`` pair."""
    if not isinstance(value, str) or not value or "${" in value:
        return None
    parts = value.split("/")
    for i in range(len(parts) - 1):
        if parts[i] in _NODE_TYPES and parts[i + 1]:
            return f"{parts[i]}/{parts[i + 1]}"
    return None


def _plain_tag(name: Any) -> bool:
    """Whether a secure-tag entry is a plain network-tag short name (``web``)
    rather than a numeric ``tagValues/123`` / fully-qualified reference — the
    presence of a ``/`` is the discriminator."""
    return isinstance(name, str) and bool(name) and "/" not in name


# -- rule normalization -------------------------------------------------------


def _unreadable_layer4(value: Any, *, as_blocks: bool) -> str | None:
    """Why a PRESENT layer-4 attribute could not be read, or ``None``.

    An ABSENT attribute legitimately declares no layer-4 restriction. A present
    one the extractor cannot read declares nothing of the sort: normalizing it
    to an empty list hands the cross-level check a rule that restricts nothing
    at layer 4 — matching every port — which is the very default this module's
    ``unsupported`` payload exists to prevent. Terraform's repeated-block
    spelling also accepts a single bare object (*as_blocks*).
    """
    if value is None:
        return None
    if as_blocks and isinstance(value, Mapping):
        return None
    if not isinstance(value, (list, tuple)):
        return (f"layer-4 configuration is {type(value).__name__}, not a list "
                f"of protocol/port objects")
    for i, entry in enumerate(value):
        if not isinstance(entry, Mapping):
            return (f"layer-4 configuration [{i}] is {type(entry).__name__}, "
                    f"not a protocol/port object")
    return None


def _build_rule(priority: Any, action: Any, direction: Any, disabled: Any,
                src: list[str], dest: list[str], layer4: list[dict[str, Any]],
                target_resources: list[str], target_service_accounts: list[str],
                target_secure_tags: list[str], *, match_present: bool,
                layer4_unreadable: str | None = None
                ) -> tuple[dict[str, Any], str | None]:
    """Assemble the normalized rule dict and decide whether the packet algebra
    can encode it. Returns ``(rule, unsupported_reason_or_None)`` — the rule is
    always built (never dropped); the reason, when set, is stamped onto the
    claim's payload so a widening check abstains rather than losing the rule."""
    rule = {
        "priority": priority,
        "action": action,
        "direction": direction,
        "disabled": disabled,
        "match": {"src_ip_ranges": src, "dest_ip_ranges": dest, "layer4": layer4},
        "target_resources": target_resources,
        "target_service_accounts": target_service_accounts,
        "target_secure_tags": target_secure_tags,
    }
    return rule, _unsupported_reason(action, priority, direction, src, dest,
                                     match_present=match_present,
                                     layer4_unreadable=layer4_unreadable)


def _unsupported_reason(action: Any, priority: Any, direction: Any,
                        src: list[str], dest: list[str], *, match_present: bool,
                        layer4_unreadable: str | None = None) -> str | None:
    if action not in _ACTIONS:
        return f"action {action!r} is not one of allow/deny/goto_next"
    if not isinstance(priority, int) or isinstance(priority, bool):
        return f"priority {priority!r} is not an integer"
    if not match_present:
        return "rule has no match block"
    if layer4_unreadable is not None:
        return layer4_unreadable
    if not src and not dest:
        return "match declares no source or destination IP ranges"
    if direction == "INGRESS" and not src:
        return "ingress rule match declares no source IP ranges"
    if direction == "EGRESS" and not dest:
        return "egress rule match declares no destination IP ranges"
    return None


def _normalize_rest_rule(rule: Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
    match = rule.get("match")
    match_present = isinstance(match, Mapping)
    src = _str_list(match.get("srcIpRanges")) if match_present else []
    dest = _str_list(match.get("destIpRanges")) if match_present else []
    configs = match.get("layer4Configs") if match_present else None
    unreadable = _unreadable_layer4(configs, as_blocks=False)
    entries = configs if isinstance(configs, (list, tuple)) else ()
    layer4 = [{"protocol": cfg.get("ipProtocol"), "ports": _str_list(cfg.get("ports"))}
              for cfg in entries if isinstance(cfg, Mapping)]
    tags = rule.get("targetSecureTags")
    tag_blocks = tags if isinstance(tags, (list, tuple)) else ()
    secure_tags = [tag.get("name")
                   for tag in tag_blocks
                   if isinstance(tag, Mapping) and isinstance(tag.get("name"), str)]
    return _build_rule(
        rule.get("priority"), rule.get("action"), rule.get("direction"),
        rule.get("disabled", False), src, dest, layer4,
        _str_list(rule.get("targetResources")),
        _str_list(rule.get("targetServiceAccounts")),
        secure_tags, match_present=match_present, layer4_unreadable=unreadable)


def _normalize_tf_rule(values: Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
    match, _ = _first_block(values.get("match"), "match")
    match_present = match is not None
    src = _str_list(match.get("src_ip_ranges")) if match_present else []
    dest = _str_list(match.get("dest_ip_ranges")) if match_present else []
    configs = match.get("layer4_config") if match_present else None
    unreadable = _unreadable_layer4(configs, as_blocks=True)
    layer4 = [{"protocol": block.get("ip_protocol"), "ports": _str_list(block.get("ports"))}
              for block, _ in _blocks(configs, "layer4_config")]
    secure_tags = [block.get("name")
                   for block, _ in _blocks(values.get("target_secure_tags"), "target_secure_tags")
                   if isinstance(block.get("name"), str)]
    return _build_rule(
        values.get("priority"), values.get("action"), values.get("direction"),
        values.get("disabled", False), src, dest, layer4,
        _str_list(values.get("target_resources")),
        _str_list(values.get("target_service_accounts")),
        secure_tags, match_present=match_present, layer4_unreadable=unreadable)


def _rule_claims(rule: dict[str, Any], unsupported: str | None, policy: str,
                 location: str, attachment_nodes: list[str] | None) -> list[Claim]:
    """The ``firewall_policy_rule`` claim for one normalized rule, plus a
    ``network_tag_ref`` per plain secure tag and a ``service_account_ref`` per
    target service account."""
    payload: dict[str, Any] = {"rule": rule, "policy": policy}
    if attachment_nodes:
        payload["attachment_nodes"] = attachment_nodes
    if unsupported is not None:
        payload["unsupported"] = unsupported
        logger.debug("%s: rule not encodable (%s) — carried as unsupported, "
                     "not dropped", location, unsupported)
    claims = [Claim.of("firewall_policy_rule", policy, location, **payload)]
    for i, tag in enumerate(rule["target_secure_tags"]):
        if _plain_tag(tag):
            claims.append(Claim("network_tag_ref", tag,
                                f"{location}.target_secure_tags[{i}]"))
        else:
            logger.debug("%s.target_secure_tags[%d] (%r) is a tagValues/ reference, "
                         "not a network tag — skipped", location, i, tag)
    for i, sa in enumerate(rule["target_service_accounts"]):
        claims.append(Claim("service_account_ref", sa,
                            f"{location}.target_service_accounts[{i}]"))
    return claims


# -- REST policy document -----------------------------------------------------


def _policy_node(doc: Mapping[str, Any]) -> tuple[str, str] | None:
    """The hierarchy node that owns a firewall policy → (node, source path).
    Prefers an explicit ``parent`` / ``parent_id``; otherwise reads the owning
    node out of the policy's ``name`` / ``selfLink`` path."""
    for field in ("parent", "parent_id"):
        node = _normalize_node(doc.get(field))
        if node is not None:
            return node, field
    for field in ("name", "selfLink"):
        node = _normalize_node(doc.get(field))
        if node is not None:
            return node, field
    return None


def _policy_name(doc: Mapping[str, Any]) -> str:
    for field in ("name", "shortName", "short_name"):
        value = doc.get(field)
        if isinstance(value, str) and value:
            return value
    return "<firewall policy>"


def _association_nodes(doc: Mapping[str, Any]) -> list[str]:
    """Attachment nodes named by a policy document's ``associations`` block, if
    any — the rules of an attached policy carry these so a check knows where the
    policy takes effect."""
    nodes = []
    declared = doc.get("associations")
    for assoc in declared if isinstance(declared, (list, tuple)) else ():
        if isinstance(assoc, Mapping):
            node = _normalize_node(assoc.get("attachmentTarget")
                                   or assoc.get("attachment_target"))
            if node is not None and node not in nodes:
                nodes.append(node)
    return nodes


def firewall_policy_claims(policy: Mapping[str, Any]) -> list[Claim]:
    """Claims made by one REST hierarchical-firewall-policy document.

    Emits a ``hierarchy_node_ref`` for the owning node, one
    ``firewall_policy_rule`` (plus its tag / service-account refs) per entry in
    ``rules[]``, and — because the policy is being *created* — no
    self-referential ``firewall_policy_ref``."""
    if not isinstance(policy, Mapping):
        raise ValueError(f"firewall policy must be a mapping, got {type(policy).__name__}")
    claims: list[Claim] = []
    node = _policy_node(policy)
    if node is not None:
        claims.append(Claim("hierarchy_node_ref", node[0], node[1]))
    name = _policy_name(policy)
    attachment_nodes = _association_nodes(policy)
    rules = policy.get("rules")
    if isinstance(rules, list):
        for i, rule in enumerate(rules):
            if not isinstance(rule, Mapping):
                logger.debug("rules[%d] is not an object — skipped", i)
                continue
            norm, unsupported = _normalize_rest_rule(rule)
            claims.extend(_rule_claims(norm, unsupported, name, f"rules[{i}]",
                                       attachment_nodes))
    elif rules is not None:
        logger.debug("rules is %s, not an array — no rule claims", type(rules).__name__)
    return claims


# -- terraform resources ------------------------------------------------------


def _tf_policy_claims(address: str, values: Mapping[str, Any]) -> list[Claim]:
    """``google_compute_firewall_policy``: a ``hierarchy_node_ref`` for its
    parent and no self-referential ``firewall_policy_ref`` (it is being
    created). Rules live in separate ``…_rule`` resources, so this resource
    normally contributes only the node reference."""
    claims: list[Claim] = []
    node = _policy_node(values)
    if node is not None:
        claims.append(Claim("hierarchy_node_ref", node[0], f"{address}.{node[1]}"))
    return claims


def _tf_rule_claims(address: str, values: Mapping[str, Any]) -> list[Claim]:
    """``google_compute_firewall_policy_rule``: exactly one
    ``firewall_policy_rule`` claim, plus a ``firewall_policy_ref`` for the
    ``firewall_policy`` the rule attaches to (skipped when that attribute is an
    unresolved interpolation)."""
    fp = values.get("firewall_policy")
    policy = fp if isinstance(fp, str) and fp else address
    norm, unsupported = _normalize_tf_rule(values)
    claims = _rule_claims(norm, unsupported, policy, address, attachment_nodes=None)
    ref = _resolved_ref(fp)
    if ref is not None:
        claims.append(Claim("firewall_policy_ref", ref, f"{address}.firewall_policy"))
    else:
        logger.debug("%s.firewall_policy is absent or an unresolved interpolation "
                     "— no firewall_policy_ref", address)
    return claims


def _tf_association_claims(address: str, values: Mapping[str, Any]) -> list[Claim]:
    """``google_compute_firewall_policy_association``: a ``firewall_policy_ref``
    for the attached policy and a ``hierarchy_node_ref`` for the
    ``attachment_target`` node."""
    claims: list[Claim] = []
    ref = _resolved_ref(values.get("firewall_policy"))
    if ref is not None:
        claims.append(Claim("firewall_policy_ref", ref, f"{address}.firewall_policy"))
    else:
        logger.debug("%s.firewall_policy is absent or an unresolved interpolation "
                     "— no firewall_policy_ref", address)
    node = _normalize_node(values.get("attachment_target"))
    if node is not None:
        claims.append(Claim("hierarchy_node_ref", node, f"{address}.attachment_target"))
    else:
        logger.debug("%s.attachment_target does not resolve to a hierarchy node "
                     "— skipped", address)
    return claims


DOCUMENT_EXTRACTORS = {"firewall_policy": firewall_policy_claims}

TF_EXTRACTORS = {
    "google_compute_firewall_policy": _tf_policy_claims,
    "google_compute_firewall_policy_rule": _tf_rule_claims,
    "google_compute_firewall_policy_association": _tf_association_claims,
}
