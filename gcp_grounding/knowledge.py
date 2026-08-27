"""Offline knowledge base: a frozen snapshot of the GCP estate.

A :class:`GcpSnapshot` is the sole source of truth for every existence
question the reasoner asks — roles, permissions, principals, org-policy
constraints, resource types. It is loaded from a committed JSON file
(``fetch.py`` populates one from live APIs, elsewhere); this module does no
network I/O and imports no GCP SDKs, so grounding runs offline,
deterministically, with no credentials.

The one semantic that matters — **unknown vs absent**:

- A category the snapshot *never enumerated* (key missing from the JSON,
  e.g. principals when Cloud Asset Inventory was not captured) answers every
  lookup with the :data:`UNKNOWN` sentinel, so the reasoner emits an honest
  ``unverified`` verdict.
- A category that *was* enumerated (present, even as an empty list) answers
  ``False``/``None`` for names it does not contain — evidence for an
  ``ungrounded`` verdict.

:data:`UNKNOWN` deliberately refuses truthiness (``bool(UNKNOWN)`` raises)
so a naive ``if not snapshot.role_exists(r)`` cannot silently turn "not
captured" into a false ``ungrounded``; compare with ``is UNKNOWN`` /
``is True`` / ``is False``.
"""

from __future__ import annotations

import json
import os
import urllib.parse
from dataclasses import dataclass
from functools import cached_property
from typing import Any, Mapping

from .core.log import get_logger

logger = get_logger(__name__)

__all__ = ["UNKNOWN", "Unknown", "GcpSnapshot"]


class Unknown:
    """Type of the :data:`UNKNOWN` sentinel — the snapshot never enumerated
    the category this lookup belongs to, so existence is undecidable here.

    Do not instantiate; ``Unknown()`` always returns the singleton.
    """

    _instance: "Unknown | None" = None

    def __new__(cls) -> "Unknown":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "UNKNOWN"

    def __bool__(self) -> bool:
        raise TypeError(
            "UNKNOWN is neither True nor False — this category was not captured "
            "in the snapshot; compare with `is UNKNOWN` and emit an 'unverified' "
            "verdict, never 'ungrounded'"
        )


UNKNOWN = Unknown()

# The eight record-map estate tables: each a name -> record object with its own
# captured bit, carrying firewall/policy/hierarchy structure the encodings read.
# Their list-valued fields are order-SEMANTIC (rule/hierarchy order matters), so
# they normalize to tuples but are NEVER sorted.
_RECORD_TABLES = ("firewall_rules", "hierarchical_firewall_policies",
                  "cloud_armor_policies", "vpc_sc_perimeters",
                  "resource_hierarchy", "iam_bindings", "org_policies",
                  "iam_deny_policies")

# Every top-level key a snapshot may carry besides captured_at. A typo here
# ("role" for "roles") must not silently demote a whole category to UNKNOWN,
# so from_dict rejects unrecognized keys outright. Nineteen in total: five
# pre-existing vocabularies, six flat vocabularies, eight record tables.
_CATEGORIES = ("roles", "permissions", "principals", "constraints", "resource_types",
               "networks", "subnetworks", "network_tags", "service_accounts",
               "access_levels", "restricted_services", *_RECORD_TABLES)


def _str_set(value: Any, where: str) -> frozenset[str] | None:
    """A JSON string array → frozenset; None (key not captured) passes through."""
    if value is None:
        return None
    if isinstance(value, (str, bytes, Mapping)) or not hasattr(value, "__iter__"):
        raise ValueError(f"snapshot.{where} must be an array of strings, got {type(value).__name__}")
    out = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise ValueError(f"snapshot.{where} entries must be non-empty strings, got {item!r}")
        out.append(item)
    return frozenset(out)


def _record_map(value: Any, where: str) -> dict[str, dict[str, Any]] | None:
    """A JSON object of name → record-object; None passes through."""
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError(f"snapshot.{where} must be an object mapping names to records, "
                         f"got {type(value).__name__}")
    out: dict[str, dict[str, Any]] = {}
    for name, record in value.items():
        if not isinstance(name, str) or not name:
            raise ValueError(f"snapshot.{where} keys must be non-empty strings, got {name!r}")
        if not isinstance(record, Mapping):
            raise ValueError(f"snapshot.{where}[{name!r}] must be an object, "
                             f"got {type(record).__name__}")
        out[name] = dict(record)
    return out


def _tuplify(obj: Any) -> Any:
    """Recursively freeze every JSON array to a tuple (dicts recurse, scalars
    pass through). Order is PRESERVED, never sorted: firewall/armor rule order
    and hierarchy order are semantic. Inverse of :func:`_listify`, so a record
    survives a to_dict/from_dict round-trip byte-for-byte."""
    if isinstance(obj, Mapping):
        return {k: _tuplify(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return tuple(_tuplify(v) for v in obj)
    return obj


def _listify(obj: Any) -> Any:
    """Emit-side inverse of :func:`_tuplify`: every tuple back to a list so
    to_dict output is plain, JSON-serializable data."""
    if isinstance(obj, Mapping):
        return {k: _listify(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_listify(v) for v in obj]
    return obj


def _str_tuple(value: Any, where: str) -> tuple[str, ...]:
    """A JSON string array → order-preserving tuple; None → empty tuple. Unlike
    :func:`_str_set` this keeps order (rule/list order is semantic)."""
    if value is None:
        return ()
    if isinstance(value, (str, bytes, Mapping)) or not hasattr(value, "__iter__"):
        raise ValueError(f"snapshot.{where} must be an array of strings, "
                         f"got {type(value).__name__}")
    out = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise ValueError(f"snapshot.{where} entries must be non-empty strings, "
                             f"got {item!r}")
        out.append(item)
    return tuple(out)


def _reject(table: str, key: str, msg: str) -> None:
    """Fail loudly, naming the table and key — a half-parsed record would mark
    the category captured with wrong content and manufacture false verdicts."""
    raise ValueError(f"snapshot.{table}[{key!r}]: {msg}")


def _rule_list(value: Any, table: str, key: str) -> tuple[dict[str, Any], ...]:
    """A list of rule/binding objects → normalized tuple; None → empty tuple.
    Structural only (each entry must be an object); nested list fields are
    frozen by _tuplify so their order survives exactly."""
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        _reject(table, key, f"'rules' must be an array, got {type(value).__name__}")
    for entry in value:
        if not isinstance(entry, Mapping):
            _reject(table, key, "each 'rules' entry must be an object")
    return tuple(_tuplify(entry) for entry in value)


def _parse_firewall_rules(value: Any) -> dict[str, dict[str, Any]] | None:
    table = _record_map(value, "firewall_rules")
    if table is None:
        return None
    for key, record in table.items():
        network = record.get("network")
        if not isinstance(network, str) or not network:
            _reject("firewall_rules", key, "'network' (non-empty string) is required")
        if record.get("direction") not in ("INGRESS", "EGRESS"):
            _reject("firewall_rules", key, "'direction' must be 'INGRESS' or "
                    f"'EGRESS', got {record.get('direction')!r}")
        if record.get("action") not in ("allow", "deny"):
            _reject("firewall_rules", key, "'action' must be 'allow' or 'deny', "
                    f"got {record.get('action')!r}")
        priority = record.get("priority", 1000)
        if not isinstance(priority, int) or isinstance(priority, bool):
            _reject("firewall_rules", key, f"'priority' must be an int, got {priority!r}")
        record["priority"] = priority
        disabled = record.get("disabled", False)
        if not isinstance(disabled, bool):
            _reject("firewall_rules", key, f"'disabled' must be a bool, got {disabled!r}")
        record["disabled"] = disabled
        for field in ("source_ranges", "destination_ranges", "source_tags",
                      "target_tags", "source_service_accounts",
                      "target_service_accounts"):
            record[field] = _str_tuple(record.get(field),
                                       f"firewall_rules[{key!r}].{field}")
        record["layer4"] = _parse_layer4(record.get("layer4"), key)
        table[key] = _tuplify(record)
    return table


def _parse_layer4(value: Any, key: str) -> tuple[dict[str, Any], ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        _reject("firewall_rules", key, f"'layer4' must be an array, got {type(value).__name__}")
    out = []
    for entry in value:
        if not isinstance(entry, Mapping):
            _reject("firewall_rules", key, "each 'layer4' entry must be an object")
        protocol = entry.get("protocol")
        if not isinstance(protocol, str) or not protocol:
            _reject("firewall_rules", key, "each 'layer4' entry needs a 'protocol' string")
        norm = dict(entry)
        norm["ports"] = _str_tuple(entry.get("ports"),
                                   f"firewall_rules[{key!r}].layer4.ports")
        out.append(norm)
    return tuple(out)


def _parse_hierarchical_firewall_policies(value: Any) -> dict[str, dict[str, Any]] | None:
    table = _record_map(value, "hierarchical_firewall_policies")
    if table is None:
        return None
    for key, record in table.items():
        record["attachments"] = _str_tuple(
            record.get("attachments"),
            f"hierarchical_firewall_policies[{key!r}].attachments")
        rules = _rule_list(record.get("rules"),
                           "hierarchical_firewall_policies", key)
        # The same two field checks _parse_firewall_rules already applies. A
        # non-int priority or a non-bool 'disabled' cannot be encoded, and
        # bool("false") is True — passing one through deletes a live DENY from
        # the evaluation order and mints a clean bill of health for the rule it
        # was preempting.
        for i, rule in enumerate(rules):
            priority = rule.get("priority", 1000)
            if not isinstance(priority, int) or isinstance(priority, bool):
                _reject("hierarchical_firewall_policies", key,
                        f"rules[{i}] 'priority' must be an int, got {priority!r}")
            disabled = rule.get("disabled", False)
            if not isinstance(disabled, bool):
                _reject("hierarchical_firewall_policies", key,
                        f"rules[{i}] 'disabled' must be a bool, got {disabled!r}")
        record["rules"] = rules
        table[key] = _tuplify(record)
    return table


def _parse_cloud_armor_policies(value: Any) -> dict[str, dict[str, Any]] | None:
    table = _record_map(value, "cloud_armor_policies")
    if table is None:
        return None
    for key, record in table.items():
        armor_type = record.get("type")
        if armor_type is not None and not isinstance(armor_type, str):
            _reject("cloud_armor_policies", key, f"'type' must be a string, got {armor_type!r}")
        record["rules"] = _rule_list(record.get("rules"), "cloud_armor_policies", key)
        table[key] = _tuplify(record)
    return table


def _parse_vpc_sc_perimeters(value: Any) -> dict[str, dict[str, Any]] | None:
    table = _record_map(value, "vpc_sc_perimeters")
    if table is None:
        return None
    for key, record in table.items():
        flag = record.get("use_explicit_dry_run_spec")
        if flag is not None and not isinstance(flag, bool):
            _reject("vpc_sc_perimeters", key,
                    f"'use_explicit_dry_run_spec' must be a bool, got {flag!r}")
        for side in ("status", "spec"):
            block = record.get(side)
            if block is not None and not isinstance(block, Mapping):
                _reject("vpc_sc_perimeters", key, f"'{side}' must be an object or null")
        table[key] = _tuplify(record)
    return table


def _parse_resource_hierarchy(value: Any) -> dict[str, dict[str, Any]] | None:
    table = _record_map(value, "resource_hierarchy")
    if table is None:
        return None
    for key, record in table.items():
        if "parent" not in record:
            _reject("resource_hierarchy", key, "'parent' key is required (may be null)")
        parent = record.get("parent")
        if parent is not None and not isinstance(parent, str):
            _reject("resource_hierarchy", key,
                    f"'parent' must be a string or null, got {parent!r}")
        node_type = record.get("type")
        if node_type not in ("organization", "folder", "project"):
            _reject("resource_hierarchy", key, "'type' must be 'organization', "
                    f"'folder', or 'project', got {node_type!r}")
        for field in ("number", "display_name"):
            val = record.get(field)
            if val is not None and not isinstance(val, str):
                _reject("resource_hierarchy", key,
                        f"'{field}' must be a string or null, got {val!r}")
        table[key] = _tuplify(record)
    return table


def _parse_iam_bindings(value: Any) -> dict[str, dict[str, Any]] | None:
    table = _record_map(value, "iam_bindings")
    if table is None:
        return None
    for key, record in table.items():
        bindings = record.get("bindings")
        if bindings is None:
            record["bindings"] = ()
        else:
            if not isinstance(bindings, (list, tuple)):
                _reject("iam_bindings", key,
                        f"'bindings' must be an array, got {type(bindings).__name__}")
            for binding in bindings:
                if not isinstance(binding, Mapping):
                    _reject("iam_bindings", key, "each 'bindings' entry must be an object")
        table[key] = _tuplify(record)
    return table


def _parse_iam_deny_policies(value: Any) -> dict[str, dict[str, Any]] | None:
    """The ``iam_deny_policies`` table: IAM v2 deny policies keyed by the v2
    REST resource name ``policies/<url-encoded-attachment>/denypolicies/<id>``.

    ``attachment_point`` is REQUIRED and stored DECODED (``projects/acme-prod``,
    ``folders/123``, ``organizations/456``) so check time never URL-decodes — a
    second parser — and it is cross-checked against the key's encoded middle
    segment, REJECTING disagreement: a mismatched key would let the containment
    walk govern the wrong node (the ``org_policies`` key/record-agreement
    precedent). Per rule the four principal/permission fields go through
    :func:`_str_tuple` (order preserved, never sorted) and ``denial_condition``
    must be absent or an object with a non-empty ``expression`` string — a
    half-parsed condition would let a conditional deny read as unconditional
    and fabricate a masked verdict.
    """
    table = _record_map(value, "iam_deny_policies")
    if table is None:
        return None
    for key, record in table.items():
        attachment = record.get("attachment_point")
        if not isinstance(attachment, str) or not attachment:
            _reject("iam_deny_policies", key,
                    "'attachment_point' (non-empty string) is required")
        segments = key.split("/")
        if (len(segments) != 4 or segments[0] != "policies"
                or segments[2] != "denypolicies"
                or not segments[1] or not segments[3]):
            _reject("iam_deny_policies", key,
                    "key must be 'policies/<url-encoded-attachment-point>/"
                    "denypolicies/<policy-id>'")
        decoded = urllib.parse.unquote(segments[1])
        agreed = (attachment,
                  f"cloudresourcemanager.googleapis.com/{attachment}")
        if decoded not in agreed:
            raise ValueError(
                f"snapshot.iam_deny_policies[{key!r}]: 'attachment_point' "
                f"({attachment!r}) disagrees with the key's encoded attachment "
                f"segment ({decoded!r}) — a mismatched key would let the "
                f"containment walk govern the wrong node")
        rules = _rule_list(record.get("rules"), "iam_deny_policies", key)
        validated = []
        for i, rule in enumerate(rules):
            rule = dict(rule)
            for field in ("denied_principals", "exception_principals",
                          "denied_permissions", "exception_permissions"):
                rule[field] = _str_tuple(
                    rule.get(field),
                    f"iam_deny_policies[{key!r}].rules[{i}].{field}")
            condition = rule.get("denial_condition")
            if condition is not None:
                expression = (condition.get("expression")
                              if isinstance(condition, Mapping) else None)
                if not isinstance(expression, str) or not expression:
                    _reject("iam_deny_policies", key,
                            f"rules[{i}] 'denial_condition' must be null or an "
                            f"object with a non-empty 'expression' string, got "
                            f"{condition!r}")
            validated.append(rule)
        record["rules"] = tuple(validated)
        table[key] = _tuplify(record)
    return table


def _parse_org_policies(value: Any) -> dict[str, dict[str, Any]] | None:
    table = _record_map(value, "org_policies")
    if table is None:
        return None
    for key, record in table.items():
        halves = key.split("|")
        if len(halves) != 2:
            raise ValueError(
                f"snapshot.org_policies[{key!r}]: key must be exactly "
                f"'<node>|<constraint>' with a single '|' separator")
        node_half, constraint_half = halves
        node = record.get("node")
        if not isinstance(node, str) or not node:
            _reject("org_policies", key, "'node' (non-empty string) is required")
        constraint = record.get("constraint")
        if not isinstance(constraint, str) or not constraint:
            _reject("org_policies", key, "'constraint' (non-empty string) is required")
        if node != node_half or constraint != constraint_half:
            raise ValueError(
                f"snapshot.org_policies[{key!r}]: record node/constraint "
                f"({node!r}/{constraint!r}) disagree with the key halves "
                f"({node_half!r}/{constraint_half!r}) — a mismatched key would let "
                f"an enforcement check compare the wrong node")
        reset = record.get("reset", False)
        if not isinstance(reset, bool):
            _reject("org_policies", key, f"'reset' must be a bool, got {reset!r}")
        record["reset"] = reset
        inherit = record.get("inherit_from_parent", False)
        if not isinstance(inherit, bool):
            _reject("org_policies", key,
                    f"'inherit_from_parent' must be a bool, got {inherit!r}")
        record["inherit_from_parent"] = inherit
        record["rules"] = _rule_list(record.get("rules"), "org_policies", key)
        table[key] = _tuplify(record)
    return table


@dataclass(frozen=True, eq=True)
class GcpSnapshot:
    """A point-in-time, offline snapshot of the vocabulary of a GCP estate.

    ``None`` in any category field means *not captured* (→ lookups answer
    :data:`UNKNOWN`); an empty collection means *captured and empty*
    (→ lookups answer ``False``).
    """

    #: ISO-8601 capture timestamp; every verdict is only as fresh as this.
    captured_at: str
    #: role name → record ({"title", "stage", "included_permissions", ...}).
    roles: dict[str, dict[str, Any]] | None = None
    #: flat enumeration of permission names (e.g. from queryTestablePermissions).
    permissions: frozenset[str] | None = None
    #: principal identifiers ("user:…", "serviceAccount:…", "group:…", …).
    principals: frozenset[str] | None = None
    #: org-policy constraint name → record ({"value_type": "boolean"|"list", ...}).
    constraints: dict[str, dict[str, Any]] | None = None
    #: TERRAFORM provider resource type names (e.g. "google_compute_firewall"),
    #: never CAI asset types: the grounding route checks the types a terraform
    #: proposal declares, and fetch.py fills this category from the terraform
    #: schema alone because unioning CAI asset types into it would flag the
    #: category as enumerated with the wrong namespace — a partial capture
    #: manufacturing false "ungrounded" evidence for perfectly real types.
    resource_types: frozenset[str] | None = None
    #: VPC networks as "projects/<project>/global/networks/<name>" (extractors
    #: normalize self-links by stripping the
    #: "https://www.googleapis.com/compute/v1/" prefix).
    networks: frozenset[str] | None = None
    #: subnetworks as "projects/<project>/regions/<region>/subnetworks/<name>".
    subnetworks: frozenset[str] | None = None
    #: bare network tag strings (e.g. "web", "bastion"). PRESENCE-ONLY: GCP has
    #: no "list all network tags" API — a tag is created implicitly by the rule
    #: naming it, so a capture is inherently partial and a miss must NEVER read
    #: as absence. See network_tag_exists, which returns True or UNKNOWN, never
    #: False.
    network_tags: frozenset[str] | None = None
    #: bare service-account emails (e.g.
    #: "ci-deployer@acme-prod.iam.gserviceaccount.com") — deliberately WITHOUT
    #: the "serviceAccount:" prefix, so this category is distinct from principals.
    service_accounts: frozenset[str] | None = None
    #: access levels as "accessPolicies/<n>/accessLevels/<name>".
    access_levels: frozenset[str] | None = None
    #: VPC-SC restricted service hostnames (e.g. "storage.googleapis.com").
    restricted_services: frozenset[str] | None = None
    #: VPC firewall rules keyed "projects/<p>/global/firewalls/<name>"; each
    #: record carries network/direction/action/priority/disabled and the tag,
    #: range, service-account and layer4 match sets (list order semantic).
    firewall_rules: dict[str, dict[str, Any]] | None = None
    #: hierarchical firewall policies keyed
    #: "organizations/<id>/locations/global/firewallPolicies/<pid>"; each record
    #: carries its hierarchy attachments and priority-ordered rules.
    hierarchical_firewall_policies: dict[str, dict[str, Any]] | None = None
    #: Cloud Armor security policies keyed
    #: "projects/<p>/global/securityPolicies/<name>"; record: type + rules.
    cloud_armor_policies: dict[str, dict[str, Any]] | None = None
    #: VPC-SC service perimeters keyed
    #: "accessPolicies/<n>/servicePerimeters/<name>"; record: perimeter_type,
    #: use_explicit_dry_run_spec, and the status/spec config blocks.
    vpc_sc_perimeters: dict[str, dict[str, Any]] | None = None
    #: resource-hierarchy nodes keyed by node name ("organizations/1",
    #: "folders/2", "projects/acme-prod"); record: parent/type/number/display_name.
    resource_hierarchy: dict[str, dict[str, Any]] | None = None
    #: IAM binding sets keyed by resource full name
    #: ("//cloudresourcemanager.googleapis.com/projects/acme-prod").
    iam_bindings: dict[str, dict[str, Any]] | None = None
    #: EFFECTIVE org-policy set-policies keyed "<node>|<constraint>" — distinct
    #: from the ``constraints`` category, which holds the constraint DEFINITION;
    #: both are needed and neither substitutes for the other.
    org_policies: dict[str, dict[str, Any]] | None = None
    #: IAM v2 deny policies keyed by the v2 REST resource name
    #: ("policies/<url-encoded-attachment>/denypolicies/<id>"); record:
    #: attachment_point (decoded node) + rules (denied/exception principals and
    #: permissions, optional denial_condition).
    iam_deny_policies: dict[str, dict[str, Any]] | None = None

    # -- construction ---------------------------------------------------------

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "GcpSnapshot":
        """Load a snapshot from a JSON file. Offline; raises ValueError with
        the path on malformed content."""
        with open(path, encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ValueError(f"snapshot {path}: not valid JSON: {exc}") from exc
        try:
            snapshot = cls.from_dict(data)
        except ValueError as exc:
            raise ValueError(f"snapshot {path}: {exc}") from exc
        logger.debug("loaded snapshot %s (captured_at=%s, captured=%s)", path,
                     snapshot.captured_at, ",".join(snapshot.captured_categories()) or "none")
        return snapshot

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GcpSnapshot":
        if not isinstance(data, Mapping):
            raise ValueError(f"snapshot must be a mapping, got {type(data).__name__}")
        unrecognized = sorted(set(data) - {"captured_at", *_CATEGORIES})
        if unrecognized:
            raise ValueError(f"unrecognized snapshot keys {unrecognized} — a typo would "
                             f"silently demote a category to UNKNOWN; expected only "
                             f"'captured_at' and {list(_CATEGORIES)}")
        captured_at = data.get("captured_at")
        if not isinstance(captured_at, str) or not captured_at:
            raise ValueError("'captured_at' (non-empty ISO-8601 string) is required — "
                             "verdicts must be stampable with snapshot freshness")

        roles = _record_map(data.get("roles"), "roles")
        if roles is not None:
            for name, record in roles.items():
                if "included_permissions" not in record:
                    continue
                perms = record["included_permissions"]
                if perms is None:
                    raise ValueError(
                        f"snapshot.roles[{name!r}].included_permissions must be an "
                        f"array of strings, got null — omit the key when the role's "
                        f"permissions were not captured")
                got = _str_set(perms, f"roles[{name!r}].included_permissions")
                record["included_permissions"] = tuple(sorted(got or ()))

        constraints = _record_map(data.get("constraints"), "constraints")
        if constraints is not None:
            for name, record in constraints.items():
                value_type = record.get("value_type")
                if not isinstance(value_type, str) or not value_type:
                    raise ValueError(f"constraints[{name!r}] needs a 'value_type' string "
                                     f"(e.g. 'boolean' or 'list') — without it wrong-typed "
                                     f"usage cannot be contradicted")
                # OPTIONAL: the v2 Constraint.constraintDefault. Absent is
                # honest (the effective-state fold abstains by name); present
                # with an unrecognized spelling is rejected at parse time,
                # mirroring the value_type check — a half-recognized default
                # would be read as "not captured" and silently demote a
                # decidable fold to an abstention, or worse, tempt a reader
                # into a guess.
                if "constraint_default" in record and \
                        record["constraint_default"] not in ("ALLOW", "DENY"):
                    raise ValueError(
                        f"constraints[{name!r}].constraint_default must be "
                        f"'ALLOW' or 'DENY', got "
                        f"{record['constraint_default']!r} — omit the key when "
                        f"the managed default was not captured")

        return cls(
            captured_at=captured_at,
            roles=roles,
            permissions=_str_set(data.get("permissions"), "permissions"),
            principals=_str_set(data.get("principals"), "principals"),
            constraints=constraints,
            resource_types=_str_set(data.get("resource_types"), "resource_types"),
            networks=_str_set(data.get("networks"), "networks"),
            subnetworks=_str_set(data.get("subnetworks"), "subnetworks"),
            network_tags=_str_set(data.get("network_tags"), "network_tags"),
            service_accounts=_str_set(data.get("service_accounts"), "service_accounts"),
            access_levels=_str_set(data.get("access_levels"), "access_levels"),
            restricted_services=_str_set(data.get("restricted_services"), "restricted_services"),
            firewall_rules=_parse_firewall_rules(data.get("firewall_rules")),
            hierarchical_firewall_policies=_parse_hierarchical_firewall_policies(
                data.get("hierarchical_firewall_policies")),
            cloud_armor_policies=_parse_cloud_armor_policies(data.get("cloud_armor_policies")),
            vpc_sc_perimeters=_parse_vpc_sc_perimeters(data.get("vpc_sc_perimeters")),
            resource_hierarchy=_parse_resource_hierarchy(data.get("resource_hierarchy")),
            iam_bindings=_parse_iam_bindings(data.get("iam_bindings")),
            org_policies=_parse_org_policies(data.get("org_policies")),
            iam_deny_policies=_parse_iam_deny_policies(
                data.get("iam_deny_policies")),
        )

    def to_dict(self) -> dict[str, Any]:
        """Inverse of :meth:`from_dict`: only captured categories appear, all
        collections sorted, so dumps are deterministic and round-trips exact."""
        out: dict[str, Any] = {"captured_at": self.captured_at}
        if self.roles is not None:
            out["roles"] = {}
            for name in sorted(self.roles):
                record = dict(self.roles[name])
                if "included_permissions" in record:
                    record["included_permissions"] = list(record["included_permissions"])
                out["roles"][name] = record
        if self.permissions is not None:
            out["permissions"] = sorted(self.permissions)
        if self.principals is not None:
            out["principals"] = sorted(self.principals)
        if self.constraints is not None:
            out["constraints"] = {name: dict(self.constraints[name])
                                  for name in sorted(self.constraints)}
        if self.resource_types is not None:
            out["resource_types"] = sorted(self.resource_types)
        if self.networks is not None:
            out["networks"] = sorted(self.networks)
        if self.subnetworks is not None:
            out["subnetworks"] = sorted(self.subnetworks)
        if self.network_tags is not None:
            out["network_tags"] = sorted(self.network_tags)
        if self.service_accounts is not None:
            out["service_accounts"] = sorted(self.service_accounts)
        if self.access_levels is not None:
            out["access_levels"] = sorted(self.access_levels)
        if self.restricted_services is not None:
            out["restricted_services"] = sorted(self.restricted_services)
        for category in _RECORD_TABLES:
            table = getattr(self, category)
            if table is not None:
                # Outer keys sorted for deterministic dumps; inner list fields
                # are listified in place, order UNTOUCHED (rule order is semantic).
                out[category] = {name: _listify(table[name]) for name in sorted(table)}
        return out

    def captured_categories(self) -> tuple[str, ...]:
        """Which categories this snapshot actually enumerated."""
        return tuple(c for c in _CATEGORIES if getattr(self, c) is not None)

    # -- conservative lookups -------------------------------------------------
    #
    # Contract: True = exists in the snapshot; False = the category was
    # enumerated and the name is not in it; UNKNOWN = the category was never
    # captured, so absence of evidence is not evidence of absence.

    def role_exists(self, name: str) -> bool | Unknown:
        if self.roles is None:
            return UNKNOWN
        return name in self.roles

    def permission_exists(self, name: str) -> bool | Unknown:
        """Membership in the permission enumeration, or — since a permission a
        real role includes necessarily exists — in any role's
        ``included_permissions``. Only an explicit enumeration can prove
        absence; the union over captured roles is not one."""
        if self.permissions is not None and name in self.permissions:
            return True
        if self.roles is not None and name in self._role_included_permissions:
            return True
        if self.permissions is not None:
            return False
        return UNKNOWN

    def principal_exists(self, name: str) -> bool | Unknown:
        if self.principals is None:
            return UNKNOWN
        return name in self.principals

    def constraint(self, name: str) -> Mapping[str, Any] | None | Unknown:
        """The constraint record (carrying ``value_type``) — or None if
        constraints were enumerated and this one does not exist, or UNKNOWN
        if constraints were never captured."""
        if self.constraints is None:
            return UNKNOWN
        return self.constraints.get(name)

    def resource_type_exists(self, name: str) -> bool | Unknown:
        if self.resource_types is None:
            return UNKNOWN
        return name in self.resource_types

    def network_exists(self, name: str) -> bool | Unknown:
        if self.networks is None:
            return UNKNOWN
        return name in self.networks

    def subnetwork_exists(self, name: str) -> bool | Unknown:
        if self.subnetworks is None:
            return UNKNOWN
        return name in self.subnetworks

    def network_tag_exists(self, name: str) -> bool | Unknown:
        """PRESENCE-ONLY: GCP has no "list all network tags" API, so a captured
        vocabulary is inherently partial and a miss is not evidence of absence.
        Returns True when the tag is in a captured vocabulary and UNKNOWN
        otherwise — NEVER False. sx-reasoner-categories enforces the same
        asymmetry at the Datalog layer."""
        if self.network_tags is not None and name in self.network_tags:
            return True
        return UNKNOWN

    def service_account_exists(self, name: str) -> bool | Unknown:
        if self.service_accounts is None:
            return UNKNOWN
        return name in self.service_accounts

    def access_level_exists(self, name: str) -> bool | Unknown:
        if self.access_levels is None:
            return UNKNOWN
        return name in self.access_levels

    def restricted_service_exists(self, name: str) -> bool | Unknown:
        if self.restricted_services is None:
            return UNKNOWN
        return name in self.restricted_services

    # -- record-table accessors -----------------------------------------------
    #
    # Contract: the record mapping when captured and present; None when the
    # table was captured but the key is absent; UNKNOWN when the table was
    # never captured (so estate checks are forced to abstain, never fabricate).

    def firewall_rule(self, name: str) -> Mapping[str, Any] | None | Unknown:
        if self.firewall_rules is None:
            return UNKNOWN
        return self.firewall_rules.get(name)

    def hierarchical_firewall_policy(self, name: str) -> Mapping[str, Any] | None | Unknown:
        if self.hierarchical_firewall_policies is None:
            return UNKNOWN
        return self.hierarchical_firewall_policies.get(name)

    def cloud_armor_policy(self, name: str) -> Mapping[str, Any] | None | Unknown:
        """The captured Cloud Armor policy — resolving a BARE policy name against
        the captured table when exactly one row carries that leaf name.

        The table is keyed ``projects/<project>/global/securityPolicies/<name>``,
        as :data:`gcp_grounding.identity.CATEGORY_SPECS` requires, but a
        terraform ``google_compute_security_policy_rule`` names its parent policy
        bare (``security_policy = "armor-policy-prod"``), so a proposed rule
        carries no project to qualify it with. Resolving the leaf name here does
        NOT mint a key from a guess: the project comes from the captured row
        itself, and an ambiguous leaf name (two projects, one policy name) stays
        None rather than picking one. That is the same shape as
        :meth:`hierarchy_node`'s alias resolution, and it is why
        ``identity.canonical_key`` can keep refusing a bare name outright —
        minting an identity and finding an existing one are different questions.
        """
        if self.cloud_armor_policies is None:
            return UNKNOWN
        record = self.cloud_armor_policies.get(name)
        if record is not None or "/" in name:
            return record
        matches = [value for key, value in self.cloud_armor_policies.items()
                   if key.rsplit("/", 1)[-1] == name]
        if len(matches) == 1:
            return matches[0]
        return None

    def vpc_sc_perimeter(self, name: str) -> Mapping[str, Any] | None | Unknown:
        if self.vpc_sc_perimeters is None:
            return UNKNOWN
        return self.vpc_sc_perimeters.get(name)

    def hierarchy_node(self, name: str) -> Mapping[str, Any] | None | Unknown:
        """The hierarchy record — resolving the ``projects/<number>`` alias VPC-SC
        uses when CRM keys the same project by id. UNKNOWN when uncaptured, None
        when captured but neither the name nor an alias matches."""
        if self.resource_hierarchy is None:
            return UNKNOWN
        record = self.resource_hierarchy.get(name)
        if record is not None:
            return record
        canonical = self._hierarchy_alias_index.get(name)
        if canonical is not None:
            return self.resource_hierarchy.get(canonical)
        return None

    def iam_binding_set(self, resource: str) -> Mapping[str, Any] | None | Unknown:
        if self.iam_bindings is None:
            return UNKNOWN
        return self.iam_bindings.get(resource)

    def org_policy(self, node: str, constraint: str) -> Mapping[str, Any] | None | Unknown:
        """The effective set-policy at ``node`` for ``constraint``. Builds the
        composite ``<node>|<constraint>`` key itself so no caller hand-joins it."""
        if self.org_policies is None:
            return UNKNOWN
        return self.org_policies.get(f"{node}|{constraint}")

    def iam_deny_policy(self, name: str) -> Mapping[str, Any] | None | Unknown:
        if self.iam_deny_policies is None:
            return UNKNOWN
        return self.iam_deny_policies.get(name)

    # -- table-wide estate accessors ------------------------------------------
    #
    # UNKNOWN when the category is uncaptured, so an ESTATE check that would sweep
    # the whole table is forced to abstain rather than read an empty sweep as
    # "no matching rule".

    def firewall_rules_for_network(self, network: str) -> tuple[Mapping[str, Any], ...] | Unknown:
        if self.firewall_rules is None:
            return UNKNOWN
        return tuple(self.firewall_rules[name]
                     for name in sorted(self.firewall_rules)
                     if self.firewall_rules[name].get("network") == network)

    def firewall_policies_attached_to(self, node: str) -> tuple[Mapping[str, Any], ...] | Unknown:
        if self.hierarchical_firewall_policies is None:
            return UNKNOWN
        return tuple(self.hierarchical_firewall_policies[name]
                     for name in sorted(self.hierarchical_firewall_policies)
                     if node in (self.hierarchical_firewall_policies[name].get("attachments") or ()))

    def iam_deny_policies_attached_to(self, node: str) -> tuple[Mapping[str, Any], ...] | Unknown:
        """The captured deny policies attached at exactly *node* — UNKNOWN when
        the table was never captured (mirrors
        :meth:`firewall_policies_attached_to`). Ancestor walks stay in the
        CHECK, composed from :meth:`hierarchy_node`, keeping this module dumb."""
        if self.iam_deny_policies is None:
            return UNKNOWN
        return tuple(self.iam_deny_policies[name]
                     for name in sorted(self.iam_deny_policies)
                     if self.iam_deny_policies[name].get("attachment_point") == node)

    # -- hierarchy name resolution --------------------------------------------

    def hierarchy_names(self) -> frozenset[str] | Unknown:
        """Every hierarchy key PLUS, for each captured project with a non-null
        number, the ``projects/<number>`` alias — VPC-SC references projects by
        number while CRM uses the id. UNKNOWN when uncaptured."""
        if self.resource_hierarchy is None:
            return UNKNOWN
        names = set(self.resource_hierarchy)
        for record in self.resource_hierarchy.values():
            number = record.get("number")
            if record.get("type") == "project" and number:
                names.add(f"projects/{number}")
        return frozenset(names)

    @cached_property
    def _hierarchy_alias_index(self) -> dict[str, str]:
        """Reverse ``projects/<number>`` alias → canonical hierarchy key."""
        index: dict[str, str] = {}
        for name, record in (self.resource_hierarchy or {}).items():
            number = record.get("number")
            if record.get("type") == "project" and number:
                index[f"projects/{number}"] = name
        return index

    @cached_property
    def _role_included_permissions(self) -> frozenset[str]:
        found: set[str] = set()
        for record in (self.roles or {}).values():
            # `or ()`: from_dict rejects a null included_permissions, but a
            # hand-constructed snapshot may still carry None — read it as
            # "nothing included", never crash.
            found.update(record.get("included_permissions") or ())
        return frozenset(found)
