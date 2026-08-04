"""The one place the requirements compiler and the grounding domains meet.

Without this module the compiler can only ever express IAM-allow and org-policy
promises: :data:`gcp_grounding.sec_ast.COLLECTIONS` ships four entries and
nothing outside ``sec_ast`` / ``sec_encode`` / ``sec_rules`` ever calls
:func:`~gcp_grounding.sec_ast.register_collection` or
:func:`~gcp_grounding.sec_rules.register_extractor`. A user who writes "no
ingress firewall rule may allow tcp/22 from 0.0.0.0/0" in markdown deserves a
rule that RUNS, not one that abstains forever.

One entry point
---------------

:func:`register` is idempotent (a module-global guard makes repeated calls
free). ``sec_ast._ensure_domains()`` and ``sec_rules.load_rules`` both call it
and NEITHER imports this module at module level, so there is no cycle. Every
import of a domain *claims* module happens INSIDE :func:`register`, guarded by
``try/except ImportError`` that logs at debug and skips just that domain — a
partial checkout registers what it has. The collection *specs*, by contrast, are
registered unconditionally: a promise naming ``armor_rules`` in a checkout
without ``armor_claims`` then compiles and abstains loudly (no extractor → a
missing_reason) instead of failing as an unknown collection.

ONE ROW PER SCALAR COMBINATION
------------------------------

The term language has no tuples, so every collection here is FLAT: a firewall
rule with two source ranges and two ports becomes FOUR records, one per
(range, port) combination, and a quantifier-free ``exists`` / ``forall`` over
the collection then says exactly what an author means. This is the difference
between a usable authoring surface and one that silently under-matches.

Two conventions follow from the flattening, and both exist to keep a promise
from passing vacuously:

* A dimension with no values contributes NO key to the row when its sort has no
  honest empty scalar (a rule with no source ranges, a protocol matching *all*
  ports, a port range too wide to enumerate — see :data:`MAX_PORT_SPAN`). The
  rule still produces rows, so a promise that does not mention the field still
  judges it; a promise that DOES mention it abstains loudly through
  ``sec_encode``'s "missing from the record" :class:`~gcp_grounding.sec_encode.
  UnsupportedTerm`. Filling in ``0.0.0.0/0`` or ``0.0.0.0/32`` instead would
  fabricate either a false ``contradicted`` or a false pass.
* A ``Str`` dimension with no values contributes the empty string, which is an
  honest "no tag" / "no expression".

A claim payload carrying the shared ``"unsupported"`` key is NOT dropped: the
extractor returns a missing_reason naming the rule, because dropping the row
would let a ``forall`` promise pass vacuously — the same fabricate-a-proof
failure the domain checks refuse.

Records come from CLAIM PAYLOADS
--------------------------------

Proposal-tier extractors read the claims the domain claims modules already
produce (``firewall_rule`` via ``fw_claims``, ``security_policy_rule`` via
``armor_claims``, ``perimeter_config`` via ``vpcsc_claims``), never by
re-parsing the document: the payload is the normalized form and a second parser
would let the two drift. The estate-tier extractors read
``ctx.snapshot.firewall_rules`` / ``ctx.snapshot.hierarchical_firewall_policies``
and honour the captured bit by comparing with ``is`` — never truth-testing,
because :data:`gcp_grounding.knowledge.UNKNOWN` refuses ``bool``. Records are
sorted by their scalar fields for determinism, mirroring the sorted-pairs
convention of ``constraints.check_policy_subset`` (constraints.py:442-446).
"""

from __future__ import annotations

import importlib
from typing import Any, Callable, Iterable, Mapping

from . import sec_ast, sec_encode, sec_rules, tf_claims
from .core.log import get_logger
from .knowledge import UNKNOWN
from .sec_ast import CollectionSpec

logger = get_logger(__name__)

__all__ = [
    "register", "reset", "registered",
    "COLLECTION_SPECS", "DOMAIN_COLLECTIONS", "DOMAIN_MODULES",
    "PROTOCOL_NUMBERS", "MAX_PORT_SPAN",
]


# -- collection specs ---------------------------------------------------------
#
# Sorts are chosen so the EXISTING ``cidr_contains`` and ``port_in`` encoders
# apply with no override: every ``Cidr`` field declares its companion
# ``<field>_mask`` of sort ``Ip4`` (sec_ast rejects a Cidr field without one),
# ports are ``Port`` and protocols ``Proto``.

#: Shared by the proposal-tier and estate-tier VPC firewall collections, so one
#: promise text can be pointed at either tier without a field rename.
_FIREWALL_FIELDS = {
    "name": "Str",
    "network": "Str",
    "direction": "Str",
    "action": "Str",
    "priority": "Int",
    "disabled": "Bool",
    "source_range": "Cidr",
    "source_range_mask": "Ip4",
    "destination_range": "Cidr",
    "destination_range_mask": "Ip4",
    "source_tag": "Str",
    "target_tag": "Str",
    "protocol": "Proto",
    "port": "Port",
}

_HIER_FIELDS = {
    "policy": "Str",
    "node": "Str",
    "priority": "Int",
    "action": "Str",
    "direction": "Str",
    "src_range": "Cidr",
    "src_range_mask": "Ip4",
    "protocol": "Proto",
    "port": "Port",
}

_ARMOR_FIELDS = {
    "policy": "Str",
    "priority": "Int",
    "action": "Str",
    "preview": "Bool",
    "src_range": "Cidr",
    "src_range_mask": "Ip4",
    "expr": "Str",
}

#: ``section`` is "status" or "spec" — the dry-run half of a perimeter is a
#: different promise from the enforced half, and conflating them would let a
#: spec-only change read as enforced.
_PERIMETER_RESOURCE_FIELDS = {"perimeter": "Str", "resource": "Str", "section": "Str"}
_PERIMETER_SERVICE_FIELDS = {"perimeter": "Str", "service": "Str", "section": "Str"}

#: Domain → its collections, in ``sec_artifact.DOMAINS``-compatible order (the
#: two domains already covered by ``sec_rules``' built-ins are absent).
DOMAIN_COLLECTIONS: dict[str, tuple[str, ...]] = {
    "vpc_firewall": ("proposed_firewall_rules", "firewall_rules"),
    "cloud_armor": ("armor_rules",),
    "hier_firewall": ("hier_firewall_rules",),
    "vpc_sc": ("perimeter_resources", "perimeter_restricted_services"),
}

#: The claims module each domain's proposal-tier extractor is built from. Absent
#: from a partial checkout is not an error — see :func:`_domain_module`.
DOMAIN_MODULES: dict[str, str] = {
    "vpc_firewall": "fw_claims",
    "cloud_armor": "armor_claims",
    "vpc_sc": "vpcsc_claims",
}

#: Every spec :func:`register` installs, in :data:`DOMAIN_COLLECTIONS` order.
COLLECTION_SPECS: tuple[CollectionSpec, ...] = (
    CollectionSpec("proposed_firewall_rules", "proposal", _FIREWALL_FIELDS),
    CollectionSpec("firewall_rules", "estate", _FIREWALL_FIELDS),
    CollectionSpec("armor_rules", "proposal", _ARMOR_FIELDS),
    CollectionSpec("hier_firewall_rules", "estate", _HIER_FIELDS),
    CollectionSpec("perimeter_resources", "proposal", _PERIMETER_RESOURCE_FIELDS),
    CollectionSpec("perimeter_restricted_services", "proposal",
                   _PERIMETER_SERVICE_FIELDS),
)

#: IANA numbers for the protocol names a GCP rule may spell; ``"all"`` has none
#: (it is every protocol) and is represented by omitting the ``protocol`` key.
PROTOCOL_NUMBERS: dict[str, int] = {
    "icmp": 1, "igmp": 2, "ipip": 4, "tcp": 6, "udp": 17, "gre": 47,
    "esp": 50, "ah": 51, "ipv6-icmp": 58, "sctp": 132,
}

#: The widest port range flattened into one row per port. A wider range (e.g.
#: ``0-65535``) yields one row whose ``port`` key is omitted, so a port-mentioning
#: promise abstains loudly instead of under-matching or exploding the instance.
MAX_PORT_SPAN = 256

#: The terraform-plan document kind, which can carry any domain's resources.
_TF_PLAN = "tf_plan"


class _Undecidable(Exception):
    """Internal: this collection cannot be built; the message IS the
    missing_reason handed back to :class:`gcp_grounding.sec_rules.CompiledRule`."""


# -- scalar helpers -----------------------------------------------------------

def _dotted(value: int) -> str:
    """A 32-bit integer → its dotted quad (the ``Ip4`` spelling of a mask)."""
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def _reject_unsupported(label: str, name: str, payload: Mapping[str, Any]) -> None:
    """Refuse a record whose payload carries the shared ``"unsupported"`` key.

    Dropping it would let a ``forall`` promise pass vacuously; naming it makes
    the whole rule abstain, which is the honest outcome."""
    reason = payload.get("unsupported")
    if reason is not None:
        raise _Undecidable(f"{label} {name!r} was not fully understood ({reason}) — "
                           "the rule was not evaluated")


def _rows(base: Mapping[str, Any], dimensions: Iterable[list]) -> list[dict]:
    """The cartesian product of *dimensions* over *base* — the flattening rule.

    Each dimension is a list of partial rows; a dimension with nothing to say
    contributes ``[{}]`` and so leaves its keys off the record."""
    rows = [dict(base)]
    for dimension in dimensions:
        rows = [{**row, **extra} for row in rows for extra in dimension]
    return rows


def _sorted(records: list[dict], fields: Mapping[str, str]) -> tuple:
    """*records* sorted by their scalar fields, in declared field order.

    An absent key sorts after every present one, so the order is total and
    deterministic even though rows are deliberately ragged."""
    order = tuple(fields)
    records.sort(key=lambda record: tuple(
        (0, str(record[field])) if field in record else (1, "") for field in order))
    return tuple(records)


# -- dimension builders -------------------------------------------------------

def _cidr_dimension(label: str, name: str, field: str, values: Any) -> list[dict]:
    """One partial row per CIDR, carrying the range and its ``Ip4`` mask.

    An empty list contributes nothing (the key is omitted); an unparseable range
    makes the whole collection abstain rather than be quietly skipped."""
    entries = [v for v in _iterable(values) if isinstance(v, str) and v]
    if not entries:
        return [{}]
    rows = []
    for value in entries:
        try:
            _base, mask = sec_encode.parse_cidr(value)
        except sec_encode.UnsupportedTerm:
            raise _Undecidable(
                f"{label} {name!r} carries {field.replace('_', ' ')} {value!r}, "
                "which is not a CIDR block — the rule was not evaluated") from None
        rows.append({field: value, f"{field}_mask": _dotted(mask)})
    return rows


def _str_dimension(field: str, values: Any) -> list[dict]:
    """One partial row per string; an empty list contributes the empty string,
    the honest "no tag" value of a ``Str`` field."""
    entries = [v for v in _iterable(values) if isinstance(v, str) and v]
    return [{field: value} for value in entries] or [{field: ""}]


def _layer4_dimension(label: str, name: str, entries: Any) -> list[dict]:
    """One partial row per (protocol, port) pair of a rule's layer-4 match."""
    blocks = [e for e in _iterable(entries) if isinstance(e, Mapping)]
    if not blocks:
        return [{}]
    rows = []
    for block in blocks:
        protocol = _protocol_number(label, name, block.get("protocol"))
        for port in _port_values(label, name, block.get("ports")):
            row: dict[str, Any] = {}
            if protocol is not None:
                row["protocol"] = protocol
            if port is not None:
                row["port"] = port
            rows.append(row)
    return rows or [{}]


def _iterable(value: Any) -> tuple:
    """*value* as a tuple of items; a non-sequence (or None) is empty. Snapshot
    records carry tuples, claim payloads carry lists — both land here."""
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return ()


def _protocol_number(label: str, name: str, protocol: Any) -> int | None:
    """The IANA number of *protocol*, or None for ``"all"`` / an absent value.

    None omits the ``protocol`` key, so a protocol-mentioning promise abstains
    rather than pick one of the 256 protocols ``all`` covers. A name with no
    number is undecidable: guessing could invert an allow/deny decision."""
    if protocol is None or protocol == "all":
        return None
    if isinstance(protocol, bool):
        number = None
    elif isinstance(protocol, int):
        number = protocol
    elif isinstance(protocol, str) and protocol.lower() in PROTOCOL_NUMBERS:
        number = PROTOCOL_NUMBERS[protocol.lower()]
    elif isinstance(protocol, str) and protocol.isdigit():
        number = int(protocol)
    else:
        number = None
    if number is None or not 0 <= number <= 255:
        raise _Undecidable(f"{label} {name!r} names protocol {protocol!r}, which has "
                           "no IANA protocol number — the rule was not evaluated")
    return number


def _port_values(label: str, name: str, ports: Any) -> list:
    """The scalar ports a layer-4 block matches.

    ``[]`` (all ports for the protocol) and a range wider than
    :data:`MAX_PORT_SPAN` yield ``None`` — one row whose ``port`` key is omitted.
    An unparseable port makes the collection abstain."""
    entries = [p for p in _iterable(ports) if isinstance(p, (str, int))]
    if not entries:
        return [None]
    scalars: set = set()
    wide = False
    for port in entries:
        low, high = _port_bounds(label, name, port)
        if high - low + 1 > MAX_PORT_SPAN:
            logger.debug("%s %r port range %r spans more than %d ports; its rows omit "
                         "the port field", label, name, port, MAX_PORT_SPAN)
            wide = True
            continue
        scalars.update(range(low, high + 1))
    values: list = sorted(scalars)
    if wide:
        values.append(None)
    return values or [None]


def _port_bounds(label: str, name: str, port: Any) -> tuple[int, int]:
    """``"22"`` → (22, 22) and ``"80-90"`` → (80, 90); anything else abstains."""
    text = str(port).strip()
    low_text, _, high_text = text.partition("-")
    high_text = high_text or low_text
    if not (low_text.isdigit() and high_text.isdigit()):
        raise _Undecidable(f"{label} {name!r} carries port {port!r}, which is neither "
                           "a port nor a port range — the rule was not evaluated")
    low, high = int(low_text), int(high_text)
    if not 0 <= low <= high <= 65535:
        raise _Undecidable(f"{label} {name!r} carries port {port!r}, which is outside "
                           "0..65535 — the rule was not evaluated")
    return low, high


# -- claim / snapshot access --------------------------------------------------

def _document_claims(ctx, module, claim_kind: str, label: str):
    """The claims of *claim_kind* the domain module makes about ``ctx.document``.

    Returns ``(claims, None)`` or ``((), missing_reason)``. A terraform plan can
    carry any domain's resources, so it goes through
    :func:`gcp_grounding.tf_claims.terraform_plan_claims` (which reaches the same
    domain extractor through the registry); every other document kind is looked
    up in the module's own ``DOCUMENT_EXTRACTORS`` table."""
    if ctx.document is None:
        return (), f"no document under review — the {label} rule was not evaluated"
    kind = ctx.document_kind
    if kind == _TF_PLAN:
        claims = tf_claims.terraform_plan_claims(ctx.document)
    else:
        extractor = getattr(module, "DOCUMENT_EXTRACTORS", {}).get(kind)
        if extractor is None:
            return (), f"the document under review is not a {label}"
        claims = extractor(ctx.document)
    return tuple(c for c in claims if c.kind == claim_kind), None


def _claim_name(payload: Mapping[str, Any], claim) -> str:
    """The record's own name: the payload's, or the claim value it is anchored
    to (a terraform rule whose name is known-after-apply has only the latter)."""
    name = payload.get("name")
    return name if isinstance(name, str) and name else claim.value


def _estate_table(snapshot, name: str) -> Mapping[str, Any]:
    """The captured estate table *name*, or abstain with the shared reason.

    The captured bit is read with ``is`` and NEVER truth-tested: ``UNKNOWN``
    raises on ``bool`` precisely so an uncaptured category cannot be mistaken for
    an empty one. A snapshot from a checkout without the estate tables has no
    such attribute at all, which is the same "not captured" answer."""
    table = getattr(snapshot, name, UNKNOWN)
    if table is UNKNOWN or table is None or not isinstance(table, Mapping):
        raise _Undecidable(f"snapshot did not capture {name} — the estate-tier rule "
                           "was not evaluated")
    return table


# -- the extractors -----------------------------------------------------------

def _firewall_records(rules: Iterable[tuple], label: str) -> tuple:
    """The flattened rows of ``(name, normalized rule)`` pairs — shared by the
    proposal and estate VPC firewall collections, which share one field set."""
    records: list[dict] = []
    for name, rule in rules:
        if not isinstance(rule, Mapping):
            raise _Undecidable(f"{label} {name!r} is not a record — the rule was not "
                               "evaluated")
        _reject_unsupported(label, name, rule)
        base: dict[str, Any] = {"name": name}
        for key in ("network", "direction", "action", "priority", "disabled"):
            value = rule.get(key)
            if value is not None:
                base[key] = value
        records.extend(_rows(base, (
            _cidr_dimension(label, name, "source_range", rule.get("source_ranges")),
            _cidr_dimension(label, name, "destination_range",
                            rule.get("destination_ranges")),
            _str_dimension("source_tag", rule.get("source_tags")),
            _str_dimension("target_tag", rule.get("target_tags")),
            _layer4_dimension(label, name, rule.get("layer4")),
        )))
    return _sorted(records, _FIREWALL_FIELDS)


def _proposed_firewall_rules(module) -> Callable:
    """``proposed_firewall_rules`` from the document's ``firewall_rule`` claims."""
    def extract(ctx):
        claims, missing = _document_claims(ctx, module, "firewall_rule",
                                           "VPC firewall rule")
        if missing is not None:
            return (), missing
        rules = [(_claim_name(c.fields(), c), c.fields()) for c in claims]
        return _firewall_records(rules, "firewall rule"), None
    return extract


def _estate_firewall_rules(ctx):
    """``firewall_rules`` from the captured estate table."""
    table = _estate_table(ctx.snapshot, "firewall_rules")
    return _firewall_records([(key, table[key]) for key in sorted(table)],
                             "firewall rule"), None


def _estate_hier_firewall_rules(ctx):
    """``hier_firewall_rules``: one row per (policy, attachment, rule, range,
    protocol/port) — the attachment is what makes a hierarchical rule reachable
    from a node, so it is a scalar dimension like any other."""
    table = _estate_table(ctx.snapshot, "hierarchical_firewall_policies")
    label = "hierarchical firewall rule"
    records: list[dict] = []
    for policy in sorted(table):
        record = table[policy]
        if not isinstance(record, Mapping):
            raise _Undecidable(f"hierarchical firewall policy {policy!r} is not a "
                               "record — the rule was not evaluated")
        nodes = _str_dimension("node", record.get("attachments"))
        for index, rule in enumerate(_iterable(record.get("rules"))):
            name = f"{policy}[{index}]"
            if not isinstance(rule, Mapping):
                raise _Undecidable(f"{label} {name!r} is not a record — the rule was "
                                   "not evaluated")
            _reject_unsupported(label, name, rule)
            base: dict[str, Any] = {"policy": policy}
            for key in ("priority", "action", "direction"):
                value = rule.get(key)
                if value is not None:
                    base[key] = value
            match = rule.get("match")
            match = match if isinstance(match, Mapping) else {}
            records.extend(_rows(base, (
                nodes,
                _cidr_dimension(label, name, "src_range", match.get("src_ip_ranges")),
                _layer4_dimension(label, name, match.get("layer4")),
            )))
    return _sorted(records, _HIER_FIELDS), None


def _armor_rules(module) -> Callable:
    """``armor_rules`` from the document's ``security_policy_rule`` claims."""
    label = "security policy rule"

    def extract(ctx):
        claims, missing = _document_claims(ctx, module, "security_policy_rule",
                                           "Cloud Armor security policy")
        if missing is not None:
            return (), missing
        records: list[dict] = []
        for claim in claims:
            payload = claim.fields()
            policy = payload.get("policy")
            policy = policy if isinstance(policy, str) and policy else claim.value
            name = f"{policy}[{payload.get('priority')}]"
            _reject_unsupported(label, name, payload)
            base: dict[str, Any] = {"policy": policy}
            for key in ("priority", "action", "preview"):
                value = payload.get(key)
                if value is not None:
                    base[key] = value
            match = payload.get("match")
            match = match if isinstance(match, Mapping) else {}
            expr = match.get("expr")
            base["expr"] = expr if isinstance(expr, str) else ""
            records.extend(_rows(base, (
                _cidr_dimension(label, name, "src_range", match.get("src_ip_ranges")),
            )))
        return _sorted(records, _ARMOR_FIELDS), None
    return extract


def _perimeter_entries(module, collection: str, field: str, source: str,
                       fields: Mapping[str, str]) -> Callable:
    """``perimeter_resources`` / ``perimeter_restricted_services`` from the
    document's ``perimeter_config`` claims — one row per (perimeter, entry,
    section), where the section is "status" (enforced) or "spec" (dry-run)."""
    def extract(ctx):
        claims, missing = _document_claims(ctx, module, "perimeter_config",
                                           "VPC Service Controls perimeter")
        if missing is not None:
            return (), missing
        records: list[dict] = []
        for claim in claims:
            payload = claim.fields()
            perimeter = _claim_name(payload, claim)
            _reject_unsupported("perimeter", perimeter, payload)
            for section in ("spec", "status"):
                block = payload.get(section)
                if not isinstance(block, Mapping):
                    continue
                for value in _iterable(block.get(source)):
                    if isinstance(value, str) and value:
                        records.append({"perimeter": perimeter, field: value,
                                        "section": section})
        return _sorted(records, fields), None
    extract.__doc__ = f"Records for the {collection} collection."
    return extract


# -- registration -------------------------------------------------------------

def _guarded(collection: str, fn: Callable) -> Callable:
    """*fn* with the two honest failure channels wired up: an
    :class:`_Undecidable` becomes the missing_reason verbatim, and any other
    exception becomes a missing_reason naming the extractor — a crashing domain
    module abstains, it never breaks the gate."""
    def extract(ctx):
        try:
            return fn(ctx)
        except _Undecidable as exc:
            return (), str(exc)
        except Exception as exc:  # noqa: BLE001 - a broken domain must not crash
            logger.debug("the %s extractor failed (%s); the rule abstains",
                         collection, exc, exc_info=True)
            return (), (f"the {collection} extractor failed ({exc}) — the rule was "
                        "not evaluated")
    extract.__name__ = f"{collection}_records"
    extract.__doc__ = f"Instance extractor for the {collection} collection."
    return extract


def _domain_module(name: str):
    """The domain claims module *name*, or None when this checkout lacks it.

    Imported by string through :mod:`importlib` (never a static import) so a
    checkout without the module still imports THIS one, exactly like
    ``registry._providers``."""
    try:
        return importlib.import_module(f"gcp_grounding.{name}")
    except ImportError as exc:
        logger.debug("domain module gcp_grounding.%s is not part of this checkout "
                     "(%s); its collections have no extractor and abstain", name, exc)
        return None


_REGISTERED = False


def registered() -> bool:
    """Whether :func:`register` has already run in this process."""
    return _REGISTERED


def reset() -> None:
    """Forget that :func:`register` ran, so the next call re-registers.

    For tests; production code never needs it (mirrors
    :func:`gcp_grounding.sec_ast.reset_domain_cache`)."""
    global _REGISTERED
    _REGISTERED = False


def register() -> None:
    """Register the domain collections and instance extractors, once.

    Idempotent: the second call returns immediately. Collections are registered
    unconditionally (re-registering an identical spec is a no-op in
    :func:`~gcp_grounding.sec_ast.register_collection`); extractors that need a
    domain claims module are registered only when that module imports.
    """
    global _REGISTERED
    if _REGISTERED:
        return
    # Cache the attempt BEFORE it runs, like sec_ast._ensure_domains, so a
    # failure is not retried on every validate().
    _REGISTERED = True

    for spec in COLLECTION_SPECS:
        try:
            sec_ast.register_collection(spec)
        except ValueError as exc:
            # Someone registered this name with a different shape. Registering
            # ours would not fix that, and raising would break every validate();
            # say so and leave theirs in place.
            logger.warning("collection %s could not be registered (%s)",
                           spec.name, exc)

    firewall = _domain_module(DOMAIN_MODULES["vpc_firewall"])
    if firewall is not None:
        sec_rules.register_extractor(
            "proposed_firewall_rules",
            _guarded("proposed_firewall_rules", _proposed_firewall_rules(firewall)))
    sec_rules.register_extractor(
        "firewall_rules", _guarded("firewall_rules", _estate_firewall_rules))

    armor = _domain_module(DOMAIN_MODULES["cloud_armor"])
    if armor is not None:
        sec_rules.register_extractor(
            "armor_rules", _guarded("armor_rules", _armor_rules(armor)))

    sec_rules.register_extractor(
        "hier_firewall_rules",
        _guarded("hier_firewall_rules", _estate_hier_firewall_rules))

    vpcsc = _domain_module(DOMAIN_MODULES["vpc_sc"])
    if vpcsc is not None:
        sec_rules.register_extractor(
            "perimeter_resources",
            _guarded("perimeter_resources",
                     _perimeter_entries(vpcsc, "perimeter_resources", "resource",
                                        "resources", _PERIMETER_RESOURCE_FIELDS)))
        sec_rules.register_extractor(
            "perimeter_restricted_services",
            _guarded("perimeter_restricted_services",
                     _perimeter_entries(vpcsc, "perimeter_restricted_services",
                                        "service", "restricted_services",
                                        _PERIMETER_SERVICE_FIELDS)))
