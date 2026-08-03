"""The shared z3 packet algebra: CIDR bitvectors, port intervals, protocol
sets, tag / service-account universes and priority-ordered ``Ite`` folds.

This is the reusable symbolic encoding behind the VPC-firewall,
hierarchical-firewall and Cloud Armor grounding checks. It is *pure
encoding*: every function here produces z3 terms and nothing else — it
never builds a :class:`~gcp_grounding.core.report.Verdict`, never reads a
snapshot, and never decides satisfiability itself. The caller owns the
solver and the polarity.

The module **never imports z3**. Exactly like :mod:`gcp_grounding.constraints`,
the caller obtains the z3 module from ``constraints._z3_module(get_solver())``
and threads it in as the first argument; on the builtin backend that argument
is ``None`` and every term-building entry point raises
:class:`UnsupportedPacket` (never ``AttributeError``), so the caller's existing
``except UnsupportedPacket`` arm produces an honest ``unverified`` instead of a
crash inside the fail-open gate. The only third-party dependency is stdlib
:mod:`ipaddress`, used for parsing.

Encoding invariants that carry the whole value of the module:

* ``src`` / ``dst`` are 32-bit bitvectors, ``proto`` 8-bit, ``port`` 16-bit;
  IPv4 only.
* CIDR containment is **mask equality**, not ``Extract``:
  ``(addr & mask) == (net & mask)`` — a ``/0`` prefix is ``BoolVal(True)``,
  which is the containment a string match on ``"0.0.0.0/0"`` cannot make.
* Every bitvector comparison is **unsigned** (``UGE`` / ``ULE`` / ``ULT`` /
  ``UGT``); Python ``>=`` on a z3 bitvector is *signed* and would misclassify
  any port ≥ 32768.
* An empty CIDR list matches **nothing** (``BoolVal(False)``) — it proves
  nothing, it does not match everything. An absent / empty port list matches
  **every** port (``BoolVal(True)``), matching GCP's "no ports means all
  ports" rule.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Mapping

__all__ = [
    "UnsupportedPacket",
    "PROTOCOL_NUMBERS",
    "SENSITIVE_PORTS",
    "NON_PUBLIC_RANGES",
    "PacketVars",
    "packet_vars",
    "universe_axioms",
    "parse_cidr",
    "cidr_match",
    "any_cidr_match",
    "is_public",
    "parse_port_range",
    "port_match",
    "protocol_match",
    "layer4_match",
    "rule_match",
    "effective_allow",
    "witness_packet",
]


class UnsupportedPacket(Exception):
    """A rule shape or operand the packet encoding cannot represent, or z3 is
    absent. The caller abstains with ``unverified`` — never a false verdict and
    never a dropped rule."""


# IP protocol numbers (IANA) for the names GCP firewall rules accept.
PROTOCOL_NUMBERS: Mapping[str, int] = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1,
    "ipip": 4,
    "gre": 47,
    "esp": 50,
    "ah": 51,
    "sctp": 132,
}

# Ports whose public exposure is a finding on its own (management planes,
# databases, container runtimes, caches). Consumed by the domain checks; the
# encoding itself is agnostic to which ports are "sensitive".
SENSITIVE_PORTS: frozenset = frozenset(
    {21, 22, 23, 135, 139, 445, 1433, 2375, 2376, 3306, 3389,
     5432, 5601, 5900, 6379, 9200, 10250, 11211, 27017}
)

# Address ranges that are NOT public: RFC 1918 / CGN / loopback / link-local /
# the unspecified address, plus GCP's own reserved ranges — the health-check
# probers (35.191.0.0/16, 130.211.0.0/22) and IAP TCP forwarding
# (35.235.240.0/20), which a rule may legitimately open without that being
# "exposed to the internet".
NON_PUBLIC_RANGES: tuple = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "0.0.0.0/32",
    "35.191.0.0/16",
    "130.211.0.0/22",
    "35.235.240.0/20",
)

_ADDR_BITS = 32
_PROTO_BITS = 8
_PORT_BITS = 16
_MAX_PORT = (1 << _PORT_BITS) - 1

_SRC_TAG = "src.tag:"
_TGT_TAG = "tgt.tag:"
_SRC_SA = "src.sa:"
_TGT_SA = "tgt.sa:"


def _require(z3):
    """Guard for every term-building entry point: turn a missing z3 module into
    the honest :class:`UnsupportedPacket` the caller already handles, rather
    than an ``AttributeError`` deep inside the encoding."""
    if z3 is None:
        raise UnsupportedPacket("no z3 module — packet terms cannot be built")


@dataclass(frozen=True)
class PacketVars:
    """The free symbolic packet: address / protocol / port bitvectors plus the
    finite boolean universes of source and target network tags and service
    accounts (each a ``{name: z3.Bool}`` mapping)."""

    src: Any
    dst: Any
    proto: Any
    port: Any
    src_tags: Mapping[str, Any]
    target_tags: Mapping[str, Any]
    src_sas: Mapping[str, Any]
    target_sas: Mapping[str, Any]


def packet_vars(z3, *, tags=(), service_accounts=()) -> PacketVars:
    """Build a fresh :class:`PacketVars` over a caller-supplied *finite*
    universe of *tags* and *service_accounts*.

    Each tag becomes one boolean per side (a source instance and a target
    instance carry tags independently); each service account likewise. The
    names are stable so that :func:`rule_match` referencing a tag by name
    reaches the very same z3 constant.
    """
    _require(z3)
    tags = tuple(tags)
    sas = tuple(service_accounts)
    return PacketVars(
        src=z3.BitVec("src", _ADDR_BITS),
        dst=z3.BitVec("dst", _ADDR_BITS),
        proto=z3.BitVec("proto", _PROTO_BITS),
        port=z3.BitVec("port", _PORT_BITS),
        src_tags={t: z3.Bool(f"{_SRC_TAG}{t}") for t in tags},
        target_tags={t: z3.Bool(f"{_TGT_TAG}{t}") for t in tags},
        src_sas={e: z3.Bool(f"{_SRC_SA}{e}") for e in sas},
        target_sas={e: z3.Bool(f"{_TGT_SA}{e}") for e in sas},
    )


def universe_axioms(z3, v: PacketVars) -> list:
    """The background constraints tying the finite universe to reality: an
    instance runs as **exactly one** service account, so each side's SA
    booleans get an at-most-one constraint. Tags carry no such constraint (an
    instance may carry several). Returns a (possibly empty) list of assertions
    the caller adds to its solver."""
    _require(z3)
    axioms: list = []
    for sa_map in (v.src_sas, v.target_sas):
        bools = list(sa_map.values())
        if len(bools) >= 2:
            axioms.append(z3.AtMost(*bools, 1))
    return axioms


def parse_cidr(text: str) -> tuple[int, int]:
    """Parse an IPv4 CIDR (or bare address, treated as ``/32``) into
    ``(network_int, prefix_length)``. An IPv6 or malformed value raises
    :class:`UnsupportedPacket` — IPv4 only."""
    try:
        net = ipaddress.ip_network(text, strict=False)
    except (ValueError, TypeError) as exc:
        raise UnsupportedPacket(f"not a valid CIDR: {text!r} ({exc})") from None
    if not isinstance(net, ipaddress.IPv4Network):
        raise UnsupportedPacket(f"IPv4 only, got {text!r}")
    return int(net.network_address), net.prefixlen


def cidr_match(z3, addr, cidr: str):
    """``addr`` (a 32-bit bitvector) is contained in *cidr*, by mask equality.
    A ``/0`` prefix is ``BoolVal(True)`` (every address)."""
    _require(z3)
    net, prefix = parse_cidr(cidr)
    if prefix == 0:
        return z3.BoolVal(True)
    mask = ((1 << _ADDR_BITS) - 1) ^ ((1 << (_ADDR_BITS - prefix)) - 1)
    return (addr & z3.BitVecVal(mask, _ADDR_BITS)) == z3.BitVecVal(net & mask, _ADDR_BITS)


def any_cidr_match(z3, addr, cidrs):
    """``addr`` is in any of *cidrs*. An empty list is ``BoolVal(False)`` — it
    proves nothing, it does not match everything."""
    _require(z3)
    terms = [cidr_match(z3, addr, c) for c in cidrs]
    if not terms:
        return z3.BoolVal(False)
    return z3.Or(terms)


def is_public(z3, addr):
    """``addr`` is a public address: outside every range in
    :data:`NON_PUBLIC_RANGES`."""
    _require(z3)
    return z3.Not(any_cidr_match(z3, addr, NON_PUBLIC_RANGES))


def parse_port_range(text: str) -> tuple[int, int]:
    """Parse ``"22"`` -> ``(22, 22)`` or ``"80-443"`` -> ``(80, 443)``. Any
    other shape raises :class:`UnsupportedPacket`."""
    parts = str(text).strip().split("-")
    try:
        if len(parts) == 1:
            lo = hi = int(parts[0])
        elif len(parts) == 2:
            lo, hi = int(parts[0]), int(parts[1])
        else:
            raise ValueError("too many components")
    except ValueError:
        raise UnsupportedPacket(f"not a port or port range: {text!r}") from None
    if not (0 <= lo <= _MAX_PORT and 0 <= hi <= _MAX_PORT and lo <= hi):
        raise UnsupportedPacket(f"port range out of bounds or inverted: {text!r}")
    return lo, hi


def port_match(z3, port, ports):
    """``port`` (a 16-bit bitvector) is in any of *ports* (a list of range
    strings). ``None`` or an empty list is ``BoolVal(True)`` — no port
    restriction means all ports, per GCP semantics. All comparisons are
    **unsigned**."""
    _require(z3)
    if not ports:
        return z3.BoolVal(True)
    terms = []
    for spec in ports:
        lo, hi = parse_port_range(spec)
        terms.append(z3.And(z3.UGE(port, z3.BitVecVal(lo, _PORT_BITS)),
                            z3.ULE(port, z3.BitVecVal(hi, _PORT_BITS))))
    return z3.Or(terms)


def protocol_match(z3, proto, name):
    """``proto`` (an 8-bit bitvector) is protocol *name*. ``"all"`` and ``""``
    are ``BoolVal(True)``; a known name maps through :data:`PROTOCOL_NUMBERS`;
    a decimal string is used as the number directly; anything else raises
    :class:`UnsupportedPacket`."""
    _require(z3)
    key = str(name).strip().lower()
    if key in ("all", ""):
        return z3.BoolVal(True)
    if key in PROTOCOL_NUMBERS:
        number = PROTOCOL_NUMBERS[key]
    elif key.isdigit():
        number = int(key)
    else:
        raise UnsupportedPacket(f"unknown protocol: {name!r}")
    return proto == z3.BitVecVal(number, _PROTO_BITS)


def layer4_match(z3, v: PacketVars, entries):
    """The layer-4 predicate: the packet's ``(proto, port)`` matches any of
    *entries*, each a ``{"protocol": name, "ports": [...]}`` mapping. An empty
    list is ``BoolVal(False)`` — no entry, nothing to match."""
    _require(z3)
    terms = []
    for entry in entries:
        proto_name = entry.get("protocol")
        if proto_name is None:
            proto_name = entry.get("ip_protocol", entry.get("IPProtocol"))
        terms.append(z3.And(protocol_match(z3, v.proto, proto_name),
                            port_match(z3, v.port, entry.get("ports"))))
    if not terms:
        return z3.BoolVal(False)
    return z3.Or(terms)


def _bool_for(z3, mapping, prefix, name):
    """The universe boolean for *name*, falling back to the stably-named
    constant if the caller's universe did not enumerate it — so a rule never
    silently fails to match because a tag was omitted from the universe."""
    existing = mapping.get(name)
    if existing is not None:
        return existing
    return z3.Bool(f"{prefix}{name}")


def _target_predicate(z3, v: PacketVars, rule):
    """A rule applies to an instance carrying any of its ``target_tags`` or
    ``target_service_accounts``. An empty target set applies to **every**
    instance (``BoolVal(True)``)."""
    terms = [_bool_for(z3, v.target_tags, _TGT_TAG, t)
             for t in (rule.get("target_tags") or [])]
    terms += [_bool_for(z3, v.target_sas, _TGT_SA, e)
              for e in (rule.get("target_service_accounts") or [])]
    if not terms:
        return z3.BoolVal(True)
    return z3.Or(terms)


def rule_match(z3, v: PacketVars, rule):
    """Does the symbolic packet match a normalized firewall *rule*? The
    conjunction of the target predicate, the layer-4 predicate, and a
    direction-specific address predicate.

    INGRESS: the source predicate is ``source_ranges`` OR ``source_tags`` OR
    ``source_service_accounts`` — if all three are empty the rule shape is
    illegal in GCP and treating it as match-all would fabricate findings, so it
    raises :class:`UnsupportedPacket`; the destination predicate is
    ``destination_ranges`` (``BoolVal(True)`` when absent). EGRESS: only the
    destination predicate over ``destination_ranges`` (``BoolVal(True)`` when
    absent, matching GCP's default ``0.0.0.0/0``); no source predicate."""
    _require(z3)
    conds = [_target_predicate(z3, v, rule)]

    layer4 = rule.get("layer4")
    conds.append(z3.BoolVal(True) if layer4 is None else layer4_match(z3, v, layer4))

    direction = str(rule.get("direction", "INGRESS")).upper()
    dest_ranges = rule.get("destination_ranges")
    dest_pred = any_cidr_match(z3, v.dst, dest_ranges) if dest_ranges else z3.BoolVal(True)

    if direction == "EGRESS":
        conds.append(dest_pred)
    else:
        src_ranges = rule.get("source_ranges") or []
        src_tags = rule.get("source_tags") or []
        src_sas = rule.get("source_service_accounts") or []
        if not src_ranges and not src_tags and not src_sas:
            raise UnsupportedPacket(
                "ingress rule has no source_ranges, source_tags or "
                "source_service_accounts — an illegal GCP shape")
        src_terms = []
        if src_ranges:
            src_terms.append(any_cidr_match(z3, v.src, src_ranges))
        src_terms += [_bool_for(z3, v.src_tags, _SRC_TAG, t) for t in src_tags]
        src_terms += [_bool_for(z3, v.src_sas, _SRC_SA, e) for e in src_sas]
        conds.append(z3.Or(src_terms) if len(src_terms) > 1 else src_terms[0])
        conds.append(dest_pred)

    return z3.And(conds)


def _rank(rule):
    """Precedence rank ``(priority, 0 if deny else 1)`` — lower is
    higher-precedence, so a lower priority number wins and, at equal priority,
    deny beats allow."""
    priority = rule.get("priority", 1000)
    return (priority, 0 if str(rule.get("action", "")).lower() == "deny" else 1)


def effective_allow(z3, v: PacketVars, rules, direction, default_allow):
    """The priority-ordered decision for *direction*: filter to that direction,
    drop disabled rules, and fold from lowest precedence to highest so the
    highest-precedence match wins (and equal-priority deny beats allow):

        formula = If(rule_match(r), BoolVal(action == "allow"), formula)

    starting from ``BoolVal(default_allow)`` — callers pass ``False`` for
    INGRESS and ``True`` for EGRESS, matching GCP's implied rules at priority
    65535."""
    _require(z3)
    want = str(direction).upper()
    applicable = [r for r in rules
                  if str(r.get("direction", "INGRESS")).upper() == want
                  and not r.get("disabled", False)]
    ordered = sorted(applicable, key=_rank)  # highest precedence first
    formula = z3.BoolVal(default_allow)
    for rule in reversed(ordered):  # lowest precedence first -> highest outermost
        allow = str(rule.get("action", "")).lower() == "allow"
        formula = z3.If(rule_match(z3, v, rule), z3.BoolVal(allow), formula)
    return formula


def witness_packet(z3, model, v: PacketVars) -> dict:
    """Render a solver *model* as a concrete packet: dotted-quad ``src`` /
    ``dst``, integer ``protocol`` / ``port``, and the lists of tags and service
    accounts the model set true (across both sides)."""
    _require(z3)

    def as_long(term):
        return model.eval(term, model_completion=True).as_long()

    def truthy(mapping):
        return sorted(name for name, boolean in mapping.items()
                      if z3.is_true(model.eval(boolean, model_completion=True)))

    tags = sorted(set(truthy(v.src_tags)) | set(truthy(v.target_tags)))
    service_accounts = sorted(set(truthy(v.src_sas)) | set(truthy(v.target_sas)))
    return {
        "src": str(ipaddress.IPv4Address(as_long(v.src))),
        "dst": str(ipaddress.IPv4Address(as_long(v.dst))),
        "protocol": as_long(v.proto),
        "port": as_long(v.port),
        "tags": tags,
        "service_accounts": service_accounts,
    }
