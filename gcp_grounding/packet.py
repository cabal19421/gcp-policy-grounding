"""A small z3 packet algebra shared by the network-layer grounding domains.

The full algebra (port intervals, protocol sets, tag / service-account
universes, priority-ordered ``Ite`` folds) is the subject of its own task;
this module carries only the surface the Cloud Armor match-expression
translator (:mod:`gcp_grounding.armor_expr`) needs today, in a shape a later
expansion can extend without breaking:

- :func:`parse_cidr` — an IPv4 CIDR string into ``(network_int, prefix_len)``;
  IPv6 and malformed inputs raise :class:`ValueError` (the offline encoding is
  the 32-bit IPv4 address space, so an IPv6 range is *unsupported*, not false).
- :func:`cidr_match` — a z3 boolean asserting a 32-bit source address is inside
  a CIDR, by bitvector masking (``(src & mask) == (base & mask)``).
- :class:`PacketVars` / :func:`packet_vars` — the free z3 variables a packet
  ranges over. ``src`` is the source IPv4 address as a 32-bit BitVec named
  ``"packet.src"``; sharing that name is what lets a firewall source range and
  an Armor ``inIpRange`` predicate be reasoned about as the same variable.

This module never imports z3 — the caller passes the module in, exactly as
:mod:`gcp_grounding.constraints` and :mod:`gcp_grounding.core.solver` do, so a
missing z3 degrades to ``unverified`` upstream rather than an import error.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

__all__ = ["PacketVars", "packet_vars", "parse_cidr", "cidr_match", "SRC_BITS", "SRC_NAME"]

# The source-address variable is 32 bits wide (IPv4) and stably named so that
# every domain that reasons about a source IP reasons about the *same* z3
# constant. ArmorVars.src reuses these directly.
SRC_BITS = 32
SRC_NAME = "packet.src"


def parse_cidr(cidr: str) -> tuple[int, int]:
    """An IPv4 CIDR string into ``(network_int, prefix_len)``.

    ``strict=False`` so a range with host bits set (e.g. ``10.0.0.5/24``) is
    accepted and its host bits are masked off, matching how ``inIpRange``
    treats the range. IPv6 literals and malformed strings raise
    :class:`ValueError` (``ipaddress`` raises ``AddressValueError`` /
    ``NetmaskValueError``, both ``ValueError`` subclasses) — the caller turns
    that into an *unsupported* verdict, never a false one.
    """
    if not isinstance(cidr, str):
        raise ValueError(f"CIDR must be a string, got {type(cidr).__name__}")
    network = ipaddress.IPv4Network(cidr, strict=False)
    return int(network.network_address), network.prefixlen


def cidr_match(z3, src, cidr: str):
    """A z3 boolean: is the 32-bit source address *src* inside *cidr*?

    Containment is bitvector masking — ``(src & mask) == (base & mask)`` — the
    same encoding a firewall rule uses, so two ranges over the shared
    :attr:`PacketVars.src` are directly comparable (a /16 provably implies the
    enclosing /8). Reuses :func:`parse_cidr`, so an IPv6 or malformed CIDR
    raises :class:`ValueError` here too.
    """
    base, prefix = parse_cidr(cidr)
    mask = (0xFFFFFFFF << (SRC_BITS - prefix)) & 0xFFFFFFFF
    return (src & z3.BitVecVal(mask, SRC_BITS)) == z3.BitVecVal(base & mask, SRC_BITS)


@dataclass(frozen=True)
class PacketVars:
    """The free z3 variables a packet ranges over. ``src`` is the source IPv4
    address as a 32-bit BitVec (see :func:`packet_vars`)."""

    src: Any


def packet_vars(z3, src=None) -> PacketVars:
    """The packet variables, minting ``src`` as ``BitVec("packet.src", 32)``
    unless the caller supplies its own (to share an existing variable)."""
    if src is None:
        src = z3.BitVec(SRC_NAME, SRC_BITS)
    return PacketVars(src=src)
