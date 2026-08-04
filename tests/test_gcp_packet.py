"""Packet-algebra tests for :mod:`gcp_grounding.packet`.

The module is pure z3 encoding: it never imports z3, never builds a Verdict,
never reads a snapshot. So the suite splits on the same ``HAS_Z3`` idiom the
constraint / preflight / cli suites use:

* The **builtin** branch (always runs) pins the degraded path — every
  module-taking entry point handed ``None`` for the z3 module raises
  :class:`UnsupportedPacket` (never ``AttributeError``), which is what lets the
  caller's ``except UnsupportedPacket`` arm degrade to an honest
  ``unverified`` — and pins the pure parsers, which take no module and work
  unconditionally.
* The **z3** branch (skipped without the z3 backend) proves the encoding: CIDR
  containment by masking, ``/0`` and split-half coverage a string match cannot
  make, the unsigned-comparison port pin, priority-ordered allow/deny folds,
  and a witness round-trip.
"""

import ipaddress

import pytest

from gcp_grounding.constraints import _z3_module
from gcp_grounding.core.solver import get_solver
from gcp_grounding.packet import (
    UnsupportedPacket,
    NON_PUBLIC_RANGES,
    PROTOCOL_NUMBERS,
    SENSITIVE_PORTS,
    any_cidr_match,
    cidr_match,
    effective_allow,
    is_public,
    layer4_match,
    packet_vars,
    parse_cidr,
    parse_port_range,
    port_match,
    protocol_match,
    rule_match,
    universe_axioms,
    witness_packet,
)

# Mirror the code's own degradation (z3 may import yet Z3Solver() can fail):
# take the z3 module from the solver's own detection, exactly as the runtime
# callers do via constraints._z3_module(get_solver()).
Z3 = _z3_module(get_solver())
HAS_Z3 = get_solver().backend == "z3"
needs_z3 = pytest.mark.skipif(not HAS_Z3, reason="z3 solver backend is not available")


def _addr(text: str) -> int:
    return int(ipaddress.IPv4Address(text))


# ---------------------------------------------------------------------------
# builtin branch: the degraded path and the module-free pure parsers.
# ---------------------------------------------------------------------------


def test_constants_have_the_specified_values():
    assert PROTOCOL_NUMBERS == {
        "tcp": 6, "udp": 17, "icmp": 1, "ipip": 4,
        "gre": 47, "esp": 50, "ah": 51, "sctp": 132,
    }
    assert 22 in SENSITIVE_PORTS and 3389 in SENSITIVE_PORTS and 80 not in SENSITIVE_PORTS
    for cidr in ("10.0.0.0/8", "35.191.0.0/16", "130.211.0.0/22", "35.235.240.0/20"):
        assert cidr in NON_PUBLIC_RANGES


def test_every_module_taking_entry_point_raises_on_none():
    # Not one of these may leak an AttributeError from inside the encoding.
    with pytest.raises(UnsupportedPacket):
        packet_vars(None)
    with pytest.raises(UnsupportedPacket):
        universe_axioms(None, None)
    with pytest.raises(UnsupportedPacket):
        cidr_match(None, None, "10.0.0.0/8")
    with pytest.raises(UnsupportedPacket):
        any_cidr_match(None, None, ["10.0.0.0/8"])
    with pytest.raises(UnsupportedPacket):
        is_public(None, None)
    with pytest.raises(UnsupportedPacket):
        port_match(None, None, ["22"])
    with pytest.raises(UnsupportedPacket):
        protocol_match(None, None, "tcp")
    with pytest.raises(UnsupportedPacket):
        layer4_match(None, None, [{"protocol": "tcp", "ports": ["22"]}])
    with pytest.raises(UnsupportedPacket):
        rule_match(None, None, {"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"]})
    with pytest.raises(UnsupportedPacket):
        effective_allow(None, None, [], "INGRESS", False)
    with pytest.raises(UnsupportedPacket):
        witness_packet(None, None, None)


def test_pure_parsers_work_without_a_module():
    assert parse_cidr("10.0.0.0/8") == (_addr("10.0.0.0"), 8)
    assert parse_cidr("10.1.2.3") == (_addr("10.1.2.3"), 32)  # bare address -> /32
    assert parse_cidr("0.0.0.0/0") == (0, 0)
    assert parse_port_range("22") == (22, 22)
    assert parse_port_range("80-443") == (80, 443)
    assert parse_port_range("1024-65535") == (1024, 65535)


def test_pure_parsers_reject_unsupported_shapes():
    with pytest.raises(UnsupportedPacket):
        parse_cidr("2001:db8::/32")          # IPv6 -> IPv4 only
    with pytest.raises(UnsupportedPacket):
        parse_cidr("not-a-cidr")
    with pytest.raises(UnsupportedPacket):
        parse_port_range("22,80")            # comma list is not a range
    with pytest.raises(UnsupportedPacket):
        parse_port_range("70000")            # out of the 16-bit port space
    with pytest.raises(UnsupportedPacket):
        parse_port_range("443-22")           # inverted


# ---------------------------------------------------------------------------
# z3 branch: the real encoding.
# ---------------------------------------------------------------------------


@pytest.fixture()
def v():
    return packet_vars(Z3, tags=("web",), service_accounts=("a@x.iam", "b@x.iam"))


def _check(*constraints):
    solver = Z3.Solver()
    for constraint in constraints:
        solver.add(constraint)
    return solver.check()


@needs_z3
def test_cidr_membership_is_decided_by_masking(v):
    inside = _check(v.src == Z3.BitVecVal(_addr("10.1.2.3"), 32),
                    cidr_match(Z3, v.src, "10.0.0.0/8"))
    outside = _check(v.src == Z3.BitVecVal(_addr("11.0.0.1"), 32),
                     cidr_match(Z3, v.src, "10.0.0.0/8"))
    assert inside == Z3.sat
    assert outside == Z3.unsat


@needs_z3
def test_slash_zero_and_split_halves_cover_every_address(v):
    # The containment a string match on "0.0.0.0/0" can never make: proving
    # that NO address escapes the range makes Not(Or(...)) unsatisfiable.
    assert _check(Z3.Not(any_cidr_match(Z3, v.src, ["0.0.0.0/0"]))) == Z3.unsat
    assert _check(Z3.Not(any_cidr_match(
        Z3, v.src, ["0.0.0.0/1", "128.0.0.0/1"]))) == Z3.unsat


@needs_z3
def test_empty_cidr_list_matches_nothing(v):
    # An empty range list proves nothing; it does not match everything.
    assert _check(any_cidr_match(Z3, v.src, [])) == Z3.unsat


@needs_z3
def test_is_public_excludes_reserved_ranges(v):
    # A 10/8 address is never public; a routable one can be.
    assert _check(v.src == Z3.BitVecVal(_addr("10.9.9.9"), 32),
                  is_public(Z3, v.src)) == Z3.unsat
    assert _check(v.src == Z3.BitVecVal(_addr("35.191.0.7"), 32),
                  is_public(Z3, v.src)) == Z3.unsat  # GCP health checker
    assert _check(v.src == Z3.BitVecVal(_addr("203.0.113.5"), 32),
                  is_public(Z3, v.src)) == Z3.sat


@needs_z3
def test_port_match_uses_unsigned_comparison(v):
    # The single most likely correctness bug: a signed compare would misclassify
    # 40000 (>= 32768) as negative and wrongly exclude it from 1024-65535.
    pm = port_match(Z3, v.port, ["1024-65535"])
    assert _check(pm, v.port == Z3.BitVecVal(40000, 16)) == Z3.sat
    assert _check(pm, v.port == Z3.BitVecVal(80, 16)) == Z3.unsat


@needs_z3
def test_empty_or_none_ports_match_all(v):
    assert _check(Z3.Not(port_match(Z3, v.port, []))) == Z3.unsat
    assert _check(Z3.Not(port_match(Z3, v.port, None))) == Z3.unsat


@needs_z3
def test_protocol_match_names_numbers_and_wildcards(v):
    assert _check(protocol_match(Z3, v.proto, "tcp"),
                  v.proto == Z3.BitVecVal(6, 8)) == Z3.sat
    assert _check(protocol_match(Z3, v.proto, "tcp"),
                  v.proto == Z3.BitVecVal(17, 8)) == Z3.unsat
    assert _check(protocol_match(Z3, v.proto, "132"),  # decimal -> number directly
                  v.proto == Z3.BitVecVal(132, 8)) == Z3.sat
    assert _check(Z3.Not(protocol_match(Z3, v.proto, "all"))) == Z3.unsat
    assert _check(Z3.Not(protocol_match(Z3, v.proto, ""))) == Z3.unsat
    with pytest.raises(UnsupportedPacket):
        protocol_match(Z3, v.proto, "quic")


@needs_z3
def test_ingress_rule_with_no_source_of_any_kind_raises(v):
    with pytest.raises(UnsupportedPacket):
        rule_match(Z3, v, {"direction": "INGRESS", "action": "allow",
                           "layer4": [{"protocol": "tcp", "ports": ["22"]}]})


@needs_z3
def test_target_and_layer4_predicates_constrain_the_match(v):
    rule = {"direction": "INGRESS", "action": "allow", "priority": 1000,
            "source_ranges": ["0.0.0.0/0"],
            "target_tags": ["web"],
            "layer4": [{"protocol": "tcp", "ports": ["443"]}]}
    match = rule_match(Z3, v, rule)
    # A tcp/443 packet at a web-tagged target matches...
    assert _check(match, v.proto == Z3.BitVecVal(6, 8),
                  v.port == Z3.BitVecVal(443, 16),
                  v.target_tags["web"]) == Z3.sat
    # ...but not when the target is not web-tagged.
    assert _check(match, v.proto == Z3.BitVecVal(6, 8),
                  v.port == Z3.BitVecVal(443, 16),
                  Z3.Not(v.target_tags["web"])) == Z3.unsat


@needs_z3
def test_effective_allow_is_priority_ordered(v):
    deny22 = {"direction": "INGRESS", "action": "deny", "priority": 900,
              "source_ranges": ["0.0.0.0/0"],
              "layer4": [{"protocol": "tcp", "ports": ["22"]}]}
    allow_all = {"direction": "INGRESS", "action": "allow", "priority": 1000,
                 "source_ranges": ["0.0.0.0/0"],
                 "layer4": [{"protocol": "tcp", "ports": ["0-65535"]}]}
    formula = effective_allow(Z3, v, [deny22, allow_all], "INGRESS", False)
    tcp = v.proto == Z3.BitVecVal(6, 8)
    # port 22 is provably denied (no allowed model exists)...
    assert _check(tcp, v.port == Z3.BitVecVal(22, 16), formula) == Z3.unsat
    # ...and port 80 is provably allowed (no denied model exists).
    assert _check(tcp, v.port == Z3.BitVecVal(80, 16), Z3.Not(formula)) == Z3.unsat


@needs_z3
def test_equal_priority_deny_beats_allow(v):
    deny = {"direction": "INGRESS", "action": "deny", "priority": 1000,
            "source_ranges": ["0.0.0.0/0"],
            "layer4": [{"protocol": "tcp", "ports": ["22"]}]}
    allow = {"direction": "INGRESS", "action": "allow", "priority": 1000,
             "source_ranges": ["0.0.0.0/0"],
             "layer4": [{"protocol": "tcp", "ports": ["22"]}]}
    formula = effective_allow(Z3, v, [allow, deny], "INGRESS", False)
    assert _check(v.proto == Z3.BitVecVal(6, 8),
                  v.port == Z3.BitVecVal(22, 16), formula) == Z3.unsat


@needs_z3
def test_disabled_rule_has_no_effect(v):
    deny22_disabled = {"direction": "INGRESS", "action": "deny", "priority": 900,
                       "disabled": True, "source_ranges": ["0.0.0.0/0"],
                       "layer4": [{"protocol": "tcp", "ports": ["22"]}]}
    allow_all = {"direction": "INGRESS", "action": "allow", "priority": 1000,
                 "source_ranges": ["0.0.0.0/0"],
                 "layer4": [{"protocol": "tcp", "ports": ["0-65535"]}]}
    formula = effective_allow(Z3, v, [deny22_disabled, allow_all], "INGRESS", False)
    # With the deny disabled, tcp/22 is allowed like everything else.
    assert _check(v.proto == Z3.BitVecVal(6, 8),
                  v.port == Z3.BitVecVal(22, 16), Z3.Not(formula)) == Z3.unsat


@needs_z3
def test_egress_default_allow_and_destination_predicate(v):
    # No matching rule -> the EGRESS default (allow) governs.
    allow_out = {"direction": "EGRESS", "action": "allow", "priority": 1000,
                 "destination_ranges": ["10.0.0.0/8"],
                 "layer4": [{"protocol": "tcp", "ports": ["0-65535"]}]}
    formula = effective_allow(Z3, v, [allow_out], "EGRESS", True)
    # A destination outside 10/8 falls through to the default allow.
    assert _check(v.dst == Z3.BitVecVal(_addr("203.0.113.9"), 32),
                  Z3.Not(formula)) == Z3.unsat


@needs_z3
def test_universe_axioms_enforce_at_most_one_service_account(v):
    axioms = universe_axioms(Z3, v)
    assert axioms  # two SAs -> a real at-most-one constraint per side
    both = _check(*axioms, v.target_sas["a@x.iam"], v.target_sas["b@x.iam"])
    one = _check(*axioms, v.target_sas["a@x.iam"])
    assert both == Z3.unsat   # an instance cannot run as two service accounts
    assert one == Z3.sat


@needs_z3
def test_witness_packet_round_trips_a_model(v):
    solver = Z3.Solver()
    solver.add(v.src == Z3.BitVecVal(_addr("203.0.113.5"), 32))
    solver.add(v.dst == Z3.BitVecVal(_addr("10.1.2.3"), 32))
    solver.add(v.proto == Z3.BitVecVal(6, 8))
    solver.add(v.port == Z3.BitVecVal(443, 16))
    solver.add(v.target_tags["web"])
    solver.add(v.target_sas["a@x.iam"])
    for axiom in universe_axioms(Z3, v):
        solver.add(axiom)
    assert solver.check() == Z3.sat
    witness = witness_packet(Z3, solver.model(), v)
    assert witness["src"] == "203.0.113.5"
    assert witness["dst"] == "10.1.2.3"
    assert witness["protocol"] == 6
    assert witness["port"] == 443
    assert "web" in witness["tags"]
    assert "a@x.iam" in witness["service_accounts"]
