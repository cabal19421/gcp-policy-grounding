"""VPC firewall ESTATE comparison: priority-ordered shadowing and re-opening.

The proposal's ``firewall_rule`` claims (extracted by
:mod:`gcp_grounding.fw_claims`, carrying the whole normalized rule mapping in
their frozen ``payload``) are compared against the rules the snapshot actually
captured for the same network — ``snapshot.firewall_rules_for_network(network)``
— so the gate answers the two questions a diff cannot: does this new rule do
anything at all, and does it undo something the estate already denies?

ABSTENTION FIRST
================

``firewall_rules_for_network`` returns the :data:`~gcp_grounding.knowledge.UNKNOWN`
singleton when the category was never captured. That is compared with ``is
UNKNOWN`` and produces one ``unverified`` verdict **per proposed rule** saying
the estate's firewall rules were not captured, so shadowing was not decided. An
uncaptured estate must never read as "nothing shadows this" — an empty sweep of
a table that was never fetched is ignorance, not evidence. The same abstention
covers a rule carrying an ``unsupported`` payload key, a rule (proposed *or*
existing) whose shape :func:`~gcp_grounding.packet.rule_match` raises
:class:`~gcp_grounding.packet.UnsupportedPacket` on, a network that does not
canonicalize (so the estate's rules for it cannot be identified), and a missing
z3. No rule is ever dropped from the comparison: dropping an existing deny would
fabricate a clean re-opening, dropping an existing allow would fabricate a
proof.

POLARITY, stated once for the whole module
==========================================

FINDINGS **A** and **C** are family **(c)** COVERAGE checks:
``And(match, Not(preempt))`` **UNSAT is the finding** ("fully covered — nothing
is left") and **sat is the healthy case**, with NO witness on the finding
branch. FINDING **B** is family **(a)**: it asserts the bad property, so **sat
is the finding** and the model IS the witness.

Do NOT apply the family (b) PAIR rule ("unsat is grounded") to A or C. That
inversion makes every dead rule pass and every live rule block — a total no-op
with a green oracle, which is precisely the failure this module exists to
prevent. Each finding function names its family in its own docstring.

Precedence
==========

Rank is ``(priority, 0 if action == "deny" else 1)`` — lower wins, and at equal
priority a deny beats an allow, exactly as GCP evaluates. Existing rules of the
same ``(network, direction)`` are partitioned against the proposed rule *r* by
STRICT rank comparison; an equal-rank rule lands in neither partition. An
existing rule with the SAME name as *r* is the version *r* replaces, so it is
excluded from both partitions — otherwise every narrowing of an existing rule
would report itself as shadowed by its own previous self. Disabled rules decide
nothing and are excluded too.

All three findings share ONE :class:`~gcp_grounding.packet.PacketVars` per
``(network, direction)`` group, over the sorted union of the tags and service
accounts named by the proposed and the existing rules, and every solver gets
that group's :func:`~gcp_grounding.packet.universe_axioms`. Solvers come from
:func:`gcp_grounding.solve.solver`, so every check is bounded; a result other
than ``sat``/``unsat`` (a timeout, or the solver giving up) yields ``unverified``
echoing the raw result.

Wiring: :data:`DOCUMENT_CHECKS` is the module-level table the registry
(:func:`gcp_grounding.registry.document_checks`) discovers lazily, with no edit
elsewhere.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .constraints import _z3_module
from .core.log import get_logger
from .core.report import Verdict
from .fw_claims import normalize_network
from .knowledge import UNKNOWN
from .packet import (
    PacketVars,
    UnsupportedPacket,
    is_public,
    packet_vars,
    rule_match,
    universe_axioms,
    witness_packet,
)
from .solve import solver as bounded_solver

logger = get_logger(__name__)

__all__ = ["check_firewall_shadowing", "DOCUMENT_CHECKS"]

#: Verdict kinds this module emits. ``firewall_shadow`` covers FINDING A (the
#: proposal is dead) and FINDING C (the proposal kills an existing allow), plus
#: every abstention — what was not decided is exactly the shadowing question.
_SHADOW = "firewall_shadow"
_REOPEN = "firewall_reopen"


# -- small shared helpers ------------------------------------------------------


def _direction(rule: Mapping[str, Any]) -> str:
    return str(rule.get("direction", "INGRESS")).upper()


def _action(rule: Mapping[str, Any]) -> str:
    return str(rule.get("action", "")).lower()


def _priority(rule: Mapping[str, Any]) -> Any:
    priority = rule.get("priority")
    return 1000 if priority is None else priority


def _rank(rule: Mapping[str, Any]) -> tuple:
    """Precedence rank ``(priority, 0 if deny else 1)`` — lower is
    higher-precedence: a lower priority number wins, and at equal priority a
    deny beats an allow."""
    return (_priority(rule), 0 if _action(rule) == "deny" else 1)


def _short_name(value: Any) -> str:
    """The bare rule name: a snapshot key is the fully-qualified
    ``projects/<p>/global/firewalls/<n>`` path while a proposal names the rule
    bare, and the two must compare (and read) as the same rule."""
    if not isinstance(value, str) or not value:
        return "<unnamed>"
    return value.rsplit("/", 1)[-1]


def _names_of(rule: Mapping[str, Any], *fields: str) -> list[str]:
    out: list[str] = []
    for field in fields:
        for item in rule.get(field) or ():
            if isinstance(item, str) and item:
                out.append(item)
    return out


def _abstain(claim: Any, reason: str) -> Verdict:
    """One honest ``unverified``: the shadowing question was not decided, and
    why. Never a pass, never a block."""
    where = claim.location or claim.value
    return Verdict("unverified", _SHADOW, claim.value, 0,
                   f"{where}: {reason} — shadowing against the estate was not "
                   f"decided")


def _solve(z3, axioms: Sequence[Any], *formulas: Any) -> tuple[str, Any]:
    """``(status, model)`` for the conjunction of *axioms* and *formulas*, over
    a bounded solver: ``("sat", model)``, ``("unsat", None)`` or the raw result
    string (``"unknown"`` — a timeout or a give-up) with no model."""
    s = bounded_solver(z3)
    for axiom in axioms:
        s.add(axiom)
    for formula in formulas:
        s.add(formula)
    result = s.check()
    if result == z3.sat:
        return "sat", s.model()
    if result == z3.unsat:
        return "unsat", None
    return str(result), None


def _render_witness(packet: Mapping[str, Any]) -> str:
    parts = [f"src {packet['src']}", f"dst {packet['dst']}",
             f"protocol {packet['protocol']}", f"port {packet['port']}"]
    if packet["tags"]:
        parts.append("tags " + ", ".join(packet["tags"]))
    if packet["service_accounts"]:
        parts.append("service accounts " + ", ".join(packet["service_accounts"]))
    return "; ".join(parts)


# -- the whole-document check --------------------------------------------------


def check_firewall_shadowing(ctx) -> list[Verdict]:
    """Compare every proposed VPC firewall rule against the captured estate.

    One pass per ``(network, direction)`` group, so the group's symbolic packet
    (and its tag / service-account universe) is built once and shared by all
    three findings. Returns one list of verdicts; an undecidable rule abstains
    rather than being dropped.
    """
    proposals = [(claim, claim.fields())
                 for claim in ctx.claims if claim.kind == "firewall_rule"]
    if not proposals:
        return []

    verdicts: list[Verdict] = []
    groups: dict[tuple[str, str], list] = {}
    for claim, rule in proposals:
        if rule.get("disabled") is True:
            # A disabled rule decides nothing and is decided by nothing; it is
            # inert, not undecidable.
            logger.debug("%s: proposed rule is disabled — no estate comparison",
                         claim.location)
            continue
        unsupported = rule.get("unsupported")
        if unsupported:
            verdicts.append(_abstain(
                claim, f"the rule shape is not supported ({unsupported})"))
            continue
        network = rule.get("network")
        if normalize_network(network) is None:
            verdicts.append(_abstain(
                claim, f"the network {network!r} does not canonicalize to "
                f"projects/<project>/global/networks/<network>, so the estate's "
                f"rules for it could not be identified"))
            continue
        groups.setdefault((network, _direction(rule)), []).append((claim, rule))

    z3 = _z3_module(ctx.solver)
    for key in sorted(groups):
        verdicts.extend(_check_group(z3, ctx, key, groups[key]))
    return verdicts


def _estate_names(snapshot) -> dict[int, str]:
    """Reverse index from a captured record's identity to its snapshot key: the
    records ``firewall_rules_for_network`` hands back carry no ``name`` field of
    their own, and a finding has to be able to say which rule it means."""
    table = getattr(snapshot, "firewall_rules", None) or {}
    return {id(record): name for name, record in table.items()}


def _check_group(z3, ctx, key: tuple[str, str], members: list) -> list[Verdict]:
    """Every finding for one ``(network, direction)`` group of proposed rules."""
    network, direction = key
    estate = ctx.snapshot.firewall_rules_for_network(network)
    if estate is UNKNOWN:
        return [_abstain(claim, "the estate's firewall rules for network "
                                f"{network!r} were not captured in the snapshot")
                for claim, _ in members]
    if z3 is None:
        return [_abstain(claim, f"z3 is not available (solver backend "
                                f"{ctx.solver.backend!r})")
                for claim, _ in members]

    index = _estate_names(ctx.snapshot)
    existing = [(_short_name(index.get(id(record), record.get("name"))), record)
                for record in estate
                if _direction(record) == direction and not record.get("disabled")]

    tags: set[str] = set()
    accounts: set[str] = set()
    for rule in [r for _, r in members] + [r for _, r in existing]:
        tags.update(_names_of(rule, "source_tags", "target_tags"))
        accounts.update(_names_of(rule, "source_service_accounts",
                                  "target_service_accounts"))
    try:
        packet = packet_vars(z3, tags=sorted(tags),
                             service_accounts=sorted(accounts))
        axioms = universe_axioms(z3, packet)
    except UnsupportedPacket as exc:  # pragma: no cover - z3 present by here
        return [_abstain(claim, f"the symbolic packet could not be built ({exc})")
                for claim, _ in members]

    verdicts: list[Verdict] = []
    for claim, rule in members:
        verdicts.extend(_check_rule(z3, packet, axioms, claim, rule, existing))
    return verdicts


def _check_rule(z3, packet: PacketVars, axioms, claim, rule,
                existing: list) -> list[Verdict]:
    """The three findings for one proposed rule against its group's estate."""
    self_name = _short_name(rule.get("name") or claim.value)
    # The same-named existing rule is the version this proposal replaces.
    others = [(name, record) for name, record in existing if name != self_name]

    try:
        match_r = rule_match(z3, packet, rule)
        encoded = [(name, record, rule_match(z3, packet, record))
                   for name, record in others]
    except UnsupportedPacket as exc:
        # Either the proposal or one of the estate rules it must be compared
        # against cannot be encoded. Comparing against the rest would answer a
        # different question than the one asked, so the whole comparison
        # abstains.
        return [_abstain(claim, f"a rule in this network/direction group could "
                                f"not be encoded ({exc})")]

    status, _ = _solve(z3, axioms, match_r)
    if status == "unsat":
        return [_abstain(claim, "the encoded rule matches no packet at all")]
    if status != "sat":
        return [_abstain(claim, f"the solver returned {status!r}")]

    rank_r = _rank(rule)
    higher = [entry for entry in encoded if _rank(entry[1]) < rank_r]
    lower = [entry for entry in encoded if _rank(entry[1]) > rank_r]

    verdicts = _finding_unreachable_proposal(z3, axioms, claim, match_r, higher)
    if _action(rule) == "allow":
        verdicts += _finding_reopened_deny(z3, packet, axioms, claim, rule,
                                           match_r, lower)
    elif _action(rule) == "deny":
        verdicts += _finding_killed_allow(z3, axioms, claim, rule, match_r, lower)
    return verdicts


# -- FINDING A -----------------------------------------------------------------


def _finding_unreachable_proposal(z3, axioms, claim, match_r,
                                  higher: list) -> list[Verdict]:
    """FINDING A — the proposed rule is unreachable (dead). Family **(c)**,
    COVERAGE: ``And(match(r), Not(Or(higher)))`` **UNSAT is the finding** (every
    packet r matches is already decided before r is consulted) and **sat is the
    healthy case**. No witness on the finding branch — there is no packet to
    exhibit, that is the point. Only FULL shadowing fires; partial overlap is
    normal configuration and produces nothing.
    """
    if not higher:
        return []
    where = claim.location or claim.value
    preempt = z3.Or([term for _, _, term in higher])
    status, _ = _solve(z3, axioms, match_r, z3.Not(preempt))
    if status == "sat":
        return []
    if status != "unsat":
        return [_abstain(claim, f"the solver returned {status!r}")]

    # Name the rules actually responsible: those whose removal makes the
    # formula satisfiable again. (Two rules that each cover r on their own are
    # individually removable, so fall back to naming the whole set.)
    culprits = []
    for i, (name, _, _) in enumerate(higher):
        rest = [term for j, (_, _, term) in enumerate(higher) if j != i]
        remaining = z3.Or(rest) if rest else z3.BoolVal(False)
        if _solve(z3, axioms, match_r, z3.Not(remaining))[0] == "sat":
            culprits.append(name)
    named = ", ".join(sorted(culprits) or sorted(name for name, _, _ in higher))
    return [Verdict("contradicted", _SHADOW, claim.value, 0,
                    f"{where}: unreachable — every packet this rule matches is "
                    f"already decided by higher-precedence rule(s) {named}; the "
                    f"rule has no effect")]


# -- FINDING B -----------------------------------------------------------------


def _finding_reopened_deny(z3, packet: PacketVars, axioms, claim, rule, match_r,
                           lower: list) -> list[Verdict]:
    """FINDING B — this allow re-opens traffic a lower-precedence deny blocks.
    Family **(a)**: the bad property is asserted directly, so **sat is the
    finding** and the model IS the witness.

    Only externally reachable holes are reported: the intersection must also
    admit a public source (INGRESS) or destination (EGRESS). An intersection
    that is entirely private is on the record as an informational ``grounded``
    — the :func:`~gcp_grounding.constraints.check_cel` tautology-warning
    precedent — and does not fail the gate.
    """
    where = claim.location or claim.value
    outside = is_public(z3, packet.dst if _direction(rule) == "EGRESS"
                        else packet.src)
    verdicts: list[Verdict] = []
    for name, record, match_d in lower:
        if _action(record) != "deny":
            continue
        status, _ = _solve(z3, axioms, match_r, match_d)
        if status == "unsat":
            continue
        if status != "sat":
            verdicts.append(_abstain(claim, f"the solver returned {status!r}"))
            continue
        public, model = _solve(z3, axioms, match_r, match_d, outside)
        if public == "sat":
            verdicts.append(Verdict(
                "contradicted", _REOPEN, claim.value, 0,
                f"{where}: this allow at priority {_priority(rule)} re-opens "
                f"traffic that the existing deny {name!r} at priority "
                f"{_priority(record)} blocks — e.g. "
                f"{_render_witness(witness_packet(z3, model, packet))}"))
        elif public == "unsat":
            verdicts.append(Verdict(
                "grounded", _REOPEN, claim.value, 0,
                f"{where}: this allow at priority {_priority(rule)} overlaps "
                f"the existing deny {name!r} at priority {_priority(record)}, "
                f"but no public address is reachable through the overlap — it "
                f"narrows an existing deny for internal ranges only"))
        else:
            verdicts.append(_abstain(claim, f"the solver returned {public!r}"))
    return verdicts


# -- FINDING C -----------------------------------------------------------------


def _finding_killed_allow(z3, axioms, claim, rule, match_r,
                          lower: list) -> list[Verdict]:
    """FINDING C — this deny makes an existing lower-precedence allow
    unreachable. Family **(c)**, COVERAGE, exactly like FINDING A: for an
    existing allow *a*, ``And(match(a), Not(match(r)))`` **UNSAT is the
    finding** (nothing is left of *a*) and **sat is the healthy case**, with no
    witness. Only full coverage fires. This is the "and vice versa" half of
    FINDING A.

    An existing allow whose own encoding matches no packet is already dead in
    the estate; the proposal did not kill it, so it is skipped rather than
    reported.
    """
    where = claim.location or claim.value
    verdicts: list[Verdict] = []
    for name, record, match_a in lower:
        if _action(record) != "allow":
            continue
        if _solve(z3, axioms, match_a)[0] != "sat":
            logger.debug("%s: existing allow %r matches no packet on its own — "
                         "not attributed to this proposal", where, name)
            continue
        status, _ = _solve(z3, axioms, match_a, z3.Not(match_r))
        if status == "sat":
            continue
        if status != "unsat":
            verdicts.append(_abstain(claim, f"the solver returned {status!r}"))
            continue
        verdicts.append(Verdict(
            "contradicted", _SHADOW, name, 0,
            f"{where}: this deny at priority {_priority(rule)} makes the "
            f"existing allow {name!r} at priority {_priority(record)} "
            f"unreachable"))
    return verdicts


# -- registry wiring -----------------------------------------------------------

#: Whole-document checks the registry discovers (no edit elsewhere).
DOCUMENT_CHECKS = (check_firewall_shadowing,)
