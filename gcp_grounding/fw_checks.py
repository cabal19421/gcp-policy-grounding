"""VPC firewall grounding checks: PROPOSAL exposure and PAIR non-enlargement.

Two z3 checks over the normalized firewall rules :mod:`gcp_grounding.fw_claims`
extracts, encoded with the shared packet algebra
(:mod:`gcp_grounding.packet`). They sit on opposite ends of the polarity
discipline, and getting that backwards would invert the security semantics:

* :func:`check_open_exposure` is a **PROPOSAL bad-property** check registered in
  :data:`CLAIM_CHECKS` for the ``firewall_rule`` claim kind. It asserts the bad
  property — a *public* source reaching a *sensitive* port through this rule —
  so **sat is** ``contradicted`` (with the witness address), and ``unsat`` is
  ``grounded``. It reads the claim payload only: no snapshot, no baseline, no
  other rule.
* :func:`check_packet_set_pair` is a **PAIR / widening** check registered in
  :data:`PAIR_CHECKS` for the ``firewall_rule`` document kind. It asserts the
  *negation* of the desired property — "the new rule set allows a packet the old
  set denied" — so **unsat is** ``grounded`` and sat is ``contradicted`` with a
  witness packet.

z3 is obtained the one way the rest of the repo obtains it:
``constraints._z3_module`` over ``CheckContext.solver``, which reuses
``core.solver``'s own detection and never adds a second import path. On the
builtin backend it is ``None`` and every check here returns exactly one
``unverified`` verdict naming the backend — an abstention, not a pass and not a
block (``unverified`` leaves ``report.ok`` alone).

Two honesty rules carry the value of the pair check:

**Never drop a rule.** If *any* rule on either side of a comparison carries an
``unsupported`` payload key or raises :class:`~gcp_grounding.packet.UnsupportedPacket`,
the whole group abstains, naming the offending rule. Dropping an old *deny*
would leave the old set looking more permissive than it is and fabricate a
widening; dropping a new *allow* would leave the new set looking narrower than
it is and fabricate a proof of safety. Neither is recoverable downstream, so the
group is not compared at all.

**Group honestly.** Rules are compared within a ``(network, direction)`` group,
never across one. A group present on only one side still participates — its
absent side contributes the *empty* rule set, which is exactly how removing the
last egress deny shows up as a widening against EGRESS's implied default-allow.
But when the two documents describe entirely different networks, there is no
comparison to make: the check says so in one ``unverified`` rather than silently
comparing unrelated rule sets.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from . import evidence, fw_claims
from .constraints import _z3_module
from .core.log import get_logger
from .core.report import Verdict
from .packet import (
    PROTOCOL_NUMBERS,
    SENSITIVE_PORTS,
    UnsupportedPacket,
    effective_allow,
    is_public,
    packet_vars,
    rule_match,
    universe_axioms,
    witness_packet,
)

logger = get_logger(__name__)

__all__ = ["check_open_exposure", "check_packet_set_pair",
           "CLAIM_CHECKS", "PAIR_CHECKS"]

#: The two verdict channels this module reports on.
_EXPOSURE = "firewall_exposure"
_PAIR = "firewall_pair"

#: Reverse of :data:`~gcp_grounding.packet.PROTOCOL_NUMBERS`, for rendering a
#: witness packet's protocol number back as the name the rule was written with.
_PROTOCOL_NAMES = {number: name for name, number in PROTOCOL_NUMBERS.items()}

#: Group key for a rule whose ``network`` did not survive normalization; it
#: still participates (never dropped) and its group abstains for that reason.
_NO_NETWORK = "<unknown network>"

#: Display name for a rule whose own name did not resolve.
_NO_NAME = "<unnamed firewall rule>"


# -- small shared helpers -----------------------------------------------------


def _backend(ctx) -> str:
    """The solver backend name, defensively (a stub context may carry None)."""
    return getattr(ctx.solver, "backend", "unknown")


def _flow(witness: Mapping[str, Any]) -> str:
    """``"tcp/22"`` — a witness packet's protocol/port, protocol by name where
    the number is one the encoding knows."""
    protocol = witness.get("protocol")
    return f"{_PROTOCOL_NAMES.get(protocol, protocol)}/{witness.get('port')}"


def _rule_name(rule: Mapping[str, Any]) -> str:
    name = rule.get("name")
    return name if isinstance(name, str) and name else _NO_NAME


def _direction_of(rule: Mapping[str, Any]) -> str:
    """The rule's direction for grouping. A rule whose ``direction`` did not
    survive normalization has no key at all; it groups with INGRESS (the GCP
    default) so that it is still *present*, and its group then abstains on the
    ``unsupported`` key rather than being silently dropped."""
    return str(rule.get("direction") or "INGRESS").upper()


def _network_of(rule: Mapping[str, Any]) -> str:
    network = rule.get("network")
    return network if isinstance(network, str) and network else _NO_NETWORK


def _universe(rules: Sequence[Mapping[str, Any]]) -> tuple[list[str], list[str]]:
    """The sorted tag and service-account universes *rules* mention, on either
    side of either field. Sorted so the formula a given pair of documents
    produces is byte-stable run to run.

    ALL FOUR FIELDS ARE LEGITIMATELY OPTIONAL, and that is why the reads declare
    ``absent=[]`` instead of abstaining: a firewall rule that names no source
    tags is the common case, not an unreadable one, and a rule set whose every
    member abstained on the absence of ``source_tags`` would decide nothing at
    all. ``fw_claims``' two normalizers set all four keys for every rule they
    emit, so an ABSENT key here means the mapping came from somewhere else; a key
    that IS present and is not a list is unread rather than empty, and that half
    now abstains through the evidence channel instead of being silently swept
    into an empty universe — a tag universe that lost a member makes every
    tag-scoped rule compare as if the tag could never be set.
    """
    tags: set[str] = set()
    accounts: set[str] = set()
    for index, rule in enumerate(rules):
        what = f"firewall rule {_rule_name(rule)!r} (rule {index})"
        for field in ("source_tags", "target_tags"):
            entries = evidence.scalar(rule, field, what=what, type=list, absent=[])
            tags.update(t for t in entries if isinstance(t, str))
        for field in ("source_service_accounts", "target_service_accounts"):
            entries = evidence.scalar(rule, field, what=what, type=list, absent=[])
            accounts.update(e for e in entries if isinstance(e, str))
    return sorted(tags), sorted(accounts)


# -- CHECK 1: PROPOSAL-only public exposure -----------------------------------


def check_open_exposure(claim, ctx) -> Verdict | None:
    """Does this one proposed firewall rule let a *public* source reach a
    *sensitive* port? Reads the claim payload only — no snapshot, no baseline.

    Skipped (``None``) unless the rule is an enabled INGRESS *allow*: an egress
    rule, a deny and a disabled rule expose nothing on their own. Otherwise the
    bad property ``And(rule_match, is_public(src), port ∈ SENSITIVE_PORTS)`` is
    asserted, so sat is ``contradicted`` with the witness source address and
    unsat is ``grounded``.

    Because :func:`~gcp_grounding.packet.is_public` excludes IAP TCP forwarding
    (35.235.240.0/20) and the health-check prober ranges, the standard IAP-SSH
    and load-balancer health-check rules ground rather than fire — which is the
    whole reason the source predicate is a CIDR containment and not a string
    match on ``"0.0.0.0/0"``.
    """
    z3 = _z3_module(ctx.solver)
    name = claim.value or _NO_NAME
    where = claim.location or "firewall rule"
    if z3 is None:
        logger.debug("exposure check degraded to unverified: backend=%s has no z3",
                     _backend(ctx))
        return Verdict("unverified", _EXPOSURE, name, 0,
                       f"{where}: z3 is not available (solver backend "
                       f"{_backend(ctx)!r}) — public exposure was not decided")

    rule = claim.fields()
    unsupported = rule.get("unsupported")
    if unsupported:
        # Checked before the applicability skip: with a broken direction or a
        # missing allow/deny entry we cannot even tell whether the check
        # applies, so "skip" would be a guess dressed up as silence.
        return Verdict("unverified", _EXPOSURE, name, 0,
                       f"{where}: the rule carries a shape the packet encoding "
                       f"cannot represent ({unsupported}) — public exposure was "
                       f"not decided")

    if (_direction_of(rule) != "INGRESS"
            or str(rule.get("action", "")).lower() != "allow"
            or rule.get("disabled", False)):
        return None

    tags, accounts = _universe([rule])
    try:
        packet = packet_vars(z3, tags=tags, service_accounts=accounts)
        bad = z3.And(rule_match(z3, packet, rule),
                     is_public(z3, packet.src),
                     z3.Or([packet.port == port for port in sorted(SENSITIVE_PORTS)]))
        axioms = universe_axioms(z3, packet)
    except UnsupportedPacket as exc:
        logger.debug("exposure check unverified (unsupported shape): %s", exc)
        return Verdict("unverified", _EXPOSURE, name, 0,
                       f"{where}: the rule carries a shape the packet encoding "
                       f"cannot represent ({exc}) — public exposure was not decided")

    solver = z3.Solver()
    for axiom in axioms:
        solver.add(axiom)
    solver.add(bad)
    result = solver.check()
    if result == z3.unsat:
        return Verdict("grounded", _EXPOSURE, name, 0,
                       f"{where}: no public source reaches a sensitive port")
    if result != z3.sat:
        return Verdict("unverified", _EXPOSURE, name, 0,
                       f"{where}: solver returned {result} — public exposure was "
                       f"not decided")
    witness = witness_packet(z3, solver.model(), packet)
    return Verdict("contradicted", _EXPOSURE, name, 0,
                   f"{where}: a public source ({witness['src']}) can reach "
                   f"{_flow(witness)} through this rule")


# -- CHECK 2: PAIR packet-set non-enlargement ---------------------------------


def _first_unsupported(rules: Sequence[Mapping[str, Any]], side: str):
    """``(side, rule name, reason)`` for the first rule of *rules* the encoding
    cannot represent, or None. See the module docstring: a group containing one
    is not compared at all."""
    for rule in rules:
        reason = rule.get("unsupported")
        if reason:
            return side, _rule_name(rule), str(reason)
    return None


def _first_unplaceable(rules: Sequence[Mapping[str, Any]], side: str):
    """``(side, rule name, reason)`` for the first rule whose *grouping key*
    itself did not survive normalization — no network, or no direction.

    Such a rule cannot be assigned to a ``(network, direction)`` group without
    guessing, and a wrong guess is not a local error: it silently empties the
    group the rule really belonged to, which reads as a widening (if it was an
    old deny) or as safety (if it was a new allow). So it abstains the whole
    comparison, not just one group."""
    for rule in rules:
        if _network_of(rule) is _NO_NETWORK or not rule.get("direction"):
            return (side, _rule_name(rule),
                    str(rule.get("unsupported") or "no network or direction"))
    return None


def _not_compared(source: str, target: str, why: str) -> Verdict:
    return Verdict("unverified", _PAIR, target, 0, f"{source}: {why}")


def check_packet_set_pair(ctx) -> list[Verdict]:
    """Does the new rule set allow any packet the baseline's set denied?

    One verdict per ``(network, direction)`` group. The desired property is
    non-enlargement, so its *negation* — ``And(allow_new, Not(allow_old))`` — is
    what is asserted: **unsat** means the new set allows nothing the old one
    denied (``grounded``); sat hands back the witness packet that got newly
    through (``contradicted``).

    ``allow_new`` / ``allow_old`` are the priority-ordered
    :func:`~gcp_grounding.packet.effective_allow` folds, defaulted to GCP's
    implied rules at priority 65535: deny-all for INGRESS, allow-all for EGRESS.
    That default is what makes *removing* an egress deny show up as the widening
    it is.
    """
    z3 = _z3_module(ctx.solver)
    source = ctx.source or "<policy>"
    if z3 is None:
        logger.debug("pair check degraded to unverified: backend=%s has no z3",
                     _backend(ctx))
        return [Verdict("unverified", _PAIR, source, 0,
                        f"{source}: z3 is not available (solver backend "
                        f"{_backend(ctx)!r}) — the packet-set comparison against "
                        f"the baseline was not decided")]

    new_rules = [claim.fields() for claim in ctx.claims
                 if getattr(claim, "kind", None) == "firewall_rule"]
    if not new_rules:
        return [_not_compared(source, source,
                              "no VPC firewall rule was extracted from the "
                              "document — no packet-set comparison was made")]
    if ctx.baseline is None:
        return [_not_compared(source, source,
                              "no baseline document was available — no packet-set "
                              "comparison was made")]
    if fw_claims.detect_kind(ctx.baseline) != "firewall_rule":
        # Reading a non-firewall baseline as a vacuously empty "old" rule set
        # would turn every new allow into a widening — a fabricated
        # contradiction, not a finding.
        return [_not_compared(source, source,
                              "the baseline is not a VPC firewall rule document "
                              "— no packet-set comparison was made")]
    try:
        baseline_claims = fw_claims.firewall_rule_claims(ctx.baseline)
    except Exception as exc:  # noqa: BLE001 — fail-open, like every other layer
        logger.debug("pair check unverified: baseline extraction failed", exc_info=True)
        return [_not_compared(source, source,
                              f"the baseline's firewall rules could not be "
                              f"extracted ({type(exc).__name__}: {exc}) — no "
                              f"packet-set comparison was made")]
    old_rules = [claim.fields() for claim in baseline_claims
                 if claim.kind == "firewall_rule"]
    if not old_rules:
        return [_not_compared(source, source,
                              "no VPC firewall rule was extracted from the "
                              "baseline — no packet-set comparison was made")]

    unplaceable = (_first_unplaceable(new_rules, "document")
                   or _first_unplaceable(old_rules, "baseline"))
    if unplaceable is not None:
        side, name, reason = unplaceable
        return [_not_compared(
            source, source,
            f"the {side}'s rule {name!r} could not be placed in a "
            f"(network, direction) group ({reason}); dropping it would "
            f"fabricate a verdict, so no packet-set comparison was made")]

    # Every rule is placeable by now, so both sets are non-empty and carry only
    # real network names.
    new_networks = {_network_of(r) for r in new_rules}
    old_networks = {_network_of(r) for r in old_rules}
    if new_networks.isdisjoint(old_networks):
        return [_not_compared(source, source,
                              f"the baseline covers a different network "
                              f"({', '.join(sorted(old_networks))}, against "
                              f"{', '.join(sorted(new_networks))} in the document) "
                              f"— no packet-set comparison was made")]

    tags, accounts = _universe([*new_rules, *old_rules])
    groups = sorted({(_network_of(r), _direction_of(r))
                     for r in (*new_rules, *old_rules)})

    verdicts: list[Verdict] = []
    for network, direction in groups:
        target = f"{network} {direction}"
        mine = [r for r in new_rules
                if (_network_of(r), _direction_of(r)) == (network, direction)]
        theirs = [r for r in old_rules
                  if (_network_of(r), _direction_of(r)) == (network, direction)]

        offender = (_first_unsupported(mine, "document")
                    or _first_unsupported(theirs, "baseline"))
        if offender is not None:
            side, name, reason = offender
            verdicts.append(_not_compared(
                source, target,
                f"the {side}'s rule {name!r} carries a shape the packet encoding "
                f"cannot represent ({reason}); dropping it would fabricate a "
                f"verdict, so {target} was not compared"))
            continue

        default_allow = direction == "EGRESS"
        try:
            packet = packet_vars(z3, tags=tags, service_accounts=accounts)
            allow_new = effective_allow(z3, packet, mine, direction,
                                        default_allow=default_allow)
            allow_old = effective_allow(z3, packet, theirs, direction,
                                        default_allow=default_allow)
            axioms = universe_axioms(z3, packet)
        except UnsupportedPacket as exc:
            verdicts.append(_not_compared(
                source, target,
                f"a rule in {target} carries a shape the packet encoding cannot "
                f"represent ({exc}); dropping it would fabricate a verdict, so "
                f"{target} was not compared"))
            continue

        solver = z3.Solver()
        for axiom in axioms:
            solver.add(axiom)
        solver.add(z3.And(allow_new, z3.Not(allow_old)))
        result = solver.check()
        if result == z3.unsat:
            verdicts.append(Verdict("grounded", _PAIR, target, 0,
                                    f"{source}: the new rule set allows no packet "
                                    f"the old set denied"))
        elif result == z3.sat:
            witness = witness_packet(z3, solver.model(), packet)
            verdicts.append(Verdict("contradicted", _PAIR, target, 0,
                                    f"{source}: the new rule set newly allows "
                                    f"{_flow(witness)} from {witness['src']} to "
                                    f"{witness['dst']}"))
        else:
            verdicts.append(_not_compared(
                source, target,
                f"solver returned {result} — {target} was not compared"))
    return verdicts


# -- registry wiring ----------------------------------------------------------

#: Per-claim checks the registry discovers (no edit elsewhere).
CLAIM_CHECKS = {"firewall_rule": check_open_exposure}

#: Baseline (widening) checks the registry discovers, keyed by document kind.
PAIR_CHECKS = {"firewall_rule": check_packet_set_pair}
