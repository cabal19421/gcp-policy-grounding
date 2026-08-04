"""Cloud Armor grounding checks: the default rule, priority-order
unreachability, priority bypass, and the preconfigured-expression vocabulary.

Cloud Armor evaluates a security policy's rules in ascending priority: the
FIRST match wins, and — unlike a VPC firewall — there is no deny-beats-allow
tie-break, because priorities are unique within a policy. Every check here
follows from that one rule.

MATCH ENCODING. One :class:`~gcp_grounding.packet.PacketVars` is built for the
whole policy and its ``src`` bitvector is shared with the Armor expression
translator (:func:`gcp_grounding.armor_expr.armor_vars` takes it), so an
``inIpRange(origin.ip, …)`` in an ``expr`` rule and the ``config.srcIpRanges``
of a config rule constrain the very same z3 constant and are therefore
comparable. A rule's predicate is
:func:`~gcp_grounding.packet.any_cidr_match` over its source ranges when the
match is config-shaped, and ``armor_expr.translate(...)`` when it is
expression-shaped. Anything the encoding cannot represent — an
``UnsupportedArmorExpr``, an :class:`~gcp_grounding.packet.UnsupportedPacket`,
an ``unsupported`` payload key from
:mod:`~gcp_grounding.armor_claims`, a ``RecursionError`` out of the translator,
an absent :mod:`~gcp_grounding.armor_expr`, or an absent z3 — produces exactly
ONE ``unverified`` verdict naming the rule and the reason, and that rule then
takes part in no comparison. Never a ``contradicted``: a rule we could not read
is ignorance, not evidence.

The four checks:

CHECK 1 — DEFAULT RULE (only for a whole-policy document, i.e. when a rule
claim carries ``policy_document``). PURE STRUCTURE, no solver: it counts rules
and reads a priority, so it decides identically on the builtin backend —
exactly like :func:`gcp_grounding.constraints.check_constraint_value`. It is
deliberately NOT gated behind z3: losing a decidable finding to an absent
solver would be a silent downgrade. A policy with no rule at
:data:`~gcp_grounding.armor_claims.DEFAULT_RULE_PRIORITY` is ``contradicted``
(GCP rejects it); a default rule whose action is ``allow`` is ``grounded``
carrying an explicit warning — informational, mirroring the ``check_cel``
tautology precedent, because an allow default is exactly how a *blocklist*
policy is written and must not fail the gate; a deny default is a plain
``grounded``.

CHECK 2 — UNREACHABLE RULE. Family (c) COVERAGE: ``And(match(r), Not(higher))``
where *higher* is the disjunction of the rules with a strictly smaller priority
number. **UNSAT is the finding** (nothing reaches r) and there is no witness on
that branch; SAT is the healthy case. The family (b) PAIR reading — unsat means
grounded — would invert this check into a no-op that passes every dead rule and
flags every live one, so it is not used here. The default rule is excluded: by
construction it matches everything at the lowest precedence.

CHECK 3 — PRIORITY BYPASS, the headline check and family (a): the bad property
is asserted, so **SAT is the finding** and carries a witness. A proposed
``allow`` at priority *p* beats every ``deny`` at a strictly larger priority
*q*, so an overlapping such pair is a real bypass. Existing rules come from the
other rules of the same document and — for a standalone
``google_compute_security_policy_rule`` whose ``security_policy_ref`` resolves —
from ``snapshot.cloud_armor_policies[<policy>]["rules"]``. The estate accessor
answers UNKNOWN / None / a record and is compared with ``is``, never
truth-tested; either abstention emits one ``unverified`` saying the existing
policy could not be read.

CHECK 4 — EXPR VOCABULARY. A ``referenced_expr_ids`` entry outside
``armor_expr.PRECONFIGURED_EXPR_IDS`` is ``unverified``, never ``ungrounded``:
that curated list is known-incomplete, so an id missing from it is ignorance,
not evidence of a hallucination.

:mod:`gcp_grounding.armor_expr` is imported lazily by name (like
:func:`gcp_grounding.preflight._tf_plan_extractor` resolves the tf extractor),
so a checkout without it degrades to the same honest ``unverified`` path as an
unsupported expression instead of failing to import.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Mapping

from . import packet
from .armor_claims import DEFAULT_RULE_PRIORITY
from .constraints import _z3_module
from .core.log import get_logger
from .core.report import Verdict
from .knowledge import UNKNOWN
from .solve import decide, model_or_none

logger = get_logger(__name__)

__all__ = ["check_security_policy", "DOCUMENT_CHECKS"]


class _Unencodable(Exception):
    """A rule this module cannot turn into a z3 predicate. Always becomes one
    ``unverified`` naming the rule — never a dropped rule and never a verdict."""


def _armor_expr_module():
    """:mod:`gcp_grounding.armor_expr`, or None where it is not part of this
    checkout. Resolved by name so its absence degrades to an abstain rather
    than an import error (the registry's own fail-open discipline)."""
    try:
        return importlib.import_module("gcp_grounding.armor_expr")
    except ImportError:
        logger.debug("gcp_grounding.armor_expr is not part of this checkout — "
                     "expression-shaped Armor rules will abstain")
        return None


@dataclass(frozen=True)
class _Rule:
    """One encodable rule: its id, where it came from, and its z3 predicate."""

    id: str
    location: str
    priority: int
    action: str
    term: Any
    #: The estate policy this rule already lives in, or None for a proposed rule.
    existing_in: str | None = None


# -- match encoding -----------------------------------------------------------


class _Encoder:
    """The one shared symbolic packet for a whole policy, plus the translation
    of a normalized rule's ``match`` into a z3 predicate over it."""

    def __init__(self, z3, expr_module) -> None:
        self.z3 = z3
        self._expr = expr_module
        self.packet_vars = packet.packet_vars(z3)
        self._armor_vars = None

    def _vars(self):
        """The :class:`~gcp_grounding.armor_expr.ArmorVars` for expression
        rules, built once over the SHARED ``src`` bitvector."""
        if self._armor_vars is None:
            if self._expr is None:
                raise _Unencodable("gcp_grounding.armor_expr is not part of this "
                                   "checkout, so match expressions cannot be translated")
            self._armor_vars = self._expr.armor_vars(self.z3, self.packet_vars.src)
        return self._armor_vars

    def match(self, rule: Mapping[str, Any]):
        """The z3 predicate for a normalized rule's ``match``."""
        unsupported = rule.get("unsupported")
        if unsupported:
            raise _Unencodable(str(unsupported))
        match = rule.get("match") or {}
        expression = match.get("expr")
        if expression:
            armor_vars = self._vars()  # _Unencodable when armor_expr is absent
            try:
                return self._expr.translate(self.z3, expression, armor_vars)
            except RecursionError:
                raise _Unencodable("expression is too deeply nested to translate") from None
            except Exception as exc:  # UnsupportedArmorExpr / UnsupportedPacket
                raise _Unencodable(f"{type(exc).__name__}: {exc}") from None
        ranges = [_range(item) for item in (match.get("src_ip_ranges") or ())]
        try:
            return packet.any_cidr_match(self.z3, self.packet_vars.src, ranges)
        except packet.UnsupportedPacket as exc:
            raise _Unencodable(str(exc)) from None

    def witness(self, model) -> tuple[str, str]:
        """A model rendered as ``(source ip, region)``. The region is ``"any"``
        unless an expression rule actually constrained ``origin.region_code``."""
        source = packet.witness_packet(self.z3, model, self.packet_vars)["src"]
        region = "any"
        if self._armor_vars is not None:
            try:
                region = model.eval(self._armor_vars.region,
                                    model_completion=True).as_string() or "any"
            except Exception:  # noqa: BLE001 — rendering must never break a verdict
                logger.debug("could not render origin.region_code from the model",
                             exc_info=True)
        return source, region


def _range(item: Any) -> Any:
    """An estate record keeps Cloud Armor's ``"*"`` wildcard verbatim (claims
    normalize it); both spellings mean every address."""
    return "0.0.0.0/0" if item == "*" else item


def _is_allow(action: str) -> bool:
    return action == "allow"


def _is_deny(action: str) -> bool:
    """``deny``, ``deny-403`` (the Terraform spelling) and ``deny(403)`` (the
    REST spelling) are all denials."""
    return action.startswith("deny")


# -- the registered document check --------------------------------------------


def check_security_policy(ctx) -> list[Verdict]:
    """Every Cloud Armor verdict for one document; ``[]`` when it carries no
    security-policy rules."""
    rules = [(claim, claim.fields()) for claim in ctx.claims
             if claim.kind == "security_policy_rule"]
    if not rules:
        return []
    verdicts = _check_default_rule(rules)
    verdicts += _check_priority_order(rules, ctx)
    verdicts += _check_expr_vocabulary(rules)
    logger.debug("check_security_policy(%s): %d rule claim(s) -> %d verdict(s)",
                 ctx.source, len(rules), len(verdicts))
    return verdicts


# -- CHECK 1: the default rule (pure structure, no solver) --------------------


def _check_default_rule(rules) -> list[Verdict]:
    marker = next((claim for claim, fields in rules
                   if fields.get("policy_document") is True), None)
    if marker is None:
        # A standalone rule resource says nothing about its policy's default.
        return []
    policy = _policy_name(rules)
    default = next(((claim, fields) for claim, fields in rules
                    if fields.get("priority") == DEFAULT_RULE_PRIORITY), None)
    if default is None:
        unreadable = [fields.get("unsupported") for _, fields in rules
                      if fields.get("unsupported")]
        if unreadable:
            # A rule the extractor could not normalize carries no priority at
            # all, so "no default rule" would be a guess, not a finding.
            return [Verdict("unverified", "armor_default", policy, 0,
                            f"{marker.location}: {len(unreadable)} rule(s) could not be "
                            f"normalized ({unreadable[0]}) — whether the policy has a "
                            f"default rule was not decided")]
        return [Verdict("contradicted", "armor_default", policy, 0,
                        f"{marker.location}: the policy has no default rule at priority "
                        f"{DEFAULT_RULE_PRIORITY} — Cloud Armor requires one and the "
                        f"policy would be rejected")]
    claim, fields = default
    action = str(fields.get("action") or "")
    if _is_allow(action):
        return [Verdict("grounded", "armor_default", policy, 0,
                        f"{claim.location}: default rule allows all traffic — this "
                        f"policy is a blocklist, not an allowlist; that is legitimate "
                        f"for a blocklist, so this is a warning, not a finding")]
    return [Verdict("grounded", "armor_default", policy, 0,
                    f"{claim.location}: the default rule at priority "
                    f"{DEFAULT_RULE_PRIORITY} is a {action!r} — traffic matching no "
                    f"earlier rule is denied")]


# -- CHECKS 2 and 3: priority order -------------------------------------------


def _check_priority_order(rules, ctx) -> list[Verdict]:
    policy = _policy_name(rules)
    where = rules[0][0].location
    z3 = _z3_module(ctx.solver)
    if z3 is None:
        # CHECK 1 above still decided; only the solver-backed pair of checks
        # abstains, and it says so once for the whole policy.
        backend = getattr(ctx.solver, "backend", "unknown")
        return [Verdict("unverified", "armor_rule", policy, 0,
                        f"{where}: z3 is not available (solver backend {backend!r}) — "
                        f"rule unreachability and priority bypass were not decided")]

    encoder = _Encoder(z3, _armor_expr_module())
    verdicts: list[Verdict] = []
    proposed: list[_Rule] = []
    for claim, fields in rules:
        rule_id = _rule_id(_policy_of(claim, fields), fields, claim.location)
        try:
            term = encoder.match(fields)
            priority = fields.get("priority")
            if not isinstance(priority, int) or isinstance(priority, bool):
                raise _Unencodable(f"priority {priority!r} is not an integer")
        except _Unencodable as exc:
            verdicts.append(_unencodable_verdict(rule_id, claim.location, exc))
            continue
        proposed.append(_Rule(id=rule_id, location=claim.location, priority=priority,
                              action=str(fields.get("action") or ""), term=term))

    existing, estate_verdicts = _estate_rules(ctx, rules, encoder, where)
    verdicts += estate_verdicts
    verdicts += _check_unreachable(z3, proposed)
    verdicts += _check_bypass(z3, encoder, proposed, existing)
    return verdicts


def _check_unreachable(z3, proposed: list[_Rule]) -> list[Verdict]:
    """CHECK 2, family (c) COVERAGE: UNSAT is the finding, SAT is healthy."""
    verdicts: list[Verdict] = []
    for rule in proposed:
        if rule.priority == DEFAULT_RULE_PRIORITY:
            continue  # matches everything, at the lowest precedence, by design
        higher = [h for h in proposed if h.priority < rule.priority]
        if not higher:
            # Nothing preempts it; "unsat" would then mean the rule's own match
            # is empty, which is a different (and unasked) question.
            continue
        reachable = decide(z3, z3.And(rule.term, z3.Not(z3.Or([h.term for h in higher]))))
        if reachable is None:
            verdicts.append(Verdict("unverified", "armor_priority", rule.id, 0,
                                    f"{rule.location}: the solver returned unknown — "
                                    f"whether the rule at priority {rule.priority} is "
                                    f"reachable was not decided"))
        elif reachable is False:
            verdicts.append(Verdict("contradicted", "armor_priority", rule.id, 0,
                                    f"{rule.location}: rule at priority {rule.priority} "
                                    f"is unreachable — rule(s) {_covering(z3, rule, higher)} "
                                    f"at lower priority already match every request it "
                                    f"matches"))
    return verdicts


def _covering(z3, rule: _Rule, higher: list[_Rule]) -> str:
    """Which higher-precedence rules to name: those that individually cover
    *rule* (one re-check each), falling back to the whole set when only their
    union does."""
    individually = [h for h in higher
                    if decide(z3, z3.And(rule.term, z3.Not(h.term))) is False]
    if individually:
        return ", ".join(f"priority {h.priority}" for h in individually)
    return ("priorities " + ", ".join(str(h.priority) for h in higher)
            + " taken together")


def _check_bypass(z3, encoder: _Encoder, proposed: list[_Rule],
                  existing: list[_Rule]) -> list[Verdict]:
    """CHECK 3, family (a) PROPOSAL: SAT is the finding and carries a witness."""
    verdicts: list[Verdict] = []
    candidates = proposed + existing
    for rule in proposed:
        if not _is_allow(rule.action):
            continue
        for other in candidates:
            if other is rule or not _is_deny(other.action):
                continue
            if other.priority <= rule.priority:
                continue  # the deny wins on its own; nothing is bypassed
            overlaps, model = model_or_none(z3, z3.And(rule.term, other.term))
            origin = (f" — the deny is an existing rule in {other.existing_in!r}"
                      if other.existing_in else "")
            if overlaps is None:
                verdicts.append(Verdict("unverified", "armor_bypass", rule.id, 0,
                                        f"{rule.location}: the solver returned unknown "
                                        f"— whether the allow at priority {rule.priority} "
                                        f"bypasses the deny at priority {other.priority} "
                                        f"was not decided{origin}"))
            elif overlaps:
                source, region = encoder.witness(model)
                verdicts.append(Verdict("contradicted", "armor_bypass", rule.id, 0,
                                        f"{rule.location}: the allow at priority "
                                        f"{rule.priority} bypasses the deny at priority "
                                        f"{other.priority} for e.g. source {source} / "
                                        f"region {region}{origin}"))
    return verdicts


def _estate_rules(ctx, rules, encoder: _Encoder,
                  where: str) -> tuple[list[_Rule], list[Verdict]]:
    """The already-deployed rules a standalone proposed rule would join, plus
    the abstentions for a policy whose rules could not be read.

    Only a standalone ``google_compute_security_policy_rule`` consults the
    estate: a whole-policy document carries its own complete rule list."""
    if any(fields.get("policy_document") is True for _, fields in rules):
        return [], []
    names = sorted({claim.value for claim in ctx.claims
                    if claim.kind == "security_policy_ref"})
    if not names:
        return [], []
    out: list[_Rule] = []
    verdicts: list[Verdict] = []
    for name in names:
        record = ctx.snapshot.cloud_armor_policy(name)
        if record is UNKNOWN:
            verdicts.append(Verdict("unverified", "armor_bypass", name, 0,
                                    f"{where}: cloud_armor_policies was not captured in "
                                    f"the snapshot, so the existing rules of {name!r} "
                                    f"could not be read — the priority-bypass check "
                                    f"against them was not made"))
            continue
        if record is None:
            verdicts.append(Verdict("unverified", "armor_bypass", name, 0,
                                    f"{where}: {name!r} is not in the snapshot's "
                                    f"captured cloud_armor_policies, so its existing "
                                    f"rules could not be read — the priority-bypass "
                                    f"check against them was not made"))
            continue
        for index, rule in enumerate(record.get("rules") or ()):
            location = f"snapshot.cloud_armor_policies[{name!r}].rules[{index}]"
            rule_id = _rule_id(name, rule, location)
            try:
                term = encoder.match(rule)
                priority = rule.get("priority")
                if not isinstance(priority, int) or isinstance(priority, bool):
                    raise _Unencodable(f"priority {priority!r} is not an integer")
            except _Unencodable as exc:
                verdicts.append(_unencodable_verdict(rule_id, location, exc))
                continue
            out.append(_Rule(id=rule_id, location=location, priority=priority,
                             action=str(rule.get("action") or ""), term=term,
                             existing_in=name))
    return out, verdicts


# -- CHECK 4: the preconfigured-expression vocabulary -------------------------


def _check_expr_vocabulary(rules) -> list[Verdict]:
    curated = _preconfigured_expr_ids()
    verdicts: list[Verdict] = []
    for claim, fields in rules:
        for expr_id in fields.get("referenced_expr_ids") or ():
            if expr_id in curated:
                continue
            verdicts.append(Verdict("unverified", "armor_expr", expr_id, 0,
                                    f"{claim.location}: preconfigured WAF expression "
                                    f"{expr_id!r} is not in this build's curated list — "
                                    f"it may be valid; not decided"))
    return verdicts


def _preconfigured_expr_ids() -> frozenset[str]:
    """The curated WAF expression ids — empty where :mod:`armor_expr` is not
    part of this checkout, which makes every referenced id merely unverified."""
    module = _armor_expr_module()
    return frozenset(getattr(module, "PRECONFIGURED_EXPR_IDS", ()) or ())


# -- small shared helpers -----------------------------------------------------


def _unencodable_verdict(rule_id: str, location: str, exc: _Unencodable) -> Verdict:
    """The ONE abstention a rule we cannot encode produces — it stands for both
    CHECK 2 and CHECK 3, which that rule then sits out of."""
    return Verdict("unverified", "armor_rule", rule_id, 0,
                   f"{location}: the rule's match could not be encoded ({exc}) — its "
                   f"reachability and any priority bypass were not decided")


def _policy_of(claim, fields: Mapping[str, Any]) -> str:
    policy = fields.get("policy")
    return policy if isinstance(policy, str) and policy else claim.value


def _policy_name(rules) -> str:
    return _policy_of(rules[0][0], rules[0][1])


def _rule_id(policy: str, rule: Mapping[str, Any], location: str) -> str:
    """A stable identifier for one rule: Cloud Armor rules have no names, so a
    policy-qualified priority is the closest thing (and the location backs it
    up when even the priority did not survive normalization)."""
    priority = rule.get("priority")
    if isinstance(priority, int) and not isinstance(priority, bool):
        return f"{policy}#{priority}"
    return f"{policy}@{location}"


#: The whole-document check registered with :mod:`gcp_grounding.registry`.
DOCUMENT_CHECKS = (check_security_policy,)
