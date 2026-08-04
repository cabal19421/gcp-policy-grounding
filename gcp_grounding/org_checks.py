"""Org Policy checks: the enforcement flag, the list values, and their nodes.

The sixth grounding domain, and the one the other five made conspicuous by its
absence. :func:`~gcp_grounding.constraints.check_constraint_value` decides only
the value *type* a policy uses, so ``enforce: true`` and ``enforce: false``
produced byte-identical reports: an agent could turn off
``constraints/iam.disableServiceAccountKeyCreation`` and the gate would say
nothing. The ``constraint_enforcement`` claim
(:func:`~gcp_grounding.claims.org_policy_claims`) carries the values
themselves, and the three checks here decide them against the estate's
``org_policies`` table:

- CHECK 1 (:func:`check_constraint_enforcement`) — **enforcement removal**.
  The prior state comes from ``snapshot.org_policy(node, constraint)`` (or, when
  a baseline document was supplied, from the baseline — a PAIR comparison beats
  an estate snapshot that may be stale). All THREE disablement spellings fire:
  ``enforce: false``, ``spec.reset: true``, and ``spec.inheritFromParent: true``
  on a policy with no rules of its own. A check that caught only the first would
  be evaded by the other two.
- CHECK 2 (same entry point) — **list widening**. A value in the proposal's
  ``allowed_values`` and not in the captured record's is a widening; so is
  ``allowAll`` over an enumerated allowlist. Removing allowed values, or adding
  denied ones, narrows and grounds.
- CHECK 3 (:func:`check_org_estate`) — **domain value grounding**. List values
  naming a resource-hierarchy node are pushed through the existing Datalog
  existence pass (:func:`~gcp_grounding.reasoner.ground_existence`) as
  ``hierarchy_node_ref`` claims, did-you-mean suggestions included. This domain
  adds no snapshot category of its own.

**Abstention.** An uncaptured ``org_policies`` table, or a node that table does
not record, yields exactly one ``unverified`` per claim and never a
``contradicted``: an unrecorded node is not an unenforced one, and letting one
read as the other would turn "we never looked" into "it was already off".

**No z3.** This is set algebra and a boolean comparison; there is no encoding,
no solver call and no ``import z3`` anywhere in this module, so it decides
identically on the builtin and z3 backends — like
:func:`~gcp_grounding.constraints.check_constraint_value`. ``ctx.solver`` is
never read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from .claims import NO_RULE_INDEX, Claim, org_policy_claims
from .core.log import get_logger
from .core.report import Verdict
from .knowledge import UNKNOWN
from .reasoner import ground_existence
from .registry import CheckContext

logger = get_logger(__name__)

__all__ = ["CLAIM_CHECKS", "DOCUMENT_CHECKS", "OPAQUE_VALUE_CONSTRAINTS",
           "VERDICT_KIND", "check_constraint_enforcement", "check_org_estate",
           "hierarchy_value_claims"]

#: ``Verdict.kind`` for every finding this module makes.
VERDICT_KIND = "org_enforcement"

#: Constraints whose list values are opaque identifiers no estate snapshot
#: enumerates — Cloud Identity customer ids, not resource names. Their values
#: get NO existence claim: grounding ``C01abcdef`` against the hierarchy would
#: manufacture a false ``ungrounded``.
OPAQUE_VALUE_CONSTRAINTS = ("constraints/iam.allowedPolicyMemberDomains",)

#: A list value naming a resource-hierarchy node, and nothing else. The prefix
#: alone is not enough: ``projects/p/zones/z/instances/i`` is the documented
#: value shape of ``constraints/compute.vmExternalIpAccess`` and is an instance,
#: not a node — grounding it would fabricate an ``ungrounded``.
_HIERARCHY_NODE = re.compile(r"(?:projects|folders|organizations)/[^/]+")

#: Payload keys of a ``constraint_enforcement`` claim that hold a rule's values,
#: paired with the REST field name a verdict points at.
_VALUE_FIELDS = (("allowed_values", "allowedValues"),
                 ("denied_values", "deniedValues"))


# -- the prior state ----------------------------------------------------------


@dataclass(frozen=True)
class _Prior:
    """The state a proposal is compared against: the rules in force before it,
    plus where that evidence came from (named in every message, because a
    baseline PAIR and a possibly-stale snapshot are not equal evidence)."""

    rules: tuple[Mapping[str, Any], ...]
    reset: bool
    inherit: bool
    source: str

    @property
    def enforced(self) -> bool:
        """Whether the prior state actually enforces the constraint: some rule
        sets ``enforce: true`` and the policy is not itself a reset."""
        return not self.reset and any(r["enforce"] is True for r in self.rules)

    @property
    def list_rules(self) -> tuple[Mapping[str, Any], ...]:
        """The prior rules that carry list values (a boolean rule sets none)."""
        return tuple(r for r in self.rules if r["enforce"] is None)


def _normalize_rule(rule: Mapping[str, Any]) -> dict[str, Any]:
    """One prior rule in the same shape a ``constraint_enforcement`` payload
    uses, reading either the snapshot's snake_case or a raw REST camelCase."""
    def flag(*keys: str) -> bool | None:
        for key in keys:
            if isinstance(rule.get(key), bool):
                return rule[key]
        return None

    def values(*keys: str) -> tuple[str, ...]:
        for key in keys:
            raw = rule.get(key)
            if isinstance(raw, (list, tuple)):
                return tuple(v for v in raw if isinstance(v, str))
        return ()

    return {"enforce": flag("enforce"),
            "allow_all": flag("allow_all", "allowAll"),
            "deny_all": flag("deny_all", "denyAll"),
            "allowed_values": values("allowed_values", "allowedValues"),
            "denied_values": values("denied_values", "deniedValues")}


def _baseline_prior(ctx: CheckContext, constraint: str) -> _Prior | None:
    """The prior state read off ``ctx.baseline`` — or None when there is no
    baseline, it is not an org policy, or it does not set *constraint*.

    The baseline is re-parsed through :func:`org_policy_claims`, so its rules
    arrive in exactly the payload shape the proposal's claims use; there is no
    second, divergent parser for the same document format.
    """
    if ctx.baseline_kind != "org_policy" or not isinstance(ctx.baseline, Mapping):
        return None
    try:
        prior_claims = [c for c in org_policy_claims(ctx.baseline)
                        if c.kind == "constraint_enforcement" and c.value == constraint]
    except ValueError:  # a baseline shape the extractor refuses — fall back
        logger.debug("baseline org policy could not be parsed — using the snapshot")
        return None
    if not prior_claims:
        logger.debug("baseline org policy sets no rule for %s — using the snapshot",
                     constraint)
        return None
    fields = [c.fields() for c in prior_claims]
    return _Prior(
        # A baseline rule the extractor could not read contributes no rule
        # CONTENT: folding its empty payload in would let an unreadable old
        # side manufacture a widening finding out of nothing.
        rules=tuple(_normalize_rule(f) for f in fields
                    if f["rule_index"] != NO_RULE_INDEX and not f["unreadable"]),
        reset=any(f["reset"] is True for f in fields),
        inherit=any(f["inherit_from_parent"] is True for f in fields),
        source="the baseline document")


def _resolve_prior(claim: Claim, fields: Mapping[str, Any],
                   ctx: CheckContext) -> tuple[_Prior | None, Verdict | None]:
    """→ (prior state, None) or (None, the one abstention verdict).

    Exactly one is not None. The abstentions are the honesty contract: an
    uncaptured table and an unrecorded node must never read as "it was already
    off", so neither can produce a ``contradicted`` or a silent pass.
    """
    constraint, node = claim.value, fields["node"]
    baseline = _baseline_prior(ctx, constraint)
    if baseline is not None:
        return baseline, None
    record = ctx.snapshot.org_policy(node, constraint)
    if record is UNKNOWN:
        return None, Verdict(
            "unverified", VERDICT_KIND, constraint, 0,
            f"{claim.location}: the estate's org policies were not captured, so a "
            f"change to enforcement was not decided")
    if not node:
        return None, Verdict(
            "unverified", VERDICT_KIND, constraint, 0,
            f"{claim.location}: this document does not name the node it is set on, "
            f"so the prior state of {constraint} could not be looked up — a change "
            f"to enforcement was not decided")
    if record is None:
        return None, Verdict(
            "unverified", VERDICT_KIND, constraint, 0,
            f"{claim.location}: the estate's org policies record nothing for "
            f"{constraint} at {node} (captured {ctx.snapshot.captured_at}), so a "
            f"change to enforcement was not decided — an unrecorded node is not an "
            f"unenforced one")
    captured = record.get("rules")
    if not isinstance(captured, (list, tuple)):
        # No empty default: a record whose rules could not be READ is not a
        # record of non-enforcement, and folding it to zero rules is how
        # "never looked" becomes "it was already off". (The read cannot go
        # through :func:`gcp_grounding.evidence.rows`, which accepts a ``list``
        # only, because a loaded snapshot's record tables hold tuples.)
        return None, Verdict(
            "unverified", VERDICT_KIND, constraint, 0,
            f"{claim.location}: the estate's record of {constraint} at {node} "
            f"(captured {ctx.snapshot.captured_at}) has no readable 'rules' list, "
            f"got {type(captured).__name__} — so a change to enforcement was not "
            f"decided; an unreadable record is not a record of non-enforcement")
    rules = tuple(_normalize_rule(r) for r in captured if isinstance(r, Mapping))
    return _Prior(rules=rules,
                  reset=record.get("reset") is True,
                  inherit=record.get("inherit_from_parent") is True,
                  source=f"the estate snapshot captured {ctx.snapshot.captured_at}"), None


# -- CHECK 1: enforcement removal ---------------------------------------------


def _disablement(fields: Mapping[str, Any]) -> str | None:
    """Which of the three disablement spellings the proposal uses, spelled out
    for the message — or None when it stops enforcing nothing."""
    if fields["enforce"] is False:
        return "enforce is false"
    if fields["reset"] is True:
        return "spec.reset is true, which drops back to the inherited default"
    if fields["inherit_from_parent"] is True and fields["rule_index"] == NO_RULE_INDEX:
        return ("spec.inheritFromParent is true and the policy sets no rules of "
                "its own, so the node keeps only what it inherits")
    return None


def _check_enforcement(claim: Claim, fields: Mapping[str, Any],
                       prior: _Prior) -> Verdict:
    constraint = claim.value
    node = fields["node"] or "the node it is set on"
    removed = _disablement(fields)
    if prior.enforced and removed is not None:
        return Verdict(
            "contradicted", VERDICT_KIND, constraint, 0,
            f"{claim.location}: this change stops enforcing {constraint} at {node} "
            f"({removed}) — the guardrail it provides is removed (prior state from "
            f"{prior.source})")
    if fields["enforce"] is True:
        detail = "enforce is true"
    elif prior.enforced:
        detail = "the policy still sets it at this node"
    else:
        detail = "it was not enforced here before this change either"
    return Verdict(
        "grounded", VERDICT_KIND, constraint, 0,
        f"{claim.location}: this change does not stop enforcing {constraint} at "
        f"{node} ({detail}) — prior state from {prior.source}")


# -- CHECK 2: list widening ---------------------------------------------------


def _is_list_shaped(fields: Mapping[str, Any]) -> bool:
    """Whether the proposal's rule sets list values at all. A rule that sets
    none can widen nothing, so CHECK 2 stays silent on it rather than minting
    a vacuous verdict."""
    return bool(fields["allow_all"] is not None or fields["deny_all"] is not None
                or fields["allowed_values"] or fields["denied_values"])


def _check_widening(claim: Claim, fields: Mapping[str, Any],
                    prior: _Prior) -> Verdict:
    constraint = claim.value
    node = fields["node"] or "the node it is set on"
    list_rules = prior.list_rules
    if not list_rules:
        return Verdict(
            "unverified", VERDICT_KIND, constraint, 0,
            f"{claim.location}: the prior state of {constraint} at {node} sets no "
            f"list values ({prior.source}), so this rule's values could not be "
            f"compared against it — a widening was not decided")
    prior_allowed = {v for r in list_rules for v in r["allowed_values"]}
    if any(r["allow_all"] is True for r in list_rules):
        return Verdict(
            "grounded", VERDICT_KIND, constraint, 0,
            f"{claim.location}: {constraint} already allows every value at {node} "
            f"({prior.source}), so this change cannot widen it")
    if fields["allow_all"] is True:
        enumerated = ", ".join(sorted(prior_allowed)) or "no value at all"
        return Verdict(
            "contradicted", VERDICT_KIND, constraint, 0,
            f"{claim.location}: this change allows ALL values for {constraint} at "
            f"{node}, replacing the enumerated allowlist ({enumerated}) — the "
            f"maximal widening (prior state from {prior.source})")
    added = sorted(set(fields["allowed_values"]) - prior_allowed)
    if added:
        return Verdict(
            "contradicted", VERDICT_KIND, constraint, 0,
            f"{claim.location}: this change adds {', '.join(added)} to the allowed "
            f"values of {constraint} at {node} — the policy is widened (prior state "
            f"from {prior.source})")
    return Verdict(
        "grounded", VERDICT_KIND, constraint, 0,
        f"{claim.location}: this change adds no value to the allowed values of "
        f"{constraint} at {node} — it narrows or leaves them as they were (prior "
        f"state from {prior.source})")


def _unreadable_proposal(claim: Claim, fields: Mapping[str, Any]) -> Verdict | None:
    """The one ``unverified`` a claim carrying an ``unreadable`` payload owes.

    The PROPOSAL side of the honesty contract, and it comes first: a rule the
    extractor could not read decides nothing about the prior state either way,
    so naming what could not be read is the whole verdict. Without it a decoy
    rule — an empty one, a description-only one, an ambiguous two-key one, a
    non-array rules value — produced no claim at all and the report read PASSED.
    """
    unreadable = fields["unreadable"]
    if not unreadable:
        return None
    node = fields["node"] or "the node it is set on"
    return Verdict(
        "unverified", VERDICT_KIND, claim.value, 0,
        f"{claim.location}: {'; '.join(unreadable)} — so what this document sets "
        f"for {claim.value} at {node} could not be read, and its effect on "
        f"enforcement was not decided")


def check_constraint_enforcement(claim: Claim, ctx: CheckContext) -> list[Verdict]:
    """CHECK 1 and CHECK 2 for one ``constraint_enforcement`` claim.

    Returns exactly one ``unverified`` when the proposal itself could not be
    read, or when the prior state cannot be resolved; otherwise the enforcement
    verdict, plus the widening verdict when the rule sets list values.
    Solver-free: ``ctx.solver`` is not read.
    """
    if claim.kind != "constraint_enforcement":
        raise ValueError(f"check_constraint_enforcement got a {claim.kind!r} claim")
    fields = claim.fields()
    unreadable = _unreadable_proposal(claim, fields)
    if unreadable is not None:
        return [unreadable]
    prior, abstention = _resolve_prior(claim, fields, ctx)
    if abstention is not None:
        return [abstention]
    verdicts = [_check_enforcement(claim, fields, prior)]
    if _is_list_shaped(fields):
        verdicts.append(_check_widening(claim, fields, prior))
    return verdicts


# -- CHECK 3: hierarchy-node values -------------------------------------------


def _value_location(location: str, field: str, index: int) -> str:
    """The json-path of one list value. A v2 rule holds its values under a
    ``values`` block; a v1 ``listPolicy`` holds them directly."""
    prefix = f"{location}.values" if location.startswith("spec.rules[") else location
    return f"{prefix}.{field}[{index}]"


def hierarchy_value_claims(claim: Claim) -> list[Claim]:
    """``hierarchy_node_ref`` claims for the list values of *claim* that name a
    resource-hierarchy node.

    Nothing is emitted for :data:`OPAQUE_VALUE_CONSTRAINTS`, nor for a value
    that is not exactly ``projects/…``, ``folders/…`` or ``organizations/…``:
    a value the snapshot's hierarchy could never contain must produce no claim
    at all, because an existence claim it cannot ground is a false
    ``ungrounded``, not a finding.
    """
    if claim.value in OPAQUE_VALUE_CONSTRAINTS:
        logger.debug("%s carries opaque customer ids — no existence claims",
                     claim.value)
        return []
    fields = claim.fields()
    out: list[Claim] = []
    for key, rest_name in _VALUE_FIELDS:
        for i, value in enumerate(fields[key]):
            if _HIERARCHY_NODE.fullmatch(value):
                out.append(Claim("hierarchy_node_ref", value,
                                 _value_location(claim.location, rest_name, i)))
            else:
                logger.debug("%s value %r names no resource-hierarchy node "
                             "— not grounded", claim.value, value)
    return out


def check_org_estate(ctx: CheckContext) -> list[Verdict]:
    """CHECK 3: ground every hierarchy-node value the document's org-policy
    claims name, through the existing Datalog existence pass."""
    claims: list[Claim] = []
    for claim in ctx.claims:
        if getattr(claim, "kind", None) == "constraint_enforcement":
            claims.extend(hierarchy_value_claims(claim))
    if not claims:
        return []
    return list(ground_existence(claims, ctx.snapshot).verdicts)


#: Registry hooks (see :mod:`gcp_grounding.registry`).
CLAIM_CHECKS = {"constraint_enforcement": check_constraint_enforcement}
DOCUMENT_CHECKS = (check_org_estate,)
