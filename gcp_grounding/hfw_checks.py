"""Hierarchical firewall: cross-level evaluation order, ``goto_next`` semantics
and multi-level shadowing.

This is the check only a hierarchy-aware, solver-backed gate can make. A VPC
firewall rule can be read on its own; a hierarchical firewall rule cannot —
whether it does anything at all depends on what the *organization* and every
*folder* above the project already decided. The classic mistake this closes is
adding a folder-level ``allow`` to "override" an org-level ``deny``: GCP never
honours it, and a rule-local check cannot see it.

LEVEL RESOLUTION. The evaluation order for a project is the org-level policies,
then folder policies outermost-first, then the project's VPC firewall rules.
It is built from :func:`gcp_grounding.hierarchy.ancestry_chain` (outermost-first
by contract) intersected with :meth:`GcpSnapshot.firewall_policies_attached_to`.
A level is NEVER guessed: the check abstains with one ``unverified`` verdict per
proposed rule, naming the missing input, when

* ``resource_hierarchy`` was not captured (``ancestry_chain`` is ``UNKNOWN``);
* ``hierarchical_firewall_policies`` was not captured;
* ``firewall_rules`` was not captured (the VPC layer is the base of the
  effective decision, so without it nothing can be folded onto it);
* the proposed rule's owning policy has no resolvable attachment node;
* that attachment node is absent from the captured hierarchy, or is not on the
  evaluation path of the project under evaluation;
* the project under evaluation cannot be derived.

The project comes from the proposed rule's ``target_resources`` (a network
self-link maps to its project) or from the association claim in the same
proposal — an attachment node that *is* a project, otherwise the unique project
below it in the captured hierarchy.

EFFECTIVE-DECISION ENCODING (:func:`effective_decision`), innermost first and
wrapping outward. It starts at the VPC layer with
:func:`packet.effective_allow` and then, for each level from the innermost
folder out to the organization, folds that level's rules lowest-precedence
first::

    e = eff                                    # the decision INSIDE this level
    for r in reversed(sorted(level, key=rank)):
        outcome = True | False | eff           # allow | deny | goto_next
        e = If(rule_match(r), outcome, e)
    eff = e

``goto_next`` yields the value of the level *inside* this one, which is exactly
``eff`` as it stood before this level's fold — that is the whole semantic, and
it is why a ``goto_next`` at a high precedence restores the inner decision that
a lower-precedence rule at the same level would otherwise have taken.

THE THREE FINDINGS, with their polarity families named because inverting one
silently inverts a security verdict:

* :func:`_finding_unreachable` — **family (c), COVERAGE**. ``And(match(r),
  Not(preempt))`` **UNSAT** is the finding (``contradicted hfw_shadow``, no
  witness — there is no packet to show); **sat** is the healthy case.
* :func:`_finding_reopen` — **family (a), PROPOSAL bad-property**. The bad
  property is asserted directly, so **sat** is the finding
  (``contradicted hfw_reopen``) and carries the witness packet.
* :func:`_finding_delta` — **family (b), PAIR/delta**. The negation of the
  desired property is asserted: ``And(eff_with, Not(eff_without))`` **unsat**
  (both ways) is ``grounded`` "no effect"; **sat** is ``contradicted
  hfw_widen`` with the newly-allowed witness.

Any :class:`packet.UnsupportedPacket`, any rule carrying an ``unsupported``
payload key at any level, a solver ``unknown``, or an absent z3 yields
``unverified`` naming the reason. As in the VPC estate check, a rule that cannot
be encoded abstains the WHOLE comparison rather than being dropped — dropping an
outer deny would fabricate a clean bill of health.

UNREADABLE IS NOT EMPTY. Three defaults used to manufacture confidence out of a
record nobody could read, and each is now an abstention naming the policy and
the field:

* an unreadable ``match.layer4`` was FILTERED down to no entries and then
  omitted, which :func:`packet.rule_match` reads as no layer-4 restriction —
  matching every port. Only an ABSENT or positively EMPTY key means that; a
  present-but-unreadable one raises (:func:`_layer4_entries`). Same for every
  other list field (:func:`_strings`);
* a non-bool ``disabled`` was passed through ``bool()``, so the string
  ``"false"`` deleted a live estate DENY from both the preemption set and the
  fold. It now raises, exactly as a non-int ``priority`` already did in
  :func:`_rank`, and :mod:`gcp_grounding.knowledge` rejects it at load;
* the effective-decision fold reported that an N-level order decides every
  packet identically after consuming ZERO rules. :func:`_place` counts what each
  captured policy contributed and abstains when the whole chain contributed
  nothing, and abstains for a captured policy scoped under the chain that
  declares no ``attachments`` instead of ignoring it.

Every one of those raises inside :func:`_place`, which is why the placement call
runs INSIDE :func:`check_hierarchical_order`'s guarding ``try``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from . import hierarchy, packet
from .constraints import _z3_module
from .core.log import get_logger
from .core.report import Verdict
from .knowledge import UNKNOWN, GcpSnapshot
from .packet import UnsupportedPacket

logger = get_logger(__name__)

__all__ = ["DOCUMENT_CHECKS", "check_hierarchical_order", "effective_decision"]

#: The claim kind carrying a proposed hierarchical firewall rule.
_RULE_KIND = "firewall_policy_rule"

#: Verdict kinds this module emits, one per finding family plus the abstention.
_SHADOW = "hfw_shadow"
_REOPEN = "hfw_reopen"
_WIDEN = "hfw_widen"
_EFFECT = "hfw_effect"
_ABSTAIN = "hfw_order"

#: Resource-hierarchy node prefixes a policy name is scoped under.
_NODE_TYPES = ("organizations", "folders", "projects")


# -- reading a record, without inventing what was not there -------------------


def _strings(container: Any, key: str, *, what: str) -> list[str]:
    """The string list at *key*, where ABSENT and positively EMPTY both mean
    "this rule restricts nothing on that dimension".

    A PRESENT value that is not a list of strings means nothing of the sort: it
    was captured and could not be read, so it raises
    :class:`packet.UnsupportedPacket` and the caller records one ``unverified``
    naming the field. Filtering it away is how an honest abstention becomes a
    confident verdict.
    """
    if not isinstance(container, Mapping):
        raise UnsupportedPacket(
            f"{what}: expected an object to read {key!r} from, got "
            f"{type(container).__name__}")
    if key not in container:
        return []
    value = container[key]
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise UnsupportedPacket(
            f"{what}: {key!r} is {type(value).__name__}, not a list of strings")
    out: list[str] = []
    for i, entry in enumerate(value):
        if not isinstance(entry, str):
            raise UnsupportedPacket(
                f"{what}: {key}[{i}] is {type(entry).__name__}, not a string")
        out.append(entry)
    return out


def _match_block(rule: Mapping[str, Any], *, what: str) -> Mapping[str, Any]:
    """A rule's ``match`` block. Absent is an empty block (the rule declares no
    match criteria, which :func:`packet.rule_match` then rejects for an ingress
    rule); a present non-object raises."""
    if "match" not in rule:
        return {}
    value = rule["match"]
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise UnsupportedPacket(
            f"{what}: 'match' is {type(value).__name__}, not an object")
    return value


def _layer4_entries(match: Mapping[str, Any], *, what: str) -> list[dict[str, Any]]:
    """The layer-4 configs of a *match* block; ``[]`` means NO layer-4
    restriction.

    An ABSENT ``layer4`` key and one present holding an EMPTY list both
    legitimately say the rule restricts nothing at layer 4. A present entry the
    encoding cannot read says no such thing —
    :func:`packet.layer4_match` itself raises on it — so dropping it would
    convert an honest abstention into a rule that matches every port, which is
    the measured defect: an outer deny silently widening to everything, or a
    healthy rule reported as shadowed by one.
    """
    if "layer4" not in match:
        return []
    value = match["layer4"]
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise UnsupportedPacket(
            f"{what}: 'match.layer4' is {type(value).__name__}, not a list of "
            f"layer-4 configs")
    entries: list[dict[str, Any]] = []
    for i, entry in enumerate(value):
        if not isinstance(entry, Mapping):
            raise UnsupportedPacket(
                f"{what}: match.layer4[{i}] is {type(entry).__name__}, not a "
                f"layer-4 config object — an unreadable layer-4 match is not "
                f"the same as no layer-4 restriction")
        entries.append(dict(entry))
    return entries


def _rule_records(policy: Any, *, what: str) -> list[Mapping[str, Any]]:
    """The rules a captured hierarchical policy declares.

    An absent key and a present empty list both yield no records — a fact the
    caller COUNTS (see :func:`_place`) rather than folding away silently. A
    present non-list raises.
    """
    if not isinstance(policy, Mapping):
        raise UnsupportedPacket(
            f"{what}: expected a policy object, got {type(policy).__name__}")
    if "rules" not in policy:
        return []
    value = policy["rules"]
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise UnsupportedPacket(
            f"{what}: 'rules' is {type(value).__name__}, not a list of rules")
    return list(value)


# -- rule shaping -------------------------------------------------------------


def _as_vpc_shape(rule: Mapping[str, Any], *, what: str = "the rule") -> dict[str, Any]:
    """A normalized *hierarchical* rule mapped onto the field names
    :func:`packet.rule_match` expects.

    ``match.src_ip_ranges`` / ``match.dest_ip_ranges`` / ``match.layer4`` become
    ``source_ranges`` / ``destination_ranges`` / ``layer4``; ``target_resources``
    and ``target_secure_tags`` both restrict the match exactly the way target
    tags do in the VPC layer, so they share the ``target_tags`` channel (a
    self-link contains ``/`` and a secure tag short name does not, so the two
    can never collide).

    An ABSENT or EMPTY ``layer4`` list is rendered as *no* ``layer4`` key — i.e.
    no layer-4 restriction — rather than as ``[]``, which
    :func:`packet.layer4_match` reads as "matches nothing". A hierarchical rule
    whose match block carries no layer4 config restricts nothing at layer 4;
    reading it as inert would silently drop it from the preemption set, and this
    module never drops a rule. A layer4 list that is PRESENT and unreadable is
    the opposite case and raises — see :func:`_layer4_entries`.

    ``disabled`` must be a real boolean. ``bool("false")`` is ``True``, so
    passing a non-bool through would delete a live estate DENY from both the
    preemption set and the fold; it raises instead, mirroring :func:`_rank`'s
    handling of a non-int priority.
    """
    if not isinstance(rule, Mapping):
        raise UnsupportedPacket(
            f"{what}: expected a rule object, got {type(rule).__name__}")
    match = _match_block(rule, what=what)
    disabled = rule.get("disabled", False)
    if not isinstance(disabled, bool):
        raise UnsupportedPacket(
            f"{what}: 'disabled' is {disabled!r}, not a boolean — a rule whose "
            f"enablement cannot be read is not silently disabled")
    shape: dict[str, Any] = {
        "action": rule.get("action"),
        "priority": rule.get("priority", 1000),
        "direction": str(rule.get("direction", "INGRESS")).upper(),
        "disabled": disabled,
        "source_ranges": _strings(match, "src_ip_ranges", what=what),
        "destination_ranges": _strings(match, "dest_ip_ranges", what=what),
        "target_tags": (_strings(rule, "target_secure_tags", what=what)
                        + _strings(rule, "target_resources", what=what)),
        "target_service_accounts": _strings(rule, "target_service_accounts",
                                            what=what),
    }
    layer4 = _layer4_entries(match, what=what)
    if layer4:
        shape["layer4"] = layer4
    return shape


def _rank(shape: Mapping[str, Any]) -> tuple[int, int]:
    """Precedence rank ``(priority, 0 if deny else 1)`` — lower is
    higher-precedence, mirroring :func:`packet.effective_allow`'s own ordering
    so the hierarchical fold and the VPC fold agree on ties."""
    priority = shape.get("priority")
    if not isinstance(priority, int) or isinstance(priority, bool):
        raise UnsupportedPacket(f"rule priority {priority!r} is not an integer")
    return (priority, 0 if str(shape.get("action", "")).lower() == "deny" else 1)


def _applicable(shapes: Iterable[Mapping[str, Any]], direction: str) -> list[Mapping[str, Any]]:
    """The rules of *shapes* that bear on *direction*: same direction, enabled,
    sorted highest-precedence first."""
    live = [s for s in shapes
            if str(s.get("direction", "INGRESS")).upper() == direction
            and not s.get("disabled", False)]
    return sorted(live, key=_rank)


# -- the effective-decision encoding ------------------------------------------


def effective_decision(z3, v: packet.PacketVars,
                       levels: Sequence[tuple[str, Sequence[Mapping[str, Any]]]],
                       vpc_rules: Sequence[Mapping[str, Any]],
                       direction: str):
    """The z3 term for "this packet is allowed", across the whole hierarchy.

    *levels* is OUTERMOST-FIRST — ``[(node, [normalized hierarchical rule, …]), …]``
    — and *vpc_rules* are the project's VPC firewall rules in the shape
    :mod:`gcp_grounding.packet` already understands. The VPC layer is the
    innermost one and supplies the starting term (GCP's implied rules: deny for
    INGRESS, allow for EGRESS); each hierarchical level then wraps outward, so
    an outer level's match overrides everything inside it.

    Raises :class:`packet.UnsupportedPacket` for a rule the algebra cannot
    encode or an action outside allow/deny/goto_next — the caller abstains for
    the whole comparison rather than dropping it.
    """
    direction = str(direction).upper()
    eff = packet.effective_allow(z3, v, vpc_rules, direction,
                                 default_allow=(direction == "EGRESS"))
    for _node, rules in reversed(list(levels)):
        shapes = _applicable(
            [_as_vpc_shape(r, what=f"a hierarchical rule at {_node}")
             for r in rules], direction)
        if not shapes:
            continue
        e = eff
        for shape in reversed(shapes):  # lowest precedence first
            action = str(shape.get("action", "")).lower()
            if action == "allow":
                outcome = z3.BoolVal(True)
            elif action == "deny":
                outcome = z3.BoolVal(False)
            elif action == "goto_next":
                # The value of the level INSIDE this one — `eff` as it stood
                # before this level's fold began. That is the whole semantic.
                outcome = eff
            else:
                raise UnsupportedPacket(
                    f"rule action {shape.get('action')!r} is not one of "
                    f"allow/deny/goto_next")
            e = z3.If(packet.rule_match(z3, v, shape), outcome, e)
        eff = e
    return eff


# -- placement: every rule that bears on this project, with its level ---------


@dataclass(frozen=True)
class _Placed:
    """One rule located in the evaluation order: *level* 0 is the organization
    and the VPC layer is the innermost level. *rule* is the normalized
    hierarchical rule (``None`` for a VPC rule, which is already in packet
    shape) and *shape* is what :func:`packet.rule_match` consumes."""

    level: int
    node: str
    label: str
    shape: Mapping[str, Any]
    rule: Mapping[str, Any] | None = None

    @property
    def action(self) -> str:
        return str(self.shape.get("action", "")).lower()

    @property
    def priority(self) -> Any:
        return self.shape.get("priority")


def _wins_over(a: _Placed, b: _Placed) -> bool:
    """Whether *a* decides a packet both rules match, before *b* ever runs: a
    strictly outer level wins, and within one level the higher precedence
    (lower priority number, deny before allow at a tie) wins. This is GCP's own
    ordering — the cross-level case the design names, plus the same-level case
    that follows from the identical rule."""
    if a.level != b.level:
        return a.level < b.level
    return _rank(a.shape) < _rank(b.shape)


# -- resolution ---------------------------------------------------------------


def _abstain(claim, reason: str) -> Verdict:
    return Verdict("unverified", _ABSTAIN, claim.value, 0,
                   f"{claim.location}: {reason} — the hierarchical evaluation "
                   f"order was not decided")


def _association_nodes(claims: Sequence[Any]) -> dict[str, list[str]]:
    """Policy name → attachment nodes declared by association resources in this
    same proposal.

    ``hfw_claims`` emits an association as two sibling claims —
    ``<address>.firewall_policy`` and ``<address>.attachment_target`` — so they
    are re-paired by their common resource address. A ``…_rule`` resource also
    emits a ``firewall_policy_ref`` but has no ``attachment_target`` sibling, so
    it drops out of the intersection.
    """
    policies: dict[str, str] = {}
    nodes: dict[str, str] = {}
    for claim in claims:
        location = getattr(claim, "location", "") or ""
        if claim.kind == "firewall_policy_ref" and location.endswith(".firewall_policy"):
            policies[location[: -len(".firewall_policy")]] = claim.value
        elif claim.kind == "hierarchy_node_ref" and location.endswith(".attachment_target"):
            nodes[location[: -len(".attachment_target")]] = claim.value
    out: dict[str, list[str]] = {}
    for address, policy in policies.items():
        node = nodes.get(address)
        if node is not None and node not in out.setdefault(policy, []):
            out[policy].append(node)
    return out


def _project_of(self_link: str) -> str | None:
    """``projects/<p>/global/networks/<n>`` (or any path containing a
    ``projects/<p>`` segment pair) → ``projects/<p>``."""
    if not isinstance(self_link, str):
        return None
    parts = self_link.split("/")
    for i in range(len(parts) - 1):
        if parts[i] == "projects" and parts[i + 1]:
            return f"projects/{parts[i + 1]}"
    return None


def _attachment_nodes(claim, ctx) -> list[str]:
    """Where the proposed rule's owning policy attaches: the association in this
    proposal first (it is the change being made), then the ``attachment_nodes``
    the claim itself carried (a REST policy document's ``associations``), then
    the estate record for an already-existing policy."""
    policy = claim.value
    from_assoc = _association_nodes(ctx.claims).get(policy)
    if from_assoc:
        return list(from_assoc)
    carried = claim.fields().get("attachment_nodes")
    if carried:
        return [n for n in carried if isinstance(n, str)]
    record = ctx.snapshot.hierarchical_firewall_policy(policy)
    if record is not UNKNOWN and record is not None:
        return _strings(record, "attachments",
                        what=f"hierarchical firewall policy {policy!r}")
    return []


def _scope_of(name: Any) -> str | None:
    """The hierarchy node a policy NAME is scoped under —
    ``organizations/1/locations/global/firewallPolicies/fp`` → ``organizations/1``
    — or None when the name carries no such pair."""
    if not isinstance(name, str):
        return None
    parts = name.split("/")
    for i in range(len(parts) - 1):
        if parts[i] in _NODE_TYPES and parts[i + 1]:
            return f"{parts[i]}/{parts[i + 1]}"
    return None


def _unattached_under(snapshot: GcpSnapshot, chain: Sequence[str]) -> str | None:
    """The reason to abstain when a CAPTURED policy scoped under a node on the
    evaluation path declares no ``attachments``, or None.

    Such a policy is an input about this project's evaluation order that could
    not be read. Ignoring it is how a whole level silently disappears from the
    fold and the remaining levels are then reported as deciding every packet.
    """
    table = snapshot.hierarchical_firewall_policies or {}
    orphans = []
    for name in sorted(table):
        scope = _scope_of(name)
        if scope is None or scope not in chain:
            continue
        if not _strings(table[name], "attachments",
                        what=f"hierarchical firewall policy {name!r}"):
            orphans.append(name)
    if not orphans:
        return None
    return (f"the captured hierarchical firewall policies {', '.join(orphans)} "
            f"are scoped under a node on the evaluation path "
            f"({' > '.join(chain)}) but declare no 'attachments', so the level "
            f"they decide at could not be read")


def _nothing_folded(chain: Sequence[str], contributed: Mapping[str, int]) -> str:
    """The reason to abstain when the fold would consume no rule at all: the
    N-level order cannot be said to decide anything when it read rules from no
    level, so the policies that contributed nothing are named."""
    where = f"{len(chain)} levels ({' > '.join(chain)})"
    if contributed:
        return (f"no hierarchical firewall rule was read from any of the "
                f"{where} — the captured policies "
                f"{', '.join(sorted(contributed))} declare no 'rules', so the "
                f"effective decision would rest on rules from no level at all")
    return (f"no captured hierarchical firewall policy attaches to any of the "
            f"{where}, so the effective decision would rest on rules from no "
            f"level at all")


def _project_under_evaluation(rule: Mapping[str, Any], node: str,
                              snapshot: GcpSnapshot) -> tuple[str | None, str]:
    """→ (project, reason-if-None). From the rule's ``target_resources`` when
    they name networks, otherwise from the attachment *node*."""
    named = _strings(rule, "target_resources", what="the proposed rule")
    targets = {p for p in (_project_of(t) for t in named) if p is not None}
    if len(targets) == 1:
        return targets.pop(), ""
    if len(targets) > 1:
        return None, (f"the rule's target_resources span {len(targets)} projects "
                      f"({', '.join(sorted(targets))}), so no single evaluation "
                      f"order applies")
    if node.startswith("projects/"):
        return node, ""
    below = hierarchy.descendants(snapshot, node)
    if below is UNKNOWN:
        return None, "the snapshot did not capture resource_hierarchy"
    projects = sorted(n for n in below if n.startswith("projects/"))
    if len(projects) == 1:
        return projects[0], ""
    if not projects:
        return None, (f"the captured hierarchy holds no project below the "
                      f"attachment node {node}")
    return None, (f"{len(projects)} projects sit below the attachment node "
                  f"{node} ({', '.join(projects)}), so no single evaluation "
                  f"order applies")


def _vpc_rules(snapshot: GcpSnapshot, project: str,
               rule: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """The project's VPC firewall rules — restricted to the networks the rule's
    ``target_resources`` name, when it names any. Caller has already established
    that ``firewall_rules`` was captured."""
    table = snapshot.firewall_rules or {}
    named = _strings(rule, "target_resources", what="the proposed rule")
    targets = {t for t in named if _project_of(t) is not None}
    out = []
    for name in sorted(table):
        record = table[name]
        network = record.get("network")
        if _project_of(network) != project:
            continue
        if targets and network not in targets:
            continue
        out.append(record)
    return out


def _place(claim, ctx, proposals: Sequence[Any]) -> tuple[Any, Any]:
    """→ (resolution, abstention verdict). Exactly one is not None.

    A resolution is ``(project, chain, placed, proposed, vpc_rules, direction)``:
    the outermost-first hierarchy *chain*, every rule that bears on the project
    as a :class:`_Placed` (the estate's levels plus this proposal's rules), the
    :class:`_Placed` entries this proposal contributes, the VPC layer, and the
    proposed rule's direction.
    """
    snapshot = ctx.snapshot
    rule = claim.fields().get("rule")
    if not isinstance(rule, Mapping):
        return None, _abstain(claim, "the claim carries no normalized rule")

    nodes = _attachment_nodes(claim, ctx)
    if not nodes:
        return None, _abstain(claim, f"the owning policy {claim.value!r} has no "
                                     f"resolvable attachment node")
    if len(nodes) > 1:
        return None, _abstain(claim, f"the owning policy {claim.value!r} attaches at "
                                     f"{len(nodes)} nodes ({', '.join(sorted(nodes))})")
    node = nodes[0]
    if snapshot.resource_hierarchy is None:
        return None, _abstain(claim, "the snapshot did not capture resource_hierarchy")
    if snapshot.hierarchy_node(node) is None:
        return None, _abstain(claim, f"the attachment node {node} is absent from the "
                                     f"captured resource hierarchy")
    if snapshot.hierarchical_firewall_policies is None:
        return None, _abstain(claim, "the snapshot did not capture "
                                     "hierarchical_firewall_policies")
    if snapshot.firewall_rules is None:
        return None, _abstain(claim, "the snapshot did not capture firewall_rules, so "
                                     "the VPC layer under the hierarchy is unknown")

    project, why = _project_under_evaluation(rule, node, snapshot)
    if project is None:
        return None, _abstain(claim, why)
    chain = hierarchy.ancestry_chain(snapshot, project)
    if chain is UNKNOWN:
        return None, _abstain(claim, "the snapshot did not capture resource_hierarchy")
    if node not in chain:
        return None, _abstain(claim, f"the attachment node {node} is not on the "
                                     f"evaluation path of {project} "
                                     f"({' > '.join(chain)})")

    direction = str(rule.get("direction", "INGRESS")).upper()
    orphaned = _unattached_under(snapshot, chain)
    if orphaned is not None:
        return None, _abstain(claim, orphaned)

    placed: list[_Placed] = []
    # captured policy -> how many rules it actually contributed to the fold.
    contributed: dict[str, int] = {}
    for level, name in enumerate(chain):
        attached = snapshot.firewall_policies_attached_to(name)
        if attached is UNKNOWN:  # pragma: no cover - guarded above
            return None, _abstain(claim, "the snapshot did not capture "
                                         "hierarchical_firewall_policies")
        for policy in attached:
            policy_name = _policy_key(snapshot, policy)
            what = f"hierarchical firewall policy {policy_name!r}"
            records = _rule_records(policy, what=what)
            contributed[policy_name] = contributed.get(policy_name, 0) + len(records)
            for i, estate_rule in enumerate(records):
                placed.append(_Placed(
                    level=level, node=name,
                    label=f"{policy_name} rule[{i}] priority "
                          f"{estate_rule.get('priority')}",
                    shape=_as_vpc_shape(estate_rule, what=what), rule=estate_rule))

    # The fold consumed nothing from a chain that claims more than one level:
    # "the N-level order decides every packet identically" would be a statement
    # about rules nobody read. Name what contributed nothing and abstain.
    if len(chain) > 1 and not sum(contributed.values()):
        return None, _abstain(claim, _nothing_folded(chain, contributed))

    vpc = _vpc_rules(snapshot, project, rule)
    vpc_level = len(chain)
    for record in vpc:
        placed.append(_Placed(level=vpc_level, node=project,
                              label=_vpc_rule_name(snapshot, record),
                              shape=record))

    level_of_node = chain.index(node)
    mine: _Placed | None = None
    for other in proposals:
        other_rule = other.fields().get("rule")
        if not isinstance(other_rule, Mapping):
            continue
        if other is not claim and _attachment_nodes(other, ctx) != nodes:
            continue  # a rule for a different policy/level in the same document
        entry = _Placed(level=level_of_node, node=node,
                        label=f"{other.value} ({other.location})",
                        shape=_as_vpc_shape(
                            other_rule,
                            what=f"the proposed rule {other.value!r} "
                                 f"({other.location})"),
                        rule=other_rule)
        placed.append(entry)
        if other is claim:
            mine = entry
    if mine is None:  # pragma: no cover - claim is always one of `proposals`
        return None, _abstain(claim, "the proposed rule could not be placed in the "
                                     "evaluation order")
    return (project, chain, placed, mine, vpc, direction), None


def _policy_key(snapshot: GcpSnapshot, record: Mapping[str, Any]) -> str:
    """The snapshot key of an attached-policy *record* (identity lookup — the
    record came out of the table)."""
    for key, stored in (snapshot.hierarchical_firewall_policies or {}).items():
        if stored is record:
            return key
    return "<policy>"  # pragma: no cover - record came from the table


def _vpc_rule_name(snapshot: GcpSnapshot, record: Mapping[str, Any]) -> str:
    for key, stored in (snapshot.firewall_rules or {}).items():
        if stored is record:
            return key
    return "<vpc rule>"  # pragma: no cover - record came from the table


# -- the findings -------------------------------------------------------------


def _solve(z3, v, *assertions):
    """→ (result, model). Adds the universe axioms so a witness is realistic
    (an instance runs as exactly one service account)."""
    s = z3.Solver()
    for axiom in packet.universe_axioms(z3, v):
        s.add(axiom)
    for assertion in assertions:
        s.add(assertion)
    result = s.check()
    return result, (s.model() if result == z3.sat else None)


def _render(witness: Mapping[str, Any]) -> str:
    text = (f"src={witness['src']} dst={witness['dst']} "
            f"proto={witness['protocol']} port={witness['port']}")
    if witness.get("tags"):
        text += f" tags={','.join(witness['tags'])}"
    if witness.get("service_accounts"):
        text += f" service_accounts={','.join(witness['service_accounts'])}"
    return text


def _finding_unreachable(z3, v, claim, mine: _Placed,
                         placed: Sequence[_Placed]) -> list[Verdict]:
    """FINDING A — unreachable across levels. **Family (c), COVERAGE**: UNSAT is
    the finding and there is no witness on the finding branch; sat is healthy.

    ``preempt`` is the Or of ``rule_match`` over every rule at a strictly outer
    level plus every strictly-higher-precedence rule at this one, restricted to
    non-``goto_next`` actions (a ``goto_next`` decides nothing — it delegates).
    """
    preempting = [p for p in placed
                  if p is not mine and p.action != "goto_next"
                  and str(p.shape.get("direction", "INGRESS")).upper()
                  == str(mine.shape.get("direction", "INGRESS")).upper()
                  and not p.shape.get("disabled", False)
                  and _wins_over(p, mine)]
    if not preempting:
        return []
    preempt = z3.Or([packet.rule_match(z3, v, p.shape) for p in preempting])
    result, _ = _solve(z3, v, packet.rule_match(z3, v, mine.shape), z3.Not(preempt))
    if result == z3.sat:
        return []
    if result != z3.unsat:
        return [_abstain(claim, f"solver returned {result} deciding reachability")]
    nodes = sorted({p.node for p in preempting})
    return [Verdict("contradicted", _SHADOW, claim.value, 0,
                    f"{claim.location}: unreachable — an ancestor policy at "
                    f"{', '.join(nodes)} already decides every packet this rule "
                    f"matches (priority {mine.priority} at {mine.node} never runs)")]


def _finding_reopen(z3, v, claim, mine: _Placed,
                    placed: Sequence[_Placed]) -> list[Verdict]:
    """FINDING B — cross-level re-opening. **Family (a), PROPOSAL bad-property**:
    the bad property is asserted directly, so **sat** is the finding and carries
    the witness packet.

    When the proposal is an ``allow`` that wins over an existing ``deny`` — an
    outer level, or a higher precedence at the same level — it re-opens what the
    deny closed. Only a *public* peer makes that a finding, so the packet is
    additionally constrained to a public source (INGRESS) or destination
    (EGRESS).
    """
    if mine.action != "allow":
        return []
    direction = str(mine.shape.get("direction", "INGRESS")).upper()
    peer = v.dst if direction == "EGRESS" else v.src
    verdicts: list[Verdict] = []
    for d in placed:
        if d is mine or d.action != "deny":
            continue
        if str(d.shape.get("direction", "INGRESS")).upper() != direction:
            continue
        if d.shape.get("disabled", False) or not _wins_over(mine, d):
            continue
        result, model = _solve(z3, v,
                               packet.rule_match(z3, v, mine.shape),
                               packet.rule_match(z3, v, d.shape),
                               packet.is_public(z3, peer))
        if result == z3.unsat:
            continue
        if result != z3.sat:
            verdicts.append(_abstain(claim, f"solver returned {result} comparing "
                                            f"against {d.label}"))
            continue
        witness = _render(packet.witness_packet(z3, model, v))
        verdicts.append(Verdict(
            "contradicted", _REOPEN, claim.value, 0,
            f"{claim.location}: re-opens traffic {d.label} denies — the proposed "
            f"allow at {mine.node} priority {mine.priority} wins over the deny at "
            f"{d.node} priority {d.priority}; witness packet {witness}"))
    return verdicts


def _finding_delta(z3, v, claim, mine: _Placed, chain, placed: Sequence[_Placed],
                   vpc_rules, direction: str, project: str) -> list[Verdict]:
    """FINDING C — effective-decision delta. **Family (b), PAIR/delta**: the
    negation of the desired property is asserted, so unsat (both ways) is
    ``grounded`` and sat is ``contradicted hfw_widen`` with the newly-allowed
    witness. This is the honest generalisation of the new⊆old pair check to a
    whole hierarchy.
    """
    def levels(exclude):
        return [(name, [p.rule for p in placed
                        if p.level == i and p.rule is not None and p is not exclude])
                for i, name in enumerate(chain)]

    eff_with = effective_decision(z3, v, levels(None), vpc_rules, direction)
    eff_without = effective_decision(z3, v, levels(mine), vpc_rules, direction)

    wider, model = _solve(z3, v, eff_with, z3.Not(eff_without))
    if wider == z3.sat:
        witness = _render(packet.witness_packet(z3, model, v))
        return [Verdict("contradicted", _WIDEN, claim.value, 0,
                        f"{claim.location}: widens the effective decision at "
                        f"{project} — this packet is allowed with the rule and "
                        f"denied without it: {witness}")]
    if wider != z3.unsat:
        return [_abstain(claim, f"solver returned {wider} comparing the effective "
                                f"decision with and without the rule")]
    narrower, _ = _solve(z3, v, eff_without, z3.Not(eff_with))
    if narrower == z3.unsat:
        return [Verdict("grounded", _EFFECT, claim.value, 0,
                        f"{claim.location}: no effect on the effective decision at "
                        f"{project} — the {len(chain)}-level order "
                        f"({' > '.join(chain)}) decides every packet identically "
                        f"with and without this rule")]
    if narrower == z3.sat:
        return [Verdict("grounded", _EFFECT, claim.value, 0,
                        f"{claim.location}: narrows the effective decision at "
                        f"{project} — the rule denies traffic that was allowed "
                        f"without it")]
    return [_abstain(claim, f"solver returned {narrower} comparing the effective "
                            f"decision without and with the rule")]


# -- the document check -------------------------------------------------------


def check_hierarchical_order(ctx) -> list[Verdict]:
    """Ground every proposed hierarchical firewall rule against the evaluation
    order its project actually has.

    Returns no verdicts at all for a document that proposes no hierarchical
    firewall rule — the registry runs this on every document.
    """
    proposals = [c for c in ctx.claims if c.kind == _RULE_KIND]
    if not proposals:
        return []

    z3 = _z3_module(ctx.solver)
    if z3 is None:
        backend = getattr(ctx.solver, "backend", "unknown")
        logger.debug("hierarchical order check degraded to unverified: backend=%s "
                     "has no z3", backend)
        return [_abstain(c, f"z3 is not available (solver backend {backend!r})")
                for c in proposals]

    # One unencodable rule abstains the WHOLE comparison: dropping it would
    # fabricate either a clean bill of health or a widening that is not there.
    blocked = [c for c in proposals if c.fields().get("unsupported")]
    if blocked:
        reasons = "; ".join(sorted(f"{c.location}: {c.fields()['unsupported']}"
                                   for c in blocked))
        return [_abstain(c, f"a proposed rule cannot be encoded ({reasons})")
                for c in proposals]

    verdicts: list[Verdict] = []
    for claim in proposals:
        try:
            # INSIDE the guard: placement is where an unreadable record is first
            # touched (`_as_vpc_shape` over every estate rule on the chain), so
            # running it outside would let an UnsupportedPacket escape the one
            # funnel that turns it into an honest `unverified`.
            resolved, abstention = _place(claim, ctx, proposals)
            if abstention is not None:
                verdicts.append(abstention)
                continue
            project, chain, placed, mine, vpc_rules, direction = resolved
            v = packet.packet_vars(
                z3,
                tags=sorted(ctx.snapshot.network_tags or ()),
                service_accounts=sorted(ctx.snapshot.service_accounts or ()))
            verdicts.extend(_finding_unreachable(z3, v, claim, mine, placed))
            verdicts.extend(_finding_reopen(z3, v, claim, mine, placed))
            verdicts.extend(_finding_delta(z3, v, claim, mine, chain, placed,
                                           vpc_rules, direction, project))
        except UnsupportedPacket as exc:
            logger.debug("hierarchical order check abstained: %s", exc)
            verdicts.append(_abstain(claim, f"a rule at some level cannot be "
                                            f"encoded ({exc})"))
    return verdicts


#: The registry seam — a whole-document check, not one hanging off a claim.
DOCUMENT_CHECKS = (check_hierarchical_order,)
