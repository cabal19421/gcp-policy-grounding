"""VPC firewall rules, hierarchical firewall policies and Cloud Armor security
policies, mapped to ``sx-kb-estate-tables`` RECORDS.

This module emits estate RECORDS and nothing else. There is no second,
REST-shaped document form for these three domains: the estate record schema in
:mod:`gcp_grounding.knowledge` IS the canonical shape, it is strictly validated
at construction, and the per-target document a pair check wants is a projection
of the record rather than a parallel encoding of the same rule. Two encodings of
one firewall rule is two places for it to be wrong, and the one that is wrong is
whichever one nobody compared.

THE TypeSet ORDER WARNING
-------------------------

``allow``, ``deny`` and the six range, tag and service-account lists of
``google_compute_firewall`` are terraform **TypeSets**. A TypeSet's JSON array
order is HASH-DETERMINED: the same configuration re-read after an apply can
serialise the same members in a different order, and two captures of one
unchanged rule would then differ in every list. So :func:`map_firewall` SORTS —
``layer4`` by protocol then ports, and the six lists by their own order
(:func:`_range_order` orders a range list by the address it starts at, which is
the only order in which ``35.191.0.0/16`` precedes ``130.211.0.0/22``) — which
makes the same rule captured twice byte-identical.

The consequence, stated so nobody builds on the wrong thing: a POSITIONAL anchor
such as ``allow[0]`` or ``source_ranges[2]`` is meaningful only WITHIN one file,
as a path to attribute an abstention to. It is never an identity, it must never
be stored in a record, and it must never be compared across two artifacts.

The lists this module does NOT sort are just as deliberate. Firewall-policy and
Cloud Armor rule order is SEMANTIC — a policy is evaluated in priority order and
a rule moved is a policy changed — so those are left in the order the artifact
gave them, and :mod:`gcp_grounding.tfsource.merge` puts fragments in priority
then address order. Sorting them here would destroy the one property that domain
is about.

WHAT IS ITERATED, AND WHY IT IS NOT THE FIRST ONE
-------------------------------------------------

EVERY ``allow`` and ``deny`` block is iterated, and every member of every list
is. Taking only the first block silently SHRINKS the rule — a rule that opens
``tcp:80`` and ``tcp:443`` would be captured as opening ``tcp:80`` alone — which
is the same class of failure as a partially parsed CIDR list, and it is why
:func:`gcp_grounding.tfsource.normalize.cidrs` and
:func:`~gcp_grounding.tfsource.normalize.ports` are all-or-nothing.

THE TWO REFUSALS
----------------

**BOTH-OR-NEITHER.** A ``google_compute_firewall`` carrying both an ``allow``
and a ``deny`` block, or neither, yields an :class:`~gcp_grounding.facts.Unresolved`
action rather than a guess. Guessing here inverts the rule's meaning, and an
inverted deny reads as traffic that is blocked when it is not.

**THE FOURTH ACTION.** ``apply_security_profile_group`` — and any
firewall-policy action outside :data:`FIREWALL_POLICY_ACTIONS` — becomes an
:class:`~gcp_grounding.facts.Unresolved` and is NEVER coerced to ``goto_next``.
Coercing an action this mapper does not model into the pass-through action would
turn a filtering rule into a rule that filters nothing, in every downstream
shadowing and packet-algebra computation that reads the policy.

FRAGMENTS, AND WHO JOINS THEM
-----------------------------

``google_compute_firewall_policy_rule``,
``google_compute_firewall_policy_association`` and
``google_compute_security_policy_rule`` each emit a FRAGMENT fact keyed onto the
PARENT policy's canonical key, computed independently through
:meth:`~gcp_grounding.tfsource.mapping.MapContext.key`. This module does not
hand-join them: :mod:`gcp_grounding.tfsource.merge` assembles fragments in
priority then address order, and a mapper that joined them itself would be a
second assembler that only sees one artifact at a time.

THE CLOUD ARMOR STANDALONE RULE IS NOT OPTIONAL. ``google_compute_security_policy_rule``
is the normal provider spelling for a policy of any size, so a policy whose
rules are authored as separate resources would otherwise capture with an empty
or truncated rule list. Cloud Armor rule order is SEMANTIC: a missing priority-1
allow reads as a policy that denies, which is a confident wrong answer about the
one domain whose entire meaning is the ordering. The ``deny(403)`` action is
kept VERBATIM as one opaque string — the response code is part of the action,
and splitting it would invent two fields the estate does not store.

THE BARE-NETWORK RULE
---------------------

``network = "default"`` is expanded to the canonical
``projects/<p>/global/networks/default`` form ONLY when the project is a
resolved literal — the resource's own ``project`` attribute or the artifact's
context. Otherwise the RAW value is kept and the path is flagged. A project is
never guessed: a network keyed to an assumed project is a confident answer about
a network in somebody else's project. The expansion itself goes through
:meth:`~gcp_grounding.tfsource.mapping.MapContext.key`, so it is the one key
builder in :mod:`gcp_grounding.identity` doing it and not a second one here.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Mapping, Sequence

from .. import facts
from ..core.log import get_logger
from . import mapping, normalize

logger = get_logger(__name__)

__all__ = [
    "DELIBERATELY_UNMAPPED",
    "FIREWALL_POLICY_ACTIONS",
    "FIREWALL_TYPESETS",
    "CLAIMS",
    "map_firewall",
    "map_firewall_policy",
    "map_firewall_policy_rule",
    "map_firewall_policy_association",
    "map_security_policy",
    "map_security_policy_rule",
    "register_all",
]

#: The network resource types this module knowingly does NOT model, one line of
#: reason each. Folded into :data:`gcp_grounding.tfsource.mapping.DELIBERATELY_UNMAPPED`
#: at import time so there stays exactly ONE list the census consults: a type
#: declared here but absent from that list would read as an oversight nobody has
#: considered, which is the opposite of what declaring it means.
DELIBERATELY_UNMAPPED = {
    "google_compute_network_firewall_policy": (
        "a NETWORK firewall policy attaches to a VPC, not to a hierarchy node; "
        "the estate's hierarchical_firewall_policies table enumerates "
        "organization-level policies only, so this has no row to key"),
    "google_compute_network_firewall_policy_rule": (
        "its parent has no row in the hierarchical_firewall_policies table, and "
        "a fragment keyed onto a row that never exists is a rule nobody reads"),
    "google_compute_network_firewall_policy_association": (
        "same absent parent row as the network-policy rule; an attachment to a "
        "policy the estate does not enumerate attaches to nothing"),
    "google_compute_region_security_policy": (
        "the cloud_armor_policies key is projects/<p>/global/securityPolicies/"
        "<name>; a REGIONAL policy is a different collection and keying it there "
        "would answer for a global policy that is not it"),
    "google_compute_network_peering": (
        "peering is reachability, not authorization; nothing in the rule set "
        "reads it, so a captured peering would be a fact no check could use"),
    "google_compute_ssl_policy": (
        "a TLS parameter set decides how a connection is encrypted, never "
        "whether it is allowed; no allow/deny answer reads one"),
}

#: The firewall-policy actions this mapper models. CLOSED on purpose — see THE
#: FOURTH ACTION in the module docstring. ``apply_security_profile_group`` is
#: deliberately absent: this mapper does not model a security profile group, and
#: an action it does not model is an abstention rather than a substitution.
FIREWALL_POLICY_ACTIONS = ("allow", "deny", "goto_next")

_RANGE_FIELDS = ("source_ranges", "destination_ranges")
_TAG_FIELDS = ("source_tags", "target_tags")
_ACCOUNT_FIELDS = ("source_service_accounts", "target_service_accounts")

#: The eight ``google_compute_firewall`` attributes whose JSON array order is
#: hash-determined. Named so the sort in :func:`map_firewall` reads as a stated
#: rule rather than as six incidental ``sorted()`` calls, and derived from the
#: three groups that sort so the list cannot drift away from what sorts.
FIREWALL_TYPESETS = ("allow", "deny", *_RANGE_FIELDS, *_TAG_FIELDS,
                     *_ACCOUNT_FIELDS)

_UNKNOWN_ACTION = (
    "not one of the firewall-policy actions this mapper models; coercing an "
    "action it does not model into the pass-through action would turn a "
    "filtering rule into a rule that filters nothing")

_BOTH_ACTIONS = (
    "a firewall carries exactly one of 'allow' and 'deny'; this one carries "
    "both, and choosing either would state a rule terraform never wrote")

_NEITHER_ACTION = (
    "a firewall carries exactly one of 'allow' and 'deny'; this one carries "
    "neither, so nothing in it says whether it permits or blocks")

_BARE_NETWORK = (
    "a bare network name needs the project it lives in; the raw value is kept "
    "rather than expanded against a project nobody wrote")


# -- shared value guards ------------------------------------------------------


def _literal_text(value: Any, *, path: str, what: str) -> str | facts.Unresolved:
    """One literal string, stripped and otherwise UNCHANGED.

    Deliberately not in :mod:`gcp_grounding.tfsource.normalize`: every function
    there returns a CANONICAL value, and this one canonicalises nothing. It only
    refuses what is not a literal — a marker passes through with the path the
    reader minted it at, a non-string and an interpolated string each become a
    marker — which is exactly what an opaque value such as Cloud Armor's
    ``deny(403)`` needs and all it needs.
    """
    if facts.is_unresolved(value):
        return value
    if not isinstance(value, str):
        return facts.Unresolved("unparsed", path, facts.truncate(
            f"{what} must be a string, got {facts.safe_repr(value)}"))
    if facts.is_interpolated(value):
        return facts.Unresolved("interpolation", path,
                                f"this {what} is a program, not a literal")
    text = value.strip()
    if not text:
        return facts.Unresolved("ambiguous_key", path,
                                f"the {what} is empty; nothing can be named from nothing")
    return text


def _as_list(value: Any) -> Any:
    """A resolved sequence as a plain list; a marker unchanged. Records are
    JSON-shaped, and a marker is not iterable."""
    return value if facts.is_unresolved(value) else list(value)


def _attr(values: Mapping[str, Any], field: str) -> Any:
    """One list-valued attribute, with an explicit ``null`` read as ABSENT.

    A reader that spells a list terraform never wrote as ``null`` means the same
    absence a missing key does, and answering ``unparsed`` to it would turn a
    rule that simply has no destination ranges into a rule this module abstains
    about.
    """
    value = values.get(field)
    return () if value is None else value


def _sequence(value: Any, *, path: str, what: str) -> list[Any] | facts.Unresolved:
    """The entry check every block list starts with. A string is a scalar here,
    never a sequence of characters."""
    if facts.is_unresolved(value):
        return value
    if value is None:
        return []
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        return facts.Unresolved("unparsed", path, facts.truncate(
            f"{what} must be a list of blocks, got {facts.safe_repr(value)}"))
    return list(value)


def _first_block(value: Any, *, path: str, what: str) -> Mapping[str, Any] | facts.Unresolved:
    """The single block of a max-one block list.

    The mapper contract says a repeated block is ALWAYS a list, even when the
    provider allows at most one of it, so a bare mapping here would mean some
    reader normalised differently and this module must not paper over that. An
    ABSENT or empty list is an empty mapping: the block was simply not written,
    which is a fact about the artifact and not an unresolved value.
    """
    blocks = _sequence(value, path=path, what=what)
    if facts.is_unresolved(blocks):
        return blocks
    if not blocks:
        return {}
    first = blocks[0]
    if facts.is_unresolved(first):
        return first
    if not isinstance(first, Mapping):
        return facts.Unresolved("unparsed", path, facts.truncate(
            f"{what} block is not an object ({facts.safe_repr(first)})"))
    return first


def _rollup(record: Mapping[str, Any], *extra: facts.Unresolved | None
            ) -> tuple[facts.Unresolved, ...]:
    """Every marker in ``record``, plus the ones that never landed in it. The
    roll-up is what makes an abstention visible to a caller that never walks the
    record itself."""
    markers = [marker for _path, marker in facts.unresolved_in(record)]
    markers.extend(marker for marker in extra if marker is not None)
    return tuple(markers)


# -- the TypeSet orders -------------------------------------------------------


def _range_order(value: str) -> tuple[int, bytes, int]:
    """Sort key for one range: the address it STARTS at, then how wide it is.

    A range list sorted as TEXT is a nonsense order — ``10.0.0.0/8`` would
    precede ``9.0.0.0/8`` — and it is not the order the estate stores. Ordering
    by the network address is the only total order over a range list in which
    ``35.191.0.0/16`` precedes ``130.211.0.0/22``. :data:`~gcp_grounding.tfsource.normalize.ANY_RANGE`
    has no address and sorts first, because it is the range that contains every
    other one.
    """
    if value == normalize.ANY_RANGE:
        return (0, b"", 0)
    network = ipaddress.ip_network(value, strict=False)
    return (network.version, network.network_address.packed, network.prefixlen)


def _sorted_ranges(value: Any) -> Any:
    """A range list in :func:`_range_order`; a marker unchanged. Every member is
    already validated by :func:`~gcp_grounding.tfsource.normalize.cidrs`, which
    is all-or-nothing, so nothing unparseable can reach the sort."""
    if facts.is_unresolved(value):
        return value
    return sorted(value, key=_range_order)


def _sorted_names(value: Any) -> Any:
    """A tag or service-account list in name order; a marker unchanged."""
    if facts.is_unresolved(value):
        return value
    return sorted(value)


def _layer4_order(block: Mapping[str, Any]) -> tuple[Any, ...]:
    """Sort key for one layer-4 entry: protocol, then ports. A block carrying a
    marker sorts LAST and in a stable place, so a rule that abstains about one
    protocol still captures byte-identically twice."""
    protocol = block.get("protocol")
    ports = block.get("ports")
    unresolved_protocol = facts.is_unresolved(protocol)
    unresolved_ports = facts.is_unresolved(ports)
    return (unresolved_protocol, "" if unresolved_protocol else str(protocol),
            unresolved_ports, () if unresolved_ports else tuple(ports or ()))


# -- shared field readers -----------------------------------------------------


def _direction(value: Any, *, path: str) -> str | facts.Unresolved:
    """``INGRESS`` or ``EGRESS``. An ABSENT direction is ``INGRESS``, which is
    the provider's own documented default and therefore a reading rather than a
    guess; anything outside the closed pair is a marker."""
    if value is None:
        return "INGRESS"
    text = _literal_text(value, path=path, what="direction")
    if facts.is_unresolved(text):
        return text
    folded = text.upper()
    if folded not in ("INGRESS", "EGRESS"):
        return facts.Unresolved("unparsed", path,
                                "a direction is 'INGRESS' or 'EGRESS'")
    return folded


def _policy_action(value: Any, *, path: str) -> str | facts.Unresolved:
    """THE FOURTH ACTION: one of :data:`FIREWALL_POLICY_ACTIONS`, or a marker.

    The case is folded because the vocabulary is CLOSED — the provider spells
    these lowercase and folding a member of a closed vocabulary is a
    canonicalisation. An action outside it is never substituted for one inside
    it; see the module docstring for what that substitution would cost.
    """
    text = _literal_text(value, path=path, what="action")
    if facts.is_unresolved(text):
        return text
    folded = text.lower()
    if folded not in FIREWALL_POLICY_ACTIONS:
        return facts.Unresolved("unparsed", path, _UNKNOWN_ACTION)
    return folded


def _tags(value: Any, *, path: str) -> Any:
    """A network-tag list, every member through
    :func:`~gcp_grounding.tfsource.normalize.network_tag`. ALL-OR-NOTHING for
    the reason ``cidrs`` is: a tag list with one member dropped is a narrower
    rule than the one that was written."""
    members = normalize.string_list(value, path=path)
    if facts.is_unresolved(members):
        return members
    out = []
    for index, member in enumerate(members):
        tag = normalize.network_tag(member, path=f"{path}[{index}]")
        if facts.is_unresolved(tag):
            return tag
        out.append(tag)
    return tuple(out)


def _emails(value: Any, *, path: str) -> Any:
    """A service-account list, every member through
    :func:`~gcp_grounding.tfsource.normalize.service_account_email`, which is
    itself a delegation to the ``service_accounts`` key builder. ALL-OR-NOTHING
    for the same reason as :func:`_tags`."""
    members = normalize.string_list(value, path=path)
    if facts.is_unresolved(members):
        return members
    out = []
    for index, member in enumerate(members):
        email = normalize.service_account_email(member, path=f"{path}[{index}]")
        if facts.is_unresolved(email):
            return email
        out.append(email)
    return tuple(out)


def _secure_tags(value: Any, *, path: str) -> Any:
    """A firewall-policy rule's secure tags as bare names. The provider spells
    each as a ``{"name": …}`` block; a plain string is accepted too, because a
    reader that already flattened it must not read as unparseable."""
    entries = _sequence(value, path=path, what="target_secure_tags")
    if facts.is_unresolved(entries):
        return entries
    out = []
    for index, entry in enumerate(entries):
        if facts.is_unresolved(entry):
            return entry
        raw = entry.get("name") if isinstance(entry, Mapping) else entry
        name = _literal_text(raw, path=f"{path}[{index}].name", what="secure tag")
        if facts.is_unresolved(name):
            return name
        out.append(name)
    return out


def _layer4(blocks: Any, *, path: str, protocol_key: str, sort: bool) -> Any:
    """EVERY protocol/ports block, as the estate's ``{"protocol", "ports"}``.

    ``protocol_key`` is the attribute the domain spells the protocol with —
    ``protocol`` on a VPC firewall, ``ip_protocol`` on a firewall-policy rule —
    and ``sort`` is true only where the blocks came from a TypeSet, because a
    firewall-policy rule's ``layer4_configs`` is an ordered list and reordering
    it would change a document nobody changed.
    """
    entries = _sequence(blocks, path=path, what="layer4")
    if facts.is_unresolved(entries):
        return entries
    out = []
    for index, block in enumerate(entries):
        if facts.is_unresolved(block):
            return block
        if not isinstance(block, Mapping):
            return facts.Unresolved("unparsed", f"{path}[{index}]", facts.truncate(
                f"a layer4 block is not an object ({facts.safe_repr(block)})"))
        raw_ports = block.get("ports")
        out.append({
            "protocol": normalize.protocol(block.get(protocol_key),
                                           path=f"{path}[{index}].{protocol_key}"),
            "ports": _as_list(normalize.ports([] if raw_ports is None else raw_ports,
                                              path=f"{path}[{index}].ports")),
        })
    return sorted(out, key=_layer4_order) if sort else out


# -- the VPC firewall ---------------------------------------------------------


def _filled(value: Any) -> bool:
    """True if this ``allow``/``deny`` attribute carries a block. A marker
    counts as filled: the block IS there, only its contents are unknown."""
    return True if facts.is_unresolved(value) else bool(value)


def _firewall_action(values: Mapping[str, Any], address: str
                     ) -> tuple[str | facts.Unresolved, Any]:
    """BOTH-OR-NEITHER: the rule's action and the blocks it was decided from.

    PRESENCE of the attribute decides, not a non-empty one. The plan-JSON
    encoding spells a block that was never written as an absent key and a block
    list that is empty as ``[]``, and ``allow = []`` is a rule that permits
    NOTHING — a rule this mapper must report as an allow with no reach, never
    one whose action it may guess. Where BOTH keys are present, an empty list on
    one side does not contradict a filled one on the other; where both are
    filled, or both empty, the action is unresolved.
    """
    present = {name: values[name] for name in ("allow", "deny") if name in values}
    if len(present) == 1:
        name, blocks = next(iter(present.items()))
        return name, blocks
    if len(present) == 2:
        filled = {name: _filled(blocks) for name, blocks in present.items()}
        if filled["allow"] != filled["deny"]:
            name = "allow" if filled["allow"] else "deny"
            return name, present[name]
        if filled["allow"]:
            marker = facts.Unresolved("ambiguous_key", f"{address}.action",
                                      _BOTH_ACTIONS)
            # The reach is undecided too: the blocks on both sides are real, and
            # merging them would describe one rule that both permits and blocks.
            return marker, marker
        # Both keys present and both empty: no block was written on either side,
        # which says exactly as little as writing neither key does.
    return facts.Unresolved("ambiguous_key", f"{address}.action", _NEITHER_ACTION), ()


def _network_of(value: Any, project: Any, ctx: mapping.MapContext, *, path: str
                ) -> tuple[Any, facts.Unresolved | None]:
    """THE BARE-NETWORK RULE: the canonical network, and the flag if it is raw.

    The expansion is a ``networks`` KEY BUILD and is therefore delegated to
    :meth:`~gcp_grounding.tfsource.mapping.MapContext.key`; a bare name plus an
    explicit project is exactly the case that builder already handles. When it
    cannot resolve one, the RAW value is kept — a record still has to say which
    network the rule is on — and the marker is returned separately so the fact
    carries the abstention rather than swallowing it.
    """
    text = normalize.strip_self_link(value, path=path)
    if facts.is_unresolved(text):
        return text, None
    canonical = ctx.key("networks", name=text, path=path,
                        project=None if facts.is_unresolved(project) else project)
    if facts.is_unresolved(canonical):
        if "/" in text:
            return text, canonical
        return text, facts.Unresolved(canonical.reason, path, _BARE_NETWORK)
    return canonical, None


def _project_for(values: Mapping[str, Any], ctx: mapping.MapContext, *, path: str) -> Any:
    """WHICH project this resource lives in: its own ``project`` attribute, else
    the artifact's context. Nothing else — the project a bare name is qualified
    with is the project terraform itself would have used, and re-deriving one
    from somewhere else is the guess this module refuses."""
    raw = values.get("project")
    if raw is not None:
        return normalize.project_of(raw, path=path)
    if ctx.project:
        return normalize.project_of(ctx.project, path=path)
    return facts.Unresolved("missing_project", path,
                            "the resource names no project and the artifact's "
                            "context supplies none")


def _side_facts(obj: facts.TfObject, ctx: mapping.MapContext,
                tags: Mapping[str, Any], accounts: Mapping[str, Any]
                ) -> list[facts.Fact]:
    """One ``network_tags`` fact per source and target tag, and one
    ``service_accounts`` fact per service-account list member.

    A rule that names a tag is evidence the tag EXISTS, which is a different
    claim from the rule itself and belongs in a different category. A list that
    could not be resolved contributes no names at all: the marker is already on
    the rule's own fact, and inventing names from a list this module refused to
    read would be the shrink these helpers are all-or-nothing to prevent.
    """
    out: list[facts.Fact] = []
    for category, lists in (("network_tags", tags), ("service_accounts", accounts)):
        for field, members in lists.items():
            if facts.is_unresolved(members):
                continue
            for member in members:
                key = ctx.key(category, name=member, path=f"{obj.address}.{field}")
                if facts.is_unresolved(key):
                    continue
                out.append(facts.Fact(category=category, key=key, source=obj.source,
                                      side=obj.side, origin=obj.artifact,
                                      address=obj.address))
    return out


def map_firewall(obj: facts.TfObject, ctx: mapping.MapContext) -> tuple[facts.Fact, ...]:
    """``google_compute_firewall`` → one ``firewall_rules`` record, plus the
    ``network_tags`` and ``service_accounts`` names it mentions."""
    values = obj.values
    key = ctx.key("firewall_rules", name=values.get("name"),
                  project=values.get("project"), path=f"{obj.address}.name")
    if facts.is_unresolved(key):
        logger.debug("%s has no resolvable firewall_rules key (%s) — no fact rather "
                     "than one keyed to a guess", obj.address, key.reason)
        return ()
    project = _project_for(values, ctx, path=f"{obj.address}.project")
    action, blocks = _firewall_action(values, obj.address)
    network, network_marker = _network_of(values.get("network"), project, ctx,
                                          path=f"{obj.address}.network")
    tags = {field: _tags(_attr(values, field), path=f"{obj.address}.{field}")
            for field in _TAG_FIELDS}
    accounts = {field: _emails(_attr(values, field), path=f"{obj.address}.{field}")
                for field in _ACCOUNT_FIELDS}
    ranges = {field: _sorted_ranges(normalize.cidrs(_attr(values, field),
                                                    path=f"{obj.address}.{field}"))
              for field in _RANGE_FIELDS}
    record = {
        "action": action,
        "destination_ranges": ranges["destination_ranges"],
        "direction": _direction(values.get("direction"), path=f"{obj.address}.direction"),
        "disabled": normalize.bool_or(values.get("disabled", False),
                                      path=f"{obj.address}.disabled"),
        "layer4": _layer4(blocks, path=f"{obj.address}.layer4",
                          protocol_key="protocol", sort=True),
        "network": network,
        "priority": normalize.int_or(values.get("priority", 1000),
                                     path=f"{obj.address}.priority"),
        "source_ranges": ranges["source_ranges"],
        "source_service_accounts": _sorted_names(accounts["source_service_accounts"]),
        "source_tags": _sorted_names(tags["source_tags"]),
        "target_service_accounts": _sorted_names(accounts["target_service_accounts"]),
        "target_tags": _sorted_names(tags["target_tags"]),
    }
    rule = facts.Fact(category="firewall_rules", key=key, record=record,
                      source=obj.source, side=obj.side, origin=obj.artifact,
                      address=obj.address,
                      unresolved=_rollup(record, network_marker))
    return (rule, *_side_facts(obj, ctx, tags, accounts))


# -- the hierarchical firewall policy -----------------------------------------


def _policy_key(values: Mapping[str, Any], ctx: mapping.MapContext, *, path: str) -> Any:
    """The parent policy's canonical key, from a policy resource's own ``name``.

    A configuration that has only a ``short_name`` is REFUSED, and refused with
    the reason that names the actual problem: the estate keys the GENERATED
    policy id, ``short_name`` is a different string for the same policy, and
    accepting both would key one policy to two rows. Passing the part explicitly
    is what turns a vague missing-name abstention into that stated refusal.
    """
    name = values.get("name")
    if isinstance(name, str) and name.strip():
        return ctx.key("hierarchical_firewall_policies", name=name,
                       parent=values.get("parent"), path=path)
    return ctx.key("hierarchical_firewall_policies", name=name,
                   parent=values.get("parent"), path=path,
                   short_name=values.get("short_name"))


def map_firewall_policy(obj: facts.TfObject,
                        ctx: mapping.MapContext) -> tuple[facts.Fact, ...]:
    """``google_compute_firewall_policy`` → the policy's own (empty) record.

    The policy resource speaks for the policy's EXISTENCE and for nothing else:
    its rules and its attachments are separate resources, and this record is the
    base :mod:`gcp_grounding.tfsource.merge` folds their fragments into. Both
    lists are emitted EMPTY rather than omitted, because the estate's own
    constructor stores an absent list and an empty one identically and an
    explicit empty one says which of the two this resource meant.
    """
    key = _policy_key(obj.values, ctx, path=f"{obj.address}.name")
    if facts.is_unresolved(key):
        logger.debug("%s has no resolvable hierarchical_firewall_policies key (%s)",
                     obj.address, key.reason)
        return ()
    record: dict[str, Any] = {"attachments": [], "rules": []}
    return (facts.Fact(category="hierarchical_firewall_policies", key=key,
                       record=record, source=obj.source, side=obj.side,
                       origin=obj.artifact, address=obj.address),)


def _parent_policy_key(obj: facts.TfObject, ctx: mapping.MapContext) -> Any:
    """The key of the policy a rule or an association hangs off, computed from
    the ``firewall_policy`` attribute ALONE. The parent resource does not have
    to be in the same artifact: a fragment that only existed when its parent did
    would silently vanish from a split configuration."""
    return ctx.key("hierarchical_firewall_policies",
                   name=obj.values.get("firewall_policy"),
                   path=f"{obj.address}.firewall_policy")


def map_firewall_policy_rule(obj: facts.TfObject,
                             ctx: mapping.MapContext) -> tuple[facts.Fact, ...]:
    """``google_compute_firewall_policy_rule`` → a ``rules`` FRAGMENT keyed onto
    the parent policy. The rule is NOT sorted into place here; ordering
    fragments is :mod:`gcp_grounding.tfsource.merge`'s job and it does it by
    priority then address."""
    key = _parent_policy_key(obj, ctx)
    if facts.is_unresolved(key):
        logger.debug("%s names no resolvable parent policy (%s)", obj.address, key.reason)
        return ()
    values = obj.values
    match = _first_block(values.get("match"), path=f"{obj.address}.match", what="match")
    if facts.is_unresolved(match):
        matched: Any = match
    else:
        matched = {
            "dest_ip_ranges": _as_list(normalize.cidrs(
                _attr(match, "dest_ip_ranges"),
                path=f"{obj.address}.match.dest_ip_ranges")),
            "layer4": _layer4(_attr(match, "layer4_configs"),
                              path=f"{obj.address}.match.layer4_configs",
                              protocol_key="ip_protocol", sort=False),
            "src_ip_ranges": _as_list(normalize.cidrs(
                _attr(match, "src_ip_ranges"),
                path=f"{obj.address}.match.src_ip_ranges")),
        }
    rule = {
        "action": _policy_action(values.get("action"), path=f"{obj.address}.action"),
        "direction": _direction(values.get("direction"), path=f"{obj.address}.direction"),
        "disabled": normalize.bool_or(values.get("disabled", False),
                                      path=f"{obj.address}.disabled"),
        "match": matched,
        "priority": normalize.int_or(values.get("priority"),
                                     path=f"{obj.address}.priority"),
        "target_resources": _as_list(normalize.string_list(
            _attr(values, "target_resources"),
            path=f"{obj.address}.target_resources")),
        "target_secure_tags": _secure_tags(
            _attr(values, "target_secure_tags"),
            path=f"{obj.address}.target_secure_tags"),
        "target_service_accounts": _as_list(_emails(
            _attr(values, "target_service_accounts"),
            path=f"{obj.address}.target_service_accounts")),
    }
    record = {"rules": [rule]}
    return (facts.Fact(category="hierarchical_firewall_policies", key=key,
                       record=record, fragment="rules", source=obj.source,
                       side=obj.side, origin=obj.artifact, address=obj.address,
                       unresolved=_rollup(record)),)


def map_firewall_policy_association(obj: facts.TfObject,
                                    ctx: mapping.MapContext) -> tuple[facts.Fact, ...]:
    """``google_compute_firewall_policy_association`` → an ``attachments``
    FRAGMENT keyed onto the parent policy. The attachment target is kept as the
    node name terraform wrote; which nodes a policy reaches is the hierarchy's
    question, not this mapper's."""
    key = _parent_policy_key(obj, ctx)
    if facts.is_unresolved(key):
        logger.debug("%s names no resolvable parent policy (%s)", obj.address, key.reason)
        return ()
    target = _literal_text(obj.values.get("attachment_target"),
                           path=f"{obj.address}.attachment_target",
                           what="attachment target")
    record = {"attachments": [target] if not facts.is_unresolved(target) else target}
    return (facts.Fact(category="hierarchical_firewall_policies", key=key,
                       record=record, fragment="attachments", source=obj.source,
                       side=obj.side, origin=obj.artifact, address=obj.address,
                       unresolved=_rollup(record)),)


# -- cloud armor --------------------------------------------------------------


def _armor_rule(values: Mapping[str, Any], *, path: str) -> dict[str, Any]:
    """One Cloud Armor rule, in the estate's stored shape.

    ``action`` is kept VERBATIM: ``deny(403)`` is one opaque string in which the
    response code is part of the action, and splitting it would invent a field
    the estate does not store. ``match`` is flattened to the REST shape the
    estate keeps — the provider nests ``config`` and ``expr`` one block deeper
    than the API does, and the estate stores the API's shape.
    """
    match = _first_block(values.get("match"), path=f"{path}.match", what="match")
    if facts.is_unresolved(match):
        matched: Any = match
    else:
        config = _first_block(match.get("config"), path=f"{path}.match.config",
                              what="config")
        expression = _first_block(match.get("expr"), path=f"{path}.match.expr",
                                  what="expr")
        versioned = match.get("versioned_expr")
        matched = {
            "expr": _armor_expression(expression, path=f"{path}.match.expr"),
            "src_ip_ranges": config if facts.is_unresolved(config) else _as_list(
                normalize.cidrs(_attr(config, "src_ip_ranges"),
                                path=f"{path}.match.config.src_ip_ranges")),
            "versioned_expr": None if versioned is None else _literal_text(
                versioned, path=f"{path}.match.versioned_expr",
                what="versioned expression"),
        }
    return {
        "action": _literal_text(values.get("action"), path=f"{path}.action",
                                what="action"),
        "match": matched,
        "preview": normalize.bool_or(values.get("preview", False),
                                     path=f"{path}.preview"),
        "priority": normalize.int_or(values.get("priority"), path=f"{path}.priority"),
    }


def _armor_expression(block: Any, *, path: str) -> Any:
    """A rule's CEL expression, or ``None`` when no ``expr`` block was written.
    ``None`` is the estate's own spelling for that, and it is not an abstention:
    a rule matching on ranges genuinely has no expression."""
    if facts.is_unresolved(block):
        return block
    if not block:
        return None
    return _literal_text(block.get("expression"), path=f"{path}.expression",
                         what="expression")


def _armor_rules(blocks: Any, *, path: str) -> Any:
    """EVERY inline rule block, or one marker for the whole list. A block that
    is not an object fails the WHOLE list rather than being skipped: rule order
    is the policy, so a rule quietly dropped out of the middle of one is a
    different policy that still looks complete."""
    if facts.is_unresolved(blocks):
        return blocks
    out = []
    for index, block in enumerate(blocks):
        if facts.is_unresolved(block):
            return block
        if not isinstance(block, Mapping):
            return facts.Unresolved("unparsed", f"{path}[{index}]", facts.truncate(
                f"a rule is not an object ({facts.safe_repr(block)}); the WHOLE "
                f"rule list is unresolved rather than silently shortened"))
        out.append(_armor_rule(block, path=f"{path}[{index}]"))
    return out


def map_security_policy(obj: facts.TfObject,
                        ctx: mapping.MapContext) -> tuple[facts.Fact, ...]:
    """``google_compute_security_policy`` → a ``cloud_armor_policies`` record
    carrying the policy's INLINE rules, in the order the artifact wrote them.

    They are not sorted: rule order is the whole meaning of a Cloud Armor
    policy, and :mod:`gcp_grounding.tfsource.merge` puts these and the standalone
    fragments into priority order together.
    """
    values = obj.values
    key = ctx.key("cloud_armor_policies", name=values.get("name"),
                  project=values.get("project"), path=f"{obj.address}.name")
    if facts.is_unresolved(key):
        logger.debug("%s has no resolvable cloud_armor_policies key (%s)",
                     obj.address, key.reason)
        return ()
    blocks = _sequence(values.get("rule"), path=f"{obj.address}.rule", what="rule")
    rules = _armor_rules(blocks, path=f"{obj.address}.rule")
    record: dict[str, Any] = {"rules": rules}
    armor_type = values.get("type")
    if armor_type is not None:
        # Emitted only when the artifact carries it: an absent 'type' is a key
        # the estate does not store either, and inventing one would make a
        # policy captured without it differ from the same policy in the estate.
        record["type"] = _literal_text(armor_type, path=f"{obj.address}.type",
                                       what="policy type")
    return (facts.Fact(category="cloud_armor_policies", key=key, record=record,
                       source=obj.source, side=obj.side, origin=obj.artifact,
                       address=obj.address, unresolved=_rollup(record)),)


def map_security_policy_rule(obj: facts.TfObject,
                             ctx: mapping.MapContext) -> tuple[facts.Fact, ...]:
    """``google_compute_security_policy_rule`` → a ``rules`` FRAGMENT keyed onto
    the parent policy.

    NOT OPTIONAL. This is the normal provider spelling for a policy of any size,
    and a policy whose rules are authored as separate resources would otherwise
    capture with an empty or truncated rule list. Because rule order IS the
    policy, a missing priority-1 allow reads as a policy that denies — a
    confident wrong answer about the one domain whose entire meaning is order.
    """
    key = ctx.key("cloud_armor_policies", name=obj.values.get("security_policy"),
                  project=obj.values.get("project"),
                  path=f"{obj.address}.security_policy")
    if facts.is_unresolved(key):
        logger.debug("%s names no resolvable parent policy (%s)", obj.address, key.reason)
        return ()
    record = {"rules": [_armor_rule(obj.values, path=obj.address)]}
    return (facts.Fact(category="cloud_armor_policies", key=key, record=record,
                       fragment="rules", source=obj.source, side=obj.side,
                       origin=obj.artifact, address=obj.address,
                       unresolved=_rollup(record)),)


# -- registration -------------------------------------------------------------

#: Every terraform type this module claims, with the estate category the type's
#: OWN identity lives in.
CLAIMS = (
    ("google_compute_firewall", map_firewall, "firewall_rules",
     "the rule NAME is the identity, never the terraform address"),
    ("google_compute_firewall_policy", map_firewall_policy,
     "hierarchical_firewall_policies",
     "the policy's existence; its rules and attachments are separate resources"),
    ("google_compute_firewall_policy_rule", map_firewall_policy_rule,
     "hierarchical_firewall_policies", "a 'rules' fragment merge orders"),
    ("google_compute_firewall_policy_association", map_firewall_policy_association,
     "hierarchical_firewall_policies", "an 'attachments' fragment merge folds in"),
    ("google_compute_security_policy", map_security_policy, "cloud_armor_policies",
     "the policy and its INLINE rules, in the order written"),
    ("google_compute_security_policy_rule", map_security_policy_rule,
     "cloud_armor_policies",
     "the standalone rule spelling; without it a split policy captures truncated"),
)


def register_all() -> None:
    """Register every type in :data:`CLAIMS`, and fold this module's stated gaps
    into the ONE list the census consults.

    Called at import time, which is how :mod:`gcp_grounding.tfsource.mapping`
    resolves a domain mapper. It is EXPORTED and idempotent because that
    registration is process-global: a caller that emptied the registry with
    :func:`~gcp_grounding.tfsource.mapping.reset_cache` cannot get these back by
    importing an already-imported module, and silently having no firewall mapper
    is exactly the missing coverage this design refuses to leave invisible.
    """
    for resource_type, reason in DELIBERATELY_UNMAPPED.items():
        mapping.DELIBERATELY_UNMAPPED.setdefault(resource_type, reason)
    registered = mapping.mappers()
    for resource_type, mapper, category, note in CLAIMS:
        if resource_type in registered:
            continue
        mapping.register(resource_type, mapper, category=category,
                         module=__name__, note=note)


register_all()
