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
would let the two drift.

The same discipline gives the two sec_rules BASE collections their terraform
arm. ``iam_bindings`` and ``org_policy_rules`` keep their untouched sec_rules
built-ins for every REST kind; over a terraform plan, :func:`register` installs
extractors that rebuild the rows from the claims ``tf_claims`` already emits —
role/member/cel claims anchored at ``<block>.role`` / ``<block>.members[i]``,
constraint/constraint_value claims anchored inside ``<block>.spec`` — with the
terraform block address threaded onto every row under
:data:`gcp_grounding.sec_rules.WITNESS_ADDRESS_FIELD`, exactly as
``proposed_firewall_rules`` does. The one value the claims attest but do not
carry (an org-policy rule's ``enforce`` boolean) is fetched from the plan at the
claim's OWN anchor through ``tf_claims``' own walker and block helpers, so no
second parser exists to drift. Extraction is conservative: a ``count`` /
``for_each`` block, a binding whose role claim is missing, an ambiguous or
unreadable rule, or any location outside the claim grammar yields NO row and one
:class:`_Undecidable` abstention naming the block — never a fabricated row,
because a fabricated row can fabricate a refutation.

The estate-tier extractors read
``ctx.snapshot.firewall_rules`` / ``ctx.snapshot.hierarchical_firewall_policies``
and honour the captured bit by comparing with ``is`` — never truth-testing,
because :data:`gcp_grounding.knowledge.UNKNOWN` refuses ``bool``. Records are
sorted by their scalar fields for determinism, mirroring the sorted-pairs
convention of ``constraints.check_policy_subset`` (constraints.py:442-446).
"""

from __future__ import annotations

import importlib
import re
from typing import Any, Callable, Iterable, Mapping

from . import evidence, sec_ast, sec_encode, sec_rules, tf_claims
from .claims import _values_shape
from .core.log import get_logger
from .knowledge import UNKNOWN
from .sec_ast import CollectionSpec

logger = get_logger(__name__)

__all__ = [
    "register", "reset", "registered",
    "COLLECTION_SPECS", "DOMAIN_COLLECTIONS", "DOMAIN_MODULES",
    "BASE_COLLECTION_OVERRIDES",
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

#: Domain → its collections, in ``sec_artifact.DOMAINS``-compatible order. The
#: ``iam`` entry is NOT the base ``iam_bindings`` collection (that one is
#: ``sec_ast``'s own and its REST extractor a ``sec_rules`` built-in): it is the
#: custom-role permission collection, which has no REST arm at all, plus the two
#: deny-policy collections built from :mod:`gcp_grounding.iam_deny`'s claims.
DOMAIN_COLLECTIONS: dict[str, tuple[str, ...]] = {
    "iam": ("proposed_role_permissions", "deny_rules", "deny_rule_exceptions"),
    "vpc_firewall": ("proposed_firewall_rules", "firewall_rules"),
    "cloud_armor": ("armor_rules",),
    "org_policy": ("effective_org_policy_bool", "effective_org_policy_values"),
    "hier_firewall": ("hier_firewall_rules",),
    "vpc_sc": ("perimeter_resources", "perimeter_restricted_services"),
}

#: The claims module each domain's proposal-tier extractor is built from. Absent
#: from a partial checkout is not an error — see :func:`_domain_module`. The
#: ``iam`` entry powers only the deny collections; ``proposed_role_permissions``
#: is claim-built from ``tf_claims``, a hard import of this module already.
DOMAIN_MODULES: dict[str, str] = {
    "iam": "iam_deny",
    "vpc_firewall": "fw_claims",
    "cloud_armor": "armor_claims",
    "org_policy": "org_effective",
    "vpc_sc": "vpcsc_claims",
}

#: The two sec_rules base collections whose registered extractors
#: :func:`register` OVERRIDES with a terraform arm. Their specs stay
#: ``sec_ast``'s own four-field originals and every non-terraform document kind
#: still reaches the untouched sec_rules built-in, so REST behaviour is
#: byte-identical; only a ``tf_plan`` document gains evaluation. Registered
#: unconditionally: everything the arm needs (``sec_rules``, ``tf_claims``,
#: ``claims``) is a hard import of this module already.
BASE_COLLECTION_OVERRIDES: tuple[str, ...] = ("iam_bindings", "org_policy_rules")

#: One row per permission a proposal's ``google_project_iam_custom_role`` block
#: includes: the role's full name (``projects/<project>/roles/<role_id>``) and
#: the permission, plus the block address under
#: :data:`gcp_grounding.sec_rules.WITNESS_ADDRESS_FIELD` (not a declared field,
#: so no promise can quantify over it — its one consumer is the witness message).
_ROLE_PERMISSION_FIELDS = {"role": "Str", "permission": "Str"}

#: One row per EFFECTIVE (rule, denied-principal, denied-permission)
#: combination of an IAM v2 deny policy, permission exceptions SUBTRACTED
#: before rows are minted: GCP applies ``deniedPermissions \
#: exceptionPermissions`` per rule, both sides exact names in one namespace, so
#: subtraction at extraction time loses nothing and every surviving row states
#: a true fact — a row minted for an excepted permission would state a
#: falsehood a ``forall`` promise could be refuted by. ``permission`` carries
#: the NORMALIZED short form (``iam.serviceAccounts.getAccessToken``), the
#: sibling-claim convention ``iam_checks.check_denied_permission`` already
#: relies on, so the promise vocabulary grounds against ``snapshot.permissions``.
#: ``denied_principal`` keeps the RAW v2 spelling — principal exceptions are
#: NOT a string set difference (``exceptionPrincipals`` may carve members out
#: of a ``principalSet://`` the strings cannot subtract), so the rows keep the
#: raw denied principal and carry ``has_principal_exceptions`` alongside; WHO
#: is exempted is the ``deny_rule_exceptions`` collection's business, joinable
#: on (policy, rule_index). A dimension with no honest values omits its key
#: (module docstring), and BOTH condition keys are omitted when the
#: ``denialCondition`` block is present but unreadable — spelling that as
#: ``has_condition=False`` would satisfy "denies … unconditionally" over a
#: condition nobody read.
_DENY_RULE_FIELDS = {
    "policy": "Str",
    "rule_index": "Int",
    "denied_principal": "Str",
    "permission": "Str",
    "has_principal_exceptions": "Bool",
    "has_condition": "Bool",
    "condition": "Str",
}

#: One row per (rule, exception principal) — the enumerated principal
#: carve-outs of the same deny rules, RAW v2 spelling, for promises about WHO
#: is exempted ("no deny rule exempts the public").
_DENY_EXCEPTION_FIELDS = {
    "policy": "Str",
    "rule_index": "Int",
    "exception_principal": "Str",
}

#: The two EFFECTIVE org-policy collections :mod:`gcp_grounding.org_effective`
#: computes — the hierarchy fold of ``snapshot.org_policies`` +
#: ``snapshot.resource_hierarchy`` + the proposal's own set-policy, split by
#: the constraint's declared ``value_type`` so no row is ever ragged: one
#: list-typed row in a shared universe would otherwise knock out every
#: ``enforce``-mentioning promise through sec_encode's missing-from-the-record
#: refusal, and filler scalars could fabricate a refutation. ``constraint`` is
#: spelled WITHOUT the ``constraints/`` prefix, matching both
#: ``org_policy_rules`` arms, so one promise phrase reads across the
#: per-document and the effective collections. ``value`` is ``""`` on an
#: all-values flag row (the documented honest empty ``Str``), and
#: ``all_values`` is always a real boolean. ESTATE tier: the records are facts
#: about the estate as amended by the document under review, and estate tier
#: is what routes them through ``CompiledRule._incomplete_estate``.
_EFFECTIVE_BOOL_FIELDS = {
    "node": "Str",         # the hierarchy node the state is computed AT
    "constraint": "Str",   # canonical id, "constraints/" prefix STRIPPED
    "enforce": "Bool",     # the folded effective enforcement
}
_EFFECTIVE_VALUES_FIELDS = {
    "node": "Str",
    "constraint": "Str",
    "polarity": "Str",     # "allow" | "deny"
    "value": "Str",        # the enumerated value; "" on an all_values row
    "all_values": "Bool",  # True on the allValues flag row, else False
}

#: Every spec :func:`register` installs, in :data:`DOMAIN_COLLECTIONS` order.
COLLECTION_SPECS: tuple[CollectionSpec, ...] = (
    CollectionSpec("proposed_role_permissions", "proposal",
                   _ROLE_PERMISSION_FIELDS),
    CollectionSpec("deny_rules", "proposal", _DENY_RULE_FIELDS),
    CollectionSpec("deny_rule_exceptions", "proposal", _DENY_EXCEPTION_FIELDS),
    CollectionSpec("proposed_firewall_rules", "proposal", _FIREWALL_FIELDS),
    CollectionSpec("firewall_rules", "estate", _FIREWALL_FIELDS),
    CollectionSpec("armor_rules", "proposal", _ARMOR_FIELDS),
    CollectionSpec("effective_org_policy_bool", "estate",
                   _EFFECTIVE_BOOL_FIELDS),
    CollectionSpec("effective_org_policy_values", "estate",
                   _EFFECTIVE_VALUES_FIELDS),
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

#: How an envelope abstention names the document it could not read. A plan is
#: THE widest arm of the applicability table — it matches every domain — so its
#: reasons have to say WHICH document they are about as well as which key.
_PLAN_WHAT = "the terraform plan under review"


def _plan_envelope(plan) -> None:
    """Refuse a plan whose two resource-bearing sections are BOTH unreadable.

    ``preflight.detect_kind`` labels ANY mapping carrying one of four top-level
    keys a plan without validating its shape, and
    :func:`gcp_grounding.tf_claims.terraform_plan_claims` hands back an EMPTY
    list for any mapping it cannot walk — no exception, no reason. Trusting that
    list is how the empty document, and a plan whose ``resource_changes`` is a
    string and whose ``planned_values`` is an integer, ground every domain
    ``forall`` over zero records.

    So the envelope is validated FIRST: ``planned_values`` must be a Mapping and
    ``resource_changes`` a list, and at least one of the two must be present and
    well formed. A plan carrying only one of them is ordinary terraform output
    and is accepted (``terraform show -json`` of a plan file omits neither by
    accident). Both are read through :mod:`gcp_grounding.evidence` so the
    difference between *unreadable* and *observed empty* reaches the ledger and
    not only the message, and both reasons are quoted so the abstention names
    the malformed key rather than just the plan.
    """
    problems: list[str] = []
    try:
        evidence.scalar(plan, "planned_values", what=_PLAN_WHAT, type=Mapping)
    except evidence.NotEvaluated as exc:
        problems.append(exc.reason)
    try:
        evidence.rows(plan, "resource_changes", what=_PLAN_WHAT)
    except evidence.NotEvaluated as exc:
        problems.append(exc.reason)
    if len(problems) == 2:
        raise _Undecidable(
            f"{_PLAN_WHAT} has neither a readable 'planned_values' mapping nor a "
            f"readable 'resource_changes' list ({'; '.join(problems)}) — the rule "
            "was not evaluated")


def _no_tf_records(label: str) -> _Undecidable:
    """The one abstention for a READABLE plan that carries nothing of *label*'s
    kind: "the plan was understood and mentions no <label>" and "the obligation
    holds over every <label> in the plan" are different facts, and only the
    second one is a pass."""
    return _Undecidable(f"{_PLAN_WHAT} carries no {label} resources — the rule "
                        "was not evaluated over any record")


def _plan_claims(document, kinds: frozenset, label: str) -> tuple:
    """The claims of *kinds* a terraform plan document makes — the ONE tf-plan
    funnel, shared by every proposal-tier extractor with a terraform arm.

    Validates the envelope first (:func:`_plan_envelope`), then filters
    :func:`gcp_grounding.tf_claims.terraform_plan_claims` down to *kinds*. A
    missing document, an unreadable envelope and a readable plan with no
    matching resource each raise :class:`_Undecidable`, which :func:`_guarded`
    turns into the rule's missing_reason."""
    if document is None:
        raise _Undecidable(f"no document under review — the {label} rule was "
                           "not evaluated")
    _plan_envelope(document)
    claims = tuple(c for c in tf_claims.terraform_plan_claims(document)
                   if c.kind in kinds)
    if not claims:
        raise _no_tf_records(label)
    return claims


def _document_claims(ctx, module, claim_kind: str, label: str):
    """The claims of *claim_kind* the domain module makes about ``ctx.document``.

    Returns ``(claims, None)`` or ``((), missing_reason)``. A terraform plan can
    carry any domain's resources, so it goes through
    :func:`gcp_grounding.tf_claims.terraform_plan_claims` (which reaches the same
    domain extractor through the registry) once :func:`_plan_envelope` has said
    the plan was understood; every other document kind is looked up in the
    module's own ``DOCUMENT_EXTRACTORS`` table.

    A READABLE plan that carries no resource of the queried collection is still
    not a positive: it abstains naming the plan and the collection, because "the
    plan was understood and mentions no firewall rule" and "the obligation holds
    over every firewall rule in the plan" are different facts, and only the
    second one is a pass."""
    if ctx.document is None:
        return (), f"no document under review — the {label} rule was not evaluated"
    kind = ctx.document_kind
    if kind == _TF_PLAN:
        return _plan_claims(ctx.document, frozenset({claim_kind}), label), None
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
    proposal and estate VPC firewall collections, which share one field set.

    A rule tuple may carry a THIRD element: the proposing document's own
    locator (a terraform block address), stored on every row of that rule under
    :data:`gcp_grounding.sec_rules.WITNESS_ADDRESS_FIELD`. It is not in
    :data:`_FIREWALL_FIELDS`, so no promise can quantify over it, the encoder
    never reads it and :func:`_sorted` never keys on it — its one consumer is
    the witness message, which uses it to name the block an operator must edit.
    The estate tier passes pairs and its rows are unchanged."""
    records: list[dict] = []
    for entry in rules:
        name, rule = entry[0], entry[1]
        address = entry[2] if len(entry) > 2 else ""
        if not isinstance(rule, Mapping):
            raise _Undecidable(f"{label} {name!r} is not a record — the rule was not "
                               "evaluated")
        _reject_unsupported(label, name, rule)
        base: dict[str, Any] = {"name": name}
        if address:
            base[sec_rules.WITNESS_ADDRESS_FIELD] = address
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
    """``proposed_firewall_rules`` from the document's ``firewall_rule`` claims.

    A terraform document's firewall claims carry the BLOCK ADDRESS as their
    ``location`` (``google_compute_firewall.allow_ssh_world`` — see
    ``fw_claims._tf_firewall_claims``), and it rides along on every row so a
    refutation can name the block to edit instead of only the flattened row
    that witnessed it. A REST document's ``location`` is a json path
    (``"name"``), which locates nothing an operator can open, so it is not
    threaded and those rows are byte-identical to what they always were."""
    def extract(ctx):
        claims, missing = _document_claims(ctx, module, "firewall_rule",
                                           "VPC firewall rule")
        if missing is not None:
            return (), missing
        tf = ctx.document_kind == _TF_PLAN
        rules = [(_claim_name(c.fields(), c), c.fields(),
                  c.location if tf else "") for c in claims]
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
    from a node, so it is a scalar dimension like any other.

    Both of a policy record's own collections are read through
    :mod:`gcp_grounding.evidence`, so an absent or wrong-typed ``rules`` /
    ``attachments`` key ABSTAINS naming the policy and the key instead of folding
    to zero rows: a policy that contributes nothing lets a ``forall`` promise
    pass over rules nobody read. Three consequences follow:

    * the unsupported-payload rejector runs on the POLICY record too, before the
      rules loop — dropping the whole policy is the same vacuous pass, one level
      up from dropping one of its rules;
    * ``attachments`` is a SCOPE SELECTOR, not a tag. The empty string is
      reserved for a genuinely captured empty list ("attached nowhere", a fact
      about the estate), so an unreadable one may not be spelled that way: it
      would judge a policy attached to an organization as attached NOWHERE, and
      a node-scoped ``forall`` would pass over a rule that violates it;
    * a table that was captured NON-EMPTY and yielded no rows abstains rather
      than returning an empty tuple, which would encode to a trivially true
      ``forall``.
    """
    table = _estate_table(ctx.snapshot, "hierarchical_firewall_policies")
    label = "hierarchical firewall rule"
    records: list[dict] = []
    for policy in sorted(table):
        record = table[policy]
        what = f"hierarchical firewall policy {policy!r}"
        if not isinstance(record, Mapping):
            raise _Undecidable(f"hierarchical firewall policy {policy!r} is not a "
                               "record — the rule was not evaluated")
        _reject_unsupported("hierarchical firewall policy", policy, record)
        nodes = _str_dimension(
            "node", evidence.scalar(record, "attachments", what=what, type=list))
        for index, rule in enumerate(evidence.rows(record, "rules", what=what)):
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
    if table and not records:
        raise _Undecidable(
            f"the captured hierarchical_firewall_policies table holds "
            f"{len(table)} policy record(s) and none of them yielded a rule — the "
            "estate-tier rule was not evaluated")
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
    section), where the section is "status" (enforced) or "spec" (dry-run).

    The shape is PINNED rather than sniffed. Skipping a section block that is not
    a Mapping, and reading one hard-coded entry key out of the ones that are, made
    every payload drift look like a perimeter that restricts nothing: zero rows,
    no reason, and a ``forall`` promise passing over entries nobody read. So a
    payload carrying NEITHER a ``spec`` nor a ``status`` Mapping abstains naming
    the perimeter and both sections, a section whose entry key is absent or not a
    list abstains naming the perimeter and THAT section (through
    :func:`gcp_grounding.evidence.rows`, which tells a present empty list apart
    from an unreadable one), and a non-empty claim list that yielded no rows
    abstains rather than returning an empty tuple.
    """
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
            blocks = {section: payload[section] for section in ("spec", "status")
                      if section in payload
                      and isinstance(payload[section], Mapping)}
            if not blocks:
                raise _Undecidable(
                    f"perimeter {perimeter!r} carries neither a 'spec' nor a "
                    f"'status' section, so its {collection} were never captured "
                    "— the rule was not evaluated")
            for section in sorted(blocks):
                what = f"perimeter {perimeter!r} {section!r} section"
                for value in evidence.rows(blocks[section], source, what=what):
                    if isinstance(value, str) and value:
                        records.append({"perimeter": perimeter, field: value,
                                        "section": section})
        if claims and not records:
            raise _Undecidable(
                f"{len(claims)} perimeter claim(s) were read and none of them "
                f"yielded a {collection} entry — the rule was not evaluated")
        return _sorted(records, fields), None
    extract.__doc__ = f"Records for the {collection} collection."
    return extract


# -- the sec_rules base collections' terraform arm ----------------------------
#
# ``iam_bindings`` and ``org_policy_rules`` are sec_ast base collections whose
# REST extractors are sec_rules built-ins this module never edits. What
# :func:`register` overrides is dispatch only: a ``tf_plan`` document takes the
# claim-built arm below, every other kind reaches the untouched built-in — so an
# IAM or org-policy promise judges a terraform proposal exactly the way a
# firewall promise already does, and a refutation names the block to edit.

#: The member claim kinds of one binding. ``claims.iam_policy_claims`` drops NO
#: member — estate principals, the two public principals and everything else
#: (``deleted:…``, federated ids) each yield exactly one claim — so together
#: these are the binding's complete member list.
_MEMBER_KINDS = frozenset({"principal", "public_principal", "unmodelled_principal"})
_IAM_KINDS = _MEMBER_KINDS | {"role", "cel"}
_ORG_KINDS = frozenset({"constraint", "constraint_value"})

#: The claim-location grammar of a terraform IAM binding / org policy, exactly
#: as ``tf_claims`` anchors them: ``<binding>.role``, ``<binding>.members[i]``
#: (or ``.member`` for a *_iam_member), ``<binding>.condition[0].expression``,
#: ``<resource>.name`` / ``<resource>.constraint`` and
#: ``<resource>.spec[0].rules[i].<key>``. A role/member claim OUTSIDE this
#: grammar is not a binding field (a perimeter identity, a provider module's
#: reference) and builds no row; an org-policy claim outside it abstains,
#: because an org-policy claim IS this collection's subject.
_ROLE_AT = re.compile(r"^(?P<binding>.+)\.role$")
_MEMBER_AT = re.compile(r"^(?P<binding>.+)\.(?:members\[\d+\]|member)$")
_CONDITION_AT = re.compile(r"^(?P<binding>.+)\.condition(?:\[\d+\])?\.expression$")
_CONSTRAINT_AT = re.compile(r"^(?P<address>.+)\.(?:name|constraint)$")
_ORG_RULE_AT = re.compile(r"^(?P<address>.+)\.spec(?:\[\d+\])?"
                          r"\.rules\[(?P<index>\d+)\]"
                          r"\.(?P<key>enforce|allow_all|deny_all|values)$")
#: The plan-side census: binding-shaped resource addresses this extraction is
#: responsible for. A plan block of one of these types that yielded NO claim
#: (role and members both stripped or malformed) must abstain by name — the
#: claims-side grouping alone cannot see a block the walker read nothing from.
_IAM_BINDING_ADDRESS = re.compile(r"^google_\w+_iam_(?:binding|member)\.[^.]+$")
_ORG_POLICY_ADDRESS = re.compile(r"^google_org_policy_policy\.[^.]+$")


def _plan_values(document) -> dict:
    """Resource address → planned values, through ``tf_claims``' OWN plan walker
    (``_google_resources``) so the claims and this lookup cannot drift."""
    return {address: values
            for address, _rtype, values in tf_claims._google_resources(document)}


def _resource_values(prefix: str, by_address: Mapping[str, Any],
                     label: str) -> Mapping[str, Any]:
    """The planned values of the resource owning *prefix* — refusing unknown
    multiplicity.

    A ``.tf.json`` configuration keeps a literal ``count`` / ``for_each`` as a
    plain attribute (a real ``terraform show -json`` plan expands instances and
    carries neither), and a block that may expand zero times must not mint a row
    a promise could be refuted by. An unresolved ``count``/``for_each`` never
    reaches here at all — ``facts.strip_unresolved`` removed it and put the path
    on the proposal's unresolved record, the existing bookkeeping that already
    downgrades every ``grounded`` on the file."""
    if prefix in by_address:
        address = prefix
    else:
        owners = [a for a in by_address if prefix.startswith(f"{a}.")]
        if not owners:
            raise _Undecidable(f"{label} {prefix!r} sits under no resource the "
                               "plan walker saw — the rule was not evaluated")
        address = max(owners, key=len)
    values = by_address[address]
    if not isinstance(values, Mapping):
        raise _Undecidable(f"{label} {prefix!r} has no planned values — the "
                           "rule was not evaluated")
    for meta in ("count", "for_each"):
        if meta in values:
            raise _Undecidable(
                f"{label} {prefix!r} carries {meta!r}, so how many instances "
                "the block creates is not decided from the configuration — no "
                "row was minted for it and the rule was not evaluated")
    return values


def _tf_iam_bindings(ctx):
    """``iam_bindings`` rows from a terraform document's role / member / cel
    claims, grouped by the binding each claim is anchored to.

    One row per (binding, member), REST-shaped: ``role`` and ``member`` from the
    claims' own values, the binding's location under
    :data:`sec_rules.WITNESS_ADDRESS_FIELD` so a refutation names the block to
    edit. ``condition`` / ``has_condition`` ride along ONLY when a ``cel`` claim
    pinned the expression: the claims cannot tell "no condition" from "a
    request-time condition the extractor conservatively skipped", and spelling
    either as ``has_condition=False`` could fabricate a refutation — so the keys
    are omitted and a promise that mentions them abstains loudly through
    sec_encode's missing-from-the-record :class:`UnsupportedTerm`. A binding
    whose member claims arrive without a role claim (a stripped interpolation,
    a malformed role) abstains naming the binding: dropping it would let a
    ``forall`` promise pass over a grant nobody read. A binding with a role and
    no members grants nothing and contributes nothing, exactly as the REST
    extractor reads an empty ``members`` array."""
    label = "IAM binding"
    claims = _plan_claims(ctx.document, _IAM_KINDS, label)
    by_address = _plan_values(ctx.document)
    groups: dict[str, dict[str, list]] = {}
    for claim in claims:
        if claim.kind == "cel":
            continue
        slot = "role" if claim.kind == "role" else "member"
        matched = (_ROLE_AT if slot == "role" else _MEMBER_AT).match(claim.location)
        if matched is None:
            continue  # a role/principal reference that is not a binding field
        group = groups.setdefault(matched.group("binding"),
                                  {"role": [], "member": []})
        group[slot].append(claim)
    if not groups:
        raise _no_tf_records(label)
    conditions: dict[str, str] = {}
    for claim in claims:
        if claim.kind != "cel":
            continue
        matched = _CONDITION_AT.match(claim.location)
        if matched is not None and matched.group("binding") in groups:
            conditions.setdefault(matched.group("binding"), claim.value)
    records: list[dict] = []
    for binding in sorted(groups):
        group = groups[binding]
        values = _resource_values(binding, by_address, label)
        if not group["role"]:
            raise _Undecidable(
                f"{label} {binding!r} carries member claims but no role claim — "
                "the role it grants was not read, and a record without it would "
                "be a guess — the rule was not evaluated")
        if len(group["role"]) > 1:
            raise _Undecidable(
                f"{label} {binding!r} carries {len(group['role'])} role claims — "
                "which role it grants is ambiguous — the rule was not evaluated")
        raw_members = values.get("members", values.get("member"))
        if not group["member"]:
            # Only a genuinely absent or empty members attribute grants
            # nothing (the REST extractor's empty-array read). A members
            # value the claim walker yielded nothing for — a bare string, a
            # map, any non-list shape — is a grant list nobody read, and
            # dropping it silently is how a forall promise passes over it.
            if raw_members is None or raw_members == []:
                continue
            raise _Undecidable(
                f"{label} {binding!r} carries a members attribute that yielded "
                "no member claims (not a list of plain strings) — the grant "
                "list was not read — the rule was not evaluated")
        if isinstance(raw_members, list) and any(
                not isinstance(member, str) for member in raw_members):
            raise _Undecidable(
                f"{label} {binding!r} carries non-string member entries — "
                "their coerced spellings could fabricate a refutation — the "
                "rule was not evaluated")
        base: dict[str, Any] = {"role": group["role"][0].value,
                                sec_rules.WITNESS_ADDRESS_FIELD: binding}
        if binding in conditions:
            base["condition"] = conditions[binding]
            base["has_condition"] = True
        records.extend({**base, "member": member.value}
                       for member in group["member"])
    unread_bindings = sorted(
        address for address in by_address
        if _IAM_BINDING_ADDRESS.match(address) and address not in groups)
    if unread_bindings:
        raise _Undecidable(
            f"{label} resource(s) {', '.join(map(repr, unread_bindings))} "
            "yielded no readable claims at all — a binding whose role and "
            "members were both stripped or malformed is a grant nobody read — "
            "the rule was not evaluated")
    if not records:
        raise _Undecidable(
            f"{_PLAN_WHAT} carries {len(groups)} IAM binding(s) and none of "
            "them names a member — the rule was not evaluated over any record")
    return _sorted(records, sec_ast.COLLECTIONS["iam_bindings"].fields), None


def _tf_enforce(raw: Any, address: str, label: str) -> bool:
    """The boolean an org-policy rule's ``enforce`` sets, in either spelling the
    provider uses (a JSON boolean, or the ``"TRUE"``/``"FALSE"`` enum strings of
    :data:`tf_claims._TF_BOOLEANS` — read from that one table, not restated)."""
    value = (raw if isinstance(raw, bool)
             else tf_claims._TF_BOOLEANS.get(raw) if isinstance(raw, str)
             else None)
    if value is None:
        raise _Undecidable(f"{label} {address!r} carries enforce={raw!r}, which "
                           "is not a boolean — the rule was not evaluated")
    return value


def _tf_org_rule(by_address: Mapping[str, Any], address: str, index: int,
                 label: str) -> Mapping[str, Any]:
    """The ``spec.rules[index]`` block a constraint_value claim was anchored to,
    re-read through ``tf_claims``' own :func:`~gcp_grounding.tf_claims._first_block`
    convention — the claim attests the shape, this fetches the one value the
    claim does not carry."""
    values = _resource_values(address, by_address, label)
    spec, _path = tf_claims._first_block(values.get("spec"), "spec")
    rules = spec.get("rules") if spec is not None else None
    if not isinstance(rules, list) or not 0 <= index < len(rules) \
            or not isinstance(rules[index], Mapping):
        raise _Undecidable(
            f"{label} {address!r} no longer carries the rule its claim is "
            f"anchored to (rules[{index}]) — the rule was not evaluated")
    return rules[index]


def _tf_org_policy_rules(ctx):
    """``org_policy_rules`` rows from a terraform document's constraint /
    constraint_value claims.

    REST-shaped rows: ``constraint`` is the claim's canonical value with its
    ``constraints/`` prefix stripped (the spelling the REST extractor's
    ``…/policies/<id>`` tail yields, so one promise matches both transports),
    ``enforce`` is fetched from the plan at the claim's own anchor, a
    list-typed rule yields one row per allowed/denied value with the REST
    extractor's own ``enforce=False`` reading of a rule that does not state it,
    and every row carries the block address. ``allow_all`` / ``deny_all`` rules
    have no REST row shape and abstain by name; so does a policy resource whose
    rules yielded no claim at all — tf_claims skips an ambiguous or unreadable
    rule silently, and dropping the whole policy would let a ``forall`` promise
    pass over rules nobody read."""
    label = "Org Policy"
    claims = _plan_claims(ctx.document, _ORG_KINDS, label)
    by_address = _plan_values(ctx.document)
    policies: dict[str, str] = {}
    for claim in claims:
        if claim.kind != "constraint":
            continue
        matched = _CONSTRAINT_AT.match(claim.location)
        if matched is None:
            raise _Undecidable(
                f"the constraint claim at {claim.location!r} names no resource "
                "address this extraction understands — the rule was not evaluated")
        policies[matched.group("address")] = claim.value
    unclaimed = sorted(
        address for address in by_address
        if _ORG_POLICY_ADDRESS.match(address) and address not in policies)
    if unclaimed:
        raise _Undecidable(
            f"{label} resource(s) {', '.join(map(repr, unclaimed))} yielded no "
            "constraint claim — a policy whose name was not readable as a "
            "constraint is a rule nobody read, and dropping it beside a healthy "
            "sibling would let a forall promise pass over it — the rule was "
            "not evaluated")
    if not policies:
        raise _no_tf_records(label)
    read: set[str] = set()
    records: list[dict] = []
    for claim in claims:
        if claim.kind != "constraint_value":
            continue
        matched = _ORG_RULE_AT.match(claim.location)
        address = matched.group("address") if matched is not None else ""
        if matched is None or address not in policies:
            raise _Undecidable(
                f"the org-policy rule claim at {claim.location!r} sits under no "
                "Org Policy resource this extraction read — the rule was not "
                "evaluated")
        constraint = claim.value
        if constraint.startswith("constraints/"):
            constraint = constraint[len("constraints/"):]
        key = matched.group("key")
        index = int(matched.group("index"))
        if key not in ("enforce", "values"):
            raise _Undecidable(
                f"{label} {address!r} rules[{index}] sets {key!r}, a shape this "
                "conservative extraction does not evaluate — the rule was not "
                "evaluated")
        rule = _tf_org_rule(by_address, address, index, label)
        read.add(address)
        base: dict[str, Any] = {"constraint": constraint,
                                sec_rules.WITNESS_ADDRESS_FIELD: address}
        if key == "enforce":
            records.append({**base, "is_list": False, "value": "",
                            "enforce": _tf_enforce(rule.get("enforce"),
                                                   address, label)})
            continue
        block, _path = tf_claims._first_block(rule.get("values"), "values")
        if block is None:
            raise _Undecidable(
                f"{label} {address!r} no longer carries the values block its "
                f"claim is anchored to (rules[{index}].values) — the rule was "
                "not evaluated")
        lists, unreadable = _values_shape(block, claim.location)
        if unreadable:
            raise _Undecidable(f"{label} {address!r}: {'; '.join(unreadable)} — "
                               "the rule was not evaluated")
        records.extend({**base, "is_list": True, "enforce": False, "value": entry}
                       for entry in (*lists["allowed_values"],
                                     *lists["denied_values"]))
    unread = sorted(a for a in policies if a not in read)
    if unread:
        raise _Undecidable(
            f"{label} resource(s) {', '.join(map(repr, unread))} yielded no "
            "rule claim — tf_claims skips an ambiguous, empty or unreadable "
            "rules block, and dropping the policy would let a forall promise "
            "pass over rules nobody read — the rule was not evaluated")
    if not records:
        raise _Undecidable(
            f"{_PLAN_WHAT} carries {len(policies)} Org Policy resource(s) and "
            "none of them yielded a rule record — the rule was not evaluated "
            "over any record")
    return _sorted(records, sec_ast.COLLECTIONS["org_policy_rules"].fields), None


# -- the proposal-tier custom-role permission collection -----------------------
#
# ``proposed_role_permissions`` follows the same claims-are-the-records
# discipline as the two base-collection terraform arms above: the rows are the
# ``permission`` claims ``tf_claims._custom_role_claims`` already emits
# (anchored at ``<block>.permissions[i]``), the one value the claims do not
# carry — the role's own full name — is read from the plan at the claim's own
# anchor through ``tf_claims``' walker, and every row carries the block address
# under :data:`gcp_grounding.sec_rules.WITNESS_ADDRESS_FIELD`. There is NO REST
# arm: no supported REST document kind carries a custom role's permission list,
# and the non-terraform branch says exactly that instead of grounding vacuously.

#: The claim-location grammar of a custom role's permission entries, exactly as
#: ``tf_claims`` anchors them. In a terraform plan, ``permission`` claims come
#: only from ``google_project_iam_custom_role`` blocks; one outside this
#: grammar is a shape this extraction does not understand and abstains on.
_PERMISSION_AT = re.compile(r"^(?P<address>.+)\.permissions\[\d+\]$")
#: The plan-side census: custom-role resource addresses this extraction is
#: responsible for, mirroring :data:`_IAM_BINDING_ADDRESS`. A block of this type
#: that yielded NO permission claim (a stripped or malformed list) must abstain
#: by name — unless its list is present and observed empty, which is the one
#: honest "grants nothing" and contributes no row.
_CUSTOM_ROLE_ADDRESS = re.compile(r"^google_project_iam_custom_role\.[^.]+$")


def _custom_role_name(values: Mapping[str, Any], address: str, label: str) -> str:
    """The full name of the custom role *address* creates, or abstain.

    Built from the block's own literal ``project`` and ``role_id`` — never from
    a provider default, which the configuration does not state and this
    extraction will not guess at."""
    role_id = values.get("role_id")
    if not isinstance(role_id, str) or not role_id:
        raise _Undecidable(
            f"{label} {address!r} carries no readable 'role_id' — the role's "
            "name was not decided, and a record without it would be a guess — "
            "the rule was not evaluated")
    project = values.get("project")
    if not isinstance(project, str) or not project:
        raise _Undecidable(
            f"{label} {address!r} does not state its 'project' in the "
            f"configuration, so the role's full name "
            f"(projects/<project>/roles/{role_id}) was not decided — the rule "
            "was not evaluated")
    return f"projects/{project}/roles/{role_id}"


def _tf_role_permissions(ctx):
    """``proposed_role_permissions`` rows from a terraform document's
    ``permission`` claims, grouped by the custom-role block each claim is
    anchored to."""
    label = "custom role"
    _plan_envelope(ctx.document)
    by_address = _plan_values(ctx.document)
    groups: dict[str, list] = {}
    for claim in tf_claims.terraform_plan_claims(ctx.document):
        if claim.kind != "permission":
            continue
        matched = _PERMISSION_AT.match(claim.location)
        if matched is None:
            raise _Undecidable(
                f"the permission claim at {claim.location!r} sits outside the "
                "permissions[] grammar this extraction reads — the rule was "
                "not evaluated")
        groups.setdefault(matched.group("address"), []).append(claim)
    granting = 0
    unread: list[str] = []
    for address in by_address:
        if not _CUSTOM_ROLE_ADDRESS.match(address) or address in groups:
            continue
        values = by_address[address]
        if isinstance(values, Mapping) and values.get("permissions") == []:
            granting += 1  # present and observed empty: grants nothing
            continue
        unread.append(address)
    if unread:
        raise _Undecidable(
            f"{label} resource(s) {', '.join(map(repr, sorted(unread)))} "
            "yielded no permission claims — a custom role whose permission "
            "list was stripped or malformed grants permissions nobody read — "
            "the rule was not evaluated")
    if not groups:
        if granting:
            raise _Undecidable(
                f"{_PLAN_WHAT} carries {granting} custom role(s) and none of "
                "them names a permission — the rule was not evaluated over "
                "any record")
        raise _no_tf_records(label)
    records: list[dict] = []
    for address in sorted(groups):
        values = _resource_values(address, by_address, label)
        raw = values.get("permissions")
        if not isinstance(raw, list) or any(
                not isinstance(p, str) or not p for p in raw):
            raise _Undecidable(
                f"{label} {address!r} carries a 'permissions' attribute that "
                "is not a list of plain permission names — entries the claim "
                "walker skipped would be permissions nobody read — the rule "
                "was not evaluated")
        role = _custom_role_name(values, address, label)
        records.extend({"role": role, "permission": claim.value,
                        sec_rules.WITNESS_ADDRESS_FIELD: address}
                       for claim in groups[address])
    return _sorted(records, _ROLE_PERMISSION_FIELDS), None


def _proposed_role_permissions(ctx):
    """``proposed_role_permissions``: the terraform arm, or the honest
    not-applicable for every other document kind — pinned rather than implied,
    because a REST custom-role document kind simply does not exist in
    :data:`gcp_grounding.preflight.DOCUMENT_KINDS` and an author deserves to
    read that fact off the abstention."""
    if ctx.document is None:
        return (), ("no document under review — the custom-role rule was not "
                    "evaluated")
    if ctx.document_kind != _TF_PLAN:
        return (), ("the document under review is not a terraform plan — no "
                    "supported REST document kind carries a custom role's "
                    "permission list, so proposed_role_permissions has no "
                    "records here and the rule was not evaluated")
    return _tf_role_permissions(ctx)


# -- the IAM deny-policy proposal collections ----------------------------------
#
# ``deny_rules`` / ``deny_rule_exceptions`` follow the claims-are-the-records
# discipline over :mod:`gcp_grounding.iam_deny`'s claims, grouped by the
# location grammar THAT module owns (its ``*_AT`` regexes — one spelling, no
# drift), with the two values the claims do not carry — the ``denialCondition``
# and the per-field entry census — fetched from the document (or the plan, at
# the block's own address through ``tf_claims``' walker) at the claim's own
# anchor. The census is what promotes the parser's conservative debug-skips (a
# non-string permission entry, a non-list field, a malformed rule object) from
# silence to a NAMED abstention without touching ``iam_deny``'s claim
# behaviour: a count that disagrees with the claims is an entry nobody read,
# and dropping it would let a ``forall`` promise pass over it. Every failure
# path raises :class:`_Undecidable` naming policy, rule and offending value;
# :func:`_guarded` converts it to the promise's missing_reason verbatim.

#: The claim kinds one deny rule anchors at its four principal/permission
#: fields. ``cel`` is deliberately absent: the condition facts come from the
#: rule block itself, because the ``cel`` claim is missing both for "no
#: condition" and for "runtime-marker condition" and cannot tell them apart.
_DENY_KINDS = frozenset({"denied_principal", "denied_permission", "permission",
                         "principal", "public_principal",
                         "unmodelled_principal"})

#: The member-shaped claim kinds (every ``exceptionPrincipals`` entry yields
#: exactly one of the three — the parser drops none).
_DENY_MEMBER_KINDS = frozenset({"principal", "public_principal",
                                "unmodelled_principal"})

_DENY_LABEL = "IAM deny policy"


def _deny_claims(ctx, module):
    """→ ``(claims, heads)`` — the one funnel for both deny collections.

    *heads* maps each policy unit's location head (``""`` for a REST document,
    ``"<address>."`` for a terraform block) to the mapping its rules are
    re-read from. A terraform head that yielded no claims is caught by the
    walk's per-rule agreement checks, and a plan with no
    ``google_iam_deny_policy`` resource at all abstains through
    :func:`_no_tf_records`."""
    if ctx.document is None:
        raise _Undecidable("no document under review — the IAM deny rule was "
                           "not evaluated")
    kind = ctx.document_kind
    if kind == _TF_PLAN:
        _plan_envelope(ctx.document)
        by_address = _plan_values(ctx.document)
        heads = {f"{address}.": _resource_values(address, by_address,
                                                 _DENY_LABEL)
                 for address in sorted(by_address)
                 if module.DENY_POLICY_ADDRESS.match(address)}
        if not heads:
            raise _no_tf_records(_DENY_LABEL)
        claims = tuple(c for c in tf_claims.terraform_plan_claims(ctx.document)
                       if c.kind in _DENY_KINDS)
        return claims, heads
    if kind == "iam_deny_policy":
        claims = tuple(c for c in module.iam_deny_policy_claims(ctx.document)
                       if c.kind in _DENY_KINDS)
        return claims, {"": ctx.document}
    raise _Undecidable(
        "the document under review is not an IAM deny policy — the deny "
        "collections have no records here and the rule was not evaluated")


def _deny_groups(claims, heads, module):
    """The funnel's claims grouped as ``{head: {rule: {field: {j: value}}}}``.

    A deny-kind claim matching no grammar row, one whose payload ``rule_index``
    or ``excepted`` flag disagrees with its own location, or one anchored under
    no deny-policy unit aborts by name — never silently regrouped: the payload
    keys are the documented discriminators, and a claim the grammar cannot
    place is a denial nobody can correlate."""
    groups: dict[str, dict[int, dict[str, dict[int, str]]]] = {}

    def put(head, i, field, j, value, location):
        if head not in heads:
            raise _Undecidable(
                f"the deny claim at {location!r} sits under no IAM deny policy "
                "unit this extraction read — the rule was not evaluated")
        slot = groups.setdefault(head, {}).setdefault(i, {}).setdefault(field, {})
        if j in slot:
            raise _Undecidable(
                f"two deny claims anchor at {location!r} — which entry is "
                "attested is ambiguous — the rule was not evaluated")
        slot[j] = value

    for claim in claims:
        location = claim.location if isinstance(claim.location, str) else ""
        payload = claim.fields()
        if claim.kind == "denied_principal":
            matched = module.DENIED_PRINCIPAL_AT.match(location)
            if matched is None:
                raise _Undecidable(
                    f"the denied_principal claim at {location!r} sits outside "
                    "the deniedPrincipals[] grammar — the rule was not evaluated")
            _deny_index_agrees(payload, matched, location)
            put(matched.group("head"), int(matched.group("i")),
                "denied_principals", int(matched.group("j")), claim.value,
                location)
        elif claim.kind == "denied_permission":
            excepted = bool(payload.get("excepted"))
            regex = (module.EXCEPTION_PERMISSION_AT if excepted
                     else module.DENIED_PERMISSION_AT)
            matched = regex.match(location)
            if matched is None:
                raise _Undecidable(
                    f"the denied_permission claim at {location!r} disagrees "
                    f"with its own excepted={excepted} payload about which "
                    "field it came from — the rule was not evaluated")
            _deny_index_agrees(payload, matched, location)
            field = "exception_permissions" if excepted else "denied_permissions"
            put(matched.group("head"), int(matched.group("i")), field,
                int(matched.group("j")), claim.value, location)
        elif claim.kind in _DENY_MEMBER_KINDS:
            matched = module.EXCEPTION_PRINCIPAL_AT.match(location)
            if matched is not None:
                put(matched.group("head"), int(matched.group("i")),
                    "exception_principals", int(matched.group("j")),
                    claim.value, location)
            # a member claim at deniedPrincipals[] is attested through its
            # denied_principal sibling; one anywhere else (a binding member in
            # the same plan) is another collection's subject
    return groups


def _deny_index_agrees(payload, matched, location: str) -> None:
    """The claim's own ``rule_index`` payload must agree with its location —
    the documented discriminator, cross-checked rather than trusted."""
    index = payload.get("rule_index")
    if isinstance(index, bool) or index != int(matched.group("i")):
        raise _Undecidable(
            f"the deny claim at {location!r} carries rule_index={index!r}, "
            "which disagrees with its own location — which rule it attests is "
            "ambiguous — the rule was not evaluated")


def _deny_entries(module, deny_rule: Mapping[str, Any], spellings: tuple,
                  what: str, field: str) -> tuple:
    """The raw entries of one deny-rule field, strings only.

    An absent field reads as observed-empty (the parser treats absent as "no
    entries" too); a non-list field or a non-string / empty-string entry aborts
    the rule: a coerced spelling could fabricate a refutation, and an entry the
    claim walker skipped is a denial nobody read."""
    raw = module._get(deny_rule, spellings)
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise _Undecidable(
            f"{what}.{field} is not an array ({type(raw).__name__}) — its "
            "entries were not read — the rule was not evaluated")
    for j, entry in enumerate(raw):
        if not isinstance(entry, str) or not entry:
            raise _Undecidable(
                f"{what}.{field}[{j}] is not a plain non-empty string "
                f"({entry!r}) — a coerced spelling could fabricate a "
                "refutation — the rule was not evaluated")
    return tuple(raw)


def _deny_agreed(entries: tuple, attested: Mapping[int, str], what: str,
                 field: str) -> None:
    """The census must agree with the claims, entry for entry: a length or
    value that disagrees is an entry the claim walker skipped (a debug-logged
    non-string, a malformed sibling) — a denial nobody read."""
    if set(attested) != set(range(len(entries))) or any(
            attested[j] != entries[j] for j in range(len(entries))):
        raise _Undecidable(
            f"{what}.{field} carries {len(entries)} readable entr(ies) but its "
            f"claims attest {len(attested)} — entries the claim walker skipped "
            "are denials nobody read — the rule was not evaluated")


def _deny_normalized(module, what: str, permission: str) -> str:
    """The one normalized short form, or abort the rule by name: dropping only
    the bad entry would let a ``forall`` pass over a permission nobody read,
    and an uncomputable subtraction poisons every sibling row."""
    normalized = module._normalize_permission(permission)
    if normalized is None:
        raise _Undecidable(
            f"{what} names permission {permission!r} with no unambiguous "
            "normalized form — the rows for this rule would be a guess — the "
            "rule was not evaluated")
    return normalized


def _deny_walk(ctx, module) -> tuple[list, list]:
    """→ ``(rule_rows, exception_rows)`` for every deny-policy unit of
    ``ctx.document`` — the shared walk both deny collections are thin over."""
    claims, heads = _deny_claims(ctx, module)
    groups = _deny_groups(claims, heads, module)
    tf = ctx.document_kind == _TF_PLAN
    rule_rows: list[dict] = []
    exception_rows: list[dict] = []
    for head in sorted(heads):
        source = heads[head]
        address = head[:-1] if tf else ""
        policy = ""
        if not tf:
            # The REST document's own name; a plan block's literal name is NOT
            # trusted (usually known-after-apply) — "" plus the block address
            # under WITNESS_ADDRESS_FIELD, which the witness message prints.
            name = source.get("name")
            policy = name if isinstance(name, str) and name else ""
        where = address or policy or "<document>"
        unit = groups.get(head, {})
        rules = evidence.rows(source, "rules", what=f"{_DENY_LABEL} {where}")
        # THE PLAN CENSUS (mirroring _IAM_BINDING_ADDRESS): a deny block whose
        # rules are present but which yielded NO claim at all is a policy whose
        # rules were stripped or malformed — it denies nobody nobody read, and
        # the per-rule agreement checks below cannot run for rules the claim
        # walker never anchored anything under.
        if tf and rules and not unit:
            raise _Undecidable(
                f"deny policy resource {address!r} yielded no readable claims "
                "— a policy whose rules were stripped or malformed denies "
                "nobody nobody read — the rule was not evaluated")
        for i, rule in enumerate(rules):
            what = f"{_DENY_LABEL} {where} rules[{i}]"
            rule_claims = unit.get(i, {})
            if not isinstance(rule, Mapping):
                raise _Undecidable(
                    f"{what} is not an object — a rule nobody read could deny "
                    "anything — the rule was not evaluated")
            deny_rule = module._as_mapping(module._get(rule,
                                                       module._DENY_RULE_KEYS))
            if deny_rule is None:
                raise _Undecidable(
                    f"{what} carries no readable denyRule object — a rule "
                    "nobody read could deny anything — the rule was not "
                    "evaluated")
            entries = {}
            for field, spellings, _flag in (*module._PRINCIPAL_FIELDS,
                                            *module._PERMISSION_FIELDS):
                snake = _DENY_FIELD_NAMES[field]
                entries[snake] = _deny_entries(module, deny_rule, spellings,
                                               what, field)
                _deny_agreed(entries[snake], rule_claims.get(snake, {}),
                             what, field)
            denied_norm = [_deny_normalized(module, what, p)
                           for p in entries["denied_permissions"]]
            excepted_norm = {_deny_normalized(module, what, p)
                             for p in entries["exception_permissions"]}
            effective = [p for p in denied_norm if p not in excepted_norm]
            base: dict[str, Any] = {
                "policy": policy, "rule_index": i,
                "has_principal_exceptions": bool(entries["exception_principals"]),
                **_deny_condition(module, deny_rule),
            }
            if address:
                base[sec_rules.WITNESS_ADDRESS_FIELD] = address
            rule_rows.extend(_rows(base, (
                [{"denied_principal": p}
                 for p in entries["denied_principals"]] or [{}],
                [{"permission": p} for p in effective] or [{}],
            )))
            for principal in entries["exception_principals"]:
                row = {"policy": policy, "rule_index": i,
                       "exception_principal": principal}
                if address:
                    row[sec_rules.WITNESS_ADDRESS_FIELD] = address
                exception_rows.append(row)
    if not rule_rows:
        raise _Undecidable(
            "the IAM deny policy unit(s) under review carry no rules — "
            "deny_rules has no records and the rule was not evaluated over "
            "any record")
    return rule_rows, exception_rows


#: The parser's canonical (camelCase) field names → the census keys the walk
#: groups under, which are also the snapshot table's snake_case spellings.
_DENY_FIELD_NAMES = {
    "deniedPrincipals": "denied_principals",
    "exceptionPrincipals": "exception_principals",
    "deniedPermissions": "denied_permissions",
    "exceptionPermissions": "exception_permissions",
}


def _deny_condition(module, deny_rule: Mapping[str, Any]) -> dict:
    """The two condition keys, from the rule block itself (never from the
    ``cel`` claim, which is absent both for "no condition" and for a
    runtime-marker condition): a readable expression → ``(True, raw text)``, a
    genuinely absent block → ``(False, "")``, and a block that is present but
    unreadable → BOTH KEYS OMITTED, so "denies … unconditionally" abstains
    loudly while permission-only promises still judge. The raw text is a
    document fact — no satisfiability is implied."""
    raw = module._get(deny_rule, module._DENIAL_CONDITION_KEYS)
    if raw is None:
        return {"has_condition": False, "condition": ""}
    block = module._as_mapping(raw)
    expression = block.get("expression") if block is not None else None
    if isinstance(expression, str) and expression.strip():
        return {"has_condition": True, "condition": expression}
    return {}


def _deny_rules_extractor(module) -> Callable:
    """``deny_rules``: one row per effective (rule, principal, permission)."""
    def extract(ctx):
        rule_rows, _exceptions = _deny_walk(ctx, module)
        return _sorted(rule_rows, _DENY_RULE_FIELDS), None
    return extract


def _deny_rule_exceptions_extractor(module) -> Callable:
    """``deny_rule_exceptions``: one row per (rule, exception principal).

    A document whose rules carry NO principal exception anywhere returns the
    ATTESTATION channel — records empty with an ``empty_because`` — so a
    ``forall`` over the empty instance grounds WITH the note instead of
    tripping the evidence floor."""
    def extract(ctx):
        _rules, exception_rows = _deny_walk(ctx, module)
        if not exception_rows:
            return evidence.observed_empty(
                "the deny document under review",
                "every deny rule was read and none carries a principal "
                "exception")
        return _sorted(exception_rows, _DENY_EXCEPTION_FIELDS), None
    return extract


def _with_terraform_arm(tf_extract: Callable, builtin: Callable) -> Callable:
    """Dispatch for an overridden base collection: a ``tf_plan`` document takes
    *tf_extract*; every other kind — including the loud unrecognized/None
    default — reaches *builtin*, sec_rules' untouched REST extractor, so a
    non-terraform document's records, refusals and messages are byte-identical
    to what they always were."""
    def extract(ctx):
        if ctx.document_kind == _TF_PLAN:
            return tf_extract(ctx)
        return builtin(ctx)
    return extract


# -- registration -------------------------------------------------------------

def _guarded(collection: str, fn: Callable) -> Callable:
    """*fn* with the honest failure channels wired up: an :class:`_Undecidable`
    becomes the missing_reason verbatim, an
    :class:`gcp_grounding.evidence.NotEvaluated` — the shared typed abstain —
    goes through the SAME channel, so a domain extractor may raise either, and
    any other exception becomes a missing_reason naming the extractor: a crashing
    domain module abstains, it never breaks the gate.

    It is also where THE evidence ledger for one extraction is opened, because
    :func:`gcp_grounding.evidence.rows` refuses to read without one."""
    def extract(ctx):
        try:
            if evidence._LEDGER.get() is not None:
                # An invoker already opened THE ledger for this invocation, and
                # evidence.ledger() refuses to NEST — nesting would hide one
                # check's evidence inside another's. Reuse the open one, so these
                # reads are counted against the check that asked for them.
                return fn(ctx)
            with evidence.ledger():
                return fn(ctx)
        except (_Undecidable, evidence.NotEvaluated) as exc:
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

    # Unconditional, like the base-collection overrides below: everything the
    # custom-role arm needs (tf_claims, sec_rules) is a hard import already.
    sec_rules.register_extractor(
        "proposed_role_permissions",
        _guarded("proposed_role_permissions", _proposed_role_permissions))

    # The deny collections need the iam_deny claims module; a checkout without
    # it registers the specs (above, unconditionally) and skips the extractors,
    # so a deny promise compiles and abstains loudly — the documented
    # partial-checkout behaviour.
    iam_deny = _domain_module(DOMAIN_MODULES["iam"])
    if iam_deny is not None:
        sec_rules.register_extractor(
            "deny_rules", _guarded("deny_rules",
                                   _deny_rules_extractor(iam_deny)))
        sec_rules.register_extractor(
            "deny_rule_exceptions",
            _guarded("deny_rule_exceptions",
                     _deny_rule_exceptions_extractor(iam_deny)))

    # The two effective org-policy collections need the org_effective fold
    # module; a checkout without it registers the specs (above,
    # unconditionally) and skips the extractors, so an effective-state promise
    # compiles and abstains loudly — the documented partial-checkout behaviour.
    org_effective = _domain_module(DOMAIN_MODULES["org_policy"])
    if org_effective is not None:
        sec_rules.register_extractor(
            "effective_org_policy_bool",
            _guarded("effective_org_policy_bool",
                     org_effective.effective_org_policy_bool_records))
        sec_rules.register_extractor(
            "effective_org_policy_values",
            _guarded("effective_org_policy_values",
                     org_effective.effective_org_policy_values_records))

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

    # The two base collections sec_rules ships (BASE_COLLECTION_OVERRIDES).
    # Their REST extractors are built-ins this module never edits; what is
    # registered here is dispatch plus the terraform arm, so an IAM or
    # org-policy promise judges a terraform proposal the way a firewall promise
    # already does — from the tf claims, with the block address on every row.
    # Each override lands ONLY over the shipped built-in: register() runs as a
    # lazy side effect of the first evaluate(), and stomping an extractor a
    # test or an operator installed first — from inside their own call — is
    # how the mutation contract's MK-I16 witness flipped on isolated runs.
    _tf_arm = {"iam_bindings": (_tf_iam_bindings, sec_rules.iam_bindings),
               "org_policy_rules": (_tf_org_policy_rules,
                                    sec_rules.org_policy_rules)}
    for name in BASE_COLLECTION_OVERRIDES:
        tf_extract, builtin = _tf_arm[name]
        if sec_rules.EXTRACTORS.get(name) is not builtin:
            continue  # a prior registration outranks a side-effect import
        sec_rules.register_extractor(
            name, _guarded(name, _with_terraform_arm(tf_extract, builtin)))
