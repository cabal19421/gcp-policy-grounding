"""Effective org-policy reasoning: the deterministic hierarchy fold.

Everything before this module judges an org-policy document in isolation:
``sec_rules.org_policy_rules`` and its terraform arm flatten ONE document's
rules, and ``org_checks.check_constraint_enforcement`` compares a proposal
against the prior AT THE SAME NODE.  Nothing anywhere answered "what is
actually enforced at this node after the org, the folders and this change
compose?" — a folder-level ``reset`` whose effect only materialises at the
projects below it was invisible to every per-document view.

This module adds that fold: a plain-Python, solver-free merge of
``snapshot.org_policies`` + ``snapshot.resource_hierarchy`` + the proposal's
own set-policy at its node, surfaced three ways:

* two ESTATE-tier collections z3 promises quantify over —
  ``effective_org_policy_bool`` (one row per (node, constraint) with the folded
  ``enforce``) and ``effective_org_policy_values`` (one row per effectively
  allowed/denied value, read-time deny precedence already applied);
* the instance extractors ``sec_domains.register`` installs for them;
* one built-in document check (:func:`check_org_effective`, kind
  ``org_effective``) reporting a proposal that is INERT (before == after at
  every governed node) or the BLAST RADIUS of one that is not.

THE MERGE, as committed to (Org Policy v2):

* boolean constraints: nearest-set-wins down the root→node chain; ``reset``
  restores the managed default; ``inheritFromParent`` is not meaningful for
  booleans and abstains.
* list constraints: walk root→node; ``inheritFromParent: true`` MERGES this
  node's rules into the parent's effective policy (union of both value sets,
  OR of the allValues flags); false REPLACES it; ``reset`` restores the managed
  default mid-chain.  At read time ``deniedValues`` beat ``allowedValues`` for
  the same value and ``denyAll`` beats everything — baked into row emission,
  because a value effectively denied must NEVER appear as an allow row (a
  refute-mode "must not allow v" promise would otherwise be refuted by a state
  that in fact denies v: a fabricated refutation).
* the managed default is decidable ONLY from the optional constraints-record
  field ``constraint_default`` ("ALLOW"/"DENY", the v2
  ``Constraint.constraintDefault``); absent → a named abstention, never a
  guess.
* a terraform ``google_org_policy_policy`` resource defines the ENTIRE policy
  at its parent for its constraint, so the overlay REPLACES the captured
  record at that (node, constraint) — it never unions with it.

EVERY case the snapshot cannot decide abstains BY NAME — conditions anywhere
on the folded chain, an unknown or undecidable node, chain damage (dangling
parents, cycles), oneof violations, type confusion against the declared
``value_type``, contradictory flags, uncaptured or incomplete
``org_policies`` / ``resource_hierarchy`` / ``constraints``, unknown
multiplicity (``count``/``for_each``) and duplicate proposal targets.  Never a
fabricated row, never a defaulted value: the extractors raise
:class:`gcp_grounding.sec_domains._Undecidable` (converted verbatim into the
promise's missing_reason by ``sec_domains._guarded``) and the document check
converts the same refusals into one ``unverified org_effective`` per target.

No I/O, no solver, standard library only.  ``org_checks`` is untouched: the
two modules answer different questions (same-node prior diff vs hierarchy
fold) and share only the claim shapes.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from . import evidence, tf_claims
from .claims import _bool_or_none, _org_policy_constraint, _org_policy_node
from .core.log import get_logger
from .core.report import Verdict
from .knowledge import UNKNOWN
from .registry import CheckContext
from .sec_domains import (_CONSTRAINT_AT, _ORG_POLICY_ADDRESS, _Undecidable,
                          _estate_table, _no_tf_records, _plan_envelope,
                          _plan_values, _resource_values, _sorted, _tf_enforce)
from .sec_rules import WITNESS_ADDRESS_FIELD, RuleContext

logger = get_logger(__name__)

__all__ = [
    "VERDICT_KIND", "DOCUMENT_CHECKS",
    "check_org_effective",
    "effective_org_policy_bool_records", "effective_org_policy_values_records",
]

#: ``Verdict.kind`` for every finding this module makes.
VERDICT_KIND = "org_effective"

#: The two constraint value types the fold can evaluate; anything else is a
#: constraint whose merge semantics this module does not know and abstains on.
_VALUE_TYPES = ("boolean", "list")

#: The canonical constraint prefix, stripped at every boundary so one promise
#: phrase reads across the per-document and the effective collections.
_PREFIX = "constraints/"

_LABEL = "Org Policy"


def _optional(name: str):
    """``gcp_grounding.<name>`` or ``None`` — the sec_rules lazy idiom, so a
    checkout without the reconciliation spine degrades to captured-bit checks."""
    try:
        return importlib.import_module(f"gcp_grounding.{name}")
    except ImportError:
        logger.debug("org_effective: gcp_grounding.%s is not part of this "
                     "checkout; the fold runs without it", name)
        return None


def _short(constraint: str) -> str:
    """The canonical constraint id with the ``constraints/`` prefix stripped."""
    return constraint[len(_PREFIX):] if constraint.startswith(_PREFIX) else constraint


# -- completeness (A9 / A10) ---------------------------------------------------


def _require_complete(snapshot: Any, category: str) -> None:
    """Abstain when absence in *category* may not be read as non-existence.

    The ``sec_rules._require_complete`` preference order: the snapshot's own
    predicate when callable (a ReconciledSnapshot answers from its ledger),
    else :func:`gcp_grounding.provenance.require_complete`, provenance resolved
    lazily so a checkout without it degrades to the captured-bit checks the
    callers already made.
    """
    own = getattr(snapshot, "require_complete", None)
    if callable(own):
        reason = own(category, rule=VERDICT_KIND)
    else:
        provenance = _optional("provenance")
        if provenance is None:
            return
        reason = provenance.require_complete(snapshot, category,
                                             rule=VERDICT_KIND)
    if reason is not None:
        raise _Undecidable(
            f"the {category} capture may not license the effective-state fold: "
            f"{reason} — the fold was not evaluated")


# -- the hierarchy (chains, A6/A7/A11/A12) ------------------------------------


def _canonical_node(table: Mapping[str, Any], node: str) -> Optional[str]:
    """*node* as a captured hierarchy key, the ``projects/<number>`` alias
    resolved from the captured records themselves — or ``None``."""
    if node in table:
        return node
    for name, record in table.items():
        if not isinstance(record, Mapping):
            continue
        number = record.get("number")
        if (record.get("type") == "project" and number
                and f"projects/{number}" == node):
            return name
    return None


def _chain(table: Mapping[str, Any], node: str) -> tuple[str, ...]:
    """The root-first chain of captured nodes from the root down to *node*.

    A parent named but not captured is chain damage (A11) and a cycle is worse
    (A12); both abstain naming the node, because a silently shortened fold
    would mint an effective state out of a keyhole.
    """
    seen: list[str] = []
    cursor: Optional[str] = node
    while cursor is not None:
        if cursor in seen:
            raise _Undecidable(
                f"the resource hierarchy contains a cycle through {cursor!r} "
                f"(walking up from {node!r}) — the chain cannot be folded and "
                "the effective state was not decided")
        record = table.get(cursor)
        if record is None:
            raise _Undecidable(
                f"the hierarchy chain from {node!r} is broken: {cursor!r} is "
                "named as a parent but is not in the captured "
                "resource_hierarchy — a truncated chain would silently shorten "
                "the fold, so the effective state was not decided")
        seen.append(cursor)
        parent = record.get("parent") if isinstance(record, Mapping) else None
        cursor = parent if isinstance(parent, str) and parent else None
    return tuple(reversed(seen))


def _universe(table: Mapping[str, Any], node: str) -> tuple[str, ...]:
    """``{node} ∪ descendants(node)`` over the captured hierarchy, sorted.

    A descendant is every captured node whose own root-first chain passes
    through *node*; chain damage anywhere abstains identically (A11/A12),
    because a descendant this walk cannot place may be one the fold owes a row.
    """
    members = {node}
    for name in sorted(table):
        if node in _chain(table, name):
            members.add(name)
    return tuple(sorted(members))


# -- the constraints record (A13, and the managed default A20) -----------------


def _constraint_record(snapshot: Any, constraint: str) -> Mapping[str, Any]:
    """The constraints record for ``constraints/<constraint>``, with a
    ``value_type`` the fold can evaluate — or abstain naming the constraint."""
    record = snapshot.constraint(f"{_PREFIX}{constraint}")
    if record is UNKNOWN:
        raise _Undecidable(
            f"snapshot did not capture constraints, so the value type of "
            f"{_PREFIX}{constraint} is unknowable — the effective state was "
            "not decided")
    if record is None:
        raise _Undecidable(
            f"the captured constraints record nothing for "
            f"{_PREFIX}{constraint}, so its value type is unknowable — the "
            "effective state was not decided")
    value_type = record.get("value_type")
    if value_type not in _VALUE_TYPES:
        raise _Undecidable(
            f"the captured constraint {_PREFIX}{constraint} declares "
            f"value_type={value_type!r}, which this fold cannot evaluate "
            f"(expected one of {list(_VALUE_TYPES)}) — the effective state "
            "was not decided")
    return record


def _default_bool(record: Mapping[str, Any], constraint: str) -> bool:
    """The managed default of a boolean constraint — DENY is enforced-by-
    default, ALLOW is not — or abstain (A20) when it was never captured."""
    default = record.get("constraint_default")
    if default == "DENY":
        return True
    if default == "ALLOW":
        return False
    raise _Undecidable(
        f"the effective state of {_PREFIX}{constraint} bottoms out at the "
        f"managed default, and the captured constraints record carries no "
        f"recognized 'constraint_default' (got {default!r}) — the default was "
        "not guessed and the effective state was not decided")


def _default_list(record: Mapping[str, Any], constraint: str) -> dict[str, Any]:
    """The managed default of a list constraint as a fold state (A20 on
    absence): ALLOW means every value allowed, DENY means every value denied."""
    default = record.get("constraint_default")
    if default == "ALLOW":
        return {"allowed": set(), "denied": set(),
                "allow_all": True, "deny_all": False}
    if default == "DENY":
        return {"allowed": set(), "denied": set(),
                "allow_all": False, "deny_all": True}
    raise _Undecidable(
        f"the effective state of {_PREFIX}{constraint} bottoms out at the "
        f"managed default, and the captured constraints record carries no "
        f"recognized 'constraint_default' (got {default!r}) — the default was "
        "not guessed and the effective state was not decided")


# -- one set-policy, normalized for the fold ----------------------------------
#
# Estate records (fetch.py's shape, or raw REST camelCase in a hand-built
# snapshot) and the proposal overlay both normalize to ONE policy shape before
# the fold reads them, so there is exactly one reader of rule content:
#
#   {"reset": bool, "inherit_from_parent": bool, "rules": (rule, ...)}
#   rule = {"enforce": bool|None, "allow_all": bool|None, "deny_all": bool|None,
#           "allowed_values": (str, ...), "denied_values": (str, ...),
#           "condition": bool}


def _flag_of(rule: Mapping[str, Any], where: str, *spellings: str) -> Optional[bool]:
    """The oneof flag under any of *spellings*: ``True`` states it, ``False``
    and ``None`` state nothing (the API's oneof semantics), anything else is a
    shape nobody can read and abstains."""
    for key in spellings:
        value = rule.get(key)
        if value is None:
            continue
        if isinstance(value, bool):
            if value:
                return True
            continue
        raise _Undecidable(
            f"{where} carries {key}={value!r}, which is not a boolean — the "
            "rule was not read and the effective state was not decided")
    return None


def _values_of(rule: Mapping[str, Any], where: str, *spellings: str) -> tuple[str, ...]:
    """The value list under any of *spellings*, strings only; a non-list or a
    non-string entry abstains — a coerced spelling could fabricate a row."""
    for key in spellings:
        if key not in rule:
            continue
        raw = rule[key]
        if not isinstance(raw, (list, tuple)):
            raise _Undecidable(
                f"{where}.{key} is not an array ({type(raw).__name__}) — its "
                "values were not read and the effective state was not decided")
        for i, entry in enumerate(raw):
            if not isinstance(entry, str) or not entry:
                raise _Undecidable(
                    f"{where}.{key}[{i}] is not a plain non-empty string "
                    f"({entry!r}) — a coerced spelling could fabricate a row, "
                    "so the effective state was not decided")
        return tuple(raw)
    return ()


def _enforce_of(rule: Mapping[str, Any], where: str) -> Optional[bool]:
    """The rule's ``enforce``: a real boolean states it, ``None``/absent states
    nothing, anything else abstains."""
    value = rule.get("enforce")
    if value is None or isinstance(value, bool):
        return value
    raise _Undecidable(
        f"{where} carries enforce={value!r}, which is not a boolean — the "
        "rule was not read and the effective state was not decided")


def _condition_of(rule: Mapping[str, Any], where: str) -> bool:
    """Whether the rule carries a condition — request-time facts this fold
    refuses to decide.  Any non-null, non-empty value counts: a condition
    nobody parsed is still a condition."""
    value = rule.get("condition")
    if value is None or value == "":
        return False
    if isinstance(value, (list, tuple)):
        return bool(value)
    return True


def _normalized_rule(rule: Any, where: str) -> dict[str, Any]:
    """One raw rule (fetch snake_case or REST camelCase) → the fold shape."""
    if not isinstance(rule, Mapping):
        raise _Undecidable(
            f"{where} is not an object ({type(rule).__name__}) — a rule "
            "nobody read could decide anything, so the effective state was "
            "not decided")
    values = rule.get("values")
    inner = values if isinstance(values, Mapping) else rule
    if values is not None and not isinstance(values, Mapping):
        raise _Undecidable(
            f"{where}.values is not an object ({type(values).__name__}) — the "
            "rule was not read and the effective state was not decided")
    return {
        "enforce": _enforce_of(rule, where),
        "allow_all": _flag_of(rule, where, "allow_all", "allowAll"),
        "deny_all": _flag_of(rule, where, "deny_all", "denyAll"),
        "allowed_values": _values_of(inner, where,
                                     "allowed_values", "allowedValues"),
        "denied_values": _values_of(inner, where,
                                    "denied_values", "deniedValues"),
        "condition": _condition_of(rule, where),
    }


def _estate_policy(record: Mapping[str, Any], node: str,
                   constraint: str) -> dict[str, Any]:
    """One captured ``org_policies`` record → the normalized fold shape."""
    where = f"the set-policy at {node} for {_PREFIX}{constraint}"
    raw = evidence.scalar(record, "rules", what=where, type=tuple, absent=())
    rules = tuple(_normalized_rule(rule, f"{where} rules[{i}]")
                  for i, rule in enumerate(raw))
    reset = record.get("reset")
    inherit = record.get("inherit_from_parent")
    return {"reset": reset is True, "inherit_from_parent": inherit is True,
            "rules": rules}


# -- the per-policy fold gates (A14-A19) ---------------------------------------


def _stated_key(rule: Mapping[str, Any], where: str) -> tuple[str, Any]:
    """Which ONE of the oneof value keys this normalized rule states (A16 on
    zero or more than one), and its payload."""
    stated: list[tuple[str, Any]] = []
    if rule["enforce"] is not None:
        stated.append(("enforce", rule["enforce"]))
    if rule["allow_all"] is True:
        stated.append(("allow_all", True))
    if rule["deny_all"] is True:
        stated.append(("deny_all", True))
    if rule["allowed_values"] or rule["denied_values"]:
        stated.append(("values", (rule["allowed_values"],
                                  rule["denied_values"])))
    if not stated:
        raise _Undecidable(
            f"{where} states nothing decidable (none of enforce, allowAll, "
            "denyAll or a non-empty values list) — the effective state was "
            "not decided")
    if len(stated) > 1:
        keys = ", ".join(key for key, _payload in stated)
        raise _Undecidable(
            f"{where} states more than one of the oneof value keys at once "
            f"({keys}) — which one decides is a guess this fold refuses, so "
            "the effective state was not decided")
    return stated[0]


def _policy_gates(policy: Mapping[str, Any], node: str, constraint: str) -> None:
    """The shape gates every encountered policy passes before either arm reads
    it: A15 (reset with rules present) and A14 (a condition anywhere)."""
    where = f"the set-policy at {node} for {_PREFIX}{constraint}"
    if policy["reset"] and policy["rules"]:
        raise _Undecidable(
            f"{where} sets reset=true AND carries {len(policy['rules'])} "
            "rule(s) — a reset policy carries no rules of its own, so this "
            "record is malformed and the effective state was not decided")
    for i, rule in enumerate(policy["rules"]):
        if rule["condition"]:
            raise _Undecidable(
                f"{where} rules[{i}] carries a condition — request-time facts "
                "are outside this fold's model, so the effective state was "
                "not decided")


def _local_bool(policy: Mapping[str, Any], node: str, constraint: str) -> bool:
    """One policy's boolean decision (A16/A17/A18/A19)."""
    where = f"the set-policy at {node} for {_PREFIX}{constraint}"
    if not policy["rules"]:
        raise _Undecidable(
            f"{where} records nothing (no rules, no reset, no "
            "inheritFromParent) — a record that records nothing decides "
            "nothing, so the effective state was not decided")
    enforces: set[bool] = set()
    for i, rule in enumerate(policy["rules"]):
        key, payload = _stated_key(rule, f"{where} rules[{i}]")
        if key != "enforce":
            raise _Undecidable(
                f"{where} rules[{i}] is list-shaped ({key}) although "
                f"{_PREFIX}{constraint} is declared boolean-typed — type "
                "confusion is never coerced, so the effective state was not "
                "decided")
        enforces.add(payload)
    if len(enforces) == 2:
        raise _Undecidable(
            f"{where} states enforce=true AND enforce=false in one policy — "
            "contradictory, so the effective state was not decided")
    return enforces.pop()


def _local_list(policy: Mapping[str, Any], node: str,
                constraint: str) -> dict[str, Any]:
    """One policy's list-value summary (A16/A17)."""
    where = f"the set-policy at {node} for {_PREFIX}{constraint}"
    summary: dict[str, Any] = {"allowed": set(), "denied": set(),
                               "allow_all": False, "deny_all": False}
    for i, rule in enumerate(policy["rules"]):
        key, payload = _stated_key(rule, f"{where} rules[{i}]")
        if key == "enforce":
            raise _Undecidable(
                f"{where} rules[{i}] is boolean-shaped (enforce) although "
                f"{_PREFIX}{constraint} is declared list-typed — type "
                "confusion is never coerced, so the effective state was not "
                "decided")
        if key == "allow_all":
            summary["allow_all"] = True
        elif key == "deny_all":
            summary["deny_all"] = True
        else:
            allowed, denied = payload
            summary["allowed"].update(allowed)
            summary["denied"].update(denied)
    return summary


# -- the two fold arms (D1-D10, MERGE-O1) --------------------------------------


def _effective_bool(chain: tuple[str, ...], pol: Callable, constraint: str,
                    record: Mapping[str, Any]) -> bool:
    """Nearest-set-wins over *chain* (root-first), reset restoring the managed
    default, ``inheritFromParent`` abstaining (unmodeled for booleans)."""
    for node in reversed(chain):
        policy = pol(node)
        if policy is None:
            continue
        _policy_gates(policy, node, constraint)
        if policy["inherit_from_parent"]:
            raise _Undecidable(
                f"the set-policy at {node} for {_PREFIX}{constraint} sets "
                "inheritFromParent=true on a boolean constraint — "
                "inheritance is not meaningful for booleans and is outside "
                "this fold's model, so the effective state was not decided")
        if policy["reset"]:
            return _default_bool(record, constraint)
        return _local_bool(policy, node, constraint)
    return _default_bool(record, constraint)


#: The lazy "managed default" sentinel of the list fold: its content is
#: resolved only if the walk ends on it, so an undecidable default abstains
#: only when it actually decides.
_DEFAULT = object()


def _effective_list(chain: tuple[str, ...], pol: Callable, constraint: str,
                    record: Mapping[str, Any]) -> dict[str, Any]:
    """Root-first replace/inherit-union fold of a list constraint."""
    state: Any = _DEFAULT

    def resolved(current: Any) -> dict[str, Any]:
        if current is _DEFAULT:
            return _default_list(record, constraint)
        return current

    for node in chain:
        policy = pol(node)
        if policy is None:
            continue
        _policy_gates(policy, node, constraint)
        if policy["reset"]:
            state = _DEFAULT
            continue
        if not policy["rules"]:
            if policy["inherit_from_parent"]:
                continue  # defers wholly to the parent
            raise _Undecidable(
                f"the set-policy at {node} for {_PREFIX}{constraint} records "
                "nothing (no rules, no reset, no inheritFromParent) — a "
                "record that records nothing decides nothing, so the "
                "effective state was not decided")
        local = _local_list(policy, node, constraint)
        if policy["inherit_from_parent"]:
            parent = resolved(state)
            state = {"allowed": parent["allowed"] | local["allowed"],
                     "denied": parent["denied"] | local["denied"],
                     "allow_all": parent["allow_all"] or local["allow_all"],
                     "deny_all": parent["deny_all"] or local["deny_all"]}
        else:
            state = local
    return resolved(state)


def _list_rows(state: Mapping[str, Any], node: str, constraint: str,
               address: str) -> list[dict[str, Any]]:
    """Row emission with read-time deny precedence (D7-D9, A21).

    ``deny_all`` suppresses every allow row; a value on both sides emits ONLY
    its deny row — soundness-critical, because an allow row for an effectively
    denied value would fabricate a refutation of "must not allow v".
    """
    if state["deny_all"] and state["allow_all"]:
        raise _Undecidable(
            f"the effective state of {_PREFIX}{constraint} at {node} folds to "
            "allValues ALLOW and DENY simultaneously — malformed, so the "
            "effective state was not decided")
    base: dict[str, Any] = {"node": node, "constraint": constraint}
    if address:
        base[WITNESS_ADDRESS_FIELD] = address
    rows: list[dict[str, Any]] = []
    if state["deny_all"]:
        rows.append({**base, "polarity": "deny", "value": "",
                     "all_values": True})
        return rows
    for value in sorted(state["denied"]):
        rows.append({**base, "polarity": "deny", "value": value,
                     "all_values": False})
    if state["allow_all"]:
        rows.append({**base, "polarity": "allow", "value": "",
                     "all_values": True})
    for value in sorted(state["allowed"] - state["denied"]):
        rows.append({**base, "polarity": "allow", "value": value,
                     "all_values": False})
    return rows


# -- the proposal overlay (A1-A6, A23-A25, MERGE-O1) ---------------------------


@dataclass(frozen=True)
class _Target:
    """One (node, constraint) the proposal determines: the canonical captured
    node, the prefix-stripped constraint, the normalized overlay policy, the
    proposing block's address ("" for a REST document), the declared value
    type and the constraints record the defaults come from."""

    node: str
    constraint: str
    policy: Mapping[str, Any]
    address: str
    value_type: str
    record: Mapping[str, Any]


def _resolve_node(table: Mapping[str, Any], node: str, where: str) -> str:
    """*node* canonicalized against the captured hierarchy (A6)."""
    canonical = _canonical_node(table, node)
    if canonical is None:
        raise _Undecidable(
            f"{where} names the node {node!r}, which is not in the captured "
            "resource_hierarchy — an unrecorded node has no chain to fold, so "
            "the effective state was not decided")
    return canonical


def _rest_overlay(document: Any, table: Mapping[str, Any]) -> list[tuple]:
    """→ ``[(node, constraint, policy, address)]`` for one REST org-policy
    document (v2 only: a v1 document names no node — A5)."""
    if not isinstance(document, Mapping):
        raise _Undecidable(
            "the org-policy document under review is not a JSON object — the "
            "effective state was not decided")
    resolved = _org_policy_constraint(document)
    if resolved is None:
        raise _Undecidable(
            "the org-policy document under review names no unambiguous "
            "constraint — the effective state was not decided")
    constraint_full, location = resolved
    node = _org_policy_node(document, location)
    if not node:
        raise _Undecidable(
            f"the org-policy document for {constraint_full} names no node (a "
            "v1 document's parent is the API call's, not the document's) — "
            "the effective state was not decided")
    where = f"the org-policy document for {constraint_full}"
    canonical = _resolve_node(table, node, where)
    spec = document.get("spec")
    if not isinstance(spec, Mapping):
        raise _Undecidable(
            f"{where} carries no readable 'spec' object — the effective "
            "state was not decided")
    raw_rules = spec.get("rules")
    if raw_rules is None:
        rules: tuple = ()
    elif isinstance(raw_rules, list):
        rules = tuple(_normalized_rule(rule, f"{where} spec.rules[{i}]")
                      for i, rule in enumerate(raw_rules))
    else:
        raise _Undecidable(
            f"{where} spec.rules is not an array "
            f"({type(raw_rules).__name__}) — the effective state was not "
            "decided")
    policy = {
        "reset": _bool_or_none(spec, "reset") is True,
        "inherit_from_parent": _bool_or_none(
            spec, "inheritFromParent", "inherit_from_parent") is True,
        "rules": rules,
    }
    return [(canonical, _short(constraint_full), policy, "")]


def _tf_flag(block: Mapping[str, Any], key: str, address: str) -> bool:
    """A terraform spec/rule boolean in either provider spelling (a JSON
    boolean or the "TRUE"/"FALSE" enum strings); absent reads as unstated."""
    raw = block.get(key)
    if raw is None:
        return False
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        value = tf_claims._TF_BOOLEANS.get(raw)
        if value is not None:
            return value
    raise _Undecidable(
        f"{_LABEL} {address!r} carries {key}={raw!r}, which is not a boolean "
        "— the effective state was not decided")


def _tf_oneof_flag(rule: Mapping[str, Any], key: str, address: str,
                   index: int) -> Optional[bool]:
    """A rule's allow_all/deny_all oneof flag: True states it, FALSE and
    absent state nothing (the provider's enum-string oneof)."""
    raw = rule.get(key)
    if raw is None:
        return None
    if isinstance(raw, bool):
        return True if raw else None
    if isinstance(raw, str):
        value = tf_claims._TF_BOOLEANS.get(raw)
        if value is not None:
            return True if value else None
    raise _Undecidable(
        f"{_LABEL} {address!r} spec.rules[{index}].{key}={raw!r} is not a "
        "boolean — the effective state was not decided")


def _tf_rule(rule: Any, address: str, index: int) -> dict[str, Any]:
    """One terraform rule block → the normalized fold shape (A23)."""
    where = f"{_LABEL} {address!r} spec.rules[{index}]"
    if not isinstance(rule, Mapping):
        raise _Undecidable(
            f"{where} is not an object — the effective state was not decided")
    enforce: Optional[bool] = None
    if rule.get("enforce") is not None:
        enforce = _tf_enforce(rule.get("enforce"), address, _LABEL)
    allowed: tuple[str, ...] = ()
    denied: tuple[str, ...] = ()
    raw_values = rule.get("values")
    if raw_values not in (None, []):
        block, _path = tf_claims._first_block(raw_values, "values")
        if block is None:
            raise _Undecidable(
                f"{where}.values is not a block — the effective state was "
                "not decided")
        allowed = _values_of(block, f"{where}.values", "allowed_values",
                             "allowedValues")
        denied = _values_of(block, f"{where}.values", "denied_values",
                            "deniedValues")
    raw_condition = rule.get("condition")
    condition = raw_condition not in (None, [])
    return {
        "enforce": enforce,
        "allow_all": _tf_oneof_flag(rule, "allow_all", address, index),
        "deny_all": _tf_oneof_flag(rule, "deny_all", address, index),
        "allowed_values": allowed,
        "denied_values": denied,
        "condition": condition,
    }


def _tf_node(values: Mapping[str, Any], address: str) -> str:
    """The node a plan's org-policy resource is set on (A5): the literal
    ``name`` prefix before ``/policies/``, cross-checked against a literal
    ``parent`` when the block states one."""
    name = values.get("name")
    if not isinstance(name, str) or name.count("/policies/") != 1:
        raise _Undecidable(
            f"{_LABEL} {address!r} states no literal name of the "
            "'<node>/policies/<constraint>' form (absent, unresolved or "
            "malformed) — which node it is set on was not decided, so the "
            "effective state was not decided")
    node = name.split("/policies/", 1)[0]
    parent = values.get("parent")
    if isinstance(parent, str) and parent and parent != node:
        raise _Undecidable(
            f"{_LABEL} {address!r} names two nodes for one policy: its name "
            f"prefix is {node!r} and its parent attribute is {parent!r} — "
            "the effective state was not decided")
    return node


def _tf_overlay(document: Any, table: Mapping[str, Any]) -> list[tuple]:
    """→ ``[(node, constraint, policy, address)]`` for a terraform plan
    (A2-A5, A23-A25)."""
    _plan_envelope(document)
    by_address = _plan_values(document)
    policies: dict[str, str] = {}
    for claim in tf_claims.terraform_plan_claims(document):
        if claim.kind != "constraint":
            continue
        matched = _CONSTRAINT_AT.match(claim.location)
        if matched is None:
            raise _Undecidable(
                f"the constraint claim at {claim.location!r} names no "
                "resource address this fold understands — the effective "
                "state was not decided")
        policies[matched.group("address")] = claim.value
    unclaimed = sorted(
        address for address in by_address
        if _ORG_POLICY_ADDRESS.match(address) and address not in policies)
    if unclaimed:
        raise _Undecidable(
            f"{_LABEL} resource(s) {', '.join(map(repr, unclaimed))} yielded "
            "no constraint claim — a policy whose constraint was not readable "
            "is a rule nobody read, so the effective state was not decided")
    if not policies:
        raise _no_tf_records(_LABEL)
    out: list[tuple] = []
    seen: dict[tuple[str, str], str] = {}
    for address in sorted(policies):
        values = _resource_values(address, by_address, _LABEL)
        node = _resolve_node(table, _tf_node(values, address),
                             f"{_LABEL} {address!r}")
        constraint = _short(policies[address])
        key = (node, constraint)
        if key in seen:
            raise _Undecidable(
                f"{_LABEL} resources {seen[key]!r} and {address!r} both "
                f"target {_PREFIX}{constraint} at {node} — which one wins is "
                "an apply-order accident this fold will not guess, so the "
                "effective state was not decided")
        seen[key] = address
        spec, _path = tf_claims._first_block(values.get("spec"), "spec")
        if spec is None:
            raise _Undecidable(
                f"{_LABEL} {address!r} carries no readable spec block — the "
                "effective state was not decided")
        raw_rules = spec.get("rules")
        if raw_rules is None:
            rules: tuple = ()
        elif isinstance(raw_rules, list):
            rules = tuple(_tf_rule(rule, address, i)
                          for i, rule in enumerate(raw_rules))
        else:
            raise _Undecidable(
                f"{_LABEL} {address!r} spec.rules is not an array "
                f"({type(raw_rules).__name__}) — the effective state was not "
                "decided")
        policy = {
            "reset": _tf_flag(spec, "reset", address),
            "inherit_from_parent": _tf_flag(spec, "inherit_from_parent",
                                            address),
            "rules": rules,
        }
        out.append((node, constraint, policy, address))
    return out


def _targets(ctx: Any, table: Mapping[str, Any]) -> list[_Target]:
    """Every (node, constraint) the proposal determines, value-typed (A13)."""
    if ctx.document is None:
        raise _Undecidable(
            "no document under review — the effective-state rule was not "
            "evaluated")
    if ctx.document_kind == "tf_plan":
        entries = _tf_overlay(ctx.document, table)
    elif ctx.document_kind == "org_policy":
        entries = _rest_overlay(ctx.document, table)
    else:
        raise _Undecidable(
            "the document under review is not an org-policy document or a "
            "terraform plan — the effective-state rule was not evaluated")
    targets = []
    for node, constraint, policy, address in entries:
        record = _constraint_record(ctx.snapshot, constraint)
        targets.append(_Target(node=node, constraint=constraint,
                               policy=policy, address=address,
                               value_type=record["value_type"], record=record))
    return targets


# -- the shared fold entry -----------------------------------------------------


def _pol(snapshot: Any, overlay: Mapping[tuple[str, str], Mapping[str, Any]],
         constraint: str) -> Callable:
    """The per-node policy resolver: the overlay REPLACES the captured record
    at its own (node, constraint) — MERGE-O1 — and every other node reads the
    snapshot's set-policy."""
    def resolve(node: str) -> Optional[Mapping[str, Any]]:
        entry = overlay.get((node, constraint))
        if entry is not None:
            return entry
        record = snapshot.org_policy(node, f"{_PREFIX}{constraint}")
        if record is UNKNOWN:
            raise _Undecidable(
                "snapshot did not capture org_policies — the effective state "
                "was not decided")
        if record is None:
            return None
        return _estate_policy(record, node, constraint)
    return resolve


def _estate_gates(snapshot: Any) -> Mapping[str, Any]:
    """The four estate refusals, in the design's order (A8, A7, A9, A10);
    returns the captured hierarchy table."""
    _estate_table(snapshot, "org_policies")
    table = _estate_table(snapshot, "resource_hierarchy")
    _require_complete(snapshot, "org_policies")
    _require_complete(snapshot, "resource_hierarchy")
    return table


def _bool_rows(target: _Target, snapshot: Any, table: Mapping[str, Any],
               overlay: Mapping) -> list[dict[str, Any]]:
    """The effective_org_policy_bool rows one boolean target determines."""
    pol = _pol(snapshot, overlay, target.constraint)
    rows = []
    for node in _universe(table, target.node):
        decided = _effective_bool(_chain(table, node), pol, target.constraint,
                                  target.record)
        row: dict[str, Any] = {"node": node, "constraint": target.constraint,
                               "enforce": decided}
        if target.address:
            row[WITNESS_ADDRESS_FIELD] = target.address
        rows.append(row)
    return rows


def _values_rows(target: _Target, snapshot: Any, table: Mapping[str, Any],
                 overlay: Mapping) -> list[dict[str, Any]]:
    """The effective_org_policy_values rows one list target determines."""
    pol = _pol(snapshot, overlay, target.constraint)
    rows: list[dict[str, Any]] = []
    for node in _universe(table, target.node):
        state = _effective_list(_chain(table, node), pol, target.constraint,
                                target.record)
        rows.extend(_list_rows(state, node, target.constraint, target.address))
    return rows


#: Declared field order of the two collections, restated here only for the
#: deterministic sort (the specs themselves live in ``sec_domains``).
_BOOL_FIELDS = {"node": "Str", "constraint": "Str", "enforce": "Bool"}
_VALUES_FIELDS = {"node": "Str", "constraint": "Str", "polarity": "Str",
                  "value": "Str", "all_values": "Bool"}


def _effective_records(ctx: RuleContext, want: str, fields: Mapping[str, str],
                       build: Callable) -> tuple:
    """The shared extractor body: estate gates, targets, the type split and
    the per-target fold."""
    table = _estate_gates(ctx.snapshot)
    targets = _targets(ctx, table)
    overlay = {(t.node, t.constraint): t.policy for t in targets}
    matching = [t for t in targets if t.value_type == want]
    if not matching:
        raise _Undecidable(
            f"the proposal's org-policy resources set no {want}-typed "
            "constraint — the rule was not evaluated over any record")
    rows: list[dict[str, Any]] = []
    for target in matching:
        rows.extend(build(target, ctx.snapshot, table, overlay))
    return _sorted(rows, fields), None


def effective_org_policy_bool_records(ctx: RuleContext) -> tuple:
    """Instance extractor for the ``effective_org_policy_bool`` collection."""
    return _effective_records(ctx, "boolean", _BOOL_FIELDS, _bool_rows)


def effective_org_policy_values_records(ctx: RuleContext) -> tuple:
    """Instance extractor for the ``effective_org_policy_values`` collection."""
    return _effective_records(ctx, "list", _VALUES_FIELDS, _values_rows)


# -- the built-in document check (inert / blast radius) ------------------------


def _engages(ctx: CheckContext) -> bool:
    """Whether this document carries org-policy content this check owns.

    Deliberately SILENT (not abstaining) where a louder abstention already
    speaks for the document: an org-policy document naming no unambiguous
    constraint gets preflight's zero-claims honesty verdict, and an unreadable
    plan gets the envelope abstention — a second, vaguer ``unverified`` here
    would be the same ignorance reported twice.
    """
    if ctx.document_kind == "org_policy":
        return (isinstance(ctx.document, Mapping)
                and _org_policy_constraint(ctx.document) is not None)
    if ctx.document_kind != "tf_plan":
        return False
    if not isinstance(ctx.document, Mapping):
        return False
    # Engagement is read off the claims PREFLIGHT extracted, never off a
    # second walk of the plan: a checkout (or a simulated one) whose tf-plan
    # extractor is absent hands this check an empty claim tuple, and the
    # "plan detected but nothing extracted" abstention is preflight's own.
    # A google_org_policy_policy resource whose constraint was unreadable
    # still carries its resource_type_ref, so the census abstention (a policy
    # nobody read) is reachable rather than silently skipped.
    for claim in ctx.claims:
        kind = getattr(claim, "kind", None)
        if kind == "constraint":
            return True
        if kind == "resource_type_ref" and \
                getattr(claim, "value", None) == "google_org_policy_policy":
            return True
    return False


def _bool_summary(before: bool, after: bool) -> str:
    return f"enforce {str(before).lower()} -> {str(after).lower()}"


def _list_delta(before: Mapping[str, Any], after: Mapping[str, Any]) -> str:
    """A one-line description of how a list constraint's effective state moved
    at one node."""
    parts: list[str] = []
    for side in ("allowed", "denied"):
        added = sorted(after[side] - before[side])
        removed = sorted(before[side] - after[side])
        if added:
            parts.append(f"{side} gains {', '.join(added)}")
        if removed:
            parts.append(f"{side} loses {', '.join(removed)}")
    for flag, phrase_on, phrase_off in (
            ("allow_all", "starts allowing every value",
             "stops allowing every value"),
            ("deny_all", "starts denying every value",
             "stops denying every value")):
        if after[flag] and not before[flag]:
            parts.append(phrase_on)
        if before[flag] and not after[flag]:
            parts.append(phrase_off)
    return "; ".join(parts) or "unchanged"


def _canonical_list(state: Mapping[str, Any]) -> tuple:
    """A list fold state as a comparable value (deny precedence applied)."""
    if state["deny_all"]:
        return (True, False, (), ())
    return (False, state["allow_all"], tuple(sorted(state["denied"])),
            tuple(sorted(state["allowed"] - state["denied"])))


def _target_verdicts(target: _Target, ctx: CheckContext,
                     table: Mapping[str, Any]) -> list[Verdict]:
    """The BEFORE/AFTER comparison for one (node, constraint) target."""
    where = target.address or "the org-policy document under review"
    full = f"{_PREFIX}{target.constraint}"
    overlay = {(target.node, target.constraint): target.policy}
    with_change = _pol(ctx.snapshot, overlay, target.constraint)
    without_change = _pol(ctx.snapshot, {}, target.constraint)
    universe = _universe(table, target.node)
    evidence.examined(len(universe), what=f"the effective fold of {full} "
                                          f"under {target.node}")
    changed: list[str] = []
    for node in universe:
        chain = _chain(table, node)
        if target.value_type == "boolean":
            before = _effective_bool(chain, without_change, target.constraint,
                                     target.record)
            after = _effective_bool(chain, with_change, target.constraint,
                                    target.record)
            if before != after:
                changed.append(f"{node}: {_bool_summary(before, after)}")
        else:
            before_state = _effective_list(chain, without_change,
                                           target.constraint, target.record)
            after_state = _effective_list(chain, with_change,
                                          target.constraint, target.record)
            if _canonical_list(before_state) != _canonical_list(after_state):
                changed.append(
                    f"{node}: {_list_delta(before_state, after_state)}")
    if not changed:
        maskers = sorted(
            node for node in universe
            if node != target.node
            and ctx.snapshot.org_policy(node, full) is not None)
        masked = (f"; the nearer set-policies at {', '.join(maskers)} keep "
                  f"deciding below it" if maskers else "")
        return [Verdict(
            "grounded", VERDICT_KIND, full, 0,
            f"{where}: this change is INERT — it restates the effective state "
            f"of {full} already in force at {target.node}, and the effective "
            f"state is unchanged at every node it governs "
            f"({len(universe)} node(s)){masked}")]
    return [Verdict(
        "grounded", VERDICT_KIND, full, 0,
        f"{where}: this change alters the effective state of {full} at "
        f"{len(changed)} of the {len(universe)} node(s) it governs — "
        + "; ".join(changed))]


def check_org_effective(ctx: CheckContext) -> list[Verdict]:
    """The inert / blast-radius finding: fold BEFORE (snapshot only) and AFTER
    (proposal overlay applied) over ``{node} ∪ descendants(node)`` per
    proposal constraint, and report which nodes' effective state changes.

    Informational: both findings are ``grounded`` (nothing here blocks — the
    blocking judgments belong to promises over the effective collections and
    to ``org_checks``' own checks), and every fold this check needs that
    abstains is one ``unverified`` naming its cause, never a silent skip.
    """
    if not _engages(ctx):
        return []
    rule_ctx = RuleContext(snapshot=ctx.snapshot, document=ctx.document,
                           document_kind=ctx.document_kind, source=ctx.source)
    try:
        table = _estate_gates(ctx.snapshot)
        targets = _targets(rule_ctx, table)
    except _Undecidable as exc:
        return [Verdict(
            "unverified", VERDICT_KIND, ctx.source, 0,
            f"the effective org-policy state of this change was not decided: "
            f"{exc}")]
    verdicts: list[Verdict] = []
    for target in targets:
        full = f"{_PREFIX}{target.constraint}"
        try:
            verdicts.extend(_target_verdicts(target, ctx, table))
        except _Undecidable as exc:
            verdicts.append(Verdict(
                "unverified", VERDICT_KIND, full, 0,
                f"the effective state {full} determines at and below "
                f"{target.node} was not decided: {exc}"))
    return verdicts


#: Registry hooks (see :mod:`gcp_grounding.registry`).
DOCUMENT_CHECKS = (check_org_effective,)
