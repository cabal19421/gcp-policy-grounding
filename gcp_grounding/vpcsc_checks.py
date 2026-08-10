"""VPC Service Controls checks: protection removal and ingress/egress widening.

Two entry points, both registered through :mod:`gcp_grounding.registry`:

``check_perimeter_estate`` (``DOCUMENT_CHECKS``)
    runs on every document, and does its work only for the perimeters a
    document actually proposes — the ``perimeter_config`` claims
    :mod:`gcp_grounding.vpcsc_claims` extracts, so a REST Access Context
    Manager document and its terraform spelling are checked identically.
``check_perimeter_pair`` (``PAIR_CHECKS["vpc_sc_perimeter"]``)
    runs instead when a ``--baseline`` document was supplied.

BASELINE RESOLUTION. The *old* perimeter is the baseline document when one was
given, otherwise :meth:`~gcp_grounding.knowledge.GcpSnapshot.vpc_sc_perimeter`.
Both accessor answers are compared with ``is UNKNOWN`` / ``is None`` and never
truth-tested — an uncaptured ``vpc_sc_perimeters`` category and an absent name
both mean *the previous state is unknown*, which is exactly one ``unverified``
per proposed perimeter, never a silent pass.

CHECK 1 — PROTECTION REMOVAL is plain set algebra over the old and new configs
(projects removed from ``resources``, services removed from
``restricted_services``, a ``PERIMETER_TYPE_REGULAR`` → ``PERIMETER_TYPE_BRIDGE``
demotion, since a bridge enforces nothing). Like
:func:`~gcp_grounding.constraints.check_constraint_value` it needs no solver, so
it decides identically with or without z3.

CHECK 2 — EGRESS / INGRESS WIDENING mirrors
:func:`~gcp_grounding.constraints.check_policy_subset`'s polarity. Each
direction is modelled as a product over four z3 String axes — identity,
service, method, resource — one policy being the conjunction of the four
per-axis ``Or``s, a wildcard (``"*"``, ``ANY_IDENTITY``, ``ANY_USER_ACCOUNT``,
``ANY_SERVICE_ACCOUNT``, or an absent/empty list, all meaning "all") being
``BoolVal(True)``, and the empty policy list being ``BoolVal(False)``. The
assertion is ``And(allowed(new), Not(allowed(old)))``: unsat → ``grounded``,
sat → ``contradicted`` with the model's four axis values as the witness,
``unknown`` or an absent z3 → ``unverified``.

DRY-RUN HONESTY. A proposal that writes only ``spec`` with
``use_explicit_dry_run_spec: true`` changes no enforcement; both checks then run
against ``spec`` instead of ``status`` and say so in every message. Treating
such a change as enforced would be a false verdict in both directions.

THE EMPTY-versus-ABSENT ASYMMETRY. An old policy list has THREE readings, not
two. *Empty* means "no egress permitted", so any new policy widens. *Absent* is
indistinguishable offline from a list that was captured empty, so when the
proposal adds policies and the old key is absent this abstains naming the
ambiguity rather than guessing. *Present but not a list* is the third:
normalization folds it to ``[]``, which reads as "none permitted" and would mint
a widening out of an old side nobody could read, so it abstains too. The same
distinction governs CHECK 1's two set-valued fields: an old ``resources`` or
``restricted_services`` that is ABSENT (which the real API does for an empty
list) or present with a shape that is not a list is differenced against nothing,
so the removal set comes out empty and the check announces that a proposal
EMPTYING the perimeter removes nothing. Both fields therefore run through the
same key-presence guard as the policy lists — read off the RAW old document or
estate record, since normalization has already replaced anything unreadable with
an empty list — and an unreadable field is one ``unverified`` naming the side,
the field and the type found instead of a difference nobody computed. And a
``grounded`` may not claim protection over an EMPTY kept-set: a perimeter that
keeps no project, or no restricted service, protects nothing, so "the change
removes nothing" is an abstention there, not a pass.

DIRECTIONAL READABILITY. Mapping an absent or unreadable axis to "all values" is
safe on the NEW side — over-approximating what a proposal permits can only
over-report a widening — and unsound on the OLD side, where over-approximating
the previous permission set can only HIDE one. :func:`_axes` therefore gives
:func:`_axis_pred` an explicit TRI-STATE input (:data:`WILDCARD`,
:data:`LITERALS`, :data:`UNREADABLE`), and an UNREADABLE axis on the OLD side
ABORTS that direction with one ``unverified`` naming the perimeter, the side,
the direction and the axis, rather than being silently widened to everything.
Malformed policy entries that are dropped rather than aborted on are logged at
debug, so no drop is silent.

Service-vocabulary questions ("is ``bigquery.googleapis.com`` a real restricted
service?") are the ``restricted_service_ref`` existence claims' job and are not
duplicated here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping

from .constraints import _z3_module
from .core.log import get_logger
from .core.report import Verdict
from .knowledge import UNKNOWN
from .vpcsc_claims import _get, _normalize_perimeter, _obj

if TYPE_CHECKING:  # annotations only — no runtime import weight, no cycle
    from .registry import CheckContext

logger = get_logger(__name__)

__all__ = ["DOCUMENT_CHECKS", "PAIR_CHECKS", "WILDCARD", "LITERALS", "UNREADABLE",
           "check_perimeter_estate", "check_perimeter_pair"]

#: ``identity_type`` values that select every identity, so the identity axis is
#: unconstrained (``BoolVal(True)``) whatever ``identities`` holds.
_ANY_IDENTITY_TYPES = ("ANY_IDENTITY", "ANY_USER_ACCOUNT", "ANY_SERVICE_ACCOUNT")

_WILDCARD = "*"
_REGULAR = "PERIMETER_TYPE_REGULAR"
_BRIDGE = "PERIMETER_TYPE_BRIDGE"
_DIRECTIONS = ("ingress", "egress")

#: The two set-valued fields CHECK 1 differences, each with the noun its message
#: counts in. Both are guarded for key presence on the OLD side.
_PROTECTION_FIELDS = (("resources", "project"),
                      ("restricted_services", "restricted service"))

#: The four axes of the widening product, in the order the witness reads them.
_AXES = ("identity", "service", "method", "resource")

#: The three states an axis input can be in — the explicit tri-state the
#: directional-readability rule needs. ``WILDCARD`` is an axis positively
#: declared unconstrained (an ``ANY_*`` identity type); ``LITERALS`` is a
#: well-formed, possibly EMPTY tuple of literals (empty means the axis declares
#: no constraint, which VPC-SC reads as every value); ``UNREADABLE`` is a
#: PRESENT value whose shape could not be read at all, which is neither.
WILDCARD = "wildcard"
LITERALS = "literals"
UNREADABLE = "unreadable"

#: Appended to every message of a dry-run-only comparison — the reader must
#: never mistake a `spec` diff for an enforcement change.
_DRY_RUN_NOTE = " (dry-run only — this change does not alter enforcement)"


# -- shapes -------------------------------------------------------------------


def _plain(value: Any) -> Any:
    """Snapshot records are tuple-frozen (``knowledge._tuplify``); the
    normalizer reads JSON lists. Thaw tuples back to lists so an estate record
    and a baseline document normalize through exactly the same code."""
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def _proposed(ctx: "CheckContext") -> list[tuple[str, str, dict[str, Any]]]:
    """``(name, location, normalized perimeter)`` per perimeter the document
    proposes — read off the ``perimeter_config`` claims, so this works for a
    REST document and a terraform plan alike."""
    out: list[tuple[str, str, dict[str, Any]]] = []
    for claim in ctx.claims:
        if getattr(claim, "kind", None) != "perimeter_config":
            continue
        fields = claim.fields()
        out.append((fields.get("name") or claim.value, claim.location, fields))
    return out


def _key_present(raw_perimeter: Any, side: str, direction: str) -> bool:
    """Whether the *old* document/record actually carries
    ``<side>.<direction>_policies``. An absent key and a captured-empty list are
    different claims about the world and only the latter is decidable."""
    config = _obj(_get(raw_perimeter, side))
    if config is None:
        return False
    return _get(config, f"{direction}_policies") is not None


def _unreadable_field(raw_perimeter: Any, side: str, field: str) -> str | None:
    """Why the OLD side's *field* cannot be differenced, or None.

    The same absent-versus-empty guard :func:`_key_present` applies to the policy
    lists, over the two set-valued protection fields — and read off the RAW
    document or estate record, because the normalized config has already turned
    both an absent key and an unreadable value into ``[]``, which differences
    against anything to nothing.
    """
    config = _obj(_get(raw_perimeter, side))
    if config is None:
        return f"there is no readable '{side}' block to read {field!r} from"
    value = _get(config, field)
    if value is None:
        return (f"'{side}.{field}' is absent, and an absent list is "
                f"indistinguishable offline from one captured empty")
    if not isinstance(value, list):
        return f"'{side}.{field}' is {type(value).__name__}, not a list"
    return None


def _names(values) -> list[str]:
    return sorted({v for v in values or [] if isinstance(v, str)})


# -- the comparison -----------------------------------------------------------


def _compare(new: Mapping[str, Any], old: Mapping[str, Any], old_raw: Any,
             name: str, location: str, ctx: "CheckContext") -> list[Verdict]:
    """Every verdict one (old, new) perimeter pair produces."""
    verdicts: list[Verdict] = []
    dry_run = _is_dry_run(new)
    side = "spec" if dry_run else "status"
    note = _DRY_RUN_NOTE if dry_run else ""
    if dry_run:
        verdicts.append(Verdict(
            "grounded", "vpcsc_dry_run", name, 0,
            f"{location}: {name} writes only 'spec' with "
            f"use_explicit_dry_run_spec=true: dry-run only — this change does "
            f"not alter enforcement; protection and widening are compared "
            f"against 'spec', not 'status'"))
    new_config = new.get(side)
    old_config = old.get(side)
    verdicts.extend(_check_protection(new, old, new_config, old_config, old_raw,
                                      name, location, side, note))
    for direction in _DIRECTIONS:
        verdicts.extend(_check_widening(direction, new_config, old_raw,
                                        name, location, side, note, ctx))
    return verdicts


def _is_dry_run(new: Mapping[str, Any]) -> bool:
    """A proposal that writes only ``spec`` and flags it dry-run."""
    return (new.get("use_explicit_dry_run_spec") is True
            and new.get("status") is None and new.get("spec") is not None)


def _check_protection(new: Mapping[str, Any], old: Mapping[str, Any],
                      new_config: Any, old_config: Any, old_raw: Any, name: str,
                      location: str, side: str, note: str) -> list[Verdict]:
    """CHECK 1: does the change take anything out from behind the perimeter?
    Pure set algebra — no solver, so this decides on every backend.

    *old_raw* is the un-normalized old document or estate record: each of the two
    set-valued fields is differenced only when the RAW old side actually carries
    it as a list, because normalization has already folded an absent or
    wrong-shaped value into ``[]``, which removes nothing from anything.
    """
    if old_config is None:
        return [Verdict("unverified", "vpcsc_protection", name, 0,
                        f"{location}: the previous {name} has no '{side}' block, so "
                        f"there is nothing to compare — protection removal was not "
                        f"decided{note}")]
    if new_config is None:
        return [Verdict("unverified", "vpcsc_protection", name, 0,
                        f"{location}: the proposal has no '{side}' block, so whether it "
                        f"clears or leaves the previous one is not decidable offline — "
                        f"protection removal was not decided{note}")]
    findings: list[Verdict] = []
    abstentions: list[Verdict] = []
    for field, noun in _PROTECTION_FIELDS:
        unreadable = _unreadable_field(old_raw, side, field)
        if unreadable is not None:
            logger.debug("vpcsc: %s not differenced on %s: %s", field, name, unreadable)
            abstentions.append(Verdict(
                "unverified", "vpcsc_protection", name, 0,
                f"{location}: the previous {name}'s {field!r} could not be read "
                f"({unreadable}), so it was not differenced against the proposal's — "
                f"whether the change removes any {noun} from perimeter {name} was not "
                f"decided{note}"))
            continue
        removed = _names(set(_names(old_config.get(field)))
                         - set(_names(new_config.get(field))))
        if removed:
            findings.append(Verdict(
                "contradicted", "vpcsc_protection", name, 0,
                f"{location}: the change removes {len(removed)} {noun}(s) from "
                f"perimeter {name}: {', '.join(removed)} — they lose VPC-SC "
                f"protection{note}"))
    if old.get("perimeter_type") == _REGULAR and new.get("perimeter_type") == _BRIDGE:
        findings.append(Verdict(
            "contradicted", "vpcsc_protection", name, 0,
            f"{location}: perimeter {name} changes from {_REGULAR} to {_BRIDGE} — "
            f"a bridge enforces nothing, so every project in it loses VPC-SC "
            f"protection{note}"))
    if findings or abstentions:
        # A field nobody could read never becomes a clean pass: the abstentions
        # travel with whatever the readable fields did find, and never alongside
        # a "removes nothing" that was only true of the fields that were read.
        return findings + abstentions
    kept_resources = _names(new_config.get("resources"))
    kept_services = _names(new_config.get("restricted_services"))
    if not kept_resources or not kept_services:
        empty = " and ".join(
            label for label, kept in (("no project", kept_resources),
                                      ("no restricted service", kept_services))
            if not kept)
        return [Verdict("unverified", "vpcsc_protection", name, 0,
                        f"{location}: the change removes nothing from perimeter {name}, "
                        f"but the perimeter it leaves behind keeps {empty} — a perimeter "
                        f"over an empty kept-set protects nothing, so this is an "
                        f"abstention rather than a statement that {name} still protects "
                        f"anything{note}")]
    return [Verdict("grounded", "vpcsc_protection", name, 0,
                    f"{location}: the change removes nothing from perimeter {name} — "
                    f"it still protects {len(kept_resources)} project(s) "
                    f"({', '.join(kept_resources)}) across "
                    f"{len(kept_services)} restricted service(s) "
                    f"({', '.join(kept_services)}){note}")]


# -- CHECK 2: widening (z3, check_policy_subset's polarity) -------------------


@dataclass(frozen=True)
class _Axis:
    """One axis of one policy, tri-stated.

    *detail* is set on :data:`UNREADABLE` only and names the offending field and
    the type found — "could not read the axis" is not actionable, "'identities'
    is str, not a list" is.
    """

    state: str
    literals: tuple[str, ...] = ()
    detail: str = ""


def _policies(config: Any, direction: str) -> list[Mapping[str, Any]]:
    """The proposal's ingress/egress policy objects, malformed entries dropped.

    Dropping is only ever applied to the NEW side and to old entries whose whole
    object is unreadable — never to an old AXIS, which
    :func:`_first_unreadable_axis` aborts on. Every drop is logged.
    """
    declared = _get(config, f"{direction}_policies")
    if not isinstance(declared, list):
        return []
    return _readable_policies(declared, direction, "proposed")


def _readable_policies(declared: list, direction: str,
                       whose: str) -> list[Mapping[str, Any]]:
    kept: list[Mapping[str, Any]] = []
    for i, policy in enumerate(declared):
        if isinstance(policy, Mapping):
            kept.append(policy)
        else:
            logger.debug("vpcsc: dropped malformed %s %s policy [%d]: %s, not an "
                         "object", whose, direction, i, type(policy).__name__)
    return kept


def _old_policies(raw_perimeter: Any, side: str,
                  direction: str) -> tuple[list[Mapping[str, Any]], str | None]:
    """The OLD side's RAW policy objects, and why they could not be read.

    Raw, not normalized: :func:`~gcp_grounding.vpcsc_claims._normalize_config`
    has already replaced every unreadable field with an empty list, and on the
    old side that substitution can only shrink the previous permission set —
    which can only HIDE a widening.
    """
    config = _obj(_get(raw_perimeter, side))
    declared = _get(config, f"{direction}_policies")
    if not isinstance(declared, list):
        return [], (f"'{side}.{direction}_policies' is "
                    f"{type(declared).__name__}, not a list")
    return _readable_policies(declared, direction, "previous"), None


# -- the tri-state axis inputs ------------------------------------------------


def _literals(container: Any, key: str) -> _Axis:
    """One axis list as a tri-state.

    An ABSENT key is ``LITERALS(())`` — the axis declares no constraint, which
    :func:`_axis_pred` reads as every value, exactly as before. A PRESENT value
    that is not a list of strings is :data:`UNREADABLE`, which is the state the
    old code had no way to express.
    """
    value = _get(container, key)
    if value is None:
        return _Axis(LITERALS)
    if not isinstance(value, list):
        return _Axis(UNREADABLE,
                     detail=f"{key!r} is {type(value).__name__}, not a list")
    for i, item in enumerate(value):
        if not isinstance(item, str):
            return _Axis(UNREADABLE,
                         detail=f"{key}[{i}] is {type(item).__name__}, not a string")
    return _Axis(LITERALS, tuple(sorted(set(value))))


def _union(first: _Axis, second: _Axis) -> _Axis:
    """The resource axis: ``resources`` ∪ (egress only) ``external_resources``."""
    for axis in (first, second):
        if axis.state == UNREADABLE:
            return axis
    if WILDCARD in (first.state, second.state):
        return _Axis(WILDCARD)
    return _Axis(LITERALS, tuple(sorted(set(first.literals + second.literals))))


def _identity_axis(frm: Any, bad: str | None) -> _Axis:
    if bad is not None:
        return _Axis(UNREADABLE, detail=bad)
    identity_type = _get(frm, "identity_type")
    if identity_type in _ANY_IDENTITY_TYPES:
        return _Axis(WILDCARD)
    if identity_type is not None and not isinstance(identity_type, str):
        return _Axis(UNREADABLE,
                     detail=f"'identity_type' is {type(identity_type).__name__}, "
                            f"not a string")
    return _literals(frm, "identities")


def _selector_literals(operation: Mapping[str, Any], index: int,
                       out: list[str]) -> str | None:
    """Append one operation's method/permission literals to *out*; the reason
    they could not be read, or None."""
    selectors = _get(operation, "method_selectors")
    if selectors is None:
        return None
    if not isinstance(selectors, list):
        return (f"operations[{index}].method_selectors is "
                f"{type(selectors).__name__}, not a list")
    for j, selector in enumerate(selectors):
        if not isinstance(selector, Mapping):
            return (f"operations[{index}].method_selectors[{j}] is "
                    f"{type(selector).__name__}, not an object")
        method = _get(selector, "method")
        permission = _get(selector, "permission")
        chosen = method if isinstance(method, str) else permission
        if isinstance(chosen, str):
            out.append(chosen)
        elif method is not None or permission is not None:
            return (f"operations[{index}].method_selectors[{j}] declares no "
                    f"readable 'method' or 'permission' string")
    return None


def _operation_axes(to: Any, bad: str | None) -> tuple[_Axis, _Axis]:
    """The service and method axes, both read off ``operations``."""
    if bad is not None:
        return _Axis(UNREADABLE, detail=bad), _Axis(UNREADABLE, detail=bad)
    operations = _get(to, "operations")
    if operations is None:
        return _Axis(LITERALS), _Axis(LITERALS)
    if not isinstance(operations, list):
        why = f"'operations' is {type(operations).__name__}, not a list"
        return _Axis(UNREADABLE, detail=why), _Axis(UNREADABLE, detail=why)
    services: list[str] = []
    methods: list[str] = []
    service_bad = method_bad = None
    for i, operation in enumerate(operations):
        if not isinstance(operation, Mapping):
            why = f"operations[{i}] is {type(operation).__name__}, not an object"
            service_bad = service_bad or why
            method_bad = method_bad or why
            continue
        service_name = _get(operation, "service_name")
        if isinstance(service_name, str):
            services.append(service_name)
        elif service_name is not None:
            service_bad = service_bad or (
                f"operations[{i}].service_name is "
                f"{type(service_name).__name__}, not a string")
        method_bad = method_bad or _selector_literals(operation, i, methods)
    service = (_Axis(UNREADABLE, detail=service_bad) if service_bad
               else _Axis(LITERALS, tuple(sorted(set(services)))))
    method = (_Axis(UNREADABLE, detail=method_bad) if method_bad
              else _Axis(LITERALS, tuple(sorted(set(methods)))))
    return service, method


def _block(policy: Mapping[str, Any], key: str) -> tuple[Any, str | None]:
    """A nested single object as ``(block, why_unreadable)``. An ABSENT key is
    ``(None, None)`` — nothing declared, which every axis below reads as no
    constraint."""
    value = _get(policy, key)
    if value is None:
        return None, None
    block = _obj(value)
    if block is None:
        return None, f"{key!r} is {type(value).__name__}, not an object"
    return block, None


def _axes(policy: Mapping[str, Any], direction: str) -> dict[str, _Axis]:
    """The four tri-stated axes of one ingress/egress policy.

    Reads through :func:`~gcp_grounding.vpcsc_claims._get`, so the SAME code
    runs over a raw REST document (camelCase), a raw terraform/estate record
    (snake_case) and the normalized policy the claim payload carries. Only the
    treatment of :data:`UNREADABLE` differs between the two sides, and that
    difference lives at the call sites, where it is visible.
    """
    frm, frm_bad = _block(policy, f"{direction}_from")
    to, to_bad = _block(policy, f"{direction}_to")
    service, method = _operation_axes(to, to_bad)
    resource = (_Axis(UNREADABLE, detail=to_bad) if to_bad
                else _union(_literals(to, "resources"),
                            _literals(to, "external_resources")))
    return {"identity": _identity_axis(frm, frm_bad), "service": service,
            "method": method, "resource": resource}


def _first_unreadable_axis(policies: list[dict[str, _Axis]]) -> tuple[str, str] | None:
    """The first ``(axis, detail)`` no side could read, in :data:`_AXES` order."""
    for axes in policies:
        for axis in _AXES:
            if axes[axis].state == UNREADABLE:
                return axis, axes[axis].detail
    return None


# -- the z3 encoding ----------------------------------------------------------


def _axis_pred(z3, var, axis: _Axis, *, unreadable_is_any: bool):
    """``Or(var == v for v in literals)`` — or ``True`` when the axis is
    unconstrained: a ``"*"`` literal, an explicit :data:`WILDCARD`, or an
    absent/empty list, all of which mean *every* value on this axis.

    An :data:`UNREADABLE` axis is "every value" ONLY where *unreadable_is_any*
    says so, which is the NEW side: over-approximating what a proposal permits
    can only over-report a widening. The OLD side never reaches here unreadable
    — :func:`_check_widening` aborts that direction first — because
    over-approximating the PREVIOUS permission set can only hide one.
    """
    if axis.state == UNREADABLE:
        if not unreadable_is_any:
            raise ValueError(
                f"an unreadable axis reached the old side's predicate "
                f"({axis.detail}) — that direction must abstain instead")
        return z3.BoolVal(True)
    if axis.state == WILDCARD or not axis.literals or _WILDCARD in axis.literals:
        return z3.BoolVal(True)
    return z3.Or([var == z3.StringVal(v) for v in axis.literals])


def _policy_pred(z3, axis_vars: Mapping[str, Any], axes: Mapping[str, _Axis], *,
                 unreadable_is_any: bool):
    """One ingress/egress policy as the product of its four axes."""
    return z3.And([_axis_pred(z3, axis_vars[axis], axes[axis],
                              unreadable_is_any=unreadable_is_any)
                   for axis in _AXES])


def _allowed(z3, axis_vars: Mapping[str, Any], policies: list[dict[str, _Axis]], *,
             unreadable_is_any: bool):
    """``Or`` over the policies — and ``BoolVal(False)`` for the empty list,
    which permits nothing."""
    if not policies:
        return z3.BoolVal(False)
    return z3.Or([_policy_pred(z3, axis_vars, axes,
                               unreadable_is_any=unreadable_is_any)
                  for axes in policies])


def _check_widening(direction: str, new_config: Any, old_raw: Any,
                    name: str, location: str, side: str, note: str,
                    ctx: "CheckContext") -> list[Verdict]:
    """CHECK 2, for one direction. The old side is read from *old_raw* and never
    from the normalized old config: normalization is exactly the step that turns
    an unreadable previous axis into "all values"."""
    kind = f"vpcsc_{direction}"
    new_policies = _policies(new_config, direction)
    if not new_policies:
        # allowed(new) is BoolVal(False), so the assertion is unsat whatever the
        # old side is: no solver needed, and the empty/absent ambiguity below
        # cannot change the answer.
        return [Verdict("grounded", kind, name, 0,
                        f"{location}: the change proposes no {direction} policies on "
                        f"perimeter {name}, so it permits no {direction} the previous "
                        f"configuration did not{note}")]
    if not _key_present(old_raw, side, direction):
        # An old EMPTY list means "none permitted" (so this would be a widening);
        # an old ABSENT key is indistinguishable from "not captured" offline.
        return [Verdict("unverified", kind, name, 0,
                        f"{location}: the previous {name} has no "
                        f"'{side}.{direction}_policies' key — an absent list and a "
                        f"captured-empty list are indistinguishable offline, so "
                        f"{direction} widening was not decided{note}")]
    old_raw_policies, unreadable = _old_policies(old_raw, side, direction)
    if unreadable is not None:
        return [Verdict("unverified", kind, name, 0,
                        f"{location}: the previous {name}'s {unreadable} — "
                        f"over-approximating the previous permission set can only "
                        f"HIDE a widening, so {direction} widening was not "
                        f"decided{note}")]
    old_axes = [_axes(policy, direction) for policy in old_raw_policies]
    blocked = _first_unreadable_axis(old_axes)
    if blocked is not None:
        axis, detail = blocked
        # DIRECTIONAL READABILITY: the new side may be over-approximated, the old
        # side may not — widening it to "all values" is exactly how a widening
        # goes unreported.
        return [Verdict("unverified", kind, name, 0,
                        f"{location}: the previous {name}'s '{side}' {direction} "
                        f"{axis} axis could not be read ({detail}) — reading an "
                        f"unreadable OLD axis as every value can only HIDE a "
                        f"widening, so {direction} widening was not decided{note}")]
    new_axes = [_axes(policy, direction) for policy in new_policies]
    z3 = _z3_module(ctx.solver)
    if z3 is None:
        logger.debug("vpcsc %s widening degraded to unverified: backend=%s has no z3",
                     direction, getattr(ctx.solver, "backend", "?"))
        return [Verdict("unverified", kind, name, 0,
                        f"{location}: z3 is not available (solver backend "
                        f"{getattr(ctx.solver, 'backend', '?')!r}) — {direction} "
                        f"widening was not decided{note}")]
    axis_vars = {axis: z3.String(f"vpcsc.{axis}") for axis in _AXES}
    solver = z3.Solver()
    solver.add(z3.And(
        _allowed(z3, axis_vars, new_axes, unreadable_is_any=True),
        z3.Not(_allowed(z3, axis_vars, old_axes, unreadable_is_any=False))))
    result = solver.check()
    if result == z3.unsat:
        return [Verdict("grounded", kind, name, 0,
                        f"{location}: perimeter {name} permits no {direction} the "
                        f"previous configuration did not{note}")]
    if result != z3.sat:
        return [Verdict("unverified", kind, name, 0,
                        f"{location}: solver returned {result} — {direction} widening "
                        f"was not decided{note}")]
    model = solver.model()

    def witness(axis: str) -> str:
        """The model's value for one axis — or ``<any …>`` where the model left
        it free (z3 completes an unconstrained String as ``""``, which would
        read as a real, empty identity rather than as "every identity")."""
        value = model.eval(axis_vars[axis], model_completion=True).as_string()
        return value or f"<any {axis}>"

    return [Verdict("contradicted", kind, name, 0,
                    f"{location}: perimeter {name} newly permits {witness('identity')} "
                    f"to reach {witness('service')}.{witness('method')} at "
                    f"{witness('resource')} — {direction} is wider than the previous "
                    f"configuration{note}")]


# -- entry points -------------------------------------------------------------


def check_perimeter_estate(ctx: "CheckContext") -> list[Verdict]:
    """ESTATE path: compare each proposed perimeter against the snapshot.

    Yields nothing when a baseline was supplied — :func:`check_perimeter_pair`
    owns that comparison — and nothing for a document proposing no perimeter.
    """
    if ctx.baseline is not None:
        return []
    verdicts: list[Verdict] = []
    for name, location, new in _proposed(ctx):
        record = ctx.snapshot.vpc_sc_perimeter(name)
        if record is UNKNOWN:
            verdicts.append(Verdict(
                "unverified", "vpcsc_protection", name, 0,
                f"{location}: no baseline was given and vpc_sc_perimeters were not "
                f"captured in the snapshot, so the previous state of {name} is "
                f"unknown — protection removal was not decided"))
            continue
        if record is None:
            verdicts.append(Verdict(
                "unverified", "vpcsc_protection", name, 0,
                f"{location}: no baseline was given and {name} is not in the "
                f"snapshot, so its previous state is unknown — protection removal "
                f"was not decided"))
            continue
        raw = _plain(record)
        verdicts.extend(_compare(new, _normalize_perimeter(raw), raw,
                                 name, location, ctx))
    return verdicts


def check_perimeter_pair(ctx: "CheckContext") -> list[Verdict]:
    """PAIR path: compare each proposed perimeter against the baseline document."""
    proposed = _proposed(ctx)
    if not proposed:
        return []
    baseline = ctx.baseline
    if not isinstance(baseline, Mapping) or ctx.baseline_kind != "vpc_sc_perimeter":
        return [Verdict("unverified", "vpcsc_protection", name, 0,
                        f"{location}: the baseline's shape was not recognized as a "
                        f"service perimeter (detected "
                        f"{ctx.baseline_kind or 'nothing'}), so the previous state of "
                        f"{name} is unknown — protection removal was not decided")
                for name, location, _new in proposed]
    old = _normalize_perimeter(baseline)
    verdicts: list[Verdict] = []
    for name, location, new in proposed:
        old_name = old.get("name")
        if old_name and name and old_name != name:
            verdicts.append(Verdict(
                "unverified", "vpcsc_protection", name, 0,
                f"{location}: the baseline describes perimeter {old_name}, not "
                f"{name}, so the previous state of {name} is unknown — protection "
                f"removal was not decided"))
            continue
        verdicts.extend(_compare(new, old, baseline, name, location, ctx))
    return verdicts


# -- registry wiring ----------------------------------------------------------

DOCUMENT_CHECKS = (check_perimeter_estate,)

PAIR_CHECKS = {"vpc_sc_perimeter": check_perimeter_pair}
