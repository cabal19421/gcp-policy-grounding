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

THE EMPTY-versus-ABSENT ASYMMETRY. An old policy list that is *empty* means "no
egress permitted", so any new policy widens. An old document that simply omits
the ``egress_policies`` key is indistinguishable offline from one that was
captured empty, so when the proposal adds policies and the old key is absent
this abstains naming the ambiguity rather than guessing.

Service-vocabulary questions ("is ``bigquery.googleapis.com`` a real restricted
service?") are the ``restricted_service_ref`` existence claims' job and are not
duplicated here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping

from .constraints import _z3_module
from .core.log import get_logger
from .core.report import Verdict
from .knowledge import UNKNOWN
from .vpcsc_claims import _get, _normalize_perimeter, _obj

if TYPE_CHECKING:  # annotations only — no runtime import weight, no cycle
    from .registry import CheckContext

logger = get_logger(__name__)

__all__ = ["DOCUMENT_CHECKS", "PAIR_CHECKS",
           "check_perimeter_estate", "check_perimeter_pair"]

#: ``identity_type`` values that select every identity, so the identity axis is
#: unconstrained (``BoolVal(True)``) whatever ``identities`` holds.
_ANY_IDENTITY_TYPES = ("ANY_IDENTITY", "ANY_USER_ACCOUNT", "ANY_SERVICE_ACCOUNT")

_WILDCARD = "*"
_REGULAR = "PERIMETER_TYPE_REGULAR"
_BRIDGE = "PERIMETER_TYPE_BRIDGE"
_DIRECTIONS = ("ingress", "egress")

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
    verdicts.extend(_check_protection(new, old, new_config, old_config,
                                      name, location, side, note))
    for direction in _DIRECTIONS:
        verdicts.extend(_check_widening(direction, new_config, old_config,
                                        old_raw, name, location, side, note, ctx))
    return verdicts


def _is_dry_run(new: Mapping[str, Any]) -> bool:
    """A proposal that writes only ``spec`` and flags it dry-run."""
    return (new.get("use_explicit_dry_run_spec") is True
            and new.get("status") is None and new.get("spec") is not None)


def _check_protection(new: Mapping[str, Any], old: Mapping[str, Any],
                      new_config: Any, old_config: Any, name: str,
                      location: str, side: str, note: str) -> list[Verdict]:
    """CHECK 1: does the change take anything out from behind the perimeter?
    Pure set algebra — no solver, so this decides on every backend."""
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
    removed_resources = _names(set(_names(old_config.get("resources")))
                               - set(_names(new_config.get("resources"))))
    if removed_resources:
        findings.append(Verdict(
            "contradicted", "vpcsc_protection", name, 0,
            f"{location}: the change removes {len(removed_resources)} project(s) "
            f"from perimeter {name}: {', '.join(removed_resources)} — they lose "
            f"VPC-SC protection{note}"))
    removed_services = _names(set(_names(old_config.get("restricted_services")))
                              - set(_names(new_config.get("restricted_services"))))
    if removed_services:
        findings.append(Verdict(
            "contradicted", "vpcsc_protection", name, 0,
            f"{location}: the change removes {len(removed_services)} restricted "
            f"service(s) from perimeter {name}: {', '.join(removed_services)} — "
            f"they lose VPC-SC protection{note}"))
    if old.get("perimeter_type") == _REGULAR and new.get("perimeter_type") == _BRIDGE:
        findings.append(Verdict(
            "contradicted", "vpcsc_protection", name, 0,
            f"{location}: perimeter {name} changes from {_REGULAR} to {_BRIDGE} — "
            f"a bridge enforces nothing, so every project in it loses VPC-SC "
            f"protection{note}"))
    if findings:
        return findings
    kept_resources = _names(new_config.get("resources"))
    kept_services = _names(new_config.get("restricted_services"))
    return [Verdict("grounded", "vpcsc_protection", name, 0,
                    f"{location}: the change removes nothing from perimeter {name} — "
                    f"it still protects {len(kept_resources)} project(s) "
                    f"({', '.join(kept_resources) or 'none'}) across "
                    f"{len(kept_services)} restricted service(s) "
                    f"({', '.join(kept_services) or 'none'}){note}")]


# -- CHECK 2: widening (z3, check_policy_subset's polarity) -------------------


def _policies(config: Any, direction: str) -> list[Mapping[str, Any]]:
    if not isinstance(config, Mapping):
        return []
    return [p for p in config.get(f"{direction}_policies") or []
            if isinstance(p, Mapping)]


def _axis_pred(z3, axis, values, wildcard: bool = False):
    """``Or(axis == v for v in values)`` — or ``True`` when the axis is
    unconstrained: a ``"*"`` literal, an explicit wildcard, or an absent/empty
    list, all of which mean *every* value on this axis."""
    literals = _names(values)
    if wildcard or not literals or _WILDCARD in literals:
        return z3.BoolVal(True)
    return z3.Or([axis == z3.StringVal(v) for v in literals])


def _policy_pred(z3, axes: Mapping[str, Any], policy: Mapping[str, Any],
                 direction: str):
    """One ingress/egress policy as the product of its four axes."""
    frm = policy.get(f"{direction}_from") or {}
    to = policy.get(f"{direction}_to") or {}
    identity_type = frm.get("identity_type")
    identity = _axis_pred(z3, axes["identity"], frm.get("identities"),
                          wildcard=identity_type in _ANY_IDENTITY_TYPES)
    resources = list(to.get("resources") or []) + list(to.get("external_resources") or [])
    resource = _axis_pred(z3, axes["resource"], resources)
    services: list[str] = []
    methods: list[str] = []
    for operation in to.get("operations") or []:
        if not isinstance(operation, Mapping):
            continue
        services.append(operation.get("service_name"))
        for selector in operation.get("method_selectors") or []:
            if isinstance(selector, Mapping):
                methods.append(selector.get("method") or selector.get("permission"))
    service = _axis_pred(z3, axes["service"], services)
    method = _axis_pred(z3, axes["method"], methods)
    return z3.And(identity, service, method, resource)


def _allowed(z3, axes: Mapping[str, Any], policies, direction: str):
    """``Or`` over the policies — and ``BoolVal(False)`` for the empty list,
    which permits nothing."""
    if not policies:
        return z3.BoolVal(False)
    return z3.Or([_policy_pred(z3, axes, p, direction) for p in policies])


def _check_widening(direction: str, new_config: Any, old_config: Any, old_raw: Any,
                    name: str, location: str, side: str, note: str,
                    ctx: "CheckContext") -> list[Verdict]:
    kind = f"vpcsc_{direction}"
    new_policies = _policies(new_config, direction)
    old_policies = _policies(old_config, direction)
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
    z3 = _z3_module(ctx.solver)
    if z3 is None:
        logger.debug("vpcsc %s widening degraded to unverified: backend=%s has no z3",
                     direction, getattr(ctx.solver, "backend", "?"))
        return [Verdict("unverified", kind, name, 0,
                        f"{location}: z3 is not available (solver backend "
                        f"{getattr(ctx.solver, 'backend', '?')!r}) — {direction} "
                        f"widening was not decided{note}")]
    axes = {axis: z3.String(f"vpcsc.{axis}")
            for axis in ("identity", "service", "method", "resource")}
    solver = z3.Solver()
    solver.add(z3.And(_allowed(z3, axes, new_policies, direction),
                      z3.Not(_allowed(z3, axes, old_policies, direction))))
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
        value = model.eval(axes[axis], model_completion=True).as_string()
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
