"""Reasoner: Datalog existence grounding of policy claims against a snapshot.

Instantiates the vendored :class:`~gcp_grounding.core.datalog.Datalog` engine
with one rule triple per existence category — the five vocabulary categories
(role, permission, principal, constraint, resource_type) plus the ten estate
categories (network, subnetwork, network_tag, service_account, access_level,
restricted_service, perimeter, firewall_policy, security_policy,
hierarchy_node). Facts come from two sides: the claims a policy
document makes (``claims_<kind>(name, location)``) and the snapshot's
enumerations (``<kind>(name)``, plus ``captured(<kind>)`` for every category
the snapshot actually enumerated)::

    grounded_role(N, L)   :- claims_role(N, L), role(N).
    ungrounded_role(N, L) :- claims_role(N, L), captured(role), not role(N).
    unverified_role(N, L) :- claims_role(N, L), not captured(role), not role(N).

The ``captured`` guard is the honesty mechanism: a category the snapshot never
enumerated (its lookups answer :data:`~gcp_grounding.knowledge.UNKNOWN`) can
make nothing ``ungrounded`` — such claims land in ``unverified`` instead. The
three rules are mutually exclusive and exhaustive, so every existence claim
receives exactly one verdict.

Ungrounded names carry near-miss suggestions: plain edit distance against the
snapshot's enumeration for the claim's own category, which is what turns the
canonical hallucination ``roles/bigquery.reader`` into a pointer at
``roles/bigquery.dataViewer``.

Claim kind and snapshot category coincide for every existence question except
resource types: extractors spell that claim kind ``resource_type_ref``
(:data:`gcp_grounding.claims.KINDS`), while the snapshot category — and
therefore the fact/relation names and the verdict's ``kind`` — stays
``resource_type``. :func:`_category` maps between the two.

Claim kinds that are not existence questions (``cel``, ``constraint_value``)
contribute no facts and get no verdict here — the constraint-solver layer
decides those.
"""

from __future__ import annotations

from typing import Any, Iterable

from .core.datalog import Datalog, lit, var
from .core.log import get_logger
from .core.report import GroundingReport, Verdict
from .knowledge import GcpSnapshot

logger = get_logger(__name__)

__all__ = ["EXISTENCE_KINDS", "existence_program", "ground_existence", "suggest"]

#: Claim kinds the Datalog pass decides; each maps to one snapshot category.
#: The five original kinds lead, in order; the ten estate kinds are appended.
EXISTENCE_KINDS = (
    "role", "permission", "principal", "constraint", "resource_type_ref",
    "network_ref", "subnetwork_ref", "network_tag_ref", "service_account_ref",
    "access_level_ref", "restricted_service_ref", "perimeter_ref",
    "firewall_policy_ref", "security_policy_ref", "hierarchy_node_ref",
)

#: Claim kind → snapshot category, where the two differ. A ``resource_type_ref``
#: claim asserts the existence of a ``resource_type``; every estate kind is
#: likewise its category plus a ``_ref`` suffix. The category is simultaneously
#: the Datalog relation suffix and the ``Verdict.kind``.
_CLAIM_CATEGORIES = {
    "resource_type_ref": "resource_type",
    "network_ref": "network",
    "subnetwork_ref": "subnetwork",
    "network_tag_ref": "network_tag",
    "service_account_ref": "service_account",
    "access_level_ref": "access_level",
    "restricted_service_ref": "restricted_service",
    "perimeter_ref": "perimeter",
    "firewall_policy_ref": "firewall_policy",
    "security_policy_ref": "security_policy",
    "hierarchy_node_ref": "hierarchy_node",
}

#: Categories answered by a flat snapshot vocabulary: category → attribute.
_VOCAB_SOURCES = {
    "network": "networks",
    "subnetwork": "subnetworks",
    "network_tag": "network_tags",
    "service_account": "service_accounts",
    "access_level": "access_levels",
    "restricted_service": "restricted_services",
}

#: Categories answered by the keys of a snapshot record table: category →
#: attribute. ``hierarchy_node`` is deliberately absent — its names come from
#: :meth:`GcpSnapshot.hierarchy_names`, which adds the number aliases.
_TABLE_SOURCES = {
    "perimeter": "vpc_sc_perimeters",
    "firewall_policy": "hierarchical_firewall_policies",
    "security_policy": "cloud_armor_policies",
}

_MAX_SUGGESTIONS = 3


def _category(kind: str) -> str:
    """The snapshot category (= Datalog relation suffix = verdict kind) a
    claim *kind* asks about; identity for all but ``resource_type_ref``."""
    return _CLAIM_CATEGORIES.get(kind, kind)


# -- snapshot → facts ---------------------------------------------------------


def _enumerated(snapshot: GcpSnapshot, kind: str) -> tuple[frozenset[str], bool]:
    """The names the snapshot proves exist for *kind* (a claim kind or its
    snapshot category), and whether the category was captured (i.e. absence
    from it is provable).

    Mirrors the lookup semantics of :class:`GcpSnapshot`: a permission is
    proven by the flat enumeration *or* by appearing in a captured role's
    ``included_permissions``, but only the enumeration can prove absence.
    """
    kind = _category(kind)
    if kind == "role":
        return frozenset(snapshot.roles or ()), snapshot.roles is not None
    if kind == "permission":
        names = set(snapshot.permissions or ())
        for record in (snapshot.roles or {}).values():
            # `or ()`: from_dict rejects a null included_permissions, but a
            # hand-constructed snapshot may still carry None — read it as
            # "nothing included", never crash.
            names.update(record.get("included_permissions") or ())
        return frozenset(names), snapshot.permissions is not None
    if kind == "principal":
        return snapshot.principals or frozenset(), snapshot.principals is not None
    if kind == "constraint":
        return frozenset(snapshot.constraints or ()), snapshot.constraints is not None
    if kind == "resource_type":
        return snapshot.resource_types or frozenset(), snapshot.resource_types is not None
    if kind == "network_tag":
        # Presence-only, the one asymmetric estate category, following the
        # `permission` arm above: the members PROVE existence, but `captured`
        # is reported False so every miss lands in `unverified`, never
        # `ungrounded`. GCP has no tag registry — a tag is created implicitly
        # by the rule that names it — so a captured `network_tags` set is
        # necessarily a subset of reality, and grounding absence against it
        # would block essentially every legitimate firewall change that
        # introduces a tag.
        return snapshot.network_tags or frozenset(), False
    if kind in _VOCAB_SOURCES:
        field = getattr(snapshot, _VOCAB_SOURCES[kind])
        return (field or frozenset(), field is not None)
    if kind in _TABLE_SOURCES:
        table = getattr(snapshot, _TABLE_SOURCES[kind])
        return (frozenset(table or ()), table is not None)
    if kind == "hierarchy_node":
        # hierarchy_names() folds in the `projects/<number>` aliases, so a
        # VPC-SC reference by number counts as existing. It answers UNKNOWN
        # when uncaptured, and UNKNOWN refuses truthiness — read `captured`
        # off the table itself first, and never call it in that case.
        captured = snapshot.resource_hierarchy is not None
        return (snapshot.hierarchy_names() if captured else frozenset()), captured
    raise ValueError(f"unknown existence kind {kind!r}; expected one of {EXISTENCE_KINDS}")


# -- the Datalog program ------------------------------------------------------


def existence_program(claims: Iterable[Any], snapshot: GcpSnapshot) -> Datalog:
    """The Datalog program deciding existence of *claims* against *snapshot*.

    Claims are duck-typed: anything carrying ``kind``/``value``/``location``
    attributes (e.g. :class:`gcp_grounding.claims.Claim`) participates; kinds
    outside :data:`EXISTENCE_KINDS` contribute no facts.
    """
    dl = Datalog()
    n, loc = var("n"), var("loc")
    for kind in EXISTENCE_KINDS:
        category = _category(kind)
        names, captured = _enumerated(snapshot, category)
        for name in names:
            dl.fact(category, name)
        if captured:
            dl.fact("captured", category)
        claims_rel = f"claims_{category}"
        dl.rule(lit(f"grounded_{category}", n, loc),
                [lit(claims_rel, n, loc), lit(category, n)])
        dl.rule(lit(f"ungrounded_{category}", n, loc),
                [lit(claims_rel, n, loc), lit("captured", category),
                 lit(category, n, negated=True)])
        dl.rule(lit(f"unverified_{category}", n, loc),
                [lit(claims_rel, n, loc), lit("captured", category, negated=True),
                 lit(category, n, negated=True)])
    for claim in claims:
        if claim.kind in EXISTENCE_KINDS:
            dl.fact(f"claims_{_category(claim.kind)}", claim.value, claim.location)
    return dl


# -- verdicts -----------------------------------------------------------------


def ground_existence(claims: Iterable[Any], snapshot: GcpSnapshot,
                     report: GroundingReport | None = None) -> GroundingReport:
    """Run the existence program and emit one verdict per existence claim.

    Policy documents have no line numbers, so every verdict's ``lineno`` is 0
    and the claim's json-path location leads the message instead. Ungrounded
    names carry near-miss suggestions from the snapshot's own enumeration for
    that category.
    """
    claims = list(claims)
    if report is None:
        report = GroundingReport()
    dl = existence_program(claims, snapshot)
    dl.run()
    skipped = 0
    for claim in claims:
        if claim.kind not in EXISTENCE_KINDS:
            skipped += 1
            continue
        kind = _category(claim.kind)
        value, location = claim.value, claim.location
        if dl.holds(f"grounded_{kind}", value, location):
            report.add(Verdict(
                "grounded", kind, value, 0,
                f"{location}: {kind} '{value}' exists in the snapshot"))
        elif dl.holds(f"ungrounded_{kind}", value, location):
            names, _ = _enumerated(snapshot, kind)
            report.add(Verdict(
                "ungrounded", kind, value, 0,
                f"{location}: {kind} '{value}' does not exist in the snapshot "
                f"(captured {snapshot.captured_at})",
                suggestions=suggest(value, names)))
        else:
            # The rule triple is exhaustive, so this is the unverified case:
            # the snapshot never enumerated this category.
            report.add(Verdict(
                "unverified", kind, value, 0,
                f"{location}: snapshot did not capture {kind}s — existence of "
                f"'{value}' is undecidable offline"))
    if skipped:
        logger.debug("%d non-existence claim(s) left to the constraint-solver layer",
                     skipped)
    return report


# -- near-miss suggestions ----------------------------------------------------


def suggest(name: str, candidates: Iterable[str],
            limit: int = _MAX_SUGGESTIONS) -> tuple[str, ...]:
    """Near-miss names for *name*: candidates within an edit-distance budget
    of ``max(2, len(name) // 3)``, closest first, at most *limit*."""
    budget = max(2, len(name) // 3)
    scored: list[tuple[int, str]] = []
    for candidate in candidates:
        if candidate == name or abs(len(candidate) - len(name)) > budget:
            continue  # the length gap alone already exceeds the budget
        distance = _levenshtein(name, candidate)
        if distance <= budget:
            scored.append((distance, candidate))
    return tuple(candidate for _, candidate in sorted(scored)[:limit])


def _levenshtein(a: str, b: str) -> int:
    """Plain edit distance, two-row dynamic programming."""
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1,                  # delete
                               current[j - 1] + 1,               # insert
                               previous[j - 1] + (ca != cb)))    # substitute
        previous = current
    return previous[-1]
