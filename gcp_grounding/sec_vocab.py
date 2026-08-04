"""Ground requirement vocabulary through the Datalog existence reasoner.

This is the highest-value property of the ``sec_requirements/`` compiler: it
grounds the REQUIREMENTS, not just the policies. A requirement that names
``roles/bigquery.reader`` gets the exact same did-you-mean treatment a policy
document gets — it fails to compile and points at ``roles/bigquery.dataViewer``
— because its ``vocabulary`` of :class:`~gcp_grounding.claims.Claim`-shaped
records is pushed through :func:`gcp_grounding.reasoner.ground_existence` before
the promise is admitted, over the same snapshot and the same near-miss
suggester that catches that typo in a policy.

There is no z3 here: existence is a Datalog question. The reasoner produces a
:class:`~gcp_grounding.core.report.Verdict` per vocabulary entry whose ``kind``
stays whatever it decided (role, permission, principal, constraint,
resource_type), so the existing :class:`~gcp_grounding.report.PolicyReport`
renderer and its did-you-mean tip line work unchanged.

Admission policy — three outcomes, mapping onto the four-bucket honesty
contract:

- **ungrounded** — the snapshot *captured* the category and proved the value
  absent (a likely hallucination). This REJECTS the promise: the caller sets
  status ``rejected`` with reason
  ``"vocabulary is not grounded: {value} does not exist in the snapshot"`` and
  the ungrounded :class:`Verdict` carries the reasoner's near-misses. This is
  the marquee behaviour.
- **unverified** — the snapshot never captured the category, so absence is not
  provable (the ``captured`` guard at ``reasoner.py:114-115`` abstained). This
  still COMPILES: the value is recorded in ``Promise.vocabulary_unverified``
  and the reasoner's ``unverified`` verdict flows into the compile report. The
  rationale: the promise's formula does not depend on the snapshot, and only
  the sanity check abstained — rejecting here would trade a sound security rule
  for an unprovable one, the opposite of the four-bucket contract.
- **grounded** — every value exists; clean admission.

A promise with an empty vocabulary yields an empty :class:`VocabOutcome` and
never blocks.

:func:`ground_all` batches the whole document through a single
:func:`~gcp_grounding.reasoner.ground_existence` pass and partitions the
verdicts back per promise by the location prefix each claim carries, so one
Datalog program decides every requirement at once.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from . import reasoner, sec_artifact
from .core.log import get_logger
from .core.report import GroundingReport, Verdict
from .knowledge import GcpSnapshot

logger = get_logger(__name__)

__all__ = ["VocabOutcome", "ground_promise_vocabulary", "ground_all"]


@dataclass(frozen=True)
class VocabOutcome:
    """The grounding of one promise's vocabulary against a snapshot.

    ``verdicts`` are every existence verdict the reasoner produced for this
    promise, in vocabulary order. ``ungrounded`` are the values the snapshot
    *proved absent* (each REJECTS the promise); ``unverified`` are values in
    categories the snapshot never captured (these still COMPILE, recorded in
    ``Promise.vocabulary_unverified``). ``suggestions`` maps each ungrounded
    value to its near-misses from the snapshot's own enumeration.
    """

    verdicts: tuple[Verdict, ...] = ()
    ungrounded: tuple[str, ...] = ()
    unverified: tuple[str, ...] = ()
    suggestions: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "verdicts", tuple(self.verdicts))
        object.__setattr__(self, "ungrounded", tuple(self.ungrounded))
        object.__setattr__(self, "unverified", tuple(self.unverified))
        object.__setattr__(self, "suggestions",
                           {value: tuple(near) for value, near in self.suggestions.items()})


def _outcome(verdicts: tuple[Verdict, ...]) -> VocabOutcome:
    """Partition one promise's verdicts into the admission buckets."""
    ungrounded = tuple(v.target for v in verdicts if v.status == "ungrounded")
    unverified = tuple(v.target for v in verdicts if v.status == "unverified")
    suggestions = {v.target: tuple(v.suggestions) for v in verdicts if v.suggestions}
    return VocabOutcome(verdicts=verdicts, ungrounded=ungrounded,
                        unverified=unverified, suggestions=suggestions)


def ground_all(promises: Iterable[sec_artifact.Promise], snapshot: GcpSnapshot,
               *, artifact_label: str = "") -> dict[str, VocabOutcome]:
    """Ground every promise's vocabulary in one Datalog pass, keyed by id.

    Builds ``sec_artifact.to_claims(p)`` for each promise, rewrites every
    claim's location to ``"{label}:{promise.id}#vocabulary[{i}]"`` (``label``
    defaults to ``"requirement"``) so verdicts are globally unique and
    self-attributing, runs :func:`~gcp_grounding.reasoner.ground_existence`
    ONCE over the whole batch, then partitions the report's verdicts back per
    promise by matching that location prefix. Every promise gets an entry, even
    one whose vocabulary is empty (an empty :class:`VocabOutcome`).
    """
    label = artifact_label or "requirement"
    promises = list(promises)
    batch: list = []
    for promise in promises:
        for i, claim in enumerate(sec_artifact.to_claims(promise)):
            location = f"{label}:{promise.id}#vocabulary[{i}]"
            batch.append(dataclasses.replace(claim, location=location))
    report = reasoner.ground_existence(batch, snapshot, GroundingReport())

    outcomes: dict[str, VocabOutcome] = {}
    for promise in promises:
        # The '#' immediately after the id delimits it from any longer id that
        # shares this prefix, so partitioning cannot cross-attribute.
        prefix = f"{label}:{promise.id}#vocabulary["
        verdicts = tuple(v for v in report.verdicts if v.message.startswith(prefix))
        outcomes[promise.id] = _outcome(verdicts)
    return outcomes


def ground_promise_vocabulary(promise: sec_artifact.Promise, snapshot: GcpSnapshot,
                              *, artifact_label: str = "") -> VocabOutcome:
    """Ground a single promise's vocabulary; a thin wrapper over
    :func:`ground_all` so the same one-pass semantics apply."""
    return ground_all([promise], snapshot, artifact_label=artifact_label)[promise.id]
