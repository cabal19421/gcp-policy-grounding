"""THE one drift vocabulary, and the adjudicator that stops a disputed fact
minting a clean pass.

This module is the one place a disagreement between two views of the current
state becomes visible, and it owns the WHOLE drift vocabulary of this design:
:data:`DRIFT_KINDS` is ``drift``, ``drift:material``, ``drift:unmanaged``,
``drift:unmergeable``, ``drift:verdict`` and ``drift:key-mismatch``. Nothing
anywhere emits a second spelling of the same concept — there is no
``state:drift`` kind, no per-module drift wording and no second renderer of a
:class:`~gcp_grounding.provenance.Dispute`.

**VOLATILE IS NOT BENIGN, and the two are easy to conflate.** Nothing arrives
here for a volatile field, and that is a property of
:mod:`gcp_grounding.compare` rather than of this module:
:data:`gcp_grounding.compare.VOLATILE_IGNORED` — ``etag``, ``self_link``,
``selfLink``, ``id``, ``fingerprint``, ``creation_timestamp``,
``creationTimestamp``, ``labels``, ``terraform_address`` and
``project_number`` — yields NO :class:`~gcp_grounding.compare.FieldDiff` at
all, so those never become disputes and therefore never become verdicts. Only
:data:`gcp_grounding.compare.BENIGN_REPORTED`, which is ``description`` plus
each category's own benign list, reaches the benign arm below. It is restated
here because conflating the two makes two views of ONE UNCHANGED RESOURCE emit
a wall of etag drift, and a wall of etag drift is a report nobody reads twice.

**Status.** Every drift verdict is ``unverified`` under ``annotate`` and under
``abstain``. Under ``block`` — and for a ``require-agreement`` escalation,
which :func:`gcp_grounding.merge.resolve` already mints as ``contradicted`` and
which is carried through verbatim — ONLY ``drift:material`` becomes
``contradicted``. No task in this design introduces a fifth verdict STATUS.

**The four entry points.**

- :func:`drift_verdicts` renders a ledger's disputes into the vocabulary above.
- :func:`adjudicate` re-grades a check's verdicts against the facts that check
  actually read.
- :func:`guarded` is the zero-overhead wrapper that collects that read set.
- :func:`postpass` re-grades the existence verdicts the reasoner adds OUTSIDE
  any check boundary.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping, Sequence

from . import merge, provenance
from .core.log import get_logger
from .core.report import GroundingReport, Verdict
from .provenance import Dispute, SourceLedger
from .reconciled import ReconciledSnapshot, reads

logger = get_logger(__name__)

__all__ = [
    "DRIFT",
    "DRIFT_MATERIAL",
    "DRIFT_UNMANAGED",
    "DRIFT_UNMERGEABLE",
    "DRIFT_VERDICT",
    "DRIFT_KEY_MISMATCH",
    "DRIFT_KINDS",
    "DRIFT_POLICIES",
    "DEFAULT_DRIFT_POLICY",
    "MAX_DRIFT_VERDICTS",
    "RESOURCE_DRIFT_MARKER",
    "RESOURCE_DRIFT_SAMPLE",
    "NOT_DECIDED",
    "drift_verdicts",
    "adjudicate",
    "guarded",
    "postpass",
]


# -- THE ONE DRIFT VOCABULARY -------------------------------------------------

#: A difference that changed no answer: a benign field difference, or
#: terraform's own ``resource_drift``.
DRIFT = "drift"
#: A disagreement about a SECURITY field, or about whether a resource exists at
#: all. The only kind that can ever be ``contradicted``.
DRIFT_MATERIAL = "drift:material"
#: Resources the estate has and terraform does not manage. Expected, aggregated,
#: never a finding.
DRIFT_UNMANAGED = "drift:unmanaged"
#: Two views that cannot be compared or merged at all.
DRIFT_UNMERGEABLE = "drift:unmergeable"
#: ONE CHECK, TWO ANSWERS: the same rule decided differently against two
#: sources. Emitted by the engine's per-source re-run; defined here because
#: this module owns the vocabulary and a second spelling is a second concept.
DRIFT_VERDICT = "drift:verdict"
#: The systematic-miss diagnostic from merge step 9a. Spelled ONCE, in
#: :data:`gcp_grounding.merge.KEY_MISMATCH_KIND`, and re-exported here rather
#: than restated so the two cannot drift apart.
DRIFT_KEY_MISMATCH = merge.KEY_MISMATCH_KIND

#: Every drift kind, in report order. THE CROSS-REFERENCE: ``gate.py``'s
#: ``ALWAYS_REPORT_KINDS`` (specified in ``tx-gate-current-state``) promises
#: that every one of these is surfaced to the operator even on an otherwise
#: clean file. That promise and :data:`MAX_DRIFT_VERDICTS` live in different
#: tasks with nothing else connecting them, which is exactly why the cap below
#: fills its budget ROUND-ROBIN over this tuple: a naive head-truncation of a
#: sorted list would drop the very verdict ``ALWAYS_REPORT_KINDS`` says will
#: always show.
DRIFT_KINDS = (DRIFT, DRIFT_MATERIAL, DRIFT_UNMANAGED, DRIFT_UNMERGEABLE,
               DRIFT_VERDICT, DRIFT_KEY_MISMATCH)

#: What a drift finding costs. ``annotate`` reports and never blocks;
#: ``block`` turns a material disagreement into a gate failure; ``abstain``
#: additionally downgrades a ``contradicted`` whose evidence is partly
#: uncertain. See :func:`adjudicate` for why ``abstain`` is opt-in.
DRIFT_POLICIES = ("annotate", "block", "abstain")

#: The default. Reporting is always on; blocking and suppressing are opt-in.
DEFAULT_DRIFT_POLICY = "annotate"

#: How many drift verdicts are listed before the summary takes over. Comfortably
#: above ``len(DRIFT_KINDS)``, which is the floor the round-robin fill needs in
#: order to keep the never-drop-the-first-of-any-kind promise.
MAX_DRIFT_VERDICTS = 50

#: The marker a plan reader writes into its :class:`
#: ~gcp_grounding.provenance.SourceRecord` note when terraform's own refresh
#: detected drift. The addresses are carried as a note rather than as a second
#: object set, because ``prior_state`` already reflects the refresh and a
#: second set would double-count every one of them.
RESOURCE_DRIFT_MARKER = "resource_drift:"

#: How many drifted addresses the aggregate verdict names.
RESOURCE_DRIFT_SAMPLE = 5

#: The bracketed clause every downgrade appends. ``unverified`` already means
#: "not decided", so no new status is introduced; the clause is what tells a
#: reader WHICH fact stopped the answer being decided.
NOT_DECIDED = "  [not decided: {reason}]"

# Where the count and the address sample sit inside a plan reader's note. Read
# tolerantly: an unparseable note still produces a verdict carrying the note
# verbatim, because a drift signal that fails to render is a drift signal the
# operator never sees.
_DRIFT_COUNT_LEAD = "drift on "
_DRIFT_SAMPLE_LEAD = "resource(s) ("

# A dispute's severity → the taint it earns the fact it is about. Mirrors
# ``merge``'s own mapping: a ``benign`` difference grants nothing and an
# ``unmanaged`` one is normal in a partially adopted estate, so neither taints.
# Both are still REPORTED.
_DISPUTE_TAINT = {"material": "disputed", "unmergeable": "unmergeable"}


def _policy(policy: Any) -> str:
    """*policy* if it is a known one, else the default — NEVER a raise.

    This module runs deep inside the call stack (a registry helper, a compiled
    promise, a hook), so a bad configuration value must cost the default
    behaviour and a debug line, not a crashed gate. ``sources.load_current`` is
    where a bad value is reported to a human as a usage error.
    """
    name = str(policy) if policy is not None else DEFAULT_DRIFT_POLICY
    if name in DRIFT_POLICIES:
        return name
    logger.debug("unrecognised drift policy %r; falling back to %r (expected one "
                 "of %s)", policy, DEFAULT_DRIFT_POLICY, list(DRIFT_POLICIES))
    return DEFAULT_DRIFT_POLICY


def _status(kind: str, policy: str) -> str:
    """The status a freshly minted drift verdict carries.

    ONE kind can ever be ``contradicted`` and only under one policy. Everything
    else is ``unverified``: drift is a statement about the evidence, and
    evidence nobody can settle is not a finding against the change under review.
    """
    if policy == "block" and kind == DRIFT_MATERIAL:
        return "contradicted"
    return "unverified"


def _annotated(verdict: Verdict, reason: str, *,
               status: str = "unverified") -> Verdict:
    """*verdict* re-graded to *status* with the bracketed not-decided clause."""
    return Verdict(status, verdict.kind, verdict.target, verdict.lineno,
                   f"{verdict.message}{NOT_DECIDED.format(reason=reason)}",
                   suggestions=verdict.suggestions)


# -- disputes → verdicts ------------------------------------------------------


def drift_verdicts(ledger: SourceLedger | None, *,
                   policy: str = DEFAULT_DRIFT_POLICY,
                   verdicts: Iterable[Verdict] = (),
                   precedence: str = merge.DEFAULT_PRECEDENCE
                   ) -> tuple[Verdict, ...]:
    """Every disagreement *ledger* recorded, as verdicts in the one vocabulary.

    THE DISPUTE SHAPES, and the kind each becomes:

    - a BENIGN field difference → ``drift``, naming the non-security field and
      each source's value, and saying no check was affected. Only
      :data:`gcp_grounding.compare.BENIGN_REPORTED` reaches this arm — see the
      module docstring on why volatile is not benign;
    - a MATERIAL FIELD conflict → ``drift:material``, naming the field, each
      value, which source the merged snapshot uses under the named precedence,
      and that every check reading it abstains;
    - a MATERIAL EXISTENCE dispute → ``drift:material``, naming the locator,
      saying the resource may have been destroyed or moved out of band, and
      that the fact is KEPT;
    - an UNMERGEABLE → ``drift:unmergeable``, carrying the reason;
    - UNMANAGED → ONE AGGREGATE verdict PER CATEGORY naming the count, with the
      names logged at debug. Never one verdict per resource, which would bury
      every real finding under a wall of noise.

    Plus two things that are not disputes. Terraform's own ``resource_drift``,
    which a plan reader carried onto the ledger as a source note, becomes ONE
    aggregate ``drift`` verdict naming the count and the first
    :data:`RESOURCE_DRIFT_SAMPLE` addresses — so it reaches the operator
    instead of dying in a reader note. And *verdicts*, which is
    :attr:`gcp_grounding.merge.MergeResult.verdicts`: merge step 9a's
    ``drift:key-mismatch`` diagnostic and any ``require-agreement`` escalation
    are ALREADY in this vocabulary and are carried through verbatim rather than
    re-derived, because re-deriving them would be a second spelling of the same
    concept. They cannot be recovered from the ledger — a key-mismatch is about
    a CATEGORY rather than a key, and :class:`
    ~gcp_grounding.provenance.SourceLedger` has no verdict field.

    The list is capped at :data:`MAX_DRIFT_VERDICTS`; see :func:`_capped`.
    """
    mode = _policy(policy)
    grouped: dict[str, list[Verdict]] = {kind: [] for kind in DRIFT_KINDS}
    if ledger is not None:
        unmanaged: dict[str, list[Dispute]] = {}
        for dispute in _ordered(ledger.disputes):
            if dispute.severity == "unmanaged":
                unmanaged.setdefault(dispute.category, []).append(dispute)
                continue
            minted = _dispute_verdict(ledger, dispute, mode, precedence)
            grouped[minted.kind].append(minted)
        for category in sorted(unmanaged):
            grouped[DRIFT_UNMANAGED].append(
                _unmanaged_verdict(category, unmanaged[category], mode))
        aggregate = _resource_drift_verdict(ledger, mode)
        if aggregate is not None:
            grouped[DRIFT].append(aggregate)
    for carried in verdicts:
        grouped.setdefault(carried.kind, []).append(_carried(carried, mode))
    return _capped(grouped)


def _ordered(disputes: Iterable[Dispute]) -> list[Dispute]:
    """Disputes in a deterministic order. ``merge`` already sorts them; sorting
    again costs nothing and means a hand-built ledger renders stably too."""
    return sorted(disputes, key=lambda d: (d.category, d.key, d.field, d.severity,
                                           d.left, d.right, d.reason))


def _dispute_verdict(ledger: SourceLedger, dispute: Dispute, policy: str,
                     precedence: str) -> Verdict:
    """One dispute, in the one vocabulary.

    The FIELD is the discriminator between the two material shapes, and it is
    a structural property of ``merge`` rather than a guess: a field-value
    dispute names the differing path and carries the two VALUES, while an
    existence dispute carries no field and its two sides are SOURCE IDS.
    """
    target = f"{dispute.category}/{dispute.key}"
    reason = dispute.reason or "no reason was recorded"
    if dispute.severity == "unmergeable":
        kind = DRIFT_UNMERGEABLE
        message = (
            f"{target} could not be merged: {reason}. The two views are held "
            f"apart rather than combined into a record that describes neither, "
            f"and nothing may treat them as one resource")
    elif dispute.severity == "benign":
        kind = DRIFT
        message = (
            f"{target}: the sources disagree about '{dispute.field}' - "
            f"'{dispute.left}' against '{dispute.right}' ({reason}). "
            f"'{dispute.field}' is not a security field, so NO CHECK WAS "
            f"AFFECTED and nothing was suppressed; the difference is reported "
            f"because precedence selects a value and never suppresses a finding")
    elif dispute.field:
        kind = DRIFT_MATERIAL
        message = (
            f"{target}: the sources disagree about the security field "
            f"'{dispute.field}' - '{dispute.left}' against '{dispute.right}' "
            f"({reason}). The merged snapshot uses the value from "
            f"'{_winner(ledger, dispute)}' under precedence '{precedence}', and "
            f"EVERY CHECK THAT READS THIS FACT ABSTAINS: the fact is tainted "
            f"'disputed', so a 'grounded' resting on it is downgraded to "
            f"'unverified'")
    else:
        kind = DRIFT_MATERIAL
        message = (
            f"{target}: '{dispute.key}' is present in '{dispute.left}' and "
            f"ABSENT from '{dispute.right}', which enumerated "
            f"'{dispute.category}' completely (locator "
            f"'{_locator(ledger, dispute, target)}'). The resource MAY HAVE "
            f"BEEN DESTROYED OR MOVED OUT OF BAND. The fact is KEPT and tainted "
            f"'disputed' - dropping it would let the merged view prove an "
            f"absence that is not proven")
    return Verdict(_status(kind, policy), kind, target, 0, message)


def _winner(ledger: SourceLedger, dispute: Dispute) -> str:
    """Which source the merged snapshot took this key's record from."""
    origin = ledger.origin_of(dispute.category, dispute.key)
    return origin.source_id if origin is not None else "no source recorded"


def _locator(ledger: SourceLedger, dispute: Dispute, fallback: str) -> str:
    """The winning fact's locator — a terraform ADDRESS for a terraform-derived
    fact, an API method or path otherwise — falling back to ``category/key``."""
    origin = ledger.origin_of(dispute.category, dispute.key)
    if origin is not None and origin.locator:
        return origin.locator
    return fallback


def _unmanaged_verdict(category: str, disputes: Sequence[Dispute],
                       policy: str) -> Verdict:
    """ONE verdict for a whole category's unmanaged resources.

    Never one per resource: an estate part-way through terraform adoption has
    hundreds of them, and a wall of expected noise buries every real finding in
    the same report. The NAMES go to the debug log, where an operator who wants
    them can find them.
    """
    names = sorted({d.key for d in disputes})
    logger.debug("drift: %d unmanaged resource(s) in '%s': %s",
                 len(names), category, ", ".join(names))
    sources = sorted({d.right for d in disputes if d.right})
    return Verdict(
        _status(DRIFT_UNMANAGED, policy), DRIFT_UNMANAGED, category, 0,
        f"'{category}': {len(names)} resource(s) exist in the estate and are "
        f"absent from terraform source(s) {sources}. UNMANAGED RESOURCES ARE "
        f"EXPECTED in a partially adopted estate and are NOT A FINDING; they "
        f"are aggregated into this one verdict rather than one per resource, "
        f"and their names are logged at debug")


def _resource_drift_verdict(ledger: SourceLedger, policy: str) -> Verdict | None:
    """Terraform's OWN detected drift, as one aggregate ``drift`` verdict.

    A plan reader records ``resource_drift`` as ADDRESSES ONLY, because
    ``prior_state`` already reflects the refresh and a second object set would
    double-count every one of them. Those addresses still have to reach the
    operator: a note on a reader is invisible to an agent, and terraform's own
    detected drift is exactly the signal a human wants.
    """
    counted = 0
    addresses: list[str] = []
    raw: list[str] = []
    for source_id in sorted(ledger.sources):
        note = ledger.sources[source_id].note or ""
        parsed = _parse_resource_drift(note)
        if parsed is None:
            continue
        count, found = parsed
        counted += count
        addresses.extend(found)
        raw.append(f"'{source_id}': {note[note.find(RESOURCE_DRIFT_MARKER):]}")
    if not raw:
        return None
    total = counted or len(addresses)
    if addresses:
        shown = ", ".join(addresses[:RESOURCE_DRIFT_SAMPLE])
        extra = len(addresses) - RESOURCE_DRIFT_SAMPLE
        sample = f"{shown} and {extra} more" if extra > 0 else shown
    else:
        # The marker was there and nothing parsed. Carry the note verbatim
        # rather than dropping the signal.
        sample = "; ".join(raw)
    return Verdict(
        _status(DRIFT, policy), DRIFT, "resource_drift", 0,
        f"terraform's own refresh detected drift on {total} resource(s) "
        f"outside this change: {sample}. No objects were taken from "
        f"'resource_drift' - 'prior_state' already reflects the refresh, so a "
        f"second object set would double-count every one of them - and the "
        f"addresses are surfaced here because a note on a reader is invisible "
        f"to the operator")


def _parse_resource_drift(note: str) -> tuple[int, tuple[str, ...]] | None:
    """``(count, addresses)`` from a source note, or ``None`` when the note
    carries no :data:`RESOURCE_DRIFT_MARKER`.

    Tolerant on purpose. The note is prose written by the plan reader and
    :meth:`gcp_grounding.provenance.LedgerBuilder.declare` may have appended
    another note beside it; a shape this cannot decompose still returns a
    count of zero and no addresses, and the caller carries the note verbatim.
    """
    at = note.find(RESOURCE_DRIFT_MARKER)
    if at < 0:
        return None
    tail = note[at + len(RESOURCE_DRIFT_MARKER):]
    count = 0
    lead = tail.find(_DRIFT_COUNT_LEAD)
    if lead >= 0:
        digits = tail[lead + len(_DRIFT_COUNT_LEAD):].split(" ", 1)[0].strip()
        if digits.isdigit():
            count = int(digits)
    addresses: tuple[str, ...] = ()
    lead = tail.find(_DRIFT_SAMPLE_LEAD)
    if lead >= 0:
        start = lead + len(_DRIFT_SAMPLE_LEAD)
        end = tail.find(")", start)
        if end > start:
            addresses = tuple(part.strip() for part in tail[start:end].split(",")
                              if part.strip())
    return count, addresses


def _carried(verdict: Verdict, policy: str) -> Verdict:
    """A verdict ``merge`` already minted in this vocabulary, carried through.

    Verbatim for ``drift:key-mismatch`` and for a ``require-agreement``
    escalation, which arrives ALREADY ``contradicted`` and stays that way under
    every drift policy — the escalation is the point of that precedence mode.
    The one thing enforced here is the promise the whole vocabulary rests on:
    NO KIND OTHER THAN ``drift:material`` is ever ``contradicted``.
    """
    if verdict.kind == DRIFT_MATERIAL:
        if verdict.status == "contradicted" or policy == "block":
            return Verdict("contradicted", verdict.kind, verdict.target,
                           verdict.lineno, verdict.message, verdict.suggestions)
        return verdict
    if verdict.status == "contradicted":
        logger.debug("drift: carried verdict of kind %r arrived 'contradicted'; "
                     "only %r may be contradicted, so it is reported as "
                     "'unverified'", verdict.kind, DRIFT_MATERIAL)
        return Verdict("unverified", verdict.kind, verdict.target, verdict.lineno,
                       verdict.message, verdict.suggestions)
    return verdict


def _capped(grouped: Mapping[str, list[Verdict]]) -> tuple[Verdict, ...]:
    """At most :data:`MAX_DRIFT_VERDICTS` verdicts, FAIRLY across kinds.

    The budget is filled ROUND-ROBIN over :data:`DRIFT_KINDS`: one verdict of
    every kind is admitted before a second of any. See the note on
    :data:`DRIFT_KINDS` for why — ``gate.ALWAYS_REPORT_KINDS`` promises every
    drift kind is surfaced on an otherwise-clean file, and a naive truncation
    of a sorted list can drop the very verdict that promise guarantees.

    When anything was dropped a final summary verdict names HOW MANY were not
    listed and WHICH KINDS were truncated, so a reader can tell the difference
    between "there was no unmanaged drift" and "the unmanaged drift did not
    fit".
    """
    order = list(DRIFT_KINDS) + sorted(k for k in grouped if k not in DRIFT_KINDS)
    total = sum(len(grouped[kind]) for kind in order)
    admitted: dict[str, list[Verdict]] = {kind: [] for kind in order}
    budget = MAX_DRIFT_VERDICTS
    index = 0
    while budget > 0 and any(len(grouped[kind]) > index for kind in order):
        for kind in order:
            if budget <= 0:
                break
            if len(grouped[kind]) > index:
                admitted[kind].append(grouped[kind][index])
                budget -= 1
        index += 1
    out = [verdict for kind in order for verdict in admitted[kind]]
    dropped = total - len(out)
    if not dropped:
        return tuple(out)
    truncated = [kind for kind in order
                 if len(admitted[kind]) < len(grouped[kind])]
    out.append(Verdict(
        "unverified", DRIFT, "drift", 0,
        f"{dropped} further drift verdict(s) were not listed: the report is "
        f"capped at {MAX_DRIFT_VERDICTS}. The truncated kind(s) are "
        f"{truncated}; the budget was filled round-robin over the drift kinds, "
        f"so the FIRST verdict of every kind above is present and only "
        f"repetition was dropped"))
    return tuple(out)


# -- the taint adjudicator ----------------------------------------------------


def adjudicate(verdicts: Iterable[Verdict], read_set: Iterable[tuple[str, str]],
               snapshot: Any, policy: str = DEFAULT_DRIFT_POLICY
               ) -> tuple[Verdict, ...]:
    """Re-grade *verdicts* against the facts the check that produced them read.

    FIVE RULES.

    1. A ``grounded`` resting on a TAINTED fact becomes ``unverified`` with the
       bracketed not-decided clause naming the fact. MANDATORY UNDER EVERY
       POLICY: a clean bill of health resting on a disputed or stale fact is
       exactly the silent pass this module exists to prevent.
    2. A ``contradicted`` KEEPS its status under ``annotate`` and ``block`` and
       flips to ``unverified`` only under ``abstain``, with the reasoning
       recorded. A finding with partly-uncertain evidence is still a finding a
       human must see, and downgrading by default would hand an attacker a
       universal suppressor: introduce drift, and every finding becomes an
       abstain.
    3. THE ONE CARVE-OUT FROM RULE 2, and it is a genuine exception rather than
       a weakening. A ``contradicted`` is DOWNGRADED to ``unverified`` — naming
       the phantom fact and BOTH sources — when EVERY fact in its read set
       carries a MATERIAL EXISTENCE dispute whose winner is a ``complete``
       source asserting ABSENCE.

       The two rules look contradictory until the read-set condition is stated,
       so: the anti-suppressor argument behind rule 2 is sound for a finding
       about the PROPOSAL'S OWN CONTENT, which needs no estate fact at all. It
       does not cover a finding whose ONLY evidence is an existence the
       higher-fidelity complete source refutes. Merge step 8 deliberately KEEPS
       such a terraform-only key and taints it ``disputed``; without this
       carve-out an estate check like the unreachable-rule finding can emit
       ``contradicted`` on the strength of a rule the authoritative source says
       was deleted, and in hook mode that is exit 2 against a legitimate
       change. THE DISTINCTION IS DISPUTE KIND, NOT SEVERITY: benign and
       material FIELD-VALUE disputes keep rule 2's annotate-only behaviour
       unchanged, and one undisputed fact anywhere in the read set is enough to
       keep the finding.
    4. An ``ungrounded`` ALWAYS becomes ``unverified``. ``ungrounded`` asserts
       that the snapshot PROVES a name absent, and a merged view built from
       sources that disagree — or that never claimed to enumerate anything
       completely — proves no such thing. The reasoner's own existence verdicts
       are graded separately and more precisely by :func:`postpass`, which can
       see the category behind the kind.
    5. An ``unverified`` is unchanged. It is already the honest answer.

    A snapshot that is not a :class:`
    ~gcp_grounding.reconciled.ReconciledSnapshot` has no provenance to
    adjudicate against, so the verdicts come back untouched.
    """
    items = tuple(verdicts)
    if not isinstance(snapshot, ReconciledSnapshot):
        return items
    mode = _policy(policy)
    pairs = tuple(dict.fromkeys(tuple(item) for item in read_set)) if read_set else ()
    taints = snapshot.taints_for(pairs)
    return tuple(_adjudicate_one(v, pairs, taints, snapshot, mode) for v in items)


def _adjudicate_one(verdict: Verdict, pairs: tuple[tuple[str, str], ...],
                    taints: tuple[tuple[str, str, str], ...], snapshot: Any,
                    policy: str) -> Verdict:
    if verdict.status == "grounded":
        if not taints:
            return verdict                                          # rule 1, clean
        return _annotated(verdict, _taint_reason(taints))           # rule 1
    if verdict.status == "ungrounded":
        return _annotated(verdict, UNGROUNDED_REASON)               # rule 4
    if verdict.status != "contradicted":
        return verdict                                              # rule 5
    phantoms = _phantom_reads(snapshot, pairs)                      # rule 3
    if pairs and len(phantoms) == len(pairs):
        first = phantoms[pairs[0]]
        return _annotated(verdict, PHANTOM_REASON.format(
            fact=f"{pairs[0][0]}/{pairs[0][1]}", present=first.left,
            absent=first.right, count=len(pairs)))
    if policy == "abstain":                                         # rule 2
        return _annotated(verdict, ABSTAIN_REASON)
    return verdict


#: Rule 4's reason.
UNGROUNDED_REASON = (
    "'ungrounded' asserts that the current-state view PROVES this name is "
    "absent, and a merged view whose sources disagree - or that never claimed "
    "to enumerate the category completely - proves no such thing"
)

#: Rule 2's reason, under ``abstain`` only.
ABSTAIN_REASON = (
    "drift policy 'abstain' was requested, so a finding whose evidence is "
    "partly uncertain is reported as undecided rather than as a finding. This "
    "is opt-in precisely because it is a universal suppressor: under the "
    "default 'annotate' the finding stands and a human sees it"
)

#: Rule 3's reason. Names the phantom fact and BOTH sources.
PHANTOM_REASON = (
    "every one of the {count} fact(s) this finding rests on is a PHANTOM: "
    "'{fact}' is present only in '{present}' and ABSENT from '{absent}', which "
    "enumerated the category completely, so the finding rests entirely on a "
    "resource the higher-fidelity source says is gone. A finding about the "
    "proposal's own content would stand; this one has no evidence left"
)


def _taint_reason(taints: tuple[tuple[str, str, str], ...]) -> str:
    named = ", ".join(f"{category}/{key or '*'} is tainted '{taint}'"
                      for category, key, taint in taints)
    return (f"this answer rests on {len(taints)} fact(s) whose provenance is in "
            f"question ({named}); a clean bill of health resting on a disputed "
            f"or stale fact is exactly the silent pass drift adjudication "
            f"exists to prevent")


def _phantom_reads(snapshot: Any, pairs: tuple[tuple[str, str], ...]
                   ) -> dict[tuple[str, str], Dispute]:
    """The read facts a ``complete`` source says do not exist.

    A whole-category read (``key == ""``) can never be a phantom: the dispute
    is about one key, and a sweep of the table depends on rows nobody disputed
    as much as on the disputed one. That keeps the carve-out conservative,
    which is the right direction for a rule that WEAKENS a finding.
    """
    ledger = getattr(snapshot, "ledger", None)
    if ledger is None:
        return {}
    found: dict[tuple[str, str], Dispute] = {}
    for category, key in pairs:
        if not key:
            continue
        dispute = _phantom_dispute(snapshot, ledger, category, key)
        if dispute is not None:
            found[(category, key)] = dispute
    return found


def _phantom_dispute(snapshot: Any, ledger: SourceLedger, category: str,
                     key: str) -> Dispute | None:
    for dispute in _disputes_about(snapshot, ledger, category, key):
        if dispute.severity != "material" or dispute.field:
            continue        # a FIELD-VALUE disagreement is not an existence one
        record = ledger.sources.get(dispute.right)
        if record is not None and record.scope == "complete":
            return dispute
    return None


def _disputes_about(snapshot: Any, ledger: SourceLedger, category: str,
                    key: str) -> tuple[Dispute, ...]:
    """Every dispute about one fact, from the snapshot and from the ledger.

    Both, because the two carry the same disputes by different routes — the
    snapshot holds what the merge could not resolve, the ledger holds what was
    written to the sidecar — and a caller that built only one of them must not
    silently lose the rule that depends on it.
    """
    out = list(snapshot.disputes_for(category, key))
    for dispute in ledger.disputes:
        if dispute.category == category and dispute.key == key and dispute not in out:
            out.append(dispute)
    return tuple(out)


# -- the guard ----------------------------------------------------------------


def guarded(callable_: Callable[[], Any], snapshot: Any,
            policy: str = DEFAULT_DRIFT_POLICY, *, label: str = "") -> Any:
    """Run *callable_*, collecting the estate facts it read, and adjudicate.

    ZERO OVERHEAD AND BYTE-IDENTICAL BEHAVIOUR when *snapshot* is not a
    :class:`~gcp_grounding.reconciled.ReconciledSnapshot`: no read set is
    pushed, nothing is allocated, and the callable's own return value comes
    back as the identical object. That property is what makes routing an
    existing call site through this guard safe.

    AN EXCEPTION FROM THE CALLABLE PROPAGATES UNTOUCHED, deliberately. Every
    caller that needs one already has an exception handler that turns a
    provider crash into exactly one honest ``unverified`` verdict; catching it
    here would either duplicate that verdict or replace it with a worse one.
    """
    if not isinstance(snapshot, ReconciledSnapshot):
        return callable_()
    with reads(label) as read_set:
        result = callable_()
    return adjudicate(result, read_set, snapshot, policy)


# -- the reasoner post-pass ---------------------------------------------------


#: Rule 1's reason, the scope rule.
SCOPE_REASON = (
    "'{category}' has {scope} coverage from {origin}{within}, so this view "
    "cannot PROVE '{target}' is absent - a partial enumeration proves no "
    "absence, and reading one as complete is how a terraform-only current "
    "state turns a name it never looked for into a hallucination"
)

#: Rule 1's more specific reason for a ``declared_not_applied`` name. The
#: sentence itself is ``merge``'s, spelled once there.
DECLARED_NOT_APPLIED_REASON = (
    "'{target}' is in the declared-not-applied set for '{category}': "
    + merge.DECLARED_NOT_APPLIED_REASON
    + ", so it is withheld from the emitted vocabulary and can mint neither a "
      "'grounded' nor a confident absence"
)

#: Rule 2's reason, the own-fact taint rule.
OWN_TAINT_REASON = (
    "'{category}' is complete, but the evidence for THIS absence is itself in "
    "question: '{category}/{target}' is tainted '{taint}'. An existence "
    "disagreement about this very name is not a proof that the name is absent"
)


def postpass(report: Any, snapshot: Any, policy: str = DEFAULT_DRIFT_POLICY, *,
             declared_not_applied: Mapping[str, Sequence[str]] | None = None
             ) -> Any:
    """Re-grade the existence verdicts the reasoner adds OUTSIDE any check.

    ``reasoner.ground_existence`` runs inside ``preflight.ground_policy``, which
    no task in this design edits, so its verdicts never pass through
    :func:`guarded`. They are also the verdicts that matter most: an
    ``ungrounded`` IS the hallucination finding, and getting it wrong in either
    direction is the tool's whole value. The category behind each one is
    resolved from the verdict KIND through
    :data:`gcp_grounding.provenance.VERDICT_KIND_CATEGORIES`.

    THREE RULES, APPLIED IN THIS ORDER.

    RULE 1, THE SCOPE RULE. An ``ungrounded`` whose category is ``uncaptured``,
    ``undeclared`` or ``partial`` becomes ``unverified``, naming the category,
    its scope and the source that supplied it, and saying that a partial
    enumeration cannot prove a name absent. This is the rule that makes a
    terraform-only current state honest BY DEFAULT: ``ungrounded`` is a
    positive claim that the snapshot PROVES the name is not there, and an
    under-approximating view proves no such thing. It also covers merge step
    9's ``declared_not_applied`` set — a name seen only below the emit fidelity
    floor — which is rewritten with the MORE SPECIFIC reason that the name is
    declared in terraform configuration but not applied, and which is checked
    first because it holds even where the category itself is complete.

    RULE 2, THE OWN-FACT TAINT RULE. An ``ungrounded`` on a COMPLETE category
    whose OWN key is disputed or stale becomes ``unverified`` naming that fact.
    The evidence for this specific absence is itself in dispute.

    RULE 3, THE SIBLING RULE, AND IT IS THE ONE THAT MUST NOT FIRE. An
    ``ungrounded`` on a COMPLETE, UNTAINTED category whose OTHER keys are
    disputed is LEFT ALONE. An existence disagreement about X is evidence about
    X; demoting the whole category on any single dispute would let one stale
    terraform file switch off hallucination detection entirely, which is this
    repo's primary value.

    *declared_not_applied* is
    :attr:`gcp_grounding.merge.MergeResult.declared_not_applied`, which is a
    property of the MERGE rather than of the snapshot and therefore cannot be
    recovered from either. When it is omitted the snapshot is asked for one, so
    a caller that stamped it onto the reconciled object does not have to pass
    it twice.

    The verdict list is REBUILT IN THE SAME ORDER rather than re-``add``-ed, so
    no spurious warning fires and no verdict changes position. *report* is
    returned so the call reads as a pipeline stage.
    """
    holder = report
    inner = getattr(report, "report", None)
    if isinstance(inner, GroundingReport):
        holder = inner
    verdicts = getattr(holder, "verdicts", None)
    if verdicts is None:
        return report
    if not isinstance(snapshot, ReconciledSnapshot) or snapshot.ledger is None:
        return report
    # THE THREE RULES ARE UNCONDITIONAL. An existence claim the view cannot
    # decide is not decided under any policy, so *policy* is normalised for the
    # diagnostic alone — there is no drift policy that buys back the right to
    # prove an absence from a partial enumeration.
    logger.debug("drift.postpass: %d verdict(s) under drift policy %r",
                 len(verdicts), _policy(policy))
    if declared_not_applied is None:
        declared_not_applied = getattr(snapshot, "declared_not_applied", None) or {}
    withheld = {str(category): set(names)
                for category, names in declared_not_applied.items()}
    holder.verdicts = [_postpass_one(v, snapshot, withheld) for v in verdicts]
    return report


def _postpass_one(verdict: Verdict, snapshot: ReconciledSnapshot,
                  withheld: Mapping[str, set]) -> Verdict:
    if verdict.status != "ungrounded":
        return verdict
    category = provenance.VERDICT_KIND_CATEGORIES.get(verdict.kind)
    if category is None:
        return verdict
    ledger = snapshot.ledger
    if verdict.target in withheld.get(category, ()):             # rule 1, specific
        return _annotated(verdict, DECLARED_NOT_APPLIED_REASON.format(
            category=category, target=verdict.target))
    scope = ledger.scope_of(category)
    if scope.scope != "complete":                                # rule 1, scope
        origin = ", ".join(scope.source_kinds) or "an undeclared source"
        within = (f" within '{scope.boundary}'" if scope.boundary
                  else " with no declared boundary")
        return _annotated(verdict, SCOPE_REASON.format(
            category=category, scope=scope.scope, origin=origin, within=within,
            target=verdict.target))
    taint = _own_taint(snapshot, ledger, category, verdict.target)
    if taint:                                                    # rule 2
        return _annotated(verdict, OWN_TAINT_REASON.format(
            category=category, target=verdict.target, taint=taint))
    # RULE 3, THE SIBLING RULE: complete, untainted, and this key's own evidence
    # is clean. LEFT ALONE — a dispute about another key is evidence about that
    # other key, and demoting on it would switch hallucination detection off.
    return verdict


def _own_taint(snapshot: ReconciledSnapshot, ledger: SourceLedger, category: str,
               key: str) -> str:
    """This key's OWN taint: its fact origin's, its category's, and whatever a
    dispute about this exact key earns it."""
    taint = ledger.taint_of(category, key)
    for dispute in _disputes_about(snapshot, ledger, category, key):
        taint = provenance.compose_taint(
            taint, _DISPUTE_TAINT.get(dispute.severity, ""))
    return taint
