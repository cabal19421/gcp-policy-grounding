"""The structured witness channel: a side table plus a ``sec`` JSON document.

:class:`gcp_grounding.core.report.Verdict` is a frozen dataclass with exactly
``status``, ``kind``, ``target``, ``lineno``, ``message`` and ``suggestions``
and **no evidence field** (``core/report.py:22-29``), so a compile-time pinned
witness or a runtime violating record has nowhere to travel inside a verdict.
``core/`` is vendored under a DO-NOT-EDIT reuse contract, so the field cannot
simply be added here.

This module takes the domain-side side-table option, and implements it as a NEW
module that COMPOSES over :class:`~gcp_grounding.report.PolicyReport` rather
than as an edit to :mod:`gcp_grounding.report`. The rationale is coordination,
not taste: ``report.py`` is a shared surface that other work may also be
extending, while a pure composition needs no :data:`gcp_grounding.report.SCHEMA`
bump there and no agreement with anyone — ``report.py`` stays byte-unchanged and
:func:`sec_document` merges its output.

.. TODO: the eventual correct home for this is an upstream
   ``evidence: tuple[tuple[str, str], ...]`` field on the harness ``Verdict``,
   followed by a re-vendor of ``core/`` — the path the reuse contract itself
   prescribes for a core change (see ``core/__init__.py:5-7``: "If a core file
   genuinely must change, that is an upstream change in harness first, then a
   re-vendor"). Until that lands, the side table is the honest workaround: it
   adds evidence *beside* the verdicts instead of pretending a verdict carries
   a field it does not.

ONE KEY, NESTED, AND ALWAYS PRESENT.  Both halves matter.

``report.SCHEMA`` is NOT bumped, because the per-verdict key set is unchanged —
but that is only defensible if the addition is *ignorable*. Merging three bare
top-level keys into a document still tagged ``gcp-grounding-report/1`` would
hand a strict consumer of that schema three keys it has never seen, which is a
schema change in everything but the version string. Nesting everything under a
single ``"sec"`` key keeps the base document byte-unchanged and makes the
addition one obvious key a consumer either reads or skips.

And ``"sec"`` is emitted UNCONDITIONALLY whenever :func:`sec_document` is
called: with no rules loaded its value is
``{"sec_schema": ..., "witnesses": [], "requirements": []}``, never an absent
key. A consumer that must first test whether a key exists is reading a shape
that depends on whether some requirement file happened to load; one stable
shape with empty lists says "the requirements channel ran and had nothing to
report", which is a different and more useful fact.

``gcp-grounding-report/1`` is an OPEN schema: consumers MUST ignore top-level
keys they do not recognize. That is precisely why an additive, nested key needs
no version bump — the version tracks the meaning of the keys the schema
defines, and ``"sec"`` is not one of them.

Everything here is deterministic: rows sort by ``(promise_id, role, index)``,
requirements sort by id, added keys are emitted sorted, and no input is ever
mutated — so two calls over the same inputs are equal dicts and byte-identical
under ``json.dumps(..., sort_keys=True)``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .core.log import get_logger

logger = get_logger(__name__)

__all__ = ["SEC_REPORT_SCHEMA", "WITNESS_ROLES", "WitnessRow", "WitnessTable",
           "sec_document", "explain_lines"]

#: Version tag of the ``"sec"`` sub-document. Independent of
#: :data:`gcp_grounding.report.SCHEMA`, which this module never bumps.
SEC_REPORT_SCHEMA = "gcp-sec-report/1"

#: What a witness row is evidence *of*: the two witnesses pinned into the
#: artifact at compile time, and the record that refuted a rule at run time.
WITNESS_ROLES = ("pinned-positive", "pinned-negative", "violating-record")

#: ``collection`` / ``index`` locate a runtime violating record inside the
#: unrolled instance. A pinned witness has no such location — it came from a
#: z3 model over symbolic constants, not from a record — so it carries the
#: empty collection and index -1 rather than a fabricated position.
_NO_COLLECTION = ""
_NO_INDEX = -1


def _sorted_keys(data: Mapping[str, Any]) -> dict[str, Any]:
    """*data* as a plain dict in sorted-key order (the determinism rule for
    every key this module adds)."""
    return {key: data[key] for key in sorted(data)}


@dataclass(frozen=True)
class WitnessRow:
    """One piece of evidence, anchored to the promise it belongs to.

    ``assignment`` maps a free-const name (pinned witnesses) or a record field
    (violating records) to a **string** literal, mirroring
    :class:`gcp_grounding.sec_artifact.Witness`: this is a rendering and
    serialization channel, so a caller building a row out of a runtime record
    (whose fields may be bools or ints — see
    :func:`gcp_grounding.sec_rules.last_witness`) stringifies them explicitly
    rather than having this module guess a rendering.
    """

    promise_id: str
    role: str
    collection: str = _NO_COLLECTION
    index: int = _NO_INDEX
    assignment: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "assignment", dict(self.assignment))
        if self.role not in WITNESS_ROLES:
            raise ValueError(f"witness role {self.role!r} not in {WITNESS_ROLES}")
        for name, value in self.assignment.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise ValueError(
                    f"witness row {self.promise_id!r}: assignment[{name!r}] must be "
                    f"a string literal, got {value!r} — stringify record values at "
                    "the boundary instead")

    def to_dict(self) -> dict[str, Any]:
        """The row as JSON data, keys sorted (including the assignment's)."""
        return _sorted_keys({
            "promise_id": self.promise_id,
            "role": self.role,
            "collection": self.collection,
            "index": self.index,
            "assignment": _sorted_keys(self.assignment),
        })


class WitnessTable:
    """The side table: witness rows collected beside a report's verdicts.

    Rows are kept in insertion order internally and only ordered on the way out
    (:meth:`rows`, :meth:`to_list`), so adding evidence never depends on when it
    was added.
    """

    def __init__(self, rows: Iterable[WitnessRow] = ()) -> None:
        self._rows: list[WitnessRow] = []
        for row in rows:
            self.add(row)

    def __len__(self) -> int:
        return len(self._rows)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"WitnessTable({len(self._rows)} row(s))"

    def add(self, row: WitnessRow) -> None:
        """Record one :class:`WitnessRow`."""
        if not isinstance(row, WitnessRow):
            raise TypeError(f"expected a WitnessRow, got {type(row).__name__}")
        self._rows.append(row)

    def rows(self) -> tuple[WitnessRow, ...]:
        """Every row, sorted by ``(promise_id, role, index)`` — so the two pinned
        witnesses of a promise precede its violating records
        (``pinned-negative`` < ``pinned-positive`` < ``violating-record``) and
        the records themselves come out in instance order."""
        return tuple(sorted(self._rows,
                            key=lambda r: (r.promise_id, r.role, r.index)))

    def to_list(self) -> list[dict[str, Any]]:
        """:meth:`rows` as JSON data — the ``"sec"`` document's ``witnesses``."""
        return [row.to_dict() for row in self.rows()]


# -- the sec document ---------------------------------------------------------


def _promise(rule: Any) -> Any:
    """The :class:`~gcp_grounding.sec_artifact.Promise` behind *rule*.

    Accepts either a :class:`gcp_grounding.sec_rules.CompiledRule` (the loaded
    form, which wraps its promise) or a bare ``Promise``, so a caller holding
    either can render evidence without unwrapping first.
    """
    return getattr(rule, "promise", rule)


def _requirement(rule: Any) -> dict[str, Any]:
    """One ``requirements`` entry: what shipped in the artifact for this rule."""
    promise = _promise(rule)
    source = promise.source
    return _sorted_keys({
        "id": promise.id,
        "source": _sorted_keys({"file": source.file, "line": source.line,
                                "text": source.text}),
        "domain": promise.domain,
        "mode": promise.mode,
        "state": promise.state,
        "severity": promise.severity,
        "status": promise.status,
        "sexpr": promise.sexpr,
    })


def sec_document(policy_report: Any, table: WitnessTable,
                 rules: Iterable[Any] = ()) -> dict[str, Any]:
    """``policy_report.to_dict()`` plus exactly one new top-level key, ``"sec"``.

    The base document (``report.py:91-112``, untouched) is reproduced key for
    key and value for value; ``"sec"`` carries :data:`SEC_REPORT_SCHEMA`, the
    table's rows and one entry per loaded rule. The key is always present, even
    with no rules and an empty table (see the module docstring). *policy_report*
    may also be a plain mapping — it is copied, never mutated.
    """
    base = (policy_report.to_dict() if hasattr(policy_report, "to_dict")
            else dict(policy_report))
    document = dict(base)
    if "sec" in document:
        logger.warning("the base report document already has a 'sec' key — the "
                       "requirements channel is overwriting it")
    document["sec"] = _sorted_keys({
        "sec_schema": SEC_REPORT_SCHEMA,
        "witnesses": table.to_list(),
        "requirements": [_requirement(rule)
                         for rule in sorted(rules, key=lambda r: _promise(r).id)],
    })
    return document


# -- the --explain block ------------------------------------------------------


#: How a promise's runtime verdict status reads on a stanza's marker line. An
#: unknown status renders as itself uppercased rather than as "holds": a status
#: this table has never seen must not read as a pass.
_STATUS_MARKERS = {"contradicted": "VIOLATED", "ungrounded": "VIOLATED",
                   "grounded": "holds", "unverified": "undecided"}

#: Stanza order: decision-relevant first — violations, then abstentions, then
#: promises no verdict cross-referenced, then the ones that hold. Within a
#: rank, promise id.
_STATUS_RANK = {"contradicted": 0, "ungrounded": 0, "unverified": 1,
                "grounded": 3}
_NO_VERDICT_MARKER = "not checked"
_NO_VERDICT_RANK = 2


def _field_name(name: str) -> str:
    """*name* without its ``collection#`` prefix. The free-const spelling
    locates a field for the solver; the reader already sees the collection in
    the stanza's ``rule:`` s-expression."""
    return name.rpartition("#")[2]


def _assignment_text(witness: Any) -> str:
    """``"field=value, ..."`` — ``collection#`` prefixes stripped, an empty
    value spelled ``''``, keys sorted by stripped name — or an honest note when
    there is nothing pinned (a non-compiled promise has no witnesses; it never
    fabricates one)."""
    if witness is None:
        return "(no pinned witness)"
    assignment = dict(witness.assignment)
    if not assignment:
        return "(empty assignment)"
    ordered = sorted(assignment, key=lambda name: (_field_name(name), name))
    return ", ".join(f"{_field_name(name)}={assignment[name] or repr('')}"
                     for name in ordered)


def _sec_verdicts(verdicts: Iterable[Any]) -> dict[str, list]:
    """The requirements-channel verdicts, keyed by target. Every ``sec:*``
    verdict targets its promise id (``sec_rules``), so this is the promise-id
    cross-reference the stanzas are marked from."""
    matched: dict[str, list] = {}
    for verdict in verdicts:
        kind = getattr(verdict, "kind", "")
        if isinstance(kind, str) and kind.startswith("sec:"):
            matched.setdefault(verdict.target, []).append(verdict)
    return matched


def _primary_verdict(promise: Any, matched: Mapping[str, list]) -> Any:
    """The verdict that judged *promise* this run — the one whose kind is the
    promise's own domain channel — or ``None`` when nothing cross-references
    (an integrity note on ``sec:artifact`` is evidence, not the judgment)."""
    for verdict in matched.get(promise.id, ()):
        if verdict.kind == f"sec:{promise.domain}":
            return verdict
    return None


def _without_id_prefix(pid: str, message: str) -> str:
    """*message* without its leading ``"<pid>: "`` — the stanza's marker line
    already names the promise."""
    prefix = f"{pid}: "
    return message[len(prefix):] if message.startswith(prefix) else message


def _stanza(rule: Any, matched: Mapping[str, list]) -> list[str]:
    """One promise's stanza: marker + id + domain, the quoted source sentence
    with its file:line, every non-boilerplate verdict message, the rule's own
    s-expression, and the two pinned witnesses — everything the old flat
    rendering carried, in reading order."""
    promise = _promise(rule)
    source = promise.source
    primary = _primary_verdict(promise, matched)
    marker = (_STATUS_MARKERS.get(primary.status, primary.status.upper())
              if primary is not None else _NO_VERDICT_MARKER)
    lines = [f"  {marker:<8}  {promise.id} [{promise.domain}]",
             f"      \"{source.text}\" ({source.file}:{source.line})"]
    for verdict in matched.get(promise.id, ()):
        # A grounded message is boilerplate ("the obligation holds…") the
        # marker already states; every other status carries a reason worth a
        # line — the refuting record, the abstention, an integrity note.
        if verdict.status == "grounded":
            continue
        lines.append(f"      {_without_id_prefix(promise.id, verdict.message)}")
    lines.append(f"      rule: {promise.sexpr}")
    lines.append(f"      + compliant: {_assignment_text(promise.positive)}")
    lines.append(f"      - violating:  {_assignment_text(promise.negative)}")
    return lines


def explain_lines(rules: Iterable[Any] = (), verdicts: Iterable[Any] = (),
                  carried: Iterable[Any] = (),
                  source: str | None = None) -> list[str]:
    """The ``--explain`` promises block: the header counting what enforces,
    then one stanza per compiled rule — cross-referenced against this run's
    *verdicts* by promise id, so the markers (VIOLATED / holds / undecided)
    cannot drift from what the gate decided — then one ``not enforcing`` line
    per *carried* verdict whose promise never became a rule.

    Every fact of the old flat rendering is still here: the s-expression, the
    source sentence and its file:line, and the two witnesses pinned at compile
    time and re-classified at load. All three extra inputs are optional, so a
    caller holding only rules still gets the stanzas ("not checked": no
    verdict was handed in to cross-reference).
    """
    ordered = sorted(rules, key=lambda r: _promise(r).id)
    enforcing = {_promise(r).id for r in ordered}
    stalled = [v for v in carried if getattr(v, "target", "") not in enforcing]
    origin = f" — from {source}" if source else ""
    lines = [f"promises in force ({len(ordered)} enforcing, "
             f"{len({v.target for v in stalled})} not{origin})"]
    if not ordered and not stalled:
        lines.append("  (no compiled requirements were loaded)")
        return lines
    matched = _sec_verdicts(verdicts)

    def rank(rule: Any) -> tuple[int, str]:
        promise = _promise(rule)
        primary = _primary_verdict(promise, matched)
        if primary is None:
            return (_NO_VERDICT_RANK, promise.id)
        return (_STATUS_RANK.get(primary.status, _NO_VERDICT_RANK), promise.id)

    for index, rule in enumerate(sorted(ordered, key=rank)):
        if index:
            lines.append("")
        lines.extend(_stanza(rule, matched))
    if stalled and ordered:
        lines.append("")
    for verdict in sorted(stalled, key=lambda v: (str(v.target), v.message)):
        lines.append(f"  not enforcing  {verdict.target} — {verdict.message}")
    return lines
