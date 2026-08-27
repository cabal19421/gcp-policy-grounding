"""The solver census: every formula a run actually executed, recorded where it
was built.

``--explain``'s constraint block used to be re-derived after the fact — the CLI
re-read the proposal, re-extracted its CEL claims and re-translated them. That
answers "what would this document encode to", which is a different question from
"what did this run solve": a promise that abstained before it ever reached the
encoder, a firewall rule the packet algebra refused, an estate collection the
snapshot never captured — none of them are visible to a re-derivation, and a
re-derivation can just as easily show a formula no check ever built.

So the formulas are recorded AT THE POINT OF CONSTRUCTION, by the construction
the executing check itself performed, and the renderer only formats what was
recorded. Nothing here re-guesses a formula, and nothing here can invent one:
with no census recording every entry point below is inert.

THREE RECORDING SEAMS, one per family that cannot reach the CLI any other way:

* :func:`evaluate_rule` wraps one compiled promise's evaluation, and
  :func:`record_obligation` — called from :func:`gcp_grounding.sec_probes.obligation`,
  the single place a promise's polarity is applied — writes down the obligation
  that evaluation handed to the solver. FIRST WRITER WINS per promise, which is
  what makes the entry the top-level obligation rather than one of the
  per-record obligations a closed decision may re-ground afterwards.
* :func:`check_scope` names the domain check the registry is about to invoke,
  and :func:`instrument` hands that check a z3 module whose ``Solver`` records
  the assembled assertion it is asked to decide. This is the only seam that can
  see the firewall and Cloud Armor packet assertions: those checks assemble the
  formula inline and drive ``z3.Solver()`` themselves, so there is no
  intermediate function holding the assembled term.
* Everything else — CEL translation, the ``--baseline`` subset assertion — is
  already re-derivable from the document alone and stays where it was.

The instrumented module is handed out ONLY while a census is recording and only
inside a check :data:`FAMILIES` names, so a run without ``--explain`` gets the
real z3 module by identity and every other check does too.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import Any, Iterator, Optional

from .core.log import get_logger

logger = get_logger(__name__)

__all__ = ["FAMILIES", "Entry", "Census", "recording", "active",
           "evaluate_rule", "record_obligation", "check_scope", "instrument",
           "sexpr_of"]

#: Check module → the census family its assertions are filed under. Only these
#: modules get an instrumented z3: every other check decides its own formulas
#: with the module the solver imported, untouched.
#:
#: THE TABLE IS THE DECLARED SCOPE, not a discovery. The census reports the
#: families ``--explain`` says it reports — the VPC firewall exposure and pair
#: checks and the Cloud Armor priority checks — so a domain whose assertions
#: nobody asked for cannot start appearing in the block because it happened to
#: build a formula. Adding one is this table plus its line in the renderer.
FAMILIES = {
    "gcp_grounding.fw_checks": "firewall",
    "gcp_grounding.armor_checks": "armor",
}


@dataclass(frozen=True)
class Entry:
    """One formula this run built, as the check that built it saw it.

    *family* and *anchor* are the sort key and together identify the entry;
    *detail* carries whatever the recording seam knew and the renderer cannot
    re-derive (the promise's mode, today).
    """

    family: str
    anchor: str
    sexpr: str
    detail: str = ""


class Census:
    """The formulas one run executed, keyed by ``(family, anchor)``.

    FIRST WRITER WINS. A check that solves repeatedly — one obligation per
    record, one assertion per firewall group — contributes the first formula it
    assembled, so the entry is the one the check's own decision rests on rather
    than the last refinement it happened to make.
    """

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], Entry] = {}
        #: The promise being evaluated, ``(family, anchor)``, or None.
        self.rule: Optional[tuple[str, str]] = None
        #: The census-family check being invoked, ``(family, anchor)``, or None.
        self.check: Optional[tuple[str, str]] = None

    def add(self, family: str, anchor: str, sexpr: str, detail: str = "") -> None:
        """Record one formula. An empty s-expression records nothing: a formula
        that would not render is not evidence that one ran."""
        key = (family, anchor)
        if not sexpr or key in self._entries:
            return
        self._entries[key] = Entry(family, anchor, sexpr, detail)

    def entries(self) -> tuple[Entry, ...]:
        """Every recorded formula, ordered by family and then anchor."""
        return tuple(sorted(self._entries.values(),
                            key=lambda entry: (entry.family, entry.anchor)))

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"Census({len(self._entries)} formula(s))"


# -- the active census --------------------------------------------------------

#: The censuses currently recording, outermost first. A list rather than a
#: single slot so a nested run cannot delete the outer run's census.
_ACTIVE: list[Census] = []


@contextlib.contextmanager
def recording() -> Iterator[Census]:
    """Record every formula built inside the block.

    Popped in a ``finally`` by identity, so an exception mid-run leaves nothing
    behind to go on collecting the next run's formulas.
    """
    census = Census()
    _ACTIVE.append(census)
    try:
        yield census
    finally:
        for index in range(len(_ACTIVE) - 1, -1, -1):
            if _ACTIVE[index] is census:
                del _ACTIVE[index]
                break


def active() -> Optional[Census]:
    """The innermost recording census, or None when nothing is recording."""
    return _ACTIVE[-1] if _ACTIVE else None


def sexpr_of(formula: Any) -> str:
    """*formula*'s s-expression on one line, or ``""`` when it will not render.

    z3 wraps a long s-expression across lines; the census renders one line per
    formula, so the whitespace is collapsed here rather than in the renderer.
    """
    try:
        text = formula.sexpr()
    except Exception:  # noqa: BLE001 — the census never costs a graded run
        logger.debug("the census could not render a formula", exc_info=True)
        return ""
    return " ".join(text.split()) if isinstance(text, str) else ""


# -- seam 1: compiled promises ------------------------------------------------


def evaluate_rule(rule: Any, ctx: Any) -> Any:
    """``rule.evaluate(ctx)`` with the obligation it reaches recorded.

    The rule is evaluated identically either way — this only names the promise
    so :func:`record_obligation` knows whose obligation it is being handed. A
    promise that abstains before the encoder (not applicable, off subject, a
    collection the snapshot did not capture, no z3) never reaches
    :func:`gcp_grounding.sec_probes.obligation` and so contributes no entry.
    """
    census = active()
    promise = getattr(rule, "promise", None)
    if census is None or promise is None:
        return rule.evaluate(ctx)
    domain = getattr(promise, "domain", "") or "?"
    previous = census.rule
    census.rule = (f"sec:{domain}", getattr(promise, "id", "") or "?")
    try:
        return rule.evaluate(ctx)
    finally:
        census.rule = previous


def record_obligation(obligation: Any, mode: str) -> None:
    """Record the obligation a promise's evaluation just built.

    Inert outside :func:`evaluate_rule`, which is what keeps the compile-time
    probes and the artifact's witness re-classification — both of which build
    obligations of their own, from the same function — out of a census of what
    this grounding run decided.

    The FIRST obligation of an evaluation is the entry, and that is the one the
    rule hands to the decider: a closed decision re-grounds the same ast once
    per record afterwards to name the record that refutes it, and those
    per-record obligations are refinements of the decision, not the decision.
    """
    census = active()
    if census is None or census.rule is None:
        return
    family, anchor = census.rule
    census.add(family, anchor, sexpr_of(obligation), detail=mode)


# -- seam 2: the domain checks that drive their own solver --------------------


@contextlib.contextmanager
def check_scope(label: str, anchor: str) -> Iterator[None]:
    """Name the check *label* is about to run, for the length of that call.

    *label* is the registry's ``<module>.<qualname>`` identity; a check outside
    :data:`FAMILIES` opens no scope at all, so it is handed the real z3 module
    exactly as it is without a census.
    """
    census = active()
    family = _family_of(label) if census is not None else None
    if census is None or family is None:
        yield
        return
    previous = census.check
    census.check = (family, anchor)
    try:
        yield
    finally:
        census.check = previous


def _family_of(label: str) -> Optional[str]:
    """The census family owning the check *label*, or None."""
    for module, family in FAMILIES.items():
        if label == module or label.startswith(f"{module}."):
            return family
    return None


def instrument(z3: Any) -> Any:
    """The z3 module a check should build with — *z3* itself, unless a census
    is recording and the check being invoked is one of :data:`FAMILIES`."""
    census = active()
    if z3 is None or census is None or census.check is None:
        return z3
    family, anchor = census.check
    return _CensusZ3(z3, census, family, anchor)


class _CensusZ3:
    """The z3 module, identical in every respect but ``Solver``.

    Attribute access forwards to the real module, so every type, constant and
    constructor a check reads is the real one — including ``sat`` / ``unsat``,
    which checks compare by identity against the result they get back.
    """

    def __init__(self, z3: Any, census: Census, family: str, anchor: str) -> None:
        self._z3 = z3
        self._census = census
        self._family = family
        self._anchor = anchor

    def __getattr__(self, name: str) -> Any:
        return getattr(self.__dict__["_z3"], name)

    def __repr__(self) -> str:
        return f"<census z3 for [{self._family}] {self._anchor}>"

    def Solver(self, *args: Any, **kwargs: Any) -> Any:  # noqa: N802 — z3's name
        """A solver that records the assertion it is asked to decide."""
        return _CensusSolver(self._z3, self._z3.Solver(*args, **kwargs),
                             self._census, self._family, self._anchor)


class _CensusSolver:
    """A z3 solver that files its assembled assertion with the census.

    Recorded on the way INTO ``check()``, so a check that reaches the solver is
    counted whatever the solver then answers — sat, unsat, or the unknown that
    becomes an abstention.
    """

    def __init__(self, z3: Any, inner: Any, census: Census, family: str,
                 anchor: str) -> None:
        self._z3 = z3
        self._inner = inner
        self._census = census
        self._family = family
        self._anchor = anchor

    def __getattr__(self, name: str) -> Any:
        return getattr(self.__dict__["_inner"], name)

    def __repr__(self) -> str:
        return repr(self._inner)

    def check(self, *args: Any, **kwargs: Any) -> Any:
        self._census.add(self._family, self._anchor,
                         _assembled(self._z3, self._inner))
        return self._inner.check(*args, **kwargs)


def _assembled(z3: Any, solver: Any) -> str:
    """The conjunction of everything asserted on *solver*, as one s-expression.

    This is the assembled assertion the check built, read back off the solver
    rather than rebuilt from the pieces — the axioms and the bad property a
    packet check adds separately are one formula to the solver, and that is the
    formula the census reports.

    THE CONJUNCTION IS ASSEMBLED AS TEXT, not as a ``z3.And`` over the terms:
    building one more term would add a node to the solver's own context, and the
    model a satisfiable check hands back is the solver's choice among many. A
    census that changed which witness a verdict names would be reporting on a
    run it had altered.
    """
    try:
        terms = list(solver.assertions())
    except Exception:  # noqa: BLE001 — the census never costs a graded run
        logger.debug("the census could not read a solver's assertions",
                     exc_info=True)
        return ""
    rendered = [sexpr_of(term) for term in terms]
    if not rendered or not all(rendered):
        return ""
    if len(rendered) == 1:
        return rendered[0]
    return "(and " + " ".join(rendered) + ")"
