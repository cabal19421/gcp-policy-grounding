"""The regression net for audit rows R26, R27, R41 and R48.

Four findings whose fix is a register entry or a sentence, so none of them has a
natural home in the module it is about — and a register that nothing grades is
exactly what the audit kept finding.

* R26 — two reasons recorded as MEASURED FACT that ``tests/mutation_entries.py``
  and ``tests/mutation_contract.py`` were "absent from this checkout" long after
  both landed. Both escalations still stood on their other, live ground, so
  nothing went red and nothing made the sentences true again. Pinned over every
  escalation reason and every strict-xfail reason at once: a text may still say a
  file is absent, but only about a file that really is.
* R27 — ``ConstraintSolver.mutually_exclusive_always_false``, called nowhere,
  overridden nowhere, with a docstring promising a z3 generalization that has no
  override seam in use. ``gcp_grounding/core/`` is vendored and out of bounds, so
  the row's own proposal is to record a ``ProductEscalation`` rather than edit.
  Pinned here so the record cannot outlive what it describes.
* R41 — every xfail marker passed ``strict=True``, but ``xfail_strict`` was unset
  in the ini, so the next marker that omitted it would have been silently
  non-strict: an escalation that stopped forcing its own retirement. Pinned as
  the RESOLVED setting, not as a line of TOML, plus the sweep that the explicit
  spelling is still on every marker.
* R48 — four of the ten ``PRODUCT_ESCALATIONS`` were quoted nowhere outside the
  register, against the field's own doc comment ("Stable id, quoted from the
  module that works around it"). Pinned over the whole register, so a new entry
  is quoted from its site or is recorded here as un-quotable and why.

WHERE THE REST OF THIS TASK'S ROWS ARE PINNED, because they belong with what
they are about: R03 is the restored ``calls["n"] == 1`` in
``tests/test_gcp_sec_ast.py``; R04 and R46 are the solver-less child run in
``tests/test_gcp_sec_cli.py``; R24 and R25 are
``test_every_count_the_gate_and_its_escalations_quote_is_the_measured_one`` in
``tests/test_gcp_mutation_contract.py``; R28, R29 and R30 are the three new pins
in ``tests/test_gcp_redact.py``, ``tests/test_gcp_sources.py`` and
``tests/test_gcp_cli.py``; R43 is the three nodes that XPASSed out of their
ceiling escalations; R49 is the corpus-table pin in
``tests/test_gcp_agentic_benign.py``; R50 and R51 are the two assertions that
were themselves the defect. R40 is a data re-stamp with NO pin, deliberately:
``line_hint`` is ADVISORY by the contract that defines it
(``tests/mutation_contract.py``, "printed in every failure, NEVER asserted"), and
asserting it would turn every later line shift in four product modules into a red
suite — which is the property content anchoring exists to remove.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

from gcp_grounding.core.solver import BuiltinSolver, ConstraintSolver, Z3Solver
from tests.escalations import ESCALATIONS, PRODUCT_ESCALATIONS
from tests.test_gcp_audit_hallucinated_refs import strict_xfail_reasons

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Every way a reason in this tree spells "this file is not here".
ABSENCE_CLAIMS = (
    "absent from this checkout",
    "not in this checkout",
    "in this checkout at all",
    "absent from this tree",
    "not in this tree",
)

#: A repo-relative module path a reason can name.
NAMED_PATH = re.compile(r"(?:tests|gcp_grounding)/[\w/]+\.py")

#: The one ``PRODUCT_ESCALATIONS`` id no site can carry, and why. Its subject is
#: a DEAD method in vendored ``gcp_grounding/core/`` — there is no workaround
#: module to quote it from, and the package is out of bounds for a test task, so
#: the register is the only place it can live. Anything else here is a defect.
UNQUOTABLE_IDS = frozenset({"ESC-CORE-SOLVER-DEAD-PROBE"})


def _register_prose() -> list[tuple[str, str]]:
    """``(who, text)`` for every sentence a register or a strict xfail asserts
    about this checkout, whitespace-flattened so a re-wrap cannot hide a claim."""
    prose = [(item.id, item.unsatisfiable) for item in ESCALATIONS]
    for item in PRODUCT_ESCALATIONS:
        prose += [(item.id, item.why), (item.id, item.product_fix),
                  (item.id, item.residual_risk)]
    prose += [(f"{module}:{line}", reason)
              for module, line, reason in strict_xfail_reasons()]
    return [(who, " ".join(text.split())) for who, text in prose]


def _tracked_python(*globs: str) -> list[Path]:
    return [path for glob in globs for path in sorted(REPO_ROOT.glob(glob))
            if path.is_file()]


def _absence_violations(prose: list[tuple[str, str]]) -> list[str]:
    """Every ``(who, text)`` claiming a file is absent that this checkout has."""
    wrong = []
    for who, text in prose:
        if not any(claim in " ".join(text.split()) for claim in ABSENCE_CLAIMS):
            continue
        for named in sorted(set(NAMED_PATH.findall(text))):
            if (REPO_ROOT / named).exists():
                wrong.append(f"{who} says {named} is absent; it is here")
    return wrong


# -- R26: a reason may only claim an absence that is real ---------------------


def test_no_reason_claims_a_file_is_absent_while_it_is_in_this_checkout():
    """MEASURED FACTS ROT, and these were load-bearing: both reasons said the two
    mutation-register modules were not in the checkout at all, which is why the
    escalation could not be closed from the task that raised it. Both files had
    landed. Each escalation still failed on its other, live ground, so the suite
    stayed green and the sentence stayed wrong — understating what a reader has
    to do to close it and pointing them at a file they would find immediately.

    The claim is still allowed; it just has to be true. Every path a claiming
    text names is resolved against the tree on every run.
    """
    wrong = _absence_violations(_register_prose())
    assert not wrong, (
        "a register reason states an absence that this checkout contradicts:\n  "
        + "\n  ".join(wrong)
        + "\n  Rewrite the reason to the ground the escalation still stands on, "
        "or retire the escalation. A reason is read by whoever tries to close "
        "it, and pytest -rx prints it on every run.")


def test_the_absence_sweep_catches_the_sentence_the_row_found():
    """MUST-FAIL-FIRST, against the retired text itself. No reason in the tree
    claims an absence any more, so the sweep above is vacuous on today's data and
    would stay green with the detector broken — the two retired sentences are
    what prove it is not.

    They are quoted here and nowhere else: a sentence still in a register would
    be a second place to rot, and the point of R26 is that the reasons agree with
    the tree.
    """
    retired = [
        ("ESC-GX-HFW-FOLD (escalations.py, before R26)",
         "both tests/mutation_entries.py and tests/mutation_contract.py are "
         "FROZEN ACCEPTANCE PATHS and neither file is in this checkout at all"),
        ("ESC-GX-HFW-FOLD-ENTRY (test_gcp_hfw_checks.py, before R26)",
         "tests/mutation_entries.py is a FROZEN acceptance path for "
         "gx-hierfw-placement and is absent from this checkout"),
    ]
    caught = _absence_violations(retired)
    assert len(caught) == 3, caught
    assert all("mutation_entries.py" in row or "mutation_contract.py" in row
               for row in caught), caught
    # A claim about a file that really is absent is left alone, which is what
    # keeps this a truth check and not a ban on the sentence.
    assert _absence_violations([
        ("a real absence", "tests/no_such_module.py is absent from this checkout"),
    ]) == []


# -- R41: strict is the default, and every marker says so anyway --------------


def test_xfail_strict_is_the_resolved_default_and_comes_from_the_ini(pytestconfig):
    """THE RESOLVED SETTING, not a line of TOML: read back through pytest's own
    config so a value that never reaches a run cannot satisfy this.

    Audit row R41 found every one of the suite's xfail markers passing
    ``strict=True`` and the ini silent, so the property held only for as long as
    every future author remembered. An xfail that is not strict does not XPASS
    when its cause is fixed, and in this suite an xfail IS an escalation: the
    XPASS is the whole retirement mechanism.
    """
    assert pytestconfig.getini("xfail_strict") is True
    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["tool"]["pytest"]["ini_options"]["xfail_strict"] is True, (
        "xfail_strict resolved True but is not set in pyproject.toml, so the run "
        "that has it is not the run the README documents")


def test_every_xfail_marker_in_the_suite_still_spells_strict_out():
    """Belt and braces, and it is the belt that names the author's intent: the
    ini makes an omission harmless, this makes it visible."""
    lax = []
    total = 0
    for path in _tracked_python("tests/*.py", "tests/**/*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and ast.unparse(node.func).endswith("xfail")):
                continue
            total += 1
            strict = {k.arg: k.value for k in node.keywords if k.arg}.get("strict")
            if not (isinstance(strict, ast.Constant) and strict.value is True):
                lax.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
    assert total >= 10, f"the marker sweep found only {total} xfails"
    assert not lax, f"xfail markers that do not spell strict=True out: {lax}"


# -- R48: a product escalation's id is quoted from the code it explains -------


def test_every_product_escalation_id_is_quoted_from_the_code_it_explains():
    """``ProductEscalation.id``'s own doc comment says the id is "quoted from the
    module that works around it", and for four of the ten it was not: their only
    mention in the whole tree was their own definition (audit row R48).

    That is the difference between a register and a filing cabinet. An operator
    meets these entries through an ABSTENTION — a message saying the gate did not
    decide something — and the id in that message is what turns "the tool was
    vague" into a record with a measured cause, a product fix and a residual
    risk. With the id only in the register, the abstention names nothing and the
    register is reached by whoever already knew it was there.
    """
    files = [path for path in _tracked_python("gcp_grounding/**/*.py", "tests/**/*.py")
             if path not in (REPO_ROOT / "tests" / "escalations.py", Path(__file__))]
    texts = {path: path.read_text(encoding="utf-8", errors="replace")
             for path in files}
    unquoted, stale = [], []
    for item in PRODUCT_ESCALATIONS:
        sites = [str(path.relative_to(REPO_ROOT)) for path, text in texts.items()
                 if item.id in text]
        if item.id in UNQUOTABLE_IDS:
            if sites:
                stale.append(f"{item.id} is recorded un-quotable but is in {sites}")
        elif not sites:
            unquoted.append(item.id)
    assert not unquoted, (
        f"product escalations quoted nowhere but their own entry: {unquoted}. "
        "Carry the id in the message that mints the abstention it explains, or "
        "in a comment at the site that works around it — or record it in "
        "UNQUOTABLE_IDS with the reason no site can carry it.")
    assert not stale, stale


# -- R27: the dead probe the register records is still dead -------------------


def test_the_dead_solver_probe_is_still_defined_and_still_reaches_no_caller():
    """The entry describes a tree, so the tree is checked: the day this method
    gains a caller or an override, or is deleted, ESC-CORE-SOLVER-DEAD-PROBE
    stops being true and must be retired rather than left standing.

    ``gcp_grounding/core/`` is vendored and out of bounds for a test task, which
    is the case ``PRODUCT_ESCALATIONS`` exists for — so this asserts the finding,
    not the fix.
    """
    name = "mutually_exclusive_always_false"
    assert hasattr(ConstraintSolver, name), (
        f"ConstraintSolver.{name} is gone, so ESC-CORE-SOLVER-DEAD-PROBE "
        "describes a tree that no longer exists and should be retired")
    base = getattr(ConstraintSolver, name)
    for subclass in (BuiltinSolver, Z3Solver):
        assert getattr(subclass, name) is base, (
            f"{subclass.__name__} now overrides {name}: the docstring's z3 "
            "generalization has a seam in use and the entry needs rewriting")
    mentions = {str(path.relative_to(REPO_ROOT)): text.count(name)
                for path, text in ((p, p.read_text(encoding="utf-8", errors="replace"))
                                   for p in _tracked_python("gcp_grounding/**/*.py"))
                if name in text}
    assert mentions == {"gcp_grounding/core/solver.py": 1}, (
        f"{name} now has a reader: {mentions}. That closes the finding — retire "
        "ESC-CORE-SOLVER-DEAD-PROBE rather than leaving it recorded as dead.")
    assert any(item.id == "ESC-CORE-SOLVER-DEAD-PROBE"
               for item in PRODUCT_ESCALATIONS)
