"""The FROZEN self-test of the append-only escalation register.

House rule 4 makes "I could not satisfy this clause" a GREEN, NAMED state — the
cheapest passing path, and strictly cheaper than rewriting the assertion to fit
the code, which is a review FAIL. That only works if the state cannot rot, so
this module (frozen for every task) asserts three things about
`tests/escalations.py` (frozen for none):

* every registered node id really carries `xfail(strict=True)` whose reason
  NAMES its escalation id — an escalation nobody landed is a story, not a state;
* ids are unique;
* a required-id tuple is still a SUBSET of the register, so a mandated
  escalation cannot be deleted to make a suite look clean.

`strict=True` is the load-bearing half: the day the owning task lands the fix,
the xfail becomes an XPASS and this suite goes RED, so an escalation cannot be
forgotten either.

The strict-marker check is decided by `ast`, never by importing the module under
inspection, for the same reason the spec-assertion register uses `ast`: a
registered node can live in a module that does not import in an unmerged
checkout, and an escalation must stay legible exactly then.
"""

from __future__ import annotations

import ast

import pytest

from tests.escalations import ESCALATIONS, OUT_OF_DOCUMENT_OWNER_TASKS, Escalation
from tests.spec_assertions import TASK_IDS
from tests.test_gcp_spec_assertions import (
    REPO_ROOT,
    clause_is_anchored,
    design_corpus,
    module_source,
    node_is_collectible,
)

# Escalations this document mandates. A SUBSET assertion, so the register stays
# append-only: new escalations are always welcome, these two may never leave.
# ESC-GX-SPEC-001 — the design corpus is untracked, so a clause anchor cannot be
# resolved inside a clean checkout. ESC-GX-SPEC-002 — one AWAITING owner is a
# task of the predecessor design document.
REQUIRED_ESCALATION_IDS = ("ESC-GX-SPEC-001", "ESC-GX-SPEC-002")


def _function_node(source: str, node_id: str) -> ast.AST | None:
    """The def named by `path::[Class::]name`, per `ast`, or None."""
    _, separator, tail = node_id.partition("::")
    if not separator or not tail:
        return None
    try:
        body = ast.parse(source).body
    except (SyntaxError, ValueError):
        return None
    found: ast.AST | None = None
    for part in (piece.split("[", 1)[0] for piece in tail.split("::")):
        for node in body:
            if isinstance(node, ast.ClassDef) and node.name == part:
                body, found = node.body, node
                break
            if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == part):
                body, found = [], node
                break
        else:
            return None
    return found


def strict_xfail_failure(escalation: Escalation, source: str) -> str | None:
    """None when the node carries a strict xfail naming this id, else why not."""
    node = _function_node(source, escalation.node_id)
    if node is None:
        return (f"{escalation.id}: {escalation.node_id} does not exist. An "
                "escalation must LAND its spec-literal assertion, not merely "
                "describe it.")
    decorators = getattr(node, "decorator_list", [])
    marks = [d for d in decorators
             if isinstance(d, ast.Call) and ast.unparse(d.func).endswith("xfail")]
    if not marks:
        return (f"{escalation.id}: {escalation.node_id} carries no "
                "pytest.mark.xfail — house rule 4 requires the SPEC-LITERAL "
                "assertion to be landed under one, never deleted or softened.")
    for mark in marks:
        keywords = {k.arg: k.value for k in mark.keywords if k.arg}
        strict = keywords.get("strict")
        if not (isinstance(strict, ast.Constant) and strict.value is True):
            continue
        reason = keywords.get("reason")
        if reason is not None and escalation.id in ast.unparse(reason):
            return None
    return (
        f"{escalation.id}: {escalation.node_id} is xfailed, but not with "
        "strict=True AND a reason naming the escalation id.\n"
        "  strict=True is what makes the escalation self-retiring: the day the "
        "owning task lands the fix the xfail becomes an XPASS and goes RED.\n"
        "  A non-strict xfail is silence with extra steps.\n"
        f"  clause:        {escalation.clause}\n"
        f"  unsatisfiable: {escalation.unsatisfiable}"
    )


def _assert_shape(escalation: Escalation) -> None:
    assert escalation.id.startswith("ESC-"), escalation
    assert escalation.clause.strip(), f"{escalation.id}: no clause recorded"
    assert escalation.unsatisfiable.strip(), (
        f"{escalation.id}: an escalation with no reason is a shrug")
    assert escalation.owner_task.strip(), f"{escalation.id}: no owner task"
    assert "::" in escalation.node_id, f"{escalation.id}: node_id is not a node id"


@pytest.mark.parametrize("escalation", ESCALATIONS,
                         ids=[e.id for e in ESCALATIONS])
def test_every_escalation_has_the_shape_the_register_promises(escalation):
    _assert_shape(escalation)


def test_ids_are_unique():
    ids = [escalation.id for escalation in ESCALATIONS]
    duplicated = sorted({name for name in ids if ids.count(name) > 1})
    assert not duplicated, f"duplicate escalation ids: {duplicated}"


def test_the_required_escalations_are_still_registered():
    """A mandated escalation cannot be deleted to tidy a suite."""
    registered = {escalation.id for escalation in ESCALATIONS}
    missing = sorted(set(REQUIRED_ESCALATION_IDS) - registered)
    assert not missing, (
        f"required escalations are gone from the register: {missing}. Retiring "
        "one means landing its fix — at which point its strict xfail XPASSes "
        "and tells you so."
    )


@pytest.mark.parametrize("escalation", ESCALATIONS,
                         ids=[e.id for e in ESCALATIONS])
def test_every_registered_node_is_strict_xfailed_naming_its_id(escalation):
    module = escalation.node_id.split("::")[0]
    source = module_source(module)
    if source is None:
        pytest.skip(f"{escalation.id}: {module} is not in this checkout")
    assert strict_xfail_failure(escalation, source) is None, \
        strict_xfail_failure(escalation, source)


@pytest.mark.parametrize("escalation", ESCALATIONS,
                         ids=[e.id for e in ESCALATIONS])
def test_every_registered_node_is_collectible(escalation):
    module = escalation.node_id.split("::")[0]
    if not (REPO_ROOT / module).is_file():
        pytest.skip(f"{escalation.id}: {module} is not in this checkout")
    assert node_is_collectible(escalation.node_id), (
        f"{escalation.id}: {escalation.node_id} does not resolve to a test")


@pytest.mark.parametrize("escalation", ESCALATIONS,
                         ids=[e.id for e in ESCALATIONS])
def test_every_escalation_clause_is_anchored_in_the_design_corpus(escalation):
    if not design_corpus():
        pytest.skip("no design corpus is reachable from this checkout "
                    "(ESC-GX-SPEC-001)")
    assert clause_is_anchored(escalation.clause), (
        f"{escalation.id}: the clause it escalates is not in the design corpus:\n"
        f"  {escalation.clause}\n"
        "  An escalation against a clause nobody wrote excuses nothing."
    )


@pytest.mark.parametrize("escalation", ESCALATIONS,
                         ids=[e.id for e in ESCALATIONS])
def test_every_escalation_owner_is_a_task_that_exists(escalation):
    assert (escalation.owner_task in TASK_IDS
            or escalation.owner_task in OUT_OF_DOCUMENT_OWNER_TASKS), (
        f"{escalation.id}: owner_task {escalation.owner_task!r} is neither a "
        "task of designs/gcp-gx-fixes.md nor recorded in "
        "escalations.OUT_OF_DOCUMENT_OWNER_TASKS, which is the append-only "
        "home for an escalation raised by a predecessor-document task."
    )


# -- the self-test's own teeth ---------------------------------------------
#
# Removing a registered escalation's strict marker was run in the working tree
# and recorded (the run is in the task notes); these drive the same checker over
# synthetic source on every run, so the teeth cannot be filed off later.


_SAMPLE = ESCALATIONS[0]

_STRICT = (
    '@pytest.mark.xfail(strict=True, reason="ESC-GX-SPEC-001: untracked")\n'
    "def test_the_design_corpus_is_tracked_in_the_repository():\n"
    "    assert False\n"
)


def test_a_strict_xfail_naming_the_id_is_accepted():
    assert strict_xfail_failure(_SAMPLE, _STRICT) is None


def test_a_dropped_strict_marker_is_caught():
    relaxed = _STRICT.replace("strict=True, ", "")
    failure = strict_xfail_failure(_SAMPLE, relaxed)
    assert failure is not None and "strict=True" in failure


def test_a_strict_xfail_that_names_another_escalation_is_caught():
    misattributed = _STRICT.replace("ESC-GX-SPEC-001", "ESC-GX-SPEC-999")
    assert strict_xfail_failure(_SAMPLE, misattributed) is not None


def test_an_unmarked_or_absent_node_is_caught():
    unmarked = _STRICT.split("\n", 1)[1]
    assert "no pytest.mark.xfail" in (strict_xfail_failure(_SAMPLE, unmarked) or "")
    assert "does not exist" in (strict_xfail_failure(_SAMPLE, "x = 1\n") or "")


def test_the_two_escalations_this_task_raises_are_both_landed_here():
    """Both live in tests/test_gcp_spec_assertions.py, the frozen self-test of
    the register — so the escape hatch and the thing it excuses are read
    together."""
    for escalation_id in REQUIRED_ESCALATION_IDS:
        escalation = next(e for e in ESCALATIONS if e.id == escalation_id)
        assert escalation.node_id.startswith("tests/test_gcp_spec_assertions.py::")
        assert (REPO_ROOT / "tests/test_gcp_spec_assertions.py").is_file()
