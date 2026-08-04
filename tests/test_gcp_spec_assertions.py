"""The FROZEN self-test of the frozen spec-assertion register.

This module and `tests/spec_assertions.py` are acceptance paths for every task
in designs/gcp-gx-fixes.md after `gx-spec-register`, and appear in NO other
task's paths. A diff that relaxes a REGISTERED predicate therefore leaves two
options: edit a frozen acceptance path, which fails review outright, or leave
this suite red. Weakening stops being the cheap path because it becomes a
guaranteed FAIL rather than a maybe-nobody-notices.

WHAT IT CHECKS, per the design clause it implements: each entry's predicate must
occur VERBATIM in the named module after WHITESPACE-ONLY normalization; the
named node id must be collectible; the clause must still occur in some file
under `designs/`, matched by TEXT and never by line number so an unrelated edit
cannot rot it; ids are unique; and every module missing from the checkout must
be listed in `PENDING_MODULES`.

COLLECTIBILITY IS DECIDED BY `ast`, NEVER BY `--collect-only`. A registered node
can live in another family's module, which in an unmerged checkout may not even
import — and spawning a collector per entry would cost the subprocess budget and
could run another family's collection-time probes. Parsing the file answers the
only question this suite asks: does a test of that name exist there.

MUST-FAIL-FIRST IS PINNED HERE, NOT JUST OBSERVED ONCE. Editing a registered
predicate in the working tree was run and recorded (the run is in the task
notes), but a self-test whose teeth were seen once and never again is
decoration, so `test_a_weakened_predicate_is_reported_and_names_its_clause` and
`test_a_present_predicate_is_accepted_however_it_is_wrapped` drive the same
checker over synthetic source on every run.
"""

from __future__ import annotations

import ast
import importlib.util
import inspect
import re
import subprocess
from pathlib import Path

import pytest

from tests.spec_assertions import (
    ASSERTIONS,
    AWAITING,
    OUT_OF_DOCUMENT_OWNERS,
    PENDING_MODULES,
    TASK_IDS,
    SpecAssertion,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

# The AWAITING ceiling. It may only SHRINK: an entry leaves AWAITING when its
# owning task lands the strict predicate, and nothing may ever be added — a task
# that cannot land its predicate ESCALATES per house rule 4 instead.
PINNED_AWAITING_MAX = 15

_AWAITING_OWNER = dict(AWAITING)

# The verdict-lineno invariant, which the amendment made REGISTERED precisely so
# that the 15 anonymous mutation survivors sitting on it become named coverage
# of the fail-open branches RC1 lives on.
LINENO_PREDICATE = "all(v.lineno == 0 for v in"
LINENO_MODULES = ("tests/test_gcp_preflight.py", "tests/test_gcp_sec_rules.py")


# -- resolution -------------------------------------------------------------


def normalize(text: str) -> str:
    """Collapse WHITESPACE ONLY, so a re-wrap cannot hide or fake a predicate.

    Nothing else is touched: no case folding, no quote normalization, no token
    equivalence. `== 1` never normalizes to `<= 1`.
    """
    return " ".join(text.split())


def module_source(relative_path: str) -> str | None:
    """The module's source, or None when it is not in this checkout.

    `inspect.getsource` over a module object built with
    `importlib.util.module_from_spec` and NEVER executed: the design asks for
    `inspect.getsource`, and skipping execution means reading another family's
    module cannot run its collection-time probes and cannot fail on an import
    that is only satisfiable in a merged checkout.
    """
    path = REPO_ROOT / relative_path
    if not path.is_file():
        return None
    name = "_spec_register_probe_" + re.sub(r"\W", "_", relative_path)
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None:
            raise ValueError(f"no import spec for {relative_path}")
        return inspect.getsource(importlib.util.module_from_spec(spec))
    except (OSError, TypeError, ValueError, AttributeError):
        return path.read_text(encoding="utf-8")


def node_is_collectible(node_id: str) -> bool:
    """Does `path::[Class::]test_name` name a test that exists, per `ast`?

    Parametrization is stripped: `test_x[case-0]` resolves to `test_x`, because
    the register pins the test, never one of its cases.
    """
    relative_path, separator, tail = node_id.partition("::")
    if not separator or not tail:
        return False
    path = REPO_ROOT / relative_path
    if not path.is_file():
        return False
    try:
        body = ast.parse(path.read_text(encoding="utf-8")).body
    except (OSError, SyntaxError, ValueError):
        return False
    for part in (piece.split("[", 1)[0] for piece in tail.split("::")):
        for node in body:
            if isinstance(node, ast.ClassDef) and node.name == part:
                body = node.body
                break
            if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == part):
                body = []
                break
        else:
            return False
    return True


def designs_directory() -> Path | None:
    """The design corpus, or None when this checkout cannot reach one.

    `designs/` is git-ignored repo-wide and tracked on no branch, so a worktree
    has no copy of its own — see ESC-GX-SPEC-001. Follow this worktree's `.git`
    POINTER FILE (`gitdir: <main>/.git/worktrees/<name>`) back to the main
    checkout, which is where the corpus really lives.
    """
    local = REPO_ROOT / "designs"
    if local.is_dir():
        return local
    pointer = REPO_ROOT / ".git"
    if not pointer.is_file():
        return None
    try:
        text = pointer.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not text.startswith("gitdir:"):
        return None
    git_dir = Path(text.split(":", 1)[1].strip())
    for parent in (git_dir, *git_dir.parents):
        if parent.name == ".git":
            candidate = parent.parent / "designs"
            if candidate.is_dir():
                return candidate
    return None


def design_corpus() -> tuple[tuple[str, str], ...]:
    """(name, normalized text) for every readable file under `designs/`."""
    directory = designs_directory()
    if directory is None:
        return ()
    documents = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        try:
            documents.append((path.name,
                              normalize(path.read_text(encoding="utf-8"))))
        except (OSError, UnicodeDecodeError):
            continue
    return tuple(documents)


def clause_is_anchored(clause: str) -> bool:
    """Does the clause still occur, as TEXT, in some design document?

    By text and never by line number: an unrelated edit that moves the clause
    down the page must not break this check.
    """
    needle = normalize(clause)
    return any(needle in text for _, text in design_corpus())


# -- the checker, so its teeth can themselves be tested ---------------------


def predicate_failure(entry: SpecAssertion, source: str) -> str | None:
    """None when the predicate is present, else the failure text to report."""
    if normalize(entry.predicate) in normalize(source):
        return None
    return (
        f"REGISTERED predicate is missing: {entry.id}\n"
        f"  module:    {entry.module}\n"
        f"  node:      {entry.node_id}\n"
        f"  predicate: {entry.predicate}\n"
        f"  design clause that mandates it: {entry.clause}\n"
        "  House rule 6: land the predicate exactly as quoted.\n"
        "  House rule 2: never resolve this by relaxing the assertion — not by\n"
        "  widening an equality into a membership, not by turning `== 1` into\n"
        "  `>= 1` or `<= 1`, not by replacing a set equality with an `all` loop.\n"
        "  House rule 4: if the clause genuinely cannot be satisfied, append an\n"
        "  Escalation to tests/escalations.py and land the predicate under\n"
        "  pytest.mark.xfail(strict=True, reason=<that id>). Editing this\n"
        "  register is not one of the options: it is a frozen acceptance path."
    )


# -- shape, which is all a PENDING entry is held to -------------------------


def assert_shape(entry: SpecAssertion) -> None:
    assert entry.id and entry.id == entry.id.strip(), entry
    assert entry.predicate.strip(), f"{entry.id}: an empty predicate pins nothing"
    assert entry.clause.strip(), f"{entry.id}: an entry with no clause is not anchored"
    assert entry.module.endswith(".py"), f"{entry.id}: module is not a python file"
    assert not entry.module.startswith("/"), f"{entry.id}: module must be repo-relative"
    assert "::" in entry.node_id, f"{entry.id}: node_id must be a pytest node id"
    assert entry.node_id.split("::")[0].endswith(".py"), entry.node_id


@pytest.mark.parametrize("entry", ASSERTIONS, ids=[a.id for a in ASSERTIONS])
def test_every_entry_has_the_shape_the_register_promises(entry):
    assert_shape(entry)


def test_ids_are_unique():
    ids = [entry.id for entry in ASSERTIONS]
    duplicated = sorted({name for name in ids if ids.count(name) > 1})
    assert not duplicated, f"duplicate spec-assertion ids: {duplicated}"


# -- the register's own contract -------------------------------------------


@pytest.mark.parametrize("entry", ASSERTIONS, ids=[a.id for a in ASSERTIONS])
def test_every_registered_predicate_is_present_or_explicitly_awaited(entry):
    """PRESENCE ALWAYS WINS: the text is looked for BEFORE anything excuses it."""
    assert_shape(entry)
    source = module_source(entry.module)
    if source is None:
        # Rule (a), the missing-module half: only the shape is checked. The
        # deletion guard is test_missing_modules_are_the_pending_ones.
        pytest.skip(f"{entry.id}: {entry.module} is not in this checkout (PENDING)")
    if predicate_failure(entry, source) is None:
        return
    if not node_is_collectible(entry.node_id):
        # Rule (a): a task that has not landed yet cannot redden this suite.
        pytest.skip(f"{entry.id}: {entry.node_id} is not collectible yet (PENDING)")
    # Rule (b): collectible node, absent predicate — this fails unless an owner
    # is on record for it.
    owner = _AWAITING_OWNER.get(entry.id)
    assert owner is not None, predicate_failure(entry, source)
    pytest.skip(f"{entry.id}: awaiting {owner}, which owes this predicate")


def test_missing_modules_are_the_pending_ones():
    """Deleting any module this register does NOT already expect to be absent
    is caught here immediately, rather than going quiet as a pending entry."""
    missing = {entry.module for entry in ASSERTIONS
               if not (REPO_ROOT / entry.module).is_file()}
    unexpected = sorted(missing - PENDING_MODULES)
    assert not unexpected, (
        "a registered module vanished from the checkout without being listed in "
        f"PENDING_MODULES: {unexpected}. A registered predicate cannot be "
        "retired by deleting the file that carries it."
    )


def test_pending_modules_names_nothing_it_does_not_need_to():
    """A stale PENDING_MODULES entry is a hole: it would let that module be
    deleted later without this suite firing. The list may only SHRINK."""
    registered = {entry.module for entry in ASSERTIONS}
    assert PENDING_MODULES <= registered, sorted(PENDING_MODULES - registered)


@pytest.mark.parametrize("entry", ASSERTIONS, ids=[a.id for a in ASSERTIONS])
def test_every_clause_is_still_anchored_in_the_design_corpus(entry):
    if not design_corpus():
        pytest.skip("no design corpus is reachable from this checkout "
                    "(ESC-GX-SPEC-001)")
    assert clause_is_anchored(entry.clause), (
        f"{entry.id}: its design clause is no longer in the corpus:\n"
        f"  {entry.clause}\n"
        "  The clause is matched by TEXT, never by line number, so this fires "
        "only when the mandating sentence itself was edited or removed — which "
        "is an amendment, not a refactor."
    )


# -- AWAITING, whose count may only shrink ---------------------------------


def test_every_awaiting_id_is_a_registered_id():
    unknown = sorted({name for name, _ in AWAITING}
                     - {entry.id for entry in ASSERTIONS})
    assert not unknown, f"AWAITING names ids that are not registered: {unknown}"


def test_awaiting_ids_are_unique():
    names = [name for name, _ in AWAITING]
    assert len(names) == len(set(names)), names


def test_the_awaiting_list_may_only_shrink():
    assert len(AWAITING) <= PINNED_AWAITING_MAX, (
        f"AWAITING grew to {len(AWAITING)} against a pin of "
        f"{PINNED_AWAITING_MAX}. An entry leaves AWAITING when its owner lands "
        "the strict predicate; nothing may be added — a predicate that cannot "
        "be landed is an Escalation, not a new excuse."
    )


def test_the_landed_gate_zero_predicates_are_not_awaited():
    """`gx-preflight-empty-key` landed BEFORE this task, so both of its
    registered predicates must be live, present and unexcused today."""
    awaited = {name for name, _ in AWAITING}
    for entry_id in ("SA-PREFLIGHT-BINDINGS-PRESENT", "SA-PREFLIGHT-NO-LINENO"):
        assert entry_id not in awaited, (
            f"{entry_id} belongs to a task that has already landed; excusing it "
            "would make this register decoration on the day it lands."
        )
        entry = next(e for e in ASSERTIONS if e.id == entry_id)
        source = module_source(entry.module)
        assert source is not None, f"{entry.module} is missing"
        assert predicate_failure(entry, source) is None, predicate_failure(entry, source)


def test_every_awaiting_owner_is_recorded_and_never_a_typo():
    """The live, non-literal form of the owner rule: an owner is either a task
    of this document, or an explicitly escalated out-of-document owner."""
    escalated = set(OUT_OF_DOCUMENT_OWNERS)
    stray = sorted({owner for _, owner in AWAITING} - set(TASK_IDS) - escalated)
    assert not stray, (
        f"AWAITING names owner tasks that do not exist: {stray}. An entry whose "
        "owner will never land is a permanent excuse wearing an owner's name."
    )


@pytest.mark.xfail(
    strict=True,
    reason=("ESC-GX-SPEC-002: SA-SECAST-CALLED-ONCE is owned by sx-sec-ast, a "
            "task of the PREDECESSOR design document, so no task id in "
            "gcp-gx-fixes.md can own it"),
)
def test_every_awaiting_owner_is_a_task_in_this_document():
    """The clause-literal assertion, landed strict-xfailed per house rule 4."""
    stray = sorted({owner for _, owner in AWAITING} - set(TASK_IDS))
    assert not stray, f"owners outside designs/gcp-gx-fixes.md: {stray}"


def test_every_escalated_owner_names_a_real_escalation():
    from tests.escalations import ESCALATIONS

    known = {escalation.id for escalation in ESCALATIONS}
    for owner, escalation_id in OUT_OF_DOCUMENT_OWNERS.items():
        assert escalation_id in known, (
            f"{owner} is excused by {escalation_id}, which is not registered in "
            "tests/escalations.py — an unrecorded exception is a route-around."
        )


def test_task_ids_are_a_subset_of_the_documents_own_task_ids():
    corpus = dict(design_corpus())
    document = corpus.get("gcp-gx-fixes.md")
    if document is None:
        pytest.skip("designs/gcp-gx-fixes.md is not reachable (ESC-GX-SPEC-001)")
    declared = set(re.findall(r"\(id: ([a-z0-9-]+)\)", document))
    invented = sorted(TASK_IDS - declared)
    assert not invented, (
        f"TASK_IDS names tasks the design does not declare: {invented}. A "
        "subset, not an equality, so a later amendment that ADDS a task cannot "
        "redden this frozen file."
    )


# -- the amendment's MUST NOW PROVE ----------------------------------------


def test_the_verdict_lineno_invariant_is_registered_in_two_test_modules():
    """Frozen and clause-anchored in both — previously nothing in the design
    pinned this invariant, which is exactly why the mutation survivors sitting
    on it could be mistaken for equivalent mutants."""
    carriers = {entry.module: entry for entry in ASSERTIONS
                if entry.predicate == LINENO_PREDICATE}
    for module in LINENO_MODULES:
        assert module in carriers, (
            f"the verdict-lineno invariant is not registered for {module}; "
            "an agent facing a lineno survivor could then answer it by deleting "
            "the invariant."
        )
        entry = carriers[module]
        assert entry.clause == (
            "policy documents have no line numbers, so every verdict's lineno "
            "is 0 and the json-path location leads the message instead"
        ), entry
        assert entry.node_id.startswith(module + "::"), entry
    if design_corpus():
        assert clause_is_anchored(carriers[LINENO_MODULES[0]].clause)


def test_the_lineno_invariant_is_live_in_preflight_and_awaited_in_sec_rules():
    owners = _AWAITING_OWNER
    assert "SA-PREFLIGHT-NO-LINENO" not in owners, (
        "gx-preflight-empty-key has landed, so its lineno entry must be PRESENT")
    assert owners.get("SA-SECRULES-NO-LINENO") == "gx-evidence-invokers", (
        "the sec_rules lineno entry must be awaited under its owner so it "
        "cannot redden this suite before that task lands")


# -- the self-test's own teeth ---------------------------------------------


_SAMPLE = ASSERTIONS[0]


def test_a_weakened_predicate_is_reported_and_names_its_clause():
    """Turning an equality into a `>=`, the exact RC3 move, must be caught and
    must print the design clause that mandates the strict form."""
    weakened = 'return (isinstance(doc, Mapping)\n        and len(doc["bindings"]) >= 0)'
    failure = predicate_failure(_SAMPLE, weakened)
    assert failure is not None
    assert _SAMPLE.clause in failure
    assert _SAMPLE.predicate in failure
    assert _SAMPLE.node_id in failure


def test_a_present_predicate_is_accepted_however_it_is_wrapped():
    """Whitespace ONLY: a re-wrap keeps the entry green, a rewrite does not."""
    wrapped = ('    return (isinstance(doc, Mapping)\n'
               '            and "bindings" in doc\n'
               '            and doc["bindings"] == [])')
    assert predicate_failure(_SAMPLE, wrapped) is None
    renamed = wrapped.replace('doc["bindings"] == []', 'doc["bindings"] == list()')
    assert predicate_failure(_SAMPLE, renamed) is not None


def test_collectibility_is_decided_by_ast_and_strips_parametrization():
    assert node_is_collectible(_SAMPLE.node_id)
    assert node_is_collectible(_SAMPLE.node_id + "[doc1]")
    assert not node_is_collectible("tests/test_gcp_preflight.py::test_no_such_test")
    assert not node_is_collectible("tests/no_such_module.py::test_x")
    assert not node_is_collectible("tests/test_gcp_preflight.py")


def test_a_clause_that_no_longer_occurs_is_not_anchored():
    if not design_corpus():
        pytest.skip("no design corpus is reachable (ESC-GX-SPEC-001)")
    assert clause_is_anchored(_SAMPLE.clause)
    assert not clause_is_anchored(
        "this sentence appears in no design document in this repository")


# -- ESC-GX-SPEC-001 --------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason=("ESC-GX-SPEC-001: designs/ is git-ignored and tracked on no branch, "
            "so a clean checkout carries no corpus to anchor a clause against"),
)
def test_the_design_corpus_is_tracked_in_the_repository():
    """The clause-literal assertion, landed strict-xfailed per house rule 4.

    Every clause check above degrades to a SKIP when the corpus is unreachable,
    which is honest but is not the anchoring the design asks for. This is the
    named, green state for that gap; the day the corpus is tracked, the strict
    xfail becomes an XPASS and forces the escalation to be retired.
    """
    result = subprocess.run(
        ["git", "ls-files", "designs"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        pytest.skip("git is not usable here, so trackedness cannot be decided")
    assert result.stdout.split(), (
        "no file under designs/ is tracked, so the clause anchor can only be "
        "resolved by reaching outside this checkout"
    )
