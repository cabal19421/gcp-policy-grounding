"""THE GATE: every register-wide assertion, and the pinned tuples nothing else owns.

It grades tests/mutation_entries.py THROUGH tests/mutation_contract.py's
machinery and reaches NEITHER -- both, and tests/test_gcp_mutation_machinery.py,
are frozen here, which makes this a gate and not a party to what it measures.
The tuples live HERE because the six repin tasks may edit the register and carry
this file frozen: no diff can park an id and raise a pin at once.

MEASURED THE DAY THIS LANDED, and printed below on every run: 44 of the 65
required ids are in the register and ALL 44 compute ACTIVE, so the AWAITING pin
is ZERO and the missing 21 are a SEED FAULT (ESC-GX-GATE-001); the whole-register
mutant run is already spent, the frozen machinery module taking 192 of the 199
marked spawns and leaving the per-Removal term (ESC-GX-GATE-002), of which this
gate uses 6, five of them new in a full run measuring 197/199; and THE SEEDED
DEFICIT that is Gate 3's acceptance criterion is that
all 7 removals are pending so ZERO kill anything, 5 of their 15 nodes do not
collect, and 4 of 15 families and 4 of 9 capabilities have a removal. Diff
19,7xx, this module 17,0xx of it -- inside the 18,000 the task pins for it.
"""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace

import pytest

from tests import mutation_contract as mc
from tests.agentic.capabilities import CAPABILITIES
from tests.agentic.env import REPO_ROOT
from tests.mutation_contract import (
    ACTIVE, AWAITING, Mutation, collects_in, contract_failures, materialise,
    mutate, owner_is_present, register, removal_failure, removal_register,
    resolve_span, run_nodes)
from tests.spec_assertions import TASK_IDS

#: THE REQUIRED-ID TUPLE, named in full and GROW-ONLY -- the opposite polarity
#: from the allowlists below, which are holes. PRESENT in EITHER state satisfies.
REQUIRED_MK_IDS = tuple("""
    MK-P01 MK-P02 MK-P03 MK-P04 MK-P05 MK-P06 MK-P07 MK-P08 MK-P09 MK-P10 MK-P11
    MK-P12 MK-P13 MK-P14 MK-P15 MK-I01 MK-I02 MK-I03 MK-I04 MK-I05 MK-I06 MK-I07
    MK-I08 MK-I09 MK-I10 MK-I11 MK-I12 MK-I13 MK-I14 MK-I15 MK-I16 MK-I17 MK-I18
    MK-I19 MK-I20 MK-I21 MK-I22 MK-I23 MK-I24 MK-I25 MK-I26 MK-I27 MK-I28 MK-I29
    MK-S01 MK-S02 MK-E01 MK-E02 MK-E03 MK-E04 MK-E05 MK-E06 MK-E07 MK-O01 MK-O02
    MK-H01 MK-H02 MK-H03 MK-H04 MK-H05 MK-V01 MK-V02 MK-V03 MK-V04 MK-V05
    """.split())

#: The ids permitted to COMPUTE AWAITING, and the count. MEASURED EMPTY.
AWAITING_IDS: frozenset = frozenset()
AWAITING_COUNT_MAX = 0

#: The ``Removal`` ids permitted to be ``pending``: Gate 3 work outstanding.
PENDING_REMOVAL_IDS = frozenset({
    "RM-IAM-ESCALATION-LAYER", "RM-IAM-PUBLIC-PRINCIPAL-KIND",
    "RM-NETWORK-PLANE-UNAVAILABLE", "RM-VPCSC-DOCUMENT-AND-PAIR-CHECKS",
    "RM-VPCSC-DOMAIN-UNREGISTERED", "RM-VPCSC-ABSENT-VERSUS-EMPTY",
    "RM-HOOK-SUCCESS-BEFORE-THE-EVENT"})
PENDING_REMOVAL_MAX = 7

#: The measured starting deficit. NO exemption: anything off it must be covered.
UNCOVERED_FAMILIES = frozenset({
    "benign", "degradation", "evasion", "orgpolicy", "plumbing", "secreq",
    "sequence", "snapshot", "sources", "tf_benign", "tf_plumbing"})
UNCOVERED_CAPABILITIES = frozenset({
    "armor", "iam_existence", "org_constraint_value", "org_enforcement",
    "tf_claims"})

#: A REAL entry whose mutant is INERT: it rewrites a COMMENT in ``ground_policy``.
_COMMENT = "        # Every claim — existence kinds included — is offered to"
SURVIVOR = Mutation(
    id="gate-selftest-survivor", module="gcp_grounding/preflight.py",
    enclosing="ground_policy", before=_COMMENT, after=_COMMENT.upper(),
    line_hint=299, behaviour="a comment is rewritten, so nothing is mutated",
    must_fail=("tests/test_gcp_preflight.py::"
               "test_absent_bindings_key_is_unverified_not_legitimately_empty",),
    owner="gx-preflight-empty-key")


def seams() -> dict:
    return dict(present=lambda owner: owner_is_present(owner, REPO_ROOT),
                collects=collects_in(REPO_ROOT))


@pytest.fixture(scope="module")
def graded():
    entries = register()
    bad, states = contract_failures(entries, REPO_ROOT, **seams())
    print("AWAITING DEBT:\n" + "\n".join(
        s.line() for s in states if s.state == AWAITING))
    return entries, bad, states


def live_removals() -> list:
    return [r for r in removal_register() if not getattr(r, "pending", False)]


def taken_by(removal) -> set:
    """Its own ``apply``, replayed against a recorder that applies nothing."""
    taken: set = set()
    removal.apply(SimpleNamespace(
        setattr=lambda t, n, v: taken.add((getattr(t, "__name__", str(t)), n)),
        setitem=lambda m, k, v: taken.add((k, "*"))))
    return taken


def capability_cover() -> dict:
    cover: dict = {}
    for removal in removal_register():
        taken = taken_by(removal)
        for name, cap in CAPABILITIES.items():
            if any((m, a) in taken or (m, "*") in taken for m, a in cap.guts):
                cover.setdefault(name, removal.id)
    return cover


def family_cover() -> dict:
    return {r.family: r.id for r in reversed(removal_register())
            if any(n.startswith(f"tests/test_gcp_agentic_{r.family}.py::")
                   for n in r.must_fail)}


def anchor_failure(entry) -> tuple:
    """(drift, failure) on CONTENT, never a line: ONE definition, ``before`` once
    inside it, the change in the span, one line differing, the sha256 moved."""
    clean = (REPO_ROOT / entry.module).read_text(encoding="utf-8")
    start, end = resolve_span(clean, entry.enclosing)
    scope = "".join(clean.splitlines(keepends=True)[start - 1:end])
    mutated, line = mutate(clean, entry)
    fail = ""
    if scope.count(entry.before) != 1 and not entry.occurrence:
        fail = f"{entry.id}: `before` occurs {scope.count(entry.before)} times"
    if sha256(mutated.encode()).hexdigest() == sha256(clean.encode()).hexdigest():
        fail = f"{entry.id}: the mutant's sha256 equals the clean source's"
    drift = "" if start <= entry.line_hint <= end else (
        f"DRIFT {entry.id}: hint {entry.line_hint} outside {entry.enclosing} "
        f"({start}-{end}); the anchor resolved at {line}")
    return drift, fail


def ordering_failure(removal, outcomes) -> str:
    """A probe answers LOUD SKIP when its subject is gone while this gate demands
    FAILED, so it must be computed BEFORE the removal: all-SKIPPED is that
    inversion, and an import-time removal leaving a node PASSING took nothing."""
    if outcomes and set(outcomes.values()) == {"SKIPPED"}:
        return (f"{removal.id}: every node SKIPPED -- the probe was evaluated "
                "AFTER the removal, so the family disabled itself instead of "
                "failing. A skip is never a kill.")
    alive = sorted(n for n, one in outcomes.items() if one == "PASSED")
    if alive and any(attr == "*" for _, attr in taken_by(removal)):
        return f"{removal.id}: an import-time removal left {alive} PASSED"
    return ""


def test_the_pinned_tuples_hold_and_the_register_names_no_stranger(graded):
    entries, _, _ = graded
    assert len(REQUIRED_MK_IDS) == len(set(REQUIRED_MK_IDS)) == 65
    ids = {e.id for e in entries}
    assert ids <= set(REQUIRED_MK_IDS), sorted(ids - set(REQUIRED_MK_IDS))
    assert all(e.owner in TASK_IDS and e.must_fail for e in entries)
    pending = {r.id for r in removal_register()} - {r.id for r in live_removals()}
    assert pending <= PENDING_REMOVAL_IDS, sorted(pending - PENDING_REMOVAL_IDS)
    assert len(pending) <= PENDING_REMOVAL_MAX
    for removal in removal_register():
        assert getattr(removal, "owner", "") in TASK_IDS and removal.must_fail


@pytest.mark.xfail(strict=True, reason="ESC-GX-GATE-001: the register holds 44 "
                   "of the 65; gx-mutation-contract-seed-b is not an ancestor")
def test_every_required_must_kill_id_is_in_the_register(graded):
    entries, _, _ = graded
    missing = sorted(set(REQUIRED_MK_IDS) - {e.id for e in entries})
    assert not missing, f"{len(missing)} required ids are absent: {missing}"


def test_awaiting_is_computed_a_subset_of_its_pin_and_under_the_floor(graded):
    _, bad, states = graded
    awaiting = {s.id for s in states if s.state == AWAITING}
    debt = "\n".join(s.line() for s in states if s.state == AWAITING)
    assert awaiting <= AWAITING_IDS, f"unlisted AWAITING entries:\n{debt}"
    assert len(awaiting) <= AWAITING_COUNT_MAX, debt
    assert not [b for b in bad if "owner PRESENT" in b], "the floor is ABSOLUTE"
    assert not bad, "\n".join(bad) + "\n" + debt
    for state in states:
        assert state.owner in TASK_IDS and state.source in mc.SOURCES
        assert state.state in (ACTIVE, AWAITING), "there is no third state"


def test_every_named_node_id_still_collects_and_each_exemption_prints(graded):
    entries, _, states = graded
    collects, live = collects_in(REPO_ROOT), {r.id for r in live_removals()}
    items = [(e, s.state == ACTIVE, f"AWAITING({s.unresolved})")
             for e, s in zip(entries, states)]
    items += [(r, r.id in live, "pending") for r in removal_register()]
    union = {n for item, inside, _ in items if inside for n in item.must_fail}
    print("\n".join(f"EXEMPT {n} {i.id} owner={getattr(i, 'owner', '?')} {why}"
                    for i, inside, why in items if not inside
                    for n in i.must_fail))
    absent = sorted(n for n in union if not collects(n))
    assert not absent, (f"uncollectible INSIDE the union: {absent}. Recover "
                        "the id or escalate; never drop the node.")
    assert union, "nothing is named at all"


def test_every_family_and_capability_has_a_removal_or_is_pinned_as_debt():
    families, capabilities = family_cover(), capability_cover()
    modules = (REPO_ROOT / "tests").glob("test_gcp_agentic_*.py")
    uncovered = frozenset(f.name[17:-3] for f in modules) - set(families)
    ungutted = set(CAPABILITIES) - set(capabilities)
    print(f"FAMILIES {families}\nUNCOVERED {sorted(uncovered)}\n"
          f"CAPABILITIES {capabilities}\nUNGUTTED {sorted(ungutted)}")
    assert uncovered <= UNCOVERED_FAMILIES, sorted(uncovered - UNCOVERED_FAMILIES)
    assert ungutted <= UNCOVERED_CAPABILITIES, sorted(ungutted - UNCOVERED_CAPABILITIES)
    assert (len(uncovered) <= len(UNCOVERED_FAMILIES)
            and len(ungutted) <= len(UNCOVERED_CAPABILITIES)), "shrink-only"


def test_the_clean_source_control_reports_every_named_node_PASSED(graded, monkeypatch):
    """GUARD 1: ONE child over the union of every ACTIVE ``must_fail``, on
    UNMUTATED source, so no must-kill is discharged by an already-red test."""
    entries, _, states = graded
    union = sorted({n for e, s in zip(entries, states) if s.state == ACTIVE
                    for n in e.must_fail})
    seen, run = [], mc.subprocess.run
    monkeypatch.setattr(mc.subprocess, "run",
                        lambda argv, **kw: seen.append((argv, kw)) or run(argv, **kw))
    outcomes = run_nodes(REPO_ROOT, union)
    red = sorted(f"{n}={got}" for n, got in outcomes.items() if got != "PASSED")
    assert not red, f"the control is not green, so no kill it grades is real: {red}"
    assert len(outcomes) == len(union) >= len([s for s in states if s.state == ACTIVE])
    assert seen[0][0][1] == "-B" and seen[0][1]["env"]["PYTHONDONTWRITEBYTECODE"]


def test_the_anchor_of_every_entry_resolves_on_content_and_drift_only_prints(graded):
    reports = [anchor_failure(entry) for entry in graded[0]]
    print("\n".join(drift for drift, _ in reports if drift))
    assert not [fail for _, fail in reports if fail], reports


def test_every_live_removal_is_executed_and_the_ordering_holds(monkeypatch):
    for removal in live_removals():
        monkeypatch.setenv("GCP_TEST_REMOVAL", removal.id)
        outcomes = run_nodes(REPO_ROOT, removal.must_fail)
        assert removal_failure(removal, outcomes) == "", removal.id
        assert ordering_failure(removal, outcomes) == "", removal.id
    removal = removal_register()[0]
    allskip = dict.fromkeys(removal.must_fail, "SKIPPED")
    assert "evaluated AFTER the removal" in ordering_failure(removal, allskip)
    assert "SKIPPED" in removal_failure(removal, allskip), "a skip is never a kill"
    import_time = next(r for r in removal_register()
                       if any(a == "*" for _, a in taken_by(r)))
    passing = dict.fromkeys(import_time.must_fail, "PASSED")
    assert "PASSED" in ordering_failure(import_time, passing)
    killed = dict.fromkeys(removal.must_fail, "FAILED")
    assert ordering_failure(removal, killed) == "" == removal_failure(removal, killed)


REFUSED = [
    ("an anchor that does not resolve", dict(enclosing="no_such_def"),
     "owner PRESENT", True),
    ("an owner naming no task", dict(owner="gx-not-a-task"),
     "no task this document declares", False),
    ("an empty must_fail", dict(must_fail=()), "must_fail is EMPTY", True),
    ("a node outside the repo's test modules",
     dict(must_fail=("tests/mutation_contract.py::test_x",)),
     "not a pytest node id", True),
]


@pytest.mark.parametrize("what,deviation,complaint,from_tree", REFUSED,
                         ids=[case[0] for case in REFUSED])
def test_the_contract_FAILS_on_a_shape_the_register_must_never_hold(
        what, deviation, complaint, from_tree):
    """An owner no task declares has no presence SIGNAL either and reading one
    RAISES, so that case is graded through the parked seams instead."""
    use = seams() if from_tree else dict(present=lambda o: False,
                                         collects=lambda n: True)
    bad, states = contract_failures([replace(SURVIVOR, **deviation)], REPO_ROOT, **use)
    assert any(complaint in failure for failure in bad), bad
    assert states[0].state in (ACTIVE, AWAITING), "never a third state"


def test_the_floor_outranks_the_listing_and_the_pin_may_only_shrink(monkeypatch):
    """THE FLOOR TEST: an entry whose OWNER IS PRESENT, LISTED, with an
    uncollectible node id FAILS naming the id and the owner rather than parking.
    Listing silences the PIN alone, so raising it is the only way in."""
    parked = replace(SURVIVOR, must_fail=("tests/test_gcp_preflight.py::test_gone",))
    bad, states = contract_failures([parked], REPO_ROOT, **seams())
    assert states[0].state == AWAITING and "test_gone" in states[0].unresolved
    assert any("beyond the pinned maximum" in failure for failure in bad)
    monkeypatch.setattr(mc, "AWAITING_MAX", frozenset({parked.id}))
    bad, _ = contract_failures([parked], REPO_ROOT, **seams())
    assert not [b for b in bad if "beyond the pinned maximum" in b], "the pin yields"
    assert [b for b in bad if parked.id in b and parked.owner in b
            and "owner PRESENT" in b], f"the floor is ABSOLUTE: {bad}"


def test_a_listed_entry_is_executed_anyway_and_a_surviving_mutant_FAILS(
        tmp_path, monkeypatch):
    """THE ANTI-ABUSE TEST: a LISTED entry that resolves, collects and has its
    owner present is EXECUTED regardless, and its mutant must kill."""
    monkeypatch.setattr(mc, "AWAITING_MAX", frozenset({SURVIVOR.id}))
    bad, states = contract_failures([SURVIVOR], REPO_ROOT, parent=tmp_path, **seams())
    assert states[0].state == ACTIVE, "a listing decides nothing"
    assert [b for b in bad if b.startswith(f"{SURVIVOR.id}: SURVIVED")], bad
    assert (tmp_path / SURVIVOR.id / "pyproject.toml").is_file(), "a fresh copy"
    assert anchor_failure(SURVIVOR) == ("", ""), "one site, in source, one line"
    with pytest.raises(FileExistsError):
        materialise(REPO_ROOT, tmp_path, SURVIVOR.id)


@pytest.mark.xfail(strict=True, reason="ESC-GX-GATE-002: the frozen ceiling "
                   "budgets ONE whole-register execution and the frozen "
                   "machinery module spends it")
def test_this_gate_can_afford_to_execute_every_active_mutation_itself(graded):
    active = len([s for s in graded[2] if s.state == ACTIVE])
    spent = mc.SPAWNS_PER_ENTRY * len(register()) + mc.CONTRACT_CONTROL_SPAWNS
    room = mc.contract_spawn_ceiling() - spent
    assert room >= mc.SPAWNS_PER_ENTRY * active + 1, (
        f"{room} marked spawns are left; executing {active} ACTIVE entries plus "
        f"one clean-source control needs {mc.SPAWNS_PER_ENTRY * active + 1}")
