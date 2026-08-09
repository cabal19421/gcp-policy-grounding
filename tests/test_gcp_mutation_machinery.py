"""The self-tests of the anchor machinery, through slice 3's execution engine.

Each makes the checker FAIL on something that must never pass: an ``after`` that
equals its ``before``, an ambiguous anchor, a rewrite escaping its scope or
changing more than one line, an outcome that is not FAILED, a rewrite leaving
the file byte-identical, a mis-shaped entry, an inert ``Removal``. SLICE 4 THEN
FLIPPED ENFORCEMENT LIVE over whatever the register holds -- green over its zero
entries today, and the oracle every seeding task validates against -- and
DELETED the manifest, nothing it listed being outstanding.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from tests.agentic.env import REPO_ROOT
from tests.mutation_contract import (
    ACTIVE, AWAITING, ContractError, Mutation, apply_to_copy, awaiting_overflow,
    collects_in, execute, floor_failure, kill_failure, materialise, mutate,
    owner_is_present, owner_signals, parse_outcomes, present_owners, register,
    resolve_span, state_of, strip_parametrization,
    AWAITING_MAX, INERT, apply_removal, contract_failures, removal_failure, run_nodes,
    CONTRACT_CONTROL_SPAWNS, SPAWNS_PER_ENTRY, contract_spawn_ceiling,
    owner_test_modules)
from tests.spec_assertions import ASSERTIONS

SAMPLE = '''\
from dataclasses import dataclass


@dataclass(frozen=True)
class Widget:
    ports = {"icmp": 1}


def alpha(packet):
    if packet.get("icmp"):
        return {"icmp": 1}
    return None


def beta(packet):
    return {"icmp": 1}
'''

ALPHA = Mutation(
    id="selftest-alpha", module="sample.py", enclosing="alpha",
    before='{"icmp": 1}', after='{"icmp": 2}', line_hint=11,
    behaviour="alpha reports the wrong protocol number",
    must_fail=("tests/test_sample.py::test_alpha",), owner="gx-hierfw-records")

#: (what it is, the entry's deviation, the refusal it must draw). The inert twin
#: is `after == before`, which must ALSO fail the must-fail check slice 2 lands;
#: the last rewrites a two-line `before` as one, renumbering every line below.
REFUSED = [
    ("inert twin", dict(after=ALPHA.before), "before == after"),
    ("ambiguous anchor", dict(enclosing='{"icmp": 1}'), "occurs 3 times"),
    ("no anchor", dict(enclosing=None), "no anchor"),
    ("ambiguous slice", dict(before="packet"), "widen the slice"),
    ("line count", dict(before='if packet.get("icmp"):\n        return {"icmp": 1}',
                        after='return {"icmp": 2}'), "LINE COUNT"),
]


@pytest.mark.parametrize("what,deviation,refusal", REFUSED, ids=[r[0] for r in REFUSED])
def test_the_checker_refuses_an_anchor_it_cannot_resolve(what, deviation, refusal):
    with pytest.raises(ContractError, match=refusal):
        mutate(SAMPLE, replace(ALPHA, **deviation))


def test_an_entry_survives_an_unrelated_edit_above_its_site():
    mutated, line = mutate("# an unrelated comment block\n" * 5 + SAMPLE, ALPHA)
    assert line == ALPHA.line_hint + 5, "the site moved; the anchor did not"
    assert mutated.splitlines()[line - 1] == '        return {"icmp": 2}'


def test_a_slice_that_also_occurs_in_another_def_mutates_only_the_named_scope():
    mutated, line = mutate(SAMPLE, ALPHA)
    start, end = resolve_span(SAMPLE, "alpha")
    assert start <= line <= end, "the rewrite escaped the resolved span"
    assert mutated.splitlines()[5] == '    ports = {"icmp": 1}'
    assert mutated.splitlines()[15] == '    return {"icmp": 1}'


def test_a_decorated_definitions_span_starts_at_its_first_decorator():
    entry = replace(ALPHA, id="selftest-decorator", enclosing="Widget", line_hint=4,
                    before="@dataclass(frozen=True)", after="@dataclass()")
    assert resolve_span(SAMPLE, "Widget") == (4, 6), "the span must cover the decorator"
    mutated, line = mutate(SAMPLE, entry)
    assert line == 4 and mutated.splitlines()[3] == "@dataclass()"


def test_a_two_line_before_is_the_sanctioned_widening_for_an_ambiguous_slice():
    mutated, line = mutate(SAMPLE, replace(
        ALPHA, id="selftest-two-line", before='    if packet.get("icmp"):\n'
        '        return {"icmp": 1}', after='    if packet.get("icmp"):\n'
        '        return {"icmp": 2}'))
    assert line == 11 and mutated.count('{"icmp": 2}') == 1


# -- SLICE 2: the two seams, the two states, the floor and the pin -----------

#: A real mutant of this slice's own stripper, so the arms below have an anchor.
STRIP_NODE = ("tests/test_gcp_mutation_machinery.py::"
              "test_node_ids_are_decided_by_collection_not_by_grep")
SYNTH = Mutation(
    id="selftest-state", module="tests/mutation_contract.py",
    enclosing="strip_parametrization", before='partition("[")[0]',
    after='partition("]")[0]', line_hint=0,
    behaviour="a parametrized node id stops stripping to its function",
    must_fail=(STRIP_NODE,), owner="gx-preflight-empty-key")


def test_owner_presence_is_read_from_the_tree_and_never_defaults_to_true(tmp_path):
    for owner, (module, signal) in owner_signals().items():
        assert owner_is_present(owner, REPO_ROOT), f"{owner}: {signal!r} not in {module}"
    assert not owner_is_present("gx-evidence-invokers", REPO_ROOT, ("gcp_grounding/no.py",))
    module, _ = owner_signals()["gx-hierfw-records"]
    stub = tmp_path / module
    stub.parent.mkdir(parents=True)
    stub.write_text("def _something_else():\n    pass\n", encoding="utf-8")
    assert owner_is_present("gx-hierfw-records", tmp_path) is False, "flipped slice"
    assert owner_is_present("gx-preflight-empty-key", tmp_path) is False
    with pytest.raises(ContractError, match="no presence signal"):
        owner_is_present("gx-not-a-declared-task", REPO_ROOT)
    assert present_owners([SYNTH], REPO_ROOT) == {SYNTH.owner: True}


def test_node_ids_are_decided_by_collection_not_by_grep():
    collects = collects_in(REPO_ROOT)
    assert collects(STRIP_NODE), "this very node"
    assert collects("tests/test_gcp_mutation_machinery.py::"
                    "test_the_checker_refuses_an_anchor_it_cannot_resolve[inert twin]")
    assert not collects("tests/test_gcp_mutation_machinery.py::test_renamed_away")
    assert strip_parametrization("a.py::t[x]") == "a.py::t"


@pytest.mark.parametrize("present,collects,unresolved", [
    (False, True, "owner"), (True, False, "must_fail node id"), (True, True, "")])
def test_a_state_is_computed_from_the_tree_and_is_only_ever_one_of_two(
        present, collects, unresolved):
    state = state_of(SYNTH, REPO_ROOT, present=lambda o: present, collects=lambda n: collects)
    assert state.state == (AWAITING if unresolved else ACTIVE)
    assert unresolved in state.unresolved and state.source in state.line()
    report = floor_failure([state], {SYNTH.owner: present})
    assert bool(report) is (present and bool(unresolved)), "the floor is ABSOLUTE"
    if report:
        assert SYNTH.id in report and SYNTH.owner in report and STRIP_NODE in report
    assert bool(awaiting_overflow([state])) is bool(unresolved), "the pin bounds it"
    assert not floor_failure([], {}) and not awaiting_overflow([]), "zero entries"


# -- SLICE 3: the execution engine. NO gate is armed and none is written. ----

#: The node the mutant below must drive RED: slice 1's own line-count guard.
REFUSAL = ("tests/test_gcp_mutation_machinery.py::"
           "test_the_checker_refuses_an_anchor_it_cannot_resolve[line count]")


def test_the_outcome_reader_reads_all_four_shapes_and_names_the_skip_inversion():
    """READ THE OUTCOME OF EVERY NAMED NODE EXPLICITLY. ``-rA`` prints a skip by
    file and line, and a skip IS the removal-before-collection inversion."""
    report = ("PASSED tests/a.py::test_p\nFAILED tests/a.py::test_f\n"
              "ERROR tests/a.py::test_e\nSKIPPED [1] tests/a.py:12: a removal\n")
    nodes = ("tests/a.py::test_p", "tests/a.py::test_f", "tests/a.py::test_e",
             "tests/a.py::test_s")
    got = parse_outcomes(report, nodes)
    assert list(got.values()) == ["PASSED", "FAILED", "ERROR", "SKIPPED"]
    with pytest.raises(ContractError, match="NO outcome"):
        parse_outcomes(report, ("tests/b.py::test_never_ran",))
    lived = kill_failure(replace(SYNTH, must_fail=nodes), got)
    assert "=PASSED" in lived and "=ERROR" in lived and "ordering inversion" in lived
    assert kill_failure(SYNTH, dict.fromkeys(SYNTH.must_fail, "FAILED")) == ""
    assert "must_fail is EMPTY" in kill_failure(replace(SYNTH, must_fail=()), {})


def test_a_mutant_is_executed_in_a_scratch_copy_and_its_named_node_must_FAIL(tmp_path):
    """The whole chain for real over a SYNTHETIC entry -- no gate calls this yet:
    a FRESH ``git archive HEAD`` copy, the UNMUTATED copy asserted green BEFORE
    any outcome is read, the sha256 proving the rewrite landed, FAILED off -rA."""
    live = replace(SYNTH, id="selftest-executed", enclosing="mutate",
                   before="if len(clean_lines) != len(mutant_lines):",
                   after="if False:", must_fail=(REFUSAL,))
    assert execute(live, REPO_ROOT, tmp_path) == "", "the mutant must be KILLED"
    copy = materialise(REPO_ROOT, tmp_path, "sha256-arm")
    apply_to_copy(copy, live)
    with pytest.raises(ContractError, match="occurs 0 times"):
        apply_to_copy(copy, live)


# -- SLICE 4: the shape gate, the ``Removal`` seam, and THE FLIP -------------

#: Well shaped AND a real mutant of gx-preflight-empty-key's frozen predicate.
PIN = next(a for a in ASSERTIONS if a.id == "SA-PREFLIGHT-BINDINGS-PRESENT")
GOOD = Mutation(
    id="selftest-shape", module=PIN.module, enclosing="_legitimately_empty",
    before=PIN.predicate, after='doc.get("bindings", []) == []', line_hint=371,
    behaviour="an absent bindings key reads as legitimately empty",
    must_fail=(PIN.node_id,), owner="gx-preflight-empty-key")
MISSHAPEN = [(dict(owner="gx-nope"), "no task this document declares"),
             (dict(must_fail=()), "must_fail is EMPTY"),
             (dict(must_fail=("tests/mutation_contract.py::test_x",)),
              "not a pytest node id"),
             (dict(after=PIN.predicate), "before == after")]


def test_the_shape_gate_fails_a_bad_entry_and_an_index_is_the_last_resort():
    """IN BOTH STATES: each deviation computes AWAITING, never excused."""
    parked = dict(present=lambda o: False, collects=lambda n: True)
    for deviation, complaint in MISSHAPEN:
        bad, at = contract_failures([replace(GOOD, **deviation)], REPO_ROOT, **parked)
        assert at[0].state == AWAITING and any(complaint in b for b in bad), bad
    mutated, line = mutate(SAMPLE, replace(ALPHA, before="packet", after="pkt",
                                           occurrence=2))
    assert line == 10 and mutated.splitlines()[9] == '    if pkt.get("icmp"):'
    with pytest.raises(ContractError, match="occurrence 9"):
        mutate(SAMPLE, replace(ALPHA, before="packet", after="pkt", occurrence=9))


def test_the_inert_removal_and_the_inert_twin_both_make_the_checker_FAIL(monkeypatch):
    """Negative controls: the removal lands AFTER collection, so its witness
    RUNS and PASSES -- SURVIVED, never the SKIPPED of the inversion."""
    assert apply_removal(INERT.id, monkeypatch) is INERT
    with pytest.raises(ContractError, match="no such Removal"):
        apply_removal("selftest-absent", monkeypatch)
    assert "not one of FAMILY_KINDS" in removal_failure(replace(INERT, family="x"), {})
    monkeypatch.setenv("GCP_TEST_REMOVAL", INERT.id)
    got = run_nodes(REPO_ROOT, INERT.must_fail)
    assert set(got.values()) == {"PASSED"} and "SURVIVED" in removal_failure(INERT, got)
    twin = replace(GOOD, after=GOOD.before)
    with pytest.raises(ContractError, match="before == after"):
        mutate("", twin)
    assert "SURVIVED" in kill_failure(twin, dict.fromkeys(twin.must_fail, "PASSED"))


def test_the_contract_is_now_ENFORCED_live_over_whatever_the_register_holds(tmp_path):
    """THE FLIP. Zero entries green; the floor FIRES on an entry parked with its
    owner PRESENT and the pin bounds it; then the REAL seams, over an EXECUTED
    ACTIVE entry and over the register itself."""
    seams = dict(present=lambda o: True, collects=lambda n: True)
    assert contract_failures((), REPO_ROOT, **seams) == ([], []), "zero entries"
    bad, at = contract_failures([replace(GOOD, module="gcp/no.py")], REPO_ROOT, **seams)
    assert GOOD.owner in at[0].line() and "Error" in at[0].unresolved
    assert any("owner PRESENT" in b for b in bad) and any("pinned max" in b for b in bad)
    live = dict(present=lambda o: owner_is_present(o, REPO_ROOT),
                collects=collects_in(REPO_ROOT), parent=tmp_path)
    bad, at = contract_failures([GOOD], REPO_ROOT, **live)
    assert [s.state for s in at] == [ACTIVE] and bad == [], bad
    bad, at = contract_failures(register(), REPO_ROOT, **live)
    debt = "\n".join(s.line() for s in at if s.state == AWAITING)
    print(debt)
    assert not bad, "\n".join(bad) + "\n" + debt
    assert {s.id for s in at if s.state == AWAITING} <= AWAITING_MAX, debt


# -- SLICE 5: cross-module witnesses, and a spawn budget of the contract's own


def test_a_witness_may_name_any_test_module_the_repo_owns_and_no_other_file():
    """BLOCKER ONE, cleared: the one-module restriction was slice 4's and not
    the design's, and excluded 26 of the evidence funnel's 29 entries. A node in
    a file that is no test module of this repo's is still REFUSED."""
    seams = dict(present=lambda o: True, collects=collects_in(REPO_ROOT))
    assert STRIP_NODE.partition("::")[0] != owner_test_modules()[GOOD.owner]
    cross = replace(GOOD, id="selftest-cross", must_fail=(PIN.node_id, STRIP_NODE))
    bad, at = contract_failures([cross], REPO_ROOT, **seams)
    assert bad == [] and [s.state for s in at] == [ACTIVE], bad
    off = [replace(GOOD, must_fail=("tests/mutation_contract.py::t",))]
    assert any("not a pytest" in b for b in contract_failures(off, REPO_ROOT, **seams)[0])


def test_the_contract_spawns_land_on_a_ceiling_of_its_own(tmp_path, subprocess_budget):
    """BLOCKER TWO, cleared: the suite's 450 measures 447 in a full run -- THREE
    spawns of headroom against an ACTIVE entry's FOUR -- so the machinery's
    children are MARKED and counted apart, EXACTLY, on a ceiling that SCALES
    with the register (controls alone at zero). The accounting is proved on the
    synthetic entry so the register executes in ONE place, the flip test; a
    register pinned EMPTY here was seed-a's third measured blocker. EVERY child
    is marked: counting some and losing others is the leak."""
    budget, live = subprocess_budget, dict(
        present=lambda o: owner_is_present(o, REPO_ROOT),
        collects=collects_in(REPO_ROOT), parent=tmp_path)
    before = budget.marked_total
    assert contract_failures([GOOD], REPO_ROOT, **live)[0] == []
    assert budget.marked_total - before == SPAWNS_PER_ENTRY, budget.marked
    assert contract_spawn_ceiling() == budget.max_marked >= CONTRACT_CONTROL_SPAWNS, (
        "the fixture pins the register-scaled ceiling, controls alone at zero")
    assert not [k for k in budget.counts if k.startswith("tests.mutation_contract")]
