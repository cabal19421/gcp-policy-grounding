"""The self-tests of the anchor machinery, through slice 3's execution engine.

Each makes the checker FAIL on something that must never pass: an ``after`` that
equals its ``before``, an ambiguous anchor, a rewrite escaping its scope or
changing more than one line, an outcome that is not FAILED, a rewrite leaving
the file byte-identical. SLICE 3 DOES NOT FLIP ENFORCEMENT LIVE and says so
rather than half-arm it: the shape gate, the ``Removal`` seam and the flip stay
in tests/mutation_contract_manifest.json, REWRITTEN and NOT deleted because they
remain. Slice 3 measured 15,999 ``git diff`` characters.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from tests.agentic.env import REPO_ROOT
from tests.mutation_contract import (
    ACTIVE, AWAITING, ContractError, Mutation, apply_to_copy, awaiting_overflow,
    collects_in, execute, floor_failure, kill_failure, materialise, mutate,
    owner_is_present, owner_signals, parse_outcomes, present_owners, register,
    resolve_span, state_of, strip_parametrization)

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
    assert register() == (), "EMPTY until seed-a lands"


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
