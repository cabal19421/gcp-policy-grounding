"""The self-tests of the anchor machinery slice 1 lands.

Each makes the checker FAIL on something that must never pass: an ``after`` that
equals its ``before``, an ambiguous anchor, a rewrite escaping its own scope or
changing more than one line. The register gate, the outcome reader and the
presence arms are slices 2 and 3, enumerated in the manifest.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from tests.mutation_contract import ContractError, Mutation, mutate, resolve_span

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
