"""The seed's own coverage literal, carried under ESC-GX-SEEDA-001.

seed-a's body makes 44 entries plus the removal set mandatory AND makes 18,000
diff characters binding, and the two cannot both be met: five entries written in
their final form measured 648 characters each, so the whole seed projects past
34,000. The clause is escalated rather than thinned, and the assertion that would
discharge it is LANDED here under a STRICT xfail instead of being deleted -- the
day the remaining parts seed MK-I01..MK-I29 and the removal set, this XPASSes and
goes RED. PIECE (c) IS THAT DAY, so the marker is CONDITIONAL now on an
incomplete register -- STRICT still, as the frozen escalation self-test requires.
"""

from __future__ import annotations

import pytest

from tests.mutation_contract import register, removal_register

#: AMENDMENT 2's two series, in full.
REQUIRED_IDS = tuple([f"MK-P{n:02d}" for n in range(1, 16)]
                     + [f"MK-I{n:02d}" for n in range(1, 30)])


def test_the_preflight_family_is_seeded_in_full():
    """The half that FITS, asserted unconditionally: all 15, no gaps."""
    seeded = [e.id for e in register()]
    missing = [i for i in REQUIRED_IDS if i.startswith("MK-P") and i not in seeded]
    assert not missing, f"MK-P entries missing from the register: {missing}"


#: Piece (b) of the escalation's measured three-way split, landed here.
FUNNEL_SEEDED = tuple(f"MK-I{n:02d}" for n in range(1, 16))


def test_the_first_fifteen_evidence_funnel_entries_are_seeded_in_full():
    """The second piece that FITS, asserted unconditionally: all 15, no gaps,
    and every one of them owned by the funnel task whose source they anchor in."""
    seeded = [e.id for e in register()]
    missing = [i for i in FUNNEL_SEEDED if i not in seeded]
    assert not missing, f"MK-I entries missing from the register: {missing}"
    owners = {e.owner for e in register() if e.id in FUNNEL_SEEDED}
    assert owners == {"gx-evidence-invokers"}, owners


def test_every_seeded_entry_carries_the_whole_mandated_shape():
    """The ten fields over BOTH blocks, so appending can neither thin an entry
    nor shape one into a third state by leaving a field out. It never relaxes
    the machinery's own gate -- it refuses what that gate would have to run."""
    for e in register():
        assert e.id and e.owner and e.module.endswith(".py"), e
        assert e.enclosing, f"{e.id}: enclosing is None, so it has no anchor"
        assert e.before != e.after, f"{e.id}: nothing is mutated"
        assert e.behaviour and isinstance(e.line_hint, int), e.id
        assert e.must_fail, f"{e.id}: must_fail is EMPTY, so nothing witnesses it"
        for node in e.must_fail:
            module, sep, name = node.partition("::")
            assert sep and name, f"{e.id}: {node!r} is no pytest node id"
            assert module.startswith("tests/test_gcp_"), f"{e.id}: {node!r}"
    ids = [e.id for e in register()]
    assert len(set(ids)) == len(ids), ids


SEED_INCOMPLETE = bool([i for i in REQUIRED_IDS
                        if i not in {e.id for e in register()}]) or not removal_register()


@pytest.mark.xfail(SEED_INCOMPLETE, strict=True,
                   reason="ESC-GX-SEEDA-001: the 44 entries and the removal set "
                          "do not fit one 18,000-character diff")
def test_the_seed_covers_every_amendment_2_entry_and_the_removal_set():
    seeded = [e.id for e in register()]
    assert not [i for i in REQUIRED_IDS if i not in seeded]
    assert removal_register(), "the removal set is unseeded"


#: The seven RC2-MEASURED removals, named in full and GROW-ONLY: a repin task
#: ADDS to this set, and no diff may drop one.
RC2_REMOVAL_IDS = frozenset({
    "RM-IAM-ESCALATION-LAYER", "RM-IAM-PUBLIC-PRINCIPAL-KIND",
    "RM-NETWORK-PLANE-UNAVAILABLE", "RM-VPCSC-DOCUMENT-AND-PAIR-CHECKS",
    "RM-VPCSC-DOMAIN-UNREGISTERED", "RM-VPCSC-ABSENT-VERSUS-EMPTY",
    "RM-HOOK-SUCCESS-BEFORE-THE-EVENT"})

#: SHRINK-ONLY, and never a licence: ``pending`` is the Gate 3 backlog, so a
#: removal whose OWNER TASK is in the checkout must be LIVE — that is what makes
#: the frozen gate EXECUTE it. Seeded at 7; MEASURED at 5, the two
#: gx-agentic-iam-repin owns having gone live with this task.
PENDING_REMOVAL_MAX = 5


def test_the_removal_set_keeps_the_three_fields_the_frozen_type_lacks():
    """Unconditional: a mandated field may not be dropped to fit a frozen type."""
    from tests.agentic.asserts import FAMILY_KINDS

    ids = {r.id for r in removal_register()}
    assert RC2_REMOVAL_IDS <= ids, sorted(RC2_REMOVAL_IDS - ids)
    for r in removal_register():
        assert r.family in FAMILY_KINDS and r.subject and r.must_fail, r.id
        assert r.owner and r.spelling and isinstance(r.pending, bool), r.id
    pending = {r.id for r in removal_register() if r.pending}
    assert pending <= RC2_REMOVAL_IDS, sorted(pending - RC2_REMOVAL_IDS)
    assert len(pending) <= PENDING_REMOVAL_MAX, sorted(pending)
