"""The seed's own coverage literal, carried under ESC-GX-SEEDA-001.

seed-a's body makes 44 entries plus the removal set mandatory AND makes 18,000
diff characters binding, and the two cannot both be met: five entries written in
their final form measured 648 characters each, so the whole seed projects past
34,000. The clause is escalated rather than thinned, and the assertion that would
discharge it is LANDED here under a STRICT xfail instead of being deleted -- the
day the remaining parts seed MK-I01..MK-I29 and the removal set, this XPASSes and
goes RED, which is what retires the escalation deliberately.
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


@pytest.mark.xfail(strict=True, reason="ESC-GX-SEEDA-001: the 44 entries and the "
                                       "removal set do not fit one 18,000-character diff")
def test_the_seed_covers_every_amendment_2_entry_and_the_removal_set():
    seeded = [e.id for e in register()]
    assert not [i for i in REQUIRED_IDS if i not in seeded]
    assert removal_register(), "the removal set is unseeded"
