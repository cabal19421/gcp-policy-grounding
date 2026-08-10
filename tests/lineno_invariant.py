"""The shared ``Verdict.lineno`` invariant, applied across the domain suites.

Promoted verbatim from ``tests/test_gcp_preflight.py`` on
``agent/gx-preflight-empty-key``. Every domain check builds ``Verdict(status,
kind, target, 0, message)`` and, before this module, nothing anywhere asserted
the ``0``, so harness's own ``int -> int + 1`` mutant survived in five modules.
Its five applications — org, hierarchical firewall, sec-cli, vpcsc, reasoner,
which collect as SIX node ids because the org arm is parametrized — landed with
the integration base. What this diff adds is the two shared modules' remaining
paydown and the measurement below.

INSTRUMENT, recorded here rather than only in the task notes because the review
gate is handed the DIFF. harness's own ``collect_sites`` / ``mutated_source``
(``harness.pipeline.mutation``) and ``run_validation``
(``harness.pipeline.backends.base``) — harness is NOT installed in this venv, so
it was reached with ``sys.path.insert(0, "/home/jones/Downloads/harness")``. One
mutant per site, applied ALONE, one suite run each, validation this task's own
``.venv/bin/python -m pytest -q tests/`` at ``timeout=900`` (it takes ~45s alone
and a timeout scores as a KILL), not-green-is-a-kill. EXHAUSTIVE is every
candidate site; the 40-DRAW is harness's own ``_sample_pairs`` over that same
list, hence a subset — and every drawn survivor below also survives
exhaustively, as it must. Sharded over eight isolated ``git archive`` copies per
ref, under a clean parent, which is part of the instrument: a parent holding a
stray ``terraform.tfstate`` binds the product's own state discovery and reds
tests no mutant touched.

GREEN BASELINE ASSERTED IN ALL SIXTEEN SHARDS BEFORE ANY MUTANT WAS WRITTEN:
each copy reported "3717 passed, 28 skipped, 5 xfailed" (the archive shape — 25
nodes need git metadata it does not carry; the checkout itself reports "3741
passed, 3 skipped, 6 xfailed"). Neither carries a failure, and a score read over
a red baseline is worthless. BOTH refs were measured here, same instrument, back
to back: BEFORE is this diff's base ``integration/gx-base`` ebf878ac, AFTER is
its tree at 78f9c5b, which differs from the committed one only in this docstring.

    module            exhaustive before -> after     40-draw before -> after
    ----------------------------------------------------------------------
    org_checks.py     52/64 0.813 -> 55/64 0.859     35/40 0.875 -> 36/40 0.900
    vpcsc_checks.py   65/81 0.802 -> 68/81 0.840     32/40 0.800 -> 34/40 0.850

WHAT MOVED, by line. ``org_checks.py`` 257 (a record that records no rule), 272
(which of the two no-rule spellings that record gets) and 419 (the node an
unreadable proposal names — the one of the three inside the draw).
``vpcsc_checks.py`` 253 (an unreadable protection field), 575 (a previous policy
list that is not a list) and 587 (a readable policy whose axis cannot be read),
of which 253 and 575 are drawn — which is what lifts that draw off 0.800 exactly.

MUST-FAIL-UNDER-MUTANT, in the only form a paydown test can take: it PASSES on
clean source (the baselines above), so the must-fail proof is THE MUTANT. Per
module, ``lineno 0 -> 1`` applied ALONE to ONE site in an isolated copy, sites
killed over sites present: ``org_checks.py`` 11/13 -> 12/13, ``vpcsc_checks.py``
16/20 -> 19/20. The two the invariant does NOT reach are named, not rounded
away. ``org_checks.py:244`` is the unreadable-RECORD abstention, and
``knowledge`` refuses to load a snapshot whose ``rules`` is not an array ("each
'rules' entry must be an object"), so nothing this suite can build reaches it.
``vpcsc_checks.py:612`` is the ``solver returned <unknown>`` arm: no offline
document drives z3 to answer ``unknown``.

RESIDUAL, handed on with the number attached rather than declared dead.
``gx-debt-org-checks`` inherits org_checks.py's 9 remaining survivors — 113,
173, 191, 192, 193, 244, 265, 321, 377, four of them drawn.
``gx-debt-vpcsc-checks`` inherits vpcsc_checks.py's 13 — 153, 163, 302, 385,
398, 424, 446, 447, 453, 605, 612, 621, 675, six of them drawn. Both modules
clear the 34/40 this task owes; neither is claimed clean.
"""


def assert_no_line_numbers(report) -> None:
    """The documented invariant, asserted once and applied per fail-open path.

    ``reasoner.ground_existence``'s own clause: a policy document is JSON, not
    source, so there is no line to point at — every verdict carries lineno 0
    and the json-path location leads the message instead (the precedent is
    ``test_gcp_reasoner.py::test_bad_role_suggests_the_near_miss``, which pins
    ``reader.lineno == 0``). Each caller pins its path's identity — status,
    kind, target and the reason named in the message — alongside this, so the
    branch is shown to have decided something and not merely been reached.
    """
    assert all(v.lineno == 0 for v in report.verdicts), \
        [(v.status, v.kind, v.target, v.lineno) for v in report.verdicts]
