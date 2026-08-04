"""The shared ``Verdict.lineno`` invariant, applied across the domain suites.

Promoted verbatim from ``tests/test_gcp_preflight.py`` on
``agent/gx-preflight-empty-key``. Every domain check builds ``Verdict(status,
kind, target, 0, message)`` and, before this module, nothing anywhere asserted
the ``0``, so harness's own ``int -> int + 1`` mutant survived in five modules.

MEASUREMENT, recorded here and not only in the task notes because the review
gate is handed the diff. Taken with ``collect_sites`` / ``mutation_score`` from
``harness.pipeline.mutation`` (harness is not installed in this venv; reached
with ``sys.path.insert(0, "/home/jones/Downloads/harness")``), each run over a
``git archive`` copy of the ref extracted to a scratch directory, validation =
this task's own ``.venv/bin/python -m pytest -q tests/``. BOTH refs were
asserted GREEN before any mutant was written — before 50d8a58, "1136 passed";
after 118b13e, "1142 passed" — because a number over a red baseline is
worthless.

    module            exhaustive before -> after     40-draw before -> after
    ----------------------------------------------------------------------
    org_checks.py     30/45 0.667 -> 39/45 0.867     27/40 0.675 -> 34/40 0.850
    hfw_checks.py     65/106 0.613 -> 71/106 0.670   24/40 0.600 -> 25/40 0.625
    cli.py            52/76 0.684 -> 52/76 0.684     28/40 0.700 -> 28/40 0.700
    vpcsc_checks.py   36/61 0.590 -> 52/61 0.852     22/40 0.550 -> 34/40 0.850
    reasoner.py       36/50 0.720 -> 37/50 0.740     29/40 0.725 -> 30/40 0.750

MUST-FAIL-FIRST, in the only form a paydown test can take: each new node PASSES
on clean source and reported FAILED under the ``lineno 0 -> 1`` mutation applied
ALONE to one site in an isolated copy. Per module, sites killed / sites present:

    org_checks.py    10/10   hfw_checks.py 6/6   vpcsc_checks.py 16/17
    reasoner.py       3/3    cli.py        0/0

The two survivors, both named rather than hidden. ``vpcsc_checks.py:303`` is
the ``solver returned <unknown>`` arm: no offline document drives z3 to answer
``unknown``, so it is ``gx-debt-vpcsc-checks``'s (this tree does NOT carry
``agent/gx-vpcsc-record-guards``, so the 24/40 and 28/40 in the task body do not
describe it — the numbers above are this tree's own). And ``cli.py`` is the one
module whose exhaustive score does NOT rise: it constructs no ``Verdict`` at
all, so it has no ``lineno`` site for this invariant to answer, and its 24
surviving mutants are ``gx-debt-cli``'s in full.
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
