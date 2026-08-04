"""Degraded worlds: a lost capability moves a block to ABSTAIN, never to pass.

This is the single most important honesty property in the repo. Every check the
gate owns is allowed to stop deciding — z3 can be absent, a claim extractor can
be missing from the checkout — and when that happens the honest outcome is an
``unverified`` verdict naming the reason. The dishonest outcome is exit 0 with
nothing on the record, which reads to a reviewer exactly like "the gate looked
and was happy".

**Why a subprocess and not a monkeypatch.** The capability has to be genuinely
gone, in a real interpreter, for the assertion to mean anything: a
``monkeypatch.setattr`` on ``get_solver`` proves the code branches, not that the
*process* degrades. So every run here goes through
:func:`tests.agentic.hookrunner.run_hook` / :func:`~tests.agentic.hookrunner.ground_json`
with the ``blocked_import_env`` overlays from ``tests/conftest.py``
(``no_z3_env``, ``no_tf_claims_env``), which put
``tests/agentic/_blockimports`` first on the child's ``PYTHONPATH`` so its
``sitecustomize`` makes exactly those imports fail to load.

**D01 is the sanity gate for the whole module.** If the child still had z3, then
"it degraded honestly" is vacuously true of every other assertion here. So D01
runs first, and every degraded assertion carries
:data:`VACUOUS_IF_D01_RED` in its message and re-checks the report's own
``backend`` field — which costs nothing, the sidecar already carries it.

**The paired shape.** D02–D04 assert a *transition*: the same document, the same
snapshot, two worlds. The with-z3 half is guarded by :data:`tests.agentic.env.HAVE_Z3`
(an ``if``, not a skip mark, so the degraded half stays UNCONDITIONAL — it is
the property under test and it must run on a machine with no solver at all).
The repo venv ships z3-solver 5.0.0, so in practice both halves run.

**Two things that are NOT degradation**, and which have a test each so a future
blanket fail-open cannot hide behind this module: existence questions go to the
Datalog pass, which needs no solver (D05), and blocking ``tf_claims`` leaves IAM
documents untouched (D09).

**Spawn count.** 23 children, not the ~16 the design estimated, and the
difference is entirely the acceptance criterion "every degraded assertion checks
the bucket, not just the exit code": a hook run proves the exit code, and the
bucket lives in the report, which is a second (sidecar) spawn. Every *paired*
assertion then doubles again for its second world. They are ~0.05s each and
:data:`MODULE_SPAWN_CAP` pins the total at module teardown.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.agentic import env
from tests.agentic.asserts import (
    assert_abstained,
    assert_blocked,
    assert_no_verdictless_pass,
    assert_recorded,
)
from tests.agentic.fake_agent import FakeAgent, Proposal
from tests.agentic.hookrunner import (
    bound_subprocess_budget,  # noqa: F401 — autouse: bind spawns to the budget
    ground_json,
    run_hook,
    run_hook_explain,
)

#: The committed catalogue payloads this module borrows from (A15/A17/B01/B07)
#: and the two documents it owns (A01's plan, D05's typo'd role).
IAM_FIXTURES = env.AGENTIC / "iam"
DEGRADED_FIXTURES = env.AGENTIC / "degraded"

#: Ceiling on the children THIS module spawns, checked at module teardown. The
#: suite-wide ceiling is shared and so cannot notice one module growing at the
#: others' expense; this one can.
MODULE_SPAWN_CAP = 24

#: Appended to every degraded-world assertion message. A red assertion here with
#: D01 also red means the child never lost z3 in the first place, and the right
#: thing to debug is the ``_blockimports`` overlay, not the gate.
VACUOUS_IF_D01_RED = (
    "\n(if test_D01_backend_is_builtin is red too, the child still had the "
    "capability and this assertion proves nothing)")

#: The degraded ``cel``/``subset`` reason, minted at ``constraints.py:294`` and
#: ``constraints.py:437``. Asserted as a substring rather than in full because
#: the two messages differ after this prefix.
NO_Z3_REASON = "z3 is not available"

#: The degraded tf-plan reason, minted at ``preflight.py:355-358`` — it names
#: the module an operator has to install to get the check back.
NO_TF_CLAIMS_REASON = "gcp_grounding.tf_claims"


# -- documents -----------------------------------------------------------------


def _document(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def dead_time_window_document() -> dict:
    """The CONTRADICTED case, lifted out of the committed ``iam_policy_bad.json``.

    D02 needs a document whose ONLY finding is the dead binding, and
    ``iam_policy_bad.json`` plants a hallucinated service account beside it. That
    principal is ungrounded in *both* worlds (existence needs no solver — see
    D05), so feeding the whole file would block either way and the transition
    this test exists to assert would be invisible behind it. Lifted from the
    fixture rather than retyped here so the CEL text has exactly one source.
    """
    source = _document(env.POLICIES / "iam_policy_bad.json")
    dead = [binding for binding in source["bindings"]
            if (binding.get("condition") or {}).get("title") == "never-true"]
    assert len(dead) == 1, (
        f"iam_policy_bad.json should plant exactly one never-true condition, "
        f"found {len(dead)} — D02 has lost its contradicted case")
    return {"version": 3, "etag": source["etag"], "bindings": dead}


def iam_payload(stem: str) -> dict:
    """A committed IAM catalogue payload, by fixture stem."""
    return _document(IAM_FIXTURES / f"{stem}.policy.json")


def baseline_path(stem: str) -> Path:
    """Path to a committed baseline document, for the ``--baseline`` runs."""
    return IAM_FIXTURES / f"{stem}.policy.json"


# -- staging -------------------------------------------------------------------


def stage(case_id: str, document, workdir, *, expect: str, kind: str = "iam",
          tool: str = "Write") -> tuple[str, dict]:
    """Write *document* into *workdir* as one scripted agent turn.

    Returns ``(path, event)``: the absolute path the agent wrote and the
    PostToolUse event it emitted, which is what the hook reads on stdin. The
    document reaches disk through a :class:`~tests.agentic.fake_agent.FakeAgent`
    rather than being pointed at in the fixtures tree because the gate is being
    asked the question an agent's edit asks it — and because the hook only
    grounds a path it can see in ``tool_input.file_path``.

    *expect* is the bucket the DEGRADED world must land in; where a case is
    paired, the with-z3 half is the exception this module measures against.
    """
    proposal = Proposal(
        id=case_id,
        kind=kind,
        tool_name=tool,
        # ``.json`` matters: cli.py's ``_HOOK_SUFFIXES`` decides whether the
        # hook grounds the edited file at all.
        rel_path=f"{case_id}.json",
        payload=document,
        expect=expect,
        rationale="degraded-world probe: the capability that would decide this "
                  "document is missing from the child",
    )
    agent = FakeAgent(workdir, [proposal])
    applied, event = agent.turn()
    return agent.file_path(applied), event


# -- shared assertions ---------------------------------------------------------


def assert_ran_without_z3(report: dict) -> None:
    """The sidecar really ran on the builtin backend — D01's check, re-made
    locally at no cost because the report already carries the field."""
    assert report.get("backend") == "builtin", (
        f"this run was supposed to have no z3, but the report says backend="
        f"{report.get('backend')!r}{VACUOUS_IF_D01_RED}")


def assert_block_became_abstain(outcome, report: dict, *reasons: str) -> None:
    """THE PROPERTY, in one place: what blocked (or proved) with the capability
    must abstain without it — never pass in silence.

    ``assert_abstained`` already covers exit 0 / ok / no manufactured
    contradiction; the two explicit summary assertions below are kept anyway
    because they are the exact failure mode this module exists to catch, and a
    naive reading of "exit 0" would satisfy neither. An exit-0 run with zero
    verdicts is a silent pass, and a ``contradicted`` minted out of ignorance is
    a fabricated finding.

    *reasons* are substrings every abstain must name; D10 passes none because
    its cases abstain for two different reasons and the invariant it asserts is
    the bucket, not the wording.
    """
    assert_ran_without_z3(report)
    assert_abstained(outcome, report, *reasons)
    summary = report["summary"]
    assert summary["contradicted"] == 0, (
        f"ignorance must not be rendered as a contradiction: {summary!r}"
        f"{VACUOUS_IF_D01_RED}")
    assert summary["unverified"] >= 1, (
        f"the block degraded to a SILENT PASS — exit 0 with nothing on the "
        f"record is the failure this test exists to catch: {summary!r}"
        f"{VACUOUS_IF_D01_RED}")


def subset_verdict(report: dict) -> dict:
    """THE ``subset`` verdict of a ``--baseline`` run, asserting there is one.

    A ``--baseline`` run that leaves no subset verdict at all has dropped the
    comparison silently, which is the missed-abstain shape rather than an
    honest one.
    """
    verdicts = [v for v in report["verdicts"] if v["kind"] == "subset"]
    assert len(verdicts) == 1, (
        f"a --baseline run must leave exactly one subset verdict, found "
        f"{len(verdicts)}: {verdicts!r}")
    return verdicts[0]


# -- D01: the sanity gate ------------------------------------------------------


def test_D01_backend_is_builtin(agent_workdir, estate_snapshot_path, no_z3_env):
    """``no_z3_env`` really removes z3 from the child.

    Run first and referenced by every other no-z3 assertion in this module: if
    the child still imports z3 then "the gate degraded honestly" is vacuously
    true everywhere below, and the bug is in the ``_blockimports`` overlay
    rather than in the gate. ``core/solver.py`` catches the blocked import and
    falls back, so the observable is the report's own ``backend`` field.
    """
    path, _ = stage("D01_backend", iam_payload("B01_scoped_grant"), agent_workdir,
                    expect="pass")
    report = ground_json(path, snapshot=estate_snapshot_path, env=no_z3_env)
    assert report["backend"] == "builtin", (
        f"the child was spawned with z3 blocked and still reports backend="
        f"{report['backend']!r} — the degraded-world overlay is not working, so "
        f"every other assertion in this module is vacuous")


# -- NO-Z3 WORLD ---------------------------------------------------------------


def test_D02_cel_unsat_degrades(agent_workdir, estate_snapshot_path, no_z3_env):
    """The dead time window: BLOCKED with z3, ABSTAINED without it.

    Both halves in one test, because the assertion is the *transition* — either
    half alone is satisfied by a gate that always blocks or one that always
    passes.
    """
    path, event = stage("D02_dead_window", dead_time_window_document(),
                        agent_workdir, expect="abstain")

    if env.HAVE_Z3:
        # The with-z3 half. Guarded rather than skip-marked so the degraded half
        # below runs on a machine with no solver at all.
        blocked = run_hook(event, snapshot=estate_snapshot_path)
        # "contradicted=1" is the rendered report's own summary line: the bucket,
        # asserted on the same stderr the agent is fed back.
        assert_blocked(blocked, "condition is never true", "contradicted=1")

    degraded = run_hook(event, snapshot=estate_snapshot_path, env=no_z3_env)
    report = ground_json(path, snapshot=estate_snapshot_path, env=no_z3_env)
    assert_block_became_abstain(degraded, report, NO_Z3_REASON)
    verdict = assert_recorded(report, status="unverified", kind="cel")
    assert "satisfiability was not decided" in verdict["message"], verdict


def test_D03_cel_tautology_degrades(agent_workdir, estate_snapshot_path, no_z3_env):
    """A17's tautology: a grounded WARNING with z3, ``unverified`` without.

    The warning rides on a grounded verdict, so this transition is not
    block-to-abstain but proof-to-abstain — and it is the one that would be
    easiest to lose silently, because both worlds exit 0. Only the bucket
    distinguishes them.
    """
    path, _ = stage("D03_tautology", iam_payload("A17_cel_tautology"),
                    agent_workdir, expect="abstain")

    if env.HAVE_Z3:
        decided = ground_json(path, snapshot=estate_snapshot_path)
        verdict = assert_recorded(decided, status="grounded", kind="cel")
        assert "always true" in verdict["message"], verdict

    report = ground_json(path, snapshot=estate_snapshot_path, env=no_z3_env)
    assert_ran_without_z3(report)
    verdict = assert_recorded(report, status="unverified", kind="cel")
    assert NO_Z3_REASON in verdict["message"], (
        f"the tautology proof degraded without naming the missing solver: "
        f"{verdict}{VACUOUS_IF_D01_RED}")
    assert report["summary"]["grounded"] == 2, (
        f"only the cel verdict may degrade — the two existence verdicts need no "
        f"solver: {report['summary']!r}")


def test_D04_subset_degrades(agent_workdir, estate_snapshot_path, no_z3_env):
    """B07's shrinking policy under ``--baseline``: new⊆old PROVED with z3,
    ``unverified`` without.

    The subset check is the one that answers "did this edit widen access", so
    losing it silently would be the most consequential silent pass in the gate:
    the report would read exactly like the proof succeeded.
    """
    path, _ = stage("D04_shrinking", iam_payload("B07_shrinking_policy"),
                    agent_workdir, expect="abstain")
    baseline = baseline_path("B07_baseline")

    if env.HAVE_Z3:
        decided = ground_json(path, snapshot=estate_snapshot_path, baseline=baseline)
        proved = subset_verdict(decided)
        assert proved["status"] == "grounded", proved
        assert "new⊆old holds" in proved["message"], proved

    report = ground_json(path, snapshot=estate_snapshot_path, baseline=baseline,
                         env=no_z3_env)
    assert_ran_without_z3(report)
    degraded = subset_verdict(report)
    assert degraded["status"] == "unverified", (
        f"without z3 the subset comparison cannot be decided, and anything but "
        f"unverified is invented: {degraded}{VACUOUS_IF_D01_RED}")
    assert NO_Z3_REASON in degraded["message"], degraded
    assert report["summary"]["contradicted"] == 0, report["summary"]


def test_D04_condition_evasion_abstains_in_both_worlds(
        agent_workdir, estate_snapshot_path, no_z3_env):
    """A15's condition evasion: ``unverified`` WITH z3 and without — and for a
    different reason each time.

    ``constraints._grant_pairs`` raises ``_Undecidable`` on the mere presence of
    a ``condition`` key, *before* the solver is ever consulted, so until
    ``sx-iam-subset-conditional`` lands this case abstains in both worlds. That
    makes it the control D04 needs: the two abstains must stay distinguishable
    in the message text, or "the solver is gone" and "the comparison is
    request-time-dependent" collapse into one unreadable verdict and an operator
    cannot tell which capability to restore.
    """
    path, _ = stage("D04b_condition_evasion", iam_payload("A15_condition_evasion"),
                    agent_workdir, expect="abstain")
    baseline = baseline_path("A15_baseline")

    if env.HAVE_Z3:
        decided = ground_json(path, snapshot=estate_snapshot_path, baseline=baseline)
        with_z3 = subset_verdict(decided)
        assert with_z3["status"] == "unverified", with_z3
        assert "conditional" in with_z3["message"], with_z3
        assert NO_Z3_REASON not in with_z3["message"], (
            f"z3 was present, so the abstain must not blame the solver: {with_z3}")

    report = ground_json(path, snapshot=estate_snapshot_path, baseline=baseline,
                         env=no_z3_env)
    assert_ran_without_z3(report)
    without_z3 = subset_verdict(report)
    assert without_z3["status"] == "unverified", without_z3
    # The reason is STILL the condition, not the solver: _Undecidable fires
    # first. If this ever flips to the z3 reason, the earlier abstain has been
    # swallowed by the later one and the two are no longer distinguishable.
    assert "conditional" in without_z3["message"], (
        f"the earlier _Undecidable abstain must survive the loss of z3, so the "
        f"two reasons stay tellable apart: {without_z3}{VACUOUS_IF_D01_RED}")
    assert report["summary"]["contradicted"] == 0, report["summary"]


def test_D05_existence_unaffected(agent_workdir, estate_snapshot_path, no_z3_env):
    """A hallucinated role still BLOCKS with no z3 at all.

    The existence pass is Datalog over the snapshot's own enumeration and needs
    no solver, so losing z3 must cost exactly the solver-backed checks and
    nothing else. This is what makes the degradation *scoped*: without this test
    a blanket fail-open — every check to unverified the moment anything is
    missing — would pass every other assertion in this module.
    """
    _, event = stage("D05_hallucinated_role",
                     _document(DEGRADED_FIXTURES / "D05_hallucinated_role.policy.json"),
                     agent_workdir, expect="block")
    outcome = run_hook(event, snapshot=estate_snapshot_path, env=no_z3_env)
    assert_blocked(
        outcome,
        "roles/bigquery.dataViewr",
        "does not exist in the snapshot",
        # The did-you-mean suggester is part of the surviving capability, not a
        # nicety: it is what turns the block into a fix the agent can apply.
        "did you mean: roles/bigquery.dataViewer",
        # The rendered summary line — the bucket, not just the exit code.
        "ungrounded=1",
    )


def test_D06_explain_says_so(agent_workdir, estate_snapshot_path, no_z3_env):
    """``--explain`` names the missing solver and the degradation it caused.

    An abstaining hook run is silent by design, so ``--explain`` is the only
    channel that tells an operator *why* the gate went quiet. ``cli.py:226-228``
    is the line, and it has to say both halves: the capability that is gone, and
    what it cost.
    """
    _, event = stage("D06_explain", iam_payload("A17_cel_tautology"),
                     agent_workdir, expect="abstain")
    outcome = run_hook_explain(event, snapshot=estate_snapshot_path, env=no_z3_env)
    assert outcome.exit_code == 0, (
        f"a degraded run must not fail the gate\n{outcome}")
    assert "z3 constraints generated this run [builtin]" in outcome.stderr, (
        f"the explain header must name the backend actually used"
        f"{VACUOUS_IF_D01_RED}\n{outcome}")
    assert "z3 is not available — no constraints were generated" in outcome.stderr, (
        f"--explain must name the missing capability\n{outcome}")
    assert "degraded to 'unverified'" in outcome.stderr, (
        f"--explain must name what the missing capability cost — an operator "
        f"reading only 'no constraints' would think the document was clean\n"
        f"{outcome}")


# -- NO-TF_CLAIMS WORLD --------------------------------------------------------


def test_D07_tf_plan_abstains(agent_workdir, estate_snapshot_path, no_tf_claims_env):
    """A benign terraform plan with the extractor missing: ONE honest abstain.

    Nothing in the plan is extracted, so a gate that merely returned no claims
    would produce a report identical to a clean pass over an empty document.
    ``preflight._extract_claims`` instead records the miss, and the verdict names
    the module — an operator can act on "install gcp_grounding.tf_claims" and
    cannot act on silence.
    """
    path, event = stage("D07_tf_plan", _document(env.POLICIES / "tf_plan_good.json"),
                        agent_workdir, expect="abstain", kind="tf_plan")
    outcome = run_hook(event, snapshot=estate_snapshot_path, env=no_tf_claims_env)
    report = ground_json(path, snapshot=estate_snapshot_path, env=no_tf_claims_env)
    assert_abstained(outcome, report, NO_TF_CLAIMS_REASON)
    assert_recorded(report, status="unverified", kind="document")
    assert len(report["verdicts"]) == 1, (
        f"the plan's claims were not extracted, so the report must carry the "
        f"one abstain and nothing else: {report['verdicts']!r}")
    assert report["summary"]["grounded"] == 0, (
        f"nothing was extracted, so nothing can have been grounded: "
        f"{report['summary']!r}")


def test_D08_adversarial_tf_abstains(agent_workdir, estate_snapshot_path,
                                     no_tf_claims_env):
    """The A01 firewall-widening plan gets the SAME single abstain as D07.

    The point is that it is the same: an adversarial plan must not become
    invisible because the extractor is missing. D07 and D08 differ only in what
    the plan does — one grants a scoped role, the other opens tcp/22 to
    ``0.0.0.0/0`` — and the gate, having lost the extractor, honestly says the
    same thing about both instead of passing the dangerous one in silence.
    """
    path, event = stage("D08_firewall_widening",
                        _document(DEGRADED_FIXTURES / "A01_firewall_widening.plan.json"),
                        agent_workdir, expect="abstain", kind="tf_plan")
    outcome = run_hook(event, snapshot=estate_snapshot_path, env=no_tf_claims_env)
    report = ground_json(path, snapshot=estate_snapshot_path, env=no_tf_claims_env)
    assert_abstained(outcome, report, NO_TF_CLAIMS_REASON)
    verdict = assert_recorded(report, status="unverified", kind="document")
    assert "detected a terraform plan" in verdict["message"], verdict
    assert len(report["verdicts"]) == 1, (
        f"an adversarial plan must leave exactly the same single abstain as the "
        f"benign one, not a quieter report: {report['verdicts']!r}")
    assert report["summary"]["grounded"] == 0, report["summary"]


def test_D09_iam_unaffected(agent_workdir, estate_snapshot_path, no_tf_claims_env):
    """An IAM policy still grounds normally with ``tf_claims`` blocked.

    The block is scoped to the one ``importlib.import_module`` call in
    ``preflight._tf_plan_extractor``; every other extractor is imported at module
    load. Without this test, a gate that abstained on *everything* the moment any
    extractor went missing would satisfy D07 and D08.
    """
    path, _ = stage("D09_iam_policy", iam_payload("B01_scoped_grant"),
                    agent_workdir, expect="pass")
    report = ground_json(path, snapshot=estate_snapshot_path, env=no_tf_claims_env)
    assert_recorded(report, status="grounded", kind="role",
                    target="roles/bigquery.dataViewer")
    assert_recorded(report, status="grounded", kind="principal",
                    target="group:data-eng@acme.example")
    assert report["summary"]["unverified"] == 0, (
        f"blocking the tf-plan extractor must cost an IAM policy nothing: "
        f"{report['summary']!r}")


# -- BOTH BLOCKED --------------------------------------------------------------

#: The tf-plan and CEL members of the A-case catalogue, run with BOTH
#: capabilities gone. ``A18_cel_outside_subset`` is deliberately absent: its
#: conditions never become ``cel`` claims at all (``claims.py``'s
#: ``_RUNTIME_ONLY_MARKERS`` skips them), so it has no solver-backed verdict to
#: degrade and would assert nothing here — that hole is A18's own case to pin in
#: ``test_gcp_agentic_iam.py``. ``A15_condition_evasion`` is covered above, in
#: both worlds, by the paired D04 control.
BOTH_BLOCKED_CASES = (
    pytest.param("A01_firewall_widening", "tf_plan", id="A01_firewall_widening"),
    pytest.param("D02_dead_window", "iam", id="A-cel-unsat-dead-window"),
    pytest.param("A17_cel_tautology", "iam", id="A17_cel_tautology"),
)


def _both_blocked_document(stem: str) -> dict:
    if stem == "A01_firewall_widening":
        return _document(DEGRADED_FIXTURES / "A01_firewall_widening.plan.json")
    if stem == "D02_dead_window":
        return dead_time_window_document()
    return iam_payload(stem)


@pytest.mark.parametrize("stem,kind", BOTH_BLOCKED_CASES)
def test_D10_both_blocked_is_never_a_verdictless_pass(
        stem, kind, agent_workdir, estate_snapshot_path, blocked_import_env):
    """With z3 AND ``tf_claims`` gone, one invariant holds across all of them:
    exit 0, at least one ``unverified``, and zero ``contradicted``.

    Exit 0 because ignorance never fails the gate; at least one unverified
    because the ignorance must be on the record; zero contradicted because a
    finding invented out of a missing capability is worse than no finding at
    all. A naive exit-code check would call all three of these a pass, which is
    exactly why this test reads the summary.
    """
    both_gone = blocked_import_env("z3", "gcp_grounding.tf_claims")
    path, event = stage(f"D10_{stem}", _both_blocked_document(stem), agent_workdir,
                        expect="abstain", kind=kind)
    outcome = run_hook(event, snapshot=estate_snapshot_path, env=both_gone)
    report = ground_json(path, snapshot=estate_snapshot_path, env=both_gone)
    assert_no_verdictless_pass(outcome, report)
    assert_block_became_abstain(outcome, report)


# -- the module's own guards ---------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _module_spawn_cap(subprocess_budget):
    """Pin this module's share of the suite-wide spawn budget.

    Checked at teardown rather than per-test so a ``-k`` selection cannot trip
    it.
    """
    before = subprocess_budget.total
    yield
    spent = subprocess_budget.total - before
    assert spent <= MODULE_SPAWN_CAP, (
        f"this module spawned {spent} children, over its cap of "
        f"{MODULE_SPAWN_CAP}; the oracle is the full test run and an unbounded "
        f"suite stops being run at all")


#: The assertion helpers that look at what the gate RECORDED. A test reaching
#: none of them can only be looking at an exit code.
_RECORDERS = frozenset({
    "assert_abstained", "assert_blocked", "assert_recorded",
    "assert_no_verdictless_pass", "assert_block_became_abstain",
    "subset_verdict",
})

#: The two tests that legitimately assert no bucket, and why. D01 asserts the
#: harness itself works (there is no verdict to check — the whole point is that
#: it is the precondition for the ones that do), and D06 asserts a rendered
#: stderr line rather than a report.
_NOT_BUCKET_ASSERTIONS = frozenset({
    "test_D01_backend_is_builtin",
    "test_D06_explain_says_so",
})


def _reachable_names(fn, depth: int = 2) -> set[str]:
    """Global names *fn* references, following calls to functions defined in
    this module up to *depth* hops — the paired tests delegate to
    ``assert_block_became_abstain`` and friends."""
    names = set(fn.__code__.co_names)
    if depth > 0:
        for name in tuple(names):
            target = globals().get(name)
            if callable(target) and hasattr(target, "__code__"):
                names |= _reachable_names(target, depth - 1)
    return names


def test_every_degraded_assertion_checks_the_bucket():
    """The acceptance criterion, enforced instead of grepped.

    "Degrades honestly" is a statement about the *bucket*: an
    ``assert outcome.exit_code == 0`` with no companion assertion about what the
    gate recorded cannot tell an abstain from the silent pass this whole module
    exists to make impossible. Checked mechanically so a test added later cannot
    quietly opt out — and the two documented exemptions are named above rather
    than being invisible holes.
    """
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_D") or not callable(fn):
            continue
        if name in _NOT_BUCKET_ASSERTIONS:
            continue
        assert _RECORDERS & _reachable_names(fn), (
            f"{name} asserts no recorded verdict — it cannot distinguish an "
            f"honest abstain from a silent pass")
