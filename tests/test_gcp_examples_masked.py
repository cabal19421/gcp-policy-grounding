"""Scenario three — the masked deny — pinned in-process.

``examples/terraform-masked/`` is the README's third scenario: the estate
carries a world-open RDP allow (``allow-rdp-broad``, tcp/3389 from 0.0.0.0/0,
priority 1000) that is DEAD, fully masked by a higher-precedence deny
(``deny-external-rdp``, priority 900). ``base.tf.json`` declares the pair
exactly as ``terraform.tfstate`` carries it, ``proposal.tf.json`` is the
accident (base minus the deny block — the dormant allow wakes up world-open)
and ``cleanup.tf.json`` is the intended fix (base minus the dead allow). This
module pins three things:

* the FIXTURES — each variant differs from the base by exactly the one deleted
  block, and the state carries both rules with the attributes the base
  declares, so the README's story cannot drift from the committed files;
* the GROUNDING, decided empirically and pinned as observed — ALL THREE
  documents are denied. The base draws the ``firewall_exposure`` finding (the
  allow's own text admits a public source to tcp/3389 — that check reads one
  rule's payload, no estate), the FINDING-A ``firewall_shadow`` (the allow is
  unreachable behind ``deny-external-rdp``) and the FINDING-C mirror (the
  restated deny kills the estate's allow). The proposal keeps exposure plus
  FINDING A — dead today by the estate fold, world-open by its own text. The
  cleanup was EXPECTED to approve and empirically does NOT: deletions are
  invisible without the parked pair tier, so the restated deny is compared
  against an estate that still holds ``allow-rdp-broad`` and draws the same
  kill-report the base drew — a true sentence about today's estate (it IS the
  mask), conservatively mis-attributed to the document that restates the deny;
* the README's step-9 invocations — four flags each, no ``--requirements``
  (nothing in the original arc is a compiled promise; every 9a-9c finding is a
  built-in estate check), each exiting 1 with the narrative the README quotes;
* the CONDITIONAL-APPROVAL ARM (9d-9f) — the deny applied-gone
  (``terraform-after-removal.tfstate``), the scenario's own one-promise corpus
  (``requirements.md``: the woken allow may admit sources only within the two
  audited partner ranges, a per-row subset obligation over the union of the
  two blocks), and the two extra runs: ``narrowed.tf.json`` (exactly the two
  ranges) APPROVES with the promise judged ``holds`` — a grounded subset
  judgment, not an abstention — while ``narrowed_extra.tf.json`` (the two
  ranges plus one unaudited /28) is DENIED with the promise refutation naming
  the smuggled range, both built-ins staying green on both runs.

Everything is in-process (no subprocess), and environment-honest: without z3
neither the exposure nor the shadow check decides anything, so every denial
pin is skipped rather than vacuously branched. The grounding pins run through
the same ``sources.load_current`` route the CLI takes; the shadow and exposure
verdicts rest on the tfstate fold (fresh) and the rule's own text, so unlike
scenario two's scope-diff warning they are NOT re-graded by the stale fixture
snapshot. The exposure witness address is a z3 model — a solver-minted example,
so the pins name the flow, never the address.
"""

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from gcp_grounding import baseline, drift, engine, gate, sources
from gcp_grounding.cli import main
from gcp_grounding.core.solver import get_solver

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
REPO_ROOT = Path(__file__).resolve().parent.parent

EXAMPLE = REPO_ROOT / "examples" / "terraform-masked"
BASE = EXAMPLE / "base.tf.json"
PROPOSAL = EXAMPLE / "proposal.tf.json"
CLEANUP = EXAMPLE / "cleanup.tf.json"
STATE = EXAMPLE / "terraform.tfstate"

# The conditional-approval arm: the deny applied-gone, and the two remediation
# candidates judged with the scenario's own corpus in force.
NARROWED = EXAMPLE / "narrowed.tf.json"
NARROWED_EXTRA = EXAMPLE / "narrowed_extra.tf.json"
STATE_AFTER = EXAMPLE / "terraform-after-removal.tfstate"
CORPUS = EXAMPLE / "requirements.md"

PROMISE_ID = "masked-allow-only-known-domains"
#: The two audited partner ranges — the "two known domains", modeled as CIDR
#: blocks (private ones: a public source on tcp/3389 would rightly draw the
#: built-in exposure finding regardless of any promise).
PARTNER_A = "10.198.51.0/24"
PARTNER_B = "10.203.113.0/26"
#: The smuggled range: unaudited, private, one octet off partner A's block.
SMUGGLED = "10.198.52.0/28"

SNAPSHOT = FIXTURES / "agentic_snapshot.json"

ALLOW_ADDRESS = "google_compute_firewall.allow_rdp_broad"
DENY_ADDRESS = "google_compute_firewall.deny_rdp"
ALLOW_NAME = "allow-rdp-broad"
DENY_NAME = "deny-external-rdp"

#: The exposure witness is a z3 model — a solver-minted example; the
#: flow it exhibits does not.
EXPOSED_FLOW = "can reach tcp/3389 through this rule"
#: FINDING A on the allow: dead behind the higher-precedence deny.
MASKED = (f"unreachable — every packet this rule matches is already decided "
          f"by higher-precedence rule(s) {DENY_NAME}; the rule has no effect")
#: FINDING C on the deny: the kill-report against the estate's allow — the
#: mask itself, re-discovered from the other side.
KILL_REPORT = (f"this deny at priority 900 makes the existing allow "
               f"'{ALLOW_NAME}' at priority 1000 unreachable")

HAVE_Z3 = get_solver().backend == "z3"

_needs_z3 = pytest.mark.skipif(
    not HAVE_Z3, reason="no z3: neither the exposure nor the shadow check "
                        "decides anything, so no document here can deny")


@pytest.fixture(autouse=True)
def _env_off(monkeypatch):
    """No test here inherits a developer's exported grounding configuration."""
    for name in list(os.environ):
        if name.startswith("GCP_GROUNDING"):
            monkeypatch.delenv(name, raising=False)


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def _evaluate(proposal: Path):
    """The library route the CLI takes, with the built-in checks only: this
    scenario compiles no promises, so there is no rule set to load."""
    built = gate.terraform_proposal(str(proposal), raw=False)
    assert built.proposal is not None, built.note
    current = sources.load_current(sources.SourceOptions(
        primary=str(SNAPSHOT), terraform_state=(str(STATE),)))
    assert not current.problem, current.problem
    report = engine.evaluate(built.proposal, current, engine.RuleSet()).report
    # The CLI's one finishing pass (cli._finish_report) re-grades existence
    # verdicts minted over a stale or partial view; the library route applies
    # the same post-pass so it pins the same decision the README commands show.
    snapshot, _ledger = baseline.current_view(current)
    drift.postpass(report, snapshot)
    return report


def _blocking(report):
    return [v for v in report.verdicts
            if v.status in ("contradicted", "ungrounded")]


# -- the fixtures themselves ---------------------------------------------------


def test_the_proposal_is_the_base_minus_exactly_the_deny_block():
    expected = deepcopy(json.loads(BASE.read_text(encoding="utf-8")))
    del expected["resource"]["google_compute_firewall"]["deny_rdp"]
    proposed = json.loads(PROPOSAL.read_text(encoding="utf-8"))
    assert proposed == expected, (
        "proposal.tf.json must be base.tf.json minus exactly the deny block — "
        "nothing more, nothing less")


def test_the_cleanup_is_the_base_minus_exactly_the_allow_block():
    expected = deepcopy(json.loads(BASE.read_text(encoding="utf-8")))
    del expected["resource"]["google_compute_firewall"]["allow_rdp_broad"]
    cleaned = json.loads(CLEANUP.read_text(encoding="utf-8"))
    assert cleaned == expected, (
        "cleanup.tf.json must be base.tf.json minus exactly the allow block — "
        "nothing more, nothing less")


def test_the_state_carries_both_rules_the_base_declares():
    declared = json.loads(BASE.read_text(encoding="utf-8"))[
        "resource"]["google_compute_firewall"]
    state = json.loads(STATE.read_text(encoding="utf-8"))
    assert state["version"] == 4
    rules = {r["name"]: r for r in state["resources"]
             if r["type"] == "google_compute_firewall"}
    assert set(rules) == {"allow_rdp_broad", "deny_rdp"}
    for name, block in declared.items():
        attributes = rules[name]["instances"][0]["attributes"]
        for key in block:
            assert attributes[key] == block[key], f"{name}.{key}"


def test_the_pair_is_the_masked_shape_the_story_needs():
    """The scenario's premise as data: same flow, same sources, and the deny
    outranks the allow — which is exactly why the allow is dead today."""
    declared = json.loads(BASE.read_text(encoding="utf-8"))[
        "resource"]["google_compute_firewall"]
    allow, deny = declared["allow_rdp_broad"], declared["deny_rdp"]
    assert allow["allow"] == [{"ports": ["3389"], "protocol": "tcp"}]
    assert deny["deny"] == [{"ports": ["3389"], "protocol": "tcp"}]
    assert allow["source_ranges"] == deny["source_ranges"] == ["0.0.0.0/0"]
    assert deny["priority"] == 900 < allow["priority"] == 1000
    assert allow["name"] == ALLOW_NAME and deny["name"] == DENY_NAME
    assert allow["network"] == deny["network"]


def test_the_example_ships_no_config_file():
    assert not (EXAMPLE / ".gcp-grounding.json").exists()


# -- the grounding, through the library route the CLI itself takes -------------


@_needs_z3
def test_the_base_is_denied_naming_the_dead_pair_from_both_directions():
    """Hygiene debt on arrival: the dead allow is named twice (world-open by
    its own text, unreachable behind the deny) and the restated deny draws the
    mirror kill-report. Three contradictions, no more."""
    report = _evaluate(BASE)
    assert not report.ok

    blocking = _blocking(report)
    assert len(blocking) == 3, blocking
    assert all(v.status == "contradicted" for v in blocking), blocking

    exposure = [v for v in blocking if v.kind == "firewall_exposure"]
    assert len(exposure) == 1, blocking
    assert exposure[0].message.startswith(ALLOW_ADDRESS)
    assert "a public source (" in exposure[0].message
    assert EXPOSED_FLOW in exposure[0].message

    shadows = sorted((v.message for v in blocking
                      if v.kind == "firewall_shadow"))
    assert len(shadows) == 2, blocking
    assert shadows[0].startswith(ALLOW_ADDRESS) and MASKED in shadows[0]
    assert shadows[1].startswith(DENY_ADDRESS) and KILL_REPORT in shadows[1]


@_needs_z3
def test_the_proposal_is_denied_on_the_exposure_and_shadow_interplay():
    """The accident: with the deny gone from the document, the allow's own
    text is world-open (exposure) while the estate fold — still holding the
    very deny this change deletes — says the rule is dead today (shadow).
    Together: dead today, world-open the moment this applies."""
    report = _evaluate(PROPOSAL)
    assert not report.ok

    blocking = _blocking(report)
    assert len(blocking) == 2, blocking

    exposure = [v for v in blocking if v.kind == "firewall_exposure"]
    assert len(exposure) == 1, blocking
    assert exposure[0].status == "contradicted"
    assert exposure[0].message.startswith(ALLOW_ADDRESS)
    assert EXPOSED_FLOW in exposure[0].message

    shadow = [v for v in blocking if v.kind == "firewall_shadow"]
    assert len(shadow) == 1, blocking
    assert shadow[0].status == "contradicted"
    assert shadow[0].message.startswith(ALLOW_ADDRESS)
    assert DENY_NAME in shadow[0].message, "the masking deny must be named"
    assert MASKED in shadow[0].message


@_needs_z3
def test_the_cleanup_is_denied_too_the_pair_tier_gap_cuts_both_ways():
    """EMPIRICAL, not the arc as first expected: deleting the dead allow was
    meant to approve, but deletions are invisible without the pair tier. The
    restated deny is compared against an estate that still carries the allow
    and draws the kill-report — the ONLY blocker, and a true sentence about
    today's estate (it is the mask itself), conservatively attributed to the
    document that restates the deny."""
    report = _evaluate(CLEANUP)
    assert not report.ok

    blocking = _blocking(report)
    assert len(blocking) == 1, blocking
    verdict = blocking[0]
    assert verdict.status == "contradicted" and verdict.kind == "firewall_shadow"
    assert verdict.message.startswith(DENY_ADDRESS)
    assert KILL_REPORT in verdict.message
    # No exposure finding anywhere: a deny exposes nothing on its own.
    assert not [v for v in report.verdicts if v.kind == "firewall_exposure"]


# -- the README's step-9 invocations, four flags each ---------------------------


def _verify(capsys, proposal: Path) -> tuple[int, str, str]:
    return invoke(
        capsys, "verify-policy",
        "--proposal", str(proposal),
        "--snapshot", str(SNAPSHOT),
        "--terraform-state", str(STATE),
        "--explain")


@_needs_z3
def test_the_readme_base_invocation_denies_naming_all_three_findings(capsys):
    code, out, err = _verify(capsys, BASE)
    assert code == 1
    assert "FAILED" in out
    assert "decision: DENIED (exit 1)" in err
    for stream in (out, err):
        assert "[firewall_exposure]" in stream
        assert "[firewall_shadow]" in stream
        assert MASKED in stream
        assert KILL_REPORT in stream


@_needs_z3
def test_the_readme_proposal_invocation_denies_with_the_two_stories(capsys):
    code, out, err = _verify(capsys, PROPOSAL)
    assert code == 1
    assert "FAILED" in out
    assert "decision: DENIED (exit 1)" in err
    # The recap — the last lines a terminal shows — carries both stories:
    # world-open by its own text, dead today behind the deny being deleted.
    recap = err[err.index("decision recap:"):]
    assert "DENIED (exit 1)" in recap
    assert "[firewall_exposure]" in recap and EXPOSED_FLOW in recap
    assert "[firewall_shadow]" in recap and MASKED in recap
    assert KILL_REPORT not in err, "no deny in the document, no kill-report"


@_needs_z3
def test_the_readme_cleanup_invocation_denies_on_the_kill_report_alone(capsys):
    code, out, err = _verify(capsys, CLEANUP)
    assert code == 1
    assert "FAILED" in out
    assert "decision: DENIED (exit 1)" in err
    recap = err[err.index("decision recap:"):]
    assert "[firewall_shadow]" in recap and KILL_REPORT in recap
    assert "[firewall_exposure]" not in err, \
        "a deny exposes nothing on its own"


# -- the conditional-approval arm (9d-9f) ---------------------------------------


def test_the_narrowed_proposal_is_the_accident_with_exactly_the_two_ranges():
    """The remediation candidate differs from the accident's shape by exactly
    the source-range narrowing — same rule, same flow, same priority."""
    expected = deepcopy(json.loads(PROPOSAL.read_text(encoding="utf-8")))
    expected["resource"]["google_compute_firewall"]["allow_rdp_broad"][
        "source_ranges"] = [PARTNER_A, PARTNER_B]
    narrowed = json.loads(NARROWED.read_text(encoding="utf-8"))
    assert narrowed == expected, (
        "narrowed.tf.json must be proposal.tf.json with source_ranges set to "
        "exactly the two audited partner ranges — nothing more, nothing less")


def test_the_smuggle_is_the_narrowed_proposal_plus_exactly_the_extra_range():
    expected = deepcopy(json.loads(NARROWED.read_text(encoding="utf-8")))
    expected["resource"]["google_compute_firewall"]["allow_rdp_broad"][
        "source_ranges"] = [PARTNER_A, PARTNER_B, SMUGGLED]
    extra = json.loads(NARROWED_EXTRA.read_text(encoding="utf-8"))
    assert extra == expected, (
        "narrowed_extra.tf.json must be narrowed.tf.json plus exactly the one "
        "unaudited /28 — nothing more, nothing less")


def test_the_after_removal_state_is_the_state_minus_exactly_the_deny():
    """The post-accident state: the deny applied-gone, the woken allow still
    world-open exactly as ``terraform.tfstate`` carried it, serial advanced on
    the same lineage — one apply later, nothing else touched."""
    before = json.loads(STATE.read_text(encoding="utf-8"))
    after = json.loads(STATE_AFTER.read_text(encoding="utf-8"))
    assert after["version"] == 4
    assert after["lineage"] == before["lineage"]
    assert after["serial"] > before["serial"]
    expected_resources = [r for r in before["resources"]
                          if r["name"] != "deny_rdp"]
    assert after["resources"] == expected_resources, (
        "terraform-after-removal.tfstate must be terraform.tfstate minus "
        "exactly the deny resource — the allow stays world-open as applied")


def test_the_corpus_is_the_one_promise_over_the_two_partner_ranges():
    text = CORPUS.read_text(encoding="utf-8")
    assert f"id: {PROMISE_ID}" in text
    assert PARTNER_A in text and PARTNER_B in text
    # The subset obligation quantifies over the proposal's own rows and is
    # scoped to the one previously masked rule.
    assert "exists r in proposed_firewall_rules" in text
    assert f'cmp eq field r.name str "{ALLOW_NAME}"' in text


@pytest.fixture
def compiled(tmp_path, capsys):
    """The scenario's own corpus, compiled like the README's step 9d. Exit 0:
    nothing in it is booby-trapped."""
    out = tmp_path / "compiled-masked"
    assert main(["compile-requirements", str(EXAMPLE), "--snapshot",
                 str(SNAPSHOT), "--out", str(out)]) == 0
    capsys.readouterr()
    return out


def _verify_arm(capsys, proposal: Path, compiled) -> tuple[int, str, str]:
    return invoke(
        capsys, "verify-policy",
        "--proposal", str(proposal),
        "--snapshot", str(SNAPSHOT),
        "--terraform-state", str(STATE_AFTER),
        "--requirements", str(compiled),
        "--explain")


@_needs_z3
def test_the_readme_narrowed_invocation_approves_on_a_grounded_judgment(
        compiled, capsys):
    """APPROVED, and the promise verdict is a grounded subset judgment — not
    an abstention that defaults to pass — with both built-ins green beside it:
    exposure (private sources only) and the pair tier, which resolves a
    baseline target here, unlike the 9a-9c shape."""
    code, out, err = _verify_arm(capsys, NARROWED, compiled)
    assert code == 0
    assert "PASSED" in out
    assert "decision: APPROVED (exit 0)" in err
    assert f"holds     {PROMISE_ID}" in err
    assert (f"[sec:vpc_firewall] {PROMISE_ID}: the obligation holds over "
            f"the document — grounded") in out
    assert "no public source reaches a sensitive port" in out
    assert "the new rule set allows no packet the old set denied" in out
    assert "refuted by" not in err


@_needs_z3
def test_the_readme_smuggle_invocation_denies_naming_the_range(
        compiled, capsys):
    """DENIED on the promise ALONE: the /28 is private (no exposure) and the
    new set still narrows the world-open state (pair grounds), so only the
    subset obligation refuses — naming the smuggled range and the block."""
    code, out, err = _verify_arm(capsys, NARROWED_EXTRA, compiled)
    assert code == 1
    assert "FAILED" in out
    assert "decision: DENIED (exit 1)" in err
    assert f"VIOLATED  {PROMISE_ID}" in err
    # Both built-ins stay green: the promise is the only blocker.
    assert "no public source reaches a sensitive port" in out
    assert "the new rule set allows no packet the old set denied" in out
    # The recap — the last lines a terminal shows — quotes the offending row:
    # the range is a constant of the document, not a solver-minted witness,
    # so it is pinned verbatim.
    recap = err[err.index("decision recap:"):]
    assert "DENIED (exit 1)" in recap
    assert f"[sec:vpc_firewall] {PROMISE_ID}: refuted by " \
           "proposed_firewall_rules[" in recap
    assert f"({ALLOW_ADDRESS})" in recap
    assert f"source_range={SMUGGLED!r}" in recap
