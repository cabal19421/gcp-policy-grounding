"""``--explain``'s solver census: the formula families a run actually executed.

In-process like :mod:`tests.test_gcp_cli`, driving :func:`gcp_grounding.cli.
main` and reading stderr with ``capsys``.

WHAT THIS MODULE IS ACTUALLY GUARDING. The block this replaces was re-derived
from the proposal document after the run: it showed what the document would
encode to, which is not the same as what the run decided. Every promise that
abstained before the encoder, every packet assertion a firewall or Cloud Armor
check assembled, was invisible in it — and everything it did show was built a
second time, by a second caller, and could disagree with the first.

So the assertions here are about the JOIN between the section and the run:

* a promise line exists exactly when that promise reached the solver, carries
  the mode its obligation was really built under, and disappears when the
  promise abstained first — asserted on a run whose promise abstains at the
  named-subject gate, one step ahead of the encoder;
* the firewall and armor lines exist on the runs whose checks assembled a
  formula, anchored where the verdicts from the same checks are anchored;
* nothing at all is printed when no family ran, header included;
* and the stdout report is byte-identical with and without the flag, which is
  what says the recording seams (a z3 module whose solver records what it is
  asked to decide, among them) changed no verdict.

Environment-honest like its neighbours: with no z3 nothing compiles, nothing
encodes and the section is the one degraded line, so the family assertions are
SKIPPED there rather than passing over an empty section.
"""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from gcp_grounding import solver_census
from gcp_grounding.cli import (REQUIREMENTS_ENV, SNAPSHOT_ENV,
                               _CENSUS_SEXPR_CAP, _explain_lines, main)
from gcp_grounding.core.solver import get_solver
from gcp_grounding.sources import TF_STATE_ENV

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"
AGENTIC = FIXTURES / "agentic"

SNAPSHOT = FIXTURES / "snapshot.json"
GOOD = POLICIES / "iam_policy_good.json"
BAD = POLICIES / "iam_policy_bad.json"
FW_OPEN = POLICIES / "fw_rule_open.json"
FW_BASELINE = POLICIES / "fw_rule_baseline.json"
ARMOR = POLICIES / "armor_policy.json"
ORG_GOOD = POLICIES / "org_policy_good.json"

AGENTIC_SNAPSHOT = FIXTURES / "agentic_snapshot.json"
AGENTIC_REQUIREMENTS = FIXTURES / "sec_requirements"
A10_POLICY = AGENTIC / "iam" / "A10_owner_to_external.policy.json"
#: An org-policy document about a DIFFERENT constraint than the org-policy
#: promise names — so that promise is applicable, is evaluated, and abstains at
#: the named-subject gate one step ahead of the encoder.
A13_POLICY = AGENTIC / "orgpolicy" / "A13_domain_allowlist_widened.policy.json"

HEADER = "z3 constraints generated this run"
NO_Z3_LINE = ("  (z3 is not available — no constraints were generated; "
              "cel and subset checks degraded to 'unverified')")

#: The words the post-build sweep removes from the documentation; the product's
#: own new output must not put fresh ones back.
_SWEPT_WORDS = ("honest", "honestly", "quietly", "simply")

HAVE_Z3 = get_solver().backend == "z3"
_needs_z3 = pytest.mark.skipif(
    not HAVE_Z3, reason="no solver: nothing encodes, so no family runs")


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture(autouse=True)
def _configuration_off(monkeypatch):
    """No test here inherits a developer's exported configuration: an ambient
    ``$GCP_GROUNDING_REQUIREMENTS`` would add promise lines to the runs that
    assert the section is absent."""
    for name in (REQUIREMENTS_ENV, SNAPSHOT_ENV, TF_STATE_ENV):
        monkeypatch.delenv(name, raising=False)


def compiled_requirements(tmp_path: Path) -> Path:
    """The agentic corpus compiled into a tmp directory.

    Exit 1 by design — the corpus carries a deliberately rejected promise — and
    the artifacts are still written, which is what the pickup reads.
    """
    out = tmp_path / "compiled"
    assert main(["compile-requirements", str(AGENTIC_REQUIREMENTS),
                 "--snapshot", str(AGENTIC_SNAPSHOT), "--out", str(out)]) == 1
    return out


def section(err: str) -> list[str]:
    """The census block's lines, header included — ``[]`` when it is absent."""
    lines = err.splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith(HEADER)]
    if not starts:
        return []
    assert len(starts) == 1, f"the section printed {len(starts)} times"
    block = [lines[starts[0]]]
    for line in lines[starts[0] + 1:]:
        if line and not line.startswith("  "):
            break
        block.append(line)
    return block


def entries(err: str, family: str) -> list[str]:
    """Every ``[family]`` line of the census, minus its indent and tag."""
    tag = f"  [{family}] "
    return [line[len(tag):] for line in section(err) if line.startswith(tag)]


def sexpr_of(entry: str) -> str:
    """The rendered s-expression of one census entry line."""
    _anchor, _sep, rendered = entry.partition(": ")
    return rendered


# -- one line per family, against a real run -----------------------------------


@_needs_z3
def test_every_promise_that_reached_the_solver_gets_one_line(capsys, tmp_path):
    """One line per evaluated promise, naming the mode its obligation was built
    under and the collection its formula was grounded over.

    The A10 run enforces six promises; three of them are iam-domain promises
    this iam document is about, and those three are exactly the lines. The
    other three are about firewall rules, perimeters and org policies, reach no
    encoder over an IAM policy, and are absent — a section listing six would be
    listing a formula this run never built.
    """
    compiled = compiled_requirements(tmp_path)
    capsys.readouterr()
    code, _out, err = invoke(capsys, "verify-policy", str(A10_POLICY),
                             "--snapshot", str(AGENTIC_SNAPSHOT),
                             "--requirements", str(compiled), "--explain")
    assert code == 1
    assert [entry.partition(" (")[0] for entry in entries(err, "sec:iam")] == [
        "impersonation-sre-only", "no-primitive-roles-outside-domain",
        "no-public-principals"]
    for entry in entries(err, "sec:iam"):
        assert "(refute over iam_bindings): (" in entry, entry
    # The promises block says all six are in force; the census says which three
    # of them this document put a question to.
    assert "promises in force (6 enforcing, 2 not" in err
    for absent in ("[sec:vpc_firewall]", "[sec:vpc_sc]", "[sec:org_policy]"):
        assert absent not in err


@_needs_z3
def test_a_promise_that_abstained_before_the_encoder_contributes_no_line(
        capsys, tmp_path):
    """The named-subject gate abstains INSIDE ``evaluate`` and ahead of the
    encoder, so the promise is evaluated, is on the record as undecided — and
    has no census line, because it built no formula."""
    compiled = compiled_requirements(tmp_path)
    capsys.readouterr()
    code, _out, err = invoke(capsys, "verify-policy", str(A13_POLICY),
                             "--snapshot", str(AGENTIC_SNAPSHOT),
                             "--requirements", str(compiled), "--explain")
    assert code == 0
    assert "undecided  sa-key-creation-disabled [org_policy]" in err
    assert "is not decided by a document about a different one" in err
    assert entries(err, "sec:org_policy") == []


@_needs_z3
def test_the_line_is_the_obligation_the_decision_rested_on(capsys, tmp_path):
    """Not one of the per-record obligations that follow it.

    A refuted promise re-grounds its ast once per record to name the record
    that refutes it, so a run like this one builds four obligations for one
    promise: the whole-document one the decision was taken on, then one per
    binding. The census line is the first — here, one naming a member of a
    binding the refutation does not point at, which no single-record obligation
    could contain.
    """
    compiled = compiled_requirements(tmp_path)
    policy = tmp_path / "three_bindings.policy.json"
    policy.write_text(json.dumps({
        "bindings": [
            {"role": "roles/bigquery.reader",
             "members": ["group:data-eng@acme.example"]},
            {"role": "roles/storage.objectViewer",
             "members": ["user:alice@acme.example"]},
            {"role": "roles/owner", "members": ["user:attacker@evil.example"]},
        ],
        "etag": "BwYCensus3=", "version": 1,
    }), encoding="utf-8")
    capsys.readouterr()
    code, _out, err = invoke(capsys, "verify-policy", str(policy), "--snapshot",
                             str(AGENTIC_SNAPSHOT), "--requirements",
                             str(compiled), "--explain")
    assert code == 1
    assert "refuted by iam_bindings[" in err, err
    assert "member='user:attacker@evil.example'" in err, err
    line = [entry for entry in entries(err, "sec:iam")
            if entry.startswith("no-primitive-roles-outside-domain")]
    assert len(line) == 1, line
    assert "group:data-eng@acme.example" in sexpr_of(line[0]), line


@_needs_z3
def test_the_cel_and_subset_lines_are_the_ones_they_always_were(capsys):
    """Both families keep their existing content: the per-condition translation
    and the new⊈old assertion, each under its own tag."""
    _code, _out, err = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                              str(SNAPSHOT), "--baseline", str(BAD), "--explain")
    assert entries(err, "cel") == [
        "bindings[2].condition.expression: (> 1798761600000000.0 request.time)"]
    assert [line for line in section(err)
            if line.startswith("  [subset] iam-policy: (")], section(err)


@_needs_z3
def test_each_firewall_check_that_built_a_formula_gets_one_line(capsys):
    """The exposure check and the pair check both assemble a packet assertion
    and drive their own solver; each contributes one line, anchored where its
    own verdicts are anchored — the rule address, and the document for the
    comparison that is about no single rule."""
    code, _out, err = invoke(capsys, "verify-policy", str(FW_OPEN), "--snapshot",
                             str(SNAPSHOT), "--baseline", str(FW_BASELINE),
                             "--explain")
    assert code == 1
    anchors = [entry.partition(": ")[0] for entry in entries(err, "firewall")]
    assert anchors == sorted(["fw-allow-open", str(FW_OPEN)])
    for entry in entries(err, "firewall"):
        # The packet algebra encodes addresses and ports as bitvectors, so the
        # assembled assertion is recognisably a packet formula.
        assert sexpr_of(entry).startswith("("), entry
        assert "port" in entry, entry


@_needs_z3
def test_the_armor_check_contributes_its_assembled_assertion(capsys):
    """Cloud Armor's priority reasoning decides through the shared solver front
    end; the first assertion it assembles is the policy document's line."""
    _code, _out, err = invoke(capsys, "verify-policy", str(ARMOR), "--snapshot",
                              str(SNAPSHOT), "--explain")
    assert [entry.partition(": ")[0] for entry in entries(err, "armor")] == [
        str(ARMOR)]
    assert sexpr_of(entries(err, "armor")[0]).startswith("(")


# -- the rendering rules -------------------------------------------------------


@_needs_z3
def test_every_rendered_sexpr_is_capped_with_an_ellipsis(capsys, tmp_path):
    """The cap is what keeps one formula to one line. A promise over a real
    document encodes past it, so this run has both a cut line and a short one —
    a run with only short formulas would assert nothing.
    """
    assert _CENSUS_SEXPR_CAP == 160
    compiled = compiled_requirements(tmp_path)
    capsys.readouterr()
    _code, _out, err = invoke(capsys, "verify-policy", str(A10_POLICY),
                              "--snapshot", str(AGENTIC_SNAPSHOT),
                              "--requirements", str(compiled), "--explain")
    rendered = [sexpr_of(entry) for entry in entries(err, "sec:iam")]
    assert rendered and all(len(one) <= _CENSUS_SEXPR_CAP for one in rendered)
    cut = [one for one in rendered if one.endswith("…")]
    assert cut, f"no formula reached the cap:\n{rendered}"
    assert all(len(one) == _CENSUS_SEXPR_CAP for one in cut)
    assert [one for one in rendered if not one.endswith("…")], (
        f"every formula was cut, so the cap asserts nothing:\n{rendered}")


@_needs_z3
def test_the_lines_are_ordered_by_family_then_anchor(capsys, tmp_path):
    """Three families in one run, in family order, with the promises inside the
    one family in anchor order — the same lines in the same order on every run
    over the same inputs."""
    compiled = compiled_requirements(tmp_path)
    capsys.readouterr()
    _code, _out, err = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                              str(AGENTIC_SNAPSHOT), "--requirements",
                              str(compiled), "--baseline", str(BAD), "--explain")
    tags = [line.split("] ")[0] + "]" for line in section(err)[1:]
            if line.startswith("  [")]
    assert tags == ["  [cel]", "  [sec:iam]", "  [sec:iam]", "  [sec:iam]",
                    "  [subset]"]
    anchors = [entry.partition(" (")[0] for entry in entries(err, "sec:iam")]
    assert anchors == sorted(anchors)


@_needs_z3
def test_the_section_is_omitted_entirely_when_no_family_ran(capsys):
    """No header, no placeholder, nothing — for a document that mints no CEL
    claim, runs against no baseline and puts no question to a promise."""
    code, _out, err = invoke(capsys, "verify-policy", str(ORG_GOOD),
                             "--snapshot", str(SNAPSHOT), "--explain")
    assert code == 0
    assert HEADER not in err
    assert section(err) == []
    # The rest of the narrative is untouched, and the state block still follows
    # the one blank line that separated it from the section.
    assert "what was proposed:" in err
    assert "\n\nstate used this run" in err


def test_the_degraded_world_keeps_its_line(monkeypatch):
    """With no z3 the header and the line explaining every degraded verdict
    above it are printed whether or not anything ran — the omission rule is
    about a working solver with no work, not about a missing one."""
    monkeypatch.setattr("gcp_grounding.cli.get_solver",
                        lambda: SimpleNamespace(backend="builtin", _z3=None))
    assert _explain_lines(str(GOOD), None) == [
        f"{HEADER} [builtin]:", NO_Z3_LINE]


@_needs_z3
def test_the_census_avoids_the_swept_words(capsys, tmp_path):
    """The new output strings carry none of the words the documentation sweep
    removes."""
    compiled = compiled_requirements(tmp_path)
    capsys.readouterr()
    _code, _out, err = invoke(capsys, "verify-policy", str(A10_POLICY),
                              "--snapshot", str(AGENTIC_SNAPSHOT),
                              "--requirements", str(compiled), "--explain")
    block = "\n".join(section(err)).casefold()
    assert block and not [word for word in _SWEPT_WORDS if word in block]


# -- what the recording may not change -----------------------------------------


#: The runs whose every verdict message is fixed by the documents alone. A
#: SATISFIABLE check names the witness the solver chose, and which of several
#: witnesses that is varies between two runs in one process with or without any
#: flag — a pre-existing property of the solver, asserted as such below.
_WITNESS_FREE = {
    "iam": ["verify-policy", str(GOOD), "--snapshot", str(SNAPSHOT)],
    "armor": ["verify-policy", str(ARMOR), "--snapshot", str(SNAPSHOT)],
    "org": ["verify-policy", str(ORG_GOOD), "--snapshot", str(SNAPSHOT)],
}


@pytest.mark.parametrize("case", sorted(_WITNESS_FREE))
@pytest.mark.parametrize("fmt", ["text", "json"])
def test_the_report_is_byte_identical_with_and_without_explain(capsys, case, fmt):
    """THE GUARD ON EVERY OTHER PIN IN THE SUITE. Recording happens around the
    grounding pass and hands the census families a z3 module of its own, so the
    exit code and the stdout report of a run with the flag have to be the ones
    the run without it produces, byte for byte — in both renders, because
    several consumers and several tests read the json one.
    """
    argv = [*_WITNESS_FREE[case], "--format", fmt]
    plain_code, plain_out, plain_err = invoke(capsys, *argv)
    explain_code, explain_out, _err = invoke(capsys, *argv, "--explain")
    assert (explain_code, explain_out) == (plain_code, plain_out)
    assert plain_err == "", "a passing run without --explain writes no stderr"


@pytest.mark.parametrize("case", ["firewall", "subset"])
def test_a_witness_bearing_run_decides_the_same_verdicts_either_way(capsys, case):
    """The two runs whose messages carry a solver-minted witness.

    Which witness z3 hands back is its own choice among many, and which one it
    picks is not stable across two runs in one process with the flag or without
    it — a pre-existing property of the solver, which is why the messages are
    not what is compared here. What must not move is the set of verdicts: same
    statuses, same kinds, same targets, in the same order, against a control run
    that carries no flag. A recording seam that changed a verdict shows here.
    """
    argv = {
        "firewall": ["verify-policy", str(FW_OPEN), "--snapshot", str(SNAPSHOT),
                     "--baseline", str(FW_BASELINE)],
        "subset": ["verify-policy", str(GOOD), "--snapshot", str(SNAPSHOT),
                   "--baseline", str(BAD)],
    }[case] + ["--format", "json"]

    def decided(out: str) -> list[tuple]:
        return [(v["status"], v["kind"], v["target"])
                for v in json.loads(out)["verdicts"]]

    first_code, first_out, _err = invoke(capsys, *argv)
    control_code, control_out, _err = invoke(capsys, *argv)
    explain_code, explain_out, _err = invoke(capsys, *argv, "--explain")
    assert decided(explain_out) == decided(control_out) == decided(first_out)
    assert explain_code == control_code == first_code
    assert json.loads(explain_out)["summary"] == json.loads(control_out)["summary"]


def test_nothing_is_instrumented_while_no_census_records():
    """The recording seams are inert by construction, not by discipline: with
    nothing recording, a check is handed the solver's own z3 module BY IDENTITY
    and the obligation seam writes nowhere."""
    sentinel = SimpleNamespace(Solver=object)
    assert solver_census.active() is None
    assert solver_census.instrument(sentinel) is sentinel
    assert solver_census.instrument(None) is None
    solver_census.record_obligation(SimpleNamespace(), "refute")  # no census
    with solver_census.recording() as census:
        # Recording, but outside every scope: still the real module, because no
        # check has been named yet.
        assert solver_census.instrument(sentinel) is sentinel
        solver_census.record_obligation(SimpleNamespace(), "refute")
        assert census.entries() == ()
    assert solver_census.active() is None


def test_a_check_outside_the_census_families_is_never_instrumented():
    """Only the checks that assemble a packet assertion get an instrumented
    module; every other domain check decides with the real one."""
    sentinel = SimpleNamespace(Solver=object)
    with solver_census.recording():
        with solver_census.check_scope("gcp_grounding.iam_checks.check", "x"):
            assert solver_census.instrument(sentinel) is sentinel
        with solver_census.check_scope("gcp_grounding.fw_checks.check_open_"
                                       "exposure", "x"):
            assert solver_census.instrument(sentinel) is not sentinel
