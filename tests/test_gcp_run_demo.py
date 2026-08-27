"""``run_demo.sh`` — every README demo arc runnable as one command.

The runner is the README's "Running the demo" section made executable: one
scenario per invocation, each step echoed and then run, each step's exit
compared to the exit the README documents for it. A DENIED step exits 1 *by
design*, so the runner cannot use ``set -e`` and a nonzero step is not a
failure by itself — the verdict is whether the OBSERVED exit is the
DOCUMENTED one.

This module is the conformance pin between the three things that can drift
apart — the README's at-a-glance table, the arcs the runner wires, and the
proposals committed under ``examples/``:

* ``--list`` enumerates exactly the table's scenarios, in its order, naming
  each row's own proposal — the runner reads that table, so a scenario added
  to the README with no arc behind it makes ``--list`` itself fail;
* every listed proposal is a file that exists under ``examples/``, and every
  example directory is reached by at least one listed scenario;
* a whole arc runs end to end through the runner — the ``compile-requirements``
  step included — and reports the verdict line, both for an arc whose steps
  are documented to exit 0 and for one documented to exit 1;
* a step that exits anything else fails the scenario and the runner exits
  nonzero, which is the property the whole thing exists for.

The three arcs run here (``3c``, ``4`` and ``w``) are the ones whose documented
exits do not depend on the clock: the runner drops any exported
``GCP_GROUNDING_*`` before running an arc (the arcs name every input by flag),
so it is the wall clock that decides snapshot freshness, and these decide the
same either side of the seven-day ceiling. Arcs are driven with ``GCP_GROUND``
pointing at the interpreter running this suite, so the arc is judged by the same
checkout and the same z3 capability the rest of the suite measures.

``w`` is the teaching walkthrough the README's "How the gate thinks" section
quotes end to end, and it is the one arc whose steps are *documentation* — the
section prints the compile's output, the artifact and the verify run's tail, so
an arc that stopped exiting as written would leave a page quoting a run nobody
can reproduce. Its three steps are pinned by count as well as by verdict,
because the section walks through each of them by name.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "run_demo.sh"
README = REPO_ROOT / "README.md"
EXAMPLES = REPO_ROOT / "examples"

#: A `| a | b | c | d |` row of the at-a-glance table.
ROW = re.compile(r"^\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|\s*$")

#: A `--list` entry: label, step count, the row's proposal.
LISTED = re.compile(r"^ {2}(\S+) +(\d+) step\(s\) {2}(examples/[^\s,]+)")


def readme_scenarios():
    """The at-a-glance table as ``(label, proposal)`` pairs, parsed here
    independently of the runner's own awk so the two must agree."""
    rows, started = [], False
    for line in README.read_text(encoding="utf-8").splitlines():
        if line.startswith("### The scenarios at a glance"):
            started = True
            continue
        if not started:
            continue
        cells = ROW.match(line)
        if cells is None:
            if rows:
                break
            continue
        label, _scenario, proposal = (
            cells.group(n).replace("`", "").strip() for n in (1, 2, 3))
        if label == "#" or set(label) == {"-"}:
            continue
        rows.append((label, proposal.split(",")[0].strip()))
    return rows


def demo(*argv, env=None):
    """Run the runner as the README spells it — the file itself, executable."""
    child = dict(os.environ)
    # Same interpreter as this suite: same checkout, same z3 capability. The
    # runner word-splits this, so a path with a space is left to its own
    # resolution (the repo venv) rather than being split into nonsense.
    if " " not in sys.executable:
        child["GCP_GROUND"] = f"{sys.executable} -m gcp_grounding"
    child.update(env or {})
    return subprocess.run([str(RUNNER), *argv], cwd=REPO_ROOT, env=child,
                          capture_output=True, text=True)


def test_the_runner_is_executable_as_the_readme_invokes_it():
    assert RUNNER.is_file() and os.access(RUNNER, os.X_OK), \
        "the README says ./run_demo.sh; it must carry its exec bit"


def test_list_enumerates_exactly_the_readme_table():
    expected = readme_scenarios()
    assert expected, "the at-a-glance table did not parse"

    proc = demo("--list")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    listed = [(m.group(1), m.group(3), int(m.group(2)))
              for m in map(LISTED.match, proc.stdout.splitlines()) if m]

    assert [(label, proposal) for label, proposal, _ in listed] == expected
    assert all(steps >= 1 for _, _, steps in listed)


def test_every_listed_scenario_names_a_proposal_under_examples():
    proc = demo("--list")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    proposals = [m.group(3) for m in map(LISTED.match, proc.stdout.splitlines())
                 if m]
    assert proposals

    missing = [p for p in proposals if not (REPO_ROOT / p).is_file()]
    assert not missing, f"listed but not committed under examples/: {missing}"

    covered = {Path(p).parent.name for p in proposals}
    present = {d.name for d in EXAMPLES.iterdir() if d.is_dir()}
    assert covered == present, "every examples/ directory is one or more scenarios"


def test_a_full_arc_runs_its_compile_step_and_reports_a_pass_verdict():
    # 3c: compile the masked-deny corpus (exit 0), then judge the narrowed
    # allow with that promise in force (exit 0) — README steps 9d and 9e.
    proc = demo("3c")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "compile-requirements examples/terraform-masked" in proc.stdout
    assert proc.stdout.count(": exit 0, as documented") == 2
    assert "scenario 3c: PASS — 2/2 steps exited as the README documents" \
        in proc.stdout


def test_an_arc_whose_step_is_documented_to_deny_passes_on_exit_1():
    # 4 is README step 10a: the gate exits 1 BY DESIGN, and a runner that
    # stopped at the first nonzero exit could not run this arc at all.
    proc = demo("4")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "expected exit: 1" in proc.stdout
    assert ": exit 1, as documented" in proc.stdout
    assert "scenario 4: PASS — 1/1 steps exited as the README documents" \
        in proc.stdout


def test_the_walkthrough_arc_compiles_then_denies_both_document_kinds():
    # w: compile the one-promise corpus (exit 0), then judge the same promise
    # over a REST IAM policy and over a terraform configuration — both DENIED
    # by design, which is what the "How the gate thinks" section walks through.
    proc = demo("w")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "compile-requirements examples/walkthrough" in proc.stdout
    assert proc.stdout.count(": exit 0, as documented") == 1
    assert proc.stdout.count(": exit 1, as documented") == 2
    for proposal in ("examples/walkthrough/policy.json",
                     "examples/walkthrough/proposal.tf.json"):
        assert f"--proposal {proposal}" in proc.stdout
    assert "scenario w: PASS — 3/3 steps exited as the README documents" \
        in proc.stdout


def test_a_step_that_exits_otherwise_fails_the_scenario(tmp_path):
    # A stub gate that always exits 3, so the arc's own documented exit
    # cannot be met: the step is reported as diverged and the runner says so
    # in its verdict and in its own exit code.
    stub = tmp_path / "stub_gate.py"
    stub.write_text("raise SystemExit(3)\n", encoding="utf-8")
    proc = demo("4c", env={"GCP_GROUND": f"{sys.executable} {stub}"})

    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "DIVERGED — exit 3, the README documents 0" in proc.stdout
    assert "scenario 4c: FAIL — 1 of 1 steps diverged" in proc.stdout


def test_a_scenario_the_readme_does_not_name_is_refused():
    proc = demo("42")
    assert proc.returncode == 2
    assert "no scenario 42" in proc.stderr


@pytest.mark.parametrize("argv, code", [(("--help",), 0), (("--nonsense",), 2),
                                        ((), 2)])
def test_the_usage_line_names_both_modes(argv, code):
    # No argument is refused rather than treated as a success: a caller whose
    # scenario variable expanded to nothing has run no arc at all.
    proc = demo(*argv)
    combined = proc.stdout + proc.stderr
    assert proc.returncode == code, combined
    assert "./run_demo.sh <scenario>" in combined
    assert "./run_demo.sh --list" in combined
