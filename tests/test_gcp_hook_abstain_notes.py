"""The hook's abstain channel: ``--abstain-notes``, asserted at the process
boundary.

The structural hole this closes: when ``report.ok`` is True the hook returns
exit 0 with ZERO stdout and ZERO stderr, so *could not judge* is byte-for-byte
identical to *judged and happy*. A raw ``.tf`` edit, an unparsable policy, a
CEL condition decided by no solver, an uncaptured snapshot category — every one
of them reaches the agent as an unqualified success. ``--abstain-notes`` prints
the ``unverified`` bucket to stderr and leaves the exit code alone.

Two contracts are asserted here, and they pull in opposite directions:

**The default is silence, and it stays silence.** ``tests/test_gcp_cli.py``
pins byte-empty streams on a passing hook run (line 280) and on an abstaining
one (line 320), and those assertions are *correct* for the default contract —
the hook's stderr is agent-visible, and a guardrail that chatters on every edit
is a guardrail that gets switched off. So the first test below runs every
abstain case with neither the flag nor the environment variable and demands
byte-empty streams; it is the local guard on those two frozen assertions. It
is not vacuous, because the very next test runs the same four documents with
the flag and shows each one really does carry an ``unverified`` verdict that
was being swallowed.

**When it is on, the ignorance is complete and the exit code is untouched.**
The notes never block: they live inside the ``report.ok`` arm, so a blocking
run renders exactly the report it always did (and no ``NOT DECIDED`` header),
and a clean run prints nothing at all, because no notes means no header.

Everything spawns a real child through
:func:`tests.agentic.hookrunner.run_hook`, whose ``SCRUBBED_ENV`` already
removes ``GCP_GROUNDING_ABSTAIN_NOTES`` — so "the environment variable is
unset" is a guarantee here, not a hope about the developer's shell.
"""

from __future__ import annotations

import json

import pytest

from gcp_grounding.cli import ABSTAIN_NOTES_ENV, _abstain_note_lines
from gcp_grounding.core.report import GroundingReport, Verdict
from tests.agentic.asserts import assert_blocked, assert_passed
from tests.agentic.env import HAVE_Z3
from tests.agentic.hookrunner import (
    bound_subprocess_budget,  # noqa: F401 — autouse: bind spawns to the budget
    run_hook,
)

#: The header the channel prints, and the string that must NEVER appear on a
#: blocking run or a clean one.
HEADER = "gcp-ground --hook: NOT DECIDED —"

#: The one-per-verdict line prefix: two spaces, the human render's question
#: mark, the bracketed kind. Every abstain below is a whole-document abstain,
#: so the kind is ``document``.
DOCUMENT_LINE = "  ? [document] "

#: The four abstain shapes, each mapped to the phrase its ``unverified``
#: message must carry. A note that does not say *why* is a silent pass wearing
#: a header.
ABSTAIN_REASONS = {
    "raw_tf": "the document is not valid JSON",
    "garbled": "the document could not be parsed",
    "unrecognized": "document kind was not recognized",
    "hybrid_org": "nothing checkable could be extracted",
}


def hook_event(path, tool_name="Write") -> dict:
    """A ``PostToolUse`` event naming *path* as the file *tool_name* wrote."""
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": tool_name,
        "tool_input": {"file_path": str(path)},
    }


@pytest.fixture
def abstain_document(tmp_path):
    """Factory: one document per key of :data:`ABSTAIN_REASONS`.

    All four are *policy candidates* by suffix — the gate opens them, looks,
    and cannot decide. That is the whole point: a file it never opened would be
    honestly out of scope, while these four are in scope and unjudged.
    """

    def make(case: str):
        if case == "raw_tf":
            # Raw HCL is not `terraform show -json` output.
            path = tmp_path / "main.tf"
            path.write_text('resource "google_project_iam_member" "x" {}\n',
                            encoding="utf-8")
        elif case == "garbled":
            path = tmp_path / "garbled.policy.json"
            path.write_bytes(b"\xff\xfe{\x00}")
        elif case == "unrecognized":
            path = tmp_path / "mystery.json"
            path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
        elif case == "hybrid_org":
            # v1 `constraint` and v2 `name` at once: the document is org-policy
            # shaped, and it names no unambiguous constraint, so the
            # conservative extractor emits nothing at all.
            path = tmp_path / "hybrid.policy.json"
            path.write_text(json.dumps({
                "name": "projects/acme-prod/policies/compute.requireOsLogin",
                "constraint": "constraints/compute.requireOsLogin",
                "spec": {"rules": [{"enforce": True}]},
            }), encoding="utf-8")
        else:  # pragma: no cover — a typo in a parametrize id
            raise AssertionError(f"unknown abstain case {case!r}")
        return path

    return make


@pytest.fixture
def clean_policy(policies_dir, tmp_path):
    """A fully grounded policy, with the CEL condition removed.

    ``iam_policy_good.json`` grounds completely *when z3 is importable*; its
    condition degrades to ``unverified`` when z3 is not, which would make the
    clean-run assertion below pass or fail on the world rather than on the
    channel. Dropping the condition makes the document clean in every world.
    """
    doc = json.loads((policies_dir / "iam_policy_good.json").read_text(
        encoding="utf-8"))
    for binding in doc["bindings"]:
        binding.pop("condition", None)
    path = tmp_path / "clean.policy.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


# -- the default: OFF, and byte-silent ----------------------------------------


@pytest.mark.parametrize("case", sorted(ABSTAIN_REASONS))
def test_default_off_stays_byte_silent_on_every_abstain(case, abstain_document,
                                                        estate_snapshot_path):
    """No flag and no environment variable: exit 0, both streams byte-empty.

    THE GUARD on ``tests/test_gcp_cli.py``'s two byte-empty assertions. This
    task adds a channel; it must not change what the default hook prints, and
    the four documents here are the same shapes those frozen tests cover.
    """
    outcome = run_hook(hook_event(abstain_document(case)),
                       snapshot=estate_snapshot_path)
    assert_passed(outcome)


# -- the channel: ON ----------------------------------------------------------


@pytest.mark.parametrize("case", sorted(ABSTAIN_REASONS))
def test_flag_on_puts_the_ignorance_on_the_record(case, abstain_document,
                                                  estate_snapshot_path,
                                                  estate_snapshot):
    """With ``--abstain-notes``: the header, the count, the mark, the kind, the
    location and the snapshot stamp — on stderr, at exit 0, with stdout still
    byte-empty.

    stdout matters as much as stderr: hook mode keeps stdout empty so the
    structured ``hookSpecificOutput`` channel stays available later.
    """
    path = abstain_document(case)
    outcome = run_hook(hook_event(path), snapshot=estate_snapshot_path,
                       extra_argv=("--abstain-notes",))
    assert outcome.exit_code == 0, (
        f"the abstain channel must never change an exit code\n{outcome}")
    assert outcome.stdout == "", (
        f"hook mode keeps stdout byte-empty; the notes go to stderr\n{outcome}")
    assert HEADER in outcome.stderr, f"expected the header\n{outcome}"
    assert "1 claim(s) could not be judged (exit 0, nothing blocked)" in \
        outcome.stderr, f"expected the count and the no-block note\n{outcome}"
    assert DOCUMENT_LINE in outcome.stderr, (
        f"expected the render's '?' mark and the bracketed kind\n{outcome}")
    assert str(path) in outcome.stderr, (
        f"expected the location the verdict names\n{outcome}")
    assert ABSTAIN_REASONS[case] in outcome.stderr, (
        f"a note must say WHY it could not judge\n{outcome}")
    assert f"[snapshot {estate_snapshot.captured_at}]" in outcome.stderr, (
        f"an unverified line is stamped with snapshot freshness\n{outcome}")


def test_flag_on_is_silent_on_a_clean_policy(clean_policy,
                                             estate_snapshot_path):
    """No notes means no header: a fully grounded document prints nothing.

    A channel that fires on clean passes is noise, and a noisy hook is a
    disabled hook — which would take the abstain reporting down with it.
    """
    outcome = run_hook(hook_event(clean_policy), snapshot=estate_snapshot_path,
                       extra_argv=("--abstain-notes",))
    assert_passed(outcome)


def test_flag_on_leaves_a_blocking_run_untouched(policies_dir,
                                                 estate_snapshot_path):
    """The notes live inside the ``report.ok`` arm, so a block is unchanged:
    exit 2, the FAILED render on stderr, and NO ``NOT DECIDED`` header — not
    once, and certainly not twice alongside the report."""
    outcome = run_hook(hook_event(policies_dir / "iam_policy_bad.json"),
                       snapshot=estate_snapshot_path,
                       extra_argv=("--abstain-notes",))
    assert_blocked(outcome, "roles/bigquery.reader")
    assert outcome.stderr.count(HEADER) == 0, (
        f"a blocking run renders its report and nothing else; the abstain "
        f"header must appear neither once nor twice\n{outcome}")


# -- the environment variable -------------------------------------------------


@pytest.mark.parametrize("value,enabled", [
    ("1", True),
    ("true", True),
    ("ON", True),          # case-insensitive
    ("0", False),
    ("off", False),        # NOT truthy — "off" is the word operators reach for
    ("", False),
    ("maybe", False),      # an unrecognized value must not opt anyone in
])
def test_environment_variable_forms(value, enabled, abstain_document,
                                    estate_snapshot_path):
    """``$GCP_GROUNDING_ABSTAIN_NOTES`` enables the channel for 1/true/yes/on,
    case-insensitively, and for nothing else."""
    outcome = run_hook(hook_event(abstain_document("garbled")),
                       snapshot=estate_snapshot_path,
                       env={ABSTAIN_NOTES_ENV: value})
    assert outcome.exit_code == 0, f"never blocks, either way\n{outcome}"
    if enabled:
        assert HEADER in outcome.stderr, (
            f"${ABSTAIN_NOTES_ENV}={value!r} must enable the channel\n{outcome}")
    else:
        assert outcome.stderr == "", (
            f"${ABSTAIN_NOTES_ENV}={value!r} is not truthy — the default "
            f"silence must hold\n{outcome}")


# -- combined with the degraded worlds and with --explain ---------------------


def test_notes_name_the_absent_solver(policies_dir, estate_snapshot_path,
                                      no_z3_env):
    """The operator-visible answer to "why did the gate stop catching things".

    Without z3 the CEL check degrades to ``unverified`` and the hook passes in
    silence — the degradation is invisible at exactly the moment it matters.
    With the channel on, the note names the missing solver.
    """
    event = hook_event(policies_dir / "iam_policy_good.json")
    outcome = run_hook(event, snapshot=estate_snapshot_path,
                       extra_argv=("--abstain-notes",), env=no_z3_env)
    assert outcome.exit_code == 0, (
        f"a missing solver is ignorance, not a finding\n{outcome}")
    assert outcome.stdout == "", f"stdout stays byte-empty\n{outcome}"
    assert HEADER in outcome.stderr, f"expected the header\n{outcome}"
    assert "? [cel] " in outcome.stderr, (
        f"the undecided claim is the CEL condition\n{outcome}")
    assert "z3 is not available" in outcome.stderr, (
        f"the note must name the absent solver\n{outcome}")

    if HAVE_Z3:
        # The honest control: the SAME document, the SAME flag, in a world that
        # has z3 — silent, because there is nothing left undecided. Without
        # this, the assertions above would also pass if the channel simply
        # fired on everything.
        control = run_hook(event, snapshot=estate_snapshot_path,
                           extra_argv=("--abstain-notes",))
        assert_passed(control)


def test_explain_and_notes_do_not_truncate_each_other(abstain_document,
                                                      estate_snapshot_path):
    """Both blocks write to stderr; both must arrive whole.

    ``--explain`` prints before the ``report.ok`` check and the notes print
    inside it, so the explain block comes first — and the assertions pin both
    of its lines, not just its header, so a truncation of either block is
    visible here.
    """
    path = abstain_document("garbled")
    outcome = run_hook(hook_event(path), snapshot=estate_snapshot_path,
                       extra_argv=("--explain", "--abstain-notes"))
    assert outcome.exit_code == 0, f"neither channel blocks\n{outcome}"
    assert outcome.stdout == "", f"both channels are stderr-only\n{outcome}"
    assert "z3 constraints generated this run" in outcome.stderr, (
        f"expected the --explain block\n{outcome}")
    assert "no constraints were generated" in outcome.stderr, (
        f"expected the --explain block's body, not only its header\n{outcome}")
    assert HEADER in outcome.stderr, f"expected the abstain block\n{outcome}"
    assert ABSTAIN_REASONS["garbled"] in outcome.stderr, (
        f"expected the abstain block's body, not only its header\n{outcome}")
    assert outcome.stderr.index("z3 constraints generated this run") < \
        outcome.stderr.index(HEADER), (
        f"--explain prints before the report.ok check, the notes inside it\n"
        f"{outcome}")


def test_uncaptured_category_finally_reaches_a_human(policies_dir,
                                                     snapshot_variant):
    """END TO END: the UNKNOWN sentinel, all the way out to stderr.

    A snapshot that never captured ``principals`` makes every member claim
    undecidable offline. That is honest, it is exit 0, and until now it was
    also completely silent — the one case where the gate knows it is blind and
    nobody finds out.
    """
    snapshot = snapshot_variant(drop=["principals"])
    outcome = run_hook(hook_event(policies_dir / "iam_policy_good.json"),
                       snapshot=snapshot, extra_argv=("--abstain-notes",))
    assert outcome.exit_code == 0, (
        f"an uncaptured category is ignorance, not a finding\n{outcome}")
    assert outcome.stdout == "", f"stdout stays byte-empty\n{outcome}"
    assert HEADER in outcome.stderr, f"expected the header\n{outcome}"
    assert "? [principal] " in outcome.stderr, (
        f"the undecided claims are the members\n{outcome}")
    # iam_policy_good.json names four members; every one of them is undecidable
    # without the category, and every one gets its own line.
    assert outcome.stderr.count("snapshot did not capture principals") == 4, (
        f"every blind claim gets its own note, not one summary line\n{outcome}")


# -- the empty case, in process -----------------------------------------------


def test_no_unverified_verdicts_means_no_lines_at_all():
    """:func:`~gcp_grounding.cli._abstain_note_lines` returns ``[]`` — not a
    header with nothing under it — when there is no ignorance to report."""
    report = GroundingReport()
    report.add(Verdict("grounded", "role", "roles/viewer", 0, "it exists"))
    assert _abstain_note_lines(report, "2026-07-25T08:00:00Z") == []
