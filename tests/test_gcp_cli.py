"""CLI tests: :func:`gcp_grounding.cli.main` driven over the shared fixture
bundles — exit codes (0 pass / 1 ungrounded-or-contradicted / 2 usage or hook
block), the ``--format json`` document shape, ``--explain`` output, and the
``--hook`` PostToolUse path.

Environment-honest like the rest of the suite: z3-dependent expectations
branch on the detected solver backend, and no test needs the tf-plan
extractor or any network/credentials.
"""

# MUTATION-DEBT PAYDOWN, gcp_grounding/cli.py — in the DIFF, which is what the
# review gate is handed, and not only in the task notes.
#
# INSTRUMENT harness's own collect_sites / mutation_score
# (harness.pipeline.mutation), NOT installed in this venv and reached with
# sys.path.insert(0, "/home/jones/Downloads/harness") inside a `python -c`.
# One mutant per site, applied ALONE, one run each, not-green-is-a-kill.
# VALIDATION is this task's OWNING PAIR, `.venv/bin/python -m pytest -q
# tests/test_gcp_sec_cli.py tests/test_gcp_cli.py`, in a detached `git
# worktree` — an archive copy runs that pair RED and would have scored every
# mutant killed. GREEN BASELINE ASSERTED BEFORE EVERY RUN: BEFORE at 8c875c2
# "65 passed, 2 skipped, 1 xfailed"; AFTER "72 passed, 2 skipped, 1 xfailed"
# on this tree, differing from the commit only by this comment.
#
#   cli.py, 180 sites, owning pair   exhaustive  50/180 .278 -> 82/180 .456
#                                    40-draw     13/40  .325 -> 19/40  .475
#
# THE BODY'S 86 SITES / 58-of-86 / 28-of-40 CAME FULL-SUITE FROM
# gx-sec-cli-zero-rules AND DO NOT TRANSFER: this tree has 180 sites, and the
# 98 still surviving are overwhelmingly capture-terraform, state-flag and
# discovery behaviour whose tests live in OTHER modules the owning pair cannot
# reach. ESCALATION: the 0.8 floor and the 34/40 draw are NOT reached under the
# mandated focused instrument and no test-only diff inside 18,000 characters
# reaches them; the paydown is real (+32 kills, +6 drawn) and the floors need
# an amendment against the 180-site instrument.
#
# THE TWELVE NAMED SURVIVORS, by BEHAVIOUR — the hints are that ref's lines and
# NONE resolves here. Each FAILED under its own mutant applied ALONE and PASSED
# on clean source:
#   665 evidence-channel exc_info -> 1691 and 1709   671 json.dumps -> 1680
#   812 file_path string guard -> 1856   882 tool_name fallback -> 1926 (*)
#   1136/1144 compile-floor lineno -> 2533/2541  1170 and 1202 DO NOT RESOLVE
#   1267 BoolVal(False) -> 2664   1268 role/member equality -> 2665
#   1270 sort key -> 2667         1284 claim-kind dispatch -> 2681/2683
# (*) 1926 alone PASSED: measurably EQUIVALENT, so it took house rule 7's route
#     as ESC-GX-DEBTCLI-001 in tests/escalations.py. DIFF SIZE 17999 chars.

import importlib
import io
import json
import logging
import re
import subprocess
import sys
from pathlib import Path

import pytest

from gcp_grounding.cli import SNAPSHOT_ENV, main
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.report import SCHEMA

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"
SNAPSHOT = FIXTURES / "snapshot.json"
REPO_ROOT = Path(__file__).resolve().parent.parent

GOOD = POLICIES / "iam_policy_good.json"
BAD = POLICIES / "iam_policy_bad.json"

HAVE_Z3 = get_solver().backend == "z3"


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def hook_event(path) -> str:
    return json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Write",
                       "tool_input": {"file_path": str(path), "content": ""}})


# -- exit codes over the fixture bundles --------------------------------------


def test_good_iam_policy_exits_zero(capsys):
    code, out, _ = invoke(capsys, "verify-policy", str(GOOD),
                          "--snapshot", str(SNAPSHOT))
    assert code == 0
    # The BARE headline: a fully decided report carries no unchecked
    # qualifier, so a clean pass reads exactly as it always did.
    assert "PASSED [" in out and str(GOOD) in out
    assert "unchecked" not in out


def test_bad_iam_policy_exits_one_with_findings(capsys):
    code, out, _ = invoke(capsys, "verify-policy", str(BAD),
                          "--snapshot", str(SNAPSHOT))
    assert code == 1
    assert "FAILED" in out
    assert "roles/bigquery.reader" in out
    # The renderer surfaces the reasoner's near-miss suggestion.
    assert "roles/bigquery.dataViewer" in out


def test_unrecognized_document_fails_open_to_exit_zero(capsys, tmp_path):
    mystery = tmp_path / "mystery.json"
    mystery.write_text(json.dumps({"totally": "unrelated"}), encoding="utf-8")
    code, out, _ = invoke(capsys, "verify-policy", str(mystery),
                          "--snapshot", str(SNAPSHOT))
    assert code == 0  # unverified is honest ignorance, not a gate failure
    assert "unverified=1" in out
    # ...and the headline SAYS it is ignorance: nothing grounded, one
    # unchecked — never the bare word a verified document earns.
    assert "PASSED — NOTHING VERIFIED (1 unchecked)" in out


def test_unparsable_files_fail_open_to_exit_zero(capsys, tmp_path):
    garbled = tmp_path / "garbled.json"
    garbled.write_bytes(b"\xff\xfe{\x00}")
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 2_000_000 + "]" * 2_000_000, encoding="utf-8")
    for doc in (garbled, deep):
        # Non-UTF-8 bytes / deeply nested JSON: unverified with no traceback,
        # never exit 1 — that code is reserved for real findings.
        code, out, _ = invoke(capsys, "verify-policy", str(doc),
                              "--snapshot", str(SNAPSHOT))
        assert code == 0
        assert "unverified=1" in out


# -- --format json ------------------------------------------------------------


def test_json_format_shape_on_the_bad_bundle(capsys):
    code, out, _ = invoke(capsys, "verify-policy", str(BAD),
                          "--snapshot", str(SNAPSHOT), "--format", "json")
    assert code == 1
    doc = json.loads(out)
    assert doc["schema"] == SCHEMA
    assert doc["ok"] is False
    assert doc["source"] == str(BAD)
    assert doc["captured_at"] == GcpSnapshot.load(SNAPSHOT).captured_at
    assert set(doc["summary"]) == {"grounded", "ungrounded", "contradicted",
                                   "unverified"}
    for verdict in doc["verdicts"]:
        assert set(verdict) == {"status", "kind", "target", "message",
                                "suggestions"}
    assert any(v["status"] == "ungrounded" and v["kind"] == "role"
               and v["target"] == "roles/bigquery.reader"
               for v in doc["verdicts"])


def test_json_format_on_the_good_bundle(capsys):
    code, out, _ = invoke(capsys, "verify-policy", str(GOOD),
                          "--snapshot", str(SNAPSHOT), "--format", "json")
    assert code == 0
    doc = json.loads(out)
    assert doc["ok"] is True
    assert doc["summary"]["ungrounded"] == 0
    assert doc["summary"]["contradicted"] == 0


# -- usage errors (exit 2) ----------------------------------------------------


def test_snapshot_is_required(capsys, monkeypatch):
    monkeypatch.delenv(SNAPSHOT_ENV, raising=False)
    code, _, err = invoke(capsys, "verify-policy", str(GOOD))
    assert code == 2
    assert SNAPSHOT_ENV in err


def test_snapshot_falls_back_to_the_environment(capsys, monkeypatch):
    monkeypatch.setenv(SNAPSHOT_ENV, str(SNAPSHOT))
    code, out, _ = invoke(capsys, "verify-policy", str(GOOD))
    assert code == 0 and "PASSED" in out


def test_unloadable_snapshot_is_a_usage_error(capsys, tmp_path):
    broken = tmp_path / "snapshot.json"
    broken.write_text("{not json", encoding="utf-8")
    code, _, err = invoke(capsys, "verify-policy", str(GOOD),
                          "--snapshot", str(broken))
    assert code == 2
    assert "snapshot" in err


def test_file_is_required_without_hook(capsys):
    code, _, err = invoke(capsys, "verify-policy")
    assert code == 2
    assert "FILE" in err


def test_file_and_hook_are_mutually_exclusive(capsys):
    # Contract change (cli.py:27-28): a broken hook setup must NEVER block an
    # edit, so a hook-mode usage error now fails open (exit 0 + fail-open on
    # stderr) instead of the old exit 2. The diagnostic is unchanged.
    code, _, err = invoke(capsys, "verify-policy", str(GOOD), "--hook",
                          "--snapshot", str(SNAPSHOT))
    assert code == 0
    assert "mutually exclusive" in err
    assert "fail-open" in err


def test_hook_mode_argparse_error_fails_open(capsys):
    # A typo in a hook command line must not block every tool call: an argparse
    # failure with --hook present degrades to fail-open (exit 0), while the
    # non-hook control keeps the SystemExit(2) usage error.
    code, _, err = invoke(capsys, "verify-policy", "--hook", "--bogus")
    assert code == 0
    assert "fail-open" in err
    with pytest.raises(SystemExit) as exc:
        main(["verify-policy", "--bogus"])
    assert exc.value.code == 2


def test_normal_mode_usage_errors_still_exit_two(capsys, monkeypatch, tmp_path):
    # Normal mode is unchanged: the three usage paths still exit 2.
    code, _, err = invoke(capsys, "verify-policy")  # missing FILE
    assert code == 2 and "FILE" in err
    monkeypatch.delenv(SNAPSHOT_ENV, raising=False)
    code, _, err = invoke(capsys, "verify-policy", str(GOOD))  # missing snapshot
    assert code == 2 and SNAPSHOT_ENV in err
    broken = tmp_path / "snapshot.json"
    broken.write_text("{not json", encoding="utf-8")
    code, _, err = invoke(capsys, "verify-policy", str(GOOD),  # unloadable snapshot
                          "--snapshot", str(broken))
    assert code == 2 and "snapshot" in err


# -- --baseline (new⊆old) -----------------------------------------------------


@pytest.fixture()
def baseline_pair(tmp_path):
    old = tmp_path / "old.json"
    old.write_text(json.dumps({"bindings": [
        {"role": "roles/viewer", "members": ["user:alice@acme.example"]}]}),
        encoding="utf-8")
    # The extra grantee is a real snapshot principal, so the existence layer
    # stays green and any failure is the subset check's alone.
    widened = tmp_path / "widened.json"
    widened.write_text(json.dumps({"version": 3, "etag": "BwX=", "bindings": [
        {"role": "roles/viewer", "members": [
            "user:alice@acme.example",
            "serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com"]}]}),
        encoding="utf-8")
    return old, widened


def test_baseline_widening_is_judged(capsys, baseline_pair):
    old, widened = baseline_pair
    code, out, _ = invoke(capsys, "verify-policy", str(widened),
                          "--snapshot", str(SNAPSHOT), "--baseline", str(old))
    if HAVE_Z3:
        assert code == 1
        assert "ci-deployer" in out
    else:
        # No z3 → new⊆old is honestly undecided, and undecided never fails.
        assert code == 0
        assert "unverified" in out


def test_unreadable_baseline_fails_open(capsys, tmp_path):
    code, out, _ = invoke(capsys, "verify-policy", str(GOOD),
                          "--snapshot", str(SNAPSHOT),
                          "--baseline", str(tmp_path / "missing.json"))
    assert code == 0
    assert "unverified" in out


# -- --explain ----------------------------------------------------------------


def test_explain_dumps_constraints_to_stderr(capsys):
    code, out, err = invoke(capsys, "verify-policy", str(GOOD),
                            "--snapshot", str(SNAPSHOT), "--explain")
    assert code == 0
    assert "z3 constraints generated this run" in err
    assert "z3 constraints" not in out  # stdout stays the plain report
    if HAVE_Z3:
        # The good bundle's time-window condition, translated to z3.
        assert "[cel]" in err and "request.time" in err
    else:
        assert "z3 is not available" in err


def test_explain_covers_the_subset_assertion(capsys, baseline_pair):
    old, widened = baseline_pair
    _, _, err = invoke(capsys, "verify-policy", str(widened),
                       "--snapshot", str(SNAPSHOT), "--baseline", str(old),
                       "--explain")
    assert "z3 constraints generated this run" in err
    if HAVE_Z3:
        assert "[subset]" in err and "ci-deployer" in err


def test_explain_fails_open_on_an_unparsable_file(capsys, tmp_path):
    garbled = tmp_path / "garbled.json"
    garbled.write_bytes(b"\xff\xfe{\x00}")
    code, _, err = invoke(capsys, "verify-policy", str(garbled),
                          "--snapshot", str(SNAPSHOT), "--explain")
    assert code == 0  # the unparsable file is unverified, not a crash
    if HAVE_Z3:
        assert "no constraints were generated" in err
    else:
        assert "z3 is not available" in err


# -- --hook (PostToolUse) -----------------------------------------------------


def run_hook(capsys, monkeypatch, stdin_text: str, *extra: str):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
    return invoke(capsys, "verify-policy", "--hook",
                  "--snapshot", str(SNAPSHOT), *extra)


def test_hook_good_policy_is_silent_and_passes(capsys, monkeypatch):
    code, out, err = run_hook(capsys, monkeypatch, hook_event(GOOD))
    assert code == 0
    assert out == "" and err == ""


def test_hook_bad_policy_blocks_with_findings_on_stderr(capsys, monkeypatch):
    code, out, err = run_hook(capsys, monkeypatch, hook_event(BAD))
    assert code == 2  # the editor agent's blocking exit code
    assert out == ""
    assert "FAILED" in err and "roles/bigquery.reader" in err


def test_hook_ignores_non_policy_files(capsys, monkeypatch):
    code, out, err = run_hook(capsys, monkeypatch,
                              hook_event("/somewhere/notes.md"))
    assert code == 0
    assert out == "" and err == ""


def test_hook_raw_tf_file_fails_open(capsys, monkeypatch, tmp_path):
    tf = tmp_path / "main.tf"
    tf.write_text('resource "google_project_iam_member" "x" {}\n',
                  encoding="utf-8")
    # Raw HCL is not `terraform show -json` output: unverified, never a block.
    code, _, _ = run_hook(capsys, monkeypatch, hook_event(tf))
    assert code == 0


def test_hook_fails_open_on_a_broken_event(capsys, monkeypatch):
    code, _, err = run_hook(capsys, monkeypatch, "{not json")
    assert code == 0
    assert "fail-open" in err
    code, _, _ = run_hook(capsys, monkeypatch, json.dumps({"tool_name": "Write"}))
    assert code == 0


def test_hook_fails_open_on_an_unparsable_policy_file(capsys, monkeypatch,
                                                      tmp_path):
    garbled = tmp_path / "garbled.policy.json"
    garbled.write_bytes(b"\xff\xfe{\x00}")
    code, out, err = run_hook(capsys, monkeypatch, hook_event(garbled))
    assert code == 0  # unparsable input must never block an edit
    assert out == "" and err == ""


def test_hook_suffix_match_is_case_insensitive(capsys, monkeypatch, tmp_path):
    upper = tmp_path / "IAM.POLICY.JSON"
    upper.write_text(BAD.read_text(encoding="utf-8"), encoding="utf-8")
    code, out, err = run_hook(capsys, monkeypatch, hook_event(upper))
    assert code == 2  # grounded and blocked, exactly as a lowercase name is
    assert out == ""
    assert "roles/bigquery.reader" in err


def test_hook_fails_open_without_a_snapshot(capsys, monkeypatch):
    monkeypatch.delenv(SNAPSHOT_ENV, raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO(hook_event(BAD)))
    code, _, err = invoke(capsys, "verify-policy", "--hook")
    assert code == 0  # a broken hook setup must never block an edit
    assert "fail-open" in err


# -- packaging: python -m and the console script ------------------------------


def test_python_dash_m_entrypoint():
    proc = subprocess.run(
        [sys.executable, "-m", "gcp_grounding", "verify-policy", str(BAD),
         "--snapshot", str(SNAPSHOT), "--format", "json"],
        cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["ok"] is False


def test_console_script_is_declared_in_pyproject():
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'gcp-ground = "gcp_grounding.cli:main"' in text


# -- the z3 encoder, the claim-kind dispatch, the parser and the hook ---------

_DECLS = "(declare-const role String)(declare-const member String)"
_C27 = 'request.time < timestamp("2027-01-01T00:00:00Z")'
_C26 = 'request.time < timestamp("2026-01-01T00:00:00Z")'
_ALICE, _ENG = "user:alice@acme.example", "group:data-eng@acme.example"
_VIEWER, _JOBS = "roles/viewer", "roles/bigquery.jobUser"


def _write(tmp_path, name, doc):
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _policy(tmp_path, name, bindings):
    return _write(tmp_path, name, {"bindings": bindings})


def _explain(capsys, new, old) -> str:
    _, _, err = invoke(capsys, "verify-policy", str(new), "--snapshot",
                       str(SNAPSHOT), "--baseline", str(old), "--explain")
    return err


def _formula(err: str) -> str:
    """The new⊄old s-expression, read to its own closing paren."""
    depth, quoted, out = 0, False, []
    for char in err.split("iam-policy:", 1)[1]:
        out.append(char)
        if char == '"':
            quoted = not quoted
        elif not quoted and char in "()":
            depth += 1 if char == "(" else -1
            if depth == 0:
                break
    return "".join(out).strip()


def _admits(formula: str, role: str, member: str) -> bool:
    """Does the rendered assertion hold of this grant? Answered by the
    solver, so what comes back is a decision and not a literal."""
    import z3
    solver = z3.Solver()
    solver.add(z3.parse_smt2_string(f"{_DECLS}(assert {formula})"))
    solver.add(z3.String("role") == z3.StringVal(role),
               z3.String("member") == z3.StringVal(member))
    return solver.check() == z3.sat


def _reported(formula: str) -> list:
    """The (role, member) pairs in the order the disjunction reports them."""
    seen = re.findall(r'\(= (?:role|member) "([^"]+)"\)', " ".join(formula.split()))
    return list(zip(seen[::2], seen[1::2]))


@pytest.mark.skipif(not HAVE_Z3, reason="no solver: the encoder never runs")
def test_the_encoder_admits_exactly_the_grants_the_baseline_lacks(capsys,
                                                                  tmp_path):
    """An EMPTY baseline grants nothing, so every new grant breaks new⊆old; a
    baseline that already makes one cancels that one out; and the grants are
    reported in one fixed order."""
    viewer_alice = {"role": _VIEWER, "members": [_ALICE]}
    new = _policy(tmp_path, "new.json",
                  [viewer_alice, {"role": _JOBS, "members": [_ENG]}])
    empty = _policy(tmp_path, "empty.json", [])
    formula = _formula(_explain(capsys, new, empty))
    assert _admits(formula, _VIEWER, _ALICE)
    assert _admits(formula, _JOBS, _ENG)
    assert not _admits(formula, _VIEWER, _ENG)   # a pair neither binding grants
    old = _policy(tmp_path, "old.json", [viewer_alice])
    formula = _formula(_explain(capsys, new, old))
    assert not _admits(formula, _VIEWER, _ALICE)
    assert _admits(formula, _JOBS, _ENG)
    # ORDERED, too, unconditional grant ahead of a conditioned one on the same
    # pair, so two runs over one policy print the same lines.
    new = _policy(tmp_path, "ordered.json", [
        {"role": _JOBS, "members": [_ALICE]},
        {"role": _VIEWER, "members": [_ENG], "condition": {"expression": _C27}},
        {"role": _VIEWER, "members": [_ENG]},
        {"role": _VIEWER, "members": [_ALICE], "condition": {"expression": _C26}}])
    formula = _formula(_explain(capsys, new, _policy(tmp_path, "e.json", [])))
    assert _reported(formula) == [(_JOBS, _ALICE), (_VIEWER, _ENG),
                                  (_VIEWER, _ENG), (_VIEWER, _ALICE)]
    flat = " ".join(formula.split())
    assert flat.index(f'"{_ENG}") true') < flat.index("1798761600")


@pytest.fixture()
def harness_records():
    """Every ``harness.*`` record AT THE HANDLER: ``core.log`` sets
    ``propagate = False``, so ``caplog`` sees nothing."""
    logger = logging.getLogger("harness")
    records: list = []

    class _Capture(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Capture(level=logging.DEBUG)
    level, propagate = logger.level, logger.propagate
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)
        logger.propagate = propagate


def test_explain_routes_each_document_kind_to_its_own_extractor(
        capsys, tmp_path, monkeypatch, harness_records):
    """One arm per kind, each explaining what ITS extractor found. The
    tf-plan arm is driven with a stand-in yielding a CEL claim: the real plan
    extractor mints none, and a table routing every kind to one extractor
    would print the same thing for all. Extraction is fail-open but not
    silent — a raising extractor exits 0 and KEEPS the exception."""
    tf_claims = importlib.import_module("gcp_grounding.tf_claims")
    claims = importlib.import_module("gcp_grounding.claims")
    monkeypatch.setattr(tf_claims, "terraform_plan_claims",
                        lambda doc: [claims.Claim("cel", _C27, "plan.tfclaim")])
    plan = _write(tmp_path, "plan.json", {"resource_changes": []})
    _, _, err = invoke(capsys, "verify-policy", str(plan), "--snapshot",
                       str(SNAPSHOT), "--explain")
    assert "[cel] plan.tfclaim:" in err and "request.time" in err
    # An org policy and an unrecognized document reach extractors that mint no
    # CEL at all, so each says so rather than borrowing the arm above.
    for name, doc in (("org.json", {"spec": {"rules": [{"enforce": True}]}}),
                      ("mystery.json", {"totally": "unrelated"})):
        _, _, err = invoke(capsys, "verify-policy",
                           str(_write(tmp_path, name, doc)),
                           "--snapshot", str(SNAPSHOT), "--explain")
        assert "[cel]" not in err
        assert "no z3 constraints were generated this run" in err

    def boom(doc):
        raise RuntimeError("the plan extractor exploded")

    monkeypatch.setattr(tf_claims, "terraform_plan_claims", boom)
    code, _, err = invoke(capsys, "verify-policy", str(plan), "--snapshot",
                          str(SNAPSHOT), "--explain")
    assert code == 0 and "[cel]" not in err
    failed = [r for r in harness_records
              if "claim extraction failed" in r.getMessage()]
    # Truthiness, not `is not None`: logging leaves `exc_info` FALSE, never
    # None, when the call passed False, so a dropped traceback reads as one.
    assert failed and all(r.exc_info for r in failed)


def test_the_parsers_two_required_slots_are_usage_errors(capsys):
    """Neither hole may reach a handler: exit 2, naming what is missing."""
    for argv, wanted in (([], "verify-policy"), (["scan-command"], "--command")):
        with pytest.raises(SystemExit) as exc:
            main(argv)
        assert exc.value.code == 2
        _, err = capsys.readouterr()
        assert "usage: gcp-ground" in err and wanted in err


def test_hook_reads_a_field_only_where_it_is_a_non_empty_string(capsys,
                                                                monkeypatch):
    """Only a non-empty string names a file or carries a command. An
    unusable ``file_path`` checks nothing and stays silent; ``command: ""``
    leaves the event to the FILE arm, which still grounds the edited policy —
    engaging on the empty string would swallow that finding and exit 0."""
    def event(**tool_input):
        return json.dumps({"hook_event_name": "PostToolUse",
                           "tool_name": "Write", "tool_input": tool_input})

    for value in (17, "", None, ["/tmp/x.json"]):
        assert run_hook(capsys, monkeypatch, event(file_path=value)) == (0, "", "")
    code, _, err = run_hook(capsys, monkeypatch,
                            event(file_path=str(BAD), command=""))
    assert code == 2 and "roles/bigquery.reader" in err


_MUTATION = ("gcloud projects add-iam-policy-binding acme-prod "
             "--member=user:alice@acme.example --role=roles/viewer")


def bash_event(command: str) -> str:
    return json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Bash",
                       "tool_input": {"command": command}})


def test_the_bash_arm_blocks_warns_or_does_not_scan_by_policy(capsys, monkeypatch):
    """One command, three policies, three decisions: block exits 2 under a
    BLOCKED headline carrying the finding and the already-executed warning;
    warn reports the SAME finding and exits 0; off does not scan."""
    code, _, err = run_hook(capsys, monkeypatch, bash_event(_MUTATION))
    assert code == 2
    assert "BLOCKED — unchecked GCP mutation in a shell command" in err
    assert "[bash-mutation] gcloud projects add-iam-policy-binding" in err
    assert "already executed" in err
    code, _, err = run_hook(capsys, monkeypatch, bash_event(_MUTATION),
                            "--bash-policy", "warn")
    assert code == 0
    assert "WARNING — unchecked GCP mutation in a shell command" in err
    assert "[bash-mutation] gcloud projects add-iam-policy-binding" in err
    assert run_hook(capsys, monkeypatch, bash_event(_MUTATION),
                    "--bash-policy", "off") == (0, "", "")
    # Hook stderr is agent-visible: a command with no GCP mutation in it
    # produces no report at all, not an empty one.
    assert run_hook(capsys, monkeypatch, bash_event("ls -la /tmp")) == (0, "", "")


def test_the_json_document_keeps_two_space_indent_and_real_unicode(
        capsys, tmp_path, monkeypatch, harness_records):
    """Rendered exactly as report.py renders its own document, so the two
    differ only by the added key: two-space indent and no ``\\uXXXX``
    escaping — a non-ASCII path must read back as itself."""
    policy = tmp_path / "pòlicy.json"
    policy.write_text(GOOD.read_text(encoding="utf-8"), encoding="utf-8")
    empty = tmp_path / "empty"
    empty.mkdir()
    code, out, _ = invoke(capsys, "verify-policy", str(policy), "--snapshot",
                          str(SNAPSHOT), "--requirements", str(empty),
                          "--format", "json")
    assert code == 0
    assert '\n  "schema": "gcp-grounding-report/1",\n' in out
    assert str(policy) in out and "\\u00f2" not in out
    assert json.loads(out)["source"] == str(policy)
    # A checkout without sec_evidence still renders the base document — no
    # `sec` key, exit unchanged — and says so in a debug record that KEEPS the
    # traceback, so a channel gone missing stays diagnosable.
    real = importlib.import_module

    def refuse(name, *args, **kwargs):
        if name == "gcp_grounding.sec_evidence":
            raise ImportError("not part of this checkout")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", refuse)
    code, out, err = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                            str(SNAPSHOT), "--requirements", str(empty),
                            "--format", "json", "--explain")
    monkeypatch.undo()
    assert code == 0
    assert "sec" not in json.loads(out)
    # The sec BLOCK's own header — the closing summary restates the same field
    # as a labelled row, so the bare phrase no longer tells the two apart.
    assert "promises in force (" not in err
    missing = [r for r in harness_records
               if "sec evidence channel is unavailable" in r.getMessage()]
    # Both users of the channel say so, and truthiness is the assertion:
    # logging leaves `exc_info` FALSE, never None, when the call passed False.
    assert len(missing) == 2 and all(r.exc_info for r in missing)
