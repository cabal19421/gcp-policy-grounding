"""The hook's ENVELOPE CONTRACT: which event fields it reads, and which it does not.

``gcp-ground verify-policy --hook`` is handed a whole Claude-Code hook event and
looks at almost none of it. That blindness is deliberate and it is load-bearing
— an event key the gate does not read is a key a future Claude Code release can
rename, drop or repurpose without silently turning the guardrail off — but until
this module existed it was nowhere written down. It survived only as the absence
of code, which is the one property a reader cannot check and a refactor cannot
notice breaking.

So this file pins it. Every "ignored" test mutates exactly ONE field on an
otherwise-blocking envelope and asserts the outcome is byte-identical to the
baseline in exit code, stdout and stderr. The day someone teaches the hook to
consult ``cwd``, or to believe ``tool_response.success``, or to prefer the
in-event ``content`` over the bytes on disk, that change shows up as a
deliberate diff in THIS file rather than as a surprise regression in an
unrelated module three tasks later.

SCOPE BOUNDARY, honoured strictly. This module pins the fields that are
DECORATIVE after every hook task in the design has landed, and nothing else:

* ``tool_name`` and ``hook_event_name`` are read, and they belong to
  ``tests/test_gcp_hook_tool_scope.py`` — the deny-list and the ``PreToolUse``
  abstain are that module's contract, asserted there.
* ``tool_input.command`` is read, and it belongs to
  ``tests/test_gcp_hook_bash.py`` — the bash-mutation arm is that module's
  contract.

Nothing here asserts anything about those three, so a future tightening of
either surface never needs to edit this file, and this file never needs to edit
theirs. Where an envelope below wants to be judged, it simply omits
``tool_name`` and ``hook_event_name`` entirely: an absent tool name is not on
the read-only deny-list and an absent event name is not ``PreToolUse``, so the
event reaches the grounding pass on the strength of its ``file_path`` alone,
whatever those two modules decide about the names they own.

Everything runs through :func:`tests.agentic.hookrunner.run_hook` and its raw
variant, so these are real child processes with real exit codes — the only
boundary that can observe stdin decoding, argv assembly and a crash that never
reaches ``sys.exit``.

COST: 55 spawns, ~2.5s. The blocking baseline is spawned ONCE for the module
(``baseline_outcome``), so the fifteen ignored-field mutations cost fifteen
children rather than thirty; the rest is the enumeration itself — six
``file_path`` shapes, four ``tool_input`` shapes, five stream cases, ten
exit-code cases and nine stdin payloads.
"""

# ── THE CONTRACT ─────────────────────────────────────────────────────────────
#
# The COMPLETE set of hook-event keys ``gcp-ground verify-policy --hook`` reads
# today. Five paths, all of them in ``gcp_grounding.cli``; nothing else in the
# envelope is consulted anywhere in the package:
#
#   tool_input             cli._hook_file_path, cli._hook_command — must be a
#                          JSON object, or there is nothing to read
#                                                            [PINNED HERE: E03]
#   tool_input.file_path   cli._hook_file_path — the document that gets
#                          grounded; must be a non-empty str
#                                                       [PINNED HERE: E01, E02]
#   tool_input.command     cli._hook_command — the shell command that gets
#                          classified   [owned by tests/test_gcp_hook_bash.py]
#   tool_name              cli._hook_scope_skip (read-only deny-list),
#                          cli._hook_bash (the finding's source label)
#                       [owned by tests/test_gcp_hook_tool_scope.py]
#   hook_event_name        cli._hook_scope_skip (the PreToolUse abstain),
#                          cli._bash_timing_line (has the command run yet?)
#                       [owned by tests/test_gcp_hook_tool_scope.py]
#
# EVERY OTHER KEY IS DECORATIVE — session_id, transcript_path, cwd,
# permission_mode, tool_response, tool_input.content, tool_input.new_string,
# tool_input.notebook_path, and any key a future Claude Code release adds. That
# list is what the "ignored" half of this module defends.

from __future__ import annotations

import json

import pytest

from gcp_grounding.report import SCHEMA
from tests.agentic.asserts import assert_blocked, assert_passed
from tests.agentic.env import REPO_ROOT
from tests.agentic.hookrunner import (
    DEFAULT_TIMEOUT,
    bind_budget,
    bound_subprocess_budget,  # noqa: F401 — autouse: bind spawns to the budget
    run_hook,
    run_hook_explain,
    run_hook_raw,
)

#: Sentinel for "this key is absent from the envelope entirely", which is a
#: different case from a key present with a JSON ``null`` value — a hook that
#: reached for ``event["cwd"]`` would fail on the first and not the second.
_ABSENT = object()

#: The ungrounded role in ``iam_policy_bad.json``. Its presence in stderr is the
#: evidence that the gate really did open and read the file, rather than exiting
#: 2 down some other path.
BAD_ROLE = "roles/bigquery.reader"

#: Clean, well-formed IAM policy text. Used only as an in-event ``content`` /
#: ``new_string`` value: the point is that the gate never looks at it.
CLEAN_POLICY_TEXT = json.dumps(
    {"version": 3, "etag": "BwYn8x2Qb0c=", "bindings": []}, indent=2)


# -- the envelope under test ---------------------------------------------------


def envelope(bad_policy, **overrides) -> dict:
    """A realistic, BLOCKING PostToolUse envelope, with *overrides* applied.

    Every decorative field a real Claude-Code event carries is present and
    plausible, so a mutation test changes exactly one thing about an otherwise
    ordinary event. Passing :data:`_ABSENT` for a key removes it entirely.

    ``tool_name`` and ``hook_event_name`` are deliberately absent — see the
    scope boundary in the module docstring.
    """
    event = {
        "session_id": "envelope-contract-0001",
        "transcript_path": "/tmp/gcp-ground-envelope/transcript.jsonl",
        "cwd": str(REPO_ROOT),
        "permission_mode": "default",
        "tool_input": {"file_path": str(bad_policy)},
        "tool_response": {"success": True, "filePath": str(bad_policy)},
    }
    for key, value in overrides.items():
        if value is _ABSENT:
            event.pop(key, None)
        else:
            event[key] = value
    return event


def tool_input_envelope(bad_policy, **fields) -> dict:
    """:func:`envelope` with *fields* merged into its ``tool_input`` object
    (a value of :data:`_ABSENT` removes the inner key)."""
    event = envelope(bad_policy)
    for key, value in fields.items():
        if value is _ABSENT:
            event["tool_input"].pop(key, None)
        else:
            event["tool_input"][key] = value
    return event


def assert_identical_to_baseline(outcome, baseline) -> None:
    """*outcome* is byte-for-byte the baseline outcome on all three channels.

    Not "also blocked": byte-identical. A field that changed the wording of one
    stderr line, or added a note, would be a field the hook reads.
    """
    assert outcome.exit_code == baseline.exit_code, (
        f"the mutated field changed the exit code "
        f"({baseline.exit_code} → {outcome.exit_code}) — the hook reads it\n"
        f"{outcome}")
    assert outcome.stdout == baseline.stdout, (
        f"the mutated field changed stdout — the hook reads it\n{outcome}")
    assert outcome.stderr == baseline.stderr, (
        f"the mutated field changed stderr — the hook reads it\n{outcome}")


@pytest.fixture(scope="module")
def bad_policy(policies_dir):
    """A KNOWN-BAD policy: grounding it exits 2. Every "byte-identical" and
    "exits 0" assertion below is only meaningful because this same file, named
    by a plain envelope, really does block."""
    return policies_dir / "iam_policy_bad.json"


@pytest.fixture(scope="module")
def baseline_outcome(bad_policy, estate_snapshot_path, subprocess_budget):
    """THE BASELINE, spawned once for the whole module.

    Asserted blocking here rather than in each caller: if the baseline ever
    stops blocking, the entire ignored-field matrix would go green by comparing
    one silent run against another, which is the one way this module could rot
    into a tautology.

    The budget is bound by hand because this fixture is module-scoped and so is
    set up *before* the function-scoped autouse ``bound_subprocess_budget``.
    """
    previous = bind_budget(subprocess_budget)
    try:
        outcome = run_hook(envelope(bad_policy), snapshot=estate_snapshot_path)
    finally:
        bind_budget(previous)
    assert_blocked(outcome, BAD_ROLE)
    return outcome


# ══ WHAT THE HOOK READS ══════════════════════════════════════════════════════
#
# Exactly one path: tool_input.file_path, and it must be a non-empty string
# inside a tool_input that is a JSON object.


def test_e01_a_minimal_event_is_a_tool_input_with_a_file_path(
        bad_policy, estate_snapshot_path):
    """E01. The whole envelope the hook needs is ``{"tool_input":
    {"file_path": ...}}`` — no ``session_id``, no ``transcript_path``, no
    ``cwd``, no ``tool_response``, nothing else — and it still blocks.

    The two identifying fields present in every real Claude-Code envelope are
    therefore NOT required. That matters twice over: a hand-rolled or
    third-party hook runner that omits them is still gated, and the gate cannot
    grow a dependency on session bookkeeping without this test going red.
    """
    event = {"tool_input": {"file_path": str(bad_policy)}}
    assert set(event) == {"tool_input"}, "E01's envelope must carry nothing else"
    assert set(event["tool_input"]) == {"file_path"}
    assert_blocked(run_hook(event, snapshot=estate_snapshot_path), BAD_ROLE)


@pytest.mark.parametrize(
    "file_path",
    [_ABSENT, None, "", 7, ["<bad>"], {"path": "<bad>"}],
    ids=["absent", "json-null", "empty-string", "int", "list", "nested-object"])
def test_e02_file_path_must_be_a_nonempty_str(
        file_path, bad_policy, estate_snapshot_path):
    """E02. Anything that is not a non-empty ``str`` means "no file", and no
    file means exit 0 with stderr BYTE-EMPTY — ``cli._run_hook`` logs the case
    at debug only, and the harness logger's default console level is WARNING.

    The ``list`` and ``nested-object`` cases carry the real bad path inside
    them, so an implementation that coerced with ``str()`` or dug one level
    deeper would block here and fail this test. Silence rather than a note is
    the deliberate half: hook stderr is agent-visible, and an envelope this
    malformed is a misconfigured runner, not something the agent did.
    """
    if isinstance(file_path, (list, dict)):
        file_path = json.loads(
            json.dumps(file_path).replace("<bad>", str(bad_policy)))
    event = tool_input_envelope(bad_policy, file_path=file_path)
    outcome = run_hook(event, snapshot=estate_snapshot_path)
    assert_passed(outcome)
    assert BAD_ROLE not in outcome.stderr, str(outcome)


@pytest.mark.parametrize(
    "tool_input",
    [_ABSENT, None, ["<bad>"], "<bad>"],
    ids=["absent", "json-null", "list", "string"])
def test_e03_tool_input_must_be_a_mapping(
        tool_input, bad_policy, estate_snapshot_path):
    """E03. ``tool_input`` that is not a JSON object is not read at all: exit 0,
    stderr byte-empty, same debug-only logging as E02.

    Both non-mapping shapes hold the bad path, so this is the adversarial form
    — ``"…/iam_policy_bad.json"`` as a bare string is exactly what a naive
    ``str(event.get("tool_input"))`` would happily ground.
    """
    if tool_input is not _ABSENT and tool_input is not None:
        tool_input = json.loads(
            json.dumps(tool_input).replace("<bad>", str(bad_policy)))
    outcome = run_hook(envelope(bad_policy, tool_input=tool_input),
                       snapshot=estate_snapshot_path)
    assert_passed(outcome)
    assert BAD_ROLE not in outcome.stderr, str(outcome)


# ══ WHAT THE HOOK IGNORES ════════════════════════════════════════════════════
#
# One test per decorative field. Each mutates ONLY that field on the blocking
# baseline envelope and demands a byte-identical outcome.


@pytest.mark.parametrize(
    "session_id", [_ABSENT, None, 4242],
    ids=["absent", "json-null", "int"])
def test_session_id_is_ignored(session_id, bad_policy, estate_snapshot_path,
                               baseline_outcome):
    """``session_id`` is bookkeeping for the runner, not evidence about the
    document. The gate must not key anything — a cache, a rate limit, a
    "seen this before" — off it."""
    outcome = run_hook(envelope(bad_policy, session_id=session_id),
                       snapshot=estate_snapshot_path)
    assert_identical_to_baseline(outcome, baseline_outcome)


@pytest.mark.parametrize(
    "transcript_path",
    [_ABSENT, "/nonexistent-directory/does-not-exist/transcript.jsonl"],
    ids=["absent", "nonexistent-path"])
def test_transcript_path_is_ignored(transcript_path, bad_policy,
                                    estate_snapshot_path, baseline_outcome):
    """A path that does not exist changes nothing, which is the assertion:
    the gate never opens the transcript. Reading it would make a verdict depend
    on conversation history — unreproducible, and a privacy surface no policy
    check needs."""
    outcome = run_hook(envelope(bad_policy, transcript_path=transcript_path),
                       snapshot=estate_snapshot_path)
    assert_identical_to_baseline(outcome, baseline_outcome)


@pytest.mark.parametrize(
    "cwd", [_ABSENT, "/nonexistent-directory/does-not-exist"],
    ids=["absent", "nonexistent-directory"])
def test_cwd_is_ignored(cwd, bad_policy, estate_snapshot_path,
                        baseline_outcome):
    """``file_path`` is absolute in every real event, so the gate never needs a
    base directory — and resolving one against an agent-supplied ``cwd`` would
    make the file it grounds depend on a field the agent controls."""
    outcome = run_hook(envelope(bad_policy, cwd=cwd),
                       snapshot=estate_snapshot_path)
    assert_identical_to_baseline(outcome, baseline_outcome)


@pytest.mark.parametrize(
    "permission_mode", [_ABSENT, "bypassPermissions", "plan"],
    ids=["absent", "bypass-permissions", "plan"])
def test_permission_mode_is_ignored(permission_mode, bad_policy,
                                    estate_snapshot_path, baseline_outcome):
    """``bypassPermissions`` is the one that matters. It relaxes Claude Code's
    OWN permission prompts, and a guardrail that read it would let the operator
    turn the gate off from inside the session it is meant to constrain. It is
    not a grounding input, so it is not read."""
    outcome = run_hook(envelope(bad_policy, permission_mode=permission_mode),
                       snapshot=estate_snapshot_path)
    assert_identical_to_baseline(outcome, baseline_outcome)


@pytest.mark.parametrize(
    "tool_response",
    [_ABSENT, None,
     {"success": False, "error": "EACCES: permission denied"},
     {"error": "the edit could not be applied"}],
    ids=["absent", "json-null", "success-false", "error-object"])
def test_tool_response_is_ignored(tool_response, bad_policy,
                                  estate_snapshot_path, baseline_outcome):
    """THE ONE THAT DESERVES ITS OWN COMMENT.

    A ``tool_response`` saying the write FAILED is ignored, so the hook can
    block on a file whose write did not actually land. That is a known
    false-positive source, and it is still the right default: ``ground_policy``
    reads the file FROM DISK, so what the gate reports on is whatever is on disk
    right now — believing a self-reported ``success: False`` and skipping the
    check would trust the very tool call the gate is auditing, and would open a
    bypass (claim the write failed, keep the file). A spurious block is
    recoverable in one turn; a bypass is not.
    """
    outcome = run_hook(envelope(bad_policy, tool_response=tool_response),
                       snapshot=estate_snapshot_path)
    assert_identical_to_baseline(outcome, baseline_outcome)


def test_an_unknown_top_level_key_is_ignored(bad_policy, estate_snapshot_path,
                                             baseline_outcome):
    """FORWARD COMPATIBILITY. A key this release has never heard of — the shape
    every future Claude Code addition arrives in — changes nothing."""
    outcome = run_hook(
        envelope(bad_policy, some_future_field={"nested": ["value", 1, None]}),
        snapshot=estate_snapshot_path)
    assert_identical_to_baseline(outcome, baseline_outcome)


@pytest.mark.parametrize("field", ["content", "new_string"],
                         ids=["write-content", "edit-new_string"])
def test_the_in_event_text_is_ignored_the_gate_reads_the_disk(
        field, bad_policy, estate_snapshot_path, baseline_outcome):
    """``tool_input.content`` (Write) and ``tool_input.new_string`` (Edit) carry
    the text the agent claims it wrote. The gate does not read either — it opens
    ``file_path`` and grounds what is actually there.

    Here that blindness is a FALSE POSITIVE: the event advertises a clean
    policy, the file on disk is the bad one, and the run still blocks. This is
    the exact counterfactual to A31 in the evasion family, where the same
    blindness is the SAFETY property — an agent that writes a bad policy and
    reports clean text in the event is caught, because the event's own account
    of itself is never evidence.
    """
    outcome = run_hook(
        tool_input_envelope(bad_policy, **{field: CLEAN_POLICY_TEXT}),
        snapshot=estate_snapshot_path)
    assert_identical_to_baseline(outcome, baseline_outcome)
    assert BAD_ROLE in outcome.stderr, (
        f"the disk content is what got grounded\n{outcome}")


def test_notebook_path_without_a_file_path_exits_zero(
        bad_policy, estate_snapshot_path):
    """``tool_input.notebook_path`` is what a real ``NotebookEdit`` carries
    INSTEAD of ``file_path``, and the hook does not read it: exit 0, both
    streams byte-empty, even though the path names a policy that blocks when
    ``file_path`` names it.

    Pinned as a known blind spot rather than as a desirable property — a policy
    document living inside a notebook cell is not a shape this gate can ground
    today, and the honest record of that is a test, not silence.
    """
    event = tool_input_envelope(bad_policy, file_path=_ABSENT,
                                notebook_path=str(bad_policy))
    assert "file_path" not in event["tool_input"]
    assert_passed(run_hook(event, snapshot=estate_snapshot_path))


# ══ STREAM AND FORMAT INVARIANTS ═════════════════════════════════════════════


@pytest.mark.parametrize(
    "case", ["pass", "block", "abstain", "fail-open", "explain"])
def test_e04_stdout_is_always_empty_in_hook_mode(
        case, bad_policy, policies_dir, estate_snapshot_path, tmp_path):
    """E04. Hook mode NEVER writes to stdout — across a clean pass, a block, an
    abstain, a fail-open and an ``--explain`` run.

    stdout is the channel a future structured-output contract would claim: a
    ``hookSpecificOutput`` object with ``additionalContext``, which Claude Code
    ingests as data instead of prose. Keeping it byte-empty today is what keeps
    that option open, so this is an invariant and not an accident.
    """
    if case == "pass":
        outcome = run_hook(envelope(policies_dir / "iam_policy_good.json"),
                           snapshot=estate_snapshot_path)
    elif case == "block":
        outcome = run_hook(envelope(bad_policy), snapshot=estate_snapshot_path)
    elif case == "abstain":
        # A raw .tf is not `terraform show -json`, so the gate abstains; the
        # opt-in channel puts that ignorance on stderr, exit code unchanged.
        raw_tf = tmp_path / "main.tf"
        raw_tf.write_text('resource "google_project_iam_binding" "b" {}\n',
                          encoding="utf-8")
        outcome = run_hook(envelope(raw_tf), snapshot=estate_snapshot_path,
                           extra_argv=("--abstain-notes",))
    elif case == "fail-open":
        # No --snapshot at all, and the env var is scrubbed from the child.
        outcome = run_hook(envelope(bad_policy), snapshot=None)
    else:
        outcome = run_hook_explain(envelope(policies_dir / "iam_policy_good.json"),
                                   snapshot=estate_snapshot_path)
    assert outcome.stdout == "", (
        f"hook mode wrote to stdout in the {case!r} case; stdout is reserved "
        f"for a future structured-output contract\n{outcome}")
    if case != "pass":
        assert outcome.stderr != "", (
            f"the {case!r} case is only a meaningful stdout assertion because "
            f"the run had something to say — on stderr\n{outcome}")


def test_e05_format_json_is_ignored_by_the_hook(bad_policy,
                                                estate_snapshot_path):
    """E05. ``--format json`` is accepted and has NO effect in hook mode:
    ``cli._run_hook`` hardcodes ``PolicyReport(...).render("human")``, so stderr
    is the human report and stdout stays empty.

    Pinned as a KNOWN LIMITATION, not as a desirable design. An operator who
    configures the hook with ``--format json`` expecting a machine-readable
    finding gets prose, silently. The honest place for that surprise is a test
    that says so; if the hook ever learns to honour the flag, this is the test
    that will demand the change be deliberate.
    """
    outcome = run_hook(envelope(bad_policy), snapshot=estate_snapshot_path,
                       extra_argv=("--format", "json"))
    assert_blocked(outcome, BAD_ROLE)
    assert "GCP policy grounding" in outcome.stderr, (
        f"expected the human render's report title\n{outcome}")
    assert SCHEMA not in outcome.stderr, (
        f"stderr carries the machine document's schema marker {SCHEMA!r}, so "
        f"--format json is no longer ignored — update this contract\n{outcome}")


def test_e06_the_hook_emits_no_structured_output(baseline_outcome):
    """E06. THE TRIPWIRE. Everything the hook communicates today rides on the
    exit code plus free text on stderr: stderr does not parse as JSON, and it
    carries none of the structured-output key names.

    This assertion is meant to be *deleted* one day, together with the change
    that adds structured output. Until then it is what stops the two contracts
    from being half-implemented at once — a JSON blob on stderr that nothing
    reads, or a ``decision`` key that Claude Code ignores because it is on the
    wrong stream.
    """
    stderr = baseline_outcome.stderr
    assert stderr.strip(), "the baseline must have printed its finding"
    with pytest.raises(ValueError):
        json.loads(stderr)
    for marker in ("hookSpecificOutput", "additionalContext", '"decision"'):
        assert marker not in stderr, (
            f"{marker!r} appeared on stderr — structured output has arrived, "
            f"and this contract needs rewriting rather than patching\n"
            f"{baseline_outcome}")


def test_e07_hook_exit_codes_are_only_0_or_2(
        bad_policy, policies_dir, estate_snapshot_path, tmp_path):
    """E07. Across ten heterogeneous events the exit codes are a subset of
    ``{0, 2}``.

    ``1`` is the whole point. In NORMAL mode 1 means "ungrounded or
    contradicted", but Claude Code reads any nonzero-but-not-2 exit as *the hook
    itself failed* and surfaces it as a hook error rather than as feedback to
    the agent — so a hook that returned 1 would report real findings through a
    channel that discards them. Hook mode must never produce it, and every arm
    that could (a usage error, a missing snapshot, an unreadable document, a bad
    flag) is represented below.
    """
    raw_tf = tmp_path / "main.tf"
    raw_tf.write_text('resource "google_compute_firewall" "f" {}\n',
                      encoding="utf-8")
    broken = tmp_path / "broken.json"
    broken.write_text("{ this is not json", encoding="utf-8")

    outcomes = {
        "pass": run_hook(envelope(policies_dir / "iam_policy_good.json"),
                         snapshot=estate_snapshot_path),
        "block": run_hook(envelope(bad_policy), snapshot=estate_snapshot_path),
        "abstain": run_hook(envelope(raw_tf), snapshot=estate_snapshot_path,
                            extra_argv=("--abstain-notes",)),
        "garbage-stdin": run_hook_raw(b"\x00\x01 not an event at all",
                                      snapshot=estate_snapshot_path),
        "no-snapshot": run_hook(envelope(bad_policy), snapshot=None),
        "unreadable-snapshot": run_hook(envelope(bad_policy),
                                        snapshot=tmp_path / "no-such-snapshot.json"),
        "non-policy-suffix": run_hook(
            envelope(bad_policy, tool_input={"file_path": str(tmp_path / "x.yaml")}),
            snapshot=estate_snapshot_path),
        "no-tool-input": run_hook(envelope(bad_policy, tool_input=_ABSENT),
                                  snapshot=estate_snapshot_path),
        "unparsable-document": run_hook(envelope(broken),
                                        snapshot=estate_snapshot_path),
        "bad-flag": run_hook(envelope(bad_policy), snapshot=estate_snapshot_path,
                             extra_argv=("--no-such-flag",)),
    }
    codes = {label: outcome.exit_code for label, outcome in outcomes.items()}
    assert set(codes.values()) <= {0, 2}, (
        f"hook mode returned an exit code outside {{0, 2}}: {codes}\n"
        + "\n\n".join(str(o) for o in outcomes.values()))
    # Not vacuous: the set really does contain both halves of the contract.
    assert codes["block"] == 2, str(outcomes["block"])
    assert codes["pass"] == 0, str(outcomes["pass"])
    assert 1 not in set(codes.values())


# ══ STDIN ROBUSTNESS ═════════════════════════════════════════════════════════
#
# Everything below goes through run_hook_raw, which writes the caller's exact
# bytes: these payloads are not events and several are not even JSON.


def _huge_event() -> bytes:
    """A ~5 MB event whose bulk is a key the hook does not read."""
    return json.dumps({"tool_input": {},
                       "some_future_field": "x" * (5 * 1024 * 1024)}).encode("utf-8")


def _long_path_event() -> bytes:
    """An event whose ``file_path`` is 100k characters and ends in ``.json``, so
    it passes the suffix filter and is actually handed to ``open()``."""
    return json.dumps(
        {"tool_input": {"file_path": "/" + "a" * 100_000 + ".json"}}).encode("utf-8")


@pytest.mark.parametrize("payload", [
    b"",
    b"{not json",
    b"\xff\xfe\x00\x80 not utf-8",
    b"null",
    b"[]",
    b'"a bare json string"',
    b"42",
    _huge_event(),
    _long_path_event(),
], ids=["empty-at-eof", "malformed-json", "non-utf8", "json-null",
        "empty-array", "bare-string", "bare-number", "5mb-event",
        "100k-char-file-path"])
def test_stdin_that_is_not_an_event_fails_open_without_crashing(
        payload, estate_snapshot_path):
    """Every one exits 0, leaves no ``Traceback`` on stderr, and finishes inside
    the driver timeout.

    A hook that dies on bad stdin blocks every edit in the session, which is the
    worst possible failure for a guardrail — worse than checking nothing,
    because the operator's fix is to remove the hook. ``run_hook_raw`` lets a
    :class:`subprocess.TimeoutExpired` propagate, so the third assertion is the
    call returning at all: the 5 MB payload and the 100k-character path are here
    to catch a quadratic path or an unbounded read, not just a crash.
    """
    outcome = run_hook_raw(payload, snapshot=estate_snapshot_path,
                           timeout=DEFAULT_TIMEOUT)
    assert outcome.exit_code == 0, (
        f"unusable stdin must fail open, not block\n{outcome}")
    assert outcome.stdout == "", str(outcome)
    assert "Traceback" not in outcome.stderr, (
        f"the gate crashed instead of degrading\n{outcome}")
