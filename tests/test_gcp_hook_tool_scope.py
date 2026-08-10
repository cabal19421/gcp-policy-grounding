"""The hook's SCOPE, asserted through the real process boundary.

Two contract changes live here, and both are about *what the gate refuses to
have an opinion on*.

**A read is not a change.** Before this, a ``PostToolUse`` (or ``PreToolUse``)
``Read`` of a known-bad policy exited 2 — the gate blocked on a file the agent
had merely inspected and never wrote. That is the classic reason operators
switch a guardrail off, it feeds a finding back to the agent as if it had just
made that error, and it makes "audit these policies" self-defeating. The fix is
a DENY-list (``cli._READ_ONLY_TOOLS``), not an allow-list of mutators, and the
anti-bypass tests below are the load-bearing half of that claim: an unknown
tool, an absent ``tool_name``, a non-string ``tool_name`` and an ``mcp__*``
writer all stay INSIDE the gate and still block.

**A PreToolUse file edit cannot be judged honestly.** ``ground_policy`` reads
the file from disk; on ``PreToolUse`` the disk still holds the pre-edit
content, so a verdict would be about the wrong document — wrong, not merely
useless. The gate abstains out loud instead, naming the path and the fix
(register on ``PostToolUse``).

Everything runs through :func:`tests.agentic.hookrunner.run_hook`, so these are
real children with real exit codes, not in-process calls to ``main``.
"""

from __future__ import annotations

import json

import pytest

from gcp_grounding.cli import _READ_ONLY_TOOLS
from tests.agentic.asserts import assert_blocked, assert_passed
from tests.agentic.fake_agent import FakeAgent, Proposal
from tests.agentic.hookrunner import (
    bound_subprocess_budget,  # noqa: F401 — autouse: bind spawns to the budget
    run_hook,
)

#: Sentinel for "this key is absent from the event entirely", which is a
#: different case from a key present with a ``None`` value.
_ABSENT = object()

#: The ungrounded role in ``iam_policy_bad.json`` — the evidence that the gate
#: really did look at the file, rather than exiting 2 for some other reason.
BAD_ROLE = "roles/bigquery.reader"


@pytest.fixture
def bad_policy(policies_dir):
    """A KNOWN-BAD policy: grounding it blocks. Every "exits 0" assertion in
    this module is only meaningful because this same file exits 2 when a
    mutating tool names it."""
    return policies_dir / "iam_policy_bad.json"


def hook_event(path, tool_name="Write", hook_event_name="PostToolUse") -> dict:
    """An editor-agent event naming *path* as the file *tool_name* touched.

    Either key can be dropped entirely by passing :data:`_ABSENT`, and
    *tool_name* can be any JSON value — the malformed-envelope cases below need
    both.
    """
    event = {
        "session_id": "hook-tool-scope",
        "tool_input": {"file_path": str(path)},
    }
    if tool_name is not _ABSENT:
        event["tool_name"] = tool_name
    if hook_event_name is not _ABSENT:
        event["hook_event_name"] = hook_event_name
    return event


# -- the deny-list: reading a bad policy is silent ----------------------------


def test_the_deny_list_is_exactly_the_curated_read_only_set():
    """Pinned, because the safety argument is about the list's *shape*: it
    names read-only tools only, so nothing that can write is on it."""
    assert _READ_ONLY_TOOLS == frozenset({
        "Read", "NotebookRead", "Glob", "Grep", "LS", "WebFetch", "WebSearch",
        "Task", "TodoWrite", "BashOutput", "KillShell", "ExitPlanMode",
        "SlashCommand", "AskUserQuestion",
    })


@pytest.mark.parametrize("tool_name", sorted(_READ_ONLY_TOOLS))
def test_a_read_only_tool_on_a_bad_policy_is_byte_silent(
        tool_name, bad_policy, estate_snapshot_path):
    """Exit 0 with BOTH streams byte-empty. Not "exit 0 with a note": the
    hook's stderr is agent-visible, so even an explanatory line here would put
    a finding the agent did not cause into its context."""
    outcome = run_hook(hook_event(bad_policy, tool_name=tool_name),
                       snapshot=estate_snapshot_path)
    assert_passed(outcome)


def test_the_same_file_reads_silently_and_writes_a_block(
        bad_policy, estate_snapshot_path):
    """The before/after contrast, in one test: ONE file, two tool names."""
    read = run_hook(hook_event(bad_policy, tool_name="Read"),
                    snapshot=estate_snapshot_path)
    write = run_hook(hook_event(bad_policy, tool_name="Write"),
                     snapshot=estate_snapshot_path)
    assert_passed(read)
    assert_blocked(write, BAD_ROLE)
    # Same event but for the tool name — nothing else explains the difference.
    assert read.stdin_bytes != write.stdin_bytes
    assert read.exit_code == 0 and write.exit_code == 2


# -- the anti-bypass half: everything unknown stays INSIDE the gate -----------


def test_an_mcp_writer_with_a_file_path_still_blocks(
        bad_policy, estate_snapshot_path):
    """THE ANTI-BYPASS ASSERTION. ``mcp__gcp__write_policy`` is unknown to this
    release and is an MCP tool, which is exactly the pair the deny-list shape
    was chosen for: because the list names read-only tools rather than
    mutating ones, a tool nobody has heard of is judged, not waved through.
    Scoping can only remove false positives; it cannot open a hole."""
    outcome = run_hook(
        hook_event(bad_policy, tool_name="mcp__gcp__write_policy"),
        snapshot=estate_snapshot_path)
    assert_blocked(outcome, BAD_ROLE)


def test_an_absent_tool_name_still_blocks(bad_policy, estate_snapshot_path):
    """The minimal-envelope contract: the hook has never required
    ``tool_name``, and scoping must not start requiring it — an event that
    names a file is grounded on the strength of the file alone."""
    event = hook_event(bad_policy, tool_name=_ABSENT)
    assert "tool_name" not in event
    assert_blocked(run_hook(event, snapshot=estate_snapshot_path), BAD_ROLE)


@pytest.mark.parametrize(
    "tool_name", [42, None, ["Read"]],
    ids=["number", "json-null", "list"])
def test_a_non_string_tool_name_is_treated_as_absent_and_blocks(
        tool_name, bad_policy, estate_snapshot_path):
    """``["Read"]`` is the adversarial one: a membership test written as
    ``event.get("tool_name") in _READ_ONLY_TOOLS`` without the ``isinstance``
    guard would still be False here, but a hand-rolled ``any(...)`` over the
    value would not. Non-string means "no tool name", which means judged."""
    assert_blocked(
        run_hook(hook_event(bad_policy, tool_name=tool_name),
                 snapshot=estate_snapshot_path),
        BAD_ROLE)


@pytest.mark.parametrize("tool_name", ["Write", "Edit", "MultiEdit",
                                       "NotebookEdit"])
def test_the_mutating_tools_all_block(tool_name, bad_policy,
                                      estate_snapshot_path):
    """Every file-mutating tool name, carrying a ``file_path``, still blocks.

    A real ``NotebookEdit`` carries ``notebook_path`` and no ``file_path`` at
    all (``tests.agentic.fake_agent`` documents that blindness); this case is
    about the *scope* check, so it hands the name a ``file_path`` and asserts
    the deny-list does not swallow it.
    """
    assert_blocked(
        run_hook(hook_event(bad_policy, tool_name=tool_name),
                 snapshot=estate_snapshot_path),
        BAD_ROLE)


# -- PreToolUse: the honest abstain -------------------------------------------


def test_pretooluse_on_a_file_declines_out_loud_and_does_not_block(
        bad_policy, estate_snapshot_path):
    """The whole point: it does NOT block. The file on disk is a policy the
    gate can and does reject on ``PostToolUse``, and the only reason this run
    exits 0 is that judging pre-edit disk content would be a verdict about the
    wrong document."""
    outcome = run_hook(
        hook_event(bad_policy, tool_name="Write",
                   hook_event_name="PreToolUse"),
        snapshot=estate_snapshot_path)
    assert outcome.exit_code == 0, str(outcome)
    assert outcome.exit_code != 2, str(outcome)  # it did NOT block
    assert outcome.stdout == "", str(outcome)
    assert "FAILED" not in outcome.stderr, str(outcome)
    assert BAD_ROLE not in outcome.stderr, str(outcome)
    # The abstain is out loud, names the path, and says how to fix it.
    for expected in ("PreToolUse", "pre-edit content", "PostToolUse",
                     str(bad_policy)):
        assert expected in outcome.stderr, (
            f"expected {expected!r} in stderr\n{outcome}")


def test_pretooluse_with_a_read_is_silent_because_the_deny_list_wins(
        bad_policy, estate_snapshot_path):
    """Order matters: the deny-list is checked FIRST, so a ``PreToolUse``
    ``Read`` skips silently rather than emitting the register-on-PostToolUse
    note. A read was never going to land an edit, so the note would be a
    confusing non-sequitur."""
    outcome = run_hook(
        hook_event(bad_policy, tool_name="Read",
                   hook_event_name="PreToolUse"),
        snapshot=estate_snapshot_path)
    assert_passed(outcome)
    assert "PostToolUse" not in outcome.stderr, str(outcome)


@pytest.mark.parametrize(
    "hook_event_name", [_ABSENT, "PostToolUse", "Stop"],
    ids=["absent", "post-tool-use", "stop"])
def test_only_the_literal_pretooluse_declines(
        hook_event_name, bad_policy, estate_snapshot_path):
    """Only ``PreToolUse`` has a stale-disk problem, so only ``PreToolUse``
    abstains. Every other event name — including none at all — is grounded."""
    assert_blocked(
        run_hook(hook_event(bad_policy, tool_name="Write",
                            hook_event_name=hook_event_name),
                 snapshot=estate_snapshot_path),
        BAD_ROLE)


# -- the agentic statement of the fix -----------------------------------------


def test_an_agent_may_read_the_bad_policy_then_is_blocked_when_it_writes_it(
        agent_workdir, bad_policy, estate_snapshot_path):
    """Two turns of one scripted session over ONE file: audit it (silent
    pass), then propose it (block).

    Turn 1 is the case that used to be broken — an agent asked to review
    policies could not read one without the guardrail blocking it. Turn 2 is
    the coverage that had to survive the fix.
    """
    document = json.loads(bad_policy.read_text(encoding="utf-8"))
    rel_path = "policies/iam.policy.json"
    seeded = agent_workdir / rel_path
    seeded.parent.mkdir(parents=True, exist_ok=True)
    # Seeded before the session so turn 1's Read has real bad content to find:
    # a Read proposal writes nothing, and an absent file would pass vacuously.
    seeded.write_text(bad_policy.read_text(encoding="utf-8"), encoding="utf-8")

    agent = FakeAgent(agent_workdir, [
        Proposal(
            id="S1_read_the_policy", kind="iam", tool_name="Read",
            rel_path=rel_path, payload=None, expect="pass",
            rationale="Asked to audit the estate, the agent reads the policy "
                      "it was pointed at — and must not be blocked for it."),
        Proposal(
            id="S2_write_the_policy", kind="iam", tool_name="Write",
            rel_path=rel_path, payload=document, expect="block",
            rationale="Having read it, the agent proposes the same bindings "
                      "back — now it really is a change, and it is wrong."),
    ])
    (read_proposal, read_event), (write_proposal, write_event) = \
        agent.script_turns()

    assert read_event["tool_name"] == "Read"
    assert seeded.read_text(encoding="utf-8"), "the Read turn must not empty the file"
    assert_passed(run_hook(read_event, snapshot=estate_snapshot_path))

    assert write_event["tool_name"] == "Write"
    assert write_event["tool_input"]["file_path"] == str(seeded)
    assert_blocked(run_hook(write_event, snapshot=estate_snapshot_path),
                   BAD_ROLE)
    assert (read_proposal.expect, write_proposal.expect) == ("pass", "block")
