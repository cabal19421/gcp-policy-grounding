"""Unit tests for the scripted fake agent — no CLI, no subprocess, no network.

The process-boundary tests (a real ``gcp-ground verify-policy --hook`` child fed
these envelopes) belong to the adversarial-family modules. Here the questions
are purely local: does a turn mutate the file *before* it describes it, is the
envelope the full realistic Claude-Code payload, and is the whole thing
byte-reproducible across two agents built from the same script?
"""

import json
from dataclasses import dataclass

import pytest

from gcp_grounding.preflight import ground_policy
from gcp_grounding.report import PolicyReport
from tests.agentic import env
from tests.agentic.fake_agent import (
    BAD_NAME_RE,
    EXPECTATIONS,
    SUGGESTION_RE,
    TOOL_NAMES,
    FakeAgent,
    Proposal,
    default_session_id,
    feedback,
    render_payload,
)

_ENVELOPE_KEYS = {
    "session_id",
    "transcript_path",
    "cwd",
    "permission_mode",
    "hook_event_name",
    "tool_name",
    "tool_input",
    "tool_response",
}

_POLICY = {
    "bindings": [
        {"role": "roles/bigquery.reader", "members": ["user:alice@acme.example"]}
    ],
    "etag": "BwYn8x2Qb0d=",
    "version": 3,
}


def _write(**overrides) -> Proposal:
    """A Write proposal with every required field filled in; *overrides* names
    the one field a test actually cares about."""
    kwargs = dict(
        id="W1_write_iam",
        kind="iam",
        tool_name="Write",
        rel_path="policies/iam.policy.json",
        payload=_POLICY,
        expect="block",
        rationale="An agent granting the data team read access writes the binding it believes exists.",
    )
    kwargs.update(overrides)
    return Proposal(**kwargs)


# -- the Proposal contract ----------------------------------------------------


def test_proposal_rejects_a_bad_expect_value():
    with pytest.raises(ValueError) as excinfo:
        _write(expect="approved")
    assert "expect" in str(excinfo.value)
    assert str(EXPECTATIONS) in str(excinfo.value)


def test_proposal_rejects_an_unknown_tool_name():
    with pytest.raises(ValueError) as excinfo:
        _write(tool_name="ApplyPatch")
    assert "tool_name" in str(excinfo.value)


def test_tool_names_are_the_eight_the_gate_must_survive():
    assert TOOL_NAMES == (
        "Write",
        "Edit",
        "MultiEdit",
        "NotebookEdit",
        "Bash",
        "Read",
        "mcp__gcp__set_iam_policy",
        "mcp__terraform__apply",
    )


def test_render_payload_covers_the_four_payload_forms():
    assert render_payload(_POLICY) == json.dumps(_POLICY, indent=2, sort_keys=True)
    assert render_payload("resource \"x\" {}\n") == "resource \"x\" {}\n"
    assert render_payload(b"\x00raw") == b"\x00raw"
    assert render_payload(None) is None
    with pytest.raises(TypeError):
        render_payload(object())


# -- apply: the file mutation, and nothing else -------------------------------


def test_apply_creates_parent_dirs_and_writes_the_rendered_payload(agent_workdir):
    agent = FakeAgent(agent_workdir, [])
    path = agent.apply(_write())
    assert path == agent_workdir / "policies" / "iam.policy.json"
    assert path.read_text(encoding="utf-8") == json.dumps(_POLICY, indent=2, sort_keys=True)


def test_apply_returns_none_when_the_proposal_touches_no_file(agent_workdir):
    agent = FakeAgent(agent_workdir, [])
    pathless = _write(
        id="B1_bash", tool_name="Bash", rel_path="", payload=None,
        command="gcloud projects add-iam-policy-binding acme-prod --role=roles/owner",
    )
    assert agent.apply(pathless) is None
    assert sorted(p.name for p in agent_workdir.iterdir()) == ["transcript.jsonl"]


def test_apply_writes_nothing_for_a_none_payload(agent_workdir):
    agent = FakeAgent(agent_workdir, [])
    path = agent.apply(_write(id="R1_read", tool_name="Read", payload=None, expect="pass"))
    assert path is not None
    assert not path.exists()


def test_delete_unlinks_the_file(agent_workdir):
    agent = FakeAgent(agent_workdir, [])
    written = agent.apply(_write())
    assert written.exists()
    reverted = agent.apply(_write(id="W1_revert", delete=True, payload=None, expect="pass"))
    assert reverted == written
    assert not written.exists()
    # missing_ok: deleting it a second time is not an error.
    assert agent.apply(_write(id="W1_revert2", delete=True, payload=None, expect="pass"))


# -- the apply-then-envelope ordering contract --------------------------------


class _DiskReadingAgent(FakeAgent):
    """Records what is on disk at the moment ``envelope`` is called — the only
    way to observe the ordering from outside ``turn()``."""

    disk_at_envelope: str | None = None

    def envelope(self, p, *, old_string=""):
        target = self.workdir / p.rel_path
        self.disk_at_envelope = target.read_text(encoding="utf-8") if target.exists() else None
        return super().envelope(p, old_string=old_string)


def test_apply_runs_before_envelope(agent_workdir):
    agent = _DiskReadingAgent(agent_workdir, [_write()])
    _, event = agent.turn()
    expected = json.dumps(_POLICY, indent=2, sort_keys=True)
    # PostToolUse: the write has already landed, so the file the hook will
    # ground already equals the content the event describes.
    assert agent.disk_at_envelope == expected
    assert event["tool_input"]["content"] == expected


def test_edit_old_string_is_the_pre_write_content(agent_workdir):
    before = {"bindings": [], "etag": "old", "version": 3}
    script = [
        _write(id="E0_seed", payload=before, expect="pass"),
        _write(id="E1_edit", tool_name="Edit"),
    ]
    agent = FakeAgent(agent_workdir, script)
    turns = agent.script_turns()
    tool_input = turns[1][1]["tool_input"]
    assert tool_input["old_string"] == json.dumps(before, indent=2, sort_keys=True)
    assert tool_input["new_string"] == json.dumps(_POLICY, indent=2, sort_keys=True)
    assert tool_input["replace_all"] is False


def test_edit_old_string_is_empty_for_a_file_that_did_not_exist(agent_workdir):
    agent = FakeAgent(agent_workdir, [_write(id="E1_edit", tool_name="Edit")])
    _, event = agent.turn()
    assert event["tool_input"]["old_string"] == ""


# -- the envelope shape -------------------------------------------------------


def test_envelope_carries_all_eight_top_level_keys(agent_workdir):
    agent = FakeAgent(agent_workdir, [_write()])
    _, event = agent.turn()
    assert set(event) == _ENVELOPE_KEYS
    assert event["session_id"] == agent.session_id
    assert event["transcript_path"] == str(agent_workdir / "transcript.jsonl")
    assert event["cwd"] == str(agent_workdir)
    assert event["permission_mode"] == "default"
    assert event["hook_event_name"] == "PostToolUse"
    assert event["tool_name"] == "Write"


def test_write_tool_input_and_response(agent_workdir):
    agent = FakeAgent(agent_workdir, [_write()])
    _, event = agent.turn()
    expected_path = str(agent_workdir / "policies" / "iam.policy.json")
    assert set(event["tool_input"]) == {"file_path", "content"}
    assert event["tool_input"]["file_path"] == expected_path
    assert event["tool_response"] == {
        "filePath": expected_path,
        "success": True,
        "userModified": False,
    }


def test_multiedit_keeps_one_file_path_across_several_edits(agent_workdir):
    seed = {"a": "one", "b": "two", "c": "three"}
    changed = {"a": "ONE", "b": "two", "c": "THREE"}
    script = [
        _write(id="M0_seed", payload=seed, expect="pass"),
        _write(id="M1_multi", tool_name="MultiEdit", payload=changed),
    ]
    agent = FakeAgent(agent_workdir, script)
    tool_input = agent.script_turns()[1][1]["tool_input"]
    assert set(tool_input) == {"file_path", "edits"}
    assert isinstance(tool_input["file_path"], str)
    # Two separated changed regions => two edits, still exactly one file_path.
    assert len(tool_input["edits"]) == 2
    for edit in tool_input["edits"]:
        assert set(edit) == {"old_string", "new_string", "replace_all"}
        assert edit["replace_all"] is False
    assert "file_path" not in tool_input["edits"][0]
    assert tool_input["edits"][0]["new_string"].strip() == '"a": "ONE",'


def test_multiedit_of_an_unchanged_file_still_emits_one_whole_file_edit(agent_workdir):
    script = [
        _write(id="M0_seed", expect="pass"),
        _write(id="M1_noop", tool_name="MultiEdit"),
    ]
    agent = FakeAgent(agent_workdir, script)
    edits = agent.script_turns()[1][1]["tool_input"]["edits"]
    assert len(edits) == 1
    assert edits[0]["old_string"] == edits[0]["new_string"]


def test_notebook_edit_has_notebook_path_and_no_file_path(agent_workdir):
    proposal = _write(
        id="N1_notebook", tool_name="NotebookEdit", rel_path="explore.ipynb",
        payload="open('iam.policy.json','w').write(POLICY)\n",
    )
    agent = FakeAgent(agent_workdir, [proposal])
    _, event = agent.turn()
    tool_input = event["tool_input"]
    assert set(tool_input) == {"notebook_path", "new_source", "cell_type", "edit_mode"}
    # The hook reads tool_input.file_path — which a NotebookEdit never has.
    assert "file_path" not in tool_input
    assert tool_input["notebook_path"] == str(agent_workdir / "explore.ipynb")
    assert tool_input["cell_type"] == "code"
    assert tool_input["edit_mode"] == "replace"
    assert tool_input["new_source"] == proposal.payload


def test_notebook_path_override_wins(agent_workdir):
    agent = FakeAgent(agent_workdir, [])
    proposal = _write(
        id="N2_notebook", tool_name="NotebookEdit", rel_path="explore.ipynb",
        payload=None, notebook_path="nested/other.ipynb",
    )
    assert agent.notebook_path(proposal) == str(agent_workdir / "nested" / "other.ipynb")


def test_bash_tool_input_has_command_and_no_file_path(agent_workdir):
    command = "gcloud projects add-iam-policy-binding acme-prod --member=allUsers --role=roles/owner"
    proposal = _write(
        id="B1_bash", tool_name="Bash", rel_path="", payload=None, command=command,
    )
    agent = FakeAgent(agent_workdir, [proposal])
    _, event = agent.turn()
    tool_input = event["tool_input"]
    assert set(tool_input) == {"command", "description", "timeout"}
    assert "file_path" not in tool_input
    assert tool_input["command"] == command
    assert tool_input["description"] == proposal.rationale
    assert isinstance(tool_input["timeout"], int)
    assert event["tool_response"] == {
        "stdout": "", "stderr": "", "interrupted": False, "isImage": False,
    }


def test_read_tool_input_and_response(agent_workdir):
    proposal = _write(
        id="R1_read", tool_name="Read", payload="line one\nline two\n", expect="pass",
    )
    agent = FakeAgent(agent_workdir, [proposal])
    _, event = agent.turn()
    file_path = str(agent_workdir / "policies" / "iam.policy.json")
    assert event["tool_input"] == {"file_path": file_path}
    assert event["tool_response"] == {
        "type": "text",
        "file": {"filePath": file_path, "numLines": 2},
    }


@pytest.mark.parametrize("tool", ["mcp__gcp__set_iam_policy", "mcp__terraform__apply"])
def test_mcp_tool_input_is_the_proposal_mcp_input(agent_workdir, tool):
    mcp_input = {"resource": "projects/acme-prod", "policy": _POLICY}
    proposal = _write(id=f"X1_{tool}", tool_name=tool, rel_path="", payload=None,
                      mcp_input=mcp_input)
    agent = FakeAgent(agent_workdir, [proposal])
    _, event = agent.turn()
    assert event["tool_input"] == mcp_input
    assert event["tool_input"] is not mcp_input  # a copy, not the proposal's mapping
    assert event["tool_response"] == {"success": True}
    # No file_path at all: this is the estate mutation the hook cannot see.
    assert "file_path" not in event["tool_input"]


def test_mcp_tool_input_defaults_to_empty(agent_workdir):
    agent = FakeAgent(agent_workdir, [])
    proposal = _write(id="X2", tool_name="mcp__terraform__apply", rel_path="", payload=None)
    assert agent.envelope(proposal)["tool_input"] == {}


def test_hook_event_name_is_overridable(agent_workdir):
    agent = FakeAgent(agent_workdir, [])
    proposal = _write(hook_event_name="PreToolUse")
    assert agent.envelope(proposal)["hook_event_name"] == "PreToolUse"


# -- determinism --------------------------------------------------------------


def _determinism_script():
    return [
        _write(id="D1_write", expect="pass"),
        _write(id="D2_edit", tool_name="Edit", payload={"bindings": [], "version": 3}),
        _write(id="D3_bash", tool_name="Bash", rel_path="", payload=None,
               command="terraform apply -auto-approve", expect="abstain"),
    ]


def test_two_agents_from_one_script_emit_byte_identical_envelopes(agent_workdir):
    # Same workdir on purpose: cwd and transcript_path are *in* the envelope, so
    # byte-identity is only a meaningful claim about the agent, not the tmpdir.
    first = [event for _, event in FakeAgent(agent_workdir, _determinism_script()).script_turns()]
    second = [event for _, event in FakeAgent(agent_workdir, _determinism_script()).script_turns()]
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_session_id_is_a_hash_of_the_script_not_a_uuid(tmp_path):
    script = _determinism_script()
    here = FakeAgent(tmp_path / "one", script)
    there = FakeAgent(tmp_path / "two", script)
    assert here.session_id == there.session_id == default_session_id(script)
    assert here.session_id.startswith("sess-")
    assert len(here.session_id) == len("sess-") + 12
    # A different script is a different session.
    assert FakeAgent(tmp_path / "three", script[:2]).session_id != here.session_id


def test_explicit_session_id_wins(agent_workdir):
    agent = FakeAgent(agent_workdir, [], session_id="sess-fixed")
    assert agent.session_id == "sess-fixed"


# -- turn bookkeeping ---------------------------------------------------------


def test_turns_taken_and_remaining_track_the_script(agent_workdir):
    agent = FakeAgent(agent_workdir, _determinism_script())
    assert (agent.turns_taken, agent.remaining()) == (0, 3)
    proposal, event = agent.turn()
    assert proposal.id == "D1_write"
    assert event["tool_name"] == "Write"
    assert (agent.turns_taken, agent.remaining()) == (1, 2)
    rest = agent.script_turns()
    assert [p.id for p, _ in rest] == ["D2_edit", "D3_bash"]
    assert (agent.turns_taken, agent.remaining()) == (3, 0)
    with pytest.raises(IndexError):
        agent.turn()


def test_constructor_creates_the_workdir_and_an_empty_transcript(tmp_path):
    agent = FakeAgent(tmp_path / "fresh" / "agent", [])
    assert agent.workdir.is_dir()
    assert agent.transcript_path.read_text(encoding="utf-8") == ""


# -- the feedback loop --------------------------------------------------------


@dataclass(frozen=True)
class _Outcome:
    """Stand-in for ``tests.agentic.hookrunner``'s run result (a later task).
    ``feedback`` and ``retry_with_suggestion`` duck-type on ``stderr`` alone."""

    stderr: str
    exit_code: int = 2
    stdout: str = ""


#: The human renderer's exact output shape (report.py:153 appends the
#: parenthesised list; reasoner.py:159-162 mints the message it hangs off).
_BLOCKED_STDERR = (
    "GCP policy grounding /w/policies/iam.policy.json FAILED [z3]  "
    "grounded=1 ungrounded=1 contradicted=0 unverified=0\n"
    "  ✗ [role] bindings[0].role: role 'roles/bigquery.reader' does not exist "
    "in the snapshot (captured 2026-07-25T08:00:00Z)  (did you mean: "
    "roles/bigquery.dataViewer, roles/bigquery.dataEditor?)\n"
    "  ✓ [principal] bindings[0].members[0]: principal 'user:alice@acme.example' "
    "exists in the snapshot [snapshot 2026-07-25T08:00:00Z]"
)

_PASSED_STDERR = (
    "GCP policy grounding /w/policies/iam.policy.json FAILED [builtin]  "
    "grounded=0 ungrounded=0 contradicted=1 unverified=0\n"
    "  ⚠ [cel] bindings[0].condition.expression: condition is never true "
    "— dead binding"
)


def test_regexes_match_the_real_renderer_output(estate_snapshot):
    # Grounded against the real pipeline rather than a hand-written string: if
    # reasoner.py's message or report.py's suggestion rendering ever changes,
    # this fails instead of the loop silently going quiet.
    policy = env.POLICIES / "iam_policy_bad.json"
    report = ground_policy(str(policy), estate_snapshot)
    rendered = PolicyReport(
        report, captured_at=estate_snapshot.captured_at, source=str(policy)
    ).render("human")
    bad = BAD_NAME_RE.search(rendered)
    assert bad is not None, rendered
    assert bad.group("kind") == "role"
    assert bad.group("name") == "roles/bigquery.reader"
    tip = SUGGESTION_RE.search(rendered, bad.end())
    assert tip is not None, rendered
    assert tip.group("suggestions").split(",")[0].strip().startswith("roles/bigquery.")


def test_feedback_is_the_stderr_an_orchestrator_pastes_back():
    assert feedback(_Outcome(stderr=_BLOCKED_STDERR)) == _BLOCKED_STDERR.strip()
    assert feedback(_Outcome(stderr="")) == ""


def test_retry_with_suggestion_rewrites_the_bad_name(agent_workdir):
    original = _write()
    agent = FakeAgent(agent_workdir, [original])
    retry = agent.retry_with_suggestion(original, _Outcome(stderr=_BLOCKED_STDERR))
    assert retry.id == "W1_write_iam-retry"
    assert retry.expect == "pass"
    assert retry.payload["bindings"][0]["role"] == "roles/bigquery.dataViewer"
    # Everything else is carried over, and the original is untouched.
    assert retry.tool_name == original.tool_name
    assert retry.rel_path == original.rel_path
    assert original.payload["bindings"][0]["role"] == "roles/bigquery.reader"
    assert retry.payload is not original.payload


def test_retry_with_suggestion_rewrites_every_occurrence(agent_workdir):
    agent = FakeAgent(agent_workdir, [])
    proposal = _write(payload={
        "bindings": [
            {"role": "roles/bigquery.reader", "members": ["user:alice@acme.example"]},
            {"role": "roles/bigquery.reader", "members": ["user:bob@acme.example"]},
        ],
        "notes": {"roles/bigquery.reader": "keep in sync with roles/bigquery.reader"},
    })
    retry = agent.retry_with_suggestion(proposal, _Outcome(stderr=_BLOCKED_STDERR))
    dumped = json.dumps(retry.payload)
    assert "roles/bigquery.reader" not in dumped
    assert dumped.count("roles/bigquery.dataViewer") == 4  # two roles, one key, one value


def test_retry_with_suggestion_rewrites_str_and_bytes_payloads(agent_workdir):
    agent = FakeAgent(agent_workdir, [])
    outcome = _Outcome(stderr=_BLOCKED_STDERR)
    text = agent.retry_with_suggestion(
        _write(rel_path="main.tf", payload='role = "roles/bigquery.reader"\n'), outcome
    )
    assert text.payload == 'role = "roles/bigquery.dataViewer"\n'
    raw = agent.retry_with_suggestion(
        _write(rel_path="main.tf", payload=b'role = "roles/bigquery.reader"\n'), outcome
    )
    assert raw.payload == b'role = "roles/bigquery.dataViewer"\n'


def test_retry_with_suggestion_raises_when_stderr_has_no_suggestion(agent_workdir):
    agent = FakeAgent(agent_workdir, [])
    outcome = _Outcome(stderr=_PASSED_STDERR)
    with pytest.raises(AssertionError) as excinfo:
        agent.retry_with_suggestion(_write(), outcome)
    message = str(excinfo.value)
    assert "W1_write_iam" in message
    assert str(outcome) in message  # the whole outcome, so the failure is loud


def test_retry_with_suggestion_raises_on_empty_stderr(agent_workdir):
    agent = FakeAgent(agent_workdir, [])
    with pytest.raises(AssertionError):
        agent.retry_with_suggestion(_write(), _Outcome(stderr="", exit_code=0))
