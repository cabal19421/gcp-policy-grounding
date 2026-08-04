"""A deterministic scripted emitter of Claude-Code tool events — NOT an LLM.

There is no network call, no API key and no model call anywhere in this module:
:class:`FakeAgent` replays a fixed ``script`` of :class:`Proposal` objects. That
is not a compromise, it is the point. What the guardrail actually observes of an
agent is exactly two things — *the sequence of tool events* and *the file
mutations those events describe* — and both are fully determined by the script.
Nothing an LLM adds on top (why it chose the edit, how it phrased the diff) is
visible at the hook boundary, so replacing the model with a script loses no
coverage while making every run byte-reproducible.

Non-goals, stated so no reader over-reads a green run:

- This suite never claims that a passing run means the policy is **safe**.
  Intent is out of scope for the whole package. What a green run asserts is
  narrower and checkable: for the checks the gate *actually implements*, its
  block / pass / abstain classification of each proposal is the honest one.
- ``expect="pass"`` therefore means "nothing this gate can decide is wrong with
  it", and ``expect="abstain"`` means "the gate is honestly unable to judge it"
  — never "approved".

**The apply-then-envelope ordering is the contract.** :meth:`FakeAgent.turn`
calls :meth:`~FakeAgent.apply` FIRST and :meth:`~FakeAgent.envelope` SECOND,
because ``PostToolUse`` means the write already landed: by the time the hook
runs, the file on disk equals the proposed content, and that file is what
``gcp_grounding.cli``'s ``--hook`` mode hands to ``ground_policy``. Inverting
the two would still produce a green suite, but it would silently be testing
``PreToolUse`` semantics against a stale (or absent) file — every ``block`` case
would degrade into "grounded nothing, passed".

The one subtlety in that ordering: an ``Edit`` event's ``old_string`` is the
*pre*-write content, so it must be read from disk BEFORE ``apply`` overwrites
the file. It is captured inside :meth:`~FakeAgent.turn` and passed into
:meth:`~FakeAgent.envelope`, which itself never touches disk.

The emitted envelope is the FULL realistic Claude-Code payload even though the
hook reads only ``tool_input.file_path``. Emitting the whole thing is precisely
what makes this a contract test: if the CLI ever starts reading
``tool_response`` or ``cwd``, these events already carry them, and the
``NotebookEdit`` case (which has ``notebook_path`` and deliberately NO
``file_path``) documents the bypass the hook is blind to.
"""

from __future__ import annotations

import copy
import difflib
import hashlib
import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Mapping

__all__ = [
    "TOOL_NAMES",
    "PROPOSAL_KINDS",
    "EXPECTATIONS",
    "PERMISSION_MODE",
    "BASH_TIMEOUT_MS",
    "SUGGESTION_RE",
    "BAD_NAME_RE",
    "Proposal",
    "FakeAgent",
    "default_session_id",
    "render_payload",
    "feedback",
]

#: Every tool a proposal may claim to have used. The first four mutate a file,
#: ``Bash`` and the two ``mcp__*`` tools can mutate the estate without any
#: ``file_path`` at all, and ``Read`` mutates nothing — the spread is the point:
#: it is the set of ways a real agent can reach a policy.
TOOL_NAMES = (
    "Write",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
    "Bash",
    "Read",
    "mcp__gcp__set_iam_policy",
    "mcp__terraform__apply",
)

#: Policy domain a proposal belongs to; ``control`` is a proposal that touches
#: no policy at all (the negative control). Advisory: unlike ``expect`` and
#: ``tool_name`` this is NOT validated, so a later adversarial family can name a
#: domain this tuple has not learned yet without a cross-task edit here.
PROPOSAL_KINDS = (
    "iam",
    "firewall",
    "hier_firewall",
    "cloud_armor",
    "vpcsc",
    "org_policy",
    "tf_plan",
    "control",
)

#: The three honest buckets a proposal can be expected to land in. ``block`` =
#: the gate exits nonzero on an ungrounded/contradicted finding; ``pass`` = it
#: exits 0 with nothing decidable wrong; ``abstain`` = it exits 0 *because* it
#: could not judge (uncaptured category, unsupported encoding, no z3).
EXPECTATIONS = ("block", "pass", "abstain")

#: ``permission_mode`` on every emitted event.
PERMISSION_MODE = "default"

#: Claude Code's default Bash timeout, in milliseconds.
BASH_TIMEOUT_MS = 120000

#: The parenthesised did-you-mean list the human renderer appends at
#: ``gcp_grounding/report.py:129`` — ``  (did you mean: a, b, c?)``.
SUGGESTION_RE = re.compile(r"\(did you mean: (?P<suggestions>[^)]*)\?\)")

#: The ungrounded message minted at ``gcp_grounding/reasoner.py:159-162``,
#: naming a claim kind and the quoted name that failed to ground:
#: ``role 'roles/bigquery.reader' does not exist in the snapshot``.
BAD_NAME_RE = re.compile(
    r"(?P<kind>[A-Za-z_][A-Za-z0-9_]*) '(?P<name>[^']+)' does not exist in the snapshot"
)


# -- the script ---------------------------------------------------------------


@dataclass(frozen=True)
class Proposal:
    """One scripted agent turn: a tool call, the file mutation it performs, and
    the bucket the gate is expected to put it in."""

    #: Stable identifier, doubling as the pytest param id (``A10_owner_to_external``).
    id: str
    #: One of :data:`PROPOSAL_KINDS` (advisory, not validated).
    kind: str
    #: One of :data:`TOOL_NAMES`.
    tool_name: str
    #: Path relative to the agent's workdir; empty for ``Bash`` and mcp
    #: proposals that touch no file.
    rel_path: str
    #: A ``dict`` (dumped ``json.dumps(indent=2, sort_keys=True)``), a ``str``
    #: (written UTF-8), ``bytes`` (written raw), or ``None`` (no write).
    payload: Any
    #: One of :data:`EXPECTATIONS`.
    expect: str
    #: One sentence on why a real agent would propose this.
    rationale: str
    #: ``Bash`` only: the command line.
    command: str | None = None
    #: ``NotebookEdit`` only: overrides the derived notebook path.
    notebook_path: str | None = None
    #: mcp tools only: the whole ``tool_input`` body.
    mcp_input: Mapping[str, Any] | None = None
    #: Hook event this turn emits.
    hook_event_name: str = "PostToolUse"
    #: When True the turn DELETEs ``rel_path`` instead of writing it (the
    #: revert case: an agent that removes the policy file rather than fixing it).
    delete: bool = False

    def __post_init__(self) -> None:
        if self.expect not in EXPECTATIONS:
            raise ValueError(
                f"proposal {self.id!r}: expect must be one of {EXPECTATIONS}, "
                f"got {self.expect!r}"
            )
        if self.tool_name not in TOOL_NAMES:
            raise ValueError(
                f"proposal {self.id!r}: tool_name must be one of {TOOL_NAMES}, "
                f"got {self.tool_name!r}"
            )


def render_payload(payload: Any) -> str | bytes | None:
    """The exact bytes/text a payload becomes on disk, or ``None`` for no write.

    Shared by :meth:`FakeAgent.apply` and :meth:`FakeAgent.envelope` so the
    event's ``content`` and the file's content can never drift apart.
    """
    if payload is None or isinstance(payload, (str, bytes)):
        return payload
    if isinstance(payload, (dict, list)):
        return json.dumps(payload, indent=2, sort_keys=True)
    raise TypeError(
        f"payload must be dict, str, bytes or None; got {type(payload).__name__}"
    )


def default_session_id(script: Iterable[Proposal]) -> str:
    """``"sess-"`` plus the first 12 hex chars of the sha1 of the joined
    proposal ids.

    Deterministic on purpose — a ``uuid4()`` here would make every envelope
    differ between runs, and a contract test could not diff one.
    """
    joined = "|".join(p.id for p in script)
    return "sess-" + hashlib.sha1(joined.encode("utf-8")).hexdigest()[:12]


# -- the agent ----------------------------------------------------------------


class FakeAgent:
    """Replays *script* against *workdir*, one turn at a time."""

    def __init__(
        self,
        workdir: Path | str,
        script: Iterable[Proposal],
        *,
        session_id: str | None = None,
    ) -> None:
        self.workdir = Path(workdir)
        self.script: tuple[Proposal, ...] = tuple(script)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.transcript_path = self.workdir / "transcript.jsonl"
        self.transcript_path.write_text("", encoding="utf-8")
        self.session_id = session_id or default_session_id(self.script)
        #: Turns already taken; ``remaining()`` counts the rest.
        self.turns_taken = 0

    def remaining(self) -> int:
        """How many proposals are left in the script."""
        return len(self.script) - self.turns_taken

    # -- the two halves of a turn, separately testable ------------------------

    def apply(self, p: Proposal) -> Path | None:
        """Perform ONLY *p*'s file mutation; emit no event.

        Returns the touched path, or ``None`` when ``rel_path`` is empty (a
        ``Bash`` or mcp proposal that mutates the estate, not the working tree).
        """
        if not p.rel_path:
            return None
        path = self.workdir / p.rel_path
        if p.delete:
            path.unlink(missing_ok=True)
            return path
        content = render_payload(p.payload)
        if content is None:  # e.g. a Read: the turn touches the file, writes nothing
            return path
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def envelope(self, p: Proposal, *, old_string: str = "") -> dict:
        """Build ONLY the hook event for *p*; never touch disk.

        *old_string* is an ``Edit``/``MultiEdit``'s pre-write file content,
        which :meth:`turn` captures before :meth:`apply` overwrites it — see the
        module docstring. Defaults to empty so a disk-free ``envelope(p)`` call
        stays valid.
        """
        return {
            "session_id": self.session_id,
            "transcript_path": str(self.transcript_path),
            "cwd": str(self.workdir),
            "permission_mode": PERMISSION_MODE,
            "hook_event_name": p.hook_event_name,
            "tool_name": p.tool_name,
            "tool_input": self._tool_input(p, old_string),
            "tool_response": self._tool_response(p),
        }

    def turn(self) -> tuple[Proposal, dict]:
        """Pop the next proposal, apply it, then build its event."""
        if self.turns_taken >= len(self.script):
            raise IndexError("script exhausted — no proposal left to take")
        p = self.script[self.turns_taken]
        # BEFORE apply: an Edit's old_string is the file as the agent found it.
        old_string = self._old_string(p)
        self.apply(p)
        event = self.envelope(p, old_string=old_string)
        self.turns_taken += 1
        return p, event

    def script_turns(self) -> list[tuple[Proposal, dict]]:
        """Drain the script, returning every ``(proposal, event)`` pair."""
        return [self.turn() for _ in range(self.remaining())]

    # -- paths ----------------------------------------------------------------

    def file_path(self, p: Proposal) -> str:
        """*p*'s absolute target path, or ``""`` when it touches no file — the
        CLI treats an empty ``file_path`` as "nothing to ground"."""
        return str(self.workdir / p.rel_path) if p.rel_path else ""

    def notebook_path(self, p: Proposal) -> str:
        """*p*'s absolute notebook path: the explicit ``notebook_path`` when
        given (resolved against the workdir if relative), else ``rel_path``."""
        if p.notebook_path is None:
            return self.file_path(p)
        given = Path(p.notebook_path)
        return str(given if given.is_absolute() else self.workdir / given)

    # -- envelope internals ---------------------------------------------------

    def _tool_input(self, p: Proposal, old_string: str) -> dict:
        tool = p.tool_name
        if tool.startswith("mcp__"):
            return dict(p.mcp_input or {})
        new_source = _as_text(render_payload(p.payload))
        if tool == "Write":
            return {"file_path": self.file_path(p), "content": new_source}
        if tool == "Edit":
            return {
                "file_path": self.file_path(p),
                "old_string": old_string,
                "new_string": new_source,
                "replace_all": False,
            }
        if tool == "MultiEdit":
            # One file_path for the whole call no matter how many edits it
            # carries — that single key is all the hook ever sees.
            return {
                "file_path": self.file_path(p),
                "edits": _multi_edits(old_string, new_source),
            }
        if tool == "NotebookEdit":
            # NO file_path key: this is exactly why the hook is blind to a
            # notebook cell that writes a policy document.
            return {
                "notebook_path": self.notebook_path(p),
                "new_source": new_source,
                "cell_type": "code",
                "edit_mode": "replace",
            }
        if tool == "Bash":
            return {
                "command": p.command or "",
                "description": p.rationale,
                "timeout": BASH_TIMEOUT_MS,
            }
        # Read — the remaining member of TOOL_NAMES, closed by __post_init__.
        return {"file_path": self.file_path(p)}

    def _tool_response(self, p: Proposal) -> dict:
        tool = p.tool_name
        if tool.startswith("mcp__"):
            return {"success": True}
        if tool == "Bash":
            return {"stdout": "", "stderr": "", "interrupted": False, "isImage": False}
        if tool == "Read":
            # numLines comes from the proposal, never from disk: envelope() is
            # disk-free by contract.
            text = _as_text(render_payload(p.payload))
            return {
                "type": "text",
                "file": {"filePath": self.file_path(p), "numLines": len(text.splitlines())},
            }
        if tool == "NotebookEdit":
            return {"filePath": self.notebook_path(p), "success": True, "userModified": False}
        # Write / Edit / MultiEdit.
        return {"filePath": self.file_path(p), "success": True, "userModified": False}

    def _old_string(self, p: Proposal) -> str:
        """The file as it is right now, for the edit tools only. Unreadable or
        absent is honestly empty — a fake agent is not the place to raise."""
        if p.tool_name not in ("Edit", "MultiEdit") or not p.rel_path:
            return ""
        try:
            return (self.workdir / p.rel_path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return ""

    # -- the feedback loop ----------------------------------------------------

    def retry_with_suggestion(self, p: Proposal, outcome: Any) -> Proposal:
        """The corrected proposal an orchestrator would send next.

        Parses the FIRST ungrounded name and its first did-you-mean suggestion
        out of ``outcome.stderr``, deep-copies ``p.payload``, replaces every
        occurrence of the bad name with the suggested one, and returns a new
        :class:`Proposal` with id ``<id>-retry`` expecting ``pass`` — the loop
        ``gate.py:41`` describes, closed.

        Raises ``AssertionError`` carrying ``str(outcome)`` when stderr has no
        suggestion to act on: a feedback loop that quietly fails to close is
        worse than a red test.
        """
        stderr = getattr(outcome, "stderr", "") or ""
        bad = BAD_NAME_RE.search(stderr)
        tip = SUGGESTION_RE.search(stderr, bad.end()) if bad is not None else None
        if bad is None or tip is None:
            raise AssertionError(
                f"cannot close the feedback loop for proposal {p.id!r}: the gate's "
                f"stderr carries no did-you-mean suggestion — {outcome}"
            )
        bad_name = bad.group("name")
        suggestion = tip.group("suggestions").split(",")[0].strip()
        payload = _rewrite(copy.deepcopy(p.payload), bad_name, suggestion)
        return replace(p, id=f"{p.id}-retry", payload=payload, expect="pass")


def feedback(outcome: Any) -> str:
    """The text an orchestrator would paste into the agent's next prompt.

    The hook contract already puts the human-rendered findings on stderr (the
    blocking exit code is 2, the findings go to stderr so the runner feeds them
    back), so the feedback *is* that text. This function exists to name the
    loop step — and to give one place to change should the framing ever need
    more than the report itself.

    *outcome* is duck-typed: anything with a ``stderr`` attribute, which is what
    ``tests.agentic.hookrunner``'s run result carries.
    """
    return (getattr(outcome, "stderr", "") or "").strip()


# -- helpers ------------------------------------------------------------------


def _as_text(content: str | bytes | None) -> str:
    """Rendered payload as the text an event field can carry."""
    if content is None:
        return ""
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    return content


def _multi_edits(old_text: str, new_text: str) -> list[dict]:
    """One edit object per changed region, which is what a real MultiEdit call
    looks like: several targeted old/new pairs against one file."""
    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    edits = [
        {
            "old_string": "".join(old_lines[i1:i2]),
            "new_string": "".join(new_lines[j1:j2]),
            "replace_all": False,
        }
        for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(
            a=old_lines, b=new_lines, autojunk=False
        ).get_opcodes()
        if tag != "equal"
    ]
    if not edits:  # nothing changed: still a whole-file edit, never an empty call
        edits.append({"old_string": old_text, "new_string": new_text, "replace_all": False})
    return edits


def _rewrite(value: Any, bad: str, good: str) -> Any:
    """Every occurrence of *bad* replaced by *good*, anywhere in a payload —
    dict keys and values, list items, strings and bytes alike."""
    if isinstance(value, str):
        return value.replace(bad, good)
    if isinstance(value, bytes):
        return value.replace(bad.encode("utf-8"), good.encode("utf-8"))
    if isinstance(value, dict):
        return {_rewrite(k, bad, good): _rewrite(v, bad, good) for k, v in value.items()}
    if isinstance(value, list):
        return [_rewrite(item, bad, good) for item in value]
    return value
