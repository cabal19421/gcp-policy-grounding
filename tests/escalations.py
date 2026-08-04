"""The append-only register of clauses this suite could not satisfy in place.

House rule 4 — ESCALATE, DO NOT ROUTE AROUND. When a task's clause cannot be
satisfied where it was asked for, the cheapest honest path is to say so by
name: an entry here, and the spec-literal assertion landed under
``pytest.mark.xfail(strict=True, reason=<id>)``. That is a GREEN, named state.
Rewriting the assertion to fit the code instead is a review FAIL.

Entries are APPEND-ONLY: an id, once published, is quoted from ``xfail``
reasons and from module docstrings, so removing or renaming one silently
detaches those references. An escalation is CLOSED by landing its
``product_fix`` and deleting the ``xfail`` — the entry stays, with
``closed_by`` naming the change.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Escalation:
    """One clause that could not be satisfied where it was asked for."""

    #: Stable id, quoted from ``xfail`` reasons. Never reused, never renamed.
    id: str
    #: The clause, in the design's own words.
    clause: str
    #: What stops it being satisfied here — the measured fact, not an opinion.
    why: str
    #: The change that would close it, concretely enough to be actioned.
    product_fix: str
    #: What is exposed while it is open. An escalation is not a dismissal.
    residual_risk: str
    #: The commit or task that landed ``product_fix``; empty while open.
    closed_by: str = ""


ESCALATIONS: tuple[Escalation, ...] = (
    Escalation(
        id="ESC-HOOKRUNNER-NO-Z3-BANNER",
        clause=(
            "assert_passed's byte-empty-both-streams contract must hold in the "
            "no-z3 world the harness explicitly supports, without relaxing "
            "assert_passed."
        ),
        why=(
            "A clean hook run on a clean policy writes 236 bytes to stderr in "
            "that world: core/solver.py:116-120 logs 'z3 package found but "
            "failed to initialize (...) — falling back to the builtin solver' "
            "at WARNING, and with no setup_logging() call logging's lastResort "
            "handler puts the bare message on stderr. The harness side is "
            "fixed — tests.agentic.hookrunner.STDERR_ALLOWLIST filters that "
            "exact line out of HookOutcome.stderr and keeps it on stderr_raw — "
            "but that changes THE MEASURING INSTRUMENT, NOT THE PRODUCT. "
            "gcp_grounding/core/ is vendored and MUST NOT be edited, so the "
            "product half cannot be fixed from a test task at all."
        ),
        product_fix=(
            "Demote the fallback warning to debug on the hook path, in the "
            "module that owns the solver: core/solver.py's get_solver() should "
            "log the 'found but failed to initialize' fallback at DEBUG (the "
            "backend is already reported by --explain and by the report "
            "document's `backend` field), or gcp_grounding should own the "
            "solver selection in a non-vendored wrapper that logs at DEBUG "
            "when running as a PostToolUse hook."
        ),
        residual_risk=(
            "On a machine whose solver is installed but not initialisable — a "
            "mismatched libz3, a wrong-arch wheel — the gate writes that line "
            "to the hook's stderr ONCE PER TOOL CALL. The hook's stderr is a "
            "contract surface: Claude Code feeds it back to the agent, and the "
            "operator reads it. A guardrail that chatters on every clean edit "
            "is a guardrail that gets switched off. Nothing downstream may "
            "claim unconditional byte-silence without naming the filtered line "
            "and why it is filtered."
        ),
    ),
)
