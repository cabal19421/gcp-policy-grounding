"""The honesty assertions every adversarial family lands through.

Three outcomes are legitimate for a proposal: it is **blocked** (exit 2 with
the finding on stderr), it **passes** (exit 0, silent), or the gate
**abstains** (exit 0, but the ignorance is on the record as ``unverified``).
Each has a helper here, and each helper attaches ``str(outcome)`` — argv, exit
code, both streams — to the ``AssertionError``, so a red run is diagnosable
from the pytest report without a rerun.

The helpers that take a *report* (the ``gcp-grounding-report/1`` document from
:func:`tests.agentic.hookrunner.ground_json`) instead of an outcome attach a
compact rendering of the verdicts for the same reason.

The two negative-space assertions are the interesting ones.
:func:`assert_not_silently_dropped` catches the failure mode that leaves *no*
trace at all: a claim the extractor never emitted produces no verdict, so the
report is indistinguishable from a clean pass. That is a missed *abstain*, and
it is worse than a missed block — a missed block is at least visible in the
diff, while a missed abstain tells the reviewer the gate looked and was happy.
:func:`assert_no_verdictless_pass` is its whole-document form.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

__all__ = [
    "assert_abstained",
    "assert_blocked",
    "assert_no_verdictless_pass",
    "assert_not_silently_dropped",
    "assert_passed",
    "assert_recorded",
]


def _render_report(report: Mapping) -> str:
    """The verdicts, one per line, for an assertion message."""
    verdicts = report.get("verdicts") or []
    lines = [f"report ok={report.get('ok')!r} summary={report.get('summary')!r}"]
    for verdict in verdicts:
        lines.append(
            f"  [{verdict.get('status')}] [{verdict.get('kind')}] "
            f"{verdict.get('target')}: {verdict.get('message')}")
    if not verdicts:
        lines.append("  (no verdicts)")
    return "\n".join(lines)


def _unverified_messages(report: Mapping) -> list[str]:
    return [v.get("message", "") for v in (report.get("verdicts") or [])
            if v.get("status") == "unverified"]


def assert_blocked(outcome, *substrings: str, expect_render: bool = True) -> None:
    """The proposal was BLOCKED: exit 2, nothing on stdout, the finding on
    stderr.

    Exit 2 is Claude Code's blocking code and stderr is what the hook runner
    feeds back to the agent, so both halves are the contract — a finding
    printed to stdout would block the edit while telling the agent nothing.

    *expect_render* additionally requires the report's own ``FAILED`` header
    (``report.py:121``), which is how a *grounding* block is distinguished
    from a block emitted by some other path; the bash-mutation block, which
    never renders a grounding report, passes ``expect_render=False``.
    """
    assert outcome.exit_code == 2, (
        f"expected exit 2 (blocked), got {outcome.exit_code}\n{outcome}")
    assert outcome.stdout == "", (
        f"a block must leave stdout byte-empty; the finding belongs on "
        f"stderr\n{outcome}")
    if expect_render:
        assert "FAILED" in outcome.stderr, (
            f"expected the rendered grounding report's FAILED header on "
            f"stderr\n{outcome}")
    for substring in substrings:
        assert substring in outcome.stderr, (
            f"expected {substring!r} in stderr\n{outcome}")


def assert_passed(outcome) -> None:
    """The proposal PASSED: exit 0 with BOTH streams byte-empty.

    Byte-empty, not "no findings": a guardrail that chatters on a clean edit
    is a guardrail that gets switched off, and the hook's stderr is agent-
    visible, so noise there is noise in the agent's context too.
    """
    assert outcome.exit_code == 0, (
        f"expected exit 0 (passed), got {outcome.exit_code}\n{outcome}")
    assert outcome.stdout == "" and outcome.stderr == "", (
        f"a clean pass must be byte-silent on both streams\n{outcome}")


def assert_abstained(outcome, report: Mapping, *substrings: str) -> None:
    """The gate ABSTAINED: exit 0, and the ignorance is on the record.

    The four-bucket honesty assertion in one place. Could-not-decide is exit 0
    — ignorance never fails the gate — but it must leave at least one
    ``unverified`` naming the reason, and it must NOT have manufactured an
    ``ungrounded`` or a ``contradicted`` from the same ignorance. Every
    substring must appear in the concatenated ``unverified`` messages: an
    abstain that does not say *why* it abstained is a silent pass wearing a
    verdict.
    """
    assert outcome.exit_code == 0, (
        f"an abstain must not fail the gate; got exit {outcome.exit_code}\n"
        f"{outcome}")
    assert outcome.stdout == "", (
        f"an abstaining hook run must leave stdout byte-empty\n{outcome}")
    assert report.get("ok") is True, (
        f"an abstain leaves the report ok\n{outcome}\n{_render_report(report)}")
    summary = report.get("summary") or {}
    assert summary.get("unverified", 0) >= 1, (
        f"an abstain must record at least one unverified verdict, not pass in "
        f"silence\n{outcome}\n{_render_report(report)}")
    assert summary.get("ungrounded", 0) == 0, (
        f"an abstain must not report anything ungrounded\n{outcome}\n"
        f"{_render_report(report)}")
    assert summary.get("contradicted", 0) == 0, (
        f"an abstain must not manufacture a contradiction out of ignorance\n"
        f"{outcome}\n{_render_report(report)}")
    joined = "\n".join(_unverified_messages(report))
    for substring in substrings:
        assert substring in joined, (
            f"expected {substring!r} in the unverified messages — an abstain "
            f"must name its reason\n{outcome}\n{_render_report(report)}")


def assert_recorded(report: Mapping, *, status=None, kind=None,
                    target=None) -> dict:
    """Return THE ONE verdict matching the given fields, asserting there is
    exactly one.

    Exactly one, not at least one: two verdicts for the same claim means the
    dispatch ran a check twice, and picking the first would hide it.
    """
    wanted = {"status": status, "kind": kind, "target": target}
    wanted = {key: value for key, value in wanted.items() if value is not None}
    assert wanted, "assert_recorded needs at least one of status/kind/target"
    matches = [v for v in (report.get("verdicts") or [])
               if all(v.get(key) == value for key, value in wanted.items())]
    assert len(matches) == 1, (
        f"expected exactly one verdict matching {wanted!r}, found "
        f"{len(matches)}\n{_render_report(report)}")
    return matches[0]


def assert_not_silently_dropped(report: Mapping, needle: str) -> None:
    """*needle* left a trace: it appears in some verdict's target or message.

    Used for ``allUsers`` and for members carrying CEL the encoder does not
    support. A claim the extractor skips produces no verdict at all, so the
    report reads exactly like a clean pass — a MISSED ABSTAIN, which is worse
    than a missed block because it is invisible.
    """
    for verdict in report.get("verdicts") or []:
        if needle in str(verdict.get("target", "")) or needle in str(verdict.get("message", "")):
            return
    raise AssertionError(
        f"{needle!r} appears in no verdict's target or message — it was "
        f"silently dropped, which reads as a clean pass\n"
        f"{_render_report(report)}")


def assert_no_verdictless_pass(outcome, report: Mapping) -> None:
    """Exit 0 AND at least one verdict.

    A recognized, non-empty document that produces zero verdicts is
    indistinguishable from a document the gate deliberately passed — the
    whole-document form of :func:`assert_not_silently_dropped`.
    """
    assert outcome.exit_code == 0, (
        f"expected exit 0, got {outcome.exit_code}\n{outcome}")
    assert report.get("verdicts"), (
        f"exit 0 with zero verdicts is indistinguishable from a clean pass; "
        f"a recognized document must leave at least one verdict\n{outcome}\n"
        f"{json.dumps(dict(report), indent=2, sort_keys=True)}")
