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

CHANNEL DISCIPLINE. An adversarial assertion is discharged only by a verdict
kind its own family OWNS. :data:`FAMILY_KINDS` says which those are and
:func:`channel` narrows a report to them, so :func:`assert_decided_on_channel`
and :func:`assert_abstained_on_channel` compute their property from that
subset and from nothing else. :data:`INCIDENTAL_KINDS` — ``resource_type`` and
``resource_type_ref`` — is the vocabulary every terraform document hits for
free, and it belongs to no family: the property is structural rather than a
rule an author has to remember, because an incidental hit is not in the
candidate set at all. A family with no :data:`FAMILY_KINDS` entry raises
``KeyError`` the first time it reaches a channel helper — a new family cannot
quietly opt out into an empty channel that satisfies nothing.

THE FLOORS UNDER THE OUTCOME HELPERS. Exit 0 with byte-empty stdout is also,
byte for byte, the CLI's "this file is not mine to judge" early return, and
exit 2 is also argparse's usage-error code. So :func:`assert_abstained`
cross-checks the report against the file the event named, requires the abstain
to say *why*, and recounts the statuses from ``verdicts`` rather than trusting
``summary``; and :func:`assert_blocked` requires a substring in every form and,
where no grounding report is rendered, rejects a crash, a usage error and a
byte-empty stderr.

The two negative-space assertions are the interesting ones.
:func:`assert_not_silently_dropped` catches the failure mode that leaves *no*
trace at all: a claim the extractor never emitted produces no verdict, so the
report is indistinguishable from a clean pass. That is a missed *abstain*, and
it is worse than a missed block — a missed block is at least visible in the
diff, while a missed abstain tells the reviewer the gate looked and was happy.
:func:`assert_no_verdictless_pass` is its whole-document form, and is NOT an
adversarial floor; its own docstring says why.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

from gcp_grounding.core.report import STATUSES

__all__ = [
    "FAMILY_KINDS",
    "INCIDENTAL_KINDS",
    "assert_abstained",
    "assert_abstained_on_channel",
    "assert_blocked",
    "assert_decided_on_channel",
    "assert_no_verdictless_pass",
    "assert_not_silently_dropped",
    "assert_passed",
    "assert_recorded",
    "channel",
]

#: Verdict kinds that are INCIDENTAL VOCABULARY HITS: they say the terraform
#: provider knows a type name, never that the proposal under review was judged.
#: ``terraform show -json`` emits one ``resource_type_ref`` claim per resource
#: (``tf_claims.py:77``) which the Datalog pass grounds under the snapshot
#: category ``resource_type`` (``reasoner.py:54``), so every tf-shaped
#: adversarial case gets one of these for free. No family may own either.
INCIDENTAL_KINDS = frozenset({"resource_type", "resource_type_ref"})

#: Adversarial family → the ``Verdict.kind`` values that family OWNS.
#:
#: A family's set is its domain's whole channel: the snapshot categories the
#: Datalog pass grounds its ``*_ref`` claims against, the claim kinds
#: ``preflight``'s catch-all surfaces verbatim while no checker has claimed
#: them yet, and the kinds its own checkers emit. Families may overlap — the
#: ``cel`` an IAM condition raises is genuinely both IAM's and the abstain
#: family's business — but none of them may reach into
#: :data:`INCIDENTAL_KINDS`, which is what
#: ``test_gcp_assert_channels.py`` pins.
FAMILY_KINDS: dict[str, frozenset[str]] = {
    "iam": frozenset({
        # existence, decided by the Datalog pass
        "role", "permission", "principal",
        "service_account", "service_account_ref",
        # the constraint-solver layer
        "cel", "subset",
        # the IAM checkers
        "iam_escalation", "iam_public",
        # claim kinds no checker has claimed yet, surfaced by preflight's
        # catch-all under the claim's own kind
        "public_principal", "unmodelled_principal",
        "denied_principal", "denied_permission",
    }),
    "network": frozenset({
        # existence
        "network", "network_ref", "subnetwork", "subnetwork_ref",
        "network_tag", "network_tag_ref",
        "firewall_policy", "firewall_policy_ref",
        "security_policy", "security_policy_ref",
        "hierarchy_node", "hierarchy_node_ref",
        # structured proposals
        "firewall_rule", "firewall_policy_rule", "security_policy_rule",
        # the VPC firewall, hierarchical firewall and Cloud Armor checkers
        "firewall_exposure", "firewall_pair",
        # `hfw_reopen` is the cross-level re-opening finding hfw_checks emits;
        # it belongs to this family exactly as `hfw_widen` does, and a channel
        # that omitted it would refuse the one verdict that names both the port
        # and the priority of the deny a proposal preempts.
        "hfw_order", "hfw_shadow", "hfw_widen", "hfw_effect", "hfw_reopen",
        "armor_rule", "armor_bypass", "armor_default", "armor_expr",
        "armor_priority",
    }),
    "vpcsc": frozenset({
        # existence
        "perimeter", "perimeter_ref", "access_level", "access_level_ref",
        "restricted_service", "restricted_service_ref",
        # structured proposals
        "perimeter_config", "perimeter_ingress", "perimeter_egress",
        # the VPC-SC checkers
        "vpcsc_protection", "vpcsc_dry_run", "vpcsc_ingress", "vpcsc_egress",
    }),
    "orgpolicy": frozenset({
        "constraint", "constraint_value", "constraint_enforcement",
        "org_enforcement",
    }),
    # The abstain family's channel is the gate's own "I could not decide"
    # vocabulary: the whole-document kind, the two solver kinds, and the
    # existence categories whose uncaptured half is an abstention. Not
    # ``resource_type`` — an uncaptured-category abstain has to be named by the
    # category the case is about, which is the entire point.
    "abstain": frozenset({
        "document", "subset", "cel",
        "role", "permission", "principal", "constraint",
    }),
    # ``sec_rules`` spells its verdict kind ``f"sec:{promise.domain}"`` over
    # the domains in its own ``_DOMAIN_KINDS`` table, plus ``sec:artifact`` for
    # findings about the compiled artifact itself.
    "secreq": frozenset({
        "sec:artifact", "sec:iam", "sec:org_policy", "sec:vpc_firewall",
        "sec:hier_firewall", "sec:cloud_armor", "sec:vpc_sc",
    }),
}

#: Statuses that are FINDINGS: the gate must have told the agent something.
_FINDING_STATUSES = ("ungrounded", "contradicted")


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


def _messages(verdicts) -> str:
    """``target`` and ``message`` of each verdict, for a substring search."""
    return "\n".join(f"{v.get('target')}: {v.get('message')}" for v in verdicts)


def _status_counts(verdicts) -> dict[str, int]:
    """The four-bucket counts of *verdicts*, computed from the verdicts.

    A verdict carrying an unknown status is invisible here exactly as it is
    invisible to :meth:`GroundingReport.counts`, which is what the report's own
    ``summary`` is built from — the two have to be comparable.
    """
    counts = {status: 0 for status in STATUSES}
    for verdict in verdicts:
        status = verdict.get("status")
        if status in counts:
            counts[status] += 1
    return counts


def _edited_path(event: Mapping) -> str | None:
    """The file a PostToolUse event says was edited — ``cli._hook_file_path``
    in the test's own words."""
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, Mapping):
        return None
    return tool_input.get("file_path")


# -- the channel --------------------------------------------------------------


def channel(report: Mapping, *, family: str) -> list[dict]:
    """The verdicts of *report* whose kind the *family* OWNS.

    A plain ``FAMILY_KINDS[family]`` on purpose: an unregistered family raises
    ``KeyError`` rather than getting an empty channel that would make every
    assertion below vacuously unsatisfiable-but-silent at authoring time.
    """
    kinds = FAMILY_KINDS[family]
    return [v for v in (report.get("verdicts") or []) if v.get("kind") in kinds]


def _channel_kinds(family: str) -> str:
    return ", ".join(sorted(FAMILY_KINDS[family]))


def assert_decided_on_channel(outcome, report: Mapping, *, family: str,
                              status: str, needles=()) -> None:
    """The *family*'s OWN channel carries a verdict with *status*.

    Computed exclusively from :func:`channel`: a ``grounded resource_type``
    from the terraform provider's vocabulary is not in the candidate set, so it
    cannot discharge an adversarial assertion by accident.

    Every needle must appear in the target/message text of the channel's
    verdicts *with that status* — again not the whole report, so a needle
    cannot be satisfied by an unrelated verdict that happens to quote the same
    resource name.
    """
    decided = [v for v in channel(report, family=family)
               if v.get("status") == status]
    assert decided, (
        f"no {status!r} verdict on the {family!r} channel — that family owns "
        f"the kinds [{_channel_kinds(family)}], and nothing else can discharge "
        f"its assertion\n{outcome}\n{_render_report(report)}")
    if status in _FINDING_STATUSES:
        silent = (outcome.exit_code == 0 and outcome.stdout == ""
                  and outcome.stderr == "")
        assert not silent, (
            f"the {family!r} channel carries a {status} verdict, but the run "
            f"exited 0 with both streams byte-empty — that is a silent pass, "
            f"so the outcome and the report are not from the same run\n"
            f"{outcome}\n{_render_report(report)}")
    joined = _messages(decided)
    for needle in needles:
        assert needle in joined, (
            f"expected {needle!r} in the {family!r} channel's {status} "
            f"verdicts\n{outcome}\n{_render_report(report)}")


def assert_abstained_on_channel(outcome, report: Mapping, *, family: str,
                                needles) -> None:
    """The gate ABSTAINED on the *family*'s OWN channel.

    :func:`assert_abstained`'s outcome-side floors — exit 0, byte-empty stdout,
    a report about the file the event named, a summary that agrees with its own
    verdict list — and then the three bucket assertions recomputed over
    :func:`channel` alone.
    """
    verdicts = channel(report, family=family)  # KeyError: unregistered family
    assert needles, (
        f"assert_abstained_on_channel needs at least one substring: an abstain "
        f"on the {family!r} channel that names no reason is a silent pass "
        f"wearing a verdict\n{outcome}")
    _assert_abstain_floor(outcome, report)
    counts = _status_counts(verdicts)
    assert counts["unverified"] >= 1, (
        f"nothing on the {family!r} channel abstained — that family owns the "
        f"kinds [{_channel_kinds(family)}], and an abstention recorded on any "
        f"other kind is not this family's abstention\n{outcome}\n"
        f"{_render_report(report)}")
    assert counts["ungrounded"] == 0, (
        f"an abstain must not report anything ungrounded on the {family!r} "
        f"channel\n{outcome}\n{_render_report(report)}")
    assert counts["contradicted"] == 0, (
        f"an abstain must not manufacture a contradiction out of ignorance on "
        f"the {family!r} channel\n{outcome}\n{_render_report(report)}")
    joined = _messages(v for v in verdicts if v.get("status") == "unverified")
    for needle in needles:
        assert needle in joined, (
            f"expected {needle!r} in the {family!r} channel's unverified "
            f"messages — an abstain must name its reason\n{outcome}\n"
            f"{_render_report(report)}")


# -- the three outcomes -------------------------------------------------------


def assert_blocked(outcome, *substrings: str, expect_render: bool = True) -> None:
    """The proposal was BLOCKED: exit 2, nothing on stdout, the finding on
    stderr.

    Exit 2 is Claude Code's blocking code and stderr is what the hook runner
    feeds back to the agent, so both halves are the contract — a finding
    printed to stdout would block the edit while telling the agent nothing.

    Exit 2 is ALSO argparse's usage-error code, and a child that dies in
    ``python -m`` exits nonzero too, so the code alone proves nothing: at least
    one substring is required in every form.

    *expect_render* additionally requires the report's own ``FAILED`` header
    (``report.py:132-133`` — the one unconditional, unqualified headline the
    renderer still has), which is how a *grounding* block is distinguished
    from a block emitted by some other path; the bash-mutation block, which
    never renders a grounding report, passes ``expect_render=False``. That form
    has no header to key off, so it rejects the three shapes a header would
    have excluded anyway: a crash, a usage error, and silence.
    """
    assert substrings, (
        "assert_blocked needs at least one substring: exit 2 is also argparse's "
        "usage-error code, so a substring-free block asserts nothing about what "
        f"the agent was actually told\n{outcome}")
    assert outcome.exit_code == 2, (
        f"expected exit 2 (blocked), got {outcome.exit_code}\n{outcome}")
    assert outcome.stdout == "", (
        f"a block must leave stdout byte-empty; the finding belongs on "
        f"stderr\n{outcome}")
    if expect_render:
        assert "FAILED" in outcome.stderr, (
            f"expected the rendered grounding report's FAILED header on "
            f"stderr\n{outcome}")
    else:
        assert outcome.stderr != "", (
            f"a block that tells the agent nothing is not a block: stderr is "
            f"byte-empty\n{outcome}")
        assert "Traceback" not in outcome.stderr, (
            f"the child crashed — a traceback is a defect that happens to exit "
            f"nonzero, not a block\n{outcome}")
        assert "usage:" not in outcome.stderr, (
            f"this is an argparse usage-error, not a block — the gate never "
            f"looked at the proposal\n{outcome}")
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


def _assert_abstain_floor(outcome, report: Mapping) -> None:
    """The floor under both abstain helpers: the run passed silently, the
    report is about the file the event named, and the summary agrees with the
    verdict list it was supposedly derived from.

    The source cross-check is the one that matters most. Exit 0 with byte-empty
    stdout is byte-identical to the CLI's "this file is not mine to judge"
    early return AND to its broken-setup fail-open, so without it an outcome
    from one run pairs happily with a sidecar report about another file.
    """
    assert outcome.exit_code == 0, (
        f"an abstain must not fail the gate; got exit {outcome.exit_code}\n"
        f"{outcome}")
    assert outcome.stdout == "", (
        f"an abstaining hook run must leave stdout byte-empty\n{outcome}")
    event = getattr(outcome, "event", None)
    if event is not None:
        edited = _edited_path(event)
        assert report["source"] == edited, (
            f"the report is about {report.get('source')!r} but the event named "
            f"{edited!r} — an abstain about a different file is not this "
            f"file's abstain\n{outcome}\n{_render_report(report)}")
    counted = _status_counts(report.get("verdicts") or [])
    summary = report.get("summary") or {}
    assert counted == {name: summary.get(name, 0) for name in STATUSES}, (
        f"the report's summary disagrees with its own verdict list: summary "
        f"says {summary!r}, the verdicts count {counted!r}\n{outcome}\n"
        f"{_render_report(report)}")


def assert_abstained(outcome, report: Mapping, *substrings: str) -> None:
    """The gate ABSTAINED: exit 0, and the ignorance is on the record.

    The four-bucket honesty assertion in one place. Could-not-decide is exit 0
    — ignorance never fails the gate — but it must leave at least one
    ``unverified`` naming the reason, and it must NOT have manufactured an
    ``ungrounded`` or a ``contradicted`` from the same ignorance. Every
    substring must appear in the concatenated ``unverified`` messages: an
    abstain that does not say *why* it abstained is a silent pass wearing a
    verdict, so at least one substring is required.

    The counts come from ``report["verdicts"]``, not from ``report["summary"]``:
    a summary claiming one unverified over an empty verdict list is a
    hand-built document, and trusting it is how one passed as evidence.
    """
    assert substrings, (
        "assert_abstained needs at least one substring: an abstain that names "
        f"no reason is not an abstain\n{outcome}")
    _assert_abstain_floor(outcome, report)
    counted = _status_counts(report.get("verdicts") or [])
    assert report.get("ok") is True, (
        f"an abstain leaves the report ok\n{outcome}\n{_render_report(report)}")
    assert counted["unverified"] >= 1, (
        f"an abstain must record at least one unverified verdict, not pass in "
        f"silence\n{outcome}\n{_render_report(report)}")
    assert counted["ungrounded"] == 0, (
        f"an abstain must not report anything ungrounded\n{outcome}\n"
        f"{_render_report(report)}")
    assert counted["contradicted"] == 0, (
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

    RETAINED for the benign and false-positive-budget families, where "the gate
    stayed quiet and still examined something" is exactly the property under
    test. FORBIDDEN as an adversarial floor: it is satisfied by ANY verdict of
    ANY kind, so an incidental ``grounded resource_type`` from the terraform
    provider's own vocabulary discharges it while the adversarial proposal goes
    unjudged. An adversarial family asserts through
    :func:`assert_decided_on_channel` or :func:`assert_abstained_on_channel`
    instead. Nothing in this helper can enforce that — the mechanism that does
    is the per-family mutation contract, which spawns one child per named
    removal from the checker under test and requires that family's tests to go
    RED; a family floored on this helper stays green under its own mutation and
    is caught there.
    """
    assert outcome.exit_code == 0, (
        f"expected exit 0, got {outcome.exit_code}\n{outcome}")
    assert report.get("verdicts"), (
        f"exit 0 with zero verdicts is indistinguishable from a clean pass; "
        f"a recognized document must leave at least one verdict\n{outcome}\n"
        f"{json.dumps(dict(report), indent=2, sort_keys=True)}")
