"""The terminal grammar and the structural de-clutter that came with it.

Two things are pinned here, and the first one is the load-bearing half:

1. THE PLAIN SURFACE IS UNTOUCHED. Every other test module in this suite, every
   README fragment and every hook contract reads bytes off a stream that is not
   a terminal. :func:`gcp_grounding.terminal.present` must return those bytes
   unchanged — not "equivalent", unchanged — because wrapping or colouring them
   would silently rewrite the surface all of those pins describe. Only once
   that holds does the terminal path (width-aware wrapping, hanging indents,
   ANSI colour, ``NO_COLOR``) mean anything.
2. The de-clutter rules whose home is not one of the domain modules: the
   compile render's domain-channel twin (:mod:`gcp_grounding.report`) and the
   per-source staleness roll-up (:mod:`gcp_grounding.baseline`). Both collapse
   a REPETITION and neither drops content — the machine document keeps every
   verdict and every reason, which is asserted alongside each one.
"""

from __future__ import annotations

import json

import pytest

from gcp_grounding import baseline, terminal
from gcp_grounding.baseline import BaselineEntry, TargetRef
from gcp_grounding.core.report import GroundingReport, Verdict
from gcp_grounding.report import PolicyReport

CAPTURED = "2026-07-18T09:30:00Z"


class _Stream:
    """A stream that answers :meth:`isatty` however the test needs it to."""

    def __init__(self, tty: bool) -> None:
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


class _Mute:
    """A stream that raises on :meth:`isatty` — a wrapper, a closed handle, a
    mock nobody finished. The plain surface is the safe answer."""

    def isatty(self) -> bool:
        raise ValueError("this stream does not answer that")


@pytest.fixture(autouse=True)
def _no_ambient_colour_settings(monkeypatch):
    """The developer's own ``NO_COLOR``/``TERM``/``COLUMNS`` must not decide
    what this module measures."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("COLUMNS", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")


# -- the plain surface is byte-identical ---------------------------------------


LONG = ("  ⚠ [sec:iam] no-primitive-roles-outside-domain: refuted by "
        "iam_bindings[0] has_condition=False member='user:attacker@evil.example' "
        "role='roles/owner'")
BLOCK = "\n".join([
    "decision: DENIED (exit 1)",
    "  why:",
    "    " + LONG.strip(),
    "",
    "  note: a terraform artifact covers only what terraform manages",
])


def test_a_stream_that_is_not_a_terminal_gets_its_bytes_back_unchanged():
    """THE CONTRACT THE WHOLE SUITE RESTS ON. Not "equal after normalisation":
    the same object, so no future wrapping rule can quietly reshape a pinned
    block by taking a path that happens to reproduce it today."""
    assert terminal.present(BLOCK, _Stream(tty=False)) is BLOCK


def test_a_stream_that_cannot_say_whether_it_is_a_terminal_is_treated_as_not_one():
    assert terminal.present(BLOCK, _Mute()) is BLOCK
    assert terminal.is_terminal(_Mute()) is False
    assert terminal.colour_enabled(_Mute()) is False


# -- width-aware wrapping ------------------------------------------------------


def test_a_terminal_wraps_to_the_width_with_a_hanging_indent(monkeypatch):
    monkeypatch.setenv("COLUMNS", "70")
    monkeypatch.setenv("NO_COLOR", "1")          # wrapping alone, no escapes
    lines = terminal.present(LONG, _Stream(tty=True)).split("\n")

    assert len(lines) > 1, "a 150-column line must not go out at 70 columns"
    assert all(len(line) <= 70 for line in lines), lines
    # The hanging indent: continuations are indented PAST the item's own
    # indentation, so a wrapped verdict never reads as a new one.
    assert lines[0].startswith("  ⚠ ")
    assert all(line.startswith("      ") for line in lines[1:]), lines
    # Nothing is dropped — wrapping moves bytes to the next line, it never
    # truncates. (Re-joining collapses only the whitespace wrapping consumed.)
    assert " ".join(line.strip() for line in lines) == " ".join(LONG.split())


def test_the_width_is_the_terminal_capped_at_a_hundred_columns(monkeypatch):
    monkeypatch.setenv("COLUMNS", "300")
    assert terminal.render_width(_Stream(tty=True)) == terminal.MAX_WIDTH
    monkeypatch.setenv("COLUMNS", "72")
    assert terminal.render_width(_Stream(tty=True)) == 72
    # ... and floored, because below this wrapping shreds rather than helps.
    monkeypatch.setenv("COLUMNS", "12")
    assert terminal.render_width(_Stream(tty=True)) == terminal.MIN_WIDTH


def test_a_line_that_fits_is_not_touched_at_all(monkeypatch):
    monkeypatch.setenv("COLUMNS", "100")
    monkeypatch.setenv("NO_COLOR", "1")
    short = "  checks that passed: 4"
    assert terminal.present(short, _Stream(tty=True)) == short


# -- colour --------------------------------------------------------------------


def _painted(text: str, monkeypatch, columns: str = "200") -> str:
    monkeypatch.setenv("COLUMNS", columns)
    return terminal.present(text, _Stream(tty=True))


def test_the_status_mark_carries_the_colour_and_the_message_does_not(monkeypatch):
    """The MARK is coloured, not the line: a message full of escape codes is a
    message nobody can grep out of a scrollback."""
    painted = _painted("  ✓ [role] role 'roles/owner' exists", monkeypatch)
    assert painted.startswith("  \033[32m✓\033[0m [role] ")
    assert "\033[" not in painted[painted.index("[role]"):]


def test_every_status_mark_has_its_own_colour_and_the_two_blockers_share_one():
    marks = terminal._STATUS_COLOURS
    assert set(marks) == {"✓", "⚠", "✗", "?"}
    assert marks["⚠"] == marks["✗"], "both fail the gate; both read as one thing"
    assert len({marks["✓"], marks["⚠"], marks["?"]}) == 3


def test_the_decision_is_bold_and_a_meta_line_is_dim(monkeypatch):
    assert _painted("decision: DENIED (exit 1)", monkeypatch) == \
        "\033[1mdecision: DENIED (exit 1)\033[0m"
    assert _painted("  result                  : DENIED (exit 1)", monkeypatch) == \
        "  \033[1mresult                  : DENIED (exit 1)\033[0m"
    assert _painted("    note: serial=7", monkeypatch) == \
        "    \033[2mnote: serial=7\033[0m"
    assert _painted("(the full narrative is above)", monkeypatch) == \
        "\033[2m(the full narrative is above)\033[0m"


def test_a_wrapped_continuation_never_gets_a_role_of_its_own(monkeypatch):
    """The role is read off the WHOLE line before it is wrapped. A finding long
    enough to wrap can put a ``(`` at the start of a continuation, and dimming
    that fragment would grey out the middle of a block."""
    finding = ("  ⚠ [iam_deny_shadow] guard_token_mint: removing rule 0 wakes "
               "the dormant grant of iam.serviceAccounts.getAccessToken "
               "(impersonation) to serviceAccount:payroll-ci@acme.example "
               "(//cloudresourcemanager.googleapis.com/projects/acme-pay-prod)")
    lines = _painted(finding, monkeypatch, columns="70").split("\n")

    assert len(lines) > 3
    assert lines[0].startswith("  \033[31m⚠\033[0m ")
    assert any(line.lstrip().startswith("(") for line in lines[1:]), lines
    assert not any("\033[" in line for line in lines[1:]), lines


def test_a_wrapped_decision_line_stays_bold_all_the_way_through(monkeypatch):
    line = "decision recap: DENIED (exit 1) — because: " + "reason " * 20
    pieces = _painted(line.rstrip(), monkeypatch, columns="60").split("\n")
    assert len(pieces) > 1
    assert all(piece.lstrip().startswith("\033[1m") for piece in pieces), pieces
    assert all(piece.endswith("\033[0m") for piece in pieces), pieces


def test_an_ordinary_line_is_left_alone(monkeypatch):
    plain = "promises in force (6 enforcing, 2 not)"
    assert _painted(plain, monkeypatch) == plain


@pytest.mark.parametrize("name,value", [("NO_COLOR", ""), ("NO_COLOR", "1"),
                                        ("TERM", "dumb")])
def test_colour_is_off_when_the_environment_says_so(monkeypatch, name, value):
    """``NO_COLOR`` counts however it is set, including empty — that is the
    convention. Wrapping is a separate question and stays on."""
    monkeypatch.setenv(name, value)
    monkeypatch.setenv("COLUMNS", "70")
    assert terminal.colour_enabled(_Stream(tty=True)) is False
    lines = terminal.present(LONG, _Stream(tty=True)).split("\n")
    assert len(lines) > 1 and not any("\033[" in line for line in lines)


def test_colour_is_off_for_a_pipe_however_friendly_the_environment_is():
    assert terminal.colour_enabled(_Stream(tty=False)) is False


# -- the compile render's domain-channel twin ----------------------------------


def _twinned() -> GroundingReport:
    """What the compiler records for a sentence it could not translate: the
    same message on the promise's own domain channel and on the compile
    channel."""
    message = ("promises.md:121: 'Changes must be reviewed.' — no promise "
               "block — the sentence was not translated")
    report = GroundingReport()
    report.add(Verdict("unverified", "sec:iam", "untranslated-review", 0, message))
    report.add(Verdict("unverified", "sec:compile", "untranslated-review", 0,
                       message))
    report.add(Verdict("grounded", "sec:compile", "no-public-principals", 0,
                       "promises.md:37: 'No binding may include allUsers.'"))
    return report


def test_the_human_compile_render_prints_the_twinned_sentence_once():
    rendered = PolicyReport(_twinned(), CAPTURED).render()
    assert rendered.count("the sentence was not translated") == 1
    # And it is the COMPILE channel that survives: that is the channel the
    # whole render is about.
    assert "[sec:compile] promises.md:121" in rendered
    assert "[sec:iam]" not in rendered


def test_the_json_document_keeps_both_channels_and_so_do_the_counts():
    """The two channels exist so a consumer can filter on either one. Nothing
    is dropped from the document, and the header's four buckets still count
    every verdict — suppression is a rendering rule, not a verdict rule."""
    policy = PolicyReport(_twinned(), CAPTURED)
    document = json.loads(policy.render(format="json"))
    kinds = sorted(v["kind"] for v in document["verdicts"])
    assert kinds == ["sec:compile", "sec:compile", "sec:iam"]
    assert policy.summary()["unverified"] == 2
    assert "unverified=2" in policy.render().splitlines()[0]


def test_a_domain_verdict_with_no_compile_twin_still_prints():
    """The rule is "the same sentence twice", not "any sec: verdict": a verify
    run has no compile channel at all and must lose nothing."""
    report = GroundingReport()
    report.add(Verdict("unverified", "sec:iam", "untranslated-review", 0,
                       "the sentence was not translated"))
    rendered = PolicyReport(report, CAPTURED).render()
    assert "[sec:iam] the sentence was not translated" in rendered


def test_a_same_kind_repeat_is_not_a_twin():
    """Two verdicts on the SAME channel are two facts, not a twin — only the
    domain-channel echo of a compile verdict is suppressed."""
    report = GroundingReport()
    for _ in range(2):
        report.add(Verdict("unverified", "sec:compile", "p", 0, "same sentence"))
    assert PolicyReport(report, CAPTURED).render().count("same sentence") == 2


# -- staleness rolls up per source ---------------------------------------------


def _stale(key: str, category: str = "firewall_rules") -> BaselineEntry:
    return BaselineEntry(
        target=TargetRef(category=category, key=key, how="tf-address"),
        status="stale", key=key, scope="complete", source_id="tf-state",
        flags=("stale",), reason=baseline.STALE_REASON)


def test_three_stale_rows_from_one_source_are_one_verdict_that_counts_them():
    verdict = baseline.stale_verdict("tf-state", [_stale("a"), _stale("b"),
                                                  _stale("c")])
    assert verdict.status == "unverified"
    assert verdict.kind == "baseline:stale"
    # Targeted at the SOURCE, because that is whose age this is about.
    assert verdict.target == "tf-state"
    assert verdict.message.startswith("3 row(s) came from 'tf-state', which is "
                                      "past its age ceiling")
    for key in ("a", "b", "c"):
        assert key in verdict.message
    assert "[firewall_rules via tf-address]" in verdict.message


def test_the_key_list_is_capped_and_says_how_many_it_left_out():
    rows = [_stale(f"row-{index}") for index in range(9)]
    message = baseline.stale_verdict("tf-state", rows).message
    assert message.startswith("9 row(s) came from ")
    assert f"+{9 - baseline._STALE_KEY_CAP} more" in message


def test_a_clause_a_row_recorded_beside_the_staleness_one_is_carried_through():
    """The roll-up collapses a REPETITION. A row that also said something else
    keeps what it said."""
    extra = _stale("b")
    other = BaselineEntry(
        target=extra.target, status="stale", key="b", source_id="tf-state",
        flags=("stale", "opaque"),
        reason=f"{baseline.STALE_REASON}; the current 'rule' set is EMPTY")
    message = baseline.stale_verdict("tf-state", [_stale("a"), other]).message
    assert "the current 'rule' set is EMPTY" in message
    assert message.count("past its age ceiling") == 1
