"""Channel discipline and the honest floors under the assertion helpers.

Every case here is a FABRICATION: an outcome/report pair that is not evidence
of what it claims to be, handed to the helper that is supposed to reject it.
Each one was accepted by ``tests/agentic/asserts.py`` before this module
landed — see the run recorded in the task notes — so each assertion below is a
test that failed first.

Three shapes of fabrication:

* AN INCIDENTAL VOCABULARY HIT. Every ``terraform show -json`` document emits
  one ``resource_type_ref`` claim per resource, so a ``grounded resource_type``
  verdict is free for the asking — it says the *provider* knows the type, never
  that the adversarial proposal was judged. :data:`INCIDENTAL_KINDS` keeps
  those two kinds out of every family's candidate set, so the channel helpers
  cannot see them at all; the property is structural rather than a rule an
  author has to remember.
* AN ABSTAIN THAT ABSTAINED ABOUT SOMETHING ELSE. Exit 0 with byte-empty
  stdout is the CLI's "this file is not mine to judge" early return, byte for
  byte, so the outcome side alone proves nothing: the report has to be about
  the file the event named, it has to say *why*, and its summary has to agree
  with its own verdict list.
* A BLOCK THAT BLOCKED NOTHING. Exit 2 is also argparse's usage-error code, so
  a usage error, an ImportError traceback and byte-empty stderr all read as a
  successful block to a substring-free ``assert_blocked``.

The module spawns nothing: the reports are synthetic and the outcomes are
constructed :class:`~tests.agentic.hookrunner.HookOutcome` records, because
what is under test is the *helper*, not the gate.
"""

from __future__ import annotations

import pytest

from tests.agentic.asserts import (
    FAMILY_KINDS,
    INCIDENTAL_KINDS,
    assert_abstained,
    assert_abstained_on_channel,
    assert_blocked,
    assert_decided_on_channel,
    assert_no_verdictless_pass,
    channel,
)
from tests.agentic.hookrunner import HookOutcome

ARGV = ("python", "-m", "gcp_grounding", "verify-policy", "--hook")

#: The file the event names and the report is about, when the two agree.
EDITED = "/estate/proposal.policy.json"

#: The six adversarial families the design names. Parametrizing over
#: ``FAMILY_KINDS`` alone would go quietly green if an entry were dropped.
NAMED_FAMILIES = ("iam", "network", "vpcsc", "orgpolicy", "abstain", "secreq")


# -- synthetic outcomes and reports -------------------------------------------


def outcome(*, exit_code=0, stdout="", stderr="", file_path=None) -> HookOutcome:
    """A :class:`HookOutcome` with no spawn behind it.

    *file_path* builds the PostToolUse event; leaving it None models
    :func:`~tests.agentic.hookrunner.run_hook_raw`, whose ``event`` is None
    because there may be no mapping to record.
    """
    event = None if file_path is None else {"tool_input": {"file_path": file_path}}
    return HookOutcome(exit_code=exit_code, stdout=stdout, stderr=stderr,
                       argv=ARGV, event=event)


def verdict(status: str, kind: str, message: str = "a reason", target: str = "t") -> dict:
    return {"status": status, "kind": kind, "target": target, "message": message,
            "suggestions": []}


def report(*verdicts, source: str = EDITED, summary=None) -> dict:
    """A ``gcp-grounding-report/1`` document over *verdicts*.

    *summary* defaults to the counts the verdicts actually support; passing one
    explicitly is how the summary-disagrees fabrication is built.
    """
    counts = {"grounded": 0, "ungrounded": 0, "contradicted": 0, "unverified": 0}
    for entry in verdicts:
        counts[entry["status"]] += 1
    return {
        "schema": "gcp-grounding-report/1",
        "ok": counts["ungrounded"] == 0 and counts["contradicted"] == 0,
        "backend": "builtin",
        "captured_at": "2026-07-25T08:00:00Z",
        "source": source,
        "summary": counts if summary is None else summary,
        "verdicts": list(verdicts),
    }


#: The message every incidental verdict carries, so a needle can be aimed at
#: it: a helper that searched the WHOLE verdict list would find it.
INCIDENTAL_MESSAGE = "module.x: resource_type 'google_compute_firewall'"


def incidental(status: str) -> dict:
    """The whole fabrication in one document: the gate looked at a terraform
    plan, said something about the provider's resource type, and judged the
    proposal NOT AT ALL.

    One per status, because each status is a different way to be discharged by
    accident — ``grounded`` fakes a decision, ``unverified`` fakes an
    abstention, and an uncaptured ``resource_types`` category really does emit
    the latter for every terraform document there is.
    """
    return report(verdict(status, "resource_type", INCIDENTAL_MESSAGE,
                          target="google_compute_firewall"))


#: All four statuses at once, for the candidate-set assertion.
INCIDENTAL_ONLY = report(*[verdict(status, "resource_type", INCIDENTAL_MESSAGE,
                                   target="google_compute_firewall")
                           for status in ("grounded", "ungrounded",
                                          "contradicted", "unverified")])


# -- the channel is a set, and the incidental kinds are outside every one -----


def test_the_incidental_kinds_are_the_two_the_design_names():
    assert INCIDENTAL_KINDS == frozenset({"resource_type", "resource_type_ref"})


def test_no_family_owns_an_incidental_kind():
    """The structural property the whole mechanism rests on."""
    assert set().union(*FAMILY_KINDS.values()) & INCIDENTAL_KINDS == frozenset()


def test_every_named_family_is_registered():
    """A family that forgot to register would otherwise raise KeyError only at
    the moment its own suite ran, which is too late to be a design property."""
    assert set(NAMED_FAMILIES) <= set(FAMILY_KINDS)


@pytest.mark.parametrize("family", NAMED_FAMILIES)
def test_the_incidental_hit_is_not_even_a_candidate(family):
    assert channel(INCIDENTAL_ONLY, family=family) == []


@pytest.mark.parametrize("family", NAMED_FAMILIES)
@pytest.mark.parametrize("status", ["grounded", "ungrounded", "contradicted",
                                    "unverified"])
def test_an_incidental_hit_decides_nothing_for_any_family(family, status):
    """The report carries a verdict of exactly the requested status, and the
    needle is aimed at its message: a helper computing over the whole verdict
    list would find both. ``match`` pins WHICH assertion fires, so satisfying
    the count from the whole list and then failing the needle would not pass
    for the right reason."""
    with pytest.raises(AssertionError, match=r"verdict on the .* channel"):
        assert_decided_on_channel(outcome(exit_code=2, stderr="FAILED"),
                                  incidental(status), family=family,
                                  status=status, needles=(INCIDENTAL_MESSAGE,))


@pytest.mark.parametrize("family", NAMED_FAMILIES)
def test_an_incidental_hit_is_not_an_abstention_for_any_family(family):
    """An uncaptured ``resource_types`` category emits exactly this verdict for
    every terraform document, so it is the free abstention a family assertion
    must not be able to spend."""
    with pytest.raises(AssertionError,
                       match=r"nothing on the .* channel abstained"):
        assert_abstained_on_channel(outcome(), incidental("unverified"),
                                    family=family,
                                    needles=(INCIDENTAL_MESSAGE,))


def test_an_unregistered_family_cannot_quietly_opt_out():
    """No ``.get`` default: a new family gets a KeyError, not an empty channel
    that vacuously satisfies nothing."""
    for call in (
        lambda: channel(INCIDENTAL_ONLY, family="brand_new_domain"),
        lambda: assert_decided_on_channel(outcome(), INCIDENTAL_ONLY,
                                          family="brand_new_domain",
                                          status="grounded"),
        lambda: assert_abstained_on_channel(outcome(), INCIDENTAL_ONLY,
                                            family="brand_new_domain",
                                            needles=("x",)),
    ):
        with pytest.raises(KeyError):
            call()


# -- the positive controls: the helpers are not merely always-raising ---------


def test_a_verdict_on_the_familys_own_kind_does_decide_it():
    blocked = outcome(exit_code=2, stderr="FAILED ...")
    decided = report(verdict("ungrounded", "role",
                             "bindings[0].role: role 'roles/bigquery.reader' "
                             "does not exist in the snapshot"))
    assert channel(decided, family="iam")
    assert_decided_on_channel(blocked, decided, family="iam", status="ungrounded",
                              needles=("roles/bigquery.reader",))


def test_an_abstention_on_the_familys_own_kind_is_an_abstention():
    abstained = report(verdict("unverified", "org_enforcement",
                               "spec.rules[0]: snapshot did not capture "
                               "org_policies — enforcement is undecidable"))
    assert_abstained_on_channel(outcome(file_path=EDITED), abstained,
                                family="orgpolicy",
                                needles=("did not capture org_policies",))


def test_a_needle_is_searched_on_the_channel_and_not_in_the_whole_report():
    """The needle names what the family's own verdict has to say. An
    incidental verdict quoting the same resource name is still incidental."""
    mixed = report(
        verdict("grounded", "firewall_exposure",
                "the proposal opens nothing new", target="allow-ssh"),
        verdict("grounded", "resource_type",
                "module.x: resource_type 'google_compute_firewall' exists",
                target="google_compute_firewall"))
    with pytest.raises(AssertionError, match="google_compute_firewall"):
        assert_decided_on_channel(outcome(), mixed, family="network",
                                  status="grounded",
                                  needles=("google_compute_firewall",))


def test_a_finding_on_the_channel_may_not_be_reported_as_a_silent_pass():
    """The one thing the *outcome* half contributes: a channel carrying an
    ungrounded verdict, paired with an exit-0 run that said nothing at all, is
    two halves of different runs."""
    decided = report(verdict("contradicted", "iam_escalation", "escalation path"))
    with pytest.raises(AssertionError, match="silent"):
        assert_decided_on_channel(outcome(), decided, family="iam",
                                  status="contradicted")


# -- assert_abstained: the three fabrications ---------------------------------


ABSTAIN_VERDICT = verdict("unverified", "document",
                          "/estate/other.json: nothing was checked",
                          target="/estate/other.json")


def test_an_abstain_about_another_file_is_not_this_files_abstain():
    """The broken-setup fail-open text, paired with an abstain report for a
    DIFFERENT file. Both halves are individually well-formed."""
    broken_setup = outcome(
        stderr="gcp-ground --hook: snapshot /nope: could not be read — "
               "nothing was checked (fail-open)",
        file_path=EDITED)
    elsewhere = report(ABSTAIN_VERDICT, source="/estate/other.json")
    with pytest.raises(AssertionError, match="a different file"):
        assert_abstained(broken_setup, elsewhere, "nothing was checked")


def test_an_abstain_that_names_no_reason_is_not_an_abstain():
    honest = report(ABSTAIN_VERDICT, source=EDITED)
    with pytest.raises(AssertionError, match="at least one substring"):
        assert_abstained(outcome(file_path=EDITED), honest)


def test_a_summary_that_disagrees_with_its_own_verdicts_is_not_evidence():
    """``summary`` is derived from ``verdicts``; a document where the two
    disagree was hand-built, and trusting the summary alone is how an empty
    verdict list passed as an abstention."""
    fabricated = report(source=EDITED,
                        summary={"grounded": 0, "ungrounded": 0,
                                 "contradicted": 0, "unverified": 1})
    with pytest.raises(AssertionError,
                       match="disagrees with its own verdict list"):
        assert_abstained(outcome(file_path=EDITED), fabricated,
                         "nothing was checked")


def test_the_strengthened_abstain_still_accepts_an_honest_one():
    honest = report(ABSTAIN_VERDICT, source=EDITED)
    assert_abstained(outcome(file_path=EDITED), honest, "nothing was checked")
    # run_hook_raw carries no event, so there is no path to cross-check against.
    assert_abstained(outcome(), honest, "nothing was checked")


# -- assert_blocked(expect_render=False): the three fabrications --------------


USAGE_ERROR = ("usage: gcp-ground verify-policy [-h] [--snapshot PATH] FILE\n"
               "gcp-ground verify-policy: error: unrecognized arguments: --bash-policy")
TRACEBACK = ("Traceback (most recent call last):\n"
             '  File "<frozen runpy>", line 198, in _run_module_as_main\n'
             "ImportError: No module named 'gcp_grounding.bash_mutation'")


@pytest.mark.parametrize("stderr, why", [
    (USAGE_ERROR, "usage:"),
    (TRACEBACK, "Traceback"),
    ("", "empty"),
])
def test_exit_two_alone_is_not_a_block(stderr, why):
    """Exit 2 is ALSO argparse's usage-error code, so the substring-free form
    accepted all three of these as successful blocks."""
    with pytest.raises(AssertionError, match="at least one substring"):
        assert_blocked(outcome(exit_code=2, stderr=stderr), expect_render=False)


@pytest.mark.parametrize("stderr, needle, match", [
    # Each `match` is text only the intended assertion emits — "usage:" and
    # "Traceback" themselves appear in the outcome dump attached to EVERY
    # message here, so matching on those would not tell the two floors apart.
    (USAGE_ERROR, "unrecognized arguments", "usage-error"),
    (TRACEBACK, "ImportError", "the child crashed"),
    ("", "anything", "byte-empty"),
])
def test_a_named_substring_does_not_rescue_a_crash_or_a_usage_error(
        stderr, needle, match):
    """The substring floor and the crash floor are separate: a caller who names
    a substring that happens to appear in a traceback still has no block."""
    with pytest.raises(AssertionError, match=match):
        assert_blocked(outcome(exit_code=2, stderr=stderr), needle,
                       expect_render=False)


def test_the_strengthened_block_still_accepts_the_two_honest_shapes():
    rendered = outcome(exit_code=2,
                       stderr="GCP policy grounding /x FAILED [z3]  grounded=0 "
                              "ungrounded=1\n  ✗ [role] bindings[0].role: ...")
    assert_blocked(rendered, "bindings[0].role")
    # The bash-mutation block renders no grounding report, so it is the
    # expect_render=False path — and it still has to say something.
    bash = outcome(exit_code=2,
                   stderr="gcp-ground: refusing 'gcloud projects add-iam-policy-binding' "
                          "— the role does not exist in the snapshot")
    assert_blocked(bash, "the role does not exist", expect_render=False)


# -- the retained floor, and what it may not be used for ----------------------


def test_the_verdictless_floor_documents_that_it_is_not_an_adversarial_one():
    """RETAINED for the benign and false-positive-budget families, FORBIDDEN as
    an adversarial floor. The docstring has to say so and has to name what
    enforces it, because the helper itself cannot."""
    doc = assert_no_verdictless_pass.__doc__ or ""
    assert "FORBIDDEN" in doc
    assert "per-family mutation contract" in doc
