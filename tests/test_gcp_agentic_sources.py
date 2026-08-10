"""THE MERGE, PRECEDENCE AND DRIFT FLAGS THROUGH THE REAL HOOK ENVELOPE.

``tests/test_gcp_drift_matrix.py`` and ``tests/test_gcp_cli_state.py`` both drive
``cli.main`` IN PROCESS. Neither runs the real hook with a fake agent, so
nothing anywhere pins that these notes and blocks survive the hook envelope —
the one surface an agent actually sees. Four cases do that here, each a real
child process reading a real PostToolUse event produced by a real fake-agent
edit, with the merge flags in the hook argv.

WHAT IS REUSED, AND THE ONE THING THAT COULD NOT BE. The hook runner and the
outcome assertions come from :mod:`tests.agentic.hookrunner` and
:mod:`tests.agentic.asserts`, the scripted agent from
:mod:`tests.agentic.fake_agent`, and the CURRENT-STATE SIDE is the five
committed two-source fixtures in ``tests/fixtures/gcp/drift/`` — no sixth estate
is committed here, and the only file this module adds under
``tests/fixtures/gcp/agentic/sources/`` is the PAYLOAD the agent writes.

The terraform repo builder from ``tests/agentic/tfrepo.py`` is deliberately NOT
used, and the reason is a property of the fixtures rather than a preference:
that corpus and ``tests/fixtures/gcp/agentic_estate_overlay.json`` model the
AGENTIC estate (``.../firewalls/allow-internal-ssh``, ``deny-external-rdp``),
while the drift fixtures are keyed to ``tests/fixtures/gcp/estate_snapshot.json``
(``.../firewalls/allow-internal``, ``deny-ssh-external``). The two key sets are
DISJOINT, so merging the repo's ``terraform.tfstate`` into a run whose primary is
the estate snapshot yields a wall of ``drift:key-mismatch`` and
``drift:unmanaged`` and NOT ONE material field dispute — precisely the finding
every case below is about. Reusing the drift fixtures and reusing that repo are
mutually exclusive; this module keeps the fixtures, because they are what carries
the behaviour under test, and builds its own three-flag argv, which is small
enough to read in one line (:func:`hook_argv`).

THE SECRET INJECTION, and why the cross-cutting assertion is not vacuous. The
committed drift fixtures carry no secret, so "no secret from any merged source
reaches either stream" would assert nothing over them as they stand. Every case
therefore merges a DERIVED copy of a committed fixture — the fixture plus its
sidecar, with one ``private_key`` attribute (a name
:func:`gcp_grounding.redact.is_sensitive_segment` calls sensitive) carrying a
unique plaintext, injected into one firewall record. It rides on ONE side only,
which merge step 7 reads as an ABSENCE rather than a differing value, so it
changes no verdict — and case one, which is byte-quiet with it present, is the
proof of that rather than an assumption.

NO ``HAVE_Z3`` BRANCH, and it is pinned rather than assumed: the payload carries
no ``condition``, so no CEL formula is ever built for it
(:func:`test_the_payload_is_benign_by_construction`), and every current-state
verdict this module reads is minted by ``merge``/``drift``, which the solver
backend does not touch. The one capability that CAN be absent — a ``cli`` whose
parser has not learned the state flags — is a behavioural probe
(:data:`HAVE_MERGE_FLAGS`), and the cases BRANCH on it rather than skipping.

SUBPROCESSES: SIX, all through the shared hook runner so the session-wide
ceiling accounts for them, all taken once in one module-scoped fixture, and the
count itself is asserted (:func:`test_the_module_spends_six_spawns_and_no_more`).
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
from pathlib import Path

import pytest

from gcp_grounding import drift, merge, provenance, redact
from gcp_grounding.knowledge import GcpSnapshot
from tests.agentic import env, hookrunner
from tests.agentic.asserts import assert_blocked, assert_passed
from tests.agentic.fake_agent import FakeAgent, Proposal
from tests.agentic.hookrunner import bound_subprocess_budget  # noqa: F401

#: The estate the committed drift fixtures describe. It is the PRIMARY of every
#: run here, exactly as it is in ``tests/test_gcp_drift_matrix.py`` — the two
#: sides of a two-source case have to describe one estate or they disagree about
#: everything and about nothing.
ESTATE = env.FIXTURES / "estate_snapshot.json"

#: The five committed two-source fixtures. Two of them are merged below; the set
#: is named so a fixture that disappears fails here instead of downstream.
DRIFT_DIR = env.FIXTURES / "drift"
DRIFT_FIXTURES = ("tf_agree", "tf_benign", "tf_dangerous", "tf_partial", "tf_stale")

#: The one document this module commits: the benign edit all four cases make.
PAYLOAD_DIR = env.AGENTIC / "sources"
PAYLOAD = PAYLOAD_DIR / "benign_iam_policy.json"

#: The pinned clock. Both fixtures are captured 2026-07-17/18, so this is inside
#: the default seven-day freshness ceiling and no staleness verdict is minted —
#: a run without a pinned clock would grow one as the wall clock moved.
NOW = "2026-07-19T00:00:00Z"

#: The rule the two material disagreements are about.
DENY = "projects/acme-prod/global/firewalls/deny-ssh-external"
WORLD = "projects/acme-prod/global/firewalls/allow-ssh-world"

#: The injected attribute and its plaintext. The NAME is what makes the value a
#: secret to this codebase; the value is unique so a leak cannot be confused with
#: a fixture string that legitimately appears somewhere.
SECRET_ATTRIBUTE = "private_key"
SECRET_VALUE = "tx-agentic-sources-hook/never-print-me/3f9c1d7e5b204a86"

#: The substring every material FIELD disagreement carries, in every case, under
#: every precedence — this document's headline invariant made assertable.
FIELD_FINDING = "disagree about 'disabled'"

#: What ``require-agreement`` adds and no other precedence does.
ESCALATION = "precedence 'require-agreement' requires the sources to agree"

#: The exact number of children this module is allowed to spawn.
MAX_SPAWNS = 6


# -- the capability probe ------------------------------------------------------

# BEHAVIOURAL, not an import check, for the reason ``tfrepo.HAVE_STATE_FLAG``
# gives: ``gcp_grounding.cli`` can be perfectly importable with the state flags
# absent, and that is exactly the world in which this module's argv would be
# refused by argparse and every hook run would fail OPEN — exit 0, byte-empty
# streams — turning four real findings into four green tests. argparse leaves
# through ``SystemExit`` (a BaseException) and prints usage on the way, so both
# are caught and the stream is swallowed.
try:
    from gcp_grounding.cli import build_parser as _build_parser

    with contextlib.redirect_stderr(io.StringIO()):
        _build_parser().parse_args(
            ["verify-policy", "--hook", "--snapshot", "s.json",
             "--merge-source", "tf.json", "--completeness", "complete",
             "--precedence", merge.DEFAULT_PRECEDENCE,
             "--drift-policy", drift.DEFAULT_DRIFT_POLICY,
             "--as-of", NOW, "--no-config"])
    HAVE_MERGE_FLAGS = True
except (Exception, SystemExit):
    HAVE_MERGE_FLAGS = False


# -- the four cases, declared ---------------------------------------------------

#: ``case id -> (fixture, extra hook argv)``. One entry per spawn, so the budget
#: is readable as a table rather than counted by hand.
CASES = {
    "agree": ("tf_agree", ()),
    "drift_quiet": ("tf_dangerous", ()),
    "drift_notes": ("tf_dangerous", ("--abstain-notes",)),
    "drift_block": ("tf_dangerous", ("--drift-policy", "block")),
    "require_agreement": ("tf_dangerous", ("--precedence", "require-agreement")),
    "fidelity_wins": ("tf_dangerous",
                      ("--precedence", "highest-fidelity-wins", "--abstain-notes")),
}


def hook_argv(source: Path, extra=()) -> tuple[str, ...]:
    """THE ONE argv shape every case passes to the hook runner.

    ``--snapshot`` is deliberately absent: it is the hook runner's own parameter.
    ``--completeness complete`` is how the primary is DECLARED a complete
    enumeration without a sidecar of its own — the same explicit override
    ``test_gcp_drift_matrix.py`` uses for its swapped-sides case — and it is what
    makes a terraform-only key an existence dispute rather than silence.
    ``--no-config`` keeps the run from walking up out of a temp directory into
    whatever a developer has on disk above it.
    """
    return ("--merge-source", str(source), "--completeness", "complete",
            "--as-of", NOW, "--no-config") + tuple(str(part) for part in extra)


def salted_source(work: Path, name: str) -> Path:
    """A committed drift fixture, plus its committed sidecar, copied into *work*
    with one secret injected into its first firewall record.

    DERIVED, never a sixth committed estate: the bytes under review stay the five
    reviewable fixtures, and the difference is one named attribute this module
    puts there on purpose. The sidecar is copied too — without it the source
    would fall back to an unattributed ledger, which changes both the coverage it
    declares and the locator every dispute quotes.
    """
    committed = DRIFT_DIR / f"{name}.json"
    document = json.loads(committed.read_text(encoding="utf-8"))
    record = document["firewall_rules"][sorted(document["firewall_rules"])[0]]
    record[SECRET_ATTRIBUTE] = SECRET_VALUE
    derived = work / f"{name}.json"
    derived.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                       encoding="utf-8")
    shutil.copyfile(provenance.origins_path(committed),
                    provenance.origins_path(derived))
    return derived


def proposal(case_id: str, payload) -> Proposal:
    """The benign edit, as one scripted ``Write`` turn."""
    return Proposal(
        id=case_id, kind="iam", tool_name="Write", rel_path="policy.json",
        payload=payload, expect="pass",
        rationale=f"{case_id}: an agent grants the data-eng group project "
                  f"viewer alongside the BigQuery read it already has")


# -- the six runs, taken once ---------------------------------------------------


@pytest.fixture(scope="module")
def runs(tmp_path_factory, subprocess_budget):
    """``case id -> (HookOutcome, merged source path)`` for all six spawns, plus
    the spawn delta under the key ``spawns``.

    It binds the session budget ITSELF: ``bound_subprocess_budget`` is
    function-scoped, so it has not run when a module-scoped fixture spawns, and
    these children would otherwise be counted against a private fallback counter
    instead of the suite-wide ceiling.

    Empty when :data:`HAVE_MERGE_FLAGS` is False — with no state flags in the
    parser there is nothing to spawn that would mean anything, and every case
    below BRANCHES on that rather than skipping.
    """
    if not HAVE_MERGE_FLAGS:
        return {}
    document = json.loads(PAYLOAD.read_text(encoding="utf-8"))
    previous = hookrunner.bind_budget(subprocess_budget)
    before = subprocess_budget.total
    outcomes = {}
    try:
        for case_id, (fixture, extra) in CASES.items():
            work = tmp_path_factory.mktemp(case_id)
            source = salted_source(work, fixture)
            agent = FakeAgent(work / "repo", [proposal(case_id, document)])
            _proposal, event = agent.turn()
            outcomes[case_id] = (
                hookrunner.run_hook(event, snapshot=ESTATE,
                                    extra_argv=hook_argv(source, extra)),
                source)
    finally:
        hookrunner.bind_budget(previous)
    outcomes["spawns"] = subprocess_budget.total - before
    return outcomes


def inert(runs) -> bool:
    """True when this checkout's parser has no state flags, so every case is
    honestly INERT rather than passing. BRANCH, NEVER SKIP."""
    if runs:
        return False
    assert not HAVE_MERGE_FLAGS, (
        "the merge flags parse, so the six runs should have been taken")
    return True


def streams(runs, case_id: str) -> str:
    """Both of one run's streams, concatenated — for the assertions that are
    about what reached the AGENT rather than about which stream it reached."""
    outcome, _source = runs[case_id]
    return outcome.stdout + outcome.stderr


# -- the corpus this module stands on -------------------------------------------


def test_the_committed_two_source_fixtures_are_the_five_named_ones():
    """No sixth estate: the current-state side of every case is a file
    ``tx-drift-matrix`` already committed and already asserts the behaviour of."""
    committed = sorted(p.stem for p in DRIFT_DIR.glob("*.json")
                       if not p.name.endswith(".origins.json"))
    assert committed == sorted(DRIFT_FIXTURES), committed
    for name in DRIFT_FIXTURES:
        assert Path(provenance.origins_path(DRIFT_DIR / f"{name}.json")).is_file()
    # ... and the fixture directory this module DOES add holds payloads alone.
    # A snapshot here would be that sixth estate arriving by the back door.
    for path in sorted(PAYLOAD_DIR.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        assert "captured_at" not in document, (
            f"{path.name} carries a capture stamp, so it is an ESTATE SNAPSHOT "
            f"and not a payload an agent writes — the current-state side of "
            f"these cases is the committed drift corpus")


def test_the_payload_is_benign_by_construction():
    """The benign edit is benign because every name in it is IN the estate, not
    because a run happened to come back clean.

    Read against ``estate_snapshot.json`` — the primary these runs actually
    ground against — and NOT through the session ``estate_snapshot`` fixture,
    which serves the agentic estate and would answer about a different vocabulary
    than the one every case here uses.

    The absent ``condition`` is the second half: with no CEL there is no formula
    for z3 to decide, which is why nothing in this module branches on the solver
    backend.
    """
    document = json.loads(PAYLOAD.read_text(encoding="utf-8"))
    snapshot = GcpSnapshot.load(ESTATE)
    roles = snapshot.roles or {}
    principals = snapshot.principals or ()
    for binding in document["bindings"]:
        assert binding["role"] in roles, binding["role"]
        assert "condition" not in binding, (
            "a CEL condition would make this module's outcomes depend on the "
            "solver backend, and none of its assertions branches on one")
        for member in binding["members"]:
            assert member in principals, member


def test_the_two_material_disagreements_are_in_the_committed_fixture():
    """The dangerous fixture disagrees with the estate about a SECURITY FIELD and
    carries a rule the complete estate does not — the two shapes cases two, three
    and four are about. Pinned here so a fixture edit fails as a fixture problem
    rather than as four mysterious hook runs that stopped finding anything."""
    estate = json.loads(ESTATE.read_text(encoding="utf-8"))["firewall_rules"]
    dangerous = json.loads((DRIFT_DIR / "tf_dangerous.json")
                           .read_text(encoding="utf-8"))["firewall_rules"]
    assert estate[DENY]["disabled"] is False
    assert dangerous[DENY]["disabled"] is True
    assert WORLD in dangerous and WORLD not in estate


# -- case one: AGREEING SOURCES ARE BYTE-QUIET ---------------------------------


def test_agreeing_sources_are_byte_quiet_through_the_hook(runs):
    """THE BUDGET TEST, and it comes first: a drift channel that fires on
    agreement is a drift channel that gets switched off.

    The agreeing terraform view is merged in, the agent's benign edit lands, and
    the hook exits 0 with BOTH streams byte-empty — no provenance note, no
    unmanaged aggregate, no coverage chatter. Every one of those verdicts exists
    and is ``unverified``, which is exactly why the default hook contract is
    silence: the ignorance is on the record without being in the agent's context.
    """
    if inert(runs):
        return
    outcome, _source = runs["agree"]
    assert_passed(outcome)


# -- case two: MATERIAL DRIFT UNDER THE DEFAULT POLICY -------------------------


def test_material_drift_annotates_and_never_blocks(runs):
    """``annotate`` is the default and it never blocks: the materially
    disagreeing source produces exit 0, and — the half that must be asserted in
    both directions rather than assumed — the drift line is ABSENT from stderr
    without ``--abstain-notes`` and PRESENT with it.

    Asserting only the present direction would pass just as well against a hook
    that printed drift unconditionally, which is the change that quietly ends the
    default-silence contract case one depends on.
    """
    if inert(runs):
        return
    quiet, _source = runs["drift_quiet"]
    noted, _source = runs["drift_notes"]

    # ABSENT: exit 0 with both streams byte-empty, on the SAME input that the
    # abstain channel below shows carries two material findings.
    assert_passed(quiet)
    assert FIELD_FINDING not in quiet.stderr, str(quiet)
    assert drift.DRIFT_MATERIAL not in quiet.stderr, str(quiet)

    # PRESENT: exit 0 still — annotate never blocks — with the finding on the
    # agent-visible stream under the NOT DECIDED header, and stdout untouched.
    assert noted.exit_code == 0, str(noted)
    assert noted.stdout == "", (
        f"the abstain channel writes to stderr alone; stdout stays byte-empty so "
        f"the structured-output option stays available\n{noted}")
    assert "NOT DECIDED" in noted.stderr, str(noted)
    assert f"[{drift.DRIFT_MATERIAL}]" in noted.stderr, str(noted)
    assert FIELD_FINDING in noted.stderr, str(noted)
    assert "'False' against 'True'" in noted.stderr, str(noted)
    assert f"firewall_rules/{DENY}" in noted.stderr, str(noted)


# -- case three: DRIFT POLICY BLOCK --------------------------------------------


def test_drift_policy_block_blocks_through_the_hook_envelope(runs):
    """The identical input under ``--drift-policy block`` exits 2 with the
    material drift on stderr and stdout byte-empty.

    In process this is ``report.ok`` going False; through the envelope it is the
    editor agent's blocking code plus the rendered report on the stream the hook
    runner feeds back to the agent. Nothing else in the suite pins that the
    second follows from the first.
    """
    if inert(runs):
        return
    outcome, _source = runs["drift_block"]
    assert_blocked(outcome, FIELD_FINDING, f"firewall_rules/{DENY}")
    # BOTH material disagreements are escalated, not merely the first one found:
    # 'block' turns the drift:material verdicts into contradicted, and a count is
    # what distinguishes that from a single lucky match.
    assert "contradicted=2" in outcome.stderr, str(outcome)
    assert "MAY HAVE BEEN DESTROYED OR MOVED OUT OF BAND" in outcome.stderr, \
        str(outcome)


# -- case four: REQUIRE-AGREEMENT, END TO END ----------------------------------


def test_require_agreement_escalates_while_fidelity_still_reports(runs):
    """THE HEADLINE INVARIANT, end to end: precedence selects a VALUE, it never
    suppresses a FINDING.

    One disagreement, two precedences. Under ``require-agreement`` the hook exits
    2 with the escalation on stderr; under ``highest-fidelity-wins`` it exits 0 —
    and the same field disagreement is STILL reported. If precedence suppressed
    findings, the winning-value arm would be silent about the field it resolved,
    and an agent would be told the two views agreed.

    ``require-agreement`` has no end-to-end coverage anywhere else in the suite.
    """
    if inert(runs):
        return
    escalated, _source = runs["require_agreement"]
    resolved, _source = runs["fidelity_wins"]

    assert_blocked(escalated, ESCALATION, FIELD_FINDING)
    assert f"firewall_rules/{DENY}" in escalated.stderr, str(escalated)
    # The escalation is ONE contradiction — the material field dispute — and the
    # key is kept: dropping it would let the merged view prove an absence that is
    # not proven.
    assert "contradicted=1" in escalated.stderr, str(escalated)
    assert "the key is KEPT" in escalated.stderr, str(escalated)

    # The SAME pair, resolved rather than escalated: exit 0, and the finding is
    # still on the record.
    assert resolved.exit_code == 0, str(resolved)
    assert ESCALATION not in resolved.stderr, (
        f"only 'require-agreement' escalates; 'highest-fidelity-wins' resolves\n"
        f"{resolved}")
    assert FIELD_FINDING in resolved.stderr, (
        f"precedence selected a value and SUPPRESSED the finding — the one thing "
        f"this document promises it never does\n{resolved}")
    assert "under precedence 'highest-fidelity-wins'" in resolved.stderr, \
        str(resolved)

    # And the finding is the same finding under both, not two different ones that
    # happen to share a phrase.
    for outcome in (escalated, resolved):
        assert FIELD_FINDING in outcome.stderr and DENY in outcome.stderr


# -- cross-cutting --------------------------------------------------------------


@pytest.mark.parametrize("case_id", list(CASES))
def test_no_secret_from_a_merged_source_reaches_either_stream(runs, case_id):
    """Every case, both streams. A merged source's records are quoted verbatim by
    the drift messages — that is the point of them — so a record carrying a
    secret-named attribute is exactly where one would escape."""
    if inert(runs):
        return
    assert SECRET_VALUE not in streams(runs, case_id), (
        f"{case_id}: the injected {SECRET_ATTRIBUTE} plaintext reached a stream "
        f"the agent reads\n{runs[case_id][0]}")


@pytest.mark.parametrize("case_id", list(CASES))
def test_the_injected_secret_is_really_in_the_merged_source(runs, case_id):
    """The assertion above is only worth its line if the secret was genuinely in
    the input: a stale injection that stopped landing would make it pass forever
    while proving nothing."""
    if inert(runs):
        return
    _outcome, source = runs[case_id]
    document = json.loads(source.read_text(encoding="utf-8"))
    carried = [key for key, record in document["firewall_rules"].items()
               if record.get(SECRET_ATTRIBUTE) == SECRET_VALUE]
    assert len(carried) == 1, (
        f"{case_id}: the merged source {source} carries the secret in "
        f"{len(carried)} record(s); the injection no longer lands")
    assert redact.is_sensitive_segment(SECRET_ATTRIBUTE), (
        f"{SECRET_ATTRIBUTE!r} is no longer a name this codebase treats as "
        f"sensitive, so the leak assertion is watching the wrong attribute")


@pytest.mark.parametrize("case_id", ["drift_block", "require_agreement"])
def test_a_blocked_run_leaves_stdout_byte_empty(runs, case_id):
    """A finding on stdout would block the edit while telling the agent nothing:
    the hook runner feeds stderr back, and stdout is reserved for the structured
    channel that has not landed yet."""
    if inert(runs):
        return
    outcome, _source = runs[case_id]
    assert outcome.exit_code == 2, str(outcome)
    assert outcome.stdout == "", str(outcome)
    assert outcome.stderr, str(outcome)


def test_the_module_spends_six_spawns_and_no_more(runs):
    """The declared budget, asserted rather than estimated. Every one of them
    goes through the shared hook runner, so the session-wide ceiling accounts for
    them."""
    if inert(runs):
        return
    assert len(CASES) == MAX_SPAWNS, sorted(CASES)
    assert runs["spawns"] == MAX_SPAWNS, runs["spawns"]
