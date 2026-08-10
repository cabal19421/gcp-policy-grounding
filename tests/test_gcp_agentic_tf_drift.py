"""TWO OVERLAPPING CURRENT-STATE VIEWS THAT DISAGREE, THROUGH THE WHOLE GATE.

Two sources exist so that they can disagree; the interesting question is what
the tool does about it. The answer this document commits to is FAIL-SAFE ON
DISAGREEMENT, HONEST IN REPORTING — report every source's answer, block if any
source that is ENTITLED to the finding says the change is dangerous, and never
let precedence silently suppress the other side. Every case below is one
terraform repo whose ``terraform.tfstate`` and whose merged estate snapshot
describe the SAME firewall rule differently.

THE SETUP, AND THE ONE PLACE IT DEVIATES FROM A LITERAL READING. The design
calls the two values "restricted" and "open". Here the open value is
``10.0.0.0/8 + 172.16.0.0/12`` — strictly WIDER than the restricted
``10.0.0.0/8`` and still entirely PRIVATE — and that is load-bearing rather than
cosmetic. ``0.0.0.0/0`` would make ``fw_checks.check_open_exposure`` and
``fw_estate``'s FINDING B fire ``contradicted`` on the PROPOSAL ALONE, in every
case, from the proposal tier, which reads neither current-state view. Case two
demands a hook exit of 0 on the same proposal document, so a public value makes
that case unachievable; and it would make case one's block come from a channel
that never looked at either source, i.e. vacuous. With a private-but-wider value
the proposal tier is quiet (:func:`test_the_proposal_tier_is_quiet_so_the_block_can_only_come_from_the_pair`)
and every exit code below is attributable to the pair/drift channel this module
is about.

THE TWO ARMS THAT DO NOT REACH THEIR DESIGNED OUTCOME, and why they are landed
as strict-xfailed spec literals rather than softened: ``ESC-TX-TFDRIFT-001`` and
``ESC-TX-TFDRIFT-002`` in :mod:`tests.escalations`. Both are the same measured
product gap — no source configured through the CLI can declare itself
``complete`` where the engine reads a source's own scope — and the register
entry carries the measurement. House rule 4: escalate, do not route around.

WHAT IS REUSED. The temp terraform repo, its probes, the shared hook argv and
the scripted-turn helper come from :mod:`tests.agentic.tfrepo`; the hook runner
and the outcome assertions from :mod:`tests.agentic.hookrunner` and
:mod:`tests.agentic.asserts`; the scripted agent from
:mod:`tests.agentic.fake_agent`. The only bytes this module commits are the six
small documents under ``tests/fixtures/gcp/agentic/tf/drift/``: four firewall
RECORDS (the API side of each case, and the two volatile twins) and two
``google_compute_firewall`` bodies (what the agent writes). Every input the gate
sees is therefore a reviewable committed document plus a named difference.

NO SKIPS, EVER. z3 and the registered firewall pair check are both capabilities
that can be absent, so :data:`HAVE_PAIR_CHECK` is a behavioural module-level
bool and every case BRANCHES on it, asserting the honest degraded shape instead
of vanishing.

SUBPROCESSES: SIX, all through the shared hook runner so the session-wide
ceiling accounts for them, all taken once in one module-scoped fixture, and the
count itself is asserted. The design's budget is eight. Every verdict-level
assertion goes through the IN-PROCESS grounding helper :func:`report_of`, which
costs no spawn at all.
"""

from __future__ import annotations

import contextlib
import io
import ipaddress
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import pytest

from gcp_grounding import cli, compare, drift, gate, provenance, registry
from tests.agentic import env, hookrunner, tfrepo
from tests.agentic.asserts import assert_blocked, assert_passed
from tests.agentic.fake_agent import FakeAgent
from tests.agentic.hookrunner import bound_subprocess_budget  # noqa: F401

#: The one estate row every case is about. It is the row the base corpus's
#: ``.gcp-grounding.json`` already names as ``main.tf.json``'s target, so the
#: two views are compared against each other over a counterpart the config file
#: — not this module — identified.
KEY = "projects/acme-prod/global/firewalls/allow-internal-ssh"

#: The committed fixtures. Records first (the API side and the value the state
#: file is regenerated to carry), then the two proposal bodies.
DRIFT_DIR = env.AGENTIC / "tf" / "drift"
RECORD_FIXTURES = ("firewall_restricted", "firewall_open",
                   "firewall_volatile_left", "firewall_volatile_right")
PROPOSAL_FIXTURES = ("proposal_open", "proposal_benign")

#: The terraform resource whose ``source_ranges`` the two views disagree about,
#: in the config, in the state and in the proposal.
RESOURCE_TYPE = "google_compute_firewall"
RESOURCE_NAME = "allow_ssh"

#: The verdict kind the registered VPC firewall widening check emits. Read from
#: nothing: it is a string the product owns and this module quotes, and the
#: behavioural probe below is what stops it being quoted after it moved.
PAIR_KIND = "firewall_pair"

#: The clause :func:`gcp_grounding.engine._apply_baseline_soundness` appends
#: when a ``contradicted`` came from a view that was not entitled to it. Case
#: two's whole point.
PARTIAL_BASELINE = "NOT a block: the baseline came from"
NOT_ENTITLED = "cannot tell a real widening from a row that view never saw"

#: What the per-source re-run brands its verdicts with.
PER_SOURCE = "[per-source: "

#: The exact number of children this module is allowed to spawn. The design
#: allows eight.
MAX_SPAWNS = 6


# -- the capability probe ------------------------------------------------------

# BEHAVIOURAL, not a presence check. `registry.pair_check` answering with a
# callable is only half the question: `fw_checks.check_packet_set_pair` degrades
# to one honest `unverified` with no z3, in which case BOTH views answer the
# same thing, no `drift:verdict` is minted and this module's headline assertion
# would be about a comparison that never ran. Both halves, in one bool, computed
# inside a try/except that can never raise at import.
try:
    HAVE_PAIR_CHECK = bool(env.HAVE_Z3) and registry.pair_check("firewall_rule") is not None
except Exception:                                   # noqa: BLE001 — never break collection
    HAVE_PAIR_CHECK = False


# -- the cases, declared -------------------------------------------------------


@dataclass(frozen=True)
class Case:
    """One built repo: which committed record each current-state view holds,
    which body the agent writes, and the flags the run carries."""

    #: The record fixture the merged estate SNAPSHOT (the API view) holds.
    api: str
    #: The record fixture whose ``source_ranges`` the STATE FILE is regenerated
    #: to carry. One committed value, two artifact shapes.
    state: str
    #: The ``google_compute_firewall`` body the scripted agent writes.
    proposal: str
    #: A SECOND snapshot source, merged with ``--merge-source``: the record
    #: fixture it holds for :data:`KEY`, or "" for none.
    mirror: str = ""
    #: That second source's DECLARED coverage, written as a real sidecar, or ""
    #: for a source that arrives unattributed.
    mirror_scope: str = ""
    #: Extra argv for both the in-process report and the hook run.
    extra: tuple[str, ...] = ()
    #: Extra argv for the hook run alone, or ``None`` for "spend no spawn".
    hook: tuple[str, ...] | None = None
    #: Which built repo this case runs in. Two cases sharing a repo differ only
    #: in flags, which is what makes case three provably the SAME input.
    repo: str = ""


#: ``--abstain-notes`` is how an exit-0 hook run says anything at all: the
#: default hook contract is silence on a passing run (see
#: ``tests/test_gcp_agentic_tf_benign.py``), so a case that must show a finding
#: on an exit-0 run has to turn the channel on. Case four deliberately does NOT,
#: because byte-empty is exactly what it asserts.
NOTES = ("--abstain-notes",)

CASES: dict[str, Case] = {
    # CASE ONE — terraform-safe, API-dangerous.
    "api_dangerous": Case(api="firewall_restricted", state="firewall_open",
                          proposal="proposal_open", hook=NOTES,
                          repo="api_dangerous"),
    # CASE THREE — the SAME repo and the same agent turn, graded differently.
    "api_dangerous_block": Case(api="firewall_restricted", state="firewall_open",
                                proposal="proposal_open",
                                extra=("--drift-policy", "block"), hook=(),
                                repo="api_dangerous"),
    # CASE TWO — the mirror: the terraform view holds the restricted rule.
    "tf_dangerous": Case(api="firewall_open", state="firewall_restricted",
                         proposal="proposal_open", hook=NOTES,
                         repo="tf_dangerous"),
    # CASE TWO, THIRD ARM — plus an API source declared COMPLETE that holds the
    # restricted rule. Same repo, same agent turn, one more source.
    "tf_dangerous_complete": Case(api="firewall_open", state="firewall_restricted",
                                  proposal="proposal_open",
                                  mirror="firewall_restricted",
                                  mirror_scope="complete", hook=NOTES,
                                  repo="tf_dangerous"),
    # CASE FOUR — the state file regenerated to AGREE.
    "agree": Case(api="firewall_restricted", state="firewall_restricted",
                  proposal="proposal_benign", hook=(), repo="agree"),
    # CASE FIVE — two views differing ONLY in an etag and a fingerprint.
    "volatile": Case(api="firewall_volatile_left", state="firewall_restricted",
                     proposal="proposal_benign",
                     mirror="firewall_volatile_right", hook=None,
                     repo="volatile"),
    # CASE SIX — a benign edit to a resource that HAS drift.
    "drifted_benign": Case(api="firewall_restricted", state="firewall_open",
                           proposal="proposal_benign", hook=NOTES,
                           repo="drifted_benign"),
}

#: The distinct repos to build, in build order.
REPOS = ("api_dangerous", "tf_dangerous", "agree", "volatile", "drifted_benign")

#: ``repo name -> every case that runs in it``. Two cases may share a repo only
#: when they describe the same TREE and differ only in flags, which is what
#: makes case three provably the same input as case one and the third arm
#: provably the same input as case two.
_BY_REPO = {name: [case for case in CASES.values() if case.repo == name]
            for name in REPOS}

MIRROR_NAME = "api_mirror.json"


# -- building one case ---------------------------------------------------------


def record_fixture(stem: str) -> dict:
    """One committed firewall RECORD, as the API side stores it."""
    return json.loads((DRIFT_DIR / f"{stem}.json").read_text(encoding="utf-8"))


def proposal_fixture(stem: str) -> dict:
    """One committed ``google_compute_firewall`` body, as the agent writes it."""
    return json.loads((DRIFT_DIR / f"{stem}.json").read_text(encoding="utf-8"))


def build_repo(root: Path, cases: list[Case]) -> tfrepo.TfRepo:
    """The base corpus, with the API side taken from a drift-specific overlay
    and the state file regenerated to the other view's ``source_ranges``.

    Both current-state views end up describing :data:`KEY` differently, and both
    differences come from ONE committed value each — the record fixtures — so a
    reader can see what the two views say without reading Python.

    *cases* is every case that runs in this tree. They must AGREE about the tree
    (that is what makes "the same input, graded differently" a fact rather than
    a claim); each one's ``--merge-source`` snapshot is written here, so a case
    that names one always finds it.
    """
    first = cases[0]
    for other in cases[1:]:
        assert (other.api, other.state, other.proposal) == \
            (first.api, first.state, first.proposal), (
                f"cases sharing repo {first.repo!r} describe different trees, so "
                f"nothing downstream can call them the same input")
    repo = tfrepo.build_tf_repo(root)
    api_record = record_fixture(first.api)
    state_ranges = list(record_fixture(first.state)["source_ranges"])

    # THE API SIDE: the merged estate snapshot's firewall table, overlaid.
    tfrepo.variant(repo, tfrepo.SNAPSHOT_NAME,
                   lambda document: _put_record(document, api_record))
    # THE TERRAFORM SIDE: the same rule, in the state file's attribute shape.
    tfrepo.variant(repo, tfrepo.STATE_NAME,
                   lambda document: _put_state_ranges(document, state_ranges))

    mirrors = {(case.mirror, case.mirror_scope) for case in cases if case.mirror}
    assert len(mirrors) <= 1, (
        f"repo {first.repo!r} would need {len(mirrors)} different "
        f"{MIRROR_NAME} files; they share one path")
    for mirror, scope in mirrors:
        _write_mirror(repo, record_fixture(mirror), scope)
    return repo


def _put_record(document: Any, record: Mapping[str, Any]) -> None:
    document["firewall_rules"][KEY] = dict(record)


def _put_state_ranges(document: Any, ranges: list) -> None:
    found = 0
    for entry in document["resources"]:
        if entry["type"] == RESOURCE_TYPE and entry["name"] == RESOURCE_NAME:
            entry["instances"][0]["attributes"]["source_ranges"] = list(ranges)
            found += 1
    assert found == 1, (
        f"the base corpus no longer holds exactly one {RESOURCE_TYPE}."
        f"{RESOURCE_NAME} instance ({found} found) — the terraform view of "
        f"{KEY} is not what this module thinks it is")


def _write_mirror(repo: tfrepo.TfRepo, record: Mapping[str, Any],
                  scope: str) -> Path:
    """A SECOND snapshot source: the firewall table alone, with :data:`KEY`
    taken from *record*.

    With *scope* it carries a real ``gcp-source-ledger/1`` sidecar declaring
    itself an ``api`` capture at that coverage — which is the ONLY surface this
    codebase has for saying "this source enumerated the domain completely".
    Without one it arrives unattributed, which is what case five wants: a second
    view of the same rows, claiming nothing.
    """
    document = json.loads(repo.snapshot_path.read_text(encoding="utf-8"))
    table = dict(document["firewall_rules"])
    table[KEY] = dict(record)
    payload = {"captured_at": document["captured_at"], "firewall_rules": table}
    path = repo.root / MIRROR_NAME
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    if scope:
        builder = provenance.LedgerBuilder()
        builder.source("api-mirror", "api", origin="compute.firewalls.list",
                       captured_at=document["captured_at"], scope=scope)
        builder.declare("firewall_rules", scope=scope, source_kinds=("api",))
        for key in sorted(table):
            builder.fact("firewall_rules", key, source_id="api-mirror")
        builder.build().write(provenance.origins_path(path))
    return path


def case_argv(repo: tfrepo.TfRepo, case: Case) -> tuple[str, ...]:
    """The shared state/config/clock argv, plus this case's own flags."""
    extra: list[str] = list(case.extra)
    if case.mirror:
        extra += ["--merge-source", str(repo.root / MIRROR_NAME)]
    return tfrepo.hook_argv(repo, extra=extra)


# -- THE IN-PROCESS GROUNDING HELPER ------------------------------------------


@contextlib.contextmanager
def _scrubbed_env():
    """The child's own determinism, in this process: every name the hook runner
    removes from a spawned child is removed here too, so a developer's exported
    ``GCP_GROUNDING_SNAPSHOT`` or pinned clock cannot change a verdict on the
    in-process instrument either."""
    saved = {name: os.environ.pop(name)
             for name in hookrunner.SCRUBBED_ENV if name in os.environ}
    try:
        yield
    finally:
        os.environ.update(saved)


def report_of(repo: tfrepo.TfRepo, case: Case) -> dict:
    """THE VERDICT-LEVEL INSTRUMENT: the same ``cli.main`` the hook child runs,
    in NORMAL mode with ``--format json``, IN THIS PROCESS.

    The hook run proves the exit-code and stream contract; this proves the
    BUCKET, the KIND and the MESSAGE. It costs no subprocess, which is what
    keeps seven cases inside a six-spawn budget, and it grounds the same
    document through the same ``_ground`` the hook path uses — the terraform
    route, the assembled current state and the engine all included.
    """
    argv = ["verify-policy", str(repo.tf_json_path),
            "--snapshot", str(repo.snapshot_path), *case_argv(repo, case),
            "--format", "json"]
    out, err = io.StringIO(), io.StringIO()
    with _scrubbed_env(), contextlib.redirect_stdout(out), \
            contextlib.redirect_stderr(err):
        exit_code = cli.main(argv)
    assert exit_code in (0, 1), (
        f"report_of expected a verdict exit (0 or 1), got {exit_code}; 2 is a "
        f"usage error, not a verdict\nargv: {' '.join(argv)}\n{err.getvalue()}")
    try:
        return json.loads(out.getvalue())
    except ValueError as exc:
        raise AssertionError(
            f"the in-process grounding helper produced no report document "
            f"({exc})\nargv: {' '.join(argv)}\nstderr:\n{err.getvalue()}") from None


# -- reading a report ----------------------------------------------------------


def of_kind(report: Mapping, kind: str) -> list[dict]:
    return [v for v in report["verdicts"] if v["kind"] == kind]


def drifts(report: Mapping) -> list[dict]:
    """Every verdict of every drift kind — the whole family, never a prefix
    match, which would fold ``drift:unmanaged`` into ``drift``."""
    return [v for v in report["verdicts"] if v["kind"] in drift.DRIFT_KINDS]


def pair_verdicts(report: Mapping) -> list[dict]:
    """Every verdict the PAIR TIER produced for this run, whatever it decided.

    Both spellings, so an absent capability is measured rather than mistaken for
    an absent finding: the registered widening check's own kind, and the
    engine's "a counterpart resolved and no check is defined for it" abstention.
    """
    return [v for v in report["verdicts"]
            if v["kind"] in (PAIR_KIND, "pair:no-check")]


def row_material(report: Mapping) -> list[dict]:
    """The ``drift:material`` verdicts the ENGINE minted for :data:`KEY`.

    TWO CHANNELS CARRY THIS FAMILY and both are real: the engine's stage 6 mints
    one per conflicting BASELINE ENTRY, targeted at the row key, and
    ``sources.load_current`` mints its own per DISPUTE, targeted at
    ``<category>/<key>``. This selects the first; the count of the whole family
    is pinned separately so a third channel cannot appear unnoticed.
    """
    return [v for v in of_kind(report, drift.DRIFT_MATERIAL) if v["target"] == KEY]


def labels(repo: tfrepo.TfRepo) -> tuple[str, str]:
    """The two source labels every message names them by: the configured PATHS.

    Deliberately not "api" and "terraform": a finding an operator has to
    translate is a finding they cannot act on, and the path is what they open.
    """
    return str(repo.snapshot_path), str(repo.state_path)


def named_sources(message: str, *known: str) -> set[str]:
    return {label for label in known if label in message}


def assert_pair_degraded(report: Mapping) -> None:
    """The honest shape when the widening check cannot decide: the pair tier
    STILL SPOKE, and said why. BRANCH, NEVER SKIP — a case that vanished on a
    machine without z3 is a case nobody runs."""
    found = pair_verdicts(report)
    assert found, (
        "the pair tier produced no verdict at all; with no widening check "
        "available the honest answer is an abstention naming the reason, not "
        "silence")
    assert {v["status"] for v in found} == {"unverified"}, found
    assert any("z3 is not available" in v["message"]
               or "no widening check is defined" in v["message"] for v in found), \
        [v["message"] for v in found]


# -- the world, built once -----------------------------------------------------


@dataclass
class World:
    repos: dict = field(default_factory=dict)
    events: dict = field(default_factory=dict)
    reports: dict = field(default_factory=dict)
    outcomes: dict = field(default_factory=dict)
    spawns: int = 0


@pytest.fixture(scope="module")
def world(tmp_path_factory, subprocess_budget) -> World:
    """Every repo, every in-process report and the six hook outcomes, taken once.

    THE ORDER IS THE POSTTOOLUSE CONTRACT: the scripted agent's turn lands
    FIRST, so ``main.tf.json`` on disk is the edit under review by the time
    anything grounds it — the in-process report and the hook child then read the
    same bytes, which is what makes the two instruments comparable. One turn per
    REPO, because the cases sharing a repo share its edit.

    It binds the session budget ITSELF: ``bound_subprocess_budget`` is
    function-scoped, so it has not run when a module-scoped fixture spawns and
    these children would otherwise land on a private counter instead of the
    suite-wide ceiling.
    """
    built = World()
    for name in REPOS:
        cases = _BY_REPO[name]
        repo = build_repo(tmp_path_factory.mktemp(name), cases)
        built.repos[name] = repo
        agent = FakeAgent(repo.root, [tfrepo.proposal_for(
            repo, name, tfrepo.TF_JSON_NAME, _edited_document(repo, cases[0]),
            _expectation(cases[0]),
            rationale=f"{name}: an agent rewrites the allow_ssh rule in a repo "
                      f"whose two current-state views disagree about it")])
        _proposal, built.events[name] = agent.turn()

    previous = hookrunner.bind_budget(subprocess_budget)
    before = subprocess_budget.total
    try:
        for case_id, case in CASES.items():
            repo = built.repos[case.repo]
            built.reports[case_id] = report_of(repo, case)
            if case.hook is None:
                continue
            built.outcomes[case_id] = hookrunner.run_hook(
                built.events[case.repo], snapshot=repo.snapshot_path,
                extra_argv=case_argv(repo, case) + tuple(case.hook))
    finally:
        hookrunner.bind_budget(previous)
    built.spawns = subprocess_budget.total - before
    return built


def _edited_document(repo: tfrepo.TfRepo, case: Case) -> dict:
    """The whole ``main.tf.json`` as the agent leaves it: the committed
    configuration with ONE resource body replaced by a committed one."""
    document = json.loads(repo.tf_json_path.read_text(encoding="utf-8"))
    document["resource"][RESOURCE_TYPE][RESOURCE_NAME] = \
        proposal_fixture(case.proposal)
    return document


def _expectation(case: Case) -> str:
    """The bucket the gate is expected to put this turn in, which is what the
    scripted proposal records — and it is ADVISORY: nothing here asserts an
    outcome from it.

    It describes the turn under the DEFAULT policy, because one turn per repo is
    replayed under several flag sets and ``--drift-policy block`` is a grading
    choice made after the edit, not a property of it. ``abstain`` for the two
    disagreeing repos, because that is what the gate honestly does under the
    default: case two says so outright, and case one's designed ``block`` is
    carried by ``ESC-TX-TFDRIFT-001`` rather than claimed here.
    """
    return "abstain" if case.proposal == "proposal_open" else "pass"


# -- the committed corpus ------------------------------------------------------


def test_the_committed_fixtures_are_the_named_ones_and_describe_one_rule():
    """The inputs under review are the six named documents, and every one of
    them is about :data:`KEY`. A fixture that quietly grew a second rule, or a
    record that stopped being a firewall record, is a fixture problem and fails
    here rather than as six mysterious runs that stopped finding anything."""
    committed = sorted(p.stem for p in DRIFT_DIR.glob("*.json"))
    assert committed == sorted(RECORD_FIXTURES + PROPOSAL_FIXTURES), committed
    for stem in RECORD_FIXTURES:
        record = record_fixture(stem)
        assert record["direction"] == "INGRESS" and record["action"] == "allow"
        assert record["network"].endswith("/prod-vpc"), record["network"]
    for stem in PROPOSAL_FIXTURES:
        body = proposal_fixture(stem)
        assert body["name"] == KEY.rsplit("/", 1)[-1], body["name"]
        assert body["direction"] == "INGRESS"


def test_the_open_record_is_strictly_wider_and_still_private():
    """THE DEVIATION, PINNED. The open value must be a genuine widening — or
    every pair check in this module answers ``grounded`` twice and there is no
    disagreement left to report — and it must contain no public range, or the
    proposal tier blocks on its own and case two's exit 0 is unreachable.
    """
    restricted = set(record_fixture("firewall_restricted")["source_ranges"])
    opened = set(record_fixture("firewall_open")["source_ranges"])
    assert restricted < opened, (restricted, opened)
    assert opened == set(proposal_fixture("proposal_open")["source_ranges"]), (
        "the agent's edit must propose exactly the open view's value, or case "
        "one is not 'the agent widens to what terraform already believes'")
    for value in opened | restricted:
        assert ipaddress.ip_network(value).is_private, (
            f"{value!r} is not a private range; a public one makes "
            f"fw_checks.check_open_exposure fire on the PROPOSAL alone, in "
            f"every case, and case two's hook exit of 0 unreachable")


def test_the_benign_proposal_narrows_and_the_volatile_twins_differ_only_there():
    """Case four's and case six's edit is a narrowing (so the widening check has
    something to answer ``grounded`` about), and case five's two views really do
    differ — in the volatile fields and NOWHERE else. Without the second half
    that case asserts zero drift over two identical documents, which any
    implementation passes."""
    benign = [ipaddress.ip_network(v)
              for v in proposal_fixture("proposal_benign")["source_ranges"]]
    restricted = [ipaddress.ip_network(v)
                  for v in record_fixture("firewall_restricted")["source_ranges"]]
    assert benign and set(benign) != set(restricted)
    assert all(any(net.subnet_of(other) for other in restricted)
               for net in benign), (
        f"{[str(n) for n in benign]} is not a narrowing of "
        f"{[str(n) for n in restricted]}, so the benign cases are proposing a "
        f"widening and the pair check has a real finding to make")

    left = record_fixture("firewall_volatile_left")
    right = record_fixture("firewall_volatile_right")
    differing = {key for key in set(left) | set(right)
                 if left.get(key) != right.get(key)}
    assert differing == {"etag", "fingerprint"}, differing
    assert differing <= compare.VOLATILE_IGNORED, (
        f"{sorted(differing - compare.VOLATILE_IGNORED)} is not a field compare "
        f"ignores, so case five is asserting something else entirely")


def test_the_probe_is_a_bool_and_the_pair_kind_is_still_the_products():
    assert isinstance(HAVE_PAIR_CHECK, bool)
    if HAVE_PAIR_CHECK:
        from gcp_grounding import fw_checks

        assert registry.pair_check("firewall_rule") is fw_checks.check_packet_set_pair
    assert drift.DRIFT_MATERIAL in drift.DRIFT_KINDS
    assert drift.DRIFT_VERDICT in drift.DRIFT_KINDS


# -- CASE ONE: terraform-safe, API-dangerous -----------------------------------


def test_case_one_reports_both_values_of_the_one_field_that_differs(world):
    """ONE material drift for the row, naming BOTH source labels, BOTH values
    and the field. The gate reports every source's value and picks none."""
    report = world.reports["api_dangerous"]
    repo = world.repos["api_dangerous"]
    snapshot_label, state_label = labels(repo)

    material = row_material(report)
    assert len(material) == 1, [v["message"] for v in material]
    message = material[0]["message"]
    assert material[0]["status"] == "unverified", material[0]
    assert named_sources(message, snapshot_label, state_label) == \
        {snapshot_label, state_label}, message
    assert "source_ranges" in message, message
    assert "'10.0.0.0/8'" in message and "'172.16.0.0/12'" in message, message
    assert "picks none" in message, message

    # THE WHOLE FAMILY, counted: the engine's per-entry verdict and the
    # loader's own per-dispute one, and nothing else. A third channel appearing
    # would double-report every disagreement to the agent.
    whole = of_kind(report, drift.DRIFT_MATERIAL)
    assert len(whole) == 2, [(v["target"], v["message"][:80]) for v in whole]
    assert {v["target"] for v in whole} == {KEY, f"firewall_rules/{KEY}"}
    for verdict in whole:
        assert named_sources(verdict["message"], snapshot_label, state_label) == \
            {snapshot_label, state_label}, verdict["message"]


def test_case_one_answers_twice_and_never_collapses_to_one_answer(world):
    """TWO per-source pair verdicts, with DIFFERENT statuses, each naming its
    own source — and the anti-silence pin, asserted by COUNTING: the report does
    not contain exactly one pair verdict, because collapsing two readings into a
    single answer is precisely the failure mode this whole channel exists to
    prevent."""
    report = world.reports["api_dangerous"]
    repo = world.repos["api_dangerous"]
    snapshot_label, state_label = labels(repo)

    found = pair_verdicts(report)
    assert len(found) == 2, [v["message"] for v in found]
    assert len(found) != 1, "collapsing to a single answer IS the failure mode"

    if not HAVE_PAIR_CHECK:
        # Honest degradation: both sides still answered, and both said why they
        # could not decide — so the count above still means two readings.
        assert_pair_degraded(report)
        return

    assert len({v["status"] for v in found}) == 2, [
        (v["status"], v["message"][-120:]) for v in found]
    # Each message names ITS OWN source and only its own: a reader who cannot
    # tell which view said what has two answers and no way to use either.
    attributed = [named_sources(v["message"], snapshot_label, state_label)
                  for v in found]
    assert all(len(names) == 1 for names in attributed), \
        [v["message"] for v in found]
    assert attributed[0] != attributed[1], [v["message"] for v in found]
    # ... and exactly one of them is the per-source re-run, so the two verdicts
    # are the two TIERS talking about the same row rather than one tier twice.
    assert sum(PER_SOURCE in v["message"] for v in found) == 1, \
        [v["message"] for v in found]


def test_case_one_puts_the_disagreement_itself_on_the_record(world):
    """One ``drift:verdict``: the same check, two answers, and the gate says so
    instead of choosing."""
    report = world.reports["api_dangerous"]
    if not HAVE_PAIR_CHECK:
        # With no decidable widening check both views answer `unverified`, so
        # there is no disagreement to report and its ABSENCE is the honest
        # state — asserted, so the case cannot pass by being empty.
        assert of_kind(report, drift.DRIFT_VERDICT) == []
        assert_pair_degraded(report)
        return
    disagreement = of_kind(report, drift.DRIFT_VERDICT)
    assert len(disagreement) == 1, [v["message"] for v in disagreement]
    assert disagreement[0]["target"] == KEY
    assert "ONE CHECK, TWO ANSWERS" in disagreement[0]["message"]
    assert "picking neither" in disagreement[0]["message"]
    assert "never which finding is true" in disagreement[0]["message"]


def test_the_proposal_tier_is_quiet_so_the_block_can_only_come_from_the_pair(world):
    """THE ANTI-VACUITY PIN for every exit code in this module.

    The proposal tier reads the document and the vocabulary and NEITHER
    current-state view. If it fired here, case one would "block on the
    disagreement" while actually blocking on a rule shape, and case two's exit 0
    would be unreachable for a reason that has nothing to do with drift.
    """
    for case_id in ("api_dangerous", "tf_dangerous", "drifted_benign"):
        report = world.reports[case_id]
        hard = [v for v in report["verdicts"]
                if v["status"] in ("contradicted", "ungrounded")
                and v["kind"] not in drift.DRIFT_KINDS]
        assert hard == [], (case_id, [(v["kind"], v["message"][:120])
                                      for v in hard])


@pytest.mark.xfail(
    strict=True,
    reason=("ESC-TX-TFDRIFT-001: no source configured through the CLI can "
            "declare itself 'complete' where the engine reads a source's own "
            "scope, so the API view's `contradicted` is always rewritten to "
            "`unverified` and the run cannot reach exit 2"),
)
def test_case_one_blocks_on_its_complete_source_finding(world):
    """THE SPEC LITERAL, landed under a strict xfail per house rule 4.

    "a not-ok report and a hook exit of 2, meaning the dangerous reading wins
    the GATE decision while both readings win the REPORT" — the REPORT half is
    asserted for real by the three tests above; this is the GATE half.
    """
    assert world.reports["api_dangerous"]["ok"] is False
    assert world.outcomes["api_dangerous"].exit_code == 2


def test_case_one_shows_both_readings_to_the_agent(world):
    """What the run DOES deliver through the envelope, asserted rather than
    assumed: both readings, on the agent-visible stream, with stdout untouched.

    This is the half of case one that survives ``ESC-TX-TFDRIFT-001``, and it is
    the half the design calls "both readings win the REPORT".
    """
    outcome = world.outcomes["api_dangerous"]
    repo = world.repos["api_dangerous"]
    snapshot_label, state_label = labels(repo)
    assert outcome.stdout == "", str(outcome)
    assert "NOT DECIDED" in outcome.stderr, str(outcome)
    assert f"[{drift.DRIFT_MATERIAL}]" in outcome.stderr, str(outcome)
    assert snapshot_label in outcome.stderr and state_label in outcome.stderr, \
        str(outcome)
    if HAVE_PAIR_CHECK:
        assert f"[{drift.DRIFT_VERDICT}]" in outcome.stderr, str(outcome)


# -- CASE TWO: the mirror ------------------------------------------------------
#
# THE DISTINCTION THAT IS EASY TO GET BACKWARDS, and the reason it is spelled
# out here rather than left to the assertions: an earlier phrasing of this
# document said the gate "blocks regardless", which reads as stronger and is the
# more attractive wrong answer. It is not what happens and must not be. A
# terraform source is structurally at most `partial`, the widening check is
# `requires_complete` by default, and engine stages 3 and 6 both rewrite such a
# `contradicted` to `unverified` naming the partial source. Blocking here would
# be a FALSE BLOCK on a view that was never entitled to the finding — the agent
# is told its change is dangerous on the authority of a source that cannot see
# the rows it is reasoning about. So: the finding is REPORTED in full (case one
# and case two are identical in that respect, which is the real invariant of the
# pair) and the GATE DECISION follows soundness, not fidelity ranking.


def test_case_two_reports_both_sides_exactly_as_case_one_does(world):
    """The mirror image, and the reporting is symmetric: one material drift for
    the row naming both labels and both values, two per-source pair verdicts,
    one ``drift:verdict``."""
    report = world.reports["tf_dangerous"]
    repo = world.repos["tf_dangerous"]
    snapshot_label, state_label = labels(repo)

    material = row_material(report)
    assert len(material) == 1, [v["message"] for v in material]
    message = material[0]["message"]
    assert named_sources(message, snapshot_label, state_label) == \
        {snapshot_label, state_label}, message
    assert "'10.0.0.0/8'" in message and "'172.16.0.0/12'" in message, message

    found = pair_verdicts(report)
    assert len(found) == 2, [v["message"] for v in found]
    if not HAVE_PAIR_CHECK:
        assert_pair_degraded(report)
        assert of_kind(report, drift.DRIFT_VERDICT) == []
        return
    assert len({v["status"] for v in found}) == 2, [
        (v["status"], v["message"][-120:]) for v in found]
    disagreement = of_kind(report, drift.DRIFT_VERDICT)
    assert len(disagreement) == 1, [v["message"] for v in disagreement]


def test_case_two_softens_the_terraform_side_and_says_which_source(world):
    """THE PARTIAL-BASELINE ASYMMETRY, applied and visible: the terraform-side
    finding is present, it is ``unverified``, and its message names the source
    whose coverage disentitled it. Present, because suppressing it would be the
    silence this module is about; ``unverified``, because blocking on it would
    be the false block."""
    report = world.reports["tf_dangerous"]
    repo = world.repos["tf_dangerous"]
    _snapshot_label, state_label = labels(repo)
    if not HAVE_PAIR_CHECK:
        assert_pair_degraded(report)
        return
    from_terraform = [v for v in pair_verdicts(report)
                      if state_label in v["message"]]
    assert len(from_terraform) == 1, [v["message"] for v in from_terraform]
    verdict = from_terraform[0]
    assert verdict["status"] == "unverified", verdict
    assert PARTIAL_BASELINE in verdict["message"], verdict["message"]
    assert NOT_ENTITLED in verdict["message"], verdict["message"]
    assert state_label in verdict["message"], verdict["message"]


def test_case_two_does_not_block_and_still_shows_the_finding(world):
    """Exit 0 under the default annotate policy, WITH the finding on the
    agent-visible stream. Both halves matter: exit 0 alone would be a gate that
    saw nothing, and the finding alone would not say whether it blocked."""
    outcome = world.outcomes["tf_dangerous"]
    repo = world.repos["tf_dangerous"]
    snapshot_label, state_label = labels(repo)
    assert outcome.exit_code == 0, str(outcome)
    assert outcome.stdout == "", str(outcome)
    assert "NOT DECIDED" in outcome.stderr, str(outcome)
    assert f"[{drift.DRIFT_MATERIAL}]" in outcome.stderr, str(outcome)
    assert snapshot_label in outcome.stderr and state_label in outcome.stderr, \
        str(outcome)
    if HAVE_PAIR_CHECK:
        assert PARTIAL_BASELINE in outcome.stderr, str(outcome)


def test_the_third_arm_adds_a_complete_source_and_still_reports_every_side(world):
    """THE THIRD ARM: the same input plus an API source that covers the firewall
    domain COMPLETELY and holds the restricted rule.

    Three views now describe the row, and all three answers reach the report —
    which is the invariant that holds whatever the gate decides. Whether the
    complete source's finding SURVIVES is the strict-xfailed half below.
    """
    report = world.reports["tf_dangerous_complete"]
    repo = world.repos["tf_dangerous"]
    mirror_label = str(repo.root / MIRROR_NAME)
    snapshot_label, state_label = labels(repo)

    material = row_material(report)
    assert len(material) == 1, [v["message"] for v in material]
    assert mirror_label in material[0]["message"], material[0]["message"]

    found = pair_verdicts(report)
    if not HAVE_PAIR_CHECK:
        assert_pair_degraded(report)
        return
    assert len(found) == 3, [v["message"] for v in found]
    seen = {label for verdict in found
            for label in named_sources(verdict["message"], snapshot_label,
                                       state_label, mirror_label)}
    assert seen == {snapshot_label, state_label, mirror_label}, sorted(seen)
    assert len(of_kind(report, drift.DRIFT_VERDICT)) == 1


@pytest.mark.xfail(
    strict=True,
    reason=("ESC-TX-TFDRIFT-002: `sources.LoadedSource.record()` flattens every "
            "configured source's own scope to 'undeclared', so "
            "`engine._source_scope` never sees the sidecar's 'complete' and the "
            "per-source `contradicted` is always rewritten"),
)
def test_the_complete_api_source_arm_blocks(world):
    """THE SPEC LITERAL, landed under a strict xfail per house rule 4.

    "configure an API source that also covers the firewall domain COMPLETELY
    and holds the restricted rule, and assert the same disagreement now produces
    a surviving `contradicted` and exit 2".
    """
    report = world.reports["tf_dangerous_complete"]
    surviving = [v for v in pair_verdicts(report) if v["status"] == "contradicted"]
    assert surviving, [v["status"] for v in pair_verdicts(report)]
    assert report["ok"] is False
    assert world.outcomes["tf_dangerous_complete"].exit_code == 2


# -- CASE THREE: the same finding, graded differently --------------------------


def test_block_mode_changes_the_bucket_and_not_one_byte_of_the_message(world):
    """``--drift-policy block`` over the SAME repo and the SAME agent turn: the
    material drift becomes ``contradicted`` and its message is byte-identical,
    so an operator can see it is the same finding graded differently rather than
    a second, different one."""
    annotated = of_kind(world.reports["api_dangerous"], drift.DRIFT_MATERIAL)
    blocked = of_kind(world.reports["api_dangerous_block"], drift.DRIFT_MATERIAL)
    assert len(annotated) == len(blocked) == 2, (len(annotated), len(blocked))
    for before, after in zip(annotated, blocked):
        assert before["status"] == "unverified", before
        assert after["status"] == "contradicted", after
        assert before["kind"] == after["kind"] == drift.DRIFT_MATERIAL
        assert before["target"] == after["target"]
        assert before["message"] == after["message"], (
            "block mode rewrote the message as well as the bucket, so the two "
            "runs no longer read as one finding graded twice")
    # The disagreement verdict is NOT escalated: `drift:material` is the only
    # kind the design lets become `contradicted`.
    if HAVE_PAIR_CHECK:
        escalated = of_kind(world.reports["api_dangerous_block"],
                            drift.DRIFT_VERDICT)
        assert [v["status"] for v in escalated] == ["unverified"], escalated
    assert world.reports["api_dangerous_block"]["ok"] is False


def test_block_mode_blocks_through_the_hook_envelope(world):
    """In process this is ``report.ok`` going False; through the envelope it is
    the editor agent's blocking exit code plus the rendered report on the stream
    the hook runner feeds back. Nothing else in this module pins that the second
    follows from the first."""
    outcome = world.outcomes["api_dangerous_block"]
    repo = world.repos["api_dangerous"]
    assert_blocked(outcome, "source_ranges", KEY)
    assert str(repo.state_path) in outcome.stderr, str(outcome)
    assert str(repo.snapshot_path) in outcome.stderr, str(outcome)


# -- CASE FOUR: agreement is silence -------------------------------------------


def test_agreeing_sources_produce_no_drift_and_one_pair_verdict(world):
    """THE BUDGET TEST for the whole feature: a drift channel that fires when
    the sources agree is noise, and noise is what gets a guardrail switched off.

    Zero drift verdicts of any kind, exactly ONE pair verdict — one baseline,
    one answer, no per-source re-run — and a byte-empty passing hook run.
    """
    report = world.reports["agree"]
    assert drifts(report) == [], [(v["kind"], v["message"][:100])
                                  for v in drifts(report)]
    found = pair_verdicts(report)
    assert len(found) == 1, [v["message"] for v in found]
    if HAVE_PAIR_CHECK:
        assert found[0]["status"] == "grounded", found[0]
        assert PER_SOURCE not in found[0]["message"], found[0]["message"]
    else:
        assert_pair_degraded(report)
    assert report["ok"] is True, report["summary"]
    assert_passed(world.outcomes["agree"])


# -- CASE FIVE: volatile fields yield no FieldDiff at all ----------------------


def test_two_views_differing_only_in_volatile_fields_drift_about_nothing(world):
    """``compare.VOLATILE_IGNORED``, end to end.

    Those fields must yield NO ``FieldDiff`` AT ALL, not merely a benign one: a
    benign classification would emit one ``drift`` verdict per field, and two
    views of one unchanged resource would produce a wall of etag noise on every
    single run.

    THE SECOND VIEW IS A SNAPSHOT SOURCE AND NOT THE TERRAFORM ONE, measured
    rather than preferred: the terraform mappers carry no ``etag`` and no
    ``fingerprint`` into a fact record at all, so a terraform-versus-API pair can
    only ever present them as an ABSENCE — and merge step 7 leaves absence to
    step 8, so nothing would reach ``compare`` and the case would pass without
    exercising anything. ``tests/test_gcp_drift_matrix.py`` drives its benign arm
    through two same-kind views for exactly this reason. The terraform state is
    still configured and still agrees.
    """
    report = world.reports["volatile"]
    assert drifts(report) == [], [(v["kind"], v["message"][:140])
                                  for v in drifts(report)]
    assert report["ok"] is True, report["summary"]

    # NON-VACUITY, in two directions. The two views really do differ, and the
    # comparison really can see a difference when there is one to see.
    left = record_fixture("firewall_volatile_left")
    right = record_fixture("firewall_volatile_right")
    assert left["etag"] != right["etag"]
    assert left["fingerprint"] != right["fingerprint"]
    assert compare.compare("firewall_rules", left, right) == (), \
        compare.compare("firewall_rules", left, right)
    control = compare.compare("firewall_rules", left,
                              dict(right, source_ranges=["0.0.0.0/0"]))
    assert [(d.field, d.severity) for d in control] == \
        [("source_ranges", compare.MATERIAL)], control


def test_the_volatile_case_really_merged_two_views_of_the_row(world):
    """The zero-drift assertion above is only worth its line if two sources
    genuinely described the row: a second source that failed to load would make
    it pass forever while proving nothing."""
    repo = world.repos["volatile"]
    mirror = repo.root / MIRROR_NAME
    assert mirror.is_file()
    document = json.loads(mirror.read_text(encoding="utf-8"))
    assert document["firewall_rules"][KEY]["etag"] == \
        record_fixture("firewall_volatile_right")["etag"]
    primary = json.loads(repo.snapshot_path.read_text(encoding="utf-8"))
    assert primary["firewall_rules"][KEY]["etag"] == \
        record_fixture("firewall_volatile_left")["etag"]
    # ... and the run really read it: a source that contributed nothing is one
    # `state:source` verdict, and there is none.
    report = world.reports["volatile"]
    assert of_kind(report, "state:source") == [], \
        [v["message"] for v in of_kind(report, "state:source")]
    assert any(str(mirror) in v["message"]
               for v in of_kind(report, "provenance")), \
        [v["message"] for v in of_kind(report, "provenance")]


# -- CASE SIX: a drift on an otherwise clean file ------------------------------


def test_a_drift_on_a_passing_file_is_still_shown_to_the_agent(world):
    """THE PIN for the always-report change: without it a drift on an otherwise
    clean file is invisible to the agent, which is the same as not detecting it.

    The file's own verdicts are all fine, so its status is ``ok`` and the run's
    ``ok`` stays True — and the drift line is STILL in the gate's findings, with
    the run's risk raised to ``low``.
    """
    repo = world.repos["drifted_benign"]
    checker = gate.PolicyGroundingGate(str(repo.snapshot_path),
                                       discover_config=True)
    result = checker.check([str(repo.tf_json_path)], as_of=tfrepo.ASOF)

    assert result.ok is True, result.render()
    assert [f.status for f in result.files] == ["ok"], result.render()
    assert result.risk == "low", (
        f"a drift on an otherwise clean file must raise the run's risk to "
        f"'low' — 'none' means the agent is told nothing at all\n"
        f"{result.render()}")
    drift_lines = [line for line in result.findings()
                   if drift.DRIFT_MATERIAL in line or "differ between the "
                   "sources that describe it" in line]
    assert drift_lines, result.findings()
    assert any(KEY in line for line in drift_lines), drift_lines
    assert drift.DRIFT_MATERIAL in gate.ALWAYS_REPORT_KINDS


def test_the_drift_on_a_passing_file_reaches_hook_stderr_too(world):
    """The gate object is one consumer; the hook envelope is the one an agent
    actually reads. Exit 0 — nothing here fails the gate — with the finding on
    stderr all the same."""
    outcome = world.outcomes["drifted_benign"]
    repo = world.repos["drifted_benign"]
    snapshot_label, state_label = labels(repo)
    assert outcome.exit_code == 0, str(outcome)
    assert outcome.stdout == "", str(outcome)
    assert f"[{drift.DRIFT_MATERIAL}]" in outcome.stderr, str(outcome)
    assert KEY in outcome.stderr, str(outcome)
    assert snapshot_label in outcome.stderr and state_label in outcome.stderr, \
        str(outcome)


def test_the_benign_edit_really_is_benign_against_both_views(world):
    """Case six is only "a benign edit to a resource that HAS drift" if the edit
    is benign against BOTH readings. If it widened against either one, the drift
    line would be riding along with a real finding and the pin would be about
    something else."""
    report = world.reports["drifted_benign"]
    assert row_material(report), "case six lost its drift"
    if not HAVE_PAIR_CHECK:
        assert_pair_degraded(report)
        return
    found = pair_verdicts(report)
    assert len(found) == 2, [v["message"] for v in found]
    assert {v["status"] for v in found} == {"grounded"}, [
        (v["status"], v["message"][-140:]) for v in found]
    # Both answers agree, so there is nothing for `drift:verdict` to report —
    # asserted, because a disagreement verdict here would mean the two views
    # decided the same edit differently and the case is not what it says.
    assert of_kind(report, drift.DRIFT_VERDICT) == []


# -- cross-cutting -------------------------------------------------------------


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_no_case_asserts_which_source_was_preferred(world, case_id):
    """THE PROPERTY THE WHOLE MODULE IS ABOUT, stated as a run-time fact rather
    than only as a discipline: whichever source won, the OTHER one's reading is
    in the report too.

    Every case where two views disagree carries a verdict naming each of them.
    No assertion anywhere above says which document became primary, and this one
    would fail if a future precedence change made the losing side disappear.
    """
    report = world.reports[case_id]
    repo = world.repos[CASES[case_id].repo]
    snapshot_label, state_label = labels(repo)
    if not row_material(report):
        return          # the agreeing and volatile cases have nothing to report
    for label in (snapshot_label, state_label):
        assert any(label in v["message"] for v in report["verdicts"]), (
            f"{case_id}: no verdict names {label}, so one view's reading left "
            f"the report entirely")


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_every_case_grounds_the_terraform_configuration_it_was_given(world, case_id):
    """The floor under every assertion above: the run really ground THIS file as
    terraform. A ``.tf.json`` that was not recognized produces one "document
    kind was not recognized" abstention and no claim at all, which reads as a
    clean pass on every case here."""
    report = world.reports[case_id]
    repo = world.repos[CASES[case_id].repo]
    assert report["source"] == str(repo.tf_json_path), report["source"]
    assert not any("kind was not recognized" in v["message"]
                   for v in report["verdicts"]), report["summary"]
    grounded = [v for v in report["verdicts"] if v["status"] == "grounded"]
    assert grounded, (
        f"{case_id}: the run produced no grounded verdict at all, so nothing "
        f"was actually read out of the configuration")


def test_the_module_spends_six_spawns_and_no_more(world):
    """The declared budget, asserted rather than estimated. The design allows
    eight; every one of these goes through the shared hook runner, so the
    session-wide ceiling accounts for them."""
    assert sum(1 for case in CASES.values() if case.hook is not None) == MAX_SPAWNS
    assert world.spawns == MAX_SPAWNS, world.spawns
