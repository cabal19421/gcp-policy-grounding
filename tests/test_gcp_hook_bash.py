"""The hook's BASH arm, asserted through the real process boundary.

THE BYPASS THIS CLOSES. Every other family in this suite drives the gate with a
file the agent wrote, because that is what a file-based guardrail can see. An
agent that wants the same effect without being seen simply stops writing files::

    gcloud projects add-iam-policy-binding acme-prod \\
        --member=user:attacker@evil.example --role=roles/owner

Before this arm that command exited 0 in silence — no verdict, no stderr, no
record anywhere that it had been proposed. For an agentic threat model it is the
cheapest path around the guardrail, so it is the one worth closing first.

Three properties are asserted here, and they are deliberately separate.

*The exit code is a POLICY decision.* A recognized mutator exits 2 under the
default ``--bash-policy=block``, exits 0 under ``warn``, and is not even scanned
under ``off``. Nothing about that decision is a grounding verdict: the four-
bucket guard below asserts stderr says neither "ungrounded" nor "contradicted",
because the gate did not refute this command — it was unable to look at all.

*An unrecognized verb abstains.* ``gcloud compute instances frobnicate`` is
NOT DECIDED, exit 0, with the verb quoted on stderr. A classifier that blocked
on everything it did not recognize would be switched off within a day, and one
that silently passed would be lying about its coverage.

*The finding reaches a machine-readable record.* The hook renders to stderr and
exits; stderr is not an artifact anyone can query afterwards. ``gcp-ground
scan-command`` runs the same classifier and prints the same
``gcp-grounding-report/1`` document, so the tests below assert on parsed
structure — kind ``bash-mutation``, status ``unverified``, ``ok`` true — rather
than only on substrings, and CI has a record that someone tried.

Everything runs through :func:`tests.agentic.hookrunner.run_hook` with
:class:`~tests.agentic.fake_agent.FakeAgent` ``Bash`` proposals, so these are
real children with real exit codes.
"""

from __future__ import annotations

import json
import sys

import pytest

from gcp_grounding.cli import (
    BASH_POLICY_ENV,
    _BASH_POLICIES,
    _DEFAULT_BASH_POLICY,
    _hook_command,
)
from tests.agentic import hookrunner
from tests.agentic.asserts import assert_blocked, assert_passed, assert_recorded
from tests.agentic.fake_agent import TOOL_NAMES, FakeAgent, Proposal
from tests.agentic.hookrunner import (
    bound_subprocess_budget,  # noqa: F401 — autouse: bind spawns to the budget
    run_hook,
)

#: THE verified bypass: an owner grant to an external member, straight at the
#: API, touching no file the file arm could ever have seen.
OWNER_GRANT = ("gcloud projects add-iam-policy-binding acme-prod "
               "--member=user:attacker@evil.example --role=roles/owner")


# -- driving the arm ----------------------------------------------------------


def bash_event(workdir, command: str, *, id: str = "A20_gcloud_owner_grant",
               expect: str = "block", hook_event_name: str = "PostToolUse",
               rationale: str = "The agent takes the shortest path to the "
                                "outcome it was asked for: change the estate "
                                "directly instead of proposing a document.",
               ) -> dict:
    """One scripted ``Bash`` turn's event.

    A ``Bash`` proposal has no ``rel_path`` and writes nothing, so
    :meth:`FakeAgent.apply` is a no-op — the whole proposal lives in the event's
    ``tool_input.command``, which is exactly the surface this arm reads.
    """
    agent = FakeAgent(workdir, [Proposal(
        id=id, kind="iam", tool_name="Bash", rel_path="", payload=None,
        command=command, expect=expect, rationale=rationale,
        hook_event_name=hook_event_name)])
    _, event = agent.turn()
    return event


def run_scan_command(command: str, *, format: str = "json",
                     stdin: bool = False) -> hookrunner.HookOutcome:
    """``gcp-ground scan-command`` through the same boundary as the hook.

    Spawned via :func:`tests.agentic.hookrunner._spawn` rather than a bare
    ``subprocess.run`` so this module's children are counted against the one
    suite-wide spawn budget like every other child in the suite.
    """
    argv = [sys.executable, "-m", "gcp_grounding", "scan-command",
            "--command", "-" if stdin else command, "--format", format]
    payload = command.encode("utf-8") if stdin else b""
    return hookrunner._spawn(argv, payload)


# -- A20: the verified bypass -------------------------------------------------


def test_A20_gcloud_owner_grant_is_blocked(agent_workdir, estate_snapshot_path):
    """The headline case. ``expect_render=False``: this block renders no
    *grounding* report, because nothing was grounded — the stderr is a policy
    decision about a command, and the report's own PASSED/counts header would
    say the opposite."""
    outcome = run_hook(bash_event(agent_workdir, OWNER_GRANT),
                       snapshot=estate_snapshot_path)
    assert_blocked(outcome, "BLOCKED", "bash-mutation",
                   "add-iam-policy-binding", "roles/owner",
                   "user:attacker@evil.example", expect_render=False)
    assert outcome.exit_code == 2, str(outcome)
    assert outcome.stdout == "", str(outcome)


def test_the_block_is_a_policy_decision_not_a_fabricated_refutation(
        agent_workdir, estate_snapshot_path):
    """THE FOUR-BUCKET GUARD. The gate never looked at the estate here, so
    claiming the command is ungrounded or contradicted would be a lie told to
    justify a block it is entitled to make anyway. The bracketed kind is the
    positive half: the finding IS on the record, as ``bash-mutation``."""
    outcome = run_hook(bash_event(agent_workdir, OWNER_GRANT),
                       snapshot=estate_snapshot_path)
    assert outcome.exit_code == 2, str(outcome)
    assert "contradicted" not in outcome.stderr, str(outcome)
    assert "ungrounded" not in outcome.stderr, str(outcome)
    assert "[bash-mutation]" in outcome.stderr, str(outcome)


# -- the mutating table -------------------------------------------------------


MUTATING = [
    ("org_policy_disable_enforce",
     "gcloud resource-manager org-policies disable-enforce "
     "constraints/compute.requireOsLogin --project=acme-prod"),
    ("firewall_open_to_the_world",
     "gcloud compute firewall-rules create allow-all --allow=tcp:22 "
     "--source-ranges=0.0.0.0/0 --network=acme-prod-vpc"),
    ("armor_rule_at_priority_one",
     "gcloud compute security-policies rules create 1 "
     "--security-policy=edge-waf --action=allow --src-ip-ranges=0.0.0.0/0"),
    ("perimeter_update",
     "gcloud access-context-manager perimeters update acme_prod "
     "--add-resources=projects/222222222222"),
    ("service_account_key",
     "gcloud iam service-accounts keys create key.json "
     "--iam-account=ci@acme-prod.iam.gserviceaccount.com"),
    ("terraform_auto_approve", "terraform apply -auto-approve"),
    ("gsutil_public_bucket",
     "gsutil iam ch allUsers:objectViewer gs://acme-prod-artifacts"),
    ("curl_set_iam_policy",
     "curl -X POST -d @body.json https://cloudresourcemanager.googleapis.com"
     "/v1/projects/acme-prod:setIamPolicy"),
]


@pytest.mark.parametrize("command", [c for _, c in MUTATING],
                         ids=[i for i, _ in MUTATING])
def test_every_mutating_shape_blocks(command, agent_workdir,
                                     estate_snapshot_path):
    """One per domain this expansion covers, each the shape a real agent would
    reach for. All eight block under the default policy."""
    outcome = run_hook(bash_event(agent_workdir, command, expect="block"),
                       snapshot=estate_snapshot_path)
    assert_blocked(outcome, "BLOCKED", "bash-mutation", expect_render=False)


# -- read-only and non-GCP: byte-silent ---------------------------------------


READ_ONLY = [
    "gcloud projects get-iam-policy acme-prod",
    "gcloud iam roles list --project=acme-prod",
    "terraform plan",
    "terraform show -json",
]


@pytest.mark.parametrize("command", READ_ONLY)
def test_a_read_only_command_passes_byte_silently(command, agent_workdir,
                                                  estate_snapshot_path):
    """Reading the estate is how an agent *avoids* guessing. Byte-empty stderr,
    not "exit 0 with a note": the hook's stderr lands in the agent's context."""
    outcome = run_hook(bash_event(agent_workdir, command, expect="pass"),
                       snapshot=estate_snapshot_path)
    assert_passed(outcome)


NON_GCP = [
    "pytest -q",
    "git commit -m 'update the policy'",
    "echo gcloud projects add-iam-policy-binding",
]


@pytest.mark.parametrize("command", NON_GCP)
def test_a_non_gcp_command_passes_byte_silently(command, agent_workdir,
                                                estate_snapshot_path):
    """THE FALSE-POSITIVE TRIPWIRE. Ordinary shell is the overwhelming majority
    of what an agent runs; a guardrail that fires on ``pytest -q`` — or on the
    word ``gcloud`` appearing inside an ``echo`` — is a guardrail that gets
    disabled, taking the real coverage with it."""
    outcome = run_hook(bash_event(agent_workdir, command, expect="pass"),
                       snapshot=estate_snapshot_path)
    assert_passed(outcome)


def test_an_unrecognized_verb_abstains_out_loud_and_does_not_block(
        agent_workdir, estate_snapshot_path):
    """NOT DECIDED, exit 0, with the verb quoted. An unknown verb is ignorance,
    and ignorance never fails this gate — but it does have to be audible, or the
    run is indistinguishable from one the classifier judged clean."""
    outcome = run_hook(
        bash_event(agent_workdir, "gcloud compute instances frobnicate acme-vm",
                   expect="abstain"),
        snapshot=estate_snapshot_path)
    assert outcome.exit_code == 0, str(outcome)
    assert outcome.exit_code != 2, str(outcome)  # it did NOT block
    assert outcome.stdout == "", str(outcome)
    assert "NOT DECIDED" in outcome.stderr, str(outcome)
    assert "frobnicate" in outcome.stderr, str(outcome)
    assert "bash-unrecognized" in outcome.stderr, str(outcome)
    assert "BLOCKED" not in outcome.stderr, str(outcome)


# -- --bash-policy ------------------------------------------------------------


def test_warn_reports_the_full_finding_and_exits_zero(agent_workdir,
                                                      estate_snapshot_path):
    """``warn`` is the escape hatch for a team that runs gcloud deliberately.
    It changes the exit code and one word of the headline — never the finding,
    which is the whole reason to run in this mode rather than ``off``."""
    outcome = run_hook(bash_event(agent_workdir, OWNER_GRANT),
                       snapshot=estate_snapshot_path,
                       extra_argv=("--bash-policy", "warn"))
    assert outcome.exit_code == 0, str(outcome)
    assert outcome.stdout == "", str(outcome)
    assert "WARNING" in outcome.stderr, str(outcome)
    assert "BLOCKED" not in outcome.stderr, str(outcome)
    for expected in ("bash-mutation", "add-iam-policy-binding", "roles/owner",
                     "user:attacker@evil.example"):
        assert expected in outcome.stderr, (
            f"expected {expected!r} in stderr\n{outcome}")


def test_off_does_not_scan_at_all(agent_workdir, estate_snapshot_path):
    """Byte-silent, like the feature is not installed — which is what ``off``
    means. Anything less would make the switch useless to whoever needs it."""
    outcome = run_hook(bash_event(agent_workdir, OWNER_GRANT),
                       snapshot=estate_snapshot_path,
                       extra_argv=("--bash-policy", "off"))
    assert_passed(outcome)


def test_the_environment_variable_sets_the_policy(agent_workdir,
                                                  estate_snapshot_path):
    """A hook is configured once, in a settings file, not per invocation — so
    the env var has to work or the flag is unreachable in practice."""
    outcome = run_hook(bash_event(agent_workdir, OWNER_GRANT),
                       snapshot=estate_snapshot_path,
                       env={BASH_POLICY_ENV: "warn"})
    assert outcome.exit_code == 0, str(outcome)
    assert "WARNING" in outcome.stderr, str(outcome)
    assert "add-iam-policy-binding" in outcome.stderr, str(outcome)


def test_the_flag_beats_the_environment(agent_workdir, estate_snapshot_path):
    """Precedence stated once, here: an explicit flag on the command line wins
    over an exported default."""
    outcome = run_hook(bash_event(agent_workdir, OWNER_GRANT),
                       snapshot=estate_snapshot_path,
                       extra_argv=("--bash-policy", "off"),
                       env={BASH_POLICY_ENV: "block"})
    assert_passed(outcome)


def test_an_unrecognized_environment_value_falls_back_to_block_with_a_note(
        agent_workdir, estate_snapshot_path):
    """Never a usage error. This arm exists because a fail-closed argv hole is
    how the bypass stayed open; turning a stale exported variable into exit 2
    would reopen it from the other side, failing every tool call in the session
    until someone noticed. So: one note, then the safe default."""
    outcome = run_hook(bash_event(agent_workdir, OWNER_GRANT),
                       snapshot=estate_snapshot_path,
                       env={BASH_POLICY_ENV: "nonsense"})
    assert outcome.exit_code == 2, str(outcome)
    assert BASH_POLICY_ENV in outcome.stderr, str(outcome)
    assert _DEFAULT_BASH_POLICY in outcome.stderr, str(outcome)
    assert "BLOCKED" in outcome.stderr, str(outcome)


def test_the_policy_vocabulary_is_pinned():
    """Three values, and ``block`` is the default — the fail-closed half of the
    contract, pinned so a later edit cannot quietly make silence the default."""
    assert _BASH_POLICIES == ("block", "warn", "off")
    assert _DEFAULT_BASH_POLICY == "block"


# -- PreToolUse vs PostToolUse: same block, different advice -------------------


def test_pretooluse_blocks_before_execution(agent_workdir,
                                            estate_snapshot_path):
    """``PreToolUse`` is the correct registration point for ``Bash``: unlike a
    file edit there is no stale-disk problem (the command text is in the event),
    and it is the one moment the hook can intervene before the estate changes."""
    outcome = run_hook(
        bash_event(agent_workdir, OWNER_GRANT, hook_event_name="PreToolUse"),
        snapshot=estate_snapshot_path)
    assert_blocked(outcome, "blocked before execution", expect_render=False)
    assert "already executed" not in outcome.stderr, str(outcome)


def test_posttooluse_blocks_and_says_the_command_already_ran(
        agent_workdir, estate_snapshot_path):
    """Registered on ``PostToolUse`` the gate is too late to prevent anything,
    so the exit code is the same and the advice is not: check the estate and
    revert. Saying "blocked" there would be false comfort."""
    outcome = run_hook(
        bash_event(agent_workdir, OWNER_GRANT, hook_event_name="PostToolUse"),
        snapshot=estate_snapshot_path)
    assert_blocked(outcome, "already executed", "verify the estate", "revert",
                   expect_render=False)
    assert "blocked before execution" not in outcome.stderr, str(outcome)


def test_both_registrations_block_and_only_the_advice_differs(
        agent_workdir, estate_snapshot_path):
    """One command, two registrations: the decision is identical, so a team
    that registers the hook on the "wrong" event still gets the block."""
    pre = run_hook(bash_event(agent_workdir, OWNER_GRANT,
                              hook_event_name="PreToolUse"),
                   snapshot=estate_snapshot_path)
    post = run_hook(bash_event(agent_workdir, OWNER_GRANT,
                               hook_event_name="PostToolUse"),
                    snapshot=estate_snapshot_path)
    assert pre.exit_code == post.exit_code == 2, f"{pre}\n{post}"
    assert "BLOCKED" in pre.stderr and "BLOCKED" in post.stderr
    assert pre.stderr != post.stderr


# -- arm ordering: the scan needs no snapshot ---------------------------------


def test_the_bash_arm_runs_without_any_snapshot(agent_workdir):
    """ARM ORDERING, asserted. ``snapshot=None`` spawns with no ``--snapshot``
    and the runner scrubs the env var, so the file arm would fail open here.
    A shell scan reads the command text alone, so the cheapest bypass must not
    also be the one an unconfigured hook waves through."""
    outcome = run_hook(bash_event(agent_workdir, OWNER_GRANT), snapshot=None)
    assert_blocked(outcome, "BLOCKED", "add-iam-policy-binding",
                   expect_render=False)
    assert "fail-open" not in outcome.stderr, str(outcome)


def test_the_bash_arm_survives_a_broken_snapshot(agent_workdir, tmp_path):
    """The same ordering from the other side: an unloadable snapshot is a
    fail-open for documents and irrelevant to a command scan."""
    broken = tmp_path / "broken_snapshot.json"
    broken.write_text("{not json", encoding="utf-8")
    outcome = run_hook(bash_event(agent_workdir, OWNER_GRANT), snapshot=broken)
    assert_blocked(outcome, "BLOCKED", "add-iam-policy-binding",
                   expect_render=False)


def test_an_unavailable_classifier_fails_open_out_loud(
        agent_workdir, estate_snapshot_path, blocked_import_env):
    """The degraded world: with ``gcp_grounding.bash_mutation`` unimportable the
    hook says so and exits 0, mirroring preflight's ``tf_claims`` arm. A
    guardrail whose classifier failed to load must not block every command an
    agent runs — but it must not pretend it checked them either."""
    outcome = run_hook(bash_event(agent_workdir, OWNER_GRANT),
                       snapshot=estate_snapshot_path,
                       env=blocked_import_env("gcp_grounding.bash_mutation"))
    assert outcome.exit_code == 0, str(outcome)
    assert "bash-mutation classifier is not available" in outcome.stderr, \
        str(outcome)
    assert "fail-open" in outcome.stderr, str(outcome)


# -- scan-command: the machine-readable record --------------------------------


def test_scan_command_json_records_the_bypass_attempt():
    """THE AUDIT TRAIL, asserted on parsed structure rather than stderr text.

    Exit 0 always: every bash verdict is ``unverified``, so ``report.ok`` stays
    True and the BLOCK decision belongs to the hook's policy flag and to nothing
    else. What CI keeps is the record — kind, status and the verb in the
    message."""
    outcome = run_scan_command(OWNER_GRANT, format="json")
    assert outcome.exit_code == 0, str(outcome)
    report = json.loads(outcome.stdout)
    assert report["schema"] == "gcp-grounding-report/1", str(outcome)
    assert report["ok"] is True, str(outcome)
    verdict = assert_recorded(report, kind="bash-mutation")
    assert verdict["status"] == "unverified"
    assert "add-iam-policy-binding" in verdict["message"]
    assert report["summary"]["ungrounded"] == 0
    assert report["summary"]["contradicted"] == 0
    assert report["summary"]["unverified"] >= 1


def test_scan_command_text_renders_the_human_report():
    outcome = run_scan_command(OWNER_GRANT, format="text")
    assert outcome.exit_code == 0, str(outcome)
    for expected in ("GCP policy grounding", "[bash-mutation]",
                     "add-iam-policy-binding", "roles/owner"):
        assert expected in outcome.stdout, (
            f"expected {expected!r} on stdout\n{outcome}")


def test_scan_command_reads_the_command_from_stdin():
    """``--command -`` is how CI feeds a command it does not want to quote
    through a second shell."""
    outcome = run_scan_command(OWNER_GRANT, format="json", stdin=True)
    assert outcome.exit_code == 0, str(outcome)
    assert_recorded(json.loads(outcome.stdout), kind="bash-mutation")


def test_scan_command_on_a_read_only_command_has_no_verdicts():
    """Zero verdicts and exit 0 — the classifier recognized the invocation and
    had nothing to say about it, which is different from the abstain above."""
    outcome = run_scan_command("gcloud projects get-iam-policy acme-prod",
                               format="json")
    assert outcome.exit_code == 0, str(outcome)
    report = json.loads(outcome.stdout)
    assert report["verdicts"] == [], str(outcome)
    assert report["ok"] is True, str(outcome)


# -- the file arm is untouched ------------------------------------------------


def test_a_clean_policy_file_event_behaves_exactly_as_before(
        policies_dir, toy_snapshot_path):
    """REGRESSION. An event with a ``file_path`` and no ``command`` never
    reaches the bash arm, so it still passes byte-silently."""
    event = {"hook_event_name": "PostToolUse", "tool_name": "Write",
             "tool_input": {"file_path": str(policies_dir / "iam_policy_good.json"),
                            "content": ""}}
    assert _hook_command(event) is None
    assert_passed(run_hook(event, snapshot=toy_snapshot_path))


def test_a_bad_policy_file_event_still_blocks_on_the_grounding_report(
        policies_dir, toy_snapshot_path):
    """The other half of the regression: the file arm's block is unchanged,
    rendered report and all (``expect_render`` defaults to True here, which is
    exactly what distinguishes it from a bash block)."""
    event = {"hook_event_name": "PostToolUse", "tool_name": "Write",
             "tool_input": {"file_path": str(policies_dir / "iam_policy_bad.json"),
                            "content": ""}}
    assert_blocked(run_hook(event, snapshot=toy_snapshot_path),
                   "roles/bigquery.reader")


@pytest.mark.parametrize("tool_name",
                         [t for t in TOOL_NAMES if t != "Bash"])
def test_no_non_bash_envelope_carries_a_command(tool_name, agent_workdir):
    """WHY THE DEFAULT BLOCK CANNOT REGRESS THE REST OF THE SUITE, stated as a
    property rather than left to a green run: no event any other family emits
    carries a ``command`` at all, so ``_hook_bash`` returns ``None`` for every
    one of them and the file arm runs exactly as it did before."""
    agent = FakeAgent(agent_workdir, [Proposal(
        id=f"R_{tool_name}", kind="control", tool_name=tool_name,
        rel_path="policies/iam.policy.json", payload={"bindings": []},
        expect="pass", rationale="A file-shaped proposal from every tool that "
                                 "is not Bash.")])
    _, event = agent.turn()
    assert _hook_command(event) is None, event
