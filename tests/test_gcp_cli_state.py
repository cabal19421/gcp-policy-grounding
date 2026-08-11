"""The ``verify-policy`` state flags: the second input, reached from the CLI.

In-process like :mod:`tests.test_gcp_cli` — :func:`gcp_grounding.cli.main` with
``capsys``, and ``--hook`` runs simulate the PostToolUse event by
monkeypatching ``sys.stdin``. NO subprocess is spawned: every assertion here is
about what one invocation printed and returned, and a child process would only
add spawn budget and startup cost to the same answer.

THE LOAD-BEARING TEST IS THE FIRST ONE. Every new flag defaults to today's
behaviour, so an invocation that names none of them must produce BYTE-IDENTICAL
output — otherwise every existing hook, CI job and frozen expectation in the
repo silently changes meaning. It is asserted against a directly-rendered
:class:`~gcp_grounding.report.PolicyReport` over
:func:`~gcp_grounding.preflight.ground_policy` rather than against a committed
golden file, so it keeps measuring "the pre-change path" rather than "whatever
was recorded once".

Environment-honest like the rest of the suite: z3-dependent expectations branch
on the detected backend, and an autouse fixture scrubs every ``GCP_GROUNDING_*``
variable so a developer's exported snapshot cannot turn a
"nothing-is-configured" case into a configured one and quietly invert it.

TWO FIXTURE FACTS THIS MODULE LEANS ON, both verified rather than assumed:

- a terraform artifact's coverage is capped at ``partial`` BY CONSTRUCTION, and
  ``estate.build`` coerces every category a terraform source contributed to down
  to it. So a widening found against a terraform-derived counterpart is REPORTED
  and never blocks (the partial-baseline asymmetry rewrites a
  requires-complete check's ``contradicted`` to ``unverified``), while one found
  against an API-side counterpart the operator declared complete does block.
  Both directions are pinned below.
- a terraform source's ``captured_at`` is the FILE's mtime, so a state file this
  module writes into ``tmp_path`` is always fresh — which is what lets the
  staleness pins compare a pinned ``--as-of`` against no ``--as-of`` without
  depending on the wall clock.
"""

from __future__ import annotations

import io
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gcp_grounding import discovery, freshness, sources
from gcp_grounding.cli import SNAPSHOT_ENV, build_parser, main
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.preflight import ground_policy
from gcp_grounding.report import PolicyReport
from gcp_grounding.tfsource import discover

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"
SNAPSHOT = FIXTURES / "snapshot.json"
ESTATE = FIXTURES / "estate_snapshot.json"
ESTATE_TFSTATE = FIXTURES / "tf" / "estate.tfstate"

GOOD = POLICIES / "iam_policy_good.json"

#: The four bundles the no-regression pin covers: a passing IAM policy, a
#: failing one, a failing org policy and a terraform plan.
BUNDLES = ("iam_policy_good", "iam_policy_bad", "org_policy_bad", "tf_plan_full")

#: The one IAM row both the estate snapshot and the estate tfstate describe.
IAM_KEY = "//cloudresourcemanager.googleapis.com/projects/acme-prod"
#: A row NO source describes — the absent-vs-unqueried pin.
MISSING_IAM_KEY = "//cloudresourcemanager.googleapis.com/projects/acme-staging"
#: The one firewall row the drift pins disagree about.
FW_KEY = "projects/acme-prod/global/firewalls/allow-internal"

HAVE_Z3 = get_solver().backend == "z3"


@pytest.fixture(autouse=True)
def _state_env_off(monkeypatch):
    """No test here inherits a developer's exported state configuration.

    Every assertion is about what a GIVEN configuration does, and an ambient
    ``$GCP_GROUNDING_TF_STATE`` (or ``$GCP_GROUNDING_SNAPSHOT``) would turn a
    "nothing is configured" case into a configured one and invert it without
    saying so.

    THE CLOCK IS THE ONE EXCEPTION, re-pinned after the scrub: the default
    freshness ceiling runs on every path (the snapshot-only one included), so
    an unpinned run measures the committed fixtures against the wall clock and
    every case here would go stale about a week after the fixtures were
    authored — and the two-invocation byte-equality cases would each resolve
    their own microsecond wall clock into ``state.as_of``. Pinning ``now`` is
    a *given configuration* like any flag in these tests, not an ambient state
    source: it configures no current state (see ``_STATE_OPTIONS``).
    """
    from tests.conftest import PINNED_NOW

    for name in list(os.environ):
        if name.startswith("GCP_GROUNDING"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(freshness.NOW_ENV, PINNED_NOW)


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def hook_event(path) -> str:
    return json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Write",
                       "tool_input": {"file_path": str(path), "content": ""}})


def run_hook(capsys, monkeypatch, event: str, *extra: str) -> tuple[int, str, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(event))
    return invoke(capsys, "verify-policy", "--hook", *extra)


def write_json(path: Path, document) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


def firewall_state(*, source_ranges=("10.0.0.0/8",),
                   network="projects/acme-prod/global/networks/vpc-main") -> dict:
    """A v4 tfstate managing ONE firewall rule.

    It deliberately manages no IAM: a terraform source drags every category it
    touches down to ``partial``, and these pins need an IAM counterpart the
    operator can still declare complete.
    """
    return {
        "version": 4,
        "terraform_version": "1.9.5",
        "serial": 3,
        "lineage": "8b1a0000-0000-4000-8000-000000000001",
        "outputs": {},
        "resources": [{
            "mode": "managed",
            "type": "google_compute_firewall",
            "name": "allow-internal",
            "provider": 'provider["registry.terraform.io/hashicorp/google"]',
            "instances": [{"schema_version": 1, "attributes": {
                "name": "allow-internal", "project": "acme-prod",
                "network": network, "direction": "INGRESS", "priority": 1000,
                "disabled": False, "source_ranges": list(source_ranges),
                "destination_ranges": [], "source_tags": [], "target_tags": [],
                "source_service_accounts": [], "target_service_accounts": [],
                "allow": [{"protocol": "tcp", "ports": ["0-65535"]}], "deny": [],
                "id": f"projects/acme-prod/global/firewalls/allow-internal"}}],
        }],
    }


def widened_policy() -> dict:
    """The estate's own IAM policy with ONE member added — a real widening
    against the counterpart the estate snapshot holds, and every name in it is
    one the snapshot carries, so the existence layer stays green and any finding
    is the pair check's alone."""
    return {"version": 3, "etag": "BwX=", "bindings": [
        {"role": "roles/owner", "members": ["user:alice@acme.example"]},
        {"role": "roles/iam.securityAdmin", "members": [
            "serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com",
            "user:alice@acme.example"]}]}


def estate_copy(path: Path, **overrides) -> str:
    """A copy of the estate snapshot, optionally with one firewall field
    changed — the disagreeing second source the drift pins use."""
    document = json.loads(ESTATE.read_text(encoding="utf-8"))
    if overrides:
        document["firewall_rules"][FW_KEY] = dict(
            document["firewall_rules"][FW_KEY], **overrides)
    return write_json(path, document)


def verdicts_of(stdout: str) -> list[dict]:
    return json.loads(stdout)["verdicts"]


def kinds_of(stdout: str, prefix: str) -> list[str]:
    return [v["kind"] for v in verdicts_of(stdout) if v["kind"].startswith(prefix)]


# -- THE NO-REGRESSION PIN -----------------------------------------------------


@pytest.mark.parametrize("bundle", BUNDLES)
@pytest.mark.parametrize("format", ("text", "json"))
def test_with_no_state_flags_the_output_is_byte_identical(capsys, bundle, format):
    """Every new flag defaults to today's behaviour, so naming none of them must
    change nothing at all — in either format, over a passing bundle, two failing
    ones and a terraform plan.

    Compared against a directly-rendered report over ``ground_policy`` rather
    than a recorded golden: the claim is "this is still the pre-change path",
    and a golden file would keep passing after the path changed under it.
    """
    document = POLICIES / f"{bundle}.json"
    snapshot = GcpSnapshot.load(str(SNAPSHOT))
    report = PolicyReport(ground_policy(str(document), snapshot),
                          captured_at=snapshot.captured_at, source=str(document))
    expected = report.render("human" if format == "text" else "json")
    code, out, err = invoke(capsys, "verify-policy", str(document),
                            "--snapshot", str(SNAPSHOT), "--format", format)
    assert err == ""
    assert out == expected + "\n"
    assert code == (0 if report.ok else 1)


def test_the_snapshot_alone_is_the_vocabulary_and_not_a_state_source(capsys):
    """The predicate the byte-identity rests on, asserted directly: ``--snapshot``
    alone configures NO current state, so the json document grows no ``state``
    key and the two invocations are byte-identical."""
    settings = discovery.resolve_settings(cli={"primary": str(SNAPSHOT)}, env={})
    from gcp_grounding.cli import _state_configured

    assert _state_configured(settings) is False
    code, bare, _ = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                           str(SNAPSHOT), "--format", "json")
    code2, knobs, _ = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                             str(SNAPSHOT), "--format", "json", "--no-config",
                             "--drift-policy", "annotate", "--max-age", "off")
    assert (code, code2) == (0, 0)
    assert "state" not in json.loads(bare)
    assert knobs == bare


def test_snapshot_stays_a_single_valued_option(capsys):
    """``--snapshot`` is NOT converted to an appending action: the frozen CLI
    module pins its shape, and a repeatable primary would be a second spelling
    of ``--merge-source``."""
    actions = {a.dest: a for a in build_parser()._subparsers._group_actions[0]
               .choices["verify-policy"]._actions}
    assert type(actions["snapshot"]).__name__ == "_StoreAction"
    assert type(actions["merge_source"]).__name__ == "_AppendAction"
    assert type(actions["terraform_state"]).__name__ == "_AppendAction"


# -- the terraform-state flag replaces --baseline ------------------------------


def test_a_state_source_finds_a_widening_with_no_baseline_flag(capsys, tmp_path):
    """THE HEADLINE CAPABILITY: the pair check runs with no ``--baseline``.

    The counterpart is derived from the configured current state, which is what
    makes the widening check reachable from a hook that never types a baseline
    path. The terraform state is configured and manages a firewall rule only, so
    the IAM counterpart is the API-side estate the operator declared complete —
    and a requires-complete widening check over a COMPLETE baseline blocks, as
    it must.
    """
    if not HAVE_Z3:
        return  # new⊆old is honestly undecided without a solver, and never fails
    state = write_json(tmp_path / "terraform.tfstate", firewall_state())
    policy = write_json(tmp_path / "widened.policy.json", widened_policy())
    code, out, _ = invoke(capsys, "verify-policy", policy,
                          "--snapshot", str(ESTATE), "--completeness", "complete",
                          "--terraform-state", state, "--max-age", "off",
                          "--no-config", "--target", f"iam_bindings:{IAM_KEY}",
                          "--format", "json")
    assert code == 1
    subset = [v for v in verdicts_of(out) if v["kind"] == "subset"]
    assert len(subset) == 1
    assert subset[0]["status"] == "contradicted"
    assert "roles/iam.securityAdmin" in subset[0]["message"]
    # The attribution is on the verdict: which row, which source, which
    # identification. An unattributed pair finding is not auditable.
    assert IAM_KEY in subset[0]["message"]
    assert str(ESTATE) in subset[0]["message"]


def test_no_auto_baseline_turns_the_pair_tier_off(capsys, tmp_path):
    """The same input with ``--no-auto-baseline``: no counterpart is derived, so
    every pair check abstains WITH A STATED REASON and the run exits 0."""
    state = write_json(tmp_path / "terraform.tfstate", firewall_state())
    policy = write_json(tmp_path / "widened.policy.json", widened_policy())
    code, out, _ = invoke(capsys, "verify-policy", policy,
                          "--snapshot", str(ESTATE), "--completeness", "complete",
                          "--terraform-state", state, "--max-age", "off",
                          "--no-config", "--target", f"iam_bindings:{IAM_KEY}",
                          "--no-auto-baseline", "--format", "json")
    assert code == 0
    assert not [v for v in verdicts_of(out) if v["kind"] == "subset"]
    skipped = [v for v in verdicts_of(out) if v["kind"] == "tier:input"]
    assert len(skipped) == 1
    assert "auto-baseline is off" in skipped[0]["message"]


def test_a_terraform_counterpart_reports_a_widening_without_blocking(capsys, tmp_path):
    """THE PARTIAL-BASELINE ASYMMETRY, from the CLI.

    With the IAM row coming from terraform the counterpart's coverage is
    ``partial`` by construction, so the same finding is REPORTED and does NOT
    block: a check that reasons from what the baseline does not contain cannot
    tell a real widening from a row that view never saw.
    """
    if not HAVE_Z3:
        return
    policy = write_json(tmp_path / "widened.policy.json", widened_policy())
    code, out, _ = invoke(capsys, "verify-policy", policy,
                          "--snapshot", str(SNAPSHOT),
                          "--terraform-state", str(ESTATE_TFSTATE),
                          "--max-age", "off", "--no-config",
                          "--target", f"iam_bindings:{IAM_KEY}", "--format", "json")
    subset = [v for v in verdicts_of(out) if v["kind"] == "subset"]
    assert len(subset) == 1
    assert subset[0]["status"] == "unverified"
    assert "'partial'" in subset[0]["message"]
    assert "NOT a block" in subset[0]["message"]


def test_an_explicit_baseline_keeps_working_alongside_a_state_source(
        capsys, tmp_path):
    """``--baseline`` is not silently superseded by the derived counterpart: the
    same new⊆old comparison still runs against the file a human named, and its
    verdict says which file that was."""
    if not HAVE_Z3:
        return
    state = write_json(tmp_path / "terraform.tfstate", firewall_state())
    old = write_json(tmp_path / "old.policy.json", {"bindings": [
        {"role": "roles/owner", "members": ["user:alice@acme.example"]}]})
    policy = write_json(tmp_path / "widened.policy.json", widened_policy())
    code, out, _ = invoke(capsys, "verify-policy", policy, "--snapshot", str(ESTATE),
                          "--terraform-state", state, "--max-age", "off",
                          "--no-config", "--baseline", old, "--format", "json")
    explicit = [v for v in verdicts_of(out) if v["kind"] == "subset"
                and "explicit baseline" in v["message"]]
    assert len(explicit) == 1
    assert explicit[0]["status"] == "contradicted"
    assert old in explicit[0]["message"]
    assert code == 1


def test_an_unreadable_document_still_fails_open_with_a_state_source(
        capsys, tmp_path):
    """The state route does not change the loader's contract: a file that
    cannot be parsed is one ``unverified`` verdict and exit 0, never a crash and
    never a finding."""
    state = write_json(tmp_path / "terraform.tfstate", firewall_state())
    garbled = tmp_path / "garbled.policy.json"
    garbled.write_bytes(b"\xff\xfe{\x00}")
    code, out, _ = invoke(capsys, "verify-policy", str(garbled), "--snapshot",
                          str(ESTATE), "--terraform-state", state,
                          "--max-age", "off", "--no-config", "--format", "json")
    assert code == 0
    document = json.loads(out)
    assert document["summary"]["ungrounded"] == 0
    assert document["summary"]["contradicted"] == 0
    assert any(v["kind"] == "document" for v in document["verdicts"])
    # The state was still assembled and is still explainable.
    assert state in [row["source"] for row in document["state"]["sources"]]


# -- merge sources, drift and precedence ---------------------------------------


def _state_run(capsys, policy, *extra):
    return invoke(capsys, "verify-policy", str(policy), "--snapshot", str(ESTATE),
                  "--completeness", "complete", "--max-age", "off", "--no-config",
                  "--format", "json", *extra)


def test_an_agreeing_merge_source_adds_exactly_the_provenance_note(capsys, tmp_path):
    """A second source that agrees adds ONE line and nothing else: the
    multi-source provenance note, without which the single ``captured_at`` in
    the report header reads as the whole truth about a view assembled from
    several artifacts of different ages."""
    twin = estate_copy(tmp_path / "twin.json")
    _, single, _ = _state_run(capsys, GOOD)
    _, merged, _ = _state_run(capsys, GOOD, "--merge-source", twin)

    def rendered(document):
        return [(v["status"], v["kind"], v["message"]) for v in verdicts_of(document)]

    added = [v for v in rendered(merged) if v not in rendered(single)]
    assert [v for v in rendered(single) if v not in rendered(merged)] == []
    assert len(added) == 1
    status, kind, message = added[0]
    assert (status, kind) == ("unverified", "provenance")
    assert "merged from 2 sources" in message
    assert twin in message


def test_a_disagreeing_source_reports_one_drift_line_and_blocks_only_on_block(
        capsys, tmp_path):
    """One materially disagreeing field, one drift line. It never blocks under
    the default policy — a disagreement is a statement about the EVIDENCE, not a
    finding against the change — and blocks under ``--drift-policy block``."""
    rogue = estate_copy(tmp_path / "rogue.json", source_ranges=["0.0.0.0/0"])
    code, annotated, _ = _state_run(capsys, GOOD, "--merge-source", rogue)
    material = [v for v in verdicts_of(annotated) if v["kind"] == "drift:material"]
    assert code == 0
    assert len(material) == 1
    assert material[0]["status"] == "unverified"
    assert "source_ranges" in material[0]["message"]
    assert FW_KEY in material[0]["target"]

    code, blocked, _ = _state_run(capsys, GOOD, "--merge-source", rogue,
                                  "--drift-policy", "block")
    material = [v for v in verdicts_of(blocked) if v["kind"] == "drift:material"]
    assert code == 1
    assert [v["status"] for v in material] == ["contradicted"]


def test_api_wins_and_terraform_wins_select_opposite_values(capsys, tmp_path):
    """Two precedences over ONE disagreeing pair, asserted through the rendered
    verdict: each names the source the merged snapshot took the value from, and
    each still prints the LOSING value — precedence decides which document is
    primary, never which finding is true."""
    state = write_json(tmp_path / "terraform.tfstate",
                       firewall_state(source_ranges=("0.0.0.0/0",)))
    chosen = {}
    for mode in ("api-wins", "terraform-wins"):
        _, out, _ = _state_run(capsys, GOOD, "--terraform-state", state,
                               "--precedence", f"{mode},firewall_rules={mode}")
        drift = [v for v in verdicts_of(out) if v["kind"] == "drift:material"
                 and "source_ranges" in v["message"]]
        assert len(drift) == 1, mode
        message = drift[0]["message"]
        # BOTH values are always named, whichever side won.
        assert "10.0.0.0/8" in message and "0.0.0.0/0" in message
        winner = message.split("uses the value from ", 1)[1].split(" under ", 1)[0]
        chosen[mode] = winner.strip("'")
    assert chosen["api-wins"] == str(ESTATE)
    assert chosen["terraform-wins"] == state
    assert chosen["api-wins"] != chosen["terraform-wins"]


def test_require_agreement_blocks_where_highest_fidelity_reports(capsys, tmp_path):
    """REQUIRE-AGREEMENT END TO END: one disagreement, two precedences, the
    finding present under BOTH.

    Under ``require-agreement`` the material disagreement is escalated to
    ``contradicted`` and the run exits 1; under ``highest-fidelity-wins`` the
    identical input exits 0 with the same disagreement still REPORTED as
    ``unverified``. A precedence that suppressed the losing side would be a
    silent pass.
    """
    state = write_json(tmp_path / "terraform.tfstate",
                       firewall_state(source_ranges=("0.0.0.0/0",)))
    code, escalated, _ = _state_run(
        capsys, GOOD, "--terraform-state", state,
        "--precedence", "require-agreement,firewall_rules=require-agreement")
    document = json.loads(escalated)
    assert code == 1
    assert document["summary"]["contradicted"] == 1
    escalation = [v for v in document["verdicts"]
                  if v["kind"] == "drift:material" and v["status"] == "contradicted"]
    assert len(escalation) == 1
    assert "require-agreement" in escalation[0]["message"]

    code, reported, _ = _state_run(
        capsys, GOOD, "--terraform-state", state,
        "--precedence", "highest-fidelity-wins,firewall_rules=highest-fidelity-wins")
    document = json.loads(reported)
    assert code == 0
    assert document["summary"]["contradicted"] == 0
    still_there = [v for v in document["verdicts"] if v["kind"] == "drift:material"]
    assert len(still_there) == 1
    assert still_there[0]["status"] == "unverified"
    assert "source_ranges" in still_there[0]["message"]


# -- usage errors, and their hook-mode fail-open twin --------------------------


def test_a_bogus_precedence_is_a_usage_error_naming_the_token(capsys):
    code, out, err = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                            str(ESTATE), "--precedence", "bogus-wins")
    assert code == 2
    assert out == ""  # nothing was grounded
    assert "bogus-wins" in err and "--precedence" in err


def test_the_same_bogus_precedence_fails_open_in_hook_mode(capsys, monkeypatch):
    """A misconfigured hook must degrade to checking nothing, NEVER to blocking
    every edit — so the identical mistake is exit 0 plus one stderr note."""
    code, out, err = run_hook(capsys, monkeypatch, hook_event(GOOD),
                              "--snapshot", str(ESTATE), "--precedence", "bogus-wins")
    assert code == 0
    assert out == ""
    assert "bogus-wins" in err and "fail-open" in err


@pytest.mark.parametrize("flag,value,token", [
    ("--max-age", "7dd", "7dd"),
    ("--as-of", "not-a-timestamp", "not-a-timestamp"),
    ("--target", "not_a_domain:x", "not_a_domain"),
    ("--target", "iam_bindings", "iam_bindings"),
])
def test_every_malformed_state_flag_is_a_usage_error(capsys, flag, value, token):
    """A typo that quietly restored the default would change what the gate
    enforces with nothing saying so, so each one exits 2 naming its token."""
    code, out, err = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                            str(ESTATE), flag, value)
    assert code == 2
    assert out == ""
    assert token in err and flag in err


# -- staleness ------------------------------------------------------------------


def test_an_as_of_past_the_ceiling_makes_the_counterpart_stale(capsys, tmp_path):
    """``--as-of`` is what makes a staleness assertion deterministic: the same
    inputs with a pinned clock a month later go stale, and without it — with
    both sources minutes old — nothing does."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    document = json.loads(ESTATE.read_text(encoding="utf-8"))
    document["captured_at"] = now.isoformat().replace("+00:00", "Z")
    fresh = write_json(tmp_path / "fresh_snapshot.json", document)
    state = write_json(tmp_path / "terraform.tfstate", firewall_state())
    common = ("--snapshot", fresh, "--completeness", "complete", "--no-config",
              "--terraform-state", state, "--max-age", "7d",
              "--target", f"iam_bindings:{IAM_KEY}", "--format", "json")

    _, current, _ = invoke(capsys, "verify-policy", str(GOOD), *common)
    assert kinds_of(current, "baseline:stale") == []
    assert kinds_of(current, "staleness") == []

    later = (now + timedelta(days=30)).isoformat().replace("+00:00", "Z")
    _, aged, _ = invoke(capsys, "verify-policy", str(GOOD), *common, "--as-of", later)
    assert kinds_of(aged, "baseline:stale") == ["baseline:stale"]
    assert kinds_of(aged, "staleness")


def test_the_default_ceiling_runs_on_the_snapshot_only_path(capsys, monkeypatch,
                                                            tmp_path):
    """``--snapshot`` alone — the hook's own configured shape — is still under
    the DEFAULT seven-day ceiling: an over-age snapshot earns the same
    per-source ``staleness`` abstention the engine path emits, every category
    it supplies is demoted (existence checks become named abstentions, never
    blessings from a vocabulary nobody can show is current), the headline
    carries the coverage qualifier, and the exit stays 0 — unverified never
    blocks."""
    monkeypatch.setenv(freshness.NOW_ENV, "2027-06-01T00:00:00Z")
    code, out, err = invoke(capsys, "verify-policy", str(GOOD),
                            "--snapshot", str(SNAPSHOT), "--no-config")
    assert code == 0 and err == ""
    # The coverage-qualified headline, never the bare PASSED. GOOD carries one
    # solver-only CEL check that survives the demotion (staleness demotes
    # snapshot-backed existence, not solver arithmetic), so the form here is
    # 'PASSED (N unchecked)'; a document with snapshot-backed claims alone
    # earns 'PASSED — NOTHING VERIFIED (N unchecked)'.
    assert "unchecked) [" in out and "PASSED [" not in out
    assert "? [staleness]" in out
    assert "past the 7 days freshness limit" in out
    assert "demoted to 'uncaptured'" in out
    assert "snapshot did not capture" in out
    assert "exists in the snapshot" not in out

    # A document whose every claim is snapshot-backed grounds NOTHING once the
    # vocabulary is demoted, and the headline says so.
    existence_only = write_json(tmp_path / "existence_only.json", {
        "bindings": [{"role": "roles/bigquery.dataViewer",
                      "members": ["group:data-eng@acme.example"]}],
        "etag": "BwXtRfPolicy=", "version": 1})
    code, nothing, _ = invoke(capsys, "verify-policy", existence_only,
                              "--snapshot", str(SNAPSHOT), "--no-config")
    assert code == 0
    assert "PASSED — NOTHING VERIFIED" in nothing
    assert "? [staleness]" in nothing


def test_a_typed_max_age_and_as_of_are_honoured_with_only_a_snapshot(capsys):
    """``--max-age`` and ``--as-of`` are read on the snapshot-only path: a
    pinned clock a year out demotes under the default ceiling, a generous
    typed ceiling admits the same snapshot, and the ``off`` spelling is the
    explicit opt-out."""
    stale_clock = ("--as-of", "2027-06-01T00:00:00Z")
    code, out, _ = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                          str(SNAPSHOT), "--no-config", *stale_clock)
    assert code == 0 and "? [staleness]" in out

    code, generous, _ = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                               str(SNAPSHOT), "--no-config", *stale_clock,
                               "--max-age", "3650d")
    assert code == 0
    assert "staleness" not in generous and "PASSED [" in generous

    code, opted_out, _ = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                                str(SNAPSHOT), "--no-config", *stale_clock,
                                "--max-age", "off")
    assert code == 0
    assert "staleness" not in opted_out and "PASSED [" in opted_out


def test_the_max_age_environment_variable_reaches_the_snapshot_only_path(
        capsys, monkeypatch):
    """``$GCP_GROUNDING_MAX_AGE`` tightens (and, malformed, refuses) the
    snapshot-only run exactly as it does the engine path: a two-day-old
    snapshot under a one-day env ceiling demotes, and a typo'd ceiling is a
    usage error naming the token — never a silent fall back."""
    monkeypatch.setenv(freshness.NOW_ENV, "2026-07-20T12:00:00Z")
    monkeypatch.setenv(sources.MAX_AGE_ENV, "1d")
    code, out, _ = invoke(capsys, "verify-policy", str(GOOD),
                          "--snapshot", str(SNAPSHOT), "--no-config")
    assert code == 0
    assert "past the 1 day freshness limit" in out

    monkeypatch.setenv(sources.MAX_AGE_ENV, "7dd")
    code, _, err = invoke(capsys, "verify-policy", str(GOOD),
                          "--snapshot", str(SNAPSHOT), "--no-config")
    assert code == 2 and "7dd" in err


def test_hook_mode_surfaces_snapshot_staleness_through_abstain_notes(
        capsys, monkeypatch):
    """The hook with only a snapshot configured stays exit 0 on staleness —
    unverified never blocks — and ``--abstain-notes`` puts the demotion on the
    record instead of byte-silence."""
    monkeypatch.setenv(freshness.NOW_ENV, "2027-06-01T00:00:00Z")
    code, out, err = run_hook(capsys, monkeypatch, hook_event(GOOD),
                              "--snapshot", str(SNAPSHOT), "--no-config",
                              "--abstain-notes")
    assert (code, out) == (0, "")
    assert "NOT DECIDED" in err
    assert "[staleness]" in err and "demoted to 'uncaptured'" in err


# -- --state-explain and the json state key ------------------------------------


def test_state_explain_writes_the_provenance_block_to_stderr(capsys, tmp_path):
    """stdout stays parseable under ``--format json``: the whole point of
    putting the block on stderr is that a machine consumer is unaffected."""
    state = write_json(tmp_path / "terraform.tfstate", firewall_state())
    code, out, err = _state_run(capsys, GOOD, "--terraform-state", state,
                                "--state-explain")
    assert code == 0
    json.loads(out)  # parseable
    assert err.startswith("state used this run:")
    assert "sources:" in err and "settings:" in err and "targets:" in err
    assert state in err and str(ESTATE) in err


def test_a_default_run_resolves_one_clock_for_the_explain_surfaces(
        capsys, tmp_path, monkeypatch):
    """On a run with NO ``--as-of`` and no pinned environment clock, the wall
    clock the run resolves for enforcement is the SAME clock the explain
    surfaces read: ``--state-explain`` prints real per-source ages (never
    'age=unknown (no clock was injected)') and the json ``state.as_of`` is the
    resolved clock, not a fallback to the oldest capture time."""
    monkeypatch.delenv(freshness.NOW_ENV, raising=False)
    state = write_json(tmp_path / "terraform.tfstate", firewall_state())
    code, out, err = _state_run(capsys, GOOD, "--terraform-state", state,
                                "--state-explain")
    assert code == 0
    assert "no clock was injected" not in err
    assert "age=unknown" not in err
    assert " age=" in err
    as_of = json.loads(out)["state"]["as_of"]
    resolved = datetime.fromisoformat(as_of.replace("Z", "+00:00"))
    assert resolved.tzinfo is not None
    # Not the oldest capture time: the estate snapshot's committed stamp.
    assert as_of != GcpSnapshot.load(str(ESTATE)).captured_at


def test_state_explain_with_a_domain_and_key_prints_the_drill_down(capsys, tmp_path):
    state = write_json(tmp_path / "terraform.tfstate", firewall_state())
    code, out, err = _state_run(capsys, GOOD, "--terraform-state", state,
                                "--target", f"iam_bindings:{IAM_KEY}",
                                "--state-explain", f"iam_bindings:{IAM_KEY}")
    json.loads(out)
    assert err.startswith(f"state fact iam_bindings {IAM_KEY}:")
    assert "  chosen: source=" in err
    assert "  alternates:" in err and "  differences:" in err


def test_explain_appends_the_state_lines_after_the_solver_block(capsys, tmp_path):
    """The narrative leads, the solver block keeps its place as reference
    detail, and the state block still comes AFTER it."""
    state = write_json(tmp_path / "terraform.tfstate", firewall_state())
    _, _, err = _state_run(capsys, GOOD, "--terraform-state", state, "--explain")
    lines = err.splitlines()
    solver = next(i for i, line in enumerate(lines)
                  if line.startswith("z3 constraints generated this run"))
    assert lines[0].startswith("what was proposed:")
    assert any(line.startswith("state used this run:")
               for line in lines[solver:])
    assert lines.index("sources:") > solver


def test_the_json_state_key_follows_configuration_and_not_load_outcome(
        capsys, tmp_path):
    """Present when a source was CONFIGURED, even when one failed to load; and
    absent — byte-identically absent — when none is."""
    state = write_json(tmp_path / "terraform.tfstate", firewall_state())
    _, configured, _ = _state_run(capsys, GOOD, "--terraform-state", state)
    document = json.loads(configured)["state"]
    assert document["schema"] == "gcp-grounding-provenance/1"
    assert sorted(row["source"] for row in document["sources"]) == sorted(
        [state, str(ESTATE)])

    missing = str(tmp_path / "gone.tfstate")
    _, failed, _ = _state_run(capsys, GOOD, "--terraform-state", missing)
    document = json.loads(failed)["state"]
    # The key is there, and the source that contributed nothing is NOT in it:
    # sources-configured-but-not-loaded is distinguishable from state-is-off.
    assert missing not in [row["source"] for row in document["sources"]]

    _, off, _ = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                       str(ESTATE), "--format", "json")
    _, plain, _ = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                         str(ESTATE), "--format", "json")
    assert "state" not in json.loads(off)
    assert off == plain


def test_an_ungrounded_name_is_re_graded_against_the_coverage_it_was_judged_by(
        capsys, tmp_path):
    """THE FINISHING PASS IS WIRED, and it is the one that matters most.

    ``ungrounded`` is a positive claim that the current state PROVES the name is
    not there, and a view whose ``roles`` coverage is merely ``undeclared``
    proves no such thing — so the finding is re-graded to ``unverified`` naming
    the coverage. ``--completeness complete`` is the operator saying the view
    really is authoritative, and the hallucination finding comes straight back:
    the whole value of this gate must not be switchable off by accident, nor
    left on where it cannot be justified.
    """
    state = write_json(tmp_path / "terraform.tfstate", firewall_state())
    common = (str(POLICIES / "iam_policy_bad.json"), "--snapshot", str(ESTATE),
              "--terraform-state", state, "--max-age", "off", "--no-config",
              "--format", "json")
    _, undeclared, _ = invoke(capsys, "verify-policy", *common)
    hallucination = [v for v in verdicts_of(undeclared)
                     if v["target"] == "roles/bigquery.reader"]
    assert [v["status"] for v in hallucination] == ["unverified"]
    assert "undeclared coverage" in hallucination[0]["message"]

    _, licensed, _ = invoke(capsys, "verify-policy", *common,
                            "--completeness", "complete")
    hallucination = [v for v in verdicts_of(licensed)
                     if v["target"] == "roles/bigquery.reader"]
    assert [v["status"] for v in hallucination] == ["ungrounded"]


# -- the incomplete-sources notice ---------------------------------------------


def test_the_incomplete_sources_notice_fires_once_for_a_failing_source(
        capsys, tmp_path):
    """A configured source that contributed nothing is otherwise invisible:
    every state verdict is ``unverified``, so the exit code is unchanged and the
    abstain channel defaults off."""
    missing = str(tmp_path / "gone.tfstate")
    code, _, err = _state_run(capsys, GOOD, "--terraform-state", missing)
    lines = [line for line in err.splitlines() if "contributed nothing" in line]
    assert code == 0  # a notice, never a block
    assert len(lines) == 1
    assert lines[0].startswith("gcp-ground verify-policy: 1 of 2 configured state")
    assert "INCOMPLETE" in lines[0]


def test_the_notice_is_silent_when_every_configured_source_loaded(capsys, tmp_path):
    """The control: a channel that fires on a healthy setup is noise, and noise
    is what gets a guardrail switched off.

    Asserted twice, because the notice has two conditions and only one of them
    is about a failure: a healthy run whose derivation DID leave a counterpart
    unqueried — no source covers that domain completely — must stay silent too.
    """
    state = write_json(tmp_path / "terraform.tfstate", firewall_state())
    code, _, err = _state_run(capsys, GOOD, "--terraform-state", state)
    assert code == 0
    assert err == ""

    code, out, err = _state_run(capsys, GOOD, "--terraform-state", state,
                                "--target", f"iam_bindings:{MISSING_IAM_KEY}")
    assert kinds_of(out, "baseline:unqueried") == ["baseline:unqueried"]
    assert code == 0
    assert err == ""


# -- the environment and the config file ---------------------------------------


def test_the_terraform_state_environment_variable_is_honoured(capsys, monkeypatch,
                                                              tmp_path):
    """One export configures a whole session's hooks, exactly as the snapshot
    variable already does."""
    state = write_json(tmp_path / "terraform.tfstate", firewall_state())
    monkeypatch.setenv(sources.TF_STATE_ENV, state)
    code, out, _ = invoke(capsys, "verify-policy", str(GOOD), "--snapshot",
                          str(ESTATE), "--max-age", "off", "--no-config",
                          "--format", "json")
    assert code == 0
    assert state in [row["source"] for row in json.loads(out)["state"]["sources"]]


def test_a_snapshot_from_a_discovered_config_is_honoured(capsys, tmp_path):
    """THE PIN THAT ``_load_snapshot`` ROUTES THROUGH ``resolve_settings``.

    No flag and no environment variable: the snapshot path exists only in a
    config file discovered by walking up from the document. Built through
    ``sources.from_env`` instead, this run would fail with "an estate snapshot
    is required" — or worse, succeed against the wrong state.
    """
    repo = tmp_path / "repo"
    write_json(repo / ".gcp-grounding.json",
               {"schema": discovery.CONFIG_SCHEMA, "snapshot": str(SNAPSHOT)})
    document = write_json(repo / "policy.json",
                          json.loads(GOOD.read_text(encoding="utf-8")))
    code, out, err = invoke(capsys, "verify-policy", document, "--format", "json")
    assert code == 0, err
    assert json.loads(out)["captured_at"] == GcpSnapshot.load(str(SNAPSHOT)).captured_at
    assert err == ""


def test_the_config_flag_and_its_environment_variable_name_the_same_file(
        capsys, monkeypatch, tmp_path):
    """A CI job whose checkout layout it does not control names one config
    instead — by flag or by ``$GCP_GROUNDING_CONFIG``, which short-circuits the
    walk. The document lives somewhere the walk would never reach it."""
    state = write_json(tmp_path / "elsewhere" / "terraform.tfstate", firewall_state())
    config = write_json(tmp_path / "elsewhere" / "config.json",
                        {"schema": discovery.CONFIG_SCHEMA, "snapshot": str(ESTATE),
                         "max_age": "off", "terraform": {"state": [state]}})
    document = write_json(tmp_path / "work" / "policy.json",
                          json.loads(GOOD.read_text(encoding="utf-8")))

    code, out, _ = invoke(capsys, "verify-policy", document, "--config", config,
                          "--format", "json")
    assert code == 0
    assert state in [row["source"] for row in json.loads(out)["state"]["sources"]]

    monkeypatch.setenv(discovery.CONFIG_ENV, config)
    code, from_env, _ = invoke(capsys, "verify-policy", document, "--format", "json")
    assert code == 0
    assert from_env == out


def test_no_config_suppresses_discovery_entirely(capsys, tmp_path):
    """``--no-config`` means the flags and the environment are the whole
    configuration: a config file sitting right next to the document is not
    read, so the snapshot it names is not found and the run says so."""
    repo = tmp_path / "repo"
    write_json(repo / ".gcp-grounding.json",
               {"schema": discovery.CONFIG_SCHEMA, "snapshot": str(SNAPSHOT)})
    document = write_json(repo / "policy.json",
                          json.loads(GOOD.read_text(encoding="utf-8")))
    assert invoke(capsys, "verify-policy", document)[0] == 0
    code, out, err = invoke(capsys, "verify-policy", document, "--no-config")
    assert code == 2
    assert out == ""
    assert SNAPSHOT_ENV in err


def test_a_missing_snapshot_is_still_a_usage_error(capsys):
    """The failure semantics are unchanged by the new resolution: exit 2 in
    normal mode, naming the environment variable."""
    code, out, err = invoke(capsys, "verify-policy", str(GOOD), "--no-config")
    assert code == 2
    assert out == ""
    assert SNAPSHOT_ENV in err


def test_a_missing_snapshot_still_fails_open_in_hook_mode(capsys, monkeypatch):
    code, out, err = run_hook(capsys, monkeypatch, hook_event(GOOD), "--no-config")
    assert code == 0
    assert out == ""
    assert "fail-open" in err


# -- the sidecar-less estate table ---------------------------------------------


def test_an_estate_table_with_no_sidecar_is_undeclared_and_not_new(capsys):
    """``baseline:unqueried`` and ``baseline:new`` license OPPOSITE conclusions.

    A snapshot that travels without its ``.origins.json`` is ``undeclared``, so a
    key it does not carry is NOT LOOKED UP rather than NEW — and
    ``--completeness complete`` is the explicit, auditable override that changes
    that, the only one there is.
    """
    common = ("--snapshot", str(ESTATE), "--no-config", "--max-age", "off",
              "--target", f"iam_bindings:{MISSING_IAM_KEY}", "--format", "json")
    _, undeclared, _ = invoke(capsys, "verify-policy", str(GOOD), *common)
    assert kinds_of(undeclared, "baseline:") == ["baseline:unqueried"]

    _, licensed, _ = invoke(capsys, "verify-policy", str(GOOD), *common,
                            "--completeness", "complete")
    assert kinds_of(licensed, "baseline:") == ["baseline:new"]


# -- a tfstate handed in as the document ---------------------------------------


def test_a_tfstate_as_the_document_is_refused_rather_than_graded(capsys):
    """It routes through ``detect_kind`` as a PLAN otherwise — zero claims, a
    clean-looking pass, over a file describing the whole estate.

    The message is asserted EQUAL to the shared constant: two message templates
    in two files with no shared owner drift, and a drifted sniff is exactly the
    silent pass this arm exists to close.
    """
    code, out, _ = invoke(capsys, "verify-policy", str(ESTATE_TFSTATE),
                          "--snapshot", str(ESTATE), "--format", "json")
    assert code == 1  # the run produced no grounding, which is not a pass
    found = verdicts_of(out)
    assert len(found) == 1
    assert found[0]["status"] == "ungrounded"
    assert found[0]["message"] == discover.STATE_NOT_A_PROPOSAL.format(
        path=str(ESTATE_TFSTATE))
    # NOT ONE CLAIM was extracted from the estate it describes.
    assert not [v for v in found if v["kind"] in ("role", "principal", "permission")]


def test_the_same_tfstate_passed_as_a_source_is_used_normally(capsys):
    """The refusal is about the ROLE the file was given, not about the file."""
    code, out, _ = _state_run(capsys, GOOD, "--terraform-state", str(ESTATE_TFSTATE))
    assert code == 0
    sources_used = [row["source"] for row in json.loads(out)["state"]["sources"]]
    assert str(ESTATE_TFSTATE) in sources_used
    assert not [v for v in verdicts_of(out) if v["kind"] == "state:not-a-proposal"]


# -- hook mode ------------------------------------------------------------------


def test_hook_blocks_on_material_drift_only_under_the_block_policy(
        capsys, monkeypatch, tmp_path):
    """Drift notes are ``unverified`` and therefore invisible in hook mode by
    default — that is deliberate. ``--drift-policy block`` is how material drift
    is made to block: exit 2, byte-empty stdout, the drift on stderr."""
    rogue = estate_copy(tmp_path / "rogue.json", source_ranges=["0.0.0.0/0"])
    common = ("--snapshot", str(ESTATE), "--completeness", "complete",
              "--max-age", "off", "--no-config", "--merge-source", rogue)
    code, out, err = run_hook(capsys, monkeypatch, hook_event(GOOD), *common)
    assert code == 0
    assert out == "" and err == ""

    code, out, err = run_hook(capsys, monkeypatch, hook_event(GOOD), *common,
                              "--drift-policy", "block")
    assert code == 2
    assert out == ""
    assert "drift:material" in err and "source_ranges" in err


def test_hook_resolves_a_different_config_for_each_edited_file(
        capsys, monkeypatch, tmp_path):
    """THE PIECE THAT MAKES ONE HOOK COMMAND LINE CORRECT FOR A WHOLE REPO.

    Two edited files under two terraform roots, one fixed command line, two
    different current states — which a hook command line, one fixed string
    nobody edits per run, structurally cannot express.
    """
    seen = {}
    for name in ("alpha", "beta"):
        root = tmp_path / name
        state = write_json(root / "terraform.tfstate", firewall_state())
        write_json(root / ".gcp-grounding.json",
                   {"schema": discovery.CONFIG_SCHEMA, "snapshot": str(ESTATE),
                    "max_age": "off", "terraform": {"state": [state]}})
        document = write_json(root / "policy.json",
                              json.loads(GOOD.read_text(encoding="utf-8")))
        code, out, err = run_hook(capsys, monkeypatch, hook_event(document),
                                  "--state-explain")
        assert code == 0
        assert out == ""
        seen[name] = (state, err)
    for name, (state, err) in seen.items():
        other = seen["beta" if name == "alpha" else "alpha"][0]
        assert state in err
        assert other not in err
