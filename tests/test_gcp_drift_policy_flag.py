"""Acceptance for audit row R01: ``--drift-policy`` beats the environment.

``README.md`` states the precedence once, for every setting — "Flags beat the
environment, the environment beats the config file" — and ``--drift-policy``
has two halves that used to obey it differently. The ``block`` half was wired
through ``EvalOptions.drift`` and behaved. The ``abstain`` half is implemented
by the taint adjudicator, which read ``$GCP_GROUNDING_DRIFT_POLICY`` from deep
inside :func:`gcp_grounding.registry._guarded_call` and never saw the resolved
options at all, so the flag was inert and the variable outranked it. The
polarity is what made that urgent: an exported ``abstain`` turns every blocking
built-in finding into an abstention and ``exit 0``, and a CI job that types
``--drift-policy annotate`` to stop exactly that did not get it.

THREE LAYERS, and the first is the one the other two rest on.

ONE, THE SEAM. :class:`~gcp_grounding.registry.CheckContext` now carries the
resolved policy and the environment is only what a context carrying none falls
back to. Both directions are asserted — a flag-shaped context winning over a
disagreeing variable, and a variable still deciding when no context resolved
one — because a fix that merely stopped reading the environment would pass the
first and break every library caller.

TWO, END TO END. The audit measured this through ``verify-policy`` over one
disputed firewall row, so its four runs plus the unconfigured control are
replayed through ``cli.main``, exit codes included.

THREE, RULE 3 IS NOT A POLICY DECISION. The carve-out that downgrades a
``contradicted`` resting only on a phantom fact is reached BEFORE rule 2 and
fires under every one of :data:`gcp_grounding.drift.DRIFT_POLICIES`, so
threading a resolved policy into the seam gives no operator a way to switch it
off. The audit never exercised it, and probing it turned up the reason a
reader would otherwise have to rediscover: rule 3 is all-or-nothing over the
read set and a WHOLE-CATEGORY read can never be a phantom, while a check that
reaches a record through ``ReconciledSnapshot``'s keyed accessor presents two
pairs — the key from the accessor's own tap, the category from the raw-field
tap in ``__getattribute__``. The carve-out therefore stays out of reach along
that route, and the measurement that shows why is pinned beside it.

Nothing here inherits an environment: an autouse fixture scrubs every
``GCP_GROUNDING_*`` variable, so no assertion can be decided by a developer's
exported policy, and the clock is pinned per run rather than taken from the
wall. In-process throughout: no subprocess is spawned, so nothing here lands on
the suite's spawn budget.
"""

from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path

import pytest

from gcp_grounding import drift, engine, provenance, reconciled, registry
from gcp_grounding.claims import Claim
from gcp_grounding.cli import EXIT_FAILED, EXIT_OK, main
from gcp_grounding.core.report import Verdict
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.provenance import (
    CategoryScope,
    Dispute,
    FactOrigin,
    SourceLedger,
    SourceRecord,
)
from gcp_grounding.reconciled import ReconciledSnapshot
from gcp_grounding.registry import CheckContext

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
DRIFT_DIR = FIXTURES / "drift"
ESTATE = FIXTURES / "estate_snapshot.json"

#: The proposal: one INGRESS rule reachable from a public source range, which
#: ``fw_checks.check_open_exposure`` answers ``contradicted`` about. It is the
#: audit's own shape — a blocking built-in finding, which is what ``abstain``
#: suppresses and what the flag has to be able to keep.
OPEN_RULE = FIXTURES / "policies" / "fw_rule_open.json"

#: Whether the exposure check can decide at all. Without z3 it abstains for its
#: own reason, no decided verdict reaches the adjudicator, and the CLI cells
#: below can tell no two policies apart — which
#: :func:`test_the_flag_decides_the_run_through_the_cli` branches on and states
#: rather than skipping.
HAVE_Z3 = get_solver().backend == "z3"

#: Pinned per run: the estate fixture is stamped 2026-07-18T09:30:00Z and the
#: drift fixtures 2026-07-17T12:00:00Z, so a wall-clock run would start
#: demoting both for staleness and change the exit codes asserted here.
NOW = "2026-07-19T00:00:00Z"

CAPTURED = "2026-01-01T00:00:00Z"
RULE = "projects/acme-prod/global/firewalls/allow-internal"
OTHER = "projects/acme-prod/global/firewalls/deny-ssh-external"
STUB = "gcp_grounding_stub_policy_flag_provider"

API_ID = "api-capture"
API_ORIGIN = "compute.firewalls.list"
API_CAPTURED_AT = "2026-07-18T09:30:00Z"

API = SourceRecord(source_id=API_ID, kind="api", scope="complete",
                   origin=API_ORIGIN)
TFSTATE = SourceRecord(source_id="tf-state", kind="tfstate", scope="partial",
                       origin="terraform.tfstate")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """No test here inherits an exported state configuration, a warm provider
    cache or an open read set from its neighbour."""
    for name in list(os.environ):
        if name.startswith("GCP_GROUNDING"):
            monkeypatch.delenv(name, raising=False)
    registry.reset_cache()
    yield
    registry.reset_cache()
    assert reconciled.active_reads() == ()


# -- LAYER ONE: the seam ------------------------------------------------------

#: A firewall table both views hold. Populated rather than left ``None`` so the
#: ledger is the only thing that can make this view anything but clean.
RULES = {
    RULE: {"network": "projects/acme-prod/global/networks/vpc",
           "direction": "INGRESS", "action": "allow", "priority": 1000,
           "disabled": False, "source_ranges": ["10.0.0.0/8"],
           "layer4": [{"protocol": "tcp", "ports": ["22"]}]},
    OTHER: {"network": "projects/acme-prod/global/networks/vpc",
            "direction": "INGRESS", "action": "deny", "priority": 900,
            "disabled": False, "source_ranges": ["0.0.0.0/0"],
            "layer4": [{"protocol": "tcp", "ports": ["22"]}]},
}


def _ledger(*, categories=None, facts=None, disputes=()) -> SourceLedger:
    return SourceLedger(sources={record.source_id: record
                                 for record in (API, TFSTATE)},
                        categories=dict(categories or {}),
                        facts=dict(facts or {}),
                        disputes=tuple(disputes))


def _snapshot(ledger: SourceLedger, *, disputes=()) -> ReconciledSnapshot:
    return ReconciledSnapshot.from_snapshot(
        GcpSnapshot(captured_at=CAPTURED, firewall_rules=dict(RULES)),
        ledger=ledger, disputes=tuple(disputes),
        policy_name="highest-fidelity-wins")


def _disputed_snapshot() -> ReconciledSnapshot:
    """A complete firewall table in which one key's own fact is tainted — the
    partly-uncertain evidence rule 2 is about, and NOT an existence dispute, so
    rule 3's carve-out cannot fire and hide which rule did the work."""
    return _snapshot(_ledger(
        categories={"firewall_rules": CategoryScope(
            scope="complete", source_kinds=("api",), keys=len(RULES))},
        facts={"firewall_rules": {
            RULE: FactOrigin(source_id="tf-state", locator="a", taint="disputed"),
            OTHER: FactOrigin(source_id=API_ID, locator="b")}}))


def _phantom_snapshot() -> ReconciledSnapshot:
    """One key the partial terraform view holds and the COMPLETE api capture
    says is gone: rule 3's phantom."""
    dispute = Dispute(
        category="firewall_rules", key=RULE, field="", severity="material",
        left="tf-state", right=API_ID,
        reason=f"'{RULE}' is present in ['tf-state'] but ABSENT from "
               f"'{API_ID}', which enumerated 'firewall_rules' completely")
    return _snapshot(_ledger(disputes=(dispute,)), disputes=(dispute,))


def _rule_contradicted(claim, ctx):
    """A check that reads exactly one estate fact and finds against it."""
    ctx.snapshot.firewall_rule(RULE)
    return [Verdict("contradicted", "firewall", RULE, 0, "the rule is unreachable")]


def _reads_two_rules(claim, ctx):
    """The same finding with a SECOND, undisputed fact behind it — rule 3's
    boundary."""
    ctx.snapshot.firewall_rule(RULE)
    ctx.snapshot.firewall_rule(OTHER)
    return [Verdict("contradicted", "firewall", RULE, 0, "the rule is unreachable")]


def install(monkeypatch, check=_rule_contradicted) -> None:
    """One stub provider registering *check*, named through
    ``PROVIDER_MODULES`` — the discovery recipe production uses."""
    module = types.ModuleType(STUB)
    module.CLAIM_CHECKS = {"firewall_rule": check}
    monkeypatch.setitem(sys.modules, STUB, module)
    monkeypatch.setattr(registry, "PROVIDER_MODULES", (STUB,))
    registry.reset_cache()


def _ctx(snapshot, policy: str = "") -> CheckContext:
    return CheckContext(snapshot=snapshot, solver=get_solver(),
                        document={"bindings": []}, document_kind="iam_policy",
                        source="<policy object>", claims=(),
                        drift_policy=policy)


def _claim() -> Claim:
    return Claim("firewall_rule", "allow-internal", "rules[0]")


def _graded(monkeypatch, policy: str, environment: str | None) -> Verdict:
    install(monkeypatch)
    if environment is not None:
        monkeypatch.setenv(registry.DRIFT_POLICY_ENV, environment)
    [verdict] = registry.run_claim_checks(_claim(), _ctx(_disputed_snapshot(),
                                                         policy))
    return verdict


def test_a_resolved_abstain_downgrades_with_nothing_in_the_environment(monkeypatch):
    """THE DEFECT, at the seam. Before the fix the context's policy was never
    consulted, so a resolved ``abstain`` did nothing at all and the finding
    stood."""
    verdict = _graded(monkeypatch, "abstain", None)
    assert verdict.status == "unverified"
    assert drift.ABSTAIN_REASON in verdict.message


@pytest.mark.parametrize("policy,environment,status", [
    ("abstain", "annotate", "unverified"),
    ("annotate", "abstain", "contradicted"),
    ("abstain", "block", "unverified"),
    ("block", "abstain", "contradicted"),
])
def test_the_resolved_policy_beats_the_environment_both_ways(
        monkeypatch, policy, environment, status):
    """Both directions, because one of them is the dangerous one: a context
    resolving ``annotate`` over an exported ``abstain`` must KEEP the finding.
    Before the fix that cell downgraded, which is a CI job asking for findings
    and being handed abstentions."""
    assert _graded(monkeypatch, policy, environment).status == status


@pytest.mark.parametrize("environment,status", [
    ("abstain", "unverified"),
    ("annotate", "contradicted"),
    (None, "contradicted"),
])
def test_the_environment_still_decides_for_a_context_that_resolved_none(
        monkeypatch, environment, status):
    """THE FALLBACK, kept. A library caller that builds its own
    :class:`~gcp_grounding.registry.CheckContext` resolves no policy, and
    :data:`gcp_grounding.registry.DRIFT_POLICY_ENV` is what still answers for
    it. A fix that stopped reading the variable would pass every assertion
    above and silently retire this."""
    assert _graded(monkeypatch, "", environment).status == status


def test_an_unrecognised_resolved_policy_costs_the_default_and_never_raises(
        monkeypatch):
    """The context is not a validation boundary. ``sources._resolve`` reports a
    bad token to a human as a usage error; this runs once per provider callable
    and must not turn a grounding run into a crash."""
    assert _graded(monkeypatch, "definitely-not-a-policy", None).status \
        == "contradicted"


def test_the_context_default_is_empty_so_no_caller_has_to_know_about_drift():
    """Every existing construction site kept working unchanged, which is the
    property that made threading this safe to land on the check seam."""
    assert CheckContext(snapshot=GcpSnapshot(captured_at=CAPTURED),
                        solver=None, document=None, document_kind=None,
                        source="", claims=()).drift_policy == ""


# -- LAYER TWO: the audit's own runs, through the CLI -------------------------


@pytest.fixture
def api_origins(tmp_path) -> str:
    """The frozen estate fixture as a DECLARED api capture, complete in every
    category it holds — the sidecar that makes the merged view reconciled and
    gives the adjudicator provenance to grade."""
    snapshot = GcpSnapshot.load(ESTATE)
    builder = provenance.LedgerBuilder()
    builder.source(API_ID, "api", origin=API_ORIGIN,
                   captured_at=API_CAPTURED_AT, scope="complete")
    for category in snapshot.captured_categories():
        builder.declare(category, scope="complete", source_kinds=("api",))
    path = tmp_path / "api.origins.json"
    builder.build().write(path)
    return str(path)


def cli_run(capsys, monkeypatch, origins: str, *, flag: str | None,
            environment: str | None):
    """``verify-policy`` over the open rule against the two-source state."""
    if environment is not None:
        monkeypatch.setenv(registry.DRIFT_POLICY_ENV, environment)
    argv = ["verify-policy", str(OPEN_RULE), "--snapshot", str(ESTATE),
            "--merge-source", str(DRIFT_DIR / "tf_dangerous.json"),
            "--origins", origins, "--as-of", NOW, "--no-config",
            "--format", "json"]
    if flag is not None:
        argv += ["--drift-policy", flag]
    code = main(argv)
    out, _err = capsys.readouterr()
    return code, json.loads(out)


def exposure(document) -> list[dict]:
    return [v for v in document["verdicts"] if v["kind"] == "firewall_exposure"]


#: ``(flag, environment, exit code, status)`` — the audit's four runs plus the
#: unconfigured control, which is row one and was always right. Rows two, four
#: and five are the three the audit measured wrong: the flag was inert, so the
#: environment alone decided all three.
CELLS = [
    (None, None, EXIT_FAILED, "contradicted"),
    ("abstain", None, EXIT_OK, "unverified"),
    (None, "abstain", EXIT_OK, "unverified"),
    ("annotate", "abstain", EXIT_FAILED, "contradicted"),
    ("abstain", "annotate", EXIT_OK, "unverified"),
]


@pytest.mark.parametrize("flag,environment,code,status", CELLS,
                         ids=[f"flag={flag or '-'},env={env or '-'}"
                              for flag, env, _code, _status in CELLS])
def test_the_flag_decides_the_run_through_the_cli(capsys, monkeypatch,
                                                  api_origins, flag,
                                                  environment, code, status):
    """The audit's measurement, as a table. The exit code is the operator's
    whole answer, so it is asserted beside the verdict that produced it.

    BRANCHED RATHER THAN SKIPPED on the backend: with no z3 the exposure check
    abstains before it decides anything, so no cell here can tell the policies
    apart and the run passes for a reason that has nothing to do with drift.
    That case is asserted for what it is — every cell exits 0 with nothing
    decided — and the seam tests above carry the contract instead."""
    exit_code, document = cli_run(capsys, monkeypatch, api_origins, flag=flag,
                                  environment=environment)
    findings = exposure(document)
    if not HAVE_Z3:
        assert exit_code == EXIT_OK
        assert {v["status"] for v in findings} <= {"unverified"}
        assert drift.ABSTAIN_REASON not in json.dumps(document)
        return
    [finding] = findings
    assert exit_code == code
    assert finding["status"] == status
    if status == "unverified":
        assert drift.ABSTAIN_REASON in finding["message"]
    else:
        assert drift.ABSTAIN_REASON not in finding["message"]


def test_the_resolved_policy_reaches_the_engine_options(monkeypatch, tmp_path):
    """The one carrier: ``EvalOptions`` speaks the engine's two-value drift
    MODE, in which ``abstain`` has no spelling at all, so the loading side's
    three-value policy travels beside it or the adjudicator never learns it."""
    from gcp_grounding import cli, discovery

    monkeypatch.setenv(registry.DRIFT_POLICY_ENV, "abstain")
    settings = discovery.resolve_settings(cli={"drift_policy": "annotate"})
    assert settings.options.drift_policy == "annotate"
    options = cli._eval_options(types.SimpleNamespace(no_auto_baseline=False),
                                settings, str(tmp_path / "policy.json"))
    assert options.drift_policy == "annotate"
    assert options.drift == engine.DEFAULT_DRIFT_MODE


def test_eval_options_refuses_a_policy_its_vocabulary_does_not_name():
    """A typo that restored the default would change what the gate enforces
    with nothing saying so — the same refusal ``drift`` already gets."""
    with pytest.raises(ValueError, match="drift_policy"):
        engine.EvalOptions(drift_policy="anotate")
    assert engine.EvalOptions().drift_policy == ""


# -- LAYER THREE: rule 3, which no policy may switch off ----------------------

#: One pair: the phantom alone, which is what rule 3's all-or-nothing condition
#: needs. A read set is a set of ``(category, key)`` pairs, and the adjudicator
#: takes it as an argument, so a probe can state one exactly.
PHANTOM_ONLY = (("firewall_rules", RULE),)

#: The phantom plus one fact nobody disputes — the boundary the carve-out is
#: only sound because of.
PHANTOM_AND_ONE = (("firewall_rules", RULE), ("firewall_rules", OTHER))


def _finding() -> Verdict:
    return Verdict("contradicted", "firewall", RULE, 0, "the rule is unreachable")


@pytest.mark.parametrize("policy", list(drift.DRIFT_POLICIES))
def test_rule_three_downgrades_a_phantom_only_finding_under_every_policy(policy):
    """THE PROBE THE AUDIT DID NOT RUN. A ``contradicted`` whose entire read
    set is a resource the COMPLETE source says was deleted has no evidence
    left, and that is a property of the evidence rather than a grading choice:
    it holds under every one of :data:`gcp_grounding.drift.DRIFT_POLICIES`, and
    the reason it names is rule 3's phantom, never rule 2's abstention. Threading
    a resolved policy into the seam must not hand an operator a way to switch
    this off, and nothing else in this module would notice if it had."""
    [verdict] = drift.adjudicate((_finding(),), PHANTOM_ONLY,
                                 _phantom_snapshot(), policy)

    assert verdict.status == "unverified"
    assert "PHANTOM" in verdict.message
    assert RULE in verdict.message                   # the phantom fact
    assert "tf-state" in verdict.message             # both sources, by name
    assert API_ID in verdict.message
    assert drift.ABSTAIN_REASON not in verdict.message


@pytest.mark.parametrize("policy", ["annotate", "block"])
def test_one_undisputed_fact_keeps_the_finding_under_every_keeping_policy(policy):
    """Rule 3's boundary, beside it: one fact nobody disputes is evidence
    enough. ``abstain`` is excluded because rule 2 then downgrades this verdict
    for its OWN reason, which is the contract layer one pins."""
    [verdict] = drift.adjudicate((_finding(),), PHANTOM_AND_ONE,
                                 _phantom_snapshot(), policy)

    assert verdict == _finding()


@pytest.mark.parametrize("policy,status", [("annotate", "contradicted"),
                                           ("block", "contradicted"),
                                           ("abstain", "unverified")])
def test_a_keyed_accessor_read_does_not_meet_rule_threes_condition(monkeypatch,
                                                                   policy, status):
    """WHAT THE PROBE FOUND, pinned rather than left as folklore.

    Rule 3 is all-or-nothing over the read set, and a whole-category read can
    never be a phantom. A check that reaches a record through the keyed
    accessor presents TWO pairs, not one: ``ReconciledSnapshot.firewall_rule``
    notes the key, and the raw-field tap in ``__getattribute__`` notes the
    category as the underlying method reads ``self.firewall_rules``. So the
    carve-out does not fire through this route, and what decides the verdict is
    the resolved policy under rule 2 — which is exactly the setting this task
    threaded, measured on the one case where both rules could plausibly apply.
    """
    install(monkeypatch)

    [verdict] = registry.run_claim_checks(_claim(),
                                          _ctx(_phantom_snapshot(), policy))

    assert verdict.status == status
    assert "PHANTOM" not in verdict.message


def test_the_keyed_accessor_read_set_is_the_two_pairs_that_explain_it():
    """The measurement behind the test above, stated once so a future reader
    does not have to rediscover why rule 3 stayed out of reach here."""
    with reconciled.reads("probe") as read_set:
        _phantom_snapshot().firewall_rule(RULE)

    assert tuple(read_set.reads) == (("firewall_rules", RULE),
                                     ("firewall_rules", ""))


@pytest.mark.parametrize("policy", ["annotate", "block"])
def test_a_sweeping_check_keeps_its_finding_whatever_the_read_set_holds(
        monkeypatch, policy):
    """The second half of the same boundary through the seam: a check that also
    reads an undisputed sibling keeps its finding under every policy that keeps
    findings at all."""
    install(monkeypatch, _reads_two_rules)

    [verdict] = registry.run_claim_checks(_claim(),
                                          _ctx(_phantom_snapshot(), policy))

    assert verdict.status == "contradicted"
    assert "PHANTOM" not in verdict.message
