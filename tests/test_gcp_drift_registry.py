"""Acceptance for the registry's two adjudication edits: every domain check now
runs through the drift guard, and every DOCUMENT check runs behind the
estate-tier completeness gate.

Three properties are pinned here, and the first is the one that makes the other
two safe to land on the highest-regression-risk seam in the repo.

ONE, IT IS INERT WHERE THERE IS NOTHING TO GUARD. With a plain ``GcpSnapshot``
the call path is the one the seam shipped with: no read context is opened at all,
which is asserted by making ``drift.reads`` RAISE rather than by inspecting what
it collected. An inert reconciled snapshot answers identically by value, and with
the drift module absent from ``sys.modules`` a whole ``ground_policy`` run is
byte-identical.

TWO, A DISPUTED FACT CANNOT MINT A CLEAN PASS — and the boundary is asserted
beside it. A check reading the disputed key loses its ``grounded``; a SIBLING
check in the SAME run reading an undisputed key keeps its own. A blanket
downgrade would pass the first assertion and fail the second.

THREE, THE ESTATE GATE STOPS AN UNSOUND NEGATIVE BEFORE THE CHECK RUNS. A
``requires_complete`` check over a partial view is not invoked at all — asserted
with a call counter, because a gate that runs the check and then rewrites its
answer has already paid for the unsound sweep — and the undeclared case is
asserted to COST a clean pass rather than to buy one.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

from gcp_grounding import drift, provenance, reconciled, registry
from gcp_grounding.claims import Claim
from gcp_grounding.core.report import Verdict
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.preflight import ground_policy
from gcp_grounding.provenance import (
    CategoryScope,
    FactOrigin,
    SourceLedger,
    SourceRecord,
)
from gcp_grounding.reconciled import ReconciledSnapshot
from gcp_grounding.registry import CheckContext

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"

#: Environment-honest exactly like ``test_gcp_registry``: the tf-plan bundle
#: grounds different verdicts depending on whether the extractor is installed,
#: and the byte-identity assertion below holds either way rather than skipping.
HAVE_TF = importlib.util.find_spec("gcp_grounding.tf_claims") is not None

CAPTURED = "2026-01-01T00:00:00Z"
RULE = "projects/acme-prod/global/firewalls/allow-internal"
OTHER = "projects/acme-prod/global/firewalls/deny-ssh-external"
STUB = "gcp_grounding_stub_drift_provider"

API = SourceRecord(source_id="api-capture", kind="api", scope="complete",
                   origin="compute.firewalls.list")
TFSTATE = SourceRecord(source_id="tf-state", kind="tfstate", scope="partial",
                       origin="terraform.tfstate")


# -- fixtures and builders ----------------------------------------------------


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """No test may leak a provider, a warm cache, a soundness registration, a
    configured drift policy or an open read set into the next.

    ``_ESTATE_SOUNDNESS_CATEGORY`` is restored through its module attribute
    because :mod:`gcp_grounding.provenance` exposes no reset — the registry is
    written once at a domain module's import time in production, so nothing but
    a test ever needs to unwind it.
    """
    monkeypatch.delenv(registry.DRIFT_POLICY_ENV, raising=False)
    registry.reset_cache()
    modes = dict(provenance.ESTATE_SOUNDNESS)
    categories = dict(provenance._ESTATE_SOUNDNESS_CATEGORY)
    CALLS.clear()
    yield
    registry.reset_cache()
    provenance.ESTATE_SOUNDNESS.clear()
    provenance.ESTATE_SOUNDNESS.update(modes)
    provenance._ESTATE_SOUNDNESS_CATEGORY.clear()
    provenance._ESTATE_SOUNDNESS_CATEGORY.update(categories)
    assert reconciled.active_reads() == ()


def install(monkeypatch, *modules: dict) -> None:
    """Inject one stub provider per mapping and name them — and only them — in
    ``PROVIDER_MODULES``: the exact discovery recipe production uses.

    Several are supported because "one check's fact is disputed and its
    sibling's is not" needs two providers registering the SAME claim kind, which
    a single module cannot express.
    """
    names = []
    for index, attrs in enumerate(modules):
        name = f"{STUB}_{index}"
        module = types.ModuleType(name)
        for key, value in attrs.items():
            setattr(module, key, value)
        monkeypatch.setitem(sys.modules, name, module)
        names.append(name)
    monkeypatch.setattr(registry, "PROVIDER_MODULES", tuple(names))
    registry.reset_cache()


#: A firewall table both views agree exists. Populated rather than left ``None``
#: so the ledger is the ONLY thing that can make this view partial: with an
#: empty table, "uncaptured" would gate the estate checks below for the wrong
#: reason and the gate would look right while reading the wrong source.
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


def _ledger(*, categories=None, facts=None) -> SourceLedger:
    return SourceLedger(sources={record.source_id: record
                                 for record in (API, TFSTATE)},
                        categories=dict(categories or {}),
                        facts=dict(facts or {}))


def _snapshot(ledger: SourceLedger | None = None, **fields) -> ReconciledSnapshot:
    fields.setdefault("firewall_rules", dict(RULES))
    return ReconciledSnapshot.from_snapshot(
        GcpSnapshot(captured_at=CAPTURED, **fields), ledger=ledger,
        policy_name="highest-fidelity-wins")


def _complete_scope() -> CategoryScope:
    return CategoryScope(scope="complete", source_kinds=("api",), keys=len(RULES))


def _partial_scope() -> CategoryScope:
    return CategoryScope(scope="partial", source_kinds=("tfstate",), keys=len(RULES))


def _disputed_snapshot() -> ReconciledSnapshot:
    """A COMPLETE firewall table in which one key's own fact is disputed. The
    category is deliberately clean, so only the per-fact taint can move a
    verdict and a category-wide downgrade cannot pass for one."""
    return _snapshot(_ledger(
        categories={"firewall_rules": _complete_scope()},
        facts={"firewall_rules": {
            RULE: FactOrigin(source_id="tf-state", locator="a", taint="disputed"),
            OTHER: FactOrigin(source_id="api-capture", locator="b")}}))


def _untainted_snapshot() -> ReconciledSnapshot:
    """The same view with nothing in dispute: the inert case."""
    return _snapshot(_ledger(
        categories={"firewall_rules": _complete_scope()},
        facts={"firewall_rules": {
            RULE: FactOrigin(source_id="api-capture", locator="a"),
            OTHER: FactOrigin(source_id="api-capture", locator="b")}}))


def _partial_snapshot() -> ReconciledSnapshot:
    """A terraform-only view: the firewall table covers what terraform manages
    and nothing else, so it can license no negative."""
    return _snapshot(_ledger(categories={"firewall_rules": _partial_scope()}))


def _plain() -> GcpSnapshot:
    """The single-capture path: the same estate data with no provenance at all."""
    return GcpSnapshot(captured_at=CAPTURED, firewall_rules=dict(RULES))


def _ctx(snapshot) -> CheckContext:
    return CheckContext(snapshot=snapshot, solver=get_solver(),
                        document={"bindings": []}, document_kind="iam_policy",
                        source="<policy object>", claims=())


def _claim() -> Claim:
    return Claim("firewall_rule", "allow-internal", "rules[0]")


# -- the stub providers, module-level so their identities are stable ----------

#: Which providers ran, in order — the counter the estate gate is asserted with.
CALLS: list[str] = []


def _rule_grounded(claim, ctx):
    ctx.snapshot.firewall_rule(RULE)          # the keyed accessor: a tapped read
    return [Verdict("grounded", "firewall", RULE, 0, "the rule is reachable")]


def _other_grounded(claim, ctx):
    ctx.snapshot.firewall_rule(OTHER)
    return [Verdict("grounded", "firewall", OTHER, 0, "the rule is reachable")]


def _rule_contradicted(claim, ctx):
    ctx.snapshot.firewall_rule(RULE)
    return [Verdict("contradicted", "firewall", RULE, 0, "the rule is unreachable")]


def _rule_raises(claim, ctx):
    raise RuntimeError("kaboom")


def _doc_rule_grounded(ctx):
    ctx.snapshot.firewall_rule(RULE)
    return [Verdict("grounded", "firewall", RULE, 0, "the document is consistent")]


def _pair_rule_grounded(ctx):
    ctx.snapshot.firewall_rule(RULE)
    return [Verdict("grounded", "subset", RULE, 0, "the change grants nothing new")]


def _estate_doc_check(ctx):
    """A fake estate-tier check: it SWEEPS the whole firewall table and concludes
    a universally-quantified NEGATIVE — exactly the claim a partial view cannot
    support, and exactly the claim a read tap cannot recognise."""
    CALLS.append("estate")
    ctx.snapshot.firewall_rules_for_network("vpc")
    return [Verdict("grounded", "firewall", "no-rule-allows-world-ssh", 0,
                    "no firewall rule anywhere allows 0.0.0.0/0 on port 22")]


def _subset_doc_check(ctx):
    """A witness-finder: a subset can only make it quieter, never wrong."""
    CALLS.append("subset")
    ctx.snapshot.firewall_rules_for_network("vpc")
    return [Verdict("contradicted", "firewall", RULE, 0,
                    "this rule allows 0.0.0.0/0 on port 22"),
            Verdict("grounded", "firewall", OTHER, 0, "and this one is fine")]


ESTATE_IDENTITY = registry._label(_estate_doc_check)
SUBSET_IDENTITY = registry._label(_subset_doc_check)


# -- one: inert where there is nothing to guard -------------------------------


def test_a_plain_snapshot_opens_no_read_context_at_all(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("a plain GcpSnapshot has no provenance to adjudicate "
                             "against, so no read context may be opened for it")

    monkeypatch.setattr(drift, "reads", explode)
    install(monkeypatch, {"CLAIM_CHECKS": {"firewall_rule": _rule_grounded}})

    out = registry.run_claim_checks(_claim(), _ctx(_plain()))

    assert [(v.status, v.kind, v.target) for v in out] == [("grounded", "firewall", RULE)]
    assert reconciled.active_reads() == ()


def test_an_untainted_reconciled_snapshot_answers_exactly_as_the_plain_one(monkeypatch):
    install(monkeypatch, {"CLAIM_CHECKS": {"firewall_rule": _rule_grounded}})

    plain = registry.run_claim_checks(_claim(), _ctx(_plain()))
    merged = registry.run_claim_checks(_claim(), _ctx(_untainted_snapshot()))

    assert merged == plain                    # equal BY VALUE, message included
    assert [v.status for v in merged] == ["grounded"]


@pytest.mark.parametrize("name", ["iam_policy_good", "tf_plan_full"])
def test_an_absent_drift_module_leaves_ground_policy_byte_identical(monkeypatch, name):
    snap = GcpSnapshot.load(FIXTURES / "snapshot.json")
    path = POLICIES / f"{name}.json"
    before = json.dumps(ground_policy(path, snap).to_dict(), sort_keys=True)

    # `from . import drift` would be answered from the package attribute and
    # sail past this; the registry resolves through importlib for that reason.
    monkeypatch.setitem(sys.modules, "gcp_grounding.drift", None)
    assert registry._guard() is None

    after = json.dumps(ground_policy(path, snap).to_dict(), sort_keys=True)
    assert after == before
    # Environment-honest rather than skipped: without the tf extractor the plan
    # bundle grounds an honest abstention instead of claims, and the identity
    # above is asserted over whichever of the two this checkout produces.
    if name == "tf_plan_full" and not HAVE_TF:
        assert "tf_claims" in after


# -- two: a disputed fact cannot mint a clean pass ----------------------------


def test_a_grounded_on_a_disputed_fact_is_downgraded_and_its_sibling_is_not(monkeypatch):
    # TWO providers, same claim kind, one run: the disputed read and the
    # undisputed one are adjudicated side by side.
    install(monkeypatch,
            {"CLAIM_CHECKS": {"firewall_rule": _rule_grounded}},
            {"CLAIM_CHECKS": {"firewall_rule": _other_grounded}})

    disputed, sibling = registry.run_claim_checks(_claim(), _ctx(_disputed_snapshot()))

    assert disputed.status == "unverified" and disputed.target == RULE
    assert "[not decided:" in disputed.message
    assert RULE in disputed.message and "disputed" in disputed.message
    # The boundary: a blanket downgrade would pass the assertion above.
    assert sibling.status == "grounded" and sibling.target == OTHER
    assert "[not decided:" not in sibling.message


def test_a_contradicted_keeps_its_status_by_default_and_abstains_on_request(monkeypatch):
    install(monkeypatch, {"CLAIM_CHECKS": {"firewall_rule": _rule_contradicted}})
    ctx = _ctx(_disputed_snapshot())

    [kept] = registry.run_claim_checks(_claim(), ctx)
    assert kept.status == "contradicted"      # the default is NOT a suppressor

    monkeypatch.setenv(registry.DRIFT_POLICY_ENV, "abstain")
    [flipped] = registry.run_claim_checks(_claim(), ctx)
    assert flipped.status == "unverified"
    assert drift.ABSTAIN_REASON in flipped.message


@pytest.mark.parametrize("factory", [
    _plain,
    _disputed_snapshot,
])
def test_a_raising_provider_still_yields_exactly_one_unverified(monkeypatch, factory):
    install(monkeypatch, {"CLAIM_CHECKS": {"firewall_rule": _rule_raises}})

    out = registry.run_claim_checks(_claim(), _ctx(factory()))

    # The guard neither swallowed the exception nor added a second verdict:
    # the pre-existing handler still owns it, outside the guard.
    assert len(out) == 1
    [v] = out
    assert v.status == "unverified" and v.kind == "document"
    assert "_rule_raises" in v.message and "RuntimeError: kaboom" in v.message
    assert reconciled.active_reads() == ()


def test_the_document_helper_downgrades_a_grounded_on_a_disputed_fact(monkeypatch):
    install(monkeypatch, {"DOCUMENT_CHECKS": (_doc_rule_grounded,)})

    out = registry.run_document_checks(_ctx(_disputed_snapshot()))

    assert len(out) == 1
    assert out[0].status == "unverified"
    assert RULE in out[0].message and "disputed" in out[0].message


def test_the_pair_helper_downgrades_a_grounded_on_a_disputed_fact():
    out = registry.run_pair_check(_pair_rule_grounded, _ctx(_disputed_snapshot()))

    assert len(out) == 1
    assert out[0].status == "unverified" and out[0].kind == "subset"
    assert RULE in out[0].message and "disputed" in out[0].message


# -- three: the estate-tier completeness gate ---------------------------------


def test_the_gate_is_inert_on_the_single_capture_path(monkeypatch):
    # A plain GcpSnapshot declares no coverage to be partial ABOUT: reading it
    # as incomplete would downgrade every clean answer every estate check has
    # ever given, on the one path this edit must not disturb.
    install(monkeypatch, {"DOCUMENT_CHECKS": (_estate_doc_check,)})

    out = registry.run_document_checks(_ctx(_plain()))

    assert CALLS == ["estate"]
    assert [(v.status, v.target) for v in out] == \
        [("grounded", "no-rule-allows-world-ssh")]
    assert "[not decided:" not in out[0].message


def test_a_requires_complete_check_is_not_invoked_at_all_over_a_partial_view(monkeypatch):
    provenance.register_estate_soundness(ESTATE_IDENTITY, "requires_complete",
                                         "firewall_rules")
    install(monkeypatch, {"DOCUMENT_CHECKS": (_estate_doc_check,)})

    out = registry.run_document_checks(_ctx(_partial_snapshot()))

    # THE POINT: not "ran and was rewritten" — never called.
    assert CALLS == []
    assert len(out) == 1
    [v] = out
    assert v.status == "unverified" and v.kind == registry.ESTATE_INCOMPLETE
    assert v.kind == "estate:incomplete"
    assert ESTATE_IDENTITY in v.message                  # the check
    assert "firewall_rules" in v.message                 # the category
    assert "tfstate" in v.message and "partial" in v.message   # sources and scope
    assert "AN ESTATE-WIDE CLAIM CANNOT BE MADE FROM A PARTIAL VIEW" in v.message
    assert "THIS CHECK DID NOT RUN" in v.message


def test_the_same_check_runs_normally_over_a_complete_untainted_view(monkeypatch):
    provenance.register_estate_soundness(ESTATE_IDENTITY, "requires_complete",
                                         "firewall_rules")
    install(monkeypatch, {"DOCUMENT_CHECKS": (_estate_doc_check,)})

    out = registry.run_document_checks(_ctx(_untainted_snapshot()))

    assert CALLS == ["estate"]
    assert [(v.status, v.target) for v in out] == \
        [("grounded", "no-rule-allows-world-ssh")]
    assert "[not decided:" not in out[0].message


def test_a_requires_complete_check_with_no_category_runs_but_is_not_trusted(monkeypatch):
    # Registered WITHOUT a category: nothing can be resolved to check, so the
    # check runs and its clean answer costs a pass rather than buying one.
    provenance.register_estate_soundness(ESTATE_IDENTITY, "requires_complete")
    install(monkeypatch, {"DOCUMENT_CHECKS": (_estate_doc_check,)})

    out = registry.run_document_checks(_ctx(_partial_snapshot()))

    assert CALLS == ["estate"]                # it RAN
    assert len(out) == 1
    assert out[0].status == "unverified"      # and was not trusted
    assert "[not decided:" in out[0].message
    assert "firewall_rules" in out[0].message and "partial" in out[0].message
    assert "must cost a clean pass, not buy one" in out[0].message
    # THE CHECK IS NAMED BY ITS KIND — the bracketed word the report already
    # prints this verdict under, and the only name for a check a reader of the
    # output has ever been given. Its dotted import path locates a source file
    # for whoever is editing this tree and names nothing for whoever is
    # reading the run.
    assert "the firewall check did not declare" in out[0].message
    assert ESTATE_IDENTITY not in out[0].message
    assert "gcp_grounding." not in out[0].message
    # One weak category is NAMED: "all 1 of them" is a list of one written the
    # long way round.
    assert "'firewall_rules' is partial" in out[0].message

    # Where SEVERAL share the clause and nothing else was declared, the list
    # collapses. Every category a single terraform capture supplies is partial
    # for the same reason, and the per-name list spent one sentence per
    # category to say one thing.
    CALLS.clear()
    uniform = _snapshot(_ledger(categories={
        "firewall_rules": _partial_scope(), "iam_bindings": _partial_scope(),
        "org_policies": _partial_scope()}))
    [collapsed] = registry.run_document_checks(_ctx(uniform))

    assert CALLS == ["estate"]
    assert "all 3 of this view's declared categories are partial" in collapsed.message
    assert "'firewall_rules' is partial" not in collapsed.message
    # ... but a view whose categories are weak for DIFFERENT reasons keeps
    # every name, grouped under the clause it shares.
    CALLS.clear()
    mixed = _snapshot(_ledger(categories={
        "firewall_rules": _partial_scope(), "iam_bindings": _partial_scope(),
        "org_policies": CategoryScope(scope="uncaptured", source_kinds=("api",))}))
    [grouped] = registry.run_document_checks(_ctx(mixed))

    assert "'firewall_rules', 'iam_bindings' are partial" in grouped.message
    assert "'org_policies' is uncaptured" in grouped.message


def test_a_subset_safe_check_keeps_its_finding_over_a_partial_view(monkeypatch):
    provenance.register_estate_soundness(SUBSET_IDENTITY, "subset_safe",
                                         "firewall_rules")
    install(monkeypatch, {"DOCUMENT_CHECKS": (_subset_doc_check,)})

    out = registry.run_document_checks(_ctx(_partial_snapshot()))

    assert CALLS == ["subset"]
    # A witness found in a subset is a real witness; the clean half is not.
    assert [(v.status, v.target) for v in out] == [("contradicted", RULE),
                                                   ("unverified", OTHER)]
    assert len(out) == 2                      # never emitted twice


def test_a_gated_document_check_reaches_the_report_exactly_once(monkeypatch):
    provenance.register_estate_soundness(ESTATE_IDENTITY, "requires_complete",
                                         "firewall_rules")
    install(monkeypatch, {"DOCUMENT_CHECKS": (_estate_doc_check,)})

    # An empty IAM allow policy: legitimately empty, so the gate's refusal is
    # the ONLY verdict the whole run can produce.
    report = ground_policy({"bindings": []}, _partial_snapshot())

    assert CALLS == []
    assert [v.kind for v in report.verdicts] == [registry.ESTATE_INCOMPLETE]


# -- configuration ------------------------------------------------------------


def test_an_unrecognised_drift_policy_falls_back_to_the_default(monkeypatch):
    monkeypatch.setenv(registry.DRIFT_POLICY_ENV, "definitely-not-a-policy")
    assert registry._drift_policy() == drift.DEFAULT_DRIFT_POLICY

    # And it costs the default behaviour, not a crash, deep in a real run:
    # under 'annotate' the contradicted stands.
    install(monkeypatch, {"CLAIM_CHECKS": {"firewall_rule": _rule_contradicted}})
    [v] = registry.run_claim_checks(_claim(), _ctx(_disputed_snapshot()))
    assert v.status == "contradicted"


def test_a_recognised_drift_policy_is_read_from_the_environment(monkeypatch):
    assert registry._drift_policy() == drift.DEFAULT_DRIFT_POLICY
    for policy in drift.DRIFT_POLICIES:
        monkeypatch.setenv(registry.DRIFT_POLICY_ENV, policy)
        assert registry._drift_policy() == policy
