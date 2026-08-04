"""Acceptance for :mod:`gcp_grounding.engine` — where the three inputs meet.

Everything here runs IN-PROCESS. Capability is branched on with plain
module-level booleans (the ``HAVE_Z3`` idiom) and never ``skipif``, so an absent
capability is asserted to degrade honestly rather than being quietly passed over.

The load-bearing tests, and the failure each one guards:

- :func:`test_the_pair_tier_dispatches_per_entry_and_never_on_the_plan_kind` —
  ``registry.PAIR_CHECKS`` is keyed by DOCUMENT KIND and the gate hands every
  ``.tf`` edit over as a terraform-plan-kind proposal, so dispatching on the
  PROPOSAL kind means ``pair_check("tf_plan")`` is None and NO pair check ever
  runs for a terraform edit at all. The regression is silent — it returns
  nothing — so the plan-kind call is counted rather than inferred.
- :func:`test_a_partial_baseline_downgrades_the_block_but_not_the_pass` and
  :func:`test_stage_six_applies_the_same_soundness_rewrite_as_stage_three` —
  the partial-baseline asymmetry, asserted from both directions and on both code
  paths. Stage 6 re-runs the pair check against the LOSING sources, so without
  the same rewrite it is a back door that reinstates exactly the false block the
  asymmetry forbids.
- :func:`test_the_estate_tier_runs_nothing_and_never_duplicates_a_verdict` —
  every registry DOCUMENT_CHECK has already run inside ``ground_policy`` by the
  time the estate tier is reached, so an engine-side re-run would duplicate
  every verdict while the ungated copy still emits its answer.
- :func:`test_after_unknown_is_derived_by_prepare_proposal` — an unknown plan
  attribute is OMITTED from ``change.after``, so nothing strips it, nothing
  reports it and the plan's LEAST CERTAIN attributes would otherwise get the
  CLEANEST pass in the whole system. Asserted with NO ``unknown_paths``
  argument, so the derivation is proved to be the helper's own.

TWO CAPABILITY BRANCHES, both probed rather than assumed:

``HAVE_Z3`` is the solver backend. ``HAVE_ESTATE_GATE`` is whether
``registry.run_document_checks`` gates a requires-complete document check
against a partial estate — the choke point ``tx-registry-adjudicate`` owns and
this task deliberately does NOT build, since ``preflight.py`` is on the
never-edit list and a second gate in the engine would duplicate every verdict.
Where the gate is present the estate test asserts the ``estate:incomplete``
abstention; where it is not, it asserts the half this module owns — that the
engine re-runs nothing and no document-check verdict is ever emitted twice.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

from gcp_grounding import (
    baseline,
    constraints,
    drift,
    engine,
    preflight,
    provenance,
    redact,
    registry,
)
from gcp_grounding.core.report import Verdict
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.provenance import Dispute, LedgerBuilder
from gcp_grounding.reconciled import ReconciledSnapshot
from gcp_grounding.registry import CheckContext

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"

HAVE_Z3 = get_solver().backend == "z3"

STUB = "gcp_grounding_stub_engine_provider"
PROBE_STUB = "gcp_grounding_stub_engine_probe"

CAPTURED_AT = "2026-07-18T09:30:00Z"

IAM_KEY = "//cloudresourcemanager.googleapis.com/projects/acme-prod"
FW_KEY = "projects/acme-prod/global/firewalls/allow-ssh"
PERIMETER_KEY = "accessPolicies/987/servicePerimeters/prod"


# -- shared fixtures ----------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_caches():
    """No test may leak an injected provider, a warm registry cache or a
    soundness registration into the next one — either registry is process-wide,
    and a leaked entry would silently change how a LATER test's check is
    graded."""
    registry.reset_cache()
    saved_pair = dict(engine.BASELINE_SOUNDNESS)
    saved_estate = dict(provenance.ESTATE_SOUNDNESS)
    yield
    engine.BASELINE_SOUNDNESS.clear()
    engine.BASELINE_SOUNDNESS.update(saved_pair)
    provenance.ESTATE_SOUNDNESS.clear()
    provenance.ESTATE_SOUNDNESS.update(saved_estate)
    registry.reset_cache()


def install(monkeypatch, **attrs) -> types.ModuleType:
    """Inject a stub provider and name it (and only it) in
    ``PROVIDER_MODULES`` — the exact discovery recipe production uses."""
    module = types.ModuleType(STUB)
    for name, value in attrs.items():
        setattr(module, name, value)
    monkeypatch.setitem(sys.modules, STUB, module)
    monkeypatch.setattr(registry, "PROVIDER_MODULES", (STUB,))
    registry.reset_cache()
    return module


def load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


def snapshot(**tables) -> GcpSnapshot:
    return GcpSnapshot(captured_at=CAPTURED_AT, **tables)


def current(snap: GcpSnapshot, ledger=None) -> ReconciledSnapshot:
    return ReconciledSnapshot.from_snapshot(snap, ledger=ledger)


def one_source_ledger(category: str, keys, *, scope="complete", kind="api",
                      source_id="api-capture", boundary=""):
    builder = LedgerBuilder()
    builder.source(source_id, kind, origin=f"<{source_id}>", captured_at=CAPTURED_AT,
                   scope=scope, boundary=boundary)
    builder.declare(category, scope=scope, boundary=boundary, source_kinds=(kind,))
    for key in keys:
        builder.fact(category, key, source_id=source_id)
    return builder.build()


def of_kind(result_or_verdicts, kind: str) -> list[Verdict]:
    verdicts = getattr(getattr(result_or_verdicts, "report", None), "verdicts", None)
    if verdicts is None:
        verdicts = result_or_verdicts
    return [v for v in verdicts if v.kind == kind]


# -- the estate-gate capability probe -----------------------------------------


def _probe_document_check(ctx):
    return (Verdict("grounded", "probe:document", ctx.source, 0, "the probe ran"),)


def _probe_estate_gate() -> bool:
    """Whether ``registry.run_document_checks`` gates a requires-complete
    document check against a PARTIAL estate.

    Probed by running the real choke point rather than by importing a name: the
    gate is a behaviour, and a module that merely exists is not the same thing
    as one that gates.
    """
    module = types.ModuleType(PROBE_STUB)
    module.DOCUMENT_CHECKS = (_probe_document_check,)
    saved_module = sys.modules.get(PROBE_STUB)
    saved_providers = registry.PROVIDER_MODULES
    sys.modules[PROBE_STUB] = module
    registry.PROVIDER_MODULES = (PROBE_STUB,)
    registry.reset_cache()
    try:
        partial = current(snapshot(firewall_rules={}),
                          one_source_ledger("firewall_rules", (), scope="partial",
                                            kind="tfstate", source_id="tf-state"))
        ctx = CheckContext(snapshot=partial, solver=get_solver(), document={},
                           document_kind="firewall_rule", source="<probe>", claims=())
        verdicts = registry.run_document_checks(ctx)
    finally:
        if saved_module is None:
            sys.modules.pop(PROBE_STUB, None)
        else:
            sys.modules[PROBE_STUB] = saved_module
        registry.PROVIDER_MODULES = saved_providers
        registry.reset_cache()
    return any(v.kind == "estate:incomplete" for v in verdicts)


HAVE_ESTATE_GATE = _probe_estate_gate()


# -- IAM material -------------------------------------------------------------

CURRENT_BINDINGS = {"bindings": [
    {"role": "roles/bigquery.dataViewer",
     "members": ["user:alice@acme.example", "user:bob@acme.example"]}]}

WIDENED = {"bindings": [
    {"role": "roles/bigquery.dataViewer",
     "members": ["user:alice@acme.example", "user:bob@acme.example",
                 "user:mallory@acme.example"]}]}

NARROWED = {"bindings": [
    {"role": "roles/bigquery.dataViewer", "members": ["user:alice@acme.example"]}]}


def iam_current(*, scope="complete", kind="api", source_id="api-capture"):
    return current(snapshot(iam_bindings={IAM_KEY: dict(CURRENT_BINDINGS)}),
                   one_source_ledger("iam_bindings", (IAM_KEY,), scope=scope,
                                     kind=kind, source_id=source_id))


def iam_options(**kwargs) -> engine.EvalOptions:
    hints = baseline.Hints(target="projects/acme-prod", project="acme-prod")
    return engine.EvalOptions(hints=hints, **kwargs)


def iam_result(document, state, **option_kwargs):
    proposal = engine.prepare_proposal(document, preflight.detect_kind(document),
                                       source="<iam proposal>")
    return engine.evaluate(proposal, state, engine.RuleSet(),
                           options=iam_options(**option_kwargs))


# -- firewall material --------------------------------------------------------


def fw_record(**overrides) -> dict:
    record = {
        "network": "projects/acme-prod/global/networks/vpc-main",
        "direction": "INGRESS",
        "action": "allow",
        "priority": 1000,
        "disabled": False,
        "source_ranges": ["10.0.0.0/8"],
        "destination_ranges": [],
        "source_tags": [],
        "target_tags": [],
        "source_service_accounts": [],
        "target_service_accounts": [],
        "layer4": [{"protocol": "tcp", "ports": ["22"]}],
    }
    record.update(overrides)
    return record


FW_PROPOSAL = {
    "kind": "compute#firewall",
    "name": FW_KEY,
    "network": "projects/acme-prod/global/networks/vpc-main",
    "direction": "INGRESS",
    "priority": 1000,
    "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
    "sourceRanges": ["10.0.0.0/8"],
}


def open_to_the_world(ctx) -> tuple[Verdict, ...]:
    """A fake widening check: the baseline is refuted when it opens 0.0.0.0/0.

    Deliberately reads the BASELINE and not the proposal, because stage 6 varies
    only the baseline — each losing source's own record — and a check that
    ignored it could not tell the sources apart.
    """
    ranges = (ctx.baseline or {}).get("sourceRanges") or []
    if "0.0.0.0/0" in ranges:
        return (Verdict("contradicted", "widening", "firewall", 0,
                        "the current rule is open to 0.0.0.0/0"),)
    return (Verdict("grounded", "widening", "firewall", 0,
                    "the current rule is not open to the world"),)


def fw_two_source_state(*, other_record, other_kind="api", other_scope="complete",
                        other_id="api-mirror", field="source_ranges"):
    """One firewall row two sources describe differently, with the disagreement
    recorded exactly as the merge records it: a losing whole record plus a
    dispute."""
    builder = LedgerBuilder()
    builder.source("api-capture", "api", origin="<api-capture>",
                   captured_at=CAPTURED_AT, scope="complete")
    builder.source(other_id, other_kind, origin=f"<{other_id}>",
                   captured_at=CAPTURED_AT, scope=other_scope)
    builder.declare("firewall_rules", scope="complete", source_kinds=("api",))
    builder.declare("firewall_rules", scope=other_scope, source_kinds=(other_kind,))
    builder.fact("firewall_rules", FW_KEY, source_id="api-capture")
    builder.alternate("firewall_rules", FW_KEY, source_id=other_id,
                      record=other_record, reason="lost on fidelity")
    builder.dispute(Dispute(category="firewall_rules", key=FW_KEY, field=field,
                            severity="material",
                            reason="two views of one rule disagree"))
    return current(snapshot(firewall_rules={FW_KEY: fw_record()}), builder.build())


def fw_result(state, monkeypatch, *, drift_mode="report", pair=open_to_the_world):
    install(monkeypatch, PAIR_CHECKS={"firewall_rule": pair})
    proposal = engine.prepare_proposal(FW_PROPOSAL,
                                       preflight.detect_kind(FW_PROPOSAL),
                                       source="<firewall proposal>")
    options = engine.EvalOptions(hints=baseline.Hints(project="acme-prod"),
                                 drift=drift_mode)
    return engine.evaluate(proposal, state, engine.RuleSet(), options=options)


# -- the tier contract --------------------------------------------------------


def test_the_tier_table_declares_one_input_set_per_tier():
    """:data:`engine.TIER_INPUTS` is TOTAL over :data:`engine.TIERS`, and each
    tier's inputs are a strict superset of the weaker tier's — the ladder is the
    contract, not a coincidence of three hand-written tuples."""
    assert engine.TIERS == ("proposal", "pair", "estate")
    assert set(engine.TIER_INPUTS) == set(engine.TIERS)
    proposal, pair, estate = (engine.TIER_INPUTS[t] for t in engine.TIERS)
    assert set(proposal) < set(pair) < set(estate)
    assert "baseline" in pair and "baseline" not in proposal
    assert "current" in estate and "current" not in pair


# -- BYTE-COMPAT --------------------------------------------------------------


@pytest.mark.parametrize("name", ["iam_policy_good.json", "iam_policy_bad.json"])
def test_wiring_the_engine_in_changes_nothing_with_no_state_source(name):
    """With no state source configured the engine's findings ARE
    ``ground_policy``'s findings, in order, verbatim.

    The one addition is the mandated ``state:no-snapshot`` verdict, minted
    BEFORE the document is ground so it leads the tuple: an empty vocabulary
    answers every existence question UNKNOWN, and staying silent about that is
    the "skipped looks like passed" failure the tier contract exists to prevent.
    It is ``unverified``, so it cannot change ``ok``.
    """
    document = load(name)
    direct = preflight.ground_policy(document, GcpSnapshot(captured_at=""))

    proposal = engine.prepare_proposal(document, preflight.detect_kind(document),
                                       source=name)
    result = engine.evaluate(proposal, None, engine.RuleSet())

    assert result.schema == engine.EVAL_SCHEMA
    assert result.report.verdicts[0].kind == engine.NO_SNAPSHOT_KIND
    assert result.report.verdicts[0].status == "unverified"
    assert tuple(result.report.verdicts[1:]) == tuple(direct.verdicts)
    assert result.report.ok is direct.ok
    assert result.report.backend == direct.backend


# -- AUTO-BASELINE ------------------------------------------------------------


def test_auto_baseline_reaches_the_subset_check_with_no_baseline_flag():
    """THE DEAD-WIDENING-CHECK FIX, asserted directly.

    ``constraints.check_policy_subset`` is the one thing in the repo that can
    say "this change grants something the old policy did not", and before the
    engine it only ran when a human typed ``--baseline``. Here it runs off the
    derived counterpart alone.
    """
    widened = iam_result(WIDENED, iam_current())
    narrowed = iam_result(NARROWED, iam_current())

    widened_subset = of_kind(widened, "subset")
    narrowed_subset = of_kind(narrowed, "subset")
    assert len(widened_subset) == 1 and len(narrowed_subset) == 1

    if HAVE_Z3:
        assert widened_subset[0].status == "contradicted"
        assert "mallory" in widened_subset[0].message
        assert widened.report.ok is False
        assert narrowed_subset[0].status == "grounded"
    else:
        # No z3, no decision — and the reason is on the record either way.
        assert widened_subset[0].status == "unverified"
        assert "z3 is not available" in widened_subset[0].message
        assert narrowed_subset[0].status == "unverified"

    # The attribution suffix: an unattributed pair finding is not auditable.
    for verdict in widened_subset + narrowed_subset:
        assert f"[target {IAM_KEY}" in verdict.message
        assert "source api-capture" in verdict.message


def test_auto_baseline_off_abstains_instead_of_falling_silent():
    """A tier whose input was not supplied says so. Turning auto-baseline off
    removes the pair tier's baseline, and a pair tier that simply produced
    nothing would be indistinguishable from one that passed."""
    result = iam_result(WIDENED, iam_current(), auto_baseline=False)

    assert of_kind(result, "subset") == []
    abstentions = of_kind(result, engine.TIER_INPUT_KIND)
    assert len(abstentions) == 1
    assert abstentions[0].status == "unverified"
    assert "baseline" in abstentions[0].message


# -- PARTIAL BASELINE ---------------------------------------------------------


def test_a_partial_baseline_downgrades_the_block_but_not_the_pass():
    """THE PARTIAL-BASELINE ASYMMETRY, from both directions at once.

    Against a terraform-derived (structurally partial) baseline the widened
    policy's ``contradicted`` becomes ``unverified`` NAMING the partial view —
    rows that view never saw look like new grants — while the narrowed policy's
    ``grounded`` stands, because new ⊆ old-subset ⊆ reality.
    """
    partial = iam_current(scope="partial", kind="tfstate", source_id="tf-state")

    widened = of_kind(iam_result(WIDENED, partial), "subset")[0]
    narrowed = of_kind(iam_result(NARROWED, partial), "subset")[0]

    if HAVE_Z3:
        assert widened.status == "unverified"
        assert "tf-state" in widened.message and "partial" in widened.message
        assert "NOT a block" in widened.message
        assert narrowed.status == "grounded"
    else:
        assert widened.status == "unverified"
        assert narrowed.status == "unverified"
    # Either way the pass is never rewritten by the partial rule.
    assert "NOT a clean result" not in narrowed.message


def test_a_subset_safe_check_keeps_its_contradicted_and_loses_its_grounded(monkeypatch):
    """The mirror image. A ``subset_safe`` check looks for a WITNESS, so a
    subset can only make it quieter: the witness it DID find is real, and the
    witness it did NOT find may be in the part of the estate the partial view
    never held."""
    engine.register_baseline_soundness("firewall_rule", "subset_safe")
    # A partial category scope, with no alternates in play: the ONLY thing
    # varying between the two runs is which status the check returned.
    builder = LedgerBuilder()
    builder.source("tf-state", "tfstate", origin="<tf-state>",
                   captured_at=CAPTURED_AT, scope="partial")
    builder.declare("firewall_rules", scope="partial", source_kinds=("tfstate",))
    builder.fact("firewall_rules", FW_KEY, source_id="tf-state")
    partial_open = current(
        snapshot(firewall_rules={FW_KEY: fw_record(source_ranges=["0.0.0.0/0"])}),
        builder.build())
    partial_closed = current(snapshot(firewall_rules={FW_KEY: fw_record()}),
                             builder.build())

    contradicted = of_kind(fw_result(partial_open, monkeypatch), "widening")
    grounded = of_kind(fw_result(partial_closed, monkeypatch), "widening")

    assert [v.status for v in contradicted] == ["contradicted"]
    assert [v.status for v in grounded] == ["unverified"]
    assert "NOT a clean result" in grounded[0].message
    assert "partial" in grounded[0].message


def test_the_default_soundness_mode_is_the_conservative_one():
    """A check nobody classified is ``requires_complete``: the mode that gives
    up a block rather than one that gives up a finding."""
    assert engine.baseline_soundness("nobody-registered-this") == \
        provenance.DEFAULT_SOUNDNESS
    assert provenance.DEFAULT_SOUNDNESS == "requires_complete"
    with pytest.raises(ValueError):
        engine.register_baseline_soundness("firewall_rule", "sometimes")


# -- PER-ENTRY DISPATCH -------------------------------------------------------


TWO_DOMAIN_PLAN = {
    "format_version": "1.2",
    "terraform_version": "1.9.5",
    "resource_changes": [
        {
            "address": "google_compute_firewall.allow_ssh",
            "mode": "managed",
            "type": "google_compute_firewall",
            "name": "allow_ssh",
            "change": {
                "actions": ["update"],
                "before": {},
                "after": {
                    "name": "allow-ssh",
                    "network": "vpc-main",
                    "direction": "INGRESS",
                    "priority": 1000,
                    "disabled": False,
                    "allow": [{"protocol": "tcp", "ports": ["22"]}],
                    "source_ranges": ["10.0.0.0/8"],
                },
                "after_unknown": {},
            },
        },
        {
            "address": "google_access_context_manager_service_perimeter.prod",
            "mode": "managed",
            "type": "google_access_context_manager_service_perimeter",
            "name": "prod",
            "change": {
                "actions": ["update"],
                "before": {},
                "after": {
                    "name": PERIMETER_KEY,
                    "title": "prod",
                    "status": [{"resources": ["projects/1234"],
                                "restricted_services": ["storage.googleapis.com"]}],
                },
                "after_unknown": {},
            },
        },
    ],
}

PERIMETER_RECORD = {
    "perimeter_type": "PERIMETER_TYPE_REGULAR",
    "use_explicit_dry_run_spec": False,
    "status": {"resources": ["projects/1234"],
               "restricted_services": ["storage.googleapis.com"]},
    "spec": {},
}


def two_domain_state():
    builder = LedgerBuilder()
    builder.source("api-capture", "api", origin="<api-capture>",
                   captured_at=CAPTURED_AT, scope="complete")
    for category, key in (("firewall_rules", FW_KEY),
                          ("vpc_sc_perimeters", PERIMETER_KEY)):
        builder.declare(category, scope="complete", source_kinds=("api",))
        builder.fact(category, key, source_id="api-capture")
    return current(snapshot(firewall_rules={FW_KEY: fw_record()},
                            vpc_sc_perimeters={PERIMETER_KEY: dict(PERIMETER_RECORD)}),
                   builder.build())


def test_the_pair_tier_dispatches_per_entry_and_never_on_the_plan_kind(monkeypatch):
    """One dispatch per managed RESOURCE, keyed by that resource's own document
    kind — never one dispatch per FILE.

    ``pair_check("tf_plan")`` is None and there is no IAM fallback for a plan, so
    per-file dispatch fails by returning NOTHING. The plan-kind call is therefore
    counted rather than inferred: a regression has to fail loudly.
    """
    def fw_pair(ctx):
        return (Verdict("grounded", "pair:firewall", ctx.source, 0,
                        f"firewall pair check saw kind {ctx.document_kind}"),)

    def perimeter_pair(ctx):
        return (Verdict("grounded", "pair:perimeter", ctx.source, 0,
                        f"perimeter pair check saw kind {ctx.document_kind}"),)

    install(monkeypatch, PAIR_CHECKS={"firewall_rule": fw_pair,
                                      "vpc_sc_perimeter": perimeter_pair})

    asked = []
    real_pair_check = registry.pair_check

    def counting_pair_check(kind):
        asked.append(kind)
        return real_pair_check(kind)

    monkeypatch.setattr(registry, "pair_check", counting_pair_check)

    proposal = engine.prepare_proposal(TWO_DOMAIN_PLAN,
                                       preflight.detect_kind(TWO_DOMAIN_PLAN),
                                       source="main.tf")
    assert proposal.kind == "tf_plan"
    options = engine.EvalOptions(hints=baseline.Hints(
        project="acme-prod", organization="1", access_policy="987",
        region="us-central1"))
    result = engine.evaluate(proposal, two_domain_state(), engine.RuleSet(),
                             options=options)

    firewall = of_kind(result, "pair:firewall")
    perimeter = of_kind(result, "pair:perimeter")
    assert len(firewall) == 1, [v.message for v in result.report.verdicts]
    assert len(perimeter) == 1

    # Each check received ITS OWN resource's document kind, not the plan's.
    assert "kind firewall_rule" in firewall[0].message
    assert "kind vpc_sc_perimeter" in perimeter[0].message
    # ... and each verdict names the resource it is about.
    assert FW_KEY in firewall[0].message
    assert PERIMETER_KEY in perimeter[0].message

    assert asked, "the pair tier never consulted the registry at all"
    assert "tf_plan" not in asked
    assert set(asked) == {"firewall_rule", "vpc_sc_perimeter"}


# -- ESTATE TIER --------------------------------------------------------------

#: Every source the fake estate check was invoked for. Module level so the
#: check's IDENTITY — ``<module>.<qualname>``, the string ``registry._label``
#: builds and the gate looks up — has no ``<locals>`` in it.
ESTATE_CALLS: list[str] = []


def estate_check(ctx):
    ESTATE_CALLS.append(ctx.source)
    return (Verdict("grounded", "estate:probe", ctx.source, 0,
                    "the estate check ran"),)


def test_the_estate_tier_runs_nothing_and_never_duplicates_a_verdict(monkeypatch):
    """THE CORRECTION: the gate lives at ``registry.run_document_checks``, and
    this stage collects what that produced and adds NOTHING.

    A requires-complete document check therefore yields EXACTLY ONE verdict for
    the whole run — the one ``ground_policy`` already emitted — whether the view
    is partial or complete. Re-running it here would duplicate the verdict while
    the ungated stage-1 copy still emitted its answer, so the abstention would be
    defeated AND the counts would be wrong.
    """
    ESTATE_CALLS.clear()
    calls = ESTATE_CALLS
    install(monkeypatch, DOCUMENT_CHECKS=(estate_check,))
    # Declared through the ONE registry the gate reads, under the identity
    # ``registry._label`` builds — the string the gate would look up.
    provenance.register_estate_soundness(
        f"{estate_check.__module__}.{estate_check.__qualname__}",
        "requires_complete", "firewall_rules")

    builder = LedgerBuilder()
    builder.source("tf-state", "tfstate", origin="<tf-state>",
                   captured_at=CAPTURED_AT, scope="partial")
    builder.declare("firewall_rules", scope="partial", source_kinds=("tfstate",))
    builder.fact("firewall_rules", FW_KEY, source_id="tf-state")
    partial = current(snapshot(firewall_rules={FW_KEY: fw_record()}), builder.build())

    proposal = engine.prepare_proposal(FW_PROPOSAL,
                                       preflight.detect_kind(FW_PROPOSAL),
                                       source="<firewall proposal>")
    options = engine.EvalOptions(hints=baseline.Hints(project="acme-prod"))
    against_partial = engine.evaluate(proposal, partial, engine.RuleSet(),
                                      options=options)

    produced = [v for v in against_partial.report.verdicts
                if v.kind.startswith("estate:")]
    assert len(produced) == 1, [v.kind for v in against_partial.report.verdicts]
    if HAVE_ESTATE_GATE:
        assert produced[0].kind == "estate:incomplete"
        assert calls == []
    else:
        # No gate in this checkout: the honest degradation is that the check
        # runs ONCE, ungated. The half this module owns — the engine adds
        # nothing — is what is pinned either way.
        assert produced[0].kind == "estate:probe"
        assert len(calls) == 1

    # Against a COMPLETE view the check runs normally, and still exactly once.
    complete = current(snapshot(firewall_rules={FW_KEY: fw_record()}),
                       one_source_ledger("firewall_rules", (FW_KEY,)))
    calls.clear()
    against_complete = engine.evaluate(proposal, complete, engine.RuleSet(),
                                       options=options)
    ran = of_kind(against_complete, "estate:probe")
    assert len(ran) == 1
    assert len(calls) == 1

    # NO document-check verdict appears twice, in either run.
    for result in (against_partial, against_complete):
        seen = [(v.kind, v.target, v.message) for v in result.report.verdicts]
        assert len(seen) == len(set(seen)), "a verdict was emitted twice"


# -- SCOPE COMPOSITION --------------------------------------------------------


def two_boundary_state(*boundaries):
    """One category two sources declare complete WITHIN different boundaries.

    ``complete within organizations/1`` and ``complete within organizations/2``
    are two different claims, so composing them is NOT complete — which is what
    makes a requires-complete check give up its block.
    """
    builder = LedgerBuilder()
    for index, boundary in enumerate(boundaries):
        source_id = f"api-{index}"
        builder.source(source_id, "api", origin=f"<{source_id}>",
                       captured_at=CAPTURED_AT, scope="complete", boundary=boundary)
        builder.declare("firewall_rules", scope="complete", boundary=boundary,
                        source_kinds=("api",))
    builder.fact("firewall_rules", FW_KEY, source_id="api-0")
    return current(snapshot(firewall_rules={FW_KEY: fw_record(source_ranges=["0.0.0.0/0"])}),
                   builder.build())


def test_two_different_boundaries_compose_to_a_partial_scope(monkeypatch):
    """Two sources carrying DIFFERENT non-empty boundaries make a
    requires-complete check abstain; the same two carrying ONE boundary let it
    run.

    Asserted on the scope lattice AND on the consequence, because the lattice
    answer alone does not prove anybody read it. The consequence is asserted
    through the requires-complete check THIS module owns — the pair tier — and,
    where the estate gate is part of the checkout, through an estate-tier
    document check as well.
    """
    differing = two_boundary_state("organizations/1", "organizations/2")
    shared = two_boundary_state("organizations/1", "organizations/1")

    assert differing.ledger.scope_of("firewall_rules").scope != "complete"
    assert shared.ledger.scope_of("firewall_rules").scope == "complete"

    abstained = of_kind(fw_result(differing, monkeypatch), "widening")
    ran = of_kind(fw_result(shared, monkeypatch), "widening")

    assert [v.status for v in abstained] == ["unverified"]
    assert "NOT a block" in abstained[0].message
    assert [v.status for v in ran] == ["contradicted"]

    if HAVE_ESTATE_GATE:
        provenance.register_estate_soundness(
            f"{estate_check.__module__}.{estate_check.__qualname__}",
            "requires_complete", "firewall_rules")
        install(monkeypatch, DOCUMENT_CHECKS=(estate_check,))
        proposal = engine.prepare_proposal(FW_PROPOSAL,
                                           preflight.detect_kind(FW_PROPOSAL),
                                           source="<firewall proposal>")
        options = engine.EvalOptions(hints=baseline.Hints(project="acme-prod"))
        gated = engine.evaluate(proposal, differing, engine.RuleSet(),
                                options=options)
        allowed = engine.evaluate(proposal, shared, engine.RuleSet(),
                                  options=options)
        assert [v.kind for v in gated.report.verdicts
                if v.kind.startswith("estate:")] == ["estate:incomplete"]
        assert of_kind(allowed, "estate:probe")


# -- UNRESOLVED / AFTER-UNKNOWN ----------------------------------------------


def test_one_stripped_path_yields_one_verdict_and_downgrades_every_grounded():
    """A stripped attribute must not buy a clean pass.

    Every ``grounded`` becomes ``unverified``; an existing ``ungrounded`` is
    UNTOUCHED, because it is a statement about what IS there and an unreadable
    neighbour does not make it go away.
    """
    from gcp_grounding import facts

    document = {"bindings": [
        {"role": "roles/bigquery.dataViewer",
         "members": ["user:alice@acme.example"]},
        {"role": facts.Unresolved("interpolation", "bindings[1].role"),
         "members": ["group:data-eng@acme.example"]}]}

    proposal = engine.prepare_proposal(document, "iam_policy", source="<iam>")
    assert proposal.unresolved == ("bindings[1].role",)

    vocabulary = snapshot(
        roles={"roles/bigquery.dataViewer": {"title": "Data Viewer"}},
        principals=frozenset({"user:alice@acme.example"}))
    result = engine.evaluate(proposal, vocabulary, engine.RuleSet())

    stripped = of_kind(result, engine.UNRESOLVED_KIND)
    assert len(stripped) == 1
    assert stripped[0].target == "bindings[1].role"
    assert "removed" in stripped[0].message.lower()
    assert "abstained" in stripped[0].message

    assert result.report.counts()["grounded"] == 0
    ungrounded = [v for v in result.report.verdicts if v.status == "ungrounded"]
    assert ungrounded, "the fixture must carry an ungrounded verdict to protect"
    assert all("could not be resolved statically" not in v.message
               for v in ungrounded)


def after_unknown_plan(*, unknown: bool) -> dict:
    """A one-resource plan whose ``allow[0].ports`` is either marked unknown and
    OMITTED from ``after`` (the trap) or present (the control)."""
    after = {"name": "allow-ssh", "network": "vpc-main", "direction": "INGRESS",
             "priority": 1000, "disabled": False,
             "allow": [{"protocol": "tcp"}], "source_ranges": ["10.0.0.0/8"]}
    after_unknown = {"allow": [{"ports": True}]}
    if not unknown:
        after["allow"] = [{"protocol": "tcp", "ports": ["22"]}]
        after_unknown = {"allow": [{}]}
    return {
        "format_version": "1.2",
        "terraform_version": "1.9.5",
        "resource_changes": [{
            "address": "google_compute_firewall.allow_ssh",
            "mode": "managed",
            "type": "google_compute_firewall",
            "name": "allow_ssh",
            "change": {"actions": ["update"], "before": {}, "after": after,
                       "after_unknown": after_unknown},
        }],
    }


def test_after_unknown_is_derived_by_prepare_proposal_itself():
    """THE PLAN'S LEAST CERTAIN ATTRIBUTES MUST NOT GET THE CLEANEST PASS.

    An unknown attribute is OMITTED from ``change.after`` entirely, so
    ``strip_unresolved`` finds nothing and — without this derivation — no path is
    reported, no verdict is emitted and the downgrade never fires. Asserted with
    NO ``unknown_paths`` argument, so what is proved is that
    ``prepare_proposal`` derives it ITSELF: a call site cannot forget.
    """
    plan = after_unknown_plan(unknown=True)
    proposal = engine.prepare_proposal(plan, "tf_plan", source="main.tf")

    assert proposal.unresolved == \
        ("google_compute_firewall.allow_ssh.allow[0].ports",)
    assert proposal.notes == ()

    result = engine.evaluate(proposal, None, engine.RuleSet())
    reported = of_kind(result, engine.UNRESOLVED_KIND)
    assert len(reported) == 1
    assert reported[0].target == "google_compute_firewall.allow_ssh.allow[0].ports"
    assert result.report.counts()["grounded"] == 0

    # The control: the same plan with the value PRESENT reports nothing.
    present = engine.prepare_proposal(after_unknown_plan(unknown=False), "tf_plan",
                                      source="main.tf")
    assert present.unresolved == ()
    assert of_kind(engine.evaluate(present, None, engine.RuleSet()),
                   engine.UNRESOLVED_KIND) == []


def test_an_unreadable_plan_reader_is_a_note_and_never_silence(monkeypatch):
    """With the plan reader unimportable the proposal says the after-unknown
    mirror could not be read.

    ``sys.modules[name] = None`` is how an import is made to fail in-process:
    the import system raises ``ImportError`` on a ``None`` entry. Silence here
    would be exactly the clean pass this derivation exists to prevent.
    """
    monkeypatch.setitem(sys.modules, "gcp_grounding.tfsource.plan", None)

    proposal = engine.prepare_proposal(after_unknown_plan(unknown=True), "tf_plan",
                                       source="main.tf")

    assert proposal.unresolved == ()
    assert len(proposal.notes) == 1
    assert "after_unknown" in proposal.notes[0]
    assert "could not be read" in proposal.notes[0]

    result = engine.evaluate(proposal, None, engine.RuleSet())
    carried = [v for v in of_kind(result, engine.UNRESOLVED_KIND)
               if "after_unknown" in v.message]
    assert len(carried) == 1


# -- DRIFT --------------------------------------------------------------------


def test_drift_reports_every_source_and_picks_neither(monkeypatch):
    """ONE CHECK, TWO ANSWERS — reported as two answers.

    Collapsing to a single answer IS the failure mode, so the count of pair
    verdicts is asserted to be two and explicitly asserted NOT to be one.
    Precedence decides which document is PRIMARY; it never suppresses the other
    side's finding.
    """
    state = fw_two_source_state(other_record=fw_record(source_ranges=["0.0.0.0/0"]))
    result = fw_result(state, monkeypatch)

    material = of_kind(result, drift.DRIFT_MATERIAL)
    assert len(material) == 1
    assert material[0].status == "unverified"
    assert "source_ranges" in material[0].message
    assert "api-capture" in material[0].message and "api-mirror" in material[0].message

    widening = of_kind(result, "widening")
    assert len(widening) == 2
    assert len(widening) != 1, "collapsing to one answer is the failure mode"
    assert {v.status for v in widening} == {"grounded", "contradicted"}

    # PRECEDENCE DECIDES ONLY WHICH DOCUMENT IS PRIMARY. The winner's own
    # answer is still there, and so is the loser's — attributed to the source
    # that produced it, or a reader cannot tell which view said what.
    primary = [v for v in widening if "source api-capture" in v.message]
    losing = [v for v in widening if "per-source: api-mirror" in v.message]
    assert len(primary) == 1 and primary[0].status == "grounded"
    assert len(losing) == 1 and losing[0].status == "contradicted"
    assert FW_KEY in losing[0].message

    # The sources disagree, so the disagreement itself is on the record.
    disagreement = of_kind(result, drift.DRIFT_VERDICT)
    assert len(disagreement) == 1
    assert "picking neither" in disagreement[0].message

    # A surviving `contradicted` from a source entitled to it still blocks.
    assert result.report.ok is False


def test_agreeing_sources_drift_without_a_verdict_disagreement(monkeypatch):
    """Two views that differ on a field NO check reads still drift — and still
    produce no ``drift:verdict``, because the check answered the same both
    times."""
    state = fw_two_source_state(other_record=fw_record(priority=500),
                                field="priority")
    result = fw_result(state, monkeypatch)

    assert len(of_kind(result, drift.DRIFT_MATERIAL)) == 1
    widening = of_kind(result, "widening")
    assert len(widening) == 2
    assert {v.status for v in widening} == {"grounded"}
    assert of_kind(result, drift.DRIFT_VERDICT) == []
    assert result.report.ok is True


def test_the_block_option_makes_the_drift_verdict_itself_contradicted(monkeypatch):
    state = fw_two_source_state(other_record=fw_record(priority=500),
                                field="priority")

    reported = fw_result(state, monkeypatch, drift_mode="report")
    blocked = fw_result(state, monkeypatch, drift_mode="block")

    assert of_kind(reported, drift.DRIFT_MATERIAL)[0].status == "unverified"
    assert reported.report.ok is True
    assert of_kind(blocked, drift.DRIFT_MATERIAL)[0].status == "contradicted"
    assert blocked.report.ok is False


def test_stage_six_applies_the_same_soundness_rewrite_as_stage_three(monkeypatch):
    """THE BACK DOOR, closed — and asserted from BOTH sides, because it is
    invisible unless both are checked.

    A terraform alternate is structurally at most ``partial``, so its
    ``contradicted`` must arrive as ``unverified`` naming that source: letting it
    through as a hard block reinstates exactly the false block stage 3's rewrite
    forbids, by a different code path. A COMPLETE alternate's ``contradicted``
    must still survive and still block, or the rewrite has become a blanket
    suppression.
    """
    open_record = fw_record(source_ranges=["0.0.0.0/0"])
    partial_alt = fw_two_source_state(other_record=open_record, other_kind="tfstate",
                                      other_scope="partial", other_id="tf-state")
    complete_alt = fw_two_source_state(other_record=open_record, other_kind="api",
                                       other_scope="complete", other_id="api-mirror")

    from_partial = fw_result(partial_alt, monkeypatch)
    from_complete = fw_result(complete_alt, monkeypatch)

    partial_verdicts = [v for v in of_kind(from_partial, "widening")
                        if "per-source: tf-state" in v.message]
    complete_verdicts = [v for v in of_kind(from_complete, "widening")
                         if "per-source: api-mirror" in v.message]

    assert len(partial_verdicts) == 1
    assert partial_verdicts[0].status == "unverified"
    assert "tf-state" in partial_verdicts[0].message
    assert "NOT a block" in partial_verdicts[0].message
    assert from_partial.report.ok is True

    assert len(complete_verdicts) == 1
    assert complete_verdicts[0].status == "contradicted"
    assert from_complete.report.ok is False


def test_secret_drift_names_two_digests_and_neither_plaintext(monkeypatch):
    """Two sources whose records differ ONLY in a value the loading boundary
    redacted still drift — reported by DIGEST.

    A tfstate or a plan can mark any attribute sensitive, so any field can
    arrive redacted. The records are put through
    :func:`gcp_grounding.redact.to_wire` exactly as ``estate.py`` does at THE
    redaction boundary, so what the drift path sees here is byte-for-byte what
    it sees in production: the wire spelling of a salted digest. Two different
    secrets still register as real drift, and neither plaintext reaches the
    report.
    """
    left = redact.Redacted.of("vpc-main-secret-one", "values.network")
    right = redact.Redacted.of("vpc-main-secret-two", "values.network")
    assert left.digest != right.digest

    def wired(secret):
        return redact.to_wire(fw_record(network=secret))

    builder = LedgerBuilder()
    builder.source("api-capture", "api", origin="<api-capture>",
                   captured_at=CAPTURED_AT, scope="complete")
    builder.source("api-mirror", "api", origin="<api-mirror>",
                   captured_at=CAPTURED_AT, scope="complete")
    builder.declare("firewall_rules", scope="complete", source_kinds=("api",))
    builder.fact("firewall_rules", FW_KEY, source_id="api-capture")
    builder.alternate("firewall_rules", FW_KEY, source_id="api-mirror",
                      record=wired(right), reason="lost on fidelity")
    builder.dispute(Dispute(category="firewall_rules", key=FW_KEY, field="network",
                            severity="material", reason="the two views differ"))
    state = current(snapshot(firewall_rules={FW_KEY: wired(left)}), builder.build())

    result = fw_result(state, monkeypatch)

    material = of_kind(result, drift.DRIFT_MATERIAL)
    assert len(material) == 1
    message = material[0].message
    assert left.digest in message and right.digest in message
    assert "vpc-main-secret-one" not in message
    assert "vpc-main-secret-two" not in message
    assert message.count(redact.WIRE_PREFIX) == 2


# -- fail-open ----------------------------------------------------------------


def test_a_provider_that_raises_produces_one_unverified_and_does_not_propagate(
        monkeypatch):
    """A crashing domain module records one honest ``unverified`` and never
    breaks the gate — the fail-open contract does not stop being true because
    the call went through one more module."""
    def exploding_pair(ctx):
        raise RuntimeError("the domain module is broken")

    state = current(snapshot(firewall_rules={FW_KEY: fw_record()}),
                    one_source_ledger("firewall_rules", (FW_KEY,)))
    result = fw_result(state, monkeypatch, pair=exploding_pair)

    crashed = [v for v in result.report.verdicts
               if "the domain module is broken" in v.message]
    assert len(crashed) == 1
    assert crashed[0].status == "unverified"
    assert of_kind(result, engine.CRASHED_KIND) == []


def test_evaluate_never_raises_even_on_a_hostile_current_state():
    """``evaluate`` is total. A current state of the wrong TYPE is a caller bug,
    and a caller bug must still come back as a report."""
    proposal = engine.prepare_proposal(load("iam_policy_good.json"), "iam_policy",
                                       source="<iam>")

    result = engine.evaluate(proposal, "not a snapshot at all", engine.RuleSet())

    assert isinstance(result, engine.EvaluationResult)
    assert of_kind(result, engine.NO_SNAPSHOT_KIND)


def test_a_stage_that_raises_becomes_one_engine_crashed_verdict(monkeypatch):
    """Every stage is wrapped, and an escaping exception is ONE
    ``engine:crashed`` verdict targeted at the proposal source."""
    def boom(*args, **kwargs):
        raise RuntimeError("stage exploded")

    monkeypatch.setattr(engine, "_stage_baseline", boom)
    proposal = engine.prepare_proposal(load("iam_policy_good.json"), "iam_policy",
                                       source="<iam>")

    result = engine.evaluate(proposal, iam_current(), engine.RuleSet())

    crashed = of_kind(result, engine.CRASHED_KIND)
    assert len(crashed) == 1
    assert crashed[0].status == "unverified"
    assert crashed[0].target == "<iam>"
    assert "stage exploded" in crashed[0].message


# -- rules and provenance -----------------------------------------------------


def test_the_ruleset_is_handed_in_and_its_carried_verdicts_survive():
    """The engine does NOT load rules — it is handed a :class:`engine.RuleSet`.
    A promise the compiler could not admit is carried through VERBATIM, or a
    requirement that failed to compile becomes invisible."""
    carried = Verdict("unverified", "sec:compile", "sec-001", 0,
                      "sec-001: the promise could not be compiled")
    rules = engine.RuleSet(carry_verdicts=(carried,))

    proposal = engine.prepare_proposal(load("iam_policy_good.json"), "iam_policy",
                                       source="<iam>")
    result = engine.evaluate(proposal, iam_current(), rules)

    assert carried in result.report.verdicts


def test_compiled_rules_degrade_to_one_note_when_the_compiler_is_absent(monkeypatch):
    monkeypatch.setattr(engine, "_sec_rules_module", lambda: None)
    rules = engine.RuleSet(compiled=(object(),))

    proposal = engine.prepare_proposal(load("iam_policy_good.json"), "iam_policy",
                                       source="<iam>")
    result = engine.evaluate(proposal, iam_current(), rules)

    notes = of_kind(result, engine.RULES_KIND)
    assert len(notes) == 1
    assert "not available" in notes[0].message


def test_the_provenance_carries_the_sources_and_one_row_per_entry(monkeypatch):
    state = fw_two_source_state(other_record=fw_record(source_ranges=["0.0.0.0/0"]))
    result = fw_result(state, monkeypatch)

    sources = [row for row in result.provenance if row["row"] == "source"]
    entries = [row for row in result.provenance if row["row"] == "baseline"]

    assert {row["source"] for row in sources} == {"api-capture", "api-mirror"}
    assert len(entries) == 1
    row = entries[0]
    assert row["target"] == FW_KEY
    assert row["key"] == FW_KEY
    assert row["how"] == "document-name"
    assert row["status"] == "conflict"
    assert row["source"] == "api-capture"
    assert "source_ranges" in row["drift"]
