"""Registry tests: the single extension seam
(:mod:`gcp_grounding.registry`) and the four small ``ground_policy`` hunks that
consult it.

This is the highest-regression-risk change in the whole expansion, so the suite
pins two things at once. First, that with *no* provider modules installed the
gate's behaviour is byte-identical to before the seam existed — asserted against
the shared fixture bundles. Second, that a provider opting in purely by defining
module-level names has its claim / document / pair checks invoked with a
correctly populated, build-once :class:`~gcp_grounding.registry.CheckContext`,
and that a crashing domain module records one honest ``unverified`` verdict
rather than breaking the gate.

Environment-honest, exactly like ``test_gcp_preflight``: the ``cel`` expectations
branch on whether z3 is importable, and the terraform expectations branch on
whether ``gcp_grounding.tf_claims`` is part of this checkout.

NAMED MUTATION MUST-KILLS PINNED HERE: MK-I01. (MK-I27 and MK-I28, on the
downgrade predicate ``_invoke`` applies, are pinned in
``test_gcp_evidence_floor.py``.)
"""

import dataclasses
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

from gcp_grounding import preflight, registry, tf_claims
from gcp_grounding.claims import Claim, iam_policy_claims
from gcp_grounding.core.report import Verdict
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.preflight import ground_policy
from gcp_grounding.registry import CheckContext

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"

HAVE_Z3 = get_solver().backend == "z3"
HAVE_TF = importlib.util.find_spec("gcp_grounding.tf_claims") is not None

#: The resource types the built-in tf extractors own; a provider module must
#: never register one of these (built-ins win), so the registry's contributed
#: tf extractors stay disjoint from this set no matter which domains land.
if HAVE_TF:
    from gcp_grounding.tf_claims import _EXTRACTORS as _BUILTIN_TF_TYPES
else:
    _BUILTIN_TF_TYPES = {}

#: The whole-document checks each landed domain module owns. A domain module
#: that is part of this checkout must contribute exactly its own row (and every
#: registered document check must belong to some gcp_grounding module), so a
#: gutted DOCUMENT_CHECKS tuple or a check that quietly moves module goes red in
#: test_no_providers_is_byte_identical rather than passing as "contributes
#: nothing".
DOCUMENT_CHECK_OWNERS = {
    "gcp_grounding.org_checks": {"check_org_estate"},
    "gcp_grounding.hfw_checks": {"check_hierarchical_order"},
    # Escalation needs both halves of a binding, so it cannot hang off a single
    # claim; it stays silent unless a role hits the curated escalation table,
    # which none of these fixtures' roles does.
    "gcp_grounding.iam_checks": {"check_escalation"},
    # A whole-document check that answered for another domain's document
    # kind would break the verdict-set equality below; that is what pins
    # its silence on these fixtures.
    "gcp_grounding.vpcsc_checks": {"check_perimeter_estate"},
    "gcp_grounding.armor_checks": {"check_security_policy"},
    "gcp_grounding.fw_estate": {"check_firewall_shadowing"},
}

STUB = "gcp_grounding_stub_provider"

CEL_GOOD = 'request.time < timestamp("2027-01-01T00:00:00Z")'
CEL_BAD = ('request.time < timestamp("2020-01-01T00:00:00Z") && '
           'request.time >= timestamp("2025-01-01T00:00:00Z")')


@pytest.fixture()
def snap() -> GcpSnapshot:
    return GcpSnapshot.load(FIXTURES / "snapshot.json")


@pytest.fixture(autouse=True)
def _clean_registry():
    """No test may leak an injected provider or a warm cache into the next."""
    registry.reset_cache()
    yield
    registry.reset_cache()


def load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


def install(monkeypatch, **attrs) -> types.ModuleType:
    """Inject a stub provider into ``sys.modules`` and name it (and only it) in
    ``PROVIDER_MODULES`` — the exact discovery recipe production uses."""
    module = types.ModuleType(STUB)
    for name, value in attrs.items():
        setattr(module, name, value)
    monkeypatch.setitem(sys.modules, STUB, module)
    monkeypatch.setattr(registry, "PROVIDER_MODULES", (STUB,))
    registry.reset_cache()
    return module


# -- byte-identical with no provider modules installed ------------------------


def _iam_good_expected():
    return [
        ("grounded", "role", "roles/bigquery.dataViewer"),
        ("grounded", "principal", "group:data-eng@acme.example"),
        ("grounded", "principal", "user:alice@acme.example"),
        ("grounded", "role", "roles/bigquery.jobUser"),
        ("grounded", "principal",
         "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com"),
        ("grounded", "role", "roles/storage.objectViewer"),
        ("grounded", "principal",
         "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com"),
        ("grounded" if HAVE_Z3 else "unverified", "cel", CEL_GOOD),
    ]


def _iam_bad_expected():
    return [
        ("ungrounded", "role", "roles/bigquery.reader"),
        ("grounded", "principal", "group:data-eng@acme.example"),
        ("grounded", "role", "roles/storage.objectViewer"),
        ("ungrounded", "principal",
         "serviceAccount:ghost-runner@acme-prod.iam.gserviceaccount.com"),
        ("grounded", "role", "roles/bigquery.jobUser"),
        ("grounded", "principal", "user:alice@acme.example"),
        ("contradicted" if HAVE_Z3 else "unverified", "cel", CEL_BAD),
    ]


def _org_bad_expected():
    return [
        ("grounded", "constraint", "constraints/compute.disableSerialPortAccess"),
        ("contradicted", "constraint", "constraints/compute.disableSerialPortAccess"),
        # gcp_grounding.org_checks IS part of this checkout, so its claim check
        # runs — and abstains, because this snapshot captures no org policies.
        ("unverified", "org_enforcement", "constraints/compute.disableSerialPortAccess"),
    ]


def _tf_full_expected():
    if not HAVE_TF:
        return [("unverified", "document", str(POLICIES / "tf_plan_full.json"))]
    return [
        ("grounded", "resource_type", "google_project_iam_binding"),
        ("grounded", "role", "roles/bigquery.dataViewer"),
        ("grounded", "principal", "group:data-eng@acme.example"),
        ("grounded", "principal", "user:alice@acme.example"),
        ("grounded", "resource_type", "google_project_iam_custom_role"),
        ("ungrounded", "permission", "bigquery.job.create"),
        ("grounded", "permission", "storage.objects.get"),
        ("grounded", "permission", "storage.objects.list"),
        ("grounded", "resource_type", "google_project_iam_member"),
        ("grounded", "role", "roles/bigquery.jobUser"),
        ("grounded", "principal",
         "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com"),
        ("grounded", "resource_type", "google_project_iam_policy"),
        ("ungrounded", "role", "roles/bigquery.reader"),
        ("ungrounded", "principal", "user:bob@acme.example"),
        ("grounded", "resource_type", "google_org_policy_policy"),
        ("grounded", "constraint", "constraints/compute.disableSerialPortAccess"),
        ("grounded", "resource_type", "google_org_policy_policy"),
        ("grounded", "constraint", "constraints/compute.vmExternalIpAccess"),
        ("grounded", "resource_type", "google_project_iam_member"),
        ("grounded" if HAVE_Z3 else "unverified", "cel", CEL_GOOD),
        ("grounded", "constraint", "constraints/compute.disableSerialPortAccess"),
        ("grounded", "constraint", "constraints/compute.vmExternalIpAccess"),
    ]


@pytest.mark.parametrize("name, expected", [
    ("iam_policy_good", _iam_good_expected()),
    ("iam_policy_bad", _iam_bad_expected()),
    ("org_policy_bad", _org_bad_expected()),
    ("tf_plan_full", _tf_full_expected()),
])
def test_no_providers_is_byte_identical(snap, name, expected):
    # The registry must not contribute anything that changes these baseline
    # (non-firewall/non-armor/…) fixtures' grounding. As domain modules land in
    # this checkout (fw_claims, hfw_claims, armor_claims, vpcsc_claims, …) they
    # may register tf extractors for their own google resource types, but only
    # NEW types: never shadowing a built-in, and never matching the iam / org
    # resource types these fixtures use, so the registry contributes nothing to
    # *their* reports. The invariant therefore relaxes from "registry is empty"
    # to "registry never shadows a built-in tf type", which keeps the gate
    # byte-identical to before the seam existed. (_BUILTIN_TF_TYPES is
    # tf_claims._EXTRACTORS, guarded by HAVE_TF so a checkout without the
    # terraform extractor still runs this assertion rather than ImportError-ing.)
    assert set(registry.tf_extractors()).isdisjoint(_BUILTIN_TF_TYPES)

    # Whole-document checks: every one is owned by a landed gcp_grounding domain
    # module — the seam never picks up a stray provider — and each module in
    # DOCUMENT_CHECK_OWNERS that is part of this checkout contributes EXACTLY the
    # checks named there, no more and no fewer. Asserted per owning module, so a
    # new domain landing adds its own row instead of loosening anyone else's.
    # Each of these returns no verdict for a document that makes none of its
    # domain's claims, which is what the byte-identical assertion below proves.
    by_module: dict[str, set] = {}
    for fn in registry.document_checks():
        assert fn.__module__.startswith("gcp_grounding."), fn
        by_module.setdefault(fn.__module__, set()).add(fn.__name__)
    for module, names in DOCUMENT_CHECK_OWNERS.items():
        if importlib.util.find_spec(module) is not None:
            assert by_module.get(module, set()) == names, module
    # `agent/gx-debt-lineno-invariant` asserted the same silence as a SUBSET of
    # the three checks landed in its own checkout — org_checks, hfw_checks,
    # vpcsc_checks. That set is not a bound in the integrated tree, where
    # `registry.document_checks()` also carries check_escalation,
    # check_security_policy and check_firewall_shadowing, so its literal text
    # would fail on branches that landed after it. The per-module EQUALITY above
    # is the same claim without the ceiling: every one of those three names is
    # pinned exactly, by its owning module, together with every check that landed
    # since — no more and no fewer per module, which is strictly more than the
    # subset asserted and is what the verdict-set equality below then pins.
    assert registry.claim_checks("role") == ()
    fixture_types = {"google_project_iam_binding", "google_project_iam_member",
                     "google_project_iam_policy", "google_project_iam_custom_role",
                     "google_org_policy_policy"}
    assert fixture_types.isdisjoint(registry.tf_extractors())
    # `agent/gx-debt-lineno-invariant`'s
    # `assert set(registry.tf_extractors()).isdisjoint(tf_claims._EXTRACTORS)`
    # is asserted at the top of this test in its HAVE_TF-guarded spelling —
    # `_BUILTIN_TF_TYPES` IS `tf_claims._EXTRACTORS` (see the import at line 50),
    # so it is the same assertion and is kept once rather than twice, in the form
    # that still runs in a checkout without the terraform extractor.
    report = ground_policy(POLICIES / f"{name}.json", snap)
    got = sorted((v.status, v.kind, v.target) for v in report.verdicts)
    assert got == sorted(expected)


def test_every_claim_receives_at_least_one_verdict(snap):
    # With no providers each extracted claim yields exactly one verdict; the
    # seam must never leave a claim silent.
    doc = load("iam_policy_good.json")
    claims = iam_policy_claims(doc)
    report = ground_policy(doc, snap)
    assert len(report.verdicts) == len(claims)
    assert {c.value for c in claims} <= {v.target for v in report.verdicts}


# -- a provider opting in -----------------------------------------------------


def test_stub_claim_and_document_checks_get_a_populated_context(snap, monkeypatch):
    seen = {}

    def rec_claim(claim, ctx):
        seen["claim"] = claim
        seen["claim_ctx"] = ctx
        return [Verdict("grounded", "role", claim.value, 0, "stub-claim")]

    def rec_doc(ctx):
        seen["doc_ctx"] = ctx
        return [Verdict("unverified", "document", "stub-doc", 0, "stub-doc")]

    install(monkeypatch, CLAIM_CHECKS={"role": rec_claim}, DOCUMENT_CHECKS=(rec_doc,))

    doc = {"bindings": [{"role": "roles/storage.objectViewer",
                         "members": ["user:alice@acme.example"]}]}
    report = ground_policy(doc, snap)

    # The claim check ran, on the role claim, with a fully populated context.
    assert seen["claim"].kind == "role"
    ctx = seen["claim_ctx"]
    assert isinstance(ctx, CheckContext)
    assert ctx.snapshot is snap
    assert ctx.document == doc
    assert ctx.document_kind == "iam_policy"
    assert ctx.source == "<policy object>"
    assert isinstance(ctx.claims, tuple)
    assert {c.kind for c in ctx.claims} == {"role", "principal"}
    assert ctx.baseline is None and ctx.baseline_kind is None
    # One context is built once and shared by every check in the run.
    assert seen["doc_ctx"] is ctx
    # Both checks' returned verdicts landed in the report.
    assert any(v.message == "stub-claim" for v in report.verdicts)
    assert any(v.message == "stub-doc" for v in report.verdicts)


def test_stub_pair_check_sees_the_parsed_baseline(snap, monkeypatch, tmp_path):
    seen = {}

    def rec_pair(ctx):
        seen["ctx"] = ctx
        return [Verdict("unverified", "subset", "stub", 0, "stub-pair")]

    # The new document is an org policy (kind != iam_policy), so _subset_verdict
    # consults the registry pair check keyed by that kind.
    install(monkeypatch, PAIR_CHECKS={"org_policy": rec_pair})

    baseline_body = {"bindings": [{"role": "roles/viewer",
                                   "members": ["user:alice@acme.example"]}]}
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline_body), encoding="utf-8")

    report = ground_policy(load("org_policy_good.json"), snap,
                           baseline=str(baseline_path))

    ctx = seen["ctx"]
    # This is the plumbing every widening check depends on: baseline is the
    # PARSED mapping, baseline_kind its detected kind — never the path.
    assert ctx.baseline == baseline_body
    assert ctx.baseline_kind == "iam_policy"
    assert any(v.message == "stub-pair" for v in report.verdicts)


def test_unreadable_baseline_yields_none_context_and_one_unverified(
        snap, monkeypatch, tmp_path):
    seen = {}

    def rec_doc(ctx):
        seen["ctx"] = ctx
        return []

    install(monkeypatch, DOCUMENT_CHECKS=(rec_doc,))

    missing = tmp_path / "does_not_exist.json"
    doc = {"bindings": [{"role": "roles/storage.objectViewer",
                         "members": ["user:alice@acme.example"]}]}
    report = ground_policy(doc, snap, baseline=str(missing))  # must not raise

    assert seen["ctx"].baseline is None and seen["ctx"].baseline_kind is None
    unreadable = [v for v in report.verdicts
                  if v.kind == "subset" and v.status == "unverified"
                  and str(missing) in v.message]
    assert len(unreadable) == 1


# -- fail-open on a crashing provider -----------------------------------------


def _boom(ctx):
    raise RuntimeError("kaboom")


_boom.__module__ = STUB


def test_a_raising_check_yields_one_unverified_naming_the_provider(snap, monkeypatch):
    install(monkeypatch, DOCUMENT_CHECKS=(_boom,))
    # A doc whose every claim grounds and which carries no cel: the only
    # unverified verdict can be the crash-abstention.
    doc = {"bindings": [{"role": "roles/storage.objectViewer",
                         "members": ["user:alice@acme.example"]}]}
    report = ground_policy(doc, snap)  # the crash must not propagate

    unverified = report.by_status("unverified")
    assert len(unverified) == 1
    [v] = unverified
    assert v.kind == "document"
    assert STUB in v.message and "raised" in v.message and "RuntimeError" in v.message
    # It kept going: the grounded role verdict is still there.
    assert any(v.status == "grounded" and v.kind == "role" for v in report.verdicts)


# -- the pre-existing catch-all still fires for an unwired claim kind ----------


def test_unwired_claim_kind_still_gets_the_catch_all(snap, monkeypatch):
    # A structured claim kind reaches the loop via a registered document
    # extractor for a new document kind; with no check wired for it, the honest
    # pre-existing catch-all must fire unchanged.
    def extract(document):
        return [Claim("firewall_rule", "allow-ssh", "rules[0]")]

    install(monkeypatch, DOCUMENT_EXTRACTORS={"fw_policy": extract})
    monkeypatch.setattr(preflight, "detect_kind", lambda doc: "fw_policy")

    report = ground_policy({"marker": True}, snap)

    [v] = report.verdicts
    assert v.status == "unverified" and v.kind == "firewall_rule"
    assert v.target == "allow-ssh"
    assert "no offline check is wired for claim kind 'firewall_rule'" in v.message


def test_load_document_is_called_exactly_once_for_the_baseline(snap, monkeypatch):
    # The refactor must parse the baseline once and share it: _subset_verdict
    # (exercised here on an IAM new⊆old) must NOT re-read it.
    calls = []
    original = preflight._load_document

    def counting(arg):
        calls.append(arg)
        return original(arg)

    monkeypatch.setattr(preflight, "_load_document", counting)

    new = {"bindings": [{"role": "roles/storage.objectViewer",
                         "members": ["user:alice@acme.example"]}]}
    baseline = {"bindings": [{"role": "roles/storage.objectViewer",
                              "members": ["user:alice@acme.example"]}]}
    report = ground_policy(new, snap, baseline=baseline)

    assert sum(1 for a in calls if a is baseline) == 1
    assert any(v.kind == "subset" for v in report.verdicts)  # _subset_verdict ran


# =============================================================================
# the named mutation must-kill in this file
#
# MEASURED to survive the suite as it stood and re-measured ALONE in an isolated
# copy (house rule 7) before being pinned here.
# =============================================================================

def test_check_context_is_frozen_and_hashable_by_intent():
    """MK-I01 (registry.py:77, ``frozen=True`` -> ``frozen=False``).

    The docstring says a check RECEIVES the context and never mutates it, and
    that it is frozen and hashable by intent — one context is built once and
    shared by every check in the run, so a check that could scribble on it would
    be editing the evidence the next check reads. The mutant makes it both
    mutable and unhashable, and nothing in the suite noticed."""
    fields = dict(snapshot=GcpSnapshot(captured_at="2026-01-01T00:00:00Z"),
                  solver=None, document=None, document_kind="iam_policy",
                  source="<policy object>", claims=())
    ctx = CheckContext(**fields)

    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.document_kind = "org_policy"
    assert ctx.document_kind == "iam_policy"      # and the scribble did not land

    # hashable-by-intent: usable as a dict key / set member across checks.
    assert hash(ctx) == hash(CheckContext(**fields))
    assert len({ctx, CheckContext(**fields)}) == 1
