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
"""

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

from gcp_grounding import preflight, registry
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
    # A landed domain module (here hfw_claims) may register tf extractors for
    # its own google-provider resource types, but none of them matches the
    # iam / org resource types these fixtures use, so the registry contributes
    # nothing to *their* reports and the output stays byte-identical.
    assert registry.document_checks() == ()
    assert registry.claim_checks("role") == ()
    fixture_types = {"google_project_iam_binding", "google_project_iam_member",
                     "google_project_iam_policy", "google_project_iam_custom_role",
                     "google_org_policy_policy"}
    assert fixture_types.isdisjoint(registry.tf_extractors())
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
