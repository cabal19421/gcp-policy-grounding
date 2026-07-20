"""Preflight tests: :func:`gcp_grounding.preflight.ground_policy` end-to-end
over the shared fixture bundles — every good bundle passes the gate, every bad
bundle fails on exactly its planted hallucinations, and bad *input* (unreadable
files, invalid JSON, unrecognizable shapes) fails open into ``unverified``.

The suite is environment-honest, mirroring the gate's own degradation: cel and
subset expectations branch on whether z3 is importable, and the tf-plan
expectations branch on whether the (separately shipped)
``gcp_grounding.tf_claims`` extractor is part of this checkout — without it a
tf plan yields one honest ``unverified``, with it the bundles ground for real.
"""

import importlib.util
import json
from pathlib import Path

import pytest

from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.preflight import DOCUMENT_KINDS, detect_kind, ground_policy

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"

GHOST = "serviceAccount:ghost-runner@acme-prod.iam.gserviceaccount.com"

HAVE_Z3 = get_solver().backend == "z3"
HAVE_TF_CLAIMS = importlib.util.find_spec("gcp_grounding.tf_claims") is not None


@pytest.fixture()
def snap() -> GcpSnapshot:
    return GcpSnapshot.load(FIXTURES / "snapshot.json")


def load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


# -- auto-detection ---------------------------------------------------------


def test_detect_kind_recognizes_every_fixture_bundle():
    assert detect_kind(load("iam_policy_good.json")) == "iam_policy"
    assert detect_kind(load("iam_policy_bad.json")) == "iam_policy"
    assert detect_kind(load("org_policy_good.json")) == "org_policy"
    assert detect_kind(load("org_policy_bad.json")) == "org_policy"
    assert detect_kind(load("tf_plan_good.json")) == "tf_plan"
    assert detect_kind(load("tf_plan_bad.json")) == "tf_plan"


def test_detect_kind_covers_v1_org_policy_and_empty_iam_policy():
    assert detect_kind({"constraint": "constraints/x", "booleanPolicy": {}}) == "org_policy"
    assert detect_kind({"version": 3, "etag": "BwX="}) == "iam_policy"
    assert detect_kind({}) is None
    assert detect_kind(["not", "an", "object"]) is None
    for kind in ("iam_policy", "org_policy", "tf_plan"):
        assert kind in DOCUMENT_KINDS


# -- IAM policy bundles end-to-end ------------------------------------------


def test_good_iam_policy_passes_the_gate(snap):
    report = ground_policy(POLICIES / "iam_policy_good.json", snap)
    assert report.ok
    counts = report.counts()
    assert counts["ungrounded"] == 0 and counts["contradicted"] == 0
    # 3 roles + 4 principals ground; the satisfiable time-window condition is
    # decided (grounded) with z3 and honestly unverified without it.
    if HAVE_Z3:
        assert counts == {"grounded": 8, "ungrounded": 0,
                          "contradicted": 0, "unverified": 0}
    else:
        assert counts == {"grounded": 7, "ungrounded": 0,
                          "contradicted": 0, "unverified": 1}
        [cel] = report.by_status("unverified")
        assert cel.kind == "cel"


def test_bad_iam_policy_fails_on_its_hallucinations(snap):
    report = ground_policy(POLICIES / "iam_policy_bad.json", snap)
    assert not report.ok
    assert {(v.kind, v.target) for v in report.ungrounded} == {
        ("role", "roles/bigquery.reader"),
        ("principal", GHOST),
    }
    [reader] = [v for v in report.ungrounded if v.kind == "role"]
    assert "roles/bigquery.dataViewer" in reader.suggestions
    # The contradictory time window (before 2020 AND from 2025 on) is a dead
    # binding — provable only with z3.
    if HAVE_Z3:
        [dead] = report.contradicted
        assert dead.kind == "cel" and "never true" in dead.message
    else:
        assert report.contradicted == []
        assert [v.kind for v in report.by_status("unverified")] == ["cel"]


# -- Org Policy bundles end-to-end ------------------------------------------


def test_good_org_policy_passes_the_gate(snap):
    report = ground_policy(POLICIES / "org_policy_good.json", snap)
    assert report.ok
    # Constraint existence + boolean usage vs the declared value type — both
    # decidable without z3, so the counts are backend-independent.
    assert report.counts() == {"grounded": 2, "ungrounded": 0,
                               "contradicted": 0, "unverified": 0}
    assert all(v.target == "constraints/iam.disableServiceAccountKeyCreation"
               for v in report.verdicts)


def test_bad_org_policy_fails_on_the_value_type_mismatch(snap):
    report = ground_policy(POLICIES / "org_policy_bad.json", snap)
    assert not report.ok
    # The constraint is real (grounds); its list-typed usage contradicts the
    # snapshot's boolean declaration.
    assert [(v.status, v.kind) for v in report.verdicts] == [
        ("grounded", "constraint"), ("contradicted", "constraint")]
    [mismatch] = report.contradicted
    assert "boolean" in mismatch.message


# -- Terraform plan bundles end-to-end --------------------------------------


def test_tf_plan_bundles_end_to_end(snap):
    good = ground_policy(POLICIES / "tf_plan_good.json", snap)
    bad = ground_policy(POLICIES / "tf_plan_bad.json", snap)
    if not HAVE_TF_CLAIMS:
        # Fail-open: the extractor is a separately shipped module; without it
        # each plan yields one honest 'unverified', never a crash or a lie.
        for report in (good, bad):
            assert report.ok
            assert [(v.status, v.kind) for v in report.verdicts] == [
                ("unverified", "document")]
            [v] = report.verdicts
            assert "tf_claims" in v.message
        return
    assert good.ok
    assert not good.ungrounded and not good.contradicted
    assert {("role", "roles/bigquery.jobUser"),
            ("principal", "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com"),
            ("constraint", "constraints/iam.disableServiceAccountKeyCreation"),
            } <= {(v.kind, v.target) for v in good.by_status("grounded")}
    assert not bad.ok
    ungrounded = {(v.kind, v.target) for v in bad.ungrounded}
    assert ("role", "roles/bigquery.reader") in ungrounded
    assert ("principal", GHOST) in ungrounded
    assert ("constraint", "constraints/compute.disableSerialPortAcces") in ungrounded


# -- fail-open on bad input --------------------------------------------------


def test_invalid_json_fails_open_to_unverified(snap, tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    report = ground_policy(broken, snap)
    assert report.ok  # unverified is honest ignorance, not a gate failure
    [v] = report.verdicts
    assert (v.status, v.kind) == ("unverified", "document")
    assert "not valid JSON" in v.message and str(broken) in v.message


def test_missing_file_fails_open_to_unverified(snap, tmp_path):
    report = ground_policy(tmp_path / "does_not_exist.json", snap)
    [v] = report.verdicts
    assert (v.status, v.kind) == ("unverified", "document")
    assert "could not be read" in v.message
    # With a baseline, the undecided new⊆old comparison is on the record too.
    with_baseline = ground_policy(tmp_path / "does_not_exist.json", snap,
                                  baseline={"bindings": []})
    assert [(v.status, v.kind) for v in with_baseline.verdicts] == [
        ("unverified", "document"), ("unverified", "subset")]


def test_unrecognized_document_fails_open_to_unverified(snap):
    report = ground_policy({"totally": "unrelated"}, snap)
    assert report.ok
    [v] = report.verdicts
    assert (v.status, v.kind) == ("unverified", "document")
    assert "not recognized" in v.message


def test_non_utf8_bytes_fail_open_to_unverified(snap, tmp_path):
    garbled = tmp_path / "garbled.json"
    garbled.write_bytes(b"\xff\xfe{\x00}")
    report = ground_policy(garbled, snap)
    assert report.ok  # bad bytes are bad input, not a gate failure
    [v] = report.verdicts
    assert (v.status, v.kind) == ("unverified", "document")
    assert "could not be parsed" in v.message and "UnicodeDecodeError" in v.message


def test_deeply_nested_json_fails_open_to_unverified(snap, tmp_path):
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 2_000_000 + "]" * 2_000_000, encoding="utf-8")
    report = ground_policy(deep, snap)
    assert report.ok
    [v] = report.verdicts
    assert (v.status, v.kind) == ("unverified", "document")
    assert "could not be parsed" in v.message and "RecursionError" in v.message


def test_parsed_object_input_matches_path_input(snap):
    from_path = ground_policy(POLICIES / "iam_policy_bad.json", snap)
    from_obj = ground_policy(load("iam_policy_bad.json"), snap)
    assert [(v.status, v.kind, v.target) for v in from_obj.verdicts] == \
           [(v.status, v.kind, v.target) for v in from_path.verdicts]


# -- zero-claims honesty on recognized documents ------------------------------


@pytest.mark.parametrize("doc", [
    # bindings as an object, not an array — the extractor skips it wholesale.
    {"bindings": {"role": "roles/hacker.superAdmin", "members": ["user:evil@x.y"]}},
    # every binding malformed (role as array, members as string) — all skipped.
    {"bindings": [{"role": ["roles/hallucinated.role"], "members": "user:evil@x.y"}]},
    # hybrid org policy: v1 'constraint' and v2 'name' at once — ambiguous.
    {"constraint": "constraints/compute.disableSerialPortAccessz",
     "name": "projects/p/policies/compute.disableSerialPortAccessz",
     "listPolicy": {"allValues": "DENY"}},
])
def test_recognized_document_with_zero_extractable_claims_is_unverified(snap, doc):
    assert detect_kind(doc) is not None  # recognized, yet nothing extracts
    report = ground_policy(doc, snap)
    assert report.ok  # unverified is honest ignorance, not a gate failure
    [v] = report.verdicts
    assert (v.status, v.kind) == ("unverified", "document")
    assert "nothing checkable" in v.message


def test_legitimately_empty_iam_policy_yields_no_verdicts(snap):
    # An empty allow policy asserts nothing: zero claims is the honest
    # outcome, not ignorance — no unverified verdict to record.
    for doc in ({"etag": "BwX=", "version": 3},
                {"etag": "BwX=", "version": 3, "bindings": []}):
        report = ground_policy(doc, snap)
        assert report.ok and report.verdicts == []


# -- baseline (new⊆old) opt-in ----------------------------------------------


def test_baseline_subset_comparison(snap):
    old = {"bindings": [
        {"role": "roles/viewer", "members": ["user:alice@acme.example",
                                             "group:data-eng@acme.example"]}]}
    shrunk = {"version": 3, "etag": "BwX=", "bindings": [
        {"role": "roles/viewer", "members": ["user:alice@acme.example"]}]}
    # The extra grantee is a real snapshot principal, so the existence layer
    # stays green and any failure is the subset check's alone.
    widened = {"version": 3, "etag": "BwX=", "bindings": [
        {"role": "roles/viewer", "members": [
            "user:alice@acme.example",
            "serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com"]}]}
    subset = ground_policy(shrunk, snap, baseline=old)
    [subset_v] = [v for v in subset.verdicts if v.kind == "subset"]
    superset = ground_policy(widened, snap, baseline=old)
    [superset_v] = [v for v in superset.verdicts if v.kind == "subset"]
    if HAVE_Z3:
        assert subset_v.status == "grounded" and subset.ok
        assert superset_v.status == "contradicted" and not superset.ok
        assert "ci-deployer" in superset_v.message
    else:
        # No z3 → new⊆old is honestly undecided either way.
        assert subset_v.status == superset_v.status == "unverified"
        assert subset.ok and superset.ok


def test_baseline_against_non_iam_document_is_unverified(snap):
    report = ground_policy(POLICIES / "org_policy_good.json", snap,
                           baseline={"bindings": []})
    [subset_v] = [v for v in report.verdicts if v.kind == "subset"]
    assert subset_v.status == "unverified"
    assert "not an IAM policy" in subset_v.message


def test_unrecognized_baseline_shape_is_unverified_not_contradicted(snap):
    new = {"bindings": [{"role": "roles/viewer",
                         "members": ["user:alice@acme.example"]}]}
    # A wrapped setIamPolicy-style body carries the very same bindings; read
    # raw it would look like "grants nothing" and mint a false contradicted.
    for baseline in ({"policy": new}, load("org_policy_good.json")):
        report = ground_policy(new, snap, baseline=baseline)
        [subset_v] = [v for v in report.verdicts if v.kind == "subset"]
        assert subset_v.status == "unverified"
        assert "baseline" in subset_v.message
        assert "not recognized" in subset_v.message
        assert report.counts()["contradicted"] == 0 and report.ok


# -- the aggregate across all bundles ----------------------------------------


def test_every_good_bundle_passes_and_every_bad_bundle_is_judged(snap):
    for name in ("iam_policy_good.json", "org_policy_good.json", "tf_plan_good.json"):
        assert ground_policy(POLICIES / name, snap).ok, name
    for name, decidable in (("iam_policy_bad.json", True),
                            ("org_policy_bad.json", True),
                            ("tf_plan_bad.json", HAVE_TF_CLAIMS)):
        report = ground_policy(POLICIES / name, snap)
        assert report.ok is not decidable, name
