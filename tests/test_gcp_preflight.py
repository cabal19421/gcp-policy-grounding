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
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from gcp_grounding import preflight, reasoner, registry
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


def assert_no_line_numbers(report) -> None:
    """The documented invariant, asserted once and applied per fail-open path.

    ``reasoner.ground_existence``'s own clause: a policy document is JSON, not
    source, so there is no line to point at — every verdict carries lineno 0
    and the json-path location leads the message instead (the precedent is
    ``test_gcp_reasoner.py::test_bad_role_suggests_the_near_miss``, which pins
    ``reader.lineno == 0``). Each caller pins its path's identity — status,
    kind, target and the reason named in the message — alongside this, so the
    branch is shown to have decided something and not merely been reached.
    """
    assert all(v.lineno == 0 for v in report.verdicts), \
        [(v.status, v.kind, v.target, v.lineno) for v in report.verdicts]


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
    # Constraint existence + boolean usage vs the declared value type, both
    # decidable without z3; the enforcement claim is honestly undecided here
    # because THIS snapshot captures the five vocabularies only — it has no
    # `org_policies` table to compare the enforce flag against. So the counts
    # stay backend-independent.
    assert report.counts() == {"grounded": 2, "ungrounded": 0,
                               "contradicted": 0, "unverified": 1}
    [undecided] = report.by_status("unverified")
    assert undecided.kind == "org_enforcement"
    assert "not captured" in undecided.message
    assert all(v.target == "constraints/iam.disableServiceAccountKeyCreation"
               for v in report.verdicts)


def test_bad_org_policy_fails_on_the_value_type_mismatch(snap):
    report = ground_policy(POLICIES / "org_policy_bad.json", snap)
    assert not report.ok
    # The constraint is real (grounds); its list-typed usage contradicts the
    # snapshot's boolean declaration. The enforce flag abstains: this snapshot
    # never captured the org policies in force.
    assert [(v.status, v.kind) for v in report.verdicts] == [
        ("grounded", "constraint"), ("contradicted", "constraint"),
        ("unverified", "org_enforcement")]
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
    assert (v.status, v.kind, v.target) == ("unverified", "document", str(broken))
    assert "not valid JSON" in v.message and str(broken) in v.message
    assert_no_line_numbers(report)


def test_missing_file_fails_open_to_unverified(snap, tmp_path):
    missing = tmp_path / "does_not_exist.json"
    report = ground_policy(missing, snap)
    [v] = report.verdicts
    assert (v.status, v.kind, v.target) == ("unverified", "document", str(missing))
    assert "could not be read" in v.message
    assert_no_line_numbers(report)
    # With a baseline, the undecided new⊆old comparison is on the record too.
    with_baseline = ground_policy(missing, snap, baseline={"bindings": []})
    assert [(v.status, v.kind, v.target) for v in with_baseline.verdicts] == [
        ("unverified", "document", str(missing)),
        ("unverified", "subset", "iam-policy")]
    document, subset = with_baseline.verdicts
    assert "could not be read" in document.message
    assert "new⊆old was not decided" in subset.message and str(missing) in subset.message
    assert_no_line_numbers(with_baseline)


def test_unrecognized_document_fails_open_to_unverified(snap):
    report = ground_policy({"totally": "unrelated"}, snap)
    assert report.ok
    [v] = report.verdicts
    assert (v.status, v.kind, v.target) == ("unverified", "document",
                                            "<policy object>")
    assert "not recognized" in v.message and "['totally']" in v.message
    assert_no_line_numbers(report)


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
    [v] = [x for x in report.verdicts if x.kind == "document"]
    assert (v.status, v.kind) == ("unverified", "document")
    assert "nothing checkable" in v.message
    # An IAM ALLOW policy abstains a second time, on the channel that owns
    # escalation: `document` is not a kind the escalation family owns, so
    # without this the escalation check would be silent over bindings it could
    # not read — and silence there reads as "no escalation was found".
    others = [(x.status, x.kind) for x in report.verdicts if x is not v]
    assert others == ([("unverified", "iam_escalation")]
                      if detect_kind(doc) == "iam_policy" else [])


@pytest.mark.parametrize("doc", [
    # A mis-cased 'Bindings' array: recognized as an IAM policy on etag +
    # version, yet the grant it carries is invisible to the extractor. An
    # absent `bindings` key is NOT an empty allow policy.
    {"etag": "BwX=", "version": 3,
     "Bindings": [{"role": "roles/owner", "members": ["allUsers"]}]},
    # etag + version and no bindings key at all — the same absence, with
    # nothing hiding behind it. Still "never looked", not "nothing to see".
    {"etag": "BwX=", "version": 3},
])
def test_absent_bindings_key_is_unverified_not_legitimately_empty(snap, doc):
    assert detect_kind(doc) == "iam_policy"
    report = ground_policy(doc, snap)
    assert report.ok  # unverified is honest ignorance, not a gate failure
    [v] = report.verdicts
    assert (v.status, v.kind, v.target) == ("unverified", "document",
                                            "<policy object>")
    assert "detected iam_policy content" in v.message
    assert "nothing checkable" in v.message
    assert_no_line_numbers(report)


def test_legitimately_empty_iam_policy_yields_no_verdicts(snap):
    # Only an explicit `bindings: []` asserts nothing: zero claims is the
    # honest outcome there, not ignorance — no unverified verdict to record.
    report = ground_policy({"etag": "BwX=", "version": 3, "bindings": []}, snap)
    assert report.ok and report.verdicts == []
    # An absent key is a different shape and does not get that pass.
    absent = ground_policy({"etag": "BwX=", "version": 3}, snap)
    assert absent.ok
    [v] = absent.verdicts
    assert (v.status, v.kind) == ("unverified", "document")


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
    # The abstention has to name the kind that was actually detected: reading
    # every document as 'unrecognized' (or rendering a None kind as "None")
    # would make the abstention lie about what the gate saw.
    for doc, detected in ((POLICIES / "org_policy_good.json", "org_policy"),
                          ({"totally": "unrelated"}, "unrecognized")):
        report = ground_policy(doc, snap, baseline={"bindings": []})
        [subset_v] = [v for v in report.verdicts if v.kind == "subset"]
        assert (subset_v.status, subset_v.target) == ("unverified", "iam-policy")
        assert f"detected as {detected}" in subset_v.message
        assert "not an IAM policy" in subset_v.message
        assert_no_line_numbers(report)


def test_unrecognized_baseline_shape_is_unverified_not_contradicted(snap):
    new = {"bindings": [{"role": "roles/viewer",
                         "members": ["user:alice@acme.example"]}]}
    # A wrapped setIamPolicy-style body carries the very same bindings; read
    # raw it would look like "grants nothing" and mint a false contradicted.
    for baseline in ({"policy": new}, load("org_policy_good.json")):
        report = ground_policy(new, snap, baseline=baseline)
        [subset_v] = [v for v in report.verdicts if v.kind == "subset"]
        assert (subset_v.status, subset_v.target) == ("unverified", "iam-policy")
        assert "baseline" in subset_v.message
        assert "not recognized" in subset_v.message
        assert report.counts()["contradicted"] == 0 and report.ok
        assert_no_line_numbers(report)


# -- the fail-open paths no bundle reaches ------------------------------------


def only(report, kind):
    """The one verdict of *kind* in *report*, asserting it really is the one.

    In the integrated tree a registered whole-document check may add its OWN
    honest abstention to a document these tests hand the gate — for an IAM
    policy, ``iam_checks.check_escalation`` says the escalation classes were not
    decided because no role claim was extracted. That is a second ``unverified``
    on a different kind, not a second answer to the question under test, so the
    channel is selected by kind and the surrounding tests still assert that
    NOTHING here decides: every other verdict must be an abstention too.
    """
    matching = [v for v in report.verdicts if v.kind == kind]
    assert len(matching) == 1, [(v.status, v.kind, v.target) for v in report.verdicts]
    assert {v.status for v in report.verdicts} == {"unverified"}, (
        [(v.status, v.kind, v.target) for v in report.verdicts])
    return matching[0]



def test_claim_kind_no_layer_decides_is_unverified_naming_the_kind(snap, monkeypatch):
    # Defensive-only: the module promises every extracted claim receives at
    # least one verdict, so a stub claim (the layers duck-type them:
    # kind/value/location) is the honest way to reach the no-layer arm.
    #
    # The kind must be one NO layer decides. `network_tag_ref` was that kind on
    # the branch this test came from; in the integrated tree the reasoner decides
    # it (it is an EXISTENCE_KIND now and comes back as kind `network_tag`), so
    # the arm was no longer being reached at all. The premise is now asserted
    # rather than assumed, which is what stops this test going vacuous the next
    # time a layer grows.
    undecided = "unmodelled_principal"
    assert undecided not in reasoner.EXISTENCE_KINDS
    assert undecided not in ("cel", "constraint_value")
    assert registry.claim_checks(undecided) == ()
    stub = SimpleNamespace(kind=undecided, value="web-tier",
                           location="bindings[0].condition.expression")
    monkeypatch.setattr(preflight, "iam_policy_claims", lambda doc: [stub])
    report = ground_policy({"bindings": [{"role": "roles/viewer",
                                          "members": ["user:alice@acme.example"]}]},
                           snap)
    assert report.ok  # an undecided kind is ignorance, not a gate failure
    v = only(report, undecided)
    assert (v.status, v.kind, v.target) == ("unverified", undecided, "web-tier")
    assert "no offline check is wired" in v.message
    assert undecided in v.message and stub.location in v.message
    assert_no_line_numbers(report)


def test_tf_plan_without_its_extractor_is_unverified(snap, monkeypatch):
    # The accessor resolves gcp_grounding.tf_claims dynamically; where that
    # module is not part of a checkout it returns None and the plan is
    # recorded unread rather than crashing on the import.
    monkeypatch.setattr(preflight, "_tf_plan_extractor", lambda: None)
    plan = POLICIES / "tf_plan_good.json"
    report = ground_policy(plan, snap)
    assert report.ok
    [v] = report.verdicts
    assert (v.status, v.kind, v.target) == ("unverified", "document", str(plan))
    assert "terraform plan" in v.message
    assert "gcp_grounding.tf_claims" in v.message
    assert_no_line_numbers(report)


def test_claim_extraction_raising_fails_open_to_unverified(snap, monkeypatch):
    def boom(doc):
        raise TypeError("members was not iterable")

    monkeypatch.setattr(preflight, "iam_policy_claims", boom)
    report = ground_policy({"bindings": [{"role": "roles/viewer",
                                          "members": ["user:alice@acme.example"]}]},
                           snap)
    assert report.ok  # a broken extractor is not a hallucination
    v = only(report, "document")
    assert (v.status, v.kind, v.target) == ("unverified", "document",
                                            "<policy object>")
    assert "iam_policy claim extraction failed" in v.message
    assert "members was not iterable" in v.message
    assert_no_line_numbers(report)


def test_claim_extraction_failure_logs_its_traceback(snap, monkeypatch, caplog):
    def boom(doc):
        raise TypeError("members was not iterable")

    monkeypatch.setattr(preflight, "iam_policy_claims", boom)
    # Nothing in this package calls setup_logging (which turns propagation off
    # on the 'harness' logger); pin that, so this assertion keeps reading the
    # channel the gate actually writes to.
    monkeypatch.setattr(logging.getLogger("harness"), "propagate", True)
    with caplog.at_level(logging.DEBUG, logger="harness.gcp_grounding.preflight"):
        report = ground_policy({"bindings": [{"role": "roles/viewer",
                                              "members": ["user:alice@acme.example"]}]},
                               snap)
    [record] = [r for r in caplog.records
                if "claim extraction failed" in r.getMessage()]
    # The swallowed exception must reach the log with its traceback: without
    # `exc_info` the record still HAS the field, holding the literal False, so
    # truthiness — not `is not None` — is what says the traceback is on it.
    assert record.exc_info, record.exc_info
    assert record.exc_info[0] is TypeError
    # Nothing decided: the extraction failure abstains on the document channel,
    # and any registered document check that also spoke abstained too.
    assert {v.status for v in report.verdicts} == {"unverified"}
    assert [v.status for v in report.verdicts
            if v.kind == "document"] == ["unverified"]


def test_unreadable_baseline_is_unverified_not_contradicted(snap, tmp_path):
    missing = tmp_path / "old_policy.json"
    new = {"version": 3, "etag": "BwX=", "bindings": [
        {"role": "roles/viewer", "members": ["user:alice@acme.example"]}]}
    report = ground_policy(new, snap, baseline=missing)
    # An unreadable old side is ignorance about new⊆old, never a contradiction.
    assert report.ok and report.counts()["contradicted"] == 0
    [subset_v] = [v for v in report.verdicts if v.kind == "subset"]
    assert (subset_v.status, subset_v.target) == ("unverified", "iam-policy")
    assert str(missing) in subset_v.message and "could not be read" in subset_v.message
    assert "new⊆old was not decided" in subset_v.message
    assert_no_line_numbers(report)


def test_subset_check_raising_value_error_is_unverified(snap, monkeypatch):
    def boom(doc, old_doc, solver):
        raise ValueError("the policies disagree on the member vocabulary")

    monkeypatch.setattr(preflight, "check_policy_subset", boom)
    old = {"version": 3, "etag": "BwX=", "bindings": [
        {"role": "roles/viewer", "members": ["user:alice@acme.example"]}]}
    report = ground_policy(dict(old), snap, baseline=old)
    assert report.ok and report.counts()["contradicted"] == 0
    [subset_v] = [v for v in report.verdicts if v.kind == "subset"]
    assert (subset_v.status, subset_v.target) == ("unverified", "iam-policy")
    assert "new⊆old was not decided" in subset_v.message
    assert "disagree on the member vocabulary" in subset_v.message
    assert_no_line_numbers(report)


# -- the aggregate across all bundles ----------------------------------------


def test_every_good_bundle_passes_and_every_bad_bundle_is_judged(snap):
    for name in ("iam_policy_good.json", "org_policy_good.json", "tf_plan_good.json"):
        assert ground_policy(POLICIES / name, snap).ok, name
    for name, decidable in (("iam_policy_bad.json", True),
                            ("org_policy_bad.json", True),
                            ("tf_plan_bad.json", HAVE_TF_CLAIMS)):
        report = ground_policy(POLICIES / name, snap)
        assert report.ok is not decidable, name
