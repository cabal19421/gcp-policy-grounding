"""Changed-file gate tests: :class:`gcp_grounding.gate.PolicyGroundingGate`
over fake changed-file lists against the shared fixtures — policy files are
grounded end-to-end, non-policy and unjudgeable files fail open into
``unverified`` (never a crash), and the aggregate ok/risk signal plus the
path-prefixed findings come out right for feeding a generator's next prompt.

Environment-honest like the preflight suite: the tf-plan expectations branch
on whether the separately shipped ``gcp_grounding.tf_claims`` extractor is
part of this checkout; everything else is asserted backend-independently, so
the suite passes with and without z3.
"""

import importlib.util
import json
from pathlib import Path

import pytest

from gcp_grounding.gate import (FILE_STATUSES, GATE_SCHEMA, RISK_LEVELS,
                                PolicyGroundingGate)
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.report import SCHEMA as REPORT_SCHEMA

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"
CAPTURED = "2026-07-18T09:30:00Z"  # the fixture snapshot's captured_at

GHOST = "serviceAccount:ghost-runner@acme-prod.iam.gserviceaccount.com"

HAVE_TF_CLAIMS = importlib.util.find_spec("gcp_grounding.tf_claims") is not None


@pytest.fixture()
def gate() -> PolicyGroundingGate:
    return PolicyGroundingGate(FIXTURES / "snapshot.json")


def statuses(result) -> list[str]:
    return [f.status for f in result.files]


# -- construction -------------------------------------------------------------


def test_gate_accepts_a_snapshot_object_or_a_path(gate):
    from_obj = PolicyGroundingGate(GcpSnapshot.load(FIXTURES / "snapshot.json"))
    for g in (gate, from_obj):
        result = g.check([POLICIES / "org_policy_good.json"])
        assert result.ok and result.captured_at == CAPTURED


def test_empty_changed_set_is_clean(gate):
    result = gate.check([])
    assert result.ok and result.risk == "none"
    assert result.files == () and result.findings() == ()
    assert "PASSED" in result.render() and "(no changed files)" in result.render()


# -- grounding the policy files of a changed set ------------------------------


def test_good_policy_files_pass_with_no_risk(gate):
    changed = [POLICIES / "iam_policy_good.json", POLICIES / "org_policy_good.json"]
    result = gate.check(changed)
    assert result.ok and result.risk == "none"
    assert statuses(result) == ["ok", "ok"]
    assert [f.path for f in result.files] == [str(p) for p in changed]
    assert all(f.policy_candidate for f in result.files)
    assert result.findings() == ()
    assert "PASSED" in result.render()


def test_bad_iam_policy_fails_the_gate_with_findings(gate):
    result = gate.check([POLICIES / "iam_policy_bad.json"])
    assert not result.ok and result.risk == "high"
    assert statuses(result) == ["failed"]
    findings = result.findings()
    text = "\n".join(findings)
    assert "roles/bigquery.reader" in text and GHOST in text
    assert "did you mean" in text and "roles/bigquery.dataViewer" in text
    # Every findings line is path-prefixed so a generator knows what to fix.
    assert all(line.startswith(str(POLICIES / "iam_policy_bad.json") + ": ")
               for line in findings)


def test_bad_org_policy_fails_on_the_value_type_mismatch(gate):
    result = gate.check([POLICIES / "org_policy_bad.json"])
    assert not result.ok and result.risk == "high"
    assert statuses(result) == ["failed"]
    assert "boolean" in "\n".join(result.findings())


def test_tf_plan_changed_files(gate):
    result = gate.check([POLICIES / "tf_plan_good.json",
                         POLICIES / "tf_plan_bad.json"])
    if not HAVE_TF_CLAIMS:
        # Fail-open: without the separately shipped extractor both plans are
        # policy-relevant but unjudgeable — honest unverified, low risk.
        assert result.ok and result.risk == "low"
        assert statuses(result) == ["unverified", "unverified"]
        assert all(f.policy_candidate for f in result.files)
        assert "tf_claims" in "\n".join(result.findings())
        return
    assert not result.ok and result.risk == "high"
    good, bad = result.files
    assert good.status == "ok" and bad.status == "failed"
    text = "\n".join(result.findings())
    assert "roles/bigquery.reader" in text and GHOST in text
    assert all(line.startswith(str(POLICIES / "tf_plan_bad.json") + ": ")
               for line in result.findings())


# -- fail-open: non-policy and unjudgeable files ------------------------------


def test_non_policy_files_are_recorded_unverified_without_risk(gate, tmp_path):
    app = tmp_path / "app.py"
    app.write_text("print('hello')\n", encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text("# nothing to see\n", encoding="utf-8")
    result = gate.check([app, readme, POLICIES / "org_policy_good.json"])
    assert result.ok and result.risk == "none"  # a changed README is no risk
    assert statuses(result) == ["unverified", "unverified", "ok"]
    assert [f.policy_candidate for f in result.files] == [False, False, True]
    assert result.findings() == ()
    [note] = result.files[0].verdicts
    assert note.status == "unverified" and "not a policy file" in note.message


def test_unrecognized_json_is_recorded_unverified_without_risk(gate, tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"name": "acme", "version": "1.0.0"}),
                   encoding="utf-8")
    result = gate.check([pkg])
    assert result.ok and result.risk == "none"
    [file] = result.files
    assert file.status == "unverified" and not file.policy_candidate
    [note] = file.verdicts
    assert "not recognized" in note.message and "not checked" in note.message


def test_missing_policy_file_is_low_risk_unverified(gate, tmp_path):
    result = gate.check([tmp_path / "gone.policy.json"])
    assert result.ok and result.risk == "low"
    [file] = result.files
    assert file.status == "unverified" and file.policy_candidate
    assert "could not be read" in "\n".join(result.findings())


def test_invalid_json_policy_file_fails_open(gate, tmp_path):
    broken = tmp_path / "broken.policy.json"
    broken.write_text("{not json", encoding="utf-8")
    result = gate.check([broken])
    assert result.ok and result.risk == "low"
    assert statuses(result) == ["unverified"]
    # The parse failure is feedback for the generator, not silence.
    assert "not valid JSON" in "\n".join(result.findings())


def test_raw_terraform_hcl_is_low_risk_unverified(gate, tmp_path):
    main_tf = tmp_path / "main.tf"
    main_tf.write_text('resource "google_project_iam_member" "x" {}\n',
                       encoding="utf-8")
    result = gate.check([main_tf])
    assert result.ok and result.risk == "low"
    [file] = result.files
    assert file.status == "unverified" and file.policy_candidate
    assert "terraform show -json" in "\n".join(result.findings())


def test_undecodable_bytes_never_crash_the_gate(gate, tmp_path):
    garbled = tmp_path / "garbled.policy.json"
    garbled.write_bytes(b"\xff\xfe{\x00}")
    result = gate.check([garbled])
    assert result.ok and result.risk == "low"
    assert statuses(result) == ["unverified"]


# -- the aggregate ------------------------------------------------------------


def test_mixed_changed_set_aggregates_ok_risk_and_counts(gate, tmp_path):
    app = tmp_path / "app.py"
    app.write_text("pass\n", encoding="utf-8")
    result = gate.check([POLICIES / "iam_policy_bad.json",
                         POLICIES / "org_policy_good.json",
                         app,
                         tmp_path / "gone.policy.json"])
    assert not result.ok and result.risk == "high"
    assert statuses(result) == ["failed", "ok", "unverified", "unverified"]
    assert result.counts() == {"ok": 1, "unverified": 2, "failed": 1}
    assert result.risk in RISK_LEVELS
    assert all(f.status in FILE_STATUSES for f in result.files)
    assert "FAILED" in result.render() and "risk: high" in result.render()


def test_duplicate_changed_paths_are_processed_once(gate):
    path = POLICIES / "org_policy_good.json"
    result = gate.check([path, path, str(path)])
    assert len(result.files) == 1 and result.ok


def test_per_file_reports_carry_source_and_snapshot_freshness(gate):
    result = gate.check([POLICIES / "iam_policy_good.json"])
    [file] = result.files
    assert file.report.captured_at == CAPTURED
    assert file.report.source == str(POLICIES / "iam_policy_good.json")
    assert file.report.ok


def test_to_dict_is_a_stable_ci_document(gate, tmp_path):
    result = gate.check([POLICIES / "iam_policy_bad.json",
                         tmp_path / "gone.policy.json"])
    doc = result.to_dict()
    assert list(doc) == ["schema", "ok", "risk", "backend", "captured_at",
                         "counts", "files", "findings"]
    assert doc["schema"] == GATE_SCHEMA and doc["ok"] is False
    assert doc["risk"] == "high" and doc["captured_at"] == CAPTURED
    assert [f["status"] for f in doc["files"]] == ["failed", "unverified"]
    assert all(f["report"]["schema"] == REPORT_SCHEMA for f in doc["files"])
    assert doc["findings"] == list(result.findings())
    json.dumps(doc)  # serializable as-is
