"""Report adapter tests: the four-bucket summary counts, the captured_at
freshness stamp on grounded/unverified lines, the stable ``--format json``
document, and the gate — ok is False iff anything is ungrounded or
contradicted. The vendored core is wrapped, never edited."""

import itertools
import json
from pathlib import Path

import pytest

from gcp_grounding.claims import iam_policy_claims
from gcp_grounding.core.report import STATUSES, GroundingReport, Verdict
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.reasoner import ground_existence
from gcp_grounding.report import FORMATS, SCHEMA, PolicyReport

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
CAPTURED = "2026-07-18T09:30:00Z"  # the fixture snapshot's captured_at

# One policy-shaped verdict per status (lineno 0, json-path in the message),
# for tests that need exact control over the report's contents.
_SAMPLES = {
    "grounded": Verdict(
        "grounded", "role", "roles/viewer", 0,
        "bindings[0].role: role 'roles/viewer' exists in the snapshot"),
    "ungrounded": Verdict(
        "ungrounded", "role", "roles/bigquery.reader", 0,
        "bindings[1].role: role 'roles/bigquery.reader' does not exist",
        suggestions=("roles/bigquery.dataViewer",)),
    "contradicted": Verdict(
        "contradicted", "constraint", "constraints/compute.vmExternalIpAccess", 0,
        "booleanPolicy: constraint is list-typed but used boolean-typed"),
    "unverified": Verdict(
        "unverified", "principal", "user:alice@acme.example", 0,
        "bindings[0].members[0]: snapshot did not capture principals"),
}


def adapted(*statuses: str, **kwargs) -> PolicyReport:
    report = GroundingReport()
    for status in statuses:
        report.add(_SAMPLES[status])
    return PolicyReport(report, CAPTURED, **kwargs)


def policy(name: str) -> dict:
    return json.loads((FIXTURES / "policies" / name).read_text(encoding="utf-8"))


@pytest.fixture()
def snap() -> GcpSnapshot:
    return GcpSnapshot.load(FIXTURES / "snapshot.json")


@pytest.fixture()
def bad(snap) -> PolicyReport:
    report = ground_existence(iam_policy_claims(policy("iam_policy_bad.json")), snap)
    return PolicyReport(report, snap.captured_at, source="iam_policy_bad.json")


# -- the four-bucket summary -----------------------------------------------


def test_summary_counts_the_bad_fixture(bad):
    assert bad.summary() == {"grounded": 4, "ungrounded": 2,
                             "contradicted": 0, "unverified": 0}


def test_summary_always_carries_all_four_buckets():
    assert adapted().summary() == {s: 0 for s in STATUSES}
    assert tuple(adapted("grounded", "unverified").summary()) == STATUSES


# -- the gate: ok is False iff anything is ungrounded/contradicted ---------


@pytest.mark.parametrize("statuses", [
    combo for r in range(len(STATUSES) + 1)
    for combo in itertools.combinations(STATUSES, r)])
def test_ok_iff_nothing_ungrounded_or_contradicted(statuses):
    pol = adapted(*statuses)
    expected = not ({"ungrounded", "contradicted"} & set(statuses))
    assert pol.ok is expected
    assert ("PASSED" if expected else "FAILED") in pol.render()
    assert json.loads(pol.render(format="json"))["ok"] is expected


# -- human renderer --------------------------------------------------------


def test_human_header_names_source_and_counts(bad):
    head = bad.render().splitlines()[0]
    assert "GCP policy grounding iam_policy_bad.json FAILED" in head
    assert "[builtin]" in head
    assert "grounded=4 ungrounded=2 contradicted=0 unverified=0" in head


def test_grounded_and_unverified_lines_carry_the_freshness_stamp():
    lines = adapted("grounded", "ungrounded", "unverified").render().splitlines()
    stamped = [line for line in lines if f"[snapshot {CAPTURED}]" in line]
    assert [line.strip()[0] for line in stamped] == ["?", "✓"]
    [ungrounded] = [line for line in lines if line.startswith("  ✗")]
    assert CAPTURED not in ungrounded


def test_every_grounded_line_of_a_clean_policy_is_stamped(snap):
    report = ground_existence(iam_policy_claims(policy("iam_policy_good.json")), snap)
    pol = PolicyReport(report, snap.captured_at)
    head, *lines = pol.render().splitlines()
    assert "PASSED" in head
    assert len(lines) == 7  # 3 roles + 4 principals, all grounded
    assert all(f"[snapshot {snap.captured_at}]" in line for line in lines)


def test_findings_keep_location_and_suggestions(bad):
    text = bad.render()
    assert "bindings[0].role" in text
    assert "did you mean: " in text
    assert "roles/bigquery.dataViewer" in text


def test_render_of_an_empty_report_says_so():
    text = adapted().render()
    assert "PASSED" in text
    assert "(no claims to ground)" in text


# -- machine output (--format json) ----------------------------------------


def test_json_document_has_the_stable_schema(bad):
    doc = json.loads(bad.render(format="json"))
    assert tuple(doc) == ("schema", "ok", "backend", "captured_at",
                          "source", "summary", "verdicts")
    assert doc["schema"] == SCHEMA
    assert doc["ok"] is False
    assert doc["backend"] == "builtin"
    assert doc["captured_at"] == CAPTURED
    assert doc["source"] == "iam_policy_bad.json"
    assert doc["summary"] == bad.summary()
    assert len(doc["verdicts"]) == 6
    for verdict in doc["verdicts"]:
        assert tuple(verdict) == ("status", "kind", "target",
                                  "message", "suggestions")


def test_json_round_trips_the_findings(bad):
    doc = json.loads(bad.render(format="json"))
    [reader] = [v for v in doc["verdicts"]
                if v["status"] == "ungrounded" and v["kind"] == "role"]
    assert reader["target"] == "roles/bigquery.reader"
    assert "roles/bigquery.dataViewer" in reader["suggestions"]


def test_json_output_is_deterministic(bad):
    assert bad.render(format="json") == bad.render(format="json")
    assert bad.render(format="json") == json.dumps(bad.to_dict(),
                                                   indent=2, ensure_ascii=False)


# -- guard rails -----------------------------------------------------------


def test_formats_are_human_and_json():
    assert FORMATS == ("human", "json")


def test_unknown_format_is_rejected():
    with pytest.raises(ValueError, match="yaml"):
        adapted().render(format="yaml")


def test_empty_captured_at_is_rejected():
    with pytest.raises(ValueError, match="captured_at"):
        PolicyReport(GroundingReport(), "")
