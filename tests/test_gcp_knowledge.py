"""Knowledge-base tests: snapshot load, round-trip, and the load-bearing
UNKNOWN-vs-absent distinction every later grounding test relies on."""

import json
from pathlib import Path

import pytest

from gcp_grounding.knowledge import UNKNOWN, GcpSnapshot, Unknown

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
SNAPSHOT_PATH = FIXTURES / "snapshot.json"


@pytest.fixture()
def snap() -> GcpSnapshot:
    return GcpSnapshot.load(SNAPSHOT_PATH)


# -- load -----------------------------------------------------------------


def test_load_exposes_captured_at(snap):
    assert snap.captured_at == "2026-07-18T09:30:00Z"


def test_role_lookup(snap):
    assert snap.role_exists("roles/bigquery.dataViewer") is True
    assert snap.role_exists("projects/acme-prod/roles/ciDeployer") is True
    # The canonical hallucination: plausible name, does not exist. Must be a
    # hard False (category was enumerated), never UNKNOWN.
    assert snap.role_exists("roles/bigquery.reader") is False


def test_permission_lookup(snap):
    assert snap.permission_exists("bigquery.jobs.create") is True
    assert snap.permission_exists("bigquery.jobs.imagine") is False


def test_principal_lookup(snap):
    assert snap.principal_exists(
        "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com") is True
    assert snap.principal_exists(
        "serviceAccount:ghost-runner@acme-prod.iam.gserviceaccount.com") is False


def test_constraint_lookup(snap):
    boolean = snap.constraint("constraints/compute.disableSerialPortAccess")
    assert boolean["value_type"] == "boolean"
    listy = snap.constraint("constraints/compute.vmExternalIpAccess")
    assert listy["value_type"] == "list"
    # Enumerated category, absent name → None (not UNKNOWN).
    assert snap.constraint("constraints/compute.disableSerialPort") is None


def test_resource_type_lookup(snap):
    assert snap.resource_type_exists("compute.googleapis.com/Instance") is True
    assert snap.resource_type_exists("compute.googleapis.com/Droplet") is False


# -- round-trip -----------------------------------------------------------


def test_to_dict_matches_fixture_exactly(snap):
    with open(SNAPSHOT_PATH, encoding="utf-8") as fh:
        assert snap.to_dict() == json.load(fh)


def test_from_dict_to_dict_round_trip(snap):
    clone = GcpSnapshot.from_dict(snap.to_dict())
    assert clone == snap
    assert clone.to_dict() == snap.to_dict()


# -- UNKNOWN vs absent ----------------------------------------------------


def test_uncaptured_categories_answer_unknown_not_false():
    # Only roles were captured (e.g. CAI not enumerated): every other
    # category must answer UNKNOWN, or the reasoner would report a false
    # 'ungrounded' where only 'unverified' is honest.
    partial = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T09:30:00Z",
        "roles": {"roles/viewer": {"included_permissions": ["resourcemanager.projects.get"]}},
    })
    assert partial.principal_exists("user:alice@acme.example") is UNKNOWN
    assert partial.constraint("constraints/compute.vmExternalIpAccess") is UNKNOWN
    assert partial.resource_type_exists("storage.googleapis.com/Bucket") is UNKNOWN
    assert partial.permission_exists("storage.objects.get") is UNKNOWN
    # ...while the captured category still answers hard True/False.
    assert partial.role_exists("roles/viewer") is True
    assert partial.role_exists("roles/editor") is False


def test_captured_empty_means_absent_not_unknown():
    empty = GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z", "principals": []})
    assert empty.principal_exists("user:alice@acme.example") is False
    assert empty.role_exists("roles/viewer") is UNKNOWN


def test_permission_in_a_captured_role_proves_existence_without_enumeration():
    partial = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T09:30:00Z",
        "roles": {"roles/viewer": {"included_permissions": ["resourcemanager.projects.get"]}},
    })
    # No permission enumeration, but a real role includes it → it exists.
    assert partial.permission_exists("resourcemanager.projects.get") is True
    assert partial.permission_exists("resourcemanager.projects.imagine") is UNKNOWN


def test_unknown_sentinel_refuses_truthiness():
    # `if not snapshot.role_exists(r)` on an uncaptured category must blow up
    # loudly instead of silently minting a false 'ungrounded'.
    with pytest.raises(TypeError):
        bool(UNKNOWN)
    assert repr(UNKNOWN) == "UNKNOWN"
    assert Unknown() is UNKNOWN  # singleton


# -- loader validation ----------------------------------------------------


def test_from_dict_requires_captured_at():
    with pytest.raises(ValueError):
        GcpSnapshot.from_dict({"roles": {}})


def test_from_dict_rejects_unrecognized_keys():
    # A typo ("role" for "roles") must not silently demote a category to UNKNOWN.
    with pytest.raises(ValueError):
        GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z", "role": {}})


def test_from_dict_requires_constraint_value_type():
    with pytest.raises(ValueError):
        GcpSnapshot.from_dict({
            "captured_at": "2026-07-18T09:30:00Z",
            "constraints": {"constraints/compute.disableSerialPortAccess": {}},
        })


def test_load_rejects_malformed_json(tmp_path):
    bad = tmp_path / "snapshot.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        GcpSnapshot.load(bad)


# -- shared policy fixtures ------------------------------------------------


def test_policy_fixtures_present_and_valid_json():
    # good + bad IAM / org-policy / tf-plan samples, used by every later test.
    names = {p.name for p in (FIXTURES / "policies").glob("*.json")}
    assert {"iam_policy_good.json", "iam_policy_bad.json",
            "org_policy_good.json", "org_policy_bad.json",
            "tf_plan_good.json", "tf_plan_bad.json"} <= names
    for name in names:
        json.loads((FIXTURES / "policies" / name).read_text(encoding="utf-8"))
