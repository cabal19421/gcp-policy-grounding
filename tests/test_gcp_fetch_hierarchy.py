"""Resource-hierarchy and full-IAM-binding fetch tests — mocked discovery-style
clients only. No network, no credentials, no GCP SDK (the module import is proof
fetch.py stays SDK-free at load time).

Covers the third fetch.py increment: a breadth-first Cloud Resource Manager v3
walk into ``resource_hierarchy`` that reports a ``truncated`` flag and is REFUSED
by ``capture_snapshot`` when truncated (a partial hierarchy marked captured would
manufacture false ``ungrounded`` verdicts for every out-of-scope node), plus the
single-pass CAI split into principals and full ``iam_bindings``."""

import logging
from unittest import mock

import pytest

from gcp_grounding.fetch import (
    capture_snapshot,
    fetch_hierarchy,
    fetch_iam_bindings,
    fetch_principals,
    fetch_principals_and_bindings,
)
from gcp_grounding.knowledge import UNKNOWN, GcpSnapshot

ROOT = "organizations/1"
SCOPE = "projects/acme-prod"
PROJECT_RESOURCE = "//cloudresourcemanager.googleapis.com/projects/acme-prod"


def _request(payload):
    """A discovery-style request object: .execute() returns the page."""
    request = mock.Mock(name="request")
    request.execute.return_value = payload
    return request


def _crm_mock(tree):
    """A Cloud Resource Manager v3 double. *tree* maps a parent node
    ("organizations/1", "folders/2", …) to ``{"folders": [...], "projects":
    [...]}``; folders.list / projects.list dispatch on the ``parent`` kwarg so a
    single mock serves the whole breadth-first walk."""
    crm = mock.Mock(name="crm")

    def folders_list(parent, pageToken=None):
        return _request({"folders": list(tree.get(parent, {}).get("folders", ()))})

    def projects_list(parent, pageToken=None):
        return _request({"projects": list(tree.get(parent, {}).get("projects", ()))})

    crm.folders.return_value.list.side_effect = folders_list
    crm.projects.return_value.list.side_effect = projects_list
    return crm


# A three-level org → folder → project tree. The project's `name` is its NUMBER
# form; its `projectId` is the human id the canonical key uses.
_THREE_LEVEL = {
    ROOT: {"folders": [{"name": "folders/2", "parent": ROOT,
                        "displayName": "prod"}],
           "projects": []},
    "folders/2": {"folders": [],
                  "projects": [{"name": "projects/123456",
                                "projectId": "acme-prod", "parent": "folders/2",
                                "displayName": "Acme Prod"}]},
}

# A cyclic parent link: folders/2 → folders/3 → folders/2.
_CYCLIC = {
    ROOT: {"folders": [{"name": "folders/2", "parent": ROOT}], "projects": []},
    "folders/2": {"folders": [{"name": "folders/3", "parent": "folders/2"}],
                  "projects": []},
    "folders/3": {"folders": [{"name": "folders/2", "parent": "folders/3"}],
                  "projects": []},
}


def _bindings_asset():
    """A fresh CAI double whose single page carries one resource with an
    unconditional binding, a conditional binding, and a role-less binding."""
    asset = mock.Mock(name="asset")
    asset.v1.return_value.searchAllIamPolicies.side_effect = [
        _request({"results": [
            {"resource": PROJECT_RESOURCE,
             "policy": {"bindings": [
                 {"role": "roles/owner", "members": ["user:alice@acme.example"]},
                 {"role": "roles/viewer",
                  "members": ["group:data-eng@acme.example"],
                  "condition": {"title": "biz-hours", "expression": "true"}},
                 {"members": ["user:norole@acme.example"]},  # no role → skipped
             ]}},
        ]}),  # single page: no nextPageToken → exactly one searchAllIamPolicies call
    ]
    return asset


# -- fetch_hierarchy: the breadth-first walk -------------------------------


def test_fetch_hierarchy_captures_three_levels_untruncated():
    hierarchy, truncated = fetch_hierarchy(_crm_mock(_THREE_LEVEL), ROOT)
    assert truncated is False
    assert set(hierarchy) == {ROOT, "folders/2", "projects/acme-prod"}
    # the root is included with a null parent
    assert hierarchy[ROOT] == {"parent": None, "type": "organization",
                               "number": "1", "display_name": None}
    # parent links are correct across levels
    assert hierarchy["folders/2"]["parent"] == ROOT
    assert hierarchy["folders/2"]["type"] == "folder"
    assert hierarchy["projects/acme-prod"]["parent"] == "folders/2"
    assert hierarchy["projects/acme-prod"]["type"] == "project"
    # the project NUMBER comes from its `name` (projects/<number>), keyed by id
    assert hierarchy["projects/acme-prod"]["number"] == "123456"
    assert hierarchy["projects/acme-prod"]["display_name"] == "Acme Prod"


def test_fetch_hierarchy_terminates_and_flags_a_cycle(caplog):
    with caplog.at_level(logging.WARNING):
        hierarchy, truncated = fetch_hierarchy(_crm_mock(_CYCLIC), ROOT)
    assert truncated is True
    # the walk terminated (both distinct folders recorded exactly once)
    assert set(hierarchy) == {ROOT, "folders/2", "folders/3"}
    assert any("cycle" in rec.message for rec in caplog.records)


def test_fetch_hierarchy_respects_max_depth_and_flags_truncation():
    hierarchy, truncated = fetch_hierarchy(_crm_mock(_THREE_LEVEL), ROOT, max_depth=1)
    assert truncated is True
    # the depth-1 folder is recorded, but its subtree (the project) is not walked
    assert set(hierarchy) == {ROOT, "folders/2"}
    assert "projects/acme-prod" not in hierarchy


def test_fetch_hierarchy_flags_truncation_on_a_per_page_error():
    crm = _crm_mock(_THREE_LEVEL)

    def boom(parent, pageToken=None):
        raise RuntimeError("permission denied on projects.list")

    crm.projects.return_value.list.side_effect = boom
    hierarchy, truncated = fetch_hierarchy(crm, ROOT)
    assert truncated is True  # a dropped subtree must not read as a captured one
    assert "projects/acme-prod" not in hierarchy


# -- capture_snapshot: a truncated walk is REFUSED -------------------------


def test_capture_snapshot_refuses_a_truncated_hierarchy(caplog):
    with caplog.at_level(logging.WARNING):
        snap = capture_snapshot(crm=_crm_mock(_CYCLIC), hierarchy_root=ROOT,
                                captured_at="2026-07-19T12:00:00Z")
    # a truncated-but-captured table would manufacture false 'ungrounded'
    # verdicts for every node outside the walk — so the category stays None
    assert "resource_hierarchy" not in snap.captured_categories()
    assert snap.hierarchy_node("folders/2") is UNKNOWN
    assert snap.hierarchy_node("organizations/1") is UNKNOWN
    assert any(ROOT in rec.message for rec in caplog.records)


def test_capture_snapshot_captures_an_untruncated_hierarchy_and_bindings():
    snap = capture_snapshot(
        crm=_crm_mock(_THREE_LEVEL), hierarchy_root=ROOT,
        asset=_bindings_asset(), asset_scope=SCOPE, capture_iam_bindings=True,
        captured_at="2026-07-19T12:00:00Z")
    assert snap.captured_categories() == ("principals", "resource_hierarchy",
                                          "iam_bindings")
    # the project-number alias resolves the id-keyed record
    node = snap.hierarchy_node("projects/123456")
    assert node is not None
    assert node["display_name"] == "Acme Prod"
    assert node == snap.hierarchy_node("projects/acme-prod")
    # both categories rode one CAI pass
    assert snap.principal_exists("user:alice@acme.example") is True
    bset = snap.iam_binding_set(PROJECT_RESOURCE)
    assert bset["bindings"][0]["role"] == "roles/owner"


# -- fetch_iam_bindings: role + members + verbatim condition ----------------


def test_fetch_iam_bindings_preserves_condition_and_skips_roleless():
    bindings = fetch_iam_bindings(_bindings_asset(), SCOPE)
    records = bindings[PROJECT_RESOURCE]["bindings"]
    # the role-less binding is skipped; the two real bindings survive
    assert [r["role"] for r in records] == ["roles/owner", "roles/viewer"]
    assert all(r["role"] for r in records)
    # an unconditional binding carries condition None
    assert records[0]["condition"] is None
    assert records[0]["members"] == ["user:alice@acme.example"]
    # a conditional binding's condition OBJECT is preserved verbatim
    assert records[1]["condition"] == {"title": "biz-hours", "expression": "true"}


def test_fetch_principals_and_bindings_is_one_pass():
    asset = _bindings_asset()
    principals, bindings = fetch_principals_and_bindings(asset, SCOPE)
    # a single pass over the estate: searchAllIamPolicies paginated exactly once
    assert asset.v1.return_value.searchAllIamPolicies.call_count == 1
    # the principal set is identical to what fetch_principals would return —
    # members from EVERY binding, role-less ones included
    assert principals == fetch_principals(_bindings_asset(), SCOPE)
    assert principals == frozenset({"user:alice@acme.example",
                                    "group:data-eng@acme.example",
                                    "user:norole@acme.example"})
    # bindings match fetch_iam_bindings (role-less skipped there)
    assert [r["role"] for r in bindings[PROJECT_RESOURCE]["bindings"]] == [
        "roles/owner", "roles/viewer"]


# -- from_dict round-trip ---------------------------------------------------


def test_produced_hierarchy_and_bindings_load_through_from_dict():
    hierarchy, truncated = fetch_hierarchy(_crm_mock(_THREE_LEVEL), ROOT)
    assert truncated is False
    _principals, bindings = fetch_principals_and_bindings(_bindings_asset(), SCOPE)
    snap = GcpSnapshot.from_dict({"captured_at": "2026-07-19T12:00:00Z",
                                  "resource_hierarchy": hierarchy,
                                  "iam_bindings": bindings})
    # the project-number alias resolves through the loaded snapshot
    node = snap.hierarchy_node("projects/123456")
    assert node is not None
    assert node["number"] == "123456"
    assert "projects/123456" in snap.hierarchy_names()
    bset = snap.iam_binding_set(PROJECT_RESOURCE)
    assert bset["bindings"][1]["condition"] == {"title": "biz-hours",
                                                "expression": "true"}


# -- capture_snapshot: paired guards ---------------------------------------


def test_capture_snapshot_crm_without_hierarchy_root_raises():
    with pytest.raises(ValueError):
        capture_snapshot(crm=mock.Mock())


def test_capture_snapshot_hierarchy_root_without_crm_raises():
    with pytest.raises(ValueError):
        capture_snapshot(hierarchy_root=ROOT)


def test_capture_snapshot_iam_bindings_without_asset_raises():
    with pytest.raises(ValueError):
        capture_snapshot(capture_iam_bindings=True)
