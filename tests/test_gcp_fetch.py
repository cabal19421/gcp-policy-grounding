"""Live-fetch tests — mocked discovery-style clients only. No network, no
credentials, no GCP SDK: the venv deliberately has none installed, so the
module import at the top of this file is itself the proof that fetch.py
touches no SDK at load time."""

import importlib.util
import json
import re
import sys
from unittest import mock

import pytest

from gcp_grounding import fetch
from gcp_grounding.fetch import (
    MissingDependencyError,
    capture_snapshot,
    fetch_asset_types,
    fetch_constraints,
    fetch_permissions,
    fetch_principals,
    fetch_resource_types,
    fetch_roles,
    fresh_captured_at,
)
from gcp_grounding.knowledge import UNKNOWN, GcpSnapshot

ORG = "organizations/123"
SCOPE = "projects/acme-prod"
RESOURCE = "//cloudresourcemanager.googleapis.com/projects/acme-prod"


def _request(payload):
    """A discovery-style request object: .execute() returns the page."""
    request = mock.Mock(name="request")
    request.execute.return_value = payload
    return request


def _iam_mock():
    iam = mock.Mock(name="iam")
    iam.roles.return_value.list.side_effect = [
        _request({"roles": [{"name": "roles/bigquery.dataViewer",
                             "title": "BigQuery Data Viewer", "stage": "GA",
                             "includedPermissions": ["bigquery.tables.get",
                                                     "bigquery.datasets.get"]}],
                  "nextPageToken": "t1"}),
        # list view without includedPermissions → must be backfilled via roles.get
        _request({"roles": [{"name": "roles/viewer", "title": "Viewer",
                             "stage": "GA"}]}),
    ]
    iam.roles.return_value.get.return_value = _request(
        {"name": "roles/viewer", "title": "Viewer", "stage": "GA",
         "includedPermissions": ["resourcemanager.projects.get"]})
    iam.organizations.return_value.roles.return_value.list.side_effect = [
        _request({"roles": [{"name": f"{ORG}/roles/ciDeployer",
                             "title": "Acme CI deployer", "stage": "GA",
                             "includedPermissions": ["storage.objects.create"]}]}),
    ]
    iam.permissions.return_value.queryTestablePermissions.side_effect = [
        _request({"permissions": [{"name": "storage.objects.get"}],
                  "nextPageToken": "p1"}),
        _request({"permissions": [{"name": "storage.objects.list"}]}),
    ]
    return iam


def _orgpolicy_mock():
    orgpolicy = mock.Mock(name="orgpolicy")
    orgpolicy.organizations.return_value.constraints.return_value.list.side_effect = [
        _request({"constraints": [
            {"name": f"{ORG}/constraints/compute.disableSerialPortAccess",
             "description": "Disable VM serial port access",
             "booleanConstraint": {}}],
            "nextPageToken": "c1"}),
        _request({"constraints": [
            {"name": f"{ORG}/constraints/compute.vmExternalIpAccess",
             "listConstraint": {"supportsIn": True}},
            {"name": f"{ORG}/constraints/example.mystery"}]}),
    ]
    return orgpolicy


def _asset_mock():
    asset = mock.Mock(name="asset")
    asset.v1.return_value.searchAllIamPolicies.side_effect = [
        _request({"results": [{"policy": {"bindings": [
            {"role": "roles/viewer",
             "members": ["user:alice@acme.example",
                         "serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com"]}]}}],
            "nextPageToken": "s1"}),
        _request({"results": [
            {"policy": {"bindings": [
                {"role": "roles/editor",
                 "members": ["user:alice@acme.example",
                             "group:data-eng@acme.example"]}]}},
            {"policy": {}}]}),
    ]
    asset.assets.return_value.list.side_effect = [
        _request({"assets": [{"assetType": "compute.googleapis.com/Instance"},
                             {"assetType": "storage.googleapis.com/Bucket"},
                             {"assetType": "compute.googleapis.com/Instance"}]}),
    ]
    return asset


TF_SCHEMA = {"format_version": "1.0", "provider_schemas": {
    "registry.terraform.io/hashicorp/google": {"resource_schemas": {
        "google_project_iam_binding": {}, "google_org_policy_policy": {}}},
    "registry.terraform.io/hashicorp/google-beta": {"resource_schemas": {
        "google_project_iam_member": {}}}}}


# -- module is SDK-free ----------------------------------------------------


def test_module_imports_without_any_gcp_sdk():
    assert "gcp_grounding.fetch" in sys.modules
    assert "googleapiclient" not in sys.modules


def test_default_client_reports_missing_sdk_clearly():
    if importlib.util.find_spec("googleapiclient") is not None:
        pytest.skip("google-api-python-client is installed here — the "
                    "missing-SDK path cannot be exercised")
    with pytest.raises(MissingDependencyError, match="google-api-python-client"):
        fetch.default_client("iam")


def test_default_client_rejects_unknown_api_without_version():
    with pytest.raises(ValueError):
        fetch.default_client("bananas")


# -- captured_at -----------------------------------------------------------


def test_fresh_captured_at_is_utc_iso8601():
    stamp = fresh_captured_at()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", stamp)
    # usable as a snapshot timestamp as-is
    GcpSnapshot.from_dict({"captured_at": stamp})


# -- IAM roles + permissions -----------------------------------------------


def test_fetch_roles_paginates_and_backfills_permissions():
    iam = _iam_mock()
    roles = fetch_roles(iam, custom_role_parents=(ORG,))
    assert set(roles) == {"roles/bigquery.dataViewer", "roles/viewer",
                          f"{ORG}/roles/ciDeployer"}
    # FULL-view permissions arrive inline, sorted for determinism
    assert roles["roles/bigquery.dataViewer"]["included_permissions"] == [
        "bigquery.datasets.get", "bigquery.tables.get"]
    # the entry the list view left bare was backfilled with one roles.get
    assert roles["roles/viewer"]["included_permissions"] == [
        "resourcemanager.projects.get"]
    iam.roles.return_value.get.assert_called_once_with(name="roles/viewer")
    # pagination: the second page was requested with the token
    assert iam.roles.return_value.list.call_args_list == [
        mock.call(view="FULL"), mock.call(view="FULL", pageToken="t1")]
    # custom roles were listed under the org parent
    iam.organizations.return_value.roles.return_value.list.assert_called_once_with(
        view="FULL", parent=ORG)
    # records are snapshot-ready
    snap = GcpSnapshot.from_dict({"captured_at": "2026-07-19T12:00:00Z",
                                  "roles": roles})
    assert snap.role_exists(f"{ORG}/roles/ciDeployer") is True


def test_fetch_roles_skips_deleted_roles():
    iam = mock.Mock(name="iam")
    iam.roles.return_value.list.side_effect = [
        _request({"roles": [{"name": "roles/gone", "deleted": True,
                             "includedPermissions": ["x.y.z"]}]}),
    ]
    assert fetch_roles(iam) == {}


def test_fetch_roles_rejects_unknown_parent_shape():
    with pytest.raises(ValueError):
        fetch_roles(mock.Mock(), custom_role_parents=("folders/1",))


def test_fetch_permissions_paginates_the_testable_enumeration():
    iam = _iam_mock()
    permissions = fetch_permissions(iam, [RESOURCE])
    assert permissions == frozenset({"storage.objects.get", "storage.objects.list"})
    bodies = [c.kwargs["body"] for c in
              iam.permissions.return_value.queryTestablePermissions.call_args_list]
    assert bodies[0] == {"fullResourceName": RESOURCE}
    assert bodies[1] == {"fullResourceName": RESOURCE, "pageToken": "p1"}


# -- Org Policy constraints ------------------------------------------------


def test_fetch_constraints_maps_value_types_and_short_names():
    orgpolicy = _orgpolicy_mock()
    constraints = fetch_constraints(orgpolicy, ORG)
    assert constraints["constraints/compute.disableSerialPortAccess"] == {
        "value_type": "boolean", "description": "Disable VM serial port access"}
    assert constraints["constraints/compute.vmExternalIpAccess"]["value_type"] == "list"
    # neither boolean- nor list-typed → still present (dropping it would read
    # as a false 'ungrounded' downstream), with an explicit unknown type
    assert constraints["constraints/example.mystery"]["value_type"] == "unknown"
    calls = orgpolicy.organizations.return_value.constraints.return_value.list.call_args_list
    assert calls == [mock.call(parent=ORG), mock.call(parent=ORG, pageToken="c1")]
    # records satisfy the knowledge-base value_type requirement
    snap = GcpSnapshot.from_dict({"captured_at": "2026-07-19T12:00:00Z",
                                  "constraints": constraints})
    assert snap.constraint("constraints/compute.vmExternalIpAccess")["value_type"] == "list"


def test_fetch_constraints_rejects_unknown_parent_shape():
    with pytest.raises(ValueError):
        fetch_constraints(mock.Mock(), "bananas/1")


# -- Cloud Asset Inventory -------------------------------------------------


def test_fetch_principals_dedupes_members_across_bindings():
    asset = _asset_mock()
    principals = fetch_principals(asset, SCOPE)
    assert principals == frozenset({
        "user:alice@acme.example",
        "serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com",
        "group:data-eng@acme.example"})
    assert asset.v1.return_value.searchAllIamPolicies.call_args_list == [
        mock.call(scope=SCOPE), mock.call(scope=SCOPE, pageToken="s1")]


def test_fetch_asset_types_lists_resource_inventory():
    asset = _asset_mock()
    types = fetch_asset_types(asset, SCOPE)
    assert types == frozenset({"compute.googleapis.com/Instance",
                               "storage.googleapis.com/Bucket"})
    asset.assets.return_value.list.assert_called_once_with(
        parent=SCOPE, contentType="RESOURCE")


# -- Terraform provider schema ---------------------------------------------


def test_fetch_resource_types_runs_terraform_and_writes_cache(tmp_path):
    cache = tmp_path / "schema.json"
    calls = []

    def runner(terraform_dir):
        calls.append(terraform_dir)
        return json.dumps(TF_SCHEMA)

    types = fetch_resource_types("/repo/infra", cache_path=cache, runner=runner)
    assert types == frozenset({"google_project_iam_binding",
                               "google_org_policy_policy",
                               "google_project_iam_member"})
    assert calls == ["/repo/infra"]
    assert json.loads(cache.read_text(encoding="utf-8")) == TF_SCHEMA


def test_fetch_resource_types_prefers_cache_over_live_run(tmp_path):
    cache = tmp_path / "schema.json"
    cache.write_text(json.dumps(TF_SCHEMA), encoding="utf-8")

    def runner(terraform_dir):
        raise AssertionError("a cache hit must not shell out to terraform")

    types = fetch_resource_types(cache_path=cache, runner=runner)
    assert "google_project_iam_binding" in types


def test_fetch_resource_types_rejects_corrupt_cache(tmp_path):
    cache = tmp_path / "schema.json"
    cache.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        fetch_resource_types(cache_path=cache)


def test_run_terraform_schema_surfaces_failure():
    proc = mock.Mock(returncode=1, stdout="", stderr="No configuration files\n")
    with mock.patch.object(fetch.subprocess, "run", return_value=proc) as run:
        with pytest.raises(RuntimeError, match="No configuration files"):
            fetch_resource_types("/repo/infra")
    assert run.call_args.args[0] == ["terraform", "providers", "schema", "-json"]
    assert run.call_args.kwargs["cwd"] == "/repo/infra"


def test_run_terraform_schema_reports_missing_binary():
    with mock.patch.object(fetch.subprocess, "run",
                           side_effect=FileNotFoundError("terraform")):
        with pytest.raises(RuntimeError, match="terraform"):
            fetch_resource_types()


# -- capture orchestration -------------------------------------------------


def test_capture_snapshot_end_to_end_round_trips(tmp_path):
    out = tmp_path / "snapshot.json"

    def runner(terraform_dir):
        return json.dumps(TF_SCHEMA)

    snap = capture_snapshot(
        iam=_iam_mock(), orgpolicy=_orgpolicy_mock(), asset=_asset_mock(),
        custom_role_parents=(ORG,), permission_resources=(RESOURCE,),
        orgpolicy_parent=ORG, asset_scope=SCOPE,
        terraform_dir="/repo/infra", schema_cache=tmp_path / "tf-schema.json",
        terraform_runner=runner,
        captured_at="2026-07-19T12:00:00Z", out_path=out)

    assert snap.captured_at == "2026-07-19T12:00:00Z"
    assert snap.captured_categories() == ("roles", "permissions", "principals",
                                          "constraints", "resource_types")
    assert snap.role_exists("roles/bigquery.dataViewer") is True
    assert snap.role_exists(f"{ORG}/roles/ciDeployer") is True
    assert snap.permission_exists("storage.objects.list") is True
    assert snap.principal_exists("user:alice@acme.example") is True
    assert snap.constraint("constraints/compute.vmExternalIpAccess")["value_type"] == "list"
    # resource_types is the terraform provider vocabulary alone — a CAI
    # asset-type name is provably absent from it, never a member
    assert snap.resource_type_exists("google_project_iam_binding") is True
    assert snap.resource_type_exists("compute.googleapis.com/Instance") is False
    # the written snapshot loads back identical
    assert GcpSnapshot.load(out) == snap


def test_capture_snapshot_leaves_unrequested_categories_unknown():
    snap = capture_snapshot(iam=_iam_mock(), captured_at="2026-07-19T12:00:00Z")
    assert snap.captured_categories() == ("roles",)
    assert snap.role_exists("roles/viewer") is True
    assert snap.principal_exists("user:alice@acme.example") is UNKNOWN
    assert snap.constraint("constraints/compute.vmExternalIpAccess") is UNKNOWN
    assert snap.resource_type_exists("compute.googleapis.com/Instance") is UNKNOWN
    # no explicit permission enumeration was requested: permissions are known
    # via captured roles, UNKNOWN beyond them — never a false absence
    assert snap.permission_exists("resourcemanager.projects.get") is True
    assert snap.permission_exists("bigquery.jobs.imagine") is UNKNOWN


def test_capture_snapshot_defaults_to_a_fresh_captured_at():
    snap = capture_snapshot(iam=_iam_mock())
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", snap.captured_at)


def test_capture_snapshot_cai_only_leaves_resource_types_uncaptured():
    # CAI feeds principals only. Its asset types are not terraform resource
    # types, so resource_types must stay uncaptured (UNKNOWN, → 'unverified')
    # rather than enumerated with the wrong vocabulary — a captured-but-wrong
    # category would let ground_existence refute real names.
    snap = capture_snapshot(asset=_asset_mock(), asset_scope=SCOPE,
                            captured_at="2026-07-19T12:00:00Z")
    assert snap.captured_categories() == ("principals",)
    assert snap.principal_exists("user:alice@acme.example") is True
    assert snap.resource_type_exists("google_project_iam_binding") is UNKNOWN
    assert snap.resource_type_exists("compute.googleapis.com/Instance") is UNKNOWN


def test_capture_snapshot_tf_schema_only_captures_resource_types_alone():
    # The dual: a terraform-schema-only capture enumerates the provider
    # vocabulary and nothing else — principals must not be marked captured.
    snap = capture_snapshot(terraform_runner=lambda d: json.dumps(TF_SCHEMA),
                            captured_at="2026-07-19T12:00:00Z")
    assert snap.captured_categories() == ("resource_types",)
    assert snap.resource_type_exists("google_project_iam_binding") is True
    assert snap.principal_exists("user:alice@acme.example") is UNKNOWN


def test_capture_snapshot_no_longer_accepts_a_cai_resource_inventory():
    # asset_parent used to union CAI asset types into resource_types; the
    # parameter is gone so the polluting path cannot be resurrected quietly.
    with pytest.raises(TypeError):
        capture_snapshot(asset=_asset_mock(), asset_scope=SCOPE,
                         asset_parent=SCOPE)


def test_capture_snapshot_rejects_halfway_configuration():
    with pytest.raises(ValueError):
        capture_snapshot(orgpolicy=mock.Mock())          # client without parent
    with pytest.raises(ValueError):
        capture_snapshot(orgpolicy_parent=ORG)           # parent without client
    with pytest.raises(ValueError):
        capture_snapshot(asset=mock.Mock())              # client without scope
    with pytest.raises(ValueError):
        capture_snapshot(asset_scope=SCOPE)              # scope without client
    with pytest.raises(ValueError):
        capture_snapshot(permission_resources=(RESOURCE,))  # enumeration without client
