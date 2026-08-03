"""Live-fetch tests for the Compute-side estate fetchers — networks,
subnetworks, firewall rules, network tags and service accounts — mirroring the
mocked, offline, SDK-free style of ``tests/test_gcp_fetch.py``.

No network, no credentials, no GCP SDK: the fetchers take a discovery-shaped
``client`` double, so the whole suite runs against ``unittest.mock`` objects and
the absence of ``googleapiclient`` from ``sys.modules`` after a run is itself the
proof that ``fetch.py`` touches no SDK.
"""

import sys
from unittest import mock

import pytest

from gcp_grounding.fetch import (
    capture_snapshot,
    fetch_firewall_rules,
    fetch_network_tags,
    fetch_networks,
    fetch_service_accounts,
    fetch_subnetworks,
)
from gcp_grounding.knowledge import GcpSnapshot

PROJECT = "acme-prod"
PREFIX = "https://www.googleapis.com/compute/v1/"


def _request(payload):
    """A discovery-style request object: .execute() returns the page."""
    request = mock.Mock(name="request")
    request.execute.return_value = payload
    return request


def _compute_mock():
    """A discovery-shaped Compute client wired for two-page walks of every
    collection the fetchers touch."""
    compute = mock.Mock(name="compute")

    # networks.list — one normal link, one malformed (skipped), across two pages.
    compute.networks.return_value.list.side_effect = [
        _request({"items": [
            {"selfLink": PREFIX + "projects/acme-prod/global/networks/vpc-main"},
            {"selfLink": "not-a-compute-self-link"},          # malformed → skipped
        ], "nextPageToken": "n1"}),
        _request({"items": [
            {"selfLink": PREFIX + "projects/acme-prod/global/networks/vpc-legacy"},
        ]}),
    ]

    # subnetworks.aggregatedList — a warning-only scope is skipped; two pages.
    compute.subnetworks.return_value.aggregatedList.side_effect = [
        _request({"items": {
            "regions/us-central1": {"subnetworks": [
                {"selfLink": PREFIX +
                 "projects/acme-prod/regions/us-central1/subnetworks/subnet-a"}]},
            "regions/us-east1": {"warning": {
                "code": "NO_RESULTS_ON_PAGE",
                "message": "No results for scope regions/us-east1"}},
        }, "nextPageToken": "sn1"}),
        _request({"items": {
            "regions/europe-west1": {"subnetworks": [
                {"selfLink": PREFIX +
                 "projects/acme-prod/regions/europe-west1/subnetworks/subnet-b"}]},
        }}),
    ]

    # firewalls.list — allow + deny survive; both/neither are skipped; two pages.
    compute.firewalls.return_value.list.side_effect = [
        _request({"items": [
            {"name": "allow-web",
             "network": PREFIX + "projects/acme-prod/global/networks/vpc-main",
             "direction": "INGRESS", "priority": 1000,
             "sourceRanges": ["0.0.0.0/0"], "targetTags": ["web"],
             "allowed": [{"IPProtocol": "tcp", "ports": ["80", "443"]}]},
            {"name": "deny-ssh",
             "network": PREFIX + "projects/acme-prod/global/networks/vpc-main",
             "direction": "INGRESS", "priority": 900,
             "sourceRanges": ["10.0.0.0/8"], "sourceTags": ["bastion"],
             "denied": [{"IPProtocol": "tcp", "ports": ["22"]}]},
        ], "nextPageToken": "f1"}),
        _request({"items": [
            {"name": "both-bad",
             "network": PREFIX + "projects/acme-prod/global/networks/vpc-main",
             "allowed": [{"IPProtocol": "tcp"}],
             "denied": [{"IPProtocol": "udp"}]},         # both → skipped
            {"name": "neither-bad",
             "network": PREFIX + "projects/acme-prod/global/networks/vpc-main",
             "direction": "INGRESS"},                    # neither → skipped
        ]}),
    ]

    # instances.aggregatedList — tags.items feed the use-site vocabulary; a
    # warning-only scope and a tagless instance are both handled; two pages.
    compute.instances.return_value.aggregatedList.side_effect = [
        _request({"items": {
            "zones/us-central1-a": {"instances": [
                {"tags": {"items": ["web", "ssh-allowed"]}}]},
            "zones/us-east1-b": {"warning": {"code": "NO_RESULTS_ON_PAGE"}},
        }, "nextPageToken": "i1"}),
        _request({"items": {
            "zones/europe-west1-b": {"instances": [
                {"tags": {"items": ["db"]}},
                {"name": "no-tags-vm"}]},
        }}),
    ]
    return compute


def _iam_mock():
    iam = mock.Mock(name="iam")
    # capture_snapshot always fetches roles from an iam client; give it an empty
    # (but captured) roles enumeration so the service-account path can be
    # exercised on its own.
    iam.roles.return_value.list.side_effect = [_request({"roles": []})]
    iam.projects.return_value.serviceAccounts.return_value.list.side_effect = [
        _request({"accounts": [
            {"email": "ci-deployer@acme-prod.iam.gserviceaccount.com"}],
            "nextPageToken": "sa1"}),
        _request({"accounts": [
            {"email": "terraform@acme-prod.iam.gserviceaccount.com"}]}),
    ]
    return iam


# -- networks --------------------------------------------------------------


def test_fetch_networks_paginates_normalizes_and_skips_malformed():
    compute = _compute_mock()
    networks = fetch_networks(compute, PROJECT)
    # both prefixes stripped to the canonical form; the junk link is dropped.
    assert networks == frozenset({
        "projects/acme-prod/global/networks/vpc-main",
        "projects/acme-prod/global/networks/vpc-legacy"})
    assert compute.networks.return_value.list.call_args_list == [
        mock.call(project=PROJECT), mock.call(project=PROJECT, pageToken="n1")]


# -- subnetworks -----------------------------------------------------------


def test_fetch_subnetworks_skips_warning_scopes_and_paginates():
    compute = _compute_mock()
    subnetworks = fetch_subnetworks(compute, PROJECT)
    # the warning-only regions/us-east1 scope contributes nothing.
    assert subnetworks == frozenset({
        "projects/acme-prod/regions/us-central1/subnetworks/subnet-a",
        "projects/acme-prod/regions/europe-west1/subnetworks/subnet-b"})
    assert compute.subnetworks.return_value.aggregatedList.call_args_list == [
        mock.call(project=PROJECT), mock.call(project=PROJECT, pageToken="sn1")]


# -- firewall rules --------------------------------------------------------


def test_fetch_firewall_rules_maps_action_and_skips_ambiguous():
    compute = _compute_mock()
    rules = fetch_firewall_rules(compute, PROJECT)
    assert set(rules) == {
        "projects/acme-prod/global/firewalls/allow-web",
        "projects/acme-prod/global/firewalls/deny-ssh"}
    allow = rules["projects/acme-prod/global/firewalls/allow-web"]
    assert allow["action"] == "allow"
    assert allow["network"] == "projects/acme-prod/global/networks/vpc-main"
    assert allow["target_tags"] == ["web"]
    assert allow["layer4"] == [{"protocol": "tcp", "ports": ["80", "443"]}]
    # a rule with `denied` becomes action deny
    deny = rules["projects/acme-prod/global/firewalls/deny-ssh"]
    assert deny["action"] == "deny"
    assert deny["layer4"] == [{"protocol": "tcp", "ports": ["22"]}]
    # both-bad (allowed AND denied) and neither-bad are skipped, not guessed
    assert "projects/acme-prod/global/firewalls/both-bad" not in rules
    assert "projects/acme-prod/global/firewalls/neither-bad" not in rules
    assert compute.firewalls.return_value.list.call_args_list == [
        mock.call(project=PROJECT), mock.call(project=PROJECT, pageToken="f1")]


def test_fetch_firewall_records_load_through_from_dict():
    compute = _compute_mock()
    rules = fetch_firewall_rules(compute, PROJECT)
    snap = GcpSnapshot.from_dict({"captured_at": "2026-07-19T12:00:00Z",
                                  "firewall_rules": rules})
    rec = snap.firewall_rule("projects/acme-prod/global/firewalls/deny-ssh")
    assert rec["action"] == "deny"
    # list-order-semantic fields survive as tuples
    assert snap.firewall_rule(
        "projects/acme-prod/global/firewalls/allow-web")["layer4"][0]["ports"] == (
        "80", "443")


# -- network tags: the use-site union --------------------------------------


def test_fetch_network_tags_unions_firewall_and_instance_tags():
    compute = _compute_mock()
    rules = fetch_firewall_rules(compute, PROJECT)
    tags = fetch_network_tags(compute, PROJECT, firewall_rules=rules)
    # firewall target/source tags (web, bastion) ∪ instance tags (web,
    # ssh-allowed, db); the empty/tagless instance contributes nothing.
    assert tags == frozenset({"web", "bastion", "ssh-allowed", "db"})
    assert compute.instances.return_value.aggregatedList.call_args_list == [
        mock.call(project=PROJECT), mock.call(project=PROJECT, pageToken="i1")]


def test_fetch_network_tags_reuses_passed_firewall_dict():
    # A caller who already fetched firewall rules must not trigger a second
    # firewalls.list pagination.
    compute = _compute_mock()
    passed = {"projects/acme-prod/global/firewalls/x": {
        "target_tags": ["frontend"], "source_tags": ["jump"]}}
    tags = fetch_network_tags(compute, PROJECT, firewall_rules=passed)
    assert {"frontend", "jump"} <= tags
    compute.firewalls.assert_not_called()


# -- service accounts ------------------------------------------------------


def test_fetch_service_accounts_stores_bare_emails_and_paginates():
    iam = _iam_mock()
    accounts = fetch_service_accounts(iam, PROJECT)
    assert accounts == frozenset({
        "ci-deployer@acme-prod.iam.gserviceaccount.com",
        "terraform@acme-prod.iam.gserviceaccount.com"})
    # bare emails, no serviceAccount: prefix
    assert all(not a.startswith("serviceAccount:") for a in accounts)
    assert iam.projects.return_value.serviceAccounts.return_value.list.call_args_list == [
        mock.call(name="projects/acme-prod"),
        mock.call(name="projects/acme-prod", pageToken="sa1")]


# -- capture orchestration -------------------------------------------------


def test_capture_snapshot_compute_needs_a_project():
    with pytest.raises(ValueError):
        capture_snapshot(compute=_compute_mock())            # client without project


def test_capture_snapshot_project_without_compute_client_raises():
    with pytest.raises(ValueError):
        capture_snapshot(compute_project=PROJECT)            # project without client


def test_capture_snapshot_compute_only_leaves_other_categories_none():
    snap = capture_snapshot(compute=_compute_mock(), compute_project=PROJECT,
                            captured_at="2026-07-19T12:00:00Z")
    # only the four compute categories are captured, in _CATEGORIES order
    assert snap.captured_categories() == (
        "networks", "subnetworks", "network_tags", "firewall_rules")
    # every other category stayed None → the KB answers UNKNOWN, never a false
    # absence
    for other in ("roles", "permissions", "principals", "constraints",
                  "resource_types", "service_accounts", "access_levels",
                  "restricted_services"):
        assert getattr(snap, other) is None
    assert snap.network_exists("projects/acme-prod/global/networks/vpc-main") is True
    assert snap.subnetwork_exists(
        "projects/acme-prod/regions/us-central1/subnetworks/subnet-a") is True
    assert snap.network_tag_exists("web") is True
    assert snap.firewall_rule(
        "projects/acme-prod/global/firewalls/deny-ssh")["action"] == "deny"


def test_capture_snapshot_service_accounts_via_iam():
    snap = capture_snapshot(iam=_iam_mock(), service_account_projects=(PROJECT,),
                            captured_at="2026-07-19T12:00:00Z")
    # roles are always fetched from an iam client; service_accounts joins them
    assert "service_accounts" in snap.captured_categories()
    assert snap.service_account_exists(
        "ci-deployer@acme-prod.iam.gserviceaccount.com") is True


def test_capture_snapshot_service_account_projects_needs_iam():
    with pytest.raises(ValueError):
        capture_snapshot(service_account_projects=(PROJECT,))  # no iam client


# -- SDK-free, network-free proof ------------------------------------------


def test_run_touches_no_gcp_sdk():
    # A full compute + iam capture against pure mocks must import no SDK.
    capture_snapshot(compute=_compute_mock(), compute_project=PROJECT,
                     iam=_iam_mock(), service_account_projects=(PROJECT,),
                     captured_at="2026-07-19T12:00:00Z")
    assert "gcp_grounding.fetch" in sys.modules
    assert "googleapiclient" not in sys.modules
