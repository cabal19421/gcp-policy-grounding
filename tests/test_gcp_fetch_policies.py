"""Live-fetch tests for the policy-surface fetchers — hierarchical firewall
policies, Cloud Armor, VPC Service Controls (perimeters, access levels, the
supported-service vocabulary) and the estate half of Org Policy — mirroring the
mocked, offline, SDK-free style of ``tests/test_gcp_fetch.py`` and
``tests/test_gcp_fetch_network.py``.

No network, no credentials, no GCP SDK: every fetcher takes a discovery-shaped
``client`` double, so the whole suite runs against ``unittest.mock`` objects and
the absence of ``googleapiclient`` from ``sys.modules`` after a run is itself the
proof that ``fetch.py`` touches no SDK.
"""

import sys
from unittest import mock

import pytest

from gcp_grounding.fetch import (
    capture_snapshot,
    fetch_access_levels,
    fetch_firewall_policies,
    fetch_org_policies,
    fetch_perimeters,
    fetch_restricted_services,
    fetch_security_policies,
)
from gcp_grounding.knowledge import GcpSnapshot

PROJECT = "acme-prod"
ACCESS_POLICY = "accessPolicies/987"


def _request(payload):
    """A discovery-style request object: .execute() returns the page."""
    request = mock.Mock(name="request")
    request.execute.return_value = payload
    return request


# -- hierarchical firewall policies: the list-then-get two-step ------------


def _firewall_policy_compute():
    """A Compute client wired for a paginated ``firewallPolicies.list`` followed
    by one ``firewallPolicies.get`` per policy."""
    compute = mock.Mock(name="compute")
    fp = compute.firewallPolicies.return_value
    # list enumerates lightweight summaries carrying only the get identifier,
    # across two pages.
    fp.list.side_effect = [
        _request({"items": [{"name": "gen-id-1"}], "nextPageToken": "p1"}),
        _request({"items": [{"name": "gen-id-2"}]}),
    ]
    # get returns the full document with rules + associations.
    fp.get.side_effect = [
        _request({
            "name": "gen-id-1", "shortName": "pol-a", "parent": "organizations/1",
            "associations": [
                {"attachmentTarget": "organizations/1"},
                # a resource-manager URL still normalizes to the folder node
                {"attachmentTarget":
                 "//cloudresourcemanager.googleapis.com/folders/2"},
            ],
            "rules": [
                {"priority": 100, "action": "deny", "direction": "INGRESS",
                 "disabled": False,
                 "match": {"srcIpRanges": ["0.0.0.0/0"], "destIpRanges": [],
                           "layer4Configs": [{"ipProtocol": "tcp",
                                              "ports": ["3389"]}]},
                 "targetResources": ["vpc-main"], "targetServiceAccounts": [],
                 "targetSecureTags": [{"name": "web"}]},
                {"priority": 500, "action": "goto_next", "direction": "INGRESS",
                 "disabled": False,
                 "match": {"srcIpRanges": ["10.0.0.0/8"], "destIpRanges": [],
                           "layer4Configs": []},
                 "targetResources": [], "targetServiceAccounts": [],
                 "targetSecureTags": []},
            ],
        }),
        _request({
            "name": "gen-id-2", "shortName": "pol-b", "parent": "folders/2",
            "associations": [{"attachmentTarget": "folders/2"}],
            "rules": [],
        }),
    ]
    return compute


def test_fetch_firewall_policies_is_a_list_plus_get_two_step():
    compute = _firewall_policy_compute()
    policies = fetch_firewall_policies(compute, "1")
    # keys are the full hierarchical names composed from parent + shortName
    assert set(policies) == {
        "organizations/1/locations/global/firewallPolicies/pol-a",
        "folders/2/locations/global/firewallPolicies/pol-b"}
    fp = compute.firewallPolicies.return_value
    # list paginated with parentId; get called once per enumerated policy
    assert fp.list.call_args_list == [
        mock.call(parentId="1"), mock.call(parentId="1", pageToken="p1")]
    assert fp.get.call_args_list == [
        mock.call(firewallPolicy="gen-id-1"), mock.call(firewallPolicy="gen-id-2")]


def test_fetch_firewall_policies_goto_next_and_associations_normalize():
    policies = fetch_firewall_policies(_firewall_policy_compute(), "1")
    pol_a = policies["organizations/1/locations/global/firewallPolicies/pol-a"]
    # associations normalize to hierarchy node names, order preserved
    assert pol_a["attachments"] == ["organizations/1", "folders/2"]
    # goto_next survives normalization verbatim (it is an action value)
    assert [r["action"] for r in pol_a["rules"]] == ["deny", "goto_next"]
    # the match block is snake_cased into the estate schema
    assert pol_a["rules"][0]["match"] == {
        "src_ip_ranges": ["0.0.0.0/0"], "dest_ip_ranges": [],
        "layer4": [{"protocol": "tcp", "ports": ["3389"]}]}
    assert pol_a["rules"][0]["target_resources"] == ["vpc-main"]
    assert pol_a["rules"][0]["target_secure_tags"] == ["web"]


# -- Cloud Armor -----------------------------------------------------------


def _armor_compute():
    compute = mock.Mock(name="compute")
    compute.securityPolicies.return_value.list.side_effect = [
        _request({"items": [
            {"name": "edge", "type": "CLOUD_ARMOR_EDGE", "rules": [
                # a match.config.srcIpRanges rule
                {"priority": 1000, "action": "deny(403)", "preview": False,
                 "match": {"config": {"srcIpRanges": ["1.2.3.0/24"]},
                           "versionedExpr": "SRC_IPS_V1"}},
                # a match.expr.expression rule
                {"priority": 2000, "action": "deny(403)", "preview": True,
                 "match": {"expr": {"expression": "origin.region_code == 'CN'"}}},
                # the default catch-all at the max priority
                {"priority": 2147483647, "action": "allow",
                 "match": {"config": {"srcIpRanges": ["*"]},
                           "versionedExpr": "SRC_IPS_V1"}},
            ]},
        ]}),
    ]
    return compute


def test_fetch_security_policies_normalizes_config_and_expr_rules():
    policies = fetch_security_policies(_armor_compute(), PROJECT)
    key = "projects/acme-prod/global/securityPolicies/edge"
    assert set(policies) == {key}
    record = policies[key]
    assert record["type"] == "CLOUD_ARMOR_EDGE"
    rules = record["rules"]
    # a config rule → src_ip_ranges + versioned_expr; expr stays None
    assert rules[0]["match"] == {
        "src_ip_ranges": ["1.2.3.0/24"], "versioned_expr": "SRC_IPS_V1",
        "expr": None}
    # an expr rule → the CEL expression string; no config, no versioned_expr
    assert rules[1]["match"] == {
        "src_ip_ranges": [], "versioned_expr": None,
        "expr": "origin.region_code == 'CN'"}
    assert rules[1]["preview"] is True
    # the default rule at 2147483647 is present
    assert any(r["priority"] == 2147483647 for r in rules)


# -- VPC Service Controls: perimeters, access levels, supported services ----


def _acm_mock():
    acm = mock.Mock(name="acm")
    acm.accessPolicies.return_value.servicePerimeters.return_value.list.side_effect = [
        _request({"servicePerimeters": [
            {"name": "accessPolicies/987/servicePerimeters/prod",
             "perimeterType": "PERIMETER_TYPE_REGULAR",
             "useExplicitDryRunSpec": True,
             "status": {  # ENFORCED config
                 "resources": ["projects/111"],
                 "restrictedServices": ["storage.googleapis.com"],
                 "accessLevels": ["accessPolicies/987/accessLevels/trusted"],
                 "ingressPolicies": [], "egressPolicies": []},
             "spec": {  # DRY-RUN config — strictly separate, not enforcement
                 "resources": ["projects/111", "projects/222"],
                 "restrictedServices": ["storage.googleapis.com",
                                        "bigquery.googleapis.com"],
                 "accessLevels": [], "ingressPolicies": [], "egressPolicies": []}},
        ]}),
    ]
    acm.accessPolicies.return_value.accessLevels.return_value.list.side_effect = [
        _request({"accessLevels": [
            {"name": "accessPolicies/987/accessLevels/trusted"}],
            "nextPageToken": "al1"}),
        _request({"accessLevels": [
            {"name": "accessPolicies/987/accessLevels/corp"}]}),
    ]
    acm.services.return_value.list.side_effect = [
        _request({"services": [
            {"name": "storage.googleapis.com"},
            {"name": "bigquery.googleapis.com"}]}),
    ]
    return acm


def test_fetch_perimeters_keeps_status_and_spec_distinct():
    acm = _acm_mock()
    perimeters = fetch_perimeters(acm, ACCESS_POLICY)
    per = perimeters["accessPolicies/987/servicePerimeters/prod"]
    assert per["perimeter_type"] == "PERIMETER_TYPE_REGULAR"
    # useExplicitDryRunSpec → use_explicit_dry_run_spec
    assert per["use_explicit_dry_run_spec"] is True
    # camelCase config fields normalize to snake_case
    assert per["status"]["restricted_services"] == ["storage.googleapis.com"]
    assert per["status"]["access_levels"] == [
        "accessPolicies/987/accessLevels/trusted"]
    # a dry-run spec is NOT enforcement: status and spec stay distinct, unmerged
    assert per["spec"]["restricted_services"] == [
        "storage.googleapis.com", "bigquery.googleapis.com"]
    assert per["status"] != per["spec"]
    assert acm.accessPolicies.return_value.servicePerimeters.return_value \
        .list.call_args_list == [mock.call(parent=ACCESS_POLICY)]


def test_fetch_perimeters_null_spec_stays_null():
    acm = mock.Mock(name="acm")
    acm.accessPolicies.return_value.servicePerimeters.return_value.list.side_effect = [
        _request({"servicePerimeters": [
            {"name": "accessPolicies/987/servicePerimeters/bare",
             "perimeterType": "PERIMETER_TYPE_REGULAR",
             "status": {"resources": [], "restrictedServices": []}}]}),
    ]
    per = fetch_perimeters(acm, ACCESS_POLICY)[
        "accessPolicies/987/servicePerimeters/bare"]
    # no dry-run spec captured → null spec, not an empty enforced config
    assert per["spec"] is None
    assert per["use_explicit_dry_run_spec"] is False


def test_fetch_access_levels_stores_full_names_and_paginates():
    levels = fetch_access_levels(_acm_mock(), ACCESS_POLICY)
    assert levels == frozenset({
        "accessPolicies/987/accessLevels/trusted",
        "accessPolicies/987/accessLevels/corp"})


def test_fetch_restricted_services_is_the_supported_vocabulary():
    services = fetch_restricted_services(_acm_mock())
    assert services == frozenset({
        "storage.googleapis.com", "bigquery.googleapis.com"})


# -- Org Policy estate: the effective set-policies -------------------------


def _orgpolicy_mock():
    """An Org Policy v2 client with a distinct accessor per node type."""
    op = mock.Mock(name="orgpolicy")
    op.organizations.return_value.policies.return_value.list.side_effect = [
        _request({"policies": [
            {"name": "organizations/1/policies/compute.requireShieldedVm",
             "spec": {"rules": [{"enforce": True}]}},
            {"name": "organizations/1/policies/iam.allowedPolicyMemberDomains",
             "spec": {"inheritFromParent": True,
                      "rules": [{"values": {"allowedValues": ["C0abcd"]}}]}},
            # a name with no policies/<id> segment is skipped, not keyed
            {"name": "organizations/1/somethingElse"},
        ]}),
    ]
    op.projects.return_value.policies.return_value.list.side_effect = [
        _request({"policies": [
            {"name": "projects/acme-prod/policies/compute.vmExternalIpAccess",
             "spec": {"reset": True, "rules": [{"denyAll": True}]}},
        ]}),
    ]
    return op


def test_fetch_org_policies_composite_keys_and_field_mapping():
    op = _orgpolicy_mock()
    policies = fetch_org_policies(op, ("organizations/1", "projects/acme-prod"))
    # the unparseable name is skipped
    assert set(policies) == {
        "organizations/1|constraints/compute.requireShieldedVm",
        "organizations/1|constraints/iam.allowedPolicyMemberDomains",
        "projects/acme-prod|constraints/compute.vmExternalIpAccess"}
    # each composite key's halves match the record's node and constraint
    for key, record in policies.items():
        node_half, constraint_half = key.split("|")
        assert record["node"] == node_half
        assert record["constraint"] == constraint_half
    # spec.rules[].values.allowedValues → allowed_values
    iam_rec = policies["organizations/1|constraints/iam.allowedPolicyMemberDomains"]
    assert iam_rec["rules"][0]["allowed_values"] == ["C0abcd"]
    # spec.inheritFromParent → inherit_from_parent
    assert iam_rec["inherit_from_parent"] is True
    # spec.reset → reset; denyAll → deny_all
    ext_rec = policies["projects/acme-prod|constraints/compute.vmExternalIpAccess"]
    assert ext_rec["reset"] is True
    assert ext_rec["rules"][0]["deny_all"] is True
    # the accessor is probed per node type (organizations vs projects)
    op.organizations.return_value.policies.return_value.list.assert_called_once_with(
        parent="organizations/1")
    op.projects.return_value.policies.return_value.list.assert_called_once_with(
        parent="projects/acme-prod")


def test_fetch_org_policies_raises_on_duplicate_composite_key():
    op = mock.Mock(name="orgpolicy")
    # the same node named twice, each returning the same constraint → a
    # composite-key collision that must raise rather than overwrite
    op.organizations.return_value.policies.return_value.list.side_effect = [
        _request({"policies": [
            {"name": "organizations/1/policies/compute.requireShieldedVm",
             "spec": {"rules": [{"enforce": True}]}}]}),
        _request({"policies": [
            {"name": "organizations/1/policies/compute.requireShieldedVm",
             "spec": {"rules": [{"enforce": False}]}}]}),
    ]
    with pytest.raises(ValueError):
        fetch_org_policies(op, ("organizations/1", "organizations/1"))


# -- every produced record loads through GcpSnapshot.from_dict -------------


def test_every_produced_record_loads_through_from_dict():
    snap = GcpSnapshot.from_dict({
        "captured_at": "2026-08-02T00:00:00Z",
        "hierarchical_firewall_policies":
            fetch_firewall_policies(_firewall_policy_compute(), "1"),
        "cloud_armor_policies": fetch_security_policies(_armor_compute(), PROJECT),
        "vpc_sc_perimeters": fetch_perimeters(_acm_mock(), ACCESS_POLICY),
        "access_levels": sorted(fetch_access_levels(_acm_mock(), ACCESS_POLICY)),
        "restricted_services": sorted(fetch_restricted_services(_acm_mock())),
        "org_policies": fetch_org_policies(
            _orgpolicy_mock(), ("organizations/1", "projects/acme-prod")),
    })
    # the record tables round-trip and the accessors read them back
    assert snap.hierarchical_firewall_policy(
        "organizations/1/locations/global/firewallPolicies/pol-a"
    )["rules"][1]["action"] == "goto_next"
    assert snap.cloud_armor_policy(
        "projects/acme-prod/global/securityPolicies/edge") is not None
    assert snap.vpc_sc_perimeter(
        "accessPolicies/987/servicePerimeters/prod")["spec"] is not None
    assert snap.access_level_exists(
        "accessPolicies/987/accessLevels/corp") is True
    assert snap.restricted_service_exists("storage.googleapis.com") is True
    assert snap.org_policy(
        "projects/acme-prod", "constraints/compute.vmExternalIpAccess") is not None


# -- capture orchestration & its half-configured guards --------------------


def _full_compute():
    """A Compute client wired for every collection a full policy-surface capture
    touches: the four network categories, plus firewall policies and Cloud
    Armor. All network collections return a single empty page."""
    compute = mock.Mock(name="compute")
    compute.networks.return_value.list.side_effect = [_request({"items": []})]
    compute.subnetworks.return_value.aggregatedList.side_effect = [
        _request({"items": {}})]
    compute.firewalls.return_value.list.side_effect = [_request({"items": []})]
    compute.instances.return_value.aggregatedList.side_effect = [
        _request({"items": {}})]
    # firewall policies: one policy under the single parent
    fp = compute.firewallPolicies.return_value
    fp.list.side_effect = [_request({"items": [{"name": "gen-id-1"}]})]
    fp.get.side_effect = [_request({
        "name": "gen-id-1", "shortName": "pol-a", "parent": "organizations/1",
        "associations": [{"attachmentTarget": "organizations/1"}],
        "rules": [{"priority": 100, "action": "deny", "direction": "INGRESS",
                   "disabled": False,
                   "match": {"srcIpRanges": ["0.0.0.0/0"], "destIpRanges": [],
                             "layer4Configs": []},
                   "targetResources": [], "targetServiceAccounts": [],
                   "targetSecureTags": []}]})]
    compute.securityPolicies.return_value.list.side_effect = [
        _request({"items": [{"name": "edge", "type": "CLOUD_ARMOR_EDGE",
                             "rules": []}]})]
    return compute


def test_capture_snapshot_full_policy_surface_capture():
    snap = capture_snapshot(
        compute=_full_compute(), compute_project=PROJECT,
        firewall_policy_parents=("1",),
        acm=_acm_mock(), access_policy=ACCESS_POLICY,
        orgpolicy=_orgpolicy_mock(),
        org_policy_nodes=("organizations/1", "projects/acme-prod"),
        captured_at="2026-08-02T00:00:00Z")
    captured = set(snap.captured_categories())
    # the compute-side policy surfaces plus the VPC-SC and org-policy estate
    assert {"hierarchical_firewall_policies", "cloud_armor_policies",
            "vpc_sc_perimeters", "access_levels", "restricted_services",
            "org_policies"} <= captured
    # org_policies is captured even though no orgpolicy_parent (constraints) was
    # requested — the two halves are independent
    assert snap.constraints is None
    assert snap.org_policy(
        "organizations/1", "constraints/compute.requireShieldedVm") is not None


def test_capture_snapshot_acm_without_access_policy_raises():
    with pytest.raises(ValueError):
        capture_snapshot(acm=_acm_mock())


def test_capture_snapshot_access_policy_without_acm_raises():
    with pytest.raises(ValueError):
        capture_snapshot(access_policy=ACCESS_POLICY)


def test_capture_snapshot_firewall_policy_parents_without_compute_raises():
    with pytest.raises(ValueError):
        capture_snapshot(firewall_policy_parents=("1",))


def test_capture_snapshot_org_policy_nodes_without_orgpolicy_raises():
    with pytest.raises(ValueError):
        capture_snapshot(org_policy_nodes=("organizations/1",))


def test_capture_snapshot_duplicate_policy_keys_across_parents_raise():
    compute = _full_compute()
    fp = compute.firewallPolicies.return_value
    # two parents each yielding a policy that resolves to the SAME full name
    fp.list.side_effect = [
        _request({"items": [{"name": "gen-a"}]}),
        _request({"items": [{"name": "gen-b"}]}),
    ]
    fp.get.side_effect = [
        _request({"name": "gen-a", "shortName": "dup",
                  "parent": "organizations/9", "associations": [], "rules": []}),
        _request({"name": "gen-b", "shortName": "dup",
                  "parent": "organizations/9", "associations": [], "rules": []}),
    ]
    with pytest.raises(ValueError):
        capture_snapshot(compute=compute, compute_project=PROJECT,
                         firewall_policy_parents=("9", "9"),
                         captured_at="2026-08-02T00:00:00Z")


# -- SDK-free, network-free proof ------------------------------------------


def test_run_touches_no_gcp_sdk():
    capture_snapshot(
        compute=_full_compute(), compute_project=PROJECT,
        firewall_policy_parents=("1",),
        acm=_acm_mock(), access_policy=ACCESS_POLICY,
        orgpolicy=_orgpolicy_mock(), org_policy_nodes=("organizations/1",),
        captured_at="2026-08-02T00:00:00Z")
    assert "gcp_grounding.fetch" in sys.modules
    assert "googleapiclient" not in sys.modules
