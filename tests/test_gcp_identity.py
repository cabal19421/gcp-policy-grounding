"""Tests for :mod:`gcp_grounding.identity` — THE canonical estate key.

With ONE canonicaliser there is no second implementation to cross-check
against, so the correctness burden lands here. Two properties carry it:

1. **Idempotence over the committed estate.** Every stored key in
   ``tests/fixtures/gcp/estate_snapshot.json`` — every record-table key and
   every flat-category name — canonicalises to ITSELF, unchanged. A
   canonicaliser that is not idempotent on its own output matches on the first
   hop and misses on the second, and no per-domain example catches that.
2. **The two historically broken cases, asserted from the fixture's own keys.**
   The ``iam_bindings`` node spelling and the hierarchical-firewall
   ``short_name``: the first must converge, the second must REFUSE rather than
   guess.

The failure this module exists to prevent is not an exception. A key that
disagrees never matches, the miss reads as absent, and absent against a
complete view is reported as a confident "new resource" about a resource that
certainly exists.
"""

import dataclasses
import json
from pathlib import Path

import pytest

from gcp_grounding import facts
from gcp_grounding.identity import (
    SPECS,
    AmbiguousKey,
    CategorySpec,
    alias_map,
    canonical_key,
    key_or_unresolved,
    normalize_self_link,
)
from gcp_grounding.knowledge import GcpSnapshot

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
ESTATE_PATH = FIXTURES / "estate_snapshot.json"

ESTATE = json.loads(ESTATE_PATH.read_text(encoding="utf-8"))
SNAPSHOT = GcpSnapshot.load(ESTATE_PATH)
ALIASES = alias_map(SNAPSHOT)

# The categories a snapshot carries, read from the model itself rather than
# restated: a category added to GcpSnapshot without a key form must fail here.
SNAPSHOT_CATEGORIES = frozenset(
    f.name for f in dataclasses.fields(GcpSnapshot) if f.name != "captured_at")


def _stored_keys() -> list[tuple[str, str]]:
    """(category, stored key) for every key in the committed estate fixture —
    a table's keys and a flat category's names alike."""
    pairs: list[tuple[str, str]] = []
    for category, value in sorted(ESTATE.items()):
        if category == "captured_at":
            continue
        # dict → its keys; list → its names. sorted() yields keys for a dict.
        for key in sorted(value):
            pairs.append((category, key))
    return pairs


STORED_KEYS = _stored_keys()


# -- SPECS covers exactly the snapshot's categories ---------------------------


def test_specs_key_set_is_exactly_the_snapshot_category_set():
    assert set(SPECS) == SNAPSHOT_CATEGORIES
    # …and every spec is a real spec that names its own category.
    for category, spec in SPECS.items():
        assert isinstance(spec, CategorySpec)
        assert spec.category == category
        assert spec.parts and spec.stored_form


def test_every_fixture_category_has_a_spec():
    assert set(ESTATE) - {"captured_at"} <= set(SPECS)


# -- property 1: idempotence over every stored key ----------------------------


@pytest.mark.parametrize("category,key", STORED_KEYS,
                         ids=[f"{c}:{k}" for c, k in STORED_KEYS])
def test_stored_key_round_trips_to_itself(category, key):
    once = canonical_key(category, name=key, aliases=ALIASES)
    assert once == key
    # A canonicaliser that is not a fixed point on its own output matches on
    # the first hop and misses on the second.
    assert canonical_key(category, name=once, aliases=ALIASES) == key


@pytest.mark.parametrize("category,key", STORED_KEYS,
                         ids=[f"{c}:{k}" for c, k in STORED_KEYS])
def test_both_facades_agree_on_every_stored_key(category, key):
    assert key_or_unresolved(category, name=key, aliases=ALIASES) == key


def test_the_property_actually_covered_every_category():
    # Guards the property above against a fixture that quietly stops carrying a
    # category: an idempotence sweep over nothing passes.
    assert {c for c, _ in STORED_KEYS} == set(ESTATE) - {"captured_at"}
    assert len(STORED_KEYS) > 50


# -- property 2a: the iam_bindings node spelling converges ---------------------


def test_iam_binding_node_and_full_resource_name_land_on_the_stored_key():
    stored = "//cloudresourcemanager.googleapis.com/projects/acme-prod"
    assert stored in ESTATE["iam_bindings"]
    # The bare hierarchy node terraform writes…
    assert canonical_key("iam_bindings", name="projects/acme-prod",
                         aliases=ALIASES) == stored
    # …and the CRM full resource name the API answers with.
    assert canonical_key("iam_bindings", name=stored, aliases=ALIASES) == stored


def test_iam_binding_project_number_resolves_through_the_alias_map():
    stored = "//cloudresourcemanager.googleapis.com/projects/acme-prod"
    assert canonical_key("iam_bindings", name="projects/123456",
                         aliases=ALIASES) == stored
    # With NO alias map the two spellings stay DISTINCT rather than merging on
    # a guess — a wrong merge attributes one project's policy to another.
    assert canonical_key("iam_bindings", name="projects/123456") == (
        "//cloudresourcemanager.googleapis.com/projects/123456")


def test_iam_binding_refuses_a_resource_whose_service_is_unknown():
    with pytest.raises(AmbiguousKey) as ei:
        canonical_key("iam_bindings", name="projects/acme-prod/buckets/logs")
    assert ei.value.reason == "ambiguous_key"
    # …but an explicit full resource name for another service is kept as-is.
    assert canonical_key(
        "iam_bindings",
        name="//iam.googleapis.com/projects/acme-prod/serviceAccounts/x@y.com"
    ) == "//iam.googleapis.com/projects/acme-prod/serviceAccounts/x@y.com"


# -- property 2b: a terraform short_name is refused, never guessed -------------


def test_hierarchical_short_name_is_refused_by_both_facades():
    stored = "organizations/1/locations/global/firewallPolicies/fp-baseline"
    assert stored in ESTATE["hierarchical_firewall_policies"]

    with pytest.raises(AmbiguousKey) as ei:
        canonical_key("hierarchical_firewall_policies",
                      short_name="fp-baseline", parent="organizations/1")
    assert ei.value.reason == "ambiguous_key"
    assert "short_name" in str(ei.value)

    marker = key_or_unresolved("hierarchical_firewall_policies",
                               short_name="fp-baseline", parent="organizations/1")
    assert facts.is_unresolved(marker)
    assert marker.reason == "ambiguous_key"
    assert marker.path


def test_hierarchical_policy_id_plus_organization_builds_the_stored_key():
    stored = "organizations/1/locations/global/firewallPolicies/fp-baseline"
    assert canonical_key("hierarchical_firewall_policies", name="fp-baseline",
                         parent="organizations/1") == stored


def test_hierarchical_folders_parent_is_refused():
    with pytest.raises(AmbiguousKey, match="folders/"):
        canonical_key("hierarchical_firewall_policies", name="fp-baseline",
                      parent="folders/2")
    # …in the full-path spelling too, not only as a part.
    with pytest.raises(AmbiguousKey, match="folders/"):
        canonical_key(
            "hierarchical_firewall_policies",
            name="folders/2/locations/global/firewallPolicies/fp-baseline")
    marker = key_or_unresolved("hierarchical_firewall_policies",
                               name="fp-baseline", parent="folders/2")
    assert facts.is_unresolved(marker) and marker.reason == "ambiguous_key"


def test_hierarchical_bare_policy_id_alone_is_refused():
    with pytest.raises(AmbiguousKey):
        canonical_key("hierarchical_firewall_policies", name="fp-baseline")


# -- three spellings, one key: firewall rules and Cloud Armor ------------------


def test_three_firewall_spellings_yield_the_identical_key():
    stored = "projects/acme-prod/global/firewalls/allow-iap-ssh"
    assert stored in ESTATE["firewall_rules"]
    self_link = ("https://www.googleapis.com/compute/v1/projects/acme-prod/"
                 "global/firewalls/allow-iap-ssh")
    other_host = ("https://compute.googleapis.com/compute/v1/projects/acme-prod/"
                  "global/firewalls/allow-iap-ssh")
    assert canonical_key("firewall_rules", name=self_link) == stored
    assert canonical_key("firewall_rules", name=other_host) == stored
    assert canonical_key("firewall_rules", name=stored) == stored
    assert canonical_key("firewall_rules", name="allow-iap-ssh",
                         project="acme-prod") == stored


def test_three_cloud_armor_spellings_yield_the_identical_key():
    stored = "projects/acme-prod/global/securityPolicies/edge-waf"
    assert stored in ESTATE["cloud_armor_policies"]
    self_link = ("https://compute.googleapis.com/compute/v1/projects/acme-prod/"
                 "global/securityPolicies/edge-waf")
    assert canonical_key("cloud_armor_policies", name=self_link) == stored
    assert canonical_key("cloud_armor_policies", name=stored) == stored
    assert canonical_key("cloud_armor_policies", name="edge-waf",
                         project="acme-prod") == stored
    # The project may be spelled "projects/<id>" too — a caller never pre-strips.
    assert canonical_key("cloud_armor_policies", name="edge-waf",
                         project="projects/acme-prod") == stored


def test_terraform_address_is_not_the_firewall_identity():
    # Renaming google_compute_firewall.a to .b must not read as a delete plus a
    # create: the rule NAME is the identity, and the address is not a part.
    with pytest.raises(ValueError, match="unknown key part"):
        canonical_key("firewall_rules", name="allow-iap-ssh", project="acme-prod",
                      address="google_compute_firewall.renamed")


# -- a bare name with no project: missing_project, never a guess ---------------


@pytest.mark.parametrize("category", ["firewall_rules", "cloud_armor_policies"])
def test_bare_name_without_a_project_refuses_rather_than_guessing(category):
    with pytest.raises(AmbiguousKey) as ei:
        canonical_key(category, name="edge-thing")
    assert ei.value.reason == "missing_project"

    marker = key_or_unresolved(category, name="edge-thing")
    assert facts.is_unresolved(marker)
    assert marker.reason == "missing_project"
    assert marker.path == f"identity.{category}"
    # The mapper facade never raises for a value it could not resolve…
    assert not isinstance(marker, str)


def test_mapper_facade_marker_path_is_the_callers_when_given():
    marker = key_or_unresolved("firewall_rules", name="x",
                               path="values.name")
    assert marker.path == "values.name"


def test_an_unresolved_part_propagates_its_own_marker():
    # A mapper hands in the marker it already minted; the key build must keep
    # THAT marker, so the path still names where the value came from.
    minted = facts.Unresolved("interpolation", "values.project", "${var.project}")
    marker = key_or_unresolved("firewall_rules", name="allow-x", project=minted)
    assert marker is minted
    with pytest.raises(AmbiguousKey) as ei:
        canonical_key("firewall_rules", name="allow-x", project=minted)
    assert ei.value.reason == "interpolation"


# -- caller errors stay loud on BOTH facades ----------------------------------


@pytest.mark.parametrize("facade", [canonical_key, key_or_unresolved])
def test_unknown_category_and_unknown_part_raise_on_both_facades(facade):
    with pytest.raises(ValueError, match="not an estate category"):
        facade("firewalls", name="x")
    with pytest.raises(ValueError, match="unknown key part"):
        facade("networks", name="x", zone="us-central1-a")


# -- service accounts: prefix stripped, case preserved ------------------------


def test_service_account_prefix_is_stripped_and_case_is_preserved():
    stored = "ci-deployer@acme-prod.iam.gserviceaccount.com"
    assert stored in ESTATE["service_accounts"]
    assert canonical_key("service_accounts",
                         name=f"serviceAccount:{stored}") == stored
    # A GCP email local part is case-sensitive in practice: never case-folded.
    mixed = "CI-Deployer@acme-prod.iam.gserviceaccount.com"
    assert canonical_key("service_accounts",
                         name=f"serviceAccount:{mixed}") == mixed
    assert canonical_key("service_accounts", name=mixed) == mixed


def test_principals_keep_the_prefix_that_service_accounts_strip():
    # The two categories are deliberately different: 'principals' is defined
    # WITH the type prefix, 'service_accounts' without it.
    principal = "serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com"
    assert principal in ESTATE["principals"]
    assert canonical_key("principals", name=principal) == principal


# -- org policies: one composite, joined in one place -------------------------


def test_org_policy_composite_is_built_from_its_two_halves():
    stored = "projects/acme-prod|constraints/compute.disableSerialPortAccess"
    assert stored in ESTATE["org_policies"]
    record = ESTATE["org_policies"][stored]
    assert canonical_key("org_policies", node=record["node"],
                         constraint=record["constraint"], aliases=ALIASES) == stored


def test_org_policy_halves_are_canonicalised_independently():
    stored = "projects/acme-prod|constraints/compute.disableSerialPortAccess"
    # A project NUMBER on the left, a parent-qualified constraint on the right:
    # both halves normalise through their own category's rule.
    assert canonical_key(
        "org_policies", node="projects/123456",
        constraint="organizations/1/constraints/compute.disableSerialPortAccess",
        aliases=ALIASES) == stored


def test_org_policy_refuses_a_malformed_composite_and_double_spelling():
    with pytest.raises(AmbiguousKey, match="single"):
        canonical_key("org_policies", name="projects/acme-prod")
    with pytest.raises(AmbiguousKey, match="never both"):
        canonical_key("org_policies", name="projects/acme-prod|constraints/x",
                      node="projects/acme-prod")


# -- the remaining key forms --------------------------------------------------


def test_network_and_subnetwork_accept_self_link_relative_and_bare_plus_parts():
    net = "projects/acme-prod/global/networks/vpc-main"
    assert canonical_key("networks", name=net) == net
    assert canonical_key(
        "networks",
        name="https://www.googleapis.com/compute/v1/" + net) == net
    assert canonical_key("networks", name="vpc-main", project="acme-prod") == net

    sub = "projects/acme-prod/regions/us-central1/subnetworks/sn-app"
    assert sub in ESTATE["subnetworks"]
    assert canonical_key("subnetworks", name=sub) == sub
    assert canonical_key("subnetworks", name="sn-app", project="acme-prod",
                         region="us-central1") == sub
    # A bare subnetwork name without its region is not a key: names are unique
    # per region, not per project.
    with pytest.raises(AmbiguousKey):
        canonical_key("subnetworks", name="sn-app", project="acme-prod")


def test_access_context_categories_need_their_access_policy():
    level = "accessPolicies/987/accessLevels/trusted_corp"
    perimeter = "accessPolicies/987/servicePerimeters/prod"
    assert canonical_key("access_levels", name="trusted_corp",
                         access_policy="accessPolicies/987") == level
    assert canonical_key("vpc_sc_perimeters", name="prod",
                         access_policy="987") == perimeter
    with pytest.raises(AmbiguousKey):
        canonical_key("access_levels", name="trusted_corp")


def test_role_forms_and_the_refused_bare_role_id():
    assert canonical_key("roles", name="roles/owner") == "roles/owner"
    assert canonical_key("roles", name="ciDeployer",
                         project="acme-prod") == "projects/acme-prod/roles/ciDeployer"
    with pytest.raises(AmbiguousKey):
        canonical_key("roles", name="ciDeployer")


def test_constraint_short_form_is_the_key():
    short = "constraints/compute.vmExternalIpAccess"
    assert short in ESTATE["constraints"]
    assert canonical_key("constraints", name=short) == short
    assert canonical_key("constraints", name="compute.vmExternalIpAccess") == short
    assert canonical_key(
        "constraints",
        name="organizations/1/constraints/compute.vmExternalIpAccess") == short


def test_hierarchy_node_keeps_an_unknown_project_number_distinct():
    assert canonical_key("resource_hierarchy", name="projects/123456",
                         aliases=ALIASES) == "projects/acme-prod"
    # Unknown number: NOT merged onto some project — the two spellings stay two.
    assert canonical_key("resource_hierarchy", name="projects/999",
                         aliases=ALIASES) == "projects/999"
    with pytest.raises(AmbiguousKey):
        canonical_key("resource_hierarchy", name="acme-prod")


# -- normalize_self_link is the one implementation ----------------------------


@pytest.mark.parametrize("spelling", [
    "https://www.googleapis.com/compute/v1/projects/p/global/networks/n",
    "https://compute.googleapis.com/compute/v1/projects/p/global/networks/n",
    "http://www.googleapis.com/compute/v1/projects/p/global/networks/n",
    "//compute.googleapis.com/projects/p/global/networks/n",
    "projects/p/global/networks/n",
    "/projects/p/global/networks/n",
])
def test_normalize_self_link_reduces_every_spelling_to_the_relative_form(spelling):
    assert normalize_self_link(spelling) == "projects/p/global/networks/n"


def test_normalize_self_link_passes_a_bare_name_through_and_is_idempotent():
    assert normalize_self_link("vpc-main") == "vpc-main"
    once = normalize_self_link(
        "https://www.googleapis.com/compute/v1/projects/p/global/networks/n")
    assert normalize_self_link(once) == once
    assert normalize_self_link("  projects/p/global/networks/n  ") == \
        "projects/p/global/networks/n"


def test_normalize_self_link_strips_the_full_resource_name_authority():
    assert normalize_self_link(
        "//cloudresourcemanager.googleapis.com/projects/acme-prod") == \
        "projects/acme-prod"


# -- alias_map ----------------------------------------------------------------


def test_alias_map_resolves_a_project_number_to_its_id():
    assert ALIASES["123456"] == "acme-prod"
    # Organizations and folders carry numbers too and get NO project alias.
    assert "1" not in ALIASES and "2" not in ALIASES


def test_alias_map_is_empty_when_the_hierarchy_table_is_absent():
    bare = GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z"})
    assert bare.resource_hierarchy is None
    assert alias_map(bare) == {}
    # …and for an object that has no such attribute at all.
    assert alias_map(object()) == {}


def test_alias_map_drops_a_number_two_nodes_claim():
    snap = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T09:30:00Z",
        "resource_hierarchy": {
            "projects/one": {"parent": None, "type": "project", "number": "7",
                             "display_name": "One"},
            "projects/two": {"parent": None, "type": "project", "number": "7",
                             "display_name": "Two"},
        },
    })
    # An ambiguous alias resolves NOTHING rather than picking a winner.
    assert alias_map(snap) == {}
    assert canonical_key("resource_hierarchy", name="projects/7",
                         aliases=alias_map(snap)) == "projects/7"
