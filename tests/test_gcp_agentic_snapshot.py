"""Agentic estate fixture tests.

Pins the two fixtures the agentic gate suite runs against:

- ``agentic_snapshot.json`` — a deliberately FIVE-category snapshot that
  today's ``GcpSnapshot.from_dict`` loads with no dependency on the domain
  work, and
- ``agentic_estate_overlay.json`` — the partial document carrying only the
  thirteen domain categories, to be merged into the base once those categories
  land.

Paths are derived locally the way every existing module does; this module must
NOT depend on ``tests/conftest.py`` (which lands in a later task).
"""

import json
from pathlib import Path

from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding import reasoner

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
AGENTIC_SNAPSHOT = FIXTURES / "agentic_snapshot.json"
AGENTIC_OVERLAY = FIXTURES / "agentic_estate_overlay.json"

CAPTURED_AT = "2026-07-25T08:00:00Z"

# The escalation-sensitive roles the whole agentic IAM arm keys off.
ESCALATION_ROLES = (
    "roles/owner",
    "roles/editor",
    "roles/viewer",
    "roles/iam.serviceAccountUser",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.securityAdmin",
    "roles/iam.roleAdmin",
    "roles/iam.organizationRoleAdmin",
    "roles/iam.workloadIdentityUser",
    "roles/resourcemanager.organizationAdmin",
    "roles/resourcemanager.folderAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/orgpolicy.policyAdmin",
    "roles/accesscontextmanager.policyAdmin",
    "roles/accesscontextmanager.policyEditor",
    "roles/compute.securityAdmin",
    "roles/compute.networkAdmin",
    "roles/compute.orgFirewallPolicyAdmin",
    "roles/compute.orgSecurityPolicyAdmin",
    "roles/compute.loadBalancerAdmin",
)

# Only acme.example identities and acme-prod service accounts.
PRINCIPALS = (
    "user:alice@acme.example",
    "user:bob@acme.example",
    "user:carol@acme.example",
    "group:data-eng@acme.example",
    "group:platform-sre@acme.example",
    "group:security@acme.example",
    "domain:acme.example",
    "serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com",
    "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com",
    "serviceAccount:terraform@acme-prod.iam.gserviceaccount.com",
    "serviceAccount:app-frontend@acme-prod.iam.gserviceaccount.com",
    "serviceAccount:break-glass@acme-prod.iam.gserviceaccount.com",
)

# The thirteen domain categories the overlay may carry.
THIRTEEN_CATEGORIES = frozenset({
    "networks",
    "subnetworks",
    "network_tags",
    "service_accounts",
    "access_levels",
    "restricted_services",
    "firewall_rules",
    "hierarchical_firewall_policies",
    "cloud_armor_policies",
    "vpc_sc_perimeters",
    "resource_hierarchy",
    "iam_bindings",
    "org_policies",
})


def _snapshot() -> GcpSnapshot:
    return GcpSnapshot.load(AGENTIC_SNAPSHOT)


def _overlay() -> dict:
    return json.loads(AGENTIC_OVERLAY.read_text(encoding="utf-8"))


def _hierarchy_names(resource_hierarchy: dict) -> set:
    """The names sx-reasoner-categories will treat as grounded hierarchy
    nodes: every ``resource_hierarchy`` key PLUS a ``projects/<number>`` alias
    for each project record carrying a non-null ``number``. Computed here from
    the overlay alone, so this check is meaningful before the domain code
    lands."""
    names = set(resource_hierarchy)
    for record in resource_hierarchy.values():
        number = record.get("number")
        if record.get("type") == "project" and number:
            names.add(f"projects/{number}")
    return names


# -- FILE 1: agentic_snapshot.json --------------------------------------------


def test_snapshot_loads_and_captured_at():
    snap = _snapshot()
    assert snap.captured_at == CAPTURED_AT


def test_at_least_forty_roles():
    snap = _snapshot()
    assert len(snap.roles) >= 40


def test_every_escalation_role_present():
    snap = _snapshot()
    for role in ESCALATION_ROLES:
        assert snap.role_exists(role) is True, role


def test_bigquery_reader_is_the_planted_near_miss():
    snap = _snapshot()
    # The canonical hallucination is absent (a hard False, not UNKNOWN) …
    assert snap.role_exists("roles/bigquery.reader") is False
    # … and roles/bigquery.dataViewer is a within-budget near-miss for it.
    # dataViewer sits exactly at the edit-distance budget (7) and TIES
    # roles/bigquery.dataEditor there; dataEditor sorts first alphabetically,
    # so the default top-3 cap would hide dataViewer behind its equidistant
    # sibling even though both are mandated present. Surface the full
    # within-budget near-miss set — dataViewer being in it is the property the
    # block-then-retry loop depends on.
    suggestions = reasoner.suggest(
        "roles/bigquery.reader", snap.roles, limit=len(snap.roles))
    assert "roles/bigquery.dataViewer" in suggestions


def test_principals_present_and_external_absent():
    snap = _snapshot()
    for principal in PRINCIPALS:
        assert snap.principal_exists(principal) is True, principal
    # The external-principal block and the ghost near-miss both depend on the
    # absence of these two — a hard False, since principals were captured.
    assert snap.principal_exists("user:attacker@evil.example") is False
    assert snap.principal_exists(
        "serviceAccount:ghost-runner@acme-prod.iam.gserviceaccount.com") is False


def test_exactly_the_five_categories():
    snap = _snapshot()
    assert snap.captured_categories() == (
        "roles", "permissions", "principals", "constraints", "resource_types")


def test_every_included_permission_is_enumerated():
    snap = _snapshot()
    for name, record in snap.roles.items():
        for perm in record.get("included_permissions", ()):
            assert perm in snap.permissions, (name, perm)


def test_resource_types_are_pure_terraform_vocabulary():
    # No CAI asset types (which carry a "googleapis.com/" host segment) folded
    # in — that would mark the category captured with the wrong vocabulary.
    snap = _snapshot()
    for resource_type in snap.resource_types:
        assert "googleapis.com/" not in resource_type, resource_type


def test_snapshot_round_trips_byte_identically():
    snap = _snapshot()
    committed = AGENTIC_SNAPSHOT.read_text(encoding="utf-8")
    assert json.dumps(snap.to_dict(), indent=2, sort_keys=True) == committed, (
        "to_dict() must serialize byte-identically to the committed JSON via "
        "json.dumps(indent=2, sort_keys=True); a spurious diff means a record "
        "field does not survive the round-trip")


# -- FILE 2: agentic_estate_overlay.json --------------------------------------


def test_overlay_is_a_mapping_of_domain_categories():
    overlay = _overlay()
    assert isinstance(overlay, dict)
    extra = set(overlay) - THIRTEEN_CATEGORIES
    assert not extra, f"overlay carries non-domain keys {sorted(extra)}"


# -- Cross-fixture consistency (merged base + overlay) ------------------------
#
# Asserted here rather than discovered as a mystery block in three downstream
# modules: for the merged document, every projects/<n> a perimeter lists, every
# access level it names, and every restricted service it names must resolve
# against the overlay's own vocabularies. An unresolved value would surface
# downstream as an `ungrounded hierarchy_node` and a spurious exit 2 on a
# BENIGN perimeter case.


def _merged() -> dict:
    base = json.loads(AGENTIC_SNAPSHOT.read_text(encoding="utf-8"))
    overlay = _overlay()
    merged = dict(base)
    merged.update(overlay)
    return merged


def test_perimeter_resources_resolve_through_hierarchy():
    merged = _merged()
    names = _hierarchy_names(merged.get("resource_hierarchy", {}))
    for pname, perimeter in merged.get("vpc_sc_perimeters", {}).items():
        for side in ("status", "spec"):
            block = perimeter.get(side)
            if not block:
                continue
            for resource in block.get("resources", ()):
                if not resource.startswith("projects/"):
                    continue
                assert resource in names, (
                    f"perimeter {pname}.{side} lists {resource!r}, which does "
                    f"not resolve through hierarchy_names() "
                    f"{sorted(names)} — downstream this surfaces as an "
                    f"'ungrounded hierarchy_node' and a spurious exit 2 on a "
                    f"BENIGN perimeter case")


def test_perimeter_access_levels_resolve():
    merged = _merged()
    vocab = set(merged.get("access_levels", ()))
    for pname, perimeter in merged.get("vpc_sc_perimeters", {}).items():
        for side in ("status", "spec"):
            block = perimeter.get(side)
            if not block:
                continue
            for level in block.get("access_levels", ()):
                assert level in vocab, (
                    f"perimeter {pname}.{side} names access level {level!r}, "
                    f"absent from the overlay access_levels vocabulary "
                    f"{sorted(vocab)} — downstream this surfaces as an "
                    f"'ungrounded hierarchy_node'-style miss and a spurious "
                    f"exit 2 on a BENIGN perimeter case")


def test_perimeter_restricted_services_resolve():
    merged = _merged()
    vocab = set(merged.get("restricted_services", ()))
    for pname, perimeter in merged.get("vpc_sc_perimeters", {}).items():
        for side in ("status", "spec"):
            block = perimeter.get(side)
            if not block:
                continue
            for service in block.get("restricted_services", ()):
                assert service in vocab, (
                    f"perimeter {pname}.{side} names restricted service "
                    f"{service!r}, absent from the overlay restricted_services "
                    f"vocabulary {sorted(vocab)} — downstream this surfaces as "
                    f"an 'ungrounded hierarchy_node'-style miss and a spurious "
                    f"exit 2 on a BENIGN perimeter case")
