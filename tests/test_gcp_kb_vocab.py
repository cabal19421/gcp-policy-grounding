"""Tests for the six new flat vocabulary categories (networks, subnetworks,
network_tags, service_accounts, access_levels, restricted_services) added to
:class:`GcpSnapshot`, mirroring the roles/permissions/principals pattern.

The load-bearing invariant is the same UNKNOWN-vs-absent distinction the older
categories carry, plus one exception: ``network_tags`` is presence-only, so its
lookup answers True or UNKNOWN but NEVER False (there is no GCP API that
enumerates every tag, so a miss can never prove absence)."""

from pathlib import Path

import pytest

from gcp_grounding.knowledge import UNKNOWN, GcpSnapshot

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
SNAPSHOT_PATH = FIXTURES / "snapshot.json"

# Canonical value forms per the design's Context section; extractors normalize
# to exactly these.
ALL_SIX = {
    "networks": ["projects/acme-prod/global/networks/vpc-main"],
    "subnetworks": ["projects/acme-prod/regions/us-central1/subnetworks/subnet-a"],
    "network_tags": ["bastion", "web"],
    "service_accounts": ["ci-deployer@acme-prod.iam.gserviceaccount.com"],
    "access_levels": ["accessPolicies/123/accessLevels/trusted"],
    "restricted_services": ["storage.googleapis.com"],
}

# The five ordinary lookups (network_tag_exists is the presence-only exception,
# tested on its own). Each: (method, present_name, absent_name).
ORDINARY = [
    ("network_exists", "projects/acme-prod/global/networks/vpc-main",
     "projects/acme-prod/global/networks/ghost"),
    ("subnetwork_exists", "projects/acme-prod/regions/us-central1/subnetworks/subnet-a",
     "projects/acme-prod/regions/us-central1/subnetworks/ghost"),
    ("service_account_exists", "ci-deployer@acme-prod.iam.gserviceaccount.com",
     "ghost@acme-prod.iam.gserviceaccount.com"),
    ("access_level_exists", "accessPolicies/123/accessLevels/trusted",
     "accessPolicies/123/accessLevels/ghost"),
    ("restricted_service_exists", "storage.googleapis.com",
     "ghost.googleapis.com"),
]


def _all_six_snapshot() -> GcpSnapshot:
    return GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z", **ALL_SIX})


# -- round-trip -----------------------------------------------------------


def test_round_trip_exact_with_all_six_captured():
    snap = _all_six_snapshot()
    clone = GcpSnapshot.from_dict(snap.to_dict())
    assert clone == snap
    assert clone.to_dict() == snap.to_dict()


def test_round_trip_exact_with_none_captured():
    snap = GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z"})
    clone = GcpSnapshot.from_dict(snap.to_dict())
    assert clone == snap
    assert clone.to_dict() == snap.to_dict()
    # None of the six leak into the serialized form when uncaptured.
    for key in ALL_SIX:
        assert key not in snap.to_dict()


# -- ordinary True/False/UNKNOWN lookups ----------------------------------


@pytest.mark.parametrize("method, present, absent", ORDINARY)
def test_ordinary_lookup_true_and_false_when_captured(method, present, absent):
    snap = _all_six_snapshot()
    assert getattr(snap, method)(present) is True
    assert getattr(snap, method)(absent) is False


@pytest.mark.parametrize("method, present, absent", ORDINARY)
def test_ordinary_lookup_unknown_when_not_captured(method, present, absent):
    snap = GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z"})
    assert getattr(snap, method)(present) is UNKNOWN


# -- network_tags: the presence-only asymmetry ----------------------------


def test_network_tag_exists_true_when_present():
    snap = _all_six_snapshot()
    assert snap.network_tag_exists("web") is True


def test_network_tag_miss_on_captured_vocab_is_unknown_never_false():
    # Pinned so a future refactor cannot quietly make it symmetric: even with a
    # captured network_tags vocabulary, a miss is UNKNOWN, never False.
    snap = _all_six_snapshot()
    assert snap.network_tag_exists("nope") is UNKNOWN
    assert snap.network_tag_exists("nope") is not False


def test_network_tag_exists_unknown_when_not_captured():
    snap = GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z"})
    assert snap.network_tag_exists("web") is UNKNOWN


# -- anti-footgun: UNKNOWN refuses truthiness -----------------------------


def test_uncaptured_lookup_refuses_truthiness():
    snap = GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z"})
    with pytest.raises(TypeError):
        bool(snap.network_exists("x"))


# -- captured_categories ordering -----------------------------------------


def test_captured_categories_lists_new_names_in_category_order():
    snap = _all_six_snapshot()
    assert snap.captured_categories() == (
        "networks", "subnetworks", "network_tags", "service_accounts",
        "access_levels", "restricted_services",
    )


def test_captured_categories_omits_uncaptured_new_names():
    snap = GcpSnapshot.from_dict({
        "captured_at": "2026-07-18T09:30:00Z",
        "networks": ["projects/acme-prod/global/networks/vpc-main"],
        "restricted_services": ["storage.googleapis.com"],
    })
    # Only the two present, in _CATEGORIES order (networks before
    # restricted_services), nothing between them.
    assert snap.captured_categories() == ("networks", "restricted_services")


# -- entry validation -----------------------------------------------------


@pytest.mark.parametrize("category", list(ALL_SIX))
def test_non_string_entry_raises_value_error_naming_category(category):
    with pytest.raises(ValueError, match=category):
        GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z", category: [123]})


@pytest.mark.parametrize("category", list(ALL_SIX))
def test_empty_string_entry_raises_value_error_naming_category(category):
    with pytest.raises(ValueError, match=category):
        GcpSnapshot.from_dict({"captured_at": "2026-07-18T09:30:00Z", category: [""]})


# -- existing fixture is undisturbed --------------------------------------


def test_existing_fixture_still_loads_with_exactly_its_original_five():
    snap = GcpSnapshot.load(SNAPSHOT_PATH)
    assert snap.captured_categories() == (
        "roles", "permissions", "principals", "constraints", "resource_types",
    )
    # The six new categories were never captured → every lookup abstains.
    assert snap.network_exists("projects/acme-prod/global/networks/vpc-main") is UNKNOWN
    assert snap.network_tag_exists("web") is UNKNOWN
