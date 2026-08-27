"""The two shared estate fixtures every later grounding domain grounds against.

``estate_snapshot.json`` captures ALL NINETEEN snapshot categories with
deliberately realistic content, so no downstream check ever blocks for the
wrong reason (an uncaptured category or an unrepresentable value). Its twin,
``estate_partial_snapshot.json``, is byte-identical EXCEPT the eight record
tables are omitted entirely — the abstention fixture, against which every
ESTATE check must degrade to ``unverified`` rather than fabricate a verdict.

The byte-equality assertion below is the load-bearing one: ``to_dict()`` after
``json.dumps(..., indent=2, sort_keys=True)`` reproduces the committed file
byte-for-byte ONLY because every defaulted field (``priority`` 1000,
``disabled`` False, the six empty firewall list fields, ``reset`` /
``inherit_from_parent`` False on org policies, and the analogous rule-record
defaults) is spelled out explicitly in the file. A record that omitted a
defaulted field would have it re-materialized by ``from_dict`` and re-emitted by
``to_dict``, breaking the round-trip — hence the explicit message.
"""

import json
from pathlib import Path

import pytest

from gcp_grounding.knowledge import UNKNOWN, GcpSnapshot

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
FULL_PATH = FIXTURES / "estate_snapshot.json"
PARTIAL_PATH = FIXTURES / "estate_partial_snapshot.json"

# The nineteen categories the full estate fixture captures: five pre-existing
# vocabularies, six flat vocabularies, eight record tables.
ALL_CATEGORIES = (
    "roles", "permissions", "principals", "constraints", "resource_types",
    "networks", "subnetworks", "network_tags", "service_accounts",
    "access_levels", "restricted_services",
    "firewall_rules", "hierarchical_firewall_policies", "cloud_armor_policies",
    "vpc_sc_perimeters", "resource_hierarchy", "iam_bindings", "org_policies",
    "iam_deny_policies",
)
# The eleven the partial fixture keeps (everything but the eight record tables).
RECORD_TABLES = (
    "firewall_rules", "hierarchical_firewall_policies", "cloud_armor_policies",
    "vpc_sc_perimeters", "resource_hierarchy", "iam_bindings", "org_policies",
    "iam_deny_policies",
)
VOCAB_CATEGORIES = tuple(c for c in ALL_CATEGORIES if c not in RECORD_TABLES)

# Every record-table accessor added in sx-kb-estate-tables, as a
# (method-name, args) pair. On the partial fixture the underlying table was
# never captured, so each MUST answer UNKNOWN — never None, never a real record.
ESTATE_ACCESSORS = (
    ("firewall_rule", ("x",)),
    ("hierarchical_firewall_policy", ("x",)),
    ("cloud_armor_policy", ("x",)),
    ("vpc_sc_perimeter", ("x",)),
    ("hierarchy_node", ("x",)),
    ("iam_binding_set", ("x",)),
    ("org_policy", ("n", "c")),
    ("firewall_rules_for_network", ("net",)),
    ("firewall_policies_attached_to", ("organizations/1",)),
    ("hierarchy_names", ()),
    ("iam_deny_policy", ("x",)),
    ("iam_deny_policies_attached_to", ("projects/x",)),
)


# -- both fixtures load ---------------------------------------------------


def test_full_fixture_loads():
    snap = GcpSnapshot.load(FULL_PATH)
    assert snap.captured_at == "2026-07-18T09:30:00Z"


def test_partial_fixture_loads():
    snap = GcpSnapshot.load(PARTIAL_PATH)
    assert snap.captured_at == "2026-07-18T09:30:00Z"


# -- byte-exact round-trip ------------------------------------------------


def _assert_round_trips_byte_equal(path):
    snap = GcpSnapshot.load(path)
    expected = json.dumps(snap.to_dict(), indent=2, sort_keys=True) + "\n"
    actual = path.read_text(encoding="utf-8")
    assert actual == expected, (
        f"{path.name} does not round-trip byte-equal through "
        f"json.dumps(to_dict(), indent=2, sort_keys=True). This holds ONLY when "
        f"every defaulted field (priority, disabled, the empty firewall list "
        f"fields, reset/inherit_from_parent, and the rule-record defaults) is "
        f"spelled out explicitly in the file: from_dict fills any omitted "
        f"default and to_dict re-emits it, so an under-specified record cannot "
        f"reproduce its own source bytes. Re-emit the fixture from to_dict() "
        f"rather than hand-editing it.")


def test_full_fixture_round_trips_byte_equal():
    _assert_round_trips_byte_equal(FULL_PATH)


def test_partial_fixture_round_trips_byte_equal():
    _assert_round_trips_byte_equal(PARTIAL_PATH)


# -- captured-category counts ---------------------------------------------


def test_full_fixture_captures_all_nineteen_categories():
    snap = GcpSnapshot.load(FULL_PATH)
    assert snap.captured_categories() == ALL_CATEGORIES
    assert len(snap.captured_categories()) == 19


def test_partial_fixture_captures_exactly_eleven_categories():
    snap = GcpSnapshot.load(PARTIAL_PATH)
    assert snap.captured_categories() == VOCAB_CATEGORIES
    assert len(snap.captured_categories()) == 11
    # none of the eight record tables were captured
    for table in RECORD_TABLES:
        assert getattr(snap, table) is None


# -- partial fixture forces every estate accessor to abstain --------------


@pytest.mark.parametrize("method, args", ESTATE_ACCESSORS)
def test_estate_accessors_return_unknown_on_partial_fixture(method, args):
    snap = GcpSnapshot.load(PARTIAL_PATH)
    assert getattr(snap, method)(*args) is UNKNOWN


def test_partial_fixture_vocab_accessors_still_answer():
    # The flat vocabularies ARE captured on the partial fixture, so existence
    # questions there still resolve — only the record tables abstain.
    snap = GcpSnapshot.load(PARTIAL_PATH)
    assert snap.network_exists(
        "projects/acme-prod/global/networks/vpc-main") is True
    assert snap.restricted_service_exists("storage.googleapis.com") is True
    assert snap.access_level_exists(
        "accessPolicies/987/accessLevels/trusted_corp") is True


# -- the full fixture is genuinely realistic (no wrong-reason blocks) ------


def test_full_fixture_records_are_reachable():
    snap = GcpSnapshot.load(FULL_PATH)
    # firewall table populated and filterable by its network
    rules = snap.firewall_rules_for_network(
        "projects/acme-prod/global/networks/vpc-main")
    assert rules is not UNKNOWN and len(rules) == 4
    # the enforced boolean the disablement check contradicts
    op = snap.org_policy("projects/acme-prod",
                         "constraints/compute.disableSerialPortAccess")
    assert op is not None and op["rules"][0]["enforce"] is True
    # every org-policy constraint is also defined in the constraints vocabulary
    for node_constraint in ("constraints/compute.disableSerialPortAccess",
                            "constraints/iam.allowedPolicyMemberDomains",
                            "constraints/compute.vmExternalIpAccess"):
        assert snap.constraint(node_constraint) is not None
    # the perimeter and its egress identity survived the round-trip
    per = snap.vpc_sc_perimeter("accessPolicies/987/servicePerimeters/prod")
    assert per["status"]["egress_policies"][0]["egress_from"]["identities"] == (
        "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com",)
