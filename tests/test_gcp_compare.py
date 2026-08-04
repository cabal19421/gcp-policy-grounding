"""Tests for :mod:`gcp_grounding.compare` — the one record comparator.

``identity.py`` answers "are these two rows the same resource"; this module's
subject answers "do they SAY the same thing", and the two failure modes it
exists to prevent pull in opposite directions:

1. **A difference that is not one.** A set-valued field written in another
   order, a protocol spelled ``TCP``, an etag reissued by the server — a
   comparator that reports these turns one unchanged firewall into a wall of
   drift, and a wall of drift is a report nobody reads. So the committed estate
   is asserted to compare EQUAL TO ITSELF, category by category, and the whole
   of ``VOLATILE_IGNORED`` is asserted to be silent in a loop.
2. **A difference silently swallowed.** An unclassified field guessed equal, a
   partially compared IAM policy, a dry-run perimeter paired with an enforced
   one. So an unknown key is asserted to be ``unmergeable`` EVEN WHEN THE TWO
   VALUES MATCH, an unrecognised key inside a binding is asserted to make the
   whole record ``Incomparable``, and the spec/status cross-pairing is asserted
   to be refused with its reason.
"""

import json
from pathlib import Path

import pytest

from gcp_grounding import identity
from gcp_grounding.compare import (
    BENIGN,
    BENIGN_REPORTED,
    DRY_RUN_SPEC_NOTE,
    FIELDS,
    MATERIAL,
    PERIMETER_CROSS_PAIR,
    SEVERITIES,
    UNMERGEABLE,
    VOLATILE_IGNORED,
    CategoryCompare,
    FieldDiff,
    Incomparable,
    compare,
    comparable,
)

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
ESTATE = json.loads((FIXTURES / "estate_snapshot.json").read_text(encoding="utf-8"))

#: Every category the committed estate carries, so a table is asserted BY NAME
#: and a failure names the table that broke.
CATEGORIES = sorted(k for k in ESTATE if k != "captured_at")


def _records(category: str) -> list:
    """Every record of one table — a record map's values, a flat vocabulary's
    own names (for a flat category the name IS the record)."""
    value = ESTATE[category]
    return sorted(value) if isinstance(value, list) else list(value.values())


# -- the tables ---------------------------------------------------------------


def test_fields_covers_exactly_the_estate_categories():
    # The same category set identity.SPECS keys, which is itself asserted equal
    # to the snapshot's own field set: a category added to the estate model
    # without a field table would report every one of its fields as unmergeable.
    assert set(FIELDS) == set(identity.SPECS)
    for category, spec in FIELDS.items():
        assert isinstance(spec, CategoryCompare)
        assert spec.category == category
        # A field cannot be two severities at once.
        assert not spec.security_fields & set(spec.benign_fields)
        assert not spec.security_fields & VOLATILE_IGNORED
        assert not set(spec.benign_fields) & VOLATILE_IGNORED
        # Every subrecord collection is a field the category classifies.
        assert set(spec.subrecord_keys) <= spec.security_fields | set(spec.benign_fields)


def test_the_two_pinned_lists_are_disjoint_and_say_what_they_say():
    assert VOLATILE_IGNORED == frozenset({
        "etag", "self_link", "selfLink", "id", "fingerprint",
        "creation_timestamp", "creationTimestamp", "labels",
        "terraform_address", "project_number"})
    assert BENIGN_REPORTED == frozenset({"description"})
    assert not VOLATILE_IGNORED & BENIGN_REPORTED
    # An IAM policy version is semantic — version 3 admits conditions version 1
    # does not — so it is in NEITHER list and stays material.
    assert "version" not in VOLATILE_IGNORED and "version" not in BENIGN_REPORTED
    assert "version" in FIELDS["iam_bindings"].security_fields


# -- the committed estate round-trips -----------------------------------------


@pytest.mark.parametrize("category", CATEGORIES)
def test_every_estate_record_is_comparable(category):
    """Every record of every table normalises without raising — and the form is
    hashable and deterministic, which is the whole promise of ``comparable``."""
    for record in _records(category):
        form = comparable(category, record)
        assert hash(form) == hash(comparable(category, record))
        assert form == comparable(category, record)


@pytest.mark.parametrize("category", CATEGORIES)
def test_every_estate_record_compares_equal_to_itself(category):
    """…and yields no diffs against itself, which pins that every field the
    committed estate actually carries is CLASSIFIED: an unclassified one would
    surface here as an unmergeable diff naming itself."""
    for record in _records(category):
        assert compare(category, record, record) == ()


# -- order normalisation ------------------------------------------------------


FIREWALL = {
    "action": "allow",
    "direction": "INGRESS",
    "disabled": False,
    "layer4": [{"protocol": "tcp", "ports": ["22"]}],
    "network": "projects/acme-prod/global/networks/vpc-main",
    "priority": 1000,
    "source_ranges": ["10.0.0.0/8", "192.168.0.0/16"],
    "destination_ranges": [],
    "source_tags": [],
    "target_tags": ["web"],
    "source_service_accounts": [],
    "target_service_accounts": [],
}


def test_range_order_and_protocol_case_are_not_differences():
    shuffled = dict(FIREWALL,
                    source_ranges=["192.168.0.0/16", "10.0.0.0/8"],
                    layer4=[{"protocol": "TCP", "ports": ["22"]}])
    assert comparable("firewall_rules", FIREWALL) == comparable("firewall_rules", shuffled)
    assert compare("firewall_rules", FIREWALL, shuffled) == ()


def test_a_single_port_is_the_one_element_interval():
    ranged = dict(FIREWALL, layer4=[{"protocol": "tcp", "ports": ["22-22"]}])
    assert comparable("firewall_rules", FIREWALL) == comparable("firewall_rules", ranged)
    assert compare("firewall_rules", FIREWALL, ranged) == ()


def test_an_unparseable_port_raises_incomparable():
    broken = dict(FIREWALL, layer4=[{"protocol": "tcp", "ports": ["ssh"]}])
    with pytest.raises(Incomparable) as excinfo:
        comparable("firewall_rules", broken)
    assert "port" in str(excinfo.value)
    with pytest.raises(Incomparable):
        compare("firewall_rules", FIREWALL, broken)


def test_a_bare_port_string_is_the_same_as_a_one_element_list():
    """An HCL artifact writes ``ports = "22"`` where the API answers a list."""
    bare = dict(FIREWALL, layer4=[{"protocol": "tcp", "ports": "22"}])
    assert comparable("firewall_rules", FIREWALL) == comparable("firewall_rules", bare)


def test_a_layer4_entry_with_extra_content_is_refused():
    """The canonical protocol/ports form cannot hold anything else, so
    normalising such an entry would drop it silently."""
    with pytest.raises(Incomparable, match="ipProtocol"):
        comparable("firewall_rules",
                   dict(FIREWALL, layer4=[{"protocol": "tcp", "ipProtocol": "6"}]))


def test_a_value_that_cannot_be_frozen_is_incomparable():
    with pytest.raises(Incomparable, match="'network' cannot be frozen"):
        comparable("firewall_rules", dict(FIREWALL, network=object()))


def test_priority_keyed_rules_ignore_their_position_in_the_array():
    """An Armor rule's identity is its priority slot, not its array index."""
    policy = ESTATE["cloud_armor_policies"]["projects/acme-prod/global/securityPolicies/edge-waf"]
    reversed_rules = dict(policy, rules=list(reversed(policy["rules"])))
    assert comparable("cloud_armor_policies", policy) == comparable(
        "cloud_armor_policies", reversed_rules)
    assert compare("cloud_armor_policies", policy, reversed_rules) == ()


# -- the severities -----------------------------------------------------------


def test_volatile_fields_yield_no_diff_at_all():
    """The volatile-ignored pin, for EVERY member of the list. Classifying
    these merely as benign would not ignore them: drift turns every benign diff
    into a verdict, and two views of one unchanged firewall would emit a wall
    of drift about etags and self-links."""
    for name in sorted(VOLATILE_IGNORED):
        left = dict(FIREWALL, **{name: "one"})
        right = dict(FIREWALL, **{name: "another"})
        assert compare("firewall_rules", left, right) == (), name
        assert comparable("firewall_rules", left) == comparable("firewall_rules", right)
    # …and the two the brief names, differing at once.
    left = dict(FIREWALL, etag="AAA=", fingerprint="xyz")
    right = dict(FIREWALL, etag="BBB=", fingerprint="zyx")
    assert compare("firewall_rules", left, right) == ()


def test_description_is_exactly_one_benign_diff():
    diffs = compare("firewall_rules", dict(FIREWALL, description="was"),
                    dict(FIREWALL, description="now"))
    assert len(diffs) == 1
    assert (diffs[0].field, diffs[0].severity) == ("description", BENIGN)
    assert (diffs[0].left, diffs[0].right) == ("was", "now")
    assert diffs[0].path == "description"


def test_source_ranges_content_is_exactly_one_material_diff():
    diffs = compare("firewall_rules", FIREWALL,
                    dict(FIREWALL, source_ranges=["10.0.0.0/8", "0.0.0.0/0"]))
    assert len(diffs) == 1
    assert (diffs[0].field, diffs[0].severity) == ("source_ranges", MATERIAL)


def test_an_unknown_field_is_one_unmergeable_diff_naming_it():
    diffs = compare("firewall_rules", dict(FIREWALL, gremlin="left"), FIREWALL)
    assert len(diffs) == 1
    assert (diffs[0].field, diffs[0].severity) == ("gremlin", UNMERGEABLE)
    assert "gremlin" in diffs[0].note


def test_an_unknown_field_is_unmergeable_even_when_the_values_match():
    """Refuse-on-surprise: an unclassified field is never silently EQUAL, or a
    provider that adds a field is a provider nobody ever looks at."""
    diffs = compare("firewall_rules", dict(FIREWALL, gremlin="same"),
                    dict(FIREWALL, gremlin="same"))
    assert [(d.field, d.severity) for d in diffs] == [("gremlin", UNMERGEABLE)]


def test_every_diff_carries_a_recognised_severity():
    with pytest.raises(ValueError):
        FieldDiff("x", "", "probably-fine", 1, 2)
    assert SEVERITIES == (MATERIAL, BENIGN, UNMERGEABLE)


# -- IAM: expansion, and the refusal ------------------------------------------


ONE_BINDING = {
    "version": 1,
    "bindings": [{"role": "roles/owner",
                  "members": ["user:alice@acme.example", "user:bob@acme.example"],
                  "condition": None}],
}
TWO_BINDINGS = {
    "version": 1,
    "bindings": [{"role": "roles/owner", "members": ["user:bob@acme.example"]},
                 {"role": "roles/owner", "members": ["user:alice@acme.example"]}],
}


def test_iam_binding_grouping_is_not_a_difference():
    assert comparable("iam_bindings", ONE_BINDING) == comparable("iam_bindings", TWO_BINDINGS)
    assert compare("iam_bindings", ONE_BINDING, TWO_BINDINGS) == ()


def test_an_added_member_is_exactly_one_material_diff():
    grown = {"version": 1,
             "bindings": [dict(ONE_BINDING["bindings"][0],
                               members=["user:alice@acme.example", "user:bob@acme.example",
                                        "user:mallory@acme.example"])]}
    diffs = compare("iam_bindings", ONE_BINDING, grown)
    assert len(diffs) == 1
    assert (diffs[0].field, diffs[0].severity) == ("bindings", MATERIAL)
    assert diffs[0].left is None and diffs[0].right is not None
    assert "mallory" in repr(diffs[0].right)


def test_the_iam_policy_version_is_one_material_diff():
    diffs = compare("iam_bindings", ONE_BINDING, dict(ONE_BINDING, version=3))
    assert len(diffs) == 1
    assert (diffs[0].field, diffs[0].severity) == ("version", MATERIAL)
    assert (diffs[0].left, diffs[0].right) == (1, 3)


def test_a_memberless_binding_is_still_something_one_view_says():
    """It grants nothing, but dropping it would be a silent equality."""
    memberless = {"version": 1, "bindings": [{"role": "roles/owner", "members": []}]}
    diffs = compare("iam_bindings", {"version": 1, "bindings": []}, memberless)
    assert [(d.field, d.severity) for d in diffs] == [("bindings", MATERIAL)]


def test_a_record_against_a_bare_name_is_incomparable():
    with pytest.raises(Incomparable, match="bare name"):
        compare("iam_bindings", ONE_BINDING, "//cloudresourcemanager.googleapis.com/x")


def test_a_binding_with_an_unrecognised_key_makes_the_record_incomparable():
    poisoned = {"bindings": [{"role": "roles/owner",
                              "members": ["user:alice@acme.example"],
                              "bindingId": "7"}]}
    with pytest.raises(Incomparable) as excinfo:
        comparable("iam_bindings", poisoned)
    assert "bindingId" in str(excinfo.value)
    with pytest.raises(Incomparable):
        compare("iam_bindings", ONE_BINDING, poisoned)


# -- the perimeter rule -------------------------------------------------------


SPEC_ONLY = {"perimeter_type": "PERIMETER_TYPE_REGULAR",
             "spec": {"restricted_services": ["storage.googleapis.com"]}}
STATUS_ONLY = {"perimeter_type": "PERIMETER_TYPE_REGULAR",
               "status": {"restricted_services": ["storage.googleapis.com"]}}


def test_a_spec_only_view_against_a_status_only_view_is_refused():
    diffs = compare("vpc_sc_perimeters", SPEC_ONLY, STATUS_ONLY)
    assert len(diffs) == 1
    assert diffs[0].severity == UNMERGEABLE
    assert diffs[0].note == PERIMETER_CROSS_PAIR
    assert "dry-run" in diffs[0].note.lower() and "enforced" in diffs[0].note.lower()
    # …and symmetrically.
    assert len(compare("vpc_sc_perimeters", STATUS_ONLY, SPEC_ONLY)) == 1


def test_status_is_compared_to_status_and_spec_to_spec():
    widened = {"perimeter_type": "PERIMETER_TYPE_REGULAR",
               "status": {"restricted_services": []}}
    diffs = compare("vpc_sc_perimeters", STATUS_ONLY, widened)
    assert [(d.field, d.severity) for d in diffs] == [("status", MATERIAL)]
    assert compare("vpc_sc_perimeters", SPEC_ONLY, SPEC_ONLY) == ()


# -- the org-policy rule ------------------------------------------------------


ORG_POLICY = ESTATE["org_policies"][
    "projects/acme-prod|constraints/compute.disableSerialPortAccess"]


def test_a_dry_run_spec_difference_is_benign_and_carries_its_note():
    diffs = compare("org_policies",
                    dict(ORG_POLICY, dry_run_spec={"rules": [{"enforce": False}]}),
                    dict(ORG_POLICY, dry_run_spec={"rules": [{"enforce": True}]}))
    assert len(diffs) == 1
    assert (diffs[0].field, diffs[0].severity) == ("dry_run_spec", BENIGN)
    assert diffs[0].note == DRY_RUN_SPEC_NOTE
    assert "never enforced" in diffs[0].note


def test_org_policy_rules_are_ordered_so_position_is_a_difference():
    two = dict(ORG_POLICY, rules=[dict(ORG_POLICY["rules"][0], enforce=True),
                                  dict(ORG_POLICY["rules"][0], enforce=False)])
    swapped = dict(ORG_POLICY, rules=list(reversed(two["rules"])))
    diffs = compare("org_policies", two, swapped)
    assert diffs and all(d.severity == MATERIAL for d in diffs)
    assert comparable("org_policies", two) != comparable("org_policies", swapped)


# -- paths --------------------------------------------------------------------


def test_a_diff_path_renders_with_the_index():
    one = dict(ORG_POLICY, rules=[dict(ORG_POLICY["rules"][0], enforce=True)])
    other = dict(ORG_POLICY, rules=[dict(ORG_POLICY["rules"][0], enforce=False)])
    diffs = compare("org_policies", one, other)
    assert [(d.path, d.severity) for d in diffs] == [("rules[0].enforce", MATERIAL)]
    assert (diffs[0].field, diffs[0].subkey) == ("rules.enforce", "0")
    # A whole subrecord present on one side only names its position too.
    grown = dict(one, rules=[one["rules"][0], dict(one["rules"][0], enforce=False)])
    added = compare("org_policies", one, grown)
    assert [d.path for d in added] == ["rules[1]"]
    assert added[0].left is None


def test_a_top_level_path_is_the_bare_field_name():
    diffs = compare("firewall_rules", FIREWALL, dict(FIREWALL, priority=100))
    assert [(d.path, d.severity) for d in diffs] == [("priority", MATERIAL)]


# -- the absent document ------------------------------------------------------


def test_comparing_against_none_yields_an_empty_tuple():
    assert compare("firewall_rules", FIREWALL, None) == ()
    assert compare("firewall_rules", None, FIREWALL) == ()
    assert compare("firewall_rules", None, None) == ()


def test_an_unknown_category_is_a_caller_error():
    with pytest.raises(ValueError, match="not an estate category"):
        compare("firewall_rulez", FIREWALL, FIREWALL)
    with pytest.raises(ValueError, match="not an estate category"):
        comparable("firewall_rulez", FIREWALL)
