"""Claim-extraction tests: exact claims (kind + value + location) from the
shared fixture policies, plus the conservative skip rules — malformed or
request-time constructs yield no claim, never a guess."""

import json
from pathlib import Path

import pytest

from gcp_grounding.claims import (KINDS, NO_RULE_INDEX, Claim, iam_policy_claims,
                                  org_policy_claims)

POLICIES = Path(__file__).parent / "fixtures" / "gcp" / "policies"


def load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


# -- IAM policy fixtures: exact claims ------------------------------------


def test_iam_policy_good_exact_claims():
    assert iam_policy_claims(load("iam_policy_good.json")) == [
        Claim("role", "roles/bigquery.dataViewer", "bindings[0].role"),
        Claim("principal", "group:data-eng@acme.example", "bindings[0].members[0]"),
        Claim("principal", "user:alice@acme.example", "bindings[0].members[1]"),
        Claim("role", "roles/bigquery.jobUser", "bindings[1].role"),
        Claim("principal", "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com",
              "bindings[1].members[0]"),
        Claim("role", "roles/storage.objectViewer", "bindings[2].role"),
        Claim("principal", "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com",
              "bindings[2].members[0]"),
        Claim("cel", 'request.time < timestamp("2027-01-01T00:00:00Z")',
              "bindings[2].condition.expression"),
    ]


def test_iam_policy_bad_exact_claims():
    # Extraction does not judge: the hallucinated role, the ghost service
    # account and the never-true condition all still become claims — the
    # reasoner is what refutes them against the snapshot.
    assert iam_policy_claims(load("iam_policy_bad.json")) == [
        Claim("role", "roles/bigquery.reader", "bindings[0].role"),
        Claim("principal", "group:data-eng@acme.example", "bindings[0].members[0]"),
        Claim("role", "roles/storage.objectViewer", "bindings[1].role"),
        Claim("principal", "serviceAccount:ghost-runner@acme-prod.iam.gserviceaccount.com",
              "bindings[1].members[0]"),
        Claim("role", "roles/bigquery.jobUser", "bindings[2].role"),
        Claim("principal", "user:alice@acme.example", "bindings[2].members[0]"),
        Claim("cel",
              'request.time < timestamp("2020-01-01T00:00:00Z") && '
              'request.time >= timestamp("2025-01-01T00:00:00Z")',
              "bindings[2].condition.expression"),
    ]


# -- Org Policy fixtures (v2 format): exact claims ------------------------


def test_org_policy_good_exact_claims():
    # Every rule yields both the value-TYPE claim and the payload-bearing
    # enforcement claim: the type alone made `enforce: true` and
    # `enforce: false` indistinguishable.
    assert org_policy_claims(load("org_policy_good.json")) == [
        Claim("constraint", "constraints/iam.disableServiceAccountKeyCreation", "name"),
        Claim("constraint_value", "constraints/iam.disableServiceAccountKeyCreation",
              "spec.rules[0].enforce", is_list=False),
        Claim.of("constraint_enforcement",
                 "constraints/iam.disableServiceAccountKeyCreation", "spec.rules[0]",
                 node="organizations/123456789012", rule_index=0, enforce=True,
                 allow_all=None, deny_all=None, allowed_values=(), denied_values=(),
                 reset=None, inherit_from_parent=None, unreadable=()),
    ]


def test_org_policy_bad_exact_claims():
    # List-typed rule on what the snapshot knows is a boolean constraint:
    # the extractor faithfully records is_list=True and lets the reasoner
    # contradict it.
    assert org_policy_claims(load("org_policy_bad.json")) == [
        Claim("constraint", "constraints/compute.disableSerialPortAccess", "name"),
        Claim("constraint_value", "constraints/compute.disableSerialPortAccess",
              "spec.rules[0].values", is_list=True),
        Claim.of("constraint_enforcement",
                 "constraints/compute.disableSerialPortAccess", "spec.rules[0]",
                 node="projects/acme-prod", rule_index=0, enforce=None,
                 allow_all=None, deny_all=None, allowed_values=("true",),
                 denied_values=(), reset=None, inherit_from_parent=None,
                 unreadable=()),
    ]


# -- Org Policy legacy v1 format ------------------------------------------


def test_legacy_list_policy_on_boolean_constraint_yields_is_list_true():
    claims = org_policy_claims({
        "constraint": "constraints/compute.disableSerialPortAccess",
        "listPolicy": {"allowedValues": ["true"]},
    })
    assert claims == [
        Claim("constraint", "constraints/compute.disableSerialPortAccess", "constraint"),
        Claim("constraint_value", "constraints/compute.disableSerialPortAccess",
              "listPolicy", is_list=True),
        # A v1 document maps onto the very same enforcement payload; it names
        # no node of its own (its parent is the API call's).
        Claim.of("constraint_enforcement",
                 "constraints/compute.disableSerialPortAccess", "listPolicy",
                 node="", rule_index=0, enforce=None, allow_all=None, deny_all=None,
                 allowed_values=("true",), denied_values=(), reset=None,
                 inherit_from_parent=None, unreadable=()),
    ]
    assert claims[1].is_list is True


def test_legacy_boolean_policy_yields_is_list_false():
    assert org_policy_claims({
        "constraint": "constraints/iam.disableServiceAccountKeyCreation",
        "booleanPolicy": {"enforced": True},
    }) == [
        Claim("constraint", "constraints/iam.disableServiceAccountKeyCreation", "constraint"),
        Claim("constraint_value", "constraints/iam.disableServiceAccountKeyCreation",
              "booleanPolicy", is_list=False),
        Claim.of("constraint_enforcement",
                 "constraints/iam.disableServiceAccountKeyCreation", "booleanPolicy",
                 node="", rule_index=0, enforce=True, allow_all=None, deny_all=None,
                 allowed_values=(), denied_values=(), reset=None,
                 inherit_from_parent=None, unreadable=()),
    ]


def test_v2_deny_all_rule_is_list_typed():
    assert org_policy_claims({
        "name": "projects/acme-prod/policies/compute.vmExternalIpAccess",
        "spec": {"rules": [{"denyAll": True}]},
    }) == [
        Claim("constraint", "constraints/compute.vmExternalIpAccess", "name"),
        Claim("constraint_value", "constraints/compute.vmExternalIpAccess",
              "spec.rules[0].denyAll", is_list=True),
        Claim.of("constraint_enforcement", "constraints/compute.vmExternalIpAccess",
                 "spec.rules[0]", node="projects/acme-prod", rule_index=0,
                 enforce=None, allow_all=None, deny_all=True, allowed_values=(),
                 denied_values=(), reset=None, inherit_from_parent=None,
                 unreadable=()),
    ]


# -- conservative skips: IAM ----------------------------------------------


def test_tag_condition_yields_no_cel_claim():
    # Tags resolve at request time — skip, don't guess.
    claims = iam_policy_claims({"bindings": [{
        "role": "roles/viewer",
        "members": ["user:alice@acme.example"],
        "condition": {"expression": "resource.matchTag('tagKeys/123', 'prod')"},
    }]})
    assert claims == [
        Claim("role", "roles/viewer", "bindings[0].role"),
        Claim("principal", "user:alice@acme.example", "bindings[0].members[0]"),
    ]


def test_runtime_only_attribute_condition_yields_no_cel_claim():
    claims = iam_policy_claims({"bindings": [{
        "role": "roles/viewer",
        "members": [],
        "condition": {"expression": "'lvl' in request.auth.access_levels"},
    }]})
    assert claims == [Claim("role", "roles/viewer", "bindings[0].role")]


def test_non_estate_members_leave_a_trace():
    # Non-estate members are no longer silently dropped: allUsers /
    # allAuthenticatedUsers become 'public_principal' grants carrying the role,
    # and everything else (deleted:…, principalSet://) becomes
    # 'unmodelled_principal' — a skipped member always leaves a trace.
    claims = iam_policy_claims({"bindings": [{
        "role": "roles/viewer",
        "members": [
            "allUsers",
            "allAuthenticatedUsers",
            "deleted:serviceAccount:gone@acme-prod.iam.gserviceaccount.com?uid=123",
            "principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*",
            "user:alice@acme.example",
        ],
    }]})
    assert claims == [
        Claim("role", "roles/viewer", "bindings[0].role"),
        Claim.of("public_principal", "allUsers", "bindings[0].members[0]",
                 polarity="grant", role="roles/viewer"),
        Claim.of("public_principal", "allAuthenticatedUsers", "bindings[0].members[1]",
                 polarity="grant", role="roles/viewer"),
        Claim("unmodelled_principal",
              "deleted:serviceAccount:gone@acme-prod.iam.gserviceaccount.com?uid=123",
              "bindings[0].members[2]"),
        Claim("unmodelled_principal",
              "principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*",
              "bindings[0].members[3]"),
        Claim("principal", "user:alice@acme.example", "bindings[0].members[4]"),
    ]


def test_malformed_binding_fields_are_skipped_individually():
    claims = iam_policy_claims({"bindings": [
        {"role": 42, "members": ["user:alice@acme.example"]},
        "not-an-object",
        {"role": "roles/viewer", "members": "not-an-array",
         "condition": {"title": "no expression here"}},
    ]})
    assert claims == [
        Claim("principal", "user:alice@acme.example", "bindings[0].members[0]"),
        Claim("role", "roles/viewer", "bindings[2].role"),
    ]


def test_empty_iam_policy_yields_no_claims():
    assert iam_policy_claims({}) == []
    assert iam_policy_claims({"bindings": []}) == []


# -- conservative skips: Org Policy ---------------------------------------


def test_org_policy_without_resolvable_constraint_yields_nothing():
    assert org_policy_claims({}) == []
    assert org_policy_claims({"spec": {"rules": [{"enforce": True}]}}) == []
    # A v2 name that does not embed exactly one constraint id.
    assert org_policy_claims({"name": "projects/acme-prod", "spec": {"rules": []}}) == []
    # v1 and v2 spellings at once — ambiguous.
    assert org_policy_claims({
        "constraint": "constraints/compute.disableSerialPortAccess",
        "name": "projects/acme-prod/policies/compute.vmExternalIpAccess",
    }) == []


def test_a_malformed_policy_name_does_not_fabricate_a_constraint():
    # A v2 `name` names exactly ONE constraint only when its /policies/ tail is a
    # single non-empty segment. Both malformed tails must leave the document
    # naming nothing — otherwise a constraint identity that appears in no
    # document at all is invented here and then collects verdicts downstream.
    # Asserting only the well-formed side is not enough: the fabrication is
    # visible solely on the two malformed ones.
    empty_suffix = {"name": "projects/acme-prod/policies/",
                    "spec": {"reset": True, "rules": [{"enforce": False}]}}
    multi_segment = {"name": "projects/acme-prod/policies/compute/serialPort",
                     "spec": {"reset": True, "rules": [{"enforce": False}]}}
    assert org_policy_claims(empty_suffix) == []
    assert org_policy_claims(multi_segment) == []
    # The other direction: a single non-empty segment still resolves, so the
    # guard rejects the malformed tails rather than every tail.
    well_formed = org_policy_claims({"name": DISABLE_DOC,
                                     "spec": {"rules": [{"enforce": False}]}})
    assert well_formed[0] == Claim("constraint", SERIAL, "name")
    assert [c.kind for c in well_formed] == ["constraint", "constraint_value",
                                             "constraint_enforcement"]


def test_v2_rule_with_two_value_type_keys_is_ambiguous():
    # RE-PIN. This test used to certify that an ambiguous rule produced NOTHING
    # but the constraint claim — which is exactly the one-key evasion: the
    # surviving constraint claim keeps the document out of the zero-claims
    # honesty guard, so a rule nobody could read was reported as silence. The
    # value-TYPE claim is still (correctly) withheld; what is new is that the
    # skip now travels as an abstain-carrying enforcement claim.
    claims = org_policy_claims({
        "name": "projects/acme-prod/policies/compute.disableSerialPortAccess",
        "spec": {"rules": [{"enforce": True, "values": {"allowedValues": ["x"]}}]},
    })
    assert [c.kind for c in claims] == ["constraint", "constraint_enforcement"]
    assert claims[0] == Claim(
        "constraint", "constraints/compute.disableSerialPortAccess", "name")
    abstain = claims[1]
    assert abstain.location == "spec.rules[0]"
    assert abstain.fields()["rule_index"] == 0
    [reason] = abstain.fields()["unreadable"]
    assert reason.startswith("spec.rules[0] carries 2 value-type keys")
    assert "enforce, values" in reason and "ambiguous" in reason


# -- the rules array is never silence -------------------------------------


DISABLE_DOC = "projects/acme-prod/policies/compute.disableSerialPortAccess"
SERIAL = "constraints/compute.disableSerialPortAccess"

#: Rule shapes the conservative value-type extractor refuses, each with the
#: opening of the reason its abstain-carrying claim must name.
DECOYS = [
    ({}, "carries none of the value-type keys"),
    ({"description": "housekeeping"}, "carries none of the value-type keys"),
    ({"condition": {"expression": "true"}}, "carries none of the value-type keys"),
    ({"enforce": True, "denyAll": True}, "carries 2 value-type keys"),
    ({"values": ["not-an-object"]}, "spec.rules[0].values is not an object, got list"),
    ({"enforce": "yes"}, "spec.rules[0].enforce is not a boolean, got str"),
    ("not-an-object", "spec.rules[0] is not an object, got str"),
]


@pytest.mark.parametrize("decoy, reason_fragment", DECOYS)
def test_a_skipped_rule_still_emits_an_abstain_carrying_claim(decoy, reason_fragment):
    # A rule the extractor cannot read is not a rule that says nothing: the
    # enforcement claim carries the skip so the check can mint one `unverified`
    # naming the location and the reason.
    claims = org_policy_claims({"name": DISABLE_DOC, "spec": {"rules": [decoy]}})
    [abstain] = [c for c in claims if c.kind == "constraint_enforcement"]
    assert abstain.location == "spec.rules[0]"
    fields = abstain.fields()
    assert fields["rule_index"] == 0
    [reason] = fields["unreadable"]
    assert reason_fragment in reason
    # It carries no value at all — an abstention must never look like content.
    assert (fields["enforce"], fields["allow_all"], fields["deny_all"]) == \
        (None, None, None)
    assert (fields["allowed_values"], fields["denied_values"]) == ([], [])
    # And the value-TYPE claim stays withheld: this is a strengthening of the
    # conservative skip, not a relaxation of it.
    assert [c.kind for c in claims] == ["constraint", "constraint_enforcement"]


@pytest.mark.parametrize("decoy, _reason", DECOYS)
@pytest.mark.parametrize("flag, key", [("reset", "reset"),
                                       ("inheritFromParent", "inherit_from_parent")])
def test_one_decoy_rule_cannot_hide_the_reset_or_inherit_spelling(decoy, _reason,
                                                                  flag, key):
    # THE ONE-KEY EVASION: the document-level claim used to be emitted only
    # when the rules array was FALSY, so a single unreadable entry hid two of
    # the three disablement spellings entirely.
    claims = org_policy_claims({"name": DISABLE_DOC,
                                "spec": {flag: True, "rules": [decoy]}})
    [document_level] = [c for c in claims if c.kind == "constraint_enforcement"
                        and c.location == "spec"]
    fields = document_level.fields()
    assert fields["rule_index"] == NO_RULE_INDEX
    assert fields[key] is True
    assert fields["unreadable"] == []


@pytest.mark.parametrize("flag, key", [("reset", "reset"),
                                       ("inheritFromParent", "inherit_from_parent")])
def test_a_readable_rule_still_suppresses_the_document_level_claim(flag, key):
    # The both-directions control: a rule that WAS read already carries the
    # spec-level switches in its own payload, so the document-level claim would
    # be a duplicate. Suppression is conditional on that, and on nothing else.
    claims = org_policy_claims({"name": DISABLE_DOC,
                                "spec": {flag: True, "rules": [{"enforce": True}]}})
    assert [c.location for c in claims if c.kind == "constraint_enforcement"] == \
        ["spec.rules[0]"]
    assert claims[-1].fields()[key] is True


def test_a_readable_rule_suppresses_exactly_one_document_level_claim():
    # BOTH DIRECTIONS OF THE SUPPRESSION RULE, and the pin on the flag that
    # carries it. The document-level claim rides along whenever reset or
    # inheritFromParent is true, INDEPENDENT of the rules array, and is
    # suppressed only when a rule of the document's own was actually read — that
    # rule already carries the same switches, so emitting both reports one
    # enforcement payload twice. A flag that never sets is invisible in the
    # decoy direction alone, which is why the read direction is asserted here.
    for flag, key in (("reset", "reset"), ("inheritFromParent", "inherit_from_parent")):
        read = org_policy_claims(
            {"name": DISABLE_DOC,
             "spec": {flag: True, "rules": [{"enforce": True}]}})
        enforcement = [c for c in read if c.kind == "constraint_enforcement"]
        assert [c.location for c in enforcement] == ["spec.rules[0]"]
        assert enforcement[0].fields()[key] is True
        assert enforcement[0].fields()["rule_index"] == 0

        decoy = org_policy_claims(
            {"name": DISABLE_DOC,
             "spec": {flag: True, "rules": [{"description": "housekeeping"}]}})
        locations = [c.location for c in decoy if c.kind == "constraint_enforcement"]
        assert locations == ["spec.rules[0]", "spec"]


def test_a_document_level_claim_carries_the_sentinel_and_a_rule_its_own_index():
    # COVERAGE, NOT A KILL — see EQ-O01. The document-level rule index is a
    # sentinel that cannot collide with a real one BY CONSTRUCTION: real indices
    # come out of enumerate() and are integers, and the sentinel deliberately is
    # not, so there is no arithmetic literal here for a mutation to shift into
    # the range of a real index.
    claims = org_policy_claims({
        "name": DISABLE_DOC,
        "spec": {"reset": True, "rules": [{"description": "one"}, {}]}})
    by_location = {c.location: c.fields()["rule_index"]
                   for c in claims if c.kind == "constraint_enforcement"}
    assert by_location == {"spec.rules[0]": 0, "spec.rules[1]": 1,
                           "spec": NO_RULE_INDEX}
    assert isinstance(by_location["spec.rules[1]"], int)
    assert not isinstance(NO_RULE_INDEX, int)


def test_a_non_list_rules_value_abstains_naming_the_key():
    claims = org_policy_claims({"name": DISABLE_DOC, "spec": {"rules": "all of them"}})
    [abstain] = [c for c in claims if c.kind == "constraint_enforcement"]
    assert abstain.location == "spec.rules"
    assert abstain.fields()["rule_index"] == NO_RULE_INDEX
    assert abstain.fields()["unreadable"] == ["spec.rules is not an array, got str"]


def test_an_explicitly_empty_rules_array_is_an_observation_not_a_skip():
    # The other direction of the same guard: an array that is present and holds
    # nothing was READ, so it must not manufacture an abstention either.
    claims = org_policy_claims({"name": DISABLE_DOC, "spec": {"rules": []}})
    assert [c.kind for c in claims] == ["constraint"]


# -- a malformed values block is unreadable, not empty --------------------


@pytest.mark.parametrize("block, field, reason", [
    ({"allowedValues": "acme.example"},
     "allowed_values", "spec.rules[0].values.allowedValues is not an array, got str"),
    ({"deniedValues": {"0": "evil.example"}},
     "denied_values", "spec.rules[0].values.deniedValues is not an array, got dict"),
])
def test_a_non_list_value_list_is_recorded_as_unreadable(block, field, reason):
    # PINS THE TYPE GUARD ITSELF: without the isinstance check the string is
    # iterated character by character and `allowed_values` fills with letters,
    # so this assertion fails on the value as well as on the flag.
    claims = org_policy_claims({"name": DISABLE_DOC,
                                "spec": {"rules": [{"values": block}]}})
    [claim] = [c for c in claims if c.kind == "constraint_enforcement"]
    assert claim.fields()[field] == []
    assert claim.fields()["unreadable"] == [reason]


def test_dropped_non_string_entries_are_recorded_as_unreadable():
    claims = org_policy_claims({
        "name": DISABLE_DOC,
        "spec": {"rules": [{"values": {"allowedValues": ["acme.example", 7, ""]}}]}})
    [claim] = [c for c in claims if c.kind == "constraint_enforcement"]
    assert claim.fields()["allowed_values"] == ["acme.example"]
    assert claim.fields()["unreadable"] == [
        "spec.rules[0].values.allowedValues: 2 of 3 entries are not non-empty strings"]


def test_a_well_formed_values_block_carries_no_unreadable_flag():
    claims = org_policy_claims({
        "name": DISABLE_DOC,
        "spec": {"rules": [{"values": {"allowedValues": ["acme.example"],
                                       "deniedValues": ["evil.example"]}}]}})
    [claim] = [c for c in claims if c.kind == "constraint_enforcement"]
    assert claim.fields()["unreadable"] == []
    assert claim.fields()["allowed_values"] == ["acme.example"]


def test_the_reason_names_the_spelling_the_document_actually_used():
    # The terraform spelling and the REST one are both accepted, so a reason
    # naming the other one would point at a field that is not there.
    claims = org_policy_claims({
        "name": DISABLE_DOC,
        "spec": {"rules": [{"values": {"denied_values": "evil.example"}}]}})
    [claim] = [c for c in claims if c.kind == "constraint_enforcement"]
    assert claim.fields()["unreadable"] == [
        "spec.rules[0].values.denied_values is not an array, got str"]


def test_a_v1_list_policy_records_its_own_malformed_values():
    [claim] = [c for c in org_policy_claims(
        {"constraint": SERIAL, "listPolicy": {"allowedValues": 3}})
        if c.kind == "constraint_enforcement"]
    assert claim.fields()["unreadable"] == [
        "listPolicy.allowedValues is not an array, got int"]


# -- claim model invariants -----------------------------------------------


def test_claim_rejects_unknown_kind():
    with pytest.raises(ValueError):
        Claim("permission_maybe", "x", "somewhere")


def test_is_list_is_exactly_the_constraint_value_field():
    with pytest.raises(ValueError):
        Claim("constraint_value", "constraints/x", "listPolicy")  # missing is_list
    with pytest.raises(ValueError):
        Claim("role", "roles/viewer", "bindings[0].role", is_list=True)
    assert "constraint_value" in KINDS


def test_extractors_reject_non_mapping_input():
    with pytest.raises(ValueError):
        iam_policy_claims(["not", "a", "policy"])
    with pytest.raises(ValueError):
        org_policy_claims(None)
