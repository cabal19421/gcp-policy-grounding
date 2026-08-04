"""IAM, org policy, VPC Service Controls and the resource hierarchy, mapped to
estate RECORDS.

Every headline record is asserted against the LOADED
``tests/fixtures/gcp/estate_snapshot.json`` rather than against hand-copied
literals, so a record-schema change fails here instead of drifting, and the
inputs are read out of the committed terraform corpus — ``estate.tfstate`` for
the plan-JSON encoding every reader is required to produce, ``main.tf`` for the
HCL spellings — so the two ends of the mapping move together.

``terraform`` is not installed on this machine and nothing here needs it.

WHY ``_assemble`` LIVES IN THIS FILE. ``gcp_grounding/merge.py`` is a separate
task and is not in this checkout, so the fragment assembly the IAM acceptance
turns on is stood in for here by :func:`_assemble`, which implements exactly
step 4 of merge's documented algorithm for these facts: order the fragments by
``priority`` (defaulting to a very large number) then by ADDRESS, concatenate
the list field the fragment names, collapse exact duplicates, and — for
``iam_bindings`` — merge bindings of the same role and identical condition with
their members sorted. When ``merge`` lands this helper becomes one call to it.
The mapper itself has no cross-resource aggregator, which is the property this
file exists to keep true.
"""

import json
from pathlib import Path

import pytest

from gcp_grounding import facts, knowledge
from gcp_grounding.tfsource import map_policy, mapping

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
ESTATE = FIXTURES / "estate_snapshot.json"
STATE = FIXTURES / "tf" / "estate.tfstate"
MAIN_TF = FIXTURES / "tf" / "hcl" / "main.tf"

PROJECT_BINDINGS = "//cloudresourcemanager.googleapis.com/projects/acme-prod"
PERIMETER = "accessPolicies/987/servicePerimeters/prod"

CTX = mapping.MapContext(project="acme-prod", region="us-central1",
                         organization="1", folder="2", access_policy="987",
                         project_number="123456")


# -- the committed corpus ------------------------------------------------------


@pytest.fixture(scope="module")
def estate():
    """The estate fixture as the estate model itself loads it — list fields
    frozen to tuples, exactly as a record table stores them."""
    return knowledge.GcpSnapshot.load(ESTATE)


@pytest.fixture(scope="module")
def state():
    return json.loads(STATE.read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def registry():
    """Registration is import-time and therefore process-global, while the
    resolved cache is not: a sibling module that reset the cache would leave
    this one testing an empty registry."""
    mapping.reset_cache()
    map_policy.register_all()
    yield
    mapping.reset_cache()


def _attributes(state, resource_type, name):
    """One resource instance's attributes from the committed v4 state — already
    in the plan-JSON encoding, which is what a mapper is contracted to see."""
    for resource in state["resources"]:
        if resource["type"] == resource_type and resource["name"] == name:
            for instance in resource["instances"]:
                if "deposed" not in instance:
                    return dict(instance["attributes"])
    raise AssertionError(f"{resource_type}.{name} is not in {STATE}")


_NOTHING = object()


def _block(text, resource_type, name):
    """The body of one ``resource "<type>" "<name>"`` block of the committed
    HCL. NOT an HCL reader — that is another task's module, and this file has to
    keep passing before one exists."""
    header = f'resource "{resource_type}" "{name}" {{'
    start = text.index(header) + len(header)
    depth = 1
    lines = []
    for line in text[start:].splitlines():
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            break
        lines.append(line)
    return "\n".join(lines)


def _literal(raw):
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw in ("true", "false"):
        return raw == "true"
    if raw.lstrip("-").isdigit():
        return int(raw)
    if raw.startswith("[") and raw.endswith("]"):
        items = [item.strip() for item in raw[1:-1].split(",") if item.strip()]
        if items and all(len(item) >= 2 and item.startswith('"') and item.endswith('"')
                         for item in items):
            return [item[1:-1] for item in items]
    return _NOTHING


def _literals(resource_type, name):
    """The block's own top-level literal attributes; nested blocks are skipped."""
    block = _block(MAIN_TF.read_text(encoding="utf-8"), resource_type, name)
    values = {}
    depth = 0
    for line in block.splitlines():
        stripped = line.strip()
        if depth == 0 and "=" in stripped and not stripped.startswith(("#", "//", "*")):
            key, _, raw = stripped.partition("=")
            parsed = _literal(raw.strip())
            if parsed is not _NOTHING:
                values[key.strip()] = parsed
        depth += stripped.count("{") - stripped.count("}")
    return values


def _object(address, resource_type, values, **overrides):
    return facts.TfObject(address=address, type=resource_type,
                          name=address.split(".")[-1],
                          source=overrides.pop("source", "tfstate"),
                          values=values, artifact=str(STATE), **overrides)


def _map(obj):
    return map_policy.map_one(obj, CTX)


def _only(mapped, category=""):
    rows = [fact for fact in mapped.facts
            if not category or fact.category == category]
    assert len(rows) == 1, [(f.category, f.key) for f in mapped.facts]
    return rows[0]


def _validated(category, key, record):
    """The record as the estate table's OWN strict constructor accepts it — a
    record that cannot be loaded back is a record no snapshot could hold."""
    snapshot = knowledge.GcpSnapshot.from_dict(
        {"captured_at": "2026-01-04T10:00:00Z", category: {key: record}})
    return getattr(snapshot, category)[key]


# -- merge's fragment assembly, stood in for ----------------------------------

_NO_PRIORITY = 2 ** 63          # merge's "defaulting to a very large number"


def _assemble(fragments):
    """Step 4 of merge's algorithm for a set of ``iam_bindings`` fragments. See
    this module's docstring: merge itself is a separate task."""
    ordered = sorted(fragments,
                     key=lambda fact: (fact.record.get("priority", _NO_PRIORITY),
                                       fact.address))
    merged = []
    for fact in ordered:
        assert fact.fragment == "bindings"
        for binding in fact.record["bindings"]:
            slot = (binding["role"],
                    json.dumps(binding["condition"], sort_keys=True, default=str))
            for existing in merged:
                if existing[0] == slot:
                    existing[1].update(binding["members"])
                    break
            else:
                merged.append((slot, set(binding["members"]), binding))
    return {"bindings": tuple(
        {"condition": binding["condition"], "members": tuple(sorted(members)),
         "role": binding["role"]}
        for _slot, members, binding in merged)}


# -- IAM ----------------------------------------------------------------------


def _binding_object(state):
    """``google_project_iam_binding.owner`` as the committed state holds it."""
    return _object("google_project_iam_binding.owner",
                   "google_project_iam_binding",
                   _attributes(state, "google_project_iam_binding", "owner"))


def _member_object(address, role, member):
    return _object(address, "google_project_iam_member",
                   {"project": "acme-prod", "role": role, "member": member,
                    "condition": []})


def test_a_binding_and_two_members_assemble_into_the_estates_record(state, estate):
    """The headline pin: three resources, one bindings document."""
    literals = _literals("google_project_iam_member", "ci_security_admin")
    fragments = [
        _only(_map(_binding_object(state))),
        # the committed main.tf member, and one that repeats a member the
        # binding already granted — an exact duplicate must collapse
        _only(_map(_member_object("google_project_iam_member.ci_security_admin",
                                  literals["role"], literals["member"]))),
        _only(_map(_member_object("google_project_iam_member.alice_owner",
                                  "roles/owner", "user:alice@acme.example"))),
    ]

    assert {fact.key for fact in fragments} == {PROJECT_BINDINGS}
    assert _assemble(fragments) == estate.iam_bindings[PROJECT_BINDINGS]


def test_the_same_members_split_differently_produce_the_identical_record(estate):
    """The same grant, authored as two member resources instead of a binding
    plus a member, is the same policy — so it is the same record."""
    fragments = [
        _only(_map(_member_object("google_project_iam_member.alice_owner",
                                  "roles/owner", "user:alice@acme.example"))),
        _only(_map(_member_object(
            "google_project_iam_member.ci_security_admin",
            "roles/iam.securityAdmin",
            "serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com"))),
    ]

    assert _assemble(fragments) == estate.iam_bindings[PROJECT_BINDINGS]


def test_the_assembled_record_loads_back_through_the_estate_tables_constructor(
        state, estate):
    assembled = _assemble([_only(_map(_binding_object(state)))])
    assert _validated("iam_bindings", PROJECT_BINDINGS, assembled)["bindings"]


HEREDOC_POLICY_DATA = '<<-EOT\n{"bindings": [{"role": "roles/owner"}]}\nEOT\n'


def test_a_heredoc_mangled_policy_data_emits_no_fact_and_one_note():
    """`google_project_iam_policy` coverage from raw HCL is effectively zero and
    is not advertised otherwise: an unread policy is a MISSING binding set."""
    mapped = _map(_object("google_project_iam_policy.project",
                          "google_project_iam_policy",
                          {"project": "acme-prod",
                           "policy_data": HEREDOC_POLICY_DATA}))

    assert mapped.facts == ()
    assert len(mapped.notes) == 1
    assert "google_project_iam_policy.project" in mapped.notes[0]


@pytest.mark.parametrize("policy_data", [
    facts.Unresolved("heredoc", "google_project_iam_policy.project.policy_data"),
    facts.Unresolved("interpolation",
                     "google_project_iam_policy.project.policy_data"),
    {"bindings": []},                       # a non-string
    "[]",                                   # valid JSON, not a policy object
    '{"bindings": ["roles/owner"]}',        # a binding that is not an object
])
def test_every_unreadable_policy_data_spelling_is_one_note_and_no_fact(policy_data):
    mapped = _map(_object("google_project_iam_policy.project",
                          "google_project_iam_policy",
                          {"project": "acme-prod", "policy_data": policy_data}))

    assert mapped.facts == ()
    assert len(mapped.notes) == 1


def test_a_readable_policy_data_is_read_whole():
    mapped = _map(_object("google_project_iam_policy.project",
                          "google_project_iam_policy",
                          {"project": "acme-prod",
                           "policy_data": json.dumps({"bindings": [
                               {"role": "roles/owner",
                                "members": ["user:b@acme.example",
                                            "user:a@acme.example"]}]})}))

    fact = _only(mapped)
    assert fact.key == PROJECT_BINDINGS
    assert fact.record["bindings"][0]["members"] == ("user:a@acme.example",
                                                     "user:b@acme.example")


def _every_iam_object(state):
    literals = _literals("google_project_iam_member", "ci_security_admin")
    return [
        _binding_object(state),
        _member_object("google_project_iam_member.ci_security_admin",
                       literals["role"], literals["member"]),
        _object("google_project_iam_policy.project", "google_project_iam_policy",
                {"project": "acme-prod", "policy_data": '{"bindings": []}'}),
        _object("google_folder_iam_binding.viewers", "google_folder_iam_binding",
                {"folder": "folders/2", "role": "roles/viewer",
                 "members": ["user:alice@acme.example"]}),
        _object("google_organization_iam_member.admin",
                "google_organization_iam_member",
                {"org_id": "1", "role": "roles/owner",
                 "member": "user:alice@acme.example"}),
        _object("google_service_account_iam_member.token",
                "google_service_account_iam_member",
                {"service_account_id":
                     "projects/acme-prod/serviceAccounts/"
                     "etl-runner@acme-prod.iam.gserviceaccount.com",
                 "role": "roles/iam.serviceAccountTokenCreator",
                 "member": "user:alice@acme.example"}),
    ]


def test_the_authoritativeness_note_is_present_on_every_iam_bindings_fact(state):
    result = mapping.map_objects(_every_iam_object(state), CTX)

    emitted = [fact for fact in result.facts if fact.category == "iam_bindings"]
    assert len(emitted) == len(_every_iam_object(state))
    for fact in emitted:
        assert map_policy.AUTHORITATIVENESS_NOTE in fact.notes
        assert fact.fragment == "bindings"
    assert not result.failures and not result.unrecognized


def test_the_four_iam_families_land_on_their_own_target(state):
    keys = {fact.address: fact.key
            for fact in mapping.map_objects(_every_iam_object(state), CTX).facts
            if fact.category == "iam_bindings"}

    assert keys["google_folder_iam_binding.viewers"] == (
        "//cloudresourcemanager.googleapis.com/folders/2")
    assert keys["google_organization_iam_member.admin"] == (
        "//cloudresourcemanager.googleapis.com/organizations/1")
    assert keys["google_service_account_iam_member.token"] == (
        "//iam.googleapis.com/projects/acme-prod/serviceAccounts/"
        "etl-runner@acme-prod.iam.gserviceaccount.com")


def test_an_iam_target_that_fails_key_resolution_names_the_address():
    marker = facts.Unresolved("interpolation",
                              "google_project_iam_member.dynamic.project")
    mapped = _map(_object("google_project_iam_member.dynamic",
                          "google_project_iam_member",
                          {"project": marker, "role": "roles/owner",
                           "member": "user:alice@acme.example"}))

    assert mapped.facts == ()
    assert len(mapped.notes) == 1
    assert "google_project_iam_member.dynamic" in mapped.notes[0]
    assert "interpolation" in mapped.notes[0]


def test_a_bare_service_account_email_is_refused_rather_than_project_guessed():
    """A service account may live in ANY project, so filling in the workspace's
    would key one account's policy onto another project's resource."""
    mapped = _map(_object("google_service_account_iam_member.token",
                          "google_service_account_iam_member",
                          {"service_account_id":
                               "etl-runner@acme-prod.iam.gserviceaccount.com",
                           "role": "roles/iam.serviceAccountTokenCreator",
                           "member": "user:alice@acme.example"}))

    assert mapped.facts == ()
    assert len(mapped.notes) == 1
    assert "google_service_account_iam_member.token" in mapped.notes[0]


def test_an_unresolvable_member_unresolves_the_whole_binding():
    """One member quietly dropped describes a policy that grants less than it
    grants, so the WHOLE list is unresolved instead."""
    fact = _only(_map(_object(
        "google_project_iam_binding.owner", "google_project_iam_binding",
        {"project": "acme-prod", "role": "roles/owner",
         "members": ["user:alice@acme.example", "${var.principal}"]})))

    assert facts.is_unresolved(fact.record["bindings"][0]["members"])
    assert fact.unresolved and fact.unresolved[0].reason == "interpolation"


# -- roles and service accounts -----------------------------------------------


def test_a_custom_roles_permissions_are_sorted(estate):
    literals = _literals("google_project_iam_custom_role", "ci_deployer")
    values = dict(literals)
    values["permissions"] = list(reversed(literals["permissions"]))

    fact = _only(_map(_object("google_project_iam_custom_role.ci_deployer",
                              "google_project_iam_custom_role", values)))

    assert fact.key == "projects/acme-prod/roles/ciDeployer"
    assert fact.record["included_permissions"] == tuple(sorted(literals["permissions"]))
    assert fact.record == estate.roles[fact.key]
    assert _validated("roles", fact.key, fact.record) == estate.roles[fact.key]


def test_a_custom_role_with_no_permissions_attribute_omits_the_field():
    """knowledge.py's own rule: omit the key when the permissions were not
    captured, because an empty list is a role that grants nothing."""
    fact = _only(_map(_object("google_project_iam_custom_role.ci_deployer",
                              "google_project_iam_custom_role",
                              {"project": "acme-prod", "role_id": "ciDeployer",
                               "title": "Acme CI deployer"})))

    assert "included_permissions" not in fact.record


def test_a_service_account_prefers_the_literal_email(state, estate):
    literal = _only(_map(_object(
        "google_service_account.etl_runner", "google_service_account",
        _attributes(state, "google_service_account", "etl-runner"))))
    derived = _only(_map(_object("google_service_account.ci_deployer",
                                 "google_service_account",
                                 _literals("google_service_account", "ci_deployer"))))

    assert literal.key == "etl-runner@acme-prod.iam.gserviceaccount.com"
    assert derived.key == "ci-deployer@acme-prod.iam.gserviceaccount.com"
    assert {literal.key, derived.key} <= estate.service_accounts


def test_a_service_account_never_derives_an_email_from_half_a_literal():
    mapped = _map(_object("google_service_account.dynamic",
                          "google_service_account",
                          {"account_id": "ci-deployer",
                           "project": facts.Unresolved(
                               "interpolation",
                               "google_service_account.dynamic.project")}))

    assert mapped.facts == ()
    assert len(mapped.notes) == 1


# -- org policy ---------------------------------------------------------------


def _org_policy_object(state, name):
    return _object(f"google_org_policy_policy.{name}", "google_org_policy_policy",
                   _attributes(state, "google_org_policy_policy", name))


@pytest.mark.parametrize("name,constraint", [
    ("disable-serial-port", "constraints/compute.disableSerialPortAccess"),
    ("member-domains", "constraints/iam.allowedPolicyMemberDomains"),
    ("vm-external-ip", "constraints/compute.vmExternalIpAccess"),
])
def test_the_org_policy_records_equal_the_estates(state, estate, name, constraint):
    """The ``enforce = "TRUE"`` policy is the first of these: the provider's
    STRING boolean has to become the JSON boolean the estate stores."""
    fact = _only(_map(_org_policy_object(state, name)))

    key = f"projects/acme-prod|{constraint}"
    assert fact.key == key
    assert fact.record == estate.org_policies[key]
    assert _validated("org_policies", key, fact.record) == estate.org_policies[key]
    assert not fact.notes


def test_the_string_boolean_becomes_a_real_boolean(state, estate):
    values = _attributes(state, "google_org_policy_policy", "disable-serial-port")
    assert values["spec"][0]["rules"][0]["enforce"] == "TRUE"

    fact = _only(_map(_org_policy_object(state, "disable-serial-port")))

    assert fact.record["rules"][0]["enforce"] is True


def test_an_org_policy_carrying_a_dry_run_spec_reads_none_of_it(state):
    values = _attributes(state, "google_org_policy_policy", "disable-serial-port")
    values["dry_run_spec"] = [{
        "inherit_from_parent": False, "reset": False,
        "rules": [{"allow_all": None, "condition": [], "deny_all": "TRUE",
                   "enforce": None, "values": [{"allowed_values": ["dry-run-only"],
                                                "denied_values": []}]}],
    }]

    fact = _only(_map(_object("google_org_policy_policy.disable_serial_port",
                              "google_org_policy_policy", values)))

    assert fact.notes == (map_policy.DRY_RUN_NOTE,)
    assert "dry-run-only" not in json.dumps(fact.record, default=str)
    assert fact.record["rules"][0]["deny_all"] is None
    # and the enforced half is untouched by the presence of the dry-run half
    assert fact.record["rules"][0]["enforce"] is True


def test_a_dry_run_only_policy_enforces_NOTHING_and_says_so():
    """The dangerous half of the same rule: with no ``spec`` at all there is
    nothing enforced, and the dry-run half must not be promoted into the gap."""
    mapped = _map(_object("google_org_policy_policy.dry_only",
                          "google_org_policy_policy",
                          {"name": "projects/acme-prod/policies/"
                                   "compute.disableSerialPortAccess",
                           "parent": "projects/acme-prod", "spec": [],
                           "dry_run_spec": [{"rules": [{"enforce": "TRUE"}]}]}))

    fact = _only(mapped)
    assert fact.record["rules"] == ()
    assert "TRUE" not in json.dumps(fact.record, default=str)
    assert fact.notes == (map_policy.DRY_RUN_NOTE,)


@pytest.mark.parametrize("spelling,enforced", [("TRUE", True), ("FALSE", False),
                                               (True, True), (False, False)])
def test_both_string_booleans_survive_the_round_trip(spelling, enforced):
    """A boolean guessed wrong is a policy that reads as enforced when it is
    not, so ``"FALSE"`` matters exactly as much as ``"TRUE"``."""
    fact = _only(_map(_object(
        "google_org_policy_policy.serial_port", "google_org_policy_policy",
        {"name": "projects/acme-prod/policies/compute.disableSerialPortAccess",
         "parent": "projects/acme-prod",
         "spec": [{"rules": [{"enforce": spelling}]}]})))

    assert fact.record["rules"][0]["enforce"] is enforced


def test_a_boolean_the_provider_never_spells_is_a_marker_and_never_a_default():
    fact = _only(_map(_object(
        "google_org_policy_policy.serial_port", "google_org_policy_policy",
        {"name": "projects/acme-prod/policies/compute.disableSerialPortAccess",
         "parent": "projects/acme-prod", "spec": [{"rules": [{"enforce": "yes"}]}]})))

    assert facts.is_unresolved(fact.record["rules"][0]["enforce"])
    assert fact.unresolved and fact.unresolved[0].reason == "unparsed"


def test_a_legacy_boolean_policy_translates_to_the_estates_rule_shape(estate):
    fact = _only(_map(_object(
        "google_project_organization_policy.serial_port",
        "google_project_organization_policy",
        {"project": "acme-prod",
         "constraint": "compute.disableSerialPortAccess",
         "boolean_policy": [{"enforced": True}]})))

    key = "projects/acme-prod|constraints/compute.disableSerialPortAccess"
    assert fact.key == key
    assert fact.record == estate.org_policies[key]


def test_a_legacy_list_policy_translates_to_the_estates_rule_shape(estate):
    fact = _only(_map(_object(
        "google_project_organization_policy.member_domains",
        "google_project_organization_policy",
        {"project": "acme-prod", "constraint": "iam.allowedPolicyMemberDomains",
         "list_policy": [{"allow": [{"values": ["C01abcdef"]}]}]})))

    key = "projects/acme-prod|constraints/iam.allowedPolicyMemberDomains"
    assert fact.record == estate.org_policies[key]


def test_a_legacy_restore_policy_is_unresolved_and_not_an_empty_rule_set():
    """An empty rule set reads as "no restriction", which is the OPPOSITE of
    what a restore means."""
    fact = _only(_map(_object(
        "google_project_organization_policy.restored",
        "google_project_organization_policy",
        {"project": "acme-prod", "constraint": "compute.vmExternalIpAccess",
         "restore_policy": [{"default": True}]})))

    assert facts.is_unresolved(fact.record["rules"])
    assert fact.record["rules"] != ()
    assert fact.record["rules"] != []
    assert fact.unresolved and fact.unresolved[0].reason == "unparsed"
    assert fact.record["reset"] is True


def test_a_legacy_policy_with_no_policy_block_at_all_is_unresolved_too():
    fact = _only(_map(_object(
        "google_project_organization_policy.empty",
        "google_project_organization_policy",
        {"project": "acme-prod", "constraint": "compute.vmExternalIpAccess"})))

    assert facts.is_unresolved(fact.record["rules"])


# -- VPC Service Controls ------------------------------------------------------


def _perimeter_object(state):
    return _object("google_access_context_manager_service_perimeter.prod",
                   "google_access_context_manager_service_perimeter",
                   _attributes(
                       state, "google_access_context_manager_service_perimeter",
                       "prod"))


def test_the_perimeter_record_equals_the_estates(state, estate):
    fact = _only(_map(_perimeter_object(state)), "vpc_sc_perimeters")

    assert fact.key == PERIMETER
    assert fact.record == estate.vpc_sc_perimeters[PERIMETER]
    assert (_validated("vpc_sc_perimeters", PERIMETER, fact.record)
            == estate.vpc_sc_perimeters[PERIMETER])
    # the project-NUMBER form is KEPT: the hierarchy alias reconciles it later
    assert fact.record["status"]["resources"] == ("projects/123456",)


def _sided_perimeter(side, block):
    return _object("google_access_context_manager_service_perimeter.prod",
                   "google_access_context_manager_service_perimeter",
                   {"name": PERIMETER, "parent": "accessPolicies/987",
                    "perimeter_type": "PERIMETER_TYPE_REGULAR",
                    "use_explicit_dry_run_spec": side == "spec",
                    side: [block]})


STATUS_ONLY = {"resources": ["projects/123456"],
               "restricted_services": ["storage.googleapis.com"],
               "access_levels": ["accessPolicies/987/accessLevels/trusted_corp"]}
SPEC_ONLY = {"resources": ["projects/999999"],
             "restricted_services": ["bigquery.googleapis.com"],
             "access_levels": ["accessPolicies/987/accessLevels/dry_run_only"]}


def test_status_and_spec_are_never_cross_populated_in_either_direction():
    """A ``status`` block is ENFORCED and a ``spec`` block is DRY-RUN. Reading
    one for the other would let a dry-run perimeter read as enforced."""
    enforced = _only(_map(_sided_perimeter("status", STATUS_ONLY)),
                     "vpc_sc_perimeters")
    dry_run = _only(_map(_sided_perimeter("spec", SPEC_ONLY)), "vpc_sc_perimeters")

    assert enforced.record["spec"] is None
    assert enforced.record["status"]["resources"] == ("projects/123456",)
    assert dry_run.record["status"] is None
    assert dry_run.record["spec"]["resources"] == ("projects/999999",)


def test_restricted_services_and_access_levels_come_from_status_only():
    both = _object("google_access_context_manager_service_perimeter.prod",
                   "google_access_context_manager_service_perimeter",
                   {"name": PERIMETER, "parent": "accessPolicies/987",
                    "perimeter_type": "PERIMETER_TYPE_REGULAR",
                    "use_explicit_dry_run_spec": True,
                    "status": [STATUS_ONLY], "spec": [SPEC_ONLY]})

    mapped = _map(both)

    services = {fact.key for fact in mapped.facts
                if fact.category == "restricted_services"}
    levels = {fact.key for fact in mapped.facts if fact.category == "access_levels"}
    assert services == {"storage.googleapis.com"}
    assert levels == {"accessPolicies/987/accessLevels/trusted_corp"}
    # the dry-run half is in the record and in NO side fact
    assert mapped.facts[0].record["spec"]["restricted_services"] == (
        "bigquery.googleapis.com",)


INGRESS_BLOCK = {"ingress_from": [{"identities": ["user:alice@acme.example"]}],
                 "ingress_to": [{"resources": ["*"]}]}


def test_a_dry_run_ingress_policy_lands_on_spec_only():
    fact = _only(_map(_object(
        "google_access_context_manager_service_perimeter_dry_run_ingress_policy.dry",
        "google_access_context_manager_service_perimeter_dry_run_ingress_policy",
        dict(INGRESS_BLOCK, perimeter=PERIMETER))))

    assert fact.fragment == "spec"
    assert set(fact.record) == {"spec"}
    assert "status" not in fact.record
    assert fact.record["spec"]["ingress_policies"][0]["ingress_from"] == {
        "identities": ("user:alice@acme.example",)}


def test_the_enforced_ingress_policy_lands_on_status_only():
    fact = _only(_map(_object(
        "google_access_context_manager_service_perimeter_ingress_policy.live",
        "google_access_context_manager_service_perimeter_ingress_policy",
        dict(INGRESS_BLOCK, perimeter=PERIMETER))))

    assert fact.fragment == "status"
    assert set(fact.record) == {"status"}


@pytest.mark.parametrize("resource_type,side", sorted(
    (resource_type, side)
    for resource_type, (side, _field) in map_policy.PERIMETER_FRAGMENTS.items()))
def test_every_dry_run_sibling_lands_on_spec_and_every_other_on_status(
        resource_type, side):
    assert side == ("spec" if "_dry_run_" in resource_type else "status")

    fact = _only(_map(_object(f"{resource_type}.fragment", resource_type,
                              {"perimeter_name": PERIMETER, "perimeter": PERIMETER,
                               "resource": "projects/123456", **INGRESS_BLOCK,
                               "egress_from": [{"identities": []}],
                               "egress_to": [{"resources": ["*"]}]})))

    assert fact.fragment == side
    assert set(fact.record) == {side}


def test_a_perimeter_resource_fragment_keeps_the_project_number(estate):
    fact = _only(_map(_object(
        "google_access_context_manager_service_perimeter_resource.prod",
        "google_access_context_manager_service_perimeter_resource",
        {"perimeter_name": PERIMETER, "resource": "projects/123456"})))

    assert fact.key == PERIMETER
    assert fact.record == {"status": {"resources": ("projects/123456",)}}
    assert estate.vpc_sc_perimeters[PERIMETER]["status"]["resources"] == (
        "projects/123456",)


def test_an_access_level_is_its_own_flat_fact(state, estate):
    fact = _only(_map(_object(
        "google_access_context_manager_access_level.trusted_corp",
        "google_access_context_manager_access_level",
        _attributes(state, "google_access_context_manager_access_level",
                    "trusted-corp"))))

    assert fact.key in estate.access_levels
    assert fact.record is None


# -- the resource hierarchy ----------------------------------------------------


def test_a_google_project_from_the_state_carries_its_number(state, estate):
    fact = _only(_map(_object("google_project.this", "google_project",
                              _attributes(state, "google_project", "this"))))

    assert fact.key == "projects/acme-prod"
    assert fact.record == estate.resource_hierarchy["projects/acme-prod"]


def test_a_google_project_from_hcl_has_a_none_number(estate):
    """The number is assigned at apply time and CANNOT appear in configuration,
    so None here is the honest answer and not a gap."""
    # the committed HCL corpus has no google_project block, so this is the
    # provider's own HCL shape: project_id plus a folder, and nothing computed.
    fact = _only(_map(_object("google_project.this", "google_project",
                              {"project_id": "acme-prod", "name": "Acme Prod",
                               "folder_id": "2"}, source="hcl-current")))

    assert fact.record["number"] is None
    assert fact.record["parent"] == "folders/2"
    stored = estate.resource_hierarchy["projects/acme-prod"]
    assert stored["number"] == "123456"          # the API knows what HCL cannot
    assert {key: fact.record[key] for key in ("display_name", "parent", "type")} == {
        key: stored[key] for key in ("display_name", "parent", "type")}


def test_no_organization_node_is_emitted_from_a_parent_string(estate):
    """A parent REFERENCE is not an observation that the parent exists."""
    objects = [
        _object("google_project.this", "google_project",
                {"project_id": "acme-prod", "name": "Acme Prod", "org_id": "1"}),
        _object("google_folder.prod", "google_folder",
                {"name": "folders/2", "display_name": "Prod",
                 "parent": "organizations/1"}),
    ]

    result = mapping.map_objects(objects, CTX)

    nodes = {fact.key for fact in result.facts
             if fact.category == "resource_hierarchy"}
    assert nodes == {"projects/acme-prod", "folders/2"}
    assert "organizations/1" not in nodes
    assert "organizations/1" in estate.resource_hierarchy   # only the API knows it


def test_a_folder_record_equals_the_estates(estate):
    fact = _only(_map(_object("google_folder.prod", "google_folder",
                              {"name": "folders/2", "folder_id": "2",
                               "display_name": "Prod",
                               "parent": "organizations/1"})))

    assert fact.record == estate.resource_hierarchy["folders/2"]


def test_a_folder_with_no_generated_id_is_refused_rather_than_guessed():
    """The folder id is generated at apply time, exactly like the hierarchical
    firewall policy id, so raw HCL cannot key one."""
    mapped = _map(_object("google_folder.prod", "google_folder",
                          {"display_name": "Prod", "parent": "organizations/1"},
                          source="hcl-current"))

    assert mapped.facts == ()
    assert len(mapped.notes) == 1
    assert "google_folder.prod" in mapped.notes[0]


# -- the registry seam ---------------------------------------------------------


def test_every_claimed_type_is_registered_through_the_one_registry():
    table = mapping.mappers()
    for resource_type in map_policy.PERIMETER_FRAGMENTS:
        assert table[resource_type].module == map_policy.__name__
    for family in map_policy.IAM_FAMILIES:
        for suffix in ("binding", "member", "policy"):
            assert table[f"{family}_{suffix}"].category == "iam_bindings"
    assert table["google_org_policy_policy"].category == "org_policies"
    assert table["google_project"].category == "resource_hierarchy"


def test_the_stated_gaps_carry_a_reason_each_and_are_never_claimed():
    table = mapping.mappers()
    for resource_type, reason in map_policy.DELIBERATELY_UNMAPPED.items():
        assert reason.strip(), resource_type
        assert resource_type not in table
        assert mapping.DELIBERATELY_UNMAPPED[resource_type] == reason

    result = mapping.map_objects(
        [_object("google_project_iam_audit_config.project",
                 "google_project_iam_audit_config", {"project": "acme-prod"})],
        CTX)

    assert [row.reason for row in result.unmapped] == ["deliberate"]
    assert not result.facts and not result.notes


UNRESOLVED_QUALIFIERS = [
    ("google_project_iam_binding", {"role": "roles/owner", "members": []}, "project"),
    ("google_folder_iam_member",
     {"role": "roles/viewer", "member": "user:a@acme.example"}, "folder"),
    ("google_organization_iam_binding", {"role": "roles/owner", "members": []},
     "org_id"),
    ("google_project_iam_custom_role", {"role_id": "ciDeployer"}, "project"),
    ("google_organization_iam_custom_role", {"role_id": "orgAuditor"}, "org_id"),
    ("google_service_account", {"account_id": "ci-deployer"}, "project"),
    ("google_org_policy_policy", {"name": "compute.disableSerialPortAccess"},
     "parent"),
    ("google_project_organization_policy",
     {"constraint": "compute.vmExternalIpAccess", "boolean_policy": [
         {"enforced": True}]}, "project"),
    ("google_access_context_manager_service_perimeter",
     {"name": "prod", "status": []}, "parent"),
    ("google_access_context_manager_access_level", {"name": "trusted_corp"},
     "parent"),
    ("google_project", {"name": "Acme Prod"}, "project_id"),
]


@pytest.mark.parametrize("resource_type,values,qualifier", UNRESOLVED_QUALIFIERS)
def test_an_unresolved_qualifier_abstains_and_never_raises(resource_type, values,
                                                           qualifier):
    """A marker in a key part is ignorance to be REPORTED, not an exception:
    Unresolved refuses truthiness precisely so a mapper cannot read it as empty,
    and a mapper that crashes on one degrades the whole object to a failure row.
    """
    address = f"{resource_type}.thing"
    marker = facts.Unresolved("interpolation", f"{address}.{qualifier}")

    mapped = _map(_object(address, resource_type,
                          dict(values, **{qualifier: marker})))

    assert mapped.facts == ()
    assert len(mapped.notes) == 1
    assert address in mapped.notes[0]


def test_map_one_says_nothing_about_a_type_this_module_does_not_claim():
    mapped = _map(_object("google_compute_firewall.allow_internal",
                          "google_compute_firewall", {"name": "allow-internal"}))

    assert mapped == map_policy.Mapped()
